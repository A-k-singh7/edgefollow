#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""The TLS front door (tls_front.py) against a stand-in upstream (2026-11-19) -- no phone, no lab, no network.

Everything runs on loopback, on free ports the system hands out:

  * a stand-in upstream in this process (plain HTTP). It records every request it receives (method, target, headers,
    body) and echoes the method, the target, the X-M2M-Origin header and the body. The X-M2M-RI header picks a
    special answer: "slow..." waits 3 s first, "missing..." answers 404, "nobody..." 204, "large..." 1 MiB, "huge..."
    8 MiB (more than loopback buffers hold, so a slow reader really holds up the write). A GET of .../pch/pcu answers
    {} (nothing queued). It checks no oneM2M rule;
  * a second counting server (the "bystander"), which nothing may ever reach: it is the address named in the refused
    poa, nu and absolute-URI attempts;
  * tls_front.py as a subprocess, and for the rows that inject a fault (a thread that cannot start, an accept() that
    fails, short body, handshake and head deadlines, a client that never reads a refusal) and the row that reads its
    default limits, its module loaded into this process. A THROWAWAY certificate authority, server certificate and
    keys are made here in a temporary folder and deleted at the end;
  * a TLS client that trusts only the throwaway authority. It sends from 127.0.0.1 and 127.0.0.2, the two bound
    addresses (127.0.0.1 = Cprobe-test-a:phone, 127.0.0.2 = Cprobe-test-b:probeB, base cse-mn-a), and from
    127.0.0.3, which is not bound.

The app's requests are rebuilt here from phone/probe_app/src/org/edgefollow/probe/LiveService.java (version 20): the
same methods, paths, Content-Type with ty=, JSON bodies (written as org.json writes them: no spaces, "/" as "\\/"),
the four oneM2M headers the app sets, and the ones its HTTP stack adds (User-Agent, Accept-Encoding, Connection, and
Host: the address of the front door, here 127.0.0.1, without the port unless a row says so).
phone/sim_phone.py, which imitates the app, is also run once through a front door (its Host carries the port).

A control row ("CONTROL (must FAIL) <the fault having gone through>") passes only when the refusal was positively
seen: the expected status (or the handshake seen not to complete), the stand-in upstream's own request counter
unchanged, and the front door answering a good request afterwards. A part of the test that ends in an unexpected
error is a failed row of its own ("SECTION ERROR"); it is never counted as a refusal seen.

Not a row, and why: the earlier row "a client that trusts another authority completed the handshake" tested the
client (Python's TLS client refusing a server it does not trust), not this program. What the program does about its
own certificate is tested instead: it refuses to start with a key that does not belong to the certificate.

    mkdir -p ~/estimed-run/tmp && TMPDIR=~/estimed-run/tmp python3 phone/test_tls_front.py

(any temporary folder works except one under /var, which main() refuses: /var filled up on this lab PC once)

TLS_FRONT_PROGRAM=<path> runs the test against another copy of the program (used for the planted-fault runs).
"""
from __future__ import annotations

import collections
import errno
import hashlib
import http.client
import importlib.util
import itertools
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROGRAM = os.environ.get("TLS_FRONT_PROGRAM") or str(HERE / "tls_front.py")
OTHER_PYTHON = "/home/edgefollow/edgefollow-lab/.venv/bin/python"     # has `cryptography`, if this one has not

RESULTS: list[tuple[str, bool, str]] = []
CONTROLS = 0
HEADER_MARK = "MARKhdr7c1e"            # sent as a forwarded X-M2M-RI value: must never be in the log
BODY_MARK = "MARKbody93af"             # planted in a request body
QUERY_MARK = "MARKqry55d0"             # planted in a (refused) query string
SLOW_S = 3.0
LARGE = bytes(range(256)) * 4096       # 1 MiB, what an RI "large..." gets
HUGE = LARGE * 8                       # 8 MiB, what an RI "huge..." gets (loopback buffers hold about 2 MB)
MAX_BODY = 262144                      # the program's default --max-body
REFUSED = "tls_front: refused"         # how the program's own refusal of its arguments starts: an exit code 2 alone
#                                        is not taken as a refusal (the interpreter exits 2 for a missing file too)
ANSWERED: dict[int, int] = {}          # front door port -> requests of ours it answered with a status
SEEN: dict[int, list[int]] = {}        # front door port -> the statuses our clients saw

BASE = "cse-mn-a"
IP_A, ORIG_A, RN_A = "127.0.0.1", "Cprobe-test-a", "phone"
IP_B, ORIG_B, RN_B = "127.0.0.2", "Cprobe-test-b", "probeB"
IP_NOT_BOUND = "127.0.0.3"
BINDS = ["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:{RN_A}", "--bind", f"{IP_B}={ORIG_B}:{RN_B}"]
FORWARDED = {"host", "x-m2m-origin", "x-m2m-ri", "x-m2m-rvi", "accept", "content-type", "content-length"}
SUBJECT = "subject: O=tlsfront throwaway test, CN=tlsfront test server"
_RI = itertools.count(1)


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def control(name, seen_refused, detail=""):
    """A control row: `name` says what must NOT have happened; the row passes only when the refusal was seen."""
    global CONTROLS
    CONTROLS += 1
    check("CONTROL (must FAIL) " + name, seen_refused is True, detail)


def section(title, fn):
    print(f"== {title}", flush=True)
    try:
        fn()
    except Exception as e:  # noqa: BLE001 -- an error here is a failed row, never a refusal seen
        check(f"SECTION ERROR (an error, not a detection): {title}", False, repr(e)[:300])


# ---------------------------------------------------------------- the stand-in upstream and the bystander

class Upstream:
    def __init__(self):
        self.lock = threading.Lock()
        self.seen: list[dict] = []

    def count(self) -> int:
        with self.lock:
            return len(self.seen)

    def last(self) -> dict:
        with self.lock:
            return self.seen[-1]

    def since(self, n: int) -> list[dict]:
        with self.lock:
            return list(self.seen[n:])


def upstream_handler(state: Upstream):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def answer(self, code: int, raw: bytes, rsc: str, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-M2M-RSC", rsc)
            self.send_header("X-M2M-RI", self.headers.get("X-M2M-RI") or "none")
            self.send_header("X-M2M-RVI", "3")
            try:
                self.end_headers()
                self.wfile.write(raw)
            except OSError:
                pass                            # the front door gave up waiting (the 504 row) and closed

        def any(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            with state.lock:
                state.seen.append({"method": self.command, "target": self.path, "body": body,
                                   "headers": {k.lower(): v for k, v in self.headers.items()}})
            ri = self.headers.get("X-M2M-RI") or ""
            if ri.startswith("slow"):
                time.sleep(SLOW_S)
            if ri.startswith("missing"):
                return self.answer(404, b'{"m2m:dbg":"resource not found"}', "4004")
            if ri.startswith("large"):
                return self.answer(200, LARGE, "2000", "application/octet-stream")
            if ri.startswith("huge"):
                return self.answer(200, HUGE, "2000", "application/octet-stream")
            if ri.startswith("nobody"):
                self.send_response(204)
                self.send_header("X-M2M-RSC", "2004")
                self.end_headers()
                return None
            if self.command == "GET" and self.path.endswith("/pch/pcu") and not ri.startswith("slow"):
                return self.answer(200, b"{}", "2000")
            echo = {"method": self.command, "target": self.path, "origin": self.headers.get("X-M2M-Origin"),
                    "body": body.decode("latin-1")}
            code, rsc = (201, "2001") if self.command == "POST" else (200, "2000")
            return self.answer(code, json.dumps(echo).encode(), rsc)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_CONNECT = any

        def log_message(self, *a):
            pass
    return H


def serve(handler_cls):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---------------------------------------------------------------- the throwaway certificates

MAKE_CERTS = r'''
import datetime, ipaddress, json, sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
out = Path(sys.argv[1])
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
t0, t1 = now - datetime.timedelta(minutes=5), now + datetime.timedelta(days=2)
def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "tlsfront throwaway test"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
ca_key = ec.generate_private_key(ec.SECP384R1())
ca_cert = (x509.CertificateBuilder().subject_name(name("tlsfront throwaway test CA"))
           .issuer_name(name("tlsfront throwaway test CA")).public_key(ca_key.public_key())
           .serial_number(x509.random_serial_number()).not_valid_before(t0).not_valid_after(t1)
           .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
           .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
           .sign(ca_key, hashes.SHA384()))
k = ec.generate_private_key(ec.SECP384R1())
leaf = (x509.CertificateBuilder().subject_name(name("tlsfront test server")).issuer_name(ca_cert.subject)
        .public_key(k.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(t0).not_valid_after(t1)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                    x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA384()))
pem = serialization.Encoding.PEM
(out / "ca.pem").write_bytes(ca_cert.public_bytes(pem))
(out / "server.pem").write_bytes(leaf.public_bytes(pem))
(out / "server.key").write_bytes(pem_key(k))
(out / "other.key").write_bytes(pem_key(ec.generate_private_key(ec.SECP384R1())))
fmt = "%Y-%m-%dT%H:%M:%SZ"
print(json.dumps({"not_before": t0.strftime(fmt), "not_after": t1.strftime(fmt)}))
'''


def make_certs_openssl(out: Path) -> dict:
    """The same files with the openssl command line, for a machine without the `cryptography` package."""
    def run(*a):
        subprocess.run(["openssl", *a], cwd=out, check=True, capture_output=True, timeout=60)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-nodes", "-sha384", "-days", "2",
        "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/O=tlsfront throwaway test/CN=tlsfront throwaway test CA",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    (out / "ext.cnf").write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
                                 "extendedKeyUsage=serverAuth\n")
    run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-nodes", "-keyout", "server.key",
        "-out", "server.csr", "-subj", "/O=tlsfront throwaway test/CN=tlsfront test server")
    run("x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-sha384",
        "-days", "2", "-extfile", "ext.cnf", "-out", "server.pem")
    run("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", "other.key")
    txt = subprocess.run(["openssl", "x509", "-in", "server.pem", "-noout", "-dates", "-dateopt", "iso_8601"],
                         cwd=out, check=True, capture_output=True, text=True, timeout=60).stdout
    d = dict(line.split("=", 1) for line in txt.strip().splitlines())
    return {"not_before": d["notBefore"].replace(" ", "T"), "not_after": d["notAfter"].replace(" ", "T")}


def make_certs(out: Path) -> tuple[dict, str]:
    if not os.environ.get("TLS_FRONT_TEST_OPENSSL"):
        for py in (sys.executable, OTHER_PYTHON):
            try:
                r = subprocess.run([py, "-c", MAKE_CERTS, str(out)], capture_output=True, text=True, timeout=120)
            except OSError:
                continue
            if r.returncode == 0:
                return json.loads(r.stdout), f"cryptography under {py}"
    return make_certs_openssl(out), "the openssl command line"


# ---------------------------------------------------------------- the front door as a subprocess, and in-process

class Front:
    def __init__(self, *args: str, wait_s: float = 10.0):
        self.lines: list[str] = []
        self.port = 0
        self.proc = subprocess.Popen([sys.executable, PROGRAM, *args], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True)
        self._ready = threading.Event()
        self._t = threading.Thread(target=self._read, daemon=True)
        self._t.start()
        if not self._ready.wait(wait_s) or not self.port:
            self.kill()
            raise RuntimeError("the front door did not start: " + " | ".join(self.lines)[-300:])
        ANSWERED.setdefault(self.port, 0)

    def _read(self):
        for line in self.proc.stderr:
            self.lines.append(line.rstrip("\n"))
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("event") == "listening":
                self.port = int(ev["port"])
                self._ready.set()
        self._ready.set()                      # the process ended: stop waiting

    def events(self, kind: str) -> list[dict]:
        out = []
        for line in self.lines:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict) and ev.get("event") == kind:
                out.append(ev)
        return out

    def stop(self, sig=signal.SIGTERM, wait_s: float = 8.0):
        """Send the signal; the exit code, or None when the process had to be killed."""
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
        try:
            rc = self.proc.wait(wait_s)
        except subprocess.TimeoutExpired:
            self.kill()
            return None
        self._t.join(3)
        return rc

    def kill(self):
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            pass


def run_cli(*args: str, timeout: float = 5.0):
    """Run the program to its end: (exit code or 'still running', stdout, stderr)."""
    try:
        r = subprocess.run([sys.executable, PROGRAM, *args], capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        return "still running", str(e.stdout or ""), str(e.stderr or "")


def load_program():
    """The program's module, loaded into this process (not run): for the rows that inject a fault."""
    spec = importlib.util.spec_from_file_location("tls_front_under_test", PROGRAM)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class InProcess:
    """The front door built by the program's own prepare() and served from a thread of this process."""
    def __init__(self, mod, argv: list[str], listener=None):
        self.front, real = mod.prepare(argv)
        if listener is not None:
            real.close()
        self.listener = listener or real
        self.port = 0 if listener is not None else real.getsockname()[1]
        self.thread = threading.Thread(target=self.front.serve, args=(self.listener,), daemon=True, name="test-serve")
        if self.port:
            ANSWERED.setdefault(self.port, 0)

    def start(self):
        self.thread.start()
        return self

    def close(self):
        self.front.stop.set()
        self.thread.join(3)
        try:
            self.listener.close()
        except OSError:
            pass

    def counts(self) -> dict:
        with self.front.lock:
            return dict(self.front.counts)


# ---------------------------------------------------------------- the TLS client and the app's requests

def client_ctx(ca_file: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)          # verifies the chain and the name; trusts ca_file only
    ctx.load_verify_locations(cafile=ca_file)
    return ctx


def tls_connect(port: int, ctx: ssl.SSLContext, source: str | None = IP_A, timeout: float = 8.0) -> ssl.SSLSocket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=timeout, source_address=(source, 0) if source else None)
    try:
        return ctx.wrap_socket(raw, server_hostname="127.0.0.1")
    except BaseException:
        raw.close()
        raise


def handshake_completes(port: int, ctx: ssl.SSLContext, source: str, timeout: float = 5.0):
    """(True, socket) when the TLS handshake completed; (False, the error) when it did not."""
    try:
        return True, tls_connect(port, ctx, source, timeout)
    except (ssl.SSLError, OSError) as e:
        return False, e


def read_response(sock, method: str = "GET"):
    r = http.client.HTTPResponse(sock, method=method)
    r.begin()
    body = r.read()
    return r.status, r.getheaders(), body, r


def note(port: int, status: int) -> None:
    ANSWERED[port] = ANSWERED.get(port, 0) + 1
    SEEN.setdefault(port, []).append(status)


def ajson(obj) -> bytes:
    """JSON as the app's org.json writes it: no spaces, '/' written as '\\/'."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).replace("/", "\\/").encode()


def app(method: str, path: str, ty: int = 0, body: bytes | None = None, *, origin: str | None = ORIG_A,
        ri: str | None = None, extra: list | None = None, close: bool = True, host: str | None = "127.0.0.1",
        rvi: str | None = "4", accept: str | None = "application/json", ctype: str | None = None) -> bytes:
    """A request as LiveService.http/httpBody (lines 493-536) sends it: X-M2M-Origin, X-M2M-RI, X-M2M-RVI 4, Accept,
    Content-Type with ty= when there is a body, plus what Android's HTTP stack adds (User-Agent, Host, Connection,
    Accept-Encoding, Content-Length). Host is the front door's address (127.0.0.1 here; Android adds the port when it
    is not 443). origin, rvi, accept or host None leaves that header out (ri None: a fresh one; ri False: none);
    ctype replaces the Content-Type the app would write; extra adds headers (repeats allowed)."""
    h = [] if origin is None else [("X-M2M-Origin", origin)]
    h += [] if ri is False else [("X-M2M-RI", ri if ri is not None else f"p{next(_RI)}")]
    h += [] if rvi is None else [("X-M2M-RVI", rvi)]
    h += [] if accept is None else [("Accept", accept)]
    if body is not None:
        h.append(("Content-Type", ctype or (f"application/json;ty={ty}" if ty else "application/json")))
    h += [("User-Agent", "Dalvik/2.1.0 (Linux; U; Android 16; test)")] + ([] if host is None else [("Host", host)])
    h += [("Connection", "close" if close else "Keep-Alive"), ("Accept-Encoding", "gzip")]
    if body is not None:
        h.append(("Content-Length", str(len(body))))
    h += list(extra or [])
    return ((f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h) + "\r\n").encode("latin-1")
            + (body or b""))


def ae_body(rn: str = RN_A, **extra) -> bytes:
    d = {"rn": rn, "api": "Nprobe.phone", "rr": False, "srv": ["4"]}
    d.update(extra)
    return ajson({"m2m:ae": d})


def sub_body(nu) -> bytes:
    return ajson({"m2m:sub": {"rn": "cmdSub", "nu": nu, "enc": {"net": [3]}, "nct": 1}})


def cin_body(con: str) -> bytes:
    return ajson({"m2m:cin": {"cnf": "application/json:0", "con": con}})


def conversation(origin: str, rn: str, cse_url: str) -> tuple[list, list]:
    """The app's whole conversation with a fresh CSE, from LiveService: (the ensureAe + one tick part, the downlink
    part). Each step: (method, path, ty, body or None)."""
    p = f"/{BASE}/{rn}"
    main = [("POST", f"/{BASE}", 2, ('{"m2m:ae":{"rn":"' + rn + '","api":"Nprobe.phone","rr":false,"srv":["4"]}}').encode()),  # 334
            ("GET", p, 0, None),                                                                                     # 336
            ("PUT", p, 0, b'{"m2m:ae":{"rr":false}}')]                                                               # 337
    for c in ("imu", "env", "loc", "radio", "wlan", "cmd", "ack"):                                                   # 338
        main.append(("POST", p, 3, ('{"m2m:cnt":{"rn":"' + c + '","mni":2000}}').encode()))                          # 339
    main.append(("POST", p, 15, b'{"m2m:pch":{"rn":"pch"}}'))                                                        # 342
    main.append(("POST", p + "/cmd", 23, ('{"m2m:sub":{"rn":"cmdSub","nu":["' + origin
                                          + '"],"enc":{"net":[3]},"nct":1}}').encode()))                             # 343
    recs = {"imu": {"accel": {"n": 25, "mean": [0.01, 0.02, 9.81], "last": [0, 0, 9.81]}, "t": 1},
            "env": {"light": {"n": 0}, "battery_pct": 80, "t": 1},
            "loc": {"fused": {"lat": 48.1, "lon": 11.5, "acc_m": 12.0}, "t": 1},
            "radio": {"operator": "TEST", "plmn": "00101", "cells": [{"registered": True, "rsrp": -95}], "t": 1},
            "wlan": {"ssid": "\"test-ap\"", "rssi": -50, "neighbours": [], "t": 1}}
    for c, r in recs.items():                                                                                        # 295
        main.append(("POST", f"{p}/{c}", 4, cin_body(json.dumps(r, separators=(",", ":")))))                        # 443
    main.append(("POST", p + "/radioTs", 30, ajson({"m2m:tsi": {"dgt": "20261119T120000,123000", "snr": 0,
                                                                "con": '{"seq":0,"rsrp":-95}'}})))                  # 436
    down = [("GET", p + "/pch/pcu", 0, None),                                                                        # 359
            ("POST", p + "/pch/pcu", 0, ajson({"m2m:rsp": {"rsc": 2000, "rqi": "rq-test-1", "rvi": "4",
                                                           "to": cse_url}})),                                        # 364
            ("POST", p + "/ack", 4, cin_body('{"id":1,"cmd":"ping","phone_t":1,"ok":true,"battery_pct":80}'))]      # 388
    return main, down


def client_hello(ctx: ssl.SSLContext) -> bytes:
    """The ClientHello this client would send first (made in memory, sent nowhere)."""
    out = ssl.MemoryBIO()
    obj = ctx.wrap_bio(ssl.MemoryBIO(), out, server_hostname="127.0.0.1")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def exchange(port: int, raw: bytes, ctx: ssl.SSLContext, source: str | None = IP_A, timeout: float = 8.0):
    """One connection, the given bytes, one response: (status, headers, body, closed-after). A connection that fails
    (closed before or in the handshake, or without an answer) gives (None, [], b"", None): a failed row where it is
    looked at, never an error that ends the section and loses its other rows."""
    try:
        s = tls_connect(port, ctx, source, timeout)
    except (ssl.SSLError, OSError):
        return None, [], b"", None
    try:
        try:
            s.sendall(raw)
        except OSError:
            pass                                # the server may have answered and closed before we finished sending
        try:
            status, headers, body, _ = read_response(s, raw.split(b" ", 1)[0].decode("latin-1"))
        except (ssl.SSLError, OSError, http.client.HTTPException):
            return None, [], b"", None
        note(port, status)
        s.settimeout(3)
        try:
            closed = s.recv(1) == b""
        except (ssl.SSLError, OSError) as e:
            closed = not isinstance(e, TimeoutError)
        return status, headers, body, closed
    finally:
        s.close()


def replay(port: int, ctx: ssl.SSLContext, steps: list, origin: str, source: str, tag: str):
    """The steps on one kept-open connection, as the app's connection pool sends them: [(status, body)]; a step not
    answered is (None, b"")."""
    done, s = handshake_completes(port, ctx, source)
    if not done:
        return [(None, b"")] * len(steps)
    out = []
    try:
        for i, (m, path, ty, body) in enumerate(steps):
            try:
                s.sendall(app(m, path, ty, body, origin=origin, ri=f"{tag}-{i}", close=False))
                st, _, rbody, _ = read_response(s, m)
            except (ssl.SSLError, OSError, http.client.HTTPException):
                break
            note(port, st)
            out.append((st, rbody))
    finally:
        s.close()
    return out + [(None, b"")] * (len(steps) - len(out))


def expected_seen(steps: list, origin: str, tag: str) -> list:
    return [(m, path, body or b"", origin, f"{tag}-{i}", "4", "application/json",
             (f"application/json;ty={ty}" if ty else "application/json") if body is not None else None)
            for i, (m, path, ty, body) in enumerate(steps)]


def as_seen(entries: list[dict]) -> list:
    return [(e["method"], e["target"], e["body"], e["headers"].get("x-m2m-origin"), e["headers"].get("x-m2m-ri"),
             e["headers"].get("x-m2m-rvi"), e["headers"].get("accept"), e["headers"].get("content-type"))
            for e in entries]


def hget(headers, name: str):
    return [v for k, v in headers if k.lower() == name.lower()]


def status_of(blob: bytes):
    try:
        return int(blob.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


def reason_of(body: bytes) -> str:
    """The reason the program gives in its own refusal ({"error": ...}); "" when the body is not that."""
    try:
        why = json.loads(body).get("error", "") if body.startswith(b"{") else ""
    except (ValueError, AttributeError):
        return ""
    return why if isinstance(why, str) else ""


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main() -> int:
    base = os.environ.get("TMPDIR") or tempfile.gettempdir()
    if str(Path(base).resolve()).startswith("/var"):
        print("TMPDIR is under /var; set TMPDIR to a folder with room")
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="tlsfront-test-", dir=base))
    os.chmod(tmp, 0o700)
    up_state, by_state = Upstream(), Upstream()
    up, bystander = serve(upstream_handler(up_state)), serve(upstream_handler(by_state))
    up_port, by_port = up.server_address[1], bystander.server_address[1]
    up_url, by_url = f"http://127.0.0.1:{up_port}", f"http://127.0.0.1:{by_port}"
    fronts: list[Front] = []
    inproc: list[InProcess] = []
    box: dict = {}
    cert, key, ca_file, log = str(tmp / "server.pem"), str(tmp / "server.key"), str(tmp / "ca.pem"), str(tmp / "a.log")

    def start(*args) -> Front:
        f = Front(*args)
        fronts.append(f)
        return f

    def std(*extra, upstream=up_url):
        return ["--listen", "127.0.0.1:0", "--upstream", upstream, "--cert", cert, "--key", key, *BINDS, *extra]

    def good(port, source=IP_A, timeout=8.0) -> bool:
        """The front door on `port` answers a plain good request (the app's GET of its own AE) now."""
        origin, rn = (ORIG_A, RN_A) if source == IP_A else (ORIG_B, RN_B)
        try:
            st, _, body, _ = exchange(port, app("GET", f"/{BASE}/{rn}", origin=origin, ri="alive"), box["ctx"],
                                      source, timeout)
            return st == 200 and json.loads(body)["target"] == f"/{BASE}/{rn}"
        except Exception:  # noqa: BLE001
            return False

    def refused(port, raw, want, source=IP_A, why=None):
        """Send `raw`; (status is `want`, nothing reached the upstream or the bystander, a good request still
        answered afterwards, and -- when `why` is given -- the refusal names that reason, so a check that a second
        check backs up is still seen to be there), and the detail."""
        n0, b0 = up_state.count(), by_state.count()
        try:
            st, _, body, _ = exchange(port, raw, box["ctx"], source)
            reason = json.loads(body).get("error", "") if body.startswith(b"{") else ""
        except Exception as e:  # noqa: BLE001
            st, reason = repr(e)[:80], ""
        seen = (up_state.count() - n0, by_state.count() - b0)
        ok = st == want and seen == (0, 0) and (why is None or why in reason) and good(port)
        return ok, f"status {st} ({reason[:70]}), upstream saw {seen[0]}, bystander {seen[1]}"

    try:
        def s_setup():
            dates, how = make_certs(tmp)
            box["dates"] = dates
            check("a throwaway certificate authority, server certificate and keys were made in the temporary folder",
                  all((tmp / n).is_file() for n in ("ca.pem", "server.pem", "server.key", "other.key")), how)
            for p in tmp.glob("*.key"):
                os.chmod(p, 0o600)
            box["ctx"] = client_ctx(ca_file)
            check("the program under test is there", Path(PROGRAM).is_file(), PROGRAM)
            box["a"] = start(*std("--log", log))
            check("the front door starts on a free loopback port and says so", box["a"].port > 0, f"port {box['a'].port}")
        section("set-up", s_setup)

        def s_app():
            a, ctx = box["a"].port, box["ctx"]
            done, s = handshake_completes(a, ctx, IP_A)
            ver = s.version() if done else repr(s)[:80]
            if done:
                s.close()
            check("a client that trusts the throwaway authority completes the handshake, in TLS 1.3",
                  ver == "TLSv1.3", str(ver))
            cse_url = f"https://127.0.0.1:{a}/{BASE}"
            main_steps, down_steps = conversation(ORIG_A, RN_A, cse_url)
            n0 = up_state.count()
            got_main = replay(a, ctx, main_steps, ORIG_A, IP_A, "app")
            got_down = replay(a, ctx, down_steps, ORIG_A, IP_A, "down")
            want_st = [201 if m == "POST" else 200 for m, *_ in main_steps + down_steps]
            check(f"the app's whole conversation ({len(want_st)} requests: AE, GET, PUT, 7 containers, pch, cmd "
                  "subscription, 5 records, radioTs, pcu GET and its answer, ack) is answered with the upstream's "
                  "own statuses", [st for st, _ in got_main + got_down] == want_st,
                  str([st for st, _ in got_main + got_down]))
            entries = up_state.since(n0)
            want = expected_seen(main_steps, ORIG_A, "app") + expected_seen(down_steps, ORIG_A, "down")
            seen_l = as_seen(entries)
            diffs = [(x, y) for x, y in itertools.zip_longest(seen_l, want) if x != y]
            check("the upstream saw exactly those requests, in order and unchanged: method, path, body byte for "
                  "byte, X-M2M-Origin, X-M2M-RI, X-M2M-RVI, Accept, Content-Type", seen_l == want and len(want) == 21,
                  f"{len(entries)} seen, {len(want)} sent" + (f"; first difference {diffs[0]}"[:300] if diffs else ""))
            extra_h = sorted({h for e in entries for h in e["headers"]} - FORWARDED)
            check("the upstream got only Host, X-M2M-Origin, X-M2M-RI, X-M2M-RVI, Accept, Content-Type and "
                  "Content-Length (User-Agent, Accept-Encoding, Connection were not passed on)",
                  bool(entries) and extra_h == [] and all(e["headers"].get("host") == "127.0.0.1" for e in entries),
                  f"other headers seen: {extra_h}")
            check("the long poll's answer came back as the upstream gave it ({} = nothing queued)",
                  got_down[0] == (200, b"{}"))
            # the second bound client, with its own originator and AE name
            n0 = up_state.count()
            two = [("POST", f"/{BASE}", 2, ae_body(RN_B)), ("POST", f"/{BASE}/{RN_B}/imu", 4, cin_body('{"t":2}'))]
            got = replay(a, ctx, two, ORIG_B, IP_B, "b")
            seen = as_seen(up_state.since(n0))
            check("the second bound address (127.0.0.2) gets through with its own originator and AE name",
                  [st for st, _ in got] == [201, 201] and seen == expected_seen(two, ORIG_B, "b"), str(got)[:200])
            # the same GET straight to the upstream and through the front door
            c = http.client.HTTPConnection("127.0.0.1", up_port, timeout=8)
            c.request("GET", f"/{BASE}/{RN_A}", headers={"X-M2M-Origin": ORIG_A, "X-M2M-RI": "ri-1"})
            r = c.getresponse()
            d_status, d_headers, d_body = r.status, r.getheaders(), r.read()
            c.close()
            st, hd, body, _ = exchange(a, app("GET", f"/{BASE}/{RN_A}", ri="ri-1"), ctx)
            check("GET: the status and the body are the upstream's own", (st, body) == (d_status, d_body) and st == 200,
                  f"{st} against {d_status}")
            check("GET: the X-M2M response headers come through (RSC, RI, RVI)",
                  (hget(hd, "X-M2M-RSC"), hget(hd, "X-M2M-RI"), hget(hd, "X-M2M-RVI")) == (["2000"], ["ri-1"], ["3"]),
                  str(hd))
            skip = {"date", "connection"}
            want_h = sorted((k.lower(), v) for k, v in d_headers if k.lower() not in skip)
            got_h = sorted((k.lower(), v) for k, v in hd if k.lower() not in skip)
            check("GET: the response headers are the upstream's, none added and none lost (Date and Connection aside)",
                  want_h == got_h, f"direct {want_h} | through {got_h}")
            n0 = up_state.count()
            payload = cin_body(json.dumps({"note": BODY_MARK + " é \u0001", "t": 3}))
            st, hd, body, _ = exchange(a, app("POST", f"/{BASE}/{RN_A}/wlan", 4, payload, ri=HEADER_MARK), ctx)
            seen = up_state.last()
            check("the set-up of the log rows holds: the marker strings did reach the upstream (RI and body)",
                  st == 201 and up_state.count() == n0 + 1 and seen["body"] == payload
                  and seen["headers"].get("x-m2m-ri") == HEADER_MARK, f"status {st}")
            st, hd, body, _ = exchange(a, app("GET", f"/{BASE}/{RN_A}", ri="missing-1"), ctx)
            check("an upstream 404 comes back as 404 with its body and its X-M2M-RSC",
                  (st, body, hget(hd, "X-M2M-RSC")) == (404, b'{"m2m:dbg":"resource not found"}', ["4004"]),
                  f"{st} {body[:60]!r}")
            st, hd, body, _ = exchange(a, app("GET", f"/{BASE}/{RN_A}", ri="nobody-1"), ctx)
            check("an upstream 204 comes back as 204 without a body", (st, body, hget(hd, "X-M2M-RSC")) == (204, b"", ["2004"]),
                  f"{st}")
            st, _, body, _ = exchange(a, app("GET", f"/{BASE}/{RN_A}", ri="large-1"), ctx, timeout=20)
            check("a 1 MiB answer comes back byte for byte (under the default --max-response of 4 MiB)",
                  st == 200 and hashlib.sha256(body).digest() == hashlib.sha256(LARGE).digest(), f"{len(body)} bytes")
            # text that ACME's comment remover would take for a comment, but inside strings, where it leaves it alone
            n0 = up_state.count()
            wlan = {"ssid": "\"Cafe #1 ;; //net /* x */\"", "rssi": -50, "neighbours": [{"ssid": "a#b"}], "t": 4}
            payload = cin_body(json.dumps(wlan, separators=(",", ":")))
            st, _, _, _ = exchange(a, app("POST", f"/{BASE}/{RN_A}/wlan", 4, payload), ctx)
            check("a record whose strings hold #, ;;, // and /* */ (a Wi-Fi name, say) is forwarded byte for byte",
                  st == 201 and up_state.count() == n0 + 1 and up_state.last()["body"] == payload
                  and b"#" in payload and b"/*" in payload, f"status {st}")
            n0 = up_state.count()
            st, _, _, _ = exchange(a, app("GET", f"/{BASE}/{RN_A}", ri="r" * 64, host=f"127.0.0.1:{a}"), ctx)
            seen = up_state.last()["headers"] if up_state.count() == n0 + 1 else {}
            check("Host with the port (127.0.0.1:PORT, as Android and urllib write it) and an X-M2M-RI of exactly 64 "
                  "characters are forwarded unchanged", st == 200 and seen.get("host") == f"127.0.0.1:{a}"
                  and seen.get("x-m2m-ri") == "r" * 64, f"status {st}, upstream saw {seen.get('host')!r}")
            n0 = up_state.count()
            st, _, _, _ = exchange(a, app("POST", f"/{BASE}/{RN_A}/imu", 4, cin_body('{"t":5}'),
                                          ctype="Application/JSON; ty=4"), ctx)
            seen = up_state.last()["headers"] if up_state.count() == n0 + 1 else {}
            check("a Content-Type written another way (Application/JSON; ty=4) is accepted and the upstream gets the "
                  "door's own application/json;ty=4, never the client's text",
                  st == 201 and seen.get("content-type") == "application/json;ty=4", f"status {st}, upstream saw "
                  f"{seen.get('content-type')!r}")
        section("the app's own requests come through unchanged", s_app)

        def s_sim():
            ctx = box["ctx"]
            s = start(*std())
            spec = importlib.util.spec_from_file_location("sim_phone_for_test", str(HERE / "sim_phone.py"))
            sim = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(sim)
            urllib.request.install_opener(urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx)))
            n0 = up_state.count()
            try:
                p = sim.SimPhone(f"https://127.0.0.1:{s.port}/{BASE}", ORIG_A, RN_A, period=30.0)
                p.live()
                end = time.monotonic() + 10
                while time.monotonic() < end and p.seq < 1:
                    time.sleep(0.05)
                time.sleep(0.6)                        # let the downlink poller make a long poll or two
                seq = p.seq                            # stop() sets the counter back to 0, as the app's restart does
                p.stop()
            finally:
                urllib.request.install_opener(None)
            rc = s.stop()
            ev = s.events("stopped")
            n_up = up_state.count() - n0
            paths = sorted({(e["method"], e["target"]) for e in up_state.since(n0)})
            check("sim_phone.SimPhone (which imitates the app) registers, posts one tick and long-polls through a "
                  "front door with nothing refused",
                  seq == 1 and p.post_ok == 5 and p.post_fail == 0 and p.ts_ok == 1 and p.ts_fail == 0
                  and rc == 0 and len(ev) == 1 and ev[0].get("requests") == n_up and n_up >= 17
                  and ("GET", f"/{BASE}/{RN_A}/pch/pcu") in paths,
                  f"seq {seq}, posts {p.post_ok}/{p.post_fail}, ts {p.ts_ok}/{p.ts_fail}, front answered "
                  f"{ev[0].get('requests') if ev else '?'}, upstream saw {n_up}")
        section("the simulated phone through a front door", s_sim)

        def s_pinning():
            a = box["a"].port
            p = f"/{BASE}/{RN_A}"
            rows = [
                ("a request with X-M2M-Origin: CAdmin (the CSE's admin) reached the upstream",
                 app("GET", p, origin="CAdmin"), 403),
                ("a request from 127.0.0.1 with the other bound client's originator reached the upstream",
                 app("GET", p, origin=ORIG_B), 403),
                ("a request with two X-M2M-Origin headers reached the upstream",
                 app("GET", p, extra=[("X-M2M-Origin", ORIG_A)]), 403),
                ("a request with no X-M2M-Origin header reached the upstream", app("GET", p, origin=None), 403),
                ("the SP-relative path /~/id-in/cse-in (another CSE) reached the upstream",
                 app("GET", "/~/id-in/cse-in"), 400),
                ("the path //x reached the upstream", app("GET", "//x"), 400),
                ("the absolute path /_/x (another service provider) reached the upstream", app("GET", "/_/x"), 400),
                ("the CSE's web UI /webui reached the upstream", app("GET", "/webui"), 403),
                (f"a path under another base with the bound AE name (/cse-in/{RN_A}) reached the upstream",
                 app("GET", f"/cse-in/{RN_A}"), 403),
                (f"the path /{BASE}/../x reached the upstream", app("GET", f"/{BASE}/../x"), 400),
                (f"the path {p}%2f.. reached the upstream", app("GET", p + "%2f.."), 400),
                (f"a path under another AE (/{BASE}/{RN_B}) reached the upstream", app("GET", f"/{BASE}/{RN_B}"), 403),
                ("a query string reached the upstream", app("GET", f"{p}?rcn=4&x={QUERY_MARK}"), 400),
                ("a DELETE reached the upstream (refused as a DELETE)", app("DELETE", p), 403, "DELETE"),
                (f"an ACP create (ty=1) under /{BASE} reached the upstream",
                 app("POST", f"/{BASE}", 1, ajson({"m2m:acp": {"rn": "acpX", "pv": {"acr": [{"acor": [ORIG_A], "acop": 63}]},
                                                               "pvs": {"acr": [{"acor": [ORIG_A], "acop": 63}]}}})), 403),
                ("the app's own AE body sent with ty=1 instead of ty=2 reached the upstream",
                 app("POST", f"/{BASE}", 1, ae_body()), 403),
                ("an AE create naming another AE (rn probeB) reached the upstream",
                 app("POST", f"/{BASE}", 2, ae_body(RN_B)), 403),
                ("an AE create carrying poa (an address for the CSE to contact) reached the upstream (refused as poa)",
                 app("POST", f"/{BASE}", 2, ae_body(poa=[f"{by_url}/x"])), 403, "poa or nu"),
                ("an AE create carrying at (announce to another CSE) reached the upstream",
                 app("POST", f"/{BASE}", 2, ae_body(at=["/id-in"])), 403),
                ("an AE create with the rn key twice (rn phone, then rn probeB) reached the upstream",
                 app("POST", f"/{BASE}", 2, b'{"m2m:ae":{"rn":"phone","api":"Nprobe.phone","rr":false,'
                                            b'"srv":["4"],"rn":"probeB"}}'), 400),
                ("a container create carrying nu reached the upstream (refused as nu)",
                 app("POST", p, 3, ajson({"m2m:cnt": {"rn": "imu", "mni": 2000, "nu": [f"{by_url}/x"]}})), 403,
                 "poa or nu"),
                ("a contentInstance into the cmd container (the app never writes its own commands) reached the upstream",
                 app("POST", f"{p}/cmd", 4, cin_body('{"cmd":"ping"}')), 403),
                ("a header name with '_' (X_M2M_Origin: CAdmin beside the right X-M2M-Origin) reached the upstream",
                 app("GET", p, extra=[("X_M2M_Origin", "CAdmin")]), 400),
                ("a request with two Host headers reached the upstream (refused as a header syntax fault)",
                 app("GET", p, extra=[("Host", "other.test")]), 400, "more than one Host"),
                ("a header value holding \\x0b reached the upstream", app("GET", p, ri="a\x0bb"), 400),
                ("a POST whose body is not JSON reached the upstream", app("POST", f"{p}/imu", 4, b"not json"), 400),
            ]
            for name, raw, want, *why in rows:
                control(name, *refused(a, raw, want, why=why[0] if why else None))
            outs = []
            for nu in ([f"{by_url}/x"], [ORIG_A, f"{by_url}/x"], [ORIG_B], ORIG_A, [], [ORIG_A, ORIG_A]):
                ok, detail = refused(a, app("POST", f"{p}/cmd", 23, sub_body(nu)), 403)
                outs.append((ok, detail))
            control("a command subscription whose nu is anything but [its own originator] reached the upstream "
                    "(a URL, the originator plus a URL, the other client, a bare string, [], the originator twice)",
                    all(ok for ok, _ in outs), "; ".join(d for _, d in outs))

            def each(name, raws, want, why=None):
                """One control row over several requests: every one refused with `want` (and `why`)."""
                outs = [refused(a, raw, want, why=why) for raw in raws]
                control(name, all(ok for ok, _ in outs), "; ".join(d for _, d in outs))

            to = f"https://127.0.0.1:{a}/{BASE}"

            def rsp(**over):
                r = {"rsc": 2000, "rqi": "rq-1", "rvi": "4", "to": to}
                r.update(over)
                return app("POST", f"{p}/pch/pcu", 0, ajson({"m2m:rsp": r}))

            def tsi(**over):
                t = {"dgt": "20261119T120000,123000", "snr": 0, "con": '{"seq":0}'}
                t.update(over)
                return app("POST", f"{p}/radioTs", 30, ajson({"m2m:tsi": t}))
            # the body as ACME reads it: ACME removes what its regex takes for a comment before it parses JSON
            each("a body with /*x*/ between tokens reached the upstream",
                 [app("POST", f"{p}/imu", 4, b'{"m2m:cin":/*x*/{"cnf":"application\\/json:0","con":"a"}}')], 400)
            each("a body with # or // after a value reached the upstream",
                 [app("POST", f"{p}/imu", 4, b'{"m2m:cin":{"cnf":"application\\/json:0","con":"a"} #x\n}'),
                  app("POST", f"{p}/imu", 4, b'{"m2m:cin":{"cnf":"application\\/json:0","con":"a"} //x\n}')], 400)
            each("a body whose string value ends in a backslash with more JSON after it on the same line (rqi x\\, "
                 "then the to URL with plain '/': ACME would cut the rest of the line as a // comment) reached the "
                 "upstream (refused by the comparison with ACME's comment remover)",
                 [app("POST", f"{p}/pch/pcu", 0, b'{"m2m:rsp":{"rsc":2000,"rqi":"x\\\\","rvi":"4","to":"' + to.encode()
                      + b'"}}')], 400, "would change this body")
            # The same misreading on a body split over two lines. ACME's regex is compiled with re.MULTILINE, so its
            # '$' matches at the end of each line and the // comment it believes it sees runs only to the end of the
            # first line. Without re.MULTILINE the copy here would find no comment (nothing follows that line's end
            # but more JSON) and pass the body on. The last '"' follows 4, not a backslash, so the backslash guard
            # does not refuse it; only the comparison with the comment remover can.
            each("a pcu answer split over two lines (rqi x\\, then the to URL with plain '/' at the end of the first "
                 "line, then rsc and rvi on the second; ACME would cut the rest of the first line as a // comment) "
                 "reached the upstream (refused by the comparison with ACME's comment remover, read line by line)",
                 [app("POST", f"{p}/pch/pcu", 0, b'{"m2m:rsp":{"rqi":"x\\\\","to":"' + to.encode()
                      + b'",\n"rsc":2000,"rvi":"4"}}')], 400, "would change this body")
            each("a body whose last string ends in a backslash (ACME's comment remover misreads it: it would store "
                 "con a\\ for a/*b*/\\, and it scans such text in quadratic time) reached the upstream",
                 [app("POST", f"{p}/imu", 4, b'{"m2m:cin":{"cnf":"application\\/json:0","con":"a/*b*/\\\\"}}'),
                  app("POST", f"{p}/imu", 4, b'{"m2m:cin":{"cnf":"application\\/json:0","con":"abc\\\\"}}')], 400,
                 "backslash")
            big = b'{"m2m:cin":{"cnf":"application\\/json:0","con":"' + b'\\"' * 24000 + b'\\\\"}}'
            t = time.monotonic()
            ok, detail = refused(a, app("POST", f"{p}/imu", 4, big), 400, why="backslash")
            took = time.monotonic() - t
            control("a 48 kB body that would keep ACME's comment regex busy for seconds (24,000 escaped quotes, then a "
                    "last string ending in a backslash) held up the front door instead of being refused at once",
                    ok and took < 2.0, f"{detail}; {took:.2f} s")
            # the request headers the app sets, and Host
            each("an X-M2M-RVI other than 4 (3, none) reached the upstream",
                 [app("GET", p, rvi="3"), app("GET", p, rvi=None)], 400, "X-M2M-RVI")
            each("an Accept other than application/json (*/*, application/json with another type, none) reached the "
                 "upstream", [app("GET", p, accept="*/*"), app("GET", p, accept="application/json, */*"),
                              app("GET", p, accept=None)], 400, "Accept")
            each("an X-M2M-RI that is not 1 to 64 printable ASCII characters without spaces (65 characters, one with "
                 "a space, one with a byte above 0x7e, none) reached the upstream",
                 [app("GET", p, ri="r" * 65), app("GET", p, ri="a b"), app("GET", p, ri="a\xe9b"),
                  app("GET", p, ri=False)], 400, "X-M2M-RI")
            each("a Host that is not this front door's address (a name, another port, another address, none) reached "
                 "the upstream", [app("GET", p, host="edge.test"), app("GET", p, host="127.0.0.1:1"),
                                  app("GET", p, host="127.0.0.2"), app("GET", p, host=None)], 400, "Host")
            # the body shapes, value by value
            each("a container create with an rn outside the app's list (pch, evil, radioTs) reached the upstream",
                 [app("POST", p, 3, ajson({"m2m:cnt": {"rn": rn, "mni": 2000}})) for rn in ("pch", "evil", "radioTs")],
                 403)
            each("a container create with an mni other than the app's 2000 (1, 2001, 2000.0, \"2000\") reached the "
                 "upstream", [app("POST", p, 3, ajson({"m2m:cnt": {"rn": "imu", "mni": m}})) for m in (1, 2001, 2000.0, "2000")],
                 403)
            each("a timeSeriesInstance with an snr that is not a whole number >= 0 (-1, 1.5, \"3\", true) reached the "
                 "upstream", [tsi(snr=v) for v in (-1, 1.5, "3", True)], 403)
            each("a timeSeriesInstance with a dgt not in the app's format (ISO with dashes, no fraction, 5 digits of "
                 "fraction) reached the upstream",
                 [tsi(dgt=v) for v in ("2026-11-19T12:00:00", "20261119T120000", "20261119T120000,12345")], 403)
            each("a pcu answer whose to is an ID instead of the app's CSE URL (/id-in, CAdmin, Cother, /id-in/cse-mn-a) "
                 "reached the upstream", [rsp(to=v) for v in ("/id-in", "CAdmin", "Cother", f"/id-in/{BASE}")], 403)
            each("a pcu answer whose rqi is outside the allowed shape (a space, 257 characters, a non-ASCII letter, "
                 "empty) reached the upstream", [rsp(rqi=v) for v in ("a b", "x" * 257, "aéb", "")], 403)
            each("a GET with a body (Content-Length 5) reached the upstream",
                 [app("GET", p, extra=[("Content-Length", "5")]) + b"hello"], 400, "a body on a request")
        section("pinning: one address, one originator, one AE subtree, only the app's requests", s_pinning)

        def s_slow():
            a, ctx = box["a"].port, box["ctx"]
            got: dict = {}

            def slow():
                t = time.monotonic()
                try:
                    st, hd, body, _ = exchange(a, app("GET", f"/{BASE}/{RN_A}/pch/pcu", ri="slow-pcu"), ctx, timeout=15)
                    got.update(status=st, target=json.loads(body)["target"], ri=hget(hd, "X-M2M-RI"))
                except Exception as e:  # noqa: BLE001
                    got["error"] = repr(e)
                got["took"], got["end"] = time.monotonic() - t, time.monotonic()
            th = threading.Thread(target=slow)
            th.start()
            time.sleep(0.4)
            t = time.monotonic()
            fast_ok = good(a)
            fast_took, fast_end = time.monotonic() - t, time.monotonic()
            th.join(20)
            check("a 3 s upstream answer to the long poll comes through with its status, body and X-M2M-RI",
                  got.get("status") == 200 and got.get("target") == f"/{BASE}/{RN_A}/pch/pcu"
                  and got.get("ri") == ["slow-pcu"] and got.get("took", 0) >= SLOW_S - 0.1, str(got))
            check("a fast request made while the slow one waits is answered first, in under 1.5 s",
                  fast_ok and fast_took < 1.5 and fast_end < got.get("end", 0),
                  f"fast {fast_took:.2f} s, slow {got.get('took', 0):.2f} s")
        section("a slow answer does not hold up the others", s_slow)

        def s_tls():
            a = box["a"].port
            n0 = up_state.count()
            old = client_ctx(ca_file)
            old.maximum_version = ssl.TLSVersion.TLSv1_2
            err = None
            try:
                s = tls_connect(a, old)
                s.sendall(app("GET", f"/{BASE}/{RN_A}"))
                read_response(s)
                s.close()
            except (ssl.SSLError, OSError, http.client.HTTPException) as e:
                err = e
            control("a client that offers TLS 1.2 at most completed the handshake",
                    isinstance(err, (ssl.SSLError, ConnectionResetError))
                    and not isinstance(err, ssl.SSLCertVerificationError) and up_state.count() == n0 and good(a),
                    repr(err)[:120])
            n0 = up_state.count()
            raw = socket.create_connection(("127.0.0.1", a), timeout=5, source_address=(IP_A, 0))
            reply = b""
            try:
                raw.sendall(app("GET", f"/{BASE}/{RN_A}"))
                while True:
                    part = raw.recv(4096)
                    if not part:
                        break
                    reply += part
                ended = True
            except ConnectionResetError:
                ended = True
            except TimeoutError:
                ended = False
            finally:
                raw.close()
            time.sleep(0.2)
            seen = up_state.count() - n0
            control("a plain-HTTP request to the TLS port was forwarded or answered over HTTP",
                    ended and not reply.startswith(b"HTTP/") and seen == 0 and good(a),
                    f"connection ended {ended}, {len(reply)} bytes back, upstream saw {seen}")
        section("TLS: who gets in at all", s_tls)

        def s_not_bound():
            a, ctx = box["a"].port, box["ctx"]
            n0 = up_state.count()
            done, what = handshake_completes(a, ctx, IP_NOT_BOUND)
            if done:
                try:
                    what.sendall(app("GET", f"/{BASE}/{RN_A}"))
                    read_response(what)
                except (ssl.SSLError, OSError, http.client.HTTPException):
                    pass
                finally:
                    what.close()
            time.sleep(0.2)
            unseen = up_state.count() == n0
            from_bound = good(a, IP_A)
            control("a client address with no --bind (127.0.0.3) completed the TLS handshake or reached the upstream",
                    done is False and not isinstance(what, ssl.SSLCertVerificationError) and unseen and from_bound,
                    f"handshake completed {done} ({repr(what)[:80]}); upstream saw {0 if unseen else 'a request'}")
        section("an address that is not bound", s_not_bound)

        def s_limits():
            a, ctx = box["a"].port, box["ctx"]
            p = f"/{BASE}/{RN_A}"
            n0 = up_state.count()
            exact = cin_body("k" * (MAX_BODY - len(cin_body(""))))
            st, _, body, _ = exchange(a, app("POST", f"{p}/imu", 4, exact), ctx, timeout=20)
            check("a body of exactly --max-body bytes (262144) is forwarded", len(exact) == MAX_BODY and st == 201
                  and up_state.count() == n0 + 1 and len(up_state.last()["body"]) == MAX_BODY, f"status {st}")
            n0 = up_state.count()
            st, _, _, closed = exchange(a, app("POST", f"{p}/imu", 4, cin_body("k" * (MAX_BODY - len(cin_body("")) + 1))),
                                        ctx, timeout=20)
            seen = up_state.count() - n0
            control("a request body one byte over --max-body reached the upstream",
                    st == 413 and seen == 0 and good(a), f"status {st}, upstream saw {seen}")
            check("after the 413 the connection is closed", closed)
            n0 = up_state.count()
            st, _, _, closed = exchange(a, app("GET", p, extra=[("X-Big", "a" * 20000)]), ctx)
            control("a header block over 16 kB reached the upstream",
                    st in (431, 400) and closed and up_state.count() == n0 and good(a), f"status {st}, closed {closed}")
            n0 = up_state.count()
            st, _, _, closed = exchange(a, app("GET", p + "/" + "p" * 20000), ctx)
            control("a request line over 16 kB reached the upstream",
                    st in (431, 400, 414) and closed and up_state.count() == n0 and good(a), f"status {st}, closed {closed}")
            n0 = up_state.count()
            st, _, _, _ = exchange(a, app("GET", p, extra=[("X-Pad", "r" * 15000)]), ctx)
            check("a request of about 15 kB of line and headers (in a header that is not passed on) is still forwarded",
                  st == 200 and up_state.count() == n0 + 1, f"status {st}")
            # Request framing. Everything but the framing is the app's own (Host the front door's address, the oneM2M
            # headers, Content-Type, a record that would pass the body check), so no other check can refuse these, and
            # each row asks for the reason the program gives: a refusal for another reason is not this check seen.
            rec = cin_body('{"t":6}')
            n0 = up_state.count()
            chunked = (app("POST", f"{p}/imu", close=False,
                           extra=[("Content-Type", "application/json;ty=4"), ("Transfer-Encoding", "chunked")])
                       + f"{len(rec):x}\r\n".encode() + rec + b"\r\n0\r\n\r\n" + app("GET", p))
            st, _, body, closed = exchange(a, chunked, ctx)
            why, seen = reason_of(body), up_state.count() - n0
            control("a request with Transfer-Encoding: chunked (a good record in one chunk, a second request behind "
                    "it, all else the app's own) reached the upstream, or was refused for another reason",
                    st == 501 and "Transfer-Encoding" in why and closed and seen == 0 and good(a),
                    f"status {st} ({why[:60]}), closed {closed}, upstream saw {seen}")
            ctl = ("Content-Type", "application/json;ty=4")
            # two Content-Length values: the first is the record's length, the second the length with 5 spaces more,
            # and both readings give a body that passes the check, so taking either one would forward it
            control("a request with two Content-Length values (the record's length, and that plus the 5 spaces sent "
                    "after it) reached the upstream, or was refused for another reason",
                    *refused(a, app("POST", f"{p}/imu", 4, rec, extra=[("Content-Length", str(len(rec) + 5))]) + b" " * 5,
                             400, why="bad Content-Length"))
            control("a request whose Content-Length is not a plain number (+N for a good record of N bytes) reached the "
                    "upstream, or was refused for another reason",
                    *refused(a, app("POST", f"{p}/imu", extra=[ctl, ("Content-Length", f"+{len(rec)}")]) + rec, 400,
                             why="bad Content-Length"))
        section("size limits and request framing", s_limits)

        def s_proxy():
            a, ctx = box["a"].port, box["ctx"]
            n0, b0 = up_state.count(), by_state.count()
            st, _, _, closed = exchange(a, f"GET http://127.0.0.1:{by_port}/x HTTP/1.1\r\nHost: 127.0.0.1:{by_port}\r\n"
                                           f"X-M2M-Origin: {ORIG_A}\r\n\r\n".encode(), ctx)
            seen = (up_state.count() - n0, by_state.count() - b0)
            control("a request with an absolute-URI target was forwarded (to the upstream or to the server it names)",
                    st == 400 and closed and seen == (0, 0) and good(a),
                    f"status {st}, upstream saw {seen[0]}, bystander saw {seen[1]}")
            n0, b0 = up_state.count(), by_state.count()
            st, tail = None, b"(not reached)"
            done, s = handshake_completes(a, ctx, IP_A)
            if done:
                try:
                    s.sendall(f"CONNECT 127.0.0.1:{by_port} HTTP/1.1\r\nHost: 127.0.0.1:{by_port}\r\n\r\n".encode())
                    r = http.client.HTTPResponse(s, method="GET")
                    r.begin()
                    st = r.status
                    r.read()
                    note(a, st)
                    try:
                        s.sendall(b"GET /x HTTP/1.0\r\n\r\n")
                        s.settimeout(3)
                        tail = s.recv(4096)
                    except (ssl.SSLError, OSError) as e:
                        tail = b"" if not isinstance(e, TimeoutError) else b"(open)"
                except (ssl.SSLError, OSError, http.client.HTTPException):
                    pass
                finally:
                    s.close()
            control("a CONNECT opened a tunnel or reached a server",
                    st in (400, 405) and tail == b"" and up_state.count() == n0 and by_state.count() == b0 and good(a),
                    f"status {st}, after it {tail[:40]!r}, bystander {by_state.count() - b0}")
            n0 = up_state.count()
            st1 = exchange(a, b"GET echo/nopath HTTP/1.1\r\nHost: edge.test\r\n\r\n", ctx)[0]
            st2 = exchange(a, b"GET /echo/sp ace HTTP/1.1\r\nHost: edge.test\r\n\r\n", ctx)[0]
            st3 = exchange(a, b"GET /echo/ctl\x01 HTTP/1.1\r\nHost: edge.test\r\n\r\n", ctx)[0]
            control("a target that does not start with '/', or holds a space or a control byte, reached the upstream",
                    (st1, st2, st3) == (400, 400, 400) and up_state.count() == n0 and good(a), f"status {st1}, {st2}, {st3}")
            n0 = up_state.count()
            sts = [exchange(a, f"{m} /{BASE}/{RN_A} HTTP/1.1\r\nHost: edge.test\r\nX-M2M-Origin: {ORIG_A}\r\n"
                               "Content-Length: 0\r\n\r\n".encode(), ctx)[0]
                   for m in ("PATCH", "OPTIONS", "HEAD", "TRACE", "get")]
            control("a method other than GET, POST, PUT (DELETE aside, refused above) reached the upstream",
                    sts == [405] * 5 and up_state.count() == n0 and good(a), f"status {sts}")
            n0 = up_state.count()
            st = exchange(a, f"GET /{BASE}/{RN_A} HTTP/1.1\r\nHost: edge.test\r\nX-M2M-Origin: {ORIG_A}\r\nX-A: 1\r\n"
                             " folded: x\r\nBad Name: 1\r\n\r\n".encode(), ctx)[0]
            control("a request with a folded header line or a space in a header name reached the upstream",
                    st == 400 and up_state.count() == n0 and good(a), f"status {st}")
        section("it is not an open proxy", s_proxy)

        def s_resources():
            ctx = box["ctx"]
            # the upstream's answer is read with a cap
            m = start(*std("--max-response", "1000000"))
            n0 = up_state.count()
            st, _, body, _ = exchange(m.port, app("GET", f"/{BASE}/{RN_A}", ri="large-2"), ctx, timeout=20)
            control("an upstream answer over --max-response (1 MiB against 1,000,000 bytes) was passed back, whole or "
                    "in part", st == 502 and up_state.count() == n0 + 1 and len(body) < 1000 and LARGE[:64] not in body
                    and good(m.port), f"status {st}, {len(body)} bytes back")
            m.stop()
            m2 = start(*std("--max-response", str(len(LARGE))))
            st, _, body, _ = exchange(m2.port, app("GET", f"/{BASE}/{RN_A}", ri="large-3"), ctx, timeout=20)
            check("an answer of exactly --max-response bytes comes back whole", st == 200 and body == LARGE,
                  f"status {st}, {len(body)} bytes")
            m2.stop()
            # connection slots: 3 in all, 2 per bound address
            lim = start(*std("--max-conns", "3", "--max-conns-per-client", "2"))
            held, more = [], []
            try:
                for _ in range(2):                                     # handshake done, then nothing sent: stalled
                    done, s = handshake_completes(lim.port, ctx, IP_A, timeout=4)
                    if done:
                        held.append(s)
                time.sleep(0.2)
                third, what = handshake_completes(lim.port, ctx, IP_A, timeout=4)
                if third:
                    more.append(what)
                t = time.monotonic()
                b_ok = good(lim.port, IP_B, timeout=4)
                b_took = time.monotonic() - t
                control("a client holding its 2 connection slots with stalled connections locked out the other bound "
                        "client, or got a third connection", len(held) == 2 and third is False and b_ok and b_took < 2.0,
                        f"{len(held)} held; third connection from 127.0.0.1 completed {third}; 127.0.0.2 answered "
                        f"{b_ok} in {b_took:.2f} s")
                time.sleep(0.3)
                done, s = handshake_completes(lim.port, ctx, IP_B, timeout=4)   # the third and last slot in all
                if done:
                    held.append(s)
                time.sleep(0.2)
                fourth, what = handshake_completes(lim.port, ctx, IP_B, timeout=4)
                if fourth:
                    more.append(what)
                control("a connection beyond --max-conns (3 in all, each held) completed the TLS handshake",
                        len(held) == 3 and fourth is False,
                        f"{len(held)} held; fourth connection completed {fourth} ({repr(what)[:60]})")
            finally:
                for s in held + more:
                    s.close()
            time.sleep(0.4)
            check("after the stalled connections close, both clients are let in again (the slots were released)",
                  good(lim.port, IP_A) and good(lim.port, IP_B) and good(lim.port, IP_A))
            rc = lim.stop()
            ev = lim.events("stopped")
            check("the two connections refused for want of a slot are counted (refused_busy 2)",
                  rc == 0 and len(ev) == 1 and ev[0].get("refused_busy") == 2, f"exit {rc}, {ev}")
        section("resources: answer size and connection slots", s_resources)

        def s_injected():
            ctx = box["ctx"]
            mod = load_program()
            box["mod"] = mod
            argv = std()
            # (1) the body has an absolute deadline
            old_body_s = mod.BODY_S
            mod.BODY_S = 1.5
            ip = InProcess(mod, argv).start()
            inproc.append(ip)
            n0 = up_state.count()
            body = cin_body("x" * 300)
            raw = app("POST", f"/{BASE}/{RN_A}/imu", 4, body)
            head = raw[:len(raw) - len(body)]
            got, sent, t0 = b"", 0, time.monotonic()
            done, s = handshake_completes(ip.port, ctx, IP_A)
            try:
                if not done:
                    raise OSError(f"no handshake: {s!r}")
                s.sendall(head)
                while time.monotonic() - t0 < 1.5 + 1.0 and sent < len(body):
                    s.sendall(body[sent:sent + 1])
                    sent += 1
                    s.settimeout(0.1)                              # about 10 bytes a second
                    try:
                        part = s.recv(4096)
                    except TimeoutError:
                        continue
                    got += part
                    break
            except (ssl.SSLError, OSError) as e:
                got += f"({e!r})".encode()
            finally:
                took = time.monotonic() - t0
                if done:
                    s.close()
            mod.BODY_S = old_body_s
            control("a body sent one byte at a time went on past BODY_S (1.5 s here) instead of ending in 408 by "
                    "BODY_S + 1 s", status_of(got) == 408 and took <= 2.5 and up_state.count() == n0,
                    f"after {took:.2f} s and {sent} bytes: {got[:40]!r}")
            ip.close()
            # (1b) the answer has an absolute deadline too: a client that reads it slowly loses the connection and
            # its one slot by BODY_S + 1 s
            mod.BODY_S = 1.5
            ip = InProcess(mod, std("--max-conns-per-client", "1", "--max-response", str(16 << 20))).start()
            inproc.append(ip)
            got, slot, ended, s, at = 0, None, "(not reached)", None, 0.0
            raw = socket.socket()
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)          # a small window: the reader paces it
            raw.settimeout(5)
            t0 = time.monotonic()
            try:
                raw.bind((IP_A, 0))
                raw.connect(("127.0.0.1", ip.port))
                s = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
                t0 = time.monotonic()
                s.sendall(app("GET", f"/{BASE}/{RN_A}", ri="huge-slow"))
                while time.monotonic() - t0 < 1.5 + 1.0:                       # about 20 kB a second
                    s.settimeout(0.2)
                    try:
                        part = s.recv(1024)
                    except TimeoutError:
                        continue
                    if not part:
                        break
                    got += len(part)
                    time.sleep(0.05)
                at = time.monotonic() - t0
                slot = good(ip.port, IP_A, timeout=3)          # its only slot, asked for while it is still open
                s.settimeout(5)
                while True:                                    # now read fast: the answer must end short of 8 MiB
                    part = s.recv(65536)
                    if not part:
                        break
                    got += len(part)
                ended = "closed (end of stream)"
            except TimeoutError:
                ended = "still open (no data for 5 s)"
            except (ssl.SSLError, OSError) as e:
                ended = f"closed ({type(e).__name__})"
            finally:
                (s or raw).close()
                mod.BODY_S = old_body_s
            counts = ip.counts()
            control("a client that read an 8 MiB answer slowly (about 20 kB/s) kept its connection, or its one slot, "
                    "past BODY_S (1.5 s here) + 1 s",
                    slot is True and ended.startswith("closed") and 0 < got < len(HUGE),
                    f"slot free again at {at:.2f} s: {slot}; connection {ended}; {got} bytes of "
                    f"{len(HUGE)} read; counts {counts}")
            ip.close()
            # (1c) the TLS handshake has a deadline: a ClientHello sent one byte at a time is closed by HANDSHAKE_S + 1 s
            old_hs = mod.HANDSHAKE_S
            mod.HANDSHAKE_S = 1.5
            ip = InProcess(mod, std("--max-conns-per-client", "1")).start()
            inproc.append(ip)
            hello = client_hello(ctx)
            sent, closed_at, slot = 0, None, None
            raw = socket.create_connection(("127.0.0.1", ip.port), timeout=5, source_address=(IP_A, 0))
            t0 = time.monotonic()
            try:
                while time.monotonic() - t0 < 1.5 + 1.0 and sent < len(hello):
                    raw.sendall(hello[sent:sent + 1])
                    sent += 1
                    raw.settimeout(0.1)                        # about 10 bytes a second
                    try:
                        part = raw.recv(4096)
                    except TimeoutError:
                        continue
                    if not part:
                        closed_at = time.monotonic() - t0
                        break
                mod.HANDSHAKE_S = old_hs
                slot = good(ip.port, IP_A, timeout=3)          # its only slot, asked for while it may still be open
            except OSError:
                closed_at = time.monotonic() - t0              # reset, or a send after the close
            finally:
                mod.HANDSHAKE_S = old_hs
                raw.close()
            if slot is None:
                slot = good(ip.port, IP_A, timeout=3)
            counts = ip.counts()
            control("a TLS handshake whose ClientHello came one byte at a time went on past HANDSHAKE_S (1.5 s here) "
                    "+ 1 s, or kept its one slot",
                    closed_at is not None and closed_at <= 2.5 and sent < len(hello) and slot
                    and counts.get("handshake_failed") == 1,
                    f"closed at {closed_at if closed_at is None else round(closed_at, 2)} s after {sent} of {len(hello)} "
                    f"bytes; slot free again {slot}; counts {counts}")
            ip.close()
            # (2) a thread that cannot start does not stop the server, and its slots come back
            ip = InProcess(mod, std("--max-conns", "1", "--max-conns-per-client", "1"))
            inproc.append(ip)
            orig_start, left = threading.Thread.start, [1]

            def flaky(self, *a, **k):
                if threading.current_thread() is ip.thread and left[0] > 0:
                    left[0] -= 1
                    raise RuntimeError("can't start new thread (raised by the test)")
                return orig_start(self, *a, **k)
            ip.start()
            threading.Thread.start = flaky
            try:
                first, what = handshake_completes(ip.port, ctx, IP_A, timeout=3)
                if first:
                    what.close()
                time.sleep(0.2)
                second = good(ip.port, IP_A, timeout=3)
            finally:
                threading.Thread.start = orig_start
            counts = ip.counts()
            control("a failure to start a connection's thread stopped the front door or kept its slot",
                    left[0] == 0 and first is False and second and ip.thread.is_alive()
                    and counts.get("thread_start_failed") == 1,
                    f"injected {1 - left[0]}, first connection completed {first}, second answered {second}, serving "
                    f"{ip.thread.is_alive()}, counts {counts}")
            ip.close()
            # (3) an accept() that keeps failing does not spin

            class FailingListener:
                calls = 0

                def settimeout(self, t):
                    pass

                def accept(self):
                    FailingListener.calls += 1
                    raise OSError(errno.EMFILE, "Too many open files (raised by the test)")

                def close(self):
                    pass
            fl = FailingListener()
            ip = InProcess(mod, std(), listener=fl)
            inproc.append(ip)
            c0 = time.process_time()
            ip.start()
            time.sleep(1.0)
            cpu = time.process_time() - c0
            ip.close()
            calls = FailingListener.calls
            control("an accept() that fails every time made the loop spin (process CPU over 1 s)",
                    cpu < 0.3 and 3 <= calls <= 20 and not ip.thread.is_alive(),
                    f"{cpu:.3f} s of CPU, {calls} accept calls, loop ended {not ip.thread.is_alive()}")
        section("injected faults: slow body, slow reader, slow handshake, thread start, accept errors", s_injected)

        def s_head_and_idle():
            ctx = box["ctx"]
            mod = load_program()                       # a fresh copy: nothing in it patched yet
            p = f"/{BASE}/{RN_A}"

            def slot_free(port, within: float) -> bool:
                """A good request from 127.0.0.1 is answered within `within` seconds (tried every 0.1 s)."""
                end = time.monotonic() + within
                while not good(port, IP_A, timeout=2):
                    if time.monotonic() >= end:
                        return False
                    time.sleep(0.1)
                return True
            # (G8) the defaults, as numbers. The rows above and below patch the time limits smaller, so without this
            # row a default that is wrong or missing would not be seen.
            want = {"HANDSHAKE_S": 10.0, "HEAD_S": 20.0, "BODY_S": 30.0, "DRAIN_S": 2.0, "DRAIN_BYTES": 4 << 20,
                    "DRAIN_QUIET_S": 0.25, "ACCEPT_PAUSE_S": 0.1, "MAX_HEAD": 16384,
                    "--max-conns": 32, "--max-conns-per-client": 4, "--max-body": MAX_BODY, "--max-response": 4 << 20,
                    "--upstream-timeout": 30.0}
            _, cfg = mod.configure(std())
            got = {k: getattr(mod, k, "(missing)") for k in want if not k.startswith("--")}
            got.update({k: cfg.get(k[2:].replace("-", "_"), "(missing)") for k in want if k.startswith("--")})
            off = {k: v for k, v in got.items() if type(v) not in (int, float) or v != want[k]}
            check("the default limits are these numbers: HANDSHAKE_S 10 s, HEAD_S 20 s, BODY_S 30 s, DRAIN_S 2 s, "
                  "DRAIN_BYTES 4 MiB, DRAIN_QUIET_S 0.25 s, ACCEPT_PAUSE_S 0.1 s, MAX_HEAD 16384; --max-conns 32, "
                  "--max-conns-per-client 4, --max-body 262144, --max-response 4 MiB, --upstream-timeout 30 s",
                  off == {}, f"not as written: {off}" if off else "")
            # (M05) the request line and headers have one deadline in all, not one per read: a head sent one byte at a
            # time, each byte inside the time a single read may wait, still ends in 408 by HEAD_S + 1 s
            old_head = mod.HEAD_S
            mod.HEAD_S = 1.5
            ip = InProcess(mod, std("--max-conns-per-client", "1")).start()
            inproc.append(ip)
            n0 = up_state.count()
            raw = app("GET", p, ri="head-by-byte")
            got_b, sent, t0, took = b"", 0, time.monotonic(), 0.0
            done, s = handshake_completes(ip.port, ctx, IP_A)
            try:
                if not done:
                    raise OSError(f"no handshake: {s!r}")
                t0 = time.monotonic()
                while time.monotonic() - t0 < 1.5 + 1.0 and sent < len(raw):
                    s.sendall(raw[sent:sent + 1])
                    sent += 1
                    s.settimeout(max(0.05, min(1.0, 1.5 + 1.0 - (time.monotonic() - t0))))   # a byte a second
                    try:
                        part = s.recv(4096)
                    except TimeoutError:
                        continue
                    got_b += part
                    break
            except (ssl.SSLError, OSError) as e:
                got_b += f"({e!r})".encode()
            finally:
                took = time.monotonic() - t0
                if done:
                    s.close()
                mod.HEAD_S = old_head
            seen = up_state.count() - n0                # before the slot is asked for: that request reaches it
            slot = slot_free(ip.port, 1.0)
            control("a request head sent one byte a second (each byte inside the 1.5 s a single read may wait) went on "
                    "past HEAD_S (1.5 s here) instead of ending in 408 by HEAD_S + 1 s, or kept its one slot",
                    status_of(got_b) == 408 and took <= 2.5 and seen == 0 and slot,
                    f"after {took:.2f} s and {sent} bytes: {got_b[:40]!r}; upstream saw {seen}; slot free again {slot}")
            ip.close()
            # (M09) the refusal's own write has a deadline. A refusal of some 300 bytes always fits in empty socket
            # buffers, so a real client that never reads cannot hold it up; the write is made to behave as it does when
            # the buffers are full: on this one connection, the front door's sendall waits for its socket's whole
            # timeout and then fails as Python's does ("The write operation timed out"). With no timeout it waits until
            # this row lets it go.
            old_body = mod.BODY_S
            mod.BODY_S = 1.0
            ip = InProcess(mod, std("--max-conns-per-client", "1")).start()
            inproc.append(ip)
            orig_sendall, stuck, release = ssl.SSLSocket.sendall, {"peer": None, "timeouts": []}, threading.Event()

            def never_read(self, data, flags=0):
                try:
                    peer = self.getpeername()[:2] if self.server_side else None
                except OSError:
                    peer = None
                if peer is None or peer != stuck["peer"]:
                    return orig_sendall(self, data, flags)
                t = self.gettimeout()
                stuck["timeouts"].append(t)
                release.wait(t)                        # None: until the row lets it go
                raise TimeoutError("The write operation timed out (a client that never reads; raised by the test)")
            n0 = up_state.count()
            freed, t0 = None, time.monotonic()
            done, s = handshake_completes(ip.port, ctx, IP_A)
            ssl.SSLSocket.sendall = never_read
            try:
                if done:
                    stuck["peer"] = s.getsockname()[:2]
                    s.sendall(app("GET", f"{p}?x=1"))      # refused (400: a query string); never read
                    t0 = time.monotonic()
                    while time.monotonic() - t0 < 1.0 + 1.0:
                        if good(ip.port, IP_A, timeout=2):
                            freed = time.monotonic() - t0
                            break
                        time.sleep(0.1)
            finally:
                release.set()
                ssl.SSLSocket.sendall = orig_sendall
                if done:
                    s.close()
                mod.BODY_S = old_body
            control("a refused request whose client never reads the refusal kept its connection and its one slot past "
                    "BODY_S (1.0 s here) + 1 s",
                    done and len(stuck["timeouts"]) == 1 and freed is not None and up_state.count() == n0 + 1,
                    f"handshake {done}; the refusal's write had the timeout {stuck['timeouts']}; slot free again after "
                    f"{freed if freed is None else round(freed, 2)} s; upstream saw {up_state.count() - n0} (the good "
                    f"request only)")
            ip.close()
            # (M10) an idle kept-open connection ends: after one answered request, a connection that sends nothing more
            # is closed by HEAD_S + 1 s and its one slot is free again (asked for while the client still holds it open)
            mod.HEAD_S = 1.5
            ip = InProcess(mod, std("--max-conns-per-client", "1")).start()
            inproc.append(ip)
            st, closed_at, slot, what = None, None, None, ""
            done, s = handshake_completes(ip.port, ctx, IP_A)
            try:
                if not done:
                    raise OSError(f"no handshake: {s!r}")
                s.sendall(app("GET", p, ri="then-idle", close=False))
                st = read_response(s)[0]
                t0 = time.monotonic()
                s.settimeout(1.5 + 1.0)
                try:
                    part = s.recv(1)
                    closed_at = time.monotonic() - t0 if part == b"" else None
                    what = "end of stream" if part == b"" else f"data {part!r}"
                except TimeoutError:
                    what = "still open"
                except (ssl.SSLError, OSError) as e:
                    closed_at, what = time.monotonic() - t0, type(e).__name__
                mod.HEAD_S = old_head
                slot = slot_free(ip.port, 0.5)
            except (ssl.SSLError, OSError, http.client.HTTPException) as e:
                what = repr(e)[:80]
            finally:
                mod.HEAD_S = old_head
                if done:
                    s.close()
            control("a kept-open connection left idle after one answered request stayed open past HEAD_S (1.5 s here) "
                    "+ 1 s, or kept its one slot",
                    st == 200 and closed_at is not None and closed_at <= 2.5 and slot is True,
                    f"status {st}; then {what} after {closed_at if closed_at is None else round(closed_at, 2)} s; slot "
                    f"free again {slot}")
            ip.close()
        section("injected faults: a slow head, a refusal never read, an idle connection; the default limits",
                s_head_and_idle)

        def s_upstream_faults():
            ctx = box["ctx"]
            dead_port = free_port()
            d = start(*std(upstream=f"http://127.0.0.1:{dead_port}"))
            st, _, _, _ = exchange(d.port, app("GET", f"/{BASE}/{RN_A}"), ctx)
            check("upstream down: 502", st == 502, f"status {st}")
            check("the front door for the dead upstream stops cleanly on SIGINT (exit 0)", d.stop(signal.SIGINT) == 0)
            c = start(*std("--upstream-timeout", "1"))
            n0 = up_state.count()
            t = time.monotonic()
            st, _, _, _ = exchange(c.port, app("GET", f"/{BASE}/{RN_A}", ri="slow-504"), ctx, timeout=10)
            took = time.monotonic() - t
            check("an upstream that does not answer within the time limit (1 s here, 30 s by default): 504",
                  st == 504 and 0.9 <= took < 2.5 and up_state.count() == n0 + 1, f"status {st} after {took:.2f} s")
            check("after the 504 the same front door still answers", good(c.port))
            st, rc, took = None, None, 0.0
            done, idle = handshake_completes(c.port, ctx, IP_A)
            try:
                if done:
                    idle.sendall(app("GET", f"/{BASE}/{RN_A}", close=False))
                    st = read_response(idle)[0]
            except (ssl.SSLError, OSError, http.client.HTTPException):
                pass
            t = time.monotonic()
            rc = c.stop()
            took = time.monotonic() - t
            if done:
                idle.close()
            check("a connection kept open and idle does not hold up the stop (exit 0 in under 1.5 s)",
                  st == 200 and rc == 0 and took < 1.5, f"status {st}, exit {rc} after {took:.2f} s")
            time.sleep(SLOW_S)                         # let the stand-in finish its sleep
        section("upstream down and upstream slow", s_upstream_faults)

        def s_log_and_stop():
            a = box["a"]
            n_up = up_state.count()
            rc = a.stop(signal.SIGTERM)
            ev = a.events("stopped")
            check("SIGTERM: the front door stops cleanly (exit 0) and reports its counts",
                  rc == 0 and len(ev) == 1 and ev[0].get("requests") == ANSWERED[a.port],
                  f"exit {rc}, {ev}, ours {ANSWERED[a.port]}")
            check("it counted the two refused handshakes (TLS 1.2, plain HTTP) and the one address not bound, and "
                  "nothing refused for want of a slot",
                  bool(ev) and ev[0].get("handshake_failed") == 2 and ev[0].get("refused_not_bound") == 1
                  and ev[0].get("refused_busy") == 0 and ev[0].get("thread_start_failed") == 0, str(ev))
            gone = False
            try:
                socket.create_connection(("127.0.0.1", a.port), timeout=3).close()
            except ConnectionRefusedError:
                gone = True
            check("after the stop nothing listens on its port", gone and up_state.count() == n_up)
            text = Path(log).read_text()
            lines = [json.loads(x) for x in text.splitlines()]
            check("the log holds one line per request answered", len(lines) == ANSWERED[a.port],
                  f"{len(lines)} lines, {ANSWERED[a.port]} requests")
            keys = {"time", "client", "method", "path", "status", "bytes", "ms"}
            check("every log line holds time, client, method, path, status, bytes, ms and nothing else",
                  bool(lines) and all(set(x) == keys for x in lines), str(lines[:1]))
            logged = collections.Counter(x["status"] for x in lines)
            check("the statuses in the log are the ones the clients saw, one for one (refusals included)",
                  logged == collections.Counter(SEEN.get(a.port, [])) and logged[403] >= 20 and logged[400] >= 15,
                  f"log {dict(sorted(logged.items()))}")
            post = [x for x in lines if x["method"] == "POST" and x["path"] == f"/{BASE}" and x["status"] == 201
                    and x["client"] == IP_A]
            check("the AE create's line: client 127.0.0.1, status 201, the bytes of the answer, a time taken",
                  len(post) == 1 and post[0]["bytes"] > 50 and isinstance(post[0]["ms"], (int, float))
                  and post[0]["ms"] >= 0, str(post))
            slow = [x for x in lines if x["path"] == f"/{BASE}/{RN_A}/pch/pcu" and x["ms"] >= 2900]
            check("the long poll's line shows about 3 s", len(slow) == 1 and slow[0]["ms"] < 6000, str(slow))
            found = [m for m in (HEADER_MARK, BODY_MARK, QUERY_MARK, "edge.test", "Nprobe") if m in text]
            control("a header value, a body text or a query string was written to the log", found == [] and len(lines) > 40,
                    f"found {found}")
            err = "\n".join(a.lines)
            found = [m for m in (HEADER_MARK, BODY_MARK, QUERY_MARK, "edge.test") if m in err]
            control("a header value, a body text or a query string was written to the program's standard error",
                    found == [] and '"listening"' in err, f"found {found}")
            check("the log file is readable by its owner only", (os.stat(log).st_mode & 0o077) == 0,
                  oct(os.stat(log).st_mode & 0o777))
        section("the log and the stop", s_log_and_stop)

        def s_cli():
            ok = ["--listen", "127.0.0.1:0", "--cert", cert, "--key", key, *BINDS]
            n0 = up_state.count()

            def refused_start(*args) -> tuple:
                rc, _, err = run_cli(*args)
                return rc == 2 and REFUSED in err and '"listening"' not in err, rc
            bad = {}
            for u in ("https://127.0.0.1:9", "http://192.0.2.1:80", "http://example.com:80", "http://localhost:80",
                      f"http://127.0.0.1:{up_port}/base", "http://user@127.0.0.1:80", "http://127.0.0.1", "ftp://127.0.0.1:21"):
                bad[u] = refused_start(*ok, "--upstream", u)
            control("a front door started with an --upstream that is https, not loopback, a name, or has a path",
                    all(v[0] for v in bad.values()), str({u: v[1] for u, v in bad.items()}))
            r4 = refused_start("--listen", "0.0.0.0:0", "--upstream", up_url, "--cert", cert, "--key", key, *BINDS)
            r6 = refused_start("--listen", "[::]:0", "--upstream", up_url, "--cert", cert, "--key", key, *BINDS)
            control("a front door started on 0.0.0.0 or :: without --allow-any-interface", r4[0] and r6[0],
                    f"exit {r4[1]}, {r6[1]}")
            rc, out, _ = run_cli("--listen", "0.0.0.0:0", "--allow-any-interface", "--upstream", up_url, "--cert", cert,
                                 "--key", key, *BINDS, "--self-check")
            check("with --allow-any-interface the same arguments are accepted (checked with --self-check)", rc == 0,
                  f"exit {rc}")
            common = ["--listen", "127.0.0.1:0", "--upstream", up_url, "--cert", cert, "--key", key]
            starts = [
                ("--bind 127.0.0.1=CAdmin:phone (the CSE's admin originator)",
                 [["--base", BASE, "--bind", f"{IP_A}=CAdmin:{RN_A}"]]),
                ("--bind 127.0.0.1=cadmin:phone (the admin originator in another case)",
                 [["--base", BASE, "--bind", f"{IP_A}=cadmin:{RN_A}"], ["--base", BASE, "--bind", f"{IP_A}=CADMIN:{RN_A}"]]),
                ("--bind with an originator that does not start with C (Sprobe, /id-x, probe)",
                 [["--base", BASE, "--bind", f"{IP_A}=Sprobe:{RN_A}"], ["--base", BASE, "--bind", f"{IP_A}=/id-x:{RN_A}"],
                  ["--base", BASE, "--bind", f"{IP_A}=probe:{RN_A}"]]),
                ("--bind with an originator holding a character outside [A-Za-z0-9_-] or longer than 64",
                 [["--base", BASE, "--bind", f"{IP_A}=Cprobe.x:{RN_A}"], ["--base", BASE, "--bind", f"{IP_A}=Cprobe/x:{RN_A}"],
                  ["--base", BASE, "--bind", f"{IP_A}=C{'a' * 64}:{RN_A}"]]),
                ("--bind with a bad AE name (ph/one, empty, 65 characters, ph.one)",
                 [["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:ph/one"], ["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:"],
                  ["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:{'a' * 65}"], ["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:ph.one"]]),
                ("the same address bound twice",
                 [["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:{RN_A}", "--bind", f"{IP_A}={ORIG_B}:{RN_B}"]]),
                ("two addresses bound to one originator",
                 [["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:{RN_A}", "--bind", f"{IP_B}={ORIG_A}:{RN_B}"]]),
                ("two addresses bound to one AE name",
                 [["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:{RN_A}", "--bind", f"{IP_B}={ORIG_B}:{RN_A}"]]),
                ("no --bind, or a --bind that is not IP=ORIGIN:RN",
                 [["--base", BASE], ["--base", BASE, "--bind", f"{ORIG_A}:{RN_A}"], ["--base", BASE, "--bind", f"phone.lan={ORIG_A}:{RN_A}"]]),
                ("no --base, or a bad one (cse/x, empty)",
                 [["--bind", f"{IP_A}={ORIG_A}:{RN_A}"], ["--base", "cse/x", "--bind", f"{IP_A}={ORIG_A}:{RN_A}"],
                  ["--base", "", "--bind", f"{IP_A}={ORIG_A}:{RN_A}"]]),
                ("--base _x (ACME reads a path _x/... as /x/..., another CSE)",
                 [["--base", "_x", "--bind", f"{IP_A}={ORIG_A}:{RN_A}"]]),
                ("--base=-x (a leading '-'; written with = so that it is the program, not argparse, that refuses)",
                 [["--base=-x", "--bind", f"{IP_A}={ORIG_A}:{RN_A}"]]),
                ("an AE name with a leading '_' or '-' (_p, -p)",
                 [["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:_p"], ["--base", BASE, "--bind", f"{IP_A}={ORIG_A}:-p"]]),
                ("--allow (the option --bind replaced)", [[*BINDS, "--allow", IP_A], ["--base", BASE, "--allow", IP_A]]),
                ("an option the program does not know", [[*BINDS, "--frobnicate"]]),
            ]
            for name, variants in starts:
                res = [refused_start(*common, *v) for v in variants]
                control(f"a front door started with {name}", all(r[0] for r in res), f"exit {[r[1] for r in res]}")
            # --self-check: reads and prints, never binds. First with the port held by this test, then with it free.
            occ = socket.socket()
            occ.bind(("127.0.0.1", 0))
            occ.listen(4)
            held_port = occ.getsockname()[1]
            rc, out, err = run_cli("--listen", f"127.0.0.1:{held_port}", "--upstream", up_url, "--cert", cert, "--key", key,
                                   *BINDS, "--self-check")
            d = box["dates"]
            check("--self-check prints the subject, the alternative names and the validity dates, and exits 0",
                  rc == 0 and SUBJECT in out and "DNS:localhost" in out and "IP:127.0.0.1" in out
                  and d["not_before"] in out and d["not_after"] in out, out.replace("\n", " | ")[:300])
            still = False
            try:
                probe = socket.create_connection(("127.0.0.1", held_port), timeout=2)
                conn, _ = occ.accept()
                still = True
                conn.close()
                probe.close()
            except OSError:
                pass
            occ.close()
            free = free_port()
            rc2, out2, err2 = run_cli("--listen", f"127.0.0.1:{free}", "--upstream", up_url, "--cert", cert, "--key", key,
                                      *BINDS, "--self-check")
            after = socket.socket()
            try:
                after.bind(("127.0.0.1", free))
                free_after = True
            except OSError:
                free_after = False
            finally:
                after.close()
            control("--self-check bound the listening port (it must only read the certificate and key)",
                    rc == 0 and SUBJECT in out and still and '"listening"' not in err + err2
                    and rc2 == 0 and SUBJECT in out2 and free_after,
                    f"with the port held by the test: exit {rc}, subject printed {SUBJECT in out}, the test's socket "
                    f"still served {still}; with it free: exit {rc2}, port free afterwards {free_after}")
            r = refused_start(*common, *BINDS[:4], "--key", str(tmp / "other.key"))
            r_sc = refused_start(*common, *BINDS[:4], "--key", str(tmp / "other.key"), "--self-check")
            control("the program started (or self-checked) with a key that does not belong to its certificate",
                    r[0] and r_sc[0], f"exit {r[1]}, {r_sc[1]}")
            r = refused_start("--listen", "127.0.0.1:0", "--upstream", up_url, "--cert", str(tmp / "nothing.pem"),
                              "--key", key, *BINDS)
            control("the program started with a certificate file that is not there", r[0], f"exit {r[1]}")
            check("none of these starts sent anything to the upstream", up_state.count() == n0)
        section("the command line", s_cli)
    finally:
        for f in fronts:
            f.kill()
        for ip in inproc:
            try:
                ip.close()
            except Exception:  # noqa: BLE001
                pass
        up.shutdown()
        bystander.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)

    left = [str(p) for p in Path(base).glob("tlsfront-test-*")]
    check("the throwaway keys are gone: the temporary folder and everything in it is deleted", not tmp.exists() and not left,
          f"left: {left}" if left else "")
    alive = [f.proc.pid for f in fronts if f.proc.poll() is None]
    check("no front door process is left running", alive == [], str(alive))

    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed; controls {CONTROLS}; skipped 0")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
