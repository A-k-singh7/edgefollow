#!/usr/bin/env python3
"""proto_bench.py -- the same oneM2M workload over ACME 2026.5.3's protocol bindings, measured at the socket.

Bindings: http, https, ws, wss (TS-0020, subprotocol oneM2M.json), mqtt (TS-0010, via a private mosquitto),
coap (TS-0008, our own stdlib client in coap_min.py). One transport class per binding behind one interface
(Transport.open / request / close + a notification queue).

ACME serves ONE http server (plain or TLS) and ONE ws server (ws or wss) per process, so the plain and the TLS
bindings run on two CSEs that differ only in the TLS flags (plus CSE-W for WSGI, CSE-C for the control):
    CSE-P  http 39110, ws 39111, coap 39112/udp, mqtt client -> mosquitto 39150     (all plain)
    CSE-T  https 39120, wss 39121                                                   (TLS, throwaway CA)
    CSE-W  http 39113 with [http.wsgi] enable=true (waitress, keep-alive)
    CSE-C  http 39130; ws 39131, coap 39132, mqtt configured but DISABLED           (control only)
Counting proxies (bytes per direction at the socket, L4 payload): 39140-39148, 39170-39173.
Notification receivers: 39160-39162.

Everything lives in /dev/shm/proto-acme (deleted at the end). Nothing here touches 8200-8202, 8085, 8101, 8300.
Run it with the Python of the venv that has acmecse, websockets and paho (the 2026-11-21 record used):
    $VENV/bin/python3 proto_bench.py --repeats 3 --rounds 4 --n-cin 40 --k-notify 12 > run.log 2>&1
Paths: PB_VENV (default: the running interpreter's prefix), PB_ACME (default $PB_VENV/bin/acmecse),
PB_OUT_DIR (default ~/estimed-run/proto-2026-11-21), PB_MOSQUITTO, PB_OPENSSL.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import dataclasses
import datetime as dt
import http.server
import json
import os
import platform
import queue
import random
import re
import secrets
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import coap_min as coap  # noqa: E402

# ------------------------------------------------------------------------------------------------ constants
VENV = Path(os.environ.get("PB_VENV", sys.prefix))
ACME = os.environ.get("PB_ACME", str(VENV / "bin" / "acmecse"))
MOSQUITTO = os.environ.get("PB_MOSQUITTO", "/usr/sbin/mosquitto")
OPENSSL = os.environ.get("PB_OPENSSL", "/usr/bin/openssl")
ROOT = Path("/dev/shm/proto-acme")
OUT_DIR = Path(os.environ.get("PB_OUT_DIR", str(Path.home() / "estimed-run" / "proto-2026-11-21")))
LAB_PORTS = (8200, 8201, 8202, 8085, 8101, 8300)          # never touched; asserted absent from our config
SP_ID = "//proto-bench.example"
RVI = "4"
CSZ = "oneM2M.json"
PORTS = dict(p_http=39110, p_ws=39111, p_coap=39112, w_http=39113, w_ws_off=39114, w_coap_off=39115,
             t_https=39120, t_wss=39121,
             c_http=39130, c_ws=39131, c_coap=39132,
             x_http=39140, x_ws=39141, x_https=39142, x_wss=39143, x_mqtt=39144, x_coap=39145,
             x_rcv_http=39146, x_rcv_https=39147, x_rcv_coap=39148,
             broker=39150, rcv_http=39160, rcv_https=39161, rcv_coap=39162,
             x_poll_http=39170, x_poll_https=39171, x_poll_coap=39172, x_http_w=39173)
UDP_KEYS = {"p_coap", "c_coap", "x_coap", "x_rcv_coap", "rcv_coap", "x_poll_coap", "w_coap_off"}
NOT_BOUND = {"c_ws", "c_coap", "w_ws_off", "w_coap_off"}       # configured on disabled bindings only
assert all(39100 <= p <= 39199 for p in PORTS.values()) and not set(PORTS.values()) & set(LAB_PORTS)
TLS_MIN_RECORD_OVERHEAD = 22          # TLS 1.3 AEAD record: 5 header + 1 inner type + 16 tag
CSE = {"P": dict(csi="id-proto-p", rn="proto-p"), "T": dict(csi="id-proto-t", rn="proto-t"),
       "C": dict(csi="id-proto-c", rn="proto-c"), "W": dict(csi="id-proto-w", rn="proto-w")}
HTTP_PORT = {"P": "p_http", "T": "t_https", "C": "c_http", "W": "w_http"}


def now() -> float:
    return time.perf_counter()


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def rqi() -> str:
    return "rq" + secrets.token_hex(6)


def jdump(o: Any) -> bytes:
    return json.dumps(o, separators=(",", ":")).encode()


# ------------------------------------------------------------------------------------------------ statistics
def percentile(sorted_vals: list[float], q: float) -> float:
    """Linear interpolation between closest ranks (numpy's default 'linear'); q in [0, 100]."""
    if not sorted_vals:
        raise ValueError("empty")
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = (len(sorted_vals) - 1) * q / 100.0
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def summarize(vals: list[float]) -> Optional[dict]:
    v = sorted(x for x in vals if x is not None)
    if not v:
        return None
    return dict(n=len(v), min=v[0], median=percentile(v, 50), p95=percentile(v, 95), p99=percentile(v, 99),
                max=v[-1], mean=sum(v) / len(v))


# ------------------------------------------------------------------------------------------------ wire sizes
def ws_frame_len(payload_len: int, masked: bool) -> int:
    """RFC 6455 5.2: 2-byte header, 16/64-bit extended length, 4-byte mask key on client->server frames."""
    ext = 0 if payload_len < 126 else (2 if payload_len < 65536 else 8)
    return 2 + ext + (4 if masked else 0) + payload_len


def mqtt_varint_len(n: int) -> int:
    k = 1
    while n >= 128:
        n //= 128
        k += 1
    return k


def mqtt_publish_len(topic: str, payload_len: int, qos: int = 0) -> int:
    """MQTT 3.1.1 PUBLISH: fixed header byte + remaining-length varint + 2-byte topic length + topic
    (+ 2-byte packet id if qos > 0) + payload."""
    rem = 2 + len(topic.encode()) + (2 if qos else 0) + payload_len
    return 1 + mqtt_varint_len(rem) + rem


def self_check(c2s_wire: Optional[int], s2c_wire: Optional[int], c2s_app: Optional[int], s2c_app: Optional[int],
               tls: bool, exact: bool) -> list[str]:
    """Bytes counted by the proxy vs bytes the client itself put into / took from the protocol layer.
    Plaintext + exact: must be equal per direction. TLS (or not exact): wire >= app (+ one record's overhead)."""
    problems = []
    for name, wire, app in (("c2s", c2s_wire, c2s_app), ("s2c", s2c_wire, s2c_app)):
        if wire is None or app is None:
            continue
        if tls:
            if app > 0 and wire < app + TLS_MIN_RECORD_OVERHEAD:
                problems.append(f"{name}: wire {wire} < app {app} + {TLS_MIN_RECORD_OVERHEAD}")
        elif exact:
            if wire != app:
                problems.append(f"{name}: wire {wire} != app {app}")
        elif wire < app:
            problems.append(f"{name}: wire {wire} < app {app}")
    return problems


# ------------------------------------------------------------------------------------------------ processes
def _child_setup() -> None:
    """In each child before exec: SIGINT default, PR_SET_PDEATHSIG SIGINT (pattern of the repo's TLS tests)."""
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    if ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGINT), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG)")


def proc_cmdline(pid: int) -> list[str]:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").decode(errors="replace").split("\0")
    except OSError:
        return []


def proc_cpu_s(pid: int) -> Optional[float]:
    try:
        f = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except (OSError, IndexError, ValueError):
        return None


def system_cpu_times() -> tuple[int, int]:
    f = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
    idle = f[3] + f[4]
    return sum(f), idle


class Child:
    """A child process we started; stopped by PID after its command line is checked."""

    def __init__(self, name: str, argv: list[str], cwd: Path, must_contain: str):
        self.name, self.argv, self.cwd, self.must_contain = name, argv, cwd, must_contain
        self.log = cwd / "stdout.log"
        with self.log.open("wb") as out:
            self.proc = subprocess.Popen(argv, cwd=cwd, env={}, stdin=subprocess.DEVNULL, stdout=out,
                                         stderr=subprocess.STDOUT, start_new_session=True,
                                         preexec_fn=_child_setup)
        self.pid = self.proc.pid
        self.t_start = now()

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self, timeout: float = 20) -> dict:
        if self.proc.poll() is not None:
            return dict(name=self.name, pid=self.pid, already_exited=self.proc.returncode)
        cmd = proc_cmdline(self.pid)
        if not (any(self.argv[0] == c for c in cmd[:2]) and any(self.must_contain in c for c in cmd)):
            raise RuntimeError(f"refusing to signal pid {self.pid}: cmdline {cmd!r} is not {self.name}")
        self.proc.send_signal(signal.SIGINT)
        try:
            rc = self.proc.wait(timeout)
            how = "SIGINT"
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = self.proc.wait(5)
            how = "SIGKILL after SIGINT timeout"
        return dict(name=self.name, pid=self.pid, cmdline_checked=" ".join(cmd)[:160], stopped=how, rc=rc)


def _proc_net_ports(table: str, state: Optional[str]) -> set[int]:
    out = set()
    for line in Path(table).read_text().splitlines()[1:]:
        f = line.split()
        if state is None or f[3] == state:
            out.add(int(f[1].split(":")[1], 16))
    return out


def listening_ports() -> dict[str, set[int]]:
    return dict(tcp=_proc_net_ports("/proc/net/tcp", "0A") | _proc_net_ports("/proc/net/tcp6", "0A"),
                udp=_proc_net_ports("/proc/net/udp", None) | _proc_net_ports("/proc/net/udp6", None))


def our_ports_in_use() -> list[str]:
    lp = listening_ports()
    busy = []
    for k, p in PORTS.items():
        if p in lp["udp" if k in UDP_KEYS else "tcp"]:
            busy.append(f"{k}:{p}")
    return busy


def ports_free_or_die() -> None:
    busy = our_ports_in_use()
    for k, p in PORTS.items():          # a bind test as well (definitive for 127.0.0.1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if k in UDP_KEYS else socket.SOCK_STREAM)
        if k not in UDP_KEYS:      # TIME_WAIT from an earlier run is not a listener
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", p))
        except OSError:
            busy.append(f"{k}:{p}(bind)")
        finally:
            s.close()
    busy = [b_ for b_ in busy if not b_.endswith("(bind)")] + \
        [b_ for b_ in busy if b_.endswith("(bind)") and "0A" in port_states(PORTS[b_.split(":")[0]], False)]
    if busy:
        raise SystemExit(f"ports in use, not starting: {busy}")


def port_states(port: int, udp: bool) -> list[str]:
    """States of every socket whose LOCAL port is `port` (any address): '0A' LISTEN, '06' TIME_WAIT, '01' EST..."""
    out = []
    for t in (("/proc/net/udp", "/proc/net/udp6") if udp else ("/proc/net/tcp", "/proc/net/tcp6")):
        for line in Path(t).read_text().splitlines()[1:]:
            f = line.split()
            if int(f[1].split(":")[1], 16) == port:
                out.append(f[3])
    return out


EPHEMERAL_NOTE = ("39100-39199 lies inside this host's ephemeral range (ip_local_port_range 32768-60999): other "
                  "processes' outgoing connections (e.g. lab clients to 8201/8202) can hold one of our port numbers as "
                  "a source port, and its client-side TIME_WAIT blocks bind() for ~60 s even with SO_REUSEADDR.")


def wait_ports_clear(keys: list[str], timeout: float = 150.0) -> dict:
    """Wait until none of the ports has any socket (another process's ephemeral source port, TIME_WAIT);
    a foreign LISTEN is fatal. Returns {key: seconds waited} for the ports that were not clear at once."""
    waited: dict[str, float] = {}
    t0 = now()
    for k in keys:
        udp = k in UDP_KEYS
        t1 = now()
        while True:
            st = port_states(PORTS[k], udp)
            if not udp and "0A" in st:
                raise SystemExit(f"foreign listener on {k}:{PORTS[k]}")
            if not st:
                break
            if now() - t0 > timeout:
                raise RuntimeError(f"port {k}:{PORTS[k]} still has sockets {st} after {timeout:.0f}s")
            time.sleep(0.5)
        if now() - t1 > 0.2:
            waited[k] = round(now() - t1, 2)
    return waited


def wait_for(pred: Callable[[], bool], timeout: float, step: float = 0.1) -> bool:
    deadline = now() + timeout
    while now() < deadline:
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(step)
    try:
        return bool(pred())
    except Exception:
        return False


def tcp_port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ------------------------------------------------------------------------------------------------ PKI
def _openssl(cwd: Path, *args: str) -> None:
    subprocess.run([OPENSSL, *args], cwd=cwd, env={}, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)


def make_ca(d: Path, name: str, cn: str) -> Path:
    (d / "ca.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n[ca_ext]\nbasicConstraints=critical,CA:TRUE\n"
                              "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
    _openssl(d, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", f"{name}.key", "-out", f"{name}.pem", "-days", "1", "-subj", f"/CN={cn}",
             "-config", "ca.cnf", "-extensions", "ca_ext")
    return d / f"{name}.pem"


def make_leaf(d: Path, ca: str, certs: Path) -> None:
    """Server certificate for 127.0.0.1 (IP SAN only), P-256, 1 day, signed by d/<ca>.pem."""
    (d / "leaf.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
                                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    certs.mkdir(parents=True, exist_ok=True)
    csr = d / f"{certs.parent.name}.csr"
    _openssl(d, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", str(certs / "acme_key.pem"), "-out", str(csr), "-subj", "/CN=127.0.0.1", "-config", "ca.cnf")
    _openssl(d, "x509", "-req", "-in", str(csr), "-CA", f"{ca}.pem", "-CAkey", f"{ca}.key", "-set_serial",
             "0x" + secrets.token_hex(16), "-days", "1", "-out", str(certs / "acme_cert.pem"), "-extfile", "leaf.cnf")


def client_ctx(cafile: Path) -> ssl.SSLContext:
    """Verifies the chain against cafile alone and checks the name (Python defaults)."""
    return ssl.create_default_context(cafile=str(cafile))


# ------------------------------------------------------------------------------------------------ configs
def render_ini(sections: dict) -> str:
    ini = "\n".join(f"[{name}]\n" + "".join(f"{k} = {v}\n" for k, v in kv.items()) for name, kv in sections.items())
    if re.search(r"(?mi)^\s*baseDirectory\s*[=:]", ini):
        raise ValueError("a private CSE's ini sets baseDirectory")
    for p in LAB_PORTS:
        if re.search(rf"\b{p}\b", ini):
            raise ValueError(f"lab port {p} in a private ini")
    return ini


def cse_sections(kind: str, secret: str) -> dict:
    c = CSE[kind]
    http_port = PORTS[HTTP_PORT[kind]]
    s: dict[str, dict] = {
        "basic.config": dict(cseType="IN", cseID=c["csi"], cseName=c["rn"], serviceProviderID=SP_ID,
                             adminID="CAdmin", networkInterface="127.0.0.1", cseHost="127.0.0.1",
                             databaseType="memory", httpPort=str(http_port), logLevel="warn",
                             consoleType="simple", secret=secret),
        "logging": dict(enableFileLogging="true", enableScreenLogging="false", stackTraceOnError="true"),
        "textui": dict(startWithTUI="false"),
        "webui": dict(enable="false"),        # its plugin adds Flask routes late in startup (startup race)
        "http": dict(enable="true", listenIF="127.0.0.1",
                     address=f"{'https' if kind == 'T' else 'http'}://127.0.0.1:{http_port}"),
        "http.security": dict(useTLS="false"),
        "websocket": dict(enable="true" if kind in "PT" else "false", listenIF="127.0.0.1",
                          port=str({"P": PORTS["p_ws"], "T": PORTS["t_wss"], "C": PORTS["c_ws"], "W": PORTS["w_ws_off"]}[kind]),
                          loglevel="warn"),
        "websocket.security": dict(useTLS="false"),
        "coap": dict(enable="true" if kind == "P" else "false", listenIF="127.0.0.1",
                     port=str({"P": PORTS["p_coap"], "T": PORTS["c_coap"], "C": PORTS["c_coap"], "W": PORTS["w_coap_off"]}[kind])),
        "mqtt": dict(enable="true" if kind == "P" else "false", address="127.0.0.1", port=str(PORTS["broker"]),
                     listenIF="127.0.0.1", keepalive="60"),
        "mqtt.security": dict(username="", password="", useTLS="false"),
    }
    s["websocket"]["address"] = (f"{'wss' if kind == 'T' else 'ws'}://127.0.0.1:{s['websocket']['port']}")
    s["coap"]["address"] = f"coap://127.0.0.1:{s['coap']['port']}"
    if kind == "W":     # same ACME, HTTP served by waitress (WSGI) instead of the werkzeug development server
        s["http.wsgi"] = dict(enable="true", threadPoolSize="100", connectionLimit="100")
    if kind == "T":
        tls = dict(useTLS="true", tlsVersion="auto", verifyCertificate="false",
                   caCertificateFile="${basic.config:baseDirectory}/certs/acme_cert.pem",
                   caPrivateKeyFile="${basic.config:baseDirectory}/certs/acme_key.pem")
        s["http.security"] = dict(tls)
        s["websocket.security"] = dict(tls)
    return s


def mosquitto_conf(logfile: Path) -> str:
    return (f"# private broker for proto_bench: one loopback listener, anonymous only there, no persistence\n"
            f"per_listener_settings true\n"
            f"listener {PORTS['broker']} 127.0.0.1\n"
            f"allow_anonymous true\n"
            f"persistence false\n"
            f"log_dest file {logfile}\n"
            f"log_type error\nlog_type warning\nlog_type notice\nlog_type information\n"
            f"connection_messages true\nlog_timestamp true\n")


# ------------------------------------------------------------------------------------------------ proxies
class _Counts:
    __slots__ = ("c2s", "s2c")

    def __init__(self):
        self.c2s = 0
        self.s2c = 0


class TcpProxy:
    """Counting TCP relay 127.0.0.1:listen -> 127.0.0.1:target. Counts each direction BEFORE forwarding, so a
    byte the far end has received is already counted. `fault` plants a counting defect for the self-check control."""

    def __init__(self, name: str, listen: int, target: int):
        self.name, self.listen, self.target = name, listen, target
        self.lock = threading.Lock()
        self.total = _Counts()
        self.conns: dict[int, _Counts] = {}          # client source port -> counts
        self.accepts = 0
        self.closes = 0
        self.fault: Optional[str] = None             # None | "skip_c2s" | "skip_s2c"
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", listen))
        self.listen = self.srv.getsockname()[1]          # listen=0 (tests): the kernel's choice
        self.srv.listen(64)
        self._stop = False
        self.thread = threading.Thread(target=self._accept_loop, name=f"proxy-{name}", daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while not self._stop:
            try:
                c, addr = self.srv.accept()
            except OSError:
                return
            try:
                u = socket.create_connection(("127.0.0.1", self.target), timeout=10)
                u.settimeout(None)
            except OSError:
                c.close()
                continue
            for s in (c, u):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            cnt = _Counts()
            with self.lock:
                self.accepts += 1
                self.conns[addr[1]] = cnt
            done = [0]
            for src, dst, d in ((c, u, "c2s"), (u, c, "s2c")):
                threading.Thread(target=self._pump, args=(src, dst, d, cnt, done, c, u), daemon=True).start()

    def _pump(self, src, dst, d, cnt, done, c, u):
        while True:
            try:
                data = src.recv(65536)
            except OSError:
                data = b""
            if not data:
                with contextlib.suppress(OSError):
                    dst.shutdown(socket.SHUT_WR)
                break
            with self.lock:
                if self.fault != f"skip_{d}":
                    setattr(self.total, d, getattr(self.total, d) + len(data))
                    setattr(cnt, d, getattr(cnt, d) + len(data))
            try:
                dst.sendall(data)
            except OSError:
                break
        with self.lock:
            done[0] += 1
            last = done[0] == 2
            if last:
                self.closes += 1
        if last:
            for s in (c, u):
                with contextlib.suppress(OSError):
                    s.close()

    def snap(self, port: Optional[int] = None) -> tuple[int, int, int, int]:
        with self.lock:
            c = self.total if port is None else self.conns.get(port, _Counts())
            return c.c2s, c.s2c, self.accepts, self.closes

    def settle(self, quiet: float = 0.02, max_wait: float = 1.0) -> None:
        last = self.snap()
        t_end = now() + max_wait
        t_quiet = now() + quiet
        while now() < t_end:
            time.sleep(0.004)
            cur = self.snap()
            if cur != last:
                last = cur
                t_quiet = now() + quiet
            elif now() >= t_quiet:
                return

    def close(self):
        self._stop = True
        with contextlib.suppress(OSError):
            self.srv.shutdown(socket.SHUT_RDWR)       # wakes the blocked accept(); close alone does not
        with contextlib.suppress(OSError):
            self.srv.close()
        self.thread.join(2)


class UdpProxy:
    """Counting UDP relay: per client address one upstream socket (NAT-like), counts per direction and per client."""

    def __init__(self, name: str, listen: int, target: int):
        self.name, self.listen, self.target = name, listen, target
        self.lock = threading.Lock()
        self.total = _Counts()
        self.conns: dict[int, _Counts] = {}
        self.accepts = 0
        self.closes = 0
        self.fault: Optional[str] = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", listen))
        self.listen = self.sock.getsockname()[1]
        self.up: dict[tuple, socket.socket] = {}
        self.back: dict[socket.socket, tuple] = {}
        self._stop = False
        self.thread = threading.Thread(target=self._loop, name=f"uproxy-{name}", daemon=True)
        self.thread.start()

    def _count(self, d: str, port: int, n: int):
        with self.lock:
            if self.fault != f"skip_{d}":
                setattr(self.total, d, getattr(self.total, d) + n)
                c = self.conns.setdefault(port, _Counts())
                setattr(c, d, getattr(c, d) + n)

    def _loop(self):
        while not self._stop:
            socks = [self.sock, *self.back.keys()]
            try:
                r, _, _ = select.select(socks, [], [], 0.2)
            except (OSError, ValueError):
                return
            for s in r:
                try:
                    if s is self.sock:
                        data, addr = s.recvfrom(65535)
                        if addr not in self.up:
                            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            u.connect(("127.0.0.1", self.target))
                            self.up[addr] = u
                            self.back[u] = addr
                            with self.lock:
                                self.accepts += 1
                        self._count("c2s", addr[1], len(data))
                        self.up[addr].send(data)
                    else:
                        data = s.recv(65535)
                        addr = self.back[s]
                        self._count("s2c", addr[1], len(data))
                        self.sock.sendto(data, addr)
                except OSError:
                    continue

    def snap(self, port: Optional[int] = None) -> tuple[int, int, int, int]:
        with self.lock:
            c = self.total if port is None else self.conns.get(port, _Counts())
            return c.c2s, c.s2c, self.accepts, self.closes

    settle = TcpProxy.settle

    def close(self):
        self._stop = True
        time.sleep(0.25)
        for s in [self.sock, *self.up.values()]:
            with contextlib.suppress(OSError):
                s.close()


# ------------------------------------------------------------------------------------------------ receivers
@dataclasses.dataclass
class Notif:
    t_recv: float
    rqi: Optional[str]
    pc: Any
    app_c2s: Optional[int] = None        # bytes client -> CSE for this notification (our reply), if known
    app_s2c: Optional[int] = None        # bytes CSE -> client (the notification), if known
    via: str = ""


def notif_marker(n: Notif) -> Optional[str]:
    try:
        return n.pc["m2m:sgn"]["nev"]["rep"]["m2m:cin"]["rn"]
    except (KeyError, TypeError):
        return None


class HttpReceiver:
    """Notification target for http(s) poa: answers 200 + X-M2M-RSC 2000."""

    def __init__(self, port: int, tls_cert: Optional[tuple[Path, Path]] = None):
        self.q: "queue.Queue[Notif]" = queue.Queue()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n) if n else b""
                t = now()
                ri = self.headers.get("X-M2M-RI")
                self.send_response(200)
                self.send_header("X-M2M-RSC", "2000")
                if ri:
                    self.send_header("X-M2M-RI", ri)
                self.send_header("Content-Length", "0")
                self.end_headers()
                try:
                    pc = json.loads(body) if body else None
                except ValueError:
                    pc = None
                outer.q.put(Notif(t, ri, pc, via="http-receiver"))

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        self.srv.daemon_threads = True
        if tls_cert:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(tls_cert[0]), str(tls_cert[1]))
            self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs=dict(poll_interval=0.2), daemon=True)
        self.thread.start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class CoapReceiver:
    """Notification target for a coap:// poa: ACKs with 2.04 + oneM2M-RSC 2000 (piggybacked); Block1 aware."""

    def __init__(self, port: int):
        self.q: "queue.Queue[Notif]" = queue.Queue()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.raw: list[str] = []
        self._stop = False
        self._blocks: dict[bytes, bytearray] = {}
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            t = now()
            try:
                m = coap.decode(data)
            except coap.CoAPFormatError:
                continue
            if len(self.raw) < 20:
                self.raw.append(coap.describe(m))
            if not 1 <= m.code <= 31:
                continue
            reply = coap.Message(mtype=coap.ACK if m.mtype == coap.CON else coap.NON, code=coap.CHANGED,
                                 mid=m.mid if m.mtype == coap.CON else random.randrange(65536), token=m.token)
            b1 = m.get_uint(coap.BLOCK1)
            payload = m.payload
            if b1 is not None:
                num, more, size = coap.block_parse(b1)
                buf = self._blocks.setdefault(m.token, bytearray())
                buf += m.payload
                if more:
                    reply.code = coap.CONTINUE
                    reply.add(coap.BLOCK1, b1)
                    self.sock.sendto(coap.encode(reply), addr)
                    continue
                payload = bytes(self._blocks.pop(m.token, b""))
                reply.add(coap.BLOCK1, b1)
            ri = m.get_str(coap.OM2M_RQI)
            reply.add(coap.OM2M_RSC, 2000)
            if ri:
                reply.add(coap.OM2M_RQI, ri)
            raw_reply = coap.encode(reply)
            self.sock.sendto(raw_reply, addr)
            try:
                pc = json.loads(payload) if payload else None
            except ValueError:
                pc = None
            self.q.put(Notif(t, ri, pc, app_c2s=len(raw_reply), app_s2c=len(data), via="coap-receiver"))

    def close(self):
        self._stop = True
        time.sleep(0.3)
        self.sock.close()


# ------------------------------------------------------------------------------------------------ transports
@dataclasses.dataclass
class Resp:
    rsc: Optional[int]
    pc: Any
    status: str = ""
    app_c2s: Optional[int] = None
    app_s2c: Optional[int] = None
    conns: int = 0
    setup: Optional[dict] = None
    t_resp: float = 0.0
    extra: dict = dataclasses.field(default_factory=dict)


class Transport:
    """One protocol binding. Subclasses implement open/close/request; `notif_q` carries in-band pushes."""
    proto = "?"
    tls = False
    exact_bytes = True                    # proxy bytes must equal app bytes (plaintext, reuse mode)

    def __init__(self, cse: dict, mode: str = "reuse"):
        self.cse, self.mode = cse, mode
        self.notif_q: "queue.Queue[Notif]" = queue.Queue()

    def open(self) -> Optional[dict]:
        return None

    def close(self) -> None:
        pass

    def request(self, prim: dict, timeout: float = 15.0) -> Resp:
        raise NotImplementedError

    def prepare(self, prim: dict) -> None:
        """Called before an op's byte window opens (e.g. MQTT subscribes a new response topic here)."""

    def local_port(self) -> Optional[int]:
        return None

    def ae_poa(self, proxied: bool) -> list[str]:
        return []


# -- HTTP / HTTPS ---------------------------------------------------------------------------------------
class HttpConn:
    """Our own HTTP/1.1 client over a socket: exact bytes out/in, TCP and TLS timed separately."""

    def __init__(self, host: str, port: int, ctx: Optional[ssl.SSLContext]):
        self.host, self.port, self.ctx = host, port, ctx
        self.sock: Optional[socket.socket] = None
        self.buf = bytearray()
        self.closed_by_server = False
        self._t_first, self._t_last, self._max_gap, self._chunks = None, None, 0.0, 0
        self.t_sent = 0.0

    def connect(self, timeout: float = 15.0) -> dict:
        t0 = now()
        s = socket.create_connection((self.host, self.port), timeout=timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        t1 = now()
        setup = dict(tcp_s=t1 - t0)
        if self.ctx is not None:
            ss = self.ctx.wrap_socket(s, server_hostname=self.host, do_handshake_on_connect=False)
            ss.do_handshake()
            setup.update(tls_s=now() - t1, tls_version=ss.version(), cipher=ss.cipher()[0])
            s = ss
        self.sock = s
        self.buf = bytearray()
        self.closed_by_server = False
        return setup

    def local_port(self) -> Optional[int]:
        try:
            return self.sock.getsockname()[1] if self.sock else None
        except OSError:
            return None

    def _fill(self) -> None:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("server closed the connection")
        t = now()
        if self._t_first is None:
            self._t_first = t
        elif self._t_last is not None:
            self._max_gap = max(self._max_gap, t - self._t_last)
        self._t_last = t
        self._chunks += 1
        self.buf += chunk

    def roundtrip(self, raw: bytes, timeout: float) -> tuple[int, dict, bytes, int, int]:
        self.sock.settimeout(timeout)
        self._t_first, self._t_last, self._max_gap, self._chunks = None, None, 0.0, 0
        self.t_sent = now()
        self.sock.sendall(raw)
        while (i := self.buf.find(b"\r\n\r\n")) < 0:
            self._fill()
        head = bytes(self.buf[:i]).decode("latin-1")
        consumed = i + 4
        lines = head.split("\r\n")
        status = int(lines[0].split()[1])
        hdrs: dict[str, str] = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        if "content-length" in hdrs:
            need = consumed + int(hdrs["content-length"])
            while len(self.buf) < need:
                self._fill()
            body = bytes(self.buf[consumed:need])
            consumed = need
        elif hdrs.get("transfer-encoding", "").lower() == "chunked":
            body = bytearray()
            while True:
                while (j := self.buf.find(b"\r\n", consumed)) < 0:
                    self._fill()
                size = int(bytes(self.buf[consumed:j]).split(b";")[0], 16)
                consumed = j + 2
                while len(self.buf) < consumed + size + 2:
                    self._fill()
                body += self.buf[consumed:consumed + size]
                consumed += size + 2
                if size == 0:
                    break
            body = bytes(body)
        else:
            with contextlib.suppress(ConnectionError):
                while True:
                    self._fill()
            body = bytes(self.buf[consumed:])
            consumed = len(self.buf)
        del self.buf[:consumed]
        if hdrs.get("connection", "").lower() == "close":
            self.closed_by_server = True
        return status, hdrs, body, len(raw), consumed

    def close(self):
        if self.sock is not None:
            with contextlib.suppress(OSError):
                self.sock.shutdown(socket.SHUT_RDWR)      # wakes a recv blocked in another thread
            with contextlib.suppress(OSError):
                self.sock.close()
            self.sock = None


HTTP_METHOD = {1: "POST", 2: "GET", 3: "PUT", 4: "DELETE", 5: "POST"}


def fc_query(fc: Optional[dict]) -> list[tuple[str, str]]:
    q = []
    for k, v in (fc or {}).items():
        q.append((k, "+".join(map(str, v)) if isinstance(v, list) else str(v)))
    return q


def http_request_bytes(prim: dict, host: str, port: int) -> bytes:
    body = jdump(prim["pc"]) if prim.get("pc") is not None else b""
    q = fc_query(prim.get("fc"))
    target = "/" + prim["to"] + ("?" + "&".join(f"{k}={v}" for k, v in q) if q else "")
    hdrs = [("Host", f"{host}:{port}"), ("X-M2M-Origin", prim["fr"]), ("X-M2M-RI", prim["rqi"]),
            ("X-M2M-RVI", prim.get("rvi", RVI)), ("Accept", "application/json")]
    if prim.get("rqet"):
        hdrs.append(("X-M2M-RET", prim["rqet"]))
    if body or prim["op"] in (1, 3, 5):
        hdrs.append(("Content-Type", "application/json" + (f";ty={prim['ty']}" if prim.get("ty") else "")))
        hdrs.append(("Content-Length", str(len(body))))
    head = f"{HTTP_METHOD[prim['op']]} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs) + "\r\n"
    return head.encode("latin-1") + body


class HttpTransport(Transport):
    def __init__(self, cse: dict, port: int, ctx: Optional[ssl.SSLContext], mode: str, poa_ports: tuple[int, int]):
        super().__init__(cse, mode)
        self.proto = "https" if ctx else "http"
        self.tls = ctx is not None
        self.port, self.ctx = port, ctx
        self.poa_ports = poa_ports           # (direct receiver port, proxied receiver port)
        self.conn: Optional[HttpConn] = None
        self.lock = threading.Lock()
        self.closed = False
        self.server_closes = 0               # responses that carried 'Connection: close'

    def open(self):
        if self.mode == "fresh":
            return None
        self.conn = HttpConn("127.0.0.1", self.port, self.ctx)
        return self.conn.connect()

    def close(self):
        with self.lock:
            self.closed = True
            if self.conn:
                self.conn.close()
                self.conn = None

    def local_port(self):
        return self.conn.local_port() if self.conn else None

    def ae_poa(self, proxied: bool) -> list[str]:
        return [f"{self.proto}://127.0.0.1:{self.poa_ports[1] if proxied else self.poa_ports[0]}"]

    def request(self, prim: dict, timeout: float = 15.0) -> Resp:
        raw = http_request_bytes(prim, "127.0.0.1", self.port)
        conns, setup = 0, None
        if self.mode == "fresh":
            c = HttpConn("127.0.0.1", self.port, self.ctx)
            setup = c.connect()
            conns = 1
        else:
            with self.lock:
                if self.closed:
                    raise ConnectionAbortedError("transport closed")
                c = self.conn
                if c is None or c.sock is None or c.closed_by_server:
                    if c is not None:
                        c.close()
                    c = self.conn = HttpConn("127.0.0.1", self.port, self.ctx)
                    setup = c.connect()
                    conns = 1
        status, hdrs, body, n_out, n_in = c.roundtrip(raw, timeout)
        t = now()
        if c.closed_by_server:
            self.server_closes += 1
        if self.mode == "fresh":
            c.close()
        rsc = int(hdrs["x-m2m-rsc"]) if "x-m2m-rsc" in hdrs else None
        try:
            pc = json.loads(body) if body else None
        except ValueError:
            pc = {"_raw": body[:200].decode(errors="replace")}
        ex = dict(hdr_rqi=hdrs.get("x-m2m-ri"), ttfb=(c._t_first - c.t_sent) if c._t_first else None,
                  rx_chunks=c._chunks, max_gap=round(c._max_gap, 6))
        return Resp(rsc, pc, str(status), n_out, n_in, conns, setup, t, extra=ex)


# -- WebSocket / WSS -------------------------------------------------------------------------------------
class _Pending:
    __slots__ = ("ev", "msg", "n", "t")

    def __init__(self):
        self.ev = threading.Event()
        self.msg = None
        self.n = 0
        self.t = 0.0


class WsTransport(Transport):
    """TS-0020 JSON primitives in text frames, subprotocol oneM2M.json, X-M2M-Origin header on connect.
    Our websockets client: compression off (permessage-deflate not negotiated), no keepalive pings."""

    def __init__(self, cse: dict, port: int, ctx: Optional[ssl.SSLContext], mode: str, origin: str):
        super().__init__(cse, mode)
        self.proto = "wss" if ctx else "ws"
        self.tls = ctx is not None
        self.port, self.ctx, self.origin = port, ctx, origin
        self.conn = None
        self.sockport: Optional[int] = None
        self.pending: dict[str, _Pending] = {}
        self.unmatched: list = []
        self.lock = threading.Lock()
        self.connect_attempts = 0
        self.connect_failures: list[dict] = []

    def _connect_retry(self, origin: str):
        """_connect; on a failed opening handshake (not a refusal) record the attempt and retry once."""
        from websockets.exceptions import ConnectionClosed, InvalidHandshake
        t0 = now()
        self.connect_attempts += 1
        try:
            return self._connect(origin)
        except (InvalidHandshake, ConnectionClosed, EOFError, ssl.SSLError, TimeoutError) as e:
            if isinstance(e, ssl.SSLCertVerificationError):
                raise
            fail = dict(err=f"{type(e).__name__}: {str(e)[:80]}", elapsed_s=round(now() - t0, 4))
            self.connect_failures.append(fail)
            self.connect_attempts += 1
            conn, setup, lp = self._connect(origin)
            setup.update(retried_after_s=fail["elapsed_s"], first_attempt_error=fail["err"])
            return conn, setup, lp

    def _connect(self, origin: str):
        from websockets.sync.client import connect as ws_connect
        t0 = now()
        s = socket.create_connection(("127.0.0.1", self.port), timeout=15)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        t1 = now()
        setup = dict(tcp_s=t1 - t0)
        if self.ctx is not None:
            ss = self.ctx.wrap_socket(s, server_hostname="127.0.0.1", do_handshake_on_connect=False)
            ss.do_handshake()
            setup.update(tls_s=now() - t1, tls_version=ss.version(), cipher=ss.cipher()[0])
            s = ss
        lp = s.getsockname()[1]
        s.settimeout(None)
        t2 = now()
        # TLS already done on s, so the URI is ws:// and websockets does not wrap a second time
        conn = ws_connect(f"ws://127.0.0.1:{self.port}/", sock=s, subprotocols=[CSZ], compression=None,
                          ping_interval=None, max_size=None, open_timeout=15,
                          additional_headers={"X-M2M-Origin": origin})
        setup["ws_upgrade_s"] = now() - t2
        setup["subprotocol"] = conn.subprotocol
        threading.Thread(target=self._reader, args=(conn,), daemon=True).start()
        return conn, setup, lp

    def _reader(self, conn):
        try:
            for msg in conn:
                t = now()
                raw = msg.encode() if isinstance(msg, str) else bytes(msg)
                n = ws_frame_len(len(raw), masked=False)
                try:
                    d = json.loads(raw)
                except ValueError:
                    self.unmatched.append(raw[:200])
                    continue
                if "rsc" not in d and "op" in d:          # a request from the CSE (notification)
                    reply = jdump({"rsc": 2000, "rqi": d.get("rqi"), "rvi": d.get("rvi", RVI),
                                   "to": d.get("fr"), "fr": d.get("to")})
                    try:
                        conn.send(reply.decode())
                    except Exception:
                        pass
                    self.notif_q.put(Notif(t, d.get("rqi"), d.get("pc"), app_c2s=ws_frame_len(len(reply), True),
                                           app_s2c=n, via="ws-inband"))
                    continue
                with self.lock:
                    p = self.pending.pop(d.get("rqi"), None)
                if p is None:
                    self.unmatched.append(d)
                    continue
                p.msg, p.n, p.t = d, n, t
                p.ev.set()
        except Exception:
            pass

    def open(self):
        if self.mode == "fresh":
            return None
        self.conn, setup, self.sockport = self._connect_retry(self.origin)
        return setup

    def close(self):
        if self.conn is not None:
            with contextlib.suppress(Exception):
                self.conn.close()
            self.conn = None

    def local_port(self):
        return self.sockport

    def ae_poa(self, proxied: bool) -> list[str]:
        return ["ws://default"]            # ACME's own constant: push only over an associated connection

    def request(self, prim: dict, timeout: float = 15.0) -> Resp:
        wire = {k: prim[k] for k in ("op", "to", "fr", "rqi", "rvi", "ty", "pc", "fc", "rqet") if prim.get(k) is not None}
        data = jdump(wire)
        conns, setup = 0, None
        conn = self.conn
        if self.mode == "fresh":
            conn, setup, _ = self._connect_retry(prim["fr"])
            conns = 1
        p = _Pending()
        with self.lock:
            self.pending[prim["rqi"]] = p
        conn.send(data.decode())
        ok = p.ev.wait(timeout)
        if self.mode == "fresh":
            t_close = now()
            with contextlib.suppress(Exception):
                conn.close()
            setup = dict(setup or {}, close_s=now() - t_close)
        if not ok:
            with self.lock:
                self.pending.pop(prim["rqi"], None)
            return Resp(None, None, "timeout", ws_frame_len(len(data), True), None, conns, setup, now())
        return Resp(p.msg.get("rsc"), p.msg.get("pc"), "frame", ws_frame_len(len(data), True), p.n, conns, setup, p.t)


# -- MQTT ------------------------------------------------------------------------------------------------
class MqttTransport(Transport):
    """TS-0010 over a private mosquitto: requests to /oneM2M/req/<originator>/<CSE-ID>/json, responses on
    /oneM2M/resp/<originator>/<CSE-ID>/json, CSE requests (notifications) on /oneM2M/req/<CSE-ID>/<AE-ID>/json.
    QoS 0 both ways (ACME publishes and subscribes with paho's default QoS 0), MQTT 3.1.1."""
    proto = "mqtt"

    def __init__(self, cse: dict, port: int, origin: str, broker_port: int):
        super().__init__(cse, "reuse")
        self.port, self.origin, self.broker_port = port, origin, broker_port
        self.cli = None
        self.pending: dict[str, _Pending] = {}
        self.lock = threading.Lock()
        self.unmatched: list = []
        self.sockport: Optional[int] = None
        self._suback = threading.Event()
        self._connack = threading.Event()
        self._sock_t = 0.0
        self.subscribed: set[str] = set()

    def topic_req(self, fr: str, to_csi: Optional[str] = None) -> str:
        return f"/oneM2M/req/{fr}/{to_csi or self.cse['csi']}/json"

    def topic_resp(self, fr: str, to_csi: Optional[str] = None) -> str:
        return f"/oneM2M/resp/{fr}/{to_csi or self.cse['csi']}/json"

    def _on_message(self, client, userdata, msg):
        t = now()
        n = mqtt_publish_len(msg.topic, len(msg.payload), msg.qos)
        try:
            d = json.loads(msg.payload)
        except ValueError:
            self.unmatched.append((msg.topic, msg.payload[:200]))
            return
        parts = msg.topic.split("/")
        if len(parts) == 6 and parts[2] == "req":           # CSE -> us: notification
            rtopic = f"/oneM2M/resp/{parts[3]}/{parts[4]}/json"
            reply = jdump({"rsc": 2000, "rqi": d.get("rqi"), "rvi": d.get("rvi", RVI), "to": d.get("fr"),
                           "fr": d.get("to")})
            client.publish(rtopic, reply, qos=0)
            self.notif_q.put(Notif(t, d.get("rqi"), d.get("pc"), app_c2s=mqtt_publish_len(rtopic, len(reply)),
                                   app_s2c=n, via="mqtt-broker"))
            return
        with self.lock:
            p = self.pending.pop(d.get("rqi"), None)
        if p is None:
            self.unmatched.append((msg.topic, d))
            return
        p.msg, p.n, p.t = d, n, t
        p.ev.set()

    def subscribe(self, topics: list[str], timeout: float = 10.0) -> None:
        self._suback.clear()
        self.cli.subscribe([(t, 0) for t in topics])
        if not self._suback.wait(timeout):
            raise TimeoutError("SUBACK")
        self.subscribed.update(topics)

    def open(self):
        import paho.mqtt.client as mqtt
        c = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=f"pb-{self.origin}",
                        clean_session=True, protocol=mqtt.MQTTv311)

        def on_sock(client, userdata, sock):
            self._sock_t = now()
            with contextlib.suppress(Exception):
                self.sockport = sock.getsockname()[1]
                # paho 2.1.0 leaves Nagle on; ours turns it off so that our side adds no Nagle wait
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        c.on_socket_open = on_sock
        c.on_connect = lambda *a: self._connack.set()
        c.on_subscribe = lambda *a: self._suback.set()
        c.on_message = self._on_message
        self.cli = c
        t0 = now()
        c.connect("127.0.0.1", self.port, keepalive=600)
        c.loop_start()
        if not self._connack.wait(10):
            raise TimeoutError("CONNACK")
        t1 = now()
        self.subscribe([self.topic_resp(self.origin), f"/oneM2M/req/{self.cse['csi']}/{self.origin}/json"])
        t2 = now()
        return dict(tcp_s=self._sock_t - t0 if self._sock_t else None, mqtt_connect_s=t1 - t0,
                    mqtt_subscribe_s=t2 - t1)

    def close(self):
        if self.cli is not None:
            with contextlib.suppress(Exception):
                self.cli.disconnect()
                self.cli.loop_stop()
            self.cli = None

    def local_port(self):
        return self.sockport

    def ae_poa(self, proxied: bool) -> list[str]:
        return [f"mqtt://127.0.0.1:{self.broker_port}"]

    def prepare(self, prim: dict, to_csi: Optional[str] = None) -> None:
        rt = self.topic_resp(prim["fr"], to_csi)
        if rt not in self.subscribed:
            self.subscribe([rt])

    def request(self, prim: dict, timeout: float = 15.0, to_csi: Optional[str] = None) -> Resp:
        fr = prim["fr"]
        rt = self.topic_resp(fr, to_csi)
        if rt not in self.subscribed:
            self.subscribe([rt])
        wire = {k: prim[k] for k in ("op", "to", "fr", "rqi", "rvi", "ty", "pc", "fc", "rqet") if prim.get(k) is not None}
        data = jdump(wire)
        topic = self.topic_req(fr, to_csi)
        p = _Pending()
        with self.lock:
            self.pending[prim["rqi"]] = p
        self.cli.publish(topic, data, qos=0)
        n_out = mqtt_publish_len(topic, len(data))
        if not p.ev.wait(timeout):
            with self.lock:
                self.pending.pop(prim["rqi"], None)
            return Resp(None, None, "timeout", n_out, 0, 0, None, now())
        return Resp(p.msg.get("rsc"), p.msg.get("pc"), "publish", n_out, p.n, 0, None, p.t)


# -- CoAP ------------------------------------------------------------------------------------------------
COAP_METHOD = {1: coap.POST, 2: coap.GET, 3: coap.PUT, 4: coap.DELETE, 5: coap.POST}
COAP_BLOCK = 1024                         # CoAPthon's MAX_PAYLOAD; its server reads datagrams of <= 4096 B
ACK_TIMEOUT, MAX_RETRANSMIT = 2.0, 4


def coap_rsc(m: coap.Message) -> Optional[int]:
    """ACME sets oneM2M-RSC from a str ('2001'); depending on how CoAPthon encodes that, the option holds the
    ASCII digits or a uint. Accept both."""
    v = m.get(coap.OM2M_RSC)
    if v is None:
        return None
    if len(v) == 4 and v.isdigit():
        return int(v.decode())
    return coap.bytes_uint(v)


class CoapTransport(Transport):
    """Our own CoAP client (coap_min.py) over one UDP socket: CON requests, piggybacked or separate responses,
    Block1 for request payloads > 1024 B, Block2 for responses the server splits."""
    proto = "coap"

    def __init__(self, cse: dict, port: int, poa_ports: tuple[int, int]):
        super().__init__(cse, "reuse")
        self.port, self.poa_ports = port, poa_ports
        self.sock: Optional[socket.socket] = None
        self.mid = random.randrange(65536)
        self.retransmissions = 0
        self.closed = False

    def open(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.connect(("127.0.0.1", self.port))
        return dict(tcp_s=None)

    def close(self):
        self.closed = True
        if self.sock:
            with contextlib.suppress(OSError):
                self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
            self.sock = None

    def local_port(self):
        return self.sock.getsockname()[1] if self.sock else None

    def ae_poa(self, proxied: bool) -> list[str]:
        return [f"coap://127.0.0.1:{self.poa_ports[1] if proxied else self.poa_ports[0]}"]

    def _next_mid(self) -> int:
        self.mid = (self.mid + 1) & 0xFFFF
        return self.mid

    def _exchange(self, m: coap.Message, timeout: float, acct: list[int]) -> coap.Message:
        """Send a CON, return the response (piggybacked in the ACK, or separate CON that we ACK)."""
        m.mtype, m.mid = coap.CON, self._next_mid()
        raw = coap.encode(m)
        deadline = now() + timeout
        tries, wait = 0, ACK_TIMEOUT
        acked = False
        self.sock.send(raw)
        acct[0] += len(raw)
        t_resend = now() + wait
        while True:
            left = min(deadline, t_resend if not acked else deadline) - now()
            if left <= 0:
                if acked or now() >= deadline or tries >= MAX_RETRANSMIT:
                    raise TimeoutError("CoAP response timeout")
                tries += 1
                self.retransmissions += 1
                self.sock.send(raw)
                acct[0] += len(raw)
                wait *= 2
                t_resend = now() + wait
                continue
            self.sock.settimeout(left)
            try:
                data = self.sock.recv(65535)
            except socket.timeout:
                continue
            acct[1] += len(data)
            r = coap.decode(data)
            if r.mtype == coap.ACK and r.mid == m.mid:
                if r.code == coap.EMPTY:
                    acked = True                    # separate response follows
                    continue
                if r.token == m.token:
                    return r
            elif r.mtype in (coap.CON, coap.NON) and r.token == m.token and r.code >= 64:
                if r.mtype == coap.CON:
                    ack = coap.encode(coap.Message(mtype=coap.ACK, code=coap.EMPTY, mid=r.mid))
                    self.sock.send(ack)
                    acct[0] += len(ack)
                return r
            # anything else (stale duplicate): ignore

    def _base_msg(self, prim: dict, token: bytes) -> coap.Message:
        m = coap.Message(code=COAP_METHOD[prim["op"]], token=token)
        for seg in prim["to"].split("/"):
            m.add(coap.URI_PATH, seg)
        m.add(coap.ACCEPT, coap.CF_JSON)
        m.add(coap.OM2M_FR, prim["fr"]).add(coap.OM2M_RQI, prim["rqi"]).add(coap.OM2M_RVI, prim.get("rvi", RVI))
        if prim.get("ty"):
            m.add(coap.OM2M_TY, int(prim["ty"]))
        if prim.get("rqet"):
            m.add(coap.OM2M_RQET, prim["rqet"])
        for k, v in fc_query(prim.get("fc")):
            m.add(coap.URI_QUERY, f"{k}={v}")
        return m

    def request(self, prim: dict, timeout: float = 15.0) -> Resp:
        if self.closed:
            raise ConnectionAbortedError("transport closed")
        acct = [0, 0]
        token = secrets.token_bytes(4)
        body = jdump(prim["pc"]) if prim.get("pc") is not None else b""
        blocks1 = 0
        if len(body) > COAP_BLOCK:
            szx = coap.szx_for(COAP_BLOCK)
            nblk = (len(body) + COAP_BLOCK - 1) // COAP_BLOCK
            r = None
            for num in range(nblk):
                m = self._base_msg(prim, token)
                m.add(coap.CONTENT_FORMAT, coap.CF_JSON)
                more = num < nblk - 1
                m.add(coap.BLOCK1, coap.block_value(num, more, szx))
                if num == 0:
                    m.add(coap.SIZE1, len(body))
                m.payload = body[num * COAP_BLOCK:(num + 1) * COAP_BLOCK]
                r = self._exchange(m, timeout, acct)
                blocks1 += 1
                if more and r.code != coap.CONTINUE:
                    break
        else:
            m = self._base_msg(prim, token)
            if body:
                m.add(coap.CONTENT_FORMAT, coap.CF_JSON)
                m.payload = body
            r = self._exchange(m, timeout, acct)
        first = r
        payload = bytearray(r.payload)
        blocks2 = 1
        b2 = r.get_uint(coap.BLOCK2)
        template = self._base_msg(prim, token)        # follow-ups repeat the first request's options (RFC 7959 2.4)
        while b2 is not None:
            num, more, size = coap.block_parse(b2)
            if not more:
                break
            m = coap.block2_followup(template, num + 1, coap.szx_for(size))
            r = self._exchange(m, timeout, acct)
            payload += r.payload
            blocks2 += 1
            b2 = r.get_uint(coap.BLOCK2)
        t = now()
        try:
            pc = json.loads(bytes(payload)) if payload else None
        except ValueError:
            pc = {"_raw": bytes(payload[:200]).decode(errors="replace")}
        return Resp(coap_rsc(first), pc, coap.code_str(first.code), acct[0], acct[1], 0, None, t,
                    extra=dict(blocks1=blocks1, blocks2=blocks2))


# ------------------------------------------------------------------------------------------------ environment
@dataclasses.dataclass
class Variant:
    key: str
    proto: str
    mode: str          # reuse | fresh
    mech: str          # core (full workload, push where the binding has one) | pch (pollingChannel only)
    cse: str           # P | T


VARIANTS = [
    Variant("http/reuse", "http", "reuse", "core", "P"), Variant("http/fresh", "http", "fresh", "core", "P"),
    Variant("https/reuse", "https", "reuse", "core", "T"), Variant("https/fresh", "https", "fresh", "core", "T"),
    Variant("ws/reuse", "ws", "reuse", "core", "P"), Variant("ws/fresh", "ws", "fresh", "core", "P"),
    Variant("wss/reuse", "wss", "reuse", "core", "T"), Variant("wss/fresh", "wss", "fresh", "core", "T"),
    Variant("mqtt/reuse", "mqtt", "reuse", "core", "P"), Variant("coap/reuse", "coap", "reuse", "core", "P"),
    Variant("http-wsgi/reuse", "http", "reuse", "core", "W"), Variant("http-wsgi/fresh", "http", "fresh", "core", "W"),
    Variant("http-pch/reuse", "http", "reuse", "pch", "P"), Variant("https-pch/reuse", "https", "reuse", "pch", "T"),
    Variant("coap-pch/reuse", "coap", "reuse", "pch", "P"),
]
MAIN_PROXY = dict(http="x_http", https="x_https", ws="x_ws", wss="x_wss", mqtt="x_mqtt", coap="x_coap")
LEG_PROXY = dict(http="x_rcv_http", https="x_rcv_https", coap="x_rcv_coap")
POLL_PROXY = dict(http="x_poll_http", https="x_poll_https", coap="x_poll_coap")


def main_proxy_key(v: "Variant") -> str:
    return "x_http_w" if v.cse == "W" else MAIN_PROXY[v.proto]


class Env:
    def __init__(self, root: Path):
        self.root = root
        self.pki = root / "pki"
        self.children: dict[str, Child] = {}
        self.proxies: dict[str, Any] = {}
        self.receivers: dict[str, Any] = {}
        self.secrets: dict[str, str] = {}
        self.inis: dict[str, str] = {}
        self.stops: list[dict] = []
        self.port_waits: list[dict] = []
        self.start_retries: list[dict] = []
        self.good_ctx: Optional[ssl.SSLContext] = None
        self.bad_ctx: Optional[ssl.SSLContext] = None

    # -- one-time ---------------------------------------------------------------------------------
    def setup(self) -> None:
        self.pki.mkdir(parents=True)
        make_ca(self.pki, "ca", "proto-bench throwaway CA")
        make_ca(self.pki, "other-ca", "proto-bench OTHER CA (never signs the server)")
        for kind in "PTCW":
            base = self.root / f"cse-{kind.lower()}"
            base.mkdir()
            self.secrets[kind] = secrets.token_urlsafe(24)
            self.inis[kind] = render_ini(cse_sections(kind, self.secrets[kind]))
            (base / "acme.ini").write_text(self.inis[kind])
        make_leaf(self.pki, "ca", self.root / "cse-t" / "certs")
        (self.root / "broker").mkdir()
        (self.root / "broker" / "mosquitto.conf").write_text(mosquitto_conf(self.root / "broker" / "mosquitto.log"))
        self.good_ctx = client_ctx(self.pki / "ca.pem")
        self.bad_ctx = client_ctx(self.pki / "other-ca.pem")
        self.port_waits.append(dict(phase="setup", waited=wait_ports_clear(
            [k for k in PORTS if k.startswith(("x_", "rcv_"))])))
        cert = (self.root / "cse-t" / "certs" / "acme_cert.pem", self.root / "cse-t" / "certs" / "acme_key.pem")
        self.receivers = dict(http=HttpReceiver(PORTS["rcv_http"]), https=HttpReceiver(PORTS["rcv_https"], cert),
                              coap=CoapReceiver(PORTS["rcv_coap"]))
        tcp_pairs = dict(x_http="p_http", x_ws="p_ws", x_https="t_https", x_wss="t_wss", x_mqtt="broker",
                         x_rcv_http="rcv_http", x_rcv_https="rcv_https", x_poll_http="p_http",
                         x_poll_https="t_https", x_http_w="w_http")
        for k, t in tcp_pairs.items():
            self.proxies[k] = TcpProxy(k, PORTS[k], PORTS[t])
        self.proxies["x_coap"] = UdpProxy("x_coap", PORTS["x_coap"], PORTS["p_coap"])
        self.proxies["x_rcv_coap"] = UdpProxy("x_rcv_coap", PORTS["x_rcv_coap"], PORTS["rcv_coap"])
        self.proxies["x_poll_coap"] = UdpProxy("x_poll_coap", PORTS["x_poll_coap"], PORTS["p_coap"])

    def redacted_inis(self) -> dict[str, str]:
        out = {}
        for k, txt in self.inis.items():
            out[f"cse-{k.lower()}"] = txt.replace(self.secrets[k], "<redacted: per-run token_urlsafe(24)>")
        out["mosquitto.conf"] = (self.root / "broker" / "mosquitto.conf").read_text()
        return out

    # -- per repeat -------------------------------------------------------------------------------
    def start_services(self, kinds: str = "PT") -> dict:
        t = {}
        if "P" in kinds and "broker" not in self.children:
            self.port_waits.append(dict(phase="start broker", waited=wait_ports_clear(["broker"])))
            t0 = now()
            b = Child("mosquitto", [MOSQUITTO, "-c", str(self.root / "broker" / "mosquitto.conf")],
                      self.root / "broker", str(self.root / "broker"))
            self.children["broker"] = b
            if not wait_for(lambda: tcp_port_open(PORTS["broker"]), 10):
                raise RuntimeError("broker did not listen: " + b.log.read_text()[-500:])
            t["broker_s"] = now() - t0
        own = dict(P=["p_http", "p_ws", "p_coap"], T=["t_https", "t_wss"], C=["c_http"], W=["w_http"])
        for kind in kinds:
            base = self.root / f"cse-{kind.lower()}"
            port = PORTS[HTTP_PORT[kind]]
            ctx = self.good_ctx if kind == "T" else None
            for attempt in range(4):
                self.port_waits.append(dict(phase=f"start {kind} attempt {attempt}", waited=wait_ports_clear(own[kind])))
                t0 = now()
                ch = Child(f"acme-{kind}", [ACME, "--headless", "--config", "acme.ini", "--base-directory", str(base)],
                           base, str(base))
                self.children[kind] = ch
                # No request may reach ACME before its startup is complete: an HTTP request that arrives while
                # plugins still register Flask routes aborts the startup ('add_url_rule ... already handled its
                # first request', seen 2026-11-21). So: all listeners up (read from /proc, no connection), a grace
                # period, no startup error in the log, process alive -- only then the first request.
                need_tcp = {PORTS[k] for k in own[kind] if k not in UDP_KEYS}
                need_udp = {PORTS[k] for k in own[kind] if k in UDP_KEYS}
                ready = False
                deadline = now() + 90
                while now() < deadline and ch.alive():
                    lp = listening_ports()
                    if need_tcp <= lp["tcp"] and need_udp <= lp["udp"]:
                        ready = True
                        break
                    time.sleep(0.2)
                if ready:
                    time.sleep(2.0)
                    errs = [p_.read_text(errors="replace") for p_ in (base / "logs").glob("*.log*")]
                    ready = ch.alive() and not any("Error during startup" in e for e in errs)
                if ready:
                    ready = wait_for(lambda: ch.alive() and self.cse_ready(kind, port, ctx), 30, 0.3)
                if ready:
                    t[f"cse_{kind}_s"] = now() - t0
                    break
                tail = ch.log.read_text(errors="replace")[-600:]
                logs = "".join(p.read_text(errors="replace")[-600:] for p in sorted((base / "logs").glob("*.log*")))
                self.start_retries.append(dict(kind=kind, attempt=attempt, alive=ch.alive(),
                                               addr_in_use=("in use" in tail + logs),
                                               startup_error=("Error during startup" in logs),
                                               log_head=re.sub(r"\s+", " ", logs)[:300]))
                self.stops.append(ch.stop())
                self.children.pop(kind, None)
            else:
                raise RuntimeError(f"CSE {kind} did not come up in 4 attempts: {self.start_retries[-1]}")
        if "P" in kinds:      # the CSE's MQTT client must be subscribed before mqtt workloads
            t0 = now()
            if not wait_for(self.mqtt_ready, 30, 0.5):
                raise RuntimeError("CSE-P not answering over MQTT")
            t["mqtt_ready_s"] = now() - t0
        return t

    def cse_ready(self, kind: str, port: int, ctx) -> bool:
        c = HttpConn("127.0.0.1", port, ctx)
        c.connect(2)
        try:
            prim = dict(op=2, to=CSE[kind]["rn"], fr="CAdmin", rqi=rqi(), rvi=RVI)
            st, hdrs, _, _, _ = c.roundtrip(http_request_bytes(prim, "127.0.0.1", port), 3)
            return st == 200 and hdrs.get("x-m2m-rsc") == "2000"
        finally:
            c.close()

    def mqtt_ready(self) -> bool:
        m = MqttTransport(CSE["P"], PORTS["broker"], "CAdmin", PORTS["broker"])
        m.open()
        try:
            r = m.request(dict(op=2, to=CSE["P"]["rn"], fr="CAdmin", rqi=rqi(), rvi=RVI), timeout=2)
            return r.rsc == 2000
        finally:
            m.close()

    def stop_services(self, kinds: str = "PTCW", broker: bool = True) -> None:
        for k in [*kinds, *(["broker"] if broker else [])]:
            ch = self.children.pop(k, None)
            if ch is not None:
                self.stops.append(ch.stop())

    def cse_pid(self, kind: str) -> Optional[int]:
        ch = self.children.get(kind)
        return ch.pid if ch else None

    def close_all(self) -> None:
        with contextlib.suppress(Exception):
            self.stop_services()
        for p in self.proxies.values():
            with contextlib.suppress(Exception):
                p.close()
        for r in self.receivers.values():
            with contextlib.suppress(Exception):
                r.close()


def make_transport(env: Env, v: Variant, origin: str, proxied: bool, ctx: Optional[ssl.SSLContext] = None,
                   proxy_key: Optional[str] = None) -> Transport:
    cse = CSE[v.cse]
    ctx = ctx or env.good_ctx
    px = lambda k, d: PORTS[proxy_key or k] if proxied else PORTS[d]  # noqa: E731
    if v.proto == "http" and v.cse == "W":
        return HttpTransport(cse, px("x_http_w", "w_http"), None, v.mode, (PORTS["rcv_http"], PORTS["x_rcv_http"]))
    if v.proto == "http":
        return HttpTransport(cse, px("x_http", "p_http"), None, v.mode, (PORTS["rcv_http"], PORTS["x_rcv_http"]))
    if v.proto == "https":
        return HttpTransport(cse, px("x_https", "t_https"), ctx, v.mode, (PORTS["rcv_https"], PORTS["x_rcv_https"]))
    if v.proto == "ws":
        return WsTransport(cse, px("x_ws", "p_ws"), None, v.mode, origin)
    if v.proto == "wss":
        return WsTransport(cse, px("x_wss", "t_wss"), ctx, v.mode, origin)
    if v.proto == "mqtt":
        return MqttTransport(cse, px("x_mqtt", "broker"), origin, PORTS["broker"])
    if v.proto == "coap":
        return CoapTransport(cse, px("x_coap", "p_coap"), (PORTS["rcv_coap"], PORTS["x_rcv_coap"]))
    raise ValueError(v.proto)


# ------------------------------------------------------------------------------------------------ workload
class WCtx:
    def __init__(self, env: Env, v: Variant, tr: Transport, proxied: bool):
        self.env, self.v, self.tr, self.proxied = env, v, tr, proxied
        self.proxy = env.proxies[main_proxy_key(v)] if proxied else None
        self.leg = env.proxies.get(LEG_PROXY.get(v.proto, "")) if proxied and v.mech == "core" else None
        self.samples: list[dict] = []

    def snap(self):
        """Proxy totals: each proxy carries one client at a time (the poller has its own proxy)."""
        return self.proxy.snap() if self.proxy else None


PAYLOAD: dict[str, str] = {}
SIZES = dict(small=100, large=4000)


def make_payloads(seed: int) -> None:
    rnd = random.Random(seed)
    for k, n in SIZES.items():
        PAYLOAD[k] = base64.b64encode(rnd.randbytes(n)).decode()[:n]


def _delta(a, b) -> tuple[int, int, int]:
    return b[0] - a[0], b[1] - a[1], b[2] - a[2]


def do_op(w: WCtx, op: str, prim: dict, size: Optional[str] = None, expect: Optional[int] = None,
          check: Optional[Callable[[Resp], Optional[str]]] = None) -> tuple[dict, Resp]:
    w.tr.prepare(prim)
    before = w.snap()
    t0 = now()
    try:
        r = w.tr.request(prim)
    except Exception as e:      # recorded, not fatal
        r = Resp(None, None, f"error:{type(e).__name__}:{str(e)[:80]}", None, None, 0, None, now())
    s: dict[str, Any] = dict(op=op, lat=r.t_resp - t0, rsc=r.rsc, st=r.status, ac=r.app_c2s, as_=r.app_s2c,
                             conns=r.conns)
    if size:
        s["size"] = size
    if r.setup:
        s["setup"] = r.setup
        if "retried_after_s" in r.setup:
            s["connect_retry"] = r.setup["retried_after_s"]
    if r.extra:
        s.update({k: v for k, v in r.extra.items() if k != "hdr_rqi"})
    if w.proxy:
        w.proxy.settle()
        after = w.snap()
        s["wc"], s["ws"], s["acc"] = _delta(before, after)
        exact = w.tr.exact_bytes and (not r.conns or w.tr.proto == "http")    # plain TCP setup carries no payload
        probs = self_check(s["wc"], s["ws"], s["ac"], s["as_"], w.tr.tls, exact)
        if probs:
            s["selfcheck"] = probs
    s["ok"] = (r.rsc == expect) if expect is not None else (r.rsc is not None and 2000 <= r.rsc < 3000)
    if check and s["ok"]:
        msg = check(r)
        if msg:
            s["ok"] = False
            s["check"] = msg
    w.samples.append(s)
    return s, r


def notif_queue(w: WCtx) -> "queue.Queue[Notif]":
    if w.v.proto in ("http", "https", "coap") and w.v.mech == "core":
        return w.env.receivers[w.v.proto].q
    return w.tr.notif_q


def drain(q: "queue.Queue") -> int:
    n = 0
    with contextlib.suppress(queue.Empty):
        while True:
            q.get_nowait()
            n += 1
    return n


def notify_ops(w: WCtx, base_to: str, origin: str, k: int, q: "queue.Queue[Notif]",
               poller: Optional["PchPoller"] = None, wait_s: float = 5.0) -> None:
    misses = 0
    for i in range(k):
        size = "small" if i % 2 == 0 else "large"
        marker = f"n{i}x{secrets.token_hex(3)}"
        prim = dict(op=1, to=base_to, fr=origin, rqi=rqi(), rvi=RVI, ty=4,
                    pc={"m2m:cin": {"rn": marker, "cnf": "text/plain:0", "con": PAYLOAD[size], "lbl": [f"bench:{size}"]}})
        leg0 = w.leg.snap() if w.leg else None
        pol0 = poller.snap() if poller else None
        before = w.snap()
        t0 = now()
        try:
            r = w.tr.request(prim)
        except Exception as e:
            r = Resp(None, None, f"error:{type(e).__name__}", None, None, 0, None, now())
        got, stale = None, 0
        deadline = t0 + wait_s
        while True:
            left = deadline - now()
            if left <= 0:
                break
            try:
                n = q.get(timeout=left)
            except queue.Empty:
                break
            if notif_marker(n) == marker:
                got = n
                break
            stale += 1
        s: dict[str, Any] = dict(op="notify", size=size, lat=r.t_resp - t0, rsc=r.rsc, st=r.status, ac=r.app_c2s,
                                 as_=r.app_s2c, conns=r.conns, delay=(got.t_recv - t0) if got else None,
                                 via=(got.via if got else None), stale=stale)
        if got:
            s["n_ac"], s["n_as"] = got.app_c2s, got.app_s2c
        if w.proxy:
            w.proxy.settle()
            if w.leg:
                w.leg.settle()
            after = w.snap()
            s["wc"], s["ws"], s["acc"] = _delta(before, after)
            if w.leg:
                lc, ls, la = _delta(leg0, w.leg.snap())
                s["leg_wc"], s["leg_ws"], s["leg_acc"] = lc, ls, la
            if poller:
                pc_, ps_, _ = _delta(pol0, poller.snap())
                s["poll_wc"], s["poll_ws"] = pc_, ps_
            # in-band pushes (ws, mqtt) share the main connection: app bytes = request + response + push + reply
            if got and w.v.proto in ("ws", "wss", "mqtt"):
                ac = (s["ac"] or 0) + (got.app_c2s or 0)
                as_ = (s["as_"] or 0) + (got.app_s2c or 0)
            else:
                ac, as_ = s["ac"], s["as_"]
            probs = self_check(s["wc"], s["ws"], ac, as_, w.tr.tls,
                               w.tr.exact_bytes and (not r.conns or w.tr.proto == "http"))
            if probs:
                s["selfcheck"] = probs
        s["ok"] = r.rsc == 2001 and got is not None
        w.samples.append(s)
        if got is None:
            misses += 1
            if misses >= 2:
                w.samples.append(dict(op="notify_abandoned", after=i + 1,
                                      reason=f"2 notifications not received within {wait_s:.0f} s each"))
                return
        else:
            misses = 0


class PchPoller:
    """Long-polls <pch>/pcu on its own connection (http/https) or socket (coap); answers each delivered
    request with a NOTIFY carrying m2m:rsp to the same pcu (what ACME's PCH_PCU.handleNotifyRequest wants)."""

    def __init__(self, w: WCtx, pcu: str, origin: str, proxied: bool):
        self.w, self.pcu, self.origin = w, pcu, origin
        v = dataclasses.replace(w.v, mode="reuse")
        self.tr = make_transport(w.env, v, origin, proxied, proxy_key=POLL_PROXY[v.proto])
        self.tr.open()
        self.proxy = w.env.proxies[POLL_PROXY[v.proto]] if proxied else None
        self.q: "queue.Queue[Notif]" = queue.Queue()
        self.polls = 0
        self.timeouts = 0
        self.errors: list[str] = []
        self.first_raw: Optional[Any] = None
        self._stop = False
        self.th = threading.Thread(target=self._loop, daemon=True)
        self.th.start()

    def snap(self):
        return self.proxy.snap() if self.proxy else (0, 0, 0, 0)

    @staticmethod
    def extract(pc: Any) -> Optional[dict]:
        """The request ACME hands out at the pcu: find the primitive that carries op/pc (m2m:rqp or bare)."""
        if not isinstance(pc, dict):
            return None
        if "m2m:rqp" in pc:
            return pc["m2m:rqp"]
        if "op" in pc and "pc" in pc:
            return pc
        if "m2m:agrp" in pc and pc["m2m:agrp"]:
            return PchPoller.extract(pc["m2m:agrp"][0])
        return None

    def _loop(self):
        while not self._stop:
            prim = dict(op=2, to=self.pcu, fr=self.origin, rqi=rqi(), rvi=RVI)
            try:
                r = self.tr.request(prim, timeout=15)
            except Exception as e:
                if not self._stop:
                    self.errors.append(f"{type(e).__name__}: {str(e)[:100]}")
                return
            self.polls += 1
            if self._stop:
                return
            if r.rsc != 2000:
                if r.rsc == 4008:
                    self.timeouts += 1
                else:
                    self.errors.append(f"poll rsc {r.rsc} {r.status}")
                    time.sleep(0.05)
                continue
            if self.first_raw is None:
                self.first_raw = r.pc
            inner = self.extract(r.pc)
            if inner is None:
                self.errors.append(f"unrecognised pcu payload keys {list(r.pc)[:5] if isinstance(r.pc, dict) else type(r.pc)}")
                continue
            t = r.t_resp
            rsp = {"m2m:rsp": {"rsc": 2000, "rqi": inner.get("rqi"), "rvi": inner.get("rvi", RVI),
                               "fr": self.origin, "to": inner.get("fr")}}
            ans = dict(op=5, to=self.pcu, fr=self.origin, rqi=rqi(), rvi=RVI, pc=rsp)
            try:
                ar = self.tr.request(ans, timeout=10)
                if ar.rsc not in (2000, 2004):
                    self.errors.append(f"pcu NOTIFY answer rsc {ar.rsc}")
            except Exception as e:
                self.errors.append(f"answer {type(e).__name__}")
            self.q.put(Notif(t, inner.get("rqi"), inner.get("pc"), via=f"{self.w.v.proto}-pch"))

    def stop(self) -> dict:
        t0 = now()
        self._stop = True
        self.tr.close()            # ends a pending long-poll on our side; ACME's own wait times out by itself
        self.th.join(3)
        return dict(stop_s=round(now() - t0, 3), thread_alive=self.th.is_alive())


class _OpenFailed(Exception):
    pass


def ae_prim(origin: str, ae_rn: str, cse_rn: str, rr: bool, poa: list[str]) -> dict:
    ae = {"rn": ae_rn, "api": "Nproto.bench", "rr": rr, "srv": [RVI]}
    if poa:
        ae["poa"] = poa
    return dict(op=1, to=cse_rn, fr=origin, rqi=rqi(), rvi=RVI, ty=2, pc={"m2m:ae": ae})


def run_workload(env: Env, v: Variant, proxied: bool, n_cin: int, k_notify: int, push_ok: bool = True) -> dict:
    origin = f"Cb{v.proto}{v.mode[0]}{v.mech[0]}{secrets.token_hex(3)}"
    intruder = f"Cintruder{secrets.token_hex(3)}"
    ae_rn = "pb-" + origin[1:]
    cse_rn = CSE[v.cse]["rn"]
    ae_to, cnt_to = f"{cse_rn}/{ae_rn}", f"{cse_rn}/{ae_rn}/data"
    tr = make_transport(env, v, origin, proxied)
    w = WCtx(env, v, tr, proxied)
    pid = env.cse_pid(v.cse)
    meta: dict[str, Any] = dict(variant=v.key, proxied=proxied, origin=origin, t_utc=utc(), load=os.getloadavg())
    cpu0, sys0 = proc_cpu_s(pid), system_cpu_times()
    bro0 = proc_cpu_s(env.cse_pid("broker")) if v.proto == "mqtt" else None
    t_w0 = now()
    q = notif_queue(w) if v.mech == "core" else None
    if q is not None:
        meta["drained_before"] = drain(q)
    poller = None
    try:
        before = w.proxy.snap() if w.proxy else None          # totals: the connection does not exist yet
        t0 = now()
        try:
            setup = tr.open()
        except Exception as e:
            w.samples.append(dict(op="connect", lat=now() - t0, ok=False, st=f"error:{type(e).__name__}:{str(e)[:120]}"))
            raise _OpenFailed(str(e))
        s = dict(op="connect", lat=now() - t0, setup=setup, ok=True)
        if setup and "retried_after_s" in setup:
            s["connect_retry"] = setup["retried_after_s"]
        if w.proxy:
            w.proxy.settle(quiet=0.05)
            s["wc"], s["ws"], s["acc"] = _delta(before, w.proxy.snap())
        if v.mode == "reuse":
            w.samples.append(s)
        if v.mech == "core":
            poa = tr.ae_poa(proxied)
            do_op(w, "ae_create", ae_prim(origin, ae_rn, cse_rn, True, poa), expect=2001)
            do_op(w, "cnt_create", dict(op=1, to=ae_to, fr=origin, rqi=rqi(), rvi=RVI, ty=3,
                                        pc={"m2m:cnt": {"rn": "data"}}), expect=2001)
            for i in range(n_cin):
                size = "small" if i % 2 == 0 else "large"
                do_op(w, "cin_create", dict(op=1, to=cnt_to, fr=origin, rqi=rqi(), rvi=RVI, ty=4,
                                            pc={"m2m:cin": {"cnf": "text/plain:0", "con": PAYLOAD[size],
                                                            "lbl": [f"bench:{size}"]}}), size=size, expect=2001)
            last = "small" if (n_cin - 1) % 2 == 0 else "large"
            do_op(w, "retrieve_la", dict(op=2, to=cnt_to + "/la", fr=origin, rqi=rqi(), rvi=RVI), size=last,
                  expect=2000, check=lambda r: None if len(((r.pc or {}).get("m2m:cin") or {}).get("con", "")) ==
                  SIZES[last] else "la con length mismatch")
            n_small = (n_cin + 1) // 2
            do_op(w, "discovery", dict(op=2, to=cnt_to, fr=origin, rqi=rqi(), rvi=RVI,
                                       fc={"fu": 1, "lbl": ["bench:small"]}), expect=2000,
                  check=lambda r: None if len((r.pc or {}).get("m2m:uril", [])) == n_small
                  else f"discovery found {len((r.pc or {}).get('m2m:uril', []))} != {n_small}")
            do_op(w, "ctl_wrong_orig_retrieve", dict(op=2, to=cnt_to, fr=intruder, rqi=rqi(), rvi=RVI), expect=4103)
            do_op(w, "ctl_wrong_orig_create", dict(op=1, to=cnt_to, fr=intruder, rqi=rqi(), rvi=RVI, ty=4,
                                                   pc={"m2m:cin": {"con": "x"}}), expect=4103)
            if v.mode == "reuse" and k_notify:
                ss, _ = do_op(w, "sub_create", dict(op=1, to=cnt_to, fr=origin, rqi=rqi(), rvi=RVI, ty=23,
                                                    pc={"m2m:sub": {"rn": "sub", "nu": [origin],
                                                                    "enc": {"net": [3]}, "nct": 1}}), expect=2001)
                if ss["ok"]:
                    if push_ok:
                        notify_ops(w, cnt_to, origin, k_notify, q)
                    else:      # nothing arrived in this repeat's warm-up: one short attempt per workload, recorded
                        meta["push_probe_only"] = True
                        notify_ops(w, cnt_to, origin, 1, q, wait_s=2.0)
        else:   # pollingChannel: an AE that is not request-reachable, its <pch>, a container, a subscription
            do_op(w, "ae_create", ae_prim(origin, ae_rn, cse_rn, False, []), expect=2001)
            do_op(w, "pch_create", dict(op=1, to=ae_to, fr=origin, rqi=rqi(), rvi=RVI, ty=15,
                                        pc={"m2m:pch": {"rn": "pch"}}), expect=2001)
            do_op(w, "cnt_create", dict(op=1, to=ae_to, fr=origin, rqi=rqi(), rvi=RVI, ty=3,
                                        pc={"m2m:cnt": {"rn": "data"}}), expect=2001)
            ss, _ = do_op(w, "sub_create", dict(op=1, to=cnt_to, fr=origin, rqi=rqi(), rvi=RVI, ty=23,
                                                pc={"m2m:sub": {"rn": "sub", "nu": [origin], "enc": {"net": [3]},
                                                                "nct": 1}}), expect=2001)
            if ss["ok"] and k_notify:
                poller = PchPoller(w, f"{ae_to}/pch/pcu", origin, proxied)
                time.sleep(0.05)
                notify_ops(w, cnt_to, origin, k_notify, poller.q, poller)
                meta["pch"] = dict(polls=poller.polls, timeouts=poller.timeouts, errors=poller.errors[:5],
                                   first_raw_keys=(list(poller.first_raw)[:5] if isinstance(poller.first_raw, dict)
                                                   else str(type(poller.first_raw))))
                if proxied:
                    pc_, ps_, acc_, _ = poller.snap()
                    meta["pch"]["poller_proxy_totals"] = [pc_, ps_, acc_]
                meta["pch"]["stop"] = poller.stop()
                poller = None
        do_op(w, "ae_delete", dict(op=4, to=ae_to, fr=origin, rqi=rqi(), rvi=RVI), expect=2002)
    except _OpenFailed as e:
        meta["open_failed"] = str(e)[:200]
    finally:
        if poller:
            poller.stop()
        with contextlib.suppress(Exception):
            tr.close()
    sys1 = system_cpu_times()
    meta.update(dur_s=now() - t_w0, cse_cpu_s=(proc_cpu_s(pid) or 0) - (cpu0 or 0),
                host_busy=1 - (sys1[1] - sys0[1]) / max(1, sys1[0] - sys0[0]), load_end=os.getloadavg())
    if bro0 is not None:
        meta["broker_cpu_s"] = (proc_cpu_s(env.cse_pid("broker")) or 0) - bro0
    if isinstance(tr, CoapTransport):
        meta["coap_retransmissions"] = tr.retransmissions
    if isinstance(tr, WsTransport):
        meta["ws_connects"] = dict(attempts=tr.connect_attempts, failures=tr.connect_failures)
        meta["ws_unmatched_responses"] = len(tr.unmatched)
    if isinstance(tr, HttpTransport):
        meta["http_server_closes"] = tr.server_closes
    if isinstance(tr, (WsTransport, MqttTransport)) and tr.unmatched:
        meta["unmatched"] = [str(x)[:160] for x in tr.unmatched[:3]]
    meta["samples"] = w.samples
    return meta


# ------------------------------------------------------------------------------------------------ controls
def control_wrong_ca(env: Env) -> dict:
    out = {}
    for name, fn in (("https", lambda c: HttpConn("127.0.0.1", PORTS["t_https"], c).connect(5)),
                     ("wss", lambda c: WsTransport(CSE["T"], PORTS["t_wss"], c, "reuse", "CAdmin")._connect("CAdmin"))):
        res = {}
        for which, ctx in (("right_ca", env.good_ctx), ("other_ca", env.bad_ctx)):
            try:
                r = fn(ctx)
                res[which] = dict(outcome="connected", tls_version=(r or {}).get("tls_version") if isinstance(r, dict)
                                  else r[1].get("tls_version"))
                if not isinstance(r, dict):
                    with contextlib.suppress(Exception):
                        r[0].close()
            except ssl.SSLCertVerificationError as e:
                res[which] = dict(outcome="rejected by client", error=f"SSLCertVerificationError: {e.verify_message}")
            except Exception as e:
                res[which] = dict(outcome="error", error=f"{type(e).__name__}: {str(e)[:120]}")
        res["pass"] = res["right_ca"]["outcome"] == "connected" and res["other_ca"]["outcome"] == "rejected by client"
        out[name] = res
    out["pass"] = all(v["pass"] for v in out.values())
    return out


def control_disabled_bindings(env: Env) -> dict:
    t = env.start_services("C")
    res: dict[str, Any] = dict(start=t)
    try:
        prim = dict(op=2, to=CSE["C"]["rn"], fr="CAdmin", rqi=rqi(), rvi=RVI)
        c = HttpConn("127.0.0.1", PORTS["c_http"], None)
        c.connect()
        st, hdrs, _, _, _ = c.roundtrip(http_request_bytes(prim, "127.0.0.1", PORTS["c_http"]), 5)
        c.close()
        res["http_enabled_positive"] = dict(status=st, rsc=hdrs.get("x-m2m-rsc"))
        lp = listening_ports()
        res["listeners"] = dict(ws_tcp_39131=PORTS["c_ws"] in lp["tcp"], coap_udp_39132=PORTS["c_coap"] in lp["udp"])
        try:
            WsTransport(CSE["C"], PORTS["c_ws"], None, "reuse", "CAdmin")._connect("CAdmin")
            res["ws_disabled"] = dict(outcome="CONNECTED (unexpected)")
        except ConnectionRefusedError as e:
            res["ws_disabled"] = dict(outcome="connection refused", error=str(e))
        except Exception as e:
            res["ws_disabled"] = dict(outcome="error", error=f"{type(e).__name__}: {e}")
        cp = CoapTransport(CSE["C"], PORTS["c_coap"], (0, 0))
        cp.open()
        try:
            r = cp.request(prim, timeout=3)
            res["coap_disabled"] = dict(outcome=f"ANSWERED (unexpected) rsc={r.rsc}")
        except ConnectionRefusedError as e:
            res["coap_disabled"] = dict(outcome="connection refused (ICMP port unreachable)", error=str(e))
        except TimeoutError:
            res["coap_disabled"] = dict(outcome="no answer within 3 s")
        finally:
            cp.close()
        m = MqttTransport(CSE["C"], PORTS["broker"], "CAdmin", PORTS["broker"])
        m.open()
        try:
            r = m.request(prim, timeout=3)
            res["mqtt_disabled"] = dict(outcome="no response within 3 s" if r.status == "timeout"
                                        else f"ANSWERED (unexpected) rsc={r.rsc}")
        finally:
            m.close()
        res["pass"] = (res["http_enabled_positive"]["rsc"] == "2000" and not res["listeners"]["ws_tcp_39131"]
                       and not res["listeners"]["coap_udp_39132"]
                       and res["ws_disabled"]["outcome"] == "connection refused"
                       and res["coap_disabled"]["outcome"].startswith(("connection refused", "no answer"))
                       and res["mqtt_disabled"]["outcome"].startswith("no response"))
    finally:
        env.stop_services("C", broker=False)
    return res


def control_mqtt_topics(env: Env) -> dict:
    origin = f"Cbmqttctl{secrets.token_hex(3)}"
    m = MqttTransport(CSE["P"], PORTS["broker"], origin, PORTS["broker"])
    m.open()
    out = {}
    try:
        r = m.request(ae_prim(origin, "pb-" + origin[1:], CSE["P"]["rn"], True, []))
        out["ae_create_right_topic"] = r.rsc
        prim = dict(op=2, to=f"{CSE['P']['rn']}/pb-{origin[1:]}", fr=origin, rqi=rqi(), rvi=RVI)
        r = m.request(prim, timeout=3, to_csi="id-nonexistent")
        out["wrong_receiver_topic"] = dict(topic=m.topic_req(origin, "id-nonexistent"),
                                           outcome="no response within 3 s" if r.status == "timeout" else f"rsc {r.rsc}")
        intr = f"Cintruder{secrets.token_hex(3)}"
        r = m.request(dict(prim, fr=intr, rqi=rqi()), timeout=5)
        out["wrong_originator_right_topic"] = dict(topic=m.topic_req(intr), rsc=r.rsc)
        r = m.request(dict(prim, rqi=rqi()), timeout=5)
        out["right_originator_positive"] = r.rsc
        m.request(dict(op=4, to=f"{CSE['P']['rn']}/pb-{origin[1:]}", fr=origin, rqi=rqi(), rvi=RVI))
        out["pass"] = (out["wrong_receiver_topic"]["outcome"].startswith("no response")
                       and out["wrong_originator_right_topic"]["rsc"] == 4103 and out["right_originator_positive"] == 2000)
    finally:
        m.close()
    return out


def control_planted_fault(env: Env) -> dict:
    """The same short workload through the proxy with the byte counter skipping one direction: the
    self-check must flag the ops; with the counter intact it must flag none."""
    out = {}
    for vkey, fault in (("http/reuse", None), ("http/reuse", "skip_s2c"), ("http/reuse", "skip_c2s"),
                        ("https/reuse", "skip_s2c"), ("ws/reuse", "skip_s2c"), ("mqtt/reuse", "skip_c2s"),
                        ("coap/reuse", "skip_s2c")):
        v = next(x for x in VARIANTS if x.key == vkey)
        px = env.proxies[MAIN_PROXY[v.proto]]
        px.fault = fault
        try:
            meta = run_workload(env, v, True, 4, 0)
        finally:
            px.fault = None
        ops = [s for s in meta["samples"] if s["op"] not in ("connect",) and s.get("ac") is not None]
        flagged = [s for s in ops if s.get("selfcheck")]
        out[f"{vkey} fault={fault}"] = dict(ops=len(ops), flagged=len(flagged),
                                            example=(flagged[0]["selfcheck"] if flagged else None),
                                            pass_=(len(flagged) == 0) if fault is None else (len(flagged) == len(ops)))
    out["pass"] = all(x["pass_"] for x in out.values() if isinstance(x, dict))
    return out


def control_client_crosscheck(env: Env, n: int = 40) -> dict:
    """Is our HTTP client the bottleneck? The same GET (CSEBase, admin originator) with `requests` and with ours,
    alternating, on CSE-P (werkzeug), CSE-T (werkzeug + TLS) and CSE-W (waitress). requests without a Session opens
    a connection per call (like our fresh mode); with a Session it reuses when the server allows."""
    import requests
    out = {}
    for kind, scheme in (("P", "http"), ("T", "https"), ("W", "http")):
        port = PORTS[HTTP_PORT[kind]]
        url = f"{scheme}://127.0.0.1:{port}/{CSE[kind]['rn']}"
        verify = str(env.pki / "ca.pem") if scheme == "https" else True
        ctx = env.good_ctx if scheme == "https" else None
        res: dict[str, list[float]] = {"ours_fresh": [], "requests_new": [], "requests_session": []}
        sess = requests.Session()
        for i in range(n):
            h = {"X-M2M-Origin": "CAdmin", "X-M2M-RI": rqi(), "X-M2M-RVI": RVI, "Accept": "application/json"}
            t0 = now()
            c = HttpConn("127.0.0.1", port, ctx)
            c.connect()
            st, hd, _, _, _ = c.roundtrip(http_request_bytes(dict(op=2, to=CSE[kind]["rn"], fr="CAdmin", rqi=h["X-M2M-RI"],
                                                                  rvi=RVI), "127.0.0.1", port), 10)
            c.close()
            res["ours_fresh"].append((now() - t0) * 1e3)
            t0 = now()
            r = requests.get(url, headers=dict(h, **{"X-M2M-RI": rqi()}), verify=verify, timeout=10)
            res["requests_new"].append((now() - t0) * 1e3)
            t0 = now()
            r2 = sess.get(url, headers=dict(h, **{"X-M2M-RI": rqi()}), verify=verify, timeout=10)
            res["requests_session"].append((now() - t0) * 1e3)
            assert st == 200 and r.status_code == 200 and r2.status_code == 200
        sess.close()
        out[f"CSE-{kind} {scheme}"] = {k: summarize(v) for k, v in res.items()}
    return out


def diag_mqtt_path(env: Env, k: int = 8) -> dict:
    """Where does the MQTT write-to-notification time go? A sniffer subscribed to /oneM2M/# on the broker
    timestamps every PUBLISH the broker forwards: our request, the CSE's response, the CSE's notification."""
    import paho.mqtt.client as mqtt
    seen: list[tuple[float, str, Optional[str], Any]] = []
    sn = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2, client_id=f"pb-sniff-{secrets.token_hex(2)}",
                     clean_session=True, protocol=mqtt.MQTTv311)
    ev = threading.Event()

    def on_msg(c, u, m):
        t = now()
        try:
            d = json.loads(m.payload)
        except ValueError:
            d = {}
        mk = notif_marker(Notif(0, None, d.get("pc"))) if isinstance(d, dict) else None
        seen.append((t, m.topic, d.get("rqi") if isinstance(d, dict) else None, mk))

    sn.on_message = on_msg
    sn.on_subscribe = lambda *a: ev.set()
    sn.connect("127.0.0.1", PORTS["broker"], keepalive=600)
    sn.loop_start()
    sn.subscribe("/oneM2M/#", qos=0)
    ev.wait(5)
    origin = f"Cbmqttdiag{secrets.token_hex(3)}"
    ae_rn = "pb-" + origin[1:]
    m = MqttTransport(CSE["P"], PORTS["broker"], origin, PORTS["broker"])
    m.open()
    rows = []
    try:
        cse_rn = CSE["P"]["rn"]
        m.request(ae_prim(origin, ae_rn, cse_rn, True, m.ae_poa(False)))
        m.request(dict(op=1, to=f"{cse_rn}/{ae_rn}", fr=origin, rqi=rqi(), rvi=RVI, ty=3, pc={"m2m:cnt": {"rn": "data"}}))
        m.request(dict(op=1, to=f"{cse_rn}/{ae_rn}/data", fr=origin, rqi=rqi(), rvi=RVI, ty=23,
                       pc={"m2m:sub": {"rn": "sub", "nu": [origin], "enc": {"net": [3]}, "nct": 1}}))
        drain(m.notif_q)
        for i in range(k):
            marker = f"d{i}x{secrets.token_hex(3)}"
            rq = rqi()
            t0 = now()
            r = m.request(dict(op=1, to=f"{cse_rn}/{ae_rn}/data", fr=origin, rqi=rq, rvi=RVI, ty=4,
                               pc={"m2m:cin": {"rn": marker, "con": PAYLOAD["small"]}}))
            got = None
            with contextlib.suppress(queue.Empty):
                while True:
                    nn = m.notif_q.get(timeout=3)
                    if notif_marker(nn) == marker:
                        got = nn
                        break
            time.sleep(0.05)
            req_seen = next((t for t, tp, q, _ in seen if q == rq and "/req/" in tp), None)
            rsp_seen = next((t for t, tp, q, _ in seen if q == rq and "/resp/" in tp), None)
            ntf_seen = next((t for t, tp, q, mk in seen if mk == marker and "/req/" in tp), None)
            f = lambda x: None if x is None else round((x - t0) * 1e3, 3)  # noqa: E731
            rows.append(dict(req_at_broker_ms=f(req_seen), resp_at_broker_ms=f(rsp_seen), resp_at_client_ms=f(r.t_resp),
                             notif_at_broker_ms=f(ntf_seen), notif_at_client_ms=f(got.t_recv if got else None)))
        m.request(dict(op=4, to=f"{cse_rn}/{ae_rn}", fr=origin, rqi=rqi(), rvi=RVI))
    finally:
        m.close()
        sn.disconnect()
        sn.loop_stop()
    keys = list(rows[0]) if rows else []
    return dict(rows=rows, median_ms={k_: (summarize([r_[k_] for r_ in rows if r_[k_] is not None]) or {}).get("median")
                                      for k_ in keys},
                note="times from sending the CIN CREATE; *_at_broker = when the broker delivered the PUBLISH to a "
                     "sniffer subscribed to /oneM2M/# (approximately when it forwarded it to the CSE / to us)")


# ------------------------------------------------------------------------------------------------ summary
def _vproto(vk: str) -> tuple[str, bool]:
    v = next((x for x in VARIANTS if x.key == vk), None)
    proto = v.proto if v else vk.split("/")[0].split("-")[0]
    return proto, proto in ("https", "wss")


def _lat_key(s: dict) -> str:
    return s["op"] + (f"[{s['size']}]" if s.get("size") else "")


def build_summary(workloads: list[dict]) -> dict:
    """Statistics over the measured workloads (warm-ups and controls excluded). Latency: direct pass, OK samples,
    ops without a retried WebSocket handshake; what is left out is counted per cell in latency_excluded."""
    real = [w for w in workloads if not w.get("warmup") and not w.get("control")]
    summ: dict[str, Any] = {"latency_ms": {}, "latency_excluded": {}, "bytes": {}, "setup": {}, "notify": {},
                            "notify_split": {}, "cse_cpu_ms_per_workload": {}, "stability": {}, "selfcheck": {},
                            "selfcheck_classes": {"exact": 0, "exact_flagged": 0, "lower_bound": 0,
                                                  "lower_bound_tls": 0, "lower_bound_new_connection": 0,
                                                  "lower_bound_flagged": 0, "not_checked": 0},
                            "wrong_originator": {}, "failures": {}}
    by_v: dict[str, list[dict]] = {}
    for w in real:
        by_v.setdefault(w["variant"], []).append(w)
    for vk, ws in by_v.items():
        proto, tls = _vproto(vk)
        direct = [w for w in ws if not w["proxied"]]
        prox = [w for w in ws if w["proxied"]]
        lat: dict[str, list[float]] = {}
        excl: dict[str, dict[str, int]] = {}
        for w in direct:
            for s in w["samples"]:
                if "lat" not in s or s["op"] in ("connect", "notify_abandoned"):
                    continue
                k = _lat_key(s)
                if "connect_retry" in s:
                    excl.setdefault(k, {"connect_retry": 0, "not_ok": 0})["connect_retry"] += 1
                elif not s.get("ok"):
                    if s["op"] == "notify" and s.get("rsc") == 2001:   # create fine, notification missing: not a latency exclusion
                        lat.setdefault(k, []).append(s["lat"] * 1e3)
                    else:
                        excl.setdefault(k, {"connect_retry": 0, "not_ok": 0})["not_ok"] += 1
                else:
                    lat.setdefault(k, []).append(s["lat"] * 1e3)
        summ["latency_ms"][vk] = {k: summarize(v) for k, v in sorted(lat.items())}
        if excl:
            summ["latency_excluded"][vk] = excl
        byt: dict[str, dict[str, list[int]]] = {}
        for w in prox:
            for s in w["samples"]:
                if "wc" in s and s["op"] != "notify_abandoned":
                    d = byt.setdefault(_lat_key(s), {"c2s": [], "s2c": [], "conns": []})
                    d["c2s"].append(s["wc"])
                    d["s2c"].append(s["ws"])
                    d["conns"].append(s.get("acc", 0))
                    for leg in ("leg_wc", "leg_ws", "poll_wc", "poll_ws"):
                        if leg in s:
                            d.setdefault(leg, []).append(s[leg])
                    # which byte check applied (same rule as do_op / notify_ops)
                    sc = summ["selfcheck_classes"]
                    if s["op"] == "connect" or s.get("ac") is None:
                        sc["not_checked"] += 1
                    elif tls or not ((not s.get("conns")) or proto == "http"):
                        sc["lower_bound"] += 1
                        sc["lower_bound_tls" if tls else "lower_bound_new_connection"] += 1
                        sc["lower_bound_flagged"] += bool(s.get("selfcheck"))
                    else:
                        sc["exact"] += 1
                        sc["exact_flagged"] += bool(s.get("selfcheck"))
        summ["bytes"][vk] = {k: {kk: (summarize(vv)["median"] if vv else None) for kk, vv in d.items()}
                             for k, d in sorted(byt.items())}
        st: dict[str, list[float]] = {}
        for w in direct:
            for s in w["samples"]:
                for k, val in (s.get("setup") or {}).items():
                    if isinstance(val, (int, float)) and k != "retried_after_s":
                        st.setdefault(("open." if s["op"] == "connect" else "per_op.") + k, []).append(val * 1e3)
        summ["setup"][vk] = {k: summarize(v) for k, v in sorted(st.items())}
        nd = [s for w in direct for s in w["samples"] if s["op"] == "notify"]
        if nd:
            dl = lambda xs: summarize([s["delay"] * 1e3 for s in xs if s["delay"] is not None])  # noqa: E731
            summ["notify"][vk] = dict(attempted=len(nd), delivered=sum(1 for s in nd if s["delay"] is not None),
                                      via=sorted({s["via"] for s in nd if s.get("via")}), delay_ms=dl(nd),
                                      delay_ms_small=dl([s for s in nd if s["size"] == "small"]),
                                      delay_ms_large=dl([s for s in nd if s["size"] == "large"]),
                                      abandoned=sum(1 for w in direct for s in w["samples"] if s["op"] == "notify_abandoned"),
                                      not_ok_creates=sum(1 for s in nd if s.get("rsc") not in (2001, None)))
            per_w = lambda wl: [[s for s in w["samples"] if s["op"] == "notify"] for w in wl]  # noqa: E731
            first_all = [n[0] for n in per_w(ws) if n]
            later_d = [s for n in per_w(direct) for s in n[1:]]
            later_p = [s for n in per_w(prox) for s in n[1:]]
            ok_lat = lambda xs: summarize([s["lat"] * 1e3 for s in xs if s.get("rsc") == 2001])  # noqa: E731
            summ["notify_split"][vk] = dict(
                first_delay_ms=dl(first_all), first_delay_ms_direct=dl([n[0] for n in per_w(direct) if n]),
                later_delay_ms_direct=dl(later_d), later_delay_ms_proxied=dl(later_p),
                cin_response_first_ms_direct=ok_lat([n[0] for n in per_w(direct) if n]),
                cin_response_later_ms_direct=ok_lat(later_d))
        summ["cse_cpu_ms_per_workload"][vk] = summarize([w["cse_cpu_s"] * 1e3 for w in direct])
        hs = [s for w in direct for s in w["samples"] if s.get("ttfb") is not None and s["op"] == "cin_create"
              and s.get("size") == "small" and s.get("ok")]
        if hs:
            summ.setdefault("http_response_timing", {})[vk] = dict(
                ttfb_ms=summarize([x["ttfb"] * 1e3 for x in hs]), max_gap_ms=summarize([x["max_gap"] * 1e3 for x in hs]),
                rx_chunks=summarize([x["rx_chunks"] for x in hs]))
        per_rep: dict[int, list[float]] = {}
        for w in direct:
            vals = [s["lat"] * 1e3 for s in w["samples"] if s["op"] == "cin_create" and s.get("size") == "small"
                    and s.get("ok") and "connect_retry" not in s]
            per_rep.setdefault(w["rep"], []).extend(vals)
        meds = {r: summarize(v)["median"] for r, v in sorted(per_rep.items()) if v}
        summ["stability"][vk] = dict(cin_small_median_ms_per_repeat=meds,
                                     max_over_min=(max(meds.values()) / min(meds.values())) if meds else None,
                                     load1_range=[min(w["load"][0] for w in direct), max(w["load"][0] for w in direct)]
                                     if direct else None,
                                     host_busy_range=[min(w["host_busy"] for w in direct), max(w["host_busy"] for w in direct)]
                                     if direct else None)
        allp = [s for w in prox for s in w["samples"] if "wc" in s]
        summ["selfcheck"][vk] = dict(checked=len(allp), flagged=sum(1 for s in allp if s.get("selfcheck")),
                                     examples=[s["selfcheck"] for s in allp if s.get("selfcheck")][:3])
        wo = [s for w in ws for s in w["samples"] if s["op"].startswith("ctl_wrong_orig")]
        if wo:
            summ["wrong_originator"][vk] = dict(n=len(wo), rsc=sorted({s["rsc"] for s in wo}, key=str),
                                                all_4103=all(s["rsc"] == 4103 for s in wo))
        bad = [(s["op"], s.get("rsc"), s.get("st"), s.get("check")) for w in ws for s in w["samples"]
               if not s.get("ok") and s["op"] not in ("notify_abandoned",) and not s["op"].startswith("ctl_")]
        if bad:
            summ["failures"][vk] = dict(n=len(bad), examples=[list(map(str, b)) for b in bad[:5]])
        wd = [w for w in ws if "ws_unmatched_responses" in w]
        if wd:
            summ.setdefault("ws_duplicates", {})[vk] = dict(
                workloads=len(wd), dups=sum(w["ws_unmatched_responses"] for w in wd),
                odd_rsc=sum(1 for w in wd for s in w["samples"] if s.get("rsc") in (4105, 5000)))
        # WebSocket opening handshakes: connections = attempts - failed first attempts (each failure retried once)
        incl = [w for w in workloads if w["variant"] == vk and not w.get("control") and "ws_connects" in w]
        meas = [w for w in ws if "ws_connects" in w]
        if incl:
            cnt = lambda wl: (sum(w["ws_connects"]["attempts"] - len(w["ws_connects"]["failures"]) for w in wl),  # noqa: E731
                              sum(len(w["ws_connects"]["failures"]) for w in wl))
            (mc, mf), (ic, inf_) = cnt(meas), cnt(incl)
            summ.setdefault("ws_connect_stalls", {})[vk] = dict(
                connections=mc, failed=mf, connections_incl_warmup=ic, failed_incl_warmup=inf_,
                direct_ops_retried=sum(1 for w in direct for s in w["samples"] if "connect_retry" in s and s["op"] != "connect"),
                direct_open_retried=sum(1 for w in direct for s in w["samples"] if "connect_retry" in s and s["op"] == "connect"),
                examples=[f for w in meas for f in w["ws_connects"]["failures"]][:4])
    return summ


def fmt(x: Optional[float], nd: int = 2) -> str:
    return "-" if x is None else f"{x:.{nd}f}"


def _g(d: Optional[dict], *ks, default=None):
    for k in ks:
        if not isinstance(d, dict) or k not in d or d[k] is None:
            return default
        d = d[k]
    return d


def key_findings(rec: dict) -> list[str]:
    """Short statements with every number computed from this record (variants missing in a subset run are skipped)."""
    s = rec["summary"]
    L: list[str] = []
    lm = lambda vk, k, f="median": _g(s, "latency_ms", vk, k, f)  # noqa: E731
    h, p = lm("https/reuse", "cin_create[small]"), lm("http/reuse", "cin_create[small]")
    if h and p:
        tls = _g(s, "setup", "https/reuse", "per_op.tls_s", "median")
        tt_h = _g(s, "http_response_timing", "https/reuse", "ttfb_ms", "median")
        tt_p = _g(s, "http_response_timing", "http/reuse", "ttfb_ms", "median")
        line = (f"HTTPS: ACME's built-in HTTPS server (werkzeug with TLS): CIN 100 B create {fmt(h, 1)} ms vs "
                f"{fmt(p, 1)} ms over its plain HTTP server. The server closes every connection, so each request "
                f"includes a TLS handshake, ~{fmt(tls, 1)} ms of the difference")
        if tt_h and tt_p:
            line += (f"; ~{fmt(tt_h - tt_p, 1)} ms more is server time before the first response byte "
                     f"({fmt(tt_h, 2)} vs {fmt(tt_p, 2)} ms after the request was sent), not explained by this run")
        k, f = lm("wss/reuse", "cin_create[small]"), lm("wss/fresh", "cin_create[small]")
        if k and f:
            line += f". wss on the same CSE: {fmt(k, 1)} ms on a kept connection, {fmt(f, 1)} ms with a new TLS connection per request"
        L.append(line + ".")
    r_, f_ = lm("http-wsgi/reuse", "cin_create[small]"), lm("http-wsgi/fresh", "cin_create[small]")
    if r_ and f_:
        sr = list(_g(s, "stability", "http-wsgi/reuse", "cin_small_median_ms_per_repeat", default={}).values())
        sf = list(_g(s, "stability", "http-wsgi/fresh", "cin_small_median_ms_per_repeat", default={}).values())
        line = (f"HTTP keep-alive: only with WSGI (CSE-W, waitress); not with ACME's built-in server, and a "
                f"TLS-terminating proxy in front of WSGI was not tested. On loopback, CIN 100 B {fmt(r_)} ms kept vs "
                f"{fmt(f_)} ms new connection per request")
        if sr and sf:
            line += (f"; per-repeat medians {fmt(min(sr))}-{fmt(max(sr))} vs {fmt(min(sf))}-{fmt(max(sf))} ms, so "
                     f"the difference is within the run-to-run spread")
        L.append(line + ".")
    ns = _g(s, "notify_split", "mqtt/reuse")
    if ns:
        fa, ld, lp = ns["first_delay_ms"], ns["later_delay_ms_direct"], ns["later_delay_ms_proxied"]
        cf, cl = ns["cin_response_first_ms_direct"], ns["cin_response_later_ms_direct"]
        oc = lm("mqtt/reuse", "cin_create[small]")
        aed = lm("mqtt/reuse", "ae_delete")
        others = [lm(vk, "ae_delete") for vk in ("http/reuse", "https/reuse", "ws/reuse", "wss/reuse", "coap/reuse",
                                                 "http-wsgi/reuse") if lm(vk, "ae_delete")]
        line = "MQTT: "
        if fa:
            line += (f"the first notification in a workload arrives after {fmt(fa['median'], 1)} ms "
                     f"({fmt(fa['min'], 1)}-{fmt(fa['max'], 1)}, n={fa['n']}, direct + proxied)")
        if ld:
            line += f"; later ones after {fmt(ld['median'], 1)} ms direct (p95 {fmt(ld['p95'], 1)}, n={ld['n']})"
        if lp:
            line += f" / {fmt(lp['median'], 1)} ms proxied (n={lp['n']})"
        L.append(line + ".")
        if cf and cl and oc:
            line = (f"MQTT notification phase: the CIN CREATE response itself takes {fmt(cl['median'], 1)} ms for "
                    f"creates after the first notification (n={cl['n']}) vs {fmt(cf['median'], 1)} ms for the first one and "
                    f"{fmt(oc, 1)} ms for ordinary creates")
            if aed and others:
                line += (f"; the MQTT AE delete after it takes {fmt(aed, 1)} ms vs {fmt(min(others), 1)}-"
                         f"{fmt(max(others), 1)} ms on the other bindings")
            L.append(line + ".")
        mp = _g(rec, "diagnostics", "mqtt_path", "median_ms")
        line = ("MQTT, what is known about the stall: Nagle is on in both ACME's broker socket (paho 2.1.0 does not "
                "set TCP_NODELAY) and mosquitto's (set_tcp_nodelay not set; its default is false); our client sets "
                "TCP_NODELAY")
        if mp:
            line += (f". With isolated writes (diagnostic, k=8) the CSE's response reaches the broker after "
                     f"{fmt(mp.get('resp_at_broker_ms'), 1)} ms and its notification after "
                     f"{fmt(mp.get('notif_at_broker_ms'), 1)} ms")
        line += (". A separate debug-log probe showed ACME handing the notification to its MQTT client in the same "
                 "millisecond as the response (logged before it). Where the time goes is not localized and not proven.")
        L.append(line)
    cs = _g(s, "ws_connect_stalls")
    if cs:
        wss = [d for vk, d in cs.items() if vk.startswith("wss/")]
        wsp = [d for vk, d in cs.items() if vk.startswith("ws/")]
        tot = lambda ds, k: sum(d[k] for d in ds)  # noqa: E731
        if wss:
            line = (f"WebSocket opening handshakes: wss {tot(wss, 'failed')} of {tot(wss, 'connections')} connections "
                    f"in measured workloads ({tot(wss, 'failed_incl_warmup')} of {tot(wss, 'connections_incl_warmup')} "
                    f"including warm-ups) got no answer for 10 s; each was retried once")
            if wsp:
                line += (f"; ws {tot(wsp, 'failed')} of {tot(wsp, 'connections')} ({tot(wsp, 'failed_incl_warmup')} of "
                         f"{tot(wsp, 'connections_incl_warmup')} including warm-ups)")
            line += (f". In the direct pass {tot(wss, 'direct_ops_retried')} ops and {tot(wss, 'direct_open_retried')} "
                     f"connection open had a 10 s retry; they are left out of the latency cells (footnoted).")
            L.append(line)
    dup = _g(s, "ws_duplicates")
    if dup:
        reuse = {vk: d for vk, d in dup.items() if vk.endswith("/reuse")}
        no_ok = sum(sum(x["not_ok"] for x in _g(s, "latency_excluded", vk, default={}).values()) for vk in reuse)
        L.append("WebSocket duplicate processing: " + "; ".join(
            f"{vk} {d['dups']} duplicate responses in {d['workloads']} workloads, {d['odd_rsc']} ops answered 4105/5000"
            for vk, d in dup.items()) + f". The {no_ok} non-OK ops in the direct pass are left out of the latency cells.")
    cp = _g(s, "notify", "coap/reuse")
    if cp:
        pch = _g(s, "notify", "coap-pch/reuse", "delay_ms", "median")
        L.append(f"CoAP push: {cp['delivered']} of {cp['attempted']} notifications delivered (direct pass; ACME's CoAP "
                 f"sender has no method for NOTIFY)" + (f"; pollingChannel over CoAP {fmt(pch, 1)} ms median" if pch else "") +
                 f". CoAP 4 KB: CIN create {fmt(lm('coap/reuse', 'cin_create[large]'), 1)} ms, retrieve la "
                 f"{fmt(lm('coap/reuse', 'retrieve_la[large]'), 1)} ms (block-wise).")
    return L


def summary_markdown(rec: dict) -> str:
    s = rec["summary"]
    p = rec["params"]
    L = [f"# Protocol bench {rec['started_utc']} (ACME {rec['software']['acme']})", "",
         f"Same oneM2M workload per binding; {p['repeats']} repeats x {p['rounds']} interleaved rounds, "
         f"{p['n_cin']} contentInstances per workload ({SIZES['small']} B / {SIZES['large']} B con, alternating), "
         f"{p['k_notify']} notifications per workload. Latency from the direct pass (no proxy), bytes from the "
         f"proxied pass (L4 payload at a counting proxy). Host: {rec['host']['cpu_count']} CPUs, load1 "
         f"{fmt(rec['host']['load1_min'])}-{fmt(rec['host']['load1_max'])}. Raw record: `{rec['_json_name']}`.", ""]
    if rec.get("caveats"):
        L += ["## Record-specific caveats", ""] + [f"- {x}" for x in rec["caveats"]] + [""]
    L += ["## Findings (numbers from this record)", ""] + [f"- {x}" for x in key_findings(rec)]
    notes: list[str] = []

    def foot(vk: str, k: str) -> str:
        e = _g(s, "latency_excluded", vk, k)
        if not e:
            return ""
        parts = []
        if e["connect_retry"]:
            parts.append(f"excluding {e['connect_retry']} op(s) whose WebSocket opening handshake got no answer for 10 s")
        if e["not_ok"]:
            parts.append(f"excluding {e['not_ok']} op(s) answered with an error (4105/5000, duplicate processing)")
        notes.append(f"{vk} {k}: " + "; ".join(parts))
        return f" [{len(notes)}]"

    def cell(vk: str, d: dict, k: str) -> str:
        x = d.get(k)
        c = "-" if not x else f"{fmt(x['median'])} / {fmt(x['p95'])} / {fmt(x['p99'])} / {fmt(x['max'])} ({x['n']})"
        return c + foot(vk, k)

    L += ["", "## Latency per operation (ms, median / p95 / p99 / max, n)", "",
          "| variant | AE create | CNT create | CIN 100 B | CIN 4 KB | retrieve la | discovery | AE delete |",
          "|---|---|---|---|---|---|---|---|"]
    for vk, d in s["latency_ms"].items():
        la = "retrieve_la[large]" if "retrieve_la[large]" in d else "retrieve_la[small]"
        L.append(f"| {vk} | {cell(vk, d, 'ae_create')} | {cell(vk, d, 'cnt_create')} | {cell(vk, d, 'cin_create[small]')} | "
                 f"{cell(vk, d, 'cin_create[large]')} | {cell(vk, d, la)} | {cell(vk, d, 'discovery')} | "
                 f"{cell(vk, d, 'ae_delete')} |")
    L += ["", "Cells with n=12 (one sample per workload) have p95/p99 interpolated between the two largest values "
          "(linear interpolation); read them as 'near the max'. The retrieve la column is the 4 KB instance. "
          "OK responses only; errors and retried handshakes are footnoted."]
    L += [f"[{i}] {t}" for i, t in enumerate(notes, 1)]
    L += ["", "## Bytes on the wire per operation (median, client->CSE / CSE->client; connections opened)", "",
          "| variant | open (setup) | AE create | CIN 100 B | CIN 4 KB | retrieve la | discovery | notify (main conn) | notify leg / poll conn |",
          "|---|---|---|---|---|---|---|---|---|"]
    for vk, d in s["bytes"].items():
        def b(k):
            x = d.get(k)
            return "-" if not x else f"{x['c2s']:.0f} / {x['s2c']:.0f}" + (f" ({x['conns']:.0f}c)" if x.get("conns") else "")
        nl = d.get("notify[small]") or {}
        leg = "-"
        if nl.get("leg_wc") is not None:
            leg = f"{nl['leg_wc']:.0f} / {nl['leg_ws']:.0f} (CSE->rcv / rcv->CSE, small)"
        elif nl.get("poll_wc") is not None:
            leg = f"{nl['poll_wc']:.0f} / {nl['poll_ws']:.0f} (poll conn, small)"
        la = "retrieve_la[large]" if "retrieve_la[large]" in d else "retrieve_la[small]"
        L.append(f"| {vk} | {b('connect')} | {b('ae_create')} | {b('cin_create[small]')} | {b('cin_create[large]')} | "
                 f"{b(la)} | {b('discovery')} | {b('notify[small]')} | {leg} |")
    L += ["", "## Connection setup (ms, median / p95; from the successful attempt)", "",
          "| variant | measure | median | p95 | n |", "|---|---|---|---|---|"]
    for vk, d in s["setup"].items():
        for k, x in d.items():
            if x:
                L.append(f"| {vk} | {k} | {fmt(x['median'], 3)} | {fmt(x['p95'], 3)} | {x['n']} |")
    L += ["", "## Write-to-notification delay (ms, from sending the CIN CREATE to the notification in our code)", "",
          "| variant | via | delivered / attempted (direct) | first in workload, median (min-max, n; direct+proxied) | "
          "later, direct: median / p95 (n) | later, proxied: median | CIN response in notify phase, direct: first / later | all, direct: median / p95 / p99 / max |",
          "|---|---|---|---|---|---|---|---|"]
    for vk, d in s["notify"].items():
        x = d["delay_ms"] or {}
        ns = s["notify_split"].get(vk, {})
        fa, ld, lp = ns.get("first_delay_ms") or {}, ns.get("later_delay_ms_direct") or {}, ns.get("later_delay_ms_proxied") or {}
        cf, cl = ns.get("cin_response_first_ms_direct") or {}, ns.get("cin_response_later_ms_direct") or {}
        first = (f"{fmt(fa['median'])} ({fmt(fa['min'])}-{fmt(fa['max'])}, {fa['n']})" if fa else "-")
        later = (f"{fmt(ld['median'])} / {fmt(ld['p95'])} ({ld['n']})" if ld else "-")
        odd = f" ({d['not_ok_creates']} of the creates answered 4105)" if d.get("not_ok_creates") else ""
        L.append(f"| {vk} | {','.join(d['via']) or '-'} | {d['delivered']} / {d['attempted']}{odd} | {first} | {later} | "
                 f"{fmt(lp.get('median'))} | {fmt(cf.get('median'))} / {fmt(cl.get('median'))} | "
                 f"{fmt(x.get('median'))} / {fmt(x.get('p95'))} / {fmt(x.get('p99'))} / {fmt(x.get('max'))} |")
    ns = s["notify_split"].get("mqtt/reuse")
    if ns:
        oc = _g(s, "latency_ms", "mqtt/reuse", "cin_create[small]") or {}
        ae = _g(s, "latency_ms", "mqtt/reuse", "ae_delete") or {}
        rows = [("first notification in a workload (direct + proxied)", ns.get("first_delay_ms")),
                ("later notifications, direct", ns.get("later_delay_ms_direct")),
                ("later notifications, proxied", ns.get("later_delay_ms_proxied")),
                ("CIN CREATE response, first create of the notify phase (direct)", ns.get("cin_response_first_ms_direct")),
                ("CIN CREATE response, later creates of the notify phase (direct)", ns.get("cin_response_later_ms_direct")),
                ("CIN 100 B CREATE response outside the notify phase (direct)", oc),
                ("AE delete after the notify phase (direct)", ae)]
        L += ["", "## MQTT timing in detail (ms)", "", "| what | median | p95 | min | max | n |", "|---|---|---|---|---|---|"]
        for name, x in rows:
            if x:
                L.append(f"| {name} | {fmt(x['median'])} | {fmt(x['p95'])} | {fmt(x['min'])} | {fmt(x['max'])} | {x['n']} |")
    L += ["", "## Stability (CIN 100 B create, median ms per repeat; CSE CPU per workload)", "",
          "| variant | per repeat | max/min | load1 range | host busy | CSE CPU ms / workload (median) |", "|---|---|---|---|---|---|"]
    for vk, d in s["stability"].items():
        cpu = s["cse_cpu_ms_per_workload"].get(vk) or {}
        L.append(f"| {vk} | {', '.join(fmt(v) for v in d['cin_small_median_ms_per_repeat'].values())} | "
                 f"{fmt(d['max_over_min'])} | {d['load1_range'] and '-'.join(fmt(x) for x in d['load1_range'])} | "
                 f"{d['host_busy_range'] and '-'.join(f'{x:.0%}' for x in d['host_busy_range'])} | {fmt(cpu.get('median'), 0)} |")
    L += ["", "CSE CPU compares only variants with the same operations: the reuse variants include the subscription and "
          f"{p['k_notify']} notifications; fresh variants have no notification phase; pollingChannel variants have no "
          "CIN/la/discovery phase (not comparable); coap/reuse has one push probe instead of the notifications."]
    if s.get("http_response_timing"):
        L += ["", "## HTTP response timing, CIN 100 B create (ms, median / p95): time from sending the request to the "
              "first response byte, largest gap between response chunks, recv chunks", "",
              "| variant | total | to first byte | largest gap | chunks |", "|---|---|---|---|---|"]
        for vk, d in s["http_response_timing"].items():
            tot = s["latency_ms"].get(vk, {}).get("cin_create[small]") or {}
            L.append(f"| {vk} | {fmt(tot.get('median'))} | {fmt(d['ttfb_ms']['median'])} / {fmt(d['ttfb_ms']['p95'])} | "
                     f"{fmt(d['max_gap_ms']['median'])} / {fmt(d['max_gap_ms']['p95'])} | {fmt(d['rx_chunks']['median'], 0)} |")
    if s.get("ws_connect_stalls"):
        L += ["", "## WebSocket opening handshakes with no answer for 10 s (each retried once)", "",
              "| variant | connections (measured) | no answer | connections incl. warm-ups | no answer | direct-pass ops / opens retried | example |",
              "|---|---|---|---|---|---|---|"]
        for vk, d in s["ws_connect_stalls"].items():
            ex = d["examples"][0] if d["examples"] else {}
            L.append(f"| {vk} | {d['connections']} | {d['failed']} | {d['connections_incl_warmup']} | {d['failed_incl_warmup']} | "
                     f"{d['direct_ops_retried']} / {d['direct_open_retried']} | "
                     f"{ex.get('err', '-')}{(' after ' + str(ex.get('elapsed_s')) + ' s') if ex else ''} |")
    if s.get("ws_duplicates"):
        L += ["", "## WebSocket duplicate responses (same rqi answered twice)", "",
              "| variant | workloads | duplicate responses | ops with rsc 4105/5000 |", "|---|---|---|---|"]
        for vk, d in s["ws_duplicates"].items():
            L.append(f"| {vk} | {d['workloads']} | {d['dups']} | {d['odd_rsc']} |")
    L += ["", "## Controls", ""]
    for k, v in rec["controls"].items():
        L.append(f"- **{k}**: pass = {v.get('pass') if isinstance(v, dict) else v}")
    wo = s["wrong_originator"]
    if wo:
        L.append("- **wrong originator, every binding**: " + "; ".join(
            f"{vk} {d['rsc']}" for vk, d in wo.items()) + f" -> all 4103: {all(d['all_4103'] for d in wo.values())}")
    sc = s.get("selfcheck_classes") or {}
    if sc:
        L.append(f"- **byte self-check on all proxied samples**: exact equality {sc['exact']} (flagged "
                 f"{sc['exact_flagged']}); lower bound {sc['lower_bound']} (TLS: wire >= app + 22 B, "
                 f"{sc['lower_bound_tls']}; new ws connection incl. upgrade/close, {sc['lower_bound_new_connection']}; "
                 f"flagged {sc['lower_bound_flagged']}); not checked {sc['not_checked']} (connect samples, no app bytes)")
    if s["failures"]:
        L += ["", "## Operations that did not return the expected result", ""]
        for vk, d in s["failures"].items():
            L.append(f"- {vk}: {d['n']} e.g. {d['examples'][:3]}")
    dg = rec.get("diagnostics") or {}
    if dg.get("client_crosscheck_ms"):
        L += ["", "## Diagnostic: our HTTP client vs `requests` (GET CSEBase, ms median / p95)", "",
              "| CSE | ours, new connection | requests, new connection | requests.Session |", "|---|---|---|---|"]
        for k, d in dg["client_crosscheck_ms"].items():
            L.append(f"| {k} | " + " | ".join(f"{fmt(d[x]['median'])} / {fmt(d[x]['p95'])}"
                                             for x in ("ours_fresh", "requests_new", "requests_session")) + " |")
    if dg.get("mqtt_path"):
        mp = dg["mqtt_path"]["median_ms"]
        L += ["", "## Diagnostic: MQTT path with isolated writes (median ms from sending the CIN CREATE, k=8)", "",
              "| request at broker | response at broker | response at client | notification at broker | notification at client |",
              "|---|---|---|---|---|",
              "| " + " | ".join(fmt(mp.get(k)) for k in ("req_at_broker_ms", "resp_at_broker_ms", "resp_at_client_ms",
                                                         "notif_at_broker_ms", "notif_at_client_ms")) + " |",
              "", "'at broker' = when the broker delivered the PUBLISH to a sniffer subscribed to /oneM2M/#. These "
              "timestamps do not say where between ACME and the broker the time is spent."]
    L += ["", "## Not measured / limits", ""] + [f"- {x}" for x in rec["limits"]]
    return "\n".join(L) + "\n"


def versions() -> dict:
    def run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10, env={}).stdout.strip() or \
                subprocess.run(cmd, capture_output=True, text=True, timeout=10, env={}).stderr.strip()
        except Exception as e:
            return f"? {e}"
    import paho.mqtt
    import websockets
    import importlib.metadata
    try:
        acme_v = importlib.metadata.version("acmecse")
    except importlib.metadata.PackageNotFoundError:
        acme_v = "?"
    return dict(acme=acme_v, python=sys.version.split()[0], python_exe=sys.executable,
                websockets=websockets.__version__, paho=paho.mqtt.__version__, openssl_py=ssl.OPENSSL_VERSION,
                openssl_cli=run([OPENSSL, "version"]), mosquitto=run([MOSQUITTO, "-h"]).splitlines()[0][:80],
                kernel=platform.release())


def top_cpu_snapshot() -> list[str]:
    try:
        out = subprocess.run(["ps", "-eo", "pcpu,comm", "--sort=-pcpu"], capture_output=True, text=True, timeout=5).stdout
        return [ln.strip() for ln in out.splitlines()[1:9]]
    except Exception:
        return []


def acme_log_digest(root: Path, secrets_: list[str]) -> dict:
    out = {}
    for base in sorted(root.glob("cse-*")):
        lines: dict[str, int] = {}
        for p in sorted((base / "logs").glob("*.log*")):
            for ln in p.read_text(errors="replace").splitlines():
                if "WARNING" in ln or "ERROR" in ln:
                    msg = re.sub(r"\b[0-9a-f]{6,}\b|rq[0-9a-f]+|C[a-z]+[0-9a-f]{6}|\d+(\.\d+)?", "#", ln.split("]", 3)[-1])[:160]
                    for sct in secrets_:
                        msg = msg.replace(sct, "<redacted>")
                    lines[msg.strip()] = lines.get(msg.strip(), 0) + 1
        out[base.name] = sorted(([n, m] for m, n in lines.items()), reverse=True)[:25]
    return out


LIMITS = [
    "HTTP: ACME's built-in HTTP server (werkzeug 3.1.8 development server, used when [http.wsgi] is off) sends "
    "'Connection: close' on every response, so http/reuse and https/reuse open a new TCP (and TLS) connection for "
    "every request. Keep-alive HTTP was measured on CSE-W (same ACME, [http.wsgi] enable=true, waitress). ACME refuses "
    "WSGI together with TLS, so HTTPS keep-alive is not available with ACME's built-in server; a TLS-terminating proxy "
    "in front of WSGI was not tested.",
    "CoAP push: a notification to a coap:// poa is never sent (ACME logs 'Creating new CoAP client' and nothing "
    "after; its CoAP sender maps only CREATE/RETRIEVE/UPDATE/DELETE to methods, CoAPthonTools.operationsMethodsMap has "
    "no NOTIFY). coap/reuse therefore has no push numbers; the pollingChannel over CoAP (coap-pch) works.",
    "WebSocket: ACME's receive loop hands each frame to a worker as `lambda: _handleReceivedMessage(websocket, "
    "message, ...)`; `message` is read when the worker runs, so two frames arriving back-to-back can be processed as "
    "the second frame twice (and the first lost). Our client answers each pushed notification at once and then sends "
    "its next request, which triggers this; duplicate responses are counted (ws_unmatched_responses), not hidden.",
    "ACME 2026.5.3 runs one HTTP server (plain OR TLS) and one WS server (ws OR wss) per process, so http/ws/mqtt/coap "
    "ran on CSE-P and https/wss on CSE-T: same version, same ini apart from the TLS flags and IDs/ports.",
    "Bytes are L4 payload (TCP stream / UDP datagram) at a counting proxy; IP/TCP/UDP headers, TCP ACKs and the "
    "TCP handshake segments are not included.",
    "MQTT bytes are the client<->broker leg only; the broker relays each PUBLISH to the CSE over a second "
    "connection (CSE<->broker leg, not counted). QoS 0 both ways (ACME's default); no MQTT TLS.",
    "MQTT timing: Nagle is on in ACME's broker socket (paho 2.1.0 does not set TCP_NODELAY) and in mosquitto's "
    "(set_tcp_nodelay not set in our conf; mosquitto's default is false); our MQTT client sets TCP_NODELAY. The "
    "extra time on MQTT notifications and on notify-phase and AE-delete responses is reported as measured; where it "
    "arises between ACME, its paho client and the broker is not localized, and its cause is not proven.",
    "CoAP without DTLS (ACME's client side says 'CoAP security is not yet supported'; no DTLS client in the stdlib). "
    "No CoAP fresh/reuse distinction (connectionless).",
    "ws/wss: our client does not negotiate permessage-deflate and sends no keepalive pings; ACME's server would accept "
    "deflate, which would change ws byte counts.",
    "fresh mode (one connection per request) was run for http/https/ws/wss; MQTT and CoAP have no per-request "
    "connection in their normal use. Notifications were measured in reuse mode only.",
    "ACME startup race (observed 2026-11-21): an HTTP request that reaches a starting CSE before its plugins have "
    "registered their Flask routes aborts the startup ('add_url_rule ... It has already handled its first request'). "
    "The harness sends nothing until all of the CSE's listeners exist + 2 s, and records every start retry "
    "(start_retries); the first full-run attempt was aborted by this and is kept as *_ABORTED_startup_race.json.",
    "Latency of the proxied pass is not used for the latency tables (the proxy runs in the client's process); the "
    "direct pass has no proxy. Proxied notification delays are shown separately where they differ.",
    "Another agent was running lab tests on the same host during this run; both disturb each other's timing. load1 "
    "and host CPU busy fraction are recorded per workload.",
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--n-cin", type=int, default=20)
    ap.add_argument("--k-notify", type=int, default=10)
    ap.add_argument("--variants", default="all", help="comma list of variant keys, or 'all'")
    ap.add_argument("--seed", type=int, default=20261121)
    ap.add_argument("--no-controls", action="store_true")
    ap.add_argument("--out", default=str(OUT_DIR))
    ap.add_argument("--tag", default="")
    ap.add_argument("--keep-logs", default="", help="copy ACME/broker logs (no keys) to this dir before cleanup")
    a = ap.parse_args(argv)
    variants = VARIANTS if a.variants == "all" else [v for v in VARIANTS if v.key in a.variants.split(",")]
    if ROOT.exists():
        raise SystemExit(f"{ROOT} exists (an earlier run?); inspect and remove it first")
    ports_free_or_die()
    ROOT.mkdir(mode=0o700)
    (ROOT / ".proto_bench").write_text(str(os.getpid()))
    make_payloads(a.seed)
    rng = random.Random(a.seed)
    rec: dict[str, Any] = dict(schema="proto_bench/1", started_utc=utc(), argv=sys.argv,
                               coap_block2_followups="same options as the first request + Block2 (RFC 7959 2.4)",
                               params=dict(repeats=a.repeats, rounds=a.rounds, n_cin=a.n_cin, k_notify=a.k_notify,
                                           seed=a.seed, variants=[v.key for v in variants], sizes=SIZES,
                                           body_bytes={k: len(jdump({"m2m:cin": {"cnf": "text/plain:0", "con": PAYLOAD[k],
                                                                                   "lbl": [f"bench:{k}"]}}))
                                                       for k in SIZES}),
                               host=dict(cpu_count=os.cpu_count(), load_start=os.getloadavg(),
                                         os=f"{platform.system()} {platform.release()} {platform.machine()}",
                                         top_cpu_start=top_cpu_snapshot()),
                               software=versions(), ports=PORTS, workloads=[], controls={}, repeats=[])
    env = Env(ROOT)
    stopping = {"sig": None}

    def on_sig(signum, frame):
        stopping["sig"] = signum
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_sig)
    rc = 0
    try:
        env.setup()
        rec["config"] = env.redacted_inis()
        rec["tls"] = dict(server_cert="ECDSA P-256 leaf, CN/SAN IP 127.0.0.1, 1 day, signed by a throwaway P-256 CA "
                          "made with the openssl CLI in /dev/shm/proto-acme/pki (deleted at the end)",
                          client="ssl.create_default_context(cafile=<throwaway CA>) (chain + hostname checked)",
                          server_side="ACME ssl.SSLContext(PROTOCOL_TLS) with tlsVersion=auto, verifyCertificate=false")
        for rep in range(a.repeats):
            rinfo: dict[str, Any] = dict(rep=rep, t_utc=utc())
            rinfo["start"] = env.start_services("PTW")
            push_ok: dict[str, bool] = {}
            rinfo["pids"] = {k: c.pid for k, c in env.children.items()}
            for v in variants:            # warm-up (recorded, excluded from the statistics)
                m = run_workload(env, v, False, 4, 2)
                m.update(rep=rep, round=-1, warmup=True)
                rec["workloads"].append(m)
                nt = [s for s in m["samples"] if s["op"] == "notify"]
                push_ok[v.key] = (not nt) or any(s.get("delay") is not None for s in nt)
                print(f"rep {rep} warmup {v.key:16} {m['dur_s']:6.2f}s open_failed={m.get('open_failed')} "
                      f"bad {sum(1 for s in m['samples'] if not s.get('ok') and not s['op'].startswith('ctl_'))}", flush=True)
            for rnd in range(a.rounds):
                tasks = [(v, px) for v in variants for px in (False, True)]
                rng.shuffle(tasks)
                rinfo.setdefault("orders", []).append([f"{v.key}{'+proxy' if px else ''}" for v, px in tasks])
                for v, px in tasks:
                    m = run_workload(env, v, px, a.n_cin, a.k_notify, push_ok.get(v.key, True))
                    m.update(rep=rep, round=rnd)
                    rec["workloads"].append(m)
                    print(f"rep {rep} round {rnd} {v.key:16} {'proxied' if px else 'direct ':7} "
                          f"{m['dur_s']:6.2f}s load1 {m['load'][0]:.2f} "
                          f"bad {sum(1 for s in m['samples'] if not s.get('ok') and not s['op'].startswith('ctl_'))}",
                          flush=True)
            if rep == a.repeats - 1 and not a.no_controls:
                rec["controls"]["wrong_ca_rejected_by_client"] = control_wrong_ca(env)
                rec["controls"]["mqtt_wrong_topic_and_originator"] = control_mqtt_topics(env)
                rec["controls"]["planted_byte_counter_fault"] = control_planted_fault(env)
                rec["diagnostics"] = dict(client_crosscheck_ms=control_client_crosscheck(env),
                                          mqtt_path=diag_mqtt_path(env))
                rec["controls"]["disabled_binding_refuses"] = control_disabled_bindings(env)
            rinfo["coap_receiver_seen"] = env.receivers["coap"].raw[:5]
            rinfo["push_ok_after_warmup"] = push_ok
            rinfo["log_digest"] = acme_log_digest(ROOT, list(env.secrets.values()))
            env.stop_services("PTW")
            rec["repeats"].append(rinfo)
    except KeyboardInterrupt:
        rec["interrupted"] = f"signal {stopping['sig'] or 'SIGINT'}"
        rc = 130
    except Exception:
        import traceback
        rec["error"] = traceback.format_exc()[-3000:]
        rc = 1
    finally:
        env.close_all()
        rec["stops"] = env.stops
        rec["port_waits"] = [x for x in env.port_waits if x["waited"]]
        rec["start_retries"] = env.start_retries
        rec["ephemeral_range_note"] = EPHEMERAL_NOTE
        rec["host"].update(load_end=os.getloadavg(), top_cpu_end=top_cpu_snapshot())
        loads = [w["load"][0] for w in rec["workloads"]] or [0]
        rec["host"].update(load1_min=min(loads), load1_max=max(loads))
        time.sleep(0.5)
        rec["leftover_listeners"] = our_ports_in_use()
        if a.keep_logs and ROOT.exists():
            kd = Path(a.keep_logs)
            for f in list(ROOT.glob("cse-*/logs/*")) + list(ROOT.glob("*/stdout.log")) + list(ROOT.glob("broker/*.log")):
                dst = kd / f.relative_to(ROOT)
                dst.parent.mkdir(parents=True, exist_ok=True)
                txt = f.read_text(errors="replace")
                for sct in env.secrets.values():
                    txt = txt.replace(sct, "<redacted>")
                dst.write_text(txt)
        if ROOT.exists() and (ROOT / ".proto_bench").exists():
            shutil.rmtree(ROOT)
        rec["root_removed"] = not ROOT.exists()
        rec["finished_utc"] = utc()
        rec["limits"] = LIMITS
        try:
            rec["summary"] = build_summary(rec["workloads"])
        except Exception as e:
            rec["summary_error"] = repr(e)
            rec["summary"] = None
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"proto_bench_{stamp}{('_' + a.tag) if a.tag else ''}.json"
        rec["_json_name"] = name
        (out / name).write_text(json.dumps(rec, separators=(",", ":"), default=str))
        if rec.get("summary"):
            (out / name.replace(".json", ".md")).write_text(summary_markdown(rec))
        print(f"record: {out / name}  leftover listeners: {rec['leftover_listeners']}  root removed: {rec['root_removed']}")
        if rec.get("error"):
            print(rec["error"])
    return rc


if __name__ == "__main__":
    sys.exit(main())
