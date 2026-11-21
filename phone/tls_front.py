#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""A TLS front door for one of the lab's edge CSEs (2026-11-19; pinning and limits added the same day).

The CSE keeps listening on loopback in plain HTTP. This program listens on an address a phone on the Wi-Fi network
can reach, speaks TLS 1.3 there, checks each request against what the probe app sends, and passes the ones that fit
to the CSE on loopback and the answer back.

    python3 phone/tls_front.py --listen 192.0.2.10:8443 --upstream http://127.0.0.1:8201 \
        --cert server-chain.pem --key server-key.pem --base cse-mn-a \
        --bind 192.0.2.77=Cprobe-example:phone --log front.log
    python3 phone/tls_front.py ... --self-check        # load the certificate and key, print what they are, exit
                                                       # (0; 1 when today is outside the validity dates); never binds

Why the checks: the CSE behind this door (ACME 2026.5.3) gives full rights to a request whose X-M2M-Origin is its
admin originator CAdmin, forwards a request whose path starts /~/, // or /_/ to another CSE, sends requests to any
address put in an AE's poa or a subscription's nu, and serves a web UI at /webui. An address filter alone would let
anyone holding an allowed address do all of that.

What this enforces
  * One address -> one originator -> one AE subtree. Each --bind IP=ORIGIN:RN ties one client address to one
    originator and one AE resource name under /BASE (--base). A connection from an address with no --bind is closed
    before the TLS handshake and before anything is read from it. Every request must carry exactly one X-M2M-Origin
    header, equal to that address's ORIGIN (the exact string), else 403.
  * Only the app's own requests: the table below, and nothing else (400 or 403, and the request never reaches the
    CSE). Path, method, the ty= in Content-Type, the headers passed on and the JSON body are all checked; a body must
    parse as one JSON object, with no key twice, and with exactly the keys the app sends.
  * The CSE reads the body that was checked: ACME removes what its regex takes for a comment before it parses JSON
    (its regex is copied here as ACME_COMMENT). A body that this regex would change, or whose last string ends in a
    backslash (where the regex misreads where the string ends, and is slow), is refused (400). The bytes forwarded
    are the bytes checked.
  * Never the admin: an ORIGIN that is CAdmin in any case is refused at start, and an ORIGIN must start with C.
  * Never another CSE, never an address of the client's choosing: only paths under /BASE made of [A-Za-z0-9_-]
    segments; no query string, no %, no //, /~/, /_/, /./ or /../; no poa or nu key in a body except the one nu
    of the command subscription, which must be exactly [ORIGIN] (the app's own polling channel).
  * Bounded resources: at most --max-conns connections in all and --max-conns-per-client from one bound address
    (taken without waiting; when none is free the new connection is closed and counted); a request's line and
    headers within HEAD_S, its body within BODY_S from the first attempt to read it (else 408); the upstream's
    answer at most --max-response bytes (else 502, nothing of it passed on); a thread that cannot be started, or an
    accept() that fails, does not stop the program (a failing accept() is retried after 0.1 s, not in a busy loop).

What this does NOT give
  * It does not authenticate the device. No client certificate is asked for; a --bind is a source IP address,
    which another device on the same network can take. Whoever takes over a bound address can act as that one
    device within its subtree: read and write its containers, answer its polling channel, create its own
    subscription. It cannot act as another bound device, as the admin, or outside that subtree.
  * The CSE behind it still trusts the X-M2M-Origin header as given. Anything that reaches the CSE by another way
    (loopback, another port, another front door) is not checked here.
  * TLS authenticates the server only: to a client that trusts the lab certificate authority and checks the name,
    the phone knows it talks to the holder of the server key.
  * Between this program and the CSE the traffic is plain HTTP on loopback; any local process can read or make it.
  * It does not look inside a record's content (con) and does not check the CSE's answers.
  * It does not limit the request rate: a bound client may send its allowed requests as often as it likes.
  * It makes no key and no certificate; it only reads the two files it is given.

Requests let through. BASE = --base; ORIGIN and RN = the --bind of the client's address. Derived from
phone/probe_app/src/org/edgefollow/probe/LiveService.java (version 20; the "line" column is its line numbers);
phone/sim_phone.py, which imitates the app, sends the same. A body is JSON with exactly these keys and values
(TEXT: any string; "/" may be written "\\/", as org.json does).

  method  path                Content-Type             body                                                     line
  POST    /BASE               application/json;ty=2    {"m2m:ae":{"rn":RN,"api":"Nprobe.phone","rr":false,      334
                                                        "srv":["4"]}}
  GET     /BASE/RN            -                        none (asked when the create is refused: already there)   336
  PUT     /BASE/RN            application/json         {"m2m:ae":{"rr":false}}                                  337
  POST    /BASE/RN            application/json;ty=3    {"m2m:cnt":{"rn":C,"mni":2000}},                         338-339
                                                        C one of imu env loc radio wlan cmd ack
  POST    /BASE/RN            application/json;ty=15   {"m2m:pch":{"rn":"pch"}}                                 342
  POST    /BASE/RN/cmd        application/json;ty=23   {"m2m:sub":{"rn":"cmdSub","nu":[ORIGIN],                 343-344
                                                        "enc":{"net":[3]},"nct":1}}
  POST    /BASE/RN/R          application/json;ty=4    {"m2m:cin":{"cnf":"application/json:0","con":TEXT}},     295, 441-443
                                                        R one of imu env loc radio wlan
  POST    /BASE/RN/ack        application/json;ty=4    the same                                                 388, 441-443
  POST    /BASE/RN/radioTs    application/json;ty=30   {"m2m:tsi":{"dgt":"yyyymmddThhmmss,ffffff",              436-437
                                                        "snr":N,"con":TEXT}}, N a whole number >= 0
  GET     /BASE/RN/pch/pcu    -                        none (the long poll)                                     359
  POST    /BASE/RN/pch/pcu    application/json         {"m2m:rsp":{"rsc":2000,"rqi":TEXT,"rvi":"4",             364-366
                                                        "to":"http(s)://HOST/BASE"}} (the app's CSE address)

  Request headers the app sets (lines 497-502 and 520-525): X-M2M-Origin, X-M2M-RI, X-M2M-RVI, Accept, and
  Content-Type when there is a body. Passed on: those, Host, and Content-Length (recomputed); every other header
  (User-Agent, Accept-Encoding, Connection, ... which the phone's HTTP stack adds) is dropped. Each of these must be
  there and be what the app sends, else 400: X-M2M-RVI exactly 4; Accept exactly application/json; X-M2M-RI 1 to 64
  printable ASCII characters without a space (the app: "p" or "q" and a clock reading); Host the address the client
  connected to, with or without the port (the --listen address; the phone's HTTP stack writes it from the CSE URL).
  Content-Type is passed on as the table's own text, not the client's. A GET with a body or a Content-Type, and a
  header named twice among those passed on, are refused.

Behaviour
  * --upstream must be http://<loopback IP address>:<port> with no path; anything else is refused (exit 2). Every
    request goes to that one address: an absolute-URI target and CONNECT are refused.
  * --listen must be an IP address and a port. 0.0.0.0 and :: need --allow-any-interface.
  * At start (exit 2, a line starting "tls_front: refused:"): an unknown option (also --allow, which --bind
    replaced); a --base or an RN that is not a letter or digit followed by up to 63 of [A-Za-z0-9_-] (a leading _
    would make ACME read the path _x/... as /x/..., another CSE); an ORIGIN that is CAdmin in any case, does not start
    with C, holds anything outside [A-Za-z0-9_-] or is longer than 64; the same address bound twice; two addresses
    bound to the same ORIGIN or the same RN (either compared without regard to case).
  * Header syntax: a header name must be an HTTP token without "_"; a value must hold no byte below 0x20 other than
    TAB, and no 0x7f; Host at most once. Otherwise 400.
  * A request body needs a Content-Length; Transfer-Encoding in a request is refused (501). A body over --max-body
    gets 413 and is not forwarded. A request line plus headers over 16 kB gets 431. After any refusal the
    connection is closed.
  * One thread per connection, so a long poll does not hold up other requests.
  * No answer from the upstream within --upstream-timeout (30 s; applied to each wait for data) -> 504. Upstream
    not reachable, an answer that is not HTTP, or one over --max-response -> 502.
  * --log FILE: one JSON line per answered request: time, client address, method, path (without the query),
    status, bytes of the answer's body, milliseconds. Never a header, never a body, never a query string.
  * Standard error: one JSON line when it listens and one when it stops (SIGTERM or SIGINT), with the counts:
    requests, refused_not_bound, refused_busy (no connection slot free), thread_start_failed, accept_errors,
    handshake_failed.

Standard library only.
"""
from __future__ import annotations

import argparse
import datetime
import http.client
import ipaddress
import json
import os
import re
import signal
import socket
import ssl
import sys
import threading
import time
from typing import NamedTuple
from urllib.parse import urlsplit

MAX_HEAD = 16384                       # request line plus headers, bytes
METHODS = ("GET", "POST", "PUT", "DELETE")   # parsed; DELETE is then refused by the allow list (403)
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
              "trailer", "transfer-encoding", "upgrade"}
TOKEN = set("!#$%&'*+-.^`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")   # no "_"
HANDSHAKE_S = 10.0                     # a client has this long for the TLS handshake (each wait for data)
HEAD_S = 20.0                          # ... and this long in all to send a request's line and headers (also the idle
#                                        time a kept-open connection may wait for its next request)
BODY_S = 30.0                          # ... and this long in all, from the first attempt to read it, for its body
DRAIN_S, DRAIN_BYTES, DRAIN_QUIET_S = 2.0, 4 << 20, 0.25   # after a refusal: read and drop what the client still
#                                        sends, within these; stop at the first quiet spell of DRAIN_QUIET_S
ACCEPT_PAUSE_S = 0.1                   # after accept() fails: wait this long before the next try
REFUSED = "tls_front: refused: "
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")   # --base and RN: no leading _ (ACME reads a path _x/... as /x/...,
#                                                        another CSE) and no leading -
ORIGIN = re.compile(r"C[A-Za-z0-9_-]{1,63}")
SEGMENT_PATH = re.compile(r"(?:/[A-Za-z0-9_-]{1,64})+")
DGT = re.compile(r"[0-9]{8}T[0-9]{6},[0-9]{6}")
RQI = re.compile(r"[\x21-\x7e]{1,256}")
RI = re.compile(r"[\x21-\x7e]{1,64}")                  # the X-M2M-RI header: printable ASCII, no space, at most 64
# The CSE (ACME 2026.5.3) does not parse a JSON body as it comes: it first removes what this regex takes for a comment
# (/*...*/, //..., #..., ;;... where it believes it is outside a string) and parses what is left. Copied unchanged from
# acmecse/helpers/TextTools.py:17-49 (_commentRegex, removeCommentsFromJSON), which acmecse/etc/RequestUtils.py:64-65
# calls before json.loads; not imported. Its string tracking takes a quote after a backslash for an escaped one, so it
# misreads where a string ends when the string ends in a backslash ("x\\").
ACME_COMMENT = re.compile(r'(\".*?(?<!\\)\".*?(?<!\\))|(/\*.*?\*/|//[^\r\n]*$|#[^\r\n]*$|;;[^\r\n]*$)',
                          re.MULTILINE | re.DOTALL)
ADDRESS_KEYS = {"poa", "nu", "pointofaccess", "notificationuri"}   # keys that tell the CSE where to send requests
PASSED_ON = {"host": "Host", "x-m2m-origin": "X-M2M-Origin", "x-m2m-ri": "X-M2M-RI", "x-m2m-rvi": "X-M2M-RVI",
             "accept": "Accept", "content-type": "Content-Type"}   # Content-Length is recomputed
CONTAINERS = ("imu", "env", "loc", "radio", "wlan", "cmd", "ack")  # LiveService 338
RECORDS = ("imu", "env", "loc", "radio", "wlan")                    # LiveService 295 (and "ack", 388)


class Refuse(Exception):
    """The arguments are refused: the text is printed and the exit code is 2."""


class BadRequest(Exception):
    def __init__(self, status: int, why: str, method: str = "-", path: str = "-"):
        super().__init__(why)
        self.status, self.why, self.method, self.path = status, why, method, path


class Binding(NamedTuple):
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    origin: str
    rn: str


# ---------------------------------------------------------------- the allow list (see the table in the module text)

def _same(x, y) -> bool:
    """Equal, and of the same JSON types all the way down (so true is not 1 and 3.0 is not 3)."""
    if type(x) is not type(y):
        return False
    if isinstance(x, dict):
        return x.keys() == y.keys() and all(_same(x[k], y[k]) for k in x)
    if isinstance(x, list):
        return len(x) == len(y) and all(_same(a, b) for a, b in zip(x, y))
    return x == y


def _inner(doc: dict, key: str, keys: set) -> dict | None:
    """doc is {key: {...}} with exactly `keys` inside: that inner object, else None."""
    if not isinstance(doc, dict) or set(doc) != {key}:
        return None
    inner = doc[key]
    return inner if isinstance(inner, dict) and set(inner) == keys else None


def body_ae_create(doc, b: Binding, base: str) -> bool:                                       # 334
    return _same(doc, {"m2m:ae": {"rn": b.rn, "api": "Nprobe.phone", "rr": False, "srv": ["4"]}})


def body_ae_update(doc, b: Binding, base: str) -> bool:                                       # 337
    return _same(doc, {"m2m:ae": {"rr": False}})


def body_cnt(doc, b: Binding, base: str) -> bool:                                             # 338-339
    c = _inner(doc, "m2m:cnt", {"rn", "mni"})
    return c is not None and isinstance(c["rn"], str) and c["rn"] in CONTAINERS and _same(c["mni"], 2000)


def body_pch(doc, b: Binding, base: str) -> bool:                                             # 342
    return _same(doc, {"m2m:pch": {"rn": "pch"}})


def body_sub(doc, b: Binding, base: str) -> bool:                                             # 343-344
    return _same(doc, {"m2m:sub": {"rn": "cmdSub", "nu": [b.origin], "enc": {"net": [3]}, "nct": 1}})


def body_cin(doc, b: Binding, base: str) -> bool:                                             # 441-443
    c = _inner(doc, "m2m:cin", {"cnf", "con"})
    return c is not None and _same(c["cnf"], "application/json:0") and isinstance(c["con"], str)


def body_tsi(doc, b: Binding, base: str) -> bool:                                             # 436-437
    t = _inner(doc, "m2m:tsi", {"dgt", "snr", "con"})
    return (t is not None and isinstance(t["dgt"], str) and DGT.fullmatch(t["dgt"]) is not None
            and type(t["snr"]) is int and 0 <= t["snr"] < 1 << 63 and isinstance(t["con"], str))


def body_rsp(doc, b: Binding, base: str) -> bool:                                             # 364-366
    r = _inner(doc, "m2m:rsp", {"rsc", "rqi", "rvi", "to"})
    return (r is not None and _same(r["rsc"], 2000) and isinstance(r["rqi"], str) and RQI.fullmatch(r["rqi"]) is not None
            and _same(r["rvi"], "4") and isinstance(r["to"], str)
            and re.fullmatch(r"https?://[A-Za-z0-9.:\[\]-]{1,255}/" + re.escape(base), r["to"]) is not None)


# (method, path below /BASE with the bound RN written {rn}) -> (Content-Type, body check or None)
ROUTES = {
    ("POST", ""): ("application/json;ty=2", body_ae_create),                                  # 334
    ("GET", "{rn}"): (None, None),                                                            # 336
    ("PUT", "{rn}"): ("application/json", body_ae_update),                                    # 337
    ("POST", "{rn}"): None,                                                                   # 338-342: by ty, below
    ("POST", "{rn}/cmd"): ("application/json;ty=23", body_sub),                               # 343-344
    **{("POST", "{rn}/" + r): ("application/json;ty=4", body_cin) for r in RECORDS + ("ack",)},   # 295, 388, 443
    ("POST", "{rn}/radioTs"): ("application/json;ty=30", body_tsi),                           # 436-437
    ("GET", "{rn}/pch/pcu"): (None, None),                                                    # 359
    ("POST", "{rn}/pch/pcu"): ("application/json", body_rsp),                                 # 364-366
}
AE_CHILDREN = {"application/json;ty=3": body_cnt, "application/json;ty=15": body_pch}         # POST /BASE/RN


def _no_twice(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"the key {k!r} is given twice")
        out[k] = v
    return out


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def acme_uncomment(text: str) -> str:
    """The text as ACME's removeCommentsFromJSON leaves it (its _replacer: a comment goes, a string stays)."""
    return ACME_COMMENT.sub(lambda m: "" if m.group(2) else m.group(1), text)


def address_keys(doc) -> list[tuple]:
    """Where in the document a key names an address for the CSE to contact (poa, nu), as key paths."""
    found, stack = [], [(doc, ())]
    while stack:
        node, at = stack.pop()
        if isinstance(node, dict):
            for k, v in node.items():
                if k.lower() in ADDRESS_KEYS:
                    found.append(at + (k,))
                stack.append((v, at + (k,)))
        elif isinstance(node, list):
            stack.extend((v, at + (i,)) for i, v in enumerate(node))
    return found


# ---------------------------------------------------------------- arguments

def parse_listen(text: str, allow_any: bool) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit() or not 0 <= int(port) <= 65535:
        raise Refuse(f"--listen {text!r}: want IP:PORT (an IPv6 address in square brackets)")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise Refuse(f"--listen {text!r}: the host must be an IP address") from None
    if ip.is_unspecified and not allow_any:
        raise Refuse(f"--listen {text!r}: every interface; give --allow-any-interface if that is meant")
    return ip, int(port)


def parse_upstream(text: str) -> tuple[str, int]:
    try:
        u = urlsplit(text)
        port = u.port
    except ValueError:
        raise Refuse(f"--upstream {text!r}: not a URL") from None
    if u.scheme != "http":
        raise Refuse(f"--upstream {text!r}: the scheme must be http")
    if u.username is not None or u.password is not None or u.path not in ("", "/") or u.query or u.fragment:
        raise Refuse(f"--upstream {text!r}: want http://<loopback address>:<port> and nothing more")
    try:
        ip = ipaddress.ip_address(u.hostname or "")
    except ValueError:
        raise Refuse(f"--upstream {text!r}: the host must be a loopback IP address, not a name") from None
    if not ip.is_loopback:
        raise Refuse(f"--upstream {text!r}: the host is not a loopback address")
    if port is None or port == 0:
        raise Refuse(f"--upstream {text!r}: a port is required")
    return str(ip), port


def _plain(ip):
    """An IPv4-mapped IPv6 address as the IPv4 address it is."""
    return ip.ipv4_mapped if ip.version == 6 and ip.ipv4_mapped is not None else ip


def host_names(local) -> frozenset:
    """The Host values a request may carry on a connection whose local end is `local` (from getsockname()): that
    address with or without the port, as the app's HTTP stack writes it from its CSE URL. This is the --listen
    address; with --allow-any-interface, the address of this machine that the client reached."""
    ip = _plain(ipaddress.ip_address(local[0].split("%")[0]))
    name = str(ip) if ip.version == 4 else f"[{ip}]"
    return frozenset({name, f"{name}:{local[1]}"})


def parse_base(text: str | None) -> str:
    if text is None or not NAME.fullmatch(text):
        raise Refuse(f"--base {text!r}: want the CSE's resource name, a letter or digit then up to 63 of "
                     f"[A-Za-z0-9_-] (e.g. cse-mn-a)")
    return text


def parse_binds(values: list[str] | None) -> dict:
    """{client address: Binding}. Refuses the admin originator, a bad name, and any address, originator or AE name
    used twice."""
    if not values:
        raise Refuse("at least one --bind IP=ORIGIN:RN is required")
    out: dict = {}
    origins: set = set()
    rns: set = set()
    for v in values:
        ip_text, sep, rest = v.partition("=")
        origin, sep2, rn = rest.partition(":")
        if not sep or not sep2:
            raise Refuse(f"--bind {v!r}: want IP=ORIGIN:RN")
        try:
            ip = _plain(ipaddress.ip_address(ip_text))
        except ValueError:
            raise Refuse(f"--bind {v!r}: {ip_text!r} is not an IP address") from None
        if ip.is_unspecified or ip.is_multicast:
            raise Refuse(f"--bind {v!r}: {ip_text!r} is not the address of one client")
        if origin.lower() == "cadmin":
            raise Refuse(f"--bind {v!r}: CAdmin is the CSE's admin originator; it is never bound")
        if not origin.startswith("C"):
            raise Refuse(f"--bind {v!r}: the originator must start with C")
        if not ORIGIN.fullmatch(origin):
            raise Refuse(f"--bind {v!r}: the originator must be C plus 1 to 63 of [A-Za-z0-9_-]")
        if not NAME.fullmatch(rn):
            raise Refuse(f"--bind {v!r}: the AE name must be a letter or digit then up to 63 of [A-Za-z0-9_-]")
        if ip in out:
            raise Refuse(f"--bind {v!r}: the address {ip} is bound twice")
        if origin.lower() in origins:
            raise Refuse(f"--bind {v!r}: the originator {origin} is bound to two addresses")
        if rn.lower() in rns:
            raise Refuse(f"--bind {v!r}: the AE name {rn} is bound to two addresses")
        out[ip] = Binding(ip, origin, rn)
        origins.add(origin.lower())
        rns.add(rn.lower())
    return out


def _no_password():
    raise Refuse("the key file is encrypted; this program asks for no passphrase")


def make_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_NONE                    # no client certificate: the device is NOT authenticated here
    try:
        ctx.load_cert_chain(certfile=cert, keyfile=key, password=_no_password)
    except Refuse:
        raise
    except (OSError, ssl.SSLError, ValueError) as e:
        raise Refuse(f"the certificate {cert!r} and key {key!r} could not be loaded "
                     f"(missing, unreadable, or they do not belong together): {type(e).__name__}") from None
    return ctx


# ---------------------------------------------------------------- --self-check: reading the certificate (DER)

def _tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """One DER element at pos: (tag, content, position after it)."""
    if pos + 2 > len(buf):
        raise ValueError("truncated")
    tag, n = buf[pos], buf[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or pos + k > len(buf):
            raise ValueError("bad length")
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    if pos + n > len(buf):
        raise ValueError("truncated")
    return tag, buf[pos:pos + n], pos + n


def _items(buf: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(buf):
        tag, val, pos = _tlv(buf, pos)
        out.append((tag, val))
    return out


def _oid(val: bytes) -> str:
    parts, n = [], 0
    for b in val:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            if not parts:
                first = min(n // 40, 2)
                parts += [first, n - 40 * first]
            else:
                parts.append(n)
            n = 0
    return ".".join(map(str, parts))


_ATTR = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU"}


def _name(val: bytes) -> str:
    out = []
    for _, rdn in _items(val):
        for _, atv in _items(rdn):
            (_, oid), (tag, text) = _items(atv)[:2]
            s = text.decode("utf-16-be" if tag == 0x1E else "utf-8", "replace")
            out.append(f"{_ATTR.get(_oid(oid), _oid(oid))}={s}")
    return ", ".join(out) or "(empty)"


def _time(tag: int, val: bytes) -> datetime.datetime:
    s = val.decode("ascii")
    if tag == 0x17:                                    # UTCTime: two-digit year
        s = ("20" if int(s[:2]) < 50 else "19") + s
    return datetime.datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)


def read_certificate(pem_text: str) -> dict:
    """Subject, subject alternative names and validity dates of the first certificate in a PEM file."""
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    i, j = pem_text.find(begin), pem_text.find(end)
    if i < 0 or j < i:
        raise ValueError("no certificate in the file")
    der = ssl.PEM_cert_to_DER_cert(pem_text[i:j + len(end)])
    _, cert, _ = _tlv(der, 0)
    _, tbs, _ = _tlv(cert, 0)
    f = _items(tbs)
    if f and f[0][0] == 0xA0:                          # the version, when present
        f = f[1:]
    # f: serial, signature algorithm, issuer, validity, subject, public key, then the optional parts
    (t0, v0), (t1, v1) = _items(f[3][1])[:2]
    sans: list[str] = []
    for tag, val in f[6:]:
        if tag != 0xA3:
            continue
        for _, ext in _items(_items(val)[0][1]):
            parts = _items(ext)
            if _oid(parts[0][1]) != "2.5.29.17":
                continue
            for gtag, gval in _items(_items(parts[-1][1])[0][1]):
                if gtag == 0x82:
                    sans.append("DNS:" + gval.decode("ascii", "replace"))
                elif gtag == 0x87 and len(gval) in (4, 16):
                    sans.append("IP:" + str(ipaddress.ip_address(gval)))
                elif gtag == 0x81:
                    sans.append("email:" + gval.decode("ascii", "replace"))
                elif gtag == 0x86:
                    sans.append("URI:" + gval.decode("ascii", "replace"))
                else:
                    sans.append(f"other(tag {gtag & 0x1F})")
    return {"subject": _name(f[4][1]), "issuer": _name(f[2][1]), "sans": sans,
            "not_before": _time(t0, v0), "not_after": _time(t1, v1)}


def self_check(cert: str) -> int:
    """Print what the certificate is. The key was already loaded with it by make_context. Binds nothing."""
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        with open(cert, encoding="ascii", errors="replace") as fh:
            c = read_certificate(fh.read())
    except (OSError, ValueError, IndexError) as e:
        raise Refuse(f"the certificate {cert!r} could not be read: {type(e).__name__}") from None
    now = datetime.datetime.now(datetime.timezone.utc)
    inside = c["not_before"] <= now <= c["not_after"]
    print(f"subject: {c['subject']}")
    print(f"issuer: {c['issuer']}")
    print(f"subject alternative names: {', '.join(c['sans']) or '(none)'}")
    print(f"not before: {c['not_before'].strftime(fmt)}")
    print(f"not after: {c['not_after'].strftime(fmt)}")
    print(f"within its validity dates now: {'yes' if inside else 'NO'}")
    print("key: loaded, belongs to the certificate")
    print("TLS: minimum version 1.3, no client certificate asked for (the device is not authenticated)")
    return 0 if inside else 1


# ---------------------------------------------------------------- the front door

def _close(s) -> None:
    try:
        s.close()
    except OSError:
        pass


class Front:
    def __init__(self, ctx: ssl.SSLContext, upstream: tuple[str, int], base: str, binds: dict, max_body: int,
                 max_response: int, upstream_timeout: float, max_conns: int, max_conns_per_client: int,
                 log_path: str | None):
        self.ctx, self.upstream, self.base, self.binds = ctx, upstream, base, binds
        self.max_body, self.max_response, self.upstream_timeout = max_body, max_response, upstream_timeout
        self.slots = threading.BoundedSemaphore(max_conns)
        self.client_slots = {ip: threading.BoundedSemaphore(max_conns_per_client) for ip in binds}
        self.lock = threading.Lock()
        self.counts = {"requests": 0, "refused_not_bound": 0, "refused_busy": 0, "thread_start_failed": 0,
                       "accept_errors": 0, "handshake_failed": 0}
        self.busy = 0                                  # requests being answered right now
        self.stop = threading.Event()
        self.log = None
        if log_path:
            fd = os.open(log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            self.log = os.fdopen(fd, "a", encoding="utf-8")

    def count(self, what: str) -> None:
        with self.lock:
            self.counts[what] += 1

    def write_log(self, client: str, method: str, path: str, status: int, nbytes: int, t0: float) -> None:
        with self.lock:
            self.counts["requests"] += 1
            if self.log is None:
                return
            line = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
                    "client": client, "method": method, "path": path[:512], "status": status, "bytes": nbytes,
                    "ms": round((time.monotonic() - t0) * 1000, 1)}
            self.log.write(json.dumps(line) + "\n")
            self.log.flush()

    # ---- who it is

    def binding(self, addr: str) -> Binding | None:
        try:
            ip = _plain(ipaddress.ip_address(addr.split("%")[0]))
        except ValueError:
            return None
        return self.binds.get(ip)

    # ---- the listener

    def serve(self, listener: socket.socket) -> None:
        listener.settimeout(0.5)
        while not self.stop.is_set():
            try:
                raw, addr = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stop.is_set():
                    break
                self.count("accept_errors")
                self.stop.wait(ACCEPT_PAUSE_S)        # e.g. no file descriptor left: do not spin on it
                continue
            self.admit(raw, addr[0])

    def admit(self, raw: socket.socket, client: str) -> None:
        """Start a thread for a connection from a bound address that gets both of its slots; close anything else
        before the handshake and count it."""
        b = self.binding(client)
        if b is None:
            self.count("refused_not_bound")            # closed here: no handshake, nothing read
            _close(raw)
            return
        own = self.client_slots[b.ip]
        if not self.slots.acquire(blocking=False):
            self.count("refused_busy")
            _close(raw)
            return
        if not own.acquire(blocking=False):
            self.slots.release()
            self.count("refused_busy")
            _close(raw)
            return
        try:
            threading.Thread(target=self.connection, args=(raw, client, b, own), daemon=True,
                             name="tls-front-conn").start()
        except RuntimeError:                           # "can't start new thread": refuse this one, keep serving
            own.release()
            self.slots.release()
            self.count("thread_start_failed")
            _close(raw)

    def wait_idle(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            with self.lock:
                if self.busy == 0:
                    return
            time.sleep(0.05)

    # ---- one connection

    def connection(self, raw: socket.socket, client: str, b: Binding, own: threading.BoundedSemaphore) -> None:
        tls = None
        try:
            hosts = host_names(raw.getsockname())
            raw.settimeout(HANDSHAKE_S)
            try:
                tls = self.ctx.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                self.count("handshake_failed")
                return
            buf = b""
            while not self.stop.is_set():
                keep, buf = self.one_request(tls, client, b, buf, hosts)
                if not keep:
                    break
        except (ssl.SSLError, OSError):
            pass                                       # the client went away
        finally:
            for s in (tls, raw):
                if s is not None:
                    _close(s)
            own.release()
            self.slots.release()

    def read_head(self, tls: ssl.SSLSocket, buf: bytes) -> tuple[bytes | None, bytes]:
        """The request line and headers (without the blank line) and what was read beyond them. None: the client
        closed or stayed silent before a request began."""
        end = time.monotonic() + HEAD_S
        while True:
            i = buf.find(b"\r\n\r\n")
            if 0 <= i <= MAX_HEAD - 4:
                return buf[:i], buf[i + 4:]
            if i > MAX_HEAD - 4 or len(buf) >= MAX_HEAD:
                raise BadRequest(431, "request line and headers over 16 kB")
            left = end - time.monotonic()
            if left <= 0:
                if buf:
                    raise BadRequest(408, "request not complete in time")
                return None, b""
            tls.settimeout(left)
            try:
                part = tls.recv(8192)
            except TimeoutError:
                continue
            if not part:
                return None, b""
            buf += part

    def read_body(self, tls: ssl.SSLSocket, buf: bytes, length: int, method: str, path: str) -> tuple[bytes, bytes] | None:
        """(body, what was read beyond it); None when the client closed. 408 past BODY_S from the first try."""
        end = time.monotonic() + BODY_S
        while len(buf) < length:
            left = end - time.monotonic()
            if left <= 0:
                raise BadRequest(408, "request body not complete in time", method, path)
            tls.settimeout(left)
            try:
                part = tls.recv(min(65536, length - len(buf)))
            except TimeoutError:
                continue
            if not part:
                return None
            buf += part
        return buf[:length], buf[length:]

    def check_head(self, b: Binding, method: str, target: str, headers: list[tuple[str, str]],
                   length: int, hosts: frozenset) -> tuple[str | None, object, list[tuple[str, str]]]:
        """The allow list, for what is known before the body: (Content-Type to pass on, body check, headers to pass
        on). Raises BadRequest (400: malformed; 403: not one of the app's requests)."""
        path, _, query = target.partition("?")
        if "?" in target or "#" in target:
            raise BadRequest(400, "a query string is not served", method, path)
        if "%" in path:
            raise BadRequest(400, "percent-encoding in the path is not served", method, path)
        for bad in ("//", "/~/", "/_/", "/./", "/../"):
            if bad in path + "/":
                raise BadRequest(400, f"{bad!r} in the path is not served (no other CSE, no dot segments)",
                                 method, path)
        if not SEGMENT_PATH.fullmatch(path):
            raise BadRequest(400, "the path holds a character the app never sends", method, path)
        segs = path.split("/")[1:]
        if segs[0] != self.base:
            raise BadRequest(403, f"only paths under /{self.base} are served", method, path)
        if method == "DELETE":
            raise BadRequest(403, "DELETE is not served", method, path)
        below = segs[1:]
        if below and below[0] != b.rn:
            raise BadRequest(403, "the path is not under this client's own AE", method, path)
        low = [(k.lower(), v) for k, v in headers]
        origins = [v for k, v in low if k == "x-m2m-origin"]
        if len(origins) != 1 or origins[0] != b.origin:
            raise BadRequest(403, "X-M2M-Origin must be given once and be the originator bound to this address",
                             method, path)
        for k in PASSED_ON:
            if sum(1 for h, _ in low if h == k) > 1:
                raise BadRequest(400, f"the header {PASSED_ON[k]} is given more than once", method, path)
        one = {k: v for k, v in low if k in PASSED_ON}                   # each at most once: checked just above
        if one.get("host", "").lower() not in hosts:
            raise BadRequest(400, "Host must be this front door's address, with or without the port", method, path)
        if one.get("x-m2m-rvi") != "4":
            raise BadRequest(400, "X-M2M-RVI must be 4, as the app sends", method, path)
        if one.get("accept") != "application/json":
            raise BadRequest(400, "Accept must be application/json, as the app sends", method, path)
        if RI.fullmatch(one.get("x-m2m-ri", "")) is None:
            raise BadRequest(400, "X-M2M-RI must be 1 to 64 printable ASCII characters without spaces", method, path)
        ctype = next((v.replace(" ", "").lower() for k, v in low if k == "content-type"), None)
        rel = "/".join(["{rn}"] + below[1:]) if below else ""
        route = ROUTES.get((method, rel), "none")
        if route is None:                              # POST /BASE/RN: the child's type decides
            route = (ctype, AE_CHILDREN[ctype]) if ctype in AE_CHILDREN else "none"
        if route == "none" or route[0] != ctype:
            raise BadRequest(403, "not a request the probe app sends (method, path and Content-Type)", method, path)
        want_ctype, check = route
        if check is None and length:
            raise BadRequest(400, "a body on a request that has none", method, path)
        out = [(PASSED_ON[k], v) for k, v in low if k in PASSED_ON and k not in ("content-type", "x-m2m-origin")]
        out.append(("X-M2M-Origin", b.origin))
        if want_ctype is not None:
            out.append(("Content-Type", want_ctype))
        return want_ctype, check, out

    def check_body(self, b: Binding, check, body: bytes, method: str, path: str) -> None:
        """The allow list, for the body: one JSON object of exactly the app's shape, which the CSE reads as the same
        text (see ACME_COMMENT). The bytes checked are the bytes forwarded. Raises BadRequest."""
        try:
            text = body.decode("utf-8")
            doc = json.loads(text, object_pairs_hook=_no_twice, parse_constant=_no_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise BadRequest(400, "the body is not JSON (or gives a key twice)", method, path) from None
        if not isinstance(doc, dict):
            raise BadRequest(400, "the body is not a JSON object", method, path)
        allowed = [("m2m:sub", "nu")] if check is body_sub else []
        if any(at not in allowed for at in address_keys(doc)):
            raise BadRequest(403, "the body names an address for the CSE to contact (poa or nu)", method, path)
        if not check(doc, b, self.base):
            raise BadRequest(403, "the body is not what the probe app sends for this request", method, path)
        # The CSE's comment remover must leave the text exactly as it is. It runs after the shape check, and only when
        # the last '"' does not follow a backslash: on text where it does, the regex misreads where that last string
        # ends and scans what is left once from every quote and every '/*' in it (measured: 32 kB took 4 s of CPU,
        # with the GIL held). With that refused and a body of one of the shapes above (one free string, con or rqi,
        # at most), it runs in linear time. A body that has more free strings would need this looked at again.
        last = text.rfind('"')
        if last > 0 and text[last - 1] == "\\":
            raise BadRequest(400, "the body's last string ends in a backslash: the CSE's comment remover misreads "
                                  "where it ends", method, path)
        if acme_uncomment(text) != text:
            raise BadRequest(400, "the CSE's comment remover would change this body (text it takes for a comment "
                                  "outside a string), so the CSE would act on another body", method, path)

    def one_request(self, tls: ssl.SSLSocket, client: str, b: Binding, buf: bytes,
                    hosts: frozenset) -> tuple[bool, bytes]:
        """Read one request and answer it. (keep the connection open, bytes already read of the next request)."""
        t0 = time.monotonic()
        method, path = "-", "-"
        counted = False                                # an idle kept-open connection does not hold up the stop
        try:
            try:
                head, buf = self.read_head(tls, buf)
                if head is None:
                    return False, b""
                with self.lock:
                    self.busy += 1
                counted = True
                t0 = time.monotonic()
                method, target, headers, length, keep = parse_head(head)
                path = target.split("?", 1)[0]
                _, check, out_headers = self.check_head(b, method, target, headers, length, hosts)
                if length > self.max_body:
                    raise BadRequest(413, "request body over --max-body", method, path)
                got = self.read_body(tls, buf, length, method, path)
                if got is None:
                    return False, b""
                body, buf = got
                if check is not None:
                    self.check_body(b, check, body, method, path)
            except BadRequest as e:
                method, path = (e.method, e.path) if e.method != "-" else (method, path)
                self.refuse(tls, client, method, path, e.status, e.why, t0)
                return False, b""
            status, reason, resp_headers, resp_body = self.forward(method, path, out_headers, body)
            if not keep:
                resp_headers.append(("Connection", "close"))
            if not (status in (204, 304) or 100 <= status < 200):
                resp_headers.append(("Content-Length", str(len(resp_body))))
            else:
                resp_body = b""
            blob = (f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in resp_headers) + "\r\n")
            tls.settimeout(BODY_S)
            sent = 0
            try:
                tls.sendall(blob.encode("latin-1") + resp_body)
                sent = len(resp_body)
            finally:
                self.write_log(client, method, path, status, sent, t0)
            return keep, buf
        finally:
            if counted:
                with self.lock:
                    self.busy -= 1

    def refuse(self, tls: ssl.SSLSocket, client: str, method: str, path: str, status: int, why: str, t0: float) -> None:
        """Answer a request that is not forwarded, then drop what the client still sends and let the caller close."""
        body = (json.dumps({"error": why}) + "\n").encode()
        reason = http.client.responses.get(status, "Error")
        extra = "Allow: GET, POST, PUT\r\n" if status == 405 else ""
        sent = 0
        try:
            tls.settimeout(BODY_S)
            tls.sendall((f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n{extra}"
                         f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body)
            sent = len(body)
        finally:
            self.write_log(client, method, path, status, sent, t0)
        # A close with unread data would reset the connection and the client could lose the answer just sent.
        end, n = time.monotonic() + DRAIN_S, 0
        try:
            while n < DRAIN_BYTES and time.monotonic() < end:
                tls.settimeout(max(0.05, min(DRAIN_QUIET_S, end - time.monotonic())))
                part = tls.recv(65536)
                if not part:
                    break
                n += len(part)
        except (ssl.SSLError, OSError):
            pass                                       # a quiet spell (timeout) or the client went away

    def forward(self, method: str, path: str, headers: list[tuple[str, str]], body: bytes):
        """Send the request to the one upstream; (status, reason, headers, body) of its answer, or of our 502/504."""
        conn = http.client.HTTPConnection(self.upstream[0], self.upstream[1], timeout=self.upstream_timeout)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            has_host = False
            for k, v in headers:
                has_host = has_host or k == "Host"
                conn.putheader(k, v)
            if not has_host:
                conn.putheader("Host", f"{self.upstream[0]}:{self.upstream[1]}")
            if body or method in ("POST", "PUT"):
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body or None)
            r = conn.getresponse()
            if r.length is not None and r.length > self.max_response:
                return self.own(502, "the upstream's answer is over --max-response")
            parts, total = [], 0
            while True:
                part = r.read(min(65536, self.max_response + 1 - total))
                if not part:
                    break
                parts.append(part)
                total += len(part)
                if total > self.max_response:
                    return self.own(502, "the upstream's answer is over --max-response")
            named = {t.strip().lower() for v in r.headers.get_all("Connection", []) for t in v.split(",")}
            drop = HOP_BY_HOP | named | {"content-length"}
            out_headers = [(k, v) for k, v in r.getheaders() if k.lower() not in drop]
            return r.status, r.reason or "", out_headers, b"".join(parts)
        except TimeoutError:
            return self.own(504, "no answer from the upstream in time")
        except (OSError, http.client.HTTPException, ValueError):
            return self.own(502, "the upstream could not be reached or did not answer in HTTP")
        finally:
            conn.close()

    @staticmethod
    def own(status: int, why: str):
        return (status, http.client.responses.get(status, "Error"), [("Content-Type", "application/json")],
                (json.dumps({"error": why}) + "\n").encode())


def parse_head(head: bytes) -> tuple[str, str, list[tuple[str, str]], int, bool]:
    """(method, target, every header, body length, keep the connection). Raises BadRequest on bad syntax."""
    lines = head.split(b"\r\n")
    try:
        first = lines[0].decode("ascii")
    except UnicodeDecodeError:
        raise BadRequest(400, "request line is not ASCII") from None
    parts = first.split(" ")
    if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
        raise BadRequest(400, "malformed request line")
    method, target, version = parts
    safe_method = method if method.isalpha() and len(method) <= 16 else "-"
    if method == "CONNECT":
        raise BadRequest(405, "CONNECT is not served", safe_method)
    if not target.startswith("/") or any(not 0x21 <= ord(c) <= 0x7E for c in target):
        # an absolute-URI ("http://..."), an authority, "*", or a target with a space or control byte
        raise BadRequest(400 if method in METHODS else 405, "the request target must be a path starting with /",
                         safe_method)
    path = target.split("?", 1)[0]
    if method not in METHODS:
        raise BadRequest(405, "method not served", safe_method, path)
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        try:
            k, v = name.decode("ascii"), value.decode("latin-1").strip(" \t")
        except UnicodeDecodeError:
            raise BadRequest(400, "malformed header", method, path) from None
        if not sep or not k or any(c not in TOKEN for c in k):
            raise BadRequest(400, "malformed header name (an HTTP token, without '_')", method, path)
        if any((ord(c) < 0x20 and c != "\t") or ord(c) == 0x7F for c in v):
            raise BadRequest(400, "a control character in a header value", method, path)
        headers.append((k, v))
    low = [(k.lower(), v) for k, v in headers]
    if sum(1 for k, _ in low if k == "host") > 1:
        raise BadRequest(400, "more than one Host header", method, path)
    if any(k == "transfer-encoding" for k, _ in low):
        raise BadRequest(501, "Transfer-Encoding in a request is not served; send Content-Length", method, path)
    lengths = [v for k, v in low if k == "content-length"]
    if len(lengths) > 1 or (lengths and not (lengths[0].isascii() and lengths[0].isdigit() and len(lengths[0]) <= 12)):
        raise BadRequest(400, "bad Content-Length", method, path)
    length = int(lengths[0]) if lengths else 0
    conn_tokens = {t.strip().lower() for k, v in low if k == "connection" for t in v.split(",")}
    keep = version == "HTTP/1.1" and "close" not in conn_tokens
    return method, target, headers, length, keep


# ---------------------------------------------------------------- start

class _Parser(argparse.ArgumentParser):
    def error(self, message):                          # exit 2 with the program's own refusal line
        raise Refuse(message)


def configure(argv: list[str] | None) -> tuple[argparse.Namespace, dict]:
    """Parse and check the arguments: (the arguments, what Front and the listener are made from). Raises Refuse."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a == "--allow" or a.startswith("--allow=") for a in argv):
        raise Refuse("--allow is gone: give --bind IP=ORIGIN:RN for each client, and --base NAME")
    ap = _Parser(description="TLS 1.3 front door for one loopback HTTP upstream (see the module text).",
                 allow_abbrev=False)
    ap.add_argument("--listen", required=True, metavar="HOST:PORT")
    ap.add_argument("--upstream", required=True, metavar="http://127.0.0.1:PORT")
    ap.add_argument("--cert", required=True, metavar="FILE", help="server certificate chain, PEM (read only)")
    ap.add_argument("--key", required=True, metavar="FILE", help="server key, PEM, not encrypted (read only)")
    ap.add_argument("--base", required=True, metavar="NAME", help="the CSE's resource name, e.g. cse-mn-a")
    ap.add_argument("--bind", action="append", metavar="IP=ORIGIN:RN",
                    help="a client address, its originator and its AE name; repeatable; one at least")
    ap.add_argument("--allow-any-interface", action="store_true", help="accept --listen 0.0.0.0 or ::")
    ap.add_argument("--max-body", type=int, default=262144, metavar="BYTES")
    ap.add_argument("--max-response", type=int, default=4 << 20, metavar="BYTES")
    ap.add_argument("--max-conns", type=int, default=32, metavar="N")
    ap.add_argument("--max-conns-per-client", type=int, default=4, metavar="N")
    ap.add_argument("--upstream-timeout", type=float, default=30.0, metavar="SECONDS")
    ap.add_argument("--log", metavar="FILE")
    ap.add_argument("--self-check", action="store_true", help="load certificate and key, print them, do not listen")
    a = ap.parse_args(argv)
    ip, port = parse_listen(a.listen, a.allow_any_interface)
    upstream = parse_upstream(a.upstream)
    base = parse_base(a.base)
    binds = parse_binds(a.bind)
    if not 0 <= a.max_body <= 64 << 20 or not 0 < a.upstream_timeout <= 3600:
        raise Refuse("--max-body must be within 0..64 MiB and --upstream-timeout within 0..3600 s")
    if not 1 <= a.max_response <= 1 << 30:
        raise Refuse("--max-response must be within 1 byte..1 GiB")
    if not 1 <= a.max_conns <= 4096 or not 1 <= a.max_conns_per_client <= a.max_conns:
        raise Refuse("--max-conns must be within 1..4096 and --max-conns-per-client within 1..--max-conns")
    ctx = make_context(a.cert, a.key)
    return a, {"ctx": ctx, "upstream": upstream, "base": base, "binds": binds, "max_body": a.max_body,
               "max_response": a.max_response, "upstream_timeout": a.upstream_timeout, "max_conns": a.max_conns,
               "max_conns_per_client": a.max_conns_per_client, "log_path": a.log, "ip": ip, "port": port}


def open_listener(ip, port: int) -> socket.socket:
    listener = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((str(ip), port))
        listener.listen(64)
    except OSError:
        listener.close()
        raise
    return listener


def _front(cfg: dict) -> Front:
    return Front(**{k: v for k, v in cfg.items() if k not in ("ip", "port")})


def prepare(argv: list[str]) -> tuple[Front, socket.socket]:
    """The front door and its listening socket, made as main() makes them; no signal handler, nothing printed.
    Raises Refuse or OSError. (For tests that run it inside their own process.)"""
    _, cfg = configure(argv)
    return _front(cfg), open_listener(cfg["ip"], cfg["port"])


def main(argv: list[str] | None = None) -> int:
    try:
        a, cfg = configure(argv)
        if a.self_check:
            return self_check(a.cert)
    except Refuse as e:
        print(REFUSED + str(e), file=sys.stderr)
        return 2
    try:
        listener = open_listener(cfg["ip"], cfg["port"])
    except OSError as e:
        print(f"tls_front: cannot listen on {a.listen}: {e}", file=sys.stderr)
        return 1
    front = _front(cfg)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: front.stop.set())
    print(json.dumps({"event": "listening", "host": str(cfg["ip"]), "port": listener.getsockname()[1],
                      "upstream": f"http://{cfg['upstream'][0]}:{cfg['upstream'][1]}", "base": cfg["base"],
                      "bind": [f"{b.ip}={b.origin}:{b.rn}" for b in cfg["binds"].values()],
                      "max_conns": cfg["max_conns"], "max_conns_per_client": cfg["max_conns_per_client"]}),
          file=sys.stderr, flush=True)
    try:
        front.serve(listener)
    finally:
        listener.close()
        front.wait_idle(2.0)                           # let the requests in flight finish, briefly
        with front.lock:
            counts = dict(front.counts)
            if front.log is not None:
                front.log.close()
                front.log = None
        print(json.dumps({"event": "stopped", **counts}), file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
