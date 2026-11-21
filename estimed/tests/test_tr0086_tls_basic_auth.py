"""TR-0086 5.2.4.1 (developer guide, the TR-0086 device-registration branch, print of 2026-10-29, pp. 5-7):
the IN-CSE set up in 5.2.4.1.4 with [http.security] useTLS=true and enableBasicAuth=true, its 5.2.4.1.5 check (a
well-formed oneM2M GET with Basic auth), and 5.2.4 step 3: an MN-CSE registering to that IN with registrar credentials
(5.2.4.1.5 exports them as ACME_CSE_REGISTRAR_SECURITY_HTTPUSERNAME and ..._HTTPPASSWORD; ACME reads those variables).
An older markdown copy of TR-0086 has no 5.2.4.1.

The lab IN on :8200 is plain HTTP and stays so: nothing here sends it anything. Every CSE below is a PRIVATE ACME
2026.5.3 process this file starts on loopback, in a temporary directory, with env={} (an MN gets the two variables
above and nothing else), and stops again with SIGINT (by the kernel too, should this process die):

    :8270  the IN (estimed-id-in / estimed-in / //acme.example.com: the guide's example names), HTTPS only, Basic auth:
           the guide's 5.2.4.1.4 lines with the changes in IN_CHANGES and the three fixes in FIX_LINES
    :8271  an MN (estimed-id-mn-t) that registers to it over HTTPS; also run with a wrong password and with none
    :8272  the IN as the guide writes it (no FIX_LINES), then the same IN with them, each with an MN on :8273

Secrets (the author's rule for this file): the CA, the IN certificates and keys are made by the openssl CLI at test
time in a directory from tempfile.mkdtemp (outside the repo), used only by these loopback CSEs, never reused, and
removed with that directory at the end (the guard asserts it is gone). The Basic-auth user name and password, the
CSEs' secrets and the wrong password are secrets.token_urlsafe values made per run; they are never printed or
logged by this file (_Secret's repr is redacted; checks on what carries them reduce it to booleans first). ACME
itself would log the user name at warn on each refused attempt, so the private INs run at logLevel=error; an end
test reads every file the run wrote and finds the password in none. No file in the repo holds key material or a
credential: a test scans this file for any, another every repo file written while the module ran for this run's
credentials and keys.

Findings on ACME 2026.5.3 with the guide's IN lines, each shown on the :8272 IN as written and closed on :8270 by one
FIX_LINES entry (for the guide's authors):
  F1  without an [http] address line the IN's CSEBase advertises poa http://127.0.0.1:<port> while it serves TLS only
      ([cse] poa is interpolated from the http: address before ACME switches it to https). An MN registers over the
      configured https address, then checks its registrar at the poa: every check is refused ("Registrar CSE
      unreachable - assuming it is still there"), the IN still lists the MN, and each check sends the registrar
      credentials in CLEAR TEXT (read off the wire below). Fix: address=https://...
  F2  enableBasicAuth=true with token auth off (the default) lets ANY "Authorization: Bearer <anything>" through:
      a CSE-ID matching /estimed-id* registers without the password, and __mgmt__/config (with the IN's secret) and
      the upper tester answer. Fix: enableTokenAuth=true with a token file that holds no token.
  F3  enableStructureEndpoint=true serves __structure__ (the whole resource tree, registrees included) without any
      credentials. Fix: enableStructureEndpoint=false.
  F4  (MN side, open) the MN keeps its registrar's user name and password as userinfo in the poa of its local
      <remoteCSE> for the IN, readable over the MN's plain HTTP by any client sending X-M2M-Origin CAdmin or
      /estimed-id-in (ACME's own TODO in _updateLocalCSRAuthInfo). In memory here (databaseType=memory).

NOT shown, by any test here:
  * that the MN verifies the IN's certificate: it does not (pinned as a limit). ACME clears verifyCertificate on a
    CSE whose own server is plain HTTP, and verifyCertificate=true on a TLS server also demands client certificates
    (read in the code, not run). The guide's own check is `curl -sk`.
  * TLS on the MN or on IN->MN requests: the MN serves plain HTTP, as in the guide and the lab
  * the guide's flexContainer definitions (3 .fcp + 1 .rtp), Kubernetes, the MEC platform, a remote host, 0.0.0.0
  * a CA, a certificate lifecycle, revocation or a key store: one throwaway CA per run
  * the guide's tinydb or debug logging (memory and error/warn instead; debug was not run)
  * not a conformance claim
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
NEW_FILES = (Path(__file__).resolve(),)          # the files this change adds: scanned for key material

# Expected values, by hand.
ACME = "/home/edgefollow/estimed-venv/bin/acmecse"
ACME_DIST = Path("/home/edgefollow/estimed-venv/lib/python3.13/site-packages/acmecse-2026.5.3.dist-info")
OPENSSL = "/usr/bin/openssl"
SP = "//acme.example.com"
IN_ID, IN_RN = "estimed-id-in", "estimed-in"                 # the guide's example names
IN_PORT, MN_PORT, AW_IN_PORT, AW_MN_PORT = 8270, 8271, 8272, 8273
PRIVATE_PORTS = (IN_PORT, MN_PORT, AW_IN_PORT, AW_MN_PORT)  # no other file's: 8200-8204, 8210-8240 and
#                                                           8250/8251 (test_mec_svc_oneM2M.py) are taken
MN_ID, MN_RN = "estimed-id-mn-t", "estimed-mn-t"
IN_BASE, MN_BASE = f"https://127.0.0.1:{IN_PORT}/{IN_RN}", f"http://127.0.0.1:{MN_PORT}/{MN_RN}"
LAB_RUN, LAB_DIRS, LAB_PORTS = Path("/home/edgefollow/estimed-run"), ("in", "mn-a", "mn-b"), (8200, 8201, 8202)
USER_VAR, PASS_VAR = "ACME_CSE_REGISTRAR_SECURITY_HTTPUSERNAME", "ACME_CSE_REGISTRAR_SECURITY_HTTPPASSWORD"
CHECK_INTERVAL = 2                                          # the MNs' [cse.registration] checkInterval, seconds
# ACME's own log texts (plugins/bindings/HttpServer.py:550, :575, plugins/services/RemoteCSEManager.py:508)
UNAUTHORIZED = "Unauthorized access when sending HTTP request"
FAILED_SEND = "Failed to send request"
UNREACHABLE = "Registrar CSE unreachable - assuming it is still there"

# 5.2.4.1.4 as printed. [basic.config] and the other sections, then [http.security] word for word.
TR_BASIC = {"cseType": "IN", "cseID": IN_ID, "cseName": IN_RN, "serviceProviderID": SP, "adminID": "CAdmin",
            "networkInterface": "0.0.0.0", "cseHost": "mncse.exactagss.com", "databaseType": "tinydb",
            "httpPort": "9090", "consoleTheme": "dark", "consoleType": "rich", "logLevel": "debug"}
TR_SECTIONS = {
    "http": {"enableManagementEndpoint": "true", "enableStructureEndpoint": "true", "enableUpperTesterEndpoint": "true"},
    "textui": {"startWithTUI": "false"},
    "cse.registration": {"allowedCSROriginators": "/estimed-id*"},
    "cse.operation.requests": {"enable": "true"},
    "http.security": {"useTLS": "true", "tlsVersion": "auto", "verifyCertificate": "false",
                      "caCertificateFile": "${basic.config:baseDirectory}/certs/acme_cert.pem",
                      "caPrivateKeyFile": "${basic.config:baseDirectory}/certs/acme_key.pem",
                      "enableBasicAuth": "true",
                      "basicAuthFile": "${basic.config:baseDirectory}/certs/http_basic_auth.txt"}}
# What this file changes in [basic.config], and why: loopback only, nothing on disk, headless, no user name in a log
IN_CHANGES = {"networkInterface": "127.0.0.1", "cseHost": "127.0.0.1", "databaseType": "memory",
              "httpPort": "<port>", "consoleType": "simple", "logLevel": "error"}
IN_ADDED = ("secret",)                                      # a random secret per run instead of ACME's default 'acme'
LOGGING = {"enableFileLogging": "true", "enableScreenLogging": "false", "stackTraceOnError": "true"}
FIX_LINES = {                                               # F1, F3, F2 (module docstring)
    ("http", "address"): "https://${basic.config:cseHost}:${basic.config:httpPort}${http:root}",
    ("http", "enableStructureEndpoint"): "false",
    ("http.security", "enableTokenAuth"): "true",
    ("http.security", "tokenAuthFile"): "${basic.config:baseDirectory}/certs/http_token_auth.txt"}
TOKEN_FILE_TEXT = "# token auth is on only so that ACME checks Bearer headers (F2); this file holds no token\n"

_STARTED: list[subprocess.Popen] = []                       # every process this module started


# ------------------------------------------------------------------------------------------ secrets
class _Secret(str):
    """A per-run secret: its value where code needs it, '<redacted>' wherever pytest or a message shows it."""
    __slots__ = ()

    def __repr__(self) -> str:
        return "'<redacted>'"


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _forms(creds) -> dict[str, bytes]:
    """The ways the run's credentials could appear in a file or on the wire."""
    return {"password": creds.password.encode(), "user": creds.user.encode(), "wrong password": creds.wrong.encode(),
            "user:password base64": base64.b64encode(f"{creds.user}:{creds.password}".encode()),
            "IN secret": creds.in_secret.encode()}


_DASH5 = "-" * 5
SCAN_PATTERNS = {
    "PEM armor": re.compile(_DASH5 + r"BEGIN [A-Z0-9 ]+" + _DASH5),
    "private key name": re.compile("PRIVATE" + r"\s+" + "KEY"),
    "base64 run of 64+": re.compile(r"[A-Za-z0-9+/]{64,}={0,2}"),
    "hex run of 40+": re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{40,}(?![0-9A-Za-z])"),
    "URL userinfo": re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"<>]+:[^\s/@'\"<>]+@"),
    "Basic credentials": re.compile(r"Basic\s+([A-Za-z0-9+/]{8,}={0,2})"),   # and it decodes to user:password
    "Bearer token": re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{20,}"),
    "credential assignment": re.compile(
        r"(?i)(?:password|passwd|secret|token|api[_-]?key)\w*['\"]?\s*[:=]\s*['\"][^'\"\s]{6,}['\"]"),
}


def _decodes_to_userinfo(token: str) -> bool:
    try:
        return b":" in base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except ValueError:
        return False


def _scan_text(text: str) -> list[str]:
    """Names of the SCAN_PATTERNS that match, with the line number (never the match itself)."""
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        for name, rx in SCAN_PATTERNS.items():
            found = [m for m in rx.finditer(line)
                     if name != "Basic credentials" or _decodes_to_userinfo(m.group(1).rstrip("="))]
            if found:
                hits.append(f"{name} at line {n}")
    return hits


# ------------------------------------------------------------------------------------------ processes
def _stop_with_this_process() -> None:
    """In each private CSE's process, before ACME runs (copied from test_tr0086_options_c_d.py, with its control
    below): SIGINT back to its default disposition, then PR_SET_PDEATHSIG SIGINT, so a killed test process does not
    leave a private CSE, its port or its key file in use."""
    import ctypes
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    if ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGINT), 0, 0, 0) != 0:     # 1: PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG)")


def _port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _fd_links(pid: int | str) -> set[str]:
    """What the process's fds point to. Read one by one: an fd closed meanwhile (the listing's own, in this
    process) is skipped, not the whole process (test_tr0086_options_c_d.py's _listener skips the process)."""
    links = set()
    try:
        fds = list(Path(f"/proc/{pid}/fd").iterdir())
    except OSError:
        return links
    for fd in fds:
        with contextlib.suppress(OSError):
            links.add(os.readlink(fd))
    return links


def _listener(port: int) -> list[int]:
    """pids holding the listening TCP socket on 127.0.0.1:port, from /proc/net/tcp and the processes' fds."""
    inodes = {f[9] for f in (line.split() for line in Path("/proc/net/tcp").read_text().splitlines()[1:])
              if f[1] == f"0100007F:{port:04X}" and f[3] == "0A"}
    if not inodes:
        return []
    return sorted(int(p.name) for p in Path("/proc").glob("[0-9]*")
                  if any(f"socket:[{i}]" in _fd_links(p.name) for i in inodes))


def _listening(pid: int) -> list[str]:
    """Every listening TCP socket (v4 and v6) the process holds, as 'address:port'."""
    links = _fd_links(pid)
    out = []
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        for f in (line.split() for line in Path(table).read_text().splitlines()[1:]):
            if f[3] == "0A" and f"socket:[{f[9]}]" in links:
                addr, port = f[1].split(":")
                host = socket.inet_ntoa(bytes.fromhex(addr)[::-1]) if len(addr) == 8 else f"[{addr}]"
                out.append(f"{host}:{int(port, 16)}")
    return sorted(out)


def _started(pid: int) -> int:
    """The process's start time in clock ticks since boot (field 22 of /proc/<pid>/stat)."""
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19])


def _wait(pred, timeout: float, step: float = 0.2) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return bool(pred())


LEFTOVER_AGE_S = 3600


def _sweep_leftovers(now: float | None = None) -> list[Path]:
    """Remove throwaway directories (keys, CA keys, inis with CSE secrets) that an earlier run of this module left
    behind because pytest itself was killed (SIGKILL skips every finally). Only this module's own prefix, only
    directories older than LEFTOVER_AGE_S, only in the temporary directory. Returns what was removed."""
    now = time.time() if now is None else now
    gone = []
    for d in Path(tempfile.gettempdir()).glob("tr0086-tls-*"):
        try:
            if d.is_dir() and not d.is_symlink() and now - d.stat().st_mtime > LEFTOVER_AGE_S:
                shutil.rmtree(d, ignore_errors=True)
                gone.append(d)
        except OSError:
            pass
    return gone


def _start_acme(base: Path, env: dict) -> subprocess.Popen:
    """ACME on base/acme.ini with base as its base directory; logs in base/logs."""
    with (base / "stdout.log").open("wb") as out:
        proc = subprocess.Popen([ACME, "--headless", "--config", "acme.ini", "--base-directory", str(base)],
                                cwd=base, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                start_new_session=True, preexec_fn=_stop_with_this_process)
    _STARTED.append(proc)
    return proc


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)


def _log_count(base: Path, phrase: str) -> int:
    """How many lines of the CSE's log files contain the fixed phrase (the lines themselves are not returned)."""
    return sum(line.count(phrase) for p in sorted((base / "logs").glob("*.log*"))
               for line in p.read_text(errors="replace").splitlines())


# ------------------------------------------------------------------------------------------ PKI
def _openssl(cwd: Path, *args: str) -> None:
    subprocess.run([OPENSSL, *args], cwd=cwd, env={}, check=True, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)


def _make_ca(d: Path, name: str, cn: str) -> Path:
    (d / "ca.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n[ca_ext]\nbasicConstraints=critical,CA:TRUE\n"
                              "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
    _openssl(d, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", f"{name}.key", "-out", f"{name}.pem", "-days", "1", "-subj", f"/CN={cn}",
             "-config", "ca.cnf", "-extensions", "ca_ext")
    return d / f"{name}.pem"


def _make_leaf(pki, certs: Path) -> None:
    """A server certificate for 127.0.0.1 (IP SAN only) signed by the run's CA, at the guide's paths
    (certs/acme_cert.pem, certs/acme_key.pem under the CSE's base directory)."""
    d = pki.dir
    (d / "leaf.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
                                "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    certs.mkdir(parents=True)
    csr = d / f"{certs.parent.name}.csr"
    _openssl(d, "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
             "-keyout", str(certs / "acme_key.pem"), "-out", str(csr), "-subj", "/CN=127.0.0.1", "-config", "ca.cnf")
    _openssl(d, "x509", "-req", "-in", str(csr), "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial",
             "0x" + secrets.token_hex(16), "-days", "1", "-out", str(certs / "acme_cert.pem"), "-extfile", "leaf.cnf")


def _client(cafile: Path) -> ssl.SSLContext:
    """A client that verifies the chain against cafile alone and checks the name (Python's defaults)."""
    return ssl.create_default_context(cafile=str(cafile))


# ------------------------------------------------------------------------------------------ ini files
def _render(sections: dict) -> str:
    ini = "\n".join(f"[{name}]\n" + "".join(f"{k} = {v}\n" for k, v in kv.items()) for name, kv in sections.items())
    if re.search(r"(?mi)^\s*baseDirectory\s*[=:]", ini):
        raise ValueError("a private CSE's ini sets baseDirectory")       # its logs would leave the temp directory
    return ini


def _in_sections(port: int, secret: str, *, fixed: bool) -> dict:
    """The guide's IN: TR_BASIC with IN_CHANGES and a secret, [logging], TR_SECTIONS, and FIX_LINES if fixed."""
    basic = {**TR_BASIC, **IN_CHANGES, "httpPort": str(port), "secret": secret}
    s = {"basic.config": basic, "logging": dict(LOGGING), **{k: dict(v) for k, v in TR_SECTIONS.items()}}
    if fixed:
        for (section, key), value in FIX_LINES.items():
            s[section][key] = value
    return s


def _mn_sections(csi: str, rn: str, port: int, registrar_port: int, secret: str) -> dict:
    """An MN on plain HTTP whose registrar is the IN at https://127.0.0.1:<registrar_port>. Its registrar credentials
    come from USER_VAR and PASS_VAR in its environment (acme.ini.default reads them), as the guide exports them."""
    return {"basic.config": {"cseType": "MN", "cseID": csi, "cseName": rn, "serviceProviderID": SP, "adminID": "CAdmin",
                             "networkInterface": "127.0.0.1", "cseHost": "127.0.0.1", "databaseType": "memory",
                             "httpPort": str(port), "consoleTheme": "dark", "consoleType": "simple", "logLevel": "warn",
                             "secret": secret, "registrarCseHost": "127.0.0.1", "registrarCsePort": str(registrar_port),
                             "registrarCseID": IN_ID, "registrarCseName": IN_RN},
            "logging": dict(LOGGING),
            "textui": {"startWithTUI": "false"},
            "cse.registration": {"checkInterval": str(CHECK_INTERVAL)},
            "cse.registrar": {"address": "https://${basic.config:registrarCseHost}:${basic.config:registrarCsePort}"}}


# ------------------------------------------------------------------------------------------ requests
def _m2m(method: str, url: str, *, ctx: ssl.SSLContext | None = None, auth=None, authorization: str | None = None,
         origin: str = "CAdmin", ty: int | None = None, body: dict | None = None, onem2m: bool = True,
         extra: dict | None = None, timeout: float = 10.0) -> tuple[int, int | None, dict | None, dict]:
    """One request -> (http status, X-M2M-RSC, parsed body, response headers). No proxy; https only with ctx.
    Transport failures raise (OSError, http.client.HTTPException, urllib.error.URLError)."""
    headers = {"Accept": "application/json"}
    if onem2m:
        headers.update({"X-M2M-Origin": origin, "X-M2M-RI": f"tls-{uuid.uuid4().hex[:12]}", "X-M2M-RVI": "4"})
    if body is not None:
        headers["Content-Type"] = f"application/json;ty={ty}" if ty else "application/json"
    if auth is not None:
        headers["Authorization"] = _basic(*auth)
    if authorization is not None:
        headers["Authorization"] = authorization
    headers.update(extra or {})
    handlers = [urllib.request.ProxyHandler({})] + ([urllib.request.HTTPSHandler(context=ctx)] if ctx else [])
    r = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                               headers=headers)
    try:
        with urllib.request.build_opener(*handlers).open(r, timeout=timeout) as resp:
            raw, status, hdrs = resp.read(), resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw, status, hdrs = e.read(), e.code, dict(e.headers)
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    code = {k.lower(): v for k, v in hdrs.items()}.get("x-m2m-rsc")
    return status, (int(code) if code else None), parsed, hdrs


def _failure(fn) -> BaseException | None:
    """The transport error fn raised (URLError unwrapped), or None if fn got any HTTP answer."""
    try:
        fn()
    except urllib.error.HTTPError:
        return None
    except urllib.error.URLError as e:
        return e.reason if isinstance(e.reason, BaseException) else e
    except (OSError, http.client.HTTPException) as e:
        return e
    return None


def _tls_handshake(port: int, ctx: ssl.SSLContext, name: str = "127.0.0.1") -> tuple[dict, str]:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=name) as s:
        return s.getpeercert(), s.version()


def _in_get(pki, port: int, path: str = "", **kw):
    return _m2m("GET", f"https://127.0.0.1:{port}/{IN_RN}{path}", ctx=pki.ctx, auth=pki.auth, **kw)


def _in_csrs(pki, port: int) -> list[str] | None:
    """Every <remoteCSE> the IN on port holds, read over TLS with the run's credentials; None if it did not answer."""
    try:
        st, _, body, _ = _in_get(pki, port, "?fu=1&ty=16")
    except (OSError, http.client.HTTPException):
        return None
    return sorted(body["m2m:uril"]) if st == 200 else None


def _up(pki, port: int) -> bool:
    """The IN on port answers a GET of its CSEBase with 200, over TLS with the run's credentials or else over plain
    HTTP. Which one, and whether it should, is for the tests to say."""
    for fn in (lambda: _in_get(pki, port), lambda: _m2m("GET", f"http://127.0.0.1:{port}/{IN_RN}")):
        try:
            if fn()[0] == 200:
                return True
        except (OSError, http.client.HTTPException):
            pass
    return False


def _mn_csrs(port: int, rn: str) -> list[str] | None:
    try:
        st, _, body, _ = _m2m("GET", f"http://127.0.0.1:{port}/{rn}?fu=1&ty=16")
    except (OSError, http.client.HTTPException):
        return None
    return sorted(body["m2m:uril"]) if st == 200 else None


def _poa_summary(poa: list[str], creds) -> list[tuple]:
    """(scheme, host, port, user name is the run's, password is the run's) per poa URL; nothing secret."""
    out = []
    for u in poa:
        p = urllib.parse.urlsplit(u)
        out.append((p.scheme, p.hostname, p.port, p.username == creds.user, p.password == creds.password))
    return out


def _record_next_connection(port: int, timeout: float = 20.0) -> bytes:
    """Listen on 127.0.0.1:port, accept one connection and return what the peer sent first (an HTTP request head or
    a TLS ClientHello). Nothing is sent back."""
    with socket.socket() as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(timeout)
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(3)
            data = b""
            with contextlib.suppress(OSError):
                while len(data) < 16384 and b"\r\n\r\n" not in data and not data.startswith(b"\x16"):
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
    return data


def _wire_summary(data: bytes, creds) -> dict:
    """What the recorded bytes are, without the bytes: a TLS record or an HTTP request (its request line, which
    holds no credential: ACME moves userinfo into the Authorization header), and whether the run's credentials are
    in them in clear."""
    line = data.split(b"\r\n", 1)[0] if b"\r\n" in data else b""
    http_line = re.fullmatch(rb"(GET|POST|PUT|DELETE) (/\S*) HTTP/1\.[01]", line)
    forms = _forms(creds)
    return {"bytes": len(data) > 0,
            "tls record": data[:1] == b"\x16" and data[1:2] == b"\x03",
            "http request line": http_line.group(1).decode() + " " + http_line.group(2).decode() if http_line else None,
            "Basic header with the run's credentials": f"Authorization: {_basic(creds.user, creds.password)}".encode()
                                                      in data,
            "password in clear": forms["password"] in data or forms["user:password base64"] in data}


# ------------------------------------------------------------------------------------------ the lab, read only
_UNREAD = re.compile(r"(^\.env)|(\.(pem|key|p12|pfx)$)", re.I)    # names whose content is never read here


def _lab_snapshot(root: Path = LAB_RUN, dirs=LAB_DIRS, ports=LAB_PORTS) -> dict:
    """Every file under the lab's CSE folders: (inode, size, sha256), stat only for key-like names; and the pids
    (with start times) that hold the lab's ports. Read only; nothing is sent to the lab."""
    files = {}
    for d in dirs:
        for p in sorted((root / d).rglob("*")):
            st = p.lstat()
            if p.is_symlink() or not p.is_file():
                continue
            digest = f"mtime {st.st_mtime_ns}" if _UNREAD.search(p.name) else hashlib.sha256(p.read_bytes()).hexdigest()
            files[str(p)] = (st.st_ino, st.st_size, digest)
    pids = {port: [(pid, _started(pid)) for pid in _listener(port)] for port in ports}
    return {"files": files, "pids": pids}


def _lab_changes(before: dict, after: dict) -> list[str]:
    bad = [f"added {p}" for p in after["files"].keys() - before["files"].keys()]
    bad += [f"gone {p}" for p in before["files"].keys() - after["files"].keys()]
    bad += [f"changed {p}: {'inode' if a[0] != b[0] else 'size' if a[1] != b[1] else 'content'}"
            for p in before["files"].keys() & after["files"].keys()
            for b, a in [(before["files"][p], after["files"][p])] if a != b]
    bad += [f"port {port}: {before['pids'][port]} -> {after['pids'].get(port)}"
            for port in before["pids"] if before["pids"][port] != after["pids"].get(port)]
    return sorted(bad)


# ------------------------------------------------------------------------------------------ fixtures
@pytest.fixture(scope="module")
def guard():
    """Around every live test of the module: the private ports are free and the lab's three CSEs run before; after
    everything this module started has stopped, the lab's files and pids are as they were (_lab_snapshot), nothing
    listens on a private port, no process this module started is alive (any that is gets SIGKILL, by its pid, after
    being recorded) and the temporary directory is gone."""
    held = {p: _listener(p) for p in PRIVATE_PORTS if _listener(p) or _port_open(p)}
    if held:
        pytest.fail(f"private ports already held: {held}", pytrace=False)
    before = _lab_snapshot()
    if any(len(v) != 1 for v in before["pids"].values()):
        pytest.fail(f"the lab's CSEs are not each running on {LAB_PORTS}: {before['pids']}", pytrace=False)
    if not ACME_DIST.is_dir():
        pytest.fail(f"ACME 2026.5.3 is not the installed release ({ACME_DIST} missing)", pytrace=False)
    state = SimpleNamespace(t0=time.time(), t0_ns=time.time_ns(), roots=[])
    yield state
    left = [p.pid for p in _STARTED if p.poll() is None]
    for p in _STARTED:
        if p.poll() is None:
            p.kill()
            p.wait(5)
    listening = {p: _listener(p) for p in PRIVATE_PORTS if _listener(p) or _port_open(p)}
    roots = [str(r) for r in state.roots if r.exists()]
    changes = _lab_changes(before, _lab_snapshot())
    assert (left, listening, roots, changes) == ([], {}, [], []), \
        f"after the module: still running {left}, listening {listening}, temp dirs left {roots}, lab changed {changes}"


@pytest.fixture(scope="module")
def pki(guard):
    """The run's throwaway material, in a new temporary directory outside the repo: a CA (ca.pem/ca.key), another CA
    with the same name and its own key, and the credentials. Server certificates are made per IN (_make_leaf)."""
    _sweep_leftovers()
    root = Path(tempfile.mkdtemp(prefix="tr0086-tls-"))
    guard.roots.append(root)
    try:
        if root.resolve().is_relative_to(REPO):
            pytest.fail(f"the temporary directory {root} is inside the repo", pytrace=False)
        d = root / "pki"
        d.mkdir()
        cn = f"tr0086 throwaway test CA {secrets.token_hex(4)}"
        ca = _make_ca(d, "ca", cn)
        other = root / "other-ca"
        other.mkdir()
        other_ca = _make_ca(other, "ca", cn)
        creds = SimpleNamespace(user=_Secret(secrets.token_urlsafe(12)), password=_Secret(secrets.token_urlsafe(24)),
                                wrong=_Secret(secrets.token_urlsafe(24)), in_secret=_Secret(secrets.token_urlsafe(24)))
        yield SimpleNamespace(root=root, dir=d, ca=ca, other_ca=other_ca, cn=cn, ctx=_client(ca), creds=creds,
                              auth=(creds.user, creds.password), t0=guard.t0)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _start_in(pki, name: str, port: int, *, fixed: bool) -> SimpleNamespace:
    """An IN in pki.root/name on port: its certificate, the Basic-auth file (user:HMAC-SHA256(secret, password), as
    ACME's SecurityManager checks it), the token file if fixed, the ini; started and answering."""
    if _port_open(port):
        pytest.fail(f":{port} is already held", pytrace=False)
    base = pki.root / name
    _make_leaf(pki, base / "certs")
    digest = hmac.new(pki.creds.in_secret.encode(), pki.creds.password.encode(), hashlib.sha256).hexdigest()
    (base / "certs" / "http_basic_auth.txt").write_text(f"{pki.creds.user}:{digest}\n")
    if fixed:
        (base / "certs" / "http_token_auth.txt").write_text(TOKEN_FILE_TEXT)
    (base / "acme.ini").write_text(_render(_in_sections(port, pki.creds.in_secret, fixed=fixed)))
    proc = _start_acme(base, env={})
    if not _wait(lambda: proc.poll() is not None or _up(pki, port), timeout=30) or proc.poll() is not None:
        _stop(proc)
        pytest.fail(f"the private IN-CSE did not come up on :{port}; see {base}/logs", pytrace=False)
    logs = sorted(x.name for x in (base / "logs").glob("*"))
    if logs != [f"cse-{SP[2:]}-{IN_ID}.log"]:
        _stop(proc)
        pytest.fail(f"the private IN's log is not under its own base directory alone: {logs}", pytrace=False)
    return SimpleNamespace(proc=proc, base=base, port=port)


def _start_mn(pki, name: str, csi: str, rn: str, port: int, registrar_port: int, env: dict) -> SimpleNamespace:
    """An MN in pki.root/name on port, registrar the IN on registrar_port; started and answering on plain HTTP."""
    if _port_open(port):
        pytest.fail(f":{port} is already held", pytrace=False)
    base = pki.root / name
    base.mkdir()
    (base / "acme.ini").write_text(_render(_mn_sections(csi, rn, port, registrar_port, _Secret(secrets.token_urlsafe(24)))))
    proc = _start_acme(base, env=env)
    if not _wait(lambda: proc.poll() is not None or _mn_csrs(port, rn) is not None, timeout=30) \
            or proc.poll() is not None:
        _stop(proc)
        pytest.fail(f"the private MN-CSE {csi} did not come up on :{port}; see {base}/logs", pytrace=False)
    return SimpleNamespace(proc=proc, base=base, port=port, csi=csi, rn=rn)


def _creds_env(pki) -> dict:
    return {USER_VAR: pki.creds.user, PASS_VAR: pki.creds.password}


@pytest.fixture(scope="module")
def tls_in(pki):
    """The IN of 5.2.4.1 on :8270: the guide's lines, IN_CHANGES and FIX_LINES."""
    i = _start_in(pki, "in", IN_PORT, fixed=True)
    try:
        yield i
    finally:
        _stop(i.proc)


@pytest.fixture(scope="class", params=["wrong password", "no credentials"])
def refused_mn(request, pki, tls_in):
    """The MN of TestRegistration with a wrong password, or with no credentials at all (env={}); kept until it has
    logged two refused attempts (ACME's ERROR line on a 401 from its registrar), or 25 s."""
    env = {USER_VAR: pki.creds.user, PASS_VAR: pki.creds.wrong} if request.param == "wrong password" else {}
    mn = _start_mn(pki, f"mn-{request.param.replace(' ', '-')}", MN_ID, MN_RN, MN_PORT, IN_PORT, env)
    try:
        _wait(lambda: mn.proc.poll() is not None or _log_count(mn.base, UNAUTHORIZED) >= 2, timeout=25)
        yield SimpleNamespace(**vars(mn), what=request.param)
    finally:
        _stop(mn.proc)


@pytest.fixture(scope="class")
def good_mn(pki, tls_in):
    """The MN with the run's credentials, kept until the IN holds its <remoteCSE> (or 25 s). Afterwards: stopped,
    the IN no longer holds it (ACME unregisters on stop, over HTTPS with the credentials) and :8271 is free."""
    mn = _start_mn(pki, "mn", MN_ID, MN_RN, MN_PORT, IN_PORT, _creds_env(pki))
    t0 = time.monotonic()
    registered = _wait(lambda: _in_csrs(pki, IN_PORT) == [f"{IN_RN}/{MN_ID}"], timeout=25)
    try:
        yield SimpleNamespace(**vars(mn), registered=registered, after=time.monotonic() - t0, t_registered=time.monotonic())
    finally:
        _stop(mn.proc)
        left = (_in_csrs(pki, IN_PORT), _port_open(MN_PORT))
        assert left == ([], False), f"after the MN stopped: the IN holds {left[0]}, :{MN_PORT} held {left[1]}"


@contextlib.contextmanager
def _pair(pki, tag: str, *, fixed: bool, csi: str, rn: str):
    """An IN on :8272 (as the guide writes it, or with FIX_LINES) and an MN on :8273 registered to it."""
    i = _start_in(pki, f"in-{tag}", AW_IN_PORT, fixed=fixed)
    try:
        mn = _start_mn(pki, f"mn-{tag}", csi, rn, AW_MN_PORT, AW_IN_PORT, _creds_env(pki))
        try:
            registered = _wait(lambda: _in_csrs(pki, AW_IN_PORT) == [f"{IN_RN}/{csi}"], timeout=25)
            yield SimpleNamespace(inn=i, mn=mn, registered=registered, t_registered=time.monotonic())
        finally:
            _stop(mn.proc)
    finally:
        _stop(i.proc)


@pytest.fixture(scope="class")
def as_written(pki):
    with _pair(pki, "as-written", fixed=False, csi="estimed-id-mn-l", rn="estimed-mn-l") as p:
        yield p


@pytest.fixture(scope="class")
def fixed_pair(pki):
    with _pair(pki, "fixed", fixed=True, csi="estimed-id-mn-f", rn="estimed-mn-f") as p:
        yield p


# ------------------------------------------------------------------------------------------ offline
def test_secrets_the_new_files_hold_no_key_material_or_credentials():
    """No PEM block, key name, long base64 or hex run, URL userinfo, Basic/Bearer credential or credential-looking
    assignment in the files this change adds. The patterns are built from pieces so this file does not match itself.
    Not shown: anything about files other than NEW_FILES (the end test checks what the run wrote)."""
    hits = {str(p.relative_to(REPO)): _scan_text(p.read_text()) for p in NEW_FILES}
    assert hits == {str(p.relative_to(REPO)): [] for p in NEW_FILES}


def test_secrets_control_the_scanner_flags_each_kind():
    """CONTROL: one sample per pattern, made here at run time from random bytes, each flagged by its own pattern;
    ordinary text and this file's own uses (an invalid Bearer, a URL without userinfo) are not."""
    b64 = base64.b64encode(secrets.token_bytes(48)).decode()
    samples = {
        "PEM armor": _DASH5 + "BEGIN CERTIFICATE" + _DASH5,
        "private key name": "EC " + "PRIVATE" + " KEY",
        "base64 run of 64+": b64,
        "hex run of 40+": secrets.token_hex(20),
        "URL userinfo": "https://" + "u" + secrets.token_hex(3) + ":" + secrets.token_hex(6) + "@127.0.0.1:1",
        "Basic credentials": "Authorization: " + _basic("u", secrets.token_hex(6)),
        "Bearer token": "Bearer " + secrets.token_urlsafe(24).replace("-", "a").replace("_", "b"),
        "credential assignment": "pass" + "word = '" + secrets.token_hex(6) + "'",
    }
    flagged = {name: [h.split(" at line")[0] for h in _scan_text(text)] for name, text in samples.items()}
    assert all(name in flagged[name] for name in samples), flagged
    assert _scan_text("ordinary words, Bearer not-a-token, https://127.0.0.1:8270/estimed-in, 2001") == []


def test_ini_the_in_is_the_guides_lines_with_the_listed_changes_and_the_fix_lines():
    """The :8272 IN as written is 5.2.4.1.4 with exactly IN_CHANGES and IN_ADDED in [basic.config] and [logging] added;
    its [http.security] is the guide's seven lines; the :8270 IN differs from it by FIX_LINES alone. No baseDirectory
    line (ACME's --base-directory decides where logs go). Not shown: that ACME reads them so (the live tests)."""
    aw = _in_sections(AW_IN_PORT, "s", fixed=False)
    fx = _in_sections(AW_IN_PORT, "s", fixed=True)
    # the guide's [http.security] as printed (PDF p. 6), typed here rather than taken from TR_SECTIONS
    printed = """useTLS = true
tlsVersion = auto
verifyCertificate = false
caCertificateFile = ${basic.config:baseDirectory}/certs/acme_cert.pem
caPrivateKeyFile = ${basic.config:baseDirectory}/certs/acme_key.pem
enableBasicAuth = true
basicAuthFile = ${basic.config:baseDirectory}/certs/http_basic_auth.txt"""
    section = _render(aw).split("[http.security]\n", 1)[1].split("\n[", 1)[0].strip()
    assert section == printed
    assert sorted(f"{s}:{k}" for s, k in FIX_LINES) == ["http.security:enableTokenAuth", "http.security:tokenAuthFile",
                                                        "http:address", "http:enableStructureEndpoint"]
    changed = {k for k in TR_BASIC if aw["basic.config"][k] != TR_BASIC[k]}
    assert changed == set(IN_CHANGES) and set(aw["basic.config"]) - set(TR_BASIC) == set(IN_ADDED)
    assert {k: v for k, v in aw.items() if k not in ("basic.config", "logging")} == TR_SECTIONS
    diff = {(s, k): v for s, kv in fx.items() for k, v in kv.items() if aw.get(s, {}).get(k) != v}
    assert diff == FIX_LINES and set(fx) == set(aw)
    for sections in (aw, fx):
        assert not re.search(r"(?mi)^\s*baseDirectory\s*[=:]", _render(sections))
    with pytest.raises(ValueError, match="baseDirectory"):
        _render({"basic.config": {"BaseDirectory": "/home/edgefollow/estimed-run/in"}})


def test_control_a_child_dies_with_a_killed_parent_that_ignored_sigint():
    """CONTROL for _stop_with_this_process (its own source, in a parent that ignores SIGINT): the parent starts a
    child with it and is SIGKILLed; the child must be gone within 5 s."""
    import inspect
    import textwrap
    src = textwrap.dedent(inspect.getsource(_stop_with_this_process))
    parent = ("import signal, subprocess, sys, time\n"
              "signal.signal(signal.SIGINT, signal.SIG_IGN)\n" + src +
              "\nc = subprocess.Popen([sys.executable, '-I', '-c', 'import time\\nwhile True: time.sleep(0.2)'],"
              " preexec_fn=_stop_with_this_process, start_new_session=True)\n"
              "print(c.pid, flush=True)\ntime.sleep(60)\n")
    p = subprocess.Popen([sys.executable, "-I", "-c", parent], stdout=subprocess.PIPE, text=True)
    cpid = int(p.stdout.readline())
    try:
        p.kill()
        p.wait(5)
        state = "?"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{cpid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except OSError:
                state = "gone"
            if state in ("gone", "Z", "X"):
                break
            time.sleep(0.1)
        assert state in ("gone", "Z", "X"), f"the child (pid {cpid}) outlived its killed parent: state {state}"
    finally:
        with contextlib.suppress(OSError):
            os.kill(cpid, signal.SIGKILL)


def test_secrets_the_wrapper_never_shows_its_value():
    s = _Secret("a-throwaway-value")
    assert repr(s) == "'<redacted>'" and "a-throwaway-value" not in repr(s) and "a-throwaway-value" not in repr([s])
    assert str(s) == "a-throwaway-value" and s + "!" == "a-throwaway-value!"            # code still gets the value


def test_every_private_cse_starts_with_the_given_environment_and_dies_with_this_process(monkeypatch, tmp_path):
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kw):
            seen.update(kw)
            self.pid = 0

    monkeypatch.setattr(subprocess, "Popen", FakePopen)
    _start_acme(tmp_path, env={})
    _STARTED.pop()
    assert seen["env"] == {} and seen["preexec_fn"] is _stop_with_this_process and seen["start_new_session"] is True


def test_leftover_throwaway_directories_of_a_killed_run_are_swept(monkeypatch, tmp_path):
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    old, young, other = tmp_path / "tr0086-tls-old", tmp_path / "tr0086-tls-young", tmp_path / "unrelated-old"
    for d in (old, young, other):
        d.mkdir()
        (d / "ca.key").write_text("x")
    past = time.time() - LEFTOVER_AGE_S - 60
    os.utime(old, (past, past))
    os.utime(other, (past, past))
    assert _sweep_leftovers() == [old]
    assert not old.exists() and young.exists() and other.exists()


def test_control_the_lab_snapshot_sees_each_kind_of_change(tmp_path):
    """CONTROL for the guard's lab check, on a stand-in folder: an unchanged tree reads as unchanged; an appended
    line, a same-size rewrite, a replaced file (new inode), an added and a removed file are each reported."""
    for d in ("in", "mn-a"):
        (tmp_path / d / "logs").mkdir(parents=True)
        (tmp_path / d / "logs" / "a.log").write_text("one\n")
        (tmp_path / d / "cse.pid").write_text("123\n")
    snap = lambda: _lab_snapshot(tmp_path, ("in", "mn-a"), ())    # noqa: E731
    before = snap()
    assert _lab_changes(before, snap()) == []
    with (tmp_path / "in" / "logs" / "a.log").open("a") as f:
        f.write("two\n")                                           # appended
    (tmp_path / "mn-a" / "cse.pid").write_text("456\n")            # same inode, same size, other bytes
    (tmp_path / "mn-a" / "logs" / "tmp").write_text("one\n")
    os.replace(tmp_path / "mn-a" / "logs" / "tmp", tmp_path / "mn-a" / "logs" / "a.log")   # same bytes, new inode
    (tmp_path / "mn-a" / "logs" / "new.log").write_text("")      # added
    (tmp_path / "in" / "cse.pid").unlink()                       # removed
    got = _lab_changes(before, snap())
    assert got == sorted([f"changed {tmp_path}/in/logs/a.log: size", f"changed {tmp_path}/mn-a/cse.pid: content",
                          f"changed {tmp_path}/mn-a/logs/a.log: inode", f"added {tmp_path}/mn-a/logs/new.log",
                          f"gone {tmp_path}/in/cse.pid"])


def test_control_the_listener_check_finds_a_socket_this_process_holds():
    """CONTROL for _listener and _listening (the guard's 'nothing left listening'): a socket this process listens on
    is found, by port and by pid, and is gone once closed."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        assert os.getpid() in _listener(port) and f"127.0.0.1:{port}" in _listening(os.getpid())
    assert os.getpid() not in _listener(port)


# ------------------------------------------------------------------------------------------ the IN (5.2.4.1)
class TestIn:
    """The IN on :8270, read by this test as the developer does in 5.2.4.1.5, and the controls that must fail.
    Not shown here: the MN (TestRegistration); the guide's IN as written (TestAsWritten)."""

    def test_5_2_4_1_5_well_formed_get_with_basic_auth_over_tls(self, pki, tls_in):
        """5.2.4.1.5: GET {IN-CSEBase} with X-M2M-Origin CAdmin, RI, RVI and Basic auth, over TLS, verified against
        the run's CA -> 200 / 2000 and the IN as the guide names it. Its poa is https (F1's fix)."""
        st, code, body, _ = _in_get(pki, IN_PORT)
        cb = body["m2m:cb"]
        assert (st, code) == (200, 2000)
        assert (cb["ri"], cb["rn"], cb["csi"], cb["cst"], cb["spi"]) == (IN_ID, IN_RN, f"/{IN_ID}", 1, SP)
        assert cb["poa"] == [f"https://127.0.0.1:{IN_PORT}"]

    def test_5_2_4_1_5_control_a_get_without_onem2m_headers_is_rejected(self, pki, tls_in):
        """5.2.4.1.5: 'A plain HTTP GET without oneM2M headers ... is rejected by the CSE' -- with valid Basic auth
        over TLS: no RI -> 400 / 4000; RI and RVI but no originator -> 400 / 4000."""
        st, code, body, _ = _m2m("GET", IN_BASE, ctx=pki.ctx, auth=pki.auth, onem2m=False)
        assert (st, code) == (400, 4000) and "request identifier" in body["m2m:dbg"]
        r = urllib.request.Request(IN_BASE, headers={"X-M2M-RI": "r1", "X-M2M-RVI": "4", "Accept": "application/json",
                                                     "Authorization": _basic(*pki.auth)})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                        urllib.request.HTTPSHandler(context=pki.ctx)).open(r, timeout=10)
        assert (e.value.code, e.value.headers.get("X-M2M-RSC")) == (400, "4000")
        assert "originator" in json.loads(e.value.read())["m2m:dbg"]

    def test_the_in_runs_with_an_empty_environment(self, pki, tls_in):
        assert Path(f"/proc/{tls_in.proc.pid}/environ").read_bytes() == b""

    def test_control_no_credentials_is_401(self, pki, tls_in):
        """CONTROL: the same well-formed GET without Authorization -> 401, an empty body and no oneM2M result code:
        ACME answers at the HTTP layer. Observed: no WWW-Authenticate header either (RFC 9110 asks for one)."""
        st, code, body, hdrs = _m2m("GET", IN_BASE, ctx=pki.ctx)
        assert (st, code, body) == (401, None, None)
        assert "www-authenticate" not in {k.lower() for k in hdrs}

    def test_control_a_wrong_password_or_user_name_is_401(self, pki, tls_in):
        """CONTROL: the run's user name with another password, and another user name with the run's password -> 401."""
        u, p = pki.auth
        for auth in ((u, pki.creds.wrong), (_Secret(secrets.token_urlsafe(12)), p)):
            st, code, body, _ = _m2m("GET", IN_BASE, ctx=pki.ctx, auth=auth)
            assert (st, code, body) == (401, None, None)

    def test_control_plain_http_to_the_tls_port_gets_no_http_answer(self, pki, tls_in):
        """CONTROL: the well-formed GET over plain HTTP to :8270 gets no HTTP response at all (measured: the connection
        is reset). Sent without the credentials: this file never puts them on the wire in clear."""
        err = _failure(lambda: _m2m("GET", f"http://127.0.0.1:{IN_PORT}/{IN_RN}"))
        assert type(err).__name__ in ("ConnectionResetError", "RemoteDisconnected", "BadStatusLine"), repr(err)

    def test_control_a_client_verifying_against_another_ca_fails(self, pki, tls_in):
        """CONTROL: a client trusting another CA -- same name, own key -- refuses the IN's certificate, and so does
        one with the system's default trust store; the run's CA alone makes it verify."""
        for ctx in (_client(pki.other_ca), ssl.create_default_context()):
            err = _failure(lambda: _m2m("GET", IN_BASE, ctx=ctx, auth=pki.auth))
            assert isinstance(err, ssl.SSLCertVerificationError), repr(err)
            assert err.verify_message in ("unable to get local issuer certificate", "certificate signature failure")
        assert _m2m("GET", IN_BASE, ctx=_client(pki.ca), auth=pki.auth)[0] == 200

    def test_control_a_client_expecting_another_name_fails(self, pki, tls_in):
        """CONTROL: the certificate names 127.0.0.1 only; a verifying client that expects 'localhost' refuses it."""
        with pytest.raises(ssl.SSLCertVerificationError) as e:
            _tls_handshake(IN_PORT, pki.ctx, name="localhost")
        assert "mismatch" in e.value.verify_message.lower()

    def test_the_in_serves_this_runs_throwaway_certificate(self, pki, tls_in):
        """The certificate the IN presents: for IP 127.0.0.1, issued by this run's CA (its name carries a random tag),
        made after the module started, valid for one day; the key and certificate files the ini names are in the
        run's temporary directory. TLS version as negotiated with tlsVersion=auto."""
        cert, version = _tls_handshake(IN_PORT, pki.ctx)
        nb, na = ssl.cert_time_to_seconds(cert["notBefore"]), ssl.cert_time_to_seconds(cert["notAfter"])
        assert cert["subjectAltName"] == (("IP Address", "127.0.0.1"),)
        assert cert["issuer"] == ((("commonName", pki.cn),),)
        assert pki.t0 - 120 <= nb <= time.time() + 5 and na - nb == 86400
        assert version in ("TLSv1.2", "TLSv1.3")
        for f in ("acme_cert.pem", "acme_key.pem", "http_basic_auth.txt", "http_token_auth.txt"):
            assert (tls_in.base / "certs" / f).is_file()
        assert tls_in.base.resolve().is_relative_to(pki.root.resolve())

    def test_the_in_listens_on_its_tls_port_only(self, pki, tls_in):
        """The IN's process holds one listening TCP socket, 127.0.0.1:8270, which speaks TLS only (control above):
        whatever it served, including the MN's registration, came over TLS."""
        assert _listening(tls_in.proc.pid) == [f"127.0.0.1:{IN_PORT}"]
        assert _listener(IN_PORT) == [tls_in.proc.pid]
        assert _tls_handshake(IN_PORT, pki.ctx)[1].startswith("TLSv1.")

    def test_fix_f2_a_bearer_header_is_refused(self, pki, tls_in):
        """F2's fix (token auth on, no token issued): 'Authorization: Bearer ...' -> 401 on the API, on __mgmt__ and
        on the upper tester, as without any header; the admin endpoint answers to Basic auth."""
        bearer = "Bearer not-a-token"
        assert _m2m("GET", IN_BASE, ctx=pki.ctx, authorization=bearer)[:2] == (401, None)
        root = f"https://127.0.0.1:{IN_PORT}"
        for authorization in (bearer, None):
            assert _m2m("GET", f"{root}/__mgmt__/config", ctx=pki.ctx, authorization=authorization, onem2m=False)[0] == 401
            assert _m2m("POST", f"{root}/__ut__", ctx=pki.ctx, authorization=authorization, body={})[0] == 401
        assert _m2m("GET", f"{root}/__mgmt__/config", ctx=pki.ctx, auth=pki.auth, onem2m=False)[0] == 200

    def test_fix_f3_no_structure_endpoint(self, pki, tls_in):
        """F3's fix: with enableStructureEndpoint=false, __structure__ is an ordinary path and needs credentials.
        Observed beside it: ACME serves the static web UI page at /webui without credentials (its API calls do not)."""
        root = f"https://127.0.0.1:{IN_PORT}"
        assert _m2m("GET", f"{root}/__structure__/text", ctx=pki.ctx, onem2m=False)[0] == 401
        st, _, _, hdrs = _m2m("GET", f"{root}/webui", ctx=pki.ctx, onem2m=False)
        assert (st, hdrs.get("Content-Type", "").split(";")[0]) == (200, "text/html")


# ------------------------------------------------------------------------------------------ Mcc (5.2.4 step 3)
class TestRegistrationRefused:
    """CONTROLS for the registration: the same MN, same ini, same CSE-ID (one the IN admits), with a wrong password
    and with no credentials."""

    def test_mcc_control_registration_is_refused_and_the_in_holds_no_remote_cse(self, pki, tls_in, refused_mn):
        """The MN reached the IN over TLS and was answered 401 (ACME logs an ERROR line per refused attempt, two at
        least, each 2 s apart); the IN holds no <remoteCSE> and the MN none for the IN; the MN keeps running."""
        mn = refused_mn
        assert (mn.proc.poll(), _log_count(mn.base, UNAUTHORIZED) >= 2) == (None, True), mn.what
        assert _in_csrs(pki, IN_PORT) == []
        assert _in_get(pki, IN_PORT, f"/{MN_ID}")[:2] == (404, 4004)
        assert _mn_csrs(MN_PORT, MN_RN) == []
        assert _log_count(mn.base, UNREACHABLE) == 0, "the refusal must be the IN's 401, not a transport failure"


class TestRegistration:
    """5.2.4 step 3 and step 4 with the IN of 5.2.4.1: the MN registers over HTTPS with the registrar credentials."""

    def test_5_2_4_step3_the_mn_registered_over_https_with_registrar_credentials(self, pki, tls_in, good_mn):
        """The IN holds a <remoteCSE> for the MN with cst 2; the MN's registrar address is https; its environment is
        the guide's two variables and nothing else (keys read, values not); the IN speaks TLS only and refuses
        requests without the credentials, so the registration came over TLS with them."""
        mn = good_mn
        assert mn.registered, f"the IN did not hold the MN's <remoteCSE> within 25 s; see {mn.base}/logs"
        st, code, body, _ = _in_get(pki, IN_PORT, f"/{MN_ID}")
        csr = body["m2m:csr"]
        assert (st, code) == (200, 2000)
        assert (csr["ty"], csr["cst"], csr["csi"], csr["cb"], csr["pi"], csr["poa"]) == \
            (16, 2, f"/{MN_ID}", f"/{MN_ID}/{MN_RN}", IN_ID, [f"http://127.0.0.1:{MN_PORT}"])
        assert _in_csrs(pki, IN_PORT) == [f"{IN_RN}/{MN_ID}"]
        ini = (mn.base / "acme.ini").read_text()
        assert "address = https://${basic.config:registrarCseHost}:${basic.config:registrarCsePort}" in ini
        keys = sorted(e.split(b"=", 1)[0].decode() for e in Path(f"/proc/{mn.proc.pid}/environ").read_bytes().split(b"\0")
                      if e)
        assert keys == sorted([USER_VAR, PASS_VAR])
        assert _log_count(mn.base, UNAUTHORIZED) == 0

    def test_5_2_4_step4_items_1_3_4_over_tls(self, pki, tls_in, good_mn):
        """Step 4: 1 the IN-CSEBase answers (over TLS, with the credentials), 3 the MN-CSEBase answers, 4 GET
        {IN-CSEBase}/{mn-cse-csi} -> 200, ty=16. Item 2 (MEC 011) is not part of this file."""
        assert _in_get(pki, IN_PORT)[:2] == (200, 2000)
        st, code, body, _ = _m2m("GET", MN_BASE)
        assert (st, code, body["m2m:cb"]["csi"], body["m2m:cb"]["cst"]) == (200, 2000, f"/{MN_ID}", 2)
        st, code, body, _ = _in_get(pki, IN_PORT, f"/{MN_ID}")
        assert (st, code, body["m2m:csr"]["ty"]) == (200, 2000, 16)

    def test_the_mn_holds_the_in_as_its_registrar_at_an_https_poa(self, pki, good_mn):
        """The MN's own <remoteCSE> for the IN: csi /estimed-id-in, cst 1, poa https://127.0.0.1:8270 (F1's fix)."""
        assert _mn_csrs(MN_PORT, MN_RN) == [f"{MN_RN}/{IN_ID}"]
        st, _, body, _ = _m2m("GET", f"{MN_BASE}/{IN_ID}")
        csr = body["m2m:csr"]
        summary = _poa_summary(csr["poa"], pki.creds)
        assert (st, csr["csi"], csr["cst"], [s[:3] for s in summary]) == \
            (200, f"/{IN_ID}", 1, [("https", "127.0.0.1", IN_PORT)])

    def test_the_mn_keeps_checking_its_registrar_without_errors(self, pki, good_mn):
        """Over three check intervals after the registration, the MN logs no refused, failed or unreachable check and
        the IN still holds it. Not shown here that checks were sent (TestFixedOnTheWire reads one)."""
        time.sleep(max(0.0, good_mn.t_registered + 3 * CHECK_INTERVAL + 1 - time.monotonic()))
        counts = [_log_count(good_mn.base, p) for p in (UNAUTHORIZED, FAILED_SEND, UNREACHABLE)]
        assert (counts, _in_csrs(pki, IN_PORT)) == ([0, 0, 0], [f"{IN_RN}/{MN_ID}"])

    def test_open_f4_the_mn_keeps_the_registrar_credentials_in_that_poa(self, pki, good_mn):
        """OPEN (F4, ACME 2026.5.3): that poa carries the run's user name and password as URL userinfo; over the MN's
        plain HTTP, with no credential, an originator CAdmin or /estimed-id-in reads it; another originator is
        refused (403). Pinned so a release that stores them elsewhere turns this red."""
        for origin in ("CAdmin", f"/{IN_ID}"):
            st, _, body, _ = _m2m("GET", f"{MN_BASE}/{IN_ID}", origin=origin)
            assert (st, _poa_summary(body["m2m:csr"]["poa"], pki.creds)) == \
                (200, [("https", "127.0.0.1", IN_PORT, True, True)]), origin
        assert _m2m("GET", f"{MN_BASE}/{IN_ID}", origin="Cstranger")[0] == 403

    def test_limit_the_mn_does_not_verify_the_in_certificate(self, pki, tls_in, good_mn):
        """LIMIT, pinned: the IN's certificate chains only to this run's CA, which the MN was never given (its
        environment holds no CA bundle variable, its ini no verifyCertificate) and which the default trust store
        refuses -- yet the MN registered. So the MN did not verify it (ACME clears verifyCertificate on a CSE whose
        own server is plain HTTP). The guide's own check is `curl -sk`."""
        err = _failure(lambda: _m2m("GET", IN_BASE, ctx=ssl.create_default_context(), auth=pki.auth))
        assert isinstance(err, ssl.SSLCertVerificationError)
        assert "verifyCertificate" not in (good_mn.base / "acme.ini").read_text()
        assert good_mn.registered and _in_csrs(pki, IN_PORT) == [f"{IN_RN}/{MN_ID}"]


# ------------------------------------------------------------------------------------------ the guide's IN as written
class TestAsWritten:
    """The IN of 5.2.4.1.4 as written (no FIX_LINES) on :8272, with an MN on :8273 using the run's credentials:
    F1, F2 and F3 of the module docstring. Each test also asserts that TLS or Basic auth is in force, so it cannot
    pass on a plain IN."""

    def test_f1_the_in_advertises_an_http_poa_it_does_not_serve(self, pki, as_written):
        """F1: the CSEBase's poa is http://127.0.0.1:8272; plain HTTP to that port gets no answer; TLS does."""
        st, code, body, _ = _in_get(pki, AW_IN_PORT)
        assert (st, code, body["m2m:cb"]["poa"]) == (200, 2000, [f"http://127.0.0.1:{AW_IN_PORT}"])
        err = _failure(lambda: _m2m("GET", f"http://127.0.0.1:{AW_IN_PORT}/{IN_RN}"))
        assert type(err).__name__ in ("ConnectionResetError", "RemoteDisconnected", "BadStatusLine"), repr(err)

    def test_f1_the_mn_reports_its_registrar_unreachable_while_the_in_still_lists_it(self, pki, as_written):
        """F1: the MN registers (over the configured https address), then its checks at the http poa fail and ACME
        logs 'Registrar CSE unreachable - assuming it is still there'; the IN still holds the MN, so 5.2.4 step 4
        item 4 stays green while the link is broken. Its poa for the IN is the http one."""
        mn = as_written.mn
        assert as_written.registered
        assert _wait(lambda: _log_count(mn.base, UNREACHABLE) >= 1, timeout=20)
        assert _in_csrs(pki, AW_IN_PORT) == [f"{IN_RN}/{mn.csi}"]
        st, _, body, _ = _m2m("GET", f"http://127.0.0.1:{AW_MN_PORT}/{mn.rn}/{IN_ID}")
        assert [s[:3] for s in _poa_summary(body["m2m:csr"]["poa"], pki.creds)] == [("http", "127.0.0.1", AW_IN_PORT)]

    def test_f2_any_bearer_header_passes_basic_auth(self, pki, as_written):
        """F2: without credentials the IN answers 401 (Basic auth is on); with 'Authorization: Bearer' and any word
        it answers 200, registers a CSE-ID matching /estimed-id* that has no password (201 / 2001, then listed),
        and serves __mgmt__/config, which holds the IN's secret, and the upper tester's Status command. The rogue
        <remoteCSE> is removed again."""
        base = f"https://127.0.0.1:{AW_IN_PORT}/{IN_RN}"
        bearer = "Bearer not-a-token"
        assert _m2m("GET", base, ctx=pki.ctx)[0] == 401
        assert _m2m("GET", base, ctx=pki.ctx, authorization=bearer)[:2] == (200, 2000)
        rogue = {"m2m:csr": {"rn": "estimed-id-rogue", "csi": "/estimed-id-rogue", "cb": "/estimed-id-rogue/rogue",
                             "rr": False, "poa": ["http://127.0.0.1:9"], "cst": 2, "srv": ["4"]}}
        try:
            st, code, _, _ = _m2m("POST", base, ctx=pki.ctx, authorization=bearer, origin="/estimed-id-rogue", ty=16,
                                  body=rogue)
            assert (st, code) == (201, 2001)
            assert "estimed-in/estimed-id-rogue" in _in_csrs(pki, AW_IN_PORT)
        finally:
            _m2m("DELETE", f"{base}/estimed-id-rogue", ctx=pki.ctx, auth=pki.auth)
        assert "estimed-in/estimed-id-rogue" not in _in_csrs(pki, AW_IN_PORT)
        root = f"https://127.0.0.1:{AW_IN_PORT}"
        assert _m2m("GET", f"{root}/__mgmt__/config", ctx=pki.ctx, onem2m=False)[0] == 401
        st, _, body, _ = _m2m("GET", f"{root}/__mgmt__/config", ctx=pki.ctx, authorization=bearer, onem2m=False)
        holds_secret = pki.creds.in_secret in json.dumps(body)
        assert (st, holds_secret) == (200, True)
        status = {"X-M2M-UTCMD": "Status"}
        assert _m2m("POST", f"{root}/__ut__", ctx=pki.ctx, extra=status)[0] == 401
        assert _m2m("POST", f"{root}/__ut__", ctx=pki.ctx, authorization=bearer, extra=status)[:2] == (200, 2000)

    def test_f3_the_structure_endpoint_answers_without_credentials(self, pki, as_written):
        """F3: the CSEBase needs credentials (401), __structure__/text does not (200) and names the registered MN."""
        root = f"https://127.0.0.1:{AW_IN_PORT}"
        assert _m2m("GET", f"{root}/{IN_RN}", ctx=pki.ctx)[0] == 401
        r = urllib.request.Request(f"{root}/__structure__/text")
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=pki.ctx)).open(r, timeout=10) as resp:
            st, text = resp.status, resp.read().decode(errors="replace")
        assert (st, as_written.mn.csi in text, IN_ID in text) == (200, True, True)

    def test_f1_on_the_wire_the_mn_sends_its_credentials_in_clear_text(self, pki, as_written):
        """F1 on the wire: the IN is stopped and this test listens on its port. The MN's next registrar check comes
        as a plain HTTP request whose Authorization header is Basic with the run's user name and password, in
        clear. (Ends the class: the IN stays stopped.)"""
        _stop(as_written.inn.proc)
        summary = _wire_summary(_record_next_connection(AW_IN_PORT), pki.creds)
        assert summary == {"bytes": True, "tls record": False,
                           "http request line": f"GET /~/{IN_ID}/{IN_RN}/{as_written.mn.csi}",
                           "Basic header with the run's credentials": True, "password in clear": True}


class TestFixedOnTheWire:
    """CONTROL for F1 on the wire: the same pair with FIX_LINES."""

    def test_fix_f1_on_the_wire_the_mn_speaks_tls_only(self, pki, fixed_pair):
        """With the https poa, the MN's next registrar check after the IN stops is a TLS ClientHello; neither the
        credentials nor an HTTP request line are in clear. (Ends the class: the IN stays stopped.)"""
        assert fixed_pair.registered
        assert _in_get(pki, AW_IN_PORT)[0] == 200 and _m2m("GET", f"https://127.0.0.1:{AW_IN_PORT}/{IN_RN}",
                                                             ctx=pki.ctx)[0] == 401
        _stop(fixed_pair.inn.proc)
        summary = _wire_summary(_record_next_connection(AW_IN_PORT), pki.creds)
        assert summary == {"bytes": True, "tls record": True, "http request line": None,
                           "Basic header with the run's credentials": False, "password in clear": False}
        assert _log_count(fixed_pair.mn.base, UNAUTHORIZED) == 0


# ------------------------------------------------------------------------------------------ after the run
class TestSecretsAfterTheRun:
    """What the run left in files, read while its temporary directory still exists (it is removed afterwards and the
    guard checks that). Every CSE but the :8270 IN has stopped by now; that one logs at error level only."""

    def test_secrets_the_password_is_in_no_file_and_the_user_name_only_in_the_basic_auth_files(self, pki, tls_in):
        """Every file under the temporary directory -- inis, logs, stdout, certificates, keys -- holds neither the
        password, the wrong password, the user:password base64 nor the IN's secret outside the INs' inis; the user
        name is only in the INs' Basic-auth files (ACME's format: user:HMAC). Each MN that ran left its log here, so
        the logs were among the files read."""
        forms = _forms(pki.creds)
        found = {}
        for p in sorted(x for x in pki.root.rglob("*") if x.is_file()):
            data = p.read_bytes()
            hit = sorted(name for name, form in forms.items() if form in data)
            if hit:
                found[str(p.relative_to(pki.root))] = hit
        ins = [d.name for d in pki.root.iterdir() if d.name == "in" or d.name.startswith("in-")]
        expected = {**{f"{d}/certs/http_basic_auth.txt": ["user"] for d in ins},
                    **{f"{d}/acme.ini": ["IN secret"] for d in ins}}
        assert found == expected
        mns = [d for d in pki.root.glob("mn*") if d.is_dir()]
        assert len(list(pki.root.glob("mn*/logs/*.log"))) == len(mns), [d.name for d in mns]

    def test_secrets_nothing_written_under_the_repo_during_the_run_holds_them(self, pki, guard):
        """Every repo file (outside .git) modified since the module started holds none of the run's credentials and
        none of the run's keys or certificates (the first base64 line of each PEM file in the temporary directory);
        none of the file names the run writes there appeared in the repo. Only what is this run's is looked for, so a
        file another session writes meanwhile cannot fail this. Read only."""
        forms, bad = _forms(pki.creds), []
        pems = sorted([*pki.root.rglob("*.pem"), *pki.root.rglob("*.key")])
        for f in pems:
            body = [ln for ln in f.read_text().splitlines() if ln and not ln.startswith(_DASH5)]
            forms[f"PEM {f.relative_to(pki.root)}"] = body[0].encode()
        assert len(pems) >= 4, [str(f.relative_to(pki.root)) for f in pems]   # both CAs' certificate and key at least
        names = {"acme_cert.pem", "acme_key.pem", "ca.pem", "ca.key", "http_basic_auth.txt", "http_token_auth.txt"}
        for dirpath, dirnames, filenames in os.walk(REPO):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                p = Path(dirpath) / name
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if p.is_symlink() or st.st_mtime_ns < guard.t0_ns:
                    continue
                if name in names:
                    bad.append(f"{p}: a file name the run writes")
                if st.st_size > 5_000_000:
                    continue
                data = p.read_bytes()
                bad += [f"{p}: {n}" for n, f in forms.items() if f in data]
        assert bad == []
