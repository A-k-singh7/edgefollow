"""TR-0086 deployment options C and D (developer guide 5.2.2 table, 5.2.4 procedure; test plan 5.1 MEC_CFG_01
"Single VM (MN-CSE + MEC platform co-located)") against live processes, plus offline checks of the packages at the end.

    C  oneM2M MN-CSE as a MEC APP, co-located on the MEC host, registering to the IN-CSE
    D  oneM2M MN-CSE as a MEC SERVICE, co-located on the MEC host, registering to the IN-CSE
"The IN-CSE" here is a test-private IN with the lab IN's CSE-ID and name (below), so 5.2.4 step 4 item 1 (an IN
answers as id-in) holds by construction. The lab itself is option B: estimed/run_topology.sh starts MN-A and MN-B by
hand as separate processes.

What is deployed, on the MEC platform TD_MEC_REG_03 uses (estimed/tests/test_tr0086_mec_app_deploy.py, whose relays,
helpers and MEC 010-2 fixture this file imports; estimed/mec_app_deploy.py is the platform agent):

    estimed/apps/mn_cse        an ACME MN-CSE (id-mn-c, cse-mn-c, :8203) as a MEC application. mn_cse.py starts it
                               from mn-c.ini (mn-a.ini with its own CSE-ID, name and port and no baseDirectory line)
                               with its base directory in the instance's own folder, registers at MEC 011 and confirms
                               ready only once its CSEBase answers and it holds its registrar's <remoteCSE>. Option C
                               as shipped. Option D is the same package with one descriptor field more,
                               appServiceProduced [onem2m-mn-cse]: the running app then also offers the MN-CSE as a
                               MEC 011 service whose endpoint is its CSEBase URI. That is a service produced by a MEC
                               app the agent starts at instantiation, not a part started "as part of MEC platform
                               startup", as the developer guide puts the co-located parts. It is the service
                               estimed/handover.py's target check reads; that check accepts it only with handover's IN
                               pointed at the private IN (monkeypatch). Against the lab IN, which holds no id-mn-c, it
                               refuses it, and a test asserts that.
    estimed/apps/cse_consumer  a MEC application that finds that MN-CSE through MEC 011 service discovery, accepts it
                               only if the IN the platform names holds a <remoteCSE> for the CSE-ID it answers with
                               (the two reads of handover.registered_mn), and runs the sensor AE (a byte copy of
                               estimed/apps/sensor_ae/sensor_ae.py) against it. Open: a stray onem2m-mn-cse service
                               beside the genuine one blocks the consumer (refused, not resolved), and a stray that
                               answers with a CSE-ID the IN holds passes the check (an offline row pins it).

The IN-CSE here is a PRIVATE one, started by this file on :8240 from estimed/conf/in.ini with four lines changed
(httpPort, registrarCsePort, no baseDirectory, allowedCSROriginators=/id-mn-c). Why: the lab's IN on :8200 admits
only /id-mn-a and /id-mn-b (allowedCSROriginators in conf/in.ini), so it refuses id-mn-c. Admitting id-mn-c would
mean reconfiguring and restarting the running lab, and the lab's own live tests need that IN to hold exactly id-mn-a
and id-mn-b (conftest `topology`), so a third <remoteCSE> there would fail them while this file runs. The private IN
keeps the lab IN's CSE-ID and name (id-in, cse-in); only its address differs. For the target check, handover.py's IN
address is pointed at it (monkeypatch); the platform names it to the consumer as cse-in.
Its log file name is the lab IN's (cse-estimed.example.com-id-in.log), so a log that left its base directory would
land in the lab IN's own file: the fixture refuses a baseDirectory line in any spelling and checks that the file is
under its own base, and around the whole module the lab's three log folders (in, mn-a, mn-b) must keep the same files
and inodes and gain no line naming :8240, :8203, :8204, id-mn-c or id-mn-x. Three tests read the lab's IN, read-only:
to show it was not touched, and to show that handover's target check and the consumer refuse id-mn-c against it.

Recording relays (_Tap) stand between the platform and the private IN, MEC 011 and MEC 010-2, so what went over
Mcc, over Mp1 and to the lifecycle API is read off the wire.

NOT shown, by any test here:
  * one host and ordinary processes: no VM, no container, nothing isolates the "MEC host" from anything else
  * our MEC candidates (mec011_appsupport, mec010p2) stand in for a MEC platform. Registration and service
    registration at MEC 011 and every MEC 010-2 call are unauthenticated: any local process can register, offer or
    remove a service. MEC 010-2 starts nothing; the agent does.
  * that the MN-CSE the consumer uses is the one the IN holds: the check binds a CSE-ID, not an endpoint
  * one ACME release, 2026.5.3, for every CSE (mn_cse.py refuses another one)
  * not a conformance claim
"""
from __future__ import annotations

import contextlib
import copy
import importlib.util
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

import handover
import mec_app_deploy as mad
from conftest import ESTIMED, MEC011, _port_open, http, req, rsc
from test_tr0086_mec_app_deploy import (MEC010, MEC011_ROOT, SERVICES, _edit, _instance, _listed, _mec_ids,  # noqa: F401
                                        _opoccs, _package, _ppid, _registered, _sha, _Tap, _wait, _workloads, mec010)

PKG_C = ESTIMED / "apps" / "mn_cse"
PKG_CONSUMER = ESTIMED / "apps" / "cse_consumer"
PKG_SENSOR = ESTIMED / "apps" / "sensor_ae"
CONF = ESTIMED / "conf"

# Expected values, by hand. None is read from the descriptors or from the programs under test.
ACME = "/home/edgefollow/estimed-venv/bin/acmecse"
ACME_PY = "/home/edgefollow/estimed-venv/bin/python3"           # acmecse's interpreter (its #! line)
ACME_RELEASE = "2026.5.3"
LAB_IN = ("http://127.0.0.1:8200", "cse-in")               # the lab's IN-CSE, only ever read here
PIN = ("http://127.0.0.1:8240", "cse-in")                  # the private IN-CSE of this file (id-in)
PIN_BASE = f"{PIN[0]}/{PIN[1]}"
IN_PORT, MN_PORT = 8240, 8203      # 8210-8212, 8220-8222, 8230: test_lab_scripts.py
MN = ("http://127.0.0.1:8203", "cse-mn-c")
MN_BASE = f"{MN[0]}/{MN[1]}"
MN_CSI = "/id-mn-c"
MN_LOG = "cse-estimed.example.com-id-mn-c.log"             # ACME's log file name for this CSE
IN_LOG = "cse-estimed.example.com-id-in.log"               # the private IN's log file name: the lab IN's as well
LAB_RUN, LAB_LOG_DIRS = Path("/home/edgefollow/estimed-run"), ("in", "mn-a", "mn-b")
# What only this module puts on the wire: its ports and its CSE-IDs. id-mn-x is the foreign CSE the private IN refuses;
# that refusal is the one line the private IN writes at logLevel=warn.
PRIVATE_MARKS = re.compile(r"(?<![0-9])(?:8240|8203|8204)(?![0-9])|id-mn-[cx](?![A-Za-z0-9_-])")
APP_NAME, CONSUMER_NAME, VERSION = "estimed-mn-cse", "estimed-cse-consumer", "0.1.0"
EDGE_SERVICE = "onem2m-mn-cse"                             # the serName handover.py reads (checked below)
D_PRODUCED = [{"serName": EDGE_SERVICE, "version": "4"}]   # option D's one field; "4": the oneM2M release (RVI)
C_ORIGIN, C_RN, C_CNT, C_API = "CestimedConsumer", "estimedConsumer", "readings", "Nestimed.consumer"
READING = {"temperature_c": 21.5, "source": "fixed value, no sensor"}
DEAD = "http://127.0.0.1:9/cse-mn-c"   # the platform's own entry for cse-mn-c: nothing listens on port 9
CLK_TCK = os.sysconf("SC_CLK_TCK")

CFG01_UP = {"1 IN-CSE": (200, 1), "2 MEC 011": 200, "3 MN-CSE": (200, MN_CSI, 2), "4 remoteCSE": (200, 16, MN_CSI)}
CFG01_NO_MN = {"1 IN-CSE": (200, 1), "2 MEC 011": 200, "3 MN-CSE": (0, None, None), "4 remoteCSE": (404, None, None)}

MEC_APIS = [{"serName": "mec_app_support", "version": "v2"}, {"serName": "mec_service_mgmt", "version": "v1"}]
DESCRIPTOR_C = {
    "appDVersion": "1",
    "appName": APP_NAME,
    "appProvider": "ESTIMED lab",
    "appSoftVersion": VERSION,
    "entryPoint": {"runtime": "python3", "file": "mn_cse.py", "args": ["--instance", "{instance}"]},
    "mecServicesRequired": MEC_APIS,
    "acme": {"program": ACME, "release": ACME_RELEASE, "config": "mn-c.ini"},
    "onem2m": {"mnCse": "cse-in", "api": "Nunused", "originator": "CAdmin", "rn": "cse-mn-c",
               "acp": {"rn": "unused", "readers": []}, "container": "unused"},
}
DESCRIPTOR_CONSUMER = {
    "appDVersion": "1",
    "appName": CONSUMER_NAME,
    "appProvider": "ESTIMED lab",
    "appSoftVersion": VERSION,
    "entryPoint": {"runtime": "python3", "file": "discover.py", "args": ["--instance", "{instance}"]},
    "mecServicesRequired": MEC_APIS,
    "appServiceRequired": [{"serName": EDGE_SERVICE}],
    "onem2m": {"mnCse": "cse-in", "edgeCse": "cse-mn-c", "api": C_API, "originator": C_ORIGIN, "rn": C_RN,
               "acp": {"rn": "consumerAcp", "readers": []}, "container": C_CNT},
}
# mn-c.ini is mn-a.ini with exactly these lines changed (None: removed); the private IN is in.ini with these
MN_C_FROM_MN_A = {"cseID": "id-mn-c", "cseName": "cse-mn-c", "httpPort": "8203", "baseDirectory": None,
                  "registrarCseHost": "@REGISTRAR_HOST@", "registrarCsePort": "@REGISTRAR_PORT@"}
PRIVATE_IN_FROM_IN = {"httpPort": "8240", "registrarCsePort": "8240", "baseDirectory": None,
                      "allowedCSROriginators": "/id-mn-c"}


# ------------------------------------------------------------------------------------------ helpers
def _get(url: str, origin: str = "CAdmin") -> tuple[int, dict | None]:
    """A oneM2M RETRIEVE -> (http status, body); status 0 when nothing answers."""
    try:
        st, body, _ = req("GET", url, origin)
    except OSError:
        return 0, None
    return st, body


def _status(url: str) -> int:
    try:
        return http("GET", url)[0]
    except OSError:
        return 0


def _cfg01(mn=MN, csi=MN_CSI) -> dict:
    """Developer guide 5.2.4 step 4, items 1 to 4, read by value. Item 2's URL as the guide writes it
    (GET /mec_app_support/v2/) has no route on our MEC 011 candidate: it is read at timing/current_time instead
    (see the step 4 test)."""
    st_in, b_in = _get(PIN_BASE)
    st_mn, b_mn = _get(f"{mn[0]}/{mn[1]}")
    st_r, b_r = _get(f"{PIN_BASE}/{csi.lstrip('/')}")
    cb, csr = (b_mn or {}).get("m2m:cb") or {}, (b_r or {}).get("m2m:csr") or {}
    return {"1 IN-CSE": (st_in, ((b_in or {}).get("m2m:cb") or {}).get("cst")),
            "2 MEC 011": _status(f"{MEC011}/timing/current_time"),
            "3 MN-CSE": (st_mn, cb.get("csi"), cb.get("cst")),
            "4 remoteCSE": (st_r, csr.get("ty"), csr.get("csi"))}


def _in_csrs() -> list[str]:
    """Every <remoteCSE> the private IN holds."""
    st, body = _get(f"{PIN_BASE}?fu=1&ty=16")
    assert st == 200, (st, body)
    return sorted(body["m2m:uril"])


def _edge_services() -> list[dict]:
    """Every service MEC 011 lists under the MN-CSE service name (it lists confirmed-ready instances only)."""
    st, body = http("GET", f"{SERVICES}/services?ser_name={EDGE_SERVICE}")
    assert st == 200
    return body


def _app_calls(records) -> list[tuple[str, str, int]]:
    """(method, path, status) of what the workloads sent on Mp1; the agent's own readiness polls (a GET of the whole
    service list) left out."""
    return [(r["method"], r["path"], r["status"]) for r in records
            if not (r["method"] == "GET" and r["path"] == "/mec_service_mgmt/v1/services")]


def _argv(pid: int) -> list[str]:
    return Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace").split("\0")[:-1]


def _children(pid: int) -> list[int]:
    out = []
    for p in Path("/proc").glob("[0-9]*"):
        try:
            if _ppid(int(p.name)) == pid:
                out.append(int(p.name))
        except (OSError, IndexError, ValueError):
            continue
    return sorted(out)


def _started(pid: int) -> float:
    """The process's start on the boot clock (field 22 of /proc/<pid>/stat), to 1/CLK_TCK s."""
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]) / CLK_TCK


def _boot_minus_monotonic() -> float:
    return time.clock_gettime(time.CLOCK_BOOTTIME) - time.monotonic()


def _listener(port: int) -> list[int]:
    """pids holding the listening TCP socket on 127.0.0.1:port, from /proc/net/tcp and the processes' fds."""
    inodes = {f[9] for f in (line.split() for line in Path("/proc/net/tcp").read_text().splitlines()[1:])
              if f[1] == f"0100007F:{port:04X}" and f[3] == "0A"}
    pids = []
    for p in Path("/proc").glob("[0-9]*"):
        try:
            links = {os.readlink(fd) for fd in (p / "fd").iterdir()}
        except OSError:
            continue
        if any(f"socket:[{i}]" in links for i in inodes):
            pids.append(int(p.name))
    return sorted(pids)


def _derive(text: str, changes: dict) -> str:
    """An ACME ini with each `key=` line set to the given value, or removed for None; each key on exactly one line."""
    lines = text.splitlines()
    for key, value in changes.items():
        at = [i for i, line in enumerate(lines) if line.startswith(f"{key}=")]
        assert len(at) == 1, f"{key}= is on lines {at}"
        if value is None:
            del lines[at[0]]
        else:
            lines[at[0]] = f"{key}={value}"
    return "\n".join(lines) + "\n"


def _settings(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith(";")]


def _as_option_d(dst: Path) -> Path:
    """The shipped package with option D's one field: the same program and ini, byte for byte."""
    shutil.copytree(PKG_C, dst)
    return _edit(dst, lambda d: d.__setitem__("appServiceProduced", copy.deepcopy(D_PRODUCED)))


def _load(path: Path, name: str):
    """A package's program as a module, for its pure functions. No bytecode is written: a __pycache__ in the
    package would make it a package that does not verify."""
    spec = importlib.util.spec_from_file_location(f"{name}_{uuid.uuid4().hex[:6]}", path)
    mod = importlib.util.module_from_spec(spec)
    was, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = was
    return mod


def _confirming(r) -> bool:
    return r["path"].endswith("/confirm_ready")


def _alive(pid: int) -> bool:
    """The process exists and has not exited (a zombie has)."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _stop_with_this_process() -> None:
    """In the private IN's process, before ACME runs: SIGINT back to its default disposition, then PR_SET_PDEATHSIG
    SIGINT. Should this test process die, even by SIGKILL, the kernel sends the IN SIGINT, so a killed session does not
    leave :8240 held (one did: pass 2, N8). A started ACME then stops in order; one still starting exits on the
    uncaught KeyboardInterrupt instead. Either way the port is free within a second (re-check of 2026-11-20). The reset matters: a test started with SIGINT
    ignored (e.g. `pytest ... &` in a script) passes SIG_IGN on through exec; Python then does not install its default
    SIGINT handler in ACME, and the kernel's SIGINT is ignored (re-check of 2026-11-20: the IN still held :8240)."""
    import ctypes
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    if ctypes.CDLL(None, use_errno=True).prctl(1, int(signal.SIGINT), 0, 0, 0) != 0:     # 1: PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG)")


def test_options_cd_control_a_child_dies_with_a_killed_parent_that_ignored_sigint():
    """CONTROL for _stop_with_this_process (its own source, run in a parent process that ignores SIGINT, as a test
    started with `pytest ... &` from a script does): the parent starts a child with the helper and is then SIGKILLed;
    the child must be gone within 5 s. Without the SIG_DFL reset, or without the PR_SET_PDEATHSIG, it stays."""
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
        try:
            os.kill(cpid, signal.SIGKILL)
        except OSError:
            pass


def _private_in_ini(text: str) -> str:
    """in.ini with PRIVATE_IN_FROM_IN applied. A baseDirectory line that survives in any spelling is refused: ACME's
    ini keys are case-insensitive and _derive removes only a line starting `baseDirectory=`, and such a line would put
    the private IN's log into the lab IN's own file (same name, see IN_LOG)."""
    ini = _derive(text, PRIVATE_IN_FROM_IN)
    if re.search(r"(?mi)^\s*baseDirectory\s*[=:]", ini):
        raise ValueError("the private IN's ini still sets baseDirectory")
    return ini


def _private_in_log_check(base: Path) -> None:
    """The private IN's log is where its base directory says, and nothing else is in that folder (ValueError
    otherwise): the file name alone does not tell it from the lab IN's."""
    found = sorted(x.name for x in (base / "logs").glob("*"))
    if found != [IN_LOG]:
        raise ValueError(f"the private IN-CSE's log is not {base}/logs/{IN_LOG} alone: {found}")


def _lab_logs(root: Path = LAB_RUN) -> dict[str, tuple[int, int]]:
    """(inode, size) of every file in the lab's three CSE log folders. Read only."""
    out = {}
    for d in LAB_LOG_DIRS:
        folder = root / d / "logs"
        for p in sorted(folder.iterdir()) if folder.is_dir() else []:
            st = p.lstat()
            out[str(p)] = (st.st_ino, st.st_size)
    return out


def _lab_log_changes(before: dict, root: Path = LAB_RUN) -> list[str]:
    """What this module must not have done to the lab's logs since `before`: a file added, gone, replaced (another
    inode) or shrunk, or a line appended that names one of PRIVATE_MARKS. Lines the lab's own CSEs append are
    allowed; a rotation of a lab log in that time would also show (a false alarm; not seen under the live lock)."""
    after = _lab_logs(root)
    bad = [f"added {p}" for p in after.keys() - before.keys()] + [f"gone {p}" for p in before.keys() - after.keys()]
    for p in after.keys() & before.keys():
        (ino0, size0), (ino1, size1) = before[p], after[p]
        if ino0 != ino1 or size1 < size0:
            bad.append(f"replaced or shrunk {p}")
            continue
        with open(p, "rb") as f:
            f.seek(size0)
            new = f.read(size1 - size0).decode(errors="replace")
        bad += [f"{p}: {line[:160]}" for line in new.splitlines() if PRIVATE_MARKS.search(line)]
    return sorted(bad)


@contextlib.contextmanager
def _stub_cse(cb: dict):
    """A stand-in, not a CSE: it answers a GET of /cse-mn-c with the given <CSEBase> and anything else with 404, and
    records (method, path, originator) of what it was sent. Yields (its CSEBase URI, that record)."""
    seen = []

    class Stub(BaseHTTPRequestHandler):
        def _any(self):
            seen.append((self.command, self.path, self.headers.get("X-M2M-Origin")))
            ok = self.command == "GET" and self.path == f"/{MN[1]}"
            out = json.dumps({"m2m:cb": cb} if ok else {}).encode()
            self.send_response(200 if ok else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-M2M-RSC", "2000" if ok else "4004")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = do_POST = do_PUT = do_DELETE = _any

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/{MN[1]}", seen
    finally:
        srv.shutdown()
        srv.server_close()


def _refused_consumer(p, app_d_id: str, name: str) -> SimpleNamespace:
    """An instance of the consumer package, instantiated, which must exit 3 before it is ready. What it wrote and
    what crossed Mp1 and the IN relay meanwhile (the IN reads as CAdmin: the consumer's IN check); the instance is
    taken out again."""
    n_mec, n_in = len(p.mec.seen), len(p.inn.seen)
    ciid = p.agent.create_instance(app_d_id, name)
    inst_dir = p.workdir / "instances" / ciid
    try:
        with pytest.raises(mad.DeployError, match=r"exited with 3 before it was ready"):
            p.agent.instantiate(ciid, ready_timeout=20.0)
        return SimpleNamespace(
            log=(inst_dir / "workload.log").read_text(), cfg=json.loads((inst_dir / "instance.json").read_text()),
            discovered=(inst_dir / "instance.discovered.json").exists(), mp1=_app_calls(p.mec.seen[n_mec:]),
            in_reads=[(r["path"], r["status"]) for r in p.inn.seen[n_in:]
                      if r["headers"].get("x-m2m-origin") == "CAdmin"],
            lcm=(_opoccs(ciid), _instance(ciid)["instantiationState"]),
            running=[x for x in _workloads(p.workdir) if any(ciid in a for a in _argv(x))])
    finally:
        if p.agent.instances[ciid]["proc"] is not None:
            with contextlib.suppress(mad.DeployError):
                p.agent.terminate(ciid)
        with contextlib.suppress(mad.DeployError):
            p.agent.delete_instance(ciid)


# ------------------------------------------------------------------------------------------ fixtures
@pytest.fixture(scope="module", autouse=True)
def lab_logs_untouched():
    """Around the whole module (the private IN's stop included): the lab's three CSE log folders keep their files and
    inodes and gain no line naming this module's ports or CSE-IDs (_lab_log_changes)."""
    before = _lab_logs()
    yield before
    changes = _lab_log_changes(before)
    assert changes == [], f"the lab's CSE logs changed while this module ran: {changes}"


@pytest.fixture(scope="module")
def private_in(tmp_path_factory):
    """The IN-CSE for this file (see the module docstring): in.ini with four lines changed and no baseDirectory line
    in any spelling, on :8240, base directory in a temporary folder, where its log file must be once it answers;
    stopped with SIGINT (ACME's graceful stop) afterwards, and by the kernel with SIGINT if this process dies."""
    if _port_open("127.0.0.1", IN_PORT):
        pytest.fail(f":{IN_PORT} is already held; the private IN-CSE needs it", pytrace=False)
    base = tmp_path_factory.mktemp("private-in")
    (base / "acme.ini").write_text(_private_in_ini((CONF / "in.ini").read_text()))
    with (base / "stdout.log").open("wb") as out:
        proc = subprocess.Popen([ACME, "--headless", "--config", "acme.ini", "--base-directory", str(base)],
                                cwd=base, env={}, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                                start_new_session=True, preexec_fn=_stop_with_this_process)
    try:
        if not _wait(lambda: proc.poll() is not None or _get(PIN_BASE)[0] == 200, timeout=30, step=0.2) \
                or proc.poll() is not None:
            pytest.fail(f"the private IN-CSE did not come up on :{IN_PORT}; see {base}/logs", pytrace=False)
        _private_in_log_check(base)
        yield SimpleNamespace(proc=proc, base=base)
    finally:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)


@contextlib.contextmanager
def _platform(workdir: Path):
    """A platform agent on the MEC 010-2 and MEC 011 candidates, with relays in front of the private IN, MEC 011 and
    MEC 010-2. Afterwards everything the agent started is stopped, and it is an error if a process, the MN-CSE's
    port or its <remoteCSE> at the IN was still there once the agent closed."""
    req("DELETE", f"{PIN_BASE}/{MN_CSI.lstrip('/')}", "CAdmin")     # an earlier crashed run must not decide this one
    if _port_open("127.0.0.1", MN_PORT):
        pytest.fail(f":{MN_PORT} is already held before the MN-CSE is deployed", pytrace=False)
    inn, mec, m10 = _Tap(PIN[0]), _Tap(MEC011_ROOT), _Tap(MEC010)
    agent = mad.PlatformAgent(mec010=m10.url, mec011=mec.url, cses={"cse-in": f"{inn.url}/{PIN[1]}", "cse-mn-c": DEAD},
                              workdir=workdir, grace=15.0)
    try:
        yield SimpleNamespace(agent=agent, inn=inn, mec=mec, m10=m10, workdir=workdir)
    finally:
        mec.release.set()
        agent.close()
        left = _workloads(workdir)
        for pid in left:
            os.kill(pid, signal.SIGKILL)
        csr, held = _get(f"{PIN_BASE}/{MN_CSI.lstrip('/')}")[0], _port_open("127.0.0.1", MN_PORT)
        req("DELETE", f"{PIN_BASE}/{MN_CSI.lstrip('/')}", "CAdmin")
        for tap in (inn, mec, m10):
            tap.close()
        assert (left, csr, held) == ([], 404, False), \
            f"left after the agent closed: processes {left}, <remoteCSE> answers {csr}, :{MN_PORT} held {held}"


@pytest.fixture(scope="class")
def depc(mec011, mec010, private_in, tmp_path_factory):
    """Option C: the shipped package onboarded, two instances created, one of them instantiated. The relay holds
    the app's confirm_ready back long enough to read, at that moment, what stood."""
    with _platform(tmp_path_factory.mktemp("optc")) as p:
        pkg = p.agent.onboard(PKG_C)
        iid = p.agent.create_instance(pkg["appDId"], "mn-c")
        idle = p.agent.create_instance(pkg["appDId"], "mn-c-never-instantiated")
        before = {"cfg01": _cfg01(), "csrs": _in_csrs(), "instance": _instance(iid)["instantiationState"],
                  "workloads": _workloads(p.workdir), "listener": _listener(MN_PORT)}
        offset, out = _boot_minus_monotonic(), {}
        p.mec.hold = _confirming

        def go():
            try:
                out["run"] = p.agent.instantiate(iid, ready_timeout=45.0)
            except Exception as e:  # noqa: BLE001  shown by the failure below
                out["err"] = e

        t = threading.Thread(target=go, daemon=True)
        t.start()
        _wait(lambda: any(_confirming(r) for r in p.mec.seen) or not t.is_alive(), timeout=45)
        at_confirm = {"cfg01": _cfg01(), "listed": _listed(iid), "agent_waiting": t.is_alive() and not out}
        p.mec.release.set()
        t.join(45)
        p.mec.hold = None
        if "run" not in out:
            pytest.fail(f"option C did not deploy: {out}", pytrace=False)
        yield SimpleNamespace(p=p, pkg=pkg, iid=iid, idle=idle, before=before, at_confirm=at_confirm, run=out["run"],
                              workdir=p.workdir, offset=offset)


@pytest.fixture(scope="class")
def depd(mec011, mec010, private_in, tmp_path_factory):
    """Option D: the package with appServiceProduced, instantiated; then the consumer, deployed the same way."""
    tmp = tmp_path_factory.mktemp("optd")
    with _platform(tmp / "platform") as p:
        pkg = p.agent.onboard(_as_option_d(tmp / "mn_cse_d"))
        iid = p.agent.create_instance(pkg["appDId"], "mn-c-service")
        run = p.agent.instantiate(iid, ready_timeout=45.0)
        n0, n_in0 = len(p.mec.seen), len(p.inn.seen)
        cpkg = p.agent.onboard(PKG_CONSUMER)
        ciid = p.agent.create_instance(cpkg["appDId"], "consumer")
        crun = p.agent.instantiate(ciid, ready_timeout=20.0)
        try:
            yield SimpleNamespace(p=p, pkg=pkg, iid=iid, run=run, n0=n0, cpkg=cpkg, ciid=ciid, crun=crun,
                                  workdir=p.workdir, in_window=(n_in0, len(p.inn.seen)))
        finally:
            with contextlib.suppress(mad.DeployError):
                p.agent.terminate(ciid)                 # the consumer leaves before the CSE it is registered on


# ------------------------------------------------------------------------------------------ option C
class TestOptionC:
    """Option C, the MN-CSE as a MEC application, and the controls that need an MN-CSE running without the MEC
    service. Not shown by any of these: a VM or container (processes on one host); a MEC platform (our
    unauthenticated MEC 011 and MEC 010-2 candidates); another ACME release than 2026.5.3; conformance."""

    def test_c_5_2_4_step4_items_1_to_4_by_value(self, depc):
        """Developer guide 5.2.4 step 4 on the deployed MN-CSE, and the same four reads before it was deployed.
        Not shown: anything about the IN-CSE beyond the one <remoteCSE> (the IN is this file's private one)."""
        assert _cfg01() == CFG01_UP
        assert depc.before["cfg01"] == CFG01_NO_MN, "control: the reads were already green before the deployment"
        # 1 and 3 in full: what answered is an IN (id-in) and the MN-CSE started here, at its own address
        st, body = _get(PIN_BASE)
        assert st == 200 and (body["m2m:cb"]["csi"], body["m2m:cb"]["cst"]) == ("/id-in", 1)
        st, body = _get(MN_BASE)
        cb = body["m2m:cb"]
        assert (cb["ri"], cb["rn"], cb["csi"], cb["cst"], cb["poa"]) == \
            ("id-mn-c", "cse-mn-c", MN_CSI, 2, ["http://127.0.0.1:8203"])
        # 2: the guide's URL as written has no route on our MEC 011 candidate
        assert _status(f"{MEC011}/") == 404, "GET /mec_app_support/v2/ now answers: read it as the guide writes it"
        # 4 in full: the one <remoteCSE> the IN holds, for this MN-CSE
        st, body = _get(f"{PIN_BASE}/id-mn-c")
        csr = body["m2m:csr"]
        assert (csr["ty"], csr["pi"], csr["csi"], csr["cb"], csr["cst"], csr["poa"]) == \
            (16, "id-in", MN_CSI, "/id-mn-c/cse-mn-c", 2, ["http://127.0.0.1:8203"])
        assert _in_csrs() == ["cse-in/id-mn-c"]

    def test_c_5_2_4_step3_the_mn_cse_registered_to_the_in_over_mcc(self, depc):
        """Step 3's registration as it went over Mcc (TD_MEC_REG_01 steps 2 and 3), read at the relay.
        Not shown: the Mcc security the guide's prerequisites name (there is none; plain HTTP, no credentials)."""
        creates = [r for r in depc.p.inn.seen
                   if r["method"] == "POST" and "ty=16" in r["headers"].get("content-type", "")]
        assert len(creates) == 1
        c = creates[0]
        # to = the IN's CSEBase, SP-relative (/~/<CSE-ID>/<CSEBase name> in the HTTP binding); fr = the MN-CSE-ID
        assert (c["path"], c["headers"]["x-m2m-origin"]) == ("/~/id-in/cse-in", MN_CSI)
        sent = c["body"]["m2m:csr"]
        assert (sent["csi"], sent["cb"], sent["poa"]) == (MN_CSI, "/id-mn-c/cse-mn-c", ["http://127.0.0.1:8203"])
        assert (c["status"], c["rsc"]) == (201, 2001)
        assert (c["reply"]["m2m:csr"]["ty"], c["reply"]["m2m:csr"]["csi"]) == (16, MN_CSI)
        # and the MN-CSE indicates it (TD_MEC_REG_01 step 5): it holds its registrar's <remoteCSE>
        st, body = _get(f"{MN_BASE}?fu=1&ty=16")
        assert st == 200 and body["m2m:uril"] == ["cse-mn-c/id-in"]

    def test_c_the_mn_cse_was_started_by_the_platform_agent_after_the_010_2_instantiate(self, depc):
        """MEC 010-2 says INSTANTIATED; /proc says: the agent (this process) started the workload, the workload
        started ACME, both after the instantiate was answered, and ACME holds :8203.
        Not shown: that a MEC platform started it (the agent is ours; the 010-2 candidate starts nothing)."""
        d = depc
        inst = _instance(d.iid)
        assert (inst["instantiationState"], inst["appDId"]) == ("INSTANTIATED", d.pkg["appDId"])
        assert _opoccs(d.iid) == [("INSTATIATE", "PROCESSING")] and d.p.agent.results[d.run["opOcc"]] == "COMPLETED"
        assert _package(d.pkg["appPkgId"])["usageState"] == "IN_USE"
        pid, inst_dir = d.run["pid"], d.workdir / "instances" / d.iid
        store = f"{d.workdir}/packages/{d.pkg['appPkgId']}"
        assert _argv(pid) == [sys.executable, "-I", "-B", f"{store}/mn_cse.py", "--instance", f"{inst_dir}/instance.json"]
        assert _ppid(pid) == os.getpid()
        assert _children(pid) != [] and len(_children(pid)) == 1
        acme = _children(pid)[0]
        assert _argv(acme) == [ACME_PY, ACME, "--headless", "--config", "acme.ini", "--base-directory", f"{inst_dir}/acme"]
        for x in (pid, acme):
            assert Path(f"/proc/{x}/environ").read_bytes() == b"", f"{x} inherited an environment"
        assert _listener(MN_PORT) == [acme], "what answers on :8203 is not the process the workload started"
        assert _workloads(d.workdir) == sorted([pid, acme])
        # the order: the instantiate answered on the MEC 010-2 wire, then the workload started, then ACME
        calls = [r for r in d.p.m10.seen
                 if r["method"] == "POST" and r["path"] == f"/app_lcm/v1/app_instances/{d.iid}/instantiate"]
        assert [r["status"] for r in calls] == [202]
        answered = calls[0]["t_out"] + d.offset
        assert answered - 1 / CLK_TCK <= _started(pid) <= _started(acme)
        # control: none of it before the instantiate
        assert d.before == {"cfg01": CFG01_NO_MN, "csrs": [], "instance": "NOT_INSTANTIATED", "workloads": [],
                            "listener": []}

    def test_c_registered_at_mec011_and_confirmed_ready_only_once_its_csebase_answered(self, depc):
        """Mp1: registered, its own service offered, confirm_ready -- and when confirm_ready was sent (the relay held
        it), the CSE already answered as itself and the IN already held it. As option C, the MN-CSE service is not
        offered. Not shown: MEC 011 authentication (none)."""
        d = depc
        assert d.at_confirm == {"cfg01": CFG01_UP, "listed": [], "agent_waiting": True}
        mids = _mec_ids(d.p.mec)
        assert mids == [d.run["mec011AppInstanceId"]] and _registered(mids[0])
        assert _app_calls(d.p.mec.seen) == [("POST", "/mec_app_support/v2/registrations", 201),
                                            ("POST", f"/mec_service_mgmt/v1/applications/{mids[0]}/services", 201),
                                            ("POST", f"/mec_app_support/v2/applications/{mids[0]}/confirm_ready", 204)]
        listed = _listed(d.iid)
        assert [(s["serName"], s["version"], s["state"], s["transportInfo"]["endpoint"]) for s in listed] == \
            [(APP_NAME, VERSION, "ACTIVE", {"uris": [MN_BASE]})]
        assert f"/applications/{mids[0]}/services/" in listed[0]["_links"]["self"]["href"]
        assert _edge_services() == [], "option C offered the MN-CSE service"

    def test_c_its_logs_are_only_under_its_own_base_directory(self, depc):
        """The ini the workload wrote has no baseDirectory line, so ACME's logs are where --base-directory says.
        Not shown: anything about log content."""
        inst_dir = depc.workdir / "instances" / depc.iid
        base = inst_dir / "acme"
        assert sorted(x.name for x in inst_dir.iterdir()) == ["acme", "instance.json", "workload.log"]
        assert sorted(x.name for x in base.iterdir()) == ["acme.ini", "logs", "stdout.log"]
        assert [x.name for x in (base / "logs").iterdir()] == [MN_LOG]
        port = depc.p.inn.url.rsplit(":", 1)[1]
        ini = (base / "acme.ini").read_text()
        assert ini == (PKG_C / "mn-c.ini").read_text().replace("@REGISTRAR_HOST@", "127.0.0.1") \
                                                       .replace("@REGISTRAR_PORT@", port)
        assert not re.search(r"(?mi)^\s*baseDirectory\s*=", ini)
        assert os.path.realpath(f"/proc/{_children(depc.run['pid'])[0]}/cwd") == str(base)
        # nowhere else: not in the lab's run directory (where a baseDirectory line copied from mn-a.ini would put it)
        assert list(Path("/home/edgefollow/estimed-run").glob(f"*/logs/{MN_LOG}")) == []
        assert not (Path.cwd() / "logs" / MN_LOG).exists()

    def test_c_5_3_a_device_ae_registers_on_it_and_publishes(self, depc):
        """Developer guide 5.3.3 steps 1 to 4, this test acting as the device on Mca.
        Not shown: a real device, downlink, or any device credential (ACME admits a C-prefixed AE-ID as asked)."""
        name = f"tr86c-{uuid.uuid4().hex[:8]}"
        origin, sample = f"C{name}", {"temperature_c": 19.0, "seq": 1}
        try:
            st, body, h = req("POST", MN_BASE, origin, ty=2, body={"m2m:ae": {
                "rn": name, "api": "Nestimed.device", "rr": True, "srv": ["4"]}})
            assert (st, rsc(h)) == (201, 2001)
            ae = body["m2m:ae"]
            assert (ae["aei"], ae["pi"], ae["rr"]) == (origin, "id-mn-c", True)
            st, _, h = req("POST", f"{MN_BASE}/{name}", origin, ty=3, body={"m2m:cnt": {"rn": "telemetry"}})
            assert (st, rsc(h)) == (201, 2001)
            st, _, h = req("POST", f"{MN_BASE}/{name}/telemetry", origin, ty=4, body={"m2m:cin": {
                "cnf": "application/json:0", "con": json.dumps(sample)}})
            assert (st, rsc(h)) == (201, 2001)
            st, body, h = req("GET", f"{MN_BASE}/{name}/telemetry/la", origin)
            assert (st, rsc(h)) == (200, 2000) and json.loads(body["m2m:cin"]["con"]) == sample
        finally:
            req("DELETE", f"{MN_BASE}/{name}", origin)
        assert _get(f"{MN_BASE}/{name}")[0] == 404

    def test_c_control_an_instance_never_instantiated_is_not_running(self, depc):
        """The second instance of the same package: created at MEC 010-2, never instantiated.
        Not shown: anything a MEC platform would do with such an instance (ours does nothing)."""
        d = depc
        assert _instance(d.idle)["instantiationState"] == "NOT_INSTANTIATED" and _opoccs(d.idle) == []
        assert d.p.agent.instances[d.idle]["proc"] is None
        assert not (d.workdir / "instances" / d.idle).exists()
        assert [x for x in _workloads(d.workdir) if any(d.idle in a for a in _argv(x))] == []
        assert _listed(d.idle) == []
        # beside it: the instantiated one runs, and it alone is at the IN
        assert _workloads(d.workdir) == sorted([d.run["pid"], *_children(d.run["pid"])])
        assert _in_csrs() == ["cse-in/id-mn-c"]

    def test_c_control_a_cse_not_deployed_is_not_counted(self, depc, monkeypatch):
        """A CSE that was never deployed (cse-mn-d, :8204) fails 5.2.4 items 3 and 4 and handover.py's target check;
        the IN counts only the deployed one, and counted none before it. Not shown: a CSE that runs but is not
        registered (ACME registers on its own once it is up)."""
        assert not _port_open("127.0.0.1", 8204), ":8204 is held: the ghost is not a ghost"
        ghost = ("http://127.0.0.1:8204", "cse-mn-d")
        assert _cfg01(ghost, "/id-mn-d") == CFG01_NO_MN
        monkeypatch.setattr(handover, "IN_CSE", PIN)
        assert handover.target_ready(ghost) is False and handover.target_ready(ghost, SERVICES) is False
        # registered_mn for a CSE where nothing listens: today the URLError leaves it (target_ready catches it;
        # handover._handover calls it before any write). Raising and answering False are both a refusal, so either
        # passes here: a later handover.py that answers False must not turn this control red.
        try:
            ghost_ok = handover.registered_mn(ghost)[0]
        except OSError:
            ghost_ok = False
        assert ghost_ok is False
        assert handover.registered_mn(MN) == (True, MN_CSI)
        assert _in_csrs() == ["cse-in/id-mn-c"] and depc.before["csrs"] == []

    def test_c_control_handover_check_refuses_an_mn_cse_offered_as_an_app_only(self, depc, monkeypatch):
        """The difference between C and D as handover.py's target check sees it: the oneM2M half passes, but the app's
        own service (named after the app, endpoint the CSEBase) is not the MN-CSE service. Not shown: any handover."""
        monkeypatch.setattr(handover, "IN_CSE", PIN)
        assert handover.target_ready(MN) is True
        assert [(s["serName"], s["transportInfo"]["endpoint"]) for s in _listed(depc.iid)] == \
            [(APP_NAME, {"uris": [MN_BASE]})]
        assert _edge_services() == []
        assert handover.target_ready(MN, SERVICES) is False

    @pytest.mark.parametrize("what, uri, state", [
        ("the CSE's HTTP root", "http://127.0.0.1:8203", "ACTIVE"),
        ("a trailing slash", f"{MN_BASE}/", "ACTIVE"),
        ("a resource below the CSEBase", f"{MN_BASE}/estimedSensor", "ACTIVE"),
        ("another CSE (the IN)", PIN_BASE, "ACTIVE"),
        ("another port", "http://127.0.0.1:8213/cse-mn-c", "ACTIVE"),
        ("the right endpoint, INACTIVE", MN_BASE, "INACTIVE")])
    def test_d_control_a_service_whose_endpoint_is_not_the_csebase_is_refused(self, depc, monkeypatch, what, uri, state):
        """An onem2m-mn-cse service registered by this test itself (its app confirmed ready, so MEC 011 lists it)
        while the MN-CSE runs as option C: handover.py's target check refuses it; beside it the same registration
        with the CSEBase URI is accepted. Not shown: who may register such a service (anyone: unauthenticated)."""
        monkeypatch.setattr(handover, "IN_CSE", PIN)
        assert _edge_services() == []
        with _offered(uri, state) as s:
            assert s in _edge_services(), "not listed: the refusal would be the registry's, not the check's"
            assert handover.target_ready(MN, SERVICES) is False, what
        with _offered(MN_BASE, "ACTIVE"):
            assert handover.target_ready(MN, SERVICES) is True
        assert handover.target_ready(MN, SERVICES) is False and _edge_services() == []

    def test_d_control_a_consumer_that_finds_no_service_registers_nothing(self, depc):
        """The consumer on a platform whose MN-CSE is option C: MEC 011 lists no onem2m-mn-cse service. The right
        address IS in the platform's configuration this time (cse-mn-c); the platform hands the consumer only the
        IN's (cse-in, the CSE its descriptor names), and the consumer asks no CSE anything. Not shown: discovery
        scoped to a MEC host or a locality (the candidate lists everything it holds)."""
        p = depc.p
        assert _edge_services() == []
        p.agent.cses["cse-mn-c"] = MN_BASE
        try:
            cpkg = p.agent.onboard(PKG_CONSUMER)
            ciid = p.agent.create_instance(cpkg["appDId"], "consumer-without-service")
            n0, n_in = len(p.mec.seen), len(p.inn.seen)
            with pytest.raises(mad.DeployError, match=r"exited with 3 before it was ready.*found 0, need 1"):
                p.agent.instantiate(ciid, ready_timeout=20.0)
        finally:
            p.agent.cses["cse-mn-c"] = DEAD
        # discovery only: no registration, no service, no confirm on Mp1; no read at the IN; no AE on the CSE
        assert _app_calls(p.mec.seen[n0:]) == [("GET", f"/mec_service_mgmt/v1/services?ser_name={EDGE_SERVICE}", 200)]
        assert [r for r in p.inn.seen[n_in:] if r["headers"].get("x-m2m-origin") == "CAdmin"] == []
        assert _get(f"{MN_BASE}/{C_RN}")[0] == 404
        inst_dir = p.workdir / "instances" / ciid
        assert json.loads((inst_dir / "instance.json").read_text())["cse"] == f"{p.inn.url}/{PIN[1]}"
        assert not (inst_dir / "instance.discovered.json").exists()
        assert _listed(ciid) == [] and [x for x in _workloads(p.workdir) if any(ciid in a for a in _argv(x))] == []
        assert _opoccs(ciid) == [("INSTATIATE", "FAILED"), ("TERMINATE", "PROCESSING")]
        assert _instance(ciid)["instantiationState"] == "NOT_INSTANTIATED"
        p.agent.delete_instance(ciid)
        p.agent.offboard(cpkg["appPkgId"])

    @pytest.mark.parametrize("what, cb, why, at_in", [
        ("nothing answers there", None, r"FAILED URLError: .*Connection refused", []),
        ("a middle node the IN does not hold", {"ri": "id-mn-x", "csi": "/id-mn-x", "cst": 2},
         r"is not an MN-CSE the IN-CSE holds: the IN holds no <remoteCSE> for /id-mn-x \(404\)",
         [("/cse-in/id-mn-x", 404)]),
        ("an IN-CSE", {"ri": "id-in", "csi": "/id-in", "cst": 1},
         r"is not an MN-CSE the IN-CSE holds: .* with cst 1, not a middle node \(2\)", [])])
    def test_d_control_the_consumer_refuses_a_lone_stray_service(self, depc, what, cb, why, at_in):
        """A lone onem2m-mn-cse service at a CSEBase named cse-mn-c, offered by the test itself (MEC 011 registration
        is unauthenticated) while the genuine MN-CSE runs as option C: the consumer asks that endpoint and the IN the
        platform names, refuses it, and has created nothing anywhere. Beside it, the same check passes for the
        genuine MN-CSE. Not shown: a stray that answers with a CSE-ID the IN holds (it passes; offline row
        test_discover_registered_mn_is_handovers)."""
        p = depc.p
        assert _edge_services() == []
        disc = _load(PKG_CONSUMER / "discover.py", "discover")
        assert disc.registered_mn(MN_BASE, PIN_BASE) == (True, MN_CSI)        # beside the control
        cpkg = p.agent.onboard(PKG_CONSUMER)
        try:
            with contextlib.ExitStack() as stack:
                if cb is None:
                    assert not _port_open("127.0.0.1", 8204), ":8204 is held: nothing should answer there"
                    uri, stub = "http://127.0.0.1:8204/cse-mn-c", None
                else:
                    uri, stub = stack.enter_context(_stub_cse(cb))
                stack.enter_context(_offered(uri, "ACTIVE"))
                assert [s["transportInfo"]["endpoint"]["uris"] for s in _edge_services()] == [[uri]]
                got = _refused_consumer(p, cpkg["appDId"], "consumer-lone-stray")
        finally:
            with contextlib.suppress(mad.DeployError):
                p.agent.offboard(cpkg["appPkgId"])
        assert re.search(why, got.log), got.log
        assert got.cfg["cse"] == f"{p.inn.url}/{PIN[1]}"
        assert got.mp1 == [("GET", f"/mec_service_mgmt/v1/services?ser_name={EDGE_SERVICE}", 200)]
        assert got.in_reads == at_in
        assert stub is None or stub == [("GET", f"/{MN[1]}", "CAdmin")]
        assert not got.discovered and got.running == [] and _get(f"{MN_BASE}/{C_RN}")[0] == 404
        assert got.lcm == ([("INSTATIATE", "FAILED"), ("TERMINATE", "PROCESSING")], "NOT_INSTANTIATED")
        assert _edge_services() == []

    def test_c_control_the_private_in_admits_only_id_mn_c(self, depc):
        """The private IN is not an open door: a <remoteCSE> Create from another CSE-ID is refused, as the lab's IN
        refuses one. Not shown: that the originator is who it says (nothing checks it)."""
        try:
            st, _, h = req("POST", PIN_BASE, "/id-mn-x", ty=16, body={"m2m:csr": {
                "rn": "id-mn-x", "csi": "/id-mn-x", "cb": "/id-mn-x/cse-mn-x", "rr": True, "cst": 2, "srv": ["4"],
                "poa": ["http://127.0.0.1:9"], "dcse": []}})
            assert (st, rsc(h)) == (403, 4103)
        finally:
            req("DELETE", f"{PIN_BASE}/id-mn-x", "CAdmin")
        assert _in_csrs() == ["cse-in/id-mn-c"]

    def test_c_control_the_lab_in_was_not_touched(self, depc):
        """Read-only: the lab's IN on :8200 still holds exactly id-mn-a and id-mn-b, and nothing for id-mn-c.
        Not shown: that the lab is otherwise healthy (that is conftest's `topology`)."""
        assert handover.IN_CSE == LAB_IN
        assert handover.edges_ok(handover.registered_edges())
        assert _get(f"{LAB_IN[0]}/{LAB_IN[1]}/id-mn-c")[0] == 404


@contextlib.contextmanager
def _offered(uri: str, state: str):
    """An onem2m-mn-cse service registered at MEC 011 by the test itself, its app confirmed ready; removed after."""
    st, body = http("POST", f"{MEC011}/registrations", {"appName": "tr86-cd-offered-by-the-test"})
    assert st == 201
    mid = body["appInstanceId"]
    try:
        st, s = http("POST", f"{SERVICES}/applications/{mid}/services", {
            "serName": EDGE_SERVICE, "version": "4", "state": state, "serializer": "JSON",
            "transportInfo": {"id": "offered-by-the-test", "name": "oneM2M Mca", "type": "REST_HTTP",
                              "protocol": "HTTP", "version": "1.1", "security": {}, "endpoint": {"uris": [uri]}}})
        assert st == 201
        assert http("POST", f"{MEC011}/applications/{mid}/confirm_ready", {"indication": "READY"})[0] == 204
        yield s
    finally:
        http("DELETE", f"{MEC011}/registrations/{mid}")


# ------------------------------------------------------------------------------------------ option D
class TestOptionD:
    """Option D, the same MN-CSE also offered as a MEC service, and a consumer that finds it there. Not shown by any
    of these: a VM or container (processes on one host); a MEC platform (our unauthenticated MEC 011 and MEC 010-2
    candidates: anyone may offer an onem2m-mn-cse service); another ACME release than 2026.5.3; conformance."""

    def test_d_the_mn_cse_is_offered_as_the_mec_service_handover_reads(self, depd):
        """MEC 011 lists one onem2m-mn-cse service: endpoint its CSEBase URI, the producing instance's ids, both
        services offered before confirm_ready (the moment of confirm_ready itself is read in option C, same program).
        Not shown: serCategory, locality or liveness (not set)."""
        d = depd
        assert handover.EDGE_SERVICE == EDGE_SERVICE
        listed = _edge_services()
        assert len(listed) == 1, f"not exactly one {EDGE_SERVICE} service: {listed}"
        s, mid = listed[0], d.run["mec011AppInstanceId"]
        assert (s["serName"], s["version"], s["state"], s["serializer"]) == (EDGE_SERVICE, "4", "ACTIVE", "JSON")
        assert s["transportInfo"]["endpoint"] == {"uris": [MN_BASE]}
        assert s["transportInfo"]["id"] == d.iid                                  # the MEC 010-2 instance
        assert s["_links"]["self"]["href"].endswith(f"/applications/{mid}/services/{s['serInstanceId']}")  # MEC 011's
        assert sorted(x["serName"] for x in _listed(d.iid)) == sorted([APP_NAME, EDGE_SERVICE])
        assert _app_calls(d.p.mec.seen[:d.n0]) == [
            ("POST", "/mec_app_support/v2/registrations", 201),
            ("POST", f"/mec_service_mgmt/v1/applications/{mid}/services", 201),
            ("POST", f"/mec_service_mgmt/v1/applications/{mid}/services", 201),
            ("POST", f"/mec_app_support/v2/applications/{mid}/confirm_ready", 204)]
        assert [r["body"]["serName"] for r in d.p.mec.seen[:d.n0]
                if r["method"] == "POST" and r["path"].endswith("/services")] == [APP_NAME, EDGE_SERVICE]
        # still the MN-CSE of option C: 5.2.4 step 4 holds
        assert _cfg01() == CFG01_UP and _in_csrs() == ["cse-in/id-mn-c"]

    def test_d_the_consumer_discovered_it_through_mec011_and_registered_its_ae_there(self, depd):
        """The consumer's address for the MN-CSE came from MEC 011 alone: the platform hands it only the IN's address
        (its own entry for cse-mn-c is a dead one, port 9, and is not handed out), and the consumer's first Mp1 call
        is the discovery. It used the endpoint only after the IN answered with id-mn-c's <remoteCSE>, one read on the
        IN relay. Not shown: a consumer on another host; any authorization of the consumer by the service (none);
        that the endpoint is the CSE the IN holds (the check binds the CSE-ID it answers with, not the address)."""
        d = depd
        svc = _edge_services()[0]
        calls = _app_calls(d.p.mec.seen[d.n0:])
        mid = d.crun["mec011AppInstanceId"]
        assert calls == [("GET", f"/mec_service_mgmt/v1/services?ser_name={EDGE_SERVICE}", 200),
                         ("POST", "/mec_app_support/v2/registrations", 201),
                         ("POST", f"/mec_service_mgmt/v1/applications/{mid}/services", 201),
                         ("POST", f"/mec_app_support/v2/applications/{mid}/confirm_ready", 204)]
        inst_dir = d.workdir / "instances" / d.ciid
        assert json.loads((inst_dir / "instance.json").read_text())["cse"] == f"{d.p.inn.url}/{PIN[1]}"
        assert [(r["method"], r["path"], r["status"]) for r in d.p.inn.seen[slice(*d.in_window)]
                if r["headers"].get("x-m2m-origin") == "CAdmin"] == [("GET", "/cse-in/id-mn-c", 200)]
        assert json.loads((inst_dir / "instance.discovered.json").read_text()) == {
            "lcmInstanceId": d.ciid, "mec011": d.p.mec.url, "cse": MN_BASE, "serInstanceId": svc["serInstanceId"]}
        # one process, the one the agent started, now running the sensor AE program on what it found
        pid, store = d.crun["pid"], f"{d.workdir}/packages/{d.cpkg['appPkgId']}"
        assert _argv(pid) == [sys.executable, "-I", "-B", f"{store}/sensor_ae.py",
                              "--instance", f"{inst_dir}/instance.discovered.json"]
        assert _ppid(pid) == os.getpid() and _workloads(d.workdir).count(pid) == 1
        # on the MN-CSE: its AE, directly under the CSEBase, naming both instance ids, with its one reading
        st, body = _get(f"{MN_BASE}/{C_RN}")
        assert st == 200
        ae = body["m2m:ae"]
        assert (ae["pi"], ae["aei"], ae["api"]) == ("id-mn-c", C_ORIGIN, C_API)
        assert sorted(ae["lbl"]) == sorted([f"mec:appInstanceId:{mid}", f"mec:lcmInstanceId:{d.ciid}"])
        st, body = _get(f"{MN_BASE}/{C_RN}/{C_CNT}/la", C_ORIGIN)
        assert st == 200 and json.loads(body["m2m:cin"]["con"]) == READING and body["m2m:cin"]["cr"] == C_ORIGIN
        assert [(s["serName"], s["transportInfo"]["endpoint"]) for s in _listed(d.ciid)] == \
            [(CONSUMER_NAME, {"uris": [f"{MN_BASE}/{C_RN}"]})]

    def test_d_handover_target_check_accepts_it_only_against_the_private_in(self, depd, monkeypatch):
        """handover.target_ready, called as the orchestrator calls it, with the IN it reads pointed at the private
        IN (monkeypatch): accepted. With handover's own IN (the lab's, which holds no id-mn-c; read only): refused.
        Not shown: a handover to it."""
        s = _edge_services()[0]
        monkeypatch.setattr(handover, "IN_CSE", PIN)
        assert handover.registered_mn(MN) == (True, MN_CSI)
        assert handover._advertises(s, MN_BASE, MN[1], MN_CSI) is True
        assert handover.target_ready(MN, SERVICES) is True
        monkeypatch.setattr(handover, "IN_CSE", LAB_IN)
        assert handover.target_ready(MN, SERVICES) is False

    def test_d_control_a_stray_beside_it_blocks_the_consumer(self, depd):
        """What remains open: a second onem2m-mn-cse service at a CSEBase named cse-mn-c, offered by the test itself
        (unauthenticated) beside the genuine one. The consumer refuses both (found 2) before it asks any CSE anything:
        refused, not resolved, so a stray can still stop a consumer from starting. The consumer already running is
        not touched. Not shown: which of two a consumer should take (none here)."""
        d = depd
        genuine = _edge_services()
        with _stub_cse({"ri": "id-mn-x", "csi": "/id-mn-x", "cst": 2}) as (uri, stub), _offered(uri, "ACTIVE"):
            assert len(_edge_services()) == 2
            got = _refused_consumer(d.p, d.cpkg["appDId"], "consumer-beside-a-stray")
        assert f"MEC service {EDGE_SERVICE!r} at a CSEBase named 'cse-mn-c': found 2, need 1" in got.log
        assert got.mp1 == [("GET", f"/mec_service_mgmt/v1/services?ser_name={EDGE_SERVICE}", 200)]
        assert (got.in_reads, stub, got.discovered, got.running) == ([], [], False, [])
        assert _edge_services() == genuine and len(genuine) == 1
        assert _get(f"{MN_BASE}/{C_RN}")[0] == 200

    def test_d_control_the_consumer_checks_the_in_the_platform_names(self, depd):
        """The same consumer and the same genuine service, but the platform names the lab's IN as cse-in: that IN
        holds no id-mn-c, so the consumer refuses the MN-CSE (one read of the lab IN, read only, not through a relay).
        Not shown: which IN a platform should name (ours is told)."""
        p = depd.p
        was = p.agent.cses["cse-in"]
        p.agent.cses["cse-in"] = f"{LAB_IN[0]}/{LAB_IN[1]}"
        try:
            got = _refused_consumer(p, depd.cpkg["appDId"], "consumer-lab-in")
        finally:
            p.agent.cses["cse-in"] = was
        assert got.cfg["cse"] == f"{LAB_IN[0]}/{LAB_IN[1]}"
        assert re.search(r"is not an MN-CSE the IN-CSE holds: the IN holds no <remoteCSE> for /id-mn-c \(404\)",
                         got.log), got.log
        assert (got.in_reads, got.discovered, got.running) == ([], False, [])
        assert got.mp1 == [("GET", f"/mec_service_mgmt/v1/services?ser_name={EDGE_SERVICE}", 200)]


# ------------------------------------------------------------------------------------------ terminate (C and D)
def test_c_d_control_terminate_through_mec010_stops_the_cse_and_its_remote_cse_and_service_go(
        mec011, mec010, private_in, tmp_path, monkeypatch):
    """Option D deployed, then terminated through MEC 010-2: the workload and ACME are gone, :8203 is free, the IN
    holds no <remoteCSE> (ACME deleted its own over Mcc on SIGINT), MEC 011 holds nothing, the target check refuses.
    And in this order: MEC 011 stopped offering both services before the IN saw ACME's <remoteCSE> DELETE (the two
    relays' times, one clock), and ACME was gone, reaped by its supervisor, when the supervisor sent its last request
    (the relay holds that deregistration while the test looks).
    Not shown: termination of a CSE that has registrees or devices (they would be left without a CSE)."""
    monkeypatch.setattr(handover, "IN_CSE", PIN)
    with _platform(tmp_path / "platform") as p:
        pkg = p.agent.onboard(_as_option_d(tmp_path / "mn_cse_d"))
        iid = p.agent.create_instance(pkg["appDId"], "mn-c-to-terminate")
        run = p.agent.instantiate(iid, ready_timeout=45.0)
        pid, mid, acme = run["pid"], run["mec011AppInstanceId"], _children(run["pid"])
        # beside the control: all of it is there while it runs
        assert len(acme) == 1 and _listener(MN_PORT) == acme and _cfg01() == CFG01_UP
        assert _in_csrs() == ["cse-in/id-mn-c"] and handover.target_ready(MN, SERVICES) is True
        n_in, n_mec = len(p.inn.seen), len(p.mec.seen)

        def last(r) -> bool:
            return r["method"] == "DELETE" and r["path"] == f"/mec_app_support/v2/registrations/{mid}"

        p.mec.hold, out = last, {}

        def stop():
            try:
                out["done"] = p.agent.terminate(iid)
            except Exception as e:  # noqa: BLE001  shown by the assertion below
                out["err"] = e

        t = threading.Thread(target=stop, daemon=True)
        t.start()
        _wait(lambda: any(last(r) for r in p.mec.seen[n_mec:]) or not t.is_alive(), timeout=20)
        at_last = {"acme": Path(f"/proc/{acme[0]}").exists(), "supervisor": _alive(pid)}
        p.mec.release.set()
        t.join(30)
        p.mec.hold = None
        assert "done" in out, out
        assert at_last == {"acme": False, "supervisor": True}, \
            f"when the supervisor deregistered: {at_last} (ACME must be gone before its supervisor exits)"
        done = out["done"]
        assert (done["exitCode"], done["forced"]) == (0, False)
        assert not Path(f"/proc/{pid}").exists() and not Path(f"/proc/{acme[0]}").exists()
        assert _workloads(p.workdir) == [] and _listener(MN_PORT) == [] and not _port_open("127.0.0.1", MN_PORT)
        assert _cfg01() == CFG01_NO_MN and _in_csrs() == []
        # on Mcc: the MN-CSE itself deleted its <remoteCSE> at the IN (SP-relative, as it registered)
        assert [(r["path"], r["headers"]["x-m2m-origin"], r["status"], r["rsc"]) for r in p.inn.seen[n_in:]
                if r["method"] == "DELETE"] == [("/~/id-in/cse-in/id-mn-c", MN_CSI, 200, 2002)]
        # on Mp1: the workload said goodbye, removed both services, then its registration
        tail = [(m, path.rsplit("/", 1)[-1], st) for m, path, st in _app_calls(p.mec.seen[n_mec:])]
        assert [t[0] for t in tail] == ["POST", "DELETE", "DELETE", "DELETE"]
        assert tail[0] == ("POST", "confirm_termination", 204) and tail[-1] == ("DELETE", mid, 204)
        # the order, on the two relays' clocks (time.monotonic of this process)
        ser_del = [r for r in p.mec.seen[n_mec:] if r["method"] == "DELETE" and "/services/" in r["path"]]
        csr_del = [r for r in p.inn.seen[n_in:] if r["method"] == "DELETE"]
        dereg = [r for r in p.mec.seen[n_mec:] if last(r)]
        assert (len(ser_del), len(csr_del), len(dereg)) == (2, 1, 1)
        assert max(r["t_out"] for r in ser_del) < csr_del[0]["t_in"], \
            "MEC 011 still offered the MN-CSE when the IN was asked to drop it"
        assert csr_del[0]["t_out"] < dereg[0]["t_in"]
        assert not _registered(mid) and _listed(iid) == [] and _edge_services() == []
        assert handover.target_ready(MN, SERVICES) is False
        # MEC 010-2
        assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED"
        assert _opoccs(iid) == [("INSTATIATE", "PROCESSING"), ("TERMINATE", "PROCESSING")]
        assert p.agent.results[done["opOcc"]] == "COMPLETED"
        assert _package(pkg["appPkgId"])["usageState"] == "NOT_IN_USE"
        p.agent.delete_instance(iid)
        p.agent.offboard(pkg["appPkgId"])


def test_c_control_a_killed_workload_does_not_leave_its_cse_behind(mec011, mec010, private_in, tmp_path):
    """The agent kills a workload that will not stop (SIGKILL after the grace period); here it is killed outright.
    ACME, its child, then gets SIGINT from the kernel (PR_SET_PDEATHSIG) and stops in order: its port is free and its
    <remoteCSE> at the IN goes. The dead app's MEC 011 registration stays until the agent's terminate removes it.
    Not shown: a kill of the whole host or of ACME itself (that <remoteCSE> would stay at the IN)."""
    with _platform(tmp_path / "platform") as p:
        pkg = p.agent.onboard(PKG_C)
        iid = p.agent.create_instance(pkg["appDId"], "mn-c-killed")
        run = p.agent.instantiate(iid, ready_timeout=45.0)
        pid, mid, acme = run["pid"], run["mec011AppInstanceId"], _children(run["pid"])
        assert len(acme) == 1 and _in_csrs() == ["cse-in/id-mn-c"] and _registered(mid)    # beside the control
        os.kill(pid, signal.SIGKILL)
        assert _wait(lambda: not Path(f"/proc/{acme[0]}").exists(), timeout=15), "ACME outlived its supervisor"
        assert not _port_open("127.0.0.1", MN_PORT) and _in_csrs() == []
        assert _registered(mid), "something removed the registration the dead workload could not"
        done = p.agent.terminate(iid)
        assert (done["exitCode"], done["forced"]) == (-9, False)
        assert not _registered(mid) and _listed(iid) == []
        assert _opoccs(iid) == [("INSTATIATE", "PROCESSING"), ("TERMINATE", "FAILED")]


def test_c_control_a_port_already_held_is_refused_before_anything_starts(mec011, mec010, private_in, tmp_path):
    """Something already listens on :8203 (a bare socket here, standing for a stale CSE of an earlier run, which
    would answer as id-mn-c and could be taken for this one): the workload refuses before it registers anywhere or
    starts ACME. Not shown: a port taken after the check (between the check and ACME's bind)."""
    with _platform(tmp_path / "platform") as p:
        pkg = p.agent.onboard(PKG_C)
        iid = p.agent.create_instance(pkg["appDId"], "mn-c-port-held")
        n_mec, n_in = len(p.mec.seen), len(p.inn.seen)
        with socket.socket() as s:
            s.bind(("127.0.0.1", MN_PORT))
            s.listen()
            with pytest.raises(mad.DeployError, match="127.0.0.1:8203 already answers before this CSE was started"):
                p.agent.instantiate(iid, ready_timeout=20.0)
        assert _app_calls(p.mec.seen[n_mec:]) == [] and p.inn.seen[n_in:] == []
        assert not (p.workdir / "instances" / iid / "acme").exists() and _workloads(p.workdir) == []
        assert _in_csrs() == []
        assert _opoccs(iid) == [("INSTATIATE", "FAILED"), ("TERMINATE", "PROCESSING")]


# ------------------------------------------------------------------------------------------ offline: the packages
# No CSE, no MEC candidate, no network below this line.
def test_pkg_mn_cse_verifies_and_says_what_the_live_tests_expect():
    assert sorted(x.name for x in PKG_C.iterdir()) == ["appd.json", "mn-c.ini", "mn_cse.py"]
    d = mad.verify_package(PKG_C)
    assert d.pop("files") == {"mn-c.ini": _sha(PKG_C / "mn-c.ini"), "mn_cse.py": _sha(PKG_C / "mn_cse.py")}
    d.pop("appDescription", None)
    assert d == DESCRIPTOR_C
    assert "appServiceProduced" not in d, "the shipped package is option C"


def test_pkg_mn_c_ini_is_mn_a_ini_with_only_the_stated_changes():
    assert _settings((PKG_C / "mn-c.ini").read_text()) == \
        _settings(_derive((CONF / "mn-a.ini").read_text(), MN_C_FROM_MN_A))
    assert not re.search(r"(?mi)^\s*baseDirectory\s*=", (PKG_C / "mn-c.ini").read_text())


def test_pkg_option_d_is_the_shipped_package_with_one_field_more(tmp_path):
    dpkg = _as_option_d(tmp_path / "d")
    c, d = mad.verify_package(PKG_C), mad.verify_package(dpkg)
    assert {k for k in c.keys() | d.keys() if c.get(k) != d.get(k)} == {"appServiceProduced"}
    assert d["appServiceProduced"] == D_PRODUCED
    for f in ("mn_cse.py", "mn-c.ini"):
        assert _sha(dpkg / f) == _sha(PKG_C / f)
    assert mad.descriptor_digest(dpkg) != mad.descriptor_digest(PKG_C)      # a package of its own at app_pkgm


def test_pkg_cse_consumer_verifies_and_runs_the_sensor_ae_byte_for_byte():
    assert sorted(x.name for x in PKG_CONSUMER.iterdir()) == ["appd.json", "discover.py", "sensor_ae.py"]
    d = mad.verify_package(PKG_CONSUMER)
    assert d.pop("files") == {"discover.py": _sha(PKG_CONSUMER / "discover.py"),
                              "sensor_ae.py": _sha(PKG_SENSOR / "sensor_ae.py")}
    d.pop("appDescription", None)
    assert d == DESCRIPTOR_CONSUMER
    assert (PKG_CONSUMER / "sensor_ae.py").read_bytes() == (PKG_SENSOR / "sensor_ae.py").read_bytes()


def test_pkg_programs_use_the_standard_library_only():
    import ast
    for prog in (PKG_C / "mn_cse.py", PKG_CONSUMER / "discover.py"):
        tree = ast.parse(prog.read_text())
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
                {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        assert names - {"__future__"} <= sys.stdlib_module_names, (prog.name, names - sys.stdlib_module_names)


def test_pkg_the_lab_in_allow_list_is_why_the_in_here_is_private():
    """Read from the configs: the lab's IN admits id-mn-a and id-mn-b only; the private IN is the same file with four
    lines changed, admitting id-mn-c only."""
    lab = (CONF / "in.ini").read_text()
    assert re.findall(r"(?m)^allowedCSROriginators=(.*)$", lab) == ["/id-mn-a,/id-mn-b"]
    mine = _derive(lab, PRIVATE_IN_FROM_IN)
    assert re.findall(r"(?m)^allowedCSROriginators=(.*)$", mine) == ["/id-mn-c"]
    assert set(_settings(lab)) - set(_settings(mine)) == {
        "httpPort=8200", "registrarCsePort=8200", "baseDirectory=/home/edgefollow/estimed-run/in",
        "allowedCSROriginators=/id-mn-a,/id-mn-b"}
    assert re.findall(r"(?m)^(cseID|cseName)=(.*)$", mine) == [("cseID", "id-in"), ("cseName", "cse-in")]


@pytest.mark.parametrize("planted", ["baseDirectory =/home/edgefollow/estimed-run/in",
                                     " baseDirectory=/home/edgefollow/estimed-run/in", "BASEDIRECTORY = /x",
                                     "basedirectory: /x"])
def test_private_in_ini_control_refuses_a_base_directory_in_any_spelling(planted):
    """The private IN's ini is refused if a baseDirectory line survives _derive in any spelling ACME would read."""
    lab = (CONF / "in.ini").read_text()
    assert not re.search(r"(?mi)^\s*baseDirectory", _private_in_ini(lab))     # beside the control: the real one
    assert lab.count("[basic.config]\n") == 1
    with pytest.raises(ValueError, match="baseDirectory"):
        _private_in_ini(lab.replace("[basic.config]\n", f"[basic.config]\n{planted}\n"))


def _append(path: Path, line: str) -> None:
    with path.open("a") as f:
        f.write(line + "\n")


@pytest.mark.parametrize("what, plant, found", [
    ("nothing", lambda r: None, []),
    ("a lab line of its own", lambda r: _append(r / "in/logs/lab.log", "WARNING id-mn-b refused on :8200, 18203 ms"),
     []),
    ("a line naming :8240", lambda r: _append(r / "in/logs/lab.log", "INFO http server on 127.0.0.1:8240"),
     ["in/logs/lab.log: INFO http server on 127.0.0.1:8240"]),
    ("a line naming id-mn-c", lambda r: _append(r / "mn-a/logs/lab.log", "WARNING /id-mn-c not found"),
     ["mn-a/logs/lab.log: WARNING /id-mn-c not found"]),
    ("a line naming id-mn-x", lambda r: _append(r / "in/logs/lab.log", 'WARNING Add "id-mn-x" to the configuration'),
     ['in/logs/lab.log: WARNING Add "id-mn-x" to the configuration']),
    ("a line naming :8204", lambda r: _append(r / "mn-b/logs/lab.log", "x http://127.0.0.1:8204/cse-mn-d"),
     ["mn-b/logs/lab.log: x http://127.0.0.1:8204/cse-mn-d"]),
    ("a file added", lambda r: (r / f"in/logs/{IN_LOG}").write_text(""), [f"added in/logs/{IN_LOG}"]),
    ("a file rotated", lambda r: ((r / "mn-a/logs/lab.log").rename(r / "mn-a/logs/lab.log.1"),
                                  (r / "mn-a/logs/lab.log").write_text("x\n")),
     ["added mn-a/logs/lab.log.1", "replaced or shrunk mn-a/logs/lab.log"]),
    # written beside it, then renamed over it: another inode for certain, and longer, so only the inode tells
    ("a file replaced by a longer one", lambda r: ((r / "mn-b/logs/lab.new").write_text("INFO CSE started\nINFO x\n"),
                                                   (r / "mn-b/logs/lab.new").replace(r / "mn-b/logs/lab.log")),
     ["replaced or shrunk mn-b/logs/lab.log"])])
def test_lab_log_check_control_sees_what_it_must(tmp_path, what, plant, found):
    """_lab_log_changes on a stand-in of the lab's run folder (never the lab's): each planted change is reported, a
    line the lab's own CSEs could write is not."""
    for d in LAB_LOG_DIRS:
        (tmp_path / d / "logs").mkdir(parents=True)
        (tmp_path / d / "logs" / "lab.log").write_text("INFO CSE started\n")
    before = _lab_logs(tmp_path)
    assert len(before) == 3 and _lab_log_changes(before, tmp_path) == []
    plant(tmp_path)
    assert [x.replace(f"{tmp_path}/", "") for x in _lab_log_changes(before, tmp_path)] == found


@pytest.mark.parametrize("what, files, ok", [
    ("its log alone", [IN_LOG], True),
    ("no logs folder", None, False),
    ("an empty logs folder", [], False),
    ("another CSE's log", ["cse-estimed.example.com-id-mn-c.log"], False),
    ("its log and another file", [IN_LOG, f"{IN_LOG}.1"], False)])
def test_private_in_log_check_control(tmp_path, what, files, ok):
    """_private_in_log_check, which the private-IN fixture runs once the IN answers, on stand-in base folders."""
    if files is not None:
        (tmp_path / "logs").mkdir()
        for f in files:
            (tmp_path / "logs" / f).write_text("")
    if ok:
        _private_in_log_check(tmp_path)
    else:
        with pytest.raises(ValueError, match="is not .* alone"):
            _private_in_log_check(tmp_path)


def _mn():
    return _load(PKG_C / "mn_cse.py", "mn_cse")


REGISTRAR = "http://127.0.0.1:41234/cse-in"


def test_mn_cse_render_ini_fills_the_registrar_and_reads_its_own_address():
    m = _mn()
    tpl, desc = (PKG_C / "mn-c.ini").read_text(), json.loads((PKG_C / "appd.json").read_text())
    got = m.render_ini(tpl, REGISTRAR, desc)
    assert got["text"] == tpl.replace("@REGISTRAR_HOST@", "127.0.0.1").replace("@REGISTRAR_PORT@", "41234")
    assert {k: v for k, v in got.items() if k != "text"} == {
        "host": "127.0.0.1", "port": 8203, "base_url": MN_BASE, "csi": MN_CSI, "admin": "CAdmin",
        "registrar_csr": "cse-mn-c/id-in"}


@pytest.mark.parametrize("change, why", [
    (lambda t, r, d: (t.replace("cseType=MN", "cseType=MN\nbaseDirectory=/home/edgefollow/estimed-run/mn-c"), r, d),
     "baseDirectory"),
    (lambda t, r, d: (t.replace("cseType=MN", "cseType=MN\nBASEDIRECTORY = /x"), r, d), "baseDirectory"),
    (lambda t, r, d: (t.replace("cseName=cse-mn-c", "cseName=cse-mn-a"), r, d), "cseName"),
    (lambda t, r, d: (t.replace("adminID=CAdmin", "adminID=CRoot"), r, d), "adminID"),
    (lambda t, r, d: (t.replace("cseType=MN", "cseType=IN"), r, d), "cseType"),
    (lambda t, r, d: (t.replace("registrarCseName=cse-in", "registrarCseName=cse-other"), r, d), "registrarCseName"),
    (lambda t, r, d: (t.replace("@REGISTRAR_PORT@", "8200"), r, d), "@REGISTRAR_PORT@"),
    (lambda t, r, d: (t, "http://127.0.0.1:41234/cse-other", d), "registrar"),
    (lambda t, r, d: (t, "https://127.0.0.1:41234/cse-in", d), "registrar"),
    (lambda t, r, d: (t, "http://127.0.0.1/cse-in", d), "registrar"),
    (lambda t, r, d: (t, "http://127.0.0.1:41234/cse-in/x", d), "registrar")])
def test_mn_cse_render_ini_control_refuses(change, why):
    m = _mn()
    tpl, desc = (PKG_C / "mn-c.ini").read_text(), json.loads((PKG_C / "appd.json").read_text())
    assert m.render_ini(tpl, REGISTRAR, desc)["csi"] == MN_CSI             # beside the control: the shipped one passes
    with pytest.raises(m.Failed, match=why):
        m.render_ini(*change(tpl, REGISTRAR, desc))


def test_mn_cse_finds_the_installed_acme_release(tmp_path):
    m = _mn()
    assert m.acme_releases(Path(ACME)) == [ACME_RELEASE]
    # control: another release beside it, or none, is what it reports
    fake = tmp_path / "venv"
    (fake / "bin").mkdir(parents=True)
    (fake / "bin" / "acmecse").write_text("")
    assert m.acme_releases(fake / "bin" / "acmecse") == []
    (fake / "lib" / "python3.13" / "site-packages" / "acmecse-2026.1.0.dist-info").mkdir(parents=True)
    assert m.acme_releases(fake / "bin" / "acmecse") == ["2026.1.0"]


def test_mn_cse_produced_services():
    m = _mn()
    assert m.produced({}) == [] and m.produced({"appServiceProduced": []}) == []
    assert m.produced({"appServiceProduced": copy.deepcopy(D_PRODUCED)}) == D_PRODUCED
    for bad in ([{"serName": "mec_v2x", "version": "1"}], [{"serName": EDGE_SERVICE}],
                [{"serName": EDGE_SERVICE, "version": ""}], D_PRODUCED * 2, {"serName": EDGE_SERVICE}, ["x"]):
        with pytest.raises(m.Failed, match="appServiceProduced"):
            m.produced({"appServiceProduced": bad})


class _Running:
    """A stand-in for ACME's Popen that has not exited."""
    returncode = None

    def poll(self):
        return None


CSE_FACTS = {"base_url": MN_BASE, "admin": "CAdmin", "csi": MN_CSI, "registrar_csr": "cse-mn-c/id-in"}


@pytest.mark.parametrize("what, cb, uril, ready", [
    ("as itself, holding its registrar", {"csi": MN_CSI, "cst": 2}, ["cse-mn-c/id-in"], True),
    ("another CSE-ID", {"csi": "/id-mn-a", "cst": 2}, ["cse-mn-c/id-in"], False),
    ("not a middle node", {"csi": MN_CSI, "cst": 1}, ["cse-mn-c/id-in"], False),
    ("a <remoteCSE>, not its registrar's", {"csi": MN_CSI, "cst": 2}, ["cse-mn-c/id-mn-x"], False),
    ("the registrar's name under another CSE", {"csi": MN_CSI, "cst": 2}, ["cse-mn-a/id-in"], False),
    ("no <remoteCSE>", {"csi": MN_CSI, "cst": 2}, [], False)])
def test_mn_cse_wait_up_counts_only_this_cse_holding_its_registrar(monkeypatch, what, cb, uril, ready):
    """wait_up, the readiness behind confirm_ready, on faked RETRIEVE answers: only this CSE (its CSE-ID, cst 2)
    holding its registrar's <remoteCSE> is ready; anything else times out as not ready."""
    m = _mn()
    monkeypatch.setattr(m, "READY_S", 0.5)
    asked = []

    def retrieve(url, origin):
        asked.append((url, origin))
        if url == MN_BASE:
            return 2000, {"m2m:cb": cb}
        if url == f"{MN_BASE}?fu=1&ty=16":
            return 2000, {"m2m:uril": uril}
        return 4004, None

    monkeypatch.setattr(m, "retrieve", retrieve)
    if ready:
        m.wait_up(_Running(), CSE_FACTS)
        assert asked == [(MN_BASE, "CAdmin"), (f"{MN_BASE}?fu=1&ty=16", "CAdmin")]
    else:
        with pytest.raises(m.Failed, match=r"not up and registered within 0.5 s"):
            m.wait_up(_Running(), CSE_FACTS)
        assert asked and {o for _, o in asked} == {"CAdmin"}


class _NoHandler(Exception):
    """SIGTERM reached the test's own guard, not a handler of the supervisor's."""


def _no_handler(*_):
    raise _NoHandler


STAND_IN = """#!{python} -I
import os, pathlib, signal, sys, time
{on_sigint}
pathlib.Path("up").write_text(str(os.getpid()))
time.sleep(60)
"""


@pytest.mark.parametrize("what, on_sigint, code, acme_exit", [
    ("stops on SIGINT with 0", "signal.signal(signal.SIGINT, lambda *a: sys.exit(0))", 0, "0"),
    ("ignores SIGINT", "signal.signal(signal.SIGINT, signal.SIG_IGN)", 3, "-9"),
    ("stops on SIGINT with 1", "signal.signal(signal.SIGINT, lambda *a: sys.exit(1))", 3, "1")])
def test_mn_cse_main_reports_an_acme_that_did_not_stop_cleanly(tmp_path, monkeypatch, capsys, what, on_sigint, code,
                                                               acme_exit):
    """mn_cse.py's main, in this process, with a stand-in for ACME (a small program in a fake venv carrying the
    release's dist-info) and MEC 011 and the CSE's answers faked; the termination request is a SIGTERM to this
    process. A child that ignores SIGINT is killed after STOP_S and the supervisor exits 3, as it does for a child
    that stops with 1; a child that stops with 0 gives exit 0. Either way the child is gone (reaped) when main
    returns, and the supervisor still deregisters. No network: MEC 011, the CSE and the port probe are faked."""
    venv = tmp_path / "venv"
    (venv / "lib" / "python3.13" / "site-packages" / f"acmecse-{ACME_RELEASE}.dist-info").mkdir(parents=True)
    (venv / "bin").mkdir()
    prog = venv / "bin" / "acmecse"
    prog.write_text(STAND_IN.format(python=sys.executable, on_sigint=on_sigint))
    prog.chmod(0o755)
    pkg = tmp_path / "pkg"
    shutil.copytree(PKG_C, pkg)
    desc = json.loads((pkg / "appd.json").read_text())
    desc["acme"]["program"] = str(prog)
    (pkg / "appd.json").write_text(json.dumps(desc))
    inst = tmp_path / "inst"
    inst.mkdir()
    (inst / "instance.json").write_text(json.dumps({"lcmInstanceId": "lcm-1", "mec011": "http://mec011.invalid",
                                                    "cse": REGISTRAR}))
    m = _load(pkg / "mn_cse.py", "mn_cse")
    up, calls, timers = inst / "acme" / "up", [], []

    def call(method, url, body=None, headers=None):
        calls.append((method, url.removeprefix("http://mec011.invalid")))
        if url.endswith("/registrations"):
            return 201, {"appInstanceId": "mec-1"}, {}
        if url.endswith("/services"):
            return 201, {"serInstanceId": f"s{len(calls)}"}, {}
        if url.endswith("/confirm_ready"):
            timers.append(threading.Timer(0.3, os.kill, (os.getpid(), signal.SIGTERM)))
            timers[-1].start()
        return 204, None, {}

    def retrieve(url, origin):
        if not up.exists():
            return 0, None
        return (2000, {"m2m:cb": {"csi": MN_CSI, "cst": 2}}) if url == MN_BASE else \
            (2000, {"m2m:uril": ["cse-mn-c/id-in"]})

    for name, value in (("call", call), ("retrieve", retrieve), ("_answers", lambda host, port: False),
                        ("STOP_S", 1.0)):
        monkeypatch.setattr(m, name, value)
    monkeypatch.chdir(inst)
    monkeypatch.setattr(sys, "argv", ["mn_cse.py", "--instance", str(inst / "instance.json")])
    saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    # The termination request is a SIGTERM to this process: without this guard, a supervisor that installs no SIGTERM
    # handler would take pytest down with it, and the session's private IN with it (pass 2, planted fault N8).
    signal.signal(signal.SIGTERM, _no_handler)
    child = None
    try:
        try:
            got = m.main()
        except _NoHandler:
            got = "the supervisor installed no SIGTERM handler"
        child = int(up.read_text())
        left = Path(f"/proc/{child}").exists()
    finally:
        for t in timers:
            t.cancel()
            t.join()
        for s, h in saved.items():
            signal.signal(s, h)
        if child is not None and Path(f"/proc/{child}").exists():      # a supervisor that did not wait for it
            with contextlib.suppress(ProcessLookupError):
                os.kill(child, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(child, 0)
    said = capsys.readouterr().out
    assert (got, left) == (code, False), f"exit {got!r}, child still there: {left}; it said: {said[-400:]!r}"
    assert f"ACME stopped: exit {acme_exit}\n" in said
    assert calls == [("POST", "/mec_app_support/v2/registrations"),
                     ("POST", "/mec_service_mgmt/v1/applications/mec-1/services"),
                     ("POST", "/mec_app_support/v2/applications/mec-1/confirm_ready"),
                     ("POST", "/mec_app_support/v2/applications/mec-1/confirm_termination"),
                     ("DELETE", "/mec_service_mgmt/v1/applications/mec-1/services/s2"),
                     ("DELETE", "/mec_app_support/v2/registrations/mec-1")]


def _svc(uri=MN_BASE, name=EDGE_SERVICE, state="ACTIVE", sid="s1"):
    return {"serName": name, "state": state, "serInstanceId": sid, "transportInfo": {"endpoint": {"uris": [uri]}}}


def test_discover_choose_takes_the_one_service_at_a_csebase_of_that_name():
    m = _load(PKG_CONSUMER / "discover.py", "discover")
    assert m.choose([_svc()], EDGE_SERVICE, "cse-mn-c") == (MN_BASE, "s1")
    # others beside it do not disturb the choice
    assert m.choose([_svc("http://127.0.0.1:8201/cse-mn-a", sid="a"), _svc(sid="c"), _svc(state="INACTIVE", sid="i"),
                     _svc(name="estimed-mn-cse", sid="n")], EDGE_SERVICE, "cse-mn-c") == (MN_BASE, "c")


@pytest.mark.parametrize("listed, found", [
    ([], 0),
    ([_svc(sid="a"), _svc("http://127.0.0.1:8213/cse-mn-c", sid="b")], 2),       # two: refused, not guessed
    ([_svc(name="estimed-mn-cse")], 0),
    ([_svc(state="INACTIVE")], 0),
    ([_svc(f"{MN_BASE}/")], 0),
    ([_svc("http://127.0.0.1:8203")], 0),
    ([_svc(f"{MN_BASE}/estimedSensor")], 0),
    ([_svc("http://127.0.0.1:8203/xcse-mn-c")], 0),
    ([_svc(f"{MN_BASE}?fu=1")], 0),
    ([_svc("ftp://127.0.0.1:8203/cse-mn-c")], 0),
    ([{"serName": EDGE_SERVICE, "state": "ACTIVE", "transportInfo": ["not", "a", "dict"]}], 0),
    ({"m2m:uril": []}, 0)])
def test_discover_choose_control_refuses(listed, found):
    m = _load(PKG_CONSUMER / "discover.py", "discover")
    with pytest.raises(m.Failed, match=f"found {found}, need 1"):
        m.choose(listed, EDGE_SERVICE, "cse-mn-c")


STRAY = ("http://127.0.0.1:41999", "cse-mn-c")
CB_C, CSR_C = {"m2m:cb": {"csi": MN_CSI, "cst": 2}}, {"m2m:csr": {"csi": MN_CSI, "cst": 2}}


@pytest.mark.parametrize("what, dst, at_cse, at_in, want", [
    ("the genuine MN-CSE", MN, (200, CB_C), (200, CSR_C), (True, MN_CSI)),
    ("a middle node the IN does not hold", STRAY, (200, {"m2m:cb": {"csi": "/id-mn-x", "cst": 2}}), (404, None), False),
    ("an IN-CSE", STRAY, (200, {"m2m:cb": {"csi": "/id-in", "cst": 1}}), (200, CSR_C), False),
    ("an ASN-CSE", STRAY, (200, {"m2m:cb": {"csi": MN_CSI, "cst": 3}}), (200, CSR_C), False),
    ("no CSE-ID", STRAY, (200, {"m2m:cb": {"cst": 2}}), (200, CSR_C), False),
    ("the read refused", STRAY, (403, {"m2m:dbg": "no"}), (200, CSR_C), False),
    ("the IN's <remoteCSE> of another CSE-ID", STRAY, (200, CB_C), (200, {"m2m:csr": {"csi": "/id-mn-x", "cst": 2}}),
     False),
    ("the IN's <remoteCSE> not a middle node", STRAY, (200, CB_C), (200, {"m2m:csr": {"csi": MN_CSI, "cst": 1}}),
     False),
    ("nothing answers at the endpoint", STRAY, OSError, (200, CSR_C), OSError),
    ("nothing answers at the IN", STRAY, (200, CB_C), OSError, OSError),
    ("OPEN: a stray answering with a CSE-ID the IN holds", STRAY, (200, CB_C), (200, CSR_C), (True, MN_CSI))])
def test_discover_registered_mn_is_handovers(monkeypatch, what, dst, at_cse, at_in, want):
    """The consumer's IN check and estimed/handover.py registered_mn, on the same faked answers: the same requests
    (URL, originator, order) and the same outcome, row by row. The endpoint is a stray's address (:41999) in every
    row but the first, so the last row, the same answers as the first, is what stays open: the check binds the
    CSE-ID the endpoint answers with, not the address the IN holds for it. A handover.py that closes it turns that
    row red here, or makes the two differ."""
    disc = _load(PKG_CONSUMER / "discover.py", "discover")
    assert disc.READER == handover.ORCHESTRATOR
    monkeypatch.setattr(handover, "IN_CSE", PIN)

    def answer(url):
        got = at_cse if url == f"{dst[0]}/{dst[1]}" else at_in if url.startswith(f"{PIN_BASE}/") else None
        assert got is not None, url
        if got is OSError:
            raise urllib.error.URLError("[Errno 111] Connection refused")
        return got

    def outcome(fn, asked):
        try:
            r = fn()
        except OSError:
            return OSError, asked
        return (r if r[0] else False), asked

    asked_h, asked_d = [], []
    monkeypatch.setattr(handover, "_req", lambda method, url, origin, **kw: (asked_h.append((method, url, origin)),
                                                                            answer(url))[1])
    monkeypatch.setattr(disc, "retrieve", lambda url: (asked_d.append(("GET", url, disc.READER)), answer(url))[1])
    h = outcome(lambda: handover.registered_mn(dst), asked_h)
    d = outcome(lambda: disc.registered_mn(f"{dst[0]}/{dst[1]}", PIN_BASE), asked_d)
    assert d == h
    assert d[0] == want
