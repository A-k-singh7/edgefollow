"""TR-0086 deployment option A, live: the oneM2M MEC-IPE as a MEC application on the MEC host, the IN-CSE in the
cloud, no MN-CSE on the edge (developer guide 5.2.2 table, row A; 5.2.3 prerequisites; 5.2.4 procedure; 5.6.4).

The lab underneath is option B (MN-A :8201 and MN-B :8202 stay registered at the IN :8200). Option A here means: the
IPE is instantiated through our MEC 010-2 candidate (which holds the instance INSTANTIATED while it runs), registers as
an <AE> straight at the IN-CSE over Mca, and the workload process itself connects to no CSE port: to the IN only
through the recording relay, to MN-A and MN-B not at all, as far as a recorder inside the workload process sees
(socket calls through Python; its limits are listed below).

    estimed/apps/mec_ipe               the package: mec_ipe_app.py (the MEC lifecycle) around estimed/mec_ipe.py and
                                       estimed/handover.py, carried byte for byte (checked below)
    mec010p2/candidate.py      :8092   MEC 010-2 package management and lifecycle; started here if absent
    mec011_appsupport/candidate.py     MEC 011 registration and service registry, :8091 (conftest)
    estimed/mec_app_deploy.py          the platform agent: checks the digests, starts and stops the workload. It is
                                       given one CSE, cse-in. In the live tests its python3 runtime has the test's
                                       connect recorder (RECORDER below) put in front of the program
    mec013_look/candidate.py   :8101   MEC 013 location with its fixed users (acr:10.0.0.x); must already run

Two recording relays stand between the workload and the lab, one on Mca (in front of the IN) and one on Mp1 (in front
of MEC 011), so what the IPE sent is read off the wire, not taken from its log. Inside the workload's process a
test-only recorder logs every socket connect it makes (Python's audit hook), so where it connected is read from the
process too, not only from what passed the relays.

    5.2.3   the instance configuration holds the MEC 011 endpoint and the IN-CSE, the descriptor the api; nothing in
            either names an MN-CSE
    5.2.4   step 1 the IN answers 2000 with cst 1; step 2 MEC 011 answers; steps 3-4 for option A: the IPE's <AE>
            directly under the IN's CSEBase (no <remoteCSE> added), its poa the workload's own listening socket, its
            tree; its MEC 011 registration listed ready, confirmed only after its last write at the IN
    010-2   read from the candidate, not from the agent: INSTANTIATED while the IPE runs, holding the INSTATIATE
            occurrence the agent named; after termination NOT_INSTANTIATED, holding the TERMINATE occurrence. Both
            stay PROCESSING there (the candidate has no route that completes one); "COMPLETED" is the agent's own
            record and is labelled so where it is checked
    5.6.4   an operator-registered UE identity and a device's request -> location contentInstances written by the IPE
            into the device's container on the IN, equal to an independent read of MEC 013
    controls  no running instance -> nothing written; a device naming another device's container is refused on the IN
            path; a device with no ue-registry entry gets nothing written (registered, the same request is served);
            a device cannot write the UE registry; the workload connects to no CSE port itself; termination through
            MEC 010-2 stops the process and removes the <AE> (and nothing answers at its poa); a killed IPE instead
            leaves its <AE> at the IN with a poa that does not answer, until the next instance replaces it; a second
            instance does not evict the first; the MN-A and MN-B trees are the same after the module as before it

What this does NOT show:
    * processes on one host: no container, no VM, no isolation of the workload (mec_app_deploy.py says the same)
    * our MEC candidates, not a MEC platform: the MEC 011 registration is unauthenticated, MEC 010-2 starts nothing
      itself, and none of the credentials 5.2.3 asks for exist here
    * the IPE polls MEC 013 (GET /location/v3/queries/users every notificationPeriod); it does not use MEC 013
      subscriptions (mec_ipe.py says why). The MEC 013 address is a descriptor argument, not discovered over Mp1, and
      the UEs are the MEC 013 candidate's fixed users
    * the guide's MEC 011 check "GET /mec_app_support/v2/ -> 200" answers 404 at our candidate; timing/current_time and
      the service list are what is checked
    * "no MN-CSE involved" rests on the workload process's own record (the recorder: the audit events socket.connect,
      socket.sendto and socket.sendmsg, with subprocess / os.posix_spawn starts and ctypes library loads logged too
      and required absent), on the relay's record (every path under the IN's CSEBase, so nothing retargeted through
      the IN), and on the MN-CSEs' trees before and after. Not seen: a connection made without Python's socket
      module (a raw system call); a child started through _posixsubprocess.fork_exec as multiprocessing's "spawn"
      does (it raises no audit event; a review run showed such a child reading MN-A unseen); a native module
      imported without ctypes; some other process on the host; and, because the recorder shares the workload's
      process, a workload that silences or rewrites the recorder (a review run did so). The shipped workload imports
      none of _posixsubprocess, _ctypes or multiprocessing (checked in review). The text check for MN-CSE names (NOT_HERE) is only
      secondary: a name built at run time passes it
    * the recorder runs in the workload's process, so the live tests do not run the agent's command line byte for
      byte: two arguments sit in front of the program (the argv check says so; the bare one is checked offline)
    * not a conformance claim
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

import mec_app_deploy as mad
from conftest import (EDGE_A, EDGE_B, ESTIMED, IN_CSE, MEC011, MEC_VENV_PY, REPO, TY_ACP, TY_AE, TY_CIN, TY_CNT,
                      TY_CSR, TY_SUB, _port_open, http, req, rsc)
from test_tr0086_mec_app_deploy import _instance, _opoccs

PKG = ESTIMED / "apps" / "mec_ipe"
MEC010 = "http://127.0.0.1:8092"
MEC011_ROOT = MEC011.rsplit("/mec_app_support", 1)[0]
SERVICES = MEC011_ROOT + "/mec_service_mgmt/v1"
MEC013 = "http://127.0.0.1:8101/location/v3"
IN_BASE = f"{IN_CSE[0]}/{IN_CSE[1]}"
MNS = (EDGE_A, EDGE_B)

# What the shipped package is expected to say and do, by hand.
APP_NAME, APP_VERSION = "estimed-mec-ipe", "0.1.0"
ORIGIN, RN, API = "Cmec-ipe", "mec-ipe", "Nestimed.mec-ipe"
IPE = f"{IN_BASE}/{RN}"
OPERATOR = "Cin-ops"                       # non-admin: ACME's CAdmin bypasses every ACP
UE = "acr:10.0.0.4"                        # one of the MEC 013 candidate's fixed users
ALL, CREATE, RETRIEVE = 63, 1, 2
DESCRIPTOR = {
    "appDVersion": "1",
    "appName": APP_NAME,
    "appProvider": "ESTIMED lab",
    "appSoftVersion": APP_VERSION,
    "entryPoint": {"runtime": "python3", "file": "mec_ipe_app.py",
                   "args": ["--instance", "{instance}", "--mec013", MEC013, "--operator", OPERATOR]},
    "mecServicesRequired": [{"serName": "mec_app_support", "version": "v2"},
                            {"serName": "mec_service_mgmt", "version": "v1"}],
    "onem2m": {"mnCse": "cse-in", "api": API, "originator": ORIGIN, "rn": RN,
               "acp": {"rn": "operator", "readers": []}, "container": "location-requests"},
}
PACKAGE_FILES = ("handover.py", "mec_ipe.py", "mec_ipe_app.py")
NOT_HERE = ("cse-mn-a", "cse-mn-b", ":8201", ":8202")      # what would name an MN-CSE (a secondary, text-only check)
CSE_PORTS = {8200, 8201, 8202}                             # the IN, MN-A, MN-B: the workload connects to none itself
MEC013_AT = ("127.0.0.1", 8101)

# Test-only. The agent's python3 runtime gets this script and a log path put in front of the program, so the
# workload runs inside it: it logs, from inside that process, the addresses the program connects or sends to through
# Python's socket module, subprocess / posix_spawn starts and ctypes loads (limits in the module text), then runs the
# program as __main__ in the same process.
RECORDER = '''\
"""Test-only (test_tr0086_option_a.py): log what the program connects to, then run the program in this process."""
import os
import runpy
import sys

_fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
_PID = os.getpid()
_ADDRESS = {"socket.connect", "socket.sendto", "socket.sendmsg"}
_OTHER = {"subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn", "os.system", "os.fork", "os.forkpty",
          "ctypes.dlopen"}


def _hook(event, args):
    if event in _ADDRESS:
        os.write(_fd, (repr((_PID, event, args[1])) + "\\n").encode())
    elif event in _OTHER:
        os.write(_fd, (repr((_PID, event, repr(args[:1]))) + "\\n").encode())


sys.addaudithook(_hook)
sys.argv = sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


# ------------------------------------------------------------------------------------------ helpers
def _sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _wait(pred, timeout=10.0, step=0.05) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return bool(pred())


def _workloads(workdir) -> list[int]:
    """pids of live processes with an argument under `workdir` (the agent's package store and instance folders)."""
    found = []
    for p in Path("/proc").glob("[0-9]*"):
        try:
            args = (p / "cmdline").read_bytes().decode(errors="replace").split("\0")
        except OSError:
            continue
        if any(a.startswith(f"{workdir}/") for a in args):
            found.append(int(p.name))
    return sorted(found)


def _listening_ports(pid: int) -> set[int]:
    """TCP ports process `pid` itself listens on: its socket fds matched against the kernel's table."""
    inodes = set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        with contextlib.suppress(OSError):
            link = os.readlink(fd)
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
    ports = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        f = line.split()
        if f[3] == "0A" and f[9] in inodes:                 # 0A = LISTEN
            ports.add(int(f[1].rsplit(":", 1)[1], 16))
    return ports


def _answers(url: str) -> bool:
    """Does anything accept a connection at url's host:port?"""
    host, _, port = url.split("://", 1)[1].split("/", 1)[0].rpartition(":")
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex((host, int(port))) == 0


def _ipe_ae() -> dict | None:
    st, body, _ = req("GET", IPE, "CAdmin")
    return body["m2m:ae"] if st == 200 else None


def _tree(edge) -> list[str]:
    st, body, _ = req("GET", f"{edge[0]}/{edge[1]}?fu=1", "CAdmin")
    assert st == 200, (edge, st, body)
    return sorted(body["m2m:uril"])


def _ipes(edge) -> list[str]:
    st, body, _ = req("GET", f"{edge[0]}/{edge[1]}?fu=1&ty={TY_AE}&lbl=role:mec-ipe", "CAdmin")
    assert st == 200, (edge, st, body)
    return body["m2m:uril"]


def _listed(lcm_iid: str) -> list[dict]:
    """The services MEC 011 lists for the instance (it lists services of confirmed-ready instances only)."""
    st, body = http("GET", f"{SERVICES}/services")
    assert st == 200
    return [s for s in body if (s.get("transportInfo") or {}).get("id") == lcm_iid]


def _registered(mec_iid: str) -> bool:
    """Whether MEC 011 still holds the app instance (a read with no side effect)."""
    st, _ = http("GET", f"{MEC011}/applications/{mec_iid}/dns_rules")
    assert st in (200, 404)
    return st == 200


def _mec_ids(tap) -> list[str]:
    """appInstanceIds MEC 011 handed out through this relay, in order."""
    return [r["reply"]["appInstanceId"] for r in tap.seen
            if r["method"] == "POST" and r["path"].endswith("/registrations") and r["status"] == 201]


def _occ(oid: str) -> tuple[str, str, str] | None:
    """The operation occurrence `oid` as the 010-2 candidate holds it: (lcmOperation, operationState, appInstanceId);
    None if it holds none by that id."""
    st, body = http("GET", f"{MEC010}/app_lcm/v1/app_lcm_op_occs/{oid}")
    return (body["lcmOperation"], body["operationState"], body["appInstanceId"]) if st == 200 else None


def _connects(log: Path) -> list[tuple]:
    """(pid, event, address) the recorder logged for the workloads of one platform, in order; [] if none ran."""
    if not log.exists():
        return []
    return [ast.literal_eval(line) for line in log.read_text().splitlines()]


def _port(url: str) -> int:
    return int(url.split("://", 1)[1].split("/", 1)[0].rpartition(":")[2])


def _to_cse_ports(recs) -> list:
    return sorted({a for _, _, a in recs if isinstance(a, tuple) and len(a) >= 2 and a[1] in CSE_PORTS})


def _ty(rec) -> int | None:
    ct = rec["headers"].get("content-type", "")
    return int(ct.split("ty=", 1)[1]) if "ty=" in ct else None


def _json(raw: bytes):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


class _Relay(BaseHTTPRequestHandler):
    def _relay(self):
        tap = self.server.tap
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        rec = {"method": self.command, "path": self.path, "body": _json(raw), "status": None, "rsc": None,
               "headers": {k.lower(): v for k, v in self.headers.items()}, "t_in": time.monotonic()}
        tap.seen.append(rec)
        fwd = urllib.request.Request(tap.upstream + self.path, data=raw or None, method=self.command, headers={
            k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")})
        try:
            with urllib.request.urlopen(fwd, timeout=10) as r:
                status, hdrs, out = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, hdrs, out = e.code, e.headers, e.read()
        rec.update(status=status, rsc=rsc(dict(hdrs)), reply=_json(out), t_out=time.monotonic())
        try:
            self.send_response(status)
            for k, v in hdrs.items():
                if k.lower() not in ("transfer-encoding", "connection", "content-length", "date", "server"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        except OSError:
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _relay

    def log_message(self, *a):
        pass


class _Tap:
    """A recording relay in front of `upstream`."""

    def __init__(self, upstream: str):
        self.upstream, self.seen = upstream, []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Relay)
        self.srv.daemon_threads = True
        self.srv.tap = self
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


# ------------------------------------------------------------------------------------------ fixtures
_SEEN: list[dict] = []          # every request the IN relays of this module took, for the last test
_CONNECTS: list[tuple] = []     # every line the recorder logged for this module's workloads, for the last test


@pytest.fixture(scope="session")
def mec010():
    """The MEC 010-2 candidate on :8092. Reused if that is what answers there, otherwise started for the session."""
    proc = None
    if _port_open("127.0.0.1", 8092):
        st, body = http("GET", f"{MEC010}/")
        if st != 200 or "app_lcm" not in (body or {}).get("apis", []):
            pytest.fail(f":8092 is held by something that is not the MEC 010-2 candidate (GET / -> {st})",
                        pytrace=False)
    else:
        proc = subprocess.Popen([MEC_VENV_PY, str(REPO / "mec010p2" / "candidate.py")], cwd=str(REPO),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        if not _wait(lambda: _port_open("127.0.0.1", 8092), timeout=10, step=0.2):
            proc.kill()
            pytest.fail("MEC 010-2 candidate did not come up on :8092", pytrace=False)
    yield MEC010
    if proc is not None:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture(scope="session")
def mec013():
    st, body = http("GET", f"{MEC013}/queries/users?address={UE}")
    if st != 200 or not (body or {}).get("user"):
        pytest.fail(f"MEC 013 candidate not answering for {UE} on :8101 (mec013_look/candidate.py): {st}",
                    pytrace=False)
    return MEC013


@pytest.fixture(scope="module")
def mn_trees(topology):
    """MN-A's and MN-B's whole trees before the first deployment of this module."""
    return {edge[1]: _tree(edge) for edge in MNS}


@contextlib.contextmanager
def _platform(workdir: Path):
    """An agent that knows one CSE, the IN, reached through a relay, and MEC 011 through another; every workload it
    starts runs under the test's connect recorder (RECORDER). Afterwards everything the agent started is stopped, and
    it is an error if a workload or the IPE's <AE> was still there."""
    ae = _ipe_ae()
    if ae is not None:                         # a stale AE of a crashed run is removed; a live IPE is not ours to take
        if any(_answers(u) for u in ae.get("poa", [])):
            pytest.fail(f"a live MEC-IPE already holds {IPE} (poa {ae['poa']}); stop it first", pytrace=False)
        req("DELETE", IPE, "CAdmin")
    recorder, connects = workdir / "connect_recorder.py", workdir / "connects.log"
    recorder.write_text(RECORDER)
    cse, mec = _Tap(IN_CSE[0]), _Tap(MEC011_ROOT)
    agent = mad.PlatformAgent(mec010=MEC010, mec011=mec.url, cses={IN_CSE[1]: f"{cse.url}/{IN_CSE[1]}"},
                              workdir=workdir, grace=5.0)
    runtime = mad.RUNTIMES["python3"]
    mad.RUNTIMES["python3"] = [*runtime, str(recorder), str(connects)]          # test-only, undone below
    try:
        yield SimpleNamespace(agent=agent, cse=cse, mec=mec, workdir=workdir, recorder=recorder, connects=connects)
    finally:
        agent.close()
        mad.RUNTIMES["python3"] = runtime
        cse.close()
        mec.close()
        _SEEN.extend(cse.seen)
        _CONNECTS.extend(_connects(connects))
        left, stale = _workloads(workdir), _ipe_ae()
        for pid in left:
            os.kill(pid, signal.SIGKILL)
        req("DELETE", IPE, "CAdmin")
        assert (left, stale) == ([], None), f"left after the agent closed: processes {left}, IPE AE {stale}"


@pytest.fixture
def platform(mn_trees, mec011, mec010, mec013, tmp_path):
    with _platform(tmp_path) as p:
        yield p


@pytest.fixture(scope="class")
def dep(mn_trees, mec011, mec010, mec013, tmp_path_factory):
    """The shipped package taken through the whole path once: onboard, create the instance, instantiate."""
    with _platform(tmp_path_factory.mktemp("opt-a")) as p:
        pkg = p.agent.onboard(PKG)
        iid = p.agent.create_instance(pkg["appDId"], "mec-ipe")
        before = {"instance": _instance(iid)["instantiationState"], "occurrences": _opoccs(iid),
                  "workloads": _workloads(p.workdir), "ipe": _ipe_ae()}
        run = p.agent.instantiate(iid)
        yield SimpleNamespace(p=p, pkg=pkg, iid=iid, before=before, run=run, workdir=p.workdir)


@pytest.fixture
def devices(topology):
    """Device AEs registered at the IN, each with a `location` container that lets the IPE create contentInstances
    and read the container itself (the IPE reads it to check that it belongs to the requesting device)."""
    made = []

    def make(prefix="tr86a"):
        name = f"{prefix}-{uuid.uuid4().hex[:8]}"
        origin = f"C{name}"
        made.append((name, origin))
        assert req("POST", IN_BASE, origin, ty=TY_AE, body={"m2m:ae": {
            "rn": name, "api": "Nestimed.vehicle", "rr": True, "srv": ["4"]}})[0] == 201
        st, body, _ = req("POST", f"{IN_BASE}/{name}", origin, ty=TY_ACP, body={"m2m:acp": {
            "rn": "ipe-writes",
            "pv": {"acr": [{"acor": [origin], "acop": ALL},
                           {"acor": [ORIGIN], "acop": CREATE, "acod": [{"chty": [TY_CIN]}]},
                           {"acor": [ORIGIN], "acop": RETRIEVE}]},
            "pvs": {"acr": [{"acor": [origin], "acop": ALL}]}}})
        assert st == 201, body
        assert req("POST", f"{IN_BASE}/{name}", origin, ty=TY_CNT, body={"m2m:cnt": {
            "rn": "location", "acpi": [body["m2m:acp"]["ri"]]}})[0] == 201
        return SimpleNamespace(name=name, origin=origin, target=f"{IN_CSE[1]}/{name}/location")

    yield make
    for name, origin in made:
        req("DELETE", f"{IN_BASE}/{name}", origin)
        req("DELETE", f"{IN_BASE}/{name}", "CAdmin")


def _register_ue(ae_id, ue, origin=OPERATOR):
    return req("POST", f"{IPE}/ue-registry", origin, ty=TY_CIN, body={"m2m:cin": {
        "con": json.dumps({"aeId": ae_id, "ueIdentity": ue})}})


def _device_request(origin, ae_id, target, period=1, count=2):
    return req("POST", f"{IPE}/location-requests", origin, ty=TY_CIN, body={"m2m:cin": {
        "cr": None, "con": json.dumps({"aeId": ae_id, "targetContainer": target,
                                       "notificationPeriod": period, "count": count})}})


def _cni(dev) -> int | None:
    st, body, _ = req("GET", f"{IN_CSE[0]}/{dev.target}", dev.origin)
    return body["m2m:cnt"]["cni"] if st == 200 else None


def _reports(dev, want, timeout=8.0) -> int | None:
    _wait(lambda: (_cni(dev) or 0) >= want, timeout=timeout, step=0.2)
    return _cni(dev)


def _from_ipe(seen) -> list[dict]:
    """The relay's records of requests the IPE sent (the tests send some through the relay themselves)."""
    return [r for r in seen if r["headers"].get("x-m2m-origin") == ORIGIN]


def _ipe_writes_into(tap, dev) -> list[tuple[str, int]]:
    return [(r["headers"].get("x-m2m-origin"), r["status"]) for r in tap.seen
            if r["method"] == "POST" and r["path"] == f"/{dev.target}" and _ty(r) == TY_CIN]


def _mec013_truth(ue):
    st, body = http("GET", f"{MEC013}/queries/users?address={ue}")
    assert st == 200
    return body["user"][0]


# ------------------------------------------------------------------------------------------ no running instance
def test_option_a_control_no_running_instance_nothing_is_written(platform, devices):
    """Without a running IPE the same requests the tests below make have nowhere to go: first with nothing onboarded,
    then with the package onboarded and an instance created but not instantiated."""
    p = platform

    def attempt():
        dev = devices()
        st1, _, h1 = _register_ue(dev.origin, UE)
        st2, _, h2 = _device_request(dev.origin, dev.origin, dev.target)
        time.sleep(3.0)                            # three notification periods
        return {"ipes at the IN": _ipes(IN_CSE), "operator": (st1, rsc(h1)), "device": (st2, rsc(h2)),
                "written": _cni(dev)}

    nothing = {"ipes at the IN": [], "operator": (404, 4004), "device": (404, 4004), "written": 0}
    assert attempt() == nothing
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "not-instantiated")
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED" and _workloads(p.workdir) == []
    assert attempt() == nothing
    assert _listed(iid) == [] and p.cse.seen == [] and p.mec.seen == [], "something ran"
    assert _connects(p.connects) == [], "a workload ran under the recorder"


# ------------------------------------------------------------------------------------------ the deployed IPE
class TestOptionA:
    # --- 5.2.3: what the IPE is configured with
    def test_5_2_3_configuration_names_mec011_and_the_in_and_no_mn_cse(self, dep):
        store = f"{dep.workdir}/packages/{dep.pkg['appPkgId']}"
        cfg_path = f"{dep.workdir}/instances/{dep.iid}/instance.json"
        argv = [sys.executable, "-I", "-B", f"{store}/mec_ipe_app.py", "--instance", cfg_path,
                "--mec013", MEC013, "--operator", OPERATOR]
        # what the agent runs, with the test's recorder and its log put in front of the program (test-only; the
        # agent's own command line, without them, is test_pkg_shipped_package_verifies_and_says_...)
        ran = [*argv[:3], str(dep.p.recorder), str(dep.p.connects), *argv[3:]]
        assert dep.run["argv"] == ran
        assert Path(f"/proc/{dep.run['pid']}/cmdline").read_bytes().decode().split("\0")[:-1] == ran
        assert _workloads(dep.workdir) == [dep.run["pid"]]
        cfg = json.loads(Path(cfg_path).read_text())
        # the MEC 011 endpoint and the IN-CSE, each through its relay; the relay on Mca leads to the IN
        assert cfg == {"lcmInstanceId": dep.iid, "mec011": dep.p.mec.url, "cse": f"{dep.p.cse.url}/{IN_CSE[1]}"}
        assert (dep.p.cse.upstream, dep.p.mec.upstream) == (IN_CSE[0], MEC011_ROOT)
        assert dep.p.agent.cses == {IN_CSE[1]: cfg["cse"]}, "the platform knows a CSE other than the IN"
        desc = json.loads(Path(store, "appd.json").read_text())
        assert (desc["onem2m"]["mnCse"], desc["onem2m"]["api"], desc["onem2m"]["originator"]) == (IN_CSE[1], API, ORIGIN)
        # secondary, text only (see test_pkg_app_and_descriptor_name_no_mn_cse); the connect record is what holds
        for what, text in (("instance.json", json.dumps(cfg)), ("argv", json.dumps(argv)),
                           ("appd.json", json.dumps(desc))):
            assert [m for m in NOT_HERE if m in text] == [], what

    # --- MEC 010-2: the lifecycle as the candidate holds it, not as the agent tells it
    def test_mec010_candidate_holds_the_instance_instantiated_while_it_runs(self, dep):
        inst = _instance(dep.iid)
        assert (inst["instantiationState"], inst["appDId"]) == ("INSTANTIATED", dep.pkg["appDId"])
        # the occurrence the agent named is the candidate's INSTATIATE (ETSI's schema spelling) of this instance,
        # and its only one; it stays PROCESSING there, as the candidate has no route that completes one
        assert _opoccs(dep.iid) == [("INSTATIATE", "PROCESSING")]
        assert _occ(dep.run["opOcc"]) == ("INSTATIATE", "PROCESSING", dep.iid)
        # control: none of it before the instantiate call
        assert dep.before == {"instance": "NOT_INSTANTIATED", "occurrences": [], "workloads": [], "ipe": None}
        # the agent's own record, not the candidate's: COMPLETED once MEC 011 listed the app as ready
        assert dep.p.agent.results == {dep.run["opOcc"]: "COMPLETED"}

    # --- 5.2.4 step 1: the IN-CSE
    def test_5_2_4_step1_in_cse_reachable_and_is_what_the_ipe_reaches(self, dep):
        st, body, h = req("GET", IN_BASE, "CAdmin")
        assert (st, rsc(h)) == (200, 2000) and (body["m2m:cb"]["cst"], body["m2m:cb"]["ri"]) == (1, "id-in")
        # through the IPE's own CSE address: the same IN (cst 1 = an IN-CSE, an MN-CSE says 2)
        st, body, h = req("GET", f"{dep.p.cse.url}/{IN_CSE[1]}", "CAdmin")
        assert (st, rsc(h)) == (200, 2000) and (body["m2m:cb"]["cst"], body["m2m:cb"]["csi"]) == (1, "/id-in")

    # --- 5.2.4 step 2: MEC 011
    def test_5_2_4_step2_mec011_reachable(self, dep):
        st, body = http("GET", f"{MEC011}/timing/current_time")
        assert st == 200 and isinstance(body["seconds"], int)
        st, body = http("GET", f"{SERVICES}/services")
        assert st == 200 and isinstance(body, list)

    # --- 5.2.4 steps 3 and 4, option A: an <AE> at the IN, no MN-CSE
    def test_5_2_4_step3_ipe_is_an_ae_under_the_in_with_the_workload_as_its_poa(self, dep):
        ae = _ipe_ae()
        assert ae is not None, "no MEC-IPE <AE> at the IN"
        assert (ae["ty"], ae["pi"], ae["rn"], ae["aei"], ae["ri"], ae["api"]) == (TY_AE, "id-in", RN, ORIGIN, ORIGIN, API)
        assert len(ae["poa"]) == 1
        host, _, port = ae["poa"][0].rpartition(":")
        assert host == "http://127.0.0.1" and int(port) in _listening_ports(dep.run["pid"]), \
            f"the poa {ae['poa']} is not a socket of the deployed workload"
        assert _answers(ae["poa"][0])
        # one IPE in the lab, and it is at the IN
        assert (_ipes(IN_CSE), _ipes(EDGE_A), _ipes(EDGE_B)) == ([f"{IN_CSE[1]}/{RN}"], [], [])
        # an AE over Mca, not a CSE over Mcc: the IN's <remoteCSE>s are still exactly the two MNs of the lab
        st, body, _ = req("GET", f"{IN_BASE}?fu=1&ty={TY_CSR}", "CAdmin")
        assert st == 200 and sorted(body["m2m:uril"]) == [f"{IN_CSE[1]}/id-mn-a", f"{IN_CSE[1]}/id-mn-b"]

    def test_5_2_4_step3_ipe_tree_at_the_in(self, dep):
        def kids(ty):
            st, body, _ = req("GET", f"{IPE}?fu=1&ty={ty}", "CAdmin")
            assert st == 200
            return sorted(body["m2m:uril"])
        root = f"{IN_CSE[1]}/{RN}"
        assert kids(TY_ACP) == [f"{root}/operator", f"{root}/requesters"]
        assert kids(TY_CNT) == [f"{root}/location", f"{root}/location-requests", f"{root}/ue-registry"]
        assert kids(TY_SUB) == [f"{root}/location-requests/ipe", f"{root}/location/ipe"]
        # the operator the descriptor names, and only it, may write the registry and the operator requests
        acps = {rn: req("GET", f"{IPE}/{rn}", "CAdmin")[1]["m2m:acp"] for rn in ("operator", "requesters")}
        assert acps["operator"]["pv"] == {"acr": [{"acor": [ORIGIN], "acop": ALL},
                                                  {"acor": [OPERATOR], "acop": CREATE, "acod": [{"chty": [TY_CIN]}]}]}
        assert acps["requesters"]["pv"] == {"acr": [{"acor": [ORIGIN], "acop": ALL},
                                                    {"acor": ["all"], "acop": CREATE, "acod": [{"chty": [TY_CIN]}]}]}
        for rn, acp in (("ue-registry", "operator"), ("location", "operator"), ("location-requests", "requesters")):
            assert req("GET", f"{IPE}/{rn}", "CAdmin")[1]["m2m:cnt"]["acpi"] == [acps[acp]["ri"]], rn
        poa = _ipe_ae()["poa"][0]
        for rn in ("location", "location-requests"):
            assert req("GET", f"{IPE}/{rn}/ipe", "CAdmin")[1]["m2m:sub"]["nu"] == [f"{poa}/notify"], rn

    def test_5_2_4_step4_mec011_registration_confirmed_after_the_in_registration(self, dep):
        mids = _mec_ids(dep.p.mec)
        assert len(mids) == 1 and dep.run["mec011AppInstanceId"] == mids[0]
        listed = _listed(dep.iid)
        assert len(listed) == 1
        s = listed[0]
        assert (s["serName"], s["version"], s["state"]) == (APP_NAME, APP_VERSION, "ACTIVE")
        assert f"/applications/{mids[0]}/services/" in s["_links"]["self"]["href"]
        assert s["transportInfo"]["endpoint"] == {"uris": [f"{dep.p.cse.url}/{IN_CSE[1]}/{RN}"]}
        # the <AE> names both instance identifiers (the two candidates do not share one)
        assert sorted(_ipe_ae()["lbl"]) == sorted(["role:mec-ipe", "mec:service:location",
                                                   f"mec:appInstanceId:{mids[0]}", f"mec:lcmInstanceId:{dep.iid}"])
        # on Mp1: registered, offered its service, confirmed ready
        posts = [(r["path"].rsplit("/", 1)[-1], r["status"]) for r in dep.p.mec.seen if r["method"] == "POST"]
        assert posts == [("registrations", 201), ("services", 201), ("confirm_ready", 204)]
        # ... and only once every write of its start had been answered by the IN, in this order
        confirmed = [r["t_in"] for r in dep.p.mec.seen if r["path"].endswith("/confirm_ready")][0]
        before = [r for r in dep.p.cse.seen if r["method"] != "GET" and r["t_in"] < confirmed]
        p = f"/{IN_CSE[1]}/{RN}"
        assert [(r["method"], r["path"], _ty(r), r["status"]) for r in before] == [
            ("DELETE", p, None, 404),                                    # mec_ipe: a stale AE would go first
            ("POST", f"/{IN_CSE[1]}", TY_AE, 201),
            ("POST", p, TY_ACP, 201), ("POST", p, TY_ACP, 201),
            ("POST", p, TY_CNT, 201), ("POST", p, TY_CNT, 201), ("POST", p, TY_CNT, 201),
            ("POST", f"{p}/location", TY_SUB, 201), ("POST", f"{p}/location-requests", TY_SUB, 201),
            ("PUT", p, None, 200)]                                        # the instance labels
        assert {r["headers"]["x-m2m-origin"] for r in before} == {ORIGIN}
        assert confirmed > max(r["t_out"] for r in before)

    # --- 5.6.4 through the IN
    def test_5_6_4_device_on_the_in_receives_its_network_location_from_the_ipe(self, dep, devices):
        dev = devices()
        st, _, h = _register_ue(dev.origin, UE)
        assert (st, rsc(h)) == (201, 2001)
        st, _, h = _device_request(dev.origin, dev.origin, dev.target)
        assert (st, rsc(h)) == (201, 2001)
        assert _reports(dev, 2) == 2
        # on the wire: two Creates into the device's container, from the IPE, through its relay to the IN
        assert _wait(lambda: _ipe_writes_into(dep.p.cse, dev) == [(ORIGIN, 201)] * 2, timeout=3), \
            _ipe_writes_into(dep.p.cse, dev)
        st, body, _ = req("GET", f"{IN_CSE[0]}/{dev.target}/la", dev.origin)
        assert st == 200
        fix = json.loads(body["m2m:cin"]["con"])
        truth = _mec013_truth(UE)                                      # MEC 013 read independently
        assert (fix["source"], fix["ueIdentity"]) == ("MEC013", UE)
        assert (fix["zoneId"], fix["accessPointId"], fix["lat"], fix["lon"]) == (
            truth["zoneId"], truth["accessPointId"], truth["locationInfo"]["latitude"],
            truth["locationInfo"]["longitude"])
        time.sleep(1.5)
        assert _cni(dev) == 2, "more reports than the request's count"

    def test_5_6_4_control_request_into_another_devices_container_is_refused_on_the_in(self, dep, devices):
        victim, attacker = devices("tr86a-vic"), devices("tr86a-att")
        assert _register_ue(attacker.origin, UE)[0] == 201
        assert _device_request(attacker.origin, attacker.origin, victim.target)[0] == 201
        # the IPE did look -- it read the victim's container (its ownership check) -- and wrote nothing there
        assert _wait(lambda: any(r["method"] == "GET" and r["path"] == f"/{victim.target}" for r in dep.p.cse.seen),
                     timeout=5), "the IPE never examined the target"
        time.sleep(2.5)
        assert (_cni(victim), _ipe_writes_into(dep.p.cse, victim)) == (0, [])
        # beside it: the same requester is served into its own container
        assert _device_request(attacker.origin, attacker.origin, attacker.target)[0] == 201
        assert _reports(attacker, 2) == 2
        assert (_cni(victim), _ipe_writes_into(dep.p.cse, victim)) == (0, [])

    def test_5_6_4_control_device_without_a_ue_registry_entry_gets_nothing(self, dep, devices):
        """The wrapper adds nothing to what the IPE does: a device the operator has not registered asks for its own
        location in its own container, and nothing is written; once registered, the same request is served."""
        dev = devices("tr86a-unreg")
        t0 = time.monotonic()
        assert _device_request(dev.origin, dev.origin, dev.target)[0] == 201

        def looked_up() -> bool:              # the IPE took the request: the ownership read, then the registry read
            paths = [r["path"].split("?")[0] for r in _from_ipe(dep.p.cse.seen) if r["method"] == "GET"
                     and r["t_in"] > t0]
            return f"/{dev.target}" in paths and \
                f"/{IN_CSE[1]}/{RN}/ue-registry" in paths[paths.index(f"/{dev.target}"):]
        assert _wait(looked_up, timeout=5), "the IPE never looked the device up"
        time.sleep(2.5)                                                # more than two notification periods
        assert (_cni(dev), _ipe_writes_into(dep.p.cse, dev)) == (0, [])
        # beside it: registered by the operator, the same request into the same container is served
        assert _register_ue(dev.origin, UE)[0] == 201
        assert _device_request(dev.origin, dev.origin, dev.target)[0] == 201
        assert _reports(dev, 2) == 2
        assert _ipe_writes_into(dep.p.cse, dev) == [(ORIGIN, 201)] * 2

    def test_5_6_4_control_only_the_operator_writes_the_ue_registry(self, dep, devices):
        dev = devices()
        st, _, h = _register_ue(dev.origin, "acr:10.0.0.1", origin=dev.origin)
        assert (st, rsc(h)) == (403, 4103)
        st, _, h = _register_ue(dev.origin, "acr:10.0.0.1")            # beside it: the operator the descriptor names
        assert (st, rsc(h)) == (201, 2001)

    def test_option_a_control_nothing_reaches_the_mn_cses_while_it_runs(self, dep, mn_trees):
        assert {edge[1]: _tree(edge) for edge in MNS} == mn_trees
        assert _from_ipe(dep.p.cse.seen), "the relay saw nothing from the IPE"
        assert {r["path"].split("?")[0].split("/")[1] for r in dep.p.cse.seen} == {IN_CSE[1]}
        # from inside the workload's process: it connected to no CSE port itself, MN or IN
        assert {_port(e[0]) for e in (IN_CSE, EDGE_A, EDGE_B)} == CSE_PORTS
        recs = _connects(dep.p.connects)
        assert {pid for pid, _, _ in recs} == {dep.run["pid"]}, "the log is not the workload's"
        assert [r for r in recs if r[1] != "socket.connect"] == [], "a datagram, a process start or a library load"
        assert _to_cse_ports(recs) == [], "the workload connected to a CSE itself, not through the relay"
        # control: the recorder sees the workload's traffic -- both relays, and MEC 013 once a device is served
        to, relays = {a for _, _, a in recs}, {("127.0.0.1", _port(dep.p.cse.url)), ("127.0.0.1", _port(dep.p.mec.url))}
        assert relays <= to <= relays | {MEC013_AT}, to


# ------------------------------------------------------------------------------------------ terminate
def test_option_a_terminate_through_010_2_stops_the_ipe_and_removes_its_ae(platform, devices):
    p = platform
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "terminated")
    run = p.agent.instantiate(iid)
    pid, mid = run["pid"], run["mec011AppInstanceId"]
    poa = _ipe_ae()["poa"][0]
    # beside the control: all of it is there while the instance runs, with a report stream going
    assert _workloads(p.workdir) == [pid] and _answers(poa) and _registered(mid) and len(_listed(iid)) == 1
    assert _instance(iid)["instantiationState"] == "INSTANTIATED" and _opoccs(iid) == [("INSTATIATE", "PROCESSING")]
    dev = devices()
    assert _register_ue(dev.origin, UE)[0] == 201
    assert _device_request(dev.origin, dev.origin, dev.target, period=1, count=0)[0] == 201
    assert _reports(dev, 1) >= 1
    done = p.agent.terminate(iid)
    assert (done["exitCode"], done["forced"]) == (0, False)              # the agent's account; the process next
    assert not Path(f"/proc/{pid}").exists() and _workloads(p.workdir) == []
    # removed, and nothing answers at its poa either
    assert _ipe_ae() is None, "the IPE's <AE> is still at the IN"
    assert not _answers(poa)
    deletes = [(r["path"], r["headers"]["x-m2m-origin"], r["rsc"]) for r in p.cse.seen if r["method"] == "DELETE"]
    assert deletes == [(f"/{IN_CSE[1]}/{RN}", ORIGIN, 4004), (f"/{IN_CSE[1]}/{RN}", ORIGIN, 2002)]
    # MEC 011: the app said goodbye and left, in this order
    assert _listed(iid) == [] and not _registered(mid), "MEC 011 still holds the instance"
    ser = [r["reply"]["serInstanceId"] for r in p.mec.seen if r["method"] == "POST" and r["path"].endswith("/services")]
    tail = [(r["method"], r["path"].rsplit("/", 1)[-1], r["status"]) for r in p.mec.seen if r["method"] != "GET"][3:]
    assert tail == [("POST", "confirm_termination", 204), ("DELETE", ser[0], 204), ("DELETE", mid, 204)]
    # the stream stopped with it, and a new request has nowhere to go
    settled = _cni(dev)
    time.sleep(2.5)
    assert _cni(dev) == settled, "reports continued after the termination"
    st, _, h = _device_request(dev.origin, dev.origin, dev.target)
    assert (st, rsc(h)) == (404, 4004)
    # MEC 010-2 as the candidate holds it: not instantiated, and the occurrence the agent named is this instance's
    # TERMINATE -- PROCESSING, where every success stays (the candidate has no route that completes one)
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED"
    assert _opoccs(iid) == [("INSTATIATE", "PROCESSING"), ("TERMINATE", "PROCESSING")]
    assert _occ(done["opOcc"]) == ("TERMINATE", "PROCESSING", iid)
    # the agent's own record, not the candidate's
    assert p.agent.results[done["opOcc"]] == "COMPLETED"
    p.agent.delete_instance(iid)
    p.agent.offboard(pkg["appPkgId"])
    assert http("GET", f"{MEC010}/app_lcm/v1/app_instances/{iid}")[0] == 404


def test_option_a_control_a_killed_ipe_leaves_its_ae_with_a_poa_that_does_not_answer(platform):
    """The other way out, stated plainly: a killed IPE (a crash, or the agent's SIGKILL after the grace period) cannot
    remove its <AE>. The IN keeps it, with a poa nothing answers; the agent has no oneM2M identity to remove it. The
    next instance replaces such a stale <AE> (mec_ipe.py's rule), and its graceful stop removes it."""
    p = platform
    pkg = p.agent.onboard(PKG)
    first = p.agent.create_instance(pkg["appDId"], "killed")
    run = p.agent.instantiate(first)
    before = _ipe_ae()
    os.kill(run["pid"], signal.SIGKILL)
    assert _wait(lambda: not _answers(before["poa"][0]), timeout=5)
    done = p.agent.terminate(first)
    assert (done["exitCode"], done["forced"]) == (-9, False)                 # the agent's account
    # as the candidate holds it: taken back to NOT_INSTANTIATED, the termination recorded as failed
    assert _instance(first)["instantiationState"] == "NOT_INSTANTIATED"
    assert _opoccs(first) == [("INSTATIATE", "PROCESSING"), ("TERMINATE", "FAILED")]
    assert not _registered(run["mec011AppInstanceId"]), "the agent did not remove the registration the app could not"
    stale = _ipe_ae()
    assert stale is not None and (stale["ri"], stale["poa"]) == (before["ri"], before["poa"])
    assert not _answers(stale["poa"][0])
    # the next instance takes its place
    second = p.agent.create_instance(pkg["appDId"], "after-the-kill")
    p.agent.instantiate(second)
    now = _ipe_ae()
    assert now["poa"] != before["poa"] and _answers(now["poa"][0])
    assert f"mec:lcmInstanceId:{second}" in now["lbl"] and f"mec:lcmInstanceId:{first}" not in now["lbl"]
    assert _instance(second)["instantiationState"] == "INSTANTIATED"
    assert p.agent.terminate(second)["exitCode"] == 0             # the agent's own record of the workload's exit
    assert _ipe_ae() is None
    assert _instance(second)["instantiationState"] == "NOT_INSTANTIATED"
    assert _opoccs(second) == [("INSTATIATE", "PROCESSING"), ("TERMINATE", "PROCESSING")]


def test_option_a_control_second_instance_does_not_evict_the_first(platform):
    p = platform
    pkg = p.agent.onboard(PKG)
    first = p.agent.create_instance(pkg["appDId"], "first")
    run = p.agent.instantiate(first)
    ae_before = _ipe_ae()
    second = p.agent.create_instance(pkg["appDId"], "second")
    t0 = time.monotonic()
    with pytest.raises(mad.DeployError, match="exited with 3 before it was ready"):   # the agent's own message
        p.agent.instantiate(second)
    # the first IPE is untouched: the same <AE> resource, still answering, still registered and listed
    assert _ipe_ae() == ae_before and _answers(ae_before["poa"][0])
    assert [(r["method"], r["path"]) for r in p.cse.seen if r["method"] != "GET" and r["t_in"] > t0] == [], \
        "the refused instance wrote at the IN"
    mids = _mec_ids(p.mec)
    assert len(mids) == 2 and mids[0] == run["mec011AppInstanceId"]
    assert _registered(mids[0]) and len(_listed(first)) == 1
    assert not _registered(mids[1]) and _listed(second) == []
    assert _workloads(p.workdir) == [run["pid"]]
    # as the candidate holds them: the first still instantiated; the second's start failed and was taken back
    assert _instance(first)["instantiationState"] == "INSTANTIATED" and _opoccs(first) == [("INSTATIATE", "PROCESSING")]
    assert _instance(second)["instantiationState"] == "NOT_INSTANTIATED"
    assert _opoccs(second) == [("INSTATIATE", "FAILED"), ("TERMINATE", "PROCESSING")]


# ------------------------------------------------------------------------------------------ last: the MN-CSEs
def test_option_a_nothing_reached_the_mn_cses(mn_trees):
    """After every deployment above was torn down: the MN-CSEs' trees are what they were before the first one, every
    request the IPEs sent went to the IN's CSEBase, and no workload connected to a CSE port itself. (Run alone, this
    test fails: nothing was recorded.)"""
    assert {edge[1]: _tree(edge) for edge in MNS} == mn_trees
    assert _from_ipe(_SEEN), "no IN relay recorded a request of an IPE: the deployments above did not reach the IN"
    assert {r["path"].split("?")[0].split("/")[1] for r in _SEEN} == {IN_CSE[1]}
    assert _CONNECTS, "the recorder logged nothing: no workload ran under it"
    assert [r for r in _CONNECTS if r[1] != "socket.connect"] == [], "a datagram, a process start or a library load"
    assert _to_cse_ports(_CONNECTS) == [], "a workload connected to a CSE itself"
    assert {a[0] for _, _, a in _CONNECTS} == {"127.0.0.1"}


# ------------------------------------------------------------------------------------------ offline: the package
# No CSE, no MEC candidate, no network below this line.
def test_pkg_shipped_package_verifies_and_says_what_the_live_tests_expect():
    assert sorted(x.name for x in PKG.iterdir()) == ["appd.json", *PACKAGE_FILES]
    d = mad.verify_package(PKG)
    assert d.pop("files") == {n: _sha(PKG / n) for n in PACKAGE_FILES}
    d.pop("appDescription", None)
    assert d == DESCRIPTOR
    assert mad.descriptor_digest(PKG) == _sha(PKG / "appd.json")
    # the agent's own command line for it, without the recorder the live tests put in front of the program
    assert mad.RUNTIMES == {"python3": [sys.executable, "-I", "-B"]}
    assert mad.command(mad.verify_package(PKG), Path("/store"), Path("/inst/instance.json")) == [
        sys.executable, "-I", "-B", "/store/mec_ipe_app.py", "--instance", "/inst/instance.json",
        "--mec013", MEC013, "--operator", OPERATOR]


def test_pkg_carries_the_labs_ipe_byte_for_byte():
    """What runs as the MEC app is the IPE that test_tr0086_location.py tests. A change to either lab file without
    the package's copy fails here; refresh with cp, then `mec_app_deploy.py digests estimed/apps/mec_ipe --write`."""
    assert {n: _sha(PKG / n) for n in ("mec_ipe.py", "handover.py")} == \
        {n: _sha(ESTIMED / n) for n in ("mec_ipe.py", "handover.py")}


def test_pkg_app_uses_the_standard_library_and_its_package_only():
    import ast
    tree = ast.parse((PKG / "mec_ipe_app.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
            {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names - {"__future__", "mec_ipe", "handover"} <= sys.stdlib_module_names


def test_pkg_app_and_descriptor_name_no_mn_cse():
    """Secondary, text only: a name built at run time (say "/".join(mec_ipe.EDGE_A)) passes it. What holds is the
    workload's connect record in the live tests."""
    for name in ("appd.json", "mec_ipe_app.py"):
        text = (PKG / name).read_text()
        assert [m for m in NOT_HERE if m in text] == [], name
    # control: the check sees one where there is one -- handover.py, carried for _req, names both MN-CSEs
    assert [m for m in NOT_HERE if m in (PKG / "handover.py").read_text()] == list(NOT_HERE)
