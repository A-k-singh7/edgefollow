"""TD_MEC_REG_03 (test plan 7.2.3.1): deploy a new oneM2M AE as a MEC application, register it to the MN-CSE and
verify the resource tree -- against the live lab, plus offline checks of the package verifier at the end.

What "MEC platform" means here, plainly: two candidate servers and one program on this host.

    mec010p2/candidate.py           :8092  GS MEC 010-2 package management and lifecycle API. Keeps state, starts
                                           nothing; started by the fixture below if it is not running.
    mec011_appsupport/candidate.py  :8091  GS MEC 011 application support and service registry (conftest).
    estimed/mec_app_deploy.py              the platform agent: checks the package digests, starts the workload as a
                                           process of this user, stops it.

No container, no sandbox, no isolation. Not a conformance claim.

The package deployed is estimed/apps/sensor_ae as shipped. Between the workload and the lab stand two recording
relays (_Tap), so what the AE sent on Mca and on Mp1 is read off the wire, not taken from the app's own account.

Each positive check has a control beside it. Expected values are written by hand in the constants below; none is
read from the descriptor or from mec_app_deploy.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import shutil
import signal
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
from conftest import EDGE_A, ESTIMED, MEC011, MEC_VENV_PY, REPO, _port_open, http, req, rsc

PKG = ESTIMED / "apps" / "sensor_ae"
MEC010 = "http://127.0.0.1:8092"
MEC011_ROOT = MEC011.rsplit("/mec_app_support", 1)[0]
SERVICES = MEC011_ROOT + "/mec_service_mgmt/v1"
BASE = f"{EDGE_A[0]}/{EDGE_A[1]}"

# What the shipped package is expected to say and do, by hand.
APP_NAME, APP_VERSION = "estimed-sensor-ae", "0.1.0"
ORIGIN, AE_RN, API = "CestimedSensor", "estimedSensor", "Nestimed.sensor"
ACP_RN, READER, CNT = "sensorAcp", "CestimedSensorReader", "readings"
READING = {"temperature_c": 21.5, "source": "fixed value, no sensor"}
ALL, RETRIEVE = 63, 2                      # accessControlOperations (TS-0004 6.3.4.2.3): all six bits; RETRIEVE
DESCRIPTOR = {
    "appDVersion": "1",
    "appName": APP_NAME,
    "appProvider": "ESTIMED lab",
    "appSoftVersion": APP_VERSION,
    "entryPoint": {"runtime": "python3", "file": "sensor_ae.py", "args": ["--instance", "{instance}"]},
    "mecServicesRequired": [{"serName": "mec_app_support", "version": "v2"},
                            {"serName": "mec_service_mgmt", "version": "v1"}],
    "onem2m": {"mnCse": "cse-mn-a", "api": API, "originator": ORIGIN, "rn": AE_RN,
               "acp": {"rn": ACP_RN, "readers": [READER]}, "container": CNT},
}


# ------------------------------------------------------------------------------------------ helpers
def _sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _wait(pred, timeout=10.0, step=0.05) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


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


def _ppid(pid: int) -> int:
    return int(Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[1])


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


def _instance(iid: str) -> dict:
    st, body = http("GET", f"{MEC010}/app_lcm/v1/app_instances/{iid}")
    assert st == 200, (st, body)
    return body


def _package(pid: str) -> dict:
    st, body = http("GET", f"{MEC010}/app_pkgm/v1/onboarded_app_packages/{pid}")
    assert st == 200, (st, body)
    return body


def _opoccs(iid: str) -> list[tuple[str, str]]:
    """(lcmOperation, operationState) of the instance's operation occurrences at the 010-2 candidate, in order."""
    st, body = http("GET", f"{MEC010}/app_lcm/v1/app_lcm_op_occs")
    assert st == 200
    return [(o["lcmOperation"], o["operationState"]) for o in body if o["appInstanceId"] == iid]


def _ae(origin="CAdmin"):
    return req("GET", f"{BASE}/{AE_RN}", origin)


def _tree() -> list[str]:
    """Every resource below the AE, as the CSE's administrator sees it."""
    st, body, _ = req("GET", f"{BASE}/{AE_RN}?fu=1", "CAdmin")
    assert st == 200, (st, body)
    return sorted(body["m2m:uril"])


def _baseline() -> list[str]:
    """The tree the descriptor describes: one <ACP>, one <container>, and the one reading in it."""
    st, body, _ = req("GET", f"{BASE}/{AE_RN}/{CNT}/la", "CAdmin")
    assert st == 200, (st, body)
    root = f"{EDGE_A[1]}/{AE_RN}"
    return sorted([f"{root}/{ACP_RN}", f"{root}/{CNT}", f"{root}/{CNT}/{body['m2m:cin']['rn']}"])


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
        if tap.hold is not None and tap.hold(rec):
            tap.release.wait()
        fwd = urllib.request.Request(tap.upstream + self.path, data=raw or None, method=self.command, headers={
            k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")})
        try:
            with urllib.request.urlopen(fwd, timeout=10) as r:
                status, hdrs, out = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, hdrs, out = e.code, e.headers, e.read()
        rec.update(status=status, rsc=rsc(dict(hdrs)), reply=_json(out), t_out=time.monotonic())
        headers = [(k, v) for k, v in hdrs.items()
                   if k.lower() not in ("transfer-encoding", "connection", "content-length", "date", "server")]
        if tap.mangle is not None:                 # the record above keeps what the upstream really answered
            headers, out = tap.mangle(rec, headers, out)
        try:
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        except OSError:
            pass                                   # the workload was stopped while its request was held

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _relay

    def log_message(self, *a):
        pass


class _Tap:
    """A recording relay in front of `upstream`. `hold` (a predicate on the request record) keeps matching
    requests back until `release` is set: that is how a test stands between the app and its confirm_ready.
    `mangle(record, headers, body) -> (headers, body)` alters what the workload is told, for the controls on
    the app's own checks."""

    def __init__(self, upstream: str):
        self.upstream, self.seen, self.hold, self.release = upstream, [], None, threading.Event()
        self.mangle = None
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Relay)
        self.srv.daemon_threads = True
        self.srv.tap = self
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.release.set()
        self.srv.shutdown()
        self.srv.server_close()


# ------------------------------------------------------------------------------------------ fixtures
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
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait(lambda: _port_open("127.0.0.1", 8092), timeout=10, step=0.2):
            proc.kill()
            pytest.fail("MEC 010-2 candidate did not come up on :8092", pytrace=False)
    yield MEC010
    if proc is not None:
        proc.terminate()
        proc.wait(timeout=10)


@contextlib.contextmanager
def _platform(workdir: Path):
    """An agent that reaches edge A and MEC 011 through two relays. Afterwards everything the agent started is
    stopped, and it is an error if a workload process or the package's AE was still there once the agent closed."""
    req("DELETE", f"{BASE}/{AE_RN}", "CAdmin")              # an earlier crashed run must not decide this one
    cse, mec = _Tap(EDGE_A[0]), _Tap(MEC011_ROOT)
    agent = mad.PlatformAgent(mec010=MEC010, mec011=mec.url, cses={EDGE_A[1]: f"{cse.url}/{EDGE_A[1]}"},
                              workdir=workdir, grace=5.0)
    try:
        yield SimpleNamespace(agent=agent, cse=cse, mec=mec, workdir=workdir)
    finally:
        mec.release.set()
        agent.close()
        cse.close()
        mec.close()
        left, stale = _workloads(workdir), _ae()[0]
        for pid in left:
            os.kill(pid, signal.SIGKILL)
        req("DELETE", f"{BASE}/{AE_RN}", "CAdmin")
        assert (left, stale) == ([], 404), f"left after the agent closed: processes {left}, AE answers {stale}"


@pytest.fixture
def platform(topology, mec011, mec010, tmp_path):
    with _platform(tmp_path) as p:
        yield p


def _deploy(p, name="sensor-ae", **kw):
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], name)
    return pkg, iid, p.agent.instantiate(iid, **kw)


@pytest.fixture(scope="class")
def dep(topology, mec011, mec010, tmp_path_factory):
    """The shipped package taken through the whole path once: onboard, create the instance, instantiate."""
    with _platform(tmp_path_factory.mktemp("reg03")) as p:
        pkg = p.agent.onboard(PKG)
        iid = p.agent.create_instance(pkg["appDId"], "sensor-ae")
        before = {"instance": _instance(iid)["instantiationState"], "usage": _package(pkg["appPkgId"])["usageState"],
                  "workloads": _workloads(p.workdir), "ae": _ae()[0]}
        run = p.agent.instantiate(iid)
        yield SimpleNamespace(p=p, pkg=pkg, iid=iid, before=before, run=run, workdir=p.workdir)


# ------------------------------------------------------------------------------------------ the TD, step by step
class TestDeployedSensorAe:
    # --- step 1: deploy the AE workload as a MEC application on the MEC platform
    def test_td_mec_reg_03_step1_onboarded_and_instantiated_through_the_010_2_api(self, dep):
        pkg = _package(dep.pkg["appPkgId"])
        assert (pkg["appName"], pkg["appSoftwareVersion"]) == (APP_NAME, APP_VERSION)
        # the checksum the candidate holds is the SHA-256 of the descriptor, which carries every file's digest
        assert pkg["checksum"] == {"algorithm": "SHA-256", "hash": _sha(PKG / "appd.json")}
        assert (pkg["operationalState"], pkg["usageState"]) == ("ENABLED", "IN_USE")
        inst = _instance(dep.iid)
        assert (inst["instantiationState"], inst["appDId"]) == ("INSTANTIATED", pkg["appDId"])
        # control: none of that held before the instantiate call
        assert dep.before == {"instance": "NOT_INSTANTIATED", "usage": "NOT_IN_USE", "workloads": [], "ae": 404}
        # The candidate has no route that completes an operation occurrence: a successful one stays PROCESSING
        # there ("INSTATIATE" is the spelling ETSI's schema demands). The agent keeps the result itself.
        assert _opoccs(dep.iid) == [("INSTATIATE", "PROCESSING")]
        assert dep.p.agent.results[dep.run["opOcc"]] == "COMPLETED"

    def test_td_mec_reg_03_step1_control_a_running_instance_and_its_package_cannot_be_removed(self, dep):
        assert http("DELETE", f"{MEC010}/app_lcm/v1/app_instances/{dep.iid}")[0] == 409
        assert http("DELETE", f"{MEC010}/app_pkgm/v1/app_packages/{dep.pkg['appPkgId']}")[0] == 403
        with pytest.raises(mad.DeployError, match="answered 409"):
            dep.p.agent.delete_instance(dep.iid)
        with pytest.raises(mad.DeployError, match="still has instances"):
            dep.p.agent.offboard(dep.pkg["appPkgId"])
        assert _instance(dep.iid)["instantiationState"] == "INSTANTIATED"
        assert _package(dep.pkg["appPkgId"])["operationalState"] == "ENABLED"       # not half taken out either
        assert _workloads(dep.workdir) == [dep.run["pid"]]

    def test_td_mec_reg_03_step1_workload_is_its_own_process_started_from_the_package(self, dep):
        pid = dep.run["pid"]
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().decode().split("\0")[:-1]
        store = f"{dep.workdir}/packages/{dep.pkg['appPkgId']}"
        # runtime and isolation flags from the agent, program and arguments from the package's descriptor
        assert argv == [sys.executable, "-I", "-B", f"{store}/sensor_ae.py",
                        "--instance", f"{dep.workdir}/instances/{dep.iid}/instance.json"]
        assert argv == dep.run["argv"]
        assert pid != os.getpid() and _ppid(pid) == os.getpid()
        assert os.path.realpath(f"/proc/{pid}/exe") == os.path.realpath(sys.executable)
        # what runs is the platform's own copy, byte for byte the shipped program, and nothing else is beside it
        assert _sha(f"{store}/sensor_ae.py") == _sha(PKG / "sensor_ae.py")
        assert sorted(x.name for x in Path(store).iterdir()) == ["appd.json", "sensor_ae.py"]
        assert Path(f"/proc/{pid}/environ").read_bytes() == b"", "the workload inherited the agent's environment"
        assert _workloads(dep.workdir) == [pid]
        assert json.loads(Path(argv[5]).read_text()) == {
            "lcmInstanceId": dep.iid, "mec011": dep.p.mec.url, "cse": f"{dep.p.cse.url}/{EDGE_A[1]}"}

    # --- steps 2 and 3: the AE Create on Mca and its answer
    def test_td_mec_reg_03_step2_3_ae_create_on_the_wire(self, dep):
        creates = [r for r in dep.p.cse.seen
                   if r["method"] == "POST" and "ty=2" in r["headers"].get("content-type", "")]
        assert len(creates) == 1
        c = creates[0]
        # step 2: op = Create, to = the MN-CSEBase name, ty = 2, fr = its own originator, pc carries api
        assert c["path"] == f"/{EDGE_A[1]}"
        assert c["headers"]["x-m2m-origin"] == ORIGIN
        sent = c["body"]["m2m:ae"]
        assert (sent["api"], sent["rn"]) == (API, AE_RN)
        assert "aei" not in sent                    # the TD's "pc with aei" cannot be sent: see the control below
        # step 3: rsc 2001 and the serialized <AE> with the assigned AE-ID, which for a self-declared C-prefixed
        # identity is the originator itself (developer guide 2026-10-29; TS-0001 7.2)
        assert (c["status"], c["rsc"]) == (201, 2001)
        got = c["reply"]["m2m:ae"]
        assert got["aei"] == ORIGIN and got["ri"] == ORIGIN and got["ty"] == 2 and got["api"] == API

    # --- step 4: <AE> present under the MN-CSE with the correct access control policy
    def test_td_mec_reg_03_step4_ae_present_with_least_privilege_acp(self, dep):
        st, body, _ = _ae()
        assert st == 200
        ae = body["m2m:ae"]
        st, cb, _ = req("GET", BASE, "CAdmin")
        assert st == 200 and cb["m2m:cb"]["cst"] == 2
        assert ae["pi"] == cb["m2m:cb"]["ri"] == "id-mn-a"          # directly under the MN-CSE's CSEBase
        assert (ae["ty"], ae["rn"], ae["api"], ae["aei"]) == (2, AE_RN, API, ORIGIN)
        st, body, _ = req("GET", f"{BASE}/{AE_RN}/{ACP_RN}", "CAdmin")
        assert st == 200
        acp = body["m2m:acp"]
        assert ae["acpi"] == [acp["ri"]]
        assert acp["pv"] == {"acr": [{"acor": [ORIGIN], "acop": ALL}, {"acor": [READER], "acop": RETRIEVE}]}
        assert acp["pvs"] == {"acr": [{"acor": [ORIGIN], "acop": ALL}]}
        # the named reader may read the AE and its data
        assert _ae(READER)[0] == 200
        st, body, _ = req("GET", f"{BASE}/{AE_RN}/{CNT}/la", READER)
        assert st == 200 and json.loads(body["m2m:cin"]["con"]) == READING

    def test_td_mec_reg_03_step4_control_stranger_reads_nothing(self, dep):
        stranger = f"Cstranger-{uuid.uuid4().hex[:6]}"
        for path in (AE_RN, f"{AE_RN}/{CNT}", f"{AE_RN}/{CNT}/la", f"{AE_RN}/{ACP_RN}"):
            st, _, h = req("GET", f"{BASE}/{path}", stranger)
            assert (st, rsc(h)) == (403, 4103), path
        st, body, _ = req("GET", f"{BASE}/{AE_RN}?fu=1", stranger)        # discovery shows it nothing either
        assert st == 200 and body == {"m2m:uril": []}

    def test_td_mec_reg_03_step4_control_stranger_and_reader_write_nothing(self, dep):
        before = _tree()
        for who in (f"Cstranger-{uuid.uuid4().hex[:6]}", READER):
            for method, path, ty, body in (
                    ("POST", f"{AE_RN}/{CNT}", 4, {"m2m:cin": {"con": "forged"}}),
                    ("POST", AE_RN, 3, {"m2m:cnt": {"rn": "planted"}}),
                    ("PUT", f"{AE_RN}/{CNT}", None, {"m2m:cnt": {"lbl": ["defaced"]}}),
                    ("PUT", f"{AE_RN}/{ACP_RN}", None, {"m2m:acp": {"pv": {"acr": [{"acor": [who], "acop": ALL}]}}}),
                    ("DELETE", f"{AE_RN}/{CNT}", None, None),
                    ("DELETE", AE_RN, None, None)):
                st, _, h = req(method, f"{BASE}/{path}", who, ty=ty, body=body)
                assert (st, rsc(h)) == (403, 4103), (who, method, path)
        assert _tree() == before == _baseline()

    # --- step 5: the AE creates its baseline <container> under its AE resource
    def test_td_mec_reg_03_step5_baseline_container_was_created_by_the_ae(self, dep):
        st, body, _ = req("GET", f"{BASE}/{AE_RN}/{CNT}", "CAdmin")
        assert st == 200
        cnt = body["m2m:cnt"]
        acp_ri = req("GET", f"{BASE}/{AE_RN}/{ACP_RN}", "CAdmin")[1]["m2m:acp"]["ri"]
        assert (cnt["ty"], cnt["rn"], cnt["pi"], cnt["acpi"]) == (3, CNT, ORIGIN, [acp_ri])
        assert cnt["cr"] == ORIGIN, "the creator the CSE recorded is not the AE"
        # and on the wire: the one <container> Create came from the AE's own originator
        made = [(r["path"], r["headers"]["x-m2m-origin"], r["status"], r["rsc"]) for r in dep.p.cse.seen
                if r["method"] == "POST" and "ty=3" in r["headers"].get("content-type", "")]
        assert made == [(f"/{EDGE_A[1]}/{AE_RN}", ORIGIN, 201, 2001)]
        # it published one reading into it
        st, body, _ = req("GET", f"{BASE}/{AE_RN}/{CNT}/la", "CAdmin")
        assert st == 200 and cnt["cni"] == 1
        assert json.loads(body["m2m:cin"]["con"]) == READING and body["m2m:cin"]["cr"] == ORIGIN

    # --- step 6: the tree is correct and the AE is authorized for CRUD
    def test_td_mec_reg_03_step6_tree_is_exactly_what_the_descriptor_says(self, dep):
        tree = _tree()
        assert len(tree) == 3 and tree == _baseline()
        for ty, want in ((1, [ACP_RN]), (3, [CNT])):
            st, body, _ = req("GET", f"{BASE}/{AE_RN}?fu=1&ty={ty}", "CAdmin")
            assert st == 200 and body["m2m:uril"] == [f"{EDGE_A[1]}/{AE_RN}/{w}" for w in want]

    def test_td_mec_reg_03_step6_ae_may_create_read_update_delete_under_its_own_subtree(self, dep):
        own = f"{BASE}/{AE_RN}"
        st, _, h = req("POST", own, ORIGIN, ty=3, body={"m2m:cnt": {"rn": "scratch"}})
        assert (st, rsc(h)) == (201, 2001)                                                      # Create
        try:
            st, _, h = req("POST", f"{own}/scratch", ORIGIN, ty=4, body={"m2m:cin": {"con": "1"}})
            assert (st, rsc(h)) == (201, 2001)
            assert len(_tree()) == 5, "control: the exact-tree check would not see an extra resource"
            st, body, h = req("GET", f"{own}/scratch/la", ORIGIN)
            assert (st, rsc(h)) == (200, 2000) and body["m2m:cin"]["con"] == "1"                # Retrieve
            st, body, h = req("PUT", f"{own}/scratch", ORIGIN, body={"m2m:cnt": {"lbl": ["updated"]}})
            assert (st, rsc(h)) == (200, 2004) and body["m2m:cnt"]["lbl"] == ["updated"]        # Update
        finally:
            st, _, h = req("DELETE", f"{own}/scratch", ORIGIN)
        assert (st, rsc(h)) == (200, 2002)                                                      # Delete
        st, body, h = req("GET", f"{own}?fu=1", ORIGIN)
        assert (st, rsc(h)) == (200, 2000) and sorted(body["m2m:uril"]) == _baseline()          # and Discover
        assert _tree() == _baseline()

    # --- the link back to MEC
    def test_td_mec_reg_03_mec_link_instance_listed_ready_and_named_by_the_ae(self, dep):
        mids = _mec_ids(dep.p.mec)
        assert len(mids) == 1 and dep.run["mec011AppInstanceId"] == mids[0]
        mid = str(uuid.UUID(mids[0]))
        listed = _listed(dep.iid)
        assert len(listed) == 1
        s = listed[0]
        assert (s["serName"], s["version"], s["state"]) == (APP_NAME, APP_VERSION, "ACTIVE")
        assert f"/applications/{mid}/services/" in s["_links"]["self"]["href"]
        assert s["transportInfo"]["endpoint"] == {"uris": [f"{dep.p.cse.url}/{EDGE_A[1]}/{AE_RN}"]}
        # the AE names both instance identifiers (the two candidates do not share one)
        assert sorted(_ae()[1]["m2m:ae"]["lbl"]) == sorted([f"mec:appInstanceId:{mid}",
                                                             f"mec:lcmInstanceId:{dep.iid}"])
        # on Mp1 the app registered, offered its service, and confirmed ready only once its tree stood
        posts = [(r["path"].rsplit("/", 1)[-1], r["status"]) for r in dep.p.mec.seen if r["method"] == "POST"]
        assert posts == [("registrations", 201), ("services", 201), ("confirm_ready", 204)]
        confirmed = [r["t_in"] for r in dep.p.mec.seen if r["path"].endswith("/confirm_ready")][0]
        writes = [r["t_out"] for r in dep.p.cse.seen if r["method"] in ("POST", "PUT")]
        assert len(writes) == 5 and confirmed > max(writes)         # AE, ACP, AE acpi, container, reading


def test_td_mec_reg_03_step4_control_package_naming_no_reader_admits_only_the_owner(platform, tmp_path):
    """Beside the reader's 200 above: the reader is admitted because the descriptor names it, not by default."""
    p = platform
    pkg = p.agent.onboard(_edit(_copy_pkg(tmp_path / "no-reader"), lambda d: d["onem2m"]["acp"].update(readers=[])))
    iid = p.agent.create_instance(pkg["appDId"], "no-reader")
    p.agent.instantiate(iid)
    acp = req("GET", f"{BASE}/{AE_RN}/{ACP_RN}", "CAdmin")[1]["m2m:acp"]
    assert acp["pv"] == acp["pvs"] == {"acr": [{"acor": [ORIGIN], "acop": ALL}]}
    for path in (AE_RN, f"{AE_RN}/{CNT}/la"):
        st, _, h = req("GET", f"{BASE}/{path}", READER)
        assert (st, rsc(h)) == (403, 4103), path
    assert req("GET", f"{BASE}/{AE_RN}/{CNT}/la", ORIGIN)[0] == 200


def test_td_mec_reg_03_step2_control_a_create_carrying_aei_in_pc_is_refused(topology):
    """The TD writes "pc = AE representation with api, aei". aei is assigned by the registrar and may not be in a
    Create (TS-0004: not present on Create); ACME refuses it, so the AE-ID asked for travels as the originator."""
    name = f"reg03-{uuid.uuid4().hex[:8]}"
    try:
        st, _, h = req("POST", BASE, f"C{name}", ty=2, body={"m2m:ae": {
            "rn": name, "api": API, "rr": False, "srv": ["4"], "aei": f"C{name}"}})
        assert (st, rsc(h)) == (400, 4000)
        assert req("GET", f"{BASE}/{name}", "CAdmin")[0] == 404
    finally:
        req("DELETE", f"{BASE}/{name}", "CAdmin")


def _is_ae_create(rec) -> bool:
    return rec["method"] == "POST" and "ty=2" in rec["headers"].get("content-type", "")


def _answer_rsc_2000(rec, headers, out):
    if _is_ae_create(rec):
        headers = [(k, "2000" if k.lower() == "x-m2m-rsc" else v) for k, v in headers]
    return headers, out


def _answer_another_aei(rec, headers, out):
    if _is_ae_create(rec):
        body = json.loads(out)
        body["m2m:ae"]["aei"] = "Csomeone-else"
        out = json.dumps(body).encode()
    return headers, out


@pytest.mark.parametrize("mangle, said", [(_answer_rsc_2000, "AE Create rsc: got 2000, need 2001"),
                                          (_answer_another_aei, "AE-ID: got 'Csomeone-else', need 'CestimedSensor'")])
def test_td_mec_reg_03_step3_control_app_does_not_go_ready_on_any_other_answer(platform, mangle, said):
    """Step 3 as the app itself checks it: told another rsc or another AE-ID than the TD requires (the relay
    alters the CSE's answer on its way back), it does not confirm ready, leaves in order and exits 3."""
    p = platform
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "wrong-answer")
    p.cse.mangle = mangle
    with pytest.raises(mad.DeployError, match=f"exited with 3 before it was ready.*{said}"):
        p.agent.instantiate(iid)
    assert [(r["status"], r["rsc"]) for r in p.cse.seen if _is_ae_create(r)] == [(201, 2001)]   # the CSE did create
    assert _listed(iid) == [] and _workloads(p.workdir) == []
    assert _ae()[0] == 404, "the app left the AE it had created"
    assert not _registered(_mec_ids(p.mec)[0])
    assert [r["path"].rsplit("/", 1)[-1] for r in p.mec.seen if r["method"] == "POST"] == \
        ["registrations", "services", "confirm_termination"]                                    # never confirm_ready


# ------------------------------------------------------------------------------------------ ready means confirmed
def _confirming(r) -> bool:
    return r["path"].endswith("/confirm_ready")


def test_td_mec_reg_03_mec_link_listed_ready_only_after_the_app_confirmed(platform):
    p = platform
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "gated")
    p.mec.hold = _confirming                       # the relay keeps the app's confirm_ready back
    out = {}

    def go():
        try:
            out["run"] = p.agent.instantiate(iid, ready_timeout=15.0)
        except Exception as e:  # noqa: BLE001  shown by the assertion below
            out["err"] = e

    t = threading.Thread(target=go, daemon=True)
    t.start()
    assert _wait(lambda: any(_confirming(r) for r in p.mec.seen)), f"the app never tried to confirm: {out}"
    # everything is in place except the confirmation: registered, service offered, AE with its tree
    assert _mec_ids(p.mec) and _registered(_mec_ids(p.mec)[0])
    assert [r["status"] for r in p.mec.seen if r["method"] == "POST" and r["path"].endswith("/services")] == [201]
    assert _tree() == _baseline()
    time.sleep(0.4)                                # time for a platform that does not wait for the confirmation
    assert _listed(iid) == [], "control: listed as ready before the app confirmed"
    assert t.is_alive() and not out, "control: the agent called the instance ready before the app confirmed"
    p.mec.release.set()
    t.join(15)
    assert "run" in out, out
    assert len(_listed(iid)) == 1


def test_td_mec_reg_03_control_instance_that_never_confirms_is_not_ready_and_is_removed(platform):
    p = platform
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "never-ready")
    p.mec.hold = _confirming                       # never released while the agent waits
    with pytest.raises(mad.DeployError, match="not listed as ready"):
        p.agent.instantiate(iid, ready_timeout=1.5)
    mid = _mec_ids(p.mec)[0]
    assert _listed(iid) == []
    assert _workloads(p.workdir) == []
    assert _ae()[0] == 404, "the stopped app left its AE behind"
    assert not _registered(mid), "the stopped app left its MEC 011 registration behind"
    # the failure is recorded where the candidate keeps it; the candidate had already said INSTANTIATED when it
    # took the call, so the agent takes the instance back with a terminate call
    assert _opoccs(iid) == [("INSTATIATE", "FAILED"), ("TERMINATE", "PROCESSING")]
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED"
    assert _package(pkg["appPkgId"])["usageState"] == "NOT_IN_USE"


# ------------------------------------------------------------------------------------------ package digests
def _copy_pkg(dst: Path) -> Path:
    shutil.copytree(PKG, dst)
    return dst


def _packages() -> set[str]:
    st, body = http("GET", f"{MEC010}/app_pkgm/v1/app_packages")
    assert st == 200
    return {p["id"] for p in body}


def test_td_mec_reg_03_control_package_with_a_wrong_digest_is_not_onboarded(platform, tmp_path):
    p = platform
    bad = _copy_pkg(tmp_path / "tampered")
    with (bad / "sensor_ae.py").open("ab") as f:
        f.write(b"\n# one line the descriptor does not know about\n")
    before = _packages()
    with pytest.raises(mad.PackageError, match="sensor_ae.py"):
        p.agent.onboard(bad)
    assert _packages() == before, "the refused package reached app_pkgm"
    assert not (p.workdir / "packages").exists() or list((p.workdir / "packages").iterdir()) == []
    # beside it: the same changed program with its digest written into the descriptor is a valid package
    d = json.loads((bad / "appd.json").read_text())
    d["files"]["sensor_ae.py"] = _sha(bad / "sensor_ae.py")
    (bad / "appd.json").write_text(json.dumps(d, indent=2) + "\n")
    pkg = p.agent.onboard(bad)
    assert _package(pkg["appPkgId"])["checksum"]["hash"] == _sha(bad / "appd.json") != _sha(PKG / "appd.json")


@pytest.mark.parametrize("how", ["program", "program and descriptor"])
def test_td_mec_reg_03_control_package_changed_after_onboarding_is_not_started(platform, how):
    """The platform's copy is checked again at the moment of use. Changing the program alone breaks its digest;
    changing the descriptor to match breaks the checksum that app_pkgm was given at onboarding."""
    p = platform
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "changed")
    store = p.workdir / "packages" / pkg["appPkgId"]
    with (store / "sensor_ae.py").open("ab") as f:
        f.write(b"\nprint('not what was onboarded')\n")
    if how == "program and descriptor":
        d = json.loads((store / "appd.json").read_text())
        d["files"]["sensor_ae.py"] = _sha(store / "sensor_ae.py")
        (store / "appd.json").write_text(json.dumps(d, indent=2) + "\n")
    with pytest.raises(mad.PackageError, match="sensor_ae.py" if how == "program" else "checksum"):
        p.agent.instantiate(iid)
    assert _workloads(p.workdir) == []
    assert [r for r in p.cse.seen + p.mec.seen if r["method"] != "GET"] == [], "the workload ran"
    assert _ae()[0] == 404
    # refused before the lifecycle call: the candidate never said INSTANTIATED and holds no occurrence
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED" and _opoccs(iid) == []


def test_td_mec_reg_03_control_disabled_package_is_not_instantiated(platform):
    p = platform
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "disabled")
    assert http("PATCH", f"{MEC010}/app_pkgm/v1/app_packages/{pkg['appPkgId']}",
                {"operationalState": "DISABLED"})[0] == 200
    with pytest.raises(mad.DeployError, match="DISABLED"):
        p.agent.instantiate(iid)
    assert _workloads(p.workdir) == [] and _ae()[0] == 404
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED" and _opoccs(iid) == []


def test_td_mec_reg_03_control_package_for_an_mn_cse_the_platform_does_not_have_is_not_started(platform):
    p = platform
    p.agent.cses = {"cse-mn-b": "http://127.0.0.1:8202/cse-mn-b"}          # the descriptor says cse-mn-a
    pkg = p.agent.onboard(PKG)
    iid = p.agent.create_instance(pkg["appDId"], "no-such-cse")
    with pytest.raises(mad.DeployError, match="no MN-CSE named 'cse-mn-a'"):
        p.agent.instantiate(iid)
    assert _workloads(p.workdir) == [] and _ae()[0] == 404
    assert req("GET", f"http://127.0.0.1:8202/cse-mn-b/{AE_RN}", "CAdmin")[0] == 404
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED" and _opoccs(iid) == []


# ------------------------------------------------------------------------------------------ terminate
def test_td_mec_reg_03_control_nothing_is_left_after_terminate(platform):
    p = platform
    pkg, iid, run = _deploy(p)
    pid, mid = run["pid"], run["mec011AppInstanceId"]
    # beside the control: all of it is there while the instance runs
    assert _workloads(p.workdir) == [pid] and _ae()[0] == 200 and _registered(mid) and len(_listed(iid)) == 1
    with pytest.raises(mad.DeployError, match="already running"):         # one instance, one workload
        p.agent.instantiate(iid)
    assert _workloads(p.workdir) == [pid] and _opoccs(iid) == [("INSTATIATE", "PROCESSING")]
    done = p.agent.terminate(iid)
    assert (done["exitCode"], done["forced"]) == (0, False)
    assert not Path(f"/proc/{pid}").exists() and _workloads(p.workdir) == []
    assert _ae()[0] == 404, "the AE is still registered at the MN-CSE"
    assert _listed(iid) == [] and not _registered(mid), "MEC 011 still holds the instance"
    # the app itself said goodbye on Mp1, in this order, and removed its own AE on Mca
    tail = [(r["method"], r["path"].rsplit("/", 1)[-1], r["status"]) for r in p.mec.seen if r["method"] != "GET"][3:]
    assert tail[0] == ("POST", "confirm_termination", 204) and tail[-1] == ("DELETE", mid, 204)
    assert [(r["path"], r["headers"]["x-m2m-origin"], r["rsc"]) for r in p.cse.seen if r["method"] == "DELETE"] == \
        [(f"/{EDGE_A[1]}/{AE_RN}", ORIGIN, 2002)]
    # the 010-2 side: terminated, package free again, and now both can be removed
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED"
    assert _opoccs(iid) == [("INSTATIATE", "PROCESSING"), ("TERMINATE", "PROCESSING")]
    assert p.agent.results[done["opOcc"]] == "COMPLETED"
    assert _package(pkg["appPkgId"])["usageState"] == "NOT_IN_USE"
    with pytest.raises(mad.DeployError, match="not running"):
        p.agent.terminate(iid)
    p.agent.delete_instance(iid)
    p.agent.offboard(pkg["appPkgId"])
    assert http("GET", f"{MEC010}/app_lcm/v1/app_instances/{iid}")[0] == 404
    assert http("GET", f"{MEC010}/app_pkgm/v1/app_packages/{pkg['appPkgId']}")[0] == 404
    assert not (p.workdir / "packages" / pkg["appPkgId"]).exists()


STUBBORN = "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(600)\n"


def _stub_pkg(dst: Path, program: str) -> Path:
    """A valid package (right digests, the shipped descriptor otherwise) around another program."""
    dst.mkdir()
    (dst / "stub.py").write_text(program)
    d = copy.deepcopy(DESCRIPTOR)
    d["entryPoint"]["file"] = "stub.py"
    d["files"] = {"stub.py": _sha(dst / "stub.py")}
    (dst / "appd.json").write_text(json.dumps(d, indent=2) + "\n")
    return dst


def test_td_mec_reg_03_control_workload_that_ignores_the_stop_request_is_killed(platform, tmp_path):
    """Needs no CSE: the stub never registers anywhere, so it is never ready; told to stop, it ignores SIGTERM."""
    p = platform
    p.agent.grace = 0.5
    pkg = p.agent.onboard(_stub_pkg(tmp_path / "stubborn", STUBBORN))
    iid = p.agent.create_instance(pkg["appDId"], "stubborn")
    with pytest.raises(mad.DeployError, match=r"not listed as ready.*exit -9, killed"):
        p.agent.instantiate(iid, ready_timeout=1.0)
    assert _workloads(p.workdir) == []
    assert _opoccs(iid) == [("INSTATIATE", "FAILED"), ("TERMINATE", "PROCESSING")]
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED"


READY_AND_STUBBORN = '''import json, signal, sys, time, urllib.request
cfg = json.load(open(sys.argv[2]))


def post(path, body):
    r = urllib.request.Request(cfg["mec011"] + path, data=json.dumps(body).encode(), method="POST",
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=10) as x:
        raw = x.read()
        return json.loads(raw) if raw else None


signal.signal(signal.SIGTERM, signal.SIG_IGN)
inst = post("/mec_app_support/v2/registrations", {"appName": "stub"})["appInstanceId"]
post(f"/mec_service_mgmt/v1/applications/{inst}/services", {
    "serName": "stub", "version": "1", "state": "ACTIVE", "serializer": "JSON",
    "transportInfo": {"id": cfg["lcmInstanceId"]}})
post(f"/mec_app_support/v2/applications/{inst}/confirm_ready", {"indication": "READY"})
time.sleep(600)
'''


def test_td_mec_reg_03_control_ready_workload_that_will_not_stop_is_killed_and_deregistered(platform, tmp_path):
    """Needs no CSE: the stub registers with MEC 011, confirms ready, and then ignores the termination request.
    The agent kills it and removes the MEC 011 registration the stub can no longer remove itself. (An <AE> of a
    killed workload would stay: the agent has no oneM2M identity. This stub creates none.)"""
    p = platform
    p.agent.grace = 0.5
    pkg = p.agent.onboard(_stub_pkg(tmp_path / "ready-stubborn", READY_AND_STUBBORN))
    iid = p.agent.create_instance(pkg["appDId"], "ready-stubborn")
    run = p.agent.instantiate(iid)
    mid = run["mec011AppInstanceId"]
    assert _workloads(p.workdir) == [run["pid"]] and _registered(mid) and len(_listed(iid)) == 1
    done = p.agent.terminate(iid)
    assert (done["exitCode"], done["forced"]) == (-9, True)
    assert _workloads(p.workdir) == []
    assert not _registered(mid) and _listed(iid) == []
    assert _opoccs(iid) == [("INSTATIATE", "PROCESSING"), ("TERMINATE", "FAILED")]
    assert p.agent.results[done["opOcc"]] == "FAILED"
    assert _instance(iid)["instantiationState"] == "NOT_INSTANTIATED"


# ------------------------------------------------------------------------------------------ one originator, one AE
def test_td_mec_reg_03_control_second_instance_with_the_same_originator_is_refused(platform):
    p = platform
    pkg, first, run = _deploy(p, "first")
    ae_before = _ae()[1]["m2m:ae"]
    second = p.agent.create_instance(pkg["appDId"], "second")
    with pytest.raises(mad.DeployError, match="exited with 3 before it was ready"):
        p.agent.instantiate(second)
    # on the wire: the second Create came from the same originator and the CSE refused it
    creates = [(r["headers"]["x-m2m-origin"], r["status"], r["rsc"]) for r in p.cse.seen
               if r["method"] == "POST" and "ty=2" in r["headers"].get("content-type", "")]
    assert creates == [(ORIGIN, 201, 2001), (ORIGIN, 403, 4117)]
    # the second instance is gone from everywhere it had got to
    mids = _mec_ids(p.mec)
    assert len(mids) == 2 and mids[0] == run["mec011AppInstanceId"]
    assert _workloads(p.workdir) == [run["pid"]]
    assert not _registered(mids[1]) and _listed(second) == []
    assert _opoccs(second) == [("INSTATIATE", "FAILED"), ("TERMINATE", "PROCESSING")]
    assert _instance(second)["instantiationState"] == "NOT_INSTANTIATED"
    # and the first is untouched: the same <AE> resource (not a re-created one), its tree, its registration
    assert _ae()[1]["m2m:ae"] == ae_before
    assert _tree() == _baseline()
    assert _registered(mids[0]) and len(_listed(first)) == 1
    assert _instance(first)["instantiationState"] == "INSTANTIATED"


# ------------------------------------------------------------------------------------------ offline: the package
# No CSE, no MEC candidate, no network below this line.
def _edit(pkg: Path, change) -> Path:
    d = json.loads((pkg / "appd.json").read_text())
    change(d)
    (pkg / "appd.json").write_text(json.dumps(d, indent=2) + "\n")
    return pkg


def test_pkg_shipped_package_verifies_and_says_what_the_live_tests_expect():
    assert sorted(x.name for x in PKG.iterdir()) == ["appd.json", "sensor_ae.py"]
    d = mad.verify_package(PKG)
    assert d == json.loads((PKG / "appd.json").read_text())
    assert d.pop("files") == {"sensor_ae.py": _sha(PKG / "sensor_ae.py")}
    d.pop("appDescription", None)
    assert d == DESCRIPTOR
    assert mad.descriptor_digest(PKG) == _sha(PKG / "appd.json")


def test_pkg_sensor_ae_uses_the_standard_library_only():
    import ast
    tree = ast.parse((PKG / "sensor_ae.py").read_text())
    names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
            {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert names - {"__future__"} <= sys.stdlib_module_names, names - sys.stdlib_module_names


def _plant_digest(pkg):
    with (pkg / "sensor_ae.py").open("ab") as f:
        f.write(b"\n")


def _plant_extra(pkg):
    (pkg / "json.py").write_text("raise SystemExit('shadowed')\n")


def _plant_missing(pkg):
    (pkg / "sensor_ae.py").unlink()


def _plant_symlink(pkg):
    real = pkg.parent / "elsewhere.py"
    shutil.move(pkg / "sensor_ae.py", real)                  # same bytes, so the digest alone would pass
    (pkg / "sensor_ae.py").symlink_to(real)


@pytest.mark.parametrize("plant, names", [(_plant_digest, "sensor_ae.py"), (_plant_extra, "json.py"),
                                          (_plant_missing, "sensor_ae.py"), (_plant_symlink, "sensor_ae.py")])
def test_pkg_control_content_that_differs_from_the_descriptor_is_refused(tmp_path, plant, names):
    pkg = _copy_pkg(tmp_path / "pkg")
    assert mad.verify_package(pkg)["appName"] == APP_NAME          # beside the control: the copy itself is fine
    plant(pkg)
    with pytest.raises(mad.PackageError, match=names):
        mad.verify_package(pkg)


@pytest.mark.parametrize("field", [
    "appName", "appProvider", "appSoftVersion", "appDVersion", "entryPoint", "files", "mecServicesRequired",
    "onem2m", "entryPoint.runtime", "entryPoint.file", "entryPoint.args", "onem2m.mnCse", "onem2m.api",
    "onem2m.originator", "onem2m.rn", "onem2m.acp", "onem2m.container", "onem2m.acp.rn", "onem2m.acp.readers"])
def test_pkg_control_missing_descriptor_field_is_refused(tmp_path, field):
    def drop(d):
        *path, last = field.split(".")
        for k in path:
            d = d[k]
        del d[last]
    pkg = _edit(_copy_pkg(tmp_path / "pkg"), drop)
    with pytest.raises(mad.PackageError, match=field.rsplit(".", 1)[-1]):
        mad.verify_package(pkg)


def test_pkg_control_no_descriptor_or_not_json_is_refused(tmp_path):
    pkg = _copy_pkg(tmp_path / "pkg")
    (pkg / "appd.json").write_text("{not json")
    with pytest.raises(mad.PackageError, match="appd.json"):
        mad.verify_package(pkg)
    (pkg / "appd.json").unlink()
    with pytest.raises(mad.PackageError, match="appd.json"):
        mad.verify_package(pkg)


@pytest.mark.parametrize("entry, why", [
    ({"file": "other.py"}, "other.py"),                       # a program the package does not contain
    ({"file": "../sensor_ae.py"}, "sensor_ae.py"),            # outside the package
    ({"file": "/usr/bin/env"}, "/usr/bin/env"),
    ({"runtime": "bash"}, "bash"),                            # a runtime the platform does not offer
    ({"args": ["--instance", 5]}, "args"),
    ({"args": "--instance {instance}"}, "args")])
def test_pkg_control_unknown_entry_point_is_refused(tmp_path, entry, why):
    pkg = _edit(_copy_pkg(tmp_path / "pkg"), lambda d: d["entryPoint"].update(entry))
    with pytest.raises(mad.PackageError, match=why):
        mad.verify_package(pkg)


@pytest.mark.parametrize("key, value", [
    ("originator", "SestimedSensor"), ("originator", "estimedSensor"), ("originator", "C"),
    ("originator", "Cab/cd"), ("api", "estimed.sensor"), ("rn", "a/b"), ("rn", ".."), ("container", "x?fu=1"),
    ("mnCse", ""), ("acp", {"rn": "a/b", "readers": []}), ("acp", {"rn": "sensorAcp", "readers": ["C any one"]}),
    ("acp", {"rn": "sensorAcp", "readers": [5]})])
def test_pkg_control_identity_the_cse_could_not_take_as_written_is_refused(tmp_path, key, value):
    pkg = _edit(_copy_pkg(tmp_path / "pkg"), lambda d: d["onem2m"].update({key: value}))
    with pytest.raises(mad.PackageError, match=key):
        mad.verify_package(pkg)


@pytest.mark.parametrize("need", [{"serName": "mec_v2x", "version": "v1"},
                                  {"serName": "mec_app_support", "version": "v9"}, "mec_app_support"])
def test_pkg_control_mec_service_the_platform_does_not_offer_is_refused(tmp_path, need):
    pkg = _edit(_copy_pkg(tmp_path / "pkg"), lambda d: d["mecServicesRequired"].append(need))
    with pytest.raises(mad.PackageError, match="mecServicesRequired"):
        mad.verify_package(pkg)


def test_pkg_command_is_built_from_the_descriptor():
    d = copy.deepcopy(DESCRIPTOR)
    assert mad.command(d, Path("/store/p1"), Path("/inst/i1/instance.json")) == \
        [sys.executable, "-I", "-B", "/store/p1/sensor_ae.py", "--instance", "/inst/i1/instance.json"]
    d["entryPoint"] = {"runtime": "python3", "file": "bin/run.py", "args": ["-v", "--cfg={instance}"]}
    assert mad.command(d, Path("/s"), Path("/i.json")) == [sys.executable, "-I", "-B", "/s/bin/run.py", "-v",
                                                           "--cfg=/i.json"]


def test_pkg_digests_command_reports_and_refreshes_a_changed_package(tmp_path):
    pkg = _copy_pkg(tmp_path / "pkg")
    cli = [sys.executable, "-B", str(ESTIMED / "mec_app_deploy.py"), "digests", str(pkg)]
    assert subprocess.run(cli, capture_output=True, text=True).returncode == 0
    _plant_digest(pkg)
    r = subprocess.run(cli, capture_output=True, text=True)
    assert r.returncode == 1 and "sensor_ae.py" in r.stdout + r.stderr
    assert subprocess.run(cli + ["--write"], capture_output=True, text=True).returncode == 0
    assert mad.verify_package(pkg)["files"] == {"sensor_ae.py": _sha(pkg / "sensor_ae.py")}


def test_agent_control_unknown_ids_are_refused_before_any_call(tmp_path):
    """Nothing listens on the addresses given: a refusal that needed the network would not be this refusal."""
    dead = "http://127.0.0.1:9"
    agent = mad.PlatformAgent(mec010=dead, mec011=dead, cses={}, workdir=tmp_path)
    with pytest.raises(mad.DeployError, match="not onboarded"):
        agent.create_instance(str(uuid.uuid4()), "x")
    for call in (agent.instantiate, agent.terminate, agent.delete_instance):
        with pytest.raises(mad.DeployError, match="unknown instance"):
            call(str(uuid.uuid4()))
    with pytest.raises(mad.PackageError, match="sensor_ae.py"):          # refused before app_pkgm is asked
        bad = _copy_pkg(tmp_path / "bad")
        _plant_digest(bad)
        agent.onboard(bad)
    with pytest.raises(mad.DeployError, match="127.0.0.1:9"):            # control: a good package does need it
        agent.onboard(PKG)
    assert list(tmp_path.glob("packages/*")) == []
