"""ESTIMED test plan (TR-0086 test plan v0.2.0) descriptions run against the live stack.

Each test name carries its TD_MEC_* identifier. The plan's sequences are followed
step by step; each positive check has a control beside it that must come out the
other way. HO_04 (CMDH policy) is not here: it needs a CMDH policy engine we do not
have yet, and a test that skipped it would read as covered.

    TD_MEC_REG_02  MEC app registered, confirmed ready, listed in the service registry
    TD_MEC_HO_02   downlink commands and subscriptions after handover
    TD_MEC_HO_03   staged cutover while the device keeps publishing
    TD_MEC_HO_05   ranked targets, fallback when the first one refuses
    TD_MEC_HO_06   handover held until the target confirms readiness
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import handover
from conftest import CSI, EDGE_A, EDGE_B, IN_CSE, MEC011, TY_ACP, TY_SUB, http, notified_cin, req

SAMPLES = ["48.1351,11.5820", "48.1361,11.5835", "48.1372,11.5849"]
SERVICES = MEC011.rsplit("/mec_app_support", 1)[0] + "/mec_service_mgmt/v1"
CMD = "commands"
CREATE, RETRIEVE, NOTIFY, DISCOVER = 1, 2, 16, 32


def _wait(pred, timeout=8.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def _ae(edge, name=handover.AE_NAME, origin=handover.AE_ORIGIN):
    st, body, _ = req("GET", f"{edge[0]}/{edge[1]}/{name}", origin)
    return st, (body or {}).get("m2m:ae")


def _attach_on_a(**ae_attrs):
    assert handover.create_ae(EDGE_A, **ae_attrs)[0] == 201
    assert handover.create_container(EDGE_A)[0] == 201
    for s in SAMPLES:
        assert handover.add_sample(EDGE_A, s)[0] == 201


def _route(origin=handover.AE_ORIGIN):
    """Where the IN-CSE says the AE is served: the edges whose announced AE carries its label."""
    st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}?fu=1&lbl=aei:{origin}", "CAdmin")
    assert st == 200
    by_csi = {v: k for k, v in CSI.items()}
    out = []
    for uri in body.get("m2m:uril", []):
        s, b, _ = req("GET", f"{IN_CSE[0]}/{uri}", "CAdmin")
        assert s == 200, uri
        out.append(by_csi[b["m2m:aeA"]["lnk"].split("/")[1]])
    return out


def _assert_untouched():
    """The vehicle is still served by A as before, nothing on B, the IN still routes to A."""
    st, a = _ae(EDGE_A)
    assert st == 200 and a["rr"] is True
    assert handover.read_samples(EDGE_A) == SAMPLES
    assert _ae(EDGE_B)[0] == 404
    assert _route() == [EDGE_A]


# --- TD_MEC_REG_02 ------------------------------------------------------------------

def _edge_service(mec011, edge, state="ACTIVE", ready=True):
    """An edge app on the MEC platform advertising the MN-CSE at `edge`. Returns (inst, ser)."""
    st, body = http("POST", f"{mec011}/registrations", {"appName": f"mn-cse-{edge[1]}"})
    assert st == 201 and body["appInstanceId"]
    inst = body["appInstanceId"]
    st, ser = http("POST", f"{SERVICES}/applications/{inst}/services", {
        "serName": handover.EDGE_SERVICE, "version": "1.0", "state": state, "serializer": "JSON",
        "transportInfo": {"id": f"t-{edge[1]}", "name": "oneM2M HTTP", "type": "REST_HTTP",
                          "protocol": "HTTP", "version": "1.1", "security": {},
                          "endpoint": {"uris": [f"{edge[0]}/{edge[1]}"]}}})
    assert st == 201, ser
    if ready:
        assert http("POST", f"{mec011}/applications/{inst}/confirm_ready", {"indication": "READY"})[0] == 204
    return inst, ser["serInstanceId"]


def _listed(ser_id):
    st, body = http("GET", f"{SERVICES}/services?ser_name={handover.EDGE_SERVICE}")
    assert st == 200
    return [s for s in body if s["serInstanceId"] == ser_id]


def test_td_mec_reg_02_registered_app_is_discoverable(mec011):
    st, body = http("POST", f"{mec011}/registrations", {"appName": "estimed-edge-app"})
    assert st == 201 and body.get("appInstanceId")                                 # steps 1-2
    inst = body["appInstanceId"]
    try:
        st, ser = http("POST", f"{SERVICES}/applications/{inst}/services", {
            "serName": handover.EDGE_SERVICE, "version": "1.0", "state": "ACTIVE",
            "serializer": "JSON"})
        assert st == 201 and ser["serInstanceId"]
        assert _listed(ser["serInstanceId"]) == [], "control: listed before the app confirmed ready"
        assert http("POST", f"{mec011}/applications/{inst}/confirm_ready",
                    {"indication": "READY"})[0] == 204                               # step 3
        listed = _listed(ser["serInstanceId"])                                         # step 4
        assert len(listed) == 1 and listed[0]["state"] == "ACTIVE"                    # step 5
        assert http("POST", f"{mec011}/applications/{inst}/confirm_termination",
                    {"operationAction": "TERMINATING"})[0] == 204
        assert _listed(ser["serInstanceId"]) == [], "control: still listed after termination"
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


def test_td_mec_reg_02_control_service_of_unknown_app_is_refused(mec011):
    st, _ = http("POST", f"{SERVICES}/applications/{uuid.uuid4()}/services", {
        "serName": handover.EDGE_SERVICE, "version": "1.0", "state": "ACTIVE", "serializer": "JSON"})
    assert st == 404


@pytest.mark.parametrize("drop", ["serName", "state", "serializer", "version"])
def test_td_mec_reg_02_control_incomplete_service_info_is_400(mec011, drop):
    inst = http("POST", f"{mec011}/registrations", {"appName": "x"})[1]["appInstanceId"]
    try:
        info = {"serName": "s", "version": "1.0", "state": "ACTIVE", "serializer": "JSON"}
        del info[drop]
        assert http("POST", f"{SERVICES}/applications/{inst}/services", info)[0] == 400
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


# --- TD_MEC_HO_06 -------------------------------------------------------------------

def _gate(edge):
    return handover.target_ready(edge, SERVICES)


def test_td_mec_ho_06_blocked_while_target_not_ready(vehicle, mec011):
    _attach_on_a()
    inst, _ = _edge_service(mec011, EDGE_B, ready=False)
    try:
        assert not _gate(EDGE_B)
        assert handover.handover(EDGE_A, EDGE_B, SAMPLES, ready=_gate, ready_timeout=1.0) is False
        _assert_untouched()                                                            # step 2
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


def test_td_mec_ho_06_queued_then_completes_once_ready(vehicle, mec011, monkeypatch):
    _attach_on_a()
    inst, _ = _edge_service(mec011, EDGE_B, ready=False)
    started, confirmed = [], []
    real = handover.set_reachability

    def spy(edge, value, *a, **kw):
        if edge == EDGE_A and value is False:
            started.append((time.monotonic(), _ae(EDGE_A)[1]["rr"]))
        return real(edge, value, *a, **kw)

    def confirm():                                                                     # step 3
        time.sleep(1.0)
        confirmed.append(time.monotonic())
        http("POST", f"{mec011}/applications/{inst}/confirm_ready", {"indication": "READY"})

    monkeypatch.setattr(handover, "set_reachability", spy)
    t = threading.Thread(target=confirm)
    try:
        t.start()
        assert handover.handover(EDGE_A, EDGE_B, SAMPLES, ready=_gate, ready_timeout=10.0)
        t.join()
        assert started and confirmed and started[0][0] > confirmed[0], \
            "the handover began before the target confirmed readiness"
        assert handover.read_samples(EDGE_B) == SAMPLES                                # step 4
        assert _ae(EDGE_A)[0] == 404 and _route() == [EDGE_B]
    finally:
        t.join()
        http("DELETE", f"{mec011}/registrations/{inst}")


def test_td_mec_ho_06_control_inactive_service_is_not_ready(mec011):
    inst, _ = _edge_service(mec011, EDGE_B, state="INACTIVE")
    try:
        assert not _gate(EDGE_B)
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


def test_td_mec_ho_06_control_readiness_is_per_target(mec011):
    """An edge ready for A says nothing about B; the gate is not vacuous."""
    inst, _ = _edge_service(mec011, EDGE_A)
    try:
        assert _gate(EDGE_A) and not _gate(EDGE_B)
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


@pytest.mark.parametrize("cse", [("http://127.0.0.1:9", "cse-mn-x"),          # nothing listens
                                 (EDGE_B[0], "cse-mn-x")],                      # answers, not that CSE
                         ids=["down", "wrong-csebase"])
def test_td_mec_ho_06_control_platform_ready_but_cse_down(mec011, cse):
    inst, _ = _edge_service(mec011, cse)
    try:
        assert not _gate(cse)
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


def _etsi_edge_service(mec011, edge, csi, root=None, name=None, state="ACTIVE"):
    """The MN-CSE advertised the way ETSI's sandbox CSE advertises itself (meep-acme-mn-cse MECSupport.py:462-499,
    STF_685 @0d72b40): serName its own resource name, serCategory.id its CSE-ID, the endpoint its HTTP ROOT (no
    CSEBase name), security null. Our gate looked only for serName onem2m-mn-cse at {host}/{cb} and never saw it."""
    inst = http("POST", f"{mec011}/registrations", {"appName": f"acme-{edge[1]}"})[1]["appInstanceId"]
    st, ser = http("POST", f"{SERVICES}/applications/{inst}/services", {
        "serName": name or edge[1], "version": "v1", "state": state, "serializer": "JSON",
        "serCategory": {"href": "catalogueHref", "id": csi, "name": edge[1], "version": "v1"},
        "scopeOfLocality": "MEC_HOST", "consumedLocalOnly": True,
        "transportInfo": {"id": "acme-mn-cse-transport", "name": "REST", "type": "REST_HTTP", "protocol": "HTTP",
                          "version": "5.0", "endpoint": {"uris": [root or edge[0]]}, "security": None}})
    assert st == 201, ser
    assert http("POST", f"{mec011}/applications/{inst}/confirm_ready", {"indication": "READY"})[0] == 204
    return inst


@pytest.mark.parametrize("csi", ["/id-mn-b", "id-mn-b"], ids=["csi-with-slash", "bare-cse-id"])
def test_td_mec_ho_06_etsi_style_registration_is_ready(mec011, csi):
    """B4 (2026-10-29): the gate recognises a CSE registered the ETSI sandbox's way."""
    inst = _etsi_edge_service(mec011, EDGE_B, csi)
    try:
        assert _gate(EDGE_B)
        assert not _gate(EDGE_A), "control: B's registration says nothing about A"
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


def test_td_mec_ho_06_etsi_style_target_takes_the_handover(vehicle, mec011):
    _attach_on_a()
    inst = _etsi_edge_service(mec011, EDGE_B, "/id-mn-b")
    try:
        assert handover.handover(EDGE_A, EDGE_B, SAMPLES, ready=_gate, ready_timeout=2.0)
        assert handover.read_samples(EDGE_B) == SAMPLES and _route() == [EDGE_B]
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


@pytest.mark.parametrize("kw", [
    {"state": "INACTIVE"},
    {"csi": "/id-mn-a"},                                   # another CSE's ID
    {"name": "cse-mn-a"},                                  # another CSE's name
    {"root": "http://127.0.0.1:8201"},                     # another CSE's root
    {"root": "http://127.0.0.1:820"},                      # a string prefix that is not a path prefix
    {"root": "http://127.0.0.1:8202/cse-mn-b/sub"},        # deeper than the CSEBase
], ids=["inactive", "other-cse-id", "other-name", "other-root", "lookalike-prefix", "below-the-csebase"])
def test_td_mec_ho_06_control_etsi_style_near_misses_are_not_ready(mec011, kw):
    kw = {"csi": "/id-mn-b", **kw}
    inst = _etsi_edge_service(mec011, EDGE_B, kw.pop("csi"), **kw)
    try:
        assert not _gate(EDGE_B)
    finally:
        http("DELETE", f"{mec011}/registrations/{inst}")


# --- TD_MEC_HO_05 -------------------------------------------------------------------

class _Refusing(BaseHTTPRequestHandler):
    """A target MN-CSE that answers but refuses admission (the plan's simulated failure)."""

    def _answer(self, code, rsc, body=None):
        raw = json.dumps(body).encode() if body else b""
        self.server.seen.append((self.command, self.path))
        self.send_response(code)
        self.send_header("X-M2M-RSC", str(rsc))
        self.send_header("X-M2M-RI", self.headers.get("X-M2M-RI", ""))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):  # noqa: N802
        self._answer(200, 2000, {"m2m:cb": {"rn": "cse-refusing", "csi": "/id-refusing", "cst": 2}})

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._answer(403, 4103, {"m2m:dbg": "admission refused"})

    def do_DELETE(self):  # noqa: N802
        self._answer(404, 4004)

    def do_PUT(self):  # noqa: N802
        self._answer(404, 4004)

    def log_message(self, *a):
        pass


@pytest.fixture
def refusing(monkeypatch):
    """Stub targets that refuse ADMISSION. They are not registered at the IN, so the registration gate
    (handover.registered_mn, tested in test_handover_offline.py and test_tr0086_handover.py) is told these stubs are:
    what refuses them here must still be their own admission decision."""
    stubs = set()
    real = handover.registered_mn
    monkeypatch.setattr(handover, "registered_mn", lambda dst: (True, "stub") if dst in stubs else real(dst))

    def start():
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Refusing)
        srv.seen = []
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        edge = (f"http://127.0.0.1:{srv.server_address[1]}", "cse-refusing")
        stubs.add(edge)
        return srv, edge
    servers = []
    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def test_td_mec_ho_05_ranking_is_deterministic():
    cands = [{"edge": ("h1", "c"), "trust": 0.9, "latency_ms": 20, "load": 0.5},
             {"edge": ("h2", "c"), "trust": 0.9, "latency_ms": 5, "load": 0.9},
             {"edge": ("h3", "c"), "trust": 0.5, "latency_ms": 1, "load": 0.0},
             {"edge": ("h4", "c"), "trust": 0.9, "latency_ms": 5, "load": 0.1}]
    want = [("h4", "c"), ("h2", "c"), ("h1", "c"), ("h3", "c")]
    for order in (cands, cands[::-1], cands[1:] + cands[:1]):
        assert [c["edge"] for c in handover.rank(order)] == want


def test_td_mec_ho_05_primary_refuses_fallback_completes(vehicle, refusing):
    _attach_on_a()
    stub, primary = refusing()
    cands = [{"edge": EDGE_B, "trust": 0.9, "latency_ms": 20, "load": 0.4},
             {"edge": primary, "trust": 0.9, "latency_ms": 5, "load": 0.4}]
    assert handover.rank(cands)[0]["edge"] == primary                                  # step 2
    edge, attempts = handover.handover_ranked(EDGE_A, cands, SAMPLES)
    assert ("POST", f"/{primary[1]}") in stub.seen, "the primary was never asked to admit"  # step 3
    assert attempts == [(primary, False), (EDGE_B, True)]                              # step 4
    assert edge == EDGE_B                                                              # step 5
    assert handover.read_samples(EDGE_B) == SAMPLES
    assert _ae(EDGE_A)[0] == 404 and _route() == [EDGE_B]


def test_td_mec_ho_05_control_every_candidate_refuses(vehicle, refusing):
    _attach_on_a()
    (s1, p1), (s2, p2) = refusing(), refusing()
    edge, attempts = handover.handover_ranked(
        EDGE_A, [{"edge": p1, "trust": 0.9, "latency_ms": 5, "load": 0},
                 {"edge": p2, "trust": 0.8, "latency_ms": 5, "load": 0}], SAMPLES)
    assert edge is None and attempts == [(p1, False), (p2, False)]
    assert all(("POST", f"/{p1[1]}") in s.seen for s in (s1, s2)), "each candidate was asked to admit, and refused"
    _assert_untouched()


def test_td_mec_ho_05_control_source_is_never_a_candidate(vehicle):
    _attach_on_a()
    edge, attempts = handover.handover_ranked(
        EDGE_A, [{"edge": EDGE_A, "trust": 1.0, "latency_ms": 0, "load": 0}], SAMPLES)
    assert edge is None and attempts == []
    _assert_untouched()


# --- TD_MEC_HO_03 -------------------------------------------------------------------

class Publisher(threading.Thread):
    """The vehicle publishing telemetry continuously to the edge it is attached to."""

    def __init__(self, edge, period=0.01):
        super().__init__(daemon=True)
        self.edge, self.period = edge, period
        self.produced, self.kept, self.failed, self.on_hold = [], [], [], []
        self._held = False
        self._lock = threading.Lock()                      # held across one write
        self._stop = threading.Event()

    def run(self):
        i = 0
        while not self._stop.is_set():
            v = f"p{i:05d}"
            i += 1
            with self._lock:
                self.produced.append(v)
                if self._held:
                    self.kept.append(v)
                else:
                    self._send(v)
            time.sleep(self.period)

    def _send(self, v):
        st, _ = handover.add_sample(self.edge, v)
        if st != 201:
            self.failed.append((self.edge, v, st))

    def hold(self):
        for f in self.on_hold:
            f()
        with self._lock:
            self._held = True

    def resume(self, edge):
        with self._lock:
            self.edge = edge
            for v in self.kept:
                self._send(v)
            self.kept.clear()
            self._held = False

    def stop(self):
        self._stop.set()
        self.join()


def _publishing_into_the_move(monkeypatch, pub, extra=5):
    """Hold the handover in DUAL_ATTACH until the device has published `extra` more samples."""
    real = handover.create_ae

    def spy(edge, *a, **kw):
        r = real(edge, *a, **kw)
        if edge == EDGE_B:
            n = len(pub.produced)
            assert _wait(lambda: len(pub.produced) >= n + extra)
        return r

    monkeypatch.setattr(handover, "create_ae", spy)


def test_td_mec_ho_03_staged_cutover_while_publishing(vehicle, monkeypatch):
    assert handover.create_ae(EDGE_A)[0] == 201
    assert handover.create_container(EDGE_A)[0] == 201
    pub = Publisher(EDGE_A)
    pub.start()
    try:
        assert _wait(lambda: len(pub.produced) >= 5)
        dual = []
        pub.on_hold.append(lambda: dual.append((_ae(EDGE_A)[0], _ae(EDGE_B)[0])))
        _publishing_into_the_move(monkeypatch, pub)
        assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A), device=pub)  # step 1
        n = len(pub.produced)
        assert _wait(lambda: len(pub.produced) >= n + 5)
    finally:
        pub.stop()
    assert dual == [(200, 200)], "not registered at both edges during the cutover"    # step 2
    assert pub.failed == []
    on_b = handover.read_samples(EDGE_B)
    assert on_b == pub.produced, "telemetry lost or reordered across the cutover"     # step 3
    assert _ae(EDGE_A)[0] == 404 and _route() == [EDGE_B]                             # step 4
    assert len(set(on_b)) == len(on_b), "duplicate CINs on the target"                # step 5


def test_td_mec_ho_03_control_without_catch_up_samples_are_lost(vehicle, monkeypatch):
    """The catch-up is what carries samples written during the move: without it they go missing."""
    assert handover.create_ae(EDGE_A)[0] == 201
    assert handover.create_container(EDGE_A)[0] == 201
    pub = Publisher(EDGE_A)
    pub.start()
    try:
        assert _wait(lambda: len(pub.produced) >= 5)
        _publishing_into_the_move(monkeypatch, pub)
        monkeypatch.setattr(handover, "_catch_up", lambda *a: 0)
        assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A), device=pub)
    finally:
        pub.stop()
    assert handover.read_samples(EDGE_B) != pub.produced


def test_td_mec_ho_03_control_device_not_moved_loses_writes(vehicle, monkeypatch):
    """Without the device hand-off it keeps publishing to the released source and fails."""
    assert handover.create_ae(EDGE_A)[0] == 201
    assert handover.create_container(EDGE_A)[0] == 201
    pub = Publisher(EDGE_A)
    pub.start()
    try:
        assert _wait(lambda: len(pub.produced) >= 5)
        assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
        assert _wait(lambda: pub.failed, timeout=3.0)
    finally:
        pub.stop()
    assert all(e == EDGE_A for e, _, _ in pub.failed)


def test_td_mec_ho_03_control_stale_sample_list_is_refused(vehicle):
    """A caller whose idea of the source is wrong must not get a 'verified' copy of it."""
    _attach_on_a()
    assert handover.handover(EDGE_A, EDGE_B, SAMPLES[1:]) is False
    _assert_untouched()


def test_td_mec_ho_03_rollback_resumes_device_on_source(vehicle, monkeypatch):
    assert handover.create_ae(EDGE_A)[0] == 201
    assert handover.create_container(EDGE_A)[0] == 201
    pub = Publisher(EDGE_A)
    pub.start()
    try:
        assert _wait(lambda: len(pub.produced) >= 5)
        monkeypatch.setattr(handover, "read_subscriptions",
                            lambda edge, *a, **kw: [] if edge == EDGE_A else [("x", {"rn": "x"}, "y")])
        assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A), device=pub) is False
        n = len(pub.produced)
        assert _wait(lambda: len(pub.produced) >= n + 5)
    finally:
        pub.stop()
    assert pub.failed == [] and pub.edge == EDGE_A
    assert handover.read_samples(EDGE_A) == pub.produced
    assert _ae(EDGE_B)[0] == 404


# --- TD_MEC_HO_02 -------------------------------------------------------------------

def _downlink_setup(receiver_url):
    """Vehicle on A with a `commands` container it subscribes to as itself, and an operator
    allowed to write commands. Returns the operator's originator."""
    origin, base = handover.AE_ORIGIN, f"{EDGE_A[0]}/{EDGE_A[1]}/{handover.AE_NAME}"
    _attach_on_a(poa=[receiver_url])
    assert handover.create_container(EDGE_A, name=CMD)[0] == 201
    op = f"Cop-{uuid.uuid4().hex[:6]}"
    st, body, _ = req("POST", base, origin, ty=TY_ACP, body={"m2m:acp": {
        "rn": "operators",
        "pv": {"acr": [{"acor": [origin], "acop": 63},
                       {"acor": [op], "acop": CREATE | RETRIEVE | DISCOVER}]},
        "pvs": {"acr": [{"acor": [origin], "acop": 63}]}}})
    assert st == 201, body
    assert req("PUT", f"{base}/{CMD}", origin,
               body={"m2m:cnt": {"acpi": [body["m2m:acp"]["ri"]]}})[0] == 200
    st, body, _ = req("POST", f"{base}/{CMD}", origin, ty=TY_SUB, body={"m2m:sub": {
        "rn": "cmd-sub", "nu": [origin], "enc": {"net": [3]}, "nct": 1}})
    assert st == 201, body
    return op


def _command(op, value, edge=None):
    """The operator sends a command where the IN-CSE says the vehicle is served."""
    edge = edge or _route()[0]
    return req("POST", f"{edge[0]}/{edge[1]}/{handover.AE_NAME}/{CMD}", op, ty=4,
               body={"m2m:cin": {"con": value}})[0]


def _deliveries(receiver, value):
    return [n for n in receiver.got if (notified_cin(n) or {}).get("con") == value]


def _sub_ri(edge):
    st, body, _ = req("GET", f"{edge[0]}/{edge[1]}/{handover.AE_NAME}/{CMD}/cmd-sub", "CAdmin")
    assert st == 200
    return body["m2m:sub"]["ri"]


def test_td_mec_ho_02_downlink_and_subscriptions_after_handover(vehicle, receiver, monkeypatch):
    op = _downlink_setup(receiver.url)
    assert _command(op, "cmd-0") == 201
    assert receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == "cmd-0")
    real = handover.create_ae

    def during_prep(edge, *a, **kw):                    # HANDOVER_PREP: IN still names A
        if edge == EDGE_B:
            assert _route() == [EDGE_A]
            assert _command(op, "cmd-prep") == 201
        return real(edge, *a, **kw)

    monkeypatch.setattr(handover, "create_ae", during_prep)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert _route() == [EDGE_B]
    assert _command(op, "cmd-1") == 201                                                # step 1
    for v in ("cmd-prep", "cmd-1"):
        assert receiver.wait_for(lambda n, v=v: (notified_cin(n) or {}).get("con") == v), v
    time.sleep(2.0)                                     # room for a duplicate to show up
    counts = {v: len(_deliveries(receiver, v)) for v in ("cmd-0", "cmd-prep", "cmd-1")}
    assert counts == {"cmd-0": 1, "cmd-prep": 1, "cmd-1": 1}, counts                   # step 3
    b_sub = _sub_ri(EDGE_B)
    for v in ("cmd-prep", "cmd-1"):                                                    # step 2
        sur = _deliveries(receiver, v)[0]["m2m:sgn"]["sur"]
        assert sur.endswith(b_sub), f"{v} not delivered via the target's subscription: {sur}"
    assert _command(op, "cmd-2", edge=EDGE_A) == 404                                   # step 4
    assert [c for c in handover.read_samples(EDGE_B, cnt=CMD)] == ["cmd-0", "cmd-prep", "cmd-1"]
    assert handover.read_samples(EDGE_B) == SAMPLES


def test_td_mec_ho_02_control_source_drops_downlink_in_prep(vehicle, receiver):
    """With the AE unreachable (rr=false) the source does not deliver the command at all:
    the cmd-prep delivery above can only have come from the target."""
    op = _downlink_setup(receiver.url)
    assert handover.set_reachability(EDGE_A, False)[0] == 200
    assert _command(op, "cmd-dropped") == 201
    assert receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == "cmd-dropped",
                             timeout=3.0) == []


def test_td_mec_ho_02_control_late_device_subscription_loses_prep_command(vehicle, receiver, monkeypatch):
    """Ordering matters: subscribing the AE only after the catch-up loses cmd-prep."""
    op = _downlink_setup(receiver.url)
    real = handover.create_ae

    def during_prep(edge, *a, **kw):
        if edge == EDGE_B:
            assert _command(op, "cmd-prep") == 201
        return real(edge, *a, **kw)

    monkeypatch.setattr(handover, "create_ae", during_prep)
    real_sub = handover._subscribe
    calls = []

    def late(dst, subs):                                # first call (AE subs) deferred to the second
        calls.append(list(subs))
        if len(calls) == 1:
            return True
        return real_sub(dst, calls[0] + list(subs))

    monkeypatch.setattr(handover, "_subscribe", late)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == "cmd-prep",
                             timeout=3.0) == []
