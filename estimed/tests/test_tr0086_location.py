"""oneM2M TR-0086 5.6 (location-aware device) against the live stack.

5.6.5  device-provided location: a `location` container aged out by mni, read via
       <latest>, pushed to a subscriber
5.6.3 / 5.6.4  network-provided location through estimed/mec_ipe.py, the MEC-IPE that
       turns MEC 013 into oneM2M contentInstances, with its trust boundaries as controls

The subscription test here is also the positive control for the handover
subscription gap: it shows the receiver and ACME's notifications work, so the
handover test failing is about the handover, not the plumbing.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import uuid

import pytest

from conftest import (EDGE_A, EDGE_B, ESTIMED, IN_CSE, TY_ACP, TY_AE, TY_CIN, TY_CNT, TY_SUB, http,
                      notified_cin, req, rsc)


def _fix(i):
    return {"lat": 48.1351 + i / 1000, "lon": 11.5820 + i / 1000, "alt": 519.0,
            "accuracy": 5, "timestamp": f"2026-10-20T16:00:0{i}Z", "source": "GPS"}


@pytest.fixture
def located(ae):
    name, origin = ae
    base = f"{EDGE_A[0]}/{EDGE_A[1]}"
    assert req("POST", base, origin, ty=TY_AE, body={"m2m:ae": {
        "rn": name, "api": "Nestimed.vehicle", "rr": True, "srv": ["4"]}})[0] == 201
    st, _, _ = req("POST", f"{base}/{name}", origin, ty=TY_CNT,
                   body={"m2m:cnt": {"rn": "location", "mni": 3}})
    assert st == 201
    return f"{base}/{name}/location", origin


def _publish(url, origin, fix):
    return req("POST", url, origin, ty=TY_CIN,
               body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(fix)}})[0]


def test_5_6_5_latest_is_the_newest_fix(located):
    url, origin = located
    for i in range(2):
        assert _publish(url, origin, _fix(i)) == 201
    st, body, _ = req("GET", f"{url}/la", origin)
    assert st == 200 and json.loads(body["m2m:cin"]["con"]) == _fix(1)


def test_5_6_5_mni_ages_out_old_fixes(located):
    """Step 4: old instances are aged out by mni -- 5 published, the newest 3 kept."""
    url, origin = located
    for i in range(5):
        assert _publish(url, origin, _fix(i)) == 201
    st, body, _ = req("GET", url, origin)
    assert body["m2m:cnt"]["cni"] == 3
    st, body, _ = req("GET", f"{url}/ol", origin)
    assert json.loads(body["m2m:cin"]["con"]) == _fix(2)


def test_5_6_5_control_without_mni_nothing_ages_out(ae):
    name, origin = ae
    base = f"{EDGE_A[0]}/{EDGE_A[1]}"
    assert req("POST", base, origin, ty=TY_AE, body={"m2m:ae": {
        "rn": name, "api": "Nestimed.vehicle", "rr": True, "srv": ["4"]}})[0] == 201
    assert req("POST", f"{base}/{name}", origin, ty=TY_CNT,
               body={"m2m:cnt": {"rn": "location"}})[0] == 201
    for i in range(5):
        assert _publish(f"{base}/{name}/location", origin, _fix(i)) == 201
    st, body, _ = req("GET", f"{base}/{name}/location", origin)
    assert body["m2m:cnt"]["cni"] == 5


def test_5_6_5_subscriber_receives_each_fix(located, receiver):
    """Step 5: a <subscription> on `location` notifies on every new fix."""
    url, origin = located
    st, body, _ = req("POST", url, origin, ty=TY_SUB, body={"m2m:sub": {
        "rn": "cloud-app", "nu": [receiver.url], "enc": {"net": [3]}, "nct": 1}})
    assert st == 201, body
    assert _publish(url, origin, _fix(7)) == 201
    hits = receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == json.dumps(_fix(7)))
    assert hits, receiver.got


def test_5_6_5_control_no_notification_for_other_containers(located, receiver):
    """The subscription is scoped: a write elsewhere under the AE does not notify."""
    url, origin = located
    assert req("POST", url, origin, ty=TY_SUB, body={"m2m:sub": {
        "rn": "cloud-app", "nu": [receiver.url], "enc": {"net": [3]}, "nct": 1}})[0] == 201
    ae_url = url.rsplit("/", 1)[0]
    assert req("POST", ae_url, origin, ty=TY_CNT, body={"m2m:cnt": {"rn": "other"}})[0] == 201
    assert _publish(f"{ae_url}/other", origin, _fix(8)) == 201
    events = receiver.wait_for(lambda n: "nev" in n.get("m2m:sgn", {}), timeout=3.0)
    assert events == [], "a write outside `location` produced a notification"


# --- 5.6.3 / 5.6.4: network-provided location through the MEC-IPE (estimed/mec_ipe.py) ------

IPE_PORT = 8410
OPERATOR = "Cin-ops"                       # non-admin: ACME's CAdmin bypasses every ACP
IPE_BASE = f"{EDGE_A[0]}/{EDGE_A[1]}/mec-ipe"
MEC013 = "http://127.0.0.1:8101/location/v3"


@pytest.fixture(scope="module")
def ipe(topology, tmp_path_factory):
    if http("GET", f"{MEC013}/queries/users")[0] != 200:
        pytest.fail("MEC 013 candidate not answering on :8101 (mec013_look/candidate.py)",
                    pytrace=False)
    # A leftover IPE on the port would answer for this one and be tested instead.
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", IPE_PORT)) == 0:
            pytest.fail(f"something already listens on :{IPE_PORT}; stop it first", pytrace=False)
    log_path = tmp_path_factory.mktemp("ipe") / "mec_ipe.log"
    log = log_path.open("w")      # a file, not a pipe: an unread pipe would block the IPE
    proc = subprocess.Popen([sys.executable, str(ESTIMED / "mec_ipe.py"), "--edge", "a",
                             "--port", str(IPE_PORT), "--operator", OPERATOR],
                            cwd=str(ESTIMED), stdout=log, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    for _ in range(50):
        if req("GET", IPE_BASE, "Cmec-ipe")[0] == 200 and \
                req("GET", f"{IPE_BASE}/location-requests/ipe", "Cmec-ipe")[0] == 200:
            break
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail(f"MEC-IPE did not register: {log_path.read_text()}", pytrace=False)
    yield proc
    proc.terminate()
    proc.wait(timeout=10)
    log.close()
    assert req("GET", IPE_BASE, "Cmec-ipe")[0] == 404, "the IPE must deregister on SIGTERM"


def _device(ae, grant_ipe=True, edge=EDGE_A):
    """A device AE whose `location` container lets the IPE create contentInstances and read the container itself
    (or neither). The IPE reads it to check that the container belongs to the requesting device (W01, 2026-10-29)."""
    name, origin = ae
    base = f"{edge[0]}/{edge[1]}"
    assert req("POST", base, origin, ty=TY_AE, body={"m2m:ae": {
        "rn": name, "api": "Nestimed.vehicle", "rr": True, "srv": ["4"]}})[0] == 201
    cnt = {"rn": "location"}
    if grant_ipe:
        st, body, _ = req("POST", f"{base}/{name}", origin, ty=TY_ACP, body={"m2m:acp": {
            "rn": "ipe-writes",
            "pv": {"acr": [{"acor": [origin], "acop": 63},
                           {"acor": ["Cmec-ipe"], "acop": 1, "acod": [{"chty": [TY_CIN]}]},
                           {"acor": ["Cmec-ipe"], "acop": 2}]},
            "pvs": {"acr": [{"acor": [origin], "acop": 63}]}}})
        assert st == 201, body
        cnt["acpi"] = [body["m2m:acp"]["ri"]]
    assert req("POST", f"{base}/{name}", origin, ty=TY_CNT, body={"m2m:cnt": cnt})[0] == 201
    return name, origin, f"{edge[1]}/{name}/location"


def _register_ue(ae_id, ue, origin=OPERATOR, ipe_base=IPE_BASE):
    return req("POST", f"{ipe_base}/ue-registry", origin, ty=TY_CIN, body={"m2m:cin": {
        "con": json.dumps({"aeId": ae_id, "ueIdentity": ue})}})


def _device_request(origin, ae_id, target, period=1, count=2, ipe_base=IPE_BASE):
    return req("POST", f"{ipe_base}/location-requests", origin, ty=TY_CIN, body={"m2m:cin": {
        "cr": None, "con": json.dumps({"aeId": ae_id, "targetContainer": target,
                                       "notificationPeriod": period, "count": count})}})


def _reports(target, origin, want, timeout=8.0, host=EDGE_A[0]):
    end = time.time() + timeout
    while time.time() < end:
        st, body, _ = req("GET", f"{host}/{target}", origin)
        if st == 200 and body["m2m:cnt"]["cni"] >= want:
            return body["m2m:cnt"]["cni"]
        time.sleep(0.2)
    st, body, _ = req("GET", f"{host}/{target}", origin)
    return body["m2m:cnt"]["cni"] if st == 200 else None


def _mec013_truth(ue):
    st, body = http("GET", f"{MEC013}/queries/users?address={ue}")
    assert st == 200
    return body["user"][0]


def test_5_6_3_mec_ipe_is_registered_on_the_mn(ipe):
    st, body, _ = req("GET", f"{EDGE_A[0]}/{EDGE_A[1]}?fu=1&ty={TY_AE}&lbl=role:mec-ipe", "CAdmin")
    assert st == 200 and len(body["m2m:uril"]) == 1
    st, body, _ = req("GET", IPE_BASE, "Cmec-ipe")
    assert body["m2m:ae"]["poa"] == [f"http://127.0.0.1:{IPE_PORT}"]


def test_5_6_4_device_receives_its_network_location(ipe, ae):
    name, origin, target = _device(ae)
    assert _register_ue(origin, "acr:10.0.0.4")[0] == 201
    assert _device_request(origin, origin, target)[0] == 201
    assert _reports(target, origin, 2) == 2
    st, body, _ = req("GET", f"{EDGE_A[0]}/{target}/la", origin)
    fix = json.loads(body["m2m:cin"]["con"])
    truth = _mec013_truth("acr:10.0.0.4")                 # read MEC 013 independently
    assert fix["source"] == "MEC013" and fix["ueIdentity"] == "acr:10.0.0.4"
    assert (fix["zoneId"], fix["accessPointId"]) == (truth["zoneId"], truth["accessPointId"])
    assert (fix["lat"], fix["lon"]) == (truth["locationInfo"]["latitude"],
                                        truth["locationInfo"]["longitude"])


def test_5_6_4_control_request_for_another_ae_is_refused(ipe, ae):
    """A device may only ask for itself: cr must equal the aeId it names."""
    name, origin, target = _device(ae)
    assert _register_ue("Cvictim", "acr:10.0.0.1")[0] == 201
    assert _device_request(origin, "Cvictim", target)[0] == 201
    assert _reports(target, origin, 1, timeout=3.0) == 0


def test_5_6_4_control_unregistered_ae_gets_nothing(ipe, ae):
    name, origin, target = _device(ae)
    assert _device_request(origin, origin, target)[0] == 201
    assert _reports(target, origin, 1, timeout=3.0) == 0


def test_5_6_4_control_ipe_cannot_write_without_the_device_grant(ipe, ae):
    name, origin, target = _device(ae, grant_ipe=False)
    assert _register_ue(origin, "acr:10.0.0.4")[0] == 201
    assert _device_request(origin, origin, target)[0] == 201
    assert _reports(target, origin, 1, timeout=3.0) == 0


def test_5_6_4_control_device_cannot_write_the_ue_registry(ipe, ae):
    """The registry is the trust anchor: a device that could write it could locate anyone."""
    name, origin, target = _device(ae)
    st, _, h = _register_ue(origin, "acr:10.0.0.1", origin=origin)
    assert st == 403 and rsc(h) == 4103


def test_5_6_3_operator_configures_location_for_a_device(ipe, ae):
    name, origin, target = _device(ae)
    st, _, _ = req("POST", f"{IPE_BASE}/location", OPERATOR, ty=TY_CIN, body={"m2m:cin": {
        "con": json.dumps({"ueIdentity": "acr:10.0.0.1", "notificationUri": target,
                           "notificationPeriod": 1, "count": 1})}})
    assert st == 201
    assert _reports(target, origin, 1) == 1
    st, body, _ = req("GET", f"{EDGE_A[0]}/{target}/la", origin)
    fix = json.loads(body["m2m:cin"]["con"])
    assert (fix["ueIdentity"], fix["zoneId"]) == ("acr:10.0.0.1", "zone002")


def test_5_6_3_control_device_cannot_configure_the_operator_path(ipe, ae):
    name, origin, target = _device(ae)
    st, _, h = req("POST", f"{IPE_BASE}/location", origin, ty=TY_CIN, body={"m2m:cin": {
        "con": json.dumps({"ueIdentity": "acr:10.0.0.1", "notificationUri": target,
                           "notificationPeriod": 1})}})
    assert st == 403 and rsc(h) == 4103


def test_5_6_4_period_zero_cancels_reports(ipe, ae):
    name, origin, target = _device(ae)
    assert _register_ue(origin, "acr:10.0.0.3")[0] == 201
    assert _device_request(origin, origin, target, period=1, count=0)[0] == 201
    assert _reports(target, origin, 1) >= 1
    assert _device_request(origin, origin, target, period=0, count=0)[0] == 201
    time.sleep(0.5)                                       # a report already in flight may land
    settled = _reports(target, origin, 0)
    time.sleep(2.5)
    assert _reports(target, origin, 0) == settled, "reports continued after cancellation"


def test_5_6_4_control_device_cannot_cancel_another_devices_stream(ipe, ae):
    """Streams are per requester: a cancel naming someone else's container changes nothing."""
    name, origin, target = _device(ae)
    assert _register_ue(origin, "acr:10.0.0.3")[0] == 201
    assert _device_request(origin, origin, target, period=1, count=0)[0] == 201
    assert _reports(target, origin, 1) >= 1

    attacker = f"Cattacker-{uuid.uuid4().hex[:6]}"
    assert _register_ue(attacker, "acr:10.0.0.2")[0] == 201
    assert req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}", attacker, ty=TY_AE, body={"m2m:ae": {
        "rn": attacker[1:], "api": "Nattacker", "rr": True, "srv": ["4"]}})[0] == 201
    try:
        assert _device_request(attacker, attacker, target, period=0, count=0)[0] == 201
        before = _reports(target, origin, 0)
        assert _reports(target, origin, before + 2, timeout=6.0) >= before + 2, \
            "the victim's reports stopped after another device's cancel"
    finally:
        req("DELETE", f"{EDGE_A[0]}/{EDGE_A[1]}/{attacker[1:]}", attacker)
        _device_request(origin, origin, target, period=0, count=0)


# --- TR-0086 5.2.4.6.1 option A: no MN-CSE, the MEC-IPE registers directly with the IN over Mca ----------------------
# By construction option A keeps the device's network location on the IN-CSE; the PoC does not use it for that reason
# (the PoC's data-sources rule: positions never reach the city). Fixture UEs only (mec013_look).

IN_IPE_PORT = 8411
IN_IPE_BASE = f"{IN_CSE[0]}/{IN_CSE[1]}/mec-ipe"


@pytest.fixture(scope="module")
def ipe_on_in(topology, tmp_path_factory):
    if http("GET", f"{MEC013}/queries/users")[0] != 200:
        pytest.fail("MEC 013 candidate not answering on :8101 (mec013_look/candidate.py)", pytrace=False)
    with socket.socket() as s:
        if s.connect_ex(("127.0.0.1", IN_IPE_PORT)) == 0:
            pytest.fail(f"something already listens on :{IN_IPE_PORT}; stop it first", pytrace=False)
    log_path = tmp_path_factory.mktemp("ipe-in") / "mec_ipe.log"
    log = log_path.open("w")
    proc = subprocess.Popen([sys.executable, str(ESTIMED / "mec_ipe.py"), "--edge", "in",
                             "--port", str(IN_IPE_PORT), "--operator", OPERATOR],
                            cwd=str(ESTIMED), stdout=log, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    for _ in range(50):
        if req("GET", f"{IN_IPE_BASE}/location-requests/ipe", "Cmec-ipe")[0] == 200:
            break
        time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail(f"MEC-IPE did not register on the IN: {log_path.read_text()}", pytrace=False)
    yield proc
    proc.terminate()
    proc.wait(timeout=10)
    log.close()
    assert req("GET", IN_IPE_BASE, "Cmec-ipe")[0] == 404, "the IPE must deregister from the IN on SIGTERM"


@pytest.fixture
def ae_on_in(topology):
    name = f"tr86a-{uuid.uuid4().hex[:8]}"
    origin = f"C{name}"
    yield name, origin
    req("DELETE", f"{IN_CSE[0]}/{IN_CSE[1]}/{name}", origin)
    req("DELETE", f"{IN_CSE[0]}/{IN_CSE[1]}/{name}", "CAdmin")


def test_5_2_4_6_1_option_a_ipe_registers_on_the_in_only(ipe_on_in):
    st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}?fu=1&ty={TY_AE}&lbl=role:mec-ipe", "CAdmin")
    assert st == 200 and body["m2m:uril"] == [f"{IN_CSE[1]}/mec-ipe"], body
    st, body, _ = req("GET", IN_IPE_BASE, "Cmec-ipe")
    assert body["m2m:ae"]["poa"] == [f"http://127.0.0.1:{IN_IPE_PORT}"], "the IN's IPE is this process"
    # control: MN-B, which no fixture gives an IPE, has none (MN-A may hold the module's option-B IPE)
    st, body, _ = req("GET", f"{EDGE_B[0]}/{EDGE_B[1]}?fu=1&ty={TY_AE}&lbl=role:mec-ipe", "CAdmin")
    assert st == 200 and body["m2m:uril"] == [], body


def test_5_2_4_6_1_option_a_device_on_the_in_receives_its_network_location(ipe_on_in, ae_on_in):
    name, origin, target = _device(ae_on_in, edge=IN_CSE)
    assert _register_ue(origin, "acr:10.0.0.4", ipe_base=IN_IPE_BASE)[0] == 201
    assert _device_request(origin, origin, target, ipe_base=IN_IPE_BASE)[0] == 201
    assert _reports(target, origin, 2, host=IN_CSE[0]) == 2
    st, body, _ = req("GET", f"{IN_CSE[0]}/{target}/la", origin)
    fix = json.loads(body["m2m:cin"]["con"])
    truth = _mec013_truth("acr:10.0.0.4")
    assert fix["source"] == "MEC013" and (fix["zoneId"], fix["accessPointId"]) == (truth["zoneId"], truth["accessPointId"])


def test_5_2_4_6_1_option_a_control_device_cannot_write_the_ue_registry(ipe_on_in, ae_on_in):
    name, origin, target = _device(ae_on_in, edge=IN_CSE)
    st, _, h = _register_ue(origin, "acr:10.0.0.1", origin=origin, ipe_base=IN_IPE_BASE)
    assert st == 403 and rsc(h) == 4103


# --- W01: a device's stream goes only into a container of that device (2026-10-29) -------------------------------
# The IPE checked that a request's creator is the aeId it names, never that targetContainer belongs to that AE: a
# registered device could have its own location written into another device's container (one that grants the IPE
# write), and that device's readers saw the wrong position.

def _second_device(name_prefix):
    name = f"{name_prefix}-{uuid.uuid4().hex[:6]}"
    return name, f"C{name}"


def _drop(name, origin, edge=EDGE_A):
    req("DELETE", f"{edge[0]}/{edge[1]}/{name}", origin)
    req("DELETE", f"{edge[0]}/{edge[1]}/{name}", "CAdmin")


def test_5_6_4_control_request_into_another_devices_container_is_refused(ipe, ae):
    victim, victim_origin, victim_target = _device(ae)
    attacker = _second_device("tr86-att")
    try:
        _device(attacker)
        assert _register_ue(attacker[1], "acr:10.0.0.4")[0] == 201
        assert _device_request(attacker[1], attacker[1], victim_target)[0] == 201
        assert _reports(victim_target, victim_origin, 1, timeout=3.0) == 0, \
            "the attacker's stream was written into the victim's container"
    finally:
        _drop(*attacker)


def test_5_6_4_control_the_same_requester_is_served_into_its_own_container(ipe):
    """The refusal above is about the target: the same kind of requester is served into its own container."""
    attacker = _second_device("tr86-own")
    try:
        name, origin, target = _device(attacker)
        assert _register_ue(origin, "acr:10.0.0.4")[0] == 201
        assert _device_request(origin, origin, target)[0] == 201
        assert _reports(target, origin, 2) == 2
    finally:
        _drop(*attacker)


# --- U04: a second MEC-IPE does not evict a live one (2026-10-29) ---------------------------------------------------
# register() deleted whatever AE held mec-ipe before creating its own, so a second start silently took a running
# IPE's AE, policies and subscriptions away. A live AE (its poa answers) is refused; a stale one is still replaced.

B_IPE_BASE = f"{EDGE_B[0]}/{EDGE_B[1]}/mec-ipe"


def _start_ipe(edge_flag, port, log_dir):
    log = (log_dir / f"ipe-{port}.log").open("w")
    proc = subprocess.Popen([sys.executable, str(ESTIMED / "mec_ipe.py"), "--edge", edge_flag, "--port", str(port),
                             "--operator", OPERATOR], cwd=str(ESTIMED), stdout=log, stderr=subprocess.STDOUT, text=True,
                            start_new_session=True)
    return proc, log


def _ae_on_b():
    st, body, _ = req("GET", B_IPE_BASE, "Cmec-ipe")
    return body["m2m:ae"] if st == 200 else None


@pytest.fixture
def ipes_on_b(topology, tmp_path):
    if http("GET", f"{MEC013}/queries/users")[0] != 200:
        pytest.fail("MEC 013 candidate not answering on :8101 (mec013_look/candidate.py)", pytrace=False)
    for port in (8412, 8413):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                pytest.fail(f"something already listens on :{port}; stop it first", pytrace=False)
    started = []

    def start(port):
        proc, log = _start_ipe("b", port, tmp_path)
        started.append((proc, log))
        return proc
    yield start
    for proc, log in started:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        log.close()
    req("DELETE", B_IPE_BASE, "Cmec-ipe")


def _wait_registered(port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        a = _ae_on_b()
        if a and a.get("poa") == [f"http://127.0.0.1:{port}"] and \
                req("GET", f"{B_IPE_BASE}/location-requests/ipe", "Cmec-ipe")[0] == 200:
            return a
        time.sleep(0.2)
    return None


def test_u04_a_second_ipe_does_not_evict_a_live_one(ipes_on_b, ae, tmp_path):
    first = ipes_on_b(8412)
    before = _wait_registered(8412)
    assert before, "IPE#1 did not register on MN-B"
    second = ipes_on_b(8413)
    assert second.wait(timeout=10) != 0, "IPE#2 must refuse to start while IPE#1 is live"
    assert "live" in (tmp_path / "ipe-8413.log").read_text()
    after = _ae_on_b()
    assert after and (after["ri"], after["ct"], after["poa"]) == (before["ri"], before["ct"], before["poa"]), after
    assert first.poll() is None
    name, origin, target = _device(ae, edge=EDGE_B)
    assert _register_ue(origin, "acr:10.0.0.4", ipe_base=B_IPE_BASE)[0] == 201
    assert _device_request(origin, origin, target, ipe_base=B_IPE_BASE)[0] == 201
    assert _reports(target, origin, 2, host=EDGE_B[0]) == 2, "IPE#1 must still serve after IPE#2 was refused"


def test_u04_control_a_stale_ipe_is_replaced(ipes_on_b):
    first = ipes_on_b(8412)
    assert _wait_registered(8412)
    first.kill()                                       # no deregistration: its AE stays, nothing answers its poa
    first.wait(timeout=10)
    ipes_on_b(8413)
    assert _wait_registered(8413), "a stale IPE AE must still be replaced"
