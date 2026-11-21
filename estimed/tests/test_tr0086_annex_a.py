"""oneM2M TR-0086 Annex A (device workflow example), the 2026-10 draft, on the live stack.

The guide's GasTempSensorAE: three telemetry containers and a Command container, one <ACP> per container
(CommandWriteACP also admitting a trusted controller), a subscription on Command, a <group> over the telemetry,
readings, latest retrieval singly and through the group's fan-out point, and the downlink command flow (a controller's
command, and one the device raises itself). "The example applies to all deployment options": it runs on an MN-CSE
(options B-D) and directly on the IN-CSE (option A, no MN).

Where ACME 2026.5.3 differs from the guide's examples (asserted as ACME behaves, noted for the TR's authors):
  * A.2.9 the verification request's `sur` is the subscription's resource ID (/<csi>/<ri>), not the structured path
    the guide shows, and it carries `cr`; it is resolved here rather than compared as text;
  * A.2.5 the stored `mid` holds the members' resource IDs, not the structured paths posted;
  * A.2.8 each aggregated m2m:rsp carries rsc/rqi/rvi but no `to` (optional in TS-0004): a member is told apart by
    its content's `pi`, not by the `to` the guide's example shows;
  * A.2.4 a subscription whose callback cannot be reached fails at once (500), it does not "remain pending".
"""
from __future__ import annotations

import time
import uuid

import pytest

from conftest import EDGE_A, IN_CSE, TY_ACP, TY_AE, TY_CIN, TY_CNT, TY_SUB, notified_cin, req, rsc

TY_GRP = 9
CREATE = 1
TELEMETRY = {"TempContainer": "T=24.50", "HumidityContainer": "H=41.20", "GasContainer": "GAS=312"}
CONTAINERS = [*TELEMETRY, "Command"]
ACP_OF = {"TempContainer": "TempWriteACP", "HumidityContainer": "HumidityWriteACP",
          "GasContainer": "GasWriteACP", "Command": "CommandWriteACP"}


@pytest.fixture(params=[EDGE_A, IN_CSE], ids=["options-B-D-on-the-MN", "option-A-on-the-IN"])
def gastemp(request, topology):
    """A.2.1-A.2.3: the device registered, its four containers each under their own <ACP>."""
    edge = request.param
    name, tag = "GasTempSensorAE", uuid.uuid4().hex[:6]
    rn = f"{name}-{tag}"
    dev, ctl = f"CSensorGasTemp-{tag}", f"Cdashboard-{tag}"
    base = f"{edge[0]}/{edge[1]}"
    st, _, _ = req("POST", base, dev, ty=TY_AE, body={"m2m:ae": {"rn": rn, "api": "Nestimed.gastemp", "rr": True,
                                                                  "srv": ["3"]}})
    assert st == 201
    acp, cnt = {}, {}
    try:
        for c in CONTAINERS:
            st, body, _ = req("POST", f"{base}/{rn}", dev, ty=TY_CNT, body={"m2m:cnt": {"rn": c}})
            assert st == 201, (c, body)
            cnt[c] = body["m2m:cnt"]["ri"]
            rules = [{"acor": [dev], "acop": 63}] + ([{"acor": [ctl], "acop": CREATE}] if c == "Command" else [])
            st, body, _ = req("POST", f"{base}/{rn}", dev, ty=TY_ACP, body={"m2m:acp": {
                "rn": ACP_OF[c], "pv": {"acr": rules}, "pvs": {"acr": [{"acor": [dev], "acop": 63}]}}})
            assert st == 201, (c, body)
            acp[c] = body["m2m:acp"]["ri"]
            assert req("PUT", f"{base}/{rn}/{c}", dev, body={"m2m:cnt": {"acpi": [acp[c]]}})[0] == 200
        yield {"edge": edge, "base": base, "rn": rn, "ae": f"{base}/{rn}", "dev": dev, "ctl": ctl, "acp": acp, "cnt": cnt}
    finally:
        req("DELETE", f"{base}/{rn}", dev)
        req("DELETE", f"{base}/{rn}", "CAdmin")


def _write(g, c, con, origin=None):
    return req("POST", f"{g['ae']}/{c}", origin or g["dev"], ty=TY_CIN,
               body={"m2m:cin": {"cnf": "text/plain:0", "con": con}})[0]


def _command_sub(g, nu, rn="CommandSub"):
    return req("POST", f"{g['ae']}/Command", g["dev"], ty=TY_SUB,
               body={"m2m:sub": {"rn": rn, "nu": [nu], "nct": 1, "enc": {"net": [3]}}})


# --- A.2.1-A.2.3: containers, one policy each ------------------------------------------

def test_a_2_3_each_container_carries_its_own_policy(gastemp):
    g = gastemp
    for c in CONTAINERS:
        st, body, _ = req("GET", f"{g['ae']}/{c}", g["dev"])
        assert st == 200 and body["m2m:cnt"]["acpi"] == [g["acp"][c]], c
        assert _write(g, c, f"{c}=1") == 201, c


def test_a_2_2_control_policies_admit_only_whom_they_name(gastemp):
    """A stranger writes nowhere; the trusted controller writes Command and nothing else."""
    g = gastemp
    for c in CONTAINERS:
        assert _write(g, c, "x", origin=f"Cstranger-{uuid.uuid4().hex[:4]}") == 403, c
    for c in TELEMETRY:
        assert _write(g, c, "x", origin=g["ctl"]) == 403, c
    assert _write(g, "Command", "HEATER=ON", origin=g["ctl"]) == 201


# --- A.2.4 / A.2.9: the command subscription and its verification ----------------------

def test_a_2_4_command_subscription_is_verified_before_it_exists(gastemp, receiver):
    g = gastemp
    st, body, _ = _command_sub(g, receiver.url)
    assert st == 201, body
    first = next((n for n in receiver.got if n), {}).get("m2m:sgn", {})
    assert first.get("vrq") is True, receiver.got[:1]
    assert first.get("cr") == g["dev"]
    st, sub, _ = req("GET", f"{g['edge'][0]}/~{first['sur']}", g["dev"])
    assert st == 200 and sub["m2m:sub"]["rn"] == "CommandSub", (first["sur"], st)


def test_a_2_4_control_unreachable_callback_creates_no_subscription(gastemp):
    g = gastemp
    st, _, _ = _command_sub(g, "http://127.0.0.1:9/notify", rn="DeadSub")
    assert st != 201
    assert req("GET", f"{g['ae']}/Command/DeadSub", g["dev"])[0] == 404


def test_a_2_9_a_controllers_command_reaches_the_device(gastemp, receiver):
    g = gastemp
    assert _command_sub(g, receiver.url)[0] == 201
    assert _write(g, "Command", "HEATER=OFF", origin=g["ctl"]) == 201
    hits = receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == "HEATER=OFF")
    assert hits and hits[0]["m2m:sgn"]["nev"]["net"] == 3


def test_a_2_10_a_command_the_device_raises_itself_notifies_too(gastemp, receiver):
    g = gastemp
    assert _command_sub(g, receiver.url)[0] == 201
    assert _write(g, "Command", "HEATER=OFF") == 201
    assert receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == "HEATER=OFF")


def test_a_2_9_control_telemetry_does_not_reach_the_command_subscriber(gastemp, receiver):
    g = gastemp
    assert _command_sub(g, receiver.url)[0] == 201
    assert _write(g, "TempContainer", "T=99.00") == 201
    assert receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == "T=99.00", timeout=2.0) == []


# --- A.2.5-A.2.8: readings, latest, and the group's fan-out point -----------------------

def _group(g):
    mid = [f"{g['edge'][1]}/{g['rn']}/{c}" for c in TELEMETRY]
    st, body, h = req("POST", g["ae"], g["dev"], ty=TY_GRP, body={"m2m:grp": {"rn": "SensorGroup", "mid": mid,
                                                                             "mnm": len(mid)}})
    assert st == 201 and rsc(h) == 2001, body
    return body["m2m:grp"]


def _fan_out(g, origin=None):
    st, body, _ = req("GET", f"{g['ae']}/SensorGroup/fopt/la", origin or g["dev"])
    if st != 200:
        return st, None
    by_parent = {v: k for k, v in g["cnt"].items()}
    rsp = body["m2m:agr"]["m2m:rsp"]
    assert all(r["rsc"] == 2000 for r in rsp), rsp
    return st, {by_parent[r["pc"]["m2m:cin"]["pi"]]: r["pc"]["m2m:cin"]["con"] for r in rsp}


def test_a_2_7_latest_reading_of_one_container(gastemp):
    g = gastemp
    for c, v in TELEMETRY.items():
        assert _write(g, c, v) == 201
    st, body, _ = req("GET", f"{g['ae']}/TempContainer/la", g["dev"])
    assert st == 200 and body["m2m:cin"]["con"] == "T=24.50"


def test_a_2_8_latest_readings_of_all_members_in_one_request(gastemp):
    g = gastemp
    grp = _group(g)
    assert grp["cnm"] == 3 and sorted(grp["mid"]) == sorted(g["cnt"][c] for c in TELEMETRY), grp
    for c, v in TELEMETRY.items():
        assert _write(g, c, v) == 201
    assert _fan_out(g) == (200, TELEMETRY)
    assert _write(g, "TempContainer", "T=25.00") == 201
    time.sleep(0.05)
    assert _fan_out(g)[1]["TempContainer"] == "T=25.00", "control: the fan-out reads the members now, not a copy"


def test_a_2_8_control_a_stranger_cannot_read_through_the_group(gastemp):
    g = gastemp
    _group(g)
    for c, v in TELEMETRY.items():
        assert _write(g, c, v) == 201
    assert _fan_out(g, origin=f"Cstranger-{uuid.uuid4().hex[:4]}")[0] == 403
