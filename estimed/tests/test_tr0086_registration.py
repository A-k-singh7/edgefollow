"""oneM2M TR-0086 (developer guide, draft v0.0.1 2026-06-05) 5.2 and 5.3 against the live stack.

5.2  start the CSEs and register each MN-CSE to the IN-CSE
5.3  register a device AE to an MN-CSE and publish telemetry

Each positive check has a control beside it that must come out the other way, so a
check that passes on everything shows up as a failing control.
"""
from __future__ import annotations

import json

from conftest import (CSI, EDGE_A, EDGE_B, IN_CSE, TY_AE, TY_CIN, TY_CNT, TY_CSEBASE,
                      TY_CSR, req, rsc)


# --- 5.2 Step 1 / Step 3: every CSEBase answers --------------------------------------

def test_5_2_every_csebase_is_reachable(topology):
    for edge in (IN_CSE, EDGE_A, EDGE_B):
        st, body, h = req("GET", f"{edge[0]}/{edge[1]}", "CAdmin")
        assert st == 200 and rsc(h) == 2000, edge
        cb = body["m2m:cb"]
        assert cb["ty"] == TY_CSEBASE
        assert cb["csi"] == f"/{CSI[edge]}"


def test_5_2_control_unknown_csebase_is_not_found(topology):
    st, _, h = req("GET", f"{IN_CSE[0]}/no-such-cse", "CAdmin")
    assert st == 404 and rsc(h) == 4004


# --- 5.2 Step 3 / Step 4.4: the IN-CSE holds a <remoteCSE> per MN-CSE -----------------

def test_5_2_in_cse_holds_remotecse_for_each_mn(topology):
    for edge in (EDGE_A, EDGE_B):
        st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/{CSI[edge]}", "CAdmin")
        assert st == 200, edge
        csr = body["m2m:csr"]
        assert csr["ty"] == TY_CSR
        assert csr["csi"] == f"/{CSI[edge]}"
        assert csr["poa"] == [edge[0]], "point of access must be the MN-CSE's own address"
        assert csr["rr"] is True


def test_5_2_control_unregistered_csi_has_no_remotecse(topology):
    st, _, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/id-mn-zz", "CAdmin")
    assert st == 404


def test_5_2_each_mn_holds_remotecse_for_the_in(topology):
    """Mcc registration is mutual: the MN-CSE also keeps a <remoteCSE> for its registrar."""
    for edge in (EDGE_A, EDGE_B):
        st, body, _ = req("GET", f"{edge[0]}/{edge[1]}/{CSI[IN_CSE]}", "CAdmin")
        assert st == 200, edge
        assert body["m2m:csr"]["csi"] == f"/{CSI[IN_CSE]}"


# --- 5.3 Step 1: AE registration --------------------------------------------------------

def _register(edge, name, origin, **extra):
    attrs = {"rn": name, "api": "Nestimed.device.v1", "rr": True, "srv": ["4"]} | extra
    return req("POST", f"{edge[0]}/{edge[1]}", origin, ty=TY_AE, body={"m2m:ae": attrs})


def test_5_3_ae_registration_assigns_aei(ae):
    name, origin = ae
    st, body, h = _register(EDGE_A, name, origin)
    assert st == 201 and rsc(h) == 2001
    a = body["m2m:ae"]
    assert a["rn"] == name
    assert a["aei"] == origin, "a C-originator keeps its own AE-ID (TS-0001 7.2)"
    assert a["api"] == "Nestimed.device.v1"
    assert a["rr"] is True


def test_5_3_control_duplicate_registration_is_refused(ae):
    """A second AE create with the same originator must not yield a second AE.

    ACME answers 403/4105 (originator already registered) rather than 409.
    """
    name, origin = ae
    assert _register(EDGE_A, name, origin)[0] == 201
    st, _, h = _register(EDGE_A, name + "-twin", origin)
    assert st in (403, 409) and rsc(h) in (4105, 4117), (st, rsc(h))


def test_5_3_control_api_without_n_or_r_prefix_is_refused(ae):
    """TS-0001: App-ID starts with 'R' (registered) or 'N' (non-registered)."""
    name, origin = ae
    st, _, h = _register(EDGE_A, name, origin, api="estimed.device.v1")
    assert st == 400 and rsc(h) == 4000, (st, rsc(h))


# --- 5.3 Steps 2-4: container, telemetry, <latest> --------------------------------------

def test_5_3_telemetry_round_trip_through_latest(ae):
    name, origin = ae
    base = f"{EDGE_A[0]}/{EDGE_A[1]}/{name}"
    assert _register(EDGE_A, name, origin)[0] == 201
    st, _, _ = req("POST", base, origin, ty=TY_CNT, body={"m2m:cnt": {"rn": "telemetry"}})
    assert st == 201
    samples = [{"seq": i, "speed_kmh": 40 + i} for i in range(3)]
    for s in samples:
        st, _, _ = req("POST", f"{base}/telemetry", origin, ty=TY_CIN,
                       body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(s)}})
        assert st == 201
    st, body, _ = req("GET", f"{base}/telemetry/la", origin)
    assert st == 200
    assert json.loads(body["m2m:cin"]["con"]) == samples[-1]
    st, body, _ = req("GET", f"{base}/telemetry/ol", origin)
    assert json.loads(body["m2m:cin"]["con"]) == samples[0]
    st, body, _ = req("GET", f"{base}/telemetry", origin)
    assert body["m2m:cnt"]["cni"] == 3


def test_5_3_control_latest_of_empty_container_is_not_found(ae):
    name, origin = ae
    base = f"{EDGE_A[0]}/{EDGE_A[1]}/{name}"
    assert _register(EDGE_A, name, origin)[0] == 201
    assert req("POST", base, origin, ty=TY_CNT, body={"m2m:cnt": {"rn": "telemetry"}})[0] == 201
    st, _, _ = req("GET", f"{base}/telemetry/la", origin)
    assert st == 404


def test_5_3_control_cin_under_missing_container_is_not_found(ae):
    name, origin = ae
    assert _register(EDGE_A, name, origin)[0] == 201
    st, _, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}/nope", origin, ty=TY_CIN,
                   body={"m2m:cin": {"con": "x"}})
    assert st == 404
