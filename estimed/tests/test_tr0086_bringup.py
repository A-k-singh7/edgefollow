"""oneM2M TR-0086 5.2.4 (bring up the CSEs and the MEC platform), the checks the 2026-10 draft adds, on the live stack.

Draft: the TR-0086 device-registration branch of ESTIMED/WP6/TR-0086, read 2026-10-29. Each check the guide asks a
developer to run is asserted here with a control that must come out the other way:

    5.2.4.1.5  a well-formed oneM2M GET reaches the IN; a plain HTTP GET without the oneM2M headers is rejected
    5.2.4.3.4  MEC 011 checks 1-2: timing/current_time and the service list answer 200
    5.2.4.4    the IN reports cst 1 and every MN-CSE cst 2 (a CSE reporting cst 1 at an MN's place is an IN)
    5.2.4.5    the IN discovers one <remoteCSE> (ty=16) per MN, named after the MN's CSE-ID; the reciprocal one exists
               at each MN; and the IN reaches each MN over the advertised poa

Lab note on 5.2.4.5's poa rule ("a loopback poa means the IN cannot reach the MN"): this lab runs every CSE on one
host, so a loopback poa IS reachable here; the reachability itself is what test_5_2_4_5_in_reaches_each_mn_over_its_poa
asserts. A multi-host deployment needs a routable cseHost, as the guide says.
"""
from __future__ import annotations

import urllib.error
import urllib.request
import uuid

import pytest

from conftest import CSI, EDGE_A, EDGE_B, IN_CSE, TY_ACP, TY_AE, TY_CSR, http, req, rsc

MNS = (EDGE_A, EDGE_B)
RETRIEVE = 2


def _plain_get(url: str, headers: dict) -> int:
    r = urllib.request.Request(url, headers={"Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code


def _cb(edge) -> dict:
    st, body, h = req("GET", f"{edge[0]}/{edge[1]}", "CAdmin")
    assert st == 200 and rsc(h) == 2000, edge
    return body["m2m:cb"]


# --- 5.2.4.1.5: reachability needs a well-formed oneM2M request ----------------------

@pytest.mark.parametrize("headers", [{}, {"X-M2M-Origin": "CAdmin"}, {"X-M2M-Origin": "CAdmin", "X-M2M-RVI": "3"}],
                         ids=["no-onem2m-headers", "origin-only", "no-request-id"])
def test_5_2_4_1_5_plain_get_is_rejected(topology, headers):
    """A plain GET does not demonstrate reachability: ACME refuses it (400: the request identifier is mandatory)."""
    assert _plain_get(f"{IN_CSE[0]}/{IN_CSE[1]}", headers) == 400


def test_5_2_4_1_5_control_well_formed_get_reaches_the_in(topology):
    """The same URL with Origin, RI and RVI (the guide's three headers) answers 200 / 2000."""
    assert _plain_get(f"{IN_CSE[0]}/{IN_CSE[1]}", {"X-M2M-Origin": "CAdmin", "X-M2M-RI": "check01",
                                                   "X-M2M-RVI": "3"}) == 200


# --- 5.2.4.3.4: MEC 011 verification checks 1 and 2 -----------------------------------

def test_5_2_4_3_4_mec011_checks(mec011):
    st, body = http("GET", f"{mec011}/timing/current_time")
    assert st == 200 and isinstance(body.get("seconds"), int) and "timeSourceStatus" in body, body
    st, body = http("GET", mec011.replace("mec_app_support/v2", "mec_service_mgmt/v1") + "/services")
    assert st == 200 and isinstance(body, list), (st, body)


# --- 5.2.4.4: the CSE type ------------------------------------------------------------

def test_5_2_4_4_every_mn_reports_cst_2(topology):
    for edge in MNS:
        assert _cb(edge)["cst"] == 2, f"{edge[1]} is not a middle node"


def test_5_2_4_4_control_the_in_reports_cst_1(topology):
    """The check distinguishes: the IN's own CSEBase is cst 1, so an IN at an MN's place would be caught."""
    assert _cb(IN_CSE)["cst"] == 1


# --- 5.2.4.5: Mcc registration ----------------------------------------------------------

def _discover_csr(edge) -> list[str]:
    st, body, h = req("GET", f"{edge[0]}/{edge[1]}?fu=1&ty={TY_CSR}", "CAdmin")
    assert st == 200 and rsc(h) == 2000, edge
    return sorted(body.get("m2m:uril", []))


def test_5_2_4_5_in_discovers_one_remotecse_per_mn(topology):
    assert _discover_csr(IN_CSE) == sorted(f"{IN_CSE[1]}/{CSI[e]}" for e in MNS)


def test_5_2_4_5_remotecse_is_named_after_the_cse_id(topology):
    """'The resource is named after the CSE-ID of the registree, not after its CSEBase name.'"""
    for edge in MNS:
        st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/{CSI[edge]}", "CAdmin")
        assert st == 200, edge
        csr = body["m2m:csr"]
        assert (csr["rn"], csr["csi"], csr["cb"], csr["cst"]) == (CSI[edge], f"/{CSI[edge]}",
                                                                  f"/{CSI[edge]}/{edge[1]}", 2), csr


def test_5_2_4_5_control_no_remotecse_under_the_csebase_name(topology):
    for edge in MNS:
        assert req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/{edge[1]}", "CAdmin")[0] == 404, edge


def test_5_2_4_5_reciprocal_remotecse_at_each_mn(topology):
    for edge in MNS:
        assert _discover_csr(edge) == [f"{edge[1]}/{CSI[IN_CSE]}"], edge
        st, body, _ = req("GET", f"{edge[0]}/{edge[1]}/{CSI[IN_CSE]}", "CAdmin")
        csr = body["m2m:csr"]
        assert st == 200 and (csr["cst"], csr["cb"]) == (1, f"/{CSI[IN_CSE]}/{IN_CSE[1]}"), csr


def test_5_2_4_5_in_reaches_each_mn_over_its_poa(topology):
    """The IN forwards over Mcc to the poa it holds. Shown on a resource only that MN has: a probe AE whose policy
    grants exactly the forwarded IN admin (/id-in/CAdmin), read back by name through the IN."""
    forwarded = f"/{CSI[IN_CSE]}/CAdmin"
    for edge in MNS:
        name = f"bringup-{uuid.uuid4().hex[:8]}"
        base = f"{edge[0]}/{edge[1]}"
        st, body, _ = req("POST", base, "CAdmin", ty=TY_ACP, body={"m2m:acp": {
            "rn": f"{name}-acp", "pv": {"acr": [{"acor": [forwarded], "acop": RETRIEVE}]},
            "pvs": {"acr": [{"acor": ["CAdmin"], "acop": 63}]}}})
        assert st == 201, body
        try:
            st, _, _ = req("POST", base, f"C{name}", ty=TY_AE, body={"m2m:ae": {
                "rn": name, "api": "Nestimed.bringup", "rr": False, "srv": ["3"], "acpi": [body["m2m:acp"]["ri"]]}})
            assert st == 201
            st, got, h = req("GET", f"{IN_CSE[0]}/~/{CSI[edge]}/{edge[1]}/{name}", "CAdmin")
            assert st == 200 and rsc(h) == 2000 and got["m2m:ae"]["rn"] == name, (edge, st, got)
            assert req("GET", f"{IN_CSE[0]}/~/{CSI[edge]}/{edge[1]}/{name}", "Cstranger")[0] == 403, \
                "control: the policy is what admits the forwarded request"
        finally:
            req("DELETE", f"{base}/{name}", "CAdmin")
            req("DELETE", f"{base}/{name}-acp", "CAdmin")


def test_5_2_4_5_control_the_ins_admin_is_not_the_mns_admin(topology):
    """Forwarded, the IN's CAdmin arrives as /id-in/CAdmin: the MN refuses it a RETRIEVE of its CSEBase. Without
    this, 'reachable' above could be any CSE answering anything."""
    for edge in MNS:
        st, _, h = req("GET", f"{IN_CSE[0]}/~/{CSI[edge]}/{edge[1]}", "CAdmin")
        assert st == 403 and rsc(h) == 4103, (edge, st, rsc(h))
