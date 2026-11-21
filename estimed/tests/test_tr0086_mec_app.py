"""oneM2M TR-0086 5.4 (deploy an AE as a MEC application) against the live stack.

Step 1  register the app instance with the MEC platform (GS MEC 011 mec_app_support)
Step 2  confirm_ready
Step 3  the app registers as an AE on the co-located MN-CSE
Step 4  baseline tree: output + config containers and an <ACP> for subscribers

The <ACP> part is checked as least privilege: the subscriber may read and subscribe,
may not write, and an originator outside the policy may do neither.
"""
from __future__ import annotations

import json
import uuid

import pytest

from conftest import EDGE_A, TY_ACP, TY_AE, TY_CIN, TY_CNT, TY_SUB, http, req, rsc

# accessControlOperations bits (TS-0004 6.3.4.2.3)
CREATE, RETRIEVE, UPDATE, DELETE, NOTIFY, DISCOVER = 1, 2, 4, 8, 16, 32
ALL = CREATE | RETRIEVE | UPDATE | DELETE | NOTIFY | DISCOVER


def _register_app(mec011, name):
    st, body = http("POST", f"{mec011}/registrations", {"appName": name})
    assert st == 201, (st, body)
    return body["appInstanceId"]


# --- Steps 1-2: MEC 011 ------------------------------------------------------------------

def test_5_2_mec011_api_answers(mec011):
    """5.2.4 Step 2, read against GS MEC 011: the API serves a defined resource.

    TR-0086 writes `GET /mec_app_support/v2/ -> 200`, but MEC 011 defines no resource at
    the API root; timing/current_time is the cheapest one it does define.
    """
    st, body = http("GET", f"{mec011}/timing/current_time")
    assert st == 200 and "seconds" in body


def test_5_4_register_then_confirm_ready(mec011):
    inst = _register_app(mec011, "estimed-analytics")
    uuid.UUID(inst)                                            # a real identifier, not a fixture string
    st, _ = http("POST", f"{mec011}/applications/{inst}/confirm_ready", {"indication": "READY"})
    assert st == 204


def test_5_4_control_confirm_ready_for_unknown_instance_is_404(mec011):
    st, _ = http("POST", f"{mec011}/applications/{uuid.uuid4()}/confirm_ready",
                 {"indication": "READY"})
    assert st == 404


def test_5_4_control_confirm_ready_after_deregistration_is_404(mec011):
    inst = _register_app(mec011, "estimed-analytics")
    assert http("DELETE", f"{mec011}/registrations/{inst}")[0] == 204
    st, _ = http("POST", f"{mec011}/applications/{inst}/confirm_ready", {"indication": "READY"})
    assert st == 404


@pytest.mark.parametrize("body", [{}, {"indication": "MAYBE"}, None])
def test_5_4_confirm_ready_without_valid_indication_is_400(mec011, body):
    """AppReadyConfirmation.indication is mandatory and READY is its only value."""
    inst = _register_app(mec011, "estimed-analytics")
    st, _ = http("POST", f"{mec011}/applications/{inst}/confirm_ready", body)
    assert st == 400


def test_5_4_confirm_termination_requires_operation_action(mec011):
    inst = _register_app(mec011, "estimed-analytics")
    assert http("POST", f"{mec011}/applications/{inst}/confirm_termination", {})[0] == 400
    st, _ = http("POST", f"{mec011}/applications/{inst}/confirm_termination",
                 {"operationAction": "TERMINATING"})
    assert st == 204


# --- Steps 3-4: the MEC app as an AE with a least-privilege <ACP> --------------------------

@pytest.fixture
def mec_app_ae(mec011, ae):
    """Registered MEC app instance + its AE, output/config containers, and a subscriber ACP."""
    name, origin = ae
    inst = _register_app(mec011, name)
    assert http("POST", f"{mec011}/applications/{inst}/confirm_ready",
                {"indication": "READY"})[0] == 204
    base = f"{EDGE_A[0]}/{EDGE_A[1]}"
    st, body, _ = req("POST", base, origin, ty=TY_AE, body={"m2m:ae": {
        "rn": name, "api": "Nestimed.analytics", "rr": True, "srv": ["4"],
        "lbl": [f"mec:appInstanceId:{inst}"]}})
    assert st == 201, body
    subscriber = f"Cdash-{uuid.uuid4().hex[:6]}"
    # Subscribing needs CREATE on the container as well as RETRIEVE (ACME checks both),
    # so CREATE is granted for <subscription> children only (acod.chty); a plain
    # CREATE would also let the subscriber write forged contentInstances.
    st, body, _ = req("POST", f"{base}/{name}", origin, ty=TY_ACP, body={"m2m:acp": {
        "rn": "subscribers",
        "pv": {"acr": [{"acor": [origin], "acop": ALL},
                       {"acor": [subscriber], "acop": RETRIEVE | NOTIFY | DISCOVER},
                       {"acor": [subscriber], "acop": CREATE, "acod": [{"chty": [TY_SUB]}]}]},
        "pvs": {"acr": [{"acor": [origin], "acop": ALL}]}}})
    assert st == 201, body
    acp_ri = body["m2m:acp"]["ri"]
    for cnt in ("output", "config"):
        st, _, _ = req("POST", f"{base}/{name}", origin, ty=TY_CNT,
                       body={"m2m:cnt": {"rn": cnt, "acpi": [acp_ri]}})
        assert st == 201
    st, _, _ = req("POST", f"{base}/{name}/output", origin, ty=TY_CIN,
                   body={"m2m:cin": {"cnf": "application/json:0",
                                     "con": json.dumps({"congestion": 0.42})}})
    assert st == 201
    yield {"name": name, "origin": origin, "inst": inst, "subscriber": subscriber,
           "out": f"{base}/{name}/output"}
    http("DELETE", f"{mec011}/registrations/{inst}")


def test_5_4_ae_carries_its_mec_app_instance(mec_app_ae):
    st, body, _ = req("GET", f"{EDGE_A[0]}/{EDGE_A[1]}/{mec_app_ae['name']}", mec_app_ae["origin"])
    assert st == 200
    assert f"mec:appInstanceId:{mec_app_ae['inst']}" in body["m2m:ae"]["lbl"]


def test_5_4_subscriber_may_read_output(mec_app_ae):
    st, body, _ = req("GET", f"{mec_app_ae['out']}/la", mec_app_ae["subscriber"])
    assert st == 200
    assert json.loads(body["m2m:cin"]["con"]) == {"congestion": 0.42}


def test_5_4_subscriber_may_subscribe(mec_app_ae, receiver):
    st, body, _ = req("POST", mec_app_ae["out"], mec_app_ae["subscriber"], ty=TY_SUB,
                      body={"m2m:sub": {"rn": "dash", "nu": [receiver.url], "enc": {"net": [3]}}})
    assert st == 201, body


def test_5_4_control_subscriber_may_not_write(mec_app_ae):
    st, _, h = req("POST", mec_app_ae["out"], mec_app_ae["subscriber"], ty=TY_CIN,
                   body={"m2m:cin": {"con": "forged"}})
    assert st == 403 and rsc(h) == 4103


def test_5_4_control_stranger_may_not_read(mec_app_ae):
    st, _, h = req("GET", f"{mec_app_ae['out']}/la", f"Cstranger-{uuid.uuid4().hex[:6]}")
    assert st == 403 and rsc(h) == 4103


def test_5_4_control_owner_still_may_write(mec_app_ae):
    """The policy did not lock the owner out (pvs and its own acr entry hold)."""
    st, _, _ = req("POST", mec_app_ae["out"], mec_app_ae["origin"], ty=TY_CIN,
                   body={"m2m:cin": {"con": json.dumps({"congestion": 0.5})}})
    assert st == 201
