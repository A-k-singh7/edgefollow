"""oneM2M TR-0086 5.5 (handover to another MN-CSE) against handover.py on the live stack.

TR-0086 5.5.3 state model:  ATTACHED(source) -> HANDOVER_PREP -> DUAL_ATTACH -> ATTACHED(target),
with FAILED/ROLLBACK when the target refuses.

Each state and the rollback path are asserted on the live CSEs; every positive check
has a control beside it that must come out the other way.
"""
from __future__ import annotations

import time
import uuid

import handover
from conftest import EDGE_A, EDGE_B, IN_CSE, TY_ACP, TY_SUB, notified_cin, req

SAMPLES = ["48.1351,11.5820", "48.1361,11.5835", "48.1372,11.5849"]


def _attach_on_a(name, origin):
    assert handover.create_ae(EDGE_A, name, origin)[0] == 201
    assert handover.create_container(EDGE_A, name, origin=origin)[0] == 201
    for s in SAMPLES:
        assert handover.add_sample(EDGE_A, s, name, origin=origin)[0] == 201


def _ae(edge, name, origin):
    st, body, _ = req("GET", f"{edge[0]}/{edge[1]}/{name}", origin)
    return st, (body or {}).get("m2m:ae")


# --- ATTACHED(target): the parts handover.py implements ---------------------------------

def test_5_5_telemetry_continuity(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert handover.read_samples(EDGE_B) == SAMPLES


def test_5_5_ae_id_preserved(vehicle):
    """5.5.4 Step 4 / Step 5.1: the AE-ID is unchanged at the target."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _, before = _ae(EDGE_A, name, origin)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    st, after = _ae(EDGE_B, name, origin)
    assert st == 200
    assert after["aei"] == before["aei"] == origin


def test_5_5_source_released(vehicle):
    """ATTACHED(target): the source registration is gone, the target is the single serving CSE."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert _ae(EDGE_A, name, origin)[0] == 404
    assert _ae(EDGE_B, name, origin)[0] == 200


def test_5_5_dual_attach_before_release(vehicle, monkeypatch):
    """DUAL_ATTACH: when the source is released, the target already holds the full subtree.

    Observed from inside the run: delete_ae is wrapped, and at the moment it is called
    for the SOURCE the target must already serve the AE and every sample.
    """
    name, origin = vehicle
    _attach_on_a(name, origin)
    releases = []                                  # target state at EVERY source release
    real_delete = handover.delete_ae

    def spy(edge, *a, **kw):
        if edge == EDGE_A:
            releases.append((_ae(EDGE_B, name, origin)[0], handover.read_samples(EDGE_B)))
        return real_delete(edge, *a, **kw)

    monkeypatch.setattr(handover, "delete_ae", spy)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert releases and all(r == (200, SAMPLES) for r in releases), releases


DEAD_TARGET = ("http://127.0.0.1:9", "cse-mn-x")          # discard port: nothing listens


def _assert_rolled_back(name, origin):
    """FAILED/ROLLBACK end state: source serves the vehicle again, nothing left on B."""
    st, a = _ae(EDGE_A, name, origin)
    assert st == 200 and a["rr"] is True, "source reachability must be restored"
    assert handover.read_samples(EDGE_A) == SAMPLES
    assert _ae(EDGE_B, name, origin)[0] == 404, "the partial copy must be removed"


def test_5_5_5_unreachable_target_reports_failed_and_rolls_back(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.handover(EDGE_A, DEAD_TARGET, handover.read_samples(EDGE_A)) is False
    st, a = _ae(EDGE_A, name, origin)
    assert st == 200 and a["rr"] is True
    assert handover.read_samples(EDGE_A) == SAMPLES


def test_5_5_5_rollback_when_replay_is_refused(vehicle, monkeypatch):
    """FAILED/ROLLBACK on a target that answers but refuses the telemetry replay."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    monkeypatch.setattr(handover, "add_sample", lambda *a, **kw: (403, None))
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    _assert_rolled_back(name, origin)


def test_5_5_control_handover_detects_a_corrupted_copy(vehicle, monkeypatch):
    """The target verification is real: a replay that drops a sample must fail the handover."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    real_add = handover.add_sample
    calls = {"n": 0}

    def lossy(edge, value, *a, **kw):
        calls["n"] += 1
        if edge == EDGE_B and calls["n"] == 2:
            return 201, None                                   # claims success, writes nothing
        return real_add(edge, value, *a, **kw)

    monkeypatch.setattr(handover, "add_sample", lossy)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    _assert_rolled_back(name, origin)


def test_5_5_in_cse_keeps_both_edges(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert sorted(handover.registered_edges()) == ["cse-in/id-mn-a", "cse-in/id-mn-b"]


# --- HANDOVER_PREP, subscription continuity, IN-CSE routing ------------------------------

def test_5_5_handover_prep_marks_source_unreachable(vehicle, monkeypatch):
    """5.5.4 Step 3: rr=false at the source before the target is touched."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    seen = {}
    real_create = handover.create_ae

    def spy(edge, *a, **kw):
        if edge == EDGE_B:
            seen["source_rr"] = _ae(EDGE_A, name, origin)[1]["rr"]
        return real_create(edge, *a, **kw)

    monkeypatch.setattr(handover, "create_ae", spy)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert seen["source_rr"] is False
    assert _ae(EDGE_B, name, origin)[1]["rr"] is True, "the target serves the AE as reachable"


def _subscribe(name, origin, url, rn="app-sub"):
    st, _, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}/{handover.CONTAINER}", origin,
                   ty=TY_SUB, body={"m2m:sub": {"rn": rn, "nu": [url],
                                                 "enc": {"net": [3]}, "nct": 1}})
    assert st == 201


def test_5_5_subscriber_notified_from_target_without_resubscribing(vehicle, receiver):
    """5.5.4 Step 5.2: the existing subscriber hears from the target, no new subscription."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _subscribe(name, origin, receiver.url)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert handover.add_sample(EDGE_B, "48.1383,11.5862", name, origin=origin)[0] == 201
    hits = receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == "48.1383,11.5862")
    assert hits, "the subscriber was not notified by the target MN-CSE"


def test_5_5_replayed_history_is_not_notified_again(vehicle, receiver):
    """Subscriptions are re-created after the replay, so subscribers see no duplicates."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _subscribe(name, origin, receiver.url)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    replayed = receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") in SAMPLES, timeout=3.0)
    assert replayed == [], "replayed samples were notified a second time"


def test_5_5_control_unreachable_subscriber_rolls_back(vehicle, receiver):
    """A subscriber the target cannot verify must fail the handover, not be silently dropped.

    ACME refuses a dead nu at creation (5204), so the subscriber is alive when it
    subscribes and gone by the time the target re-creates the subscription.
    """
    name, origin = vehicle
    _attach_on_a(name, origin)
    _subscribe(name, origin, receiver.url)
    receiver.shutdown()
    receiver.server_close()
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    _assert_rolled_back(name, origin)
    subs = handover.read_subscriptions(EDGE_A)
    assert [s[1]["rn"] for s in subs] == ["app-sub"], "the source keeps its subscription"


def _serving_edges(origin):
    """CSE-IDs the IN-CSE routes this AE-ID to: the `lnk` of each announced AE carrying its label."""
    st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}?fu=1&lbl=aei:{origin}", "CAdmin")
    assert st == 200
    edges = []
    for uri in body.get("m2m:uril", []):
        s, b, _ = req("GET", f"{IN_CSE[0]}/{uri}", "CAdmin")
        assert s == 200, uri
        lnk = b["m2m:aeA"]["lnk"]
        edges.append(lnk.split("/")[1])                    # "/id-mn-b/<ri>" -> "id-mn-b"
    return edges


def test_5_5_in_cse_routes_ae_to_target(vehicle):
    """5.5.4 Step 5.3: exactly one IN entry for the AE-ID, linking to the serving MN-CSE."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert _serving_edges(origin) == ["id-mn-a"]
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert _serving_edges(origin) == ["id-mn-b"]


def test_5_5_in_cse_route_unchanged_after_rollback(vehicle, monkeypatch):
    name, origin = vehicle
    _attach_on_a(name, origin)
    monkeypatch.setattr(handover, "add_sample", lambda *a, **kw: (403, None))
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    assert _serving_edges(origin) == ["id-mn-a"]


# --- the IN routes the AE-ID to the target before the source is released (added 2026-11-21) ------------------------
# tinyIoT as MN-B, after a restart, answered the vehicle's AE CREATE 201 and announced nothing (its <aeA> forward to the
# IN was answered 4004, and it answered 201 anyway): handover() returned True with the IN routing the vehicle to no
# edge, and the way back was refused by the route check before a handover. On the lab's ACME the same condition is
# made by sending the target's AE CREATE without at/aa. The offline twins are P5 in test_handover_before_offline.py.

LOCK_URL = f"{IN_CSE[0]}/{IN_CSE[1]}/{handover.lock_name()}"


def _create_unannounced(edge, monkeypatch):
    """handover's AE CREATE on `edge` goes out without at/aa: the target registers the AE (201), announces nothing."""
    real = handover._req

    def drop(method, url, origin, *, ty=None, body=None):
        if method == "POST" and ty == handover.TY_AE and url == f"{edge[0]}/{edge[1]}":
            body = {"m2m:ae": {k: v for k, v in body["m2m:ae"].items() if k not in ("at", "aa")}}
        return real(method, url, origin, ty=ty, body=body)

    monkeypatch.setattr(handover, "_req", drop)


def _drop_announcement(origin, csi):
    """Delete, at the IN, the announced AE of this AE-ID that links to the edge `csi` (e.g. "id-mn-b")."""
    st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}?fu=1&lbl=aei:{origin}", "CAdmin")
    assert st == 200
    gone = [uri for uri in body["m2m:uril"]
            if req("GET", f"{IN_CSE[0]}/{uri}", "CAdmin")[1]["m2m:aeA"]["lnk"].startswith(f"/{csi}/")]
    assert len(gone) == 1, gone
    assert req("DELETE", f"{IN_CSE[0]}/{gone[0]}", "CAdmin")[0] == 200


def test_5_5_control_an_ae_created_without_at_aa_is_answered_201_and_not_routed(vehicle, monkeypatch):
    """The planted condition is tinyIoT's: the target answers 201 and holds the AE, the IN routes nothing to it."""
    name, origin = vehicle
    _create_unannounced(EDGE_B, monkeypatch)
    assert handover.create_ae(EDGE_B, name, origin)[0] == 201
    assert _ae(EDGE_B, name, origin)[0] == 200
    assert _serving_edges(origin) == []


def test_5_5_target_that_does_not_announce_the_ae_rolls_back_and_the_source_keeps_it(vehicle, monkeypatch, capsys):
    """5.5.4 Step 5.3 before the release: no route to the target, no release. The source stays the only copy, with
    every sample, and the IN keeps routing the vehicle to it alone; the target holds nothing."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _create_unannounced(EDGE_B, monkeypatch)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    assert "the target did not announce the AE to the IN-CSE" in capsys.readouterr().out
    _assert_rolled_back(name, origin)
    assert _serving_edges(origin) == ["id-mn-a"]
    assert req("GET", LOCK_URL, "CAdmin")[0] == 404, "the transaction was left open"


def test_5_5_control_the_in_routes_to_both_edges_when_the_source_is_released(vehicle, monkeypatch):
    """The normal move: at the moment the source is released the IN routes the vehicle to both edges (DUAL_ATTACH),
    after it to the target alone."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    at_release = []
    real_delete = handover.delete_ae

    def spy(edge, *a, **kw):
        if edge == EDGE_A:
            at_release.append(sorted(_serving_edges(origin)))
        return real_delete(edge, *a, **kw)

    monkeypatch.setattr(handover, "delete_ae", spy)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert at_release == [["id-mn-a", "id-mn-b"]], at_release
    assert _serving_edges(origin) == ["id-mn-b"]


class _LosesTargetRoute:
    """A device held for the last copy just as the target's announcement disappears from the IN."""

    def __init__(self, origin):
        self.origin, self.resumed = origin, []

    def hold(self):
        _drop_announcement(self.origin, "id-mn-b")

    def resume(self, edge):
        self.resumed.append(edge)


def test_5_5_target_route_lost_during_the_move_rolls_back_before_the_release(vehicle):
    """The route is read again at the last moment before the release, not only after the target's CREATE."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    dev = _LosesTargetRoute(origin)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A), device=dev) is False
    assert dev.resumed == [EDGE_A], "the device must resume on the source"
    _assert_rolled_back(name, origin)
    assert _serving_edges(origin) == ["id-mn-a"]


def test_5_5_target_route_lost_at_the_release_is_inconsistent_and_the_target_copy_kept(vehicle, monkeypatch, capsys):
    """After the release nothing is rolled back: the target holds the only copy. A route that does not name the target
    alone is reported INCONSISTENT and the move is not a success."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    real_delete = handover.delete_ae

    def release(edge, *a, **kw):
        if edge == EDGE_A:
            _drop_announcement(origin, "id-mn-b")
        return real_delete(edge, *a, **kw)

    monkeypatch.setattr(handover, "delete_ae", release)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    assert "INCONSISTENT" in capsys.readouterr().out
    assert _ae(EDGE_A, name, origin)[0] == 404
    assert _ae(EDGE_B, name, origin)[0] == 200 and handover.read_samples(EDGE_B) == SAMPLES, \
        "the target's copy, the only one, was removed"
    assert _serving_edges(origin) == []
    assert req("GET", LOCK_URL, "CAdmin")[0] == 404


def test_5_5_a_refused_source_release_is_inconsistent_not_success(vehicle, monkeypatch, capsys):
    """The source's DELETE is refused, so the IN still routes the vehicle to both edges: not a success. The target keeps
    its copy and the source is not made reachable again (the device was resumed on the target)."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    real_delete = handover.delete_ae
    monkeypatch.setattr(handover, "delete_ae",
                        lambda edge, *a, **kw: (403, None) if edge == EDGE_A else real_delete(edge, *a, **kw))
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    assert "INCONSISTENT" in capsys.readouterr().out
    assert _ae(EDGE_B, name, origin)[0] == 200 and handover.read_samples(EDGE_B) == SAMPLES
    assert _ae(EDGE_A, name, origin)[1]["rr"] is False
    assert sorted(_serving_edges(origin)) == ["id-mn-a", "id-mn-b"]
    assert req("GET", LOCK_URL, "CAdmin")[0] == 404


# --- a consumer with its own identity (security context + its subscription) --------------

CREATE, RETRIEVE, NOTIFY, DISCOVER = 1, 2, 16, 32


def _dashboard_on_a(name, origin, receiver_url, record_creator=True):
    """A dashboard granted read + subscribe on the vehicle's telemetry, subscribed as itself."""
    dash = f"Cdash-{uuid.uuid4().hex[:6]}"
    base = f"{EDGE_A[0]}/{EDGE_A[1]}/{name}"
    st, body, _ = req("POST", base, origin, ty=TY_ACP, body={"m2m:acp": {
        "rn": "dashboards",
        "pv": {"acr": [{"acor": [origin], "acop": 63},
                       {"acor": [dash], "acop": RETRIEVE | NOTIFY | DISCOVER},
                       {"acor": [dash], "acop": CREATE, "acod": [{"chty": [TY_SUB]}]}]},
        "pvs": {"acr": [{"acor": [origin], "acop": 63}]}}})
    assert st == 201, body
    st, _, _ = req("PUT", f"{base}/{handover.CONTAINER}", origin,
                   body={"m2m:cnt": {"acpi": [body["m2m:acp"]["ri"]]}})
    assert st == 200
    sub = {"rn": "dash-sub", "nu": [receiver_url], "enc": {"net": [3]}, "nct": 1}
    if record_creator:
        sub["cr"] = None
    st, body, _ = req("POST", f"{base}/{handover.CONTAINER}", dash, ty=TY_SUB, body={"m2m:sub": sub})
    assert st == 201, body
    return dash


def _notified_from_b(name, origin, receiver, value):
    assert handover.add_sample(EDGE_B, value, name, origin=origin)[0] == 201
    return receiver.wait_for(lambda n: (notified_cin(n) or {}).get("con") == value)


def test_5_5_third_party_subscriber_still_notified_and_still_owns_it(vehicle, receiver):
    """A dashboard's own subscription moves, and stays the dashboard's (it may delete it)."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    dash = _dashboard_on_a(name, origin, receiver.url)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert _notified_from_b(name, origin, receiver, "48.1390,11.5870"), \
        "the dashboard's own subscription did not survive the handover"
    url = f"{EDGE_B[0]}/{EDGE_B[1]}/{name}/{handover.CONTAINER}/dash-sub"
    st, body, _ = req("GET", url, dash)
    assert st == 200 and body["m2m:sub"]["cr"] == dash
    assert req("DELETE", url, dash)[0] == 200, "the dashboard can no longer manage its subscription"


def test_5_5_subscriber_without_recorded_creator_still_notified(vehicle, receiver):
    """No cr recorded: the subscription still moves (re-created by the orchestrator)."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _dashboard_on_a(name, origin, receiver.url, record_creator=False)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert _notified_from_b(name, origin, receiver, "48.1391,11.5871")


def test_5_5_access_policy_carried_to_target(vehicle, receiver):
    """Security context: the dashboard may still read the telemetry on B, a stranger still may not."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    dash = _dashboard_on_a(name, origin, receiver.url)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    url = f"{EDGE_B[0]}/{EDGE_B[1]}/{name}/{handover.CONTAINER}/la"
    assert req("GET", url, dash)[0] == 200, "the dashboard lost read access on the target"
    assert req("GET", url, f"Cstranger-{uuid.uuid4().hex[:6]}")[0] == 403
    st, _, _ = req("POST", f"{EDGE_B[0]}/{EDGE_B[1]}/{name}/{handover.CONTAINER}", dash,
                   ty=4, body={"m2m:cin": {"con": "forged"}})
    assert st == 403, "the carried policy must still forbid the dashboard to write"


def test_5_5_control_policy_outside_the_ae_blocks_the_handover(vehicle):
    """An ACP the handover cannot carry (at the CSEBase) must stop it, not be dropped."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    acp_rn = f"cb-acp-{uuid.uuid4().hex[:6]}"
    st, body, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}", "CAdmin", ty=TY_ACP, body={"m2m:acp": {
        "rn": acp_rn,
        "pv": {"acr": [{"acor": [origin], "acop": 63}]},
        "pvs": {"acr": [{"acor": ["CAdmin"], "acop": 63}]}}})
    assert st == 201, body
    try:
        assert req("PUT", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}/{handover.CONTAINER}", origin,
                   body={"m2m:cnt": {"acpi": [body["m2m:acp"]["ri"]]}})[0] == 200
        assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
        _assert_rolled_back(name, origin)
    finally:
        req("DELETE", f"{EDGE_A[0]}/{EDGE_A[1]}/{acp_rn}", "CAdmin")


# --- flexContainers (TS-0023 cod:*, ETSI's mec:*) and what cannot be carried (deep check 2026-10-29) ----
# Our phone keeps TS-0023 modules (cod:bat, cod:geoLn, cod:tempe) directly under its AE
# (the lab's phone suites); ETSI's MEC-IPE writes mec:* flexContainers. The handover copied
# ACP/CNT/CIN/SUB only and dropped every other child type without a word.

TY_FCNT, TY_GRP = 28, 9
BATTERY = "org.onem2m.common.moduleclass.battery"


def _module(name, origin, rn="battery", parent="", lvl=80):
    st, body, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}{parent}", origin, ty=TY_FCNT,
                      body={"cod:bat": {"rn": rn, "cnd": BATTERY, "lvl": lvl}})
    assert st == 201, body


def _flex(edge, path, origin):
    st, body, _ = req("GET", f"{edge[0]}/{edge[1]}/{path}", origin)
    return st, next(iter((body or {}).values()), None)


def test_5_5_flexcontainer_carried_to_target(vehicle):
    """A TS-0023 module under the AE arrives on the target with its state, and leaves with the source."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _module(name, origin, lvl=77)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    st, b = _flex(EDGE_B, f"{name}/battery", origin)
    assert st == 200 and b["lvl"] == 77 and b["cnd"] == BATTERY, (st, b)
    assert _flex(EDGE_A, f"{name}/battery", origin)[0] == 404


def test_5_5_nested_module_carried(vehicle):
    """TS-0023 devices hold their modules as flexContainer children of a device flexContainer."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    st, body, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}", origin, ty=TY_FCNT, body={"cod:devTr": {
        "rn": "thermo", "cnd": "org.onem2m.common.device.deviceThermometer"}})
    assert st == 201, body
    _module(name, origin, rn="tbat", parent="/thermo", lvl=5)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert _flex(EDGE_B, f"{name}/thermo", origin)[0] == 200
    st, b = _flex(EDGE_B, f"{name}/thermo/tbat", origin)
    assert st == 200 and b["lvl"] == 5, (st, b)


def test_5_5_subscription_on_a_flexcontainer_carried(vehicle, receiver):
    """A subscriber to a module hears its next update from the target."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _module(name, origin)
    st, _, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}/battery", origin, ty=TY_SUB, body={"m2m:sub": {
        "rn": "bat-sub", "nu": [receiver.url], "enc": {"net": [1]}, "nct": 1}})
    assert st == 201
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert req("PUT", f"{EDGE_B[0]}/{EDGE_B[1]}/{name}/battery", origin, body={"cod:bat": {"lvl": 42}})[0] == 200
    lvl = lambda n: ((((n.get("m2m:sgn") or {}).get("nev") or {}).get("rep") or {}).get("cod:bat") or {}).get("lvl")  # noqa: E731
    assert receiver.wait_for(lambda n: lvl(n) == 42), "the module's subscriber was not notified by the target"


def test_5_5_flexcontainer_access_policy_carried(vehicle):
    """The module's own access policy moves with it: its reader may still read it, a stranger still may not."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _module(name, origin)
    reader = f"Creader-{uuid.uuid4().hex[:6]}"
    base = f"{EDGE_A[0]}/{EDGE_A[1]}/{name}"
    st, body, _ = req("POST", base, origin, ty=TY_ACP, body={"m2m:acp": {
        "rn": "modules",
        "pv": {"acr": [{"acor": [origin], "acop": 63}, {"acor": [reader], "acop": RETRIEVE}]},
        "pvs": {"acr": [{"acor": [origin], "acop": 63}]}}})
    assert st == 201, body
    assert req("PUT", f"{base}/battery", origin, body={"cod:bat": {"acpi": [body["m2m:acp"]["ri"]]}})[0] == 200
    assert req("GET", f"{base}/battery", reader)[0] == 200
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    url = f"{EDGE_B[0]}/{EDGE_B[1]}/{name}/battery"
    assert req("GET", url, reader)[0] == 200, "the module's reader lost access on the target"
    assert req("GET", url, f"Cstranger-{uuid.uuid4().hex[:6]}")[0] == 403


class _UpdatingDevice:
    """A device that updates its module while it is being moved: the write lands on the source before hold() returns."""

    def __init__(self, name, origin):
        self.name, self.origin, self.resumed = name, origin, None

    def hold(self):
        assert req("PUT", f"{EDGE_A[0]}/{EDGE_A[1]}/{self.name}/battery", self.origin,
                   body={"cod:bat": {"lvl": 55}})[0] == 200

    def resume(self, edge):
        self.resumed = edge


def test_5_5_flexcontainer_updated_during_the_move_arrives_current(vehicle):
    """The target holds the module's LAST state, not the one copied before the device stopped writing."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _module(name, origin, lvl=80)
    dev = _UpdatingDevice(name, origin)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A), device=dev)
    assert dev.resumed == EDGE_B
    st, b = _flex(EDGE_B, f"{name}/battery", origin)
    assert st == 200 and b["lvl"] == 55, (st, b)


def test_5_5_control_flexcontainer_refused_by_target_rolls_back(vehicle, monkeypatch):
    """A target that refuses the module is FAILED/ROLLBACK, not a move without it."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _module(name, origin)
    real = handover._req
    monkeypatch.setattr(handover, "_req", lambda m, url, o, ty=None, body=None: (403, None)
                        if m == "POST" and ty == TY_FCNT and url.startswith(EDGE_B[0]) else real(m, url, o, ty=ty, body=body))
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    _assert_rolled_back(name, origin)
    assert _flex(EDGE_A, f"{name}/battery", origin)[0] == 200


def test_5_5_control_flexcontainer_history_blocks_the_handover(vehicle):
    """A versioned module (fcied) keeps <flexContainerInstance>s that only the CSE can make; the handover must
    stop with the source untouched rather than move the module without its history."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    st, body, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}", origin, ty=TY_FCNT, body={"cod:tempe": {
        "rn": "temp", "cnd": "org.onem2m.common.moduleclass.temperature", "curT0": 20.0, "fcied": True}})
    assert st == 201, body
    assert req("PUT", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}/temp", origin, body={"cod:tempe": {"curT0": 21.0}})[0] == 200
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    _assert_rolled_back(name, origin)


def test_5_5_control_uncarried_child_blocks_the_handover(vehicle):
    """Any other child the handover does not carry (here a <group>) stops it; it is never left behind silently."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    st, body, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}", origin, ty=TY_GRP, body={"m2m:grp": {
        "rn": "members", "mt": 3, "mnm": 2, "mid": []}})
    assert st == 201, body
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    _assert_rolled_back(name, origin)
    assert req("GET", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}/members", origin)[0] == 200


def test_5_5_control_unlistable_children_block_the_handover(vehicle, monkeypatch):
    """If the source will not list a parent's children, "nothing uncarried" is unknown: stop, never assume it."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    real = handover._req
    monkeypatch.setattr(handover, "_req", lambda m, url, o, ty=None, body=None: (403, None)
                        if m == "GET" and url.startswith(EDGE_A[0]) and url.endswith("?fu=1&lvl=1") else real(m, url, o, ty=ty, body=body))
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
    monkeypatch.setattr(handover, "_req", real)
    _assert_rolled_back(name, origin)


def test_5_5_control_module_policy_outside_the_ae_blocks_the_handover(vehicle):
    """A module whose ACP lives at the CSEBase cannot keep its policy on the target: stop, do not drop it."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    _module(name, origin)
    acp_rn = f"cb-acp-{uuid.uuid4().hex[:6]}"
    st, body, _ = req("POST", f"{EDGE_A[0]}/{EDGE_A[1]}", "CAdmin", ty=TY_ACP, body={"m2m:acp": {
        "rn": acp_rn,
        "pv": {"acr": [{"acor": [origin], "acop": 63}]},
        "pvs": {"acr": [{"acor": ["CAdmin"], "acop": 63}]}}})
    assert st == 201, body
    try:
        assert req("PUT", f"{EDGE_A[0]}/{EDGE_A[1]}/{name}/battery", origin,
                   body={"cod:bat": {"acpi": [body["m2m:acp"]["ri"]]}})[0] == 200
        assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
        _assert_rolled_back(name, origin)
    finally:
        req("DELETE", f"{EDGE_A[0]}/{EDGE_A[1]}/{acp_rn}", "CAdmin")


# --- V01/W03: the target name must be free or the vehicle's own (deep check 2026-10-29) --------------------------
# A 409 on the target AE create counted as success: with a squatter's AE holding the vehicle's name on B and granting
# the vehicle everything but DELETE, the whole subtree was written under the squatter's AE. The handover now reads who
# holds the name first and writes nothing there unless it is free or the vehicle's own.

def test_5_5_control_target_name_held_by_another_originator_blocks_the_handover(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    squatter = f"Csq-{uuid.uuid4().hex[:6]}"
    base = f"{EDGE_B[0]}/{EDGE_B[1]}"
    st, _, _ = req("POST", base, squatter, ty=handover.TY_AE, body={"m2m:ae": {
        "rn": name, "api": "Nsquatter", "rr": False, "srv": ["4"]}})
    assert st == 201
    try:
        st, body, _ = req("POST", f"{base}/{name}", squatter, ty=TY_ACP, body={"m2m:acp": {
            "rn": "lure", "pv": {"acr": [{"acor": [squatter], "acop": 63},
                                         {"acor": [origin], "acop": 55}]},                # the vehicle: all but DELETE
            "pvs": {"acr": [{"acor": [squatter], "acop": 63}]}}})
        assert st == 201, body
        assert req("PUT", f"{base}/{name}", squatter, body={"m2m:ae": {"acpi": [body["m2m:acp"]["ri"]]}})[0] == 200
        assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A)) is False
        st, a = _ae(EDGE_A, name, origin)
        assert st == 200 and a["rr"] is True and handover.read_samples(EDGE_A) == SAMPLES
        st, b, _ = req("GET", f"{base}/{name}", "CAdmin")
        assert st == 200 and b["m2m:ae"]["aei"] == squatter, "the squatter's AE must be left as it was"
        st, kids, _ = req("GET", f"{base}/{name}?fu=1&lvl=1", "CAdmin")
        assert st == 200 and kids["m2m:uril"] == [f"{EDGE_B[1]}/{name}/lure"], kids
        assert _serving_edges(origin) == ["id-mn-a"]
    finally:
        req("DELETE", f"{base}/{name}", squatter)
        req("DELETE", f"{base}/{name}", "CAdmin")           # never leave the name taken for the tests after this


# --- R2: the target must be a registered MN-CSE (lab fixes of 2026-10-29) --------------------------------
# A handover aimed at the IN-CSE itself (cst 1) used to proceed when called without the readiness gate, as
# scenario.py and handover.main call it, and would have put the vehicle, positions included, on the city's CSE.

def test_5_5_control_a_handover_to_the_in_itself_is_refused(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.handover(EDGE_A, IN_CSE, handover.read_samples(EDGE_A)) is False
    assert req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/{name}", "CAdmin")[0] == 404, "the vehicle must not land on the IN"
    st, a = _ae(EDGE_A, name, origin)
    assert st == 200 and a["rr"] is True and handover.read_samples(EDGE_A) == SAMPLES


# --- before a handover starts, on the live CSEs (TR-0077 v0.4.0 7.2.4.2, added 2026-11-18; the offline twins with
# their planted faults are in test_handover_before_offline.py) ------------------------------------------------

def _polling_vehicle_on_a(name, origin):
    """A device that polls registers with rr = false (TR-0086 5.3.3.1: true only "if the device accepts downlink")."""
    assert handover.create_ae(EDGE_A, name, origin, rr=False)[0] == 201
    assert handover.create_container(EDGE_A, name, origin=origin)[0] == 201
    for s in SAMPLES:
        assert handover.add_sample(EDGE_A, s, name, origin=origin)[0] == 201


def test_before_a_handover_onto_the_source_is_refused_and_the_vehicle_is_untouched(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.handover(EDGE_A, EDGE_A, handover.read_samples(EDGE_A)) is False
    st, a = _ae(EDGE_A, name, origin)
    assert st == 200 and a["rr"] is True and handover.read_samples(EDGE_A) == SAMPLES


def test_before_the_in_routes_the_vehicle_to_its_source_alone(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.serving_edges(origin) == ["/id-mn-a"]


def test_before_a_leftover_registration_is_not_taken_for_the_serving_one(vehicle):
    """Served by B, with a second registration of the same AE-ID left on A: the IN links the AE-ID to two edges,
    and a handover A -> B would delete B's AE as "our own stale copy". It must stop and leave B as it is."""
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))
    assert handover.create_ae(EDGE_A, name, origin)[0] == 201
    assert handover.serving_edges(origin) == ["/id-mn-a", "/id-mn-b"]
    assert handover.handover(EDGE_A, EDGE_B, []) is False
    assert _ae(EDGE_B, name, origin)[0] == 200 and handover.read_samples(EDGE_B) == SAMPLES


def test_before_a_polling_device_is_still_unreachable_after_a_rollback(vehicle, monkeypatch):
    name, origin = vehicle
    _polling_vehicle_on_a(name, origin)
    monkeypatch.setattr(handover, "add_sample", lambda *a, **kw: (403, None))
    assert handover.handover(EDGE_A, EDGE_B, SAMPLES) is False
    st, a = _ae(EDGE_A, name, origin)
    assert st == 200 and a["rr"] is False, "the rollback changed what the device registered"
    assert _ae(EDGE_B, name, origin)[0] == 404


def test_before_a_polling_device_arrives_unreachable_on_the_target(vehicle):
    name, origin = vehicle
    _polling_vehicle_on_a(name, origin)
    assert handover.handover(EDGE_A, EDGE_B, SAMPLES)
    st, b = _ae(EDGE_B, name, origin)
    assert st == 200 and b["rr"] is False


def test_before_a_second_handover_is_refused_while_a_transaction_is_open(vehicle):
    name, origin = vehicle
    _attach_on_a(name, origin)
    assert handover.take_lock("/id-mn-a", "/id-mn-b") is not None
    try:
        assert handover.take_lock("/id-mn-a", "/id-mn-b") is None, "the live IN-CSE gave the same name twice"
        assert handover.handover(EDGE_A, EDGE_B, SAMPLES) is False
        st, a = _ae(EDGE_A, name, origin)
        assert st == 200 and a["rr"] is True and _ae(EDGE_B, name, origin)[0] == 404
    finally:
        handover.release_lock()
    assert handover.handover(EDGE_A, EDGE_B, SAMPLES), "control: with the transaction closed the vehicle moves"
    assert req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/{handover.lock_name()}", "CAdmin")[0] == 404, "left open after success"


def test_before_a_transaction_past_its_validity_time_is_taken_over(vehicle):
    assert handover.take_lock("/id-mn-a", "/id-mn-b", validity_s=2) is not None
    try:
        time.sleep(3.2)
        assert handover.take_lock("/id-mn-a", "/id-mn-b") is not None
    finally:
        handover.release_lock()


def test_before_a_failed_handover_leaves_no_transaction_open(vehicle, monkeypatch):
    name, origin = vehicle
    _attach_on_a(name, origin)
    monkeypatch.setattr(handover, "add_sample", lambda *a, **kw: (403, None))
    assert handover.handover(EDGE_A, EDGE_B, SAMPLES) is False
    assert req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/{handover.lock_name()}", "CAdmin")[0] == 404
