"""The VRU warning AE (estimed/apps/vru_warning) on the live stack: a roadside sensor's "road user present" and the
vehicle's "approaching, in the zone" give a warning in the vehicle's command container, on whichever edge serves it.

The organisers' use case (ESTIMED "final use cases and reference architecture", p6, Vulnerable Road User Detection):
the MN-CSE near the vehicle "gathers real-time data from local sensors and smartphones" and warns about collisions
with "immediate, sub-second warnings". This file proves the warning reaches the vehicle before and after a handover,
and that the warning AE can read and write nothing it was not granted.

Two kinds of test, told apart by the `live` MARKER (registered by this file with the running pytest; the names still
start with test_offline_ or test_live_, but a name or a folder is no selector -- a copy under a folder named "offline"
once made -k offline select every test):
    not marked     no lab: the rule, the record shapes, and the AE against an in-memory stand-in CSE (FakeCse)
    @live          the live CSEs; refused (fail, not skip) unless THIS run holds the lab lock
Offline only:  /home/edgefollow/edgefollow-lab/.venv/bin/python -B -m pytest -p no:cacheprovider --strict-markers \
                   -m "not live" estimed/tests/test_vru_warning.py
Live:          flock -o /home/edgefollow/estimed-run/.live.lock timeout -s INT 300 <that command without -m>
--strict-markers makes a misspelt marker an error; test_offline_every_test_that_touches_the_lab_is_marked_live holds
the marking. Two limits of that: (1) `live` is registered when THIS file is imported (there is no conftest or ini of its
own), so under --strict-markers another test file that uses @pytest.mark.live and is collected before this one fails;
(2) the marking test looks at FIXTURE NAMES only (lab, live_lock, topology): a test that reaches the lab some other way
-- calling req() itself, with none of those fixtures -- is not caught by it.

Who is who (every identity is its own originator; nobody here is CAdmin except the orchestrator):
    vehicle01 / Cvehicle01     handover.py's vehicle on edge A (moves to B), rr=false; its <AE> readable by the
                               warning AE (so it can tell the vehicle from whoever holds the name); containers
                               telemetry (positions, readable by the vehicle alone), ctx (zone + approaching, mni 1),
                               cmd, ack
    vruRsu-<tag>               a SIMULATED roadside sensor on edge A (stays): containers vru (detections) and env
    vruWarning-<tag>           the warning AE on edge A, its own <AE>, <ACP> and `log`
    CAdmin                     the orchestrator only: it runs the handover and publishes the route record at the IN

The simulated vehicle reads its <cmd> container (it is not request-reachable); see SimVehicle for why it does not
long-poll a <pollingChannel> as the probe app does.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import re
import subprocess
import sys
import threading
import time
import types
import uuid

import pytest

import handover
from conftest import EDGE_A, EDGE_B, ESTIMED, IN_CSE, TY_ACP, TY_AE, TY_CIN, TY_CNT, TY_SUB, req

# The `live` marker, registered with the running pytest before any test below uses it: this file has no conftest or
# ini of its own (pytest.mark._config is the config pytest's mark plugin holds while a session runs).
_CFG = getattr(pytest.mark, "_config", None)
if _CFG is not None and "live" not in {x.split(":")[0].split("(")[0].strip() for x in _CFG.getini("markers")}:
    _CFG.addinivalue_line("markers", "live: needs the lab CSEs; runs only under this run's hold of the lab lock")
live = pytest.mark.live

APP = ESTIMED / "apps" / "vru_warning" / "vru_warning.py"
LIVE_LOCK = os.environ.get("ESTIMED_LIVE_LOCK", "/home/edgefollow/estimed-run/.live.lock")
ZONE = "crossing-1"
SAMPLES = ["48.1351,11.5820", "48.1361,11.5835"]          # the vehicle's own positions, in `telemetry` only
CREATE, RETRIEVE, UPDATE, DELETE, NOTIFY, DISCOVER = 1, 2, 4, 8, 16, 32
BASE = {EDGE_A: f"{EDGE_A[0]}/{EDGE_A[1]}", EDGE_B: f"{EDGE_B[0]}/{EDGE_B[1]}", IN_CSE: f"{IN_CSE[0]}/{IN_CSE[1]}"}
CSI_OF = {EDGE_A: "/id-mn-a", EDGE_B: "/id-mn-b"}
PERIOD = 0.05                                              # warning AE and vehicle both look every 50 ms

# What the warning AE may write, stated here and NOT taken from the module, so a fault that widens both the record and
# the module's own constant is still caught.
WARNING_KEYS = {"cmd", "id", "rule", "zone", "class", "event_t", "issued_t", "expires_t"}
LOG_KEYS, LOG_EVENTS = {"event", "id"}, {"issued", "written", "acked", "expired"}
HELD = {"route-none", "route-stale", "route-moving", "route-unknown", "not-the-vehicle"}   # {"event": "held", "id": ...}
RULE_ID = "vru-present-and-vehicle-approaching-in-zone/1"
_HEX12 = re.compile(r"[0-9a-f]{12}\Z")


def _load():
    """The app module, loaded from its file (it is a deployable package, not an installed one)."""
    spec = importlib.util.spec_from_file_location("vru_warning", APP)
    if spec is None or not APP.exists():
        pytest.fail(f"{APP} does not exist", pytrace=False)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def vw():
    return _load()


def _now_ms() -> int:
    return int(time.time() * 1000)


def _int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _warning_errors(con) -> list[str]:
    """Why a warning record is not exactly what the vehicle is to be told ([] when it is)."""
    try:
        d = json.loads(con) if isinstance(con, str) else con
    except ValueError:
        return ["not JSON"]
    if not isinstance(d, dict):
        return ["not an object"]
    bad = [f"key {k!r}" for k in sorted(set(d) ^ WARNING_KEYS)]
    if bad:
        return bad
    checks = {"cmd": d["cmd"] == "vru-warning", "id": isinstance(d["id"], str) and bool(_HEX12.match(d["id"])),
              "rule": d["rule"] == RULE_ID, "zone": d["zone"] == ZONE, "class": d["class"] in ("pedestrian", "cyclist"),
              "event_t": _int(d["event_t"]), "issued_t": _int(d["issued_t"]), "expires_t": _int(d["expires_t"])}
    return [f"value of {k}: {d[k]!r}" for k, ok in checks.items() if not ok]


def _log_errors(con) -> list[str]:
    try:
        d = json.loads(con) if isinstance(con, str) else con
    except ValueError:
        return ["not JSON"]
    if not isinstance(d, dict) or set(d) != LOG_KEYS:
        return [f"keys {sorted(d) if isinstance(d, dict) else d!r}"]
    if d["event"] == "held":
        return [] if d["id"] in HELD else [f"values {d}"]
    return [] if d["event"] in LOG_EVENTS and isinstance(d["id"], str) and _HEX12.match(d["id"]) else [f"values {d}"]


# --- offline: the rule, the record shapes, the route record -----------------------------------------------------

def _rec(**kw):
    now = 1_000_000
    s = {"zone": ZONE, "present": True, "class": "pedestrian", "t": now - 100, "sim": True}
    v = {"zone": ZONE, "approach": True, "t": now - 100, "sim": True}
    for k, val in kw.items():
        who, _, key = k.partition("__")
        (s if who == "s" else v)[key] = val
    return s, v, now


def test_offline_rule_fires_on_a_present_road_user_and_an_approaching_vehicle_in_the_zone(vw):
    s, v, now = _rec()
    assert vw.rule_fires(s, v, ZONE, now) == (True, "fires")
    s, v, now = _rec(s__class="cyclist")
    assert vw.rule_fires(s, v, ZONE, now)[0] is True


@pytest.mark.parametrize("change", [
    {"s__present": False}, {"s__present": "true"}, {"s__class": "car"}, {"s__class": ["pedestrian"]},
    {"s__zone": "crossing-2"}, {"v__zone": "crossing-2"}, {"v__approach": False}, {"v__approach": 1},
    {"s__t": 1_000_000 - 2001}, {"v__t": 1_000_000 - 2001}, {"s__t": 1_000_000 + 1000}, {"v__t": 1_000_000 + 1000},
    {"v__t": 1_000_000 + 10_000_000}, {"s__t": True}, {"v__t": None},
], ids=lambda c: ",".join(f"{k}={v}" for k, v in c.items()))
def test_offline_control_rule_does_not_fire(vw, change):
    s, v, now = _rec(**change)
    fires, why = vw.rule_fires(s, v, ZONE, now)
    assert fires is False and why != "fires", (change, why)


def test_offline_control_rule_needs_both_records(vw):
    s, v, now = _rec()
    assert vw.rule_fires(None, v, ZONE, now)[0] is False
    assert vw.rule_fires(s, None, ZONE, now)[0] is False
    assert vw.rule_fires(s, v, "crossing-2", now)[0] is False, "the AE watches its own zone only"


def test_offline_the_warning_and_the_log_record_are_exactly_their_keys(vw):
    assert _warning_errors(vw.warning_body("ab12cd34ef56", ZONE, "pedestrian", 1_000, 1_050, 4_000)) == []
    assert _log_errors(vw.log_record("written", "ab12cd34ef56")) == []


@pytest.mark.parametrize("extra", [{"pos": [0.0, 0.0]}, {"edge": "/id-mn-a"}, {"vehicle": "Cvehicle01"}],
                         ids=["pos", "edge", "vehicle"])
def test_offline_control_the_shape_check_catches_an_added_key(vw, extra):
    assert _warning_errors(vw.warning_body("ab12cd34ef56", ZONE, "pedestrian", 1, 2, 3) | extra) != []
    assert _log_errors(vw.log_record("acked", "ab12cd34ef56") | extra) != []


def test_offline_control_route_record_names_one_fresh_known_edge_or_nothing(vw):
    edges, now = {"/id-mn-a", "/id-mn-b"}, 10_000_000
    good = {"aei": "Cv", "serving": "/id-mn-b", "state": "ATTACHED", "t": now - 1000}
    assert vw.route_edge(good, "Cv", edges, now) == "/id-mn-b"
    for bad in ({**good, "state": "MOVING"}, {**good, "serving": None}, {**good, "serving": "/id-mn-c"},
                {**good, "aei": "Cother"}, {**good, "serving": ["/id-mn-a"]}, {**good, "t": now - 60_001},
                {**good, "t": now + 1000}, {**good, "t": None}, None, "x"):
        assert vw.route_edge(bad, "Cv", edges, now) is None, bad
    moving = {"aei": "Cv", "state": "MOVING", "serving": None}
    assert vw.route_state(moving | {"t": now - vw.MAX_MOVE_MS}, "Cv", edges, now) == (None, "route-moving")
    assert vw.route_state(moving | {"t": now - vw.MAX_MOVE_MS - 1}, "Cv", edges, now) == (None, "route-stale"), \
        "a MOVING record older than MAX_MOVE_MS: its keeper died inside the move"
    two = {"aei": "Cv", "state": "UNKNOWN", "serving": None, "t": now}
    assert vw.route_state(two, "Cv", edges, now) == (None, "route-unknown")


# --- offline: the AE against an in-memory stand-in CSE ---------------------------------------------------------

# Closed loopback ports: a request that ever escapes the stand-in is refused here, never resolved or sent anywhere.
FA, FB, FIN = "http://127.0.0.1:9/cse-mn-a", "http://127.0.0.1:9/cse-mn-b", "http://127.0.0.1:9/cse-in"
FV = "Cvehicle01"


class FakeCse:
    """Not a CSE: containers (url -> [(ri, con)]), <AE>s (url -> aei), answered as the AE's client asks. A delay or
    an exception can be set per URL prefix. Every request goes into the AE client's `sent`, as the real client does."""

    def __init__(self):
        self.cnt, self.aes, self.delay, self.raise_on, self.n = {}, {}, {}, {}, 0
        self.forbidden: set[str] = set()                         # URLs answered 403

    def put(self, url, con):
        self.n += 1
        self.cnt.setdefault(url, []).append((f"ri{self.n}", con if isinstance(con, str) else json.dumps(con)))

    def req(self, client, method, url, ty=None, body=None):
        for p, d in self.delay.items():
            if url.startswith(p):
                time.sleep(d)
        for p, e in self.raise_on.items():
            if url.startswith(p):
                raise e
        status, out = 404, None
        if url in self.forbidden:
            status = 403
        elif method == "GET" and url.endswith("/la") and self.cnt.get(url[:-3]):
            ri, con = self.cnt[url[:-3]][-1]
            status, out = 200, {"m2m:cin": {"ri": ri, "con": con}}
        elif method == "GET" and url.endswith("?rcn=4") and url[:-6] in self.cnt:
            status, out = 200, {"m2m:cnt": {"m2m:cin": [{"ri": r, "con": c} for r, c in self.cnt[url[:-6]]]}}
        elif method == "GET" and url in self.aes:
            status, out = 200, {"m2m:ae": {"aei": self.aes[url]}}
        elif method == "POST" and ty == TY_CIN and url in self.cnt:
            self.put(url, body["m2m:cin"]["con"])
            status = 201
        client.sent.append({"t": time.time(), "method": method, "url": url, "ty": ty, "origin": client.origin,
                            "status": status, "body": body})
        return status, out

    def route(self, state="ATTACHED", serving="/id-mn-a", t=None):
        self.put(f"{FIN}/route-{FV}", {"aei": FV, "state": state, "serving": serving, "t": _now_ms() if t is None else t})

    def event(self, **kw):
        self.put(f"{FA}/rsu/vru", {"zone": ZONE, "present": True, "class": "pedestrian", "t": _now_ms()} | kw)

    def ctx(self, edge=FA, **kw):
        self.put(f"{edge}/vehicle01/ctx", {"zone": ZONE, "approach": True, "t": _now_ms()} | kw)


def _fake(vw, **over):
    f = FakeCse()
    ae = vw.WarningAE({"origin": "Cw", "rn": "w", "cse": FA, "in": FIN, "edges": {"/id-mn-a": FA, "/id-mn-b": FB},
                       "vehicle": {"aei": FV, "rn": "vehicle01"}, "sensor": f"{FA}/rsu/vru", "zone": ZONE} | over)
    ae.client.req = lambda m, u, ty=None, body=None: f.req(ae.client, m, u, ty, body)
    for edge in (FA, FB):
        f.aes[f"{edge}/vehicle01"] = FV
        for c in ("ctx", "cmd", "ack"):
            f.cnt.setdefault(f"{edge}/vehicle01/{c}", [])
    for url in (f"{FA}/rsu/vru", f"{FIN}/route-{FV}", f"{FA}/w/log"):
        f.cnt.setdefault(url, [])
    return f, ae


def _cmd_posts(ae, edge=None):
    return [s for s in ae.client.sent if s["method"] == "POST" and s["url"].endswith("/cmd")
            and (edge is None or s["url"].startswith(edge))]


def _an_open_warning(vw, **over):
    f, ae = _fake(vw, **over)
    f.route()
    f.ctx()
    f.event()
    ae.step()
    assert len(ae.warnings) == 1 and len(_cmd_posts(ae, FA)) == 1, ae.events
    return f, ae, next(iter(ae.warnings.values()))


@pytest.mark.parametrize("where", ["rsu/vru", "vehicle01/ctx", "vehicle01/ack"])
@pytest.mark.parametrize("con", ["[" * 100_000, "x" * 100_000, json.dumps({"zone": ZONE, "present": True,
                                                                           "class": ["pedestrian"], "t": 0})],
                         ids=["deep-nesting", "too-long", "class-is-a-list"])
def test_offline_control_one_bad_record_does_not_stop_the_watch(vw, where, con):
    """A record in any container the AE reads: run() keeps going, and the open warning is still handled (it expires
    on time, no exception escapes, no write after it)."""
    f, ae, w = _an_open_warning(vw, ttl_ms=300)
    f.put(f"{FA}/{where}", con)
    stop, escaped = threading.Event(), []

    def target():
        try:
            ae.run(stop, 0.01)
        except BaseException as e:  # noqa: BLE001
            escaped.append(repr(e)[:120])
    t = threading.Thread(target=target, daemon=True)
    t.start()
    time.sleep(0.6)
    alive = t.is_alive()
    stop.set()
    t.join(2)
    assert alive and not escaped, escaped
    assert w["status"] == "expired", w
    assert all(int(s["t"] * 1000) <= w["expires_t"] for s in _cmd_posts(ae))


def test_offline_control_a_parser_recursion_error_is_no_record(vw, monkeypatch):
    """A parser that gives up on nesting: no record, never raised. (CPython 3.13's C parser raises RecursionError
    only past about 9000 levels, more than MAX_CON_CHARS allows; the pure-Python one past the recursion limit.)"""
    def deep(_):
        raise RecursionError("maximum recursion depth exceeded while decoding a JSON array")
    monkeypatch.setattr(vw, "json", types.SimpleNamespace(loads=deep, dumps=json.dumps))
    assert vw.parse_con('[[["deep"]]]') is None


def test_offline_control_an_oversized_record_is_no_record(vw):
    """A detection that would fire, padded past MAX_CON_CHARS: no record, so no warning."""
    f, ae = _fake(vw)
    f.route()
    f.ctx()
    f.event(pad="x" * vw.MAX_CON_CHARS)
    ae.step()
    assert ae.warnings == {} and _cmd_posts(ae) == []
    f.event()                                                  # control: the same detection, unpadded
    ae.step()
    assert len(ae.warnings) == 1


def test_offline_control_run_survives_a_failing_step(vw):
    f, ae, w = _an_open_warning(vw, ttl_ms=300)
    real, calls = ae.step, []

    def step():
        calls.append(1)
        if len(calls) == 1:
            raise RecursionError("planted in step")
        real()
    ae.step = step
    stop, escaped = threading.Event(), []

    def target():
        try:
            ae.run(stop, 0.01)
        except BaseException as e:  # noqa: BLE001
            escaped.append(repr(e)[:120])
    t = threading.Thread(target=target, daemon=True)
    t.start()
    time.sleep(0.5)
    alive = t.is_alive()
    stop.set()
    t.join(2)
    assert alive and not escaped and len(calls) > 2 and w["status"] == "expired", (escaped, len(calls), w)


def test_offline_control_an_exception_in_a_look_does_not_stop_the_watch(vw):
    f, ae, w = _an_open_warning(vw, ttl_ms=300)
    f.ctx()
    f.event()                                                    # a new event: the event half reads the route too
    f.raise_on[f"{FIN}/route-"] = RecursionError("planted")      # every route read fails from here
    stop, escaped = threading.Event(), []

    def target():
        try:
            ae.run(stop, 0.01)
        except BaseException as e:  # noqa: BLE001
            escaped.append(repr(e)[:120])
    t = threading.Thread(target=target, daemon=True)
    t.start()
    time.sleep(0.5)
    alive = t.is_alive()
    stop.set()
    t.join(2)
    assert alive and not escaped and w["status"] == "expired", (escaped, w)
    assert any(e.get("event") == "error" for e in ae.events), "the failure is recorded, not silent"


def test_offline_control_one_sensor_event_gives_one_warning(vw):
    """The same detection stays the sensor's latest for several looks: still one warning, written once."""
    f, ae, w = _an_open_warning(vw)
    for _ in range(5):
        ae.step()
    assert list(ae.warnings) == [w["id"]] and len(_cmd_posts(ae)) == 1, (list(ae.warnings), len(_cmd_posts(ae)))


def test_offline_control_a_negative_acknowledgement_does_not_count(vw):
    f, ae, w = _an_open_warning(vw)
    f.put(f"{FA}/vehicle01/ack", {"id": w["id"], "ok": False})
    f.put(f"{FA}/vehicle01/ack", {"id": w["id"]})
    for _ in range(3):
        ae.step()
    assert w["status"] == "open", w
    f.put(f"{FA}/vehicle01/ack", {"id": w["id"], "ok": True})
    ae.step()
    assert w["status"] == "acked"


def test_offline_control_no_write_after_expiry_even_when_the_ack_read_is_slow(vw):
    """Written to A, unanswered; the route names B; B answers the ack read slowly, past the warning's expiry: the AE
    looks at the clock again before the write and writes nothing to B."""
    f, ae, w = _an_open_warning(vw, ttl_ms=600)
    f.route(serving="/id-mn-b")
    time.sleep(max(0.0, (w["expires_t"] - _now_ms()) / 1000) - 0.25)    # about 250 ms left
    f.delay[f"{FB}/vehicle01/ack"] = 0.5
    ae.step()
    assert _cmd_posts(ae, FB) == [] and w["status"] == "expired", (w, _cmd_posts(ae, FB))


def test_offline_control_a_warning_about_to_expire_is_not_written(vw):
    """Less than WRITE_MARGIN_MS left when its turn comes (the route has just named B): dropped, not written -- the CSE
    would get it after its et, refuse it and log that."""
    f, ae, w = _an_open_warning(vw, ttl_ms=600)
    f.route(serving="/id-mn-b")
    time.sleep(max(0.0, (w["expires_t"] - _now_ms() - vw.WRITE_MARGIN_MS // 2) / 1000))
    ae.step()
    assert _cmd_posts(ae, FB) == [] and w["status"] == "expired", (w, _cmd_posts(ae, FB))


def test_offline_the_warning_expires_counted_from_the_sensor_event_not_from_its_issue(vw):
    f, ae = _fake(vw)
    f.route()
    f.ctx()
    t_event = _now_ms() - 1500
    f.event(t=t_event)
    ae.step()
    (w,) = ae.warnings.values()
    assert w["expires_t"] == t_event + vw.WARNING_TTL_MS, w
    (post,) = _cmd_posts(ae, FA)
    assert post["body"]["m2m:cin"]["et"] == vw.stamp(w["expires_t"]), "the CSE is told when to drop it"


def test_offline_control_a_stale_or_future_route_record_routes_nothing(vw):
    for t in (_now_ms() - 61_000, _now_ms() + 10_000):
        f, ae = _fake(vw)
        f.route(t=t)
        f.ctx()
        f.event()
        ae.step()
        assert _cmd_posts(ae) == [] and ae.warnings == {}, t


def test_offline_control_not_the_vehicles_ae_at_its_name_gets_nothing(vw):
    f, ae, w = _an_open_warning(vw)
    f.aes[f"{FA}/vehicle01"] = "Cimpostor"                      # the name on A is someone else's now
    f.put(f"{FA}/vehicle01/ack", {"id": w["id"], "ok": True})
    f.ctx()
    f.event()
    for _ in range(3):
        ae.step()
    assert w["status"] == "open" and len(ae.warnings) == 1 and len(_cmd_posts(ae)) == 1, ae.warnings


@pytest.mark.parametrize("answer", [403, 404], ids=["forbidden", "absent"])
def test_offline_control_an_ae_that_cannot_be_read_at_the_vehicles_name_is_not_the_vehicle(vw, answer):
    """The name on A answers 403 (an impostor that does not grant its <AE>) or 404: not the vehicle; nothing read under
    it, nothing written, the open warning held, and why is logged."""
    f, ae, w = _an_open_warning(vw)
    del f.aes[f"{FA}/vehicle01"]
    if answer == 403:
        f.forbidden.add(f"{FA}/vehicle01")
    f.put(f"{FA}/vehicle01/ack", {"id": w["id"], "ok": True})
    f.ctx()
    f.event()
    n = len(ae.client.sent)
    for _ in range(3):
        ae.step()
    under = [x["url"] for x in ae.client.sent[n:] if x["url"].startswith(f"{FA}/vehicle01/")]
    assert w["status"] == "open" and len(ae.warnings) == 1 and len(_cmd_posts(ae)) == 1 and under == [], \
        (w["status"], len(ae.warnings), under)
    assert {"event": "held", "id": "not-the-vehicle"} in ae.events


def test_offline_a_held_warning_is_logged_with_its_reason_at_most_every_10_s(vw, monkeypatch):
    """No usable route: the AE logs held/<reason> once, not again within HELD_LOG_EVERY_MS, then again; each reason
    on its own clock. On a fake clock."""
    clock = [5_000_000]
    monkeypatch.setattr(vw, "now_ms", lambda: clock[0])
    f, ae = _fake(vw)
    f.route(t=clock[0] - 61_000)                                 # stale
    f.ctx(t=clock[0])
    f.event(t=clock[0])

    def held():
        return [e["id"] for e in ae.events if e.get("event") == "held"]
    ae.step(clock[0])
    assert held() == ["route-stale"]
    for dt in (1_000, 5_000, 9_999):
        f.event(t=clock[0] + dt)                                 # new, fresh events: the route is still needed
        f.ctx(t=clock[0] + dt)
        clock[0] += dt - (clock[0] - 5_000_000)
        ae.step(clock[0])
    assert held() == ["route-stale"], held()
    clock[0] = 5_000_000 + 10_000
    f.event(t=clock[0])
    f.ctx(t=clock[0])
    ae.step(clock[0])
    assert held() == ["route-stale", "route-stale"], held()
    f.route(state="MOVING", serving=None, t=clock[0])
    f.event(t=clock[0])
    ae.step(clock[0])
    assert held() == ["route-stale", "route-stale", "route-moving"], held()
    assert _cmd_posts(ae) == [] and ae.warnings == {}
    logged = [json.loads(x["body"]["m2m:cin"]["con"]) for x in ae.client.sent if x["url"].endswith("/w/log")]
    assert logged == [{"event": "held", "id": r} for r in held()], logged


def test_offline_the_route_keeper_publishes_on_time_and_moving_around_a_move(vw):
    """On a fake clock: published at open, again once period_s has passed, never in between; MOVING at the start of a
    move, then settle_s for the vehicle to see it, then the move, nothing periodic during it, the new edge right after;
    a failed publication is tried again."""
    t, calls, answer = [0.0], [], [201]
    serving = [["/id-mn-a"]]

    def publish(in_base, aei, edges, *, moving=False, origin=None, timeout=None):
        calls.append(("MOVING" if moving else tuple(edges), t[0]))
        return answer[0]
    k = vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw", FV], serving=lambda: serving[0], period_s=30,
                       settle_s=0.2, clock=lambda: t[0], publish=publish, sleep=lambda d: calls.append(("sleep", d)))
    assert k.publish() == 201 and k.tick() is False
    for t[0] in (10.0, 29.9):
        assert k.tick() is False
    t[0] = 30.0
    assert k.tick() is True
    with k.moving():
        calls.append(("the move", t[0]))
        t[0] = 100.0
        assert k.tick() is False, "nothing periodic during a move"
        serving[0] = ["/id-mn-b"]
    assert calls[2:] == [("MOVING", 30.0), ("sleep", 0.2), ("the move", 30.0), (("/id-mn-b",), 100.0)], calls
    assert [c[0] for c in calls[:2]] == [("/id-mn-a",), ("/id-mn-a",)], calls
    answer[0] = 500
    t[0] = 131.0
    assert k.tick() is False and k.tick() is False, "a refused publication is not counted as done"
    answer[0] = 201
    assert k.tick() is True and calls[-1] == (("/id-mn-b",), 131.0)
    assert vw.ROUTE_SETTLE_S >= 2 * PERIOD, "the default settle covers two of the vehicle's looks at its route"


def _beating_keeper(vw, record, t, fail_every=0, fail_how="raises"):
    """A keeper on a fake clock: each heartbeat wait advances it by the wait's length (real time barely moves)."""
    lock, n = threading.Lock(), [0]

    def publish(in_base, aei, edges, *, moving=False, origin=None, timeout=None):
        with lock:
            n[0] += 1
            if fail_every and moving and n[0] > 1 and n[0] % fail_every == 0:
                if fail_how == "raises":
                    raise OSError("the IN did not answer this beat")
                return 500                                        # refused: an answer, not a MOVING
            record.append(("MOVING" if moving else tuple(edges), t[0]))
        return 201

    def wait(stop, seconds):
        if stop.wait(0.002):
            return True
        with lock:
            t[0] += seconds
        return False
    return vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw", FV], serving=lambda: ["/id-mn-b"], settle_s=0.0,
                          clock=lambda: t[0], publish=publish, sleep=lambda d: None, wait=wait)


def test_offline_a_60_s_move_keeps_moving_fresh_and_ends_with_the_edge(vw):
    """The heartbeat: while a move lasts 60 s (fake clock) the record says MOVING and is never older than
    MOVING_BEAT_MS; when the move ends the heartbeat stops and the last word is the edge the IN names."""
    beat = vw.MOVING_BEAT_MS / 1000
    assert vw.MOVING_BEAT_MS * 3 <= vw.MAX_MOVE_MS, "two missed beats still leave MOVING fresh"
    t, record = [0.0], []
    k = _beating_keeper(vw, record, t)
    deadline = time.time() + 10                                   # real time: a stalled heartbeat fails, not hangs
    with k.moving():
        while t[0] < 60.0 and time.time() < deadline:
            time.sleep(0.001)                                     # the handover, 60 s on the fake clock
    n = len(record)
    time.sleep(0.1)
    moving = [x for x in record if x[0] == "MOVING"]
    gaps = [b[1] - a[1] for a, b in zip(moving, moving[1:])]
    assert record[-1][0] == ("/id-mn-b",) and len(record) == n, "the heartbeat went on after the move"
    assert moving[0][1] == 0.0 and moving[-1][1] >= 60.0 - beat and max(gaps) <= beat, (moving[:3], max(gaps))
    assert all(x[0] == "MOVING" for x in record[:-1]), "only MOVING during the move"


@pytest.mark.parametrize("how", ["raises", "refused"])
def test_offline_a_failed_heartbeat_does_not_abort_the_move(vw, how):
    """Every third heartbeat publication fails (an exception, or a refusal): the move goes on, the beats after a failure
    still publish, the failures are kept, MOVING never ages past two beats, and the move ends with the edge."""
    beat = vw.MOVING_BEAT_MS / 1000
    t, record = [0.0], []
    k = _beating_keeper(vw, record, t, fail_every=3, fail_how=how)
    deadline = time.time() + 10
    with k.moving():
        while t[0] < 30.0 and time.time() < deadline:
            time.sleep(0.001)
    moving = [x[1] for x in record if x[0] == "MOVING"]
    gaps = [b - a for a, b in zip(moving, moving[1:])]
    assert record[-1][0] == ("/id-mn-b",) and k.errors and max(gaps) <= 2 * beat < vw.MAX_MOVE_MS / 1000, \
        (gaps, k.errors[:2])
    first_gap = next(i for i, g in enumerate(gaps) if g > beat)           # the first failed beat
    assert len(moving) - (first_gap + 1) >= 5, "the heartbeat stopped at a failure"


def test_offline_control_a_beat_after_the_move_is_dropped(vw):
    """H1: a heartbeat publication that comes when no move is on publishes nothing (0)."""
    record = []
    k = vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw"], serving=lambda: ["/id-mn-b"], publish=_record(record),
                       sleep=lambda d: None)
    assert k.publish(moving=True, beat=True) == 0 and record == []
    assert k.publish() == 201 and record == ["ATTACHED /id-mn-b"], "control: the route itself is published"


def test_offline_control_the_heartbeat_is_stopped_before_the_edge_is_published(vw):
    """H2 (and with H1, H12), the reviewer's shape: a beat falls due exactly when the edge has been published. The
    heartbeat must already be stopped then -- it sees the stop, never a due beat after the edge -- and the record's
    last word is the edge."""
    log, edge_done, seen = [], threading.Event(), []

    def publish(in_base, aei, edges, *, moving=False, origin=None, timeout=None):
        log.append("MOVING" if moving else "EDGE")
        if not moving:
            edge_done.set()
        return 201

    def wait(stop, seconds):
        while True:
            if edge_done.is_set():
                seen.append("beat due after the edge")
                return False
            if stop.is_set():
                seen.append("stopped")
                return True
            time.sleep(0.005)
    k = vw.RouteKeeper("http://127.0.0.1:9/cse-in", "Cv", ["Cw"], serving=lambda: ["/id-mn-b"], publish=publish,
                       settle_s=0.0, wait=wait, beat_s=0.01, sleep=lambda d: None)
    with k.moving():
        time.sleep(0.05)
    time.sleep(0.3)
    assert seen == ["stopped"] and log == ["MOVING", "EDGE"], (seen, log)


def test_offline_two_timed_out_beats_still_leave_moving_fresh(vw, monkeypatch):
    """Two beat publications in a row time out (each takes the beat's client timeout, BEAT_TIMEOUT_S): on a fake clock
    the record is then at most 3 beats + 2 timeouts old when the third beat refreshes it -- under MAX_MOVE_MS. The
    keeper must hand the short timeout to the publication, and publish_route must hand it to the client."""
    beat, tmo, bound = vw.MOVING_BEAT_MS / 1000, vw.BEAT_TIMEOUT_S, vw.MAX_MOVE_MS / 1000
    assert 3 * beat + 2 * tmo < bound, "the constants do not leave room for two timed-out beats"
    t, record, n, lock = [0.0], [], [0], threading.Lock()

    def publish(in_base, aei, edges, *, moving=False, origin=None, timeout=None):
        with lock:
            n[0] += 1
            if moving and n[0] in (2, 3):                         # the first two beats time out
                t[0] += timeout if timeout is not None else 5.0   # the client's default if none was handed over
                return 0
            record.append(("MOVING" if moving else tuple(edges), t[0]))
        return 201

    def wait(stop, seconds):
        if stop.wait(0.002):
            return True
        with lock:
            t[0] += seconds
        return False
    k = vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw"], serving=lambda: ["/id-mn-b"], settle_s=0.0,
                       clock=lambda: t[0], publish=publish, sleep=lambda d: None, wait=wait)
    deadline = time.time() + 10
    with k.moving():
        while t[0] < 30.0 and time.time() < deadline:
            time.sleep(0.001)
    moving = [x[1] for x in record if x[0] == "MOVING"]
    gaps = [b - a for a, b in zip(moving, moving[1:])]
    assert max(gaps) == pytest.approx(3 * beat + 2 * tmo) and max(gaps) < bound, (gaps[:3], bound)
    seen = []
    monkeypatch.setattr(vw, "_admin", lambda m, u, ty=None, body=None, origin=None, timeout=5.0:
                        seen.append(timeout) or (201, None))
    assert vw.publish_route("http://127.0.0.1:9/cse-in", FV, [], moving=True, timeout=tmo) == 201 and seen == [tmo]


def test_offline_control_the_route_keeper_publishes_nothing_it_cannot_read(vw):
    def unreadable():
        raise OSError("the IN did not answer")
    calls = []
    k = vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw"], serving=unreadable, period_s=0.01, settle_s=0.0,
                       publish=lambda *a, **kw: calls.append(a) or 201)
    stop = threading.Event()
    th = threading.Thread(target=k.run, args=(stop, 0.01), daemon=True)
    th.start()
    time.sleep(0.2)
    stop.set()
    th.join(2)
    assert calls == [] and k.errors and k.last is None, (calls, k.errors[:2])


def test_offline_the_module_offers_no_route_keeper_command(vw, capsys):
    """One keeper per route, in the handover driver's process: the module has no command that would start a second."""
    with pytest.raises(SystemExit) as e:
        vw.main(["keep-route", "--in", "http://127.0.0.1:9/cse-in", "--aei", FV, "--reader", "Cw"])
    assert e.value.code == 2 and "keep-route" not in (vw.__doc__ or "")
    assert "ONE keeper per route" in vw.__doc__ and "not supported" in vw.__doc__
    capsys.readouterr()


def _record(state_log):
    def publish(in_base, aei, edges, *, moving=False, origin=None, timeout=None):
        state_log.append("MOVING" if moving else (f"ATTACHED {edges[0]}" if len(edges) == 1 else "UNKNOWN"))
        return 201
    return publish


def test_offline_control_a_tick_that_passed_its_check_cannot_overwrite_moving(vw):
    """The reviewer's race: the keeper's own tick() passes its not-moving check, is pre-empted 0.2 s before it takes the
    lock, and moving() begins meanwhile. The record must say MOVING for the whole move."""
    record, t = [], [0.0]
    k = vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw", FV], serving=lambda: ["/id-mn-a"], period_s=30,
                       publish=_record(record), clock=lambda: t[0], sleep=lambda d: None)
    k.publish()
    t[0] = 31.0
    real = k._lock

    class SlowFirst:
        n = 0

        def __enter__(self):
            SlowFirst.n += 1
            if SlowFirst.n == 1 and threading.current_thread().name == "ticker":
                time.sleep(0.2)                                  # pre-empted after its _moving check
            return real.__enter__()

        def __exit__(self, *a):
            return real.__exit__(*a)
    k._lock = SlowFirst()
    th = threading.Thread(target=k.tick, name="ticker")
    th.start()
    time.sleep(0.05)
    with k.moving():
        time.sleep(0.3)                                          # the handover
        during = record[-1]
    th.join(2)
    assert during == "MOVING" and record[-1] == "ATTACHED /id-mn-a", record


class FakeAdmin:
    """The IN's route record and ACP, for RouteKeeper.open(): what exists, and every request made."""

    def __init__(self, acp=None, cnt=None, other=None):
        self.acp, self.cnt, self.other, self.calls = acp, cnt, other, []

    def __call__(self, method, url, ty=None, body=None, origin=None):
        self.calls.append((method, url.rsplit("/", 1)[-1], origin))
        name = url.rsplit("/", 1)[-1]
        if method == "GET":
            if self.other is not None and name == f"route-{FV}":
                return 200, self.other
            hit = self.acp if name.endswith("-acp") else self.cnt
            return (200, hit) if hit is not None else (404, None)
        if method == "POST" and ty == TY_ACP:
            self.acp = {"m2m:acp": body["m2m:acp"] | {"ri": "acpNEW"}}
            return 201, self.acp
        if method == "POST" and ty == TY_CNT:
            self.cnt = {"m2m:cnt": body["m2m:cnt"]}
            return 201, self.cnt
        if method == "PUT":
            self.acp["m2m:acp"].update(body["m2m:acp"])
            return 200, self.acp
        return 404, None


def _keeper(vw, admin, record):
    return vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw", FV], serving=lambda: ["/id-mn-a"], admin=admin,
                          publish=_record(record), sleep=lambda d: None)


def test_offline_a_restarted_keeper_takes_its_own_record_over_and_clears_moving(vw):
    """The keeper died inside a move: its record (last word MOVING) and its ACP are still there. A new keeper of the
    same originator looks first, takes both over (no CREATE: nothing the CSE would answer 409), and publishes the route
    as the IN names it now."""
    own_acp = {"m2m:acp": {"rn": f"route-{FV}-acp", "ri": "acpOLD", "pv": {"acr": [{"acor": ["Cw"], "acop": 2}]},
                           "pvs": {"acr": [{"acor": ["CAdmin"], "acop": 63}]}}}
    admin, record = FakeAdmin(acp=own_acp, cnt={"m2m:cnt": {"rn": f"route-{FV}", "acpi": ["acpOLD"]}}), ["MOVING"]
    assert _keeper(vw, admin, record).open() == 201
    assert record == ["MOVING", "ATTACHED /id-mn-a"], record
    assert [c[0] for c in admin.calls] == ["GET", "GET", "PUT"], admin.calls      # its readers set, nothing created
    assert admin.acp["m2m:acp"]["pv"] == {"acr": [{"acor": ["Cw", FV], "acop": 2}]}


_OWN_PVS = {"acr": [{"acor": ["CAdmin"], "acop": 63}]}


def _route_acp(pvs=None, ri="acpOLD"):
    return {"m2m:acp": {"ri": ri, "pv": {"acr": [{"acor": ["Cw"], "acop": 2}]}, "pvs": pvs or _OWN_PVS}}


_NOT_OURS = {
    "an AE": dict(other={"m2m:ae": {"rn": f"route-{FV}", "aei": "Csquat"}}),
    "another originator's ACP": dict(acp=_route_acp({"acr": [{"acor": ["Csomeone"], "acop": 63}]}, "acpX"),
                                     cnt={"m2m:cnt": {"acpi": ["acpX"]}}),
    "T3 ACP self-privileges also a stranger's (two rules)": dict(
        acp=_route_acp({"acr": [{"acor": ["CAdmin"], "acop": 63}, {"acor": ["Cevil"], "acop": 63}]}),
        cnt={"m2m:cnt": {"acpi": ["acpOLD"]}}),
    "T3b ACP self-privileges also a stranger's (one rule)": dict(
        acp=_route_acp({"acr": [{"acor": ["CAdmin", "Cevil"], "acop": 63}]}), cnt={"m2m:cnt": {"acpi": ["acpOLD"]}}),
    "T4 the record carries another ACP": dict(acp=_route_acp(), cnt={"m2m:cnt": {"acpi": ["acpOTHER"]}}),
    "T4b the record carries ours and another": dict(acp=_route_acp(), cnt={"m2m:cnt": {"acpi": ["acpOLD", "acpEVIL"]}}),
    "T6 our ACP left, the record gone (a crash between the two creates)": dict(acp=_route_acp()),
}


@pytest.mark.parametrize("held", list(_NOT_OURS))
def test_offline_control_a_keeper_does_not_take_over_what_is_not_its_own(vw, held):
    """The name is held by something that is not exactly this keeper's -- another party's <AE> at the route's name, an
    ACP whose self-privileges are someone else's or ALSO someone else's, a record that carries another ACP (or ours and
    another), or a half-made pair: open() refuses (409) without any CREATE, UPDATE or publication."""
    admin = FakeAdmin(**_NOT_OURS[held])
    record = []
    assert _keeper(vw, admin, record).open() == 409
    assert record == [] and {c[0] for c in admin.calls} == {"GET"}, admin.calls


def test_offline_control_a_keeper_that_cannot_read_the_in_refuses(vw):
    """T8: the IN does not answer (status 0): no record can be judged, so open() refuses (409) and writes nothing."""
    calls = []

    def down(method, url, ty=None, body=None, origin=None):
        calls.append(method)
        return 0, None
    record = []
    assert _keeper(vw, down, record).open() == 409 and record == [] and set(calls) == {"GET"}, calls


def test_offline_a_keeper_with_nothing_there_makes_the_record(vw):
    admin, record = FakeAdmin(), []
    assert _keeper(vw, admin, record).open() == 201
    assert [c[0] for c in admin.calls] == ["GET", "GET", "POST", "POST"] and record == ["ATTACHED /id-mn-a"]


def test_offline_two_announced_edges_are_no_route(vw, monkeypatch):
    """The dual-attach window (DUAL_ATTACH: the IN routes the AE-ID to source and target): publish_route records
    UNKNOWN, no edge; the AE holds (route-unknown) and writes nothing."""
    sent = []
    monkeypatch.setattr(vw, "_admin", lambda m, u, ty=None, body=None, origin=None, timeout=5.0:
                        sent.append(body) or (201, None))
    assert vw.publish_route("http://127.0.0.1:9/cse-in", FV, ["/id-mn-a", "/id-mn-b"]) == 201
    rec = json.loads(sent[-1]["m2m:cin"]["con"])
    assert rec["state"] == "UNKNOWN" and rec["serving"] is None, rec
    record = []
    k = vw.RouteKeeper("http://127.0.0.1:9/cse-in", FV, ["Cw"], serving=lambda: ["/id-mn-a", "/id-mn-b"],
                       publish=_record(record), sleep=lambda d: None)
    assert k.publish() == 201 and record == ["UNKNOWN"] and k.published[-1][1] == "UNKNOWN"
    f, ae = _fake(vw)
    f.put(f"{FIN}/route-{FV}", rec)
    f.ctx()
    f.event()
    ae.step()
    assert _cmd_posts(ae) == [] and {"event": "held", "id": "route-unknown"} in ae.events


def test_offline_memory_is_bounded(vw):
    f, ae = _fake(vw, keep=50)
    f.route()
    for i in range(300):
        f.ctx()
        f.event()
        if ae.warnings:
            f.put(f"{FA}/vehicle01/ack", {"id": list(ae.warnings)[-1], "ok": True})
        ae.step()
    n_open = sum(w["status"] == "open" for w in ae.warnings.values())
    assert len(ae.warnings) <= 50 + n_open and len(ae.events) <= 50 and len(ae._warned_events) <= 50, \
        (len(ae.warnings), len(ae.events), len(ae._warned_events))


def test_offline_the_client_keeps_a_bounded_request_record(vw, monkeypatch):
    """client.sent keeps the last KEEP_SENT requests. Sent to a closed loopback port (nothing listens on 9)."""
    monkeypatch.setattr(vw, "KEEP_SENT", 5)
    c = vw.Client("Cx", timeout=0.5)
    for i in range(12):
        assert c.req("GET", f"http://127.0.0.1:9/x{i}")[0] == 0
    assert [s["url"][-3:] for s in c.sent] == ["/x7", "/x8", "/x9", "x10", "x11"]


# --- live: the parties -------------------------------------------------------------------------------------------

def _lock_holders(path: str) -> set[int]:
    """Pids holding a flock(2) lock on the file, from /proc/locks ("N: FLOCK ADVISORY WRITE <pid> MAJ:MIN:INODE ...",
    device numbers in hex; a waiting request carries "->" and is not a holder)."""
    st = os.stat(path)
    key = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
    with open("/proc/locks") as f:
        return {int(x[4]) for x in (line.split() for line in f) if len(x) >= 6 and x[1] == "FLOCK" and x[5] == key}


def _this_run() -> set[int]:
    """This process and its ancestors."""
    pids, pid = set(), os.getpid()
    while pid > 1 and pid not in pids:
        pids.add(pid)
        try:
            with open(f"/proc/{pid}/stat") as f:
                pid = int(f.read().rsplit(")", 1)[1].split()[1])      # field 4, after the command name
        except (OSError, ValueError, IndexError):
            break
    return pids


def _require_live_lock():
    """Live tests run only under THIS run's hold of the lab lock (flock -o LIVE_LOCK <command>): the lock's holder must
    be this process or one of its ancestors. Nobody holding it, or someone else holding it, is refused."""
    try:
        holders = _lock_holders(LIVE_LOCK)
    except OSError as e:
        pytest.fail(f"no lab lock at {LIVE_LOCK}: {e}", pytrace=False)
    if not holders:
        pytest.fail(f"live test without the lab lock: run under `flock -o {LIVE_LOCK} ...`", pytrace=False)
    if not holders & _this_run():
        pytest.fail(f"the lab lock is held by pid {sorted(holders)}, not by this run: wait for it under "
                    f"`flock -o {LIVE_LOCK} ...`", pytrace=False)


_LAB_FIXTURES = {"lab", "live_lock", "topology"}


def test_offline_every_test_that_touches_the_lab_is_marked_live(request):
    """`live` is registered with this run, and a test carries it exactly when it requests a fixture that reaches the
    lab (lab, live_lock, topology). By fixture names only: a test that sent requests to the lab itself, without those
    fixtures, would pass this check unmarked (and -m "not live" would run it)."""
    import inspect
    assert "live" in {x.split(":")[0].split("(")[0].strip() for x in request.config.getini("markers")}
    tests = {n: f for n, f in globals().items() if n.startswith("test_") and callable(f)}
    assert len(tests) > 50
    wrong = [n for n, f in tests.items()
             if bool(_LAB_FIXTURES & set(inspect.signature(f).parameters))
             != any(m.name == "live" for m in getattr(f, "pytestmark", []))]
    assert wrong == [], wrong


def test_offline_the_lock_guard_admits_only_a_lock_this_run_holds(tmp_path, monkeypatch):
    """On a scratch lock file, never the lab's: nobody holds it -> refused; another process holds it -> refused; this
    process holds it -> admitted; no lock file -> refused."""
    lock = tmp_path / "scratch.lock"
    lock.write_text("")
    monkeypatch.setattr(sys.modules[__name__], "LIVE_LOCK", str(lock))
    with pytest.raises(pytest.fail.Exception, match="without the lab lock"):
        _require_live_lock()
    other = subprocess.Popen([sys.executable, "-I", "-c", "import fcntl, sys, time; f = open(sys.argv[1]); "
                              "fcntl.flock(f, fcntl.LOCK_EX); print('held', flush=True); time.sleep(20)", str(lock)],
                             stdout=subprocess.PIPE, text=True)
    try:
        assert other.stdout.readline().strip() == "held"
        with pytest.raises(pytest.fail.Exception, match="not by this run"):
            _require_live_lock()                             # held, but by a process that is not this run
    finally:
        other.kill()                                         # the one process this test started
        other.wait(5)
    with open(lock) as held:
        fcntl.flock(held.fileno(), fcntl.LOCK_EX)
        _require_live_lock()                                 # held by this process: admitted
    with pytest.raises(pytest.fail.Exception, match="no lab lock"):
        monkeypatch.setattr(sys.modules[__name__], "LIVE_LOCK", str(tmp_path / "absent.lock"))
        _require_live_lock()


def _cin(url, origin, con, **attrs) -> tuple[int, dict | None]:
    st, body, _ = req("POST", url, origin, ty=TY_CIN, body={"m2m:cin": {
        "cnf": "application/json:0", "con": json.dumps(con, sort_keys=True), **attrs}})
    return st, body


def _acp(parent, owner, rn, rules) -> str:
    st, body, _ = req("POST", parent, owner, ty=TY_ACP, body={"m2m:acp": {
        "rn": rn, "pv": {"acr": [{"acor": [owner], "acop": 63}, *rules]}, "pvs": {"acr": [{"acor": [owner], "acop": 63}]}}})
    assert st == 201, (rn, body)
    return body["m2m:acp"]["ri"]


def _container(parent, owner, rn, acpi=None, mni=50):
    st, body, _ = req("POST", parent, owner, ty=TY_CNT, body={"m2m:cnt": {"rn": rn, "mni": mni}})
    assert st == 201, (rn, body)
    if acpi:
        assert req("PUT", f"{parent}/{rn}", owner, body={"m2m:cnt": {"acpi": [acpi]}})[0] == 200, rn


def _cins(url, origin) -> list[dict]:
    """Every contentInstance of a container as `origin` may read it, oldest first (by ct, then st)."""
    st, body, _ = req("GET", f"{url}?rcn=4", origin)
    assert st == 200, (url, st, body)
    items = (body or {}).get("m2m:cnt", {}).get("m2m:cin", [])
    return sorted(items, key=handover._creation_order)


def _cons(url, origin) -> list[dict]:
    return [json.loads(c["con"]) for c in _cins(url, origin)]


class SimRsu:
    """A SIMULATED roadside sensor on edge A (it stays there). `vru` holds detections, `env` its own readings."""

    def __init__(self, tag: str, warner: str):
        self.rn, self.origin = f"vruRsu-{tag}", f"CvruRsu-{tag}"
        self.ae = f"{BASE[EDGE_A]}/{self.rn}"
        st, body, _ = req("POST", BASE[EDGE_A], self.origin, ty=TY_AE, body={"m2m:ae": {
            "rn": self.rn, "api": "Nestimed.rsu", "rr": False, "srv": ["4"]}})
        assert st == 201, body
        _container(self.ae, self.origin, "vru", _acp(self.ae, self.origin, "vruAcp", [{"acor": [warner], "acop": RETRIEVE}]))
        _container(self.ae, self.origin, "env", _acp(self.ae, self.origin, "envAcp", []))
        assert _cin(f"{self.ae}/env", self.origin, {"battery_pct": 80, "sim": True})[0] == 201

    def detect(self, present=True, cls="pedestrian", zone=ZONE, t=None) -> int:
        """One detection record; returns its t (epoch ms), the sensor event time."""
        t = _now_ms() if t is None else t
        st, _ = _cin(f"{self.ae}/vru", self.origin, {"zone": zone, "present": present, "class": cls, "t": t, "sim": True})
        assert st == 201
        return t

    def remove(self):
        req("DELETE", self.ae, self.origin)
        req("DELETE", self.ae, "CAdmin")


class SimVehicle:
    """handover.py's vehicle01, rr=false, as a device would hold it, with a reader that acknowledges warnings.

    Downlink: it READS its <cmd> container every PERIOD (GET cmd/la; on a new instance, all of cmd) and answers each
    warning once in <ack> -- unless the warning has expired (expires_t passed): that one it ignores (kept in
    `ignored`). It also reads its own route record each PERIOD. While that says MOVING (and is at most max_move_ms
    old) it still READS <cmd> and acts on a warning (kept in `read`), but WRITES nothing: its acknowledgement waits in
    `pending` until the record names an edge again, and may_write() is False for whoever writes its context --
    handover.py fails a move in which a full container gets a write (see the module's "THE VEHICLE WHILE IT MOVES").
    A MOVING record older than max_move_ms it treats as stale (its keeper died): it writes again. The vehicle's check is the one that holds after a handover, which carries <cmd> without `et`. Not the
    probe app's <pollingChannel>: on ACME 2026.5.3 an idle long-poll of <pcu> ends in a REQUEST_TIMEOUT that the CSE
    writes to its log, and a notification fetched there and not answered within 10 s does the same (both seen on the
    lab's MN-A, 2026-11-20); handover.py does not carry a <pollingChannel> either (CARRIED).
    Implements handover.Device: hold() returns once no read or ack is in flight; resume(edge) reads there.
    """

    def __init__(self, warner: str, max_move_ms: int):
        self.name, self.origin, self.warner, self.max_move_ms = handover.AE_NAME, handover.AE_ORIGIN, warner, max_move_ms
        self.edge = None
        self.acked: dict[str, dict] = {}            # warning id -> the ack written
        self.ignored: dict[str, int] = {}           # warning id -> ms past its expires_t when read
        self.read: dict[str, int] = {}              # warning id -> when it was read and acted on
        self.pending: dict[str, dict] = {}          # warning id -> its ack, not yet written (route MOVING)
        self._last_ri = None
        self._run = threading.Event()
        self._idle = threading.Event()
        self._idle.set()
        self._thread = None
        self._in_flight = False
        self._lock = threading.Lock()
        self.route_url = None                       # its route record at the IN (it is one of the readers)
        self.moving = False

    def may_write(self) -> bool:
        """Not held by a handover, and its route does not say MOVING."""
        return self._idle.is_set() and not self.moving

    def attach(self, edge):
        assert handover.create_ae(edge, rr=False)[0] == 201
        ae = f"{BASE[edge]}/{self.name}"
        aeacp = _acp(ae, self.origin, "aeAcp", [{"acor": [self.warner], "acop": RETRIEVE}])
        assert req("PUT", ae, self.origin, body={"m2m:ae": {"acpi": [aeacp]}})[0] == 200
        _container(ae, self.origin, handover.CONTAINER, _acp(ae, self.origin, "telemetryAcp", []))
        for s in SAMPLES:
            assert handover.add_sample(edge, s)[0] == 201
        _container(ae, self.origin, "ctx", _acp(ae, self.origin, "ctxAcp", [{"acor": [self.warner], "acop": RETRIEVE}]),
                   mni=1)
        _container(ae, self.origin, "cmd", _acp(ae, self.origin, "cmdAcp", [
            {"acor": [self.warner], "acop": CREATE, "acod": [{"chty": [TY_CIN]}]}]))
        _container(ae, self.origin, "ack", _acp(ae, self.origin, "ackAcp", [{"acor": [self.warner], "acop": RETRIEVE}]),
                   mni=8)
        self.edge = edge
        self._run.set()
        self._thread = threading.Thread(target=self._loop, name="sim-vehicle", daemon=True)
        self._thread.start()

    def ctx(self, zone=ZONE, approach=True, t=None):
        st, _ = _cin(f"{BASE[self.edge]}/{self.name}/ctx", self.origin,
                     {"zone": zone, "approach": approach, "t": _now_ms() if t is None else t, "sim": True})
        assert st == 201

    # handover.Device
    def hold(self):
        with self._lock:
            self._idle.clear()
        while self._in_flight:
            time.sleep(0.005)

    def resume(self, edge):
        with self._lock:
            self.edge, self._last_ri = edge, None
            self._idle.set()

    def stop(self):
        self._run.clear()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _loop(self):
        while self._run.is_set():
            if self._idle.is_set():
                self._in_flight = True
                try:
                    self._read_once()
                except OSError:
                    pass
                finally:
                    self._in_flight = False
            time.sleep(PERIOD)

    def _read_once(self):
        if self.route_url:
            st, body, _ = req("GET", f"{self.route_url}/la", self.origin)
            rec = json.loads(body["m2m:cin"]["con"]) if st == 200 else {}
            t = rec.get("t")
            self.moving = rec.get("state") == "MOVING" and _int(t) and _now_ms() - t <= self.max_move_ms
        edge = self.edge
        if not self.moving:                                 # the answers it held back while the route said MOVING
            for wid, ack in list(self.pending.items()):
                if _cin(f"{BASE[edge]}/{self.name}/ack", self.origin, ack)[0] == 201:
                    self.acked[wid] = ack | {"edge": edge}
                    del self.pending[wid]
        url = f"{BASE[edge]}/{self.name}/cmd"
        st, body, _ = req("GET", f"{url}/la", self.origin)
        ri = (body or {}).get("m2m:cin", {}).get("ri") if st == 200 else None
        if ri is None or ri == self._last_ri:
            return
        self._last_ri = ri
        for c in _cins(url, self.origin):
            try:
                cmd = json.loads(c["con"])
            except (ValueError, TypeError):
                continue
            wid = cmd.get("id") if isinstance(cmd, dict) and cmd.get("cmd") == "vru-warning" else None
            if wid is None or wid in self.acked or wid in self.ignored or wid in self.pending:
                continue
            now = _now_ms()
            if not _int(cmd.get("expires_t")) or now > cmd["expires_t"]:
                self.ignored[wid] = now - cmd["expires_t"] if _int(cmd.get("expires_t")) else -1
                continue
            self.read[wid] = now                            # acted on: a real vehicle warns its driver here
            ack = {"id": wid, "cmd": "vru-warning", "ok": True, "vehicle_t": now, "sim": True}
            if self.moving:
                self.pending[wid] = ack                     # written once the record names an edge again
            elif _cin(f"{BASE[edge]}/{self.name}/ack", self.origin, ack)[0] == 201:
                self.acked[wid] = ack | {"edge": edge}


@pytest.fixture(scope="session")
def live_lock():
    """Before anything touches the lab (it is requested ahead of conftest's `topology`, same scope)."""
    _require_live_lock()


@pytest.fixture
def lab(live_lock, topology, vw):
    """The three parties on edge A, the route record at the IN naming the warning AE, the warning AE running.

    Everything is removed afterwards: the warning AE's own AE, the sensor, the route record, and the vehicle
    (handover.reset(), which also closes any handover transaction left open)."""
    tag = uuid.uuid4().hex[:8]
    handover.reset()
    w_rn, w_origin = f"vruWarning-{tag}", f"CvruWarning-{tag}"
    veh, rsu, ae, stop, thread = SimVehicle(w_origin, vw.MAX_MOVE_MS), None, None, threading.Event(), None
    aei = handover.AE_ORIGIN
    vw.close_route(BASE[IN_CSE], aei)                          # a route record a failed run left behind
    keeper = vw.RouteKeeper(BASE[IN_CSE], aei, [w_origin, aei], serving=handover.serving_edges)
    k_stop, k_thread = threading.Event(), None
    try:
        rsu = SimRsu(tag, w_origin)
        veh.route_url = f"{BASE[IN_CSE]}/{vw.route_rn(aei)}"
        veh.attach(EDGE_A)
        assert keeper.open() == 201 and keeper.published, keeper.errors
        k_thread = threading.Thread(target=keeper.run, args=(k_stop, 0.1), name="route-keeper", daemon=True)
        k_thread.start()

        def stop_keeper():
            k_stop.set()
            k_thread.join(timeout=5)
        ae = vw.WarningAE({"origin": w_origin, "rn": w_rn, "cse": BASE[EDGE_A], "in": BASE[IN_CSE],
                           "edges": {CSI_OF[EDGE_A]: BASE[EDGE_A], CSI_OF[EDGE_B]: BASE[EDGE_B]},
                           "vehicle": {"aei": aei, "rn": handover.AE_NAME}, "sensor": f"{rsu.ae}/vru", "zone": ZONE})
        ae.register()

        def start():
            nonlocal thread
            thread = threading.Thread(target=ae.run, args=(stop, PERIOD), name="vru-warning", daemon=True)
            thread.start()

        yield {"vw": vw, "ae": ae, "veh": veh, "rsu": rsu, "w": w_origin, "w_rn": w_rn, "aei": aei, "start": start,
               "keeper": keeper, "stop_keeper": stop_keeper}
    finally:
        stop.set()
        if thread is not None:
            thread.join(timeout=5)
        k_stop.set()
        if k_thread is not None:
            k_thread.join(timeout=5)
        veh.stop()
        if ae is not None:
            ae.deregister()
        req("DELETE", f"{BASE[EDGE_A]}/{w_rn}", "CAdmin")
        if rsu is not None:
            rsu.remove()
        vw.close_route(BASE[IN_CSE], aei)
        handover.reset()


def _wait(pred, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if v := pred():
            return v
        time.sleep(0.01)
    return None


def _move(lab, src, dst, device=True) -> bool:
    """The orchestrator's move through the route keeper: the record says MOVING (and the vehicle, a reader, stops
    writing), handover.handover() moves the vehicle (held for the last copy and resumed on dst, unless device=False),
    then the record names what the IN's announced AE names."""
    with lab["keeper"].moving():
        ok = handover.handover(src, dst, handover.read_samples(src), device=lab["veh"] if device else None)
    assert lab["keeper"].published[-1][1] == "ATTACHED", lab["keeper"].published[-3:]
    return ok


def _delivered(lab, t_event, timeout=5.0):
    """The vehicle's ack of the warning issued for the sensor event at t_event, and the warning itself."""
    def find():
        for w in list(lab["ae"].warnings.values()):
            if w["event_t"] == t_event and w["id"] in lab["veh"].acked:
                return w, lab["veh"].acked[w["id"]]
        return None
    return _wait(find, timeout)


def _written(lab, wid, edge=None) -> bool:
    w = lab["ae"].warnings.get(wid)
    return bool(w) and (w["written_to"] if edge is None else edge in w["written_to"])


def _the_warning(lab, t_event, timeout=3.0) -> dict | None:
    return _wait(lambda: next((w for w in list(lab["ae"].warnings.values()) if w["event_t"] == t_event), None), timeout)


def _to_vehicle_on(lab, edge, sent) -> list[dict]:
    return [s for s in sent if s["url"].startswith(f"{BASE[edge]}/{handover.AE_NAME}")]


# --- live: delivery before and after a move -------------------------------------------------------------------

@live
def test_live_warning_delivered_on_edge_a_before_a_move(lab):
    lab["veh"].ctx(approach=True)
    lab["start"]()
    t_event = lab["rsu"].detect()
    got = _delivered(lab, t_event)
    assert got, f"no acknowledged warning; AE events: {lab['ae'].events[-5:]}"
    w, ack = got
    assert ack["edge"] == EDGE_A and w["written_to"] == [CSI_OF[EDGE_A]]
    ms = ack["vehicle_t"] - t_event
    print(f"\n    edge A: sensor event -> ack written by the vehicle: {ms} ms")
    assert 0 <= ms < 1000, "the use case asks for sub-second warnings"
    time.sleep(0.3)                                          # several more looks at the same detection
    assert [x["id"] for x in list(lab["ae"].warnings.values()) if x["event_t"] == t_event] == [w["id"]]
    on_a = _cons(f"{BASE[EDGE_A]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN)
    assert [c["id"] for c in on_a] == [w["id"]] and on_a[0]["cmd"] == "vru-warning"


@live
def test_live_after_a_handover_the_next_warning_lands_on_b_and_is_acked(lab):
    veh = lab["veh"]
    veh.ctx(approach=True)
    lab["start"]()
    t1 = lab["rsu"].detect()
    first = _delivered(lab, t1)
    assert first and first[1]["edge"] == EDGE_A
    t_move = time.time()
    assert _move(lab, EDGE_A, EDGE_B), "the handover failed"
    t_moved = time.time()
    assert handover.serving_edges() == [CSI_OF[EDGE_B]]
    veh.ctx(approach=True)                                   # the vehicle's next context, now on B
    t2 = lab["rsu"].detect()
    second = _delivered(lab, t2)
    assert second, f"no acknowledged warning after the move; AE events: {lab['ae'].events[-6:]}"
    w, ack = second
    assert ack["edge"] == EDGE_B and w["written_to"] == [CSI_OF[EDGE_B]]
    ms = ack["vehicle_t"] - t2
    print(f"\n    move A->B took {(t_moved - t_move) * 1000:.0f} ms; edge B: sensor event -> ack: {ms} ms "
          f"(edge A before: {first[1]['vehicle_t'] - t1} ms)")
    assert 0 <= ms < 1000
    on_b = [c["id"] for c in _cons(f"{BASE[EDGE_B]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN)]
    assert on_b == [first[0]["id"], w["id"]], "B holds the carried first warning, then the new one"
    acks_b = [c["id"] for c in _cons(f"{BASE[EDGE_B]}/{handover.AE_NAME}/ack", handover.AE_ORIGIN)]
    assert acks_b == [first[0]["id"], w["id"]]


@live
def test_live_control_after_the_move_no_request_to_the_vehicle_on_edge_a(lab):
    """After the route names B, the warning AE sends nothing to edge A but its reads of the sensor (which stays on
    A) and its own log; and edge A holds no record of the vehicle."""
    veh = lab["veh"]
    veh.ctx(approach=True)
    lab["start"]()
    assert _delivered(lab, lab["rsu"].detect())
    assert _move(lab, EDGE_A, EDGE_B)
    n = len(lab["ae"].client.sent)
    veh.ctx(approach=True)
    assert _delivered(lab, lab["rsu"].detect())
    after = lab["ae"].client.sent[n:]
    to_a = [s for s in after if s["url"].startswith(BASE[EDGE_A] + "/")]
    allowed = (f"{lab['rsu'].ae}/vru", f"{BASE[EDGE_A]}/{lab['w_rn']}")
    assert all(s["url"].startswith(allowed) for s in to_a), [s["url"] for s in to_a if not s["url"].startswith(allowed)]
    assert not _to_vehicle_on(lab, EDGE_A, after)
    assert [s for s in after if s["method"] == "POST" and "/cmd" in s["url"]], "no warning was written after the move"
    assert all(s["url"].startswith(BASE[EDGE_B]) for s in after if s["method"] == "POST" and s["url"].endswith("/cmd"))
    assert req("GET", f"{BASE[EDGE_A]}/{handover.AE_NAME}", "CAdmin")[0] == 404


@live
def test_live_control_while_the_route_says_moving_nothing_is_written_anywhere(lab):
    """The AE has just warned the vehicle on A. Then the route says MOVING: a new sensor event is written nowhere,
    not to A (the edge it knew last) either; once the route names an edge again it is written there and acked."""
    vw, veh = lab["vw"], lab["veh"]
    veh.ctx(approach=True)
    lab["start"]()
    first = _delivered(lab, lab["rsu"].detect())
    assert first and first[1]["edge"] == EDGE_A, "control: the AE knew the vehicle on A"
    assert vw.publish_route(BASE[IN_CSE], lab["aei"], [], moving=True) == 201
    n = len(lab["ae"].client.sent)
    veh.ctx(approach=True)
    t_event = lab["rsu"].detect()
    time.sleep(0.5)
    writes = [s for s in lab["ae"].client.sent[n:] if s["method"] == "POST" and s["url"].endswith("/cmd")]
    assert writes == [], writes
    assert [c["id"] for c in _cons(f"{BASE[EDGE_A]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN)] == [first[0]["id"]]
    veh.ctx(approach=True)                                   # still fresh when the route is back
    assert vw.publish_route(BASE[IN_CSE], lab["aei"], handover.serving_edges()) == 201
    assert _delivered(lab, t_event), "the held event was not warned once the route was back"


@live
def test_live_a_warning_in_flight_during_the_move_is_acked_once_on_b(lab):
    """Written to A, not read by the vehicle when the move starts: the handover carries it in <cmd>; once the route
    names B the AE writes it there again (it was not answered) and to no other edge -- nothing more to A; the vehicle,
    reading on B, answers it once. (B's <cmd> then holds it twice, the carried copy and the rewrite: a stated limit.)"""
    veh = lab["veh"]
    veh.ctx(approach=True)
    veh.hold()                                                # the vehicle reads nothing for now
    lab["start"]()
    t_event = lab["rsu"].detect()
    w = _the_warning(lab, t_event)
    assert w and _wait(lambda: _written(lab, w["id"], CSI_OF[EDGE_A])), "not written to A"
    assert w["status"] == "open" and w["id"] not in veh.acked
    assert _move(lab, EDGE_A, EDGE_B, device=False)          # the vehicle stays held through the move
    n = len(lab["ae"].client.sent)
    assert _wait(lambda: _written(lab, w["id"], CSI_OF[EDGE_B])), lab["ae"].events[-6:]
    veh.resume(EDGE_B)
    assert _wait(lambda: lab["ae"].warnings[w["id"]]["status"] == "acked"), lab["ae"].events[-6:]
    assert veh.acked[w["id"]]["edge"] == EDGE_B
    acks_b = [c["id"] for c in _cons(f"{BASE[EDGE_B]}/{handover.AE_NAME}/ack", handover.AE_ORIGIN)]
    assert acks_b.count(w["id"]) == 1, acks_b
    assert _to_vehicle_on(lab, EDGE_A, lab["ae"].client.sent[n:]) == [], "a request to the old edge after the move"
    on_b = [c["id"] for c in _cons(f"{BASE[EDGE_B]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN)]
    print(f"\n    in flight across the move: sensor event -> ack on B {veh.acked[w['id']]['vehicle_t'] - t_event} ms; "
          f"written to {lab['ae'].warnings[w['id']]['written_to']}; in B's cmd {on_b.count(w['id'])} times")


@live
def test_live_control_a_warning_held_past_its_ttl_is_never_written_to_the_new_edge(lab):
    """Written to A, unanswered, and the move outlasts its time to live: once the route names B it is dropped
    (expired), never written there late; the vehicle, reading B's carried copy (no et after the handover), does not
    act on it either. An earlier warning's acknowledgement in <ack> does not count for it."""
    veh, ae = lab["veh"], lab["ae"]
    veh.ctx(approach=True)
    lab["start"]()
    assert _delivered(lab, lab["rsu"].detect()), "control: a first warning is answered, so <ack> is not empty"
    ae.ttl_ms = 300
    veh.hold()
    veh.ctx(approach=True)
    t_event = lab["rsu"].detect()
    w = _the_warning(lab, t_event)
    assert w and _wait(lambda: _written(lab, w["id"], CSI_OF[EDGE_A]))
    assert w["expires_t"] == t_event + 300, "the time to live counts from the sensor event"
    assert lab["vw"].publish_route(BASE[IN_CSE], lab["aei"], [], moving=True) == 201
    assert handover.handover(EDGE_A, EDGE_B, handover.read_samples(EDGE_A))   # the vehicle stays held
    time.sleep(max(0.0, (w["expires_t"] - _now_ms()) / 1000) + 0.1)
    n = len(ae.client.sent)
    assert lab["vw"].publish_route(BASE[IN_CSE], lab["aei"], handover.serving_edges()) == 201
    assert _wait(lambda: ae.warnings[w["id"]]["status"] == "expired", 2.0), ae.warnings[w["id"]]
    time.sleep(0.2)
    late = [s for s in ae.client.sent[n:] if s["method"] == "POST" and s["url"].endswith("/cmd")]
    assert late == [] and ae.warnings[w["id"]]["written_to"] == [CSI_OF[EDGE_A]], late
    assert [e["event"] for e in ae.events if e.get("id") == w["id"]] == ["issued", "written", "expired"]
    carried = [c for c in _cins(f"{BASE[EDGE_B]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN)
               if json.loads(c["con"]).get("id") == w["id"]]
    assert len(carried) == 1 and carried[0].get("et") != lab["vw"].stamp(w["expires_t"]), \
        "the handover's copy keeps no et (handover._copy writes con and cnf only)"
    veh.resume(EDGE_B)
    assert _wait(lambda: w["id"] in veh.ignored, 3.0) and w["id"] not in veh.acked, (veh.ignored, veh.acked)


@live
def test_live_control_an_expired_warning_is_not_acted_on_by_the_vehicle(lab):
    """No move: the warning waits in A's <cmd> past its expiry (the vehicle is not reading). It carries et =
    expires_t; the AE drops it; the vehicle, reading again, ignores it."""
    veh, ae = lab["veh"], lab["ae"]
    ae.ttl_ms = 300
    veh.ctx(approach=True)
    veh.hold()
    lab["start"]()
    w = _the_warning(lab, lab["rsu"].detect())
    assert w and _wait(lambda: _written(lab, w["id"], CSI_OF[EDGE_A]))
    (cin,) = _cins(f"{BASE[EDGE_A]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN)
    assert cin["et"] == lab["vw"].stamp(w["expires_t"]), cin.get("et")
    assert _wait(lambda: ae.warnings[w["id"]]["status"] == "expired", 2.0)
    time.sleep(0.1)
    veh.resume(EDGE_A)
    assert _wait(lambda: w["id"] in veh.ignored, 3.0) and w["id"] not in veh.acked
    assert veh.ignored[w["id"]] > 0


@live
def test_live_control_an_impostor_at_the_vehicles_name_gets_nothing(lab):
    """The vehicle leaves A without a handover (the route record still says A, and is fresh). Another originator
    registers an <AE> named vehicle01 on A and grants the warning AE all the vehicle granted, with a matching context
    and an acknowledgement of the open warning. The warning AE writes nothing into it and counts nothing from it."""
    veh, ae, w_or = lab["veh"], lab["ae"], lab["w"]
    veh.ctx(approach=True)
    lab["start"]()
    assert _delivered(lab, lab["rsu"].detect()), "control: the vehicle on A is warned"
    veh.hold()
    veh.ctx(approach=True)
    w = _the_warning(lab, lab["rsu"].detect())
    assert w and _wait(lambda: _written(lab, w["id"], CSI_OF[EDGE_A]))       # open, written to the real vehicle
    veh.stop()
    assert handover.delete_ae(EDGE_A)[0] == 200
    imp, base = f"Cimpostor-{uuid.uuid4().hex[:6]}", f"{BASE[EDGE_A]}/{handover.AE_NAME}"
    try:
        st, body, _ = req("POST", BASE[EDGE_A], imp, ty=TY_AE, body={"m2m:ae": {
            "rn": handover.AE_NAME, "api": "Nestimed.vehicle", "rr": False, "srv": ["4"]}})
        assert st == 201, body
        assert req("PUT", base, imp, body={"m2m:ae": {"acpi": [
            _acp(base, imp, "aeAcp", [{"acor": [w_or], "acop": RETRIEVE}])]}})[0] == 200
        _container(base, imp, "ctx", _acp(base, imp, "ctxAcp", [{"acor": [w_or], "acop": RETRIEVE}]), mni=1)
        _container(base, imp, "cmd", _acp(base, imp, "cmdAcp", [{"acor": [w_or], "acop": CREATE,
                                                                  "acod": [{"chty": [TY_CIN]}]}]))
        _container(base, imp, "ack", _acp(base, imp, "ackAcp", [{"acor": [w_or], "acop": RETRIEVE}]))
        assert req("GET", base, w_or)[0] == 200, "control: the AE can read the impostor's <AE> (and its aei)"
        n = len(ae.client.sent)
        assert _cin(f"{base}/ack", imp, {"id": w["id"], "cmd": "vru-warning", "ok": True, "vehicle_t": _now_ms()},
                    cr=None)[0] == 201
        assert _cin(f"{base}/ctx", imp, {"zone": ZONE, "approach": True, "t": _now_ms()}, cr=None)[0] == 201
        t2 = lab["rsu"].detect()
        time.sleep(0.6)
        assert ae.warnings[w["id"]]["status"] in ("open", "expired"), ae.warnings[w["id"]]
        assert not [x for x in ae.warnings.values() if x["event_t"] == t2], "a warning was raised for the impostor"
        assert _cins(f"{base}/cmd", imp) == [], "a warning reached the impostor"
        reads = {s["url"] for s in ae.client.sent[n:] if s["url"].startswith(base)}
        assert reads <= {base}, reads                         # it looked at the <AE> and at nothing under it
    finally:
        req("DELETE", base, imp)
        req("DELETE", base, "CAdmin")


@live
def test_live_control_an_earlier_acknowledgement_does_not_count_for_a_new_warning(lab):
    """<ack> already holds the answer to a first warning; a second one, written while the vehicle reads nothing,
    stays open (the AE would otherwise stop caring about a warning nobody saw), and is acked once the vehicle reads."""
    veh, ae = lab["veh"], lab["ae"]
    veh.ctx(approach=True)
    lab["start"]()
    assert _delivered(lab, lab["rsu"].detect()), "control: <ack> holds one answer"
    veh.hold()
    veh.ctx(approach=True)
    w = _the_warning(lab, lab["rsu"].detect())
    assert w and _wait(lambda: _written(lab, w["id"], CSI_OF[EDGE_A]))
    time.sleep(0.4)                                          # several looks at <ack> on A
    assert ae.warnings[w["id"]]["status"] == "open" and w["id"] not in veh.acked, ae.warnings[w["id"]]
    veh.resume(EDGE_A)
    assert _wait(lambda: ae.warnings[w["id"]]["status"] == "acked"), ae.events[-4:]
    assert ae.warnings[w["id"]]["acked"]["id"] == w["id"]


@live
def test_live_delivery_times_before_and_after_the_move(lab):
    """Ten sensor events on each side of a move: every one warned, written to the serving edge, acknowledged
    there, sensor event -> acknowledgement under one second."""
    veh, n = lab["veh"], 10
    lab["start"]()

    def one(edge):
        veh.ctx(approach=True)
        t = lab["rsu"].detect()
        got = _delivered(lab, t)
        assert got and got[1]["edge"] == edge and got[0]["written_to"] == [CSI_OF[edge]], (edge, got)
        return got[1]["vehicle_t"] - t

    before = [one(EDGE_A) for _ in range(n)]
    t0 = time.time()
    assert _move(lab, EDGE_A, EDGE_B)
    move_ms = (time.time() - t0) * 1000
    after = [one(EDGE_B) for _ in range(n)]
    for label, xs in (("edge A, before", before), ("edge B, after", after)):
        s = sorted(xs)
        print(f"\n    {label}: n={len(s)} min {s[0]} median {s[len(s) // 2]} max {s[-1]} ms  {xs}", end="")
    print(f"\n    the move (route MOVING -> handover -> route B): {move_ms:.0f} ms")
    assert max(before + after) < 1000


# --- live: the vehicle updating its context through a move; the route keeper ------------------------------------

def _context_writer(lab, stop, period, honour_moving):
    """The vehicle writing its context every `period` s, on whichever edge it is on now; it never writes while held
    (the handover.Device contract) and, if honour_moving, not while its route says MOVING. Returns {edge: writes}."""
    veh, n = lab["veh"], {}

    def loop():
        while not stop.is_set():
            if veh._idle.is_set() and (veh.may_write() or not honour_moving):
                edge = veh.edge
                try:
                    st, _ = _cin(f"{BASE[edge]}/{handover.AE_NAME}/ctx", handover.AE_ORIGIN,
                                 {"zone": ZONE, "approach": True, "t": _now_ms(), "sim": True})
                    if st == 201:
                        n[edge] = n.get(edge, 0) + 1
                except OSError:
                    pass
            time.sleep(period)
    th = threading.Thread(target=loop, name="ctx-writer", daemon=True)
    th.start()
    return n, th


@live
def test_live_the_vehicle_keeps_updating_its_context_and_the_move_succeeds(lab):
    """The reviewer's shape: the vehicle writes its context every 20 ms, before, around and after the move. It holds
    while its route says MOVING (it reads the record), so ctx keeps mni 1 and handover.handover() succeeds; the next
    warning is delivered on B."""
    stop = threading.Event()
    n, th = _context_writer(lab, stop, 0.02, honour_moving=True)
    try:
        lab["start"]()
        time.sleep(0.2)
        assert _delivered(lab, lab["rsu"].detect()), "control: warned on A while it updates"
        assert _move(lab, EDGE_A, EDGE_B), "the move failed while the vehicle updated its context"
        assert handover.serving_edges() == [CSI_OF[EDGE_B]]
        time.sleep(0.2)
        got = _delivered(lab, lab["rsu"].detect())
        assert got and got[1]["edge"] == EDGE_B
    finally:
        stop.set()
        th.join(2)
    print(f"\n    context writes: {n.get(EDGE_A, 0)} on A, {n.get(EDGE_B, 0)} on B; the move succeeded")
    assert n.get(EDGE_A, 0) > 5 and n.get(EDGE_B, 0) > 5, n


@live
def test_live_a_move_longer_than_max_move_ms_succeeds_while_the_vehicle_updates(lab):
    """The reviewer's long move: the vehicle holds 1400 instances the handover must copy, and writes its context every
    50 ms whenever it may. The move outlasts MAX_MOVE_MS several times; the keeper's heartbeat keeps MOVING fresh, so
    the vehicle never writes during it and handover.handover() succeeds."""
    veh, vw = lab["veh"], lab["vw"]
    a = f"{BASE[EDGE_A]}/{handover.AE_NAME}"
    assert req("POST", a, handover.AE_ORIGIN, ty=TY_CNT, body={"m2m:cnt": {"rn": "hist", "mni": 2000}})[0] == 201
    for i in range(1400):
        assert _cin(f"{a}/hist", handover.AE_ORIGIN, {"i": i})[0] == 201
    stop, writes = threading.Event(), []

    def writer():
        while not stop.is_set():
            if veh._idle.is_set() and veh.may_write():
                edge = veh.edge
                try:
                    if _cin(f"{BASE[edge]}/{handover.AE_NAME}/ctx", handover.AE_ORIGIN,
                            {"zone": ZONE, "approach": True, "t": _now_ms(), "sim": True})[0] == 201:
                        writes.append(time.time())
                except OSError:
                    pass
            time.sleep(0.05)
    th = threading.Thread(target=writer, name="ctx-writer", daemon=True)
    th.start()
    time.sleep(0.3)
    t0 = time.time()
    try:
        ok = _move(lab, EDGE_A, EDGE_B)
    finally:
        t1 = time.time()
        stop.set()
        th.join(2)
    during = [round(x - t0, 1) for x in writes if t0 + 0.3 < x < t1]
    beats = [p for p in lab["keeper"].published if p[1] == "MOVING"]
    print(f"\n    long move: {'succeeded' if ok else 'REFUSED'} after {t1 - t0:.1f} s, {len(beats)} MOVING publications, "
          f"context writes during it {len(during)}")
    assert t1 - t0 > vw.MAX_MOVE_MS / 1000, "not a long move: the test proves nothing"
    assert ok and handover.serving_edges() == [CSI_OF[EDGE_B]] and during == [], (ok, during[:5])


@live
def test_live_control_a_vehicle_writing_its_context_through_the_move_breaks_it(lab):
    """The same writer, ignoring MOVING (only the late hold() of handover.Device): handover.py refuses the move and
    rolls back -- the reason the vehicle holds. The vehicle stays on A, the route names A again."""
    stop = threading.Event()
    n, th = _context_writer(lab, stop, 0.02, honour_moving=False)
    try:
        time.sleep(0.2)
        ok = _move(lab, EDGE_A, EDGE_B)
    finally:
        stop.set()
        th.join(2)
    assert ok is False and handover.serving_edges() == [CSI_OF[EDGE_A]], (ok, handover.serving_edges(), n)


@live
def test_live_a_stale_moving_record_does_not_silence_the_vehicle(lab):
    """The reviewer's S2: the keeper died inside a move, its record says MOVING. Past MAX_MOVE_MS the vehicle treats it
    as stale: it reads and answers the warning in its <cmd>; the AE holds, as route-stale. At 12 s (past MAX_MOVE_MS,
    inside ROUTE_MAX_AGE_MS) and at 120 s."""
    veh, aei, vw = lab["veh"], lab["aei"], lab["vw"]
    lab["stop_keeper"]()
    route = f"{BASE[IN_CSE]}/{vw.route_rn(aei)}"
    lab["start"]()
    for age_ms in (12_000, 120_000):
        st, _ = _cin(route, "CAdmin", {"aei": aei, "state": "MOVING", "serving": None, "t": _now_ms() - age_ms})
        assert st == 201
        veh.ctx(approach=True)
        lab["rsu"].detect()                                          # an event: the AE needs the route
        wid, now = f"5ca1ab1e{age_ms // 1000:04x}", _now_ms()
        assert _cin(f"{BASE[EDGE_A]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN,
                    vw.warning_body(wid, ZONE, "pedestrian", now, now, now + 3000))[0] == 201
        assert _wait(lambda: wid in veh.acked, 2.0), (age_ms, veh.moving, veh.pending)
        assert veh.moving is False and veh.may_write()
        assert _wait(lambda: {"event": "held", "id": "route-stale"} in lab["ae"].events, 2.0), lab["ae"].events[-4:]
        assert not [x for x in lab["ae"].client.sent if x["method"] == "POST" and x["url"].endswith("/cmd")]


@live
def test_live_while_moving_the_vehicle_reads_its_warning_and_answers_after(lab):
    """The reviewer's S3: a warning is in the vehicle's <cmd>; the route turns MOVING. The vehicle reads it and acts on
    it at once, but writes its answer only once the record names an edge again."""
    veh, keeper = lab["veh"], lab["keeper"]
    veh.ctx(approach=True)
    lab["start"]()
    veh.hold()
    t_event = lab["rsu"].detect()
    w = _the_warning(lab, t_event)
    assert w and _wait(lambda: _written(lab, w["id"], CSI_OF[EDGE_A]))
    assert keeper.publish(moving=True) == 201
    veh.resume(EDGE_A)
    assert _wait(lambda: w["id"] in veh.read, 1.0), "not read while the route said MOVING"
    time.sleep(0.4)
    assert w["id"] in veh.pending and w["id"] not in veh.acked, "an answer was written while MOVING"
    t_back = _now_ms()
    assert keeper.publish() == 201
    assert _wait(lambda: w["id"] in veh.acked, 2.0)
    print(f"\n    S3: read {veh.read[w['id']] - t_event} ms after the event (route MOVING), answered "
          f"{_now_ms() - t_back} ms after the record named A again")


@live
def test_live_a_restarted_keeper_clears_the_moving_its_predecessor_left(lab):
    """The driver's keeper dies inside a move (its last word MOVING). A new keeper of the same originator opens the
    same record -- looking first, so no CREATE the CSE would refuse -- and publishes A: the vehicle writes again and
    the next warning is delivered."""
    veh, aei, vw = lab["veh"], lab["aei"], lab["vw"]
    lab["stop_keeper"]()
    assert lab["keeper"].publish(moving=True) == 201
    assert _wait(lambda: veh.moving, 1.0)
    calls = []

    def admin(m, u, ty=None, body=None, origin=vw.ORCHESTRATOR):
        calls.append(m)
        return vw._admin(m, u, ty, body, origin)
    k2 = vw.RouteKeeper(BASE[IN_CSE], aei, [lab["w"], aei], serving=handover.serving_edges, admin=admin)
    assert k2.open() == 201 and "POST" not in calls, calls
    assert k2.published[-1][1] == "ATTACHED" and _wait(lambda: not veh.moving, 1.0)
    lab["start"]()
    veh.ctx(approach=True)
    assert _delivered(lab, lab["rsu"].detect())


@live
def test_live_control_a_keeper_refuses_a_route_name_someone_else_holds(lab):
    """Another originator registered an <AE> under the route's name at the IN first: open() refuses (409) on what it
    reads, sending no CREATE -- nothing the CSE would answer 409 and log."""
    tag = uuid.uuid4().hex[:6]
    aei2, squat = f"Cvru2-{tag}", f"Csquat-{tag}"
    rn = lab["vw"].route_rn(aei2)
    calls = []

    def admin(m, u, ty=None, body=None, origin=lab["vw"].ORCHESTRATOR):
        calls.append(m)
        return lab["vw"]._admin(m, u, ty, body, origin)
    try:
        assert req("POST", BASE[IN_CSE], squat, ty=TY_AE, body={"m2m:ae": {"rn": rn, "api": "Nsquat", "rr": False,
                                                                           "srv": ["4"]}})[0] == 201
        k = lab["vw"].RouteKeeper(BASE[IN_CSE], aei2, [lab["w"]], serving=lambda: ["/id-mn-a"], admin=admin)
        assert k.open() == 409 and set(calls) == {"GET"} and k.published == [], calls
    finally:
        req("DELETE", f"{BASE[IN_CSE]}/{rn}", squat)
        req("DELETE", f"{BASE[IN_CSE]}/{rn}", "CAdmin")


@live
def test_live_the_route_keeper_keeps_the_route_fresh_past_its_age_bound(lab):
    """Scaled down (age bound 2 s, keeper every 0.5 s): warnings keep flowing for three times the bound. Control: the
    keeper stopped, the record ages out, the next event is held, written nowhere, and the AE logs held/route-stale."""
    ae, keeper = lab["ae"], lab["keeper"]
    ae.route_max_age_ms, keeper.period_s = 2000, 0.5
    lab["start"]()
    t0 = time.time()
    for _ in range(3):
        lab["veh"].ctx(approach=True)
        assert _delivered(lab, lab["rsu"].detect()), (time.time() - t0, ae.events[-4:])
        time.sleep(2.0)
    assert time.time() - t0 > 6.0 and len(keeper.published) >= 10, len(keeper.published)
    lab["stop_keeper"]()
    time.sleep(2.3)
    n = len(ae.client.sent)
    lab["veh"].ctx(approach=True)
    lab["rsu"].detect()
    time.sleep(0.5)
    assert [s for s in ae.client.sent[n:] if s["method"] == "POST" and s["url"].endswith("/cmd")] == []
    assert {"event": "held", "id": "route-stale"} in ae.events, ae.events[-4:]
    assert {"event": "held", "id": "route-stale"} in _cons(f"{BASE[EDGE_A]}/{lab['w_rn']}/log", lab["w"])


@live
def test_live_the_route_keeper_keeps_warnings_flowing_past_60_s(lab):
    """At the real bounds (record valid 60 s, keeper every 30 s): a warning at the start and one 62 s later are both
    delivered, and nothing is held. Takes about 65 s."""
    ae, keeper = lab["ae"], lab["keeper"]
    assert ae.route_max_age_ms == 60_000 and keeper.period_s == 30.0
    lab["start"]()
    lab["veh"].ctx(approach=True)
    assert _delivered(lab, lab["rsu"].detect())
    time.sleep(62.0)
    lab["veh"].ctx(approach=True)
    assert _delivered(lab, lab["rsu"].detect()), ae.events[-4:]
    assert len(keeper.published) >= 3 and not [e for e in ae.events if e.get("event") == "held"], keeper.published


@live
def test_live_control_an_impostor_that_hides_its_ae_gets_nothing(lab):
    """The reviewer's shape: the vehicle gone from A without a handover (route fresh, still A); an impostor registers
    vehicle01 there with the vehicle's label, grants ctx, cmd and ack to the warning AE but NOT its <AE>: the AE reads
    nothing under it, writes nothing into it, and logs held/not-the-vehicle."""
    veh, ae, w_or = lab["veh"], lab["ae"], lab["w"]
    veh.stop()
    assert handover.delete_ae(EDGE_A)[0] == 200
    imp, base = f"Cimpostor-{uuid.uuid4().hex[:6]}", f"{BASE[EDGE_A]}/{handover.AE_NAME}"
    try:
        st, body, _ = req("POST", BASE[EDGE_A], imp, ty=TY_AE, body={"m2m:ae": {
            "rn": handover.AE_NAME, "api": "Nestimed.vehicle", "rr": False, "srv": ["4"],
            "lbl": [f"aei:{handover.AE_ORIGIN}"]}})
        assert st == 201, body
        _container(base, imp, "ctx", _acp(base, imp, "ctxAcp", [{"acor": [w_or], "acop": RETRIEVE}]), mni=1)
        _container(base, imp, "cmd", _acp(base, imp, "cmdAcp", [{"acor": [w_or], "acop": CREATE,
                                                                  "acod": [{"chty": [TY_CIN]}]}]))
        _container(base, imp, "ack", _acp(base, imp, "ackAcp", [{"acor": [w_or], "acop": RETRIEVE}]))
        assert _cin(f"{base}/ctx", imp, {"zone": ZONE, "approach": True, "t": _now_ms()})[0] == 201
        assert req("GET", base, w_or)[0] == 403, "control: it cannot read the impostor's <AE>"
        assert req("GET", f"{base}/ctx/la", w_or)[0] == 200, "control: it could read the impostor's context"
        n = len(ae.client.sent)
        lab["start"]()
        t = lab["rsu"].detect()
        time.sleep(0.6)
        under = [x["url"] for x in ae.client.sent[n:] if x["url"].startswith(f"{base}/")]
        assert under == [] and not [x for x in ae.warnings.values() if x["event_t"] == t], under
        assert _cins(f"{base}/cmd", imp) == []
        assert {"event": "held", "id": "not-the-vehicle"} in ae.events
    finally:
        req("DELETE", base, imp)
        req("DELETE", base, "CAdmin")


@live
def test_live_why_the_ae_grant_is_the_whole_resource_an_attribute_rule_reaches_strangers(lab):
    """Why the vehicle grants RETRIEVE of its whole <AE> and not of aei alone (ACME 2026.5.3): an attribute rule (aca)
    for one originator applies to every originator, so a stranger could read aei on each edge and learn which one
    serves the vehicle. If this test ever fails, the grant can be narrowed to aei."""
    tag = uuid.uuid4().hex[:6]
    rn, owner, stranger = f"vruAca-{tag}", f"CvruAca-{tag}", f"Cstranger-{tag}"
    ae = f"{BASE[EDGE_A]}/{rn}"
    try:
        assert req("POST", BASE[EDGE_A], owner, ty=TY_AE, body={"m2m:ae": {"rn": rn, "api": "Nestimed.vehicle",
                                                                         "rr": False, "srv": ["4"]}})[0] == 201
        st, body, _ = req("POST", ae, owner, ty=TY_ACP, body={"m2m:acp": {"rn": "aeAcp", "pv": {"acr": [
            {"acor": [owner], "acop": 63}, {"acor": [lab["w"]], "acop": RETRIEVE, "aca": ["aei"]}]},
            "pvs": {"acr": [{"acor": [owner], "acop": 63}]}}})
        assert st == 201, body
        assert req("PUT", ae, owner, body={"m2m:ae": {"acpi": [body["m2m:acp"]["ri"]]}})[0] == 200
        assert req("GET", ae, lab["w"])[0] == 403, "control: the rule does narrow the AE's own read"
        st, body, _ = req("GET", f"{ae}%23aei", lab["w"])
        assert st == 200 and body == {"m2m:ae": {"aei": owner}}, (st, body)
        st, body, _ = req("GET", f"{ae}%23aei", stranger)
        assert st == 200 and body == {"m2m:ae": {"aei": owner}}, ("ACME no longer leaks aca rules", st, body)
    finally:
        req("DELETE", ae, owner)
        req("DELETE", ae, "CAdmin")


# --- live controls: the rule, reading, writing, a stranger, the record shapes ---------------------------------

@live
def test_live_control_no_warning_when_the_rule_does_not_fire(lab):
    rsu, veh, ae = lab["rsu"], lab["veh"], lab["ae"]
    veh.ctx(approach=False)
    lab["start"]()
    rsu.detect()                                            # pedestrian present, vehicle not approaching
    time.sleep(0.3)
    veh.ctx(zone="crossing-2", approach=True)                # approaching, another zone
    rsu.detect()
    time.sleep(0.3)
    veh.ctx(approach=True)
    rsu.detect(present=False)                                # nobody there
    time.sleep(0.3)
    rsu.detect(cls="car")                                    # a car is not a vulnerable road user
    time.sleep(0.3)
    rsu.detect(t=_now_ms() - 5000)                           # a stale detection
    time.sleep(0.3)
    veh.ctx(approach=True, t=_now_ms() - 5000)               # a stale vehicle context, fresh detection
    rsu.detect()
    time.sleep(0.4)
    assert ae.warnings == {}, ae.warnings
    assert _cins(f"{BASE[EDGE_A]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN) == []
    assert not [s for s in ae.client.sent if s["method"] == "POST" and s["url"].endswith("/cmd")]
    veh.ctx(approach=True)                                  # control of the control: now it must fire
    assert _delivered(lab, rsu.detect()), "the rule never fires: the cases above prove nothing"


@live
def test_live_control_the_warning_ae_cannot_read_a_container_whose_acp_does_not_name_it(lab):
    w, a = lab["w"], BASE[EDGE_A]
    veh_ae = f"{a}/{handover.AE_NAME}"
    lab["veh"].ctx()
    lab["rsu"].detect()
    # cmd holds something, or its /la answers 404 before any access check and the 403 below would prove nothing
    assert _cin(f"{veh_ae}/cmd", handover.AE_ORIGIN, {"cmd": "ping", "id": "own"})[0] == 201
    assert req("GET", f"{veh_ae}/cmd/la", handover.AE_ORIGIN)[0] == 200
    assert req("GET", f"{veh_ae}/ctx/la", w)[0] == 200, "control: what it IS granted it reads"
    assert req("GET", f"{lab['rsu'].ae}/vru/la", w)[0] == 200
    st, body, _ = req("GET", veh_ae, w)
    assert st == 200 and body["m2m:ae"]["aei"] == handover.AE_ORIGIN, "it may read the vehicle's <AE> (who holds it)"
    assert set(body["m2m:ae"]) == {"aa", "acpi", "aei", "api", "at", "ct", "et", "lbl", "lt", "pi", "ri", "rn", "rr",
                                   "srv", "ty"}, sorted(body["m2m:ae"])        # what that grant shows it (a stated limit)
    for url in (f"{veh_ae}/{handover.CONTAINER}/la", f"{veh_ae}/{handover.CONTAINER}", f"{lab['rsu'].ae}/env/la",
                f"{veh_ae}/cmd/la", lab["rsu"].ae):
        assert req("GET", url, w)[0] == 403, url
    st, body, _ = req("GET", f"{veh_ae}?fu=1&ty={TY_CIN}", w)
    assert st == 403 or (body or {}).get("m2m:uril") == [], (st, body)


@live
def test_live_control_the_warning_ae_cannot_read_history(lab):
    """It needs the vehicle's context NOW and the route NOW: both containers keep one instance, so even a full
    read gives it nothing older (the vehicle's context at other crossings, the route's past)."""
    vw, veh, w = lab["vw"], lab["veh"], lab["w"]
    for zone in ("crossing-7", "crossing-9", ZONE):
        veh.ctx(zone=zone)
    for _ in range(3):
        assert vw.publish_route(BASE[IN_CSE], lab["aei"], handover.serving_edges()) == 201
    st, body, _ = req("GET", f"{BASE[EDGE_A]}/{handover.AE_NAME}/ctx?rcn=4", w)
    ctx = [json.loads(c["con"])["zone"] for c in (body or {}).get("m2m:cnt", {}).get("m2m:cin", [])]
    assert st == 200 and ctx == [ZONE], ctx
    st, body, _ = req("GET", f"{BASE[IN_CSE]}/{vw.route_rn(lab['aei'])}?rcn=4", w)
    assert st == 200 and len((body or {}).get("m2m:cnt", {}).get("m2m:cin", [])) == 1, body
    for i in range(12):                                      # the vehicle's <ack> keeps its last 8 answers
        assert _cin(f"{BASE[EDGE_A]}/{handover.AE_NAME}/ack", handover.AE_ORIGIN, {"id": f"{i:012x}", "ok": True})[0] == 201
    st, body, _ = req("GET", f"{BASE[EDGE_A]}/{handover.AE_NAME}/ack?rcn=4", w)
    acks = [json.loads(c["con"])["id"] for c in (body or {}).get("m2m:cnt", {}).get("m2m:cin", [])]
    assert st == 200 and sorted(acks) == [f"{i:012x}" for i in range(4, 12)], acks


@live
def test_live_control_the_warning_ae_cannot_write_anywhere_but_the_command_container(lab):
    w, a = lab["w"], BASE[EDGE_A]
    veh_ae, rsu = f"{a}/{handover.AE_NAME}", lab["rsu"].ae
    route = f"{BASE[IN_CSE]}/{lab['vw'].route_rn(lab['aei'])}"
    lab["veh"].ctx()
    assert _cin(f"{veh_ae}/ack", handover.AE_ORIGIN, {"id": "000000000000", "ok": True})[0] == 201  # ack/la exists
    # Ordered so that, if a fault lets them through, nothing is left that the CSE would try to notify (a failed
    # notification is a line in the lab's log): the subscription is made only on child creation, after the last
    # change to cmd, and cmd itself is deleted last, taking it along. Every name is distinct.
    x = uuid.uuid4().hex[:4]
    refused = {
        "vehicle ctx": ("POST", f"{veh_ae}/ctx", TY_CIN, {"m2m:cin": {"con": "{}"}}),
        "vehicle ctx: update": ("PUT", f"{veh_ae}/ctx", None, {"m2m:cnt": {"mni": 1}}),
        "vehicle ack": ("POST", f"{veh_ae}/ack", TY_CIN, {"m2m:cin": {"con": "{}"}}),
        "vehicle ack: update": ("PUT", f"{veh_ae}/ack", None, {"m2m:cnt": {"mni": 50}}),
        "vehicle ack: delete latest": ("DELETE", f"{veh_ae}/ack/la", None, None),
        "vehicle ack: delete": ("DELETE", f"{veh_ae}/ack", None, None),
        "vehicle telemetry": ("POST", f"{veh_ae}/{handover.CONTAINER}", TY_CIN, {"m2m:cin": {"con": "0,0"}}),
        "vehicle AE: new container": ("POST", veh_ae, TY_CNT, {"m2m:cnt": {"rn": f"x-ae-{x}"}}),
        "vehicle AE: update": ("PUT", veh_ae, None, {"m2m:ae": {"rr": False}}),
        "vehicle AE: delete": ("DELETE", veh_ae, None, None),
        "cmdAcp: update": ("PUT", f"{veh_ae}/cmdAcp", None, {"m2m:acp": {"pv": {"acr": [{"acor": [w], "acop": 63}]}}}),
        "sensor vru": ("POST", f"{rsu}/vru", TY_CIN, {"m2m:cin": {"con": "{}"}}),
        "sensor AE": ("POST", rsu, TY_CNT, {"m2m:cnt": {"rn": f"x-rsu-{x}"}}),
        "route record": ("POST", route, TY_CIN, {"m2m:cin": {"con": "{}"}}),
        "route record: update": ("PUT", route, None, {"m2m:cnt": {"mni": 1}}),
        "route record: delete latest": ("DELETE", f"{route}/la", None, None),
        "route record: delete": ("DELETE", route, None, None),
        "edge A CSEBase": ("POST", a, TY_CNT, {"m2m:cnt": {"rn": f"x-a-{x}"}}),
        "edge B CSEBase": ("POST", BASE[EDGE_B], TY_CNT, {"m2m:cnt": {"rn": f"x-b-{x}"}}),
        "IN CSEBase": ("POST", BASE[IN_CSE], TY_CNT, {"m2m:cnt": {"rn": f"x-in-{x}"}}),
        "cmd: update": ("PUT", f"{veh_ae}/cmd", None, {"m2m:cnt": {"mni": 49}}),
        "cmd: a container": ("POST", f"{veh_ae}/cmd", TY_CNT, {"m2m:cnt": {"rn": f"x-cnt-{x}"}}),
        "cmd: a subscription": ("POST", f"{veh_ae}/cmd", TY_SUB, {"m2m:sub": {"rn": f"x-sub-{x}", "nu": [w],
                                                                           "enc": {"net": [3]}}}),
        "cmd: delete": ("DELETE", f"{veh_ae}/cmd", None, None),
    }
    got = {}
    try:
        got = {k: req(m, u, w, ty=ty, body=b)[0] for k, (m, u, ty, b) in refused.items()}
    finally:                                                 # anything that WAS created is taken out again
        for k, (m, u, ty, b) in refused.items():
            if got.get(k) == 201 and ty in (TY_CNT, TY_SUB):
                req("DELETE", f"{u}/{next(iter(b.values()))['rn']}", "CAdmin")
    assert all(st == 403 for st in got.values()), {k: v for k, v in got.items() if v != 403}
    st, _ = _cin(f"{veh_ae}/cmd", w, lab["vw"].warning_body("c0ffee000000", ZONE, "pedestrian", 1, 2, 3))
    assert st == 201, "control: the one write it is granted"
    assert [c["id"] for c in _cons(f"{veh_ae}/cmd", handover.AE_ORIGIN)] == ["c0ffee000000"]
    assert req("DELETE", f"{veh_ae}/cmd/la", w)[0] == 403, "it cannot take a warning back either"


@live
def test_live_control_a_stranger_cannot_read_the_warning(lab):
    lab["veh"].ctx(approach=True)
    lab["start"]()
    assert _delivered(lab, lab["rsu"].detect())
    stranger = f"Cstranger-{uuid.uuid4().hex[:6]}"
    veh_ae = f"{BASE[EDGE_A]}/{handover.AE_NAME}"
    for url in (f"{veh_ae}/cmd/la", f"{veh_ae}/cmd?rcn=4", f"{veh_ae}/ack/la", veh_ae,
                f"{BASE[EDGE_A]}/{lab['w_rn']}/log/la", f"{BASE[IN_CSE]}/{lab['vw'].route_rn(lab['aei'])}/la"):
        assert req("GET", url, stranger)[0] == 403, url
    st, body, _ = req("GET", f"{veh_ae}/cmd?fu=1&ty={TY_CIN}", stranger)
    assert st == 403 or (body or {}).get("m2m:uril") == [], (st, body)
    assert req("GET", f"{veh_ae}/cmd/la", handover.AE_ORIGIN)[0] == 200, "control: the vehicle reads it"


@live
def test_live_why_a_route_record_the_warning_ae_cannot_read_the_announced_ae(lab):
    """Why the route record exists (ACME 2026.5.3): the IN routes vehicle01 by its announced AE, but no originator
    other than CAdmin and the announcing CSE may read it -- not the warning AE, not the vehicle itself. If this
    test ever fails, the warning AE could read the announced AE directly and the record could go."""
    aei = lab["aei"]
    st, body, _ = req("GET", f"{BASE[IN_CSE]}?fu=1&ty=10002&lbl=aei:{aei}", "CAdmin")
    assert st == 200 and len(body["m2m:uril"]) == 1, "control: the IN does hold the route"
    annc = f"{IN_CSE[0]}/{body['m2m:uril'][0]}"
    for who in (lab["w"], aei):
        st, body, _ = req("GET", f"{BASE[IN_CSE]}?fu=1&ty=10002&lbl=aei:{aei}", who)
        assert st == 200 and body.get("m2m:uril") == [], (who, body)
        assert req("GET", annc, who)[0] == 403, who
    assert req("GET", f"{BASE[IN_CSE]}/{lab['vw'].route_rn(aei)}/la", lab["w"])[0] == 200, "the record it may read"


def _shape_errors(lab, s) -> list[str]:
    """Why a request the warning AE sent is not EXACTLY one it may make ([] if it is): every attribute and value of its
    registration, its ACP, its acpi, its log container, its log records and its warnings (with et = the warning's
    expires_t)."""
    own, b, m, u, w = f"{BASE[EDGE_A]}/{lab['w_rn']}", s["body"], s["method"], s["url"], lab["w"]
    if b is None:
        return []
    acpi = [x for x in (lab["ae"].client.sent) if x["method"] == "PUT" and x["url"] == own]
    acpi = acpi[0]["body"]["m2m:ae"]["acpi"] if acpi else None
    exact = {
        ("POST", BASE[EDGE_A], TY_AE): {"m2m:ae": {"rn": lab["w_rn"], "api": "Nestimed.vruWarning", "rr": False,
                                                   "srv": ["4"], "lbl": [lab["ae"].label]}},
        ("POST", own, TY_ACP): {"m2m:acp": {"rn": "vruWarningAcp", "pv": {"acr": [{"acor": [w], "acop": 63}]},
                                            "pvs": {"acr": [{"acor": [w], "acop": 63}]}}},
        ("POST", own, TY_CNT): {"m2m:cnt": {"rn": "log", "mni": 500, "acpi": acpi}},
    }
    if (m, u, s["ty"]) in exact:
        want = exact[(m, u, s["ty"])]
        return [] if b == want else [f"{m} {u}: {b} is not {want}"]
    if (m, u, s["ty"]) == ("PUT", own, None):
        ok = set(b) == {"m2m:ae"} and set(b["m2m:ae"]) == {"acpi"} and isinstance(b["m2m:ae"]["acpi"], list) \
            and len(b["m2m:ae"]["acpi"]) == 1 and isinstance(b["m2m:ae"]["acpi"][0], str)
        return [] if ok else [f"PUT {u}: {b}"]
    cmd = {f"{BASE[e]}/{handover.AE_NAME}/cmd" for e in (EDGE_A, EDGE_B)}
    if m != "POST" or s["ty"] != TY_CIN or u not in cmd | {f"{own}/log"}:
        return [f"{m} {u}: not a write it makes"]
    cin = b.get("m2m:cin") if set(b) == {"m2m:cin"} else None
    if u.endswith("/log"):
        if not isinstance(cin, dict) or set(cin) != {"cnf", "con"} or cin["cnf"] != "application/json:0":
            return [f"POST {u}: {b}"]
        return _log_errors(cin["con"])
    if not isinstance(cin, dict) or set(cin) != {"cnf", "con", "et"} or cin["cnf"] != "application/json:0":
        return [f"POST {u}: {b}"]
    errs = _warning_errors(cin["con"])
    if not errs and cin["et"] != lab["vw"].stamp(json.loads(cin["con"])["expires_t"]):
        errs = [f"et {cin['et']} is not the warning's expires_t"]
    return errs


def _everything_it_wrote(lab) -> list[str]:
    """Every record the warning AE wrote, checked against its exact shape: read back from the CSEs where they are now
    (the vehicle's cmd on the serving edge, its own log) and every request body it sent."""
    edge = next(e for e in (EDGE_A, EDGE_B) if CSI_OF[e] in handover.serving_edges())
    errs = [f"cmd: {x}" for c in _cins(f"{BASE[edge]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN)
            for x in _warning_errors(c["con"])]
    errs += [f"log: {x}" for c in _cins(f"{BASE[EDGE_A]}/{lab['w_rn']}/log", lab["w"]) for x in _log_errors(c["con"])]
    return errs + [x for s in list(lab["ae"].client.sent) for x in _shape_errors(lab, s)]


@live
def test_live_control_every_record_the_warning_ae_writes_is_exactly_its_shape(lab):
    """The warning is exactly its eight keys and values; the log record is the event kind and the warning id; nothing
    else is written. A planted record with one key more is found by the same read-back."""
    veh = lab["veh"]
    veh.ctx(approach=True)
    lab["start"]()
    assert _delivered(lab, lab["rsu"].detect())
    assert _move(lab, EDGE_A, EDGE_B)
    veh.ctx(approach=True)
    assert _delivered(lab, lab["rsu"].detect())
    time.sleep(0.2)                                          # the last log records
    n_cmd = len(_cins(f"{BASE[EDGE_B]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN))
    n_log = len(_cins(f"{BASE[EDGE_A]}/{lab['w_rn']}/log", lab["w"]))
    assert n_cmd >= 2 and n_log >= 6 and _everything_it_wrote(lab) == [], _everything_it_wrote(lab)
    planted = lab["vw"].warning_body("bad000000000", ZONE, "pedestrian", 1, 2, 3) | {"pos": [0.0, 0.0]}
    assert _cin(f"{BASE[EDGE_B]}/{handover.AE_NAME}/cmd", handover.AE_ORIGIN, planted)[0] == 201
    assert [e for e in _everything_it_wrote(lab) if "pos" in e], "the planted key was not found"


@live
def test_live_control_the_warning_ae_sends_only_as_itself_and_reads_only_what_it_needs(lab):
    """Every request carries its own originator; its writes are its own subtree and the vehicle's cmd; its reads are
    the route record's latest, the sensor's latest, the vehicle's <AE>, the vehicle's latest context and its acks."""
    veh = lab["veh"]
    veh.ctx(approach=True)
    lab["start"]()
    assert _delivered(lab, lab["rsu"].detect())
    assert _move(lab, EDGE_A, EDGE_B)
    veh.ctx(approach=True)
    assert _delivered(lab, lab["rsu"].detect())
    sent = list(lab["ae"].client.sent)
    assert sent and {s["origin"] for s in sent} == {lab["w"]}
    mine = f"{BASE[EDGE_A]}/{lab['w_rn']}"
    veh_at = [f"{BASE[e]}/{handover.AE_NAME}" for e in (EDGE_A, EDGE_B)]
    writes = {(s["method"], s["url"]) for s in sent if s["method"] != "GET"}
    assert all(u.startswith(mine) or u in {f"{v}/cmd" for v in veh_at} or (m, u) == ("POST", BASE[EDGE_A])
               for m, u in writes), writes
    may_read = {f"{BASE[IN_CSE]}/{lab['vw'].route_rn(lab['aei'])}/la", f"{lab['rsu'].ae}/vru/la", mine,
                *veh_at, *(f"{v}/ctx/la" for v in veh_at), *(f"{v}/ack?rcn=4" for v in veh_at)}
    reads = {s["url"] for s in sent if s["method"] == "GET"}
    assert reads <= may_read, sorted(reads - may_read)
