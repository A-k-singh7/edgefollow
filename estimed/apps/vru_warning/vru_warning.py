#!/usr/bin/env python3
"""A vulnerable-road-user (VRU) collision warning AE on the edge (ESTIMED use cases, p6: "Vulnerable Road User
Detection ... immediate, sub-second warnings").

It runs as its own AE, with its own originator, on the MN-CSE of the crossing it watches. It combines two records and
warns the vehicle through oneM2M:

    the roadside sensor   <sensor AE>/vru/la      {"zone", "present", "class", "t"}   read through an ACP naming it
    the vehicle's AE      <vehicle AE>            its aei must be the vehicle's      read through an ACP naming it
    the vehicle           <vehicle AE>/ctx/la     {"zone", "approach", "t"}          read through an ACP naming it;
                                                                                     mni 1, so there is no history
    the warning           <vehicle AE>/cmd        one <contentInstance>, et set      CREATE of a contentInstance is
                                                                                     the one write the vehicle grants
    the acknowledgement   <vehicle AE>/ack        {"id", "ok", "vehicle_t"}          read through an ACP naming it

THE RULE (RULE below). A warning is raised for one sensor event when, at that moment,
    the sensor reports a road user present, of a vulnerable class (pedestrian or cyclist), in the AE's zone, and
    the vehicle reports itself in the same zone and approaching it, and
    both records are fresh (at most MAX_AGE_MS old, at most SKEW_MS in the future).
Why this one: it is the smallest conjunction the use case names -- a local sensor's VRU detection fused with a vehicle
behaviour indicator ("proximity to intersections") -- and both inputs are DERIVED values. A zone is a name, never a
position, so the AE can decide without reading where anybody is. The warning is exactly WARNING_KEYS; the AE's own
`log` records are exactly {"event", "id"}: no position, no vehicle, no zone, no edge (the project's privacy rule: the
city never holds positions; and the log is no movement record either).

WHERE THE VEHICLE IS. The vehicle moves between edges (estimed/handover.py), so every warning is routed again: the AE
reads the vehicle's route record at the IN-CSE and writes only to the edge it names, only when it names exactly one
edge as ATTACHED, only when the record is at most ROUTE_MAX_AGE_MS old, and only when the <AE> at the vehicle's name on
that edge carries the vehicle's AE-ID (a stale record must not hand the warning to whoever registered that name since).
While the record says MOVING (or is stale, or names nothing, or an edge the AE does not know) a warning is held, never
written; a MOVING record older than MAX_MOVE_MS counts as stale (a keeper alive inside a move re-publishes MOVING
every MOVING_BEAT_MS, however long the move takes, so only a dead keeper's MOVING gets that old); and the AE logs why: {"event": "held", "id": <one of HELD_REASONS>}, at most once per HELD_LOG_EVERY_MS for
each reason, so a silent AE is visible. Once the record names the new edge the warning is written there.
The record stays fresh only if something re-publishes it: RouteKeeper below (orchestrator side) publishes what the
IN's announced AE names every ROUTE_KEEP_S, MOVING for the length of a handover (RouteKeeper.moving()), and the new
edge right after; while the handover runs, moving() re-publishes MOVING every MOVING_BEAT_MS (a heartbeat), so a long move
(46 s were measured with 1400 instances to copy) never looks like a dead keeper's. ONE keeper per route, owned by the
handover driver in its own process: it calls open(), runs run() in a thread and wraps every handover in moving(). A
second keeper of the same route is not supported: its periodic publication would overwrite MOVING during the driver's
move -- and it is not detected: a second keeper opened while the first is alive takes the record over (open() cannot
tell a live owner from a dead one) and both then publish. A keeper restarted after dying (inside a move or not) takes its
own record and ACP over in open() and publishes the route as the IN names it now, which clears a MOVING left behind --
when both are still there. Half-made (its ACP there, the record gone: it died between the two creates) open() refuses
with 409 and the ACP has to be removed by hand (DELETE <IN-CSE>/route-<AE-ID>-acp as the orchestrator); an IN that does
not answer also yields 409 (try again). A record taken over keeps the mni it was made with (open() changes only the
readers). Without a keeper the record ages out after ROUTE_MAX_AGE_MS and
every warning is held (logged as held/route-stale).

THE VEHICLE WHILE IT MOVES. handover.py copies every instance of every container and then requires the target to START
with all it copied (_matches); an instance the source drops meanwhile (mni reached, or expired) is read as a 404. So a
container that is full, or fills, during the move and gets a write then fails the move, whatever its mni. Measured
2026-11-20 with writes every 20 ms during handover.handover(): mni 1; mni 16 starting empty (26 writes, so it filled);
mni 16 full (and at one write per 200 ms); mni 64 full -- every move refused and rolled back. A container that stayed
below its mni survived: the reviewer's control, mni 50 with 72 writes in the run, and mni 2000 (one such move took 46 s
to copy 1385 instances). The vehicle therefore WRITES nothing (context, acknowledgements) while its route record says
MOVING -- it is one of the record's readers, and RouteKeeper.moving() waits ROUTE_SETTLE_S after publishing MOVING
before the handover starts -- but it keeps READING its <cmd> and acting on a warning (it answers it once the record
names an edge again). A MOVING record older than MAX_MOVE_MS it treats as stale: it stops waiting and writes again. That keeps ctx at mni 1
(the AE can read no history of where the vehicle was). The same handover.py rule holds the phone's mni-2000 containers
once they are full; the fix belongs in handover._matches (proposed in the build report), not here. A warning that was written but not yet acknowledged when the route changes is written again to the new edge,
unless its acknowledgement is already there (the handover carries <cmd> and <ack>); the vehicle answers each warning id
once.

EXPIRY. A warning lives WARNING_TTL_MS from the SENSOR EVENT (expires_t = event_t + ttl). The AE drops it then, checks
again immediately before every write (with less than WRITE_MARGIN_MS left it is dropped, not written), and writes it
with `et` = expires_t, so the CSE removes it too. That holds on the
edge it was written to. After a handover it does not: handover._copy re-creates a contentInstance with con and cnf
only, so the carried copy has no et. The check that holds everywhere is the VEHICLE's: it acts on no warning whose
expires_t has passed (the simulated vehicle in tests/test_vru_warning.py does exactly that).

The route record exists because ACME 2026.5.3 lets no other originator read an announced AE at the IN: it has no acpi
of its own (the vehicle's acpi is carried only when the AE is announced after its acpi is set, and the IN then does not
honour an ACP held on another CSE), and only its creator, the announcing MN-CSE, may set one (measured 2026-11-20,
4 ways). So the orchestrator, which reads the announced AE for every handover anyway (handover.serving_edges, as
CAdmin), copies it into <IN-CSE>/route-<AE-ID> (mni 1), a container only the readers it names may read (open_route,
publish_route, close_route below: ORCHESTRATOR SIDE, never called by the warning AE).

ROBUSTNESS. A record's con longer than MAX_CON_CHARS, or not JSON, or nested past the parser's limit, is no record.
One failing look never stops the watch: each half of step() and each step in run() is guarded, the error kept in
`events` (memory only). What it keeps in memory is bounded (KEEP).

What the AE writes: its own registration (<AE>, its <ACP>, a container `log`) and warnings in the vehicle's <cmd>.
Every request it sends carries its own originator and is kept in `client.sent`, so a test can show where it went.

Not done (stated):
  * an in-flight warning rewritten after a move is in the new edge's <cmd> twice (the carried copy and the rewrite; the
    vehicle answers once);
  * the route name at the IN can be taken first by any C-originator (RouteKeeper.open() then refuses, without a request
    the CSE would answer 409: warnings are held, never misrouted);
  * a keeper (and with it the handover driver, same process) that dies inside a move: the heartbeat stops, after
    MAX_MOVE_MS the vehicle writes again; what the half-done handover left is handover.py's to clear (its transaction
    lock expires; nothing here rolls it back);
  * the vehicle's grant on its <AE> is RETRIEVE of the whole resource: the AE sees aa, acpi, aei, api, at, ct, et, lbl,
    lt, pi, ri, rn, rr, srv, ty (and poa, if a vehicle had one). An attribute rule (aca: ["aei"]) would show it aei
    alone, but ACME 2026.5.3 applies an aca rule to EVERY originator: a stranger could then read aei on each edge and
    learn which one serves the vehicle (measured 2026-11-20; tests/test_vru_warning.py pins it);
  * the AE can read the vehicle's last acknowledgements (warning ids and the vehicle's times, as many as the vehicle's
    <ack> keeps; the simulated vehicle keeps 8).

Run as a process (standard library only):  python3 -I -B vru_warning.py --config config.json   (keys: see WarningAE).
The route keeper has no command of its own: it lives in the handover driver's process (see above).
"""
from __future__ import annotations

import argparse
import contextlib
import json
import secrets
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

RULE = "vru-present-and-vehicle-approaching-in-zone/1"
VRU_CLASSES = frozenset({"pedestrian", "cyclist"})
MAX_AGE_MS = 2000           # a record older than this is not evidence of now
SKEW_MS = 250               # a record from further in the future than this is not trusted either
WARNING_TTL_MS = 3000       # a warning lives this long from the sensor event; never written or acted on later
WRITE_MARGIN_MS = 100       # less than this left: not written (the CSE must get it before its et; ACME refuses an et
                            # in the past and writes a WARNING to its log for each such request)
ROUTE_MAX_AGE_MS = 60_000   # a route record older than this routes nothing
ROUTE_KEEP_S = 30.0         # RouteKeeper re-publishes at least this often (half the age bound)
ROUTE_SETTLE_S = 0.2        # RouteKeeper.moving(): time for the vehicle to see MOVING before the handover starts
MAX_MOVE_MS = 10_000        # a MOVING record older than this is stale. A live keeper re-publishes MOVING every
                            # MOVING_BEAT_MS for as long as its move lasts (46 s measured), so only a dead keeper's
                            # MOVING gets this old; a vehicle whose keeper died inside a move waits at most 10 s
MOVING_BEAT_MS = 2_000      # the heartbeat: a fifth of MAX_MOVE_MS; a 46 s move costs 23 writes to an mni-1 container,
                            # and the vehicle (reading every 50 ms) sees each within one look
BEAT_TIMEOUT_S = 1.5        # the client timeout of a heartbeat publication (the client's default is 5 s). Two beat
                            # publications in a row may fail, even by timing out: MOVING is then at most
                            # 3 x 2 s + 2 x 1.5 s = 9 s old when the third beat refreshes it, under MAX_MOVE_MS. Three
                            # failures in a row are not covered (the vehicle may then write again, and a move under way
                            # may be refused and rolled back). With the 5 s default two timed-out beats left it 16 s old
HELD_LOG_EVERY_MS = 10_000  # a held reason is logged at most this often
HELD_REASONS = ("route-none", "route-stale", "route-moving", "route-unknown", "not-the-vehicle")
MAX_CON_CHARS = 8192        # a record longer than this is no record
KEEP = 2000                 # at most this many finished warnings, remembered sensor events and kept events
KEEP_SENT = 20_000          # at most this many requests kept in client.sent
CREATE, RETRIEVE, UPDATE, DELETE, NOTIFY, DISCOVER, ALL = 1, 2, 4, 8, 16, 32, 63
TY_ACP, TY_AE, TY_CNT, TY_CIN = 1, 2, 3, 4
ORCHESTRATOR = "CAdmin"     # the orchestrator's identity at the IN; the warning AE never uses it
WARNING_KEYS = frozenset({"cmd", "id", "rule", "zone", "class", "event_t", "issued_t", "expires_t"})
LOG_EVENTS = ("issued", "written", "acked", "expired", "held")


def now_ms() -> int:
    return int(time.time() * 1000)


def stamp(ms: int) -> str:
    """oneM2M timestamp (UTC) of epoch milliseconds."""
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime(ms // 1000)) + f",{ms % 1000:03d}000"


def parse_con(con):
    """A contentInstance's con as JSON, or None: too long, not JSON, or nested past the parser's limit."""
    if not isinstance(con, str):
        return con if isinstance(con, (dict, list)) else None
    if len(con) > MAX_CON_CHARS:
        return None
    try:
        return json.loads(con)
    except (ValueError, RecursionError):
        return None


# ---- the rule -----------------------------------------------------------------------------------------------
def _fresh(t, now: int, max_age_ms: int) -> bool:
    return isinstance(t, (int, float)) and not isinstance(t, bool) and -SKEW_MS <= now - t <= max_age_ms


def sensor_reason(sensor, zone: str, now: int, max_age_ms: int = MAX_AGE_MS) -> str | None:
    """The sensor half of RULE: None when it holds, else why not."""
    if not isinstance(sensor, dict):
        return "no sensor record"
    if sensor.get("present") is not True:
        return "no road user present"
    cls = sensor.get("class")
    if not isinstance(cls, str) or cls not in VRU_CLASSES:
        return "not a vulnerable road user"
    if sensor.get("zone") != zone:
        return "the sensor reports another zone"
    if not _fresh(sensor.get("t"), now, max_age_ms):
        return "the sensor record is not fresh"
    return None


def vehicle_reason(vehicle, zone: str, now: int, max_age_ms: int = MAX_AGE_MS) -> str | None:
    """The vehicle half of RULE: None when it holds, else why not."""
    if not isinstance(vehicle, dict):
        return "no vehicle context"
    if vehicle.get("zone") != zone:
        return "the vehicle is not in the zone"
    if vehicle.get("approach") is not True:
        return "the vehicle is not approaching"
    if not _fresh(vehicle.get("t"), now, max_age_ms):
        return "the vehicle context is not fresh"
    return None


def rule_fires(sensor, vehicle, zone: str, now: int, max_age_ms: int = MAX_AGE_MS) -> tuple[bool, str]:
    """RULE: (True, "fires") or (False, the first reason it does not)."""
    why = sensor_reason(sensor, zone, now, max_age_ms) or vehicle_reason(vehicle, zone, now, max_age_ms)
    return (False, why) if why else (True, "fires")


def warning_body(wid: str, zone: str, cls: str, event_t, issued_t: int, expires_t: int) -> dict:
    """What the vehicle is told, exactly WARNING_KEYS: which zone, what kind of road user, when seen, until when."""
    return {"cmd": "vru-warning", "id": wid, "rule": RULE, "zone": zone, "class": cls, "event_t": event_t,
            "issued_t": issued_t, "expires_t": expires_t}


def log_record(what: str, wid: str) -> dict:
    """What the AE keeps in its own `log`: the kind of event and the warning's id (for "held": the reason, one of
    HELD_REASONS), nothing else."""
    return {"event": what, "id": wid}


# ---- the route record ---------------------------------------------------------------------------------------
def route_rn(aei: str) -> str:
    return f"route-{aei}"


def route_state(record, aei: str, known, now: int, max_age_ms: int = ROUTE_MAX_AGE_MS) -> tuple[str | None, str | None]:
    """(the one edge a route record names for this AE-ID, None) -- ATTACHED, a known edge, at most max_age_ms old --
    or (None, why not: one of HELD_REASONS)."""
    if not isinstance(record, dict) or record.get("aei") != aei:
        return None, "route-none"
    if not _fresh(record.get("t"), now, max_age_ms):
        return None, "route-stale"
    if record.get("state") == "MOVING":
        return None, "route-moving" if now - record["t"] <= MAX_MOVE_MS else "route-stale"
    edge = record.get("serving")
    if record.get("state") != "ATTACHED" or not isinstance(edge, str) or edge not in known:
        return None, "route-unknown"
    return edge, None


def route_edge(record, aei: str, known, now: int, max_age_ms: int = ROUTE_MAX_AGE_MS) -> str | None:
    return route_state(record, aei, known, now, max_age_ms)[0]


# ---- oneM2M over HTTP, one originator, every request kept ---------------------------------------------------
def _trim(items: list, keep: int) -> None:
    if len(items) > keep:
        del items[:len(items) - keep]


class Client:
    def __init__(self, origin: str, timeout: float = 5.0):
        self.origin, self.timeout = origin, timeout
        self.sent: list[dict] = []
        self._lock = threading.Lock()

    def req(self, method: str, url: str, ty: int | None = None, body=None) -> tuple[int, dict | None]:
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(url, data=data, method=method, headers={
            "X-M2M-Origin": self.origin, "X-M2M-RI": f"vru{uuid.uuid4().hex[:12]}", "X-M2M-RVI": "4",
            "Accept": "application/json", "Content-Type": f"application/json;ty={ty}" if ty else "application/json"})
        status, raw = 0, b""
        try:
            with urllib.request.urlopen(r, timeout=self.timeout) as resp:
                status, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        except (urllib.error.URLError, OSError, ValueError):
            status = 0
        try:
            parsed = json.loads(raw) if raw else None
        except (ValueError, RecursionError):
            parsed = None
        with self._lock:
            self.sent.append({"t": time.time(), "method": method, "url": url, "ty": ty, "origin": self.origin,
                              "status": status, "body": body})
            _trim(self.sent, KEEP_SENT)
        return status, parsed if isinstance(parsed, dict) else None

    def latest(self, url: str):
        """The latest contentInstance of a container: (status, its con parsed or None, its ri or None)."""
        st, body = self.req("GET", f"{url}/la")
        cin = (body or {}).get("m2m:cin") if st == 200 else None
        if not isinstance(cin, dict):
            return st, None, None
        ri = cin.get("ri")
        return st, parse_con(cin.get("con")), ri if isinstance(ri, str) else None


# ---- the warning AE -----------------------------------------------------------------------------------------
class WarningAE:
    """cfg:
        origin     its originator (C-prefixed; the AE-ID it registers with)
        rn         its <AE>'s resource name
        cse        its own MN-CSE, CSEBase URL (e.g. http://127.0.0.1:8201/cse-mn-a)
        in         the IN-CSE's CSEBase URL (where the route records are)
        edges      {CSE-ID: CSEBase URL} of every edge a vehicle may be served by
        vehicle    {"aei": AE-ID, "rn": its <AE>'s resource name on whichever edge serves it}
        sensor     URL of the sensor's detection container
        zone       the zone this AE watches (the sensor's)
        readers    optional: originators that may read its log (nobody else may)
        ttl_ms, max_age_ms, route_max_age_ms, keep   optional: WARNING_TTL_MS, MAX_AGE_MS, ROUTE_MAX_AGE_MS, KEEP
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.client = Client(cfg["origin"])
        self.zone = cfg["zone"]
        self.ttl_ms = int(cfg.get("ttl_ms", WARNING_TTL_MS))
        self.max_age_ms = int(cfg.get("max_age_ms", MAX_AGE_MS))
        self.route_max_age_ms = int(cfg.get("route_max_age_ms", ROUTE_MAX_AGE_MS))
        self.keep = int(cfg.get("keep", KEEP))
        self.aei, self.vrn = cfg["vehicle"]["aei"], cfg["vehicle"]["rn"]
        self.ae_url = f"{cfg['cse']}/{cfg['rn']}"
        self.label = f"vru:instance:{uuid.uuid4().hex[:12]}"
        self.warnings: dict[str, dict] = {}       # id -> state of each warning (open ones, and the last `keep` others)
        self.events: list[dict] = []              # what happened, in order (memory only, last `keep`)
        self._warned_events: dict[str, float] = {}  # sensor record ri -> its t, while it could still be fresh
        self._held_t: dict[str, int] = {}          # held reason -> when it was last logged
        self.registered = False

    # registration
    def register(self) -> None:
        c, o = self.client, self.cfg["origin"]
        st, body = c.req("POST", self.cfg["cse"], TY_AE, {"m2m:ae": {
            "rn": self.cfg["rn"], "api": "Nestimed.vruWarning", "rr": False, "srv": ["4"], "lbl": [self.label]}})
        if st != 201 or (body or {}).get("m2m:ae", {}).get("aei") != o:
            raise RuntimeError(f"AE create answered {st}: {body}")
        self.registered = True
        rules = [{"acor": [o], "acop": ALL}] + ([{"acor": list(self.cfg["readers"]), "acop": RETRIEVE}]
                                               if self.cfg.get("readers") else [])
        st, body = c.req("POST", self.ae_url, TY_ACP, {"m2m:acp": {
            "rn": "vruWarningAcp", "pv": {"acr": rules}, "pvs": {"acr": [{"acor": [o], "acop": ALL}]}}})
        if st != 201:
            raise RuntimeError(f"ACP create answered {st}: {body}")
        acpi = [body["m2m:acp"]["ri"]]
        if c.req("PUT", self.ae_url, None, {"m2m:ae": {"acpi": acpi}})[0] != 200:
            raise RuntimeError("AE acpi update refused")
        st, body = c.req("POST", self.ae_url, TY_CNT, {"m2m:cnt": {"rn": "log", "mni": 500, "acpi": acpi}})
        if st != 201:
            raise RuntimeError(f"log container create answered {st}: {body}")

    def deregister(self) -> None:
        """Remove its own <AE> -- only one carrying this instance's label."""
        if not self.registered:
            return
        st, body = self.client.req("GET", self.ae_url)
        if st == 200 and self.label in ((body or {}).get("m2m:ae", {}).get("lbl") or []):
            self.client.req("DELETE", self.ae_url)
        self.registered = False

    # where the vehicle is
    def serving_edge(self) -> tuple[str | None, str | None]:
        """(the CSE-ID of the one edge a fresh route record names as ATTACHED, None) or (None, why not)."""
        _, rec, _ = self.client.latest(f"{self.cfg['in']}/{route_rn(self.aei)}")
        return route_state(rec, self.aei, self.cfg["edges"], now_ms(), self.route_max_age_ms)

    def _vehicle(self, edge: str) -> str:
        return f"{self.cfg['edges'][edge]}/{self.vrn}"

    def _is_the_vehicle(self, edge: str, seen: dict) -> bool:
        """The <AE> at the vehicle's name on that edge is the vehicle's (its aei), once per look. Anything else -- another
        aei, or no answer to read (403, 404, ...) -- is not the vehicle."""
        if edge not in seen:
            st, body = self.client.req("GET", self._vehicle(edge))
            seen[edge] = st == 200 and (body or {}).get("m2m:ae", {}).get("aei") == self.aei
        return seen[edge]

    def _held(self, reason: str | None, logs: list) -> None:
        """Record why a warning (or an event) is held: at most once per HELD_LOG_EVERY_MS for each reason."""
        reason = reason if reason in HELD_REASONS else "route-none"
        t = now_ms()
        if t - self._held_t.get(reason, -HELD_LOG_EVERY_MS) >= HELD_LOG_EVERY_MS:
            self._held_t[reason] = t
            logs.append(("held", reason))

    # one look
    def step(self, now: int | None = None) -> None:
        """Read the sensor; on a new event that holds, read the route and the vehicle and maybe raise a warning; then
        write each open warning to the one edge the route names, or hold it, and look for its acknowledgement. Each
        half is guarded: a bad record in one never stops the other. The `log` records are written last."""
        now = now_ms() if now is None else now
        logs: list[tuple[str, str]] = []
        seen: dict[str, bool] = {}
        route = {}                                          # read at most once per look
        try:
            self._new_event(now, logs, seen, route)
        except Exception as e:  # noqa: BLE001 -- a look at the inputs must not stop the open warnings
            self._error("event", e)
        try:
            self._open_warnings(logs, seen, route)
        except Exception as e:  # noqa: BLE001
            self._error("open", e)
        for what, wid in dict.fromkeys(logs):              # a reason held twice in one look is logged once
            try:
                self._log(what, wid)
            except Exception as e:  # noqa: BLE001
                self._error("log", e)
        self._prune(now)

    def _route(self, route: dict, logs: list) -> str | None:
        if "edge" not in route:
            route["edge"], route["why"] = self.serving_edge()
        if route["edge"] is None:
            self._held(route["why"], logs)
        return route["edge"]

    def _usable(self, route: dict, seen: dict, logs: list) -> str | None:
        """The edge to read and write the vehicle on now, or None (held, and why is logged)."""
        edge = self._route(route, logs)
        if edge is not None and not self._is_the_vehicle(edge, seen):
            self._held("not-the-vehicle", logs)
            return None
        return edge

    def _new_event(self, now: int, logs: list, seen: dict, route: dict) -> None:
        _, sensor, s_ri = self.client.latest(self.cfg["sensor"])
        if s_ri is None or s_ri in self._warned_events or sensor_reason(sensor, self.zone, now, self.max_age_ms):
            return
        edge = self._usable(route, seen, logs)
        if edge is None:
            return                                          # not evaluable now; the event stays open while fresh
        _, vehicle, _ = self.client.latest(f"{self._vehicle(edge)}/ctx")
        if not rule_fires(sensor, vehicle, self.zone, now, self.max_age_ms)[0]:
            return
        self._warned_events[s_ri] = sensor["t"]
        wid = secrets.token_hex(6)
        self.warnings[wid] = {"id": wid, "event_t": int(sensor["t"]), "class": sensor["class"], "issued_t": now,
                              "expires_t": int(sensor["t"]) + self.ttl_ms, "written_to": [], "acked": None,
                              "status": "open"}
        logs.append(("issued", wid))

    def _expired(self, w: dict, logs: list, margin_ms: int = 0) -> bool:
        if now_ms() > w["expires_t"] - margin_ms:
            w["status"] = "expired"
            logs.append(("expired", w["id"]))
            return True
        return False

    def _open_warnings(self, logs: list, seen: dict, route: dict) -> None:
        acks = None
        for w in [w for w in list(self.warnings.values()) if w["status"] == "open"]:
            if self._expired(w, logs):
                continue
            edge = self._usable(route, seen, logs)
            if edge is None:
                continue                                    # held: no single fresh route, or not the vehicle there
            if w["written_to"]:                             # written somewhere: has the vehicle answered here?
                acks = self._acks(edge) if acks is None else acks
                if w["id"] in acks:
                    w.update(status="acked", acked=acks[w["id"]], acked_seen_t=now_ms())
                    logs.append(("acked", w["id"]))
                    continue
                if edge in w["written_to"]:
                    continue
            if self._expired(w, logs, WRITE_MARGIN_MS):     # again, right before the write
                continue
            body = warning_body(w["id"], self.zone, w["class"], w["event_t"], w["issued_t"], w["expires_t"])
            st, _ = self.client.req("POST", f"{self._vehicle(edge)}/cmd", TY_CIN, {"m2m:cin": {
                "cnf": "application/json:0", "con": json.dumps(body, sort_keys=True), "et": stamp(w["expires_t"])}})
            if st == 201:
                w["written_to"].append(edge)
                w["written_t"] = now_ms()
                logs.append(("written", w["id"]))

    def warnings_open(self) -> bool:
        return any(w["status"] == "open" for w in list(self.warnings.values()))

    def _acks(self, edge: str) -> dict[str, dict]:
        """The vehicle's POSITIVE acknowledgements on that edge, by warning id."""
        st, body = self.client.req("GET", f"{self._vehicle(edge)}/ack?rcn=4")
        items = (body or {}).get("m2m:cnt", {}).get("m2m:cin", []) if st == 200 else []
        out = {}
        for c in items if isinstance(items, list) else []:
            a = parse_con(c.get("con")) if isinstance(c, dict) else None
            if isinstance(a, dict) and isinstance(a.get("id"), str) and a.get("ok") is True:
                out[a["id"]] = a
        return out

    def _log(self, what: str, wid: str) -> None:
        rec = log_record(what, wid)
        self.events.append(rec)
        self.client.req("POST", f"{self.ae_url}/log", TY_CIN, {"m2m:cin": {
            "cnf": "application/json:0", "con": json.dumps(rec, sort_keys=True)}})

    def _error(self, where: str, e: BaseException) -> None:
        self.events.append({"event": "error", "where": where, "why": f"{type(e).__name__}: {str(e)[:120]}"})

    def _prune(self, now: int) -> None:
        """Keep memory bounded: finished warnings beyond `keep`, sensor events that can no longer be fresh, old events."""
        done = [k for k, w in self.warnings.items() if w["status"] != "open"]
        for k in done[:max(0, len(done) - self.keep)]:
            del self.warnings[k]
        horizon = now - self.max_age_ms - SKEW_MS - 1000
        for ri in [ri for ri, t in self._warned_events.items() if not isinstance(t, (int, float)) or t < horizon]:
            del self._warned_events[ri]
        while len(self._warned_events) > self.keep:
            del self._warned_events[next(iter(self._warned_events))]
        _trim(self.events, self.keep)

    def run(self, stop: threading.Event, period_s: float = 0.05) -> None:
        while not stop.is_set():
            t0 = time.monotonic()
            try:
                self.step()
            except Exception as e:  # noqa: BLE001 -- one bad look never stops the watch
                self._error("step", e)
            stop.wait(max(0.0, period_s - (time.monotonic() - t0)))


# ---- ORCHESTRATOR SIDE: the route record at the IN-CSE (never called by the warning AE) ------------------------
def _admin(method: str, url: str, ty=None, body=None, origin: str = ORCHESTRATOR, timeout: float = 5.0):
    return Client(origin, timeout=timeout).req(method, url, ty, body)


def open_route(in_base: str, aei: str, readers: list[str], origin: str = ORCHESTRATOR, admin=None) -> int:
    """<IN-CSE>/route-<AE-ID> (mni 1: no history; it does not move with the vehicle): a container whose <ACP> lets the
    named readers RETRIEVE and nobody else anything. The readers are the warning AE and the vehicle itself (it holds
    its writes while the record says MOVING)."""
    admin = admin or _admin
    st, body = admin("POST", in_base, TY_ACP, route_acp(aei, readers, origin), origin=origin)
    if st != 201:
        return st
    st, _ = admin("POST", in_base, TY_CNT, {"m2m:cnt": {"rn": route_rn(aei), "mni": 1,
                                                       "acpi": [body["m2m:acp"]["ri"]]}}, origin=origin)
    return st


def route_acp(aei: str, readers: list[str], origin: str = ORCHESTRATOR) -> dict:
    return {"m2m:acp": {"rn": f"{route_rn(aei)}-acp", "pv": {"acr": [{"acor": list(readers), "acop": RETRIEVE}]},
                        "pvs": {"acr": [{"acor": [origin], "acop": ALL}]}}}


def publish_route(in_base: str, aei: str, serving: list[str], *, moving: bool = False,
                  origin: str = ORCHESTRATOR, timeout: float = 5.0) -> int:
    """Record what the IN routes this AE-ID to (handover.serving_edges()): ATTACHED to the one edge, MOVING while a
    handover runs, UNKNOWN otherwise (none, or more than one). RouteKeeper calls it; ROUTE_MAX_AGE_MS after the last
    publication the record routes nothing."""
    state = "MOVING" if moving else ("ATTACHED" if len(serving) == 1 else "UNKNOWN")
    rec = {"aei": aei, "state": state, "serving": serving[0] if state == "ATTACHED" else None, "t": now_ms()}
    return _admin("POST", f"{in_base}/{route_rn(aei)}", TY_CIN, {"m2m:cin": {
        "cnf": "application/json:0", "con": json.dumps(rec, sort_keys=True)}}, origin, timeout=timeout)[0]


def close_route(in_base: str, aei: str, origin: str = ORCHESTRATOR) -> None:
    _admin("DELETE", f"{in_base}/{route_rn(aei)}", origin=origin)
    _admin("DELETE", f"{in_base}/{route_rn(aei)}-acp", origin=origin)


def announced_edges(in_base: str, aei: str, origin: str = ORCHESTRATOR) -> list[str]:
    """The CSE-IDs the IN routes this AE-ID to: the link of every announced AE carrying its label (the same reading as
    estimed/handover.py serving_edges). Raises OSError when the IN cannot be read: no answer is not "no edge"."""
    host = in_base.split("/", 3)
    host = "/".join(host[:3])
    st, body = _admin("GET", f"{in_base}?fu=1&ty=10002&lbl=aei:{aei}", origin=origin)
    if st != 200 or not isinstance(body, dict):
        raise OSError(f"route of {aei} at the IN: {st}")
    edges = []
    for uri in body.get("m2m:uril", []):
        s, b = _admin("GET", f"{host}/{uri}", origin=origin)
        lnk = ((b or {}).get("m2m:aeA") or {}).get("lnk") if s == 200 else None
        if not isinstance(lnk, str) or not lnk.strip("/"):
            raise OSError(f"{uri}: {s}, no link")
        edges.append("/" + lnk.strip("/").split("/")[0])
    return sorted(edges)


class RouteKeeper:
    """ORCHESTRATOR SIDE: keeps <IN-CSE>/route-<AE-ID> fresh for its readers.

        open()      the record and its ACP (made, or this keeper's own taken over), and a first publication
        tick()      publish what serving() names if the last publication is period_s old (not during a move)
        run(stop)   tick() until stop is set -- in a thread of the handover driver's process
        moving()    a context manager around a handover: MOVING at once, settle_s for the vehicle (one of the
                    readers) to see it and stop writing, then the caller's handover, then what serving() names now
        close()     the record and its ACP removed
    serving() is what the IN's announced AE names (announced_edges, or handover.serving_edges). A publication that
    fails is tried again at the next tick; a serving() that cannot be read publishes nothing, so the record ages out
    (the AE then holds and logs held/route-stale) rather than naming a guess."""

    def __init__(self, in_base: str, aei: str, readers: list[str], *, serving=None, period_s: float = ROUTE_KEEP_S,
                 settle_s: float = ROUTE_SETTLE_S, origin: str = ORCHESTRATOR, clock=time.monotonic,
                 publish=publish_route, sleep=time.sleep, admin=None, beat_s: float = MOVING_BEAT_MS / 1000, beat_timeout_s: float = BEAT_TIMEOUT_S,
                 wait=None):
        self.in_base, self.aei, self.readers, self.origin = in_base, aei, list(readers), origin
        self.serving = serving or (lambda: announced_edges(in_base, aei, origin))
        self.period_s, self.settle_s, self.clock, self._publish, self._sleep = period_s, settle_s, clock, publish, sleep
        self._admin = admin or _admin
        self.beat_s, self.beat_timeout_s = beat_s, beat_timeout_s
        self._wait = wait or (lambda stop, seconds: stop.wait(seconds))      # True once stop is set
        self.last: float | None = None             # clock() of the last successful publication
        self.published: list[tuple[float, str]] = []   # (clock(), state) of each one, the last KEEP
        self.errors: list[str] = []
        self._moving = False
        self._lock = threading.Lock()

    def open(self) -> int:
        """201 once the record is ready and the route published. The record and its ACP are looked at first (a GET; a
        CREATE of a taken name would be a 409, which ACME logs as a WARNING): both absent -> made; both this keeper's
        own (its ACP's self-privileges are this originator's alone, and the record carries that ACP) -> taken over,
        readers set to ours, the current route published over whatever was there; anything else -> 409, nothing
        written."""
        acp_url, cnt_url = f"{self.in_base}/{route_rn(self.aei)}-acp", f"{self.in_base}/{route_rn(self.aei)}"
        st_a, acp = self._admin("GET", acp_url, origin=self.origin)
        st_c, cnt = self._admin("GET", cnt_url, origin=self.origin)
        if st_a == 404 and st_c == 404:
            st = open_route(self.in_base, self.aei, self.readers, self.origin, admin=self._admin)
            if st != 201:
                return st
        elif st_a == 200 and st_c == 200 and self._ours(acp, cnt):
            want = route_acp(self.aei, self.readers, self.origin)["m2m:acp"]["pv"]
            if acp["m2m:acp"].get("pv") != want:
                if self._admin("PUT", acp_url, body={"m2m:acp": {"pv": want}}, origin=self.origin)[0] != 200:
                    return 409
        else:
            return 409
        return self.publish()

    def _ours(self, acp, cnt) -> bool:
        a = (acp or {}).get("m2m:acp") if isinstance(acp, dict) else None
        c = (cnt or {}).get("m2m:cnt") if isinstance(cnt, dict) else None
        return isinstance(a, dict) and isinstance(c, dict) and \
            a.get("pvs") == {"acr": [{"acor": [self.origin], "acop": ALL}]} and c.get("acpi") == [a.get("ri")]

    def publish(self, moving: bool = False, beat: bool = False) -> int:
        """Publish the route (or MOVING). Checked under the lock, skipped (0): a non-moving publication while a move is
        on (a tick() that passed its own check just before moving() began cannot overwrite MOVING), and a heartbeat
        (beat) once the move is over (a late beat cannot overwrite the edge published after it)."""
        with self._lock:
            if (not moving and self._moving) or (beat and not self._moving):
                return 0
            serving = [] if moving else list(self.serving())
            kw = {"timeout": self.beat_timeout_s} if beat else {}   # a heartbeat may not wait the client's 5 s
            st = self._publish(self.in_base, self.aei, serving, moving=moving, origin=self.origin, **kw)
            if st == 201:
                self.last = self.clock()
                self.published.append((self.last, "MOVING" if moving else ("ATTACHED" if len(serving) == 1
                                                                            else "UNKNOWN")))
                _trim(self.published, KEEP)
            return st

    def tick(self) -> bool:
        """Publish if due; True when it did."""
        if self._moving or (self.last is not None and self.clock() - self.last < self.period_s):
            return False
        return self.publish() == 201

    def run(self, stop: threading.Event, poll_s: float = 1.0) -> None:
        while not stop.is_set():
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001 -- the keeper keeps going; the record ages out meanwhile
                self.errors.append(f"{type(e).__name__}: {str(e)[:120]}")
                _trim(self.errors, KEEP)
            stop.wait(min(poll_s, self.period_s))

    @contextlib.contextmanager
    def moving(self):
        """MOVING, settle_s, then the caller's handover with a heartbeat re-publishing MOVING every beat_s; then the
        heartbeat is stopped (and waited for) BEFORE the edge the IN names now (the new one, or the old one after a
        rollback) is published. A failed heartbeat publication is kept in `errors` and never aborts the move."""
        self._moving = True
        stop, beater = threading.Event(), None
        try:
            self.publish(moving=True)
            self._sleep(self.settle_s)
            beater = threading.Thread(target=self._heartbeat, args=(stop,), name="route-heartbeat", daemon=True)
            beater.start()
            yield
        finally:
            stop.set()
            if beater is not None:
                beater.join(timeout=self.beat_s + 10)
            self._moving = False
            try:
                self.publish()
            except Exception as e:  # noqa: BLE001 -- the record stays MOVING: readers hold, never guess
                self.errors.append(f"{type(e).__name__}: {str(e)[:120]}")

    def _heartbeat(self, stop: threading.Event) -> None:
        while not self._wait(stop, self.beat_s):
            try:
                if self.publish(moving=True, beat=True) not in (201, 0):
                    self.errors.append("heartbeat: MOVING not published")
            except Exception as e:  # noqa: BLE001 -- a missed beat; the next one comes, the move goes on
                self.errors.append(f"heartbeat: {type(e).__name__}: {str(e)[:120]}")
            _trim(self.errors, KEEP)

    def close(self) -> None:
        close_route(self.in_base, self.aei, self.origin)


# ---- as a process ---------------------------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--config", required=True, help="JSON with the WarningAE keys, plus optional period_s")
    a = ap.parse_args(argv)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    cfg = json.loads(Path(a.config).read_text())
    ae = WarningAE(cfg)
    try:
        ae.register()
        print(f"watching {ae.zone} for {ae.aei}", flush=True)
        ae.run(stop, float(cfg.get("period_s", 0.05)))
    except (RuntimeError, OSError) as e:
        print(f"FAILED {e}", flush=True)
        return 3
    finally:
        ae.deregister()
    return 0


if __name__ == "__main__":
    sys.exit(main())
