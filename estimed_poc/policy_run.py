#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""The policy-driven handover driver, host part, with a SIMULATED device. It serves
TD_MEC_HO_04 (steps 1-4) and TD_MEC_OBS_02 (steps 1-6) on the lab's three CSEs and writes a results JSON. Every
decision is policy_core's; this file does the oneM2M requests and hands policy_core what the CSEs answered.

Policy-driven, own modelling of the rule; no CMDH management object in the lab's CSE (ACME 2026.5.3 answers 500 to a
CREATE of <mgmtObj> mgd 1011 cmdhPolicy: it has the name in its enumeration table and no resource class).

  the rule        IN-CSE  cse-in/hoPolicy/rule       the latest <contentInstance> is the rule in force (earlier ones
                                                     stay as the history of changes): metric, threshold, dwell_s,
                                                     allowed_targets
  the events      IN-CSE  cse-in/hoPolicy/events     one <contentInstance> per diagnostic event; a policy conflict is
                                                     the record  "event": "policy-conflict"  there
  the constraint  each edge  <cse>/mecPolicy/constraint   the MEC side's word on that edge (admit, latency_limit_ms,
                                                     latency_ms), under an AE of the edge's own originator. It is
                                                     published on the edge's own MN-CSE because it is that edge's
                                                     statement: only that edge's originator writes it, the engine
                                                     reads it where the device would be served, and an edge that does
                                                     not answer cannot be taken for one that permits. It is OUR
                                                     stand-in: no MEC API (MEC 010, 011) carries or checks it.
  the violations  each edge  <cse>/mecPolicy/violations   what the MEC-side check holds against a device served there
  the device      sim_phone.SimPhone as the library's vehicle (AE vehicle01): its records, its ping command and its
                  acknowledgement in <ack>. Registered announced with a point of access, and commanded by
                  notification instead of the app's <pollingChannel>, because the library handover refuses to carry a
                  <pollingChannel> and needs the announcement for the route check.
  the quantity    round trip of the ping command: creation time of the command in <cmd> at the serving CSE to creation
                  time of the device's acknowledgement in <ack> there, both stamped by that CSE. The delay is INJECTED
                  ON THE HOST: a sleep before each post of the simulated device toward one edge. Not a radio effect.
  the engine      a thread of its own: every tick it reads the route, the rule and the constraints, pings the device
                  and asks policy_core.Engine. It calls the library handover() by itself; the timeline below never
                  does. The timeline only changes the injected delay, the rule, the constraints and the injected
                  registration failure, and reads the CSEs.

    python -B estimed_poc/policy_run.py        (the lab must be up: IN :8200, MN-A :8201, MN-B :8202)
"""
from __future__ import annotations

import hashlib
import json
import queue
import statistics
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "estimed"))
sys.path.insert(0, str(HERE.parent / "phone"))
import handover as ho  # noqa: E402
import policy_core as pc  # noqa: E402
import sim_phone  # noqa: E402
from estimed_poc2 import STEPS, Abort, require, run_record, step  # noqa: E402

ADMIN = "CAdmin"
IN_URL = f"{ho.IN_CSE[0]}/{ho.IN_CSE[1]}"
A_URL, B_URL = (f"{e[0]}/{e[1]}" for e in (ho.EDGE_A, ho.EDGE_B))
POLICY_AE, POLICY_ORIGIN = "hoPolicy", "ChoPolicy"
MEC_AE, MEC_ORIGIN = "mecPolicy", {A_URL: "CmecPolicyA", B_URL: "CmecPolicyB"}
BLOCKER = "a4blocker"          # the injected registration failure: an AE on the target under the device's AE-ID
LISTEN = 8471                  # the device's point of access; the lab's notification range is loopback 8400-8499
RESULTS_DIR = Path("/home/edgefollow/estimed-run/sim")

THRESHOLD_MS, DWELL_S = 250, 3.0           # the rule's numbers (ours)
DELAY_HIGH_S = 0.45                        # the injected delay per device post toward the source edge
TICK_S, PING_TIMEOUT_S = 0.5, 3.0
OPEN = {"admit": True, "latency_limit_ms": 200, "latency_ms": 20, "sim": True}
SHUT = {**OPEN, "admit": False}
BROKEN = {"admit": False, "latency_limit_ms": 1, "latency_ms": 20, "sim": True}


def utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def put(url: str, origin: str, obj: dict) -> int:
    return ho._req("POST", url, origin, ty=ho.TY_CIN,
                   body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(obj)}})[0]


def latest(url: str, origin: str):
    """The latest contentInstance of a container as JSON, or None (no instance, no container, not JSON)."""
    st, b = ho._req("GET", f"{url}/la", origin)
    try:
        return json.loads(b["m2m:cin"]["con"]) if st == 200 else None
    except (KeyError, TypeError, ValueError):
        return None


def everything(url: str, origin: str) -> list[dict]:
    st, b = ho._req("GET", f"{url}?rcn=4", origin)
    cins = sorted(((b or {}).get("m2m:cnt") or {}).get("m2m:cin", []), key=lambda c: c["ct"]) if st == 200 else []
    return [json.loads(c["con"]) for c in cins]


def status(url: str) -> int:
    return ho._req("GET", url, ADMIN)[0]


def describe(cse_url: str, name: str) -> dict | None:
    """Type and number of resources below a top-level name ("cse-in/x") of that CSE; None if it cannot be read."""
    url = f"{cse_url.rsplit('/', 1)[0]}/{name}"
    st, b = ho._req("GET", url, ADMIN)
    st2, kids = ho._req("GET", f"{url}?fu=1&rcn=6", ADMIN)
    body = next(iter((b or {}).values()), None) if st == 200 else None
    rrf = ((kids or {}).get("m2m:rrl") or {}).get("rrf") if st2 == 200 else None
    if not isinstance(body, dict) or not isinstance(rrf, list):
        return None
    return {"ty": body.get("ty"), "children": len(rrf)}


def top(url: str) -> list[str]:
    return sorted((ho._req("GET", f"{url}?fu=1&lvl=1", ADMIN)[1] or {}).get("m2m:uril", []))


class _Tee:
    """stdout that also keeps what one thread prints: the library handover reports why it stopped only by print()."""

    def __init__(self, real):
        self.real, self.keep = real, {}

    def write(self, s):
        buf = self.keep.get(threading.get_ident())
        if buf is not None:
            buf.append(s)
        return self.real.write(s)

    def flush(self):
        self.real.flush()


class _Poa(BaseHTTPRequestHandler):
    """The device's point of access: answers 2000 to every notification and hands it to the device."""

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("X-M2M-RSC", "2000")
        self.send_header("X-M2M-RI", self.headers.get("X-M2M-RI", ""))
        self.send_header("Content-Length", "0")
        self.end_headers()
        try:
            self.server.notes.put(json.loads(raw))
        except ValueError:
            pass

    def log_message(self, *a):
        pass


class PolicyPhone(sim_phone.SimPhone):
    """sim_phone.SimPhone as the library's vehicle01 (see the module text). What differs from the app's model:
    announced registration with rr = true and a point of access (ho.create_ae), commands by notification, hold() and
    resume() as the library's Device protocol asks, and `delay`: seconds slept before each post to a given CSE.
    The command handling (ping, period) is SimPhone._poll_loop's, repeated here because it sits inside that loop."""

    def __init__(self, edge, port: int):
        super().__init__(f"{edge[0]}/{edge[1]}", ho.AE_ORIGIN, ho.AE_NAME, period=2.0)
        self.delay: dict[str, float] = {}
        self.held, self.kept, self._w = False, [], threading.RLock()
        self.log: list[list] = []         # every record the device produced: [monotonic time, container, accepted or None]
        self.last_error = None
        self.srv = ThreadingHTTPServer(("127.0.0.1", port), _Poa)
        self.srv.daemon_threads, self.srv.notes = True, queue.Queue()
        self.poa = f"http://127.0.0.1:{port}/notify"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        threading.Thread(target=self._cmd_loop, daemon=True).start()

    def _ensure_ae(self) -> bool:
        cse, rn = self.cse, self.rn
        edge = (cse.rsplit("/", 1)[0], cse.rsplit("/", 1)[1])
        st, _ = ho.create_ae(edge, poa=[self.poa])
        if st != 201:
            s, b = self._http("GET", f"{cse}/{rn}")
            if s != 200 or ((b or {}).get("m2m:ae") or {}).get("aei") != self.origin:
                self.last_error = f"AE create answered {st}; GET answered {s}"
                return False
        ok = True
        for c in (*sim_phone.CNTS, "cmd", "ack"):
            r, _ = self._http("POST", f"{cse}/{rn}", 3, {"m2m:cnt": {"rn": c, "mni": 2000}})
            ok &= r in (201, 409)
        r, _ = self._http("POST", f"{cse}/{rn}/cmd", 23, {"m2m:sub": {"rn": "cmdSub", "nu": [self.origin],
                                                                     "enc": {"net": [3]}, "nct": 1}})
        return ok and r in (201, 409)

    def _post(self, cnt, con) -> None:
        entry = [time.monotonic(), cnt, None]          # produced now; accepted is filled in when a CSE has answered
        self.log.append(entry)
        d = self.delay.get(self.cse, 0.0)
        if d:
            time.sleep(d)                 # the injected delay: on the host, before each post of the device (records and
        with self._w:                     # acknowledgements alike) toward that edge; slept outside the write lock
            if self.held:
                self.kept.append((cnt, con, entry))
            else:
                self._send(cnt, con, entry)

    def _send(self, cnt, con, entry) -> None:      # only ever called with self._w held, so post_ok moves for this post alone
        n = self.post_ok
        super()._post(cnt, con)
        entry[2] = self.post_ok > n

    def hold(self) -> None:
        with self._w:                     # taken once no write is in flight
            self.held = True

    def resume(self, edge) -> None:
        with self._w:
            self.cse, self.held = f"{edge[0]}/{edge[1]}", False
            kept, self.kept = self.kept, []
            for cnt, con, entry in kept:
                self._send(cnt, con, entry)

    def _cmd_loop(self) -> None:
        while True:
            note = self.srv.notes.get()
            if note is None:
                return
            sgn = sim_phone._find(note, "m2m:sgn")
            cin = sim_phone._find(sgn, "m2m:cin") if isinstance(sgn, dict) and not sgn.get("vrq") else None
            try:
                cmd = json.loads(cin.get("con", "{}")) if isinstance(cin, dict) else None
            except ValueError:
                cmd = None
            if not isinstance(cmd, dict):
                continue
            ack = {"id": cmd.get("id"), "cmd": cmd.get("cmd"), "phone_t": int(time.time() * 1000), "sim": True}
            if cmd.get("cmd") == "ping":
                ack.update(ok=True, battery_pct=80)
            elif cmd.get("cmd") == "period" and isinstance(cmd.get("value"), int) and 1 <= cmd["value"] <= 60:
                self.period = cmd["value"]
                ack.update(ok=True, period=cmd["value"])
            else:
                ack.update(ok=False, error="unknown command or value out of range")
            self.cmds += 1
            self._post("ack", ack)

    def close(self) -> None:
        self.stop()
        self.srv.notes.put(None)
        self.srv.shutdown()
        self.srv.server_close()


class LiveEngine(threading.Thread):
    """The policy engine against the live CSEs. Nothing outside this class calls ho.handover()."""

    def __init__(self, dev: PolicyPhone, edges: dict, tee: _Tee):
        super().__init__(daemon=True, name="policy-engine")
        self.core, self.dev, self.edges, self.tee = pc.Engine(), dev, edges, tee
        self.samples: list[dict] = []          # every tick: t, serving, rtt_ms, action, why
        self.windows: list[list] = []          # every call of the library handover: [start, end, outcome], monotonic
        self.handover_calls, self.errors, self._n, self._bad_rule = 0, [], 0, None
        self._halt = threading.Event()

    def run(self) -> None:
        while not self._halt.is_set():
            t0 = time.monotonic()
            try:
                self.tick()
            except (ho.Unreadable, OSError, ValueError, KeyError) as e:
                self.errors.append(f"{type(e).__name__}: {e}")
            self._halt.wait(max(0.0, TICK_S - (time.monotonic() - t0)))

    def halt(self) -> None:
        self._halt.set()
        if self.is_alive():
            self.join(timeout=90)

    def event(self, ev: dict) -> None:
        if put(f"{IN_URL}/{POLICY_AE}/events", POLICY_ORIGIN, ev) != 201:
            self.errors.append(f"event not written: {ev['event']}")

    def ping(self, url: str) -> float | None:
        """One ping through the serving CSE; the round trip from that CSE's two creation times, or None."""
        self._n += 1
        pid = f"a4-{self._n}"
        st, b = ho._req("POST", f"{url}/{ho.AE_NAME}/cmd", ADMIN, ty=ho.TY_CIN, body={"m2m:cin": {
            "cnf": "application/json:0", "con": json.dumps({"cmd": "ping", "id": pid})}})
        if st != 201:
            return None
        end = time.monotonic() + PING_TIMEOUT_S
        while time.monotonic() < end and not self._halt.is_set():
            s, a = ho._req("GET", f"{url}/{ho.AE_NAME}/ack/la", ADMIN)
            cin = (a or {}).get("m2m:cin") or {}
            if s == 200 and '"id": "%s"' % pid in cin.get("con", ""):
                return pc.rtt_ms(b["m2m:cin"]["ct"], cin["ct"])
            time.sleep(0.02)
        return None

    def tick(self) -> None:
        route = ho.serving_edges()
        if len(route) != 1 or route[0] not in self.edges:
            self.samples.append({"t": time.monotonic(), "serving": route, "rtt_ms": None, "action": "none", "why": "no single route"})
            return
        serving = route[0]
        rule = latest(f"{IN_URL}/{POLICY_AE}/rule", POLICY_ORIGIN)
        rtt = self.ping(self.edges[serving])
        cons = {csi: latest(f"{url}/{MEC_AE}/constraint", ADMIN) for csi, url in self.edges.items()}
        d = self.core.step(time.monotonic(), rtt, rule, serving, cons)
        self.samples.append({"t": time.monotonic(), "serving": serving, "rtt_ms": None if rtt is None else round(rtt, 1),
                             "action": d["action"], "target": d["target"], "why": d["why"]})
        if d.get("failure") == "rule-invalid" and self._bad_rule != json.dumps(rule, sort_keys=True):
            self._bad_rule = json.dumps(rule, sort_keys=True)
            self.event(pc.event("rule-invalid", utc(), reason=d["why"]))
        if d["action"] == "conflict":
            self.event(pc.conflict_event(pc.parse_rule(rule), serving, d["reasons"], utc()))
        elif d["action"] == "handover":
            self.run_handover(serving, d, rtt, cons)

    def run_handover(self, serving: str, d: dict, rtt: float, cons: dict) -> None:
        src, dst = (tuple(self.edges[c].rsplit("/", 1)) for c in (serving, d["target"]))
        st, b = ho._req("GET", f"{IN_URL}/{ho.lock_name()}", ADMIN)
        if st == 200 and pc.lock_state(((b or {}).get("m2m:cnt") or {}).get("lbl"), time.time()) == "expired":
            self.event(pc.event("transaction-expired", utc(), labels=b["m2m:cnt"].get("lbl")))
        self.event(pc.event("handover-started", utc(), by="policy engine", source=serving, target=d["target"],
                            why=d["why"], rtt_ms=round(rtt, 1), target_constraint=cons[d["target"]],
                            forbidden=d["reasons"]))
        self.handover_calls += 1
        buf = self.tee.keep[threading.get_ident()] = []
        t0 = time.monotonic()
        try:
            ok = ho.handover(src, dst, [], device=self.dev, ready=ho.target_ready)
        finally:
            del self.tee.keep[threading.get_ident()]
        self.windows.append([t0, time.monotonic(), "completed" if ok else "rolled-back"])
        log = [ln.strip() for ln in "".join(buf).splitlines() if ln.strip()]
        took = round(time.monotonic() - t0, 2)
        if ok:
            self.event(pc.event("handover-completed", utc(), source=serving, target=d["target"], seconds=took, log=log))
        else:
            self.event(pc.event(pc.classify_failure("\n".join(log)), utc(), source=serving, target=d["target"],
                                seconds=took, rolled_back=True, log=log))


def wait(pred, timeout: float, poll: float = 0.1) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(poll)
    return bool(pred())


def above_span(samples: list[dict]) -> tuple[int, float]:
    """(samples above the threshold, longest unbroken stretch of them in seconds)."""
    best, first, n = 0.0, None, 0
    for s in samples:
        if s["rtt_ms"] is not None and s["rtt_ms"] > THRESHOLD_MS:
            n += 1
            first = s["t"] if first is None else first
            best = max(best, s["t"] - first)
        else:
            first = None
    return n, round(best, 2)


def rtts(samples: list[dict]) -> list[float]:
    return [s["rtt_ms"] for s in samples if s["rtt_ms"] is not None]


def spread(values: list[float]) -> dict:
    return {"N": len(values), "unit": "ms", "sim": True, "min": min(values) if values else None,
            "median": statistics.median(values) if values else None, "max": max(values) if values else None}


def events(kind: str | None = None) -> list[dict]:
    """The diagnostic events as the IN-CSE holds them now (read as the admin, the way an operator would)."""
    return [e for e in everything(f"{IN_URL}/{POLICY_AE}/events", ADMIN) if kind is None or e.get("event") == kind]


def ae_state(url: str) -> dict:
    st, b = ho._req("GET", f"{url}/{ho.AE_NAME}", ADMIN)
    a = (b or {}).get("m2m:ae") or {}
    return {"status": st, "rr": a.get("rr"), "lt": a.get("lt")}


def cni(url: str, cnt: str) -> int:
    st, b = ho._req("GET", f"{url}/{ho.AE_NAME}/{cnt}", ADMIN)
    return ((b or {}).get("m2m:cnt") or {}).get("cni", 0) if st == 200 else -1


def mec_check(url: str, observed: float | None) -> list[str]:
    """The MEC-side check of one edge (our stand-in): hold the edge's own constraint against the device it serves and
    write each violation into the edge's <violations>. Returns what it raised."""
    found = pc.violations(latest(f"{url}/{MEC_AE}/constraint", MEC_ORIGIN[url]), observed)
    for v in found:
        put(f"{url}/{MEC_AE}/violations", MEC_ORIGIN[url], {"violation": v, "device": ho.AE_ORIGIN, "at": utc(), "sim": True})
    return found


def remove_ours() -> None:
    ho._req("DELETE", f"{IN_URL}/{POLICY_AE}", POLICY_ORIGIN)
    for url, origin in MEC_ORIGIN.items():
        ho._req("DELETE", f"{url}/{MEC_AE}", origin)
    ho._req("DELETE", f"{B_URL}/{BLOCKER}", ho.AE_ORIGIN)
    ho.reset()                                    # the library's vehicle01 on both edges and an open transaction


def main() -> int:  # noqa: C901, PLR0912, PLR0915  one timeline, like the neighbouring drivers
    STEPS.clear()
    results = RESULTS_DIR / f"policy_sim_{time.strftime('%Y%m%dT%H%M%S')}.json"
    X: dict = {"kpi": {"sim": True}, "cleanup": {}}
    aborted, dev, eng = None, None, None
    tee = sys.stdout = _Tee(sys.stdout)
    try:
        print("== the lab")
        up = {n: status(u) for n, u in (("IN", IN_URL), ("MN-A", A_URL), ("MN-B", B_URL))}
        require("the IN-CSE and both MN-CSEs answer, and the IN holds both edges",
                set(up.values()) == {200} and ho.edges_ok(ho.registered_edges()), str(up))
        X["before"] = {n: top(u) for n, u in (("IN", IN_URL), ("MN-A", A_URL), ("MN-B", B_URL))}
        X["vehicle01_found_before"] = {n: status(f"{u}/{ho.AE_NAME}") == 200 for n, u in (("MN-A", A_URL), ("MN-B", B_URL))}
        remove_ours()
        csi = {u: ho._csi(tuple(u.rsplit("/", 1))) for u in (A_URL, B_URL)}
        edges = {csi[A_URL]: A_URL, csi[B_URL]: B_URL}
        a_csi, b_csi = csi[A_URL], csi[B_URL]
        rule = {"metric": pc.METRIC, "threshold": THRESHOLD_MS, "dwell_s": DWELL_S, "allowed_targets": [b_csi], "sim": True}

        print("== the rule's home on the IN-CSE, each edge's MEC-side constraint, the simulated device")
        made = [ho._req("POST", IN_URL, POLICY_ORIGIN, ty=ho.TY_AE, body={"m2m:ae": {
            "rn": POLICY_AE, "api": "Nestimed.policy", "rr": False, "srv": ["4"]}})[0]]
        made += [ho._req("POST", f"{IN_URL}/{POLICY_AE}", POLICY_ORIGIN, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": c, "mni": 200}})[0]
                 for c in ("rule", "events")]
        for url, origin in MEC_ORIGIN.items():
            made.append(ho._req("POST", url, origin, ty=ho.TY_AE, body={"m2m:ae": {
                "rn": MEC_AE, "api": "Nestimed.mecpolicy", "rr": False, "srv": ["4"]}})[0])
            made += [ho._req("POST", f"{url}/{MEC_AE}", origin, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": c, "mni": 200}})[0]
                     for c in ("constraint", "violations")]
            made.append(put(f"{url}/{MEC_AE}/constraint", origin, OPEN))
        require("policy AE with <rule> and <events> on the IN-CSE; on each edge an AE of the edge's own originator with "
                "<constraint> and <violations>, constraint: admit, limit 200 ms, stated 20 ms", set(made) == {201}, str(made))
        dev = PolicyPhone(ho.EDGE_A, LISTEN)
        dev.live()
        require("the simulated device (AE vehicle01) posts on edge A and the IN-CSE routes it to edge A alone",
                wait(lambda: cni(A_URL, "radio") >= 2, 30) and ho.serving_edges() == [a_csi],
                f"radio instances {cni(A_URL, 'radio')}; route {ho.serving_edges()}; {dev.last_error or ''}")
        eng = LiveEngine(dev, edges, tee)
        eng.start()
        mark = lambda: len(eng.samples)  # noqa: E731
        since = lambda m: eng.samples[m:]  # noqa: E731
        calm = lambda m, n=2: wait(lambda: len([s for s in since(m) if s["rtt_ms"] is not None  # noqa: E731
                                                and s["rtt_ms"] <= THRESHOLD_MS]) >= n, 20)

        print("== the quantity: the device answers the ping command through the serving CSE")
        m = mark()
        wait(lambda: len(since(m)) >= 5, 20)
        base = rtts(since(m))
        X["kpi"]["ping_round_trip_no_delay_ms"] = spread(base)
        require("5 pings answered by the device; round trip (command created -> acknowledgement created, both stamped by "
                f"the serving CSE) below the rule's {THRESHOLD_MS} ms", len(base) >= 5 and max(base) < THRESHOLD_MS,
                f"{base}")

        print("== no rule yet, the stimulus applied: nothing may happen")
        m = mark()
        dev.delay[A_URL] = DELAY_HIGH_S
        wait(lambda: above_span(since(m))[1] >= DWELL_S + 1.5, DWELL_S + 15)
        n_up, span = above_span(since(m))
        dev.delay[A_URL] = 0.0
        step(f"the stimulus is there: with {DELAY_HIGH_S} s injected per device post the round trip stayed above "
             f"{THRESHOLD_MS} ms for longer than the dwell time", span >= DWELL_S, f"{n_up} samples above, {span} s unbroken")
        step("CONTROL (must FAIL) the rule absent and the same stimulus started a handover",
             eng.handover_calls > 0 or bool(events()) or status(f"{B_URL}/{ho.AE_NAME}") == 200,
             f"handover calls {eng.handover_calls}, events {len(events())}, vehicle01 on B HTTP {status(f'{B_URL}/{ho.AE_NAME}')}")
        X["stimulus_without_rule"] = {"samples_above": n_up, "unbroken_s": span}
        calm(mark())

        print("== TD_MEC_HO_04 pre-test: the rule is configured")
        st_r = put(f"{IN_URL}/{POLICY_AE}/rule", POLICY_ORIGIN, rule)
        back = latest(f"{IN_URL}/{POLICY_AE}/rule", ADMIN)
        require(f"the rule is a resource on the IN-CSE ({ho.IN_CSE[1]}/{POLICY_AE}/rule, latest instance) and reads back; "
                f"{pc.RECORD_NOTE}", st_r == 201 and back == rule, json.dumps(back))
        m = mark()
        calm(m, 3)
        step("rule in force, round trip below the threshold: no handover, no event",
             eng.handover_calls == 0 and not events() and "handover" not in [s["action"] for s in since(m)], f"{rtts(since(m))}")

        print("== a stimulus shorter than the dwell time")
        m = mark()
        dev.delay[A_URL] = DELAY_HIGH_S
        wait(lambda: above_span(since(m))[0] >= 2, 15, poll=0.02)
        dev.delay[A_URL] = 0.0
        calm(mark(), 3)
        n_up, span = above_span(since(m))
        step(f"the short stimulus is there: round trip above the threshold, for less than the dwell time of {DWELL_S} s",
             n_up >= 1 and span < DWELL_S, f"{n_up} samples above, {span} s unbroken")
        step("CONTROL (must FAIL) a stimulus shorter than the dwell time triggered",
             eng.handover_calls > 0 or bool(events()), f"handover calls {eng.handover_calls}, events {len(events())}")

        print("== TD_MEC_OBS_02 steps 4-6: policy conflict (the rule's only allowed target is forbidden by its MEC side)")
        st_c = put(f"{B_URL}/{MEC_AE}/constraint", MEC_ORIGIN[B_URL], SHUT)
        m, ok0, fail0, cni0 = mark(), dev.post_ok, dev.post_fail, cni(A_URL, "radio")
        dev.delay[A_URL] = DELAY_HIGH_S                                            # step 4: the conflict is injected
        got = wait(lambda: bool(events("policy-conflict")), DWELL_S + 15)
        t_first = time.monotonic()
        wait(lambda: False, DWELL_S + 2.0)                                          # the conflict goes on: still one event
        conf = events("policy-conflict")
        phase = since(m)
        dev.delay[A_URL] = 0.0
        n_up, span = above_span(phase)
        require("step 4: edge B's constraint set to admit false while the rule allows only edge B; stimulus applied",
                st_c == 201 and got and span >= DWELL_S, f"constraint HTTP {st_c}; {n_up} samples above, {span} s unbroken")
        step(f"step 5: the conflict is a diagnostic event an operator can read on the IN-CSE: {ho.IN_CSE[1]}/{POLICY_AE}/events "
             "holds a record 'policy-conflict' with handover_started false, the rule, the serving edge and the reason per target",
             len(conf) >= 1 and conf[0].get("handover_started") is False and conf[0].get("serving") == a_csi
             and conf[0].get("reasons") == {b_csi: "admit is not true"} and conf[0].get("rule", {}).get("allowed_targets") == [b_csi]
             and conf[0].get("sim") is True, json.dumps(conf[:1]))
        step(f"one event for the episode: the conflict lasted {time.monotonic() - t_first:.1f} s more and was not reported again "
             "(plan row A4: no handover, one event)", len(conf) == 1 and len(events()) == 1, f"{len(conf)} conflict events, {len(events())} events in all")
        on_b, lock = status(f"{B_URL}/{ho.AE_NAME}"), status(f"{IN_URL}/{ho.lock_name()}")
        step("step 5: the handover does not proceed: no handover call, no transaction at the IN-CSE, nothing of the device on edge B, "
             "the IN-CSE still routes it to edge A", eng.handover_calls == 0 and on_b == 404 and lock == 404 and ho.serving_edges() == [a_csi],
             f"handover calls {eng.handover_calls}; B HTTP {on_b}; transaction HTTP {lock}; route {ho.serving_edges()}")
        posted, failed, grew = dev.post_ok - ok0, dev.post_fail - fail0, cni(A_URL, "radio") - cni0
        unanswered = sum(1 for s in phase if s["rtt_ms"] is None)
        step("step 6: the device kept working at the source throughout: its posts to edge A went on, none failed, and it answered "
             "every ping there", posted >= 5 and failed == 0 and grew >= 1 and unanswered == 0 and len(phase) >= 5,
             f"{posted} posts accepted, {failed} failed, radio instances on A +{grew}; {len(phase)} pings, {unanswered} unanswered")
        step("CONTROL (must FAIL) a conflict started a handover anyway", eng.handover_calls > 0 or on_b == 200,
             f"handover calls {eng.handover_calls}; vehicle01 on B HTTP {on_b}")
        step("CONTROL (must FAIL) a conflict left no diagnostic record on the IN-CSE", len(conf) == 0, f"{len(conf)} record(s)")
        step("CONTROL (must FAIL) the target forbidden by its MEC-side constraint (edge B) was chosen",
             any(s.get("target") == b_csi for s in phase), f"targets chosen: {sorted({str(s.get('target')) for s in phase})}")
        X["kpi"]["device_posts_during_conflict"] = {"numerator": posted, "denominator": posted + failed, "N": posted + failed,
                                                    "unit": "posts accepted by edge A", "sim": True}
        X["kpi"]["ping_round_trip_with_delay_ms"] = spread([v for v in rtts(phase) if v > THRESHOLD_MS])
        calm(mark())

        print("== TD_MEC_OBS_02 steps 1-3: target registration fails during the handover, rollback")
        put(f"{B_URL}/{MEC_AE}/constraint", MEC_ORIGIN[B_URL], OPEN)
        st_b = ho._req("POST", B_URL, ho.AE_ORIGIN, ty=ho.TY_AE, body={"m2m:ae": {
            "rn": BLOCKER, "api": "Nestimed.blocker", "rr": False, "srv": ["4"]}})[0]
        before, fail0, n_ev = ae_state(A_URL), dev.post_fail, len(events())
        m = mark()
        dev.delay[A_URL] = DELAY_HIGH_S
        got = wait(lambda: len(events()) >= n_ev + 2, DWELL_S + 40)            # handover-started, then the failure
        m_after = mark()
        wait(lambda: any(s["rtt_ms"] is not None for s in since(m_after)), 10)
        dev.delay[A_URL] = 0.0
        new = events()[n_ev:]
        ref = next((e for e in new if e["event"] == "target-registration-refused"), {})
        log = " | ".join(ref.get("log", []))
        require("step 1: registration failure injected (an AE on edge B already holds the device's AE-ID, so edge B refuses the "
                "device's registration); the engine started a handover by itself and the target refused the registration after "
                "the transaction was opened", st_b == 201 and got and new[0]["event"] == "handover-started"
                and "AE create on destination refused: 403" in log and "handover transaction" in log,
                f"blocker HTTP {st_b}; events {[e['event'] for e in new]}; library: {log}")
        after = ae_state(A_URL)
        on_b, lock = status(f"{B_URL}/{ho.AE_NAME}"), status(f"{IN_URL}/{ho.lock_name()}")
        step("step 1: the failure fell in HANDOVER_PREP: the source AE was modified (rr set false, then restored) during the attempt",
             before["lt"] != after["lt"], f"AE last modified {before['lt']} -> {after['lt']}")
        step("step 2: FAILED/ROLLBACK, the AE is ATTACHED(source): the device's AE is on edge A, nothing of it on edge B, the IN-CSE "
             "routes it to edge A alone, no transaction is left open, and the event names the failure",
             after["status"] == 200 and on_b == 404 and ho.serving_edges() == [a_csi] and lock == 404 and ref.get("rolled_back") is True,
             f"A HTTP {after['status']}; B HTTP {on_b}; route {ho.serving_edges()}; transaction HTTP {lock}")
        answered = [s["rtt_ms"] for s in since(m_after) if s["rtt_ms"] is not None]
        step("step 3: the source's reachability is what it was (rr true), and downlink delivery resumed at the source: a ping sent "
             "after the rollback was delivered to the device and acknowledged", before["rr"] is True and after["rr"] is True
             and bool(answered) and dev.post_fail == fail0, f"rr {before['rr']} -> {after['rr']}; ping after rollback {answered[:1]} ms; "
             f"device posts failed {dev.post_fail - fail0}")
        st_d = ho._req("DELETE", f"{B_URL}/{BLOCKER}", ho.AE_ORIGIN)[0]
        require("the injected failure is removed", st_d == 200 and status(f"{B_URL}/{BLOCKER}") == 404, f"HTTP {st_d}")
        calm(mark(), 3)

        print("== TD_MEC_HO_04 steps 1-4: the policy condition is met, the allowed target is permitted")
        n_ev, calls0 = len(events()), eng.handover_calls
        m = mark()
        dev.delay[A_URL] = DELAY_HIGH_S                                            # step 1
        done = wait(lambda: any(e["event"] == "handover-completed" for e in events()[n_ev:]), DWELL_S + 90)
        dev.delay[A_URL] = 0.0
        new = events()[n_ev:]
        started = next((e for e in new if e["event"] == "handover-started"), {})
        completed = next((e for e in new if e["event"] == "handover-completed"), {})
        n_up, span = above_span(since(m))
        require("step 1: the policy condition was met: round trip above the threshold for the dwell time",
                done and span >= DWELL_S - TICK_S, f"{n_up} samples above, {span} s unbroken; events {[e['event'] for e in new]}")
        step("step 2: the handover was started by the policy engine by itself (one call of the library handover from the engine's "
             "thread; the timeline of this driver calls none), recorded as 'handover-started' on the IN-CSE",
             eng.handover_calls == calls0 + 1 and started.get("by") == "policy engine", f"why: {started.get('why')}")
        b_con = latest(f"{B_URL}/{MEC_AE}/constraint", ADMIN)
        step("step 3: the target is one the rule allows and its MEC-side constraint permits (admit true, stated latency within the limit)",
             started.get("target") == b_csi and b_csi in rule["allowed_targets"] and pc.permits(b_con)[0]
             and started.get("target_constraint") == b_con, f"target {started.get('target')}; constraint {json.dumps(b_con)}")
        m = mark()
        wait(lambda: len(rtts(since(m))) >= 4, 20)
        on_a, on_b, lock = status(f"{A_URL}/{ho.AE_NAME}"), status(f"{B_URL}/{ho.AE_NAME}"), status(f"{IN_URL}/{ho.lock_name()}")
        at_b = rtts([s for s in since(m) if s["serving"] == b_csi])
        step("the handover completed: the device's AE is on edge B and gone from edge A, the IN-CSE routes it to edge B alone, the "
             "transaction is closed, the device posts to edge B with no failed post in the whole run",
             on_a == 404 and on_b == 200 and ho.serving_edges() == [b_csi] and lock == 404 and dev.cse == B_URL and dev.post_fail == 0
             and not dev.kept, f"A HTTP {on_a}; B HTTP {on_b}; route {ho.serving_edges()}; handover {completed.get('seconds')} s; "
             f"device posts failed {dev.post_fail}")
        step(f"after the handover the round trip on edge B is back below the rule's {THRESHOLD_MS} ms (no delay is injected toward B)",
             len(at_b) >= 4 and max(at_b) < THRESHOLD_MS, f"{at_b}")
        raised = mec_check(B_URL, at_b[-1] if at_b else None)
        n_viol = len(everything(f"{B_URL}/{MEC_AE}/violations", ADMIN))
        step("step 4: no violation is raised on the target after the handover: edge B's MEC-side check (admit still true, device "
             "round trip within B's limit) raised none and B's <violations> is empty", raised == [] and n_viol == 0,
             f"raised {raised}; records {n_viol}; device round trip on B {at_b[-1:] or None} ms, limit {(b_con or {}).get('latency_limit_ms')} ms")
        put(f"{B_URL}/{MEC_AE}/constraint", MEC_ORIGIN[B_URL], BROKEN)        # planted: the constraint is broken on the target
        raised = mec_check(B_URL, at_b[-1] if at_b else None)
        n_viol = len(everything(f"{B_URL}/{MEC_AE}/violations", ADMIN))
        step("CONTROL (must FAIL) the handover is complete, the constraint on the target is broken (admit false, limit 1 ms) and "
             "no violation was raised", raised == [] or n_viol == 0, f"raised {raised}; records on edge B {n_viol}")
        X["kpi"]["handover_duration_s"] = {"values": [completed.get("seconds")], "N": 1, "unit": "s", "sim": True}
        X["kpi"]["ping_round_trip_on_target_ms"] = spread(at_b)
        X["kpi"]["conflict_events"] = {"value": len(events("policy-conflict")), "N": 1, "unit": "events per conflict episode", "sim": True}
    except Abort as e:
        aborted = str(e)
    except Exception as e:  # noqa: BLE001  the record says where the run stopped; cleanup still runs
        aborted = f"{type(e).__name__}: {e}"
        traceback.print_exc()
    finally:
        try:                                    # whatever happens here, the CSEs are cleaned below
            if eng is not None:
                eng.halt()
                X["engine"] = {"samples": [[round(s["t"] - eng.samples[0]["t"], 2), s["serving"], s["rtt_ms"], s["action"]]
                                           for s in eng.samples], "errors": eng.errors, "handover_calls": eng.handover_calls}
            if dev is not None:
                dev.close()
                X["device"] = {"posts_accepted": dev.post_ok, "posts_failed": dev.post_fail, "commands_answered": dev.cmds}
            if eng is not None and dev is not None and eng.samples:
                zero = eng.samples[0]["t"]         # the rounded lists are what is stored AND what the rate is worked out from
                posts = [[round(t - zero, 3), cnt, ok] for t, cnt, ok in list(dev.log)]
                wins = [[round(a - zero, 3), round(b - zero, 3), how] for a, b, how in eng.windows]
                X["device_posts"] = {"format": "seconds since the engine's first tick when the device produced the record, "
                                               "container, accepted (null: still held by the device at the end)", "posts": posts}
                X["handover_windows"] = wins
                n = pc.loss_in_windows(posts, wins)
                if n["denominator"]:
                    X["kpi"]["telemetry_loss_during_handover"] = {
                        **n, "N": n["denominator"], "unit": "%", "sim": True,
                        "value": str((Decimal(100 * n["numerator"]) / Decimal(n["denominator"])).quantize(Decimal("0.1"), ROUND_HALF_UP)),
                        "scope": "records the simulated device produced while a call of the library handover was running "
                                 "(completed or rolled back) that no CSE accepted by the end of the run; a record held during "
                                 "the handover and posted after it counts as delivered"}
        except Exception as e:  # noqa: BLE001
            aborted = aborted or f"teardown: {type(e).__name__}: {e}"
        try:
            X["events"] = events()
            X["violations_on_B"] = everything(f"{B_URL}/{MEC_AE}/violations", ADMIN)
            remove_ours()
            names = (("IN", IN_URL), ("MN-A", A_URL), ("MN-B", B_URL))
            after = {n: top(u) for n, u in names}
            gone = {f"{n}/{r}": status(f"{u}/{r}") for n, u in names for r in (POLICY_AE, MEC_AE, BLOCKER, ho.AE_NAME, ho.lock_name())}
            new = {r: u for n, u in names for r in set(after[n]) - set(X.get("before", {}).get(n, after[n]))}
            left, of_the_cse = pc.leftovers(X.get("before", {}), after, {r: d for r, u in new.items() if (d := describe(u, r))})
            X["cleanup"] = {
                "status_of_every_name_this_run_used": gone, "after": after,
                "route_of_the_device_at_the_IN_CSE": ho.serving_edges(),
                "left_on_the_CSEs": left + sorted(k for k, v in gone.items() if v != 404) + [f"route: {r}" for r in ho.serving_edges()],
                "made_by_the_CSE_itself": {"names": of_the_cse, "what": "an announced CSEBase (<cbA>, ty 10005) holding nothing: "
                                           "ACME makes one on the IN-CSE per edge at the first announced registration after "
                                           "a start and keeps it; not a resource of this run"},
                "removed_that_was_there_before": sorted(f"{n}: {r}" for n in after for r in set(X.get("before", {}).get(n, [])) - set(after[n])),
                "note": "vehicle01 is the library's AE: ho.reset() removed it from both edges at the start and at the end, as the "
                        "tests do; `python estimed/handover.py` puts the demonstration vehicle back on edge B"}
        except Exception as e:  # noqa: BLE001
            X["cleanup"] = {"left_on_the_CSEs": [f"cleanup did not finish: {type(e).__name__}: {e}"]}
        sys.stdout = tee.real
    return 0 if finish(results, X, aborted) else 1


def finish(path: Path, X: dict, aborted: str | None) -> bool:
    """Verdict and results file, by the neighbours' rule: PASS needs the run to reach its end, every step to pass, every
    control (at least one) to fail as it must, and nothing of this run left on the CSEs."""
    ctl = [(s_, o) for s_, o, _ in STEPS if s_.startswith("CONTROL")]
    real = [(s_, o) for s_, o, _ in STEPS if not s_.startswith("CONTROL")]
    ok = sum(1 for _, o in real if o)
    clean = not X["cleanup"].get("left_on_the_CSEs")
    good = aborted is None and ok == len(real) and bool(ctl) and not any(o for _, o in ctl) and clean
    print(f"\n  RESULT: {'PASS' if good else 'FAIL'}  ({ok}/{len(real)} steps; controls {len(ctl)}, all failed as they must: "
          f"{bool(ctl) and not any(o for _, o in ctl)}; cleanup complete: {clean}; SIMULATED device, delay injected on the host)"
          + (f"; STOPPED after: {aborted}" if aborted else ""))
    run = run_record()
    run.pop("mec", None)        # the phone drivers' MEC addresses; this run uses none of them
    for f in ("estimed_poc/policy_core.py", "estimed_poc/policy_run.py", "estimed_poc/test_policy.py",
              "estimed_poc/PLAYBOOK_FAILURES.md"):
        run["files_sha256"][f] = hashlib.sha256((HERE.parent / f).read_bytes()).hexdigest()
    exe = Path(sys.executable).resolve()
    run["python"] = {"version": sys.version.split()[0], "executable": str(exe), "sha256": hashlib.sha256(exe.read_bytes()).hexdigest()}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "record": "estimed.policy-handover.sim-run.v1", "device": "none: the device is simulated (sim_phone.SimPhone)", "sim": True,
        "verdict": "PASS" if good else "FAIL", "aborted_at": aborted,
        "verdict_scope": "the rows that ran, with a simulated device and a delay injected on the host; TD_MEC_HO_04 and "
                         "TD_MEC_OBS_02 are not passed with a device by this record",
        "rule_modelling": pc.RECORD_NOTE,
        "cmdh_probe": "ACME 2026.5.3 at the IN-CSE: CREATE <mgmtObj> mgd 1011 (cmdhPolicy) answered 500, '1011 is not a valid "
                      "ResourceTypes' (2026-11-18); a <mgmtObj> mgd 1006 (battery) under the same <node> answered 201",
        "where": {"rule": f"{ho.IN_CSE[1]}/{POLICY_AE}/rule (latest contentInstance)", "events": f"{ho.IN_CSE[1]}/{POLICY_AE}/events",
                  "constraint": f"<edge CSE>/{MEC_AE}/constraint (latest contentInstance), written by the edge's own originator",
                  "violations": f"<edge CSE>/{MEC_AE}/violations"},
        "quantity": {"name": pc.METRIC, "sim": True,
                     "what": "creation time of the ping command in <cmd> to creation time of the device's acknowledgement in <ack>, "
                             "both stamped by the serving CSE",
                     "delay": f"injected on the host: {DELAY_HIGH_S} s slept by the simulated device before each of its posts (records "
                              "and acknowledgements) toward edge A; not a radio effect, not a network measurement"},
        "numbers_of_ours": {"threshold_ms": THRESHOLD_MS, "dwell_s": DWELL_S, "tick_s": TICK_S, "ping_timeout_s": PING_TIMEOUT_S,
                            "constraint_open": OPEN, "constraint_forbidding": SHUT, "constraint_broken_for_the_control": BROKEN},
        "preregistration": {"sha256": None, "go_phrase": None, "result": "NA",
                            "reason": "a host-only run with a simulated device; no preregistration was frozen for it"},
        "clock_offset": {"result": "NA", "reason": "the device, the engine and the three CSEs run on one host; the round trip is "
                                                   "the difference of two creation times stamped by one CSE"},
        "device_labels": {"vehicle01": {"originator": ho.AE_ORIGIN, "sim": True, "class": "simulated phone (sim_phone.SimPhone), "
                                        "registered as the library's vehicle"},
                          POLICY_AE: {"originator": POLICY_ORIGIN, "cse": ho.IN_CSE[1], "role": "rule and events; the engine", "sim": True},
                          MEC_AE: {"originator": sorted(MEC_ORIGIN.values()), "role": "each edge's MEC-side constraint (stand-in)", "sim": True}},
        "kpi": X.get("kpi", {}),
        "steps": [{"step": s_, "pass": o, "detail": d} for s_, o, d in STEPS],
        "controls": [{"control": s_, "expected": "FAIL", "observed": "PASS" if o else "FAIL", "detail": d}
                     for s_, o, d in STEPS if s_.startswith("CONTROL")],
        "not_run": [{"row": r, "result": "NOT-RUN", "reason": why} for r, why in (
            ("the best target forbidden, the next one taken (three or more candidates)", "the lab has two edges; shown offline in test_policy.py"),
            ("target-not-ready, route-not-on-source, transaction-open, transaction-expired, rule-invalid as live events",
             "named offline from the library's messages (test_policy.py); the library's own tests exercise those refusals live"),
            ("TD_MEC_HO_04 pre-test 'TD_MEC_HO_01 has passed'", "not established by this run"))],
        "not_shown": [
            "a real device: the phone is simulated in this driver's process and every record it posts says sim: true",
            "a radio or network effect: the round trip rises because the simulated device sleeps on the host before it posts",
            "a CMDH policy: the rule is our own JSON object in a <container>; the CSE does not interpret it",
            "a MEC platform's own policy check: the constraint and the violation check are our stand-in resources on each edge's "
            "MN-CSE; no MEC 010 / MEC 011 interface carried, enforced or raised anything",
            "the app's <pollingChannel> downlink: the device here takes commands by notification to a point of access",
            "an authenticated originator: the lab CSEs take X-M2M-Origin as given over plain HTTP on loopback; the engine pings and "
            "reads the constraints as the lab's admin originator",
            "separate machines: 'edge A', 'edge B' and the IN-CSE are three processes on one PC",
            "the constraint broken DURING a handover: the control breaks it after the handover completed and checks that the "
            "MEC-side check then raises a violation",
            "agreement with any test suite: this is a demonstration of mechanisms, not a conformance claim"],
        "cleanup": X["cleanup"], "run": run,
        "raw": {"vehicle01_found_before": X.get("vehicle01_found_before"), "top_level_before": X.get("before"),
                "stimulus_without_rule": X.get("stimulus_without_rule"), "events_on_the_IN_CSE": X.get("events"),
                "device_posts": X.get("device_posts"), "handover_windows": X.get("handover_windows"),
                "violations_on_edge_B": X.get("violations_on_B"), "device": X.get("device"),
                "engine_samples_format": "seconds since the first tick, serving CSE-ID, round trip ms or null, decision",
                "engine": X.get("engine")}},
        indent=1, default=str))
    print(f"  results: {path}")
    return good


if __name__ == "__main__":
    sys.exit(main())
