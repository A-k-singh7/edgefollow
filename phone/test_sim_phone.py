#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""The SIMULATED phone (sim_phone.py) stopped and started again (2026-11-19) -- no phone, no lab, no network.

Defect found on 2026-11-19 while the MEC 046 wrapper was built, ours: after stop() and live() on the same CSE the
simulated phone posted records again but no longer took commands. stop() dropped the downlink poller, and live()
started a new one only inside a registration, which did not run again because the phone still counted itself as
registered. The probe app does not behave so: a stopped LiveService is destroyed, and a new start registers again
(LiveService.onStartCommand / ensureAe).

Also held here since 2026-11-19: the phone's sample counter starts again at 0 after stop(), as the app's does
(LiveService.seq is a field of the service; a service started after a stop is a new one). Until then the simulated
phone's counter carried on across stop(). A running phone that is only re-pointed keeps its counter.

The CSE here is a small HTTP server in this process that answers what the simulated phone asks of a CSE: the AE,
its containers, the <pch>, the subscription, the long poll and the posts. It checks no oneM2M rule. Every device
is SIMULATED.

    python3 phone/test_sim_phone.py
"""
from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sim_phone  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []
CONTROLS = 0
ORIGIN = "CsimRestart"
HOLD_S = 0.3              # how long the fake CSE holds a long poll that has nothing to deliver


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def control(name, went_through, detail=""):
    """A control row: `name` says what must NOT have happened; the row passes when it did not."""
    global CONTROLS
    CONTROLS += 1
    check("CONTROL (must FAIL) " + name, not went_through, detail)


class FakeCse:
    """What one CSE holds for the test: per CSE name the AE creates, the posts per container and the commands
    waiting for the phone's long poll."""

    def __init__(self):
        self.lock = threading.Lock()
        self.creates: dict[str, int] = {}
        self.posts: dict[str, list] = {}           # "<cse>/<cnt>" -> contents
        self.cmds: dict[str, list] = {}            # cse -> commands not yet delivered
        self.polls: dict[str, int] = {}
        self.ts: dict[str, list] = {}              # cse -> the <tsi> the phone posted into radioTs
        self.no_ts: set[str] = set()               # CSEs that hold no radioTs: 404, as a CSE answers
        self.ts_hold: dict[str, float] = {}        # cse -> seconds the answer to a <tsi> is held back
        self.ts_seen = threading.Event()           # set when a held <tsi> has arrived
        self.hold = HOLD_S
        self.n = 0

    def count(self, cse: str, cnt: str) -> int:
        with self.lock:
            return len(self.posts.get(f"{cse}/{cnt}", []))

    def acks(self, cse: str) -> list:
        with self.lock:
            return list(self.posts.get(f"{cse}/ack", []))

    def send(self, cse: str, cmd: dict) -> None:
        with self.lock:
            self.cmds.setdefault(cse, []).append(cmd)


def handler(state: FakeCse):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def answer(self, code: int, body=None):
            raw = json.dumps(body).encode() if body is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parts = self.path.strip("/").split("/")
            cse = parts[0]
            if parts[1:] == ["phone"]:
                with state.lock:
                    there = state.creates.get(cse, 0) > 0
                return self.answer(200, {"m2m:ae": {"rn": "phone", "aei": ORIGIN}}) if there else self.answer(404)
            if parts[1:] == ["phone", "pch", "pcu"]:
                with state.lock:
                    state.polls[cse] = state.polls.get(cse, 0) + 1
                end = time.monotonic() + state.hold
                while time.monotonic() < end:
                    with state.lock:
                        cmd = state.cmds[cse].pop(0) if state.cmds.get(cse) else None
                        state.n += 1
                        rqi = f"n{state.n}"
                    if cmd is not None:
                        return self.answer(200, {"m2m:rqp": {"op": 5, "rqi": rqi, "pc": {"m2m:sgn": {
                            "nev": {"rep": {"m2m:cin": {"con": json.dumps(cmd)}}, "net": 3}, "sur": "cmdSub"}}}})
                    time.sleep(0.02)
                return self.answer(504)
            return self.answer(404)

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            parts = self.path.strip("/").split("/")
            cse = parts[0]
            if len(parts) == 1:                    # the AE: 201 the first time, then ACME's 403 "already registered"
                with state.lock:
                    state.creates[cse] = state.creates.get(cse, 0) + 1
                    first = state.creates[cse] == 1
                return self.answer(201 if first else 403)
            if parts[1:] == ["phone", "pch", "pcu"]:
                return self.answer(200)
            if parts[1:] == ["phone", "radioTs"]:
                if cse in state.no_ts:
                    return self.answer(404)
                with state.lock:
                    state.ts.setdefault(cse, []).append(body.get("m2m:tsi"))
                    held = state.ts_hold.get(cse, 0)
                if held:                           # the tick that posted this is still in flight until the answer
                    state.ts_seen.set()
                    time.sleep(held)
                return self.answer(201)
            if len(parts) == 3 and "m2m:cin" in body:
                with state.lock:
                    state.posts.setdefault(f"{cse}/{parts[2]}", []).append(json.loads(body["m2m:cin"]["con"]))
                return self.answer(201)
            return self.answer(201)                # containers, <pch>, the subscription

        def do_PUT(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.answer(200)

        def log_message(self, *a):
            pass
    return H


def wait(cond, seconds: float) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return bool(cond())


def acked(state: FakeCse, cse: str, cmd_id: int) -> list:
    return [a for a in state.acks(cse) if a.get("id") == cmd_id]


def pollers() -> int:
    return sum(1 for t in threading.enumerate() if t.name == "sim-phone-pcu" and t.is_alive())


class OldStop(sim_phone.SimPhone):
    """The planted fault: stop() as it was before the fix (the registration is kept, the poller is dropped)."""

    def stop(self) -> None:
        self._run.clear()
        if self._ticker is not None:
            self._ticker.join(timeout=self.period + 10)
        if self._poller is not None:
            self._poller.join(timeout=12)
        self._ticker = self._poller = None
        self.last_error = None


class CounterCarriesOn(sim_phone.SimPhone):
    """The planted fault: stop() keeps the sample counter, as it did until 2026-11-19."""

    def stop(self) -> None:
        self._run.clear()
        if self._ticker is not None:
            self._ticker.join(timeout=self.period + 10)
        n = self.seq                      # read once the ticker has ended: a tick in flight has added its one
        super().stop()
        self.seq = n


def numbers(state: FakeCse, cse: str) -> list:
    """The sample numbers (snr) the fake CSE received in radioTs, in the order they arrived."""
    with state.lock:
        return [x.get("snr") for x in state.ts.get(cse, []) if isinstance(x, dict)]


def counter_run(cls, state: FakeCse, base: str, first: str, second: str, stop: bool = True) -> tuple[list, list]:
    """live on `first` for three samples, stop() (not when stop is False), live on `second` for three samples.
    The sample numbers the fake CSE received before and after the second live()."""
    ph = cls(f"{base}/{first}", ORIGIN, rn="phone", period=0.2)
    n1 = 0
    try:
        ph.live()
        wait(lambda: len(numbers(state, first)) >= 3, 5)
        if stop:
            ph.stop()
        if first == second:
            n1 = len(numbers(state, first))
        ph.live(f"{base}/{second}")
        wait(lambda: len(numbers(state, second)) >= n1 + 3, 5)
    finally:
        ph.stop()
    if first == second:
        return numbers(state, first)[:n1], numbers(state, first)[n1:]
    return numbers(state, first), numbers(state, second)


def restart_run(cls, state: FakeCse, base: str, cse: str) -> dict:
    """live, a command, stop, live again on the same CSE, a command. What happened, as plain values."""
    out: dict = {}
    ph = cls(f"{base}/{cse}", ORIGIN, rn="phone", period=0.2)
    try:
        ph.live()
        out["first_records"] = wait(lambda: state.count(cse, "imu") >= 2, 5)
        state.send(cse, {"cmd": "ping", "id": 1})
        out["first_ack"] = wait(lambda: acked(state, cse, 1), 5)
        ph.stop()
        out["pollers_stopped"] = pollers()
        n0, p0 = state.count(cse, "imu"), state.polls.get(cse, 0)
        time.sleep(0.7)
        out["posted_while_stopped"] = state.count(cse, "imu") - n0
        out["polled_while_stopped"] = state.polls.get(cse, 0) - p0
        ph.live()
        out["records_again"] = wait(lambda: state.count(cse, "imu") >= n0 + 2, 5)
        state.send(cse, {"cmd": "ping", "id": 2})
        out["second_ack"] = wait(lambda: acked(state, cse, 2), 5)
        state.send(cse, {"cmd": "period", "id": 3, "value": 1})
        out["period_ack"] = wait(lambda: acked(state, cse, 3), 5)
        out["period"] = ph.period
        time.sleep(0.5)
        out["acks"] = [a.get("id") for a in state.acks(cse)]
        out["pollers_running"] = pollers()
        out["creates"] = state.creates.get(cse, 0)
    finally:
        ph.stop()
    out["pollers_end"] = pollers()
    return out


def main() -> int:
    state = FakeCse()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler(state))
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        print("== stopped and started again on the same CSE")
        r = restart_run(sim_phone.SimPhone, state, base, "cse1")
        check("before the stop: records arrive and a ping is acknowledged", r["first_records"] and r["first_ack"], str(r))
        check("while stopped: no record is posted, the CSE is not polled, no poller thread is left",
              (r["posted_while_stopped"], r["polled_while_stopped"], r["pollers_stopped"]) == (0, 0, 0),
              f"posted {r['posted_while_stopped']}, polled {r['polled_while_stopped']}, pollers {r['pollers_stopped']}")
        check("after the second live(): records arrive again", r["records_again"])
        check("after the second live(): a ping is acknowledged", r["second_ack"], f"acks seen: {r['acks']}")
        check("after the second live(): a period command is acknowledged and applied",
              r["period_ack"] and r["period"] == 1, f"period {r['period']}")
        check("every command was acknowledged once, by one poller", r["acks"] == [1, 2, 3] and r["pollers_running"] == 1,
              f"acks {r['acks']}, pollers {r['pollers_running']}")
        check("the second live() registered again, as a newly started app does (the fake CSE saw two AE creates)",
              r["creates"] == 2, f"{r['creates']} creates")
        check("after the last stop no poller thread is left", r["pollers_end"] == 0, str(r["pollers_end"]))

        o = restart_run(OldStop, state, base, "cse2")
        check("the phone with the old stop() works before its stop (the control is the restart alone)",
              o["first_records"] and o["first_ack"] and o["records_again"], str(o))
        control("a phone with the old stop() acknowledged a command after it was started again",
                o["second_ack"] or o["period_ack"], f"acks seen: {o['acks']}")

        print("== a poller that outlives stop()")
        # stop() waits 12 s for the poller. If the poller is still inside a request then, it lives on; started again,
        # the phone must run that one poller, not a second one beside it.
        state.hold = 1.5
        ph = sim_phone.SimPhone(f"{base}/cse3", ORIGIN, rn="phone", period=0.2)
        try:
            ph.live()
            wait(lambda: state.polls.get("cse3", 0) >= 1, 5)
            old = ph._poller
            old.join = lambda timeout=None: None       # the wait runs out at once: the poller is still in its request
            ph.stop()
            alive_after_stop = old.is_alive()
            ph.live()
            wait(lambda: state.creates.get("cse3", 0) >= 2, 5)
            time.sleep(0.3)
            n = pollers()
            state.send("cse3", {"cmd": "ping", "id": 7})
            got = wait(lambda: acked(state, "cse3", 7), 6)
            time.sleep(0.3)
            check("the set-up holds: the poller was still alive when stop() returned", alive_after_stop)
            check("started again with the old poller still alive: one poller runs, and a ping is acknowledged once",
                  n == 1 and got and len(acked(state, "cse3", 7)) == 1, f"pollers {n}, acks {len(acked(state, 'cse3', 7))}")
        finally:
            state.hold = HOLD_S
            del old.join
            ph.stop()
        check("after its stop no poller thread is left", pollers() == 0, str(pollers()))

        print("== started again on another CSE (the handover's re-point)")
        ph = sim_phone.SimPhone(f"{base}/cse4", ORIGIN, rn="phone", period=0.2)
        try:
            ph.live()
            wait(lambda: state.count("cse4", "imu") >= 1, 5)
            ph.stop()
            ph.live(f"{base}/cse5")
            state.send("cse5", {"cmd": "ping", "id": 9})
            got5 = wait(lambda: acked(state, "cse5", 9), 5)
            n4 = state.count("cse4", "imu")
            time.sleep(0.5)
            check("the phone registers on the new CSE, posts there and acknowledges a ping there",
                  got5 and state.creates.get("cse5") == 1 and state.count("cse5", "imu") >= 1,
                  f"creates {state.creates.get('cse5')}, records {state.count('cse5', 'imu')}")
            check("nothing more is posted to the old CSE", state.count("cse4", "imu") == n4,
                  f"{state.count('cse4', 'imu') - n4} more")
        finally:
            ph.stop()

        print("== the phone's own sequence number, as the app writes it into <radioTs> (LiveService.postTs)")
        # The app posts, after the five records of a tick, one <tsi> into <phone>/radioTs: snr = its counter, dgt =
        # the tick's time (UTC, yyyyMMddTHHmmss,SSS000), con = {"seq", "rsrp"}. A CSE without radioTs answers 404,
        # which the app ignores: no registration is lost over it.
        state.no_ts.add("cse7")
        ph = sim_phone.SimPhone(f"{base}/cse6", ORIGIN, rn="phone", period=0.2, rsrp=-91)
        ph7 = sim_phone.SimPhone(f"{base}/cse7", ORIGIN, rn="phone", period=0.2)
        try:
            ph.live()
            ph7.live()
            wait(lambda: len(state.ts.get("cse6", [])) >= 4 and state.count("cse7", "imu") >= 4, 5)
        finally:
            ph.stop()
            ph7.stop()
        ts = state.ts.get("cse6", [])
        snr = [x.get("snr") for x in ts if isinstance(x, dict)]
        check("one <tsi> per tick, numbered by the phone's counter without a gap from 0",
              len(ts) >= 4 and snr == list(range(len(ts))), str(snr[:8]))
        with state.lock:
            radio_t = [r.get("t") for r in state.posts.get("cse6/radio", [])]
        dgts = [x.get("dgt") for x in ts if isinstance(x, dict)]
        want = [time.strftime("%Y%m%dT%H%M%S", time.gmtime(t_ms // 1000)) + f",{t_ms % 1000:03d}000" for t_ms in radio_t]
        check("each <tsi> carries its tick's time as dgt: the t of the radio record of the same tick, in UTC",
              len(dgts) >= 4 and dgts == want[:len(dgts)], f"{dgts[:2]} against {want[:2]}")
        cons = [json.loads(x["con"]) for x in ts if isinstance(x, dict) and isinstance(x.get("con"), str)]
        check("its content is the app's {seq, rsrp}, marked simulated",
              len(ts) >= 4 and len(cons) == len(ts) and all(c.get("seq") == n and c.get("rsrp") == -91 and c.get("sim") is True
                                           for n, c in zip(snr, cons)), str(cons[:1]))
        check("a CSE without radioTs (404): the records still arrive and the phone does not register again",
              state.count("cse7", "imu") >= 4 and state.creates.get("cse7") == 1 and state.ts.get("cse7") is None,
              f"records {state.count('cse7', 'imu')}, AE creates {state.creates.get('cse7')}")
        marks = [c for k, v in state.posts.items() for c in v if c.get("sim") is not True]
        check("every record and every acknowledgement the fake CSE received is marked simulated", marks == [], str(marks[:2]))

        print("== the phone's counter after stop(): it starts again at 0, as the app's does (LiveService.seq)")
        # LiveService.seq is a field of the service. A stopped service is destroyed and the next start is a new
        # service, which counts from 0; a running service that is only re-pointed (a new CSE, no stop) keeps its
        # counter. Until 2026-11-19 the simulated phone's counter carried on across stop().
        b8, a8 = counter_run(sim_phone.SimPhone, state, base, "cse8", "cse8")
        check("the set-up holds: before the stop the samples are numbered from 0 without a gap",
              len(b8) >= 3 and b8 == list(range(len(b8))), str(b8[:8]))
        check("after stop() and a second live() on the same CSE the first numbered sample is 0 again, and no number "
              "after it is missing", len(a8) >= 3 and a8 == list(range(len(a8))),
              f"before the stop {b8[:8]}, after it {a8[:8]}")
        b9, a9 = counter_run(sim_phone.SimPhone, state, base, "cse9", "cse10")
        check("after stop() and live() on another CSE (how the handover driver moves the stream) the first numbered "
              "sample there is 0", len(b9) >= 3 and len(a9) >= 3 and a9 == list(range(len(a9))),
              f"old CSE {b9[:8]}, new CSE {a9[:8]}")
        b11, a11 = counter_run(sim_phone.SimPhone, state, base, "cse11", "cse12", stop=False)
        check("re-pointed while running, without a stop: the counter carries on, as the app's does",
              len(b11) >= 3 and len(a11) >= 3 and b11 + a11 == list(range(len(b11) + len(a11))),
              f"old CSE {b11[:8]}, new CSE {a11[:8]}")
        # stop() must set the counter back only after the ticker has ended: a tick in flight adds one when its
        # <tsi> is answered. The fake CSE holds that answer, and stop() is called while it is held.
        state.ts_hold["cse14"] = 0.4
        ph = sim_phone.SimPhone(f"{base}/cse14", ORIGIN, rn="phone", period=0.2)
        b14: list = []
        try:
            ph.live()
            seen = state.ts_seen.wait(5)
            ph.stop()
            state.ts_hold.pop("cse14")
            b14 = numbers(state, "cse14")
            ph.live()
            wait(lambda: len(numbers(state, "cse14")) >= len(b14) + 3, 5)
        finally:
            state.ts_hold.pop("cse14", None)
            ph.stop()
        a14 = numbers(state, "cse14")[len(b14):]
        check("a stop() that lands while a tick is in flight: that tick keeps its number, and the next run starts at 0",
              seen and b14 == [0] and len(a14) >= 3 and a14 == list(range(len(a14))),
              f"held <tsi> seen {seen}; before the stop {b14[:8]}, after it {a14[:8]}")
        bc, ac = counter_run(CounterCarriesOn, state, base, "cse13", "cse13")
        control("a phone whose counter carries on across stop() started its second run at 0",
                not (len(bc) >= 3 and ac[:1] == [len(bc)]), f"before the stop {bc[:8]}, after it {ac[:8]}")
    finally:
        srv.shutdown()

    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed; controls {CONTROLS}; skipped 0")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
