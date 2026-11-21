#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""ESTIMED: the oneM2M handover driven by ETSI's hosted MEC Sandbox -- a network-measured location, not the phone's.

    read -rs SANDBOX_MEC013 && export SANDBOX_MEC013     # paste https://try-mec.etsi.org/<sandbox>/<mep>/location/v3
    python3 sandbox_follow.py --ue <UE address in the scenario> --zone-a <zoneId> --zone-b <zoneId> --results <file>

(Reading the URL with `read -s` keeps it out of the shell history and off the screen; it is a capability.)

The sandbox's network scenario moves a UE; its MEC 013 reports the zone (and point of attachment) that serves it.
This script POLLS that query API (the sandbox cannot call back into this PC), keeps a simulated vehicle AE with
samples on edge A of the local lab, and when the UE leaves --zone-a for --zone-b it runs the verified oneM2M handover
A -> B of handover.py. Steps, each a row in the record:

  1  the sandbox's MEC 013 reports the UE (zone + point of attachment)
  2  the UE is in zone A (waited for, up to --wait-start-s); only then is the trigger armed
  3  the vehicle is on edge A with its samples; the IN-CSE holds both edges
  4  the UE is seen in zone A for at least --hold-polls polls before the change (else no move: the "before" state
     was not observed)
  5  the first poll that shows zone B starts the move; a zone mapped to no edge, a missing report or a failed poll
     starts nothing (more than MAX_FAILED_POLLS failed polls in a row end the run)
  6  after the move: edge B holds every sample, edge A answers 404, the IN-CSE routes to B
Timing: the zone change happened between the last poll in A and the first in B; the record keeps both times, so the
uncertainty is one poll period.

The lab: the run takes the lab lock (flock on $EDGEFOLLOW_RUN_DIR/.live.lock, default ~/estimed-run) for its whole
duration unless --lab-lock held says the caller already holds it. It starts and ends with handover.reset(): vehicle01
is removed from both edges and the IN-CSE's handover lock for it is released. The record is written before that
reset, and the reset runs even if the record cannot be written.

Privacy and scope: the sandbox base URL is a capability (whoever has it can drive the sandbox). It is read from the
environment only, never printed and never written (the record says "<sandbox>"); errors carry exception types and
status codes only. Accepted: https://try-mec.etsi.org (port 443 only), or a loopback http URL (tests); no whitespace
or control characters, no user info, query or fragment. Requests use no proxy from the environment and follow no
redirect. The record keeps zones and points of attachment, never coordinates. The sandbox's UE and its movement are
ETSI's simulation; the oneM2M side is the local lab.
"""
from __future__ import annotations

import argparse
import fcntl
import http.client
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

ALLOWED_HOSTS = ("try-mec.etsi.org",)
SAMPLES = ["s1", "s2", "s3"]
MAX_BODY, MAX_ZONE, MAX_FAILED_POLLS = 1 << 20, 64, 10


def check_base(base: str) -> str:
    """The MEC 013 base: https on ETSI's sandbox host (port 443), or http on loopback (tests). Anything else is
    refused, including whitespace or control characters anywhere in it."""
    bad = (not base or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base))
    u, port = None, None
    if not bad:
        try:
            u = urllib.parse.urlsplit(base)
            port = u.port
        except ValueError:                                # a colon typo, a bracketed host: the text would carry the URL
            bad = True
    ok = not bad and (
        (u.scheme == "https" and u.hostname in ALLOWED_HOSTS and port in (None, 443))
        or (u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost")))
    if not ok or u.username or u.password or u.query or u.fragment:
        raise SystemExit("SANDBOX_MEC013 must be https://try-mec.etsi.org/... (or a loopback http URL for tests)")
    return base.rstrip("/")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):                  # a 3xx is an answer, never a new destination
        return None


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def users_of(body) -> list:
    """UserInfo list of a users query, in either shape: {"user": [...]} or the sandbox's {"userList": {"user": [...]}}."""
    if not isinstance(body, dict):
        return []
    inner = body["userList"] if isinstance(body.get("userList"), dict) else body
    users = inner.get("user")
    return [u for u in users if isinstance(u, dict)] if isinstance(users, list) else []


class _Deadline(OSError):
    """The per-poll deadline; an OSError, so even a timer that fires just after the exchange is a failed poll."""


def http_fetch(base: str, ue: str, timeout: float = 10.0) -> dict | None:
    """One MEC 013 users query for the UE: {"zone", "poa"}, or None if the UE is not reported (or its zone is not a
    plain short name). One total deadline (`timeout`) covers the whole exchange, set by a timer (main thread). Errors
    raise OSError naming a status code or an exception type only, never the URL."""
    url = f"{base}/queries/users?address={urllib.parse.quote(ue, safe='')}"

    def on_alarm(signum, frame):
        raise _Deadline()
    old = signal.signal(signal.SIGALRM, on_alarm)
    signal.setitimer(signal.ITIMER_REAL, timeout)
    try:
        return _fetch(url, ue, timeout)
    except _Deadline:
        raise OSError("MEC 013 too slow") from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def _fetch(url: str, ue: str, timeout: float) -> dict | None:
    try:
        with _OPENER.open(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as r:
            raw = r.read(MAX_BODY + 1)
            declared = r.headers.get("Content-Length", "")
        if len(raw) > MAX_BODY:
            raise OSError("MEC 013 answer too large")
        if declared.isdigit() and len(raw) < int(declared):
            raise OSError("MEC 013 answer short")
        body = json.loads(raw or b"null")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise OSError(f"MEC 013 answered {int(e.code)}") from None
    except OSError as e:
        if isinstance(e, _Deadline) or str(e) in ("MEC 013 answer too large", "MEC 013 answer short"):
            raise
        raise OSError(f"MEC 013 unreachable ({type(e).__name__})") from None
    except (ValueError, RecursionError, http.client.HTTPException) as e:
        raise OSError(f"MEC 013 answer unusable ({type(e).__name__})") from None
    for u in users_of(body):
        addr = str(u.get("address", ""))
        if addr.removeprefix("acr:") == ue.removeprefix("acr:"):
            zone, poa = u.get("zoneId"), u.get("accessPointId")
            if isinstance(zone, str) and 0 < len(zone) <= MAX_ZONE:
                return {"zone": zone, "poa": str(poa)[:MAX_ZONE] if poa is not None else ""}
            return None
    return None


def follow(fetch: Callable[[], dict | None], move: Callable[[], dict], *, zone_a: str, zone_b: str,
           period: float, wait_start_s: float, max_s: float, hold_polls: int,
           clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> dict:
    """The decision logic, free of I/O: poll, arm in zone A, hold, move on the first poll in zone B."""
    rec: dict = {"zone_a": zone_a, "zone_b": zone_b, "period_s": period, "polls": [], "steps": [], "result": None,
                 "failed_polls": 0}

    def step(label: str, ok: bool, detail: str = "") -> bool:
        rec["steps"].append({"step": label, "ok": bool(ok), "detail": detail})
        return ok

    class TooManyFailures(Exception):
        pass

    t0 = clock()
    failed_in_a_row = [0]

    def poll() -> dict | None:
        try:
            got = fetch()
            failed_in_a_row[0] = 0
            return got
        except OSError as e:
            rec["failed_polls"] += 1
            failed_in_a_row[0] += 1
            rec.setdefault("poll_errors", []).append(str(e)[:80])
            if failed_in_a_row[0] > MAX_FAILED_POLLS:
                raise TooManyFailures() from None
            return None

    try:
        return _follow(rec, step, poll, fetch, move, zone_a, zone_b, period, wait_start_s, max_s, hold_polls, clock,
                       sleep, t0)
    except TooManyFailures:
        step(f"the polls kept failing ({MAX_FAILED_POLLS + 1} in a row)", False)
        rec["result"] = "ABORTED"
        return rec


def _follow(rec, step, poll, fetch, move, zone_a, zone_b, period, wait_start_s, max_s, hold_polls, clock, sleep, t0):
    first = fetch()                                       # the first poll must work: no run without the UE
    rec["polls"].append({"t": 0.0, **(first or {"zone": None, "poa": None})})
    if not step("the sandbox's MEC 013 reports the UE", first is not None, json.dumps(first)):
        rec["result"] = "ABORTED"
        return rec
    cur = first
    while cur["zone"] != zone_a:                          # wait for the UE to enter zone A
        if clock() - t0 > wait_start_s:
            step("the UE is in zone A before the trigger is armed", False, f"last zone {cur['zone']}")
            rec["result"] = "ABORTED"
            return rec
        sleep(period)
        cur = poll() or {"zone": None, "poa": None}
        rec["polls"].append({"t": round(clock() - t0, 3), **cur})
    step("the UE is in zone A before the trigger is armed", True, f"poa {cur['poa']}")
    armed_at, in_a, last_a_t = clock(), 1, round(clock() - t0, 3)
    while True:
        if clock() - armed_at > max_s:
            step(f"the UE was seen in zone A for {in_a} polls", in_a >= hold_polls)
            step("the UE reached zone B within the time limit", False, f"{max_s:.0f} s")
            rec["result"] = "NO_ZONE_CHANGE"
            return rec
        sleep(period)
        cur = poll() or {"zone": None, "poa": None}
        t = round(clock() - t0, 3)
        rec["polls"].append({"t": t, **cur})
        if cur["zone"] == zone_a:
            in_a, last_a_t = in_a + 1, t
            continue
        if cur["zone"] != zone_b:
            rec.setdefault("ignored", []).append({"t": t, "zone": cur["zone"]})
            continue                                     # unmapped zone, no report or a failed poll: no trigger
        held = step(f"the UE was seen in zone A for {in_a} polls before the change", in_a >= hold_polls,
                    f"at least {hold_polls} required")
        rec["zone_change"] = {"last_in_a_t": last_a_t, "first_in_b_t": t, "poa_b": cur["poa"]}
        if not held:
            rec["result"] = "ABORTED"                   # too few hold polls: the "before" state was not observed
            return rec
        step("the UE entered zone B: the move starts", True, f"between t={last_a_t} s and t={t} s")
        m0 = clock()
        out = move()
        rec["move"] = {**out, "duration_s": round(clock() - m0, 3)}
        ok = step("after the move: edge B holds every sample, edge A 404, IN-CSE routes to B", out.get("ok") is True,
                  json.dumps({k: v for k, v in out.items() if k != "ok"}))
        rec["result"] = "COMPLETED" if ok else "FAILED"
        return rec


def lab_prepare() -> dict:
    """The simulated vehicle on edge A with SAMPLES; the IN-CSE holds both edges."""
    import handover as ho
    ho.reset()
    st = [ho.create_ae(ho.EDGE_A)[0], ho.create_container(ho.EDGE_A)[0]] + [ho.add_sample(ho.EDGE_A, s)[0]
                                                                          for s in SAMPLES]
    return {"ok": st == [201] * (2 + len(SAMPLES)) and ho.edges_ok(ho.registered_edges())
            and ho.read_samples(ho.EDGE_A) == SAMPLES, "statuses": st}


def lab_move() -> dict:
    import handover as ho
    moved = ho.handover(ho.EDGE_A, ho.EDGE_B, ho.read_samples(ho.EDGE_A))
    on_b = ho.read_samples(ho.EDGE_B)
    a = ho._req("GET", f"{ho.EDGE_A[0]}/{ho.EDGE_A[1]}/{ho.AE_NAME}", ho.ORCHESTRATOR)[0]
    route = ho.serving_edges()
    return {"ok": bool(moved) and on_b == SAMPLES and a == 404 and route == ["/id-mn-b"],
            "moved": bool(moved), "samples_on_b": len(on_b), "edge_a_status": a, "route": route}


def lab_reset() -> None:
    import handover as ho
    try:
        ho.reset()
    except OSError:
        pass


def lab_lock_path() -> Path:
    return Path(os.environ.get("EDGEFOLLOW_RUN_DIR", str(Path.home() / "estimed-run"))) / ".live.lock"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ue", required=True, help="the UE's address in the sandbox scenario")
    ap.add_argument("--zone-a", required=True)
    ap.add_argument("--zone-b", required=True)
    ap.add_argument("--period", type=float, default=2.0)
    ap.add_argument("--wait-start-s", type=float, default=300.0)
    ap.add_argument("--max-s", type=float, default=600.0)
    ap.add_argument("--hold-polls", type=int, default=3)
    ap.add_argument("--results", required=True, help="where the JSON record is written")
    ap.add_argument("--lab-lock", choices=("take", "held"), default="take",
                    help="take the lab lock (default), or 'held' when the caller already holds it")
    a = ap.parse_args(argv)
    if a.zone_a == a.zone_b or a.period <= 0 or a.hold_polls < 1:
        ap.error("zones must differ; period > 0; hold-polls >= 1")
    base = check_base(os.environ.get("SANDBOX_MEC013", ""))
    results = Path(a.results)
    if not results.parent.is_dir() or not os.access(results.parent, os.W_OK):
        ap.error("--results: its directory must exist and be writable")
    lock_path = lab_lock_path()
    if not lock_path.parent.is_dir():
        ap.error(f"the lab run directory does not exist (set EDGEFOLLOW_RUN_DIR): {lock_path.parent}")
    try:
        lock = lock_path.open("a")
    except OSError as e:
        ap.error(f"cannot open the lab lock file ({type(e).__name__})")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        free = True
    except OSError:
        free = False
    if a.lab_lock == "held":
        if free:                                         # nobody holds it: "held" is not true
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
            ap.error("--lab-lock held, but nobody holds the lab lock")
        lock.close()
        lock = None
    elif not free:
        print("waiting for the lab lock (if you already hold it, e.g. under flock -o, pass --lab-lock held)",
              file=sys.stderr, flush=True)
        fcntl.flock(lock, fcntl.LOCK_EX)                 # the lab is shared: wait for it
    rec: dict = {"script": "sandbox_follow.py", "mec013": "<sandbox>", "ue": a.ue,
                 "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        try:
            prep = lab_prepare()
            rec["lab"] = prep
            if not prep["ok"]:
                rec["result"] = "ABORTED"
            else:
                rec.update(follow(lambda: http_fetch(base, a.ue), lab_move, zone_a=a.zone_a, zone_b=a.zone_b,
                                  period=a.period, wait_start_s=a.wait_start_s, max_s=a.max_s,
                                  hold_polls=a.hold_polls))
        except OSError as e:
            rec["result"], rec["error"] = "ABORTED", str(e)[:200]
        finally:
            try:
                results.write_text(json.dumps(rec, indent=1) + "\n")
            finally:
                lab_reset()                              # the lab is reset even if the record cannot be written
    finally:
        if lock is not None:
            lock.close()
    print(f"RESULT {rec['result']}  (record: {a.results})")
    return 0 if rec["result"] == "COMPLETED" else 1


if __name__ == "__main__":
    sys.exit(main())
