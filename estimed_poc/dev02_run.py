#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""TD_MEC_DEV_02 (TR-0086 test plan, 7.3): an AE subscribes to MEC 012 cell-change events and receives the
notification -- with a SIMULATED UE, on this one host.

  pre  a simulated UE (phone/sim_phone.py, AE dev02ue, originator Cdev02-ue) posts radio records on MN-CSE-A every
       2 s; it declares the FICTITIOUS address 192.0.2.21 (RFC 5737 documentation range) as its own. The RNIS
       (mec012/candidate.py, unmodified, served by phone/mec012_phone.py on :8412) reads it through oneM2M under an
       access policy that lets only its reader originator read.
       The AE (dev02app, originator Cdev02-app) is registered on MN-CSE-A with its notification endpoint in
       pointOfAccess (poa, TS-0001 <AE>: "the list of addresses for communicating with the registered AE"). That
       poa, READ BACK from the CSE, is the "registered callbackReference endpoint" of the plan's pre-test condition.
  1    the AE POSTs /rni/v2/subscriptions: CellChangeSubscription, filterCriteriaAssocHo = this UE (associateId
       type 1), source cell A, hoStatus COMPLETED; callbackReference = the poa
  2    201 Created; the Location header names the subscription (resolves to its _links.self, GET returns it)
  3    trigger: the simulated UE moves from cell A to cell B (the plan allows a simulated trigger)
  4    the RNIS POSTs a CellChangeNotification to the callbackReference naming the UE (associateId 1 = 192.0.2.21)
  5    the AE answers 204, and the RNIS's own send log records the send as delivered with HTTP status 204
  6    content checked field by field and against the ATS schema; latency from the oneM2M creation time of the
       UE's first sample on cell B to the notification's arrival, against LATENCY_BUDGET_S (stated below, fixed
       before the first live run)
  controls (each must FAIL): a CellChange while the UE stays on A; a second CellChange for the one move; a
       subscription filtered to another UE gets something; one filtered to another source cell (the move's target)
       gets something; a detach on B and re-attach on D gives a CellChange; the deleted subscription receives
       anything after the delete; the RNIS counts the AE's 500 answer as a delivered notification. Each is judged
       by a pure ctl_* function on the live record (fed firing and non-firing input in estimed_poc/test_dev02.py,
       which also checks that every CONTROL step is wired to one of them).
  cleanup  every subscription, both AEs, the access policy, the RNIS process and the listener; checked by GET.

Run only under the lab's live lock, simulated devices only:
    flock /home/edgefollow/estimed-run/.live.lock /home/edgefollow/edgefollow-lab/.venv/bin/python -B estimed_poc/dev02_run.py
"""
from __future__ import annotations

import argparse
import calendar
import fcntl
import hashlib
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "phone"))
import device_state as ds  # noqa: E402
import sim_phone  # noqa: E402

PY = "/home/edgefollow/edgefollow-lab/.venv/bin/python"
LOCK = "/home/edgefollow/estimed-run/.live.lock"
TESTPLAN = "/var/tmp/onem2m-tr-dl/tr-0086/testplan.md"
SCHEMA = Path("/home/edgefollow/etsi-forge-ats-reference/MEC012/SRV/RNIS/schemas/CellChangeNotification.schema.json")
OUT_DIR = Path("/home/edgefollow/estimed-run/sim")
MN_A = "http://127.0.0.1:8201/cse-mn-a"
ADMIN = "CAdmin"
# Ports of THIS run, inside the lab's loopback notification range 8400-8499 (device_state.callback_allowed). Not
# 8402: a long-running mec012_phone for the real phone holds it.
RNIS_PORT, LISTEN_PORT = 8412, 8432
RNIS = f"http://127.0.0.1:{RNIS_PORT}/rni/v2"
UE_RN, UE_ORIG = "dev02ue", "Cdev02-ue"
APP_RN, APP_ORIG = "dev02app", "Cdev02-app"
READER, STRANGER = "Cdev02-rnis", "Cdev02-stranger"
ACP_RN = "dev02ReadAcp"
CNTS = ("imu", "env", "loc", "radio", "wlan")
UE_IP, OTHER_UE_IP = "192.0.2.21", "192.0.2.99"     # RFC 5737 TEST-NET-1: fictitious, never assigned by a network
CELL_A, CELL_B, CELL_C, CELL_D = 0x0D02A01, 0x0D02B02, 0x0D02C03, 0x0D02D04
PLMN = {"mcc": "001", "mnc": "01"}                  # sim_phone's PLMN: the ITU test network
PERIOD_S = 2.0                                      # the simulated UE's sample period
HOLD_SAMPLES = 3                                    # samples held in a no-change window
MAX_BODY = 64 * 1024

# Stated before the first live run (2026-11-20). TR-0086 asks for "acceptable latency" and names no number.
LATENCY_BUDGET_S = 3.0
LATENCY_BUDGET_WHY = (
    "mec012_phone's notifier sleeps 1 s between polls; one poll reads the latest instance of five containers one "
    "after another (allowed 0.75 s on this loaded host). A sample created just after a poll read the radio container "
    "waits for the rest of that poll, the 1 s sleep and the next poll up to its radio read (1 s + 2 x 0.75 s at "
    "most), then the step and one loopback POST (allowed 0.5 s): 1 + 1.5 + 0.5 = 3.0 s. Derived from the notifier's "
    "design, not from a measurement; one host, no network in the path.")

# Callback paths under the registered endpoint (the AE's poa). The main subscription uses the poa itself.
CONTROL_PATHS = {"otherue": 204, "othersrc": 204, "witness": 204, "fail500": 500}

DOES_NOT_SHOW = [
    "a real UE: the UE is SIMULATED (phone/sim_phone.py); this script sets its cell and its attach state. Its "
    "address 192.0.2.21 is fictitious (RFC 5737) and is the UE's own claim in its radio record, not one a network "
    "assigned: no core network, no PDN session, no DHCP, and nothing checks it. No radio, no RRC, no eNB, no "
    "handover procedure",
    "a real phone's identifier: the probe app (v20) reports no UE address, so with the real phone the RNIS sends no "
    "associateId and a subscription filtered on associateId gets nothing (as before 2026-11-20)",
    "a MEC platform: the RNIS is our candidate (mec012/candidate.py + phone/mec012_phone.py). It infers a cell change "
    "from two consecutive oneM2M samples; hoStatus is always 3 (COMPLETED), IN_PREPARATION / IN_EXECUTION are never seen",
    "a network: CSE, RNIS, UE and AE all run on one host over loopback; the latency includes no network",
    "Mp1 / MEC 011: no service discovery, no authorization, no TLS; the AE reaches the RNIS directly. MEC 012 "
    "notifications are unsigned: the callback URL is the only credential",
    "MEC 013 is not used, and TD_MEC_DEV_01 is not re-run here (it is COVERED in estimed/TESTPLAN_COVERAGE.md)",
]

RUN_FILES = ("estimed_poc/dev02_run.py", "phone/mec012_phone.py", "phone/sim_phone.py", "phone/device_state.py",
             "mec012/candidate.py")


# ---------------------------------------------------------------- the judgements (pure; estimed_poc/test_dev02.py)
def ct_epoch(ct: str) -> float:
    """POSIX seconds of a oneM2M time 'YYYYMMDDTHHMMSS[,ffffff]' (UTC)."""
    base, _, frac = ct.partition(",")
    return calendar.timegm(time.strptime(base, "%Y%m%dT%H%M%S")) + (float("0." + frac) if frac else 0.0)


def latency_s(sample_ct: str, arrival: float) -> float:
    """Seconds from a sample's creation on the CSE to a notification's arrival at the AE (one host, one clock)."""
    return arrival - ct_epoch(sample_ct)


def eci(ci: int) -> str:
    return f"{ci & 0xFFFFFFF:07X}"


def ecgi(ci: int) -> dict:
    return {"plmn": dict(PLMN), "cellId": eci(ci)}


def _is_int(v, want: int) -> bool:
    return type(v) is int and v == want


def cellchange_faults(body, *, src_ci: int, trg_ci: int, ue: str, sub_href: str, now: float | None = None) -> list[str]:
    """The fields of a CellChangeNotification that are not what this move must produce; [] when all are right."""
    now = time.time() if now is None else now
    if not isinstance(body, dict):
        return ["body"]
    out = []
    if body.get("notificationType") != "CellChangeNotification":
        out.append("notificationType")
    ts = body.get("timeStamp")
    if not (isinstance(ts, dict) and type(ts.get("seconds")) is int and type(ts.get("nanoSeconds")) is int
            and abs(ts["seconds"] - now) <= 60):
        out.append("timeStamp")
    if not _is_int(body.get("hoStatus"), 3):
        out.append("hoStatus")
    if body.get("srcEcgi") != ecgi(src_ci):
        out.append("srcEcgi")
    if body.get("trgEcgi") != [ecgi(trg_ci)]:
        out.append("trgEcgi")
    a = body.get("associateId")
    if not (isinstance(a, list) and len(a) == 1 and isinstance(a[0], dict) and _is_int(a[0].get("type"), 1)
            and a[0].get("value") == ue and set(a[0]) == {"type", "value"}):
        out.append("associateId")
    links = body.get("_links")
    sub = links.get("subscription") if isinstance(links, dict) else None
    if not (isinstance(sub, dict) and sub.get("href") == sub_href):
        out.append("_links")
    return out


def location_ok(location: str | None, self_href: str | None) -> bool:
    """The Location header names the created subscription: it resolves to its _links.self and ends in an id."""
    if not location or not self_href:
        return False
    resolved = urllib.parse.urljoin(self_href, location)
    return resolved == self_href and bool(urllib.parse.urlsplit(resolved).path.rsplit("/", 1)[-1])


def status_for(path: str, base: str) -> int:
    """What the AE's listener answers: 204 on its endpoint and the named control paths, 500 on fail500, else 404."""
    if path == base:
        return 204
    if path.startswith(base + "/"):
        return CONTROL_PATHS.get(path[len(base) + 1:], 404)
    return 404


def attribute(notes: list[dict], base: str, subs: dict[str, str]) -> tuple[dict[str, list], list]:
    """Sort received POSTs by subscription: the path names it (base = main, base/<name>) and the body's
    _links.subscription.href must be that subscription's. Anything else is misattributed."""
    by: dict[str, list] = {}
    mis = []
    for n in notes:
        path = n.get("path", "")
        name = "main" if path == base else (path[len(base) + 1:] if path.startswith(base + "/") else None)
        body = n.get("body")
        links = body.get("_links") if isinstance(body, dict) else None
        sub = links.get("subscription") if isinstance(links, dict) else None
        href = sub.get("href") if isinstance(sub, dict) else None
        if name in subs and href is not None and href == subs[name]:
            by.setdefault(name, []).append(n)
        else:
            mis.append(n)
    return by, mis


def send_record_ok(lines: list[dict], href: str | None, *, ok: bool, status: int) -> tuple[bool, list[dict]]:
    """The RNIS's own account of one subscription's send: exactly one send-log line for href, saying ok and carrying
    this HTTP status (step 5: delivered, 204; the 500 endpoint: failed, 500). "ok" alone means only "some 2xx"."""
    mine = [x for x in lines if href and x.get("sub") == href]
    good = (len(mine) == 1 and mine[0].get("ok") is ok and type(mine[0].get("status")) is int
            and mine[0]["status"] == status)
    return good, mine


# ---------------------------------------------------------------- the CONTROLs' judgements (pure; test_dev02.py)
# Each returns (fired, detail); a CONTROL step passes it on as step(label, *ctl_x(NOTES, ...)). A control must be able
# to fire: estimed_poc/test_dev02.py feeds each one input that makes it fire and input that must not, and checks that
# every CONTROL step of main() is judged by one of these on the live record.
def ctl_any_post(notes: list[dict], t0: float, t1: float, prefix: str = "") -> tuple[bool, str]:
    """Fires when any POST reached the AE in [t0, t1): while the UE stayed on one cell, or over a detach and a
    re-attach on another cell (neither is a handover)."""
    got = [n for n in notes if t0 <= n["t"] < t1]
    return bool(got), f"{prefix}{len(got)} POSTs: {[n.get('path') for n in got]}"


def ctl_repeat(notes: list[dict], base: str, subs: dict[str, str], t0: float, prefix: str = "") -> tuple[bool, str]:
    """Fires when more than one notification attributed to the main subscription (path AND _links) arrived since t0:
    one move must give one CellChange."""
    by, _ = attribute(notes, base, subs)
    n = len([x for x in by.get("main", []) if x["t"] >= t0])
    return n > 1, f"{prefix}{n} at the endpoint for the main subscription"


def ctl_got(notes: list[dict], base: str, name: str) -> tuple[bool, str]:
    """Fires when anything reached the control path base/<name> (a subscription whose filter must exclude this move).
    A name the listener does not serve raises: a control on a path nothing posts to could never fire."""
    if name not in CONTROL_PATHS:
        raise ValueError(f"{name!r} is not a control path the listener serves ({sorted(CONTROL_PATHS)})")
    got = [n for n in notes if n.get("path") == f"{base}/{name}"]
    return bool(got), f"{len(got)} POSTs at {base}/{name}"


def ctl_counted_500(lines: list[dict], href: str | None) -> tuple[bool, str]:
    """Fires when the RNIS's send log says a send to the 500 endpoint's subscription was delivered (ok true)."""
    if not href:
        raise ValueError("no subscription href for the 500 endpoint")
    got = [x for x in lines if x.get("sub") == href and x.get("ok") is True]
    return bool(got), f"{len(got)} send-log lines for it say delivered"


def ctl_after_delete(notes: list[dict], base: str, t0: float) -> tuple[bool, str]:
    """Fires when the deleted subscription's endpoint (base itself) received anything at or after the delete (t0)."""
    got = [n for n in notes if n.get("path") == base and n["t"] >= t0]
    return bool(got), f"{len(got)} POSTs at {base} since the delete"


def verdict(steps: list[tuple[str, bool, str]], *, cleanup_ok: bool, aborted_at: str | None = None) -> bool:
    """PASS only if the run reached its end, every step passed, there is at least one control and every control
    failed as it must, and the clean-up left nothing behind."""
    ctl = [ok for label, ok, _ in steps if label.startswith("CONTROL")]
    real = [ok for label, ok, _ in steps if not label.startswith("CONTROL")]
    return aborted_at is None and cleanup_ok and bool(real) and all(real) and bool(ctl) and not any(ctl)


def lock_held(path: str) -> bool:
    """True when another open file holds an flock on path (the `flock` wrapper this run must be started under).
    Never takes the lock itself."""
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


# ---------------------------------------------------------------- the AE's notification endpoint
NOTES: list[dict] = []


class _AE(BaseHTTPRequestHandler):
    base = "/"
    timeout = 5

    def do_POST(self):  # noqa: N802
        t = time.time()
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = -1
        body = None
        if 0 <= n <= MAX_BODY:
            raw = self.rfile.read(n)
            try:
                body = json.loads(raw or b"null")
            except ValueError:
                body = None
            status = status_for(self.path, type(self).base)
        else:
            status = 413
            self.close_connection = True
        NOTES.append({"path": self.path, "t": t, "status": status, "body": body})
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def make_listener(port: int, base: str) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), type("AE", (_AE,), {"base": base}))
    srv.daemon_threads = True
    return srv


# ---------------------------------------------------------------- HTTP
def m2m(method: str, url: str, origin: str, ty: int | None = None, body: dict | None = None) -> tuple[int, dict | None]:
    h = {"X-M2M-Origin": origin, "X-M2M-RI": f"dev02-{time.time_ns()}", "X-M2M-RVI": "4", "Accept": "application/json"}
    if body is not None:
        h["Content-Type"] = f"application/json;ty={ty}" if ty else "application/json"
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=10) as x:
            raw = x.read()
            return x.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, (json.loads(raw) if raw else None)
        except ValueError:
            return e.code, None
    except (urllib.error.URLError, OSError) as e:
        return 0, {"error": repr(e)}


def http(method: str, url: str, body=None) -> tuple[int, dict, object]:
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                               headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=5) as x:
            raw = x.read()
            return x.status, dict(x.headers), (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, dict(e.headers), (json.loads(raw) if raw else None)
        except ValueError:
            return e.code, dict(e.headers), None
    except (urllib.error.URLError, OSError) as e:
        return 0, {}, {"error": repr(e)}


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def wait_until(pred, timeout_s: float, poll_s: float = 0.2):
    t_end = time.time() + timeout_s
    while True:
        v = pred()
        if v or time.time() >= t_end:
            return v
        time.sleep(poll_s)


def radio_samples() -> list[tuple[str, dict]]:
    """(ct, record) of every radio contentInstance of the UE, oldest first, as its owner reads them."""
    st, b = m2m("GET", f"{MN_A}/{UE_RN}/radio?rcn=4", UE_ORIG)
    if st != 200 or not b:
        return []
    out = []
    for c in (b.get("m2m:cnt") or {}).get("m2m:cin", []):
        try:
            out.append((c["ct"], json.loads(c["con"])))
        except (KeyError, ValueError):
            continue
    return sorted(out, key=lambda x: x[0])


def serving_ci(rec: dict) -> int | None:
    c = ds.serving_cell(rec)
    return c["ci"] if c else None


def samples_after(t: float, pred=lambda rec: True) -> list[tuple[str, dict]]:
    return [(ct, r) for ct, r in radio_samples() if ct_epoch(ct) > t and pred(r)]


def hold(n: int, after: float, pred=lambda rec: True, timeout_s: float | None = None) -> list[tuple[str, dict]]:
    """Wait for n samples created after `after` (matching pred), then until the RNIS has had the latency budget to
    act on the last one. Returns the samples seen."""
    got = wait_until(lambda: (s if len(s := samples_after(after, pred)) >= n else None),
                     timeout_s if timeout_s is not None else n * PERIOD_S + 15, 0.5) or samples_after(after, pred)
    if got:
        time.sleep(max(0.0, ct_epoch(got[-1][0]) + LATENCY_BUDGET_S - time.time()))
    return got


def plmn_info_status(ci: int) -> int:
    return http("GET", f"{RNIS}/queries/plmn_info?cell_id={eci(ci)}")[0]


def read_sendlog(path: Path) -> list[dict]:
    try:
        return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    except (OSError, ValueError):
        return []


# ---------------------------------------------------------------- the run
STEPS: list[tuple[str, bool, str]] = []


class Abort(Exception):
    pass


def step(label: str, ok: bool, detail: str = "") -> bool:
    STEPS.append((label, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"\n          {detail}" if detail else ""), flush=True)
    return bool(ok)


def require(label: str, ok: bool, detail: str = "") -> None:
    if not step(label, ok, detail):
        raise Abort(label)


def run_record() -> dict:
    def git(*a):
        r = subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    status = git("status", "--porcelain")
    return {"argv": [sys.executable, *sys.argv], "commit": git("rev-parse", "HEAD"),
            "uncommitted_paths": None if status is None else len(status.splitlines()),
            "files_sha256": {f: hashlib.sha256((REPO / f).read_bytes()).hexdigest() for f in RUN_FILES},
            "at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def _sigterm(*_a):
    raise KeyboardInterrupt("SIGTERM")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="TD_MEC_DEV_02 with a simulated UE on the local lab")
    ap.add_argument("--results", help="results JSON (default: a timestamped file under /home/edgefollow/estimed-run/sim)")
    a = ap.parse_args(argv)
    if not lock_held(LOCK):
        print(f"refused: start this run under the lab's live lock: flock {LOCK} <this command>")
        return 2
    busy = [p for p in (RNIS_PORT, LISTEN_PORT) if port_open(p)]
    if busy:
        print(f"refused: port(s) {busy} already in use on 127.0.0.1")
        return 2
    st, _ = m2m("GET", MN_A, ADMIN)
    if st != 200:
        print(f"PRECONDITION: MN-CSE-A not reachable at {MN_A} (HTTP {st})")
        return 2
    signal.signal(signal.SIGTERM, _sigterm)
    runid = time.strftime("%Y%m%dT%H%M%S", time.gmtime()) + "-" + secrets.token_hex(3)
    run_dir = OUT_DIR / f"dev02_{runid}"
    run_dir.mkdir(parents=True, exist_ok=True)
    results = Path(a.results) if a.results else OUT_DIR / f"dev02_sim_{runid}.json"
    sendlog = run_dir / "rnis_sendlog.jsonl"
    base = f"/dev02/{runid}"
    poa_want = f"http://127.0.0.1:{LISTEN_PORT}{base}"
    STEPS.clear()
    NOTES.clear()
    meas: dict = {"latency_budget_s": LATENCY_BUDGET_S, "latency_budget_why": LATENCY_BUDGET_WHY,
                  "ue_period_s": PERIOD_S, "notifier_poll_s": 1.0}
    subs: dict[str, str] = {}               # name -> _links.self.href of every subscription this run created
    sub_loc: dict[str, str] = {}            # name -> Location header
    deleted: set[str] = set()
    ue = srv = rnis = log = None
    aborted = None
    pre_clean = {}
    print(f"== TD_MEC_DEV_02, simulated UE, run {runid}")
    try:
        # ------------------------------------------------ pre-test
        pre_clean = {"ae " + UE_RN: m2m("DELETE", f"{MN_A}/{UE_RN}", UE_ORIG)[0],
                     "ae " + APP_RN: m2m("DELETE", f"{MN_A}/{APP_RN}", APP_ORIG)[0],
                     "acp " + ACP_RN: m2m("DELETE", f"{MN_A}/{ACP_RN}", UE_ORIG)[0]}
        ue = sim_phone.SimPhone(MN_A, UE_ORIG, UE_RN, period=PERIOD_S, ci=CELL_A, ue_ipv4=UE_IP)
        ue.live()
        first = wait_until(lambda: (s if len(s := radio_samples()) >= 2 else None), 30, 0.5) or []
        require(f"pre: simulated UE (AE {UE_RN}, {UE_ORIG}) posting on MN-CSE-A on cell {eci(CELL_A)}, declaring the "
                f"fictitious address {UE_IP}; every record marked sim",
                len(first) >= 2 and all(r.get("sim") is True and r.get("ue_ipv4") == UE_IP and serving_ci(r) == CELL_A
                                        for _, r in first),
                f"{len(first)} radio samples; leftovers removed first: {pre_clean}")
        acp = {"m2m:acp": {"rn": ACP_RN, "pv": {"acr": [{"acor": [READER], "acop": 2 | 32}, {"acor": [UE_ORIG], "acop": 63}]},
                           "pvs": {"acr": [{"acor": [UE_ORIG], "acop": 63}]}}}
        st_acp, b_acp = m2m("POST", MN_A, UE_ORIG, 1, acp)
        ri = ((b_acp or {}).get("m2m:acp") or {}).get("ri")
        puts = [m2m("PUT", f"{MN_A}/{UE_RN}", UE_ORIG, body={"m2m:ae": {"acpi": [ri]}})[0]] + \
               [m2m("PUT", f"{MN_A}/{UE_RN}/{c}", UE_ORIG, body={"m2m:cnt": {"acpi": [ri]}})[0] for c in CNTS]
        r_ok, r_no = m2m("GET", f"{MN_A}/{UE_RN}/radio/la", READER)[0], m2m("GET", f"{MN_A}/{UE_RN}/radio/la", STRANGER)[0]
        require("pre: access policy on the UE: the RNIS's reader may read (200), a stranger may not (403)",
                st_acp == 201 and puts == [200] * 6 and (r_ok, r_no) == (200, 403),
                f"ACP {st_acp}; acpi PUTs {puts}; reader {r_ok}, stranger {r_no}")
        st_ae, _ = m2m("POST", MN_A, APP_ORIG, 2, {"m2m:ae": {"rn": APP_RN, "api": "Ndev02.app", "rr": True,
                                                             "srv": ["4"], "poa": [poa_want]}})
        st_g, b_g = m2m("GET", f"{MN_A}/{APP_RN}", APP_ORIG)
        ae = (b_g or {}).get("m2m:ae") or {}
        poa = (ae.get("poa") or [None])[0]
        require("pre: the AE is registered on MN-CSE-A with its notification endpoint as pointOfAccess (poa), "
                "requestReachability true; the poa read back from the CSE is the callbackReference",
                st_ae == 201 and st_g == 200 and ae.get("aei") == APP_ORIG and ae.get("poa") == [poa_want] and ae.get("rr") is True,
                f"create {st_ae}; GET {st_g}: aei {ae.get('aei')}, poa {ae.get('poa')}, rr {ae.get('rr')}")
        callback = poa
        srv = make_listener(LISTEN_PORT, urllib.parse.urlsplit(callback).path)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        env = dict(os.environ, PHONE_CSE=MN_A, PHONE_AE=UE_RN, PHONE_READER_ORIGIN=READER,
                   PHONE_MEC012_PORT=str(RNIS_PORT), PHONE_MEC012_SENDLOG=str(sendlog))
        log = open(run_dir / "rnis.log", "wb")
        rnis = subprocess.Popen([PY, "-B", str(REPO / "phone" / "mec012_phone.py")], env=env, stdout=log,
                                stderr=subprocess.STDOUT, cwd=str(REPO))
        up = wait_until(lambda: port_open(RNIS_PORT), 20, 0.2)
        seen = wait_until(lambda: plmn_info_status(CELL_A) == 200, 15, 0.5)
        _, _, pl = http("GET", f"{RNIS}/queries/plmn_info?cell_id={eci(CELL_A)}")
        require(f"pre: the RNIS (our candidate, unmodified, + mec012_phone on :{RNIS_PORT}) reads the UE through "
                f"oneM2M: plmn_info for cell {eci(CELL_A)} answers PLMN 001/01",
                bool(up) and bool(seen) and isinstance(pl, list) and pl and pl[0].get("plmn") == [PLMN],
                f"listening {bool(up)}; plmn_info {pl}")

        # ------------------------------------------------ step 1 + 2
        print("== steps 1-2: the AE subscribes to cell changes")
        main_req = {"subscriptionType": "CellChangeSubscription", "callbackReference": callback,
                    "filterCriteriaAssocHo": {"associateId": [{"type": 1, "value": UE_IP}], "ecgi": [ecgi(CELL_A)],
                                              "hoStatus": [3]}}
        st1, h1, b1 = http("POST", f"{RNIS}/subscriptions", main_req)
        href = (((b1 or {}).get("_links") or {}).get("self") or {}).get("href") if isinstance(b1, dict) else None
        if st1 == 201 and href:
            subs["main"], sub_loc["main"] = href, h1.get("Location")
        step("1 the AE POSTs /rni/v2/subscriptions: CellChangeSubscription, filterCriteriaAssocHo = associateId "
             f"[type 1 {UE_IP}], source ecgi {eci(CELL_A)}, hoStatus [3]; callbackReference = the AE's poa",
             st1 == 201 and isinstance(b1, dict) and b1.get("callbackReference") == callback
             and b1.get("filterCriteriaAssocHo") == main_req["filterCriteriaAssocHo"],
             f"HTTP {st1}; callbackReference {callback}")
        loc = h1.get("Location")
        st_get, _, b_get = http("GET", urllib.parse.urljoin(href or RNIS, loc or "")) if loc else (0, {}, None)
        require("2 201 Created; the Location header names the subscription (resolves to its _links.self; GET on it "
                "returns the same subscription)",
                st1 == 201 and location_ok(loc, href) and st_get == 200 and isinstance(b_get, dict)
                and b_get.get("callbackReference") == callback and b_get.get("subscriptionType") == "CellChangeSubscription",
                f"Location {loc!r}; self {href}; GET {st_get}")
        ctl_req = {
            "otherue": {"associateId": [{"type": 1, "value": OTHER_UE_IP}]},
            "othersrc": {"ecgi": [ecgi(CELL_B)]},
            "witness": {"associateId": [{"type": 1, "value": UE_IP}]},
            "fail500": {"associateId": [{"type": 1, "value": UE_IP}]},
        }
        made = {}
        for name, filt in ctl_req.items():
            s_, h_, b_ = http("POST", f"{RNIS}/subscriptions", {"subscriptionType": "CellChangeSubscription",
                                                                 "callbackReference": f"{callback}/{name}",
                                                                 "filterCriteriaAssocHo": filt})
            made[name] = s_
            if s_ == 201:
                subs[name] = b_["_links"]["self"]["href"]
                sub_loc[name] = h_.get("Location")
        require("pre-controls: four more subscriptions on paths under the endpoint: another UE (192.0.2.99), source "
                f"cell {eci(CELL_B)} only, a witness (this UE, any cell), an endpoint that answers 500",
                all(v == 201 for v in made.values()), str(made))

        # ------------------------------------------------ no change
        print(f"== control: the UE stays on cell {eci(CELL_A)} for {HOLD_SAMPLES} samples")
        t_hold = time.time()
        held = hold(HOLD_SAMPLES, t_hold)
        step("CONTROL (must FAIL) a notification arrived while the UE stayed on one cell",
             *ctl_any_post(NOTES, t_hold, time.time(),
                           prefix=f"{len(held)} samples on {sorted({eci(serving_ci(r) or 0) for _, r in held})}; "))

        # ------------------------------------------------ step 3: the move A -> B
        print(f"== step 3: the simulated UE moves {eci(CELL_A)} -> {eci(CELL_B)}")
        t3 = time.time()
        ue.set_cell(CELL_B)
        first_b = wait_until(lambda: samples_after(t3, lambda r: serving_ci(r) == CELL_B), 3 * PERIOD_S + 10, 0.2) or []
        prior = [r for ct, r in radio_samples() if first_b and ct < first_b[0][0]]
        step(f"3 trigger: the UE's first sample on cell {eci(CELL_B)} is on the CSE, the one before it on "
             f"{eci(CELL_A)} (registered both times)",
             bool(first_b) and bool(prior) and serving_ci(prior[-1]) == CELL_A,
             f"first sample on B: ct {first_b[0][0] if first_b else None}; sample before it on "
             f"{eci(serving_ci(prior[-1]) or 0) if prior else None}")
        got = wait_until(lambda: [n for n in NOTES if n["t"] >= t3 and n["path"] == base], 15, 0.1) or []
        note = got[0] if got else None
        body = (note or {}).get("body")
        ok_ue = isinstance(body, dict) and body.get("associateId") == [{"type": 1, "value": UE_IP}]
        step(f"4 the RNIS POSTs to the callbackReference a CellChangeNotification naming the UE (associateId type 1 "
             f"= {UE_IP}) for the subscription it was made for",
             len(got) == 1 and isinstance(body, dict) and body.get("notificationType") == "CellChangeNotification"
             and ok_ue and ((body.get("_links") or {}).get("subscription") or {}).get("href") == subs.get("main"),
             f"{len(got)} POST(s) at {base}; associateId {body.get('associateId') if isinstance(body, dict) else None}")
        time.sleep(1.0)        # the send log line is written after the AE's answer
        ok_main, log_main = send_record_ok(read_sendlog(sendlog), subs.get("main"), ok=True, status=204)
        step("5 the AE acknowledges with 204 No Content, and the RNIS records that send as delivered with HTTP 204",
             note is not None and note["status"] == 204 and ok_main,
             f"AE answered {note and note['status']}; RNIS send log for this subscription {log_main}")
        faults = cellchange_faults(body, src_ci=CELL_A, trg_ci=CELL_B, ue=UE_IP, sub_href=subs.get("main"))
        schema_err = None
        try:
            import jsonschema
            jsonschema.validate(body, json.loads(SCHEMA.read_text()))
        except Exception as e:     # a missing jsonschema is a failure here, not a skip
            schema_err = f"{type(e).__name__}: {str(e)[:200]}"
        step("6a content: hoStatus 3, srcEcgi 001/01 " + eci(CELL_A) + ", trgEcgi [001/01 " + eci(CELL_B) + "], "
             "associateId, _links, timeStamp all as expected; valid against the ATS CellChangeNotification schema",
             note is not None and faults == [] and schema_err is None,
             f"wrong fields {faults}; schema {'valid' if schema_err is None else schema_err}")
        lat = latency_s(first_b[0][0], note["t"]) if first_b and note else None
        meas.update(sample_ct=first_b[0][0] if first_b else None,
                    sample_t_ms=first_b[0][1].get("t") if first_b else None,
                    arrival=note["t"] if note else None, latency_s=lat)
        step(f"6b latency from the sample's creation on MN-CSE-A to the notification's arrival at the AE "
             f"<= {LATENCY_BUDGET_S} s (budget stated before the first run)",
             lat is not None and 0 <= lat <= LATENCY_BUDGET_S,
             f"{lat:.3f} s" if lat is not None else "no notification")
        held_b = hold(HOLD_SAMPLES, t3, lambda r: serving_ci(r) == CELL_B)
        step("CONTROL (must FAIL) more than one notification reached the endpoint for the one move",
             *ctl_repeat(NOTES, base, subs, t3, prefix=f"over {len(held_b)} samples on {eci(CELL_B)}: "))
        by, _ = attribute(NOTES, base, subs)
        w = [n for n in by.get("witness", []) if n["t"] >= t3]
        step("the witness subscription (this UE, any cell) got the same move once",
             len(w) == 1 and cellchange_faults(w[0]["body"], src_ci=CELL_A, trg_ci=CELL_B, ue=UE_IP,
                                              sub_href=subs.get("witness")) == [], f"{len(w)}")
        step(f"CONTROL (must FAIL) the subscription filtered to another UE ({OTHER_UE_IP}) got a notification",
             *ctl_got(NOTES, base, "otherue"))
        step(f"CONTROL (must FAIL) the subscription filtered to source cell {eci(CELL_B)} (the move's target) got a "
             "notification", *ctl_got(NOTES, base, "othersrc"))
        f5 = [n for n in NOTES if n["path"] == f"{base}/fail500" and n["t"] >= t3]
        ok5, log5 = send_record_ok(read_sendlog(sendlog), subs.get("fail500"), ok=False, status=500)
        step("the RNIS sent the 500 endpoint its notification; the AE answered 500; the RNIS logged a failed send "
             "with HTTP 500",
             len(f5) == 1 and f5[0]["status"] == 500 and ok5,
             f"POSTs {len(f5)}, answered {[n['status'] for n in f5]}; send log {log5}")
        step("CONTROL (must FAIL) the RNIS counted the AE's 500 answer as a delivered notification",
             *ctl_counted_500(read_sendlog(sendlog), subs.get("fail500")))

        # ------------------------------------------------ detach on B, re-attach on D
        print(f"== control: detach on {eci(CELL_B)}, re-attach on {eci(CELL_D)}")
        pb_before = plmn_info_status(CELL_B)
        t_det = time.time()
        ue.set_attached(False)
        det = hold(2, t_det, lambda r: serving_ci(r) is None)
        pb_off = wait_until(lambda: plmn_info_status(CELL_B) == 404, 5, 0.3)
        step(f"the UE detached for {len(det)} samples and the RNIS saw it (plmn_info for {eci(CELL_B)}: "
             f"{pb_before} before, 404 while detached)", len(det) >= 2 and pb_before == 200 and bool(pb_off),
             f"detached samples without a cell or address: {sum(1 for _, r in det if 'ue_ipv4' not in r)}")
        ue.set_cell(CELL_D)
        t_re = time.time()
        ue.set_attached(True)
        re_ = hold(HOLD_SAMPLES, t_re, lambda r: serving_ci(r) == CELL_D)
        pd = plmn_info_status(CELL_D)
        step(f"the UE re-attached on {eci(CELL_D)} for {len(re_)} samples and the RNIS sees it (plmn_info 200)",
             len(re_) >= HOLD_SAMPLES and pd == 200, f"plmn_info {pd}")
        step("CONTROL (must FAIL) a notification arrived for detach + re-attach on another cell",
             *ctl_any_post(NOTES, t_det, time.time()))

        # ------------------------------------------------ delete, then move D -> C
        print("== control: the AE deletes its subscription, then the UE moves again")
        loc_main = urllib.parse.urljoin(subs["main"], sub_loc["main"])
        st_d = http("DELETE", loc_main)[0]
        st_dg = http("GET", loc_main)[0]
        if st_d == 204:
            deleted.add("main")
        step("the AE deletes its subscription: DELETE 204, then GET 404", (st_d, st_dg) == (204, 404), f"{st_d}/{st_dg}")
        t_del = time.time()
        ue.set_cell(CELL_C)
        wc = wait_until(lambda: [n for n in NOTES if n["t"] >= t_del and n["path"] == f"{base}/witness"], 3 * PERIOD_S + 10, 0.2) or []
        hold(2, t_del, lambda r: serving_ci(r) == CELL_C)
        step(f"the move {eci(CELL_D)} -> {eci(CELL_C)} happened: the witness got it",
             len(wc) == 1 and cellchange_faults(wc[0]["body"], src_ci=CELL_D, trg_ci=CELL_C, ue=UE_IP,
                                               sub_href=subs.get("witness")) == [], f"{len(wc)}")
        step("CONTROL (must FAIL) the deleted subscription's endpoint received a notification after the delete",
             *ctl_after_delete(NOTES, base, t_del))
        by, mis = attribute(NOTES, base, subs)
        step("every POST the AE received belongs to the subscription its path names (path and _links agree)",
             not mis, f"{len(NOTES)} POSTs; misattributed {[(n['path'], n['status']) for n in mis]}")
        meas["counts"] = {k: len(v) for k, v in by.items()}
    except Abort as e:
        aborted = str(e)
    except (Exception, KeyboardInterrupt) as e:
        aborted = f"{type(e).__name__}: {e}"
        traceback.print_exc()
    finally:
        cleanup = {}
        for name, href in subs.items():
            if name not in deleted:
                cleanup["sub " + name] = http("DELETE", urllib.parse.urljoin(href, sub_loc.get(name) or href))[0]
        if rnis is not None:
            rnis.terminate()
            try:
                rnis.wait(timeout=10)
            except subprocess.TimeoutExpired:
                rnis.kill()
                rnis.wait(timeout=5)
            cleanup["rnis exit"] = rnis.returncode
        if log is not None:
            log.close()
        if ue is not None:
            ue.stop()
        cleanup["ae " + APP_RN] = m2m("DELETE", f"{MN_A}/{APP_RN}", APP_ORIG)[0]
        cleanup["ae " + UE_RN] = m2m("DELETE", f"{MN_A}/{UE_RN}", UE_ORIG)[0]
        cleanup["acp " + ACP_RN] = m2m("DELETE", f"{MN_A}/{ACP_RN}", UE_ORIG)[0]
        gone = {p: m2m("GET", f"{MN_A}/{p}", ADMIN)[0] for p in (APP_RN, UE_RN, ACP_RN)}
        if srv is not None:
            srv.shutdown()
            srv.server_close()
        ports = {p: port_open(p) for p in (RNIS_PORT, LISTEN_PORT)}
        cleanup_ok = (all(v == 404 for v in gone.values()) and not any(ports.values())
                      and all(v in (200, 204) for k, v in cleanup.items() if k.startswith(("ae ", "acp ")))
                      and all(v == 204 for k, v in cleanup.items() if k.startswith("sub "))
                      and (rnis is None or "rnis exit" in cleanup))
        print(f"== clean-up: {cleanup}; afterwards GET {gone}; ports open {ports}")
    good = verdict(STEPS, cleanup_ok=cleanup_ok, aborted_at=aborted)
    ctl = [ok for s, ok, _ in STEPS if s.startswith("CONTROL")]
    real = [ok for s, ok, _ in STEPS if not s.startswith("CONTROL")]
    print(f"\n  RESULT: {'PASS' if good else 'FAIL'}  ({sum(real)}/{len(real)} steps; controls {len(ctl)}, all failed as "
          f"they must: {bool(ctl) and not any(ctl)}; clean-up {'clean' if cleanup_ok else 'NOT clean'})"
          + (f"; STOPPED after: {aborted}" if aborted else "") + "  -- SIMULATED UE, one host")
    results.parent.mkdir(parents=True, exist_ok=True)
    results.write_text(json.dumps({
        "test": "TD_MEC_DEV_02", "testplan": TESTPLAN, "runid": runid, "verdict": "PASS" if good else "FAIL",
        "device": "SIMULATED UE (phone/sim_phone.py), fictitious address " + UE_IP, "aborted_at": aborted,
        "steps": [{"step": s, "ok": ok, "detail": d} for s, ok, d in STEPS],
        "measurements": meas,
        "callback": {"oneM2M attribute": "poa (pointOfAccess) of <AE> " + APP_RN + " on MN-CSE-A, read back from the CSE",
                     "endpoint": poa_want, "paths": {"main": base, **{k: f"{base}/{k}" for k in CONTROL_PATHS}}},
        "subscriptions": subs, "notifications": NOTES, "rnis_sendlog": read_sendlog(sendlog),
        "pre_clean": pre_clean, "cleanup": cleanup, "cleanup_after_get": gone, "cleanup_ok": cleanup_ok,
        "does_not_show": DOES_NOT_SHOW, "run_record": run_record(),
    }, indent=1, default=str))
    print(f"  results: {results}")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
