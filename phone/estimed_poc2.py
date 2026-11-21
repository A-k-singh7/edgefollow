#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""TWO-DEVICE ESTIMED PoC (estimed_poc2.py): the Pixel is the VEHICLE (AE `phone`, hands over A -> B), the Nothing
phone is a ROADSIDE SENSOR (AE `rsu`, originator Crsu-NP2A, no mobile service, stays on edge A). Adds to the one-phone PoC:
per-device serving CSE on the IN-AE, the sensor's own subscription S3 that must keep notifying through the vehicle's
handover, and a PoC-level 7.4 swarm step: a context hub on the IN-AE combines DERIVED context only (signal, zone,
Wi-Fi AP count -- never positions) into recommendations; each participant's agent records its own decision; the hub
cannot write into a participant's data (CONTROL: that write must fail). Federated learning (7.3) is still not covered.

2026-10-29 (one PoC, a trigger, measurements, a phone-free mode):
  --device adb|sim  adb = the probe app on the real phones (estimed_poc/run_poc2.sh starts them); sim = sim_phone.py,
                    started here, every record marked simulated -- the PoC's mechanisms without a phone, so it can be
                    re-run after any change (an ACME upgrade). A sim result is never written over a phone result.
  --no-rsu          the vehicle alone (the one-phone PoC is now this, not a second copy)
  trigger (7.2)     the handover runs only when the RADIO AUTHORITY triggers it: a MEC 012 MeasRepUe subscription on
                    the vehicle's cell; a report whose whole RSRP bin is below --rsrp-threshold triggers. The bin is
                    read on the serving link's own scale: LTE `rsrp` TS 36.133, NR nrSCellRsrp TS 38.133 (serving_rsrp).
                    CONTROL: during a hold window no trigger may fire (sim: the signal is set good; adb: the hold
                    threshold is -157 dBm, below any reportable RSRP on either scale -- the phone's own signal cannot be set, so with
                    the phone the trigger is real data against a threshold this script chooses). The vehicle's own
                    agent must accept the hub's recommendation as well: trigger AND acceptance, else no handover.
  S1 on B before    the migrated subscription is created on B BEFORE the stream is re-pointed (it was created after,
                    so the first readings on B were never notified: an 18-19 s gap). --s1-late keeps the old order
                    for an A/B measurement.
  measurements      telemetry pause (CSE ct of the last sample on A -> first live sample on B), notification gap
                    (last S1 on A -> first S1 on B), handover duration (TRIGGERED -> COMPLETED); in the results JSON
                    and on the IN-AE <measurements>.
  fail closed       a failed precondition stops the run (require -> Abort) and an exception is a FAIL row; the
                    results file is always written and an aborted run is never a PASS.

ESTIMED PoC run on ACME, organised by TR-0077 clause 7 (TDE-2026-0052-Estimed_POC, SDS ESTIMED STF685 overview),
with the REAL phone as the vehicle AE. It began as a copy of an earlier phone handover script, with these PoC-level
additions:
  7.1  an IN-AE (estimedIN, on the IN-CSE) is the central application; MEC 013 (zone/AP, no coordinates) and the
       phone's signal strength are written into oneM2M under it ("MEC services integrated with oneM2M services")
  7.2  handover STATES recorded on the IN-AE (ATTACHED -> TRIGGERED -> TARGET_SELECTED -> MIGRATING ->
       SERVING_CHANGED -> COMPLETED); the SERVING MN-CSE recorded before and after; SUBSCRIPTION CONTINUITY: S1 on
       the phone's radio is migrated to edge B with the phone and must keep notifying; S2 is deliberately NOT
       migrated (the control) and must go silent.
  NOT covered: 7.3 federated learning; 7.4 is one rule at PoC level, not a swarm runtime.
This is a demonstration of mechanisms on our candidates + ACME, not a conformance claim.

The original phone_handover docstring follows.
ESTIMED handover with the REAL phone as the device.

The simulated scenario (estimed/scenario.py) moves a vehicle AE with 3 hand-written
samples. Here the device is the phone: its AE `phone` and five containers of real
telemetry move from edge A (MN-CSE-A) to edge B (MN-CSE-B), chosen through MEC 040,
AND the phone's live stream is re-pointed so new readings land on edge B.

Order (make-before-break for the registration, like handover.py):
  1-3  phone is live on A; MEC 013 / MEC 012 (phone-backed) see its real fix and cell
  4-6  MEC 040 lists peers, picks the peer for edge A, peer resolves to a reachable CSE
  7    pause the phone's stream (so the copied history is complete)
  8    rebuild AE + 5 containers on B, replay every contentInstance, verify bit-equal
  9    access policy on B: reader may read, stranger may not
  10   re-point the phone's stream to B; new readings arrive on B
  11   MEC 013 served from B still reports the phone, with a newer fix
  12   release the AE on A (404 afterwards)
  13   IN-CSE still holds both edges

Needs: topology up, demo/mec040.py on :8300; adb + probe app installed (--device adb). Starts/stops its own
mec013_phone (:8401) and mec012_phone (:8402) instances.
"""
from __future__ import annotations

import argparse
import calendar
import hashlib
import json
import secrets
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "estimed"))
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402
import handover as ho  # noqa: E402
import scenario as sc  # noqa: E402

ADB = str(Path.home() / "android-tools/platform-tools/adb")
PY = "/home/edgefollow/edgefollow-lab/.venv/bin/python"
OWNER, READER, AE = "Cphone-DEVC", "CphoneReader", "phone"
CNTS = ("imu", "env", "loc", "radio", "wlan")
A_URL, B_URL = f"{ho.EDGE_A[0]}/{ho.EDGE_A[1]}", f"{ho.EDGE_B[0]}/{ho.EDGE_B[1]}"
STEPS: list[tuple[str, bool, str]] = []
RESULTS_ADB = {True: "/home/edgefollow/estimed-run/estimed_poc_results.json",
               False: "/home/edgefollow/estimed-run/estimed_poc2_results.json"}   # keyed by --no-rsu
SIM_DIR = Path("/home/edgefollow/estimed-run/sim")


class Abort(Exception):
    """A precondition failed: the steps after it would only report its consequences."""


def step(label: str, ok: bool, detail: str = "") -> bool:
    STEPS.append((label, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"\n          {detail}" if detail else ""))
    return ok


def require(label: str, ok: bool, detail: str = "") -> None:
    if not step(label, ok, detail):
        raise Abort(label)


REPO = HERE.parent
RUN_FILES = ("phone/estimed_poc2.py", "phone/estimed_poc.py", "phone/sim_phone.py", "phone/mec012_phone.py",
             "phone/mec013_phone.py", "phone/device_state.py", "phone/onem2m_acp.py", "estimed/handover.py",
             "estimed/scenario.py", "demo/mec040.py", "estimed_poc/orchestrator.py", "estimed_poc/district_app.py",
             "estimed_poc/mec011_district.py")
MAINLINE_MEC011 = "/home/edgefollow/edgefollow/mec011_appsupport/candidate.py"


def run_record() -> dict:
    """What re-runs this result (the rule: "every number from a re-runnable command in the record"): the command,
    where, the commit AND the SHA-256 of every file the run executes (much of it is uncommitted), the ACME version."""
    def git(*a):
        r = subprocess.run(["git", "-C", str(REPO), *a], capture_output=True, text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    files = {f: hashlib.sha256((REPO / f).read_bytes()).hexdigest() for f in RUN_FILES if (REPO / f).exists()}
    if Path(MAINLINE_MEC011).exists():
        files[MAINLINE_MEC011] = hashlib.sha256(Path(MAINLINE_MEC011).read_bytes()).hexdigest()
    try:
        acme = subprocess.run(["/home/edgefollow/estimed-venv/bin/python", "-c",
                               "import importlib.metadata as m; print(m.version('acmecse'))"],
                              capture_output=True, text=True, timeout=20).stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        acme = None
    status = git("status", "--porcelain")
    return {"argv": [sys.executable, *sys.argv], "cwd": os.getcwd(), "commit": git("rev-parse", "HEAD"),
            "uncommitted_paths": None if status is None else len(status.splitlines()),
            "files_sha256": files, "acme": acme, "at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "mec": {"mec013": MEC013_BASE, "mec012": MEC012_BASE, "ue": UE_ADDRESS, "callback": CALLBACK_BASE}}


def finish(path, *, aborted_at: str | None, device: str, measurements: dict | None = None) -> bool:
    """Verdict + results file. PASS only if the run reached its end, every step passed and every control (there must
    be at least one) failed as it must."""
    ctl = [o for s_, o, _ in STEPS if s_.startswith("CONTROL")]
    real = [(s_, o) for s_, o, _ in STEPS if not s_.startswith("CONTROL")]
    ok = sum(1 for _, o in real if o)
    good = aborted_at is None and ok == len(real) and bool(ctl) and not any(ctl)
    print(f"\n  RESULT: {'PASS' if good else 'FAIL'}  ({ok}/{len(real)} steps; controls {len(ctl)}, all failed as they "
          f"must: {bool(ctl) and not any(ctl)})" + (f"; STOPPED after: {aborted_at}" if aborted_at else ""))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({
        "device": device, "verdict": "PASS" if good else "FAIL", "aborted_at": aborted_at,
        "measurements": measurements or {}, "run": run_record(),
        "steps": [{"step": s_, "pass": o, "detail": d} for s_, o, d in STEPS]}, indent=1))
    print(f"  results: {path}")
    return good


def fix_seconds(u) -> int | None:
    """The seconds of a MEC 013 UserInfo's fix time: the spec's timeStamp (GS MEC 013 Table 6.2.2-1) first, then the
    `timestamp` ETSI's ATS schema uses (and a server built from it may send alone); None when neither is there."""
    ts = (u or {}).get("timeStamp") or (u or {}).get("timestamp") if isinstance(u, dict) else None
    return ts.get("seconds") if isinstance(ts, dict) and isinstance(ts.get("seconds"), int) else None


# RSRP reported-value scales a MEC 012 MeasRepUe uses (GS MEC 012: `rsrp` per TS 36.214/36.133; nrSCellRsrp,
# nrBNCellRsrp, nrNCellRsrp "according to mapping table in ETSI TS 138.133"): (highest valid report, upper edge of bin 0).
#   LTE TS 36.133 Table 9.1.4-1: RSRP_00 < -140; RSRP_k (1..96) [-141 + k, -140 + k); RSRP_97 >= -44.
#   NR  TS 38.133 V19.6.0 Table 10.1.6.1-1 (L3 SS-RSRP): RSRP_0 < -156; RSRP_k (1..125) [-157 + k, -156 + k);
#       RSRP_126 >= -31; RSRP_127 = 'Infinity', for network thresholds only, "not for the purpose of measurement
#       reporting" -> not a valid report.
RSRP_SCALES = {"LTE": (97, -140), "NR": (126, -156)}
HOLD_NEVER_DBM = -157.0   # below the lowest bin edge of both scales: a hold window that must never trigger


def rsrp_bin(value, rat: str = "LTE") -> tuple[float, float] | None:
    """[lower, upper) dBm of an RSRP reported value on its RAT's scale; None if the value or RAT is not valid."""
    if rat not in RSRP_SCALES or not isinstance(value, int) or isinstance(value, bool):
        return None
    top, base = RSRP_SCALES[rat]
    if not 0 <= value <= top:
        return None
    return (float("-inf") if value == 0 else base - 1 + value, float("inf") if value == top else base + value)


def decide(rsrp_reported, threshold_dbm: float, rat: str = "LTE") -> bool:
    """Trigger iff the WHOLE bin of a MEC 012 RSRP reported value (on its RAT's scale) lies below the threshold.
    An NR value read with the LTE table is wrong by 16 dB: NR RSRP_41..56 is weak (<= -100 dBm) but reads as LTE
    -100..-84 dBm, a missed handover (test_estimed_poc CONTROL)."""
    b = rsrp_bin(rsrp_reported, rat)
    return b is not None and b[1] <= threshold_dbm


def serving_rsrp(n) -> tuple[str | None, int | None]:
    """(RAT, reported value) of the vehicle's own link in a MEC 012 MeasRepUeNotification: the E-UTRA serving cell's
    `rsrp` when present (in EN-DC the LTE cell is the anchor), else the STRONGEST NR serving cell
    (newRadioMeasInfo[].nrSCs.nrSCellRsrp: the link is weak only if every serving cell is). Neighbours (nrBNCs,
    newRadioMeasNeiInfo) are other cells, never the vehicle's link. (None, None) if there is no valid value."""
    if not isinstance(n, dict):
        return None, None
    lte = n.get("rsrp")
    if rsrp_bin(lte, "LTE") is not None:
        return "LTE", lte
    nr = [((m.get("nrSCs") or {}).get("nrSCellRsrp") if isinstance(m.get("nrSCs"), dict) else None)
          for m in (n.get("newRadioMeasInfo") if isinstance(n.get("newRadioMeasInfo"), list) else [])
          if isinstance(m, dict)]
    nr = [v for v in nr if rsrp_bin(v, "NR") is not None]
    return ("NR", max(nr)) if nr else (None, None)


def accept_mec012(path: str, body, exp: dict) -> bool:
    """A MEC 012 report counts as a trigger input only if it is OUR subscription's: delivered to our unguessable
    callback path (/mec012/<token>), naming our subscription, for the vehicle's cell. MEC 012 notifications carry
    no signature, so the callback URL is the credential; the link and cell bind the report to what we asked for."""
    return (isinstance(body, dict) and body.get("notificationType") == "MeasRepUeNotification"
            and bool(exp.get("token")) and path == f"/mec012/{exp['token']}"
            and ((body.get("_links") or {}).get("subscription") or {}).get("href") == exp.get("sub")
            and (body.get("ecgi") or {}).get("cellId") == exp.get("cell"))


def ae_ours_or_absent(url: str, origin: str) -> tuple[bool, str]:
    """May this run (re)create the AE at url as origin? Only when the name is free (404) or the AE there carries
    origin as its AE-ID: a 409 once counted as success and the vehicle went under another originator's AE.
    Anything unreadable counts as not ours (deep check 2026-10-29)."""
    st, body = ho._req("GET", url, origin)
    if st == 404:
        return True, "free"
    aei = ((body or {}).get("m2m:ae") or {}).get("aei") if st == 200 else None
    return aei == origin, f"GET {st}" + (f", aei {aei!r}" if st == 200 else "")


def users_of(body) -> list:
    """The UserInfo list of a MEC 013 users query, in either shape. GS MEC 013 Table 7.4.3.1-2 answers a UserList
    ({"user": [...]}: what ETSI's ATS validates and our service sends); the spec's own Annex B example and ETSI's
    sandbox wrap it as {"userList": {"user": [...]}} (meep-loc-serv loc-serv.go:2223)."""
    if not isinstance(body, dict):
        return []
    inner = body["userList"] if isinstance(body.get("userList"), dict) else body
    users = inner.get("user")
    return [u for u in users if isinstance(u, dict)] if isinstance(users, list) else []


def vehicle_ecgi(rab, ue: str) -> dict | None:
    """The vehicle's cell (PLMN + cell id) from a MEC 012 RabInfo: the cellUserInfo entry whose ueInfo lists it.

    This, not MEC 013's accessPointId, is the cell: ETSI's sandbox serves a point-of-attachment name as
    accessPointId (meep-loc-serv sbi getNetworkLocation) and answers plmn_info only by app_ins_id (rnis.go)."""
    cells = rab.get("cellUserInfo") if isinstance(rab, dict) else None
    for c in cells if isinstance(cells, list) else []:
        if not isinstance(c, dict):
            continue
        ids = [a for i in (c.get("ueInfo") if isinstance(c.get("ueInfo"), list) else []) if isinstance(i, dict)
               for a in (i.get("associateId") if isinstance(i.get("associateId"), list) else []) if isinstance(a, dict)]
        e = c.get("ecgi") if isinstance(c.get("ecgi"), dict) else {}
        p = e.get("plmn") if isinstance(e.get("plmn"), dict) else {}
        if (any(a.get("value") == ue for a in ids) and isinstance(p.get("mcc"), str) and isinstance(p.get("mnc"), str)
                and isinstance(e.get("cellId"), str) and e["cellId"]):
            return {"plmn": {"mcc": p["mcc"], "mnc": p["mnc"]}, "cellId": e["cellId"]}
    return None


POSITION_KEYS = {"lat", "lon", "lng", "latitude", "longitude", "locationinfo", "position", "positions",
                 "coordinates", "coords", "trajectory", "trajectories", "gps", "geopoint"}
# What the control of the position scan plants on the IN-AE and deletes again: a declared fictitious point, no real
# place (until 2026-11-19 it planted the position of a real one). The scan works by key name and must find it.
SCAN_CONTROL_RECORD = {"fix": {"lat": 0.0, "lon": 0.0, "fictitious": True}}


def scan_positions(o, path: str = "") -> list[str]:
    """Paths of anything that is a position or trajectory, by key (any case, exact name, not substrings: 'below',
    'latency' are fine), looking inside JSON-encoded strings such as a contentInstance's con."""
    hits: list[str] = []
    if isinstance(o, str) and o[:1] in "{[":
        try:
            return scan_positions(json.loads(o), path)
        except ValueError:
            return []
    if isinstance(o, dict):
        for k, v in o.items():
            p = f"{path}.{k}" if path else str(k)
            if str(k).lower() in POSITION_KEYS:
                hits.append(p)
            hits += scan_positions(v, p)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            hits += scan_positions(v, f"{path}[{i}]")
    return hits


HISTORY_RULES = ("all", "latest", "none")
PRIVATE_CNTS = ("loc", "wlan")          # position history and Wi-Fi history


def history_to_copy(cnt: str, instances: list, rule: str) -> list:
    """What a handover copies of one container. Rule "all": everything (the behaviour until 2026-11-19). "latest":
    of the position and Wi-Fi containers only the newest instance. "none": of those two, nothing. The other three
    containers are always copied whole."""
    if rule not in HISTORY_RULES:
        raise ValueError(f"history rule {rule!r} is not one of {HISTORY_RULES}")
    if rule == "all" or cnt not in PRIVATE_CNTS:
        return list(instances)
    return list(instances[-1:]) if rule == "latest" else []


def history_over(history: list[str], found: list[str], allowed: list[str]) -> list[str]:
    """The records on an edge that are part of the source's history and beyond what the rule allows. history: every
    record text the source held when the stream was paused; found: the texts on the edge now; allowed: the texts the
    rule copied (each may be there once). A record posted after the move is not in the history and is not counted."""
    old, left, over = set(history), list(allowed), []
    for con in found:
        if con not in old:
            continue
        if con in left:
            left.remove(con)
        else:
            over.append(con)
    return over


# ---- 2026-11-19: the phone's own sequence numbers, commands, notifications ---------------------------------------
# The probe app numbers every tick (LiveService.seq). The number is in no record of the five containers; the app
# writes it as snr of a <tsi> into <AE>/radioTs when that <timeSeries> exists, with the tick's time as dgt. A sample
# here is (snr, t_ms). The app's counter starts again at 0 when its service is stopped and started, which is how
# this driver moves the stream; the simulated phone's counter does the same since 2026-11-19 (it carried on before).
# seq_account takes both.
TS_RN = "radioTs"
DEFAULT_PERIOD_S = 5
ACK_WAIT_S = 20.0
_DGT = re.compile(r"^(\d{8}T\d{6}),(\d{6})$")


def dgt_ms(dgt) -> int | None:
    """oneM2M dataGenerationTime 'yyyymmddThhmmss,ffffff' (UTC) -> epoch milliseconds; None when it is no such text."""
    m = _DGT.match(dgt) if isinstance(dgt, str) else None
    if not m:
        return None
    try:
        return calendar.timegm(time.strptime(m.group(1), "%Y%m%dT%H%M%S")) * 1000 + int(m.group(2)) // 1000
    except ValueError:
        return None


def samples_of(body) -> tuple[list[tuple[int, int]], int]:
    """(<timeSeries>?rcn=4 body) -> ([(snr, t_ms)] oldest first, how many instances had no usable number or time)."""
    out, bad = [], 0
    ts = body.get("m2m:ts") if isinstance(body, dict) else None
    for x in (ts.get("m2m:tsi") if isinstance(ts, dict) else None) or []:
        snr, t_ms = (x.get("snr"), dgt_ms(x.get("dgt"))) if isinstance(x, dict) else (None, None)
        if isinstance(snr, int) and not isinstance(snr, bool) and t_ms is not None:
            out.append((snr, t_ms))
        else:
            bad += 1
    return sorted(out, key=lambda s: (s[1], s[0])), bad


def seq_account(source: list, target: list, period_s: float) -> dict:
    """Lost and duplicated sequence numbers across the two edges, from the samples each edge holds.

    duplicated: one sample (same number and time) held twice by an edge, or held by both edges.
    lost: a number missing inside an edge's run; with a counter that carried on, the numbers between the source's
    last and the target's first; with a counter that started again at the target, the numbers below its first.
    Not countable (never a clean count): an edge without a sample, or a counter that started again INSIDE an edge.
    The time without a sample between the edges is given in seconds and in periods; it is not a count of losses:
    the stream is stopped for the move and takes no sample then."""
    names = {"source": source, "target": target}
    dup, held = [], {}
    for where, raw in names.items():
        seen, own = set(), []
        for s in sorted(raw, key=lambda s: (s[1], s[0])):
            if s in seen:
                dup.append({"where": where, "snr": s[0]})
            else:
                seen.add(s)
                own.append(s)
        held[where] = own
    at_source = {s[1] for s in held["source"]}
    both = [s for s in held["target"] if s[1] in at_source]
    dup += [{"where": "both edges", "snr": s[0]} for s in both]
    run = {"source": held["source"], "target": [s for s in held["target"] if s[1] not in at_source]}
    lost, restarts = [], []
    inside = {"source": [], "target": []}
    for where, own in run.items():
        for prev, cur in zip(own, own[1:]):
            if cur[0] <= prev[0]:
                restarts.append({"where": where, "after_snr": prev[0]})
            else:
                inside[where] += [{"where": where, "snr": n} for n in range(prev[0] + 1, cur[0])]
    counter = gap_s = None
    edge_lost = []
    if run["source"] and run["target"]:
        last, first = run["source"][-1], run["target"][0]
        gap_s = round((first[1] - last[1]) / 1000, 2)
        if first[0] > last[0]:
            counter = "continued"
            edge_lost = [{"where": "between the edges", "snr": n} for n in range(last[0] + 1, first[0])]
        else:
            counter = "restarted"
            edge_lost = [{"where": "target, at the start", "snr": n} for n in range(0, first[0])]
    lost = inside["source"] + edge_lost + inside["target"]
    return {"countable": bool(run["source"] and run["target"] and not restarts), "counter": counter,
            "source": {"n": len(held["source"]), "first": held["source"][0][0], "last": held["source"][-1][0]} if held["source"] else {"n": 0},
            "target": {"n": len(held["target"]), "first": held["target"][0][0], "last": held["target"][-1][0]} if held["target"] else {"n": 0},
            "lost": lost, "duplicated": dup, "restarts": restarts, "gap_s": gap_s,
            "gap_periods": round(gap_s / period_s, 2) if gap_s is not None and period_s else None}


def records_per_sample(samples: list, recs: dict) -> list[dict]:
    """Every (sample, container) that does not have exactly ONE record carrying the sample's time. recs: container ->
    the t of each record on the sample's own edge. A record of a time that has no number (copied history, a tick
    before the <timeSeries> existed) is not counted against any sample."""
    out = []
    for snr, t_ms in samples:
        for c in CNTS:
            n = list(recs.get(c, [])).count(t_ms)
            if n != 1:
                out.append({"snr": snr, "cnt": c, "records": n})
    return out


def ack_of(acks: list, cmd_id):
    """The acknowledgement that carries this command's id, or None. Nothing else makes an acknowledgement ours."""
    if cmd_id is None:
        return None
    return next((x for x in acks if isinstance(x, dict) and x.get("id") == cmd_id), None)


def notified(record_ts: list, note_ts: list) -> dict:
    """Notifications against the records they are about, by the record's time: lost = a record never notified,
    duplicated = notified more than once, unknown = a notification for a record that is not in the list."""
    return {"records": len(record_ts), "notifications": len(note_ts),
            "lost": [t_ for t_ in record_ts if note_ts.count(t_) == 0],
            "duplicated": [t_ for t_ in record_ts if note_ts.count(t_) > 1],
            "unknown": list(dict.fromkeys(t_ for t_ in note_ts if t_ not in record_ts))}


def audit_devices(record: dict, where: dict) -> list[str]:
    """Devices whose registry entry is not the ONE CSE their AE exists on (wrong edge, on two edges, or nowhere)."""
    return sorted(d for d, cse in record.items() if where.get(d, set()) != {cse})


def ct_epoch(ct: str) -> float:
    """A oneM2M creation time (UTC 'YYYYMMDDTHHMMSS[,ffffff]') as epoch seconds."""
    base, _, frac = ct.partition(",")
    return calendar.timegm(time.strptime(base, "%Y%m%dT%H%M%S")) + (float("0." + frac) if frac else 0.0)


IN = ("http://127.0.0.1:8200", "cse-in")
IN_AE, IN_ORIGIN = "estimedIN", "CestimedIN"
IN_CSI = "id-in"           # the IN-CSE's CSE-ID: a request it forwards carries From = /id-in/<originator>
# What the central IN-AE may read of the vehicle on edge B, through the IN: its signal, never its positions, Wi-Fi
# or motion (the data-sources rule: positions never reach the city). One policy on all five containers once
# let the city read loc and wlan (deep check 2026-10-29).
CITY_READS = ("radio",)


def edge_b_acr(city: bool) -> list[dict]:
    """The vehicle's read policy on edge B: phone/onem2m_acp.py's reader and owner, plus the IN-AE (as the IN-CSE
    forwards it: SP-relative "/id-in/CestimedIN", TS-0004 7.3.2.6) only on a container in CITY_READS."""
    acr = [{"acor": [READER], "acop": 34}, {"acor": [OWNER], "acop": 63}]
    return acr + ([{"acor": [f"/{IN_CSI}/{IN_ORIGIN}"], "acop": 34}] if city else [])
LISTEN = 8450  # the lab's notification range is loopback 8400-8499
NOTES: list[tuple[str, float, bool]] = []  # (path, time, carries a contentInstance)
MEC12: list[tuple[float, object, object, object]] = []  # ACCEPTED MEC 012 MeasRepUe: (time, RAT, serving RSRP value, cellId)
MEC12_REJ: list[tuple[float, str]] = []         # refused reports: (time, path) -- not ours (accept_mec012)
EXP12: dict = {}                                # token, subscription href, cell of OUR subscription
NOTE_RECS: list[tuple[str, float, object]] = []  # (path, time, the t of the notified record) of each data notification
SUBS: list[tuple[str, str]] = []                # (resource URL, originator) of each oneM2M subscription this run created

# Where this run reaches MEC, and where MEC reaches this run. The defaults are the phone-backed services this script
# starts on this host. Against another MEC platform (ETSI's sandbox serves its APIs under <host>/<sandbox>/<mep>/) give
# its MEC 013 and MEC 012 bases, the vehicle's address as THAT platform knows it, and a callback origin it can reach
# that forwards to this host's listener; the listener itself always binds loopback (B3, 2026-10-29).
LOCAL_MEC013, LOCAL_MEC012 = "http://127.0.0.1:8401/location/v3", "http://127.0.0.1:8402/rni/v2"


def _port_held(port: int) -> bool:
    import socket
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def stale_service_ports(held=None) -> list[int]:
    """The ports of our phone-backed MEC 013 (:8401) / MEC 012 (:8402) that something already holds, for the services
    this run starts itself. A leftover instance from a killed run answers instead of the run's own one (which then
    cannot bind and exits unseen) and never follows the move: "MEC 013 now sourced from edge B" failed that way on
    2026-11-20. A run must not start while one is held."""
    held = held or _port_held
    mine = [port for base, local, port in ((MEC013_BASE, LOCAL_MEC013, 8401), (MEC012_BASE, LOCAL_MEC012, 8402))
            if base == local]
    return [port for port in mine if held(port)]
MEC013_BASE, MEC012_BASE = LOCAL_MEC013, LOCAL_MEC012
MEC12_SUBS = f"{MEC012_BASE}/subscriptions"     # where OUR MEC 012 subscription is created
UE_ADDRESS = ds.PHONE_ADDRESS                   # the vehicle as MEC 013 names it (an acr: URI)
CALLBACK_BASE = f"http://127.0.0.1:{LISTEN}"


def _http_base(url: str, what: str) -> str:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.netloc or u.query or u.fragment:
        raise ValueError(f"{what} must be an http(s) URL, got {url!r}")
    return url.rstrip("/")


def configure(mec013: str | None = None, mec012: str | None = None, ue: str | None = None,
              callback: str | None = None) -> None:
    """Point the run at a MEC platform; None keeps the local default. The callback is an origin only
    (scheme://host[:port]): the listener matches the path /mec012/<token> exactly, so a proxy prefix would make
    every genuine report look forged."""
    global MEC013_BASE, MEC012_BASE, MEC12_SUBS, UE_ADDRESS, CALLBACK_BASE
    cb = _http_base(callback, "the callback base") if callback is not None else f"http://127.0.0.1:{LISTEN}"
    if urllib.parse.urlsplit(cb).path:
        raise ValueError(f"the callback base must be an origin without a path, got {callback!r}")
    MEC013_BASE = _http_base(mec013, "the MEC 013 base") if mec013 else LOCAL_MEC013
    MEC012_BASE = _http_base(mec012, "the MEC 012 base") if mec012 else LOCAL_MEC012
    MEC12_SUBS, UE_ADDRESS, CALLBACK_BASE = f"{MEC012_BASE}/subscriptions", ue or ds.PHONE_ADDRESS, cb


def users_url() -> str:
    return f"{MEC013_BASE}/queries/users?" + urllib.parse.urlencode({"address": UE_ADDRESS})


def mec012_ue() -> str:
    """The vehicle as MEC 012 names it: an associateId value is a bare address, the MEC 013 address without its
    acr: scheme (ETSI's own fixtures pair MEC 013 acr:10.0.0.1 with MEC 012 associateId 10.0.0.1)."""
    return UE_ADDRESS.removeprefix("acr:")


def callback_url(token: str) -> str:
    return f"{CALLBACK_BASE}/mec012/{token}"


MAX_BODY = 64 * 1024     # a notification is a few hundred bytes; anything above is refused, never read


class _Notify(BaseHTTPRequestHandler):
    timeout = 5          # per-connection socket timeout: a stalled client is dropped, never waited for

    def do_POST(self):  # noqa: N802
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= MAX_BODY:
            self.send_response(413 if n > MAX_BODY else 400)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        body = self.rfile.read(n)
        if self.path.startswith("/mec012"):
            try:
                n = json.loads(body or b"{}")
            except ValueError:
                n = None
            if accept_mec012(self.path, n, EXP12):
                MEC12.append((time.time(), *serving_rsrp(n), (n.get("ecgi") or {}).get("cellId")))
            else:
                MEC12_REJ.append((time.time(), self.path))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        try:
            sgn = json.loads(body or b"{}").get("m2m:sgn", {})
        except ValueError:
            sgn = {}
        rep = sgn.get("nev", {}).get("rep", {}) if isinstance(sgn.get("nev"), dict) else {}
        if not sgn.get("vrq"):
            NOTES.append((self.path, time.time(), "m2m:cin" in rep))
            if "m2m:cin" in rep:
                NOTE_RECS.append((self.path, time.time(), (record_ts([rep["m2m:cin"]]) or [None])[0]))
        self.send_response(200)
        self.send_header("X-M2M-RSC", "2000")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def make_listener(port: int = LISTEN) -> HTTPServer:
    """One thread per connection (a slow or stalled client cannot hold up a real report), daemon threads."""
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Notify)
    srv.daemon_threads = True
    return srv


def in_put(cnt: str, value: dict) -> int:
    return ho._req("POST", f"{IN[0]}/{IN[1]}/{IN_AE}/{cnt}", IN_ORIGIN, ty=4,
                   body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(value, sort_keys=True)}})[0]


def in_all(cnt: str) -> list[dict]:
    st, b = ho._req("GET", f"{IN[0]}/{IN[1]}/{IN_AE}/{cnt}?rcn=4", IN_ORIGIN)
    return [json.loads(c["con"]) for c in sorted(b.get("m2m:cnt", {}).get("m2m:cin", []), key=lambda c: c["ct"])] if st == 200 else []


RSU, RSU_ORIGIN = "rsu", "Crsu-NP2A"


def _created(st: int, url: str, origin: str) -> int:
    if st == 201:
        SUBS.append((url, origin))
    return st


def rsu_subscribe(rn: str, cnt: str = "imu") -> int:
    url = f"{A_URL}/{RSU}/{cnt}"
    return _created(ho._req("POST", url, RSU_ORIGIN, ty=23, body={"m2m:sub": {
        "rn": rn, "nu": [f"http://127.0.0.1:{LISTEN}/{rn}"], "enc": {"net": [3]}, "nct": 1}})[0], f"{url}/{rn}", RSU_ORIGIN)


def rsu_latest(cnt: str):
    st, b = ho._req("GET", f"{A_URL}/{RSU}/{cnt}/la", RSU_ORIGIN)
    if st != 200:
        return None
    con = b["m2m:cin"]["con"]
    return json.loads(con) if isinstance(con, str) else con


def count_items(o) -> int:
    """Largest list length in a telemetry record (e.g. Wi-Fi APs seen): derived metadata, no positions."""
    best = 0
    if isinstance(o, dict):
        for v in o.values():
            best = max(best, count_items(v))
    elif isinstance(o, list):
        best = max([len(o)] + [count_items(v) for v in o[:8]])
    return best


def subscribe(edge, rn: str) -> int:
    url = f"{edge[0]}/{edge[1]}/{AE}/radio"
    return _created(ho._req("POST", url, OWNER, ty=23, body={"m2m:sub": {
        "rn": rn, "nu": [f"http://127.0.0.1:{LISTEN}/{rn}"], "enc": {"net": [3]}, "nct": 1}})[0], f"{url}/{rn}", OWNER)


def cleanup_subscriptions(req=None, http=None) -> dict:
    """DELETE every subscription this run created -- the oneM2M ones it recorded (newest first, each with its own
    originator) and OUR MEC 012 one by its _links.self.href -- so nothing notifies this run's listener after it is gone
    (deep check 2026-10-29: they were left behind). {resource: status, or 'error: ...'}; never raises."""
    req, http = req or ho._req, http or http_json
    out = {}
    for url, origin in reversed(SUBS):
        key = url.split("/", 3)[-1]
        try:
            out[key] = req("DELETE", url, origin)[0]
        except Exception as e:  # noqa: BLE001 -- one failed DELETE must not stop the rest
            out[key] = f"error: {type(e).__name__}"
    SUBS.clear()
    if EXP12.get("sub"):
        try:
            # the href may be relative (our MEC 012 answers /rni/v2/subscriptions/<id>): resolve it where it was created
            out["mec012 " + EXP12["sub"].rsplit("/", 1)[-1]] = http("DELETE", urllib.parse.urljoin(MEC12_SUBS, EXP12["sub"]))[0]
        except Exception as e:  # noqa: BLE001
            out["mec012 " + EXP12["sub"].rsplit("/", 1)[-1]] = f"error: {type(e).__name__}"
    return out


def signal_fields(con) -> dict:
    """Signal-strength numbers from the phone's radio telemetry (no position data is in this container)."""
    out = {}
    def walk(o, p=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{p}.{k}" if p else k)
        elif isinstance(o, list):
            for i, v in enumerate(o[:4]):
                walk(v, f"{p}[{i}]")
        elif isinstance(o, (int, float)) and abs(o) < 2147483647 and any(t in p.lower() for t in ("rsrp", "rsrq", "rssi", "dbm", "sinr")):
            out[p] = o
    walk(json.loads(con) if isinstance(con, str) else con)
    return out


def adb_live(cse: str | None, period: int = DEFAULT_PERIOD_S) -> None:
    base = [ADB, "shell", "am", "start", "-n", "org.edgefollow.probe/.Main"]
    if cse is None:
        subprocess.run(base + ["-e", "mode", "live-stop"], capture_output=True, timeout=20)
    else:
        subprocess.run(base + ["-e", "mode", "live", "-e", "cse", cse, "-e", "origin", OWNER,
                               "--ei", "period", str(int(period))], capture_output=True, timeout=20)


class AdbDevice:
    """The probe app on the real phone, commanded over adb (ANDROID_SERIAL picks the phone)."""
    kind, word, period = "adb", "real", 5.0

    def live(self, cse: str) -> None:
        adb_live(cse, int(self.period))      # a newly started service takes its period from here, not from a command

    def stop(self) -> None:
        adb_live(None)

    def set_signal(self, rsrp: int) -> None:
        raise NotImplementedError("a real radio cannot be told its signal")


class SimDevice:
    """sim_phone.SimPhone behind the same interface; every record it posts is marked simulated."""
    kind, word = "sim", "simulated"

    def __init__(self, phone):
        self.ph = phone
        self.period = phone.period

    def live(self, cse: str) -> None:
        self.ph.live(cse)

    def stop(self) -> None:
        self.ph.stop()

    def set_signal(self, rsrp: int) -> None:
        self.ph.set_signal(rsrp)


def cins(edge, cnt: str) -> list[dict]:
    """Every contentInstance (con + ct), oldest first."""
    st, body = ho._req("GET", f"{edge[0]}/{edge[1]}/{AE}/{cnt}?rcn=4", OWNER)
    if st != 200:
        return []
    return sorted(body.get("m2m:cnt", {}).get("m2m:cin", []), key=lambda c: c["ct"])


def record_ts(instances: list) -> list:
    """The t of each record (a contentInstance whose con is the app's JSON); a record without one gives None."""
    out = []
    for c in instances:
        con = c.get("con") if isinstance(c, dict) else None
        try:
            con = json.loads(con) if isinstance(con, str) else con
        except ValueError:
            con = None
        out.append(con.get("t") if isinstance(con, dict) else None)
    return out


def make_ts(url: str) -> int:
    """A fresh, empty <timeSeries> radioTs under the vehicle's AE (owner only: it is given no access policy)."""
    ho._req("DELETE", f"{url}/{AE}/{TS_RN}", OWNER)
    return ho._req("POST", f"{url}/{AE}", OWNER, ty=29, body={"m2m:ts": {"rn": TS_RN, "mni": 5000}})[0]


def read_samples(url: str) -> tuple[list, int]:
    st, body = ho._req("GET", f"{url}/{AE}/{TS_RN}?rcn=4", OWNER)
    return samples_of(body) if st == 200 else ([], 0)


def post_cmd(url: str, cmd: dict) -> int:
    """A downlink command into the vehicle's <cmd>, as the vehicle's owner (no other party is given that right)."""
    return ho._req("POST", f"{url}/{AE}/cmd", OWNER, ty=4,
                   body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(cmd)}})[0]


def read_acks(url: str) -> list:
    st, body = ho._req("GET", f"{url}/{AE}/ack?rcn=4", OWNER)
    out = []
    for c in ((body or {}).get("m2m:cnt", {}).get("m2m:cin", []) if st == 200 else []):
        try:
            out.append(json.loads(c["con"]) if isinstance(c.get("con"), str) else c.get("con"))
        except ValueError:
            pass
    return out


def send_cmd(url: str, cmd: dict, wait_s: float = ACK_WAIT_S) -> tuple[int, dict | None, float]:
    """Post the command at this edge and wait for the phone's acknowledgement in the SAME edge's <ack>.
    (HTTP status of the post, the acknowledgement or None, seconds waited)."""
    t0, ack = time.time(), None
    st = post_cmd(url, cmd)
    while st == 201 and ack is None and time.time() - t0 < wait_s:
        ack = ack_of(read_acks(url), cmd["id"])
        if ack is None:
            time.sleep(0.5)
    return st, ack, time.time() - t0


def period_arg(text: str) -> int:
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("a whole number of seconds") from None
    if not 1 <= v <= 60:
        raise argparse.ArgumentTypeError("1..60 s, the range the probe app takes")
    return v


def cni(edge, cnt: str) -> int:
    st, body = ho._req("GET", f"{edge[0]}/{edge[1]}/{AE}/{cnt}", OWNER)
    return body["m2m:cnt"].get("cni", 0) if st == 200 else -1


def get_json(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def http_json(method: str, url: str, body=None) -> tuple[int, dict]:
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                               headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=5) as x:
            raw = x.read()
            return x.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {}


def served_user(timeout_s: float = 20) -> dict | None:
    """The vehicle as MEC 013 serves it, or None if it is not served within timeout_s."""
    t_end = time.time() + timeout_s
    while time.time() < t_end:
        try:
            users = users_of(get_json(users_url()))
            if users:
                return users[0]
        except Exception:
            pass
        time.sleep(1)
    return None


def listening(port: int, timeout_s: float) -> bool:
    """True once 127.0.0.1:port accepts a TCP connection, within timeout_s: a service this run has just started.
    AB_11 (2026-10-29): the PLMN query reached mec012_phone before it listened (host load 9.3) and the run failed a
    setup step that had nothing to do with the phone. Readiness only: the query itself is still asked once."""
    t_end = time.time() + timeout_s
    while True:
        with socket.socket() as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        if time.time() >= t_end:
            return False
        time.sleep(0.2)


def wait_cni(edge, ae: str, origin: str, cnt: str, at_least: int, timeout_s: float) -> int:
    t_end, n = time.time() + timeout_s, -1
    while time.time() < t_end:
        st, b = ho._req("GET", f"{edge[0]}/{edge[1]}/{ae}/{cnt}", origin)
        n = (b or {}).get("m2m:cnt", {}).get("cni", 0) if st == 200 else -1
        if n >= at_least:
            return n
        time.sleep(1)
    return n


def sim_setup(rsu: bool) -> dict:
    """Start the simulated vehicle (and sensor) on edge A, as run_poc*.sh does for the phones, then the reader's
    access policy (onem2m_acp.py, the same script the phone runs use)."""
    import sim_phone
    for e in (ho.EDGE_A, ho.EDGE_B):
        ho.delete_ae(e, ae=AE, origin=OWNER)
    devs = {"phone": SimDevice(sim_phone.SimPhone(A_URL, OWNER, AE, period=5.0, rsrp=-85, rsrq=-7))}
    if rsu:
        for e in (ho.EDGE_A, ho.EDGE_B):
            ho.delete_ae(e, ae=RSU, origin=RSU_ORIGIN)
        devs["rsu"] = SimDevice(sim_phone.SimPhone(A_URL, RSU_ORIGIN, RSU, period=5.0, cellular=False, wifi_aps=24,
                                                   lat=48.1349, lon=11.5815))
    for d in devs.values():
        d.live(A_URL)
    n = wait_cni(ho.EDGE_A, AE, OWNER, "radio", 2, 30)
    nr = wait_cni(ho.EDGE_A, RSU, RSU_ORIGIN, "imu", 2, 30) if rsu else 2
    acp = subprocess.run([PY, str(HERE / "onem2m_acp.py")], capture_output=True, text=True, timeout=60)
    require("simulated vehicle" + (" and sensor" if rsu else "") + " posting on edge A, reader policy set (onem2m_acp.py)",
            n >= 2 and nr >= 2 and acp.returncode == 0,
            f"vehicle radio {n}, sensor imu {nr if rsu else '-'}; onem2m_acp rc {acp.returncode}")
    return devs


def parse(argv):
    ap = argparse.ArgumentParser(description="ESTIMED PoC (TR-0077 clause 7) on the local oneM2M + MEC lab")
    ap.add_argument("--device", choices=("adb", "sim"), default="adb")
    ap.add_argument("--no-rsu", action="store_true", help="the vehicle alone (PoC 1)")
    ap.add_argument("--rsrp-threshold", type=float, default=-100.0, help="dBm; MEC 012 trigger threshold")
    ap.add_argument("--sim-low-rsrp", type=int, default=-110, help="dBm the simulated vehicle drops to (sim only)")
    ap.add_argument("--hold-s", type=float, default=12.0, help="seconds of the no-trigger hold window (control)")
    ap.add_argument("--s1-late", action="store_true", help="old order: S1 on B after the re-point (A/B measurement)")
    ap.add_argument("--handover-max-s", type=float, default=60.0, help="bound on trigger -> COMPLETED (ours)")
    ap.add_argument("--history-rule", choices=HISTORY_RULES, default="all",
                    help="what the handover copies of the position and Wi-Fi history: all (default), latest, none")
    ap.add_argument("--period", type=period_arg, default=DEFAULT_PERIOD_S,
                    help="seconds between the vehicle's samples (default 5). Another value is set through the phone's "
                         "own period command at edge A and put back at the end")
    ap.add_argument("--results", help="results JSON (default: the phone file for adb, a timestamped file for sim)")
    ap.add_argument("--mec013-base", help=f"MEC 013 API base of another platform (default: this host's {LOCAL_MEC013})")
    ap.add_argument("--mec012-base", help=f"MEC 012 API base of another platform (default: this host's {LOCAL_MEC012})")
    ap.add_argument("--ue-address", help="the vehicle's MEC 013 address on that platform (default: the phone's)")
    ap.add_argument("--callback-base", help=f"origin that platform POSTs MEC 012 reports to; it must forward to "
                    f"127.0.0.1:{LISTEN}, which is all the listener binds (default: the listener itself)")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    a = parse(argv)
    try:
        configure(a.mec013_base, a.mec012_base, a.ue_address, a.callback_base)
    except ValueError as e:
        print(f"refused: {e}")
        return 2
    rsu = not a.no_rsu
    if a.results:
        results = a.results
    elif a.device == "adb":
        results = RESULTS_ADB[a.no_rsu]
    else:
        results = str(SIM_DIR / f"estimed_poc{'' if a.no_rsu else '2'}_sim_{time.strftime('%Y%m%dT%H%M%S')}.json")
    if a.device == "sim" and Path(results).resolve() in {Path(p).resolve() for p in RESULTS_ADB.values()}:
        print("refused: a simulated run never writes over a phone result")
        return 2
    stale = stale_service_ports(lambda port: _port_held(port))
    if stale:
        print(f"PRECONDITION: port(s) {stale} already held. This run starts its own phone-backed MEC services there; a "
              f"leftover instance would answer instead and never follow the move. Stop it first.")
        return 2
    try:
        urllib.request.urlopen(f"{sc.FED_BASE}/fed_resources/systems", timeout=3).close()
    except urllib.error.HTTPError:
        pass
    except Exception as e:
        print(f"PRECONDITION: MEC 040 not reachable at {sc.FED_BASE} ({e}); start demo/mec040.py")
        return 2
    print(f"== device: {a.device}{'' if rsu else ' (vehicle only)'}; trigger threshold {a.rsrp_threshold} dBm; "
          f"period {a.period} s")
    STEPS.clear()
    NOTES.clear()
    NOTE_RECS.clear()
    MEC12.clear()
    MEC12_REJ.clear()
    EXP12.clear()
    devs: dict = {}
    procs: list[subprocess.Popen] = []
    meas: dict = {"device": a.device, "s1_order": "late (old)" if a.s1_late else "before the re-point"}
    aborted = None
    srv = None
    try:
        if a.device == "sim":
            devs = sim_setup(rsu)
        else:
            devs = {"phone": AdbDevice()}
        dev = devs["phone"]
        print("== phone live on edge A")
        la = cins(ho.EDGE_A, "radio")
        st, _ = ho._req("GET", f"{A_URL}/{AE}/radio/la", OWNER)
        require(f"phone AE live on edge A with {dev.word} telemetry", st == 200 and len(la) > 0,
                f"radio instances on A: {len(la)}, latest ct {la[-1]['ct'] if la else None}")

        print("== the phone's own sequence numbers")
        st_ts = make_ts(A_URL)
        ts_r = (ho._req("GET", f"{A_URL}/{AE}/{TS_RN}", READER)[0], ho._req("GET", f"{A_URL}/{AE}/{TS_RN}", "Cstranger")[0])
        step("a <timeSeries> radioTs under the vehicle's AE on edge A takes the phone's sequence numbers; owner only "
             "(reader 403, stranger 403)", st_ts == 201 and ts_r == (403, 403), f"create HTTP {st_ts}; reader/stranger {ts_r}")
        if a.period != DEFAULT_PERIOD_S:
            st_c, ack, took = send_cmd(A_URL, {"cmd": "period", "value": a.period, "id": secrets.token_hex(4)})
            require(f"the sampling period is set to {a.period} s through the phone's own command at edge A, acknowledged",
                    st_c == 201 and isinstance(ack, dict) and ack.get("ok") is True and ack.get("period") == a.period,
                    f"POST HTTP {st_c}; acknowledgement after {took:.1f} s: {ack}")
            dev.period = float(a.period)

        print("== 7.1 central IN-AE on the IN-CSE, and the subscriptions on the phone's data")
        srv = make_listener()
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        ho._req("DELETE", f"{IN[0]}/{IN[1]}/{IN_AE}", IN_ORIGIN)
        ho.release_lock(origin=OWNER)                      # a handover transaction an aborted run left open
        st, _ = ho._req("POST", f"{IN[0]}/{IN[1]}", IN_ORIGIN, ty=ho.TY_AE,
                        body={"m2m:ae": {"rn": IN_AE, "api": "Nestimed.poc", "rr": False, "srv": ["4"]}})
        made = [ho._req("POST", f"{IN[0]}/{IN[1]}/{IN_AE}", IN_ORIGIN, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": c}})[0]
                for c in ("handover", "servingCSE", "mecLocation", "mecSignal")]
        require("7.1 central IN-AE registered on the IN-CSE with its 4 containers", st == 201 and made == [201] * 4,
                f"AE {st}, cnt {made}")
        in_put("handover", {"state": "ATTACHED", "cse": ho.EDGE_A[1]})
        for c in ("devices", "swarm", "decisions", "measurements"):
            ho._req("POST", f"{IN[0]}/{IN[1]}/{IN_AE}", IN_ORIGIN, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": c}})
        s3 = None
        if rsu:
            print(f"== roadside sensor ({'Nothing phone' if a.device == 'adb' else 'simulated'}) on edge A")
            rs, _ = ho._req("GET", f"{A_URL}/{RSU}", RSU_ORIGIN)
            rcnts = {c: ho._req("GET", f"{A_URL}/{RSU}/{c}", RSU_ORIGIN)[1].get("m2m:cnt", {}).get("cni", 0) for c in CNTS}
            require("roadside sensor AE live on edge A (second device, own originator)", rs == 200 and rcnts.get("imu", 0) > 0,
                    f"AE {rs}; instances {rcnts}")
            acpr = {"m2m:acp": {"rn": "rsuReadAcp", "pv": {"acr": [{"acor": [READER], "acop": 34}, {"acor": [RSU_ORIGIN], "acop": 63}]},
                                "pvs": {"acr": [{"acor": [RSU_ORIGIN], "acop": 63}]}}}
            st_a, b_a = ho._req("POST", A_URL, RSU_ORIGIN, ty=1, body=acpr)
            if st_a != 201:   # reset, never reuse (see B's policy below)
                st_a, b_a = ho._req("PUT", f"{A_URL}/rsuReadAcp", RSU_ORIGIN,
                                    body={"m2m:acp": {"pv": acpr["m2m:acp"]["pv"], "pvs": acpr["m2m:acp"]["pvs"]}})
            rri = b_a["m2m:acp"]["ri"]
            ho._req("PUT", f"{A_URL}/{RSU}", RSU_ORIGIN, body={"m2m:ae": {"acpi": [rri]}})
            for c in CNTS:
                ho._req("PUT", f"{A_URL}/{RSU}/{c}", RSU_ORIGIN, body={"m2m:cnt": {"acpi": [rri]}})
            r1, r2 = ho._req("GET", f"{A_URL}/{RSU}/imu/la", READER)[0], ho._req("GET", f"{A_URL}/{RSU}/imu/la", "Cstranger")[0]
            step("sensor access policy on A: reader 200, stranger 403", r1 == 200 and r2 == 403, f"{r1}/{r2}")
            s3 = rsu_subscribe("estimedS3")
        in_put("devices", {"phone": ho.EDGE_A[1], **({"rsu": ho.EDGE_A[1]} if rsu else {})})
        in_put("servingCSE", {"cse": ho.EDGE_A[1]})
        s1, s2 = subscribe(ho.EDGE_A, "estimedS1"), subscribe(ho.EDGE_A, "estimedS2")
        t_sub = time.time()
        for _ in range(25):
            time.sleep(1)
            if all(any(p == f"/{n}" and c for p, _t, c in NOTES) for n in ("estimedS1", "estimedS2")):
                break
        pre = {n: sum(1 for p, _t, c in NOTES if p == f"/{n}" and c) for n in ("estimedS1", "estimedS2")}
        if rsu:
            for _ in range(15):
                if any(p == "/estimedS3" and c for p, _t, c in NOTES):
                    break
                time.sleep(1)
            step("sensor subscription S3 notifying", s3 == 201 and any(p == "/estimedS3" and c for p, _t, c in NOTES), f"create {s3}")
        require("7.2 two subscriptions on the phone's radio data on edge A, both notifying", s1 == 201 and s2 == 201 and min(pre.values()) >= 1,
                f"create {s1}/{s2}; notifications S1 {pre['estimedS1']}, S2 {pre['estimedS2']} in {time.time() - t_sub:.0f} s")

        local13, local12 = MEC013_BASE == LOCAL_MEC013, MEC012_BASE == LOCAL_MEC012
        mec13 = None
        if local13:                                  # our phone-backed services; another platform runs its own
            mec13 = subprocess.Popen([PY, str(HERE / "mec013_phone.py")], env=dict(os.environ, PHONE_CSE=A_URL),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(mec13)
        if local12:
            procs.append(subprocess.Popen([PY, str(HERE / "mec012_phone.py")], env=dict(os.environ, PHONE_CSE=A_URL),
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        u = served_user(20)
        if local13:                                  # our instance must still be alive 2 s later: a leftover on
            t_alive = time.time()                    # :8401 makes it exit once it fails to bind (seen: ~0.5 s)
            while time.time() - t_alive < 2 and mec13.poll() is None:
                time.sleep(0.2)
            require("our own MEC 013 instance is still running 2 s after its first answer", mec13.poll() is None,
                    f"exit code {mec13.poll()}")
        acc = ((u or {}).get("locationInfo") or {}).get("accuracy")
        fresh = fix_seconds(u) is not None and time.time() - fix_seconds(u) <= 60
        # Our MEC 013 serves the phone's TAC as zoneId, its ECI as accessPointId and a fix with accuracy; another
        # platform names its own zones and points of attachment and may send no accuracy (ETSI's sandbox does not).
        ours = str((u or {}).get("zoneId", "")).startswith("tac") and len(str((u or {}).get("accessPointId", ""))) == 7 \
            and isinstance(acc, int) and acc > 0
        require(f"MEC 013 reports the {'phone (' + dev.word + ' fix + serving cell)' if local13 else 'vehicle (zone + access point)'}",
                bool(u) and fresh and (ours if local13 else bool(u.get("zoneId")) and bool(u.get("accessPointId"))),
                f"{MEC013_BASE}: zone={u and u.get('zoneId')} ap={u and u.get('accessPointId')} accuracy={acc} m "
                f"({u and u.get('contextLocationInfo')}); fix fresh (<= 60 s): {fresh}")
        if local12 and not listening(8402, 20):      # started above; served_user only waited for MEC 013
            print("          MEC 012 (:8402) was not listening within 20 s")
        ue12 = mec012_ue()
        try:
            rab = get_json(f"{MEC012_BASE}/queries/rab_info?" + urllib.parse.urlencode({"ue_ipv4_address": ue12}))
        except Exception as e:
            rab = None
            print(f"          MEC 012 rab_info: {e}")
        ecgi = vehicle_ecgi(rab, ue12)
        require(f"MEC 012 reports the vehicle's {dev.word} cell (PLMN + cell id) for its address",
                ecgi is not None, f"{MEC012_BASE}: ue {ue12} -> ecgi {ecgi}")
        mloc = {"zoneId": u["zoneId"], "accessPointId": u["accessPointId"], "accuracy_m": acc,
                "t": fix_seconds(u), "source": "MEC 013 via edge A" if local13 else f"MEC 013 at {MEC013_BASE}"}
        sig = signal_fields(cins(ho.EDGE_A, "radio")[-1]["con"])
        ok_l, ok_s = in_put("mecLocation", mloc), in_put("mecSignal", {"plmn": ecgi["plmn"], "cell": ecgi["cellId"], **sig})
        step("7.1 MEC 013 location + the phone's signal strength written into oneM2M under the IN-AE",
             ok_l == 201 and ok_s == 201 and bool(sig), f"zone {mloc['zoneId']} ap {mloc['accessPointId']}; signal {sig}")
        t_before = fix_seconds(u)

        print("== 7.2 trigger: MEC 012 MeasRepUe on the vehicle's cell (the radio authority)")
        token = secrets.token_hex(16)
        sub_st, sub_b = http_json("POST", MEC12_SUBS, {
            "subscriptionType": "MeasRepUeSubscription", "callbackReference": callback_url(token),
            "filterCriteriaAssocTri": {"ecgi": [ecgi]}})
        require("MEC 012 MeasRepUe subscription on the vehicle's cell accepted", sub_st == 201,
                f"HTTP {sub_st} {sub_b.get('_links', {}).get('self', {}).get('href') if sub_st == 201 else ''}")
        EXP12.update(token=token, sub=sub_b["_links"]["self"]["href"], cell=ecgi["cellId"])
        hold_thr = a.rsrp_threshold if a.device == "sim" else HOLD_NEVER_DBM
        t_hold = time.time()
        forged = {"notificationType": "MeasRepUeNotification", "rsrp": 0, "rsrq": 0, "trigger": 0,
                  "ecgi": {"cellId": EXP12["cell"]}, "_links": {"subscription": {"href": EXP12["sub"]}}}
        n_rej0 = len(MEC12_REJ)
        for path, body in (("/mec012", forged), (f"/mec012/{secrets.token_hex(16)}", forged),
                           (f"/mec012/{token}", {**forged, "_links": {"subscription": {"href": EXP12["sub"] + "x"}}}),
                           (f"/mec012/{token}", {**forged, "ecgi": {"cellId": "0000001"}})):
            http_json("POST", f"http://127.0.0.1:{LISTEN}{path}", body)
        time.sleep(a.hold_s)
        took = [r for t, _rat, r, _c in MEC12 if t >= t_hold and r == 0]
        step("CONTROL (must FAIL) a forged MeasRepUe from an unauthorised source was accepted", bool(took),
             f"4 forged reports (bare path, guessed token, other subscription, other cell): refused "
             f"{len(MEC12_REJ) - n_rej0}, accepted {len(took)}; the callback URL is the credential (MEC 012 signs nothing)")
        hold = [(rat, r) for t, rat, r, _c in MEC12 if t >= t_hold]
        require("MEC 012 reports the vehicle's RSRP during the hold window", len(hold) >= 1,
                f"{len(hold)} MeasRepUe in {a.hold_s:.0f} s, reported values {hold[-5:]}")
        fired = [(rat, r) for rat, r in hold if decide(r, hold_thr, rat)]
        step("CONTROL (must FAIL) a handover trigger fired during the hold window", bool(fired),
             f"hold threshold {hold_thr} dBm ({'signal set good' if a.device == 'sim' else 'below any reportable RSRP'});"
             f" triggering reports {fired[:5]}")
        if a.device == "sim":
            dev.set_signal(a.sim_low_rsrp)
        t_arm = time.time()
        trig = None
        while time.time() - t_arm < 30 and trig is None:
            time.sleep(0.5)
            trig = next(((t, r, rat) for t, rat, r, _c in MEC12 if t >= t_arm and decide(r, a.rsrp_threshold, rat)), None)
        require("7.2 the radio authority triggered the handover: MEC 012 reports the vehicle's RSRP below the threshold",
                trig is not None,
                f"{trig and trig[2]} reported value {trig and trig[1]} = below {trig and rsrp_bin(trig[1], trig[2])[1]} dBm, "
                f"threshold {a.rsrp_threshold} dBm"
                + ("" if trig else f"; last reports {[(rat, r) for _t, rat, r, _c in MEC12[-5:]]} (raise --rsrp-threshold?)")
                + (f"; simulated drop to {a.sim_low_rsrp} dBm" if a.device == "sim" else "; the phone's own radio"))
        t_trig = trig[0]
        below = rsrp_bin(trig[1], trig[2])[1]
        in_put("handover", {"state": "TRIGGERED", "by": "MEC 012 MeasRepUe", "rat": trig[2], "rsrp_reported": trig[1],
                            "rsrp_dbm_below": below, "threshold_dbm": a.rsrp_threshold})

        print("== 7.4 swarm (PoC level): context hub, recommendations, local decisions")
        ctx = {"phone": {"zone": mloc["zoneId"], "rat": trig[2], "rsrp_reported": trig[1], "rsrp_dbm_below": below, "edge": ho.EDGE_A[1]}}
        if rsu:
            ctx["rsu"] = {"wifi_aps_seen": count_items(rsu_latest("wlan")), "edge": ho.EDGE_A[1]}
        in_put("swarm", {"kind": "context", **ctx})
        flat = json.dumps(ctx).lower()
        step("7.4 the hub shares bounded context only: no positions in it", not any(k in flat for k in ("lat", "lon", "latitude", "longitude")),
             json.dumps(ctx, sort_keys=True))
        move = decide(trig[1], a.rsrp_threshold, trig[2])
        rec_phone = {"to": "phone", "recommend": "move to the peer edge" if move else "stay",
                     "why": f"MEC 012 {trig[2]} RSRP below {below} dBm vs threshold {a.rsrp_threshold} dBm"}
        in_put("swarm", {"kind": "recommendation", **rec_phone})
        in_put("decisions", {"by": "phone", "recommendation": rec_phone["recommend"], "accepted": move})
        if rsu:
            in_put("swarm", {"kind": "recommendation", "to": "rsu", "recommend": "stay", "why": "fixed roadside unit serves edge A"})
            in_put("decisions", {"by": "rsu", "recommendation": "stay", "accepted": True})
        decs = in_all("decisions")
        step("7.4 recommendations issued by the hub, decisions recorded by each participant",
             len(decs) == (2 if rsu else 1), f"phone: {rec_phone['recommend']} ({rec_phone['why']})" + ("; rsu: stay" if rsu else ""))
        hub_w = ho._req("POST", f"{A_URL}/{AE}/radio", IN_ORIGIN, ty=4,
                        body={"m2m:cin": {"cnf": "application/json:0", "con": "{\"hub\": \"override\"}"}})[0]
        step("CONTROL (must FAIL) the hub wrote into a participant's own data", hub_w == 201,
             f"HTTP {hub_w}: participants keep local authority" if hub_w != 201 else f"HTTP {hub_w}")
        require("the vehicle's own agent accepted the move: the handover runs on trigger AND acceptance",
                any(d.get("by") == "phone" and d.get("accepted") is True for d in decs), str(decs))

        print("== MEC 040 federation")
        systems = sc.federated_systems()
        step("MEC 040 lists peer systems", len(systems) >= 2,
             "; ".join(f"{s['systemId']}->{s.get('endpoint')}" for s in systems))
        peer = sc.peer_for(ho.EDGE_A[0], systems)
        require("MEC 040 selects a peer for edge A", peer is not None and peer.get("endpoint") == ho.EDGE_B[0],
                f"{peer and peer['systemId']} at {peer and peer.get('endpoint')}")
        # The phone is not registered on B yet, so B may rightly refuse it (403). What
        # this step claims is narrower: the endpoint answers AS a oneM2M CSE (an
        # X-M2M-RSC header on the response, whatever the status) and maps to a known
        # edge the same way scenario.py maps it.
        target = next((e for e in (ho.EDGE_A, ho.EDGE_B) if peer and e[0].rstrip("/") == peer["endpoint"].rstrip("/")), None)
        rsc, http = None, None
        try:
            r = urllib.request.urlopen(urllib.request.Request(f"{ho.EDGE_B[0]}/{ho.EDGE_B[1]}", headers={
                "X-M2M-Origin": OWNER, "X-M2M-RI": "reach", "X-M2M-RVI": "4", "Accept": "application/json"}), timeout=5)
            rsc, http = r.headers.get("X-M2M-RSC"), r.status
        except urllib.error.HTTPError as e:
            rsc, http = e.headers.get("X-M2M-RSC"), e.code
        except Exception:
            pass
        require("peer endpoint resolves to a reachable edge CSE", target == ho.EDGE_B and rsc is not None,
                f"{peer and peer['endpoint']} -> {target and target[1]}; HTTP {http}, X-M2M-RSC {rsc}")

        print("== before the handover (TR-0077 v0.4.0 7.2.4.2: one serving CSE, one handover at a time)")
        a_csi, b_csi = ho._csi(ho.EDGE_A), ho._csi(target)
        named = [x.get("cse") for x in in_all("servingCSE")][-1:]
        require("the target is another CSE than the source, and the IN-AE names the source as the serving CSE",
                a_csi != b_csi and named == [ho.EDGE_A[1]], f"{a_csi} -> {b_csi}; IN-AE servingCSE {named}")
        txn = ho.take_lock(a_csi, b_csi, origin=OWNER)
        require("a handover transaction with an identifier and a validity time is opened at the IN-CSE", bool(txn),
                f"transaction {txn}, valid {ho.TXN_VALIDITY_S:.0f} s")
        second = ho.take_lock(a_csi, b_csi, origin=OWNER)
        step("CONTROL (must FAIL) a second handover of the same vehicle was admitted while the first is open",
             second is not None, f"second transaction: {second}")
        meas["handover_txn"] = txn

        print("== handover")
        in_put("handover", {"state": "TARGET_SELECTED", "cse": target and target[1], "by": "MEC 040", "txn": txn})
        in_put("handover", {"state": "MIGRATING", "from": ho.EDGE_A[1], "to": ho.EDGE_B[1], "txn": txn})
        last_a_ct = (cins(ho.EDGE_A, "radio") or [{}])[-1].get("ct")
        dev.stop()
        last, t_change = cni(ho.EDGE_A, "radio"), time.time()
        t_end = time.time() + 40
        while time.time() < t_end and time.time() - t_change <= dev.period + 1:
            time.sleep(0.5)
            now = cni(ho.EDGE_A, "radio")
            if now != last:
                last, t_change = now, time.time()
        stable_s = time.time() - t_change
        last_a_ct = (cins(ho.EDGE_A, "radio") or [{}])[-1].get("ct") or last_a_ct
        require(f"phone stream paused (no new instances on A for {dev.period + 1:.0f} s)", stable_s > dev.period + 1,
                f"radio cni frozen at {last} for {stable_s:.1f} s")

        src = {c: cins(ho.EDGE_A, c) for c in CNTS}
        a_ts, a_bad = read_samples(A_URL)             # read once the stream is paused: nothing is in flight
        step("edge A holds at least 2 of the phone's numbered samples (the count across both edges needs them)",
             len(a_ts) >= 2 and a_bad == 0, f"{len(a_ts)} samples, {a_bad} instances without a usable number or time")
        mine, why = ae_ours_or_absent(f"{B_URL}/{AE}", OWNER)
        require("edge B's name for the vehicle is free or the vehicle's own (never another originator's AE)", mine, why)
        ho.delete_ae(ho.EDGE_B, ae=AE, origin=OWNER)
        st, _ = ho._req("POST", B_URL, OWNER, ty=ho.TY_AE,
                        body={"m2m:ae": {"rn": AE, "api": "Nprobe.phone", "rr": True, "srv": ["4"]}})
        ok = st == 201
        st_tsb = make_ts(B_URL)                       # empty: the source's sequence numbers are not copied
        for c in CNTS:
            s2_, _ = ho._req("POST", f"{B_URL}/{AE}", OWNER, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": c, "mni": 5000}})
            ok &= s2_ in (201, 409)
            for ci in history_to_copy(c, src[c], a.history_rule):
                s3_, _ = ho._req("POST", f"{B_URL}/{AE}/{c}", OWNER, ty=4,
                                 body={"m2m:cin": {"cnf": ci.get("cnf", "application/json:0"), "con": ci["con"]}})
                ok &= s3_ == 201
        dst = {c: cins(ho.EDGE_B, c) for c in CNTS}
        want = {c: history_to_copy(c, src[c], a.history_rule) for c in CNTS}
        same = all([x["con"] for x in want[c]] == [y["con"] for y in dst[c]] for c in CNTS)
        meas["history_rule"] = a.history_rule
        meas["history_copied"] = {c: f"{len(want[c])} of {len(src[c])}" for c in CNTS}
        if a.history_rule == "all":
            require("AE + 5 containers rebuilt on B, every instance bit-identical", ok and same,
                    ", ".join(f"{c} {len(src[c])}" for c in CNTS))
        else:
            require(f"AE + 5 containers rebuilt on B: imu, env and radio bit-identical; position and Wi-Fi history by rule "
                    f"'{a.history_rule}'", ok and same and all(len(src[c]) >= 2 for c in PRIVATE_CNTS),
                    ", ".join(f"{c} {len(want[c])} of {len(src[c])}" for c in CNTS)
                    + "; the rule shows only when the source held at least 2 records of each")

        # Edge A's read policy (phone/onem2m_acp.py) on the AE and every container; the central IN-AE is added only
        # on CITY_READS, in a policy of its own (edge_b_acr).
        ris = {}
        for rn, city in (("phoneReadAcp", False), ("phoneCityAcp", True)):
            acpb = {"m2m:acp": {"rn": rn, "pv": {"acr": edge_b_acr(city)}, "pvs": {"acr": [{"acor": [OWNER], "acop": 63}]}}}
            st, b = ho._req("POST", B_URL, OWNER, ty=1, body=acpb)
            if st != 201:   # an earlier run's policy: RESET its privileges, never reuse them (onem2m_acp.py, 2026-09-28)
                st, b = ho._req("PUT", f"{B_URL}/{rn}", OWNER,
                                body={"m2m:acp": {"pv": acpb["m2m:acp"]["pv"], "pvs": acpb["m2m:acp"]["pvs"]}})
            ris[city] = b["m2m:acp"]["ri"]
        ho._req("PUT", f"{B_URL}/{AE}", OWNER, body={"m2m:ae": {"acpi": [ris[False]]}})
        for c in CNTS:
            ho._req("PUT", f"{B_URL}/{AE}/{c}", OWNER, body={"m2m:cnt": {"acpi": [ris[c in CITY_READS]]}})
        r_ok = ho._req("GET", f"{B_URL}/{AE}/radio/la", READER)[0]
        r_no = ho._req("GET", f"{B_URL}/{AE}/radio/la", "Cstranger")[0]
        step("access policy on B: reader 200, stranger 403", r_ok == 200 and r_no == 403, f"{r_ok}/{r_no}")

        print("== 7.2 continuity: serving CSE and subscriptions")
        last_a_s1 = max((t for p, t, c in NOTES if p == "/estimedS1" and c), default=None)
        m1 = None
        t_sub_b = time.time()
        if not a.s1_late:   # S1 moves with the phone, created on B BEFORE the stream arrives there; S2 does not (the control)
            m1 = subscribe(ho.EDGE_B, "estimedS1")
        n_replayed = len(dst["radio"])
        t_switch = time.time()
        dev.live(f"http://127.0.0.1:{ho.EDGE_B[0].rsplit(':', 1)[1]}/{ho.EDGE_B[1]}")
        new = 0
        for _ in range(30):
            time.sleep(1)
            new = cni(ho.EDGE_B, "radio") - n_replayed
            if new >= 2:
                break
        t_resume = time.time()
        b_new = cins(ho.EDGE_B, "radio")[n_replayed:]
        step("phone stream re-pointed: new live readings arrive on B", new >= 2,
             f"{new} new radio instances on B; telemetry pause {t_resume - t_switch + stable_s:.0f} s (wall)")
        a_after = cni(ho.EDGE_A, "radio")
        step("no new readings on A after re-point", a_after == last, f"A radio cni {last} -> {a_after}")
        if a.s1_late:
            m1 = subscribe(ho.EDGE_B, "estimedS1")
        in_put("servingCSE", {"cse": ho.EDGE_B[1]})
        in_put("handover", {"state": "SERVING_CHANGED", "cse": ho.EDGE_B[1], "txn": txn})
        for _ in range(30):
            if sum(1 for p, t, c in NOTES if p == "/estimedS1" and c and t > t_switch) >= 2:
                break
            time.sleep(1)
        post1 = [t for p, t, c in NOTES if p == "/estimedS1" and c and t > t_switch]
        gap = (post1[0] - last_a_s1) if post1 and last_a_s1 else None
        in_put("devices", {"phone": ho.EDGE_B[1], **({"rsu": ho.EDGE_A[1]} if rsu else {})})
        step("7.2 subscription S1 migrated to edge B keeps notifying with the phone's new data", m1 == 201 and len(post1) >= 2,
             f"create on B {m1} ({meas['s1_order']}); {len(post1)} notifications after the switch; "
             f"gap from the last on A {gap and round(gap, 1)} s")

        if local13:                                  # our MEC 013 reads the phone from its serving edge: re-point it
            mec13.terminate()
            mec13.wait(5)
            mec13 = subprocess.Popen([PY, str(HERE / "mec013_phone.py")], env=dict(os.environ, PHONE_CSE=B_URL),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            procs.append(mec13)
            u2 = None
            for _ in range(20):
                time.sleep(2)
                try:
                    u2 = (users_of(get_json(users_url())) or [None])[0]
                    if (fix_seconds(u2) or 0) > t_before:
                        break
                except Exception:
                    pass
            step("our re-pointed MEC 013 instance is running (it holds :8401)", mec13.poll() is None,
                 f"exit code {mec13.poll()}")
            step("MEC 013 now sourced from edge B reports a newer fix", bool(u2) and (fix_seconds(u2) or 0) > t_before,
                 f"fix t {t_before} -> {fix_seconds(u2)}")
        else:                                        # another platform's MEC 013 does not read our edges at all
            meas["mec013_after_handover"] = f"not run: MEC 013 at {MEC013_BASE} is not sourced from edge B"
            print(f"          (not run: MEC 013 at {MEC013_BASE} is not sourced from our edges)")

        ho.delete_ae(ho.EDGE_A, ae=AE, origin=OWNER)
        st, _ = ho._req("GET", f"{A_URL}/{AE}", OWNER)
        step("phone released from edge A", st == 404, f"HTTP {st}")
        if a.history_rule != "all":
            # Row B5: after the release neither edge may hold more of the position and Wi-Fi history than the rule
            # copied. Edge A: nothing of the vehicle is left to discover. Edge B: every record there is compared, as
            # text, with the history edge A held when the stream was paused.
            def over_on_b():
                return {c: history_over([x["con"] for x in src[c]], [y["con"] for y in cins(ho.EDGE_B, c)],
                                        [x["con"] for x in want[c]]) for c in PRIVATE_CNTS}
            _, disc = ho._req("GET", f"{A_URL}?fu=1&ty={ho.TY_CIN}", "CAdmin")
            left_a = [u for u in (disc or {}).get("m2m:uril", []) if f"/{AE}/" in f"/{u}/"]
            over = over_on_b()
            n_b = {c: len(cins(ho.EDGE_B, c)) for c in PRIVATE_CNTS}
            meas["history_after_release"] = {"edge_a_instances_of_the_vehicle": len(left_a),
                                             "edge_b_over_the_rule": {c: len(v) for c, v in over.items()}, "edge_b_records": n_b}
            step(f"after the release edge A holds no record of the vehicle and edge B holds no position or Wi-Fi history "
                 f"beyond rule '{a.history_rule}'", not left_a and not any(over.values()) and all(n_b.values()),
                 f"A: {len(left_a)} instances; B: loc {n_b['loc']} records, {len(over['loc'])} over; "
                 f"wlan {n_b['wlan']} records, {len(over['wlan'])} over")
            st_p, made = ho._req("POST", f"{B_URL}/{AE}/loc", OWNER, ty=4,
                                 body={"m2m:cin": {"cnf": "application/json:0", "con": src["loc"][0]["con"]}})
            found = over_on_b()["loc"]
            rn_p = (made or {}).get("m2m:cin", {}).get("rn")
            st_d = ho._req("DELETE", f"{B_URL}/{AE}/loc/{rn_p}", OWNER)[0] if rn_p else None
            step("CONTROL (must FAIL) the history scan missed an old position planted on the target",
                 not (st_p == 201 and len(found) == 1), f"planted HTTP {st_p}; scan found {len(found)}; removed HTTP {st_d}")
            step("the planted record is gone again and the scan is clean", st_d == 200 and not any(over_on_b().values()),
                 f"DELETE HTTP {st_d}")
        edges = ho.registered_edges()
        step("IN-CSE still holds both edges", ho.edges_ok(edges), str(edges))
        in_put("handover", {"state": "COMPLETED", "cse": ho.EDGE_B[1], "txn": txn})
        ho.release_lock(origin=OWNER)
        st_lock, _ = ho._req("GET", f"{IN[0]}/{IN[1]}/{ho.lock_name(OWNER)}", "CAdmin")
        step("the handover transaction is closed once the vehicle is served by the target", st_lock == 404, f"HTTP {st_lock}")
        t_done = time.time()
        step(f"7.2 trigger -> handover COMPLETED within {a.handover_max_s:.0f} s (our bound; TR-0077 sets none)",
             t_done - t_trig <= a.handover_max_s, f"{t_done - t_trig:.1f} s")
        if rsu:
            post3 = [t for p, t, c in NOTES if p == "/estimedS3" and c and t > t_switch]
            step("the sensor's subscription S3 kept notifying through the vehicle's handover", len(post3) >= 1,
                 f"{len(post3)} S3 notifications after the vehicle switched")
            ra, rb = ho._req("GET", f"{A_URL}/{RSU}", RSU_ORIGIN)[0], ho._req("GET", f"{B_URL}/{RSU}", RSU_ORIGIN)[0]
            step("the sensor stayed on edge A (A 200, B 404)", ra == 200 and rb == 404, f"A {ra}, B {rb}")
            devs_rec = in_all("devices")
            step("per-device serving CSE on the IN-AE: vehicle A->B, sensor stays on A",
                 devs_rec[:1] == [{"phone": ho.EDGE_A[1], "rsu": ho.EDGE_A[1]}] and devs_rec[-1:] == [{"phone": ho.EDGE_B[1], "rsu": ho.EDGE_A[1]}],
                 f"{devs_rec}")
        post2 = [t for p, t, c in NOTES if p == "/estimedS2" and c and t > t_switch]
        step("CONTROL (must FAIL) S2, NOT migrated, still notifies after the handover", len(post2) >= 1,
             f"{len(post2)} S2 data notifications after the switch (a missing migration is visible)")
        states = [x["state"] for x in in_all("handover")]
        step("7.2 handover states recorded in order on the IN-AE",
             states == ["ATTACHED", "TRIGGERED", "TARGET_SELECTED", "MIGRATING", "SERVING_CHANGED", "COMPLETED"],
             " -> ".join(states))
        serving = [x["cse"] for x in in_all("servingCSE")]
        step("7.2 serving MN-CSE resolved on the IN-AE: edge A before, edge B now", serving == [ho.EDGE_A[1], ho.EDGE_B[1]], str(serving))

        print("== 7.2 after the handover: a command at the new edge, sequence numbers, notifications (TD_MEC_HO_02)")
        # After COMPLETED and after the duration above was taken, so the handover's own times stay comparable with
        # earlier runs. The commands are posted by the vehicle's owner; the phone takes them through the
        # pollingChannel it opened on edge B and answers in edge B's <ack>.
        st_c, ack, took = send_cmd(B_URL, {"cmd": "ping", "id": secrets.token_hex(4)})
        step("a downlink command (ping) posted at edge B is acknowledged by the phone in edge B's ack container",
             st_c == 201 and isinstance(ack, dict) and ack.get("ok") is True and ack.get("cmd") == "ping",
             f"POST HTTP {st_c}; acknowledgement after {took:.1f} s: {ack}")
        st_p, ack_p, took_p = send_cmd(B_URL, {"cmd": "period", "value": a.period, "id": secrets.token_hex(4)})
        step(f"a period command ({a.period} s) at edge B is acknowledged with that value",
             st_p == 201 and isinstance(ack_p, dict) and ack_p.get("ok") is True and ack_p.get("period") == a.period,
             f"POST HTTP {st_p}; acknowledgement after {took_p:.1f} s: {ack_p}")
        st_0, ack_0, took_0 = send_cmd(B_URL, {"cmd": "period", "value": 0, "id": secrets.token_hex(4)})
        refused = st_0 == 201 and isinstance(ack_0, dict) and ack_0.get("ok") is False
        step("CONTROL (must FAIL) a period of 0 s was not refused by the phone", not refused,
             f"POST HTTP {st_0}; acknowledgement after {took_0:.1f} s: {ack_0}")
        st_src = post_cmd(A_URL, {"cmd": "ping", "id": secrets.token_hex(4)})
        step("the source edge takes no command for the vehicle after the release (HTTP 404)", st_src == 404, f"HTTP {st_src}")
        meas["downlink_at_target"] = {"ping_ack_s": round(took, 2), "period_ack_s": round(took_p, 2),
                                      "posted_by": "the vehicle's owner, from the host", "wait_limit_s": ACK_WAIT_S}

        b_ts, b_bad, t_end = [], 0, time.time() + 3 * dev.period + 15
        while time.time() < t_end:
            b_ts, b_bad = read_samples(B_URL)
            if len(b_ts) >= 3:
                break
            time.sleep(1)
        b_recs = {c: record_ts(cins(ho.EDGE_B, c)) for c in CNTS}     # read AFTER the samples: a number is posted last
        a_recs = {c: record_ts(src[c]) for c in CNTS}
        acc = seq_account(a_ts, b_ts, dev.period)
        short = {"source": records_per_sample(a_ts, a_recs), "target": records_per_sample(b_ts, b_recs)}
        ts_rb = (ho._req("GET", f"{B_URL}/{AE}/{TS_RN}", READER)[0], ho._req("GET", f"{B_URL}/{AE}/{TS_RN}", "Cstranger")[0])
        step("the phone's sequence numbers across both edges: none lost, none duplicated (the <timeSeries> on edge B "
             "was made empty by the handover; reader 403, stranger 403)",
             acc["countable"] and not acc["lost"] and not acc["duplicated"] and a_bad == 0 and b_bad == 0
             and st_tsb == 201 and ts_rb == (403, 403),
             f"source {acc['source']}, target {acc['target']}, counter {acc['counter']}; lost {acc['lost'][:6]}; "
             f"duplicated {acc['duplicated'][:6]}; started again inside an edge {acc['restarts'][:3]}; "
             f"{acc['gap_s']} s = {acc['gap_periods']} periods without a sample; reader/stranger {ts_rb}")
        step("every numbered sample has exactly one record in each of the five containers on its own edge",
             bool(a_ts) and bool(b_ts) and not short["source"] and not short["target"],
             f"{len(a_ts)} samples on A, {len(b_ts)} on B; not one record: A {short['source'][:4]}, B {short['target'][:4]}")
        if len(b_ts) >= 3:        # the same count on a copy with four planted faults
            cut = seq_account(a_ts, b_ts[:1] + b_ts[2:] + [a_ts[-1]], dev.period)
            bad_recs = {c: list(v) for c, v in b_recs.items()}
            bad_recs["radio"].remove(b_ts[0][1])
            bad_recs["loc"].append(b_ts[0][1])
            cut_recs = records_per_sample(b_ts[:1], bad_recs)
            seen = ({"where": "target", "snr": b_ts[1][0]} in cut["lost"]
                    and {"where": "both edges", "snr": a_ts[-1][0]} in cut["duplicated"]
                    and cut_recs == [{"snr": b_ts[0][0], "cnt": "loc", "records": 2},
                                     {"snr": b_ts[0][0], "cnt": "radio", "records": 0}])
            planted = f"lost {cut['lost'][:3]}, duplicated {cut['duplicated'][:3]}, records {cut_recs}"
        else:
            seen, planted = False, f"only {len(b_ts)} samples on B: nothing could be planted"
        step("CONTROL (must FAIL) the count missed a number removed, a sample put on both edges, a record removed or a "
             "record doubled in a copy of the target's data", not seen, planted)
        meas["sequence"] = {"countable": acc["countable"], "counter": acc["counter"], "source": acc["source"],
                            "target": acc["target"], "lost": len(acc["lost"]), "duplicated": len(acc["duplicated"]),
                            "first_lost": acc["lost"][:20], "first_duplicated": acc["duplicated"][:20],
                            "restarts": acc["restarts"][:20], "gap_s": acc["gap_s"], "gap_periods": acc["gap_periods"],
                            "unusable_instances": {"source": a_bad, "target": b_bad},
                            "samples_without_one_record_each": {k: len(v) for k, v in short.items()}}
        if a.s1_late:
            meas["s1_notifications"] = "not counted: with --s1-late the subscription is made after the first records"
        else:
            # TD_MEC_HO_02 step 3: every new radio record on edge B, notified once by the subscription that moved
            # with the phone. The newest record is waited for; a notification of a record newer than the list is
            # outside it.
            new_t = record_ts(cins(ho.EDGE_B, "radio")[n_replayed:])
            t_end = time.time() + 5
            while time.time() < t_end and new_t and not any(p == "/estimedS1" and r == new_t[-1] for p, _t, r in list(NOTE_RECS)):
                time.sleep(0.2)
            notes = [r for p, at, r in list(NOTE_RECS) if p == "/estimedS1" and at >= t_sub_b
                     and (r is None or not new_t or new_t[-1] is None or r <= new_t[-1])]
            nres = notified(new_t, notes)
            step("subscription S1 on edge B: every new radio record was notified once, none lost, none twice",
                 len(new_t) >= 2 and None not in new_t and not (nres["lost"] or nres["duplicated"] or nres["unknown"]),
                 f"{nres['records']} records, {nres['notifications']} notifications; lost {len(nres['lost'])}, "
                 f"twice {len(nres['duplicated'])}, for no listed record {len(nres['unknown'])}")
            meas["s1_notifications"] = {k: (v if isinstance(v, int) else len(v)) for k, v in nres.items()}
        if a.period != DEFAULT_PERIOD_S:
            st_r, ack_r, took_r = send_cmd(B_URL, {"cmd": "period", "value": DEFAULT_PERIOD_S, "id": secrets.token_hex(4)})
            step(f"the sampling period is put back to {DEFAULT_PERIOD_S} s through the phone's command at edge B, acknowledged",
                 st_r == 201 and isinstance(ack_r, dict) and ack_r.get("ok") is True and ack_r.get("period") == DEFAULT_PERIOD_S,
                 f"POST HTTP {st_r}; acknowledgement after {took_r:.1f} s: {ack_r}")
            dev.period = float(DEFAULT_PERIOD_S)

        first_b_ct = b_new[0]["ct"] if b_new else None
        meas.update({
            "telemetry_pause_s": round(ct_epoch(first_b_ct) - ct_epoch(last_a_ct), 2) if first_b_ct and last_a_ct else None,
            "pause_proof_s": round(stable_s, 2),
            "notification_gap_s": round(gap, 2) if gap is not None else None,
            "handover_duration_s": round(t_done - t_trig, 2),
            "trigger_rsrp_reported": trig[1], "threshold_dbm": a.rsrp_threshold, "period_s": float(a.period)})
        in_put("measurements", meas)
        print("== what the city holds: access, positions, device locations")
        st, b = ho._req("GET", f"{IN[0]}/{IN[1]}/{IN_AE}?fu=1&ty=3", IN_ORIGIN)
        cnts_in = [x if x.startswith("/") else f"/{x}" for x in (b or {}).get("m2m:uril", [])] if st == 200 else []
        denied = {c: (ho._req("GET", f"{IN[0]}{c}", "Cstranger")[0], ho._req("GET", f"{IN[0]}{c}/la", "Cstranger")[0])
                  for c in cnts_in}
        # every container holds a record by now (measurements included): an EMPTY container's /la is 404 for anyone,
        # ACME looks the latest up before the access check -- an emptiness oracle, ACME's behaviour (noted, not ours)
        empty = [c for c in cnts_in if not ((ho._req("GET", f"{IN[0]}{c}", IN_ORIGIN)[1] or {}).get("m2m:cnt", {}).get("cni"))]
        step("a stranger reads none of the central IN-AE's records (403 on every container and its latest)",
             len(cnts_in) >= 8 and not empty and all(v == (403, 403) for v in denied.values()),
             f"{len(cnts_in)} containers, empty {empty}; not 403: {[(c, v) for c, v in denied.items() if v != (403, 403)]}")
        records, hits = 0, []
        for c in cnts_in:
            st, body = ho._req("GET", f"{IN[0]}{c}?rcn=4", IN_ORIGIN)
            records += len((body or {}).get("m2m:cnt", {}).get("m2m:cin", []))
            hits += [f"{c}:{h}" for h in scan_positions(body or {})]
        step("no position or trajectory in any record the city holds (every container on the IN-AE scanned)",
             records > 0 and not hits, f"{records} records scanned; hits {hits[:5]}")
        ho._req("POST", f"{IN[0]}/{IN[1]}/{IN_AE}", IN_ORIGIN, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": "scanControl"}})
        in_put("scanControl", SCAN_CONTROL_RECORD)
        st, body = ho._req("GET", f"{IN[0]}/{IN[1]}/{IN_AE}/scanControl?rcn=4", IN_ORIGIN)
        planted = scan_positions(body or {})
        ho._req("DELETE", f"{IN[0]}/{IN[1]}/{IN_AE}/scanControl", IN_ORIGIN)
        step("CONTROL (must FAIL) the position scan missed a planted coordinate", not planted, f"found {planted}")
        devs_now = (in_all("devices") or [{}])[-1]
        who = {"phone": (AE, OWNER), "rsu": (RSU, RSU_ORIGIN)}
        where = {d: {e[1] for e in (ho.EDGE_A, ho.EDGE_B) if ho._req("GET", f"{e[0]}/{e[1]}/{who[d][0]}", who[d][1])[0] == 200}
                 for d in devs_now if d in who}
        step("the registry's device locations match where each device's AE exists (one edge each)",
             bool(devs_now) and audit_devices(devs_now, where) == [], f"registry {devs_now}; AEs {where}")
        wrong = audit_devices({**devs_now, "phone": ho.EDGE_A[1]}, where)
        step("CONTROL (must FAIL) a registry entry naming the vehicle's old edge passed the device audit",
             "phone" not in wrong, f"flagged {wrong}")

        print("== measurements")
        for k in ("telemetry_pause_s", "pause_proof_s", "notification_gap_s", "handover_duration_s"):
            print(f"  {k:22} {meas[k]}")
        rt = ho._req("GET", f"{IN[0]}/~/id-mn-b/{ho.EDGE_B[1]}/{AE}/radio/la", IN_ORIGIN)[0]
        step("the central IN-AE reads the vehicle on edge B THROUGH the IN-CSE (retargeting)", rt == 200, f"HTTP {rt}")
        rt_x = ho._req("GET", f"{IN[0]}/~/id-mn-b/{ho.EDGE_B[1]}/{AE}/radio/la", "Cstranger")[0]
        step("CONTROL (must FAIL) a stranger read the vehicle through the IN-CSE", rt_x == 200, f"HTTP {rt_x}")
        for c in ("loc", "wlan"):
            st_c = ho._req("GET", f"{IN[0]}/~/id-mn-b/{ho.EDGE_B[1]}/{AE}/{c}/la", IN_ORIGIN)[0]
            step(f"the IN-AE cannot read the vehicle's {c} through the IN-CSE (positions never reach the city)",
                 st_c == 403, f"HTTP {st_c}")
    except Abort as e:
        aborted = str(e)
    except Exception as e:  # noqa: BLE001 -- a crash is a FAIL row, never a missing verdict
        traceback.print_exc()
        step("run completed without an exception", False, repr(e))
        aborted = f"exception: {e!r}"
    finally:
        meas["cleanup"] = cleanup_subscriptions()     # while MEC 012 and the listener still run
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
        if a.device == "sim":
            for d in devs.values():
                d.stop()
        if srv is not None:
            srv.shutdown()
            srv.server_close()
    return 0 if finish(results, aborted_at=aborted, device=a.device, measurements=meas) else 1


if __name__ == "__main__":
    sys.exit(main())
