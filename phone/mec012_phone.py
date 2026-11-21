#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""MEC 012 RNIS with the REAL phone as a measuring UE.

The unmodified `mec012/candidate.py` is loaded and served as-is (fixture cell 6060606
and all ATS behaviour intact). On top of it, for the phone's real serving cell:

  GET /rni/v2/queries/plmn_info?cell_id=<phone ECI>   -> the phone's real PLMN
  GET /rni/v2/queries/layer2_meas?cell_id=<phone ECI> -> the cell's ECGI ONLY. PRB usage
      is an eNB-side counter a UE cannot observe, so it is omitted, not invented.
  rab_info / s1_bearer_info for the phone cell        -> fall through to the candidate,
      which answers 404: bearer/tunnel state is core-network data the UE never sees.
  GET /rni/v2/queries/rab_info?ue_ipv4_address=<x>    -> the phone's serving cell, erabInfo empty, when x is
      the address the device itself reports (associateId [{type 1, x}]) or the lab's MEC 013 name for the phone
      (PHONE_ADDRESS without acr:; associateId [{value}] with NO type, since 2026-11-20: the name is not an IPv4
      address, so type 1 would be false, and the ATS RabInfo schema requires neither type nor associateId).

  CellChangeSubscription -> CellChangeNotification (hoStatus 3 COMPLETED) when the serving
      ECI changes between two consecutive registered samples. A detach/re-attach is not a
      handover and never produces one.

  MeasRepUeSubscription whose filter names the phone's cell (or no cell) receives a
  MeasRepUeNotification each time the phone posts a new radio sample:
      rsrp / rsrq as TS 136 133 reported values (Uint8 indices, NOT dBm), and the
      neighbours the phone measured (rsrp/rsrq only: a UE sees a neighbour's PCI, not
      its ECGI).

  The UE identifier (2026-11-20, TD_MEC_DEV_02). A device MAY report its own IPv4 address
  in its radio record ("ue_ipv4", read by device_state.ue_ipv4). Only then do CellChange
  and MeasRepUe notifications carry associateId [{type 1 (UE_IPv4_ADDRESS), value}], and a
  filter's associateId is matched against it (type 1 and the same address). Without one,
  everything is as before: no associateId is sent and an associateId filter gets nothing,
  because nothing the device reports binds it to such an identifier. The probe app (v20)
  reports no address, so a real-phone run is unchanged; only the simulated UE declares
  one (a documentation address, RFC 5737).

  Review pass 2 (2026-11-20):
    * each subscription's filter is judged in its own guard: one that cannot be read (hoStatus 3 as a
      bare number, which the candidate stores with 201) matches nothing, is counted in LIVE["bad_filter"]
      and named once on stderr. Before, it raised in step() on every later cell change, for everyone.
    * the serving cell is advanced before anyone is judged or notified.
    * an ECGI filter (CellChange source cell, MeasRepUe cell) names a cell by PLMN (mcc, mnc) AND cellId;
      before, cellId alone. With the real phone this changes only filters whose PLMN is not the phone's.

    PHONE_MEC012_PORT (default 8402)
    PHONE_MEC012_SENDLOG  optional file: one JSON line per notification send (time,
        subscription, type, ok, status, error), the RNIS's own account of what it delivered:
        ok = the callback answered some 2xx; status = the HTTP status it answered (None: the
        callback was refused here, or no answer came)
"""
from __future__ import annotations

import collections
import importlib.util
import json
import os
import sys
import threading
import time
from pathlib import Path

from starlette.responses import JSONResponse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402

spec = importlib.util.spec_from_file_location("mec012_candidate", HERE.parent / "mec012" / "candidate.py")
cand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cand)
PORT = int(os.environ.get("PHONE_MEC012_PORT", "8402"))
LIVE = {"snap": None, "radio_ct": None, "sent": 0, "send_fail": 0, "error": None}
SENDLOG = os.environ.get("PHONE_MEC012_SENDLOG") or None
UE_IPV4_ADDRESS = 1   # GS MEC 012 AssociateId.type: 1 = UE_IPv4_ADDRESS


def _ts() -> dict:
    t = time.time_ns()
    return {"seconds": t // 1_000_000_000, "nanoSeconds": t % 1_000_000_000}


def phone_ecgi(cell: dict) -> dict:
    return {"plmn": {"mcc": cell["mcc"], "mnc": cell["mnc"]}, "cellId": ds.eci_hex(cell["ci"])}


def _phone_cell():
    snap = LIVE["snap"]
    return ds.serving_cell(snap.get("radio")) if snap else None


@cand.app.middleware("http")
async def phone_queries(request, call_next):
    path = request.url.path
    cid = request.query_params.get("cell_id")
    cell = _phone_cell()
    if request.method == "GET" and cell and cid == ds.eci_hex(cell["ci"]) and set(request.query_params) == {"cell_id"}:
        if path == cand.QUERY_BASE + "/plmn_info":
            return JSONResponse(status_code=200, content=[{
                "appInstanceId": cand.KNOWN_APP_INS_ID, "timeStamp": _ts(),
                "plmn": [{"mcc": cell["mcc"], "mnc": cell["mnc"]}]}])
        if path == cand.QUERY_BASE + "/layer2_meas":
            return JSONResponse(status_code=200, content={
                "timeStamp": _ts(), "cellInfo": [{"ecgi": [phone_ecgi(cell)]}]})
    if (request.method == "GET" and cell and path == cand.QUERY_BASE + "/rab_info"
            and set(request.query_params) == {"ue_ipv4_address"}):
        ids = _rab_ue_ids(request.query_params["ue_ipv4_address"], ds.ue_ipv4((LIVE["snap"] or {}).get("radio")))
        if ids is not None:
            # The phone does not expose its E-RABs, so erabInfo is empty rather than invented (GS MEC 012 asks for
            # 1..N). 2026-10-29.
            return JSONResponse(status_code=200, content={
                "appInstanceId": cand.KNOWN_APP_INS_ID, "requestId": "phone-rab", "timeStamp": _ts(),
                "cellUserInfo": [{"ecgi": phone_ecgi(cell), "ueInfo": [{"associateId": ids, "erabInfo": []}]}]})
    return await call_next(request)


def _rab_ue_ids(asked: str, own_ipv4: str | None) -> list[dict] | None:
    """The associateId list naming the phone in a rab_info answer for ue_ipv4_address=asked, or None: not this phone.

    type 1 (UE_IPv4_ADDRESS) only for the address the device itself reports (device_state.ue_ipv4). The lab's MEC 013
    name for the phone (PHONE_ADDRESS without acr:, "phone-DEVC" by default; ETSI's fixtures pair acr:10.0.0.1 with
    10.0.0.1, which is why the bare name is asked, 2026-10-29) is no IPv4 address: until 2026-11-20 it was sent as
    type 1, which said it was one. It is now sent as {value} with NO type: the ATS RabInfo schema requires neither
    (GS MEC 012 table 6.5.4-1 gives type cardinality 1, so this is short of the GS, not a false type), and
    estimed_poc2.vehicle_ecgi, which finds the vehicle's cell by value, keeps working."""
    if own_ipv4 is not None and asked == own_ipv4:
        return [{"type": UE_IPV4_ADDRESS, "value": own_ipv4}]
    if asked == ds.PHONE_ADDRESS.removeprefix("acr:"):
        return [{"value": asked}]
    return None


def meas_rep_ue(radio: dict) -> dict | None:
    cell = ds.serving_cell(radio)
    if cell is None or ds.rsrp_index(cell.get("rsrp")) is None or ds.rsrq_index(cell.get("rsrq")) is None:
        return None
    nbrs = []
    for n in ds.neighbours(radio):
        p, q = ds.rsrp_index(n.get("rsrp")), ds.rsrq_index(n.get("rsrq"))
        if p is not None and q is not None:
            nbrs.append({"rsrp": p, "rsrq": q})
    body = {
        "notificationType": "MeasRepUeNotification",
        "timeStamp": _ts(),
        **_associate(ds.ue_ipv4(radio)),
        "ecgi": phone_ecgi(cell),
        "rsrp": ds.rsrp_index(cell["rsrp"]),
        "rsrq": ds.rsrq_index(cell["rsrq"]),
        "trigger": REPORTED_TRIGGER,
    }
    if nbrs:
        body["eutranNeighbourCellMeasInfo"] = nbrs
    return body


REPORTED_TRIGGER = 0  # NOT_AVAILABLE: the UE's RRC reporting trigger is not visible to us


def _associate(ue: str | None) -> dict:
    """The associateId member of a notification: present only when the device reported its address."""
    return {"associateId": [{"type": UE_IPV4_ADDRESS, "value": ue}]} if ue else {}


def _assoc_ok(f: dict, ue: str | None = None) -> bool:
    # No associateId in the filter: every UE (here: the one device). A filter naming UEs by
    # associateId matches only when the device reported its own IPv4 address and the filter
    # lists it as type 1 (UE_IPv4_ADDRESS). Without a reported address nothing binds the
    # device to such an identifier, so it is NOT sent the device's data (as before 2026-11-20).
    # appInstanceId identifies the subscribing application, not a UE; it is not a UE filter.
    want = f.get("associateId")
    if not want:
        return True
    if ue is None or not isinstance(want, list):
        return False
    return any(isinstance(a, dict) and type(a.get("type")) is int and a["type"] == UE_IPV4_ADDRESS
               and ds.ue_ipv4({"ue_ipv4": a.get("value")}) == ue for a in want)


def _ecgi_is(e: dict, want: dict) -> bool:
    """A filter's Ecgi names the cell `want` (an Ecgi as phone_ecgi builds it): the same cellId AND the same PLMN
    (mcc, mnc), as GS MEC 012 defines Ecgi. Until 2026-11-20 only cellId was compared, so a filter on 999/99 matched
    a 001/01 cell with the same cellId. An Ecgi without its PLMN names no cell. An entry that is not an object raises
    (the caller's guard: a filter that cannot be read matches nothing)."""
    if e.get("cellId") != want["cellId"]:
        return False
    p = e.get("plmn") or {}
    return p.get("mcc") == want["plmn"]["mcc"] and p.get("mnc") == want["plmn"]["mnc"]


def _matches(sub: dict, cell: dict, ue: str | None = None) -> bool:
    if sub.get("subscriptionType") != "MeasRepUeSubscription":
        return False
    f = sub.get("filterCriteriaAssocTri") or {}
    ecgis = f.get("ecgi") or []
    trig = f.get("trigger") or []
    return (_assoc_ok(f, ue) and (not trig or REPORTED_TRIGGER in trig)
            and (not ecgis or any(_ecgi_is(e, phone_ecgi(cell)) for e in ecgis)))


def _cc_matches(sub: dict, prev: dict, ue: str | None = None) -> bool:
    """A CellChangeSubscription wants this move out of `prev` (the source cell's Ecgi): source-cell filter, hoStatus
    (always 3 COMPLETED here) and associateId."""
    if sub.get("subscriptionType") != "CellChangeSubscription":
        return False
    f = sub.get("filterCriteriaAssocHo") or {}
    src_ok = not f.get("ecgi") or any(_ecgi_is(e, prev) for e in f["ecgi"])
    st_ok = not f.get("hoStatus") or 3 in f["hoStatus"]
    return src_ok and st_ok and _assoc_ok(f, ue)


def _sub_href(sub) -> str | None:
    try:
        return sub["_links"]["self"]["href"]
    except (KeyError, TypeError):
        return None


def _judged(match, sub: dict, *args) -> bool:
    """One subscription judged in its own guard. A filter that cannot be read (hoStatus 3 as a bare number, which the
    candidate stores with 201; an ecgi that is not a list of objects; a trigger that is not a list ...) matches
    nothing, is counted in LIVE["bad_filter"] and named once on stderr; the other subscriptions are judged as if it
    were not there (2026-11-20; before, it raised out of step() on every later cell change)."""
    try:
        return bool(match(sub, *args))
    except Exception as e:
        LIVE["bad_filter"] = LIVE.get("bad_filter", 0) + 1
        seen = LIVE.setdefault("bad_filter_subs", set())
        href = _sub_href(sub)
        if href not in seen and len(seen) < 1000:
            seen.add(href)
            print(f"mec012_phone: subscription {href} has a filter that cannot be read ({type(e).__name__}: {e}); "
                  "it matches nothing", file=sys.stderr, flush=True)
        return False


def _log_send(sub: dict, body: dict, ok: bool, err: str | None, status: int | None = None) -> None:
    """One line per send in PHONE_MEC012_SENDLOG, if set: the RNIS's own account, read by a test driver. A log that
    cannot be written never stops a notification."""
    if not SENDLOG:
        return
    try:
        with open(SENDLOG, "a", encoding="utf-8") as f:
            f.write(json.dumps({"t": time.time(), "sub": ((sub.get("_links") or {}).get("self") or {}).get("href"),
                                "type": body.get("notificationType"), "ok": ok, "status": status, "err": err}) + "\n")
    except OSError:
        pass


def _notify(sub: dict, body: dict) -> None:
    n = dict(body, _links={"subscription": sub["_links"]["self"]})
    err = None
    try:
        ok = bool(ds.safe_post(sub["callbackReference"], n))
        if not ok:
            err = "refused or not 2xx"
    except Exception as e:
        ok, err = False, f"{type(e).__name__}: {e}"
    status = ds.take_post_status()
    LIVE["sent" if ok else "send_fail"] += 1
    _log_send(sub, n, ok, err, status)


def step(snap: dict) -> None:
    """Process one snapshot: CellChange + MeasRepUe for any new radio sample."""
    LIVE["snap"], LIVE["error"] = snap, None
    if snap.get("radio_ct") == LIVE["radio_ct"] or not snap.get("radio"):
        return
    LIVE["radio_ct"] = snap["radio_ct"]
    body = meas_rep_ue(snap["radio"])
    cell = ds.serving_cell(snap["radio"])
    ue = ds.ue_ipv4(snap["radio"]) if cell else None   # the address the device reports in THIS sample
    with cand._lock:
        subs = [dict(s) for s in cand.SUBSCRIPTIONS.values()]
    # CellChange = the serving ECI changed between two consecutive samples in which the
    # phone was registered both times. A detach/re-attach (a sample with no serving cell
    # in between) is NOT a handover and resets the chain.
    prev = LIVE.get("serving")
    moved = prev is not None and cell is not None and ds.eci_hex(cell["ci"]) != prev["cellId"]
    # The serving cell advances BEFORE anyone is judged or notified: nothing a subscriber did can hold it back
    # (2026-11-20; before, a filter that raised left it on the old cell and the same move was sent again next time).
    LIVE["serving"] = phone_ecgi(cell) if cell else None
    LIVE.setdefault("attach_log", collections.deque(maxlen=1000)).append((time.time(), LIVE["serving"] and LIVE["serving"]["cellId"]))
    if moved:
        for s in subs:
            if _judged(_cc_matches, s, prev, ue):
                _notify(s, {"notificationType": "CellChangeNotification", "timeStamp": _ts(), **_associate(ue),
                            "hoStatus": 3, "srcEcgi": prev, "trgEcgi": [phone_ecgi(cell)]})
    if body and cell:
        for s in subs:
            if _judged(_matches, s, cell, ue):
                _notify(s, body)


def notifier() -> None:
    while True:
        try:
            step(ds.snapshot())
        except Exception as e:
            LIVE["error"] = repr(e)
        time.sleep(1)


if __name__ == "__main__":
    threading.Thread(target=notifier, daemon=True).start()
    cand._serve(cand.app, PORT)
