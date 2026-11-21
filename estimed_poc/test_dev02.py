#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline rows for TD_MEC_DEV_02 (TR-0086: an AE subscribes to MEC 012 cell-change events and receives the
notification) -- no phone, no CSE, no lab. Loopback HTTP only, on ports the OS picks.

What is held here:
  * the UE identifier: a device MAY report its own IPv4 address in its radio record ("ue_ipv4"); only then does
    mec012_phone put associateId [{type 1 (UE_IPv4_ADDRESS), value}] in CellChange and MeasRepUe notifications and
    match a filter's associateId against it. Without it (the probe app v20 reports none) the notifications and the
    filter rule are exactly as before: no associateId, and an associateId filter gets nothing;
  * the CellChange rule with a simulated UE: A,A,B -> one; a detach in between -> none; no change -> none; a filter
    on another UE, another source cell or another hoStatus -> none; a deleted subscription -> none;
  * the RNIS's account of each send: a 204 is a delivered notification, a 500 a failed one, and both are logged;
  * the simulated UE (sim_phone.py) detaches and re-attaches, changes cell, and declares its address only while
    attached; a phone made without an address posts the record shape it always posted;
  * the driver's own judgements (estimed_poc/dev02_run.py): latency from the sample's oneM2M creation time,
    the CellChange content check, the Location check, which subscription a notification belongs to, the listener's
    answers, the verdict, and that it refuses to run outside the live lock;
  * (review pass 2, 2026-11-20) each live CONTROL's judgement is a pure ctl_* function, fed here one input that makes
    it fire and inputs that must not, and every CONTROL step of the live run is wired to one of them on the live
    record; one subscription with a filter that cannot be read (hoStatus 3 as a bare number, which the candidate
    stores with 201) matches nothing and no longer stops the others or the serving cell; ECGI filters compare PLMN
    and cellId; rab_info carries associateId type 1 only with the address the device reports; the send log records
    the HTTP status; _links.subscription.href checked through a real loopback POST.

Expected values are written by hand from GS MEC 012 v2 (as the ETSI ATS schemas give it), not computed with the
code under test. Every row is counted; a row that raises is a FAIL, so a crash never shortens the list.

    python3 -I -B estimed_poc/test_dev02.py
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "phone"))
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402
import mec012_phone as m12  # noqa: E402
import sim_phone  # noqa: E402

try:
    import dev02_run as drv  # noqa: E402
except Exception as e:  # the driver is new: before it exists its rows FAIL, they are not skipped
    drv = None
    DRV_ERR = repr(e)

SCHEMAS = Path("/home/edgefollow/etsi-forge-ats-reference/MEC012/SRV/RNIS/schemas")
CANDIDATE_SHA256 = "eb92d88bff9ca67894cf50fe48bd279e0e5c2f180446b8cdfa82f5317e020c37"  # mec012/candidate.py at e3bbd9a

UE, OTHER_UE = "192.0.2.21", "192.0.2.99"      # RFC 5737 TEST-NET-1: documentation addresses, never routed
A, B, C, D = 0x0D02A01, 0x0D02B02, 0x0D02C03, 0x0D02D04
HEX = {A: "0D02A01", B: "0D02B02", C: "0D02C03", D: "0D02D04"}   # written by hand: 7 upper-case hex digits
PLMN = {"mcc": "001", "mnc": "01"}

RESULTS: list[tuple[str, bool, str]] = []
ROWS: list = []


def row(fn):
    ROWS.append(fn)
    return fn


def radio(ci, ue=None, mcc="001", mnc="01"):
    """A radio record as the probe app / sim_phone post it, by hand. ci None = no registered cell (detached)."""
    r = {"operator": "SIM", "plmn": mcc + mnc, "earfcn": 6300, "state": 0 if ci else 1, "t": 0, "sim": True,
         "cells": [{"registered": True, "rat": "LTE", "mcc": mcc, "mnc": mnc, "ci": ci, "tac": 4242,
                    "earfcn": 6300, "rsrp": -95, "rsrq": -9}] if ci else []}
    if ue is not None:
        r["ue_ipv4"] = ue
    return r


def sub(name, ftype="CellChangeSubscription", **filt):
    key = "filterCriteriaAssocHo" if ftype == "CellChangeSubscription" else "filterCriteriaAssocTri"
    return {"subscriptionType": ftype, "callbackReference": name, key: filt,
            "_links": {"self": {"href": f"http://127.0.0.1:8412/rni/v2/subscriptions/{name}"}}}


def ecgi(ci):
    return {"plmn": dict(PLMN), "cellId": HEX[ci]}


def run_seq(seq, subs: dict, ue=UE, mcc="001", mnc="01"):
    """Feed m12.step one snapshot per sample; returns [(callbackReference, notification)] as _notify gets them."""
    sent = []
    real = m12._notify
    m12._notify = lambda s, b: sent.append((s["callbackReference"], dict(b, _links={"subscription": s["_links"]["self"]})))
    try:
        m12.cand.SUBSCRIPTIONS.clear()
        m12.cand.SUBSCRIPTIONS.update({k: dict(v) for k, v in subs.items()})
        m12.LIVE.update(radio_ct=None, serving=None)
        for i, ci in enumerate(seq):
            m12.step({"radio": radio(ci, ue if ci else None, mcc, mnc), "radio_ct": f"ct{i}"})
    finally:
        m12._notify = real
        m12.cand.SUBSCRIPTIONS.clear()
    return sent


def cc(sent, name):
    return [b for n, b in sent if n == name and b.get("notificationType") == "CellChangeNotification"]


def mr(sent, name):
    return [b for n, b in sent if n == name and b.get("notificationType") == "MeasRepUeNotification"]


OWN = [{"type": 1, "value": UE}]
E262 = {A: {"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "0D02A01"},
        B: {"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "0D02B02"}}
E999 = {A: {"plmn": {"mcc": "999", "mnc": "99"}, "cellId": "0D02A01"}}     # the right cellId under another PLMN


def _client():
    from fastapi.testclient import TestClient
    return TestClient(m12.cand.app, base_url="http://127.0.0.1:8412", raise_server_exceptions=False)


# ---------------------------------------------------------------- the UE identifier (device_state)
@row
def r_ue_ipv4_valid():
    got = ds.ue_ipv4(radio(A, UE))
    return got == "192.0.2.21", repr(got)


@row
def r_ue_ipv4_not_an_address():
    cases = [radio(A), radio(A, "phone-DEVC"), radio(A, "2001:db8::1"), radio(A, 3221225985), radio(A, "192.0.2.300"),
             radio(A, ["192.0.2.21"]), radio(A, " 192.0.2.21"), None]
    got = [ds.ue_ipv4(r) for r in cases]
    return got == [None] * len(cases), repr(got)


# ---------------------------------------------------------------- CellChange with the UE identifier (mec012_phone)
@row
def r_cc_carries_associate_id():
    sent = run_seq([A, A, B], {"main": sub("main", associateId=OWN, ecgi=[ecgi(A)], hoStatus=[3])})
    got = cc(sent, "main")
    want = [{"notificationType": "CellChangeNotification", "hoStatus": 3, "srcEcgi": ecgi(A), "trgEcgi": [ecgi(B)],
             "associateId": [{"type": 1, "value": "192.0.2.21"}],
             "_links": {"subscription": {"href": "http://127.0.0.1:8412/rni/v2/subscriptions/main"}}}]
    stripped = [{k: v for k, v in b.items() if k != "timeStamp"} for b in got]
    ts = [b.get("timeStamp") for b in got]
    ts_ok = len(ts) == 1 and isinstance(ts[0], dict) and abs(ts[0].get("seconds", 0) - time.time()) < 60
    return stripped == want and ts_ok, f"{len(got)} sent: {stripped}"


@row
def r_cc_schema():
    import jsonschema
    sent = run_seq([A, B], {"main": sub("main", associateId=OWN)})
    got = cc(sent, "main")
    if len(got) != 1:
        return False, f"{len(got)} CellChange"
    jsonschema.validate(got[0], json.loads((SCHEMAS / "CellChangeNotification.schema.json").read_text()))
    return True, "valid against the ATS CellChangeNotification schema"


@row
def r_cc_other_ue():
    sent = run_seq([A, B], {"main": sub("main", associateId=OWN),
                            "other": sub("other", associateId=[{"type": 1, "value": OTHER_UE}])})
    return len(cc(sent, "main")) == 1 and not cc(sent, "other"), f"own {len(cc(sent, 'main'))}, other UE {len(cc(sent, 'other'))}"


@row
def r_cc_other_source():
    sent = run_seq([A, B], {"main": sub("main", associateId=OWN, ecgi=[ecgi(A)]),
                            "trg_as_src": sub("trg_as_src", ecgi=[ecgi(B)]),
                            "third": sub("third", ecgi=[ecgi(C)])})
    n = {k: len(cc(sent, k)) for k in ("main", "trg_as_src", "third")}
    return n == {"main": 1, "trg_as_src": 0, "third": 0}, str(n)


@row
def r_cc_ho_status():
    sent = run_seq([A, B], {"done": sub("done", hoStatus=[3]), "prep": sub("prep", hoStatus=[1, 2])})
    n = (len(cc(sent, "done")), len(cc(sent, "prep")))
    return n == (1, 0), str(n)


@row
def r_cc_detach_reattach():
    sent = run_seq([A, A, None, None, D, D], {"main": sub("main", associateId=OWN), "any": sub("any")})
    return not cc(sent, "main") and not cc(sent, "any"), f"{len(cc(sent, 'main'))}/{len(cc(sent, 'any'))}"


@row
def r_cc_no_change():
    sent = run_seq([A, A, A, A], {"main": sub("main", associateId=OWN), "any": sub("any")})
    return not cc(sent, "main") and not cc(sent, "any"), f"{len(sent)} notifications"


@row
def r_cc_sequence_counts():
    got = [len(cc(run_seq(s, {"main": sub("main", associateId=OWN)}), "main"))
           for s in ([A, A, B], [A, None, B], [A, A, A], [A, B, C], [A, B, B, B])]
    return got == [1, 0, 0, 2, 1], str(got)


@row
def r_cc_deleted_subscription():
    subs = {"main": sub("main", associateId=OWN), "witness": sub("witness", associateId=OWN)}
    sent = []
    real = m12._notify
    m12._notify = lambda s, b: sent.append((s["callbackReference"], b))
    try:
        m12.cand.SUBSCRIPTIONS.clear()
        m12.cand.SUBSCRIPTIONS.update(subs)
        m12.LIVE.update(radio_ct=None, serving=None)
        m12.step({"radio": radio(A, UE), "radio_ct": "1"})
        m12.step({"radio": radio(B, UE), "radio_ct": "2"})
        first = (len(cc(sent, "main")), len(cc(sent, "witness")))
        del m12.cand.SUBSCRIPTIONS["main"]
        m12.step({"radio": radio(C, UE), "radio_ct": "3"})
        after = (len(cc(sent, "main")), len(cc(sent, "witness")))
    finally:
        m12._notify = real
        m12.cand.SUBSCRIPTIONS.clear()
    return first == (1, 1) and after == (1, 2), f"before delete {first}, after {after}"


@row
def r_cc_no_address_as_before():
    """The probe app v20 reports no address: the body is the one sent before 2026-11-20 and an associateId filter,
    even naming this UE's would-be address, gets nothing."""
    sent = run_seq([A, B], {"any": sub("any"), "assoc": sub("assoc", associateId=OWN)}, ue=None)
    got = cc(sent, "any")
    keys = sorted(k for k in got[0] if k != "_links") if len(got) == 1 else None
    return keys == ["hoStatus", "notificationType", "srcEcgi", "timeStamp", "trgEcgi"] and not cc(sent, "assoc"), \
        f"keys {keys}; associateId filter {len(cc(sent, 'assoc'))}"


@row
def r_cc_malformed_address_is_none():
    sent = run_seq([A, B], {"any": sub("any"), "assoc": sub("assoc", associateId=[{"type": 1, "value": "phone-DEVC"}])},
                   ue="phone-DEVC")
    got = cc(sent, "any")
    return len(got) == 1 and "associateId" not in got[0] and not cc(sent, "assoc"), \
        f"any {[b.get('associateId') for b in got]}; filter on the non-address {len(cc(sent, 'assoc'))}"


@row
def r_cc_filter_type_must_be_1():
    sent = run_seq([A, B], {"t2": sub("t2", associateId=[{"type": 2, "value": UE}]),
                            "tstr": sub("tstr", associateId=[{"type": "1", "value": UE}]),
                            "tbool": sub("tbool", associateId=[{"type": True, "value": UE}]),
                            "notalist": sub("notalist", associateId={"type": 1, "value": UE}),
                            "ok": sub("ok", associateId=[{"type": 2, "value": "2001:db8::1"}, {"type": 1, "value": UE}])})
    n = {k: len(cc(sent, k)) for k in ("t2", "tstr", "tbool", "notalist", "ok")}
    return n == {"t2": 0, "tstr": 0, "tbool": 0, "notalist": 0, "ok": 1}, str(n)


@row
def r_cc_empty_associate_id_as_head():
    """associateId: [] lists no UE. With no device address (the probe app v20) it behaves as at HEAD e3bbd9a, whose
    whole rule was `not f.get("associateId")`: an empty list is no UE filter, so CellChange and MeasRepUe
    subscriptions carrying it get the device's notifications (reviewer's N06)."""
    sent = run_seq([A, B], {"empty": sub("empty", associateId=[]), "any": sub("any")}, ue=None)
    mru = m12._matches(sub("m", "MeasRepUeSubscription", associateId=[]), radio(A)["cells"][0], None)
    n = (len(cc(sent, "empty")), len(cc(sent, "any")))
    return n == (1, 1) and mru is True, f"CellChange empty/none {n}; MeasRepUe with associateId [] {mru}"


@row
def r_cc_src_plmn():
    """A source-cell filter names a cell by its whole ECGI, PLMN (mcc, mnc) and cellId (GS MEC 012 Ecgi). A move out of
    001/01 cell 0D02A01: a filter on 999/99 with the same cellId gets nothing, 001/01 gets it, an Ecgi without its
    PLMN names no cell, a list holding both gets it once. Until 2026-11-20 only cellId was compared."""
    sent = run_seq([A, B], {"right": sub("right", ecgi=[E262[A]]), "wrong": sub("wrong", ecgi=[E999[A]]),
                            "noplmn": sub("noplmn", ecgi=[{"cellId": "0D02A01"}]),
                            "both": sub("both", ecgi=[E999[A], E262[A]])}, mcc="001", mnc="01")
    n = {k: len(cc(sent, k)) for k in ("right", "wrong", "noplmn", "both")}
    src = [b["srcEcgi"] for b in cc(sent, "right")]
    return n == {"right": 1, "wrong": 0, "noplmn": 0, "both": 1} and src == [E262[A]], f"{n}; srcEcgi {src}"


def _recorded_posts():
    """ds.safe_post replaced by a recorder answering 2xx, so the REAL _notify runs; returns (posts, restore)."""
    posts, real = [], ds.safe_post
    ds.safe_post = lambda url, body, timeout=3: posts.append((url.rsplit("/", 1)[-1], body)) or True

    def restore():
        ds.safe_post = real
    return posts, restore


@row
def r_bad_filter_isolated():
    """The reviewer's sequence (M2), through the candidate's own HTTP API. A CellChange subscription and a MeasRepUe
    one exist; the UE is on A; then a CellChange subscription with hoStatus 3 as a bare number is created (the
    candidate answers 201) and placed FIRST, so it is judged before everyone; two more good ones are created after
    it. One move A->B, then two more samples on B: each good CellChange subscription gets exactly one CellChange
    (A->B), the bad one none; MeasRepUe reaches both MeasRepUe subscriptions on every sample; the serving cell
    advances to B; the bad filter is counted once. Before the fix every step raised TypeError from then on."""
    c = _client()
    posts, restore = _recorded_posts()
    mk = {"cc": ("CellChangeSubscription", "filterCriteriaAssocHo", {}),
          "mru": ("MeasRepUeSubscription", "filterCriteriaAssocTri", {}),
          "bad": ("CellChangeSubscription", "filterCriteriaAssocHo", {"hoStatus": 3})}

    def make(name, kind):
        t, key, f = mk[kind]
        return c.post("/rni/v2/subscriptions", json={"subscriptionType": t, "callbackReference": f"http://127.0.0.1:8433/{name}",
                                                       key: f}).status_code
    try:
        m12.cand.SUBSCRIPTIONS.clear()
        m12.LIVE.update(radio_ct=None, serving=None)
        bad0 = m12.LIVE.get("bad_filter", 0)
        st = {"early_cc": make("early_cc", "cc"), "early_mru": make("early_mru", "mru")}
        m12.step({"radio": radio(A, UE), "radio_ct": "m2-0"})
        st["bad"] = make("bad", "bad")
        subs = dict(m12.cand.SUBSCRIPTIONS)
        bad_id = next(k for k, v in subs.items() if v["callbackReference"].endswith("/bad"))
        m12.cand.SUBSCRIPTIONS.clear()
        m12.cand.SUBSCRIPTIONS[bad_id] = subs.pop(bad_id)
        m12.cand.SUBSCRIPTIONS.update(subs)
        st["late_cc"], st["late_mru"] = make("late_cc", "cc"), make("late_mru", "mru")
        posts.clear()
        for i, ci in enumerate([B, B, B]):
            m12.step({"radio": radio(ci, UE), "radio_ct": f"m2-{i + 1}"})
        serving, bad_n = m12.LIVE["serving"], m12.LIVE.get("bad_filter", 0) - bad0
    finally:
        restore()
        m12.cand.SUBSCRIPTIONS.clear()
    moves = {n: [(b["srcEcgi"]["cellId"], b["trgEcgi"][0]["cellId"]) for x, b in posts
                 if x == n and b.get("notificationType") == "CellChangeNotification"] for n in ("early_cc", "late_cc", "bad")}
    mrus = {n: sum(1 for x, b in posts if x == n and b.get("notificationType") == "MeasRepUeNotification")
            for n in ("early_mru", "late_mru", "bad")}
    ok = (st == dict.fromkeys(st, 201) and moves == {"early_cc": [("0D02A01", "0D02B02")], "late_cc": [("0D02A01", "0D02B02")],
                                                     "bad": []}
          and mrus == {"early_mru": 3, "late_mru": 3, "bad": 0} and serving == ecgi(B) and bad_n == 1)
    return ok, f"create {st}; CellChange {moves}; MeasRepUe {mrus}; serving {serving}; bad filter counted {bad_n}"


@row
def r_bad_filter_kinds():
    """Other filters that cannot be read: hoStatus "3", ecgi an object, ecgi [5], the whole filter a list, a
    MeasRepUe trigger 5 (bare), a MeasRepUe ecgi ["x"]. Each matches nothing, is counted (4 CellChange judgements
    on the one move + 2 MeasRepUe x 2 samples = 8) and stops nobody: the good ones get A->B once / both samples."""
    bad = {"hs": sub("hs", hoStatus="3"), "eobj": sub("eobj", ecgi={"cellId": "0D02A01"}), "e5": sub("e5", ecgi=[5]),
           "flist": dict(sub("flist"), filterCriteriaAssocHo=[1]),
           "trig": sub("trig", "MeasRepUeSubscription", trigger=5), "ex": sub("ex", "MeasRepUeSubscription", ecgi=["x"])}
    good = {"any": sub("any"), "m": sub("m", "MeasRepUeSubscription")}
    bad0 = m12.LIVE.get("bad_filter", 0)
    sent = run_seq([A, B], {**bad, **good})
    got = {k: len(cc(sent, k)) + len(mr(sent, k)) for k in bad}
    n = m12.LIVE.get("bad_filter", 0) - bad0
    return (got == dict.fromkeys(bad, 0) and len(cc(sent, "any")) == 1 and len(mr(sent, "m")) == 2 and n == 8), \
        f"bad {got}; good CellChange {len(cc(sent, 'any'))}, MeasRepUe {len(mr(sent, 'm'))}; counted {n}"


# ---------------------------------------------------------------- MeasRepUe with the UE identifier
@row
def r_mru_associate_id():
    body = m12.meas_rep_ue(radio(A, UE))
    body0 = m12.meas_rep_ue(radio(A))
    return (body.get("associateId") == [{"type": 1, "value": "192.0.2.21"}] and "associateId" not in body0), \
        f"with {body.get('associateId')}, without {body0.get('associateId')}"


@row
def r_mru_filter():
    c = radio(A, UE)["cells"][0]
    mru = sub("m", "MeasRepUeSubscription")
    got = (m12._matches(dict(mru, filterCriteriaAssocTri={"associateId": OWN}), c, UE),
           m12._matches(dict(mru, filterCriteriaAssocTri={"associateId": [{"type": 1, "value": OTHER_UE}]}), c, UE),
           m12._matches(dict(mru, filterCriteriaAssocTri={"associateId": OWN}), c, None),
           m12._matches(dict(mru, filterCriteriaAssocTri={}), c, None),
           m12._matches(dict(mru, filterCriteriaAssocTri={"associateId": OWN}), c))
    return got == (True, False, False, True, False), str(got)


@row
def r_mru_plmn():
    """A MeasRepUe ecgi filter compares PLMN and cellId: for a cell 001/01 0D02A01, 999/99 with the same cellId does
    not match, 001/01 does, an Ecgi without PLMN does not, 001/01 with another cellId does not; through step() the
    999/99 subscription gets no MeasRepUe while the 001/01 one gets both samples."""
    c = radio(A, mcc="001", mnc="01")["cells"][0]

    def mk(e):
        return sub("m", "MeasRepUeSubscription", ecgi=e)
    got = (m12._matches(mk([E262[A]]), c, None), m12._matches(mk([E999[A]]), c, None),
           m12._matches(mk([{"cellId": "0D02A01"}]), c, None), m12._matches(mk([E262[B]]), c, None))
    sent = run_seq([A, A], {"right": sub("right", "MeasRepUeSubscription", ecgi=[E262[A]]),
                            "wrong": sub("wrong", "MeasRepUeSubscription", ecgi=[E999[A]])}, mcc="001", mnc="01")
    n = (len(mr(sent, "right")), len(mr(sent, "wrong")))
    return got == (True, False, False, False) and n == (2, 0), f"_matches {got}; MeasRepUe right/wrong {n}"


@row
def r_rab_info_associate_id():
    """rab_info names the UE by associateId type 1 (UE_IPv4_ADDRESS) only with the address the device itself reports
    (ue_ipv4). Asked by the lab's MEC 013 name for the phone (PHONE_ADDRESS without acr:, which is not an IPv4
    address) it answers the same cell with associateId [{value}] and NO type: the ATS RabInfo schema requires
    neither, and type 1 would say the name is an IPv4 address. Another address, or the documentation address while
    the device reports none, does not get the phone's cell. Every answer is valid against the ATS RabInfo schema."""
    import jsonschema
    schema = json.loads((SCHEMAS / "RabInfo.schema.json").read_text())
    c = _client()
    name = ds.PHONE_ADDRESS.removeprefix("acr:")
    snap0 = m12.LIVE["snap"]
    q = lambda v: c.get("/rni/v2/queries/rab_info", params={"ue_ipv4_address": v})  # noqa: E731
    try:
        m12.LIVE["snap"] = {"radio": radio(A, UE)}
        r_ip, r_nm, r_other = q(UE), q(name), q(OTHER_UE)
        m12.LIVE["snap"] = {"radio": radio(A)}               # the probe app v20: no address reported
        r_ip0, r_nm0 = q(UE), q(name)
    finally:
        m12.LIVE["snap"] = snap0

    def cells(r):
        return r.json().get("cellUserInfo") if r.status_code == 200 else None
    want_ip = [{"ecgi": ecgi(A), "ueInfo": [{"associateId": [{"type": 1, "value": "192.0.2.21"}], "erabInfo": []}]}]
    want_nm = [{"ecgi": ecgi(A), "ueInfo": [{"associateId": [{"value": name}], "erabInfo": []}]}]
    for r in (r_ip, r_nm, r_nm0):
        if r.status_code == 200:
            jsonschema.validate(r.json(), schema)
    ok = (cells(r_ip) == want_ip and cells(r_nm) == want_nm and cells(r_nm0) == want_nm
          and "0D02A01" not in r_other.text and "0D02A01" not in r_ip0.text)
    return ok, (f"ip {r_ip.status_code} {cells(r_ip)}; name {r_nm.status_code} {cells(r_nm)}; other {r_other.status_code}; "
                f"no address: ip {r_ip0.status_code} {'phone cell' if '0D02A01' in r_ip0.text else 'not the phone'}, "
                f"name {cells(r_nm0)}")


# ---------------------------------------------------------------- the simulated UE (sim_phone)
@row
def r_sim_declares_address():
    ph = sim_phone.SimPhone("http://127.0.0.1:9/x", "Cdev02-test", "t", ci=A, ue_ipv4=UE)
    r = ph.records()["radio"]
    return r.get("ue_ipv4") == "192.0.2.21" and r.get("sim") is True and ds.serving_cell(r)["ci"] == A, \
        f"ue_ipv4 {r.get('ue_ipv4')}, sim {r.get('sim')}"


@row
def r_sim_default_shape_unchanged():
    r = sim_phone.SimPhone("http://127.0.0.1:9/x", "Cdev02-test", "t").records()["radio"]
    return sorted(r) == ["bw_khz", "cells", "earfcn", "operator", "plmn", "sim", "state", "t"], str(sorted(r))


@row
def r_sim_detach_reattach():
    ph = sim_phone.SimPhone("http://127.0.0.1:9/x", "Cdev02-test", "t", ci=A, ue_ipv4=UE)
    ph.set_attached(False)
    off = ph.records()["radio"]
    ph.set_cell(D)
    ph.set_attached(True)
    on = ph.records()["radio"]
    return (ds.serving_cell(off) is None and "ue_ipv4" not in off and off.get("sim") is True
            and ds.serving_cell(on)["ci"] == D and on.get("ue_ipv4") == UE), \
        f"detached: cell {ds.serving_cell(off)}, address {off.get('ue_ipv4')}; re-attached: {ds.serving_cell(on) and ds.serving_cell(on)['ci']:#x}"


@row
def r_sim_drives_rnis():
    """End to end without a network: the simulated UE's own records, through m12.step, give one CellChange A->B
    with its declared address, and none on detach + re-attach on D."""
    ph = sim_phone.SimPhone("http://127.0.0.1:9/x", "Cdev02-test", "t", ci=A, ue_ipv4=UE)
    sent = []
    real = m12._notify
    m12._notify = lambda s, b: sent.append((s["callbackReference"], b))
    try:
        m12.cand.SUBSCRIPTIONS.clear()
        m12.cand.SUBSCRIPTIONS["w"] = sub("w", associateId=OWN)
        m12.LIVE.update(radio_ct=None, serving=None)
        script = [("cell", A), ("cell", A), ("cell", B), ("off", None), ("cell", D), ("on", None), ("cell", D)]
        for i, (what, v) in enumerate(script):
            if what == "cell":
                ph.set_cell(v)
            else:
                ph.set_attached(what == "on")
            m12.step({"radio": ph.records()["radio"], "radio_ct": f"s{i}"})
    finally:
        m12._notify = real
        m12.cand.SUBSCRIPTIONS.clear()
    got = [(b["srcEcgi"]["cellId"], b["trgEcgi"][0]["cellId"], b.get("associateId")) for b in cc(sent, "w")]
    return got == [("0D02A01", "0D02B02", [{"type": 1, "value": "192.0.2.21"}])], str(got)


# ---------------------------------------------------------------- the RNIS's account of each send (real loopback HTTP)
class _Sink(BaseHTTPRequestHandler):
    status = 204
    bodies: list = []

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
        try:
            type(self).bodies.append(json.loads(raw))
        except ValueError:
            type(self).bodies.append(None)
        self.send_response(type(self).status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def _send_once(status: int, allow: bool = True):
    handler = type("S", (_Sink,), {"status": status, "bodies": []})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{srv.server_address[1]}"
    if allow:
        ds._CB_EXTRA.add(origin)
    log = Path(tempfile.mkdtemp(prefix="dev02-sendlog-")) / "send.jsonl"
    old_log = getattr(m12, "SENDLOG", None)
    before = (m12.LIVE["sent"], m12.LIVE["send_fail"])
    try:
        m12.SENDLOG = str(log)
        s = {"callbackReference": origin + "/cb", "_links": {"self": {"href": "http://127.0.0.1:8412/rni/v2/subscriptions/sub-9"}}}
        m12._notify(s, {"notificationType": "CellChangeNotification"})
    finally:
        m12.SENDLOG = old_log
        ds._CB_EXTRA.discard(origin)
        srv.shutdown()
        srv.server_close()
    after = (m12.LIVE["sent"], m12.LIVE["send_fail"])
    lines = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    return (after[0] - before[0], after[1] - before[1]), lines, handler.bodies


@row
def r_send_204_counted():
    d, _, _ = _send_once(204)
    return d == (1, 0), f"sent/failed +{d}"


@row
def r_send_204_logged():
    """The send log line says delivered AND records the AE's HTTP status (204), not only "some 2xx"."""
    _, lines, _ = _send_once(204)
    ok = (len(lines) == 1 and lines[0].get("ok") is True and lines[0].get("type") == "CellChangeNotification"
          and lines[0].get("sub") == "http://127.0.0.1:8412/rni/v2/subscriptions/sub-9" and lines[0].get("status") == 204)
    return ok, str(lines)


@row
def r_send_200_is_not_204():
    """A 200 answer is a delivered send, logged with status 200: a reader of the log can tell it from 204."""
    d, lines, _ = _send_once(200)
    return d == (1, 0) and len(lines) == 1 and lines[0].get("ok") is True and lines[0].get("status") == 200, str(lines)


@row
def r_send_500_counted_as_failure():
    d, _, _ = _send_once(500)
    return d == (0, 1), f"sent/failed +{d}"


@row
def r_send_500_logged_as_failure():
    _, lines, _ = _send_once(500)
    return (len(lines) == 1 and lines[0].get("ok") is False and "500" in str(lines[0].get("err"))
            and lines[0].get("status") == 500), str(lines)


@row
def r_send_refused_logged():
    """A callback outside the allowed set is never contacted: a failed send with no HTTP status, and nothing posted."""
    d, lines, bodies = _send_once(204, allow=False)
    return (d == (0, 1) and len(lines) == 1 and lines[0].get("ok") is False and lines[0].get("status") is None
            and bodies == []), f"+{d}; {lines}; {len(bodies)} bodies at the sink"


@row
def r_send_links_subscription_href():
    """Through the REAL _notify and a real loopback POST (the CellChange rows replace _notify): the body that reaches
    the callback carries _links.subscription.href = the subscription's own _links.self.href (GS MEC 012 6.4.2),
    not its callbackReference (reviewer's N04)."""
    _, _, bodies = _send_once(204)
    links = [b.get("_links") if isinstance(b, dict) else b for b in bodies]
    return links == [{"subscription": {"href": "http://127.0.0.1:8412/rni/v2/subscriptions/sub-9"}}], str(links)


# ---------------------------------------------------------------- the driver's judgements (dev02_run.py)
def _need_drv():
    if drv is None:
        raise RuntimeError(f"estimed_poc/dev02_run.py does not import: {DRV_ERR}")


@row
def r_drv_budget_stated():
    _need_drv()
    b = drv.LATENCY_BUDGET_S
    why = drv.LATENCY_BUDGET_WHY
    # Pinned to the number stated before the first live run (2026-11-20): any other value is a changed budget.
    return type(b) is float and b == 3.0 and "1 + 1.5 + 0.5 = 3.0 s" in why, f"{b} s: {why[:80]}"


@row
def r_drv_latency():
    _need_drv()
    # 2026-11-20 01:02:03.250 UTC = 1795136523.25 (from GNU date: date -u -d '2026-11-20 01:02:03' +%s = 1795136523)
    got = (drv.latency_s("20261120T010203,250000", 1795136525.75), drv.latency_s("20261120T010203", 1795136523.5),
           drv.ct_epoch("20261120T010203,250000"))
    return got == (2.5, 0.5, 1795136523.25), str(got)


@row
def r_drv_cellchange_check():
    _need_drv()
    href = "http://127.0.0.1:8412/rni/v2/subscriptions/sub-1"
    now = 1795136523
    good = {"notificationType": "CellChangeNotification", "timeStamp": {"seconds": now, "nanoSeconds": 5},
            "hoStatus": 3, "srcEcgi": {"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "0D02A01"},
            "trgEcgi": [{"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "0D02B02"}],
            "associateId": [{"type": 1, "value": "192.0.2.21"}], "_links": {"subscription": {"href": href}}}
    kw = dict(src_ci=A, trg_ci=B, ue=UE, sub_href=href, now=now)
    bad = [
        ("srcEcgi", dict(good, srcEcgi={"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "0D02B02"})),
        ("srcEcgi", dict(good, srcEcgi={"plmn": {"mcc": "999", "mnc": "99"}, "cellId": "0D02A01"})),  # right cell, wrong PLMN
        ("trgEcgi", dict(good, trgEcgi=[good["trgEcgi"][0], good["trgEcgi"][0]])),
        ("trgEcgi", dict(good, trgEcgi=[{"plmn": {"mcc": "999", "mnc": "99"}, "cellId": "0D02B02"}])),
        ("associateId", {k: v for k, v in good.items() if k != "associateId"}),
        ("hoStatus", dict(good, hoStatus=1)),
        ("_links", dict(good, _links={"subscription": {"href": href + "0"}})),
        ("notificationType", dict(good, notificationType="MeasRepUeNotification")),
        ("timeStamp", dict(good, timeStamp={"seconds": now - 3600, "nanoSeconds": 0})),
    ]
    got_good = drv.cellchange_faults(good, **kw)
    wrong = [(k, v) for k, b in bad if (v := drv.cellchange_faults(b, **kw)) != [k]]
    return got_good == [] and not wrong, f"good {got_good}; mislabelled {wrong}"


@row
def r_drv_location():
    _need_drv()
    h = "http://127.0.0.1:8412/rni/v2/subscriptions/sub-7"
    got = (drv.location_ok("/rni/v2/subscriptions/sub-7", h), drv.location_ok(h, h),
           drv.location_ok("/rni/v2/subscriptions/", h), drv.location_ok("/rni/v2/subscriptions/sub-8", h),
           drv.location_ok(None, h), drv.location_ok("", h), drv.location_ok("/rni/v2/subscriptions/sub-7", None))
    return got == (True, True, False, False, False, False, False), str(got)


@row
def r_drv_listener_answers():
    _need_drv()
    base = "/dev02/r1"
    got = [drv.status_for(p, base) for p in (base, base + "/otherue", base + "/othersrc", base + "/witness",
                                               base + "/fail500", base + "/nope", "/dev02/r2", base + "x", "/")]
    return got == [204, 204, 204, 204, 500, 404, 404, 404, 404], str(got)


@row
def r_drv_attribution():
    _need_drv()
    base = "/dev02/r1"
    subs = {"main": "http://h/rni/v2/subscriptions/sub-1", "witness": "http://h/rni/v2/subscriptions/sub-2"}

    def n(path, href):
        return {"path": path, "t": 0.0, "status": 204, "body": {"_links": {"subscription": {"href": href}}}}
    notes = [n(base, subs["main"]), n(base + "/witness", subs["witness"]), n(base, subs["witness"]),
             n(base + "/witness", subs["main"]), n("/elsewhere", subs["main"]), {"path": base, "t": 0, "status": 204, "body": None}]
    by, mis = drv.attribute(notes, base, subs)
    return (len(by.get("main", [])), len(by.get("witness", [])), len(mis)) == (1, 1, 4), \
        f"main {len(by.get('main', []))}, witness {len(by.get('witness', []))}, misattributed {len(mis)}"


@row
def r_drv_verdict():
    _need_drv()
    ok_steps = [("step 1", True, ""), ("CONTROL (must FAIL) x", False, "")]
    got = (drv.verdict(ok_steps, cleanup_ok=True),
           drv.verdict(ok_steps + [("CONTROL (must FAIL) y", True, "")], cleanup_ok=True),
           drv.verdict([("step 1", True, "")], cleanup_ok=True),
           drv.verdict(ok_steps + [("step 2", False, "")], cleanup_ok=True),
           drv.verdict(ok_steps, cleanup_ok=False),
           drv.verdict(ok_steps, cleanup_ok=True, aborted_at="step 3"))
    return got == (True, False, False, False, False, False), str(got)


@row
def r_drv_lock_guard():
    _need_drv()
    p = Path(tempfile.mkdtemp(prefix="dev02-lock-")) / ".live.lock"
    p.touch()
    free = drv.lock_held(str(p))
    fd = os.open(p, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        held = drv.lock_held(str(p))
    finally:
        os.close(fd)
    missing = drv.lock_held(str(p) + ".absent")
    return (free, held, missing) == (False, True, False), f"free {free}, held {held}, missing file {missing}"


# ---------------------------------------------------------------- the live CONTROLs' judgements (dev02_run.ctl_*)
BASE = "/dev02/r1"
H_MAIN, H_WIT, H_500 = ("http://127.0.0.1:8412/rni/v2/subscriptions/sub-1", "http://127.0.0.1:8412/rni/v2/subscriptions/sub-2",
                        "http://127.0.0.1:8412/rni/v2/subscriptions/sub-5")


def _n(path, t, href=None, status=204):
    """One POST as the driver's listener records it."""
    return {"path": path, "t": t, "status": status,
            "body": {"_links": {"subscription": {"href": href}}} if href else None}


@row
def r_ctl_any_post():
    """No-change and detach/re-attach controls: fire on any POST in [t0, t1); not on one before t0, at t1 or after,
    nor on none."""
    _need_drv()
    notes = [_n(BASE, 10.0, H_MAIN)]
    got = tuple(drv.ctl_any_post(x, t0, t1)[0] for x, t0, t1 in (
        (notes, 9.0, 11.0), (notes, 10.0, 10.5), (notes, 10.5, 12.0), (notes, 8.0, 10.0), ([], 0.0, 99.0)))
    return got == (True, True, False, False, False), str(got)


@row
def r_ctl_repeat():
    """One move, two notifications for the main subscription since the move: fires. One before the move, one each for
    main and witness, a second one whose _links names another subscription, or a single one: does not."""
    _need_drv()
    subs = {"main": H_MAIN, "witness": H_WIT}
    two = [_n(BASE, 5.0, H_MAIN), _n(BASE, 7.0, H_MAIN)]
    got = (drv.ctl_repeat(two, BASE, subs, 4.0)[0], drv.ctl_repeat(two, BASE, subs, 6.0)[0],
           drv.ctl_repeat([_n(BASE, 5.0, H_MAIN), _n(BASE + "/witness", 5.1, H_WIT)], BASE, subs, 4.0)[0],
           drv.ctl_repeat([_n(BASE, 5.0, H_MAIN), _n(BASE, 6.0, H_WIT)], BASE, subs, 4.0)[0],
           drv.ctl_repeat([_n(BASE, 5.0, H_MAIN)], BASE, subs, 4.0)[0])
    return got == (True, False, False, False, False), str(got)


@row
def r_ctl_got():
    """Other-UE / other-source controls: fire on any POST at base/<name>; not on the endpoint itself, another control
    path, another run's base, or a longer path. A name the listener does not serve raises (a control on a path
    nothing posts to can never fire: reviewer's N12)."""
    _need_drv()
    others = [_n(BASE, 1.0), _n(BASE + "/witness", 1.0), _n("/dev02/r2/otherue", 1.0), _n(BASE + "/otherue/x", 1.0)]
    got = (drv.ctl_got([_n(BASE + "/otherue", 1.0)], BASE, "otherue")[0],
           drv.ctl_got([_n(BASE + "/othersrc", 1.0)], BASE, "othersrc")[0],
           drv.ctl_got([_n(BASE + "/otherue", 1.0)], BASE, "othersrc")[0],
           drv.ctl_got(others, BASE, "otherue")[0])
    try:
        drv.ctl_got([_n(BASE + "/other_ue", 1.0)], BASE, "other_ue")
        raised = False
    except ValueError:
        raised = True
    return got == (True, True, False, False) and raised, f"{got}; unserved name raises {raised}"


@row
def r_ctl_counted_500():
    """The 500 control fires when the send log says the 500 subscription's send was delivered (ok true); not when it
    says failed, nor for another subscription's delivered send, nor on an empty log. No subscription href raises."""
    _need_drv()
    got = (drv.ctl_counted_500([{"sub": H_500, "ok": True, "status": 500}], H_500)[0],
           drv.ctl_counted_500([{"sub": H_500, "ok": False, "status": 500}], H_500)[0],
           drv.ctl_counted_500([{"sub": H_MAIN, "ok": True, "status": 204}], H_500)[0],
           drv.ctl_counted_500([], H_500)[0])
    try:
        drv.ctl_counted_500([{"sub": None, "ok": True}], None)
        raised = False
    except ValueError:
        raised = True
    return got == (True, False, False, False) and raised, f"{got}; no href raises {raised}"


@row
def r_ctl_after_delete():
    """The deleted-subscription control fires on a POST at the endpoint at or after the delete; not on one before it,
    nor on another path after it."""
    _need_drv()
    got = (drv.ctl_after_delete([_n(BASE, 10.0)], BASE, 9.0)[0], drv.ctl_after_delete([_n(BASE, 9.0)], BASE, 9.0)[0],
           drv.ctl_after_delete([_n(BASE, 8.0)], BASE, 9.0)[0],
           drv.ctl_after_delete([_n(BASE + "/witness", 10.0)], BASE, 9.0)[0])
    return got == (True, True, False, False), str(got)


@row
def r_drv_send_record():
    """Step 5 (and the 500 step) from the RNIS side: exactly one send-log line for the subscription, with the
    expected ok AND HTTP status. 200 is not 204; a line without status (as logged before 2026-11-20) is not enough;
    two lines, another subscription's line, or ok true with status 500 are not it."""
    _need_drv()
    one = lambda **kw: [dict({"sub": H_MAIN}, **kw)]  # noqa: E731
    got = (drv.send_record_ok(one(ok=True, status=204), H_MAIN, ok=True, status=204)[0],
           drv.send_record_ok(one(ok=True, status=200), H_MAIN, ok=True, status=204)[0],
           drv.send_record_ok(one(ok=True), H_MAIN, ok=True, status=204)[0],
           drv.send_record_ok(one(ok=True, status=204) * 2, H_MAIN, ok=True, status=204)[0],
           drv.send_record_ok([{"sub": H_WIT, "ok": True, "status": 204}], H_MAIN, ok=True, status=204)[0],
           drv.send_record_ok(one(ok=False, status=500), H_MAIN, ok=False, status=500)[0],
           drv.send_record_ok(one(ok=True, status=500), H_MAIN, ok=False, status=500)[0],
           drv.send_record_ok(one(ok=True, status=204), None, ok=True, status=204)[0])
    return got == (True, False, False, False, False, True, False, False), str(got)


@row
def r_drv_controls_wired():
    """Every CONTROL step in the driver's main() is judged by one of its ctl_* functions, called on the live record
    (NOTES, or the send log as read_sendlog reads it), naming only paths the listener serves; all 7 live controls,
    every ctl_* function used. A control whose input is cut off at the call site (builder's F23: `cc_hold = []`) or a
    literal verdict FAILs here, not only in a live run."""
    _need_drv()
    import ast
    tree = ast.parse(Path(drv.__file__).read_text())
    main_fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    defs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("ctl_")}
    count, used, bad = 0, set(), []
    for c in ast.walk(main_fn):
        if not (isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "step" and c.args):
            continue
        a0 = c.args[0]
        lead = a0.value if isinstance(a0, ast.Constant) else (
            a0.values[0].value if isinstance(a0, ast.JoinedStr) and a0.values and isinstance(a0.values[0], ast.Constant) else "")
        if not str(lead).startswith("CONTROL"):
            continue
        count += 1
        j = c.args[1] if len(c.args) == 2 and not c.keywords else None
        call = j.value if isinstance(j, ast.Starred) else None
        if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in defs and call.args):
            bad.append((c.lineno, "not step(label, *ctl_x(...))"))
            continue
        used.add(call.func.id)
        src = call.args[0]
        if not ((isinstance(src, ast.Name) and src.id == "NOTES")
                or (isinstance(src, ast.Call) and isinstance(src.func, ast.Name) and src.func.id == "read_sendlog")):
            bad.append((c.lineno, f"input {ast.unparse(src)}"))
        for x in call.args[1:]:
            if isinstance(x, ast.Constant) and isinstance(x.value, str) and x.value not in drv.CONTROL_PATHS:
                bad.append((c.lineno, f"path {x.value!r} is not served"))
    return count == 7 and used == defs and not bad, f"{count} CONTROL steps; ctl_ used {sorted(used)} of {sorted(defs)}; {bad}"


@row
def r_drv_does_not_show_wording():
    """DOES_NOT_SHOW says the UE address is the UE's own claim, not one a network assigned."""
    _need_drv()
    txt = " ".join(drv.DOES_NOT_SHOW)
    return "the UE's own claim" in txt and "not one a network assigned" in txt, txt[:160]


# ---------------------------------------------------------------- the ATS-scored file is untouched
@row
def r_candidate_unchanged():
    got = hashlib.sha256((REPO / "mec012" / "candidate.py").read_bytes()).hexdigest()
    return got == CANDIDATE_SHA256, got[:16]


def main() -> int:
    print("== TD_MEC_DEV_02 offline rows")
    for fn in ROWS:
        name = fn.__name__
        try:
            ok, detail = fn()
        except Exception as e:
            ok, detail = False, f"raised {type(e).__name__}: {e}"
            if os.environ.get("DEV02_TRACE"):
                traceback.print_exc()
        RESULTS.append((name, bool(ok), detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}  -- {detail}")
    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f"\nRESULT: {len(RESULTS) - len(bad)}/{len(RESULTS)} rows pass" + (f"; failing: {bad}" if bad else ""))
    return 0 if not bad and len(RESULTS) == len(ROWS) else 1


if __name__ == "__main__":
    sys.exit(main())
