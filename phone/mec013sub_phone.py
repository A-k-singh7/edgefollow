#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""MEC 013 Location SUBSCRIPTIONS with notifications driven by the REAL phone.

The unmodified `mec013_sub/candidate.py` is loaded and served as-is (subscription CRUD
exactly as the ATS scores it). A notifier evaluates every stored subscription against
the phone's live state (via mec013_phone.phone_user, i.e. the oneM2M containers) and the
fixture UEs of mec013_look (for reference users and zone counts):

  users  UserLocationPeriodicSubscription  reportingAmount reports, every reportingInterval s;
                                           result SUCCESS with the fix, ABNORMAL without one;
                                           the last carries isFinalNotification.
         UserLocationEventSubscription     ENTERING/LEAVING when the phone's access point
                                           (serving cell) changes or the phone drops off/returns.
  zones  ZoneLocationEventSubscription     ENTERING/LEAVING when the phone enters/leaves zoneId.
         ZoneStatusSubscription            userNumEvent 1/2 (zone upper/lower threshold) and
                                           3/4 (AP upper/lower) on a threshold CROSSING.
  distance UserDistanceSubscription        great-circle distance between monitored and
                                           reference users; notifies when `criteria` becomes
                                           true (and at once if checkImmediate and already true).
  area   UserAreaSubscription (circle)     ENTERING/LEAVING on a real boundary crossing.

Events fire on transitions only; nothing is emitted merely because a subscription exists
(except periodic reports and checkImmediate, which the spec asks for).

    PHONE_MEC013SUB_PORT (default 8406)
"""
from __future__ import annotations

import collections
import importlib.util
import math
import os
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402
import mec013_phone as m13  # noqa: E402  (loads mec013_look: fixture UEs + phone_user)

spec = importlib.util.spec_from_file_location("mec013_sub_candidate", HERE.parent / "mec013_sub" / "candidate.py")
cand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cand)
PORT = int(os.environ.get("PHONE_MEC013SUB_PORT", "8406"))
LIVE = {"phone": None, "sent": 0, "send_fail": 0, "error": None, "log": collections.deque(maxlen=1000)}
STATE: dict[str, dict] = {}   # per subscription id: evaluator memory


def _now() -> dict:
    t = time.time_ns()
    return {"seconds": t // 1_000_000_000, "nanoSeconds": t % 1_000_000_000}


def _cb(sub: dict) -> str | None:
    c = sub.get("callbackReference")
    if isinstance(c, dict):
        c = c.get("notifyURL")
    return c if isinstance(c, str) and c.startswith("http") else None


def _post(sub: dict, sid: str, rtype: str, body: dict) -> None:
    url = _cb(sub)
    if not url:
        return
    href = f"http://127.0.0.1:{PORT}/location/v3/subscriptions/{rtype}/{sid}"
    # GS MEC 013 v3.2.1 Table 6.4.5-1 (and ETSI's sandbox, meep-loc-serv loc-serv.go:1425) link EVERY notification,
    # periodic too, under `subscription`. ETSI's ATS schema and example put the periodic one under `self` and allow
    # extra keys -- an ATS-side defect -- so the periodic link is served under both, equal (deep check 2026-10-29).
    links = {"subscription": {"href": href}}
    if body.get("notificationType") == "UserLocationPeriodicNotification":
        links["self"] = {"href": href}
    body = dict(body, _links=links)
    try:
        if not ds.safe_post(url, body):
            LIVE["send_fail"] += 1
            return
        LIVE["sent"] += 1
        LIVE["log"].append((time.time(), rtype, body.get("notificationType")))
    except Exception:
        LIVE["send_fail"] += 1


def haversine_m(a: dict, b: dict) -> float:
    la1, lo1 = math.radians(a["latitude"][0] if isinstance(a["latitude"], list) else a["latitude"]), \
        math.radians(a["longitude"][0] if isinstance(a["longitude"], list) else a["longitude"])
    la2, lo2 = math.radians(b["latitude"][0] if isinstance(b["latitude"], list) else b["latitude"]), \
        math.radians(b["longitude"][0] if isinstance(b["longitude"], list) else b["longitude"])
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6_371_008.8 * math.asin(math.sqrt(h))


def users_now(phone: dict | None) -> dict[str, dict]:
    u = {a: r for a, r in m13.cand.USERS.items() if a != ds.PHONE_ADDRESS}
    if phone:
        u[ds.PHONE_ADDRESS] = phone
    return u


def _addr_in(sub_addr, addr: str) -> bool:
    return addr == sub_addr or (isinstance(sub_addr, list) and addr in sub_addr)


def evaluate(phone: dict | None) -> None:
    users = users_now(phone)
    with cand._lock:
        subs = {(t, sid): dict(b) for t, d in cand.SUBS.items() for sid, b in d.items()
                if sid != cand.SEED_SUBSCRIPTION_ID}
    for key in list(STATE):
        if key not in {f"{t}/{s}" for t, s in subs}:
            del STATE[key]
    for (rtype, sid), body in subs.items():
        st = STATE.setdefault(f"{rtype}/{sid}", {})
        sub = cand._inner(rtype, body)
        typ = sub.get("subscriptionType")
        if rtype == "users" and typ == "UserLocationPeriodicSubscription" and _addr_in(sub.get("address"), ds.PHONE_ADDRESS):
            pe = sub.get("periodicEventInfo") or {}
            amount, interval = int(pe.get("reportingAmount", 1)), float(pe.get("reportingInterval", 1))
            sent, due = st.get("sent", 0), st.get("due", 0.0)
            if sent < amount and time.time() >= due:
                n = {"notificationType": "UserLocationPeriodicNotification", "timeStamp": _now(),
                     "address": ds.PHONE_ADDRESS,
                     "result": "SUCCESS" if phone and "locationInfo" in phone else "ABNORMAL"}
                if phone:
                    n.update(accessPointId=phone["accessPointId"], zoneId=phone["zoneId"])
                    if "locationInfo" in phone:
                        n["locationInfo"] = phone["locationInfo"]
                if sent + 1 == amount:
                    n["isFinalNotification"] = True
                _post(sub, sid, rtype, n)
                st["sent"], st["due"] = sent + 1, time.time() + interval
        elif rtype == "users" and typ == "UserLocationEventSubscription" and _addr_in(sub.get("address"), ds.PHONE_ADDRESS):
            crit = sub.get("locationEventCriteria") or ["ENTERING_AREA_EVENT", "LEAVING_AREA_EVENT"]
            ap = phone["accessPointId"] if phone else None
            if "ap" in st and st["ap"] != ap:
                if st["ap"] is not None and "LEAVING_AREA_EVENT" in crit:
                    _post(sub, sid, rtype, {"notificationType": "UserLocationEventNotification", "timeStamp": _now(),
                                            "address": ds.PHONE_ADDRESS, "userLocationEvent": "LEAVING_AREA_EVENT",
                                            "accessPointId": st["ap"], "zoneId": st["zone"]})
                if ap is not None and "ENTERING_AREA_EVENT" in crit:
                    _post(sub, sid, rtype, {"notificationType": "UserLocationEventNotification", "timeStamp": _now(),
                                            "address": ds.PHONE_ADDRESS, "userLocationEvent": "ENTERING_AREA_EVENT",
                                            "accessPointId": ap, "zoneId": phone["zoneId"],
                                            **({"locationInfo": phone["locationInfo"]} if "locationInfo" in phone else {})})
            st["ap"], st["zone"] = ap, (phone["zoneId"] if phone else None)
        elif rtype == "zones" and typ == "ZoneLocationEventSubscription":
            zone = sub.get("zoneId")
            crit = sub.get("locationEventCriteria") or ["ENTERING_AREA_EVENT", "LEAVING_AREA_EVENT"]
            wanted = sub.get("addressList") or [ds.PHONE_ADDRESS]
            if ds.PHONE_ADDRESS in wanted:
                inside = bool(phone and phone["zoneId"] == zone)
                if "inside" in st and st["inside"] != inside:
                    ev = "ENTERING_AREA_EVENT" if inside else "LEAVING_AREA_EVENT"
                    if ev in crit:
                        _post(sub, sid, rtype, {"notificationType": "ZoneLocationEventNotification", "timeStamp": _now(),
                                                "address": ds.PHONE_ADDRESS, "zoneId": zone, "userLocationEvent": ev})
                st["inside"] = inside
        elif rtype == "zones" and typ == "ZoneStatusSubscription":
            zone = sub.get("zoneId")
            in_zone = [r for r in users.values() if r.get("zoneId") == zone]
            n_zone = len(in_zone)
            # Per access point in the zone, not "the phone's AP": each AP's own count is
            # compared with that SAME AP's previous count.
            ap_counts: dict[str, int] = {}
            for r in in_zone:
                ap_counts[r.get("accessPointId")] = ap_counts.get(r.get("accessPointId"), 0) + 1
            if "n_zone" in st:
                ev: list[tuple[int, str | None]] = []
                up, lo = sub.get("upperNumberOfUsersZoneThreshold"), sub.get("lowerNumberOfUsersZoneThreshold")
                if up is not None and st["n_zone"] <= up < n_zone:
                    ev.append((1, None))
                if lo is not None and st["n_zone"] >= lo > n_zone:
                    ev.append((2, None))
                upa, loa = sub.get("upperNumberOfUsersAPThreshold"), sub.get("lowerNumberOfUsersAPThreshold")
                for ap in sorted(set(st["ap_counts"]) | set(ap_counts), key=str):
                    before, now = st["ap_counts"].get(ap, 0), ap_counts.get(ap, 0)
                    if upa is not None and before <= upa < now:
                        ev.append((3, ap))
                    if loa is not None and before >= loa > now:
                        ev.append((4, ap))
                for e, ap in ev:
                    n = {"notificationType": "ZoneStatusNotification", "timeStamp": _now(), "zoneId": zone, "userNumEvent": e}
                    if ap:
                        n["accessPointId"] = ap
                    _post(sub, sid, rtype, n)
            st["n_zone"], st["ap_counts"] = n_zone, ap_counts
        elif rtype == "distance":
            mon, ref = sub.get("monitoredAddress") or [], sub.get("referenceAddress") or []
            if ds.PHONE_ADDRESS not in mon + ref:
                continue
            crit, dist = sub.get("criteria"), float(sub.get("distance", 0))
            located = {a: u for a, u in users.items() if "locationInfo" in u}
            # Without referenceAddress, ETSI measures every pair of monitored users.
            if ref:
                pair_ids = [(m, r) for m in mon for r in ref if m != r]
            else:
                pair_ids = [(mon[i], mon[j]) for i in range(len(mon)) for j in range(i + 1, len(mon))]
            pairs = [haversine_m(located[m]["locationInfo"], located[r]["locationInfo"])
                     for m, r in pair_ids if m in located and r in located]
            if not pairs:
                continue  # not evaluable now; state (incl. a pending checkImmediate) is kept
            within = [d <= dist for d in pairs]
            ok = {"AllWithinDistance": all(within), "AnyWithinDistance": any(within),
                  "AllBeyondDistance": not any(within), "AnyBeyondDistance": not all(within)}.get(crit, False)
            immediate = str(sub.get("checkImmediate")).lower() == "true"
            first = "ok" not in st  # first EVALUABLE moment, however late
            if ok and ((st.get("ok") is False) or (first and immediate)):
                _post(sub, sid, rtype, {"notificationType": "UserDistanceNotification", "timeStamp": _now(),
                                        "distanceEvent": crit,
                                        "monitoredUsers": {"user": [users[m] for m in mon if m in users],
                                                           "resourceURL": f"http://127.0.0.1:{m13.cand.PORT}{m13.cand.BASE}/queries/users"}})
            st["ok"], st["pairs_m"] = ok, pairs
        elif rtype == "area":
            ad = sub.get("areaDefine") or {}
            wanted = sub.get("addressList") or [ds.PHONE_ADDRESS]
            if ds.PHONE_ADDRESS not in wanted or not phone or "locationInfo" not in phone \
                    or not ad.get("points") or ad.get("radius") is None:
                continue
            c = ad["points"][0]
            inside = haversine_m(phone["locationInfo"], c) <= float(ad["radius"])
            crit = sub.get("locationEventCriteria") or ["ENTERING_AREA_EVENT", "LEAVING_AREA_EVENT"]
            if "inside" in st and st["inside"] != inside:
                ev = "ENTERING_AREA_EVENT" if inside else "LEAVING_AREA_EVENT"
                if ev in crit:
                    _post(sub, sid, rtype, {"notificationType": "UserAreaNotification", "timeStamp": _now(),
                                            "address": ds.PHONE_ADDRESS, "userLocationEvent": ev,
                                            "locationInfo": phone["locationInfo"]})
            st["inside"] = inside


def notifier() -> None:
    while True:
        try:
            phone = m13.phone_user(ds.snapshot())
            LIVE["phone"], LIVE["error"] = phone, None
            evaluate(phone)
        except Exception as e:
            LIVE["error"] = repr(e)
        time.sleep(2)


if __name__ == "__main__":
    cand._seed()  # the candidate pre-provisions its seed subscription only under its own __main__
    threading.Thread(target=notifier, daemon=True).start()
    cand._serve(cand.app, PORT)
