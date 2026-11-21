#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""MEC 013 subscriptions with the real phone, static part.

Starts mec013sub_phone (:8406) and a sink (:8407). Covers what a phone lying still
can honestly produce:
  * periodic location reports (count, cadence, final flag, schema, values)
  * distance to a fixture UE, immediate evaluation, with a criterion that must NOT fire
  * zero spurious notifications from event subscriptions while nothing changes
Transitions (cell/zone changes) are exercised by test_phone_transitions.py.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import jsonschema

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402
import mec013sub_phone as ms  # noqa: E402  (haversine, fixture users)

PY = "/home/edgefollow/edgefollow-lab/.venv/bin/python"
REF = Path.home() / "etsi-forge-ats-reference" / "MEC013" / "SRV"
BASE, SINK = "http://127.0.0.1:8406/location/v3", 8407
RESULTS: list[tuple[str, bool, str]] = []
INBOX: list[dict] = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))
    return ok


def schema(n):
    return json.loads(next(REF.glob(f"*/schemas/{n}.schema.json")).read_bytes().decode("utf-8", "replace"))


def errors(inst, sch):
    return [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message[:100]}"
            for e in jsonschema.Draft7Validator(sch).iter_errors(inst)]


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        INBOX.append({"path": self.path, "body": json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                      "rx": time.time()})
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


def post(rtype: str, body: dict) -> tuple[int, str | None]:
    r = urllib.request.Request(f"{BASE}/subscriptions/{rtype}", data=json.dumps(body).encode(), method="POST",
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=5) as x:
            return x.status, x.headers.get("Location", "").rsplit("/", 1)[-1]
    except urllib.error.HTTPError as e:
        return e.code, None


def delete(rtype: str, sid: str) -> int:
    try:
        with urllib.request.urlopen(urllib.request.Request(f"{BASE}/subscriptions/{rtype}/{sid}", method="DELETE"), timeout=5) as x:
            return x.status
    except urllib.error.HTTPError as e:
        return e.code


def cb(tag: str) -> str:
    return f"http://127.0.0.1:{SINK}/{tag}"


def main() -> int:
    snap = ds.snapshot()
    import mec013_phone as m13
    phone = m13.phone_user(snap)
    if not check("precondition: phone has a live MEC 013 record", phone is not None):
        return 2
    proc = subprocess.Popen([PY, str(HERE / "mec013sub_phone.py")], stdout=subprocess.DEVNULL,
                            stderr=open("/home/edgefollow/estimed-run/mec013sub_phone.log", "w"))
    srv = HTTPServer(("127.0.0.1", SINK), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    made = []
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen("http://127.0.0.1:8406/location/v3/subscriptions/users", timeout=1).close()
                break
            except urllib.error.HTTPError:
                break
            except Exception:
                time.sleep(0.3)

        print("== periodic location")
        c, sid = post("users", {"subscriptionType": "UserLocationPeriodicSubscription", "callbackReference": cb("periodic"),
                                "address": ds.PHONE_ADDRESS, "periodicEventInfo": {"reportingAmount": 3, "reportingInterval": 5}})
        made.append(("users", sid))
        check("UserLocationPeriodicSubscription created", c == 201, f"{c} id={sid}")

        print("== distance to fixture UE acr:10.0.0.3")
        ref = m13.cand.USERS["acr:10.0.0.3"]
        d = ms.haversine_m(phone["locationInfo"], ref["locationInfo"])
        base = {"subscriptionType": "UserDistanceSubscription", "monitoredAddress": [ds.PHONE_ADDRESS],
                "referenceAddress": ["acr:10.0.0.3"], "trackingAccuracy": 10, "checkImmediate": True}
        for tag, crit, D in [("within2x", "AllWithinDistance", 2 * d), ("beyondhalf", "AllBeyondDistance", d / 2),
                             ("CONTROL_withinhalf", "AllWithinDistance", d / 2)]:
            c, sid = post("distance", {"userDistanceSubscription": dict(base, callbackReference=cb(tag), criteria=crit, distance=round(D))})
            made.append(("distance", sid))
            check(f"distance subscription {tag} created", c == 201, str(c))

        print("== event subscriptions (must stay silent while nothing changes)")
        for rtype, body in [
            ("users", {"subscriptionType": "UserLocationEventSubscription", "callbackReference": cb("uevent"),
                       "address": ds.PHONE_ADDRESS}),
            ("zones", {"subscriptionType": "ZoneLocationEventSubscription", "callbackReference": cb("zevent"),
                       "zoneId": phone["zoneId"], "locationEventCriteria": ["ENTERING_AREA_EVENT", "LEAVING_AREA_EVENT"]}),
            ("zones", {"subscriptionType": "ZoneStatusSubscription", "callbackReference": cb("zstatus"),
                       "zoneId": phone["zoneId"], "upperNumberOfUsersZoneThreshold": 0, "lowerNumberOfUsersZoneThreshold": 1}),
            ("area", {"subscriptionType": "UserAreaSubscription", "callbackReference": cb("area"),
                      "areaDefine": {"shape": 1, "points": [{"latitude": phone["locationInfo"]["latitude"][0],
                                                             "longitude": phone["locationInfo"]["longitude"][0]}], "radius": 2000},
                      "addressList": [ds.PHONE_ADDRESS], "locationEventCriteria": ["ENTERING_AREA_EVENT", "LEAVING_AREA_EVENT"],
                      "trackingAccuracy": 10})]:
            c, sid = post(rtype, body)
            made.append((rtype, sid))
            check(f"{body['subscriptionType']} created", c == 201, str(c))

        time.sleep(20)
        per = [m["body"] for m in INBOX if m["path"] == "/periodic"]
        rx = [m["rx"] for m in INBOX if m["path"] == "/periodic"]
        check("3 periodic reports, ~5 s apart, only the last final",
              len(per) == 3 and all(4 <= b - a <= 7 for a, b in zip(rx, rx[1:]))
              and [p.get("isFinalNotification", False) for p in per] == [False, False, True],
              f"{len(per)} reports, gaps {[round(b - a, 1) for a, b in zip(rx, rx[1:])]}")
        sch = schema("UserLocationPeriodicNotification")
        e = sum((errors(p, sch) for p in per), [])
        check("periodic reports valid vs ETSI UserLocationPeriodicNotification.schema.json", per and not e, "; ".join(e[:3]))
        check("reports carry the phone's live cell + fix (result SUCCESS)",
              per and all(p["result"] == "SUCCESS" and p["accessPointId"] == phone["accessPointId"] for p in per))
        dsch = schema("UserDistanceNotification")
        w = [m["body"] for m in INBOX if m["path"] == "/within2x"]
        b = [m["body"] for m in INBOX if m["path"] == "/beyondhalf"]
        check("AllWithinDistance @ 2x true distance -> immediate UserDistanceNotification",
              len(w) == 1 and w[0]["distanceEvent"] == "AllWithinDistance", f"true distance ~{d / 1000:.0f} km")
        check("AllBeyondDistance @ 0.5x -> immediate notification", len(b) == 1)
        e = sum((errors(x, dsch) for x in w + b), [])
        check("distance notifications valid vs ETSI UserDistanceNotification.schema.json", (w + b) and not e, "; ".join(e[:3]))
        check("CONTROL AllWithinDistance @ 0.5x stays silent", not [m for m in INBOX if m["path"] == "/CONTROL_withinhalf"])
        quiet = [m["path"] for m in INBOX if m["path"] in ("/uevent", "/zevent", "/zstatus", "/area")]
        check("CONTROL event subscriptions: zero notifications while the phone is static", not quiet, str(quiet))
        n_before = len([m for m in INBOX if m["path"] == "/periodic"])
        time.sleep(8)
        check("periodic stops after reportingAmount", len([m for m in INBOX if m["path"] == "/periodic"]) == n_before)
    finally:
        for rtype, sid in made:
            if sid:
                delete(rtype, sid)
        proc.terminate()
        srv.shutdown()

    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\nRESULT: {passed}/{len(RESULTS)} checks pass")
    Path("/home/edgefollow/estimed-run/phone_mec013sub_results.json").write_text(
        json.dumps([{"check": n, "pass": ok, "detail": dd} for n, ok, dd in RESULTS], indent=1))
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
