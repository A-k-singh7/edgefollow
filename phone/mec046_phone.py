#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""MEC 046 Sensor-Sharing (`sens`), with a phone's LIVE oneM2M stream as the sensors.

The unmodified MEC 046 candidate is loaded as a module and served as-is. Its fixture sensors are replaced: before
every request to /sens/v1 the candidate's inventory is rebuilt (through its own seam, apply_inventory) from the
phone's `imu` and `env` containers on the oneM2M CSE, read as the reader originator of device_state.py. The `loc`,
`radio` and `wlan` containers are never requested: no position and no network name can come out of this service,
and no sensor carries a sensorPosition.

Sensors (identifier `<AE>:<key>`), as the probe app's records carry them:
    accel  imu.accel.last       ef:Accelerometer       om:metrePerSecond-TimeSquared   3 values
    gyro   imu.gyro.last        ef:Gyroscope           om:radianPerSecond              3 values
    mag    imu.mag.last         ef:Magnetometer        om:microtesla                   3 values
    light  env.light.last       ef:LightSensor         om:lux                          1 value
    battery_temp  env.battery_temp_c  ef:TemperatureSensor  om:degreeCelsius           1 value

THE CANDIDATE'S OWN ROUTES, own handlers, validators and filters (this file only supplies the inventory):
    GET  /                                    health
    GET  /sens/v1/queries/sensor_discovery    ?sensorInfo=<json>           the phone's sensors
    GET  /sens/v1/queries/sensor_status       ?sensorIdentifier=a,b        ONLINE: the container's newest record is at
                                              most 20 s old (device_state.MAX_SAMPLE_AGE_S) and holds a value;
                                              STANDBY: fresh record, no value in it; OFFLINE: older than 20 s
    GET  /sens/v1/queries/sensor_data         ?sensorIdentifier=a,b        the newest value, ONLINE sensors only;
                                              dataTimestamp = the CSE's creation time of that record
    GET  /sens/v1/sensor_management           ?sensorIdentifier=a,b        samplingRate (Hz) = 1 / the gap between the
                                              two newest records, MEASURED from the stream, not remembered
    PUT  /sens/v1/sensor_management           the candidate validates (known sensor, samplingRate only, 0.1..1 Hz)

WHAT THIS FILE ADDS (no new route; behaviour in front of and behind the candidate's routes):
    PUT  /sens/v1/sensor_management   after the candidate's 200: the rate must be one whole period of 1..10 s and the
                                      same for every sensor named (the phone has ONE period for all its containers),
                                      else 400. Then {"cmd":"period","value":N,"id":...} is created in the phone's
                                      <cmd> container and the phone's <ack> is awaited. 200 only when the ack with our
                                      id says ok and period N; 502 when the CSE refuses the command; 504 when no such
                                      ack is read in time (the command may still have reached the phone). After either,
                                      the inventory is rebuilt from the stream, so a later GET shows what the phone
                                      does, not what was asked for.
    GET  .../sensor_discovery?geographicalArea=   400: the sensors have no position (the candidate would answer 500).
    /sens/v1/subscriptions/*, /sens/v1/notifications/*   404, NOT SERVED: nothing here polls the CSE between requests,
                                      so no notification would ever be sent.

Access: every read is made as the reader originator (PHONE_READER_ORIGIN). A container that originator may not read
(403), an empty one, or an unreachable CSE yields no sensor at all. The command needs CREATE on <cmd> and RETRIEVE on
<ack> for the same originator. The MEC side itself is plain HTTP on loopback with no client authentication unless
MEC046_BEARER_TOKEN is set (the candidate's own static bearer check).

Period range: the phone accepts 1..60 s; this service offers 1..10 s only, because under the 20 s staleness rule a
slower stream could not show two records and would read as OFFLINE.

Not a conformance claim: a demonstration on our own candidate.

    PHONE_MEC046_PORT (default 8470)   PHONE_CSE / PHONE_AE / PHONE_READER_ORIGIN (device_state.py)
    PHONE_MEC046_ACK_WAIT_S (default 15)
    MEC046_CANDIDATE   path of candidate.py (default: ../mec046/candidate.py, else the mainline checkout)
"""
from __future__ import annotations

import asyncio
import calendar
import importlib.util
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from starlette.responses import Response

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402

_LOCAL = HERE.parent / "mec046" / "candidate.py"
CANDIDATE = os.environ.get("MEC046_CANDIDATE") or str(_LOCAL if _LOCAL.exists() else "/home/edgefollow/edgefollow/mec046/candidate.py")
spec = importlib.util.spec_from_file_location("mec046_candidate", CANDIDATE)
cand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cand)

PORT = int(os.environ.get("PHONE_MEC046_PORT", "8470"))
ACK_WAIT_S = float(os.environ.get("PHONE_MEC046_ACK_WAIT_S", "15"))
MAX_AGE_S = ds.MAX_SAMPLE_AGE_S
CONTAINERS = ("imu", "env")                     # never loc, radio or wlan
PERIOD_MIN, PERIOD_MAX = 1, 10                  # whole seconds
WINDOW_S = MAX_AGE_S + 5                        # how far back the records for the measured period are fetched
# key -> (container, field, holds {"last": [...]}, value count, sensorType, properties, unit)
SENSORS = {
    "accel": ("imu", "accel", True, 3, "ef:Accelerometer", ["ef:Acceleration"], "om:metrePerSecond-TimeSquared"),
    "gyro": ("imu", "gyro", True, 3, "ef:Gyroscope", ["ef:AngularVelocity"], "om:radianPerSecond"),
    "mag": ("imu", "mag", True, 3, "ef:Magnetometer", ["ef:MagneticFluxDensity"], "om:microtesla"),
    "light": ("env", "light", True, 1, "ef:LightSensor", ["saref:Light"], "om:lux"),
    "battery_temp": ("env", "battery_temp_c", False, 1, "ef:TemperatureSensor", ["saref:Temperature"], "om:degreeCelsius"),
}
SETTABLE = {"samplingRate": {"unit": "om:hertz", "min": 1.0 / PERIOD_MAX, "max": 1.0 / PERIOD_MIN}}


# ------------------------------------------------------------------------------------------------ pure functions
def sensor_id(key: str) -> str:
    return f"{ds.AE}:{key}"


def ct_seconds(ct: str) -> float:
    """A oneM2M creation time (UTC, 'YYYYMMDDTHHMMSS[,ffffff]') as Unix seconds."""
    base, _, frac = ct.partition(",")
    return calendar.timegm(time.strptime(base, "%Y%m%dT%H%M%S")) + (float("0." + frac) if frac else 0.0)


def timestamp(t: float) -> dict:
    """Unix seconds as a MEC TimeStamp, to the microsecond (the resolution of a CSE creation time; a float of
    this size holds no more)."""
    s = math.floor(t)
    us = round((t - s) * 1e6)
    if us >= 1_000_000:
        s, us = s + 1, 0
    return {"seconds": s, "nanoSeconds": us * 1000}


def is_live(age_s: float) -> bool:
    """The staleness rule of device_state: a record OLDER than MAX_AGE_S (20 s) is not live."""
    return age_s <= MAX_AGE_S


def rate_to_period(value: str) -> int:
    """A samplingRate in Hz as the phone's period in whole seconds (1..10). ValueError when it is not one."""
    try:
        rate = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"samplingRate {value!r} is not a number") from None
    if not math.isfinite(rate) or rate <= 0:
        raise ValueError(f"samplingRate {value!r} is not a positive rate")
    period = 1.0 / rate
    n = round(period)
    if not PERIOD_MIN <= n <= PERIOD_MAX or abs(period - n) > 0.005 * n:
        raise ValueError(f"samplingRate {value!r} Hz is a period of {period:.3f} s; the phone takes whole seconds "
                         f"{PERIOD_MIN}..{PERIOD_MAX} (rates 1/N Hz)")
    return n


def period_to_rate(n: int) -> str:
    return format(1.0 / n, ".6g")


def period_of(cts: list[float]) -> int | None:
    """The gap between the two newest creation times, in whole seconds; None when there is no such gap."""
    s = sorted(cts)
    if len(s) < 2:
        return None
    n = round(s[-1] - s[-2])
    return n if n >= 1 else None


def reading(record: dict, key: str) -> list[float] | None:
    """The sensor's newest values in one record, or None when the record holds no usable value for it."""
    _c, field, wrapped, count, *_ = SENSORS[key]
    v = record.get(field) if isinstance(record, dict) else None
    v = (v.get("last") if isinstance(v, dict) else None) if wrapped else [v]
    if not isinstance(v, list) or len(v) != count:
        return None
    for x in v:
        if isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or x == ds.UNAVAILABLE:
            return None
    return [float(x) for x in v]


def build(view: dict, now: float) -> list[dict]:
    """Candidate inventory records from what was read: view[container] = {"record", "ct_s", "cts"} or {"error"}."""
    out = []
    for key, (cnt, field, _w, _n, typ, props, unit) in SENSORS.items():
        got = view.get(cnt) or {}
        rec = got.get("record")
        if not isinstance(rec, dict) or field not in rec:
            continue                                    # unreadable container, or a phone without this sensor
        sid, age = sensor_id(key), now - got["ct_s"]
        live, vals = is_live(age), reading(rec, key)
        chars = [{"characteristicName": "provenance.source", "characteristicValue": "onem2m"},
                 {"characteristicName": "provenance.container", "characteristicValue": f"{ds.AE}/{cnt}"},
                 {"characteristicName": "provenance.timeBasis", "characteristicValue": "cse-creation-time"}]
        if rec.get("sim") is True:
            chars.append({"characteristicName": "provenance.simulated", "characteristicValue": "true"})
        period = period_of(got.get("cts") or []) if live else None
        if period is not None:
            chars.append({"characteristicName": "samplingRate", "characteristicValue": period_to_rate(period),
                          "characteristicUnitOfMeasure": "om:hertz"})
        status = {"sensorIdentifier": sid, "sensorStatusType": "ONLINE" if live and vals else "STANDBY" if live else "OFFLINE"}
        if not live:
            status["errorInformation"] = f"stale: last sample {age:.0f} s old (limit {MAX_AGE_S:.0f} s)"
        elif not vals:
            status["errorInformation"] = "no value for this sensor in the latest record"
        data = [{"sensorIdentifier": sid, "data": " ".join(repr(v) for v in vals),
                 "dataFormat": "xsd:float" if len(vals) == 1 else "custom:xsdFloatList",
                 "dataUnitOfMeasure": unit, "dataTimestamp": timestamp(got["ct_s"])}] if live and vals else []
        out.append({"discovery": {"sensorIdentifier": sid, "sensorType": typ, "sensorPropertyList": list(props),
                                  "sensorCharacteristicList": chars},
                    "status": status, "data": data, "settable": json.loads(json.dumps(SETTABLE))})
    return out


def requested_period(body, ids: set) -> int | None:
    """The one period a management PUT asks of the phone; None when it names none of the phone's sensors.
    ValueError when a rate is no whole period or two rates differ (the phone has one period)."""
    periods = set()
    for item in body if isinstance(body, list) else []:
        if not isinstance(item, dict) or item.get("sensorIdentifier") not in ids:
            continue
        for c in item.get("sensorCharacteristicList") or []:
            if isinstance(c, dict) and c.get("characteristicName") == "samplingRate":
                periods.add(rate_to_period(c.get("characteristicValue")))
    if len(periods) > 1:
        raise ValueError(f"the phone has one sampling period for all its sensors; this request asks for {sorted(periods)} s")
    return periods.pop() if periods else None


def ack_confirms(ack, cmd_id: str, period: int) -> bool:
    return (isinstance(ack, dict) and ack.get("id") == cmd_id and ack.get("cmd") == "period" and ack.get("ok") is True
            and ack.get("period") == period and not isinstance(ack.get("period"), bool))


# ------------------------------------------------------------------------------------------------ oneM2M
def recent(container: str, since_s: float) -> list[tuple[float, dict]]:
    """(creation time, content) of the container's records created after `since_s`, oldest first."""
    cra = time.strftime("%Y%m%dT%H%M%S", time.gmtime(since_s))
    cnt = ds._get(f"{ds.CSE}/{ds.AE}/{container}?rcn=4&ty=4&cra={cra}").get("m2m:cnt", {})
    out = []
    for cin in cnt.get("m2m:cin", []):
        t = ct_seconds(cin.get("ct", ""))
        if t > since_s:                                # the CSE's filter is not relied on
            try:
                out.append((t, json.loads(cin["con"])))
            except (KeyError, ValueError):
                continue
    return sorted(out, key=lambda x: x[0])


def read_view() -> dict:
    view = {}
    for c in CONTAINERS:
        try:
            rec, ct = ds.latest(c)
            t = ct_seconds(ct)
            cts = [x[0] for x in recent(c, time.time() - WINDOW_S)] if is_live(time.time() - t) else []
            view[c] = {"record": rec, "ct_s": t, "cts": cts}
        except Exception as e:  # noqa: BLE001  no policy (403), empty (404), CSE down: no sensor, never an invented one
            view[c] = {"error": str(e)[:120]}
    return view


def refresh() -> None:
    cand.apply_inventory(build(read_view(), time.time()))


def send_period(n: int) -> tuple[int, str]:
    """Create the downlink command in the phone's <cmd> and wait for its <ack>. (200 | 502 | 504, detail)."""
    cid, t0 = f"mec046-{time.time_ns()}", time.time()
    req = urllib.request.Request(
        f"{ds.CSE}/{ds.AE}/cmd", method="POST",
        data=json.dumps({"m2m:cin": {"cnf": "application/json:0", "con": json.dumps({"cmd": "period", "value": n, "id": cid})}}).encode(),
        headers={"X-M2M-Origin": ds.ORIGIN, "X-M2M-RI": f"wr{time.time_ns()}", "X-M2M-RVI": "4",
                 "Accept": "application/json", "Content-Type": "application/json;ty=4"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            st = r.status
    except urllib.error.HTTPError as e:
        st = e.code
    except (urllib.error.URLError, OSError) as e:
        return 502, f"the CSE was not reached with the period command: {e}"
    if st != 201:
        return 502, f"the CSE did not take the period command into the phone's cmd container (HTTP {st})"
    why = "no ack"
    while time.time() - t0 < ACK_WAIT_S:
        time.sleep(0.25)
        try:
            for _t, ack in recent("ack", t0 - 5):
                if isinstance(ack, dict) and ack.get("id") == cid:
                    if ack_confirms(ack, cid, n):
                        return 200, f"acknowledged by the phone: period {n} s"
                    return 502, f"the phone refused the period command: {str(ack.get('error'))[:80]}"
        except Exception as e:  # noqa: BLE001
            why = f"ack container not readable: {str(e)[:60]}"
    return 504, f"no acknowledgement from the phone within {ACK_WAIT_S:.0f} s ({why}); the command was sent"


# ------------------------------------------------------------------------------------------------ in front of the candidate
@cand.api.middleware("http")
async def phone_feed(request, call_next):
    path = request.url.path
    if not path.startswith(cand.BASE + "/"):
        return await call_next(request)
    if path.startswith((cand.BASE + "/subscriptions", cand.BASE + "/notifications")):
        return cand.problem(404, "subscriptions and notifications are not served by the phone-backed service")
    if "geographicalArea" in request.query_params:
        return cand.problem(400, "the phone's sensors are served without a position; geographicalArea cannot select them")
    await asyncio.to_thread(refresh)
    if not (request.method == "PUT" and path == cand.BASE + "/sensor_management"):
        return await call_next(request)
    raw = await request.body()

    async def receive():                        # hand the already-read body on to the candidate
        return {"type": "http.request", "body": raw, "more_body": False}
    request._receive = receive
    ids = {r["discovery"]["sensorIdentifier"] for r in cand.INVENTORY}
    resp = await call_next(request)             # the candidate validates and answers
    if resp.status_code != 200:
        return resp
    out = b"".join([chunk async for chunk in resp.body_iterator])
    try:
        n = requested_period(json.loads(raw), ids)
        status, detail = (500, "accepted by the candidate, but no sampling period was found in the request") if n is None \
            else await asyncio.to_thread(send_period, n)
    except ValueError as e:
        status, detail = 400, str(e)
    await asyncio.to_thread(refresh)            # what the stream shows, not what the candidate just wrote
    if status != 200:
        return cand.problem(status, detail)
    return Response(out, status_code=200, media_type="application/json")


if __name__ == "__main__":
    cand._serve(cand.app, PORT)
