#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Sensor sharing (MEC 046): checks of phone/mec046_phone.py.

Offline rows first (every pure function, expected values worked out by hand in the comments), then live rows against
the lab (estimed/run_topology.sh up) with a phone's oneM2M stream on edge A:

  --device sim (default)  a SIMULATED phone (sim_phone.py) started here as AE `ss046`, originator Css046-SIM, reader
                          Css046Reader. The AE and the three access policies (ss046ReadAcp, ss046CmdAcp,
                          ss046OwnerAcp) are created here and deleted at the end, also on failure.
  --device adb            NOT RUN SO FAR. Assumes the probe app is already live as AE `phone` (originator
                          Cphone-DEVC, reader CphoneReader, phone/onem2m_acp.py applied, period 5 s). Starts and stops
                          nothing on the phone. It posts period commands through oneM2M and puts the period back to 5;
                          on the CSE it adds the ss046 policies to phone/cmd and phone/ack, swaps the policy of
                          phone/env for one step, and puts all three back.

Rows print PASS/FAIL. A CONTROL is worded as the fault having gone through and must print FAIL. Exit 0 only when every
row passed, every control failed, nothing was skipped and no exception was raised. A demonstration on our own
candidate, not a conformance claim.

    /home/edgefollow/edgefollow-lab/.venv/bin/python -B phone/test_phone_mec046.py [--device sim] [--offline-only]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "estimed"))

PY = "/home/edgefollow/edgefollow-lab/.venv/bin/python"
CSE = "http://127.0.0.1:8201/cse-mn-a"
PORT, PORT_STRANGER, PORT_SHORT = 8470, 8471, 8472
STRANGER = "Css046Stranger"
MODES = {"sim": ("ss046", "Css046-SIM", "Css046Reader"), "adb": ("phone", "Cphone-DEVC", "CphoneReader")}
ACP_READ, ACP_CMD, ACP_OWNER = "ss046ReadAcp", "ss046CmdAcp", "ss046OwnerAcp"
KEYS = ("accel", "gyro", "mag", "light", "battery_temp")
TYPES = {"accel": "ef:Accelerometer", "gyro": "ef:Gyroscope", "mag": "ef:Magnetometer",
         "light": "ef:LightSensor", "battery_temp": "ef:TemperatureSensor"}
# what must never come out of the service: position and network-name fields of the phone's loc / wlan / radio records
LEAK_KEYS = {"lat", "lon", "latitude", "longitude", "alt_m", "acc_m", "ssid", "bssid", "sensorPosition", "neighbours",
             "cells", "plmn"}
LEAK_TEXT = ("sim-ap", "48.1351", "11.582", "02:00:00:00:00")      # the simulated phone's AP names, fix and BSSIDs

ROWS: list[tuple[str, str, bool, str]] = []      # (kind, name, printed PASS, detail)
SKIPPED: list[str] = []
SEEN: list = []                                  # every body the main service answered with


class Abort(Exception):
    pass


def row(name: str, ok, detail: str = "") -> bool:
    ROWS.append(("row", name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"\n          {detail}" if detail else ""), flush=True)
    return bool(ok)


def control(name: str, served, detail: str = "") -> None:
    """`served` = the fault went through. Printed FAIL (served False) is the good outcome."""
    ROWS.append(("control", name, bool(served), detail))
    print(f"  {'PASS' if served else 'FAIL'}  CONTROL (must FAIL) {name}" + (f"\n          {detail}" if detail else ""), flush=True)


def require(name: str, ok, detail: str = "") -> None:
    if not row(name, ok, detail):
        raise Abort(name)


def off(name: str, fn) -> None:
    try:
        got = fn()
        ok, detail = (got if isinstance(got, tuple) else (got, ""))
    except Exception as e:  # noqa: BLE001  a missing or broken function is a FAIL row
        ok, detail = False, repr(e)[:200]
    row(name, ok is True, detail if ok is not True else "")


def raises(fn, *a) -> bool:
    try:
        fn(*a)
    except ValueError:
        return True
    return False


def leaks(o, path: str = "") -> list[str]:
    """Paths in a JSON tree that hold a position or a network name (by key, or by the simulated phone's values)."""
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            out += [f"{path}/{k}"] if k in LEAK_KEYS else []
            out += leaks(v, f"{path}/{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            out += leaks(v, f"{path}/{i}")
    elif isinstance(o, str) and any(t in o for t in LEAK_TEXT):
        out.append(path)
    return out


# ------------------------------------------------------------------------------------------------ offline rows
CT = "20261119T015636,670235"
# By hand: 1970..2025 is 56 years with 14 leap days (1972..2024) = 20454 days; 1 Jan .. 19 Nov 2026 = 304 + 18 = 322
# days; 20776 days x 86400 = 1795046400; + 01:56:36 = 6996 s  ->  1795053396.670235
CT_S = 1795053396.670235


def sim_records() -> dict:
    import sim_phone
    return sim_phone.SimPhone(CSE, "Cnobody", rn="nobody").records(1795053396000)     # pure: no request is made


def view(mp, *, imu_age=1.0, env_age=1.0, gap=2.0, imu=True, env=True, now=CT_S + 1.0, recs=None) -> tuple[dict, float]:
    recs = recs or sim_records()

    def one(name, age):
        last = now - age
        return {"record": recs[name], "ct_s": last, "cts": [last - 2 * gap, last - gap, last]}
    v = {}
    v["imu"] = one("imu", imu_age) if imu else {"error": "HTTP 403"}
    v["env"] = one("env", env_age) if env else {"error": "HTTP 403"}
    return v, now


def by_id(inv) -> dict:
    return {r["discovery"]["sensorIdentifier"]: r for r in inv}


def chars(rec) -> dict:
    return {c["characteristicName"]: c["characteristicValue"] for c in rec["discovery"]["sensorCharacteristicList"]}


def offline(mp, ae: str) -> None:
    print("== offline: the pure functions")
    sid = lambda k: f"{ae}:{k}"  # noqa: E731
    off("the service reads the imu and env containers and no other", lambda: tuple(mp.CONTAINERS) == ("imu", "env"))
    off("the five sensors and their containers", lambda: (
        {k: v[0] for k, v in mp.SENSORS.items()} == {"accel": "imu", "gyro": "imu", "mag": "imu", "light": "env",
                                                     "battery_temp": "env"}, str(sorted(mp.SENSORS))))
    off("ct_seconds: 20261119T015636,670235 is 1795053396.670235", lambda: abs(mp.ct_seconds(CT) - CT_S) < 1e-6)
    off("ct_seconds: a creation time without a fraction", lambda: mp.ct_seconds("20261119T015636") == 1795053396.0)
    off("timestamp: seconds 1795053396, nanoSeconds 670235000",
        lambda: mp.timestamp(CT_S) == {"seconds": 1795053396, "nanoSeconds": 670235000})
    # 0.9999996 s rounds up to the next whole second, never to nanoSeconds 1000000000
    off("timestamp: 99.9999996 s is seconds 100, nanoSeconds 0; 100.0 is the same",
        lambda: mp.timestamp(99.9999996) == {"seconds": 100, "nanoSeconds": 0} == mp.timestamp(100.0))
    # the rule: OLDER than 20 s is not live; exactly 20.0 s old is still live
    off("is_live: a sample 20.0 s old is live", lambda: mp.is_live(20.0) is True)
    off("is_live: a sample 20.1 s old is not live", lambda: mp.is_live(20.1) is False)
    off("is_live: a sample from the future (clock skew, -3 s) is live", lambda: mp.is_live(-3.0) is True)
    # rate (Hz) -> whole seconds: 1/0.2 = 5, 1/0.5 = 2, 1/1 = 1, 1/0.1 = 10; 1/0.333 = 3.003, within 0.5 % of 3
    off("rate_to_period: 0.2 Hz -> 5 s, 0.5 -> 2, 1 -> 1, 0.1 -> 10, 0.333 -> 3",
        lambda: [mp.rate_to_period(x) for x in ("0.2", "0.5", "1", "0.1", "0.333")] == [5, 2, 1, 10, 3])
    # 1/0.3 = 3.33 (no whole second); 1/2 = 0.5 s and 1/0.05 = 20 s are outside 1..10; 0, -1, nan, text are not rates
    off("rate_to_period refuses 0.3, 2, 0.05, 0, -1, nan, inf and text",
        lambda: all(raises(mp.rate_to_period, x) for x in ("0.3", "2", "0.05", "0", "-1", "nan", "inf", "abc", "")))
    off("period_to_rate: 5 s -> 0.2, 2 -> 0.5, 1 -> 1, 10 -> 0.1, 3 -> 0.333333",
        lambda: [mp.period_to_rate(n) for n in (5, 2, 1, 10, 3)] == ["0.2", "0.5", "1", "0.1", "0.333333"])
    off("every whole period 1..10 survives period -> rate -> period",
        lambda: [mp.rate_to_period(mp.period_to_rate(n)) for n in range(1, 11)] == list(range(1, 11)))
    # gaps: 398.645 - 396.670 = 1.975, 400.670 - 398.645 = 2.025 -> the newest gap, rounded: 2
    off("period_of: creation times 2.025 s apart give 2", lambda: mp.period_of([1396.670, 1398.645, 1400.670]) == 2)
    off("period_of: the newest gap counts (5.0, then 2.0 -> 2), in any order", lambda: mp.period_of([10.0, 3.0, 8.0]) == 2)
    off("period_of: one record, none, or a gap under half a second give no period",
        lambda: mp.period_of([5.0]) is None and mp.period_of([]) is None and mp.period_of([5.0, 5.2]) is None)
    r = sim_records()
    off("reading: accel, gyro, mag, light, battery temperature of a simulated record", lambda: (
        [mp.reading(r[mp.SENSORS[k][0]], k) for k in KEYS]
        == [[0.0, 0.0, 9.81], [0.0, 0.0, 0.0], [20.0, -5.0, -40.0], [120.0], [25.0]]))
    off("reading: a sensor with no value in the record (proximity-style {'n': 0}) gives none",
        lambda: mp.reading({"light": {"n": 0}}, "light") is None)
    off("reading: two values where three are due, Android's 'unavailable' (2147483647), a boolean, NaN give none",
        lambda: mp.reading({"accel": {"last": [0.0, 9.81]}}, "accel") is None
        and mp.reading({"battery_temp_c": 2147483647}, "battery_temp") is None
        and mp.reading({"battery_temp_c": True}, "battery_temp") is None
        and mp.reading({"light": {"last": [float("nan")]}}, "light") is None)
    off("reading: a whole-number battery temperature 25 is served as 25.0",
        lambda: mp.reading({"battery_temp_c": 25}, "battery_temp") == [25.0])

    def built():
        inv = by_id(mp.build(*view(mp)))
        ok = (list(inv) == [sid(k) for k in KEYS]
              and {k: inv[sid(k)]["discovery"]["sensorType"] for k in KEYS} == TYPES
              and all(inv[sid(k)]["status"] == {"sensorIdentifier": sid(k), "sensorStatusType": "ONLINE"} for k in KEYS)
              and [inv[sid(k)]["data"][0]["data"] for k in KEYS] == ["0.0 0.0 9.81", "0.0 0.0 0.0", "20.0 -5.0 -40.0", "120.0", "25.0"]
              and [inv[sid(k)]["data"][0]["dataUnitOfMeasure"] for k in KEYS]
              == ["om:metrePerSecond-TimeSquared", "om:radianPerSecond", "om:microtesla", "om:lux", "om:degreeCelsius"]
              and [inv[sid(k)]["data"][0]["dataFormat"] for k in KEYS] == ["custom:xsdFloatList"] * 3 + ["xsd:float"] * 2
              # the record is 1.0 s older than `now` = CT_S + 1.0, so its time is CT_S
              and all(inv[sid(k)]["data"][0]["dataTimestamp"] == {"seconds": 1795053396, "nanoSeconds": 670235000} for k in KEYS))
        return ok, json.dumps(mp.build(*view(mp)))[:300]
    off("build: five sensors, ONLINE, the record's values, units, formats and the CSE creation time", built)
    off("build: records 2 s apart give samplingRate 0.5 om:hertz, settable 0.1..1",
        lambda: all(chars(x)["samplingRate"] == "0.5" and x["settable"] == {"samplingRate": {"unit": "om:hertz", "min": 0.1, "max": 1.0}}
                    for x in mp.build(*view(mp))))
    off("build: a record marked simulated is served as simulated; one without the mark is not", lambda: (
        all(chars(x).get("provenance.simulated") == "true" for x in mp.build(*view(mp)))
        and all("provenance.simulated" not in chars(x) for x in mp.build(*view(mp, recs={
            k: {kk: vv for kk, vv in v.items() if kk != "sim"} for k, v in sim_records().items()})))))
    off("build: no record carries a position or a network name", lambda: (not leaks(mp.build(*view(mp))), str(leaks(mp.build(*view(mp)))[:3])))

    def stale():
        inv = by_id(mp.build(*view(mp, env_age=20.1)))
        st = inv[sid("light")]["status"]
        return (len(inv) == 5 and st["sensorStatusType"] == "OFFLINE" and "stale" in st.get("errorInformation", "")
                and inv[sid("light")]["data"] == [] and inv[sid("battery_temp")]["data"] == []
                and inv[sid("accel")]["status"]["sensorStatusType"] == "ONLINE" and len(inv[sid("accel")]["data"]) == 1), json.dumps(st)
    off("build: an env record 20.1 s old -> light and battery temperature OFFLINE with no data; imu still ONLINE", stale)
    off("build: an env record 20.0 s old is still ONLINE with data",
        lambda: by_id(mp.build(*view(mp, env_age=20.0)))[sid("light")]["status"]["sensorStatusType"] == "ONLINE")
    off("build: an unreadable env container -> the three imu sensors only",
        lambda: list(by_id(mp.build(*view(mp, env=False)))) == [sid(k) for k in KEYS[:3]])
    off("build: both containers unreadable -> nothing", lambda: mp.build(*view(mp, imu=False, env=False)) == [])

    def no_value():
        recs = sim_records()
        recs["env"]["light"] = {"n": 0}
        del recs["imu"]["gyro"]
        inv = by_id(mp.build(*view(mp, recs=recs)))
        return (sid("gyro") not in inv and inv[sid("light")]["status"]["sensorStatusType"] == "STANDBY"
                and inv[sid("light")]["data"] == [] and len(inv) == 4), str(sorted(inv))
    off("build: a sensor absent from the record is not listed; one without a value is STANDBY with no data", no_value)

    def body(*pairs):
        return [{"sensorIdentifier": i, "sensorCharacteristicList": [{"characteristicName": "samplingRate", "characteristicValue": v}]}
                for i, v in pairs]
    ids = {sid(k) for k in KEYS}
    off("requested_period: one sensor at 0.5 Hz -> 2 s; two sensors at the same rate -> 2 s",
        lambda: mp.requested_period(body((sid("accel"), "0.5")), ids) == 2
        and mp.requested_period(body((sid("accel"), "0.5"), (sid("light"), "0.5")), ids) == 2)
    off("requested_period: two rates in one request are refused (one stream, one period)",
        lambda: raises(mp.requested_period, body((sid("accel"), "0.5"), (sid("light"), "0.2")), ids))
    off("requested_period: a request that names none of the phone's sensors asks for nothing",
        lambda: mp.requested_period(body(("fixture:temp-01", "0.5")), ids) is None and mp.requested_period({"x": 1}, ids) is None)
    ack = {"id": "a1", "cmd": "period", "ok": True, "period": 2, "phone_t": 1}
    off("ack_confirms: the phone's ack with our id, ok and the period asked for", lambda: mp.ack_confirms(ack, "a1", 2) is True)
    off("ack_confirms: another id, ok false, another period, no period, a ping ack, a non-object are refused", lambda: not any((
        mp.ack_confirms(ack, "a2", 2), mp.ack_confirms({**ack, "ok": False}, "a1", 2), mp.ack_confirms(ack, "a1", 3),
        mp.ack_confirms({k: v for k, v in ack.items() if k != "period"}, "a1", 2),
        mp.ack_confirms({**ack, "cmd": "ping"}, "a1", 2), mp.ack_confirms({**ack, "ok": 1}, "a1", 2), mp.ack_confirms(None, "a1", 2))))
    off("the leak scan of this script finds nothing in a clean reply",
        lambda: leaks([{"sensorIdentifier": "x", "data": "0.0 0.0 9.81"}]) == [])
    control("the leak scan missed a planted coordinate, a planted network name and the simulated phone's AP name",
            not (leaks({"a": [{"lat": 1.0}]}) and leaks({"ssid": "x"}) and leaks({"note": "seen sim-ap-0"})))


# ------------------------------------------------------------------------------------------------ live helpers
def m2m(method: str, url: str, origin: str, body: dict | None = None, ty: int | None = None) -> tuple[int, dict]:
    h = {"X-M2M-Origin": origin, "X-M2M-RI": f"t046-{time.time_ns()}", "X-M2M-RVI": "4", "Accept": "application/json"}
    if body is not None:
        h["Content-Type"] = f"application/json;ty={ty}" if ty else "application/json"
    rq = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method, headers=h)
    try:
        with urllib.request.urlopen(rq, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}
    except (urllib.error.URLError, OSError):
        return 0, {}


def mec(port: int, method: str, path: str, body=None) -> tuple[int, object]:
    data = None if body is None else json.dumps(body).encode()
    rq = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                                headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(rq, timeout=40) as r:
            st, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        st, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        return 0, None
    try:
        out = json.loads(raw) if raw else None
    except ValueError:
        out = raw.decode("utf-8", "replace")
    if port == PORT:
        SEEN.append(out)
    return st, out


def cins(ae: str, cnt: str, origin: str) -> list[dict]:
    """Every contentInstance of a container, oldest first, with its creation time in seconds (`_s`)."""
    import mec046_phone as mp
    st, b = m2m("GET", f"{CSE}/{ae}/{cnt}?rcn=4&ty=4", origin)
    out = sorted((b or {}).get("m2m:cnt", {}).get("m2m:cin", []), key=lambda c: c["ct"]) if st == 200 else []
    for c in out:
        c["_s"] = mp.ct_seconds(c["ct"])
    return out


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def start_service(port: int, ae: str, reader: str, **extra) -> subprocess.Popen:
    env = {**os.environ, "PHONE_CSE": CSE, "PHONE_AE": ae, "PHONE_READER_ORIGIN": reader, "PHONE_MEC046_PORT": str(port),
           "PHONE_MEC046_ACK_WAIT_S": "12", **extra}
    env.pop("MEC046_BEARER_TOKEN", None)
    p = subprocess.Popen([PY, "-B", str(HERE / "mec046_phone.py")], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    while time.time() - t0 < 20:
        if p.poll() is not None:
            break
        if mec(port, "GET", "/")[0] == 200:
            return p
        time.sleep(0.3)
    p.kill()
    raise Abort(f"the service on :{port} did not come up")


def put_rate(port: int, sid: str, rate: str) -> tuple[int, object]:
    return mec(port, "PUT", "/sens/v1/sensor_management", [
        {"sensorIdentifier": sid, "sensorCharacteristicList": [{"characteristicName": "samplingRate", "characteristicValue": rate}]}])


def q(ids) -> str:
    return "?sensorIdentifier=" + ",".join(ids)


def rate_served(port: int, sid: str):
    st, b = mec(port, "GET", "/sens/v1/sensor_management" + q([sid]))
    try:
        return b[0]["sensorCharacteristicList"][0]["characteristicValue"]
    except (TypeError, IndexError, KeyError):
        return f"HTTP {st}: {str(b)[:80]}"


def wait_rate(port: int, sid: str, want: str, timeout: float) -> tuple[str, float]:
    t0, got = time.time(), None
    while time.time() - t0 < timeout:
        got = rate_served(port, sid)
        if got == want:
            break
        time.sleep(1)
    return got, time.time() - t0


def gaps_after(ae: str, origin: str, since_s: float, n: int, timeout: float) -> list[float]:
    """The gaps between the imu records created after `since_s`, leaving out the first (it may still be on the old
    schedule: the probe app applies a new period after its next tick). Waits for n gaps."""
    t0, g = time.time(), []
    while time.time() - t0 < timeout:
        after = [c["_s"] for c in cins(ae, "imu", origin) if c["_s"] > since_s][1:]
        g = [round(b - a, 2) for a, b in zip(after, after[1:])]
        if len(g) >= n:
            break
        time.sleep(1)
    return g


def live(device: str, mp) -> None:  # noqa: C901, PLR0915  one timeline, like the neighbouring drivers
    ae, owner, reader = MODES[device]
    sid = lambda k: f"{ae}:{k}"  # noqa: E731
    all_ids = [sid(k) for k in KEYS]
    D, S, M = "/sens/v1/queries/sensor_discovery", "/sens/v1/queries/sensor_status", "/sens/v1/queries/sensor_data"
    procs: list[subprocess.Popen] = []
    dev, saved, made_acps, period_dirty = None, {}, [], False

    def acp(name: str, pv: list) -> str:
        body = {"m2m:acp": {"rn": name, "pv": {"acr": pv}, "pvs": {"acr": [{"acor": [owner], "acop": 63}]}}}
        st, b = m2m("POST", CSE, owner, body, ty=1)
        if st == 201:
            made_acps.append(name)
        else:   # left by an interrupted run: reset its privileges, never reuse them as found
            st, b = m2m("PUT", f"{CSE}/{name}", owner, {"m2m:acp": {"pv": {"acr": pv}}})
            if st == 200 and name not in made_acps:
                made_acps.append(name)
        ri = (b or {}).get("m2m:acp", {}).get("ri")
        if not ri:
            raise Abort(f"access policy {name}: HTTP {st}")
        return ri

    def set_acpi(cnt: str, acpi: list) -> int:
        if cnt not in saved:
            saved[cnt] = (m2m("GET", f"{CSE}/{ae}/{cnt}", owner)[1] or {}).get("m2m:cnt", {}).get("acpi")
        return m2m("PUT", f"{CSE}/{ae}/{cnt}", owner, {"m2m:cnt": {"acpi": acpi}})[0]

    try:
        print(f"== live: setup ({'SIMULATED phone' if device == 'sim' else 'the phone, as found'}, AE {ae} on {CSE})")
        ports = (PORT, PORT_STRANGER) + ((PORT_SHORT,) if device == "adb" else ())
        require(f"loopback ports {list(ports)} are free", all(port_free(p) for p in ports))
        if device == "sim":
            import sim_phone
            st, b = m2m("GET", f"{CSE}/{ae}", owner)
            if st == 200 and b.get("m2m:ae", {}).get("aei") == owner:       # ours, from an interrupted run
                m2m("DELETE", f"{CSE}/{ae}", owner)
            dev = sim_phone.SimPhone(CSE, owner, rn=ae, period=5.0)
            dev.live()
        t0 = time.time()
        while time.time() - t0 < 25 and len(cins(ae, "imu", owner)) < 2:
            time.sleep(0.5)
        require(f"AE {ae} is streaming on edge A (two imu records readable by its owner)", len(cins(ae, "imu", owner)) >= 2,
                getattr(dev, "last_error", None) or "")
        ri_read = acp(ACP_READ, [{"acor": [reader], "acop": 2 | 32}, {"acor": [owner], "acop": 63}])
        ri_cmd = acp(ACP_CMD, [{"acor": [reader], "acop": 1}, {"acor": [owner], "acop": 63}])
        ri_own = acp(ACP_OWNER, [{"acor": [owner], "acop": 63}])
        grants = {"ack": ri_read, "cmd": ri_cmd} | ({"imu": ri_read, "env": ri_read} if device == "sim" else {})
        sts = {c: set_acpi(c, [ri]) for c, ri in grants.items()}
        require("the reader's policies are on the containers (imu, env, ack: retrieve; cmd: create only)",
                all(s == 200 for s in sts.values()) and m2m("GET", f"{CSE}/{ae}/imu/la", reader)[0] == 200, str(sts))
        procs.append(start_service(PORT, ae, reader))
        procs.append(start_service(PORT_STRANGER, ae, STRANGER))
        st, b = mec(PORT, "GET", "/")
        require("the service answers on :8470 with the candidate's own health reply", st == 200 and b == {"apiName": "sens", "apiVersion": "v1"}, str(b))

        print("== 1 discovery")
        st, disc = mec(PORT, "GET", D)
        got = [d.get("sensorIdentifier") for d in disc] if isinstance(disc, list) else disc
        row("discovery lists the phone's five sensors and nothing else (no fixture sensor)", st == 200 and got == all_ids, str(got)[:200])
        row("each sensor has its type; none has a position", st == 200 and isinstance(disc, list) and len(disc) == 5
            and {d["sensorIdentifier"].split(":")[1]: d["sensorType"] for d in disc} == TYPES and not any("sensorPosition" in d for d in disc))
        if device == "sim":
            row("the simulated phone's sensors are marked simulated", isinstance(disc, list) and bool(disc) and all(
                {"characteristicName": "provenance.simulated", "characteristicValue": "true"} in d["sensorCharacteristicList"] for d in disc))
        flt = urllib.parse.quote(json.dumps({"type": "ef:LightSensor", "sensorPropertyList": ["saref:Light"]}))
        st, one = mec(PORT, "GET", f"{D}?sensorInfo={flt}")
        row("the candidate's own sensorInfo filter picks the light sensor alone", st == 200 and isinstance(one, list)
            and [d["sensorIdentifier"] for d in one] == [sid("light")], str(one)[:120])

        print("== 2 status")
        st, stat = mec(PORT, "GET", S + q(all_ids))
        states = {x["sensorIdentifier"]: x["sensorStatusType"] for x in stat} if isinstance(stat, list) else {}
        want_on = all_ids if device == "sim" else all_ids[:3]       # a real light sensor may have no value in one tick
        row(f"status of the live stream: ONLINE ({len(want_on)} sensors)", st == 200 and len(states) == 5
            and all(states.get(i) == "ONLINE" for i in want_on), str(states))

        print("== 3 data")
        st, data = mec(PORT, "GET", M + q(all_ids))
        now = time.time()
        recs = {c: {x["ct"]: json.loads(x["con"]) for x in cins(ae, c, owner)} for c in ("imu", "env")}
        ok, why = st == 200 and isinstance(data, list) and len(data) >= len(want_on), []
        for d in data if ok else []:
            k = d["sensorIdentifier"].split(":")[1]
            ts = d["dataTimestamp"]["seconds"] + d["dataTimestamp"]["nanoSeconds"] / 1e9
            src = [r for ct, r in recs[mp.SENSORS[k][0]].items() if abs(mp.ct_seconds(ct) - ts) < 1e-5]
            want = " ".join(repr(float(v)) for v in (mp.reading(src[0], k) or [])) if src else None
            if d["data"] != want or not 0 <= now - ts <= 20:
                ok = False
                why.append(f"{k}: served {d['data']!r} at age {now - ts:.1f} s, the CSE record of that time holds {want!r}")
        row("every reading served is the value of the CSE record created at the served time, and under 20 s old", ok,
            "; ".join(why) or f"{len(data) if isinstance(data, list) else 0} readings")
        if device == "sim":
            vals = {d["sensorIdentifier"]: d["data"] for d in data} if isinstance(data, list) else {}
            row("the simulated phone's fixed values come out: accel 0.0 0.0 9.81, mag 20.0 -5.0 -40.0, light 120.0, battery 25.0",
                [vals.get(sid(k)) for k in ("accel", "mag", "light", "battery_temp")] == ["0.0 0.0 9.81", "20.0 -5.0 -40.0", "120.0", "25.0"], str(vals))

        print("== 4 a sampling-period change that reaches the phone")
        got, _ = wait_rate(PORT, sid("accel"), "0.2", 15)
        row("before: the stream runs at one record per 5 s and the candidate's management GET says 0.2 Hz", got == "0.2", str(got))
        n_cmd = len(cins(ae, "cmd", owner))
        st_hi = put_rate(PORT, sid("accel"), "5")[0]         # 5 Hz: outside the settable range, the candidate's own 400
        st_frac = put_rate(PORT, sid("accel"), "0.3")[0]     # 3.33 s: no whole second, the wrapper's 400
        st_two = mec(PORT, "PUT", "/sens/v1/sensor_management", [
            {"sensorIdentifier": sid("accel"), "sensorCharacteristicList": [{"characteristicName": "samplingRate", "characteristicValue": "0.5"}]},
            {"sensorIdentifier": sid("light"), "sensorCharacteristicList": [{"characteristicName": "samplingRate", "characteristicValue": "0.2"}]}])[0]
        row("refused requests (5 Hz, 0.3 Hz, two rates at once) answer 400 and put no command into the phone's <cmd>",
            (st_hi, st_frac, st_two) == (400, 400, 400) and len(cins(ae, "cmd", owner)) == n_cmd and rate_served(PORT, sid("accel")) == "0.2",
            f"HTTP {st_hi}, {st_frac}, {st_two}; commands before {n_cmd}, after {len(cins(ae, 'cmd', owner))}")
        n_ack = len(cins(ae, "ack", owner))
        period_dirty = True
        st, b = put_rate(PORT, sid("accel"), "0.5")
        t_put = time.time()
        new_cmd = [json.loads(c["con"]) for c in cins(ae, "cmd", owner)[n_cmd:]]
        new_ack = [json.loads(c["con"]) for c in cins(ae, "ack", owner)[n_ack:]]
        acked = (len(new_cmd) == 1 and new_cmd[0].get("cmd") == "period" and new_cmd[0].get("value") == 2 and len(new_ack) == 1
                 and mp.ack_confirms(new_ack[0], new_cmd[0].get("id"), 2))
        g = gaps_after(ae, owner, t_put, 3, 40) if st == 200 and acked else []
        row("PUT samplingRate 0.5 Hz: one command {cmd: period, value: 2} in <cmd>, the phone's ack in <ack>, 200, and the "
            "next records are 2 s apart", st == 200 and acked and len(g) >= 3 and all(round(x) == 2 for x in g),
            f"HTTP {st}; cmd {new_cmd}; ack {new_ack}; gaps {g} s" + (f"; sim period {dev.period}" if dev else ""))
        got, took = wait_rate(PORT, sid("light"), "0.5", 15)
        row("after: the management GET says 0.5 Hz for every sensor of the phone (measured from the stream)", got == "0.5", f"{got} after {took:.0f} s")

        st_w = set_acpi("ack", [ri_own])                     # the reader can no longer read the phone's acks
        n_cmd = len(cins(ae, "cmd", owner))
        st, b = put_rate(PORT, sid("accel"), "0.25")
        sent = [json.loads(c["con"]) for c in cins(ae, "cmd", owner)[n_cmd:]]
        st_r = set_acpi("ack", [ri_read])
        control("a period change was reported done although the service could not read the phone's ack",
                not (st_w == 200 and st == 504 and len(sent) == 1 and st_r == 200),
                f"ack hidden HTTP {st_w}; PUT answered {st} ({str((b or {}).get('detail') if isinstance(b, dict) else b)[:90]}); "
                f"command sent {sent}; ack readable again HTTP {st_r}")
        st_w = set_acpi("cmd", [ri_own])                     # the reader can no longer create a command
        n_cmd = len(cins(ae, "cmd", owner))
        st, b = put_rate(PORT, sid("accel"), "0.25")
        n_after = len(cins(ae, "cmd", owner))
        st_r = set_acpi("cmd", [ri_cmd])
        control("a period change was reported done although the CSE refused the reader's command",
                not (st_w == 200 and st == 502 and n_after == n_cmd and st_r == 200),
                f"cmd closed HTTP {st_w}; PUT answered {st} ({str((b or {}).get('detail') if isinstance(b, dict) else b)[:90]}); "
                f"commands before {n_cmd}, after {n_after}; cmd open again HTTP {st_r}")
        n_ack = len(cins(ae, "ack", owner))
        st, b = put_rate(PORT, sid("gyro"), "0.2")
        t_put = time.time()
        back = [json.loads(c["con"]) for c in cins(ae, "ack", owner)[n_ack:]]
        g = gaps_after(ae, owner, t_put, 2, 40) if st == 200 else []
        if st == 200 and back and back[-1].get("ok") is True and back[-1].get("period") == 5:
            period_dirty = False
        row("the period is put back to 5 s the same way (PUT 0.2 Hz, ack, records 5 s apart)",
            st == 200 and not period_dirty and len(g) >= 2 and all(round(x) == 5 for x in g), f"HTTP {st}; ack {back}; gaps {g} s")

        print("== 5 access: nothing without the oneM2M access policy")
        direct = (m2m("GET", f"{CSE}/{ae}/imu/la", reader)[0], m2m("GET", f"{CSE}/{ae}/imu/la", STRANGER)[0])
        row("on the CSE itself the reader reads the imu container and an originator without the policy gets 403", direct == (200, 403), str(direct))
        if device == "sim":
            other = [m2m("GET", f"{CSE}/{ae}/{c}/la", reader)[0] for c in ("loc", "wlan", "radio")]
            row("the reader's policy does not cover the position, Wi-Fi and radio containers (403 each)", other == [403] * 3, str(other))
        r = [mec(PORT_STRANGER, "GET", D), mec(PORT_STRANGER, "GET", S + q(all_ids)), mec(PORT_STRANGER, "GET", M + q(all_ids)),
             mec(PORT_STRANGER, "GET", "/sens/v1/sensor_management" + q(all_ids))]
        control("a service reading as an originator WITHOUT the access policy served a sensor, a status or a reading",
                not all(st == 200 and body == [] for st, body in r), str([(st, str(body)[:40]) for st, body in r]))
        n_cmd = len(cins(ae, "cmd", owner))
        st, b = put_rate(PORT_STRANGER, sid("accel"), "0.5")
        control("a period change went through for an originator without the access policy",
                not (st == 400 and len(cins(ae, "cmd", owner)) == n_cmd), f"HTTP {st}; commands before {n_cmd}, after {len(cins(ae, 'cmd', owner))}")
        st_w = set_acpi("env", [ri_own])                     # the owner withdraws the env container from the reader
        st_d, d2 = mec(PORT, "GET", D)
        st_m, m2 = mec(PORT, "GET", M + q(all_ids))
        st_s, s2 = mec(PORT, "GET", S + q(all_ids))
        st_r = set_acpi("env", saved["env"] if device == "adb" else [ri_read])
        ids_d = [x["sensorIdentifier"] for x in d2] if isinstance(d2, list) else d2
        ids_m = sorted({x["sensorIdentifier"] for x in m2}) if isinstance(m2, list) else m2
        ids_s = [x["sensorIdentifier"] for x in s2] if isinstance(s2, list) else s2
        control("light or battery temperature was still served after the owner withdrew the env container from the reader",
                not (st_w == 200 and (st_d, st_m, st_s) == (200, 200, 200) and ids_d == all_ids[:3] and ids_s == all_ids[:3]
                     and set(ids_m) <= set(all_ids[:3])),
                f"withdrawal HTTP {st_w}; discovery {ids_d}; status {ids_s}; data {ids_m}")
        t0, ids_d = time.time(), None
        while time.time() - t0 < 10 and ids_d != all_ids:
            _, d3 = mec(PORT, "GET", D)
            ids_d = [x["sensorIdentifier"] for x in d3] if isinstance(d3, list) else d3
            time.sleep(0.5)
        row("granted again, all five sensors are served again", st_r == 200 and ids_d == all_ids, f"grant HTTP {st_r}; {ids_d}")

        print("== routes that are not served")
        st1, b1 = mec(PORT, "GET", D + "?geographicalArea=" + urllib.parse.quote(json.dumps(
            {"shape": 1, "points": [{"latitude": 0, "longitude": 0}], "radius": 10})))
        st2, _ = mec(PORT, "POST", "/sens/v1/subscriptions/sensor_data", {
            "subscriptionType": "SensorDataSubscription", "callbackReference": "http://127.0.0.1:8479/cb", "sensorIdentifierList": [sid("accel")]})
        st3, _ = mec(PORT, "GET", "/sens/v1/subscriptions/sensor_data")
        row("a discovery by area is refused (400: the sensors have no position) and subscriptions are not served (404)",
            (st1, st2, st3) == (400, 404, 404), f"HTTP {st1}, {st2}, {st3}")

        print("== 6 stale: a stream older than 20 s is not live")
        if device == "sim":
            dev.stop()
            time.sleep(mp.MAX_AGE_S + 2)
            st_s, s2 = mec(PORT, "GET", S + q(all_ids))
            st_m, m2 = mec(PORT, "GET", M + q(all_ids))
            st_d, d2 = mec(PORT, "GET", D)
            off_all = (st_s == 200 and isinstance(s2, list) and len(s2) == 5
                       and all(x["sensorStatusType"] == "OFFLINE" and "stale" in x.get("errorInformation", "") for x in s2))
            control("with the stream stopped for 22 s a sensor was still ONLINE or a reading was still served",
                    not (off_all and st_m == 200 and m2 == [] and st_d == 200 and len(d2) == 5),
                    f"status {[x.get('sensorStatusType') for x in s2] if isinstance(s2, list) else s2}; "
                    f"readings {len(m2) if isinstance(m2, list) else m2}; e.g. {s2[0].get('errorInformation') if off_all else ''}")
            dev.live()
            t0, on = time.time(), False
            while time.time() - t0 < 20 and not on:
                time.sleep(1)
                st_s, s2 = mec(PORT, "GET", S + q(all_ids))
                on = st_s == 200 and isinstance(s2, list) and len(s2) == 5 and all(x["sensorStatusType"] == "ONLINE" for x in s2)
            row("with the stream running again every sensor is ONLINE and a reading is served",
                on and len(mec(PORT, "GET", M + q(all_ids))[1] or []) == 5, f"after {time.time() - t0:.0f} s")
        else:   # the phone is not stopped from here: a second instance with the limit cut to 1 ms judges the same stream
            procs.append(start_service(PORT_SHORT, ae, reader, PHONE_MAX_SAMPLE_AGE_S="0.001"))
            st_s, s2 = mec(PORT_SHORT, "GET", S + q(all_ids))
            st_m, m2 = mec(PORT_SHORT, "GET", M + q(all_ids))
            control("(limit cut to 1 ms on a second instance; the 20 s limit itself is shown with the simulated phone only) "
                    "a reading older than the limit was served as live",
                    not (st_s == 200 and isinstance(s2, list) and len(s2) == 5 and all(x["sensorStatusType"] == "OFFLINE" for x in s2)
                         and st_m == 200 and m2 == []), f"status {s2}; readings {m2}"[:200])

        print("== no position and no network name in anything the service answered")
        hits = leaks(SEEN)
        row(f"{len(SEEN)} replies of the service scanned: no position field, no network name", len(SEEN) > 20 and not hits, str(hits[:3]))
    except Abort as e:
        row("the run reached its end", False, f"stopped: {e}")
    except Exception as e:  # noqa: BLE001  an exception is a FAIL row, never a silent stop
        traceback.print_exc()
        row("the run completed without an exception", False, repr(e)[:200])
    finally:
        print("== cleanup")
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
        if device == "sim":
            if dev is not None:
                dev.stop()
            m2m("DELETE", f"{CSE}/{ae}", owner)
        else:
            if period_dirty:    # the service did not get the period back to 5: post the command as the phone's owner
                m2m("POST", f"{CSE}/{ae}/cmd", owner, {"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(
                    {"cmd": "period", "value": 5, "id": f"t046-restore-{time.time_ns()}"})}}, ty=4)
            for cnt, acpi in saved.items():
                m2m("PUT", f"{CSE}/{ae}/{cnt}", owner, {"m2m:cnt": {"acpi": acpi}} if acpi else {"m2m:cnt": {"acpi": None}})
        for name in (ACP_READ, ACP_CMD, ACP_OWNER):
            m2m("DELETE", f"{CSE}/{name}", owner)
        left = {name: m2m("GET", f"{CSE}/{name}", owner)[0] for name in (ACP_READ, ACP_CMD, ACP_OWNER)}
        if device == "sim":
            left[ae] = m2m("GET", f"{CSE}/{ae}", owner)[0]
        else:
            left |= {f"{ae}/{c} acpi as found": (m2m("GET", f"{CSE}/{ae}/{c}", owner)[1] or {}).get("m2m:cnt", {}).get("acpi") == a
                     for c, a in saved.items()}
        time.sleep(0.5)
        left["ports closed"] = all(port_free(p) for p in (PORT, PORT_STRANGER, PORT_SHORT))
        row("nothing is left behind: the access policies are gone" + (", the AE is gone" if device == "sim" else ", the containers' policies are as found")
            + ", the ports are closed", all(v in (404, True) for v in left.values()), str(left))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="MEC 046 sensor sharing fed from a phone's oneM2M stream (plan row B3)")
    ap.add_argument("--device", choices=("sim", "adb"), default="sim")
    ap.add_argument("--offline-only", action="store_true", help="the pure-function rows only; the live rows count as skipped")
    ap.add_argument("--results", help="also write the rows to this JSON file")
    a = ap.parse_args(argv)
    ae, _owner, reader = MODES[a.device]
    os.environ.update(PHONE_CSE=CSE, PHONE_AE=ae, PHONE_READER_ORIGIN=reader)     # device_state reads these at import
    os.environ.pop("PHONE_MAX_SAMPLE_AGE_S", None)
    try:
        import mec046_phone as mp
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        row("phone/mec046_phone.py loads", False, repr(e)[:200])
        mp = None
    if mp is not None:
        cand = Path(mp.CANDIDATE)
        print(f"candidate: {cand}  sha256 {hashlib.sha256(cand.read_bytes()).hexdigest()[:16]}  device: {a.device}")
        offline(mp, ae)
        if a.offline_only:
            SKIPPED.append("every live row (--offline-only)")
        else:
            live(a.device, mp)
    rows = [r for r in ROWS if r[0] == "row"]
    ctl = [r for r in ROWS if r[0] == "control"]
    ok = sum(1 for r in rows if r[2])
    held = sum(1 for r in ctl if not r[2])
    good = mp is not None and ok == len(rows) and bool(ctl) and held == len(ctl) and not SKIPPED
    for s in SKIPPED:
        print(f"  SKIPPED  {s}")
    print(f"\n  RESULT: {'PASS' if good else 'FAIL'}  ({ok}/{len(rows)} rows passed; {held}/{len(ctl)} controls failed as they must; "
          f"{len(SKIPPED)} skipped; device {a.device})")
    if a.results:
        Path(a.results).write_text(json.dumps({
            "device": a.device, "verdict": "PASS" if good else "FAIL", "skipped": SKIPPED,
            "at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "rows": [{"kind": k, "name": n, "printed": "PASS" if p else "FAIL", "detail": d} for k, n, p, d in ROWS]}, indent=1))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
