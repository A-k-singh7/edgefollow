#!/usr/bin/env python3
"""ETSI GS MEC 046 Sensor-Sharing API (`sens`, V3.2.1) -- candidate.

Not a conformance claim. No ATS exists for MEC 046; the contract is a list of checks
frozen before this file was written, and its tests, its spec-vs-forge disagreements
and its decisions are kept with the author's lab (not in this repository).

    GET                 /sens/v1/queries/sensor_discovery   ?sensorInfo=<json>&geographicalArea=<json>
    GET                 /sens/v1/queries/sensor_status      ?sensorIdentifier=a,b
    GET                 /sens/v1/queries/sensor_data        ?sensorIdentifier=a,b
    GET, PUT            /sens/v1/sensor_management          (GET ?sensorIdentifier=...)
    GET, POST           /sens/v1/subscriptions/{sensor_discovery|sensor_status|sensor_data}
    GET, PUT, DELETE    /sens/v1/subscriptions/{...}/{subscriptionId}
    WS                  /sens/v1/notifications/ws/{subscriptionId}   (websocket delivery)
    GET                 /    health: {"apiName": "sens", "apiVersion": "v1"}

Default data is a DETERMINISTIC FIXTURE inventory (identifiers `fixture:*`, every
discovery record carries `provenance.source = fixture`). Real data only enters through
a separate entry point (not in this repository), from a JSON snapshot; nothing here opens a
device.

Plain HTTP on 127.0.0.1:8046. Clause 7.2 requires HTTPS and OAuth 2.0; this lab
candidate does neither by default (MEC046_BEARER_TOKEN turns on a static bearer check).

Seams (PREREG section 1): NOW, NOTIFY, BEARER_TOKEN, apply_inventory, fixture_inventory,
tick, app.
"""
from __future__ import annotations

import asyncio
import copy
import json
import logging
import math
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

PORT = 8046
BASE = "/sens/v1"
log = logging.getLogger("mec046")

# ------------------------------------------------------------------ seams ----
NOW = time.time
BEARER_TOKEN: str | None = os.environ.get("MEC046_BEARER_TOKEN") or None


def _http_notify(url: str, body: dict) -> None:
    """Default outbound notification: one HTTP POST in a daemon thread, http(s) only."""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        log.warning("notification to non-http URI %r dropped", url)
        return

    def run():
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except Exception as e:  # noqa: BLE001 -- a dead callback must not break the server
            log.warning("notification to %s failed: %s", url, e)
    threading.Thread(target=run, daemon=True).start()


NOTIFY = _http_notify

# --------------------------------------------------------------- fixture -----
FIXTURE_TIME = {"seconds": 1760500000, "nanoSeconds": 0}
_RATE = {"unit": "om:hertz", "min": 0.1, "max": 100.0}


def _fx(name, typ, props, lat, lon, status, model, rate, data, err=None):
    sid = f"fixture:{name}"
    chars = [{"characteristicName": "model", "characteristicValue": model},
             {"characteristicName": "samplingRate", "characteristicValue": rate,
              "characteristicUnitOfMeasure": "om:hertz"},
             {"characteristicName": "provenance.source", "characteristicValue": "fixture"},
             {"characteristicName": "provenance.note",
              "characteristicValue": "deterministic fixture, not a measurement"}]
    st = {"sensorIdentifier": sid, "sensorStatusType": status}
    if err:
        st["errorInformation"] = err
    return {"discovery": {"sensorIdentifier": sid, "sensorType": typ, "sensorPropertyList": props,
                          "sensorCharacteristicList": chars,
                          "sensorPosition": {"latitude": lat, "longitude": lon}},
            "status": st,
            "data": [{"sensorIdentifier": sid, "data": v, "dataFormat": f, "dataUnitOfMeasure": u,
                      "dataTimestamp": dict(FIXTURE_TIME)} for v, f, u in data],
            "settable": {"samplingRate": dict(_RATE)}}


_F, _L = "xsd:float", "custom:xsdFloatList"


def _fixture() -> list[dict]:
    return [
        _fx("temp-01", "ef:TemperatureSensor", ["saref:Temperature"], 1.0000, 1.0000, "ON", "TMP117", "1",
            [("21.5", _F, "om:degreeCelsius")]),
        _fx("temp-02", "ef:TemperatureSensor", ["saref:Temperature"], 1.0010, 1.0010, "ERROR", "TMP117", "1",
            [("19.0", _F, "om:degreeCelsius")], err="probe disconnected (fixture)"),
        _fx("humtemp-01", "ef:TemperatureSensor", ["saref:Temperature", "saref:Humidity"], 1.0020, 1.0020,
            "ON", "SHT45", "0.5", [("22.1", _F, "om:degreeCelsius"), ("45.0", _F, "om:percent")]),
        _fx("light-01", "ef:LightSensor", ["saref:Light"], 1.0030, 1.0030, "STANDBY", "VEML7700", "1",
            [("320", _F, "om:lux")]),
        _fx("accel-01", "ef:Accelerometer", ["ef:Acceleration"], 1.0040, 1.0040, "ONLINE", "LIS3DH", "50",
            [("0.02 0.01 9.81", _L, "om:metrePerSecond-TimeSquared")]),
        _fx("rssi-01", "ef:RadioSignalStrengthSensor", ["ef:ReceivedSignalStrength"], 1.0050, 1.0050,
            "OFFLINE", "CC1101", "1", [("-94.09", _F, "custom:dBm")]),
    ]


INVENTORY: list[dict] = _fixture()


def fixture_inventory() -> list[dict]:
    return copy.deepcopy(_fixture())


def _by_id(inv=None) -> dict[str, dict]:
    return {r["discovery"]["sensorIdentifier"]: r for r in (INVENTORY if inv is None else inv)}


# --------------------------------------------------------------- helpers -----
class Bad(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


_TITLES = {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
           405: "Method Not Allowed", 406: "Not Acceptable", 415: "Unsupported Media Type",
           422: "Unprocessable Entity", 429: "Too Many Requests"}


def _problem_body(status: int, detail: str) -> dict:
    return {"type": "about:blank", "title": _TITLES.get(status, "Error"), "status": status, "detail": detail}


def problem(status: int, detail: str, headers: dict | None = None) -> JSONResponse:
    # MEC 009 6.15.4: ProblemDetails in JSON is application/problem+json.
    return JSONResponse(_problem_body(status, detail), status_code=status,
                        media_type="application/problem+json", headers=headers)


def _ts(now: float | None = None) -> dict:
    now = NOW() if now is None else now
    s = int(now)
    return {"seconds": s, "nanoSeconds": int(round((now - s) * 1e9)) % 1_000_000_000}


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _is_num(x) -> bool:
    return (_is_int(x) or isinstance(x, float)) and math.isfinite(x)


def _keys(d: dict, allowed: set, where: str):
    extra = set(d) - allowed
    if extra:
        raise Bad(400, f"{where}: unknown attribute(s) {sorted(extra)}")


def _nonempty_str(x, where):
    if not isinstance(x, str) or not x:
        raise Bad(400, f"{where} shall be a non-empty string")
    return x


def v_timestamp(x, where) -> dict:
    if not isinstance(x, dict):
        raise Bad(400, f"{where} shall be a TimeStamp object")
    _keys(x, {"seconds", "nanoSeconds"}, where)
    for k in ("seconds", "nanoSeconds"):
        if k not in x or not _is_int(x[k]) or not 0 <= x[k] <= 0xFFFFFFFF:
            raise Bad(400, f"{where}.{k} shall be a Uint32 (clause 6.5.3)")
    return x


def v_point(x, where) -> tuple[float, float]:
    if not isinstance(x, dict):
        raise Bad(400, f"{where} shall be a Point object")
    _keys(x, {"latitude", "longitude"}, where)
    la, lo = x.get("latitude"), x.get("longitude")
    if not _is_num(la) or not -90 <= la <= 90:
        raise Bad(400, f"{where}.latitude shall be a number in [-90, 90] (clause 6.5.2)")
    if not _is_num(lo) or not -180 <= lo <= 180:
        raise Bad(400, f"{where}.longitude shall be a number in [-180, 180] (clause 6.5.2)")
    return float(la), float(lo)


def v_area(x, where) -> dict:
    """AreaInfo, clause 6.5.1: shape 1 = CIRCLE (1 point + radius), 2 = POLYGON (3..15 points)."""
    if not isinstance(x, dict):
        raise Bad(400, f"{where} shall be an AreaInfo object")
    _keys(x, {"shape", "points", "radius"}, where)
    shape = x.get("shape")
    if not _is_int(shape) or shape not in (1, 2):
        raise Bad(400, f"{where}.shape shall be 1 (CIRCLE) or 2 (POLYGON)")
    pts = x.get("points")
    if not isinstance(pts, list) or not pts:
        raise Bad(400, f"{where}.points shall be a non-empty array of Point")
    pts = [v_point(p, f"{where}.points[{i}]") for i, p in enumerate(pts)]
    if shape == 1:
        if len(pts) != 1:
            raise Bad(400, f"{where}: a CIRCLE shall include exactly one point")
        r = x.get("radius")
        if not _is_int(r) or r < 0:
            raise Bad(400, f"{where}.radius (UnsignedInt, metres) shall be present for a CIRCLE")
        return {"shape": 1, "points": pts, "radius": r}
    if not 3 <= len(pts) <= 15:
        raise Bad(400, f"{where}: a POLYGON shall include 3 to 15 points")
    if "radius" in x:
        raise Bad(400, f"{where}.radius applies to a CIRCLE only")
    return {"shape": 2, "points": pts}


def v_characteristic(x, where) -> dict:
    if not isinstance(x, dict):
        raise Bad(400, f"{where} shall be a SensorCharacteristic object")
    _keys(x, {"characteristicName", "characteristicValue", "characteristicUnitOfMeasure"}, where)
    _nonempty_str(x.get("characteristicName"), f"{where}.characteristicName")
    if not isinstance(x.get("characteristicValue"), str):
        raise Bad(400, f"{where}.characteristicValue shall be a string")
    if "characteristicUnitOfMeasure" in x and not isinstance(x["characteristicUnitOfMeasure"], str):
        raise Bad(400, f"{where}.characteristicUnitOfMeasure shall be a string")
    return x


def v_sensor_info(x, where) -> dict:
    if not isinstance(x, dict):
        raise Bad(400, f"{where} shall be an object")
    _keys(x, {"type", "sensorPropertyList", "sensorCharacteristicList"}, where)
    _nonempty_str(x.get("type"), f"{where}.type")
    pl = x.get("sensorPropertyList")
    if not isinstance(pl, list) or not pl:
        raise Bad(400, f"{where}.sensorPropertyList shall be a non-empty array (cardinality 1..N)")
    for i, p in enumerate(pl):
        _nonempty_str(p, f"{where}.sensorPropertyList[{i}]")
    cl = x.get("sensorCharacteristicList", [])
    if not isinstance(cl, list):
        raise Bad(400, f"{where}.sensorCharacteristicList shall be an array")
    for i, c in enumerate(cl):
        v_characteristic(c, f"{where}.sensorCharacteristicList[{i}]")
    return x


# --------------------------------------------------------------- matching ----
EARTH_R = 6371008.8


def _haversine(a, b) -> float:
    p1, l1, p2, l2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin((l2 - l1) / 2) ** 2
    return 2 * EARTH_R * math.asin(min(1.0, math.sqrt(h)))


def _in_polygon(pt, poly) -> bool:
    y, x = pt
    inside = False
    for i in range(len(poly)):
        y1, x1 = poly[i]
        y2, x2 = poly[i - 1]
        if (y1 > y) != (y2 > y):
            if x < x1 + (y - y1) * (x2 - x1) / (y2 - y1):
                inside = not inside
    return inside


def _in_area(pos, area) -> bool:
    if area["shape"] == 1:
        return _haversine(area["points"][0], pos) <= area["radius"]
    return _in_polygon(pos, area["points"])


def _info_matches(disc: dict, info: dict) -> bool:
    """Value semantics (PREREG s.1): type equal, properties a subset, characteristics equal by value."""
    if disc["sensorType"] != info["type"]:
        return False
    if not set(info["sensorPropertyList"]) <= set(disc["sensorPropertyList"]):
        return False
    have = {c["characteristicName"]: c for c in disc.get("sensorCharacteristicList", [])}
    for want in info.get("sensorCharacteristicList", []):
        c = have.get(want["characteristicName"])
        if c is None or c["characteristicValue"] != want["characteristicValue"]:
            return False
        if "characteristicUnitOfMeasure" in want and \
                c.get("characteristicUnitOfMeasure") != want["characteristicUnitOfMeasure"]:
            return False
    return True


def _selects(disc: dict, infos: list, areas: list) -> bool:
    if infos and not any(_info_matches(disc, i) for i in infos):
        return False
    if areas:
        p = disc["sensorPosition"]
        if not any(_in_area((p["latitude"], p["longitude"]), a) for a in areas):
            return False
    return True


# --------------------------------------------------------------- queries -----
def _only_params(request: Request, allowed: set):
    extra = set(request.query_params.keys()) - allowed
    if extra:
        raise Bad(400, f"unsupported query parameter(s) {sorted(extra)}; supported: {sorted(allowed)}")


def _json_param(raw: str, where: str):
    try:
        return json.loads(raw)
    except ValueError:
        raise Bad(400, f"{where} shall be a URL-encoded JSON object") from None


def _id_list(request: Request, required: bool) -> list[str] | None:
    vals = request.query_params.getlist("sensorIdentifier")
    if not vals:
        if required:
            raise Bad(400, "query parameter sensorIdentifier is required (cardinality 1..N)")
        return None
    out = []
    for v in vals:
        for part in v.split(","):
            if not part.strip():
                raise Bad(400, "sensorIdentifier shall not be empty")
            out.append(part.strip())
    return out


def _parse_discovery_query(request: Request):
    _only_params(request, {"sensorInfo", "geographicalArea"})
    infos = [v_sensor_info(_json_param(v, "sensorInfo"), "sensorInfo")
             for v in request.query_params.getlist("sensorInfo")]
    areas = [v_area(_json_param(v, "geographicalArea"), "geographicalArea")
             for v in request.query_params.getlist("geographicalArea")]
    return infos, areas


def _ok(content) -> JSONResponse:
    return JSONResponse(content, status_code=200)


api = FastAPI(title="MEC 046 Sensor-Sharing", version="v1", docs_url=None, redoc_url=None, openapi_url=None)


@api.exception_handler(StarletteHTTPException)
async def _http_exc(request, exc):
    detail = {404: "no resource at this URI", 405: f"{request.method} is not supported on this resource"}
    return problem(exc.status_code, detail.get(exc.status_code, str(exc.detail)), headers=getattr(exc, "headers", None))


@api.exception_handler(Bad)
async def _bad(request, exc):
    return problem(exc.status, exc.detail)


@api.get("/")
async def health():
    return _ok({"apiName": "sens", "apiVersion": "v1"})


@api.get(BASE + "/queries/sensor_discovery")
async def q_discovery(request: Request):
    infos, areas = _parse_discovery_query(request)
    return _ok([copy.deepcopy(r["discovery"]) for r in INVENTORY if _selects(r["discovery"], infos, areas)])


def _records_for(request: Request):
    _only_params(request, {"sensorIdentifier"})
    want = _id_list(request, required=True)
    wanted = set(want)
    return [r for r in INVENTORY if r["discovery"]["sensorIdentifier"] in wanted]


@api.get(BASE + "/queries/sensor_status")
async def q_status(request: Request):
    return _ok([copy.deepcopy(r["status"]) for r in _records_for(request)])


@api.get(BASE + "/queries/sensor_data")
async def q_data(request: Request):
    return _ok([copy.deepcopy(d) for r in _records_for(request) for d in r["data"]])


# ------------------------------------------------------------ management ----
def _settable_view(rec) -> dict:
    have = {c["characteristicName"]: c for c in rec["discovery"].get("sensorCharacteristicList", [])}
    chars = []
    for name, spec in rec.get("settable", {}).items():
        c = {"characteristicName": name, "characteristicValue": have.get(name, {}).get("characteristicValue", "")}
        if spec.get("unit"):
            c["characteristicUnitOfMeasure"] = spec["unit"]
        chars.append(c)
    return {"sensorIdentifier": rec["discovery"]["sensorIdentifier"], "sensorCharacteristicList": chars}


@api.get(BASE + "/sensor_management")
async def mgmt_get(request: Request):
    return _ok([_settable_view(r) for r in _records_for(request)])


def _require_json_ctype(request: Request):
    ct = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ct != "application/json":
        raise Bad(415, f"Content-Type {ct or '(none)'!r} is not supported; use application/json")


async def _json_body(request: Request):
    _require_json_ctype(request)
    raw = await request.body()
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise Bad(400, "request body is not valid JSON") from None


@api.put(BASE + "/sensor_management")
async def mgmt_put(request: Request):
    """Clause 5.3.8 / 7.12.3.2. All-or-nothing: any entry that cannot be applied -> 400, nothing changes."""
    body = await _json_body(request)
    if not isinstance(body, list) or not body:
        raise Bad(400, "request body shall be a non-empty array of SensorCharacteristicInfo")
    inv = copy.deepcopy(INVENTORY)
    by = _by_id(inv)
    order: list[str] = []
    for i, item in enumerate(body):
        where = f"[{i}]"
        if not isinstance(item, dict):
            raise Bad(400, f"{where} shall be a SensorCharacteristicInfo object")
        _keys(item, {"sensorIdentifier", "sensorCharacteristicList"}, where)
        sid = _nonempty_str(item.get("sensorIdentifier"), f"{where}.sensorIdentifier")
        rec = by.get(sid)
        if rec is None:
            raise Bad(400, f"{where}: no sensor {sid!r}; configuration not set")
        if sid.startswith("real:"):
            raise Bad(400, f"{where}: {sid!r} comes from the real source and is read-only; nothing is "
                           "written to devices")
        cl = item.get("sensorCharacteristicList")
        if not isinstance(cl, list) or not cl:
            raise Bad(400, f"{where}.sensorCharacteristicList shall be a non-empty array")
        for j, c in enumerate(cl):
            w = f"{where}.sensorCharacteristicList[{j}]"
            v_characteristic(c, w)
            spec = rec.get("settable", {}).get(c["characteristicName"])
            if spec is None:
                raise Bad(400, f"{w}: characteristic {c['characteristicName']!r} cannot be set on {sid!r}; "
                               f"settable: {sorted(rec.get('settable', {}))}")
            if "characteristicUnitOfMeasure" in c and c["characteristicUnitOfMeasure"] != spec.get("unit"):
                raise Bad(400, f"{w}: unit {c['characteristicUnitOfMeasure']!r} != {spec.get('unit')!r}")
            try:
                val = float(c["characteristicValue"])
            except ValueError:
                raise Bad(400, f"{w}: value {c['characteristicValue']!r} is not a number") from None
            if not (math.isfinite(val) and spec["min"] <= val <= spec["max"]):
                raise Bad(400, f"{w}: value {val} outside [{spec['min']}, {spec['max']}]")
            for dc in rec["discovery"].setdefault("sensorCharacteristicList", []):
                if dc["characteristicName"] == c["characteristicName"]:
                    dc["characteristicValue"] = c["characteristicValue"]
                    break
            else:
                rec["discovery"]["sensorCharacteristicList"].append(
                    {"characteristicName": c["characteristicName"],
                     "characteristicValue": c["characteristicValue"], "characteristicUnitOfMeasure": spec["unit"]})
        if sid not in order:
            order.append(sid)
    apply_inventory(inv)                       # emits SENSOR_UPDATE to matching discovery subscriptions
    return _ok([_settable_view(_by_id()[s]) for s in order])


# --------------------------------------------------------- subscriptions ----
KINDS = {"sensor_discovery": "SensorDiscoveryEventSubscription",
         "sensor_status": "SensorStatusSubscription",
         "sensor_data": "SensorDataSubscription"}
_COMMON = {"subscriptionType", "callbackReference", "requestTestNotification", "websockNotifConfig",
           "_links", "expiryDeadline"}
_ALLOWED = {"sensor_discovery": _COMMON | {"sensorInfo", "geographicalArea"},
            "sensor_status": _COMMON | {"sensorIdentifierList"},
            "sensor_data": _COMMON | {"sensorIdentifierList"}}

SUBS: dict[str, dict] = {}       # id -> {"kind", "rec" (response representation), "ws": bool}
_SEQ = [0]
_WS: dict[str, tuple] = {}       # id -> (loop, asyncio.Queue)
_WS_PENDING: dict[str, list] = {}
_WS_PENDING_MAX = 100


def _origin(request) -> tuple[str, str]:
    host = request.headers.get("host") or f"127.0.0.1:{PORT}"
    return f"http://{host}", f"ws://{host}"


def _validate_sub(kind: str, b, *, on_put: bool, self_path: str | None = None) -> dict:
    if not isinstance(b, dict):
        raise Bad(400, "request body shall be a JSON object")
    _keys(b, _ALLOWED[kind], KINDS[kind])
    if b.get("subscriptionType") != KINDS[kind]:
        raise Bad(400, f"subscriptionType shall be {KINDS[kind]!r} on this resource")
    if "callbackReference" in b:
        cb = b["callbackReference"]
        if not isinstance(cb, str) or urllib.parse.urlsplit(cb).scheme not in ("http", "https") \
                or not urllib.parse.urlsplit(cb).netloc:
            raise Bad(400, "callbackReference shall be an absolute http(s) URI")
    if "websockNotifConfig" in b:
        w = b["websockNotifConfig"]
        if not isinstance(w, dict):
            raise Bad(400, "websockNotifConfig shall be an object")
        _keys(w, {"websocketUri", "requestWebsocketUri"}, "websockNotifConfig")
        if "requestWebsocketUri" in w and not isinstance(w["requestWebsocketUri"], bool):
            raise Bad(400, "websockNotifConfig.requestWebsocketUri shall be a boolean")
        if "websocketUri" in w and not isinstance(w["websocketUri"], str):
            raise Bad(400, "websockNotifConfig.websocketUri shall be a string")
    if "callbackReference" not in b and "websockNotifConfig" not in b:
        raise Bad(400, "at least one of callbackReference and websockNotifConfig shall be provided "
                       "(Tables 6.3.x-1 note 2)")
    if "requestTestNotification" in b and not isinstance(b["requestTestNotification"], bool):
        raise Bad(400, "requestTestNotification shall be a boolean")
    if "_links" in b:
        if not on_put:
            raise Bad(400, "_links shall only be included in responses and PUT requests (Tables 6.3.x-1)")
        lk = b["_links"]
        href = lk.get("self", {}).get("href") if isinstance(lk, dict) and isinstance(lk.get("self"), dict) else None
        if not isinstance(href, str) or urllib.parse.urlsplit(href).path != self_path:
            raise Bad(400, "_links.self.href does not identify this subscription")
    if "expiryDeadline" in b:
        v_timestamp(b["expiryDeadline"], "expiryDeadline")
    if kind == "sensor_discovery":
        for key, fn in (("sensorInfo", v_sensor_info), ("geographicalArea", v_area)):
            if key in b:
                if not isinstance(b[key], list):
                    raise Bad(400, f"{key} shall be an array")
                for i, x in enumerate(b[key]):
                    fn(x, f"{key}[{i}]")
    else:
        sl = b.get("sensorIdentifierList")
        if not isinstance(sl, list) or not sl:
            raise Bad(400, "sensorIdentifierList shall be a non-empty array (cardinality 1..N)")
        for i, s in enumerate(sl):
            _nonempty_str(s, f"sensorIdentifierList[{i}]")
    # ---- semantics (422) after syntax (400)
    if "expiryDeadline" in b:
        e = b["expiryDeadline"]
        if e["seconds"] + e["nanoSeconds"] / 1e9 <= NOW():
            raise Bad(422, "expiryDeadline is not in the future")
    if kind != "sensor_discovery":
        known = set(_by_id())
        unknown = [s for s in b["sensorIdentifierList"] if s not in known]
        if unknown:
            raise Bad(422, f"unknown sensor identifier(s) {unknown}")
    return b


def _represent(kind: str, sid: str, b: dict, request) -> tuple[dict, bool]:
    http_o, ws_o = _origin(request)
    rec = {k: copy.deepcopy(v) for k, v in b.items() if k != "_links"}
    w = b.get("websockNotifConfig")
    use_ws = w is not None and (bool(w.get("requestWebsocketUri")) or "callbackReference" not in b)
    if use_ws:
        rec.pop("callbackReference", None)
        rec["websockNotifConfig"] = {"websocketUri": f"{ws_o}{BASE}/notifications/ws/{sid}",
                                     "requestWebsocketUri": True}
    else:
        rec.pop("websockNotifConfig", None)
    rec["_links"] = {"self": {"href": f"{http_o}{BASE}/subscriptions/{kind}/{sid}"}}
    return rec, use_ws


def _kind_or_404(kind: str):
    if kind not in KINDS:
        raise StarletteHTTPException(404)


def _sub_selects(sub: dict, sensor_id: str) -> bool:
    rec = sub["rec"]
    if sub["kind"] == "sensor_discovery":
        r = _by_id().get(sensor_id)
        if r is None:
            return False
        areas = [v_area(a, "") for a in rec.get("geographicalArea", [])]
        return _selects(r["discovery"], rec.get("sensorInfo", []), areas)
    return sensor_id in rec["sensorIdentifierList"]


@api.get(BASE + "/subscriptions/{kind}")
async def subs_list(kind: str, request: Request):
    _kind_or_404(kind)
    _only_params(request, {"sensorIdentifier"})
    want = _id_list(request, required=False)
    http_o, _ = _origin(request)
    items = [s for s in SUBS.values() if s["kind"] == kind]
    if want is not None:
        items = [s for s in items if any(_sub_selects(s, x) for x in want)]
    return _ok({"_links": {"self": {"href": f"{http_o}{BASE}/subscriptions/{kind}"},
                           "subscriptions": [{"href": s["rec"]["_links"]["self"]["href"],
                                              "subscriptionType": KINDS[kind]} for s in items]}})


@api.post(BASE + "/subscriptions/{kind}")
async def subs_create(kind: str, request: Request):
    _kind_or_404(kind)
    b = _validate_sub(kind, await _json_body(request), on_put=False)
    _SEQ[0] += 1
    sid = f"sub-{_SEQ[0]}"                     # one counter for all types, never reused
    rec, use_ws = _represent(kind, sid, b, request)
    SUBS[sid] = {"kind": kind, "rec": rec, "ws": use_ws}
    href = rec["_links"]["self"]["href"]
    if b.get("requestTestNotification") and not use_ws:
        NOTIFY(rec["callbackReference"], {"notificationType": "TestNotification",
                                          "_links": {"subscription": {"href": href}}})
    return JSONResponse(rec, status_code=201, headers={"Location": href})


def _get_sub(kind: str, sid: str) -> dict:
    _kind_or_404(kind)
    s = SUBS.get(sid)
    if s is None or s["kind"] != kind:
        raise Bad(404, f"no {KINDS[kind]} {sid!r}")
    return s


@api.get(BASE + "/subscriptions/{kind}/{sid}")
async def subs_get(kind: str, sid: str, request: Request):
    return _ok(copy.deepcopy(_get_sub(kind, sid)["rec"]))


@api.put(BASE + "/subscriptions/{kind}/{sid}")
async def subs_put(kind: str, sid: str, request: Request):
    s = _get_sub(kind, sid)                    # absence first (PREREG s.1)
    b = _validate_sub(kind, await _json_body(request), on_put=True,
                      self_path=f"{BASE}/subscriptions/{kind}/{sid}")
    rec, use_ws = _represent(kind, sid, b, request)   # "replace" semantics: nothing carried over
    s["rec"], s["ws"] = rec, use_ws
    return _ok(copy.deepcopy(rec))


@api.delete(BASE + "/subscriptions/{kind}/{sid}")
async def subs_delete(kind: str, sid: str):
    _get_sub(kind, sid)
    _drop_sub(sid)
    return Response(status_code=204)


def _drop_sub(sid: str):
    SUBS.pop(sid, None)
    _WS_PENDING.pop(sid, None)


# ----------------------------------------------------------- notifications --
def _deliver(sid: str, body: dict) -> None:
    s = SUBS.get(sid)
    if s is None:
        return
    if s["ws"]:
        ch = _WS.get(sid)
        if ch:
            loop, q = ch
            loop.call_soon_threadsafe(q.put_nowait, copy.deepcopy(body))
        else:
            pend = _WS_PENDING.setdefault(sid, [])
            if len(pend) < _WS_PENDING_MAX:
                pend.append(copy.deepcopy(body))
        return
    NOTIFY(s["rec"]["callbackReference"], body)


def _links_sub(sid):
    return {"subscription": {"href": SUBS[sid]["rec"]["_links"]["self"]["href"]}}


def tick() -> None:
    """Expire subscriptions whose expiryDeadline has passed (ExpiryNotification, clause 6.4.4)."""
    now = NOW()
    for sid, s in list(SUBS.items()):
        e = s["rec"].get("expiryDeadline")
        if e and e["seconds"] + e["nanoSeconds"] / 1e9 <= now:
            _deliver(sid, {"notificationType": "ExpiryNotification", "timeStamp": _ts(now),
                           "_links": _links_sub(sid), "expiryDeadline": copy.deepcopy(e)})
            _drop_sub(sid)


def apply_inventory(new: list[dict]) -> None:
    """Replace the inventory and notify: discovery events (6.4.1), status (6.4.2), data (6.4.3)."""
    global INVENTORY
    tick()
    old_by, new_by = _by_id(INVENTORY), _by_id(new)
    INVENTORY = copy.deepcopy(new)
    ts = _ts()
    for sid, s in list(SUBS.items()):
        rec = s["rec"]
        if s["kind"] == "sensor_discovery":
            infos = rec.get("sensorInfo", [])
            areas = [v_area(a, "") for a in rec.get("geographicalArea", [])]
            sel = lambda r: _selects(r["discovery"], infos, areas)  # noqa: E731
            events = {"NEW_SENSOR": [i for i in new_by if i not in old_by and sel(new_by[i])],
                      "SENSOR_REMOVED": [i for i in old_by if i not in new_by and sel(old_by[i])],
                      "SENSOR_UPDATE": [i for i in new_by if i in old_by
                                        and new_by[i]["discovery"] != old_by[i]["discovery"]
                                        and (sel(new_by[i]) or sel(old_by[i]))]}
            for ev, lst in events.items():
                if lst:
                    src = old_by if ev == "SENSOR_REMOVED" else new_by
                    _deliver(sid, {"notificationType": "SensorDiscoveryEventNotification", "timeStamp": ts,
                                   "sensorDiscoveryEventType": ev,
                                   "sensorDiscoveryInfo": [copy.deepcopy(src[i]["discovery"]) for i in lst],
                                   "_links": _links_sub(sid)})
        else:
            part = "status" if s["kind"] == "sensor_status" else "data"
            changed = [i for i in rec["sensorIdentifierList"]
                       if i in new_by and (i not in old_by or new_by[i][part] != old_by[i][part])]
            if not changed:
                continue
            if part == "status":
                _deliver(sid, {"notificationType": "SensorStatusNotification", "timeStamp": ts,
                               "sensorStatusInfo": [copy.deepcopy(new_by[i]["status"]) for i in changed],
                               "_links": _links_sub(sid)})
            else:
                _deliver(sid, {"notificationType": "SensorDataNotification", "timeStamp": ts,
                               "sensorData": [copy.deepcopy(d) for i in changed for d in new_by[i]["data"]],
                               "_links": _links_sub(sid)})


@api.websocket(BASE + "/notifications/ws/{sid}")
async def ws_endpoint(websocket: WebSocket, sid: str):
    """One JSON text frame per notification. TS 129 122 5.2.5.4 framing NOT implemented/checked."""
    s = SUBS.get(sid)
    if s is None or not s["ws"]:
        await websocket.close(code=1008)
        return
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue()
    _WS[sid] = (asyncio.get_running_loop(), q)
    for b in _WS_PENDING.pop(sid, []):
        q.put_nowait(b)
    recv = asyncio.ensure_future(websocket.receive())
    get = asyncio.ensure_future(q.get())
    try:
        while True:
            done, _ = await asyncio.wait({recv, get}, return_when=asyncio.FIRST_COMPLETED)
            if get in done:
                await websocket.send_text(json.dumps(get.result()))
                get = asyncio.ensure_future(q.get())
            if recv in done:
                if recv.result().get("type") == "websocket.disconnect":
                    break
                recv = asyncio.ensure_future(websocket.receive())   # client acks are ignored
    finally:
        get.cancel()
        recv.cancel()
        if _WS.get(sid, (None, None))[1] is q:
            _WS.pop(sid, None)


# ------------------------------------------------------------------- shim ----
_ACCEPTABLE = {"application/json", "application/*", "*/*"}


def _accepts_json(accept: str | None) -> bool:
    if not accept:
        return True
    return any(part.split(";")[0].strip().lower() in _ACCEPTABLE for part in accept.split(","))


class Shim:
    """Outer ASGI layer: '//' collapse, expiry tick, bearer check (opt-in), 406, title-case headers."""

    _CANON = {b"content-type": b"Content-Type", b"content-length": b"Content-Length",
              b"location": b"Location", b"www-authenticate": b"WWW-Authenticate", b"allow": b"Allow"}

    def __init__(self, inner):
        self.inner = inner

    @staticmethod
    async def _send_problem(send, status, detail, extra=()):
        body = json.dumps(_problem_body(status, detail)).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"Content-Type", b"application/problem+json"),
                                (b"Content-Length", str(len(body)).encode()), *extra]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope.get("type") not in ("http", "websocket"):
            return await self.inner(scope, receive, send)
        path = re.sub(r"/{2,}", "/", scope.get("path", ""))
        if path != scope.get("path"):
            scope = dict(scope, path=path, raw_path=path.encode())
        if scope["type"] == "websocket":
            return await self.inner(scope, receive, send)
        tick()
        hdr = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if path.startswith(BASE + "/") or path == BASE:
            tok = BEARER_TOKEN
            if tok:
                auth = hdr.get("authorization", "")
                if not auth.startswith("Bearer "):
                    return await self._send_problem(send, 401, "a bearer access token is required (clause 7.2)",
                                                    [(b"WWW-Authenticate", b'Bearer realm="sens"')])
                if auth[7:] != tok:
                    return await self._send_problem(
                        send, 401, "the access token is not valid",
                        [(b"WWW-Authenticate", b'Bearer realm="sens", error="invalid_token"')])
            if not _accepts_json(hdr.get("accept")):
                return await self._send_problem(send, 406, "only application/json can be produced")

        async def _send(message):
            if message.get("type") == "http.response.start":
                message = dict(message, headers=[(self._CANON.get(k.lower(), k), v)
                                                 for k, v in message.get("headers", [])])
            await send(message)

        await self.inner(scope, receive, _send)


app = Shim(api)


def _serve(a, port: int) -> None:
    import uvicorn

    def ticker():
        while True:
            time.sleep(1.0)
            try:
                tick()
            except Exception as e:  # noqa: BLE001
                log.warning("tick failed: %s", e)
    threading.Thread(target=ticker, daemon=True).start()
    uvicorn.Server(uvicorn.Config(a, host="127.0.0.1", port=port, log_level="warning")).run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    _serve(app, PORT)
