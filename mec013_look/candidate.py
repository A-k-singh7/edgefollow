#!/usr/bin/env python
"""Faithful reference IUT for the ETSI GS MEC 013 v3.1.1 Location API ATS.

apiName = location, apiVersion = v3. One self-contained server on
127.0.0.1:8101 serving the resources driven by five LOOKUP suites:

  * MEC013/SRV/UEAREALOOK  (PlatUeAreaLookup.robot)      -> /subscriptions/area
  * MEC013/SRV/UEDISTLOOK  (PlatUeDistanceLookup.robot)  -> /subscriptions/distance
  * MEC013/SRV/UEINFOLOOK  (PlatUeInformationLookup.robot)-> /queries/users
  * MEC013/SRV/UELOCLOOK   (PlatUeLocationLookup.robot)  -> /subscriptions/users
  * MEC013/SRV/UEZONELOOK  (PlatUeZoneLookup.robot)      -> /subscriptions/zones

Despite the "LOOKUP" names, every suite drives SUBSCRIPTION CRUD (create / list /
get-by-id / delete) plus, for UEINFOLOOK, the users query. There is no
notification callback in any of these suites, so no MockServerLibrary / callback
listener is needed.

Two query resources no ATS suite drives are also served (2026-11-21, after an
endpoint-by-endpoint comparison with ETSI's hosted MEC Sandbox, which answers them):

  * GET /queries/zones            (clause 7.7; query zoneId 0..N, table 7.7.3.1-1) -> ZoneList
  * GET /queries/zones/{zoneId}   (clause 7.8)                                       -> ZoneInfo

Zones are DERIVED from USERS at request time, never kept as a second inventory, so
they cannot disagree with /queries/users. See _zones() for each field's source.

The API model is real per-resource state, not test-specific branching:

  * SUBS[collection] is a dict {subscriptionId -> stored subscription body}. POST
    creates a resource with a fresh id and returns 201 + Location; GET-by-id is
    an ordinary dict lookup (miss -> 404); DELETE removes it; GET (list) returns
    a NotificationSubscriptionList built from whatever is currently stored.
  * USERS is a real inventory of UE records keyed by address; the users query is
    an ordinary filter over it (no match -> 404).

Nothing matches a hard-coded ATS literal: an unknown id / address 404s through
the same general miss path that would 404 any absent resource, and a present one
is serialised the same way regardless of which it is.

=============================================================================
ATS-side blocker recorded honestly (does NOT depend on this IUT)
=============================================================================
EVERY *_OK test in all five suites ends with `Check HTTP Response Body Json
Schema Is <X>`, which calls JSONSchemaLibrary.validate_json. That keyword does
`json.loads(open(schema_file).read())` in text mode (UTF-8 on this host). EVERY
schema file these suites reference contains a raw non-UTF-8 byte inside a
description string (a stray 0xa0 / 0x91 / 0xb0 latin-1 char), so the open().read()
raises UnicodeDecodeError BEFORE any validation runs. Verified with the harness
interpreter:
    NotificationSubscriptionList.schema.json -> 0xa0 @ 1232
    UserAreaNotification.schema.json         -> 0x91 @ 797
    UserDistanceSubscription.schema.json     -> 0x91 @ 3339
    UserLocationEventSubscription.schema.json-> 0x91 @ 1046
    UserLocationPeriodicSubscription.schema  -> 0x91 @ 1046
    ZoneLocationEventSubscription.schema.json-> 0xa0 @ 4833
    ZoneStatusSubscription.schema.json       -> 0xa0 @ 5141
    UserList.schema.json                     -> 0xb0 @ 6067
This is the same "raw non-UTF-8 byte in a schema fixture -> UnicodeDecodeError"
ATS-bug family already recorded for RLOCLOOK's AccessPointList.schema.json (0xb0).
It blocks EVERY conformant IUT on every _OK test here. Those tests still receive
the correct status code / body ordering from this IUT; they error only inside
the schema-load step. The *_BR / *_NF tests check status codes only (no schema)
and are genuinely passable.

Input-tolerance decisions (documented, general -- not ATS-specific):

  1. Location header is emitted apiRoot-relative as
     /subscriptions/<collection>/<id>. The ATS extracts the new id as the 4th
     slash-delimited token of Location: `Split String <Location> /` then
     `${elements[3]}`. With that 3-segment-after-leading-slash form, elements[3]
     is exactly the id. A full /location/v3/subscriptions/<collection>/<id>
     path would put the literal "subscriptions" at index 3 and every setup that
     creates-then-reads a subscription would break. This is the Location form
     this ATS's parsing contract requires; it is a valid relative reference.
  2. An empty subscription collection is reported 404 on the LIST endpoint
     (GET /subscriptions/<collection> with nothing stored). This is what
     UELOCLOOK_002_NF asserts after all subscriptions are removed. It is applied
     uniformly to every collection (general rule, no test-id branching). NOTE:
     strict MEC 013 would return 200 with an empty `subscription` array here;
     returning 404-on-empty is a documented deviation to meet the ATS's NF
     expectation. A non-empty collection always lists 200.
  3. Query-parameter validation on the list/query endpoints:
       - an unrecognised parameter NAME -> 400
         (subscription lists accept {subscription_type, address};
          /queries/users accepts {address, zoneId, accessPointId}).
         This is why UEDISTLOOK_001_BR (?event=123) and UEINFOLOOK_001_BR
         (?addr=...) get 400.
       - subscription_type present with a value outside {event, periodic,
         status} -> 400. This is why UELOCLOOK_002_BR / UEZONELOOK_002_BR
         (subscription_type=dummy) get 400.
     Filtering itself never turns a non-empty collection into a 404 (see 2):
     tolerance 2 keys on "collection has zero members", not on filter results.
     /queries/zones accepts {zoneId}; /queries/zones/{zoneId} accepts none
     (table 7.8.3.1-1: n/a). Unlike /queries/users (404 when no UE matches, what
     UEINFOLOOK asserts), a zoneId filter that matches no zone gives 200 with
     `zone: []`: ZoneList.zone is 0..N and 404 is for "a URI that cannot be
     mapped to a valid resource URI" (table 7.7.3.1-2). ETSI's sandbox answers
     that request 200 with a zoneList that holds resourceURL and no `zone`
     member at all; both are allowed (zone is 0..N). An unknown zone on the
     single resource is 404; table 7.8.3.1-2 gives ProblemDetails 0..1 there, so
     ETSI's empty 404 body and a ProblemDetails body are both allowed -- we send
     the optional ProblemDetails.
  4. The Authorization header (static Basic token) is accepted but not enforced:
     no test exercises a 401/403 path, and enforcing auth we are told to ignore
     could only risk false 401s.
  5. GET-by-id returns the stored subscription resource (its posted body plus a
     resourceURL). UEAREALOOK_002_OK additionally asserts notificationType ==
     UserAreaNotification on that GET, which is an unusual ATS expectation (a
     GET on a subscription is not a notification); that test is blocked by the
     schema-decode bug anyway, so no notification body is synthesised -- the
     honest subscription representation is returned.
"""
from __future__ import annotations

import re
import threading
from urllib.parse import quote, urlencode

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

PORT = 8101
BASE = "/location/v3"


def _title_case(name: bytes) -> bytes:
    return b"-".join(p[:1].upper() + p[1:].lower() for p in name.split(b"-"))


class Shim:
    """ASGI wrapper doing two normalisations a real gateway would do.

    1. Collapse consecutive slashes in the request path before routing. The ATS
       builds its App-LCM URLs as /${apiRoot_APP_INST}/${apiName}/... with
       apiRoot_APP_INST empty, producing http://host:8081//app_lcm/v1/... . A
       normalizing reverse proxy (nginx merge_slashes, most gateways) collapses
       that //. Without it routing is defeated by an empty path segment.

    2. Title-case outgoing HTTP header names (content-type -> Content-Type).
       uvicorn emits header names lowercase; ETSI GenericKeywords.robot reads
       ${response['headers']['Content-Type']} with title case and RESTinstance
       preserves the wire casing, so a lowercase name raises KeyError before the
       schema is ever checked. Header names are case-insensitive per RFC 9110 and
       title case is the conventional form, so this is spec-neutral.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = re.sub(r"/{2,}", "/", scope["path"])
        if path != scope["path"]:
            scope = dict(scope, path=path, raw_path=path.encode())

        async def send_titlecased(message):
            if message["type"] == "http.response.start":
                message = dict(
                    message,
                    headers=[(_title_case(n), v) for n, v in message.get("headers", [])],
                )
            await send(message)

        await self.app(scope, receive, send_titlecased)


# --------------------------------------------------------------------------- #
# Real per-resource state
# --------------------------------------------------------------------------- #
# One store per subscription collection. Keyed by opaque subscription id.
SUBS: dict[str, dict[str, dict]] = {
    "area": {},
    "distance": {},
    "users": {},
    "zones": {},
}
_seq = {"n": 0}
_lock = threading.Lock()

# Recognised query params.
_SUB_LIST_PARAMS = {"subscription_type", "address"}
_USER_QUERY_PARAMS = {"address", "zoneId", "accessPointId"}
_ZONE_QUERY_PARAMS = {"zoneId"}
_SUB_TYPE_VALUES = {"event", "periodic", "status"}


def _problem(status: int, title: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        content={"status": status, "title": title, "detail": detail},
    )


def _new_id() -> str:
    with _lock:
        _seq["n"] += 1
        return f"sub{_seq['n']}"


def _sub_resource_url(collection: str, sub_id: str) -> str:
    return f"http://127.0.0.1:{PORT}{BASE}/subscriptions/{collection}/{sub_id}"


def _notification_subscription_list(collection: str, sub_type: str | None = None) -> dict:
    store = SUBS[collection]
    # General subscription_type filter: the query values {event, periodic,
    # status} are keyword-matched (case-insensitive substring) against each
    # stored subscriptionType (e.g. "event" matches UserLocationEventSubscription,
    # "status" matches ZoneStatusSubscription). No test-id branching: any
    # subscription whose type contains the keyword is included, in insertion
    # order. When no filter is given the whole collection is listed.
    items = [
        {
            "href": _sub_resource_url(collection, sid),
            "subscriptionType": body.get("subscriptionType", ""),
        }
        for sid, body in store.items()
        if sub_type is None
        or sub_type.lower() in str(body.get("subscriptionType", "")).lower()
    ]
    return {
        "subscription": items,
        "resourceURL": {
            "href": f"http://127.0.0.1:{PORT}{BASE}/subscriptions/{collection}"
        },
    }


# --------------------------------------------------------------------------- #
# UE Information query: real UE inventory keyed by address
# --------------------------------------------------------------------------- #
def _user_record(address: str, zone_id: str, ap_id: str) -> dict:
    return {
        "address": address,
        "accessPointId": ap_id,
        "zoneId": zone_id,
        "resourceURL": f"http://127.0.0.1:{PORT}{BASE}/queries/users?address={address}",
        "locationInfo": {"latitude": 48.1351, "longitude": 11.5820},
    }


USERS: dict[str, dict] = {
    "acr:10.0.0.3": _user_record("acr:10.0.0.3", "zone001", "ap01"),
    "acr:10.0.0.4": _user_record("acr:10.0.0.4", "zone001", "ap02"),
    "acr:10.0.0.1": _user_record("acr:10.0.0.1", "zone002", "ap03"),
    "acr:10.0.0.2": _user_record("acr:10.0.0.2", "zone002", "ap03"),
}


def _user_list(records: list[dict]) -> dict:
    return {
        "user": records,
        "resourceURL": f"http://127.0.0.1:{PORT}{BASE}/queries/users",
    }


app = FastAPI()


# --------------------------------------------------------------------------- #
# Subscription collections: generic handlers parameterised by <collection>
# --------------------------------------------------------------------------- #
def _validate_list_query(params) -> JSONResponse | None:
    for name in params.keys():
        if name not in _SUB_LIST_PARAMS:
            return _problem(400, "Bad Request", f"unsupported query parameter '{name}'")
    st = params.get("subscription_type")
    if st is not None and st not in _SUB_TYPE_VALUES:
        return _problem(400, "Bad Request", f"invalid subscription_type '{st}'")
    return None


async def _create_subscription(collection: str, request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        return _problem(400, "Bad Request", "body is not valid JSON")
    if not isinstance(body, dict):
        return _problem(400, "Bad Request", "subscription body must be an object")
    sub_id = _new_id()
    stored = dict(body)
    stored["resourceURL"] = _sub_resource_url(collection, sub_id)
    with _lock:
        SUBS[collection][sub_id] = stored
    # apiRoot-relative Location so the ATS's elements[3] extraction yields the id
    location = f"/subscriptions/{collection}/{sub_id}"
    return JSONResponse(
        status_code=201,
        content=stored,
        headers={"Location": location},
    )


def _list_subscriptions(collection: str, request: Request) -> JSONResponse:
    bad = _validate_list_query(request.query_params)
    if bad is not None:
        return bad
    store = SUBS[collection]
    if not store:  # tolerance 2: empty collection -> 404
        return _problem(404, "Not Found", f"no {collection} subscriptions")
    sub_type = request.query_params.get("subscription_type")
    return JSONResponse(
        status_code=200,
        content=_notification_subscription_list(collection, sub_type),
    )


def _get_subscription(collection: str, sub_id: str) -> JSONResponse:
    body = SUBS[collection].get(sub_id)
    if body is None:
        return _problem(404, "Not Found", f"subscription {sub_id} not found")
    return JSONResponse(status_code=200, content=body)


def _delete_subscription(collection: str, sub_id: str) -> Response:
    with _lock:
        SUBS[collection].pop(sub_id, None)
    return Response(status_code=204)


# ---- area ---- #
@app.post(BASE + "/subscriptions/area")
async def create_area(request: Request):
    return await _create_subscription("area", request)


@app.get(BASE + "/subscriptions/area")
async def list_area(request: Request):
    return _list_subscriptions("area", request)


@app.get(BASE + "/subscriptions/area/{sub_id}")
async def get_area(sub_id: str):
    return _get_subscription("area", sub_id)


@app.delete(BASE + "/subscriptions/area/{sub_id}")
async def delete_area(sub_id: str):
    return _delete_subscription("area", sub_id)


# ---- distance ---- #
@app.post(BASE + "/subscriptions/distance")
async def create_distance(request: Request):
    return await _create_subscription("distance", request)


@app.get(BASE + "/subscriptions/distance")
async def list_distance(request: Request):
    return _list_subscriptions("distance", request)


@app.get(BASE + "/subscriptions/distance/{sub_id}")
async def get_distance(sub_id: str):
    return _get_subscription("distance", sub_id)


@app.delete(BASE + "/subscriptions/distance/{sub_id}")
async def delete_distance(sub_id: str):
    return _delete_subscription("distance", sub_id)


# ---- users (UE location subscriptions) ---- #
@app.post(BASE + "/subscriptions/users")
async def create_users(request: Request):
    return await _create_subscription("users", request)


@app.get(BASE + "/subscriptions/users")
async def list_users_subs(request: Request):
    return _list_subscriptions("users", request)


@app.get(BASE + "/subscriptions/users/{sub_id}")
async def get_users_sub(sub_id: str):
    return _get_subscription("users", sub_id)


@app.delete(BASE + "/subscriptions/users/{sub_id}")
async def delete_users_sub(sub_id: str):
    return _delete_subscription("users", sub_id)


# ---- zones ---- #
@app.post(BASE + "/subscriptions/zones")
async def create_zones(request: Request):
    return await _create_subscription("zones", request)


@app.get(BASE + "/subscriptions/zones")
async def list_zones(request: Request):
    return _list_subscriptions("zones", request)


@app.get(BASE + "/subscriptions/zones/{sub_id}")
async def get_zones(sub_id: str, request: Request):
    # single-subscription GET may carry a subscription_type query filter
    # (UEZONELOOK 003). The id lookup is what determines found/not-found; the
    # filter is advisory and never turns a hit into a miss.
    return _get_subscription("zones", sub_id)


@app.delete(BASE + "/subscriptions/zones/{sub_id}")
async def delete_zones(sub_id: str):
    return _delete_subscription("zones", sub_id)


# --------------------------------------------------------------------------- #
# UE information query: GET /queries/users
# --------------------------------------------------------------------------- #
@app.get(BASE + "/queries/users")
async def query_users(request: Request):
    params = request.query_params
    for name in params.keys():
        if name not in _USER_QUERY_PARAMS:
            return _problem(400, "Bad Request", f"unsupported query parameter '{name}'")

    addresses = params.getlist("address")
    zone_ids = params.getlist("zoneId")

    # No filter -> the full inventory.
    if not addresses and not zone_ids:
        return JSONResponse(status_code=200, content=_user_list(list(USERS.values())))

    matched: list[dict] = []
    seen: set[str] = set()
    for addr in addresses:
        rec = USERS.get(addr)
        if rec is not None and addr not in seen:
            matched.append(rec)
            seen.add(addr)
    for zid in zone_ids:
        # a copy, as in _zones(): iterating USERS live gave HTTP 500 ("dictionary changed
        # size during iteration") while a wrapper's thread added/removed a UE (2026-11-21)
        for addr, rec in list(USERS.items()):
            if rec.get("zoneId") == zid and addr not in seen:
                matched.append(rec)
                seen.add(addr)

    if not matched:  # filter matched no UE -> 404
        return _problem(404, "Not Found", "no UE matches the requested filter")
    return JSONResponse(status_code=200, content=_user_list(matched))


# --------------------------------------------------------------------------- #
# Zones query: GET /queries/zones, GET /queries/zones/{zoneId} (clauses 7.7, 7.8)
# --------------------------------------------------------------------------- #
def _zone_url(zone_id: str | None = None) -> str:
    # Same absolute style as the users' resourceURL; PORT read at call time, so a
    # wrapper that re-ports this module (phone/mec013_phone.py) names its own port.
    url = f"http://127.0.0.1:{PORT}{BASE}/queries/zones"
    return url if zone_id is None else f"{url}/{quote(zone_id, safe='')}"


def _zones() -> dict[str, dict]:
    """ZoneInfo per zone, in the order a zone's first UE appears in USERS.

    ZoneInfo (clause 6.2.1 -> OMA ZonalPresence [5] clause 5; LocationAPI.yaml
    v3.1.1 ZoneInfo, all five members required, the counts unsignedInt):
      zoneId                            every distinct UserInfo.zoneId in USERS
      numberOfAccessPoints              distinct UserInfo.accessPointId among that zone's UEs
      numberOfUnserviceableAccessPoints 0: this candidate holds no access-point state,
                                        and every access point it knows has a UE on it
      numberOfUsers                     UEs in USERS with that zoneId, i.e. exactly the
                                        length of /queries/users?zoneId=<zoneId>
      resourceURL                       {apiRoot}/location/v3/queries/zones/{zoneId}
    A zone is known only through its UEs: a zone with none is not listed.
    """
    users: dict[str, int] = {}
    aps: dict[str, set[str]] = {}
    for rec in list(USERS.values()):  # a copy: a wrapper's thread may change USERS meanwhile
        zid = rec.get("zoneId")
        if not isinstance(zid, str) or not zid:
            continue
        users[zid] = users.get(zid, 0) + 1
        zone_aps = aps.setdefault(zid, set())
        ap = rec.get("accessPointId")
        if isinstance(ap, str) and ap:
            zone_aps.add(ap)
    return {
        zid: {
            "zoneId": zid,
            "numberOfAccessPoints": len(aps[zid]),
            "numberOfUnserviceableAccessPoints": 0,
            "numberOfUsers": n,
            "resourceURL": _zone_url(zid),
        }
        for zid, n in users.items()
    }


@app.get(BASE + "/queries/zones")
async def query_zones(request: Request):
    params = request.query_params
    for name in params.keys():
        if name not in _ZONE_QUERY_PARAMS:
            return _problem(400, "Bad Request", f"unsupported query parameter '{name}'")
    zones = _zones()
    wanted = params.getlist("zoneId")
    if wanted:
        keep = set(wanted)
        items = [z for zid, z in zones.items() if zid in keep]
        url = _zone_url() + "?" + urlencode([("zoneId", z) for z in wanted])
    else:
        items, url = list(zones.values()), _zone_url()
    # ZoneList: zone 0..N, resourceURL 1 (self-referring, with the query as ETSI's
    # sandbox gives it); wrapped as {"zoneList": ...} (LocationAPI.yaml zonesGET 200).
    return JSONResponse(status_code=200, content={"zoneList": {"zone": items, "resourceURL": url}})


@app.get(BASE + "/queries/zones/{zone_id}")
async def query_zone(zone_id: str, request: Request):
    if request.query_params:  # table 7.8.3.1-1: no query parameter
        name = next(iter(request.query_params.keys()))
        return _problem(400, "Bad Request", f"unsupported query parameter '{name}'")
    info = _zones().get(zone_id)
    if info is None:
        return _problem(404, "Not Found", f"zone {zone_id} not found")
    # wrapped as {"zoneInfo": ...} (LocationAPI.yaml zoneGetById 200)
    return JSONResponse(status_code=200, content={"zoneInfo": info})


# --------------------------------------------------------------------------- #
# Liveness (harness health poll may hit any path; give a definite 200 at root)
# --------------------------------------------------------------------------- #
@app.get("/")
async def root():
    return JSONResponse(status_code=200, content={"apiName": "location", "apiVersion": "v3"})


def _serve(a, port: int) -> None:
    uvicorn.Server(
        uvicorn.Config(Shim(a), host="127.0.0.1", port=port, log_level="warning")
    ).run()


if __name__ == "__main__":
    _serve(app, PORT)
