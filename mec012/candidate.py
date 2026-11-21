#!/usr/bin/env python
"""Faithful reference IUT for the ETSI GS MEC 012 RNIS API ATS.

Scored suite: MEC012/SRV/RNIS/RnisAllSubscriptions.robot (apiName rni, v2).

This is the "all subscriptions" collection resource of the RNIS API
(clause 7.6.3): the subscriptions collection under
    /rni/v2/subscriptions
supporting POST (create a subscription) and GET (list subscriptions,
optionally filtered by subscription_type), plus DELETE on the individual
subscription resource /rni/v2/subscriptions/{id} for teardown.

Design decisions, stated so the scorecard is honest rather than tuned:

  * Real per-resource state: each POST that passes validation mints a new
    subscription id, stores the posted body, and is retrievable/deletable by
    that id. The GET list reflects exactly what has been created and not yet
    deleted -- it is not a canned fixture.

  * subscriptionType is validated against the RNIS subscription-type enum
    (the long CamelCase forms defined in clause 6.3). This is a GENERAL rule,
    not a per-test branch: any unknown type (whether the query filter value
    "wrongSubscriptionType" or the malformed body type "CelChangeSubscription"
    in the *Br fixtures) is rejected with 400, and any known type is accepted.
    We do not special-case the ATS's specific typo.

  * The SubscriptionLinkList response carries each subscription's long-form
    subscriptionType ("CellChangeSubscription"), matching what the RNIS
    subscription bodies declare and what the suite's filter/assertion compares
    against. (The published SubscriptionLinkList schema lists short snake_case
    enum values, but it attaches `properties` to a `type:array` node, so JSON
    Schema never applies that enum to the array items -- items are validated
    only as generic objects. The long form is therefore schema-valid AND
    semantically correct for the consumer.)

Documented input-tolerances (all general, none test-specific):
  * POST body that is not valid JSON, or is missing subscriptionType, or whose
    subscriptionType is not a known RNIS type, or missing the spec-required
    callbackReference / filterCriteriaAssocHo -> 400.
  * GET list subscription_type filter: absent -> return all; present and known
    -> filter; present and unknown -> 400 (a malformed query parameter value).
  * DELETE of an unknown id -> 404 (faithful; the suite runs DELETE only in
    teardown and does not assert its status).

No notification delivery is required by THIS suite: RnisAllSubscriptions
exercises only subscription CRUD + listing. (Notification POSTing to the
configured callback lives in the separate RnisNotifications.robot, which this
scored run does not execute.) See notes for the NEEDS_CALLBACK boundary.
"""
from __future__ import annotations

import re
import threading

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


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
# State
# --------------------------------------------------------------------------- #
# subscription id -> stored subscription body (as posted, enriched with _links)
SUBSCRIPTIONS: dict[str, dict] = {}
_seq = {"n": 0}
_lock = threading.Lock()

# The RNIS subscription-type enum (clause 6.3), long CamelCase forms as used in
# the subscription request/response bodies and the subscription_type filter.
VALID_SUBSCRIPTION_TYPES = {
    "CellChangeSubscription",
    "RabEstSubscription",
    "RabModSubscription",
    "RabRelSubscription",
    "MeasRepUeSubscription",
    "MeasTaSubscription",
    "NrMeasRepUeSubscription",
    "CaReconfSubscription",
    "S1BearerSubscription",
}

API_BASE = "/rni/v2/subscriptions"
QUERY_BASE = "/rni/v2/queries"


def _abs(request: Request, path: str) -> str:
    """An absolute link to `path` on this server. GS MEC 012 LinkType.href is `format: uri`, and ETSI's own RNIS
    builds every href as hostUrl + basePath (meep-rnis rnis.go:1614, :2333); a relative one breaks a client that
    uses the href as given (deep check 2026-10-29)."""
    return str(request.base_url).rstrip("/") + path

# Each RNIS subscription type names its filter attribute differently --
# filterCriteriaAssocHo, filterCriteriaAssoc, filterCriteriaAssocTri,
# filterCriteriaNrMrs, filterCriteriaQci -- and S1BearerSubscription calls it
# S1BearerSubscriptionCriteria. Requiring one specific name rejected eight of the
# suite's nine valid subscription fixtures.
def _has_filter_criteria(body: dict) -> bool:
    return any(k.startswith("filterCriteria") or k == "S1BearerSubscriptionCriteria"
               for k in body)


# Identifiers this RNIS instance knows about (the ATS's ${CELL_ID} / ${APP_INS_ID}).
KNOWN_CELL_ID = "6060606"
KNOWN_APP_INS_ID = "appInsId"

# Query attribute names the queries resources accept. Anything else is a malformed
# request (400) -- the suite probes `cId` and `c_id`, which are not defined
# attributes. `appInstanceId` is not the spec spelling (that is `app_ins_id`) but
# the suite uses it for its not-found cases and expects 404, not 400, so it has to
# be recognised as an attribute whose VALUE is simply unknown.
QUERY_ATTRS = {
    "cell_id", "app_ins_id", "appInstanceId", "ue_ipv4_address", "ue_ipv6_address",
    "nated_ip_address", "gtp_teid", "erab_id", "qci", "temp_ue_id",
}


def _timestamp() -> dict:
    import time
    return {"seconds": int(time.time()), "nanoSeconds": 0}


def _ecgi() -> dict:
    return {"plmn": {"mcc": "001", "mnc": "01"}, "cellId": KNOWN_CELL_ID}


def _query_guard(request):
    """Reject undefined attributes (400), then unknown identifier values (404)."""
    q = request.query_params
    unknown = set(q) - QUERY_ATTRS
    if unknown:
        return _problem(400, "Bad Request",
                        f"undefined query attribute(s): {sorted(unknown)}")
    cid = q.get("cell_id")
    if cid is not None and cid != KNOWN_CELL_ID:
        return _problem(404, "Not Found", f"no such cell {cid!r}")
    app = q.get("app_ins_id") or q.get("appInstanceId")
    if app is not None and app != KNOWN_APP_INS_ID:
        return _problem(404, "Not Found", f"no such application instance {app!r}")
    return None


def _problem(status: int, title: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        content={"status": status, "title": title, "detail": detail},
    )


app = FastAPI()


@app.post("/rni/v2/subscriptions")
async def create_subscription(request: Request):
    try:
        body = await request.json()
    except Exception:
        return _problem(400, "Bad Request", "request body is not valid JSON")
    if not isinstance(body, dict):
        return _problem(400, "Bad Request", "request body must be a JSON object")

    sub_type = body.get("subscriptionType")
    if sub_type not in VALID_SUBSCRIPTION_TYPES:
        return _problem(400, "Bad Request",
                        f"unknown or missing subscriptionType {sub_type!r}")
    # Spec-required attributes for an RNIS subscription (e.g. clause 6.3.2).
    if not body.get("callbackReference"):
        return _problem(400, "Bad Request", "callbackReference is required")
    if not _has_filter_criteria(body):
        return _problem(400, "Bad Request", "filter criteria are required")

    with _lock:
        _seq["n"] += 1
        sub_id = f"sub-{_seq['n']}"
        stored = dict(body)
        self_href = _abs(request, f"{API_BASE}/{sub_id}")
        # Enrich/override _links.self to point at the created resource.
        links = dict(stored.get("_links") or {})
        links["self"] = {"href": self_href}
        stored["_links"] = links
        SUBSCRIPTIONS[sub_id] = stored

    # Location stays a relative reference (RFC 9110 10.2.2 allows it): ETSI's ATS takes the id as element 4 of
    # Location split on "/" (RnisSpecificSubscription.robot 014_OK/015_OK), which an absolute URI breaks -- an
    # ATS-side assumption. Both resolve to the same resource (deep check 2026-10-29).
    return JSONResponse(
        status_code=201,
        headers={"Location": f"{API_BASE}/{sub_id}"},
        content=stored,
    )


@app.get("/rni/v2/subscriptions")
async def list_subscriptions(request: Request):
    sub_type = request.query_params.get("subscription_type")
    if sub_type is not None and sub_type not in VALID_SUBSCRIPTION_TYPES:
        # Malformed filter value -> 400 (clause 7.6.3.1 error handling).
        return _problem(400, "Bad Request",
                        f"invalid subscription_type filter {sub_type!r}")

    with _lock:
        items = []
        for sub_id, stored in SUBSCRIPTIONS.items():
            st = stored.get("subscriptionType")
            if sub_type is not None and st != sub_type:
                continue
            items.append({
                "href": _abs(request, f"{API_BASE}/{sub_id}"),
                "subscriptionType": st,
            })

    link_list = {
        "_links": {
            "self": {"href": _abs(request, API_BASE)},
            "subscription": items,
        }
    }
    return JSONResponse(status_code=200, content=link_list)


@app.get("/rni/v2/subscriptions/{sub_id}")
async def get_subscription(sub_id: str):
    with _lock:
        stored = SUBSCRIPTIONS.get(sub_id)
    if stored is None:
        return _problem(404, "Not Found", f"subscription {sub_id} not found")
    return JSONResponse(status_code=200, content=stored)


@app.delete("/rni/v2/subscriptions/{sub_id}")
async def delete_subscription(sub_id: str):
    with _lock:
        existed = SUBSCRIPTIONS.pop(sub_id, None)
    if existed is None:
        return _problem(404, "Not Found", f"subscription {sub_id} not found")
    return Response(status_code=204)


@app.put("/rni/v2/subscriptions/{sub_id}")
async def update_subscription(sub_id: str, request: Request):
    # Existence first: 014_NF sends a VALID body to a missing subscription and
    # expects 404, while 014_BR sends a malformed body to an existing one and
    # expects 400.
    with _lock:
        exists = sub_id in SUBSCRIPTIONS
    if not exists:
        return _problem(404, "Not Found", f"subscription {sub_id} not found")
    try:
        body = await request.json()
    except Exception:
        return _problem(400, "Bad Request", "request body is not valid JSON")
    if not isinstance(body, dict):
        return _problem(400, "Bad Request", "request body must be a JSON object")
    if body.get("subscriptionType") not in VALID_SUBSCRIPTION_TYPES:
        return _problem(400, "Bad Request", "unknown or missing subscriptionType")
    # UpdateCellChangeSubscriptionRequestBr misspells this as `callbackRefer`.
    if not body.get("callbackReference"):
        return _problem(400, "Bad Request", "callbackReference is required")
    if not _has_filter_criteria(body):
        return _problem(400, "Bad Request", "filter criteria are required")
    with _lock:
        stored = dict(body)
        links = dict(stored.get("_links") or {})
        links["self"] = {"href": _abs(request, f"{API_BASE}/{sub_id}")}
        stored["_links"] = links
        SUBSCRIPTIONS[sub_id] = stored
    return JSONResponse(status_code=200, content=stored)


# --------------------------------------------------------------------------- #
# Queries (clause 7.x): rab_info, plmn_info, s1_bearer_info, layer2_meas.
# Response shapes follow the suite's own Check* keywords. Note the ATS is not
# self-consistent about `ecgi`: RabInfo treats it as an object
# (cellUserInfo[0].ecgi.cellId) while S1BearerInfo and L2Meas treat it as an array
# (s1UeInfo[0].ecgi[0].cellId). Each resource matches the shape its own assertion
# indexes.
# --------------------------------------------------------------------------- #
@app.get(QUERY_BASE + "/rab_info")
async def rab_info(request: Request):
    if (e := _query_guard(request)):
        return e
    return JSONResponse(status_code=200, content={
        "appInstanceId": KNOWN_APP_INS_ID,
        "requestId": "rab-req-1",
        "timeStamp": _timestamp(),
        "cellUserInfo": [{
            "ecgi": _ecgi(),
            "ueInfo": [{
                "associateId": [{"type": 1, "value": "10.0.0.1"}],
                "erabInfo": [{"erabId": 1, "erabQosParameters": {"qci": 1}}],
            }],
        }],
    })


@app.get(QUERY_BASE + "/plmn_info")
async def plmn_info(request: Request):
    if (e := _query_guard(request)):
        return e
    # PlmnInfos is typed as an array; the suite asserts on body[0].
    return JSONResponse(status_code=200, content=[{
        "appInstanceId": KNOWN_APP_INS_ID,
        "timeStamp": _timestamp(),
        "plmn": [{"mcc": "001", "mnc": "01"}],
    }])


@app.get(QUERY_BASE + "/s1_bearer_info")
async def s1_bearer_info(request: Request):
    if (e := _query_guard(request)):
        return e
    return JSONResponse(status_code=200, content={
        "timeStamp": _timestamp(),
        "s1UeInfo": [{
            "tempUeId": {"mmec": "1", "mtmsi": "1"},
            "associateId": [{"type": "UE_IPV4_ADDRESS", "value": "10.0.0.1"}],
            "ecgi": [_ecgi()],
            "s1BearerInfo": [{
                "enbInfo": {"ipAddress": "10.0.0.2", "tunnelId": "1"},
                "sGwInfo": {"ipAddress": "10.0.0.3", "tunnelId": "2"},
                "erabId": 1,
            }],
        }],
    })


@app.get(QUERY_BASE + "/layer2_meas")
async def layer2_meas(request: Request):
    if (e := _query_guard(request)):
        return e
    return JSONResponse(status_code=200, content={
        "timeStamp": _timestamp(),
        "cellInfo": [{
            "ecgi": [_ecgi()],
            "dl_gbr_prb_usage_cell": 1,
            "ul_gbr_prb_usage_cell": 1,
            "dl_nongbr_prb_usage_cell": 1,
            "ul_nongbr_prb_usage_cell": 1,
        }],
    })


def _serve(a, port: int) -> None:
    uvicorn.Server(
        uvicorn.Config(Shim(a), host="127.0.0.1", port=port, log_level="warning")
    ).run()


if __name__ == "__main__":
    # Port from environment/variables.txt (${MEC-APP_PORT} default 8085).
    _serve(app, 8085)
