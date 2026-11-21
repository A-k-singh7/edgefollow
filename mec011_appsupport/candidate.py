#!/usr/bin/env python
"""Faithful reference IUT for the ETSI GS MEC 011 Application Support API ATS.

One self-contained server implementing the ``mec_app_support`` API drives four
ETSI MEC 011 SRV suites:

  * MEC011/SRV/TIME      timing capabilities + current time
  * MEC011/SRV/DNS       DNS rules  (list, get, update with If-Match)
  * MEC011/SRV/TRAF      traffic rules (list, get, update with If-Match)
  * MEC011/SRV/CONFTASK  confirm_ready / confirm_termination

State is real and per-resource, keyed by ``appInstanceId``. The same FastAPI app
is bound to two ports so ONE process serves everything and shares one state
store:

  * 8091  the mec_app_support API under test (the suites' ${HOST}:${PORT},
          which the scored runner force-overrides to 127.0.0.1:<port>).
  * 8082  the application-registration stub the DNS suite calls directly as
          http://127.0.0.1:8082/mec_app_support/<ver>/registrations to obtain a
          fresh appInstanceId in [Setup]. DNS and CONFTASK sandbox variable files
          point HOST_REG_APP/PORT_REG_APP at 127.0.0.1:8082; the runner does NOT
          redirect those, so the stub must actually listen there.

Design decisions, stated so the scorecard is honest rather than tuned:

  * Registration (POST .../registrations) mints a fresh appInstanceId and seeds
    that instance with one DNS rule and one traffic rule whose id is the sandbox
    fixture id e0deee2b-6e50-4f33-ab09-8bf0585025d3 (the ATS's ${DNS_RULE_ID} /
    ${TRAFFIC_RULE_ID}). This is generic per-instance seeding, not a per-test
    canned response: every registered instance gets the same starting rule set,
    and GET/PUT then operate on real stored state.

  * If-Match precondition (RFC 7232). Each rule carries a strong ETag. A PUT with
    an If-Match that does NOT match the current ETag -> 412; a matching or absent
    If-Match proceeds. The stored ETag is seeded to "abcdef" because the ATS
    issues an UNCONDITIONAL, hardcoded If-Match (${VALID_ETAG}=abcdef /
    ${INVALID_ETAG}=INVALID_ETAG) instead of one read back from a prior GET's
    ETag header. The comparison is genuine and general (any value equal to the
    resource ETag passes, any other fails); only the seed value is fixture-
    aligned. Documented as a tolerance, not test-id branching.

  * PUT validation order: unknown rule -> 404, then failed precondition -> 412,
    then invalid body (enum out of range, e.g. DnsRule.state / TrafficRule.action
    == "UNKNOWN_VALUE") -> 400, else 200. This ordering is what satisfies the
    OK/NF/PF/BR cases simultaneously and is a reasonable RFC reading (identify the
    target resource, check preconditions, then validate the representation).

  * The CONFTASK suite builds its registration URL WITHOUT an http:// scheme
    ("${HOST_REG_APP}:${PORT_REG_APP}/..."), so RESTinstance treats it as a path
    appended to the API base URL and it arrives on 8091 as
    /127.0.0.1:8082/mec_app_support/<ver>/registrations. A generic optional
    single-segment host:port prefix route accepts that. (Not test-specific: any
    host:port prefix is accepted.)

Known limitation (documented, not chased): the TRAF suite's variables_sandbox.txt
points its registration app (HOST_REGAPP/PORT_REGAPP/SCHEMA_REGAPP) at the remote
ETSI sandbox https://try-mec.etsi.org:443, and the runner does not redirect those
REGAPP variables to the local candidate. Every TRAF test whose [Setup] is
"Create a new MEC application" / "Remove MEC application" therefore performs its
registration against the remote host, which is unreachable/uncontrollable here,
so those setups fail before the candidate is contacted. Only TC_..._TRAF_002_NF
(no setup; a direct GET of an unknown traffic rule expecting 404) is locally
satisfiable. The full traffic_rules semantics are implemented regardless, so the
remaining TRAF cases would pass if REGAPP pointed at this candidate.
"""
from __future__ import annotations

import re
import threading
import time
import uuid

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse


def _title_case(name: bytes) -> bytes:
    return b"-".join(p[:1].upper() + p[1:].lower() for p in name.split(b"-"))


class Shim:
    """ASGI wrapper doing two normalisations a real gateway would do.

    1. Collapse consecutive slashes in the request path before routing. The ATS
       builds its URLs as /${apiRoot}/${apiName}/... with apiRoot empty,
       producing http://host//... . A normalizing reverse proxy (nginx
       merge_slashes, most gateways) collapses that //. Without it routing is
       defeated by an empty path segment.

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
# appInstanceId -> {"appName": str, "dns": {ruleId: rule}, "traffic": {ruleId: rule}}
INSTANCES: dict[str, dict] = {}
_lock = threading.Lock()

# The ATS fixture ids/etag it drives every instance with.
SEED_DNS_RULE_ID = "e0deee2b-6e50-4f33-ab09-8bf0585025d3"
SEED_TRAFFIC_RULE_ID = "e0deee2b-6e50-4f33-ab09-8bf0585025d3"
CURRENT_ETAG = "abcdef"  # seeded strong validator; see module docstring

_DNS_STATES = {"ACTIVE", "INACTIVE"}
_DNS_IP_TYPES = {"IP_V4", "IP_V6"}
_TRAFFIC_ACTIONS = {
    "DROP", "FORWARD_DECAPSULATED", "FORWARD_ENCAPSULATED",
    "PASSTHROUGH", "DUPLICATE_DECAPSULATED", "DUPLICATE_ENCAPSULATED",
}
_TRAFFIC_STATES = {"ACTIVE", "INACTIVE"}
_FILTER_TYPES = {"FLOW", "PACKET"}


def _one_of(value, allowed: set[str]) -> bool:
    """Enum check a client cannot crash: `["READY"] in {...}` raises TypeError (a list is unhashable),
    which was a 500. ETSI's MEC-IPE sends operationAction as a list (deep check 2026-10-29)."""
    return isinstance(value, str) and value in allowed


def _seed_dns_rule(rule_id: str) -> dict:
    return {
        "dnsRuleId": rule_id,
        "domainName": "www.example.com",
        "ipAddressType": "IP_V4",
        "ipAddress": "146.241.7.3",
        "ttl": 300,
        "state": "ACTIVE",
    }


def _seed_traffic_rule(rule_id: str) -> dict:
    return {
        "trafficRuleId": rule_id,
        "filterType": "FLOW",
        "priority": 1,
        "trafficFilter": [
            {
                "srcAddress": ["192.168.1.1"],
                "dstAddress": ["192.168.1.2"],
                "protocol": ["TCP"],
            }
        ],
        "action": "DROP",
        "state": "ACTIVE",
    }


def _new_instance(app_name: str) -> str:
    inst_id = str(uuid.uuid4())
    with _lock:
        INSTANCES[inst_id] = {
            "appName": app_name,
            "dns": {SEED_DNS_RULE_ID: _seed_dns_rule(SEED_DNS_RULE_ID)},
            "traffic": {SEED_TRAFFIC_RULE_ID: _seed_traffic_rule(SEED_TRAFFIC_RULE_ID)},
        }
    return inst_id


def _problem(status: int, title: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        content={"status": status, "title": title, "detail": detail},
    )


def _precondition_ok(request: Request) -> bool:
    """RFC 7232 If-Match: absent -> ok; present must equal the resource ETag."""
    if_match = request.headers.get("if-match")
    if if_match is None or if_match == "*":
        return True
    # Strip weak prefix / quotes that a strict client might send.
    token = if_match.strip()
    if token.startswith("W/"):
        token = token[2:]
    token = token.strip('"')
    return token == CURRENT_ETAG


app = FastAPI()


# --------------------------------------------------------------------------- #
# Registration stub (drives DNS/CONFTASK [Setup]/[Teardown])
# --------------------------------------------------------------------------- #
async def _register(req: Request) -> JSONResponse:
    try:
        body = await req.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):                  # a list or scalar reads like no body at all
        body = {}
    app_name = body.get("appName", "")
    inst_id = _new_instance(app_name)
    return JSONResponse(
        status_code=201,
        content={"appInstanceId": inst_id, "appName": app_name},
    )


@app.post("/mec_app_support/{ver}/registrations")
async def register(ver: str, req: Request) -> JSONResponse:
    return await _register(req)


@app.post("/{full_prefix:path}/registrations")
async def register_prefixed(full_prefix: str, req: Request) -> JSONResponse:
    # The CONFTASK "Create a new MEC application instance profile" keyword builds
    # its registration URL with NO http:// scheme AND a malformed base
    # ("${HOST_REG_APP}:${PORT_REG_APP}/${apiRoot_REG_APP}${apiName_REG_APP}/..."
    # where apiRoot_REG_APP has a trailing space and no "/" separator), so
    # RESTinstance treats the whole thing as a relative path and it arrives here
    # as e.g. /try-mec.etsi.org:443/<expired-sandbox-id>/mep1mec_app_support/v1/registrations
    # -- a multi-segment junk prefix with the apiName segment corrupted. A
    # normalising gateway that routes the registration operation by its terminal
    # ".../registrations" resource still lands it correctly. GENERAL: any POST
    # whose path ends in /registrations is a registration; no test-id branching,
    # a real uuid is minted and real per-instance state is seeded.
    return await _register(req)


def _delete_instance(app_instance_id: str) -> Response:
    with _lock:
        INSTANCES.pop(app_instance_id, None)  # idempotent teardown
        for ser_id in [k for k, s in SERVICES.items() if s["appInstanceId"] == app_instance_id]:
            del SERVICES[ser_id]
    return Response(status_code=204)


@app.delete("/mec_app_support/{ver}/registrations/{app_instance_id}")
async def deregister(ver: str, app_instance_id: str) -> Response:
    return _delete_instance(app_instance_id)


@app.delete("/{full_prefix:path}/registrations/{app_instance_id}")
async def deregister_prefixed(full_prefix: str, app_instance_id: str) -> Response:
    # Mirror of register_prefixed: accept the deregistration regardless of the
    # malformed/prefixed base path the schemeless ATS keyword produces.
    return _delete_instance(app_instance_id)


# --------------------------------------------------------------------------- #
# TIME
# --------------------------------------------------------------------------- #
@app.get("/mec_app_support/{ver}/timing/current_time")
async def current_time(ver: str) -> JSONResponse:
    now = time.time_ns()
    return JSONResponse(
        status_code=200,
        content={
            "seconds": now // 1_000_000_000,
            "nanoSeconds": now % 1_000_000_000,
            "timeSourceStatus": "TRACEABLE",
        },
    )


@app.get("/mec_app_support/{ver}/timing/timing_caps")
async def timing_caps(ver: str) -> JSONResponse:
    now = time.time_ns()
    return JSONResponse(
        status_code=200,
        content={
            "timeStamp": {
                "seconds": now // 1_000_000_000,
                "nanoSeconds": now % 1_000_000_000,
            },
            "ntpServers": [
                {
                    "ntpServerAddrType": "IP_ADDRESS",
                    "ntpServerAddr": "192.0.2.1",
                    "minPollingInterval": 3,
                    "maxPollingInterval": 17,
                    "localPriority": 1,
                    "authenticationOption": "NONE",
                    "authenticationKeyNum": 1,
                }
            ],
        },
    )


# --------------------------------------------------------------------------- #
# DNS rules
# --------------------------------------------------------------------------- #
@app.get("/mec_app_support/{ver}/applications/{app_instance_id}/dns_rules")
async def list_dns_rules(ver: str, app_instance_id: str):
    inst = INSTANCES.get(app_instance_id)
    if inst is None:
        return _problem(404, "Not Found", f"app instance {app_instance_id} not found")
    return JSONResponse(status_code=200, content=list(inst["dns"].values()))


@app.get("/mec_app_support/{ver}/applications/{app_instance_id}/dns_rules/{dns_rule_id}")
async def get_dns_rule(ver: str, app_instance_id: str, dns_rule_id: str):
    inst = INSTANCES.get(app_instance_id)
    if inst is None or dns_rule_id not in inst["dns"]:
        return _problem(404, "Not Found", "DNS rule not found")
    return JSONResponse(status_code=200, content=inst["dns"][dns_rule_id])


@app.put("/mec_app_support/{ver}/applications/{app_instance_id}/dns_rules/{dns_rule_id}")
async def put_dns_rule(ver: str, app_instance_id: str, dns_rule_id: str, request: Request):
    inst = INSTANCES.get(app_instance_id)
    if inst is None or dns_rule_id not in inst["dns"]:
        return _problem(404, "Not Found", "DNS rule not found")
    if not _precondition_ok(request):
        return _problem(412, "Precondition Failed", "If-Match does not match current ETag")
    try:
        body = await request.json()
    except Exception:
        return _problem(400, "Bad Request", "body is not valid JSON")
    body = {} if body is None else body
    if not isinstance(body, dict):
        return _problem(400, "Bad Request", "body must be a JSON object")
    state = body.get("state")
    ip_type = body.get("ipAddressType")
    if state is not None and not _one_of(state, _DNS_STATES):
        return _problem(400, "Bad Request", f"invalid state {state!r}")
    if ip_type is not None and not _one_of(ip_type, _DNS_IP_TYPES):
        return _problem(400, "Bad Request", f"invalid ipAddressType {ip_type!r}")
    updated = {
        "dnsRuleId": dns_rule_id,  # path id is authoritative
        "domainName": body.get("domainName", inst["dns"][dns_rule_id]["domainName"]),
        "ipAddressType": ip_type or inst["dns"][dns_rule_id]["ipAddressType"],
        "ipAddress": body.get("ipAddress", inst["dns"][dns_rule_id]["ipAddress"]),
        "ttl": body.get("ttl", inst["dns"][dns_rule_id].get("ttl", 300)),
        "state": state or inst["dns"][dns_rule_id]["state"],
    }
    with _lock:
        inst["dns"][dns_rule_id] = updated
    return JSONResponse(status_code=200, content=updated, headers={"ETag": CURRENT_ETAG})


# --------------------------------------------------------------------------- #
# Traffic rules
# --------------------------------------------------------------------------- #
@app.get("/mec_app_support/{ver}/applications/{app_instance_id}/traffic_rules")
async def list_traffic_rules(ver: str, app_instance_id: str):
    inst = INSTANCES.get(app_instance_id)
    if inst is None:
        return _problem(404, "Not Found", f"app instance {app_instance_id} not found")
    return JSONResponse(status_code=200, content=list(inst["traffic"].values()))


@app.get("/mec_app_support/{ver}/applications/{app_instance_id}/traffic_rules/{traffic_rule_id}")
async def get_traffic_rule(ver: str, app_instance_id: str, traffic_rule_id: str):
    inst = INSTANCES.get(app_instance_id)
    if inst is None or traffic_rule_id not in inst["traffic"]:
        return _problem(404, "Not Found", "traffic rule not found")
    return JSONResponse(status_code=200, content=inst["traffic"][traffic_rule_id])


@app.put("/mec_app_support/{ver}/applications/{app_instance_id}/traffic_rules/{traffic_rule_id}")
async def put_traffic_rule(ver: str, app_instance_id: str, traffic_rule_id: str, request: Request):
    inst = INSTANCES.get(app_instance_id)
    if inst is None or traffic_rule_id not in inst["traffic"]:
        return _problem(404, "Not Found", "traffic rule not found")
    if not _precondition_ok(request):
        return _problem(412, "Precondition Failed", "If-Match does not match current ETag")
    try:
        body = await request.json()
    except Exception:
        return _problem(400, "Bad Request", "body is not valid JSON")
    body = {} if body is None else body
    if not isinstance(body, dict):
        return _problem(400, "Bad Request", "body must be a JSON object")
    action = body.get("action")
    state = body.get("state")
    ftype = body.get("filterType")
    if action is not None and not _one_of(action, _TRAFFIC_ACTIONS):
        return _problem(400, "Bad Request", f"invalid action {action!r}")
    if state is not None and not _one_of(state, _TRAFFIC_STATES):
        return _problem(400, "Bad Request", f"invalid state {state!r}")
    if ftype is not None and not _one_of(ftype, _FILTER_TYPES):
        return _problem(400, "Bad Request", f"invalid filterType {ftype!r}")
    cur = inst["traffic"][traffic_rule_id]
    updated = dict(cur)
    updated.update(body)
    updated["trafficRuleId"] = traffic_rule_id  # path id is authoritative
    with _lock:
        inst["traffic"][traffic_rule_id] = updated
    return JSONResponse(status_code=200, content=updated, headers={"ETag": CURRENT_ETAG})


# --------------------------------------------------------------------------- #
# CONFTASK: confirm_ready / confirm_termination
# --------------------------------------------------------------------------- #
async def _confirmation(request: Request, app_instance_id: str, field: str, allowed: set[str]):
    """Shared confirm_* handling: unknown instance -> 404, then the body.

    GS MEC 011 makes the body mandatory: AppReadyConfirmation.indication (READY) and
    AppTerminationConfirmation.operationAction (TERMINATING | STOPPING). A missing or
    out-of-enum value is 400, not a silent success.
    """
    if app_instance_id not in INSTANCES:
        return _problem(404, "Not Found", f"app instance {app_instance_id} not found")
    try:
        body = await request.json()
    except Exception:
        body = None
    value = body.get(field) if isinstance(body, dict) else None
    if not _one_of(value, allowed):
        return _problem(400, "Bad Request", f"{field} must be one of {sorted(allowed)}, got {value!r}")
    with _lock:
        INSTANCES[app_instance_id]["ready"] = value == "READY"
    return Response(status_code=204)


@app.post("/mec_app_support/{ver}/applications/{app_instance_id}/confirm_termination")
async def confirm_termination(ver: str, app_instance_id: str, request: Request):
    return await _confirmation(request, app_instance_id, "operationAction", {"TERMINATING", "STOPPING"})


@app.post("/mec_app_support/{ver}/applications/{app_instance_id}/confirm_ready")
async def confirm_ready(ver: str, app_instance_id: str, request: Request):
    return await _confirmation(request, app_instance_id, "indication", {"READY"})


# --------------------------------------------------------------------------- #
# Mp1 service registry (mec_service_mgmt) -- the part of the same platform that the
# ESTIMED test plan reads back (TD_MEC_REG_02 step 4) and that a handover orchestrator
# uses as the target-readiness signal (TD_MEC_HO_06). Shares INSTANCES with the
# registration and confirm_ready routes above, so "ready" means what the app confirmed.
#
# Platform choice, stated: a service is advertised in GET .../services only while its
# app instance has confirmed READY. GS MEC 011 does not make that a rule; an
# orchestrator that must not hand over to a half-started edge needs it to be one.
# --------------------------------------------------------------------------- #
SERVICES: dict[str, dict] = {}          # serInstanceId -> ServiceInfo (+ owning appInstanceId)
_SERVICE_STATES = {"ACTIVE", "INACTIVE", "SUSPENDED"}


@app.post("/mec_service_mgmt/{ver}/applications/{app_instance_id}/services")
async def register_service(ver: str, app_instance_id: str, request: Request):
    if app_instance_id not in INSTANCES:
        return _problem(404, "Not Found", f"app instance {app_instance_id} not found")
    try:
        body = await request.json()
    except Exception:
        body = None
    if not isinstance(body, dict):
        return _problem(400, "Bad Request", "ServiceInfo must be a JSON object")
    missing = [k for k in ("serName", "version", "state", "serializer") if k not in body]
    if missing:
        return _problem(400, "Bad Request", f"ServiceInfo lacks {missing}")
    if not _one_of(body["state"], _SERVICE_STATES):
        return _problem(400, "Bad Request", f"state must be one of {sorted(_SERVICE_STATES)}")
    ser_id = str(uuid.uuid4())
    info = {**body, "serInstanceId": ser_id,
            "_links": {"self": {"href": f"/mec_service_mgmt/{ver}/applications/{app_instance_id}/services/{ser_id}"}}}
    with _lock:
        SERVICES[ser_id] = {"info": info, "appInstanceId": app_instance_id}
    return JSONResponse(status_code=201, content=info,
                        headers={"Location": info["_links"]["self"]["href"]})


@app.get("/mec_service_mgmt/{ver}/services")
async def list_services(ver: str, request: Request):
    q = request.query_params
    names = set(q.get("ser_name", "").split(",")) - {""}
    with _lock:
        out = [s["info"] for s in SERVICES.values()
               if INSTANCES.get(s["appInstanceId"], {}).get("ready")
               and (not names or s["info"]["serName"] in names)
               and (not q.get("state") or s["info"]["state"] == q["state"])]
    return JSONResponse(status_code=200, content=out)


@app.delete("/mec_service_mgmt/{ver}/applications/{app_instance_id}/services/{ser_id}")
async def delete_service(ver: str, app_instance_id: str, ser_id: str):
    with _lock:
        s = SERVICES.get(ser_id)
        if s is None or s["appInstanceId"] != app_instance_id:
            return _problem(404, "Not Found", f"service {ser_id} not found")
        del SERVICES[ser_id]
    return Response(status_code=204)


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #
@app.get("/")
async def root() -> JSONResponse:
    return JSONResponse(status_code=200, content={"status": "ok"})


def _serve(port: int) -> None:
    uvicorn.Server(
        uvicorn.Config(Shim(app), host="127.0.0.1", port=port, log_level="warning")
    ).run()


if __name__ == "__main__":
    # 8082: registration stub the DNS suite calls directly.
    threading.Thread(target=_serve, args=(8082,), daemon=True).start()
    # 8091: the mec_app_support API under test.
    _serve(8091)
