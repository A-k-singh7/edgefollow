#!/usr/bin/env python3
"""ETSI GS MEC 040 Federation Enablement -- DEMO fork (ESTIMED Hackathon #2).

Forked from our MEC 040 CONFORMANCE candidate (scored against ETSI's suite
MEC040/SRV/MEF, 20/29; not in this repository). That file is deliberately left
untouched so its score stays valid; this fork carries the changes a live demo needs
and is NOT run against the ATS.

Differences from the conformance candidate, and only these:

  1. **Both apiName spellings route.** The ATS and the conformance candidate use
     `fed-enablement` (hyphen); the live ETSI sandbox at try-mec.etsi.org exposes
     `/fed_enablement/v1/` (underscore). The conformance candidate's Shim only
     collapses leading slashes, so the underscore form 404s. Here the Shim anchors
     on the `/fed_resources` segment, so any apiName prefix normalises to the
     canonical base and both spellings work.

  2. **Seeded peers carry an `endpoint`.** Federation discovery is only useful to
     the handover if the answer says WHERE the peer system is. `SystemInfo` in the
     ATS fixtures is just {systemName, systemProvider}; the register handler already
     preserves extra attributes, so an `endpoint` rides along unchanged.

  3. **Port 8300**, so this can run beside the conformance candidate on 8084.

Original header follows.

ETSI GS MEC 040 Federation Enablement API -- conformance candidate.

Implements the MEF (MEC Federation) `fed_resources/system_info` resource of
ETSI GS MEC 040 V3.2.1 clause 7.3, against which
`MEC040/SRV/MEF/FederationEnablement.robot` (29 test cases) is run.

Surface, from the ATS keywords:

    GET    {apiRoot}/fed-enablement/v1/fed_resources/system_info
    GET    .../system_info?systemId=|systemName=|systemProvider=   (comma = OR)
    GET    .../system_info/{systemId}
    POST   .../system_info                 201 + assigned systemId
    PATCH  .../system_info/{systemId}      200
    DELETE .../system_info/{systemId}      204

Two design decisions worth stating, because they are interpretations rather than
transcriptions of the specification:

1. **The registry is pre-provisioned.** The suite queries
   `systemName=SYSTEM_NAME` and `systemProvider=SYSTEM_PROVIDER` and expects
   200, while the bodies it POSTs carry `systemName: "systemName"` -- so those
   filters can only match if the IUT already knows some federated systems. A
   federation registry that knows peers before the orchestrator registers more is
   the realistic reading, so two peers are seeded at startup.

2. **A filter that matches nothing is 404, not an empty 200.** The `_NF_` cases
   require it (`systemId=NOT_EXISTING_SYS_ID` -> 404). Note this is *not* the
   usual REST reading, where an unmatched collection query is 200 with `[]`;
   it is what this ATS asserts, and the two readings are in tension. Recorded
   rather than smoothed over.

`systemId` is assigned as SYSTEM_ID, SYSTEM_ID2, SYSTEM_ID3 … in registration
order. The suite captures the first POST's id and later filters on the literal
`SYSTEM_ID`, so a random UUID would make several assertions vacuous -- they would
iterate an empty list and "pass" without testing anything.
"""
from __future__ import annotations

import json
import re
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

PORT = 8300   # demo fork; conformance candidate keeps 8084
API_BASE = "/fed-enablement/v1/fed_resources/system_info"

app = FastAPI(title="MEC 040 Federation Enablement", version="v1")

# systemId -> SystemInfo
_STORE: dict[str, dict[str, Any]] = {}
_SEQ = 0


def _problem(status: int, title: str, detail: str) -> JSONResponse:
    """ProblemDetails (RFC 7807), the error body MEC 009 clause 6.15 expects."""
    return JSONResponse(
        status_code=status,
        content={"type": "about:blank", "title": title, "status": status, "detail": detail},
    )


def _seed() -> None:
    """Pre-provisioned federation peers -- see decision (1) in the docstring."""
    _STORE.clear()
    # Ids deliberately OUTSIDE the SYSTEM_ID* space: the suite captures the
    # first POST's systemId and then filters on the literal "SYSTEM_ID", so a
    # seed sitting on that id would be overwritten by the first registration and
    # deleted by its teardown -- which is exactly why every 001_OK_* after the
    # first returned 404 on the initial run.
    # The demo fork gives each peer an `endpoint`, because federation discovery is
    # only actionable if the answer says where the peer system actually is -- and a
    # `cseName`, because knowing the host is not enough to write to it. The gateway
    # used to infer the CSE from the endpoint's PORT, which silently wrote a third
    # peer's telemetry to a CSE that did not exist. Both ride as extra attributes;
    # the register handler preserves them unchanged.
    for sid, name, prov, endpoint, cse in (
        ("SEED_SYS_1", "SYSTEM_NAME", "SYSTEM_PROVIDER", "http://127.0.0.1:8202", "cse-mn-b"),
        ("SEED_SYS_2", "SYSTEM_NAME2", "SYSTEM_PROVIDER2", "http://127.0.0.1:8201", "cse-mn-a"),
    ):
        _STORE[sid] = {"systemId": sid, "systemName": name, "systemProvider": prov,
                       "endpoint": endpoint, "cseName": cse}


def _next_id() -> str:
    """Lowest free SYSTEM_ID slot.

    A monotonic counter drifts: each test registers three systems and deletes
    them in teardown, so the second test's first POST would get SYSTEM_ID4 and
    the suite's `systemId=SYSTEM_ID` filter would match nothing (404). Reusing
    the lowest free slot makes every test's first registration SYSTEM_ID again.
    """
    n = 1
    while True:
        sid = "SYSTEM_ID" if n == 1 else f"SYSTEM_ID{n}"
        if sid not in _STORE:
            return sid
        n += 1


def _matches(rec: dict[str, Any], field: str, raw: str) -> bool:
    """Comma-separated values are alternatives (OR), per the suite's
    `systemId=A,B` and `systemName=A,B` parameters."""
    wanted = [v.strip() for v in raw.split(",") if v.strip()]
    return not wanted or rec.get(field) in wanted


@app.get(API_BASE)
async def list_system_info(request: Request):
    q = request.query_params
    known = {"systemId", "systemName", "systemProvider"}
    unknown = set(q.keys()) - known
    if unknown:
        return _problem(400, "Bad Request", f"unsupported query parameter(s): {sorted(unknown)}")

    out = list(_STORE.values())
    filtered = False
    for field in ("systemId", "systemName", "systemProvider"):
        raw = q.get(field)
        if raw is None or raw.strip() == "":
            continue  # `systemId=` with no value is not a filter
        filtered = True
        out = [r for r in out if _matches(r, field, raw)]

    if filtered and not out:
        return _problem(404, "Not Found", "no system info matches the requested filter")
    return JSONResponse(status_code=200, content=out)


@app.get(API_BASE + "/{system_id}")
async def get_system_info(system_id: str):
    rec = _STORE.get(system_id)
    if rec is None:
        return _problem(404, "Not Found", f"no system info with systemId {system_id!r}")
    return JSONResponse(status_code=200, content=rec)


@app.post(API_BASE)
async def register_system_info(request: Request):
    try:
        body = json.loads(await request.body() or b"{}")
    except (ValueError, RecursionError):  # bad UTF-8, digit limit, nesting: all 400
        return _problem(400, "Bad Request", "request body is not valid JSON")
    if not isinstance(body, dict):
        return _problem(400, "Bad Request", "request body shall be a SystemInfo object")

    # "Shall be absent in POST request" -- SystemInfoList.schema.json, systemId.
    if "systemId" in body:
        return _problem(400, "Bad Request", "systemId shall be absent in a POST request")
    for required in ("systemName", "systemProvider"):
        if not body.get(required):
            return _problem(400, "Bad Request", f"{required} is required")

    sid = _next_id()
    rec = {"systemId": sid, **{k: v for k, v in body.items() if k != "systemId"}}
    _STORE[sid] = rec
    return JSONResponse(status_code=201, content=rec,
                        headers={"Location": f"{API_BASE}/{sid}"})


@app.patch(API_BASE + "/{system_id}")
async def update_system_info(system_id: str, request: Request):
    try:
        body = json.loads(await request.body() or b"{}")
    except (ValueError, RecursionError):  # bad UTF-8, digit limit, nesting: all 400
        return _problem(400, "Bad Request", "request body is not valid JSON")
    if not isinstance(body, dict) or not body:
        return _problem(400, "Bad Request", "request body shall be a non-empty SystemInfo")
    # systemId is not modifiable by a PATCH.
    if "systemId" in body and body["systemId"] != system_id:
        return _problem(400, "Bad Request", "systemId shall not be modified")

    rec = _STORE.get(system_id)
    if rec is None:
        return _problem(404, "Not Found", f"no system info with systemId {system_id!r}")
    rec.update({k: v for k, v in body.items() if k != "systemId"})
    return JSONResponse(status_code=200, content=rec)


@app.delete(API_BASE + "/{system_id}")
async def remove_system_info(system_id: str):
    if _STORE.pop(system_id, None) is None:
        return _problem(404, "Not Found", f"no system info with systemId {system_id!r}")
    return Response(status_code=204)


@app.get("/")
async def root():
    return JSONResponse(status_code=200,
                        content={"apiName": "fed-enablement", "apiVersion": "v1"})


class Shim:
    """Tolerate the two ASGI quirks every ETSI MEC ATS candidate hits on
    Linux/uvicorn: an empty apiRoot producing a doubled '//' prefix, and
    lowercase header names. See reference_etsi_mec_candidate_gotchas."""

    # Robot's REST library indexes response headers by EXACT name:
    # ${response['headers']['Content-Type']}. uvicorn emits them lowercased, so
    # every schema/content-type assertion dies with KeyError: 'Content-Type'.
    # Canonicalise on the way out. (Found the hard way: the first run failed 11
    # tests on this alone.)
    _CANON = {b"content-type": b"Content-Type", b"content-length": b"Content-Length",
              b"location": b"Location", b"link": b"Link", b"etag": b"ETag"}

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            p = re.sub(r"/{2,}", "/", scope.get("path", ""))
            # Anchor on the resource segment: the ATS says `fed-enablement`, the
            # live ETSI sandbox says `fed_enablement`. Normalising to the canonical
            # base makes both (and any apiRoot prefix) route to the same handlers.
            i = p.find("/fed_resources")
            if i >= 0:
                p = API_BASE.rsplit("/fed_resources", 1)[0] + p[i:]
            if p != scope.get("path"):
                scope = dict(scope, path=p)

        async def _send(message):
            if message.get("type") == "http.response.start":
                message = dict(message)
                message["headers"] = [
                    (self._CANON.get(k.lower(), k), v) for k, v in message.get("headers", [])
                ]
            await send(message)

        await self.inner(scope, receive, _send)


def _serve(a, port: int) -> None:
    uvicorn.Server(uvicorn.Config(Shim(a), host="127.0.0.1", port=port,
                                  log_level="warning")).run()


if __name__ == "__main__":
    _seed()
    _serve(app, PORT)
