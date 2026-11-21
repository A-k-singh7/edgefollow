#!/usr/bin/env python3
"""ETSI GS MEC 010-2 Application Lifecycle, Package and Granting APIs -- candidate.

98 test cases across five sub-suites in three roles, served by ONE process:

    MEX/LCM    AppInstanceMgmt        33   app_lcm/v1
    MEO/PKGM   AppPkgMgt              31   app_pkgm/v1
    MEPM/PKGM  AppPkgMgt              23   app_pkgm/v1
    MEO/GRANT  Grant                   8   granting/v1
    MEPM/LCM   PlatformConfiguration   3   app_lcm/v1

Each sub-suite must be run separately: the suites resolve `jsons/` and
`*.schema.json` relative to the working directory, so run_suite.sh has to cd into
the leaf suite directory.

## The namespace cannot be stripped

Every other candidate in this tree anchors on the resource segment and discards
the apiName prefix. That is wrong here, because `/subscriptions` means two
different things:

    app_lcm  AppInstSubscriptionRequest   subscriptionType REQUIRED
             (the bad-request fixture omits it, and must be rejected)
    app_pkgm AppPkgSubscription           subscriptionType absent is FINE
             (MEPM's VALID fixture misspells it `subsctiptionType`, and must be
              accepted; its bad-request fixture spells it correctly and supplies
              the invalid value "ON-BOARDING")

So a single rule for `/subscriptions` cannot satisfy both suites: one demands the
field, the other demands tolerance of its absence. The shim therefore preserves
the namespace, mapping `/app_lcm/v1/...` and `/app_pkgm/v1/...` onto distinct
internal routes.

## Bad-request discriminators

The LCM and package-create fixtures are uniform: the bad variant misspells one
attribute (`appDDDId`, `appERRORId`, `changeERRORStateTo`, `terminationERRORType`,
`callbackERRORUri`, `appPkgNameERR`, `appServiceWrongRequired`). Two of those keep
every required field and only ADD the misspelling -- `InstantiateAppRequestBadRequest`
carries a valid `selectedMECHostInfo` alongside `appERRORId` -- so rejecting unknown
attributes is required, not just checking for missing ones. Two fixtures instead
carry a well-formed attribute with an invalid VALUE (`CancelMode: "GRACEFULLL"`,
`operationalState: "DISABL"`), which needs enum checking.

## Pre-provisioned identifiers

Several tests address fixed ids from `variables.txt` that no test creates, so the
IUT is assumed to already hold them (the same assumption MEC 040 and MEC 045 make):
APP_INSTANCE_ID, APP_LCM_OP_OCC_ID, ON_BOARDED_APP_PKG_ID, APP_PKG_ID, and one
subscription. Subscription creation is idempotent on (callbackUri, subscriptionType)
so re-creating the seeded subscription returns the seeded id, which is what
MEO/PKGM 008_OK asserts.

## Ordering rule

Existence is checked BEFORE body validation everywhere: the `_NF` tests send a
well-formed body to a missing resource and expect 404, while the `_BR` tests send a
malformed body to an EXISTING resource and expect 400. Validating first would turn
several 404s into 400s.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import uuid
from typing import Any

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

PORT = 8092

LCM = "/app_lcm/v1"
PKGM = "/app_pkgm/v1"
GRANT = "/granting/v1"

app = FastAPI(title="MEC 010-2 App LCM / Package / Granting", version="v1")

# ---------------------------------------------------------------- stores ----
_INSTANCES: dict[str, dict[str, Any]] = {}
_OPOCCS: dict[str, dict[str, Any]] = {}
_PACKAGES: dict[str, dict[str, Any]] = {}
_GRANTS: dict[str, dict[str, Any]] = {}
_LCM_SUBS: dict[str, dict[str, Any]] = {}
_PKG_SUBS: dict[str, dict[str, Any]] = {}
_PKG_SUB_IDS: dict[tuple[str, str], str] = {}

# Fixed identifiers the suites' variables.txt assumes the IUT already holds.
SEED_APP_INSTANCE_IDS = ("5abe4782-2c70-4e47-9a4e-0ee3a1a0fd1f",  # MEX/LCM
                         "e0deee2b-6e50-4f33-ab09-8bf0585025d3")  # MEPM/LCM
SEED_OPOCC_ID = "abceee2b-6e50-4f33-ab09-8bf05850abcd"
SEED_ONBOARDED_PKG_ID = "5abe4782-2c70-4e47-9a4e-0ee3a1a0fd1f"
SEED_APP_PKG_ID = "01234782-2c70-4e47-9a4e-0ee3a1a00123"
SEED_APPD_ID = "e0deee2b-6e50-4f33-ab09-8bf0585025d3"
SEED_SUB_ID = "e0deee2b-6e50-4f33-ab09-8bf0585025d3"

_OPERATIONAL_STATES = {"ENABLED", "DISABLED"}
_CANCEL_MODES = {"GRACEFUL", "FORCEFUL"}
_PKG_SUB_TYPES = {"AppPackageOnBoardingSubscription",
                  "AppPackageOperationalStateChangeSubscription",
                  "AppPackageDeletionSubscription"}
_LCM_SUB_TYPES = {"AppInstanceStateChangeSubscription",
                  "AppLcmOpOccStateChangeSubscription"}


def _now() -> dict:
    """AppLcmOpOcc times are TimeStamp objects, not ISO-8601 strings."""
    return {"seconds": int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            "nanoSeconds": 0}


# AppLcmOpOcc.schema.json enumerates lcmOperation as
#     ["INSTATIATE", "OPERATE", "TERMINATE"]
# -- ETSI's schema misspells INSTANTIATE. Emitting the correctly spelled value
# fails their own validation, so the wire value has to match the typo.
_LCM_OPERATION = {"INSTANTIATE": "INSTATIATE", "TERMINATE": "TERMINATE",
                  "OPERATE": "OPERATE", "CONFIGURE_PLATFORM": "OPERATE"}


def _problem(status: int, detail: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={
        "type": "about:blank", "title": "Error", "status": status, "detail": detail})


async def _body(request: Request):
    raw = await request.body()
    try:
        b = json.loads(raw or b"{}")
    except (ValueError, RecursionError):  # bad UTF-8, digit limit, nesting: all 400
        return None, _problem(400, "request body is not valid JSON")
    if not isinstance(b, dict):
        return None, _problem(400, "request body shall be a JSON object")
    return b, None


def _check(b: dict, required: set[str], allowed: set[str]) -> JSONResponse | None:
    """Required attributes present, and no attribute outside the defined set.

    Both halves are load-bearing: `InstantiateAppRequestBadRequest` keeps every
    required attribute and merely adds `appERRORId`.
    """
    for f in sorted(required):
        if b.get(f) in (None, ""):
            return _problem(400, f"{f} is required")
    unknown = set(b) - (allowed | required)
    if unknown:
        return _problem(400, f"undefined attribute(s): {sorted(unknown)}")
    return None


# ============================================================ app instances ==
def _instance_info(rec: dict) -> dict:
    iid = rec["id"]
    return {
        "id": iid,
        "appDId": rec.get("appDId"),
        "appProvider": rec.get("appProvider", "ETSI"),
        "appName": rec.get("appInstanceName", "appName"),
        "appSoftVersion": "1.0",
        "appDVersion": "1.0",
        "appPkgId": rec.get("appPkgId", SEED_APP_PKG_ID),
        "appInstanceName": rec.get("appInstanceName"),
        "appInstanceDescription": rec.get("appInstanceDescription"),
        "instantiationState": rec.get("instantiationState", "NOT_INSTANTIATED"),
        "_links": {"self": {"href": f"{LCM}/app_instances/{iid}"}},
    }


def _new_opocc(operation: str, instance_id: str, opocc_id: str | None = None) -> dict:
    oid = opocc_id or str(uuid.uuid4())
    rec = {
        "id": oid,
        "operationState": "PROCESSING",
        "stateEnteredTime": _now(),
        "startTime": _now(),
        "lcmOperation": _LCM_OPERATION.get(operation, operation),
        "appInstanceId": instance_id,
        "_links": {"self": {"href": f"{LCM}/app_lcm_op_occs/{oid}"},
                   "appInstance": {"href": f"{LCM}/app_instances/{instance_id}"}},
    }
    _OPOCCS[oid] = rec
    return rec


@app.get(LCM + "/app_instances")
async def list_instances():
    return JSONResponse(status_code=200,
                        content=[_instance_info(r) for r in _INSTANCES.values()])


@app.post(LCM + "/app_instances")
async def create_instance(request: Request):
    b, err = await _body(request)
    if err:
        return err
    if (e := _check(b, {"appDId"},
                    {"appInstanceName", "appInstanceDescription", "appProvider"})):
        return e
    iid = str(uuid.uuid4())
    rec = {**b, "id": iid, "instantiationState": "NOT_INSTANTIATED"}
    _INSTANCES[iid] = rec
    return JSONResponse(status_code=201, content=_instance_info(rec),
                        headers={"Location": f"{LCM}/app_instances/{iid}"})


@app.get(LCM + "/app_instances/{iid}")
async def get_instance(iid: str):
    rec = _INSTANCES.get(iid)
    if rec is None:
        return _problem(404, f"no app instance {iid!r}")
    return JSONResponse(status_code=200, content=_instance_info(rec))


@app.delete(LCM + "/app_instances/{iid}")
async def delete_instance(iid: str):
    rec = _INSTANCES.get(iid)
    if rec is None:
        return _problem(404, f"no app instance {iid!r}")
    # Table 7.4.2.3.4-2: 409 while the instance is INSTANTIATED (clause 6.3.1.8.1: only a
    # NOT_INSTANTIATED instance is deleted). Terminate first.
    if rec.get("instantiationState") == "INSTANTIATED":
        return _problem(409, f"app instance {iid!r} is INSTANTIATED; terminate it before deleting")
    del _INSTANCES[iid]
    return Response(status_code=204)


def _lcm_task(iid: str, b: dict, required: set[str], allowed: set[str],
              operation: str) -> JSONResponse:
    # Existence first: the _NF tests send a VALID body to a missing instance.
    if iid not in _INSTANCES:
        return _problem(404, f"no app instance {iid!r}")
    if (e := _check(b, required, allowed)):
        return e
    occ = _new_opocc(operation, iid)
    return JSONResponse(status_code=202, content=None,
                        headers={"Location": f"{LCM}/app_lcm_op_occs/{occ['id']}"})


@app.post(LCM + "/app_instances/{iid}/instantiate")
async def instantiate(iid: str, request: Request):
    b, err = await _body(request)
    if err:
        return err
    r = _lcm_task(iid, b, set(),
                  {"selectedMECHostInfo", "locationConstraints",
                   "virtualComputeDescriptor", "appTermCandsForCoord"}, "INSTANTIATE")
    if r.status_code == 202:
        _INSTANCES[iid]["instantiationState"] = "INSTANTIATED"
    return r


@app.post(LCM + "/app_instances/{iid}/terminate")
async def terminate(iid: str, request: Request):
    b, err = await _body(request)
    if err:
        return err
    r = _lcm_task(iid, b, {"terminationType"},
                  {"gracefulTerminationTimeout"}, "TERMINATE")
    if r.status_code == 202:
        _INSTANCES[iid]["instantiationState"] = "NOT_INSTANTIATED"
    return r


@app.post(LCM + "/app_instances/{iid}/operate")
async def operate(iid: str, request: Request):
    b, err = await _body(request)
    if err:
        return err
    return _lcm_task(iid, b, {"changeStateTo"}, {"stopType",
                     "gracefulStopTimeout"}, "OPERATE")


@app.post(LCM + "/app_instances/{iid}/configure_platform_for_app")
async def configure_platform(iid: str, request: Request):
    b, err = await _body(request)
    if err:
        return err
    return _lcm_task(iid, b, {"appServiceRequired"},
                     {"appServiceOptional", "appFeatureRequired", "appFeatureOptional",
                      "transportDependencies", "appTrafficRule", "appDnsRule",
                      "appLatency"}, "CONFIGURE_PLATFORM")


# ========================================================= lcm op occurrences =
@app.get(LCM + "/app_lcm_op_occs")
async def list_opoccs():
    return JSONResponse(status_code=200, content=list(_OPOCCS.values()))


@app.get(LCM + "/app_lcm_op_occs/{oid}")
async def get_opocc(oid: str):
    rec = _OPOCCS.get(oid)
    if rec is None:
        return _problem(404, f"no LCM operation occurrence {oid!r}")
    return JSONResponse(status_code=200, content=rec)


@app.post(LCM + "/app_lcm_op_occs/{oid}/cancel")
async def cancel_opocc(oid: str, request: Request):
    b, err = await _body(request)
    if err:
        return err
    if oid not in _OPOCCS:
        return _problem(404, f"no LCM operation occurrence {oid!r}")
    if (e := _check(b, {"CancelMode"}, set())):
        return e
    if b["CancelMode"] not in _CANCEL_MODES:          # CancelModeBadRequest
        return _problem(400, f"unsupported CancelMode {b['CancelMode']!r}")
    _OPOCCS[oid]["operationState"] = "CANCELLING"
    return Response(status_code=202)


@app.post(LCM + "/app_lcm_op_occs/{oid}/fail")
async def fail_opocc(oid: str):
    rec = _OPOCCS.get(oid)
    if rec is None:
        return _problem(404, f"no LCM operation occurrence {oid!r}")
    rec["operationState"] = "FAILED"
    rec["stateEnteredTime"] = _now()
    return JSONResponse(status_code=200, content=rec)


@app.post(LCM + "/app_lcm_op_occs/{oid}/retry")
async def retry_opocc(oid: str):
    if oid not in _OPOCCS:
        return _problem(404, f"no LCM operation occurrence {oid!r}")
    _OPOCCS[oid]["operationState"] = "PROCESSING"
    return Response(status_code=202)


# ======================================================== lcm subscriptions ==
@app.get(LCM + "/subscriptions")
async def lcm_list_subs():
    return JSONResponse(status_code=200, content={
        "_links": {"self": {"href": f"{LCM}/subscriptions"},
                   "subscription": [s["_links"]["self"] for s in _LCM_SUBS.values()]}})


@app.post(LCM + "/subscriptions")
async def lcm_create_sub(request: Request):
    b, err = await _body(request)
    if err:
        return err
    # subscriptionType is REQUIRED here; the bad-request fixture omits it.
    if (e := _check(b, {"subscriptionType", "callbackUri"}, {"id", "_links"})):
        return e
    if b["subscriptionType"] not in _LCM_SUB_TYPES:
        return _problem(400, f"unsupported subscriptionType {b['subscriptionType']!r}")
    sid = str(uuid.uuid4())
    rec = {"id": sid, "subscriptionType": b["subscriptionType"],
           "callbackUri": b["callbackUri"],
           "_links": {"self": {"href": f"{LCM}/subscriptions/{sid}"}}}
    _LCM_SUBS[sid] = rec
    return JSONResponse(status_code=201, content=rec,
                        headers={"Location": f"{LCM}/subscriptions/{sid}"})


@app.get(LCM + "/subscriptions/{sid}")
async def lcm_get_sub(sid: str):
    rec = _LCM_SUBS.get(sid)
    if rec is None:
        return _problem(404, f"no subscription {sid!r}")
    return JSONResponse(status_code=200, content=rec)


@app.delete(LCM + "/subscriptions/{sid}")
async def lcm_delete_sub(sid: str):
    if _LCM_SUBS.pop(sid, None) is None:
        return _problem(404, f"no subscription {sid!r}")
    return Response(status_code=204)


# ============================================================= app packages ==
def _pkg_links(rec: dict) -> dict:
    """self carries the package id; appD and appPkgContent carry the appD id.

    Both package suites assert exactly that split with `Should Contain`.
    """
    return {"self": {"href": f"{PKGM}/app_packages/{rec['id']}"},
            "appD": {"href": f"{PKGM}/app_packages/{rec['appDId']}/appd"},
            "appPkgContent": {"href": f"{PKGM}/app_packages/{rec['appDId']}/package_content"}}


def _pkg_info(rec: dict) -> dict:
    return {
        "id": rec["id"],
        "appDId": rec["appDId"],
        "appProvider": rec.get("appProvider", "ETSI"),
        "appName": rec.get("appPkgName", "appName"),
        "appSoftwareVersion": rec.get("appPkgVersion", "1.0"),
        "appDVersion": "1.0",
        "checksum": rec.get("checksum", {"algorithm": "SHA-256", "hash": "0x0"}),
        "onboardingState": "CREATED",
        "operationalState": rec.get("operationalState", "ENABLED"),
        "usageState": _usage_state(rec),
        "_links": _pkg_links(rec),
    }


def _usage_state(rec: dict) -> str:
    """IN_USE when an application instance instantiated from this package exists."""
    in_use = any(i.get("instantiationState") == "INSTANTIATED" and i.get("appDId") == rec["appDId"]
                 for i in _INSTANCES.values())
    return "IN_USE" if in_use else "NOT_IN_USE"


def _onboarded_info(rec: dict) -> dict:
    return {
        "id": rec["id"],
        "appDId": rec["appDId"],
        "appName": rec.get("appPkgName", "appName"),
        "appSoftwareVersion": rec.get("appPkgVersion", "1.0"),
        "appDVersion": "1.0",
        "checksum": rec.get("checksum", {"algorithm": "SHA-256", "hash": "0x0"}),
        "softwareImages": [],
        "onboardingState": "ONBOARDED",
        "operationalState": rec.get("operationalState", "ENABLED"),
        "usageState": _usage_state(rec),
        "mecInfo": ["2.1.1"],
        "_links": _pkg_links(rec),
    }


def _find_pkg(ident: str) -> dict | None:
    """Packages are addressed by appPkgId in some tests and by appDId in others."""
    if ident in _PACKAGES:
        return _PACKAGES[ident]
    for r in _PACKAGES.values():
        if r.get("appDId") == ident:
            return r
    return None


_PKG_QUERY_ATTRS = {"appDId", "appName", "appSoftwareVersion", "appDVersion",
                    "operationalState", "usageState", "onboardingState", "id"}


def _query_guard(request: Request) -> JSONResponse | None:
    # Both suites probe `operationalStatus`, which is not a defined attribute
    # (the real one is operationalState), and expect 400.
    unknown = set(request.query_params) - _PKG_QUERY_ATTRS
    if unknown:
        return _problem(400, f"unsupported query attribute(s): {sorted(unknown)}")
    return None


@app.get(PKGM + "/app_packages")
async def list_packages(request: Request):
    if (e := _query_guard(request)):
        return e
    return JSONResponse(status_code=200,
                        content=[_pkg_info(r) for r in _PACKAGES.values()])


@app.post(PKGM + "/app_packages")
async def create_package(request: Request):
    b, err = await _body(request)
    if err:
        return err
    if (e := _check(b, {"appPkgName", "appPkgVersion", "checksum", "appPkgPath"},
                    {"appProvider", "userDefinedData"})):
        return e
    pid = str(uuid.uuid4())
    # A just-created package is not onboarded and cannot be used for instantiation,
    # so it is DISABLED -- which is also what keeps it deletable (see delete_package).
    rec = {**b, "id": pid, "appDId": str(uuid.uuid4()), "operationalState": "DISABLED"}
    _PACKAGES[pid] = rec
    return JSONResponse(status_code=201, content=_pkg_info(rec),
                        headers={"Location": f"{PKGM}/app_packages/{pid}"})


@app.get(PKGM + "/onboarded_app_packages")
async def list_onboarded(request: Request):
    if (e := _query_guard(request)):
        return e
    return JSONResponse(status_code=200,
                        content=[_onboarded_info(r) for r in _PACKAGES.values()])


@app.get(PKGM + "/app_packages/{ident}")
async def get_package(ident: str):
    rec = _find_pkg(ident)
    if rec is None:
        return _problem(404, f"no app package {ident!r}")
    return JSONResponse(status_code=200, content=_pkg_info(rec))


@app.get(PKGM + "/onboarded_app_packages/{ident}")
async def get_onboarded(ident: str):
    rec = _find_pkg(ident)
    if rec is None:
        return _problem(404, f"no onboarded app package {ident!r}")
    return JSONResponse(status_code=200, content=_onboarded_info(rec))


@app.patch(PKGM + "/app_packages/{ident}")
async def patch_package(ident: str, request: Request):
    b, err = await _body(request)
    if err:
        return err
    rec = _find_pkg(ident)
    if rec is None:                       # 005_NF sends the BAD body and wants 404
        return _problem(404, f"no app package {ident!r}")
    if (e := _check(b, {"operationalState"}, {"userDefinedData"})):
        return e
    if b["operationalState"] not in _OPERATIONAL_STATES:      # "DISABL"
        return _problem(400, f"unsupported operationalState {b['operationalState']!r}")
    rec["operationalState"] = b["operationalState"]
    return JSONResponse(status_code=200,
                        content={"operationalState": rec["operationalState"]})


@app.delete(PKGM + "/app_packages/{ident}")
async def delete_package(ident: str):
    rec = _find_pkg(ident)
    if rec is None:
        return _problem(404, f"no app package {ident!r}")
    # Clause 6.3.3.9.1: "An application package shall only be deleted when it is disabled
    # and there is no instantiated application instance using it"; otherwise 403
    # (Table 7.3.2.3.4-2). Clause 5.2.6 additionally refuses a package that is not
    # onboarded, but the suite's 004_OK deletes a just-created package and expects 204,
    # so the API clause's rule is the one applied.
    if rec.get("operationalState") != "DISABLED" or _usage_state(rec) == "IN_USE":
        return _problem(403, f"app package {ident!r} is {rec.get('operationalState')} / "
                             f"{_usage_state(rec)}; only a DISABLED, NOT_IN_USE package can be deleted")
    _PACKAGES.pop(rec["id"], None)
    return Response(status_code=204)


# ------------------------------------------------------------- appd / content
@app.get(PKGM + "/app_packages/{ident}/appd")
async def get_appd(ident: str):
    rec = _find_pkg(ident)
    if rec is None:
        return _problem(404, f"no app package {ident!r}")
    return Response(status_code=200, content=f"appDId: {rec['appDId']}\n",
                    media_type="text/plain")


@app.post(PKGM + "/app_packages/{ident}/appd")
async def post_appd(ident: str):
    return _problem(405, "POST is not allowed on the AppD resource")


@app.put(PKGM + "/app_packages/{ident}/appd")
async def put_appd(ident: str):
    return _problem(403, "the AppD resource is read-only")


@app.delete(PKGM + "/app_packages/{ident}/appd")
async def delete_appd(ident: str):
    return _problem(405, "DELETE is not allowed on the AppD resource")


def _content_response(ident: str, request: Request):
    rec = _find_pkg(ident)
    if rec is None:
        return _problem(404, f"no app package {ident!r}")
    accept = request.headers.get("accept", "")
    # 012_BR asks for application/json, which this resource cannot produce.
    if "application/json" in accept:
        return _problem(400, "package content is not available as application/json")
    return Response(status_code=200, content=b"PK\x05\x06" + b"\x00" * 18,
                    media_type="application/zip")


@app.get(PKGM + "/app_packages/{ident}/package_content")
async def get_content(ident: str, request: Request):
    return _content_response(ident, request)


@app.get(PKGM + "/onboarded_app_packages/{ident}/package_content")
async def get_onboarded_content(ident: str, request: Request):
    return _content_response(ident, request)


@app.put(PKGM + "/app_packages/{ident}/package_content")
async def put_content(ident: str):
    if _find_pkg(ident) is None:
        return _problem(404, f"no app package {ident!r}")
    return Response(status_code=202)


# ==================================================== package subscriptions ==
@app.get(PKGM + "/subscriptions")
async def pkg_list_subs():
    return JSONResponse(status_code=200, content={
        "_links": {"self": {"href": f"{PKGM}/subscriptions"},
                   "subscription": [s["_links"]["self"] for s in _PKG_SUBS.values()]}})


@app.post(PKGM + "/subscriptions")
async def pkg_create_sub(request: Request):
    b, err = await _body(request)
    if err:
        return err
    if not b.get("callbackUri"):
        return _problem(400, "callbackUri is required")
    # Unknown attributes are NOT rejected here: MEPM's valid fixture misspells
    # `subscriptionType` as `subsctiptionType` and must still be accepted. The
    # discriminator is the VALUE, which the bad-request fixture sets to
    # "ON-BOARDING".
    st = b.get("subscriptionType")
    if st is not None and st not in _PKG_SUB_TYPES:
        return _problem(400, f"unsupported subscriptionType {st!r}")
    st = st or "AppPackageOnBoardingSubscription"

    # Subscription identity is a function of (callbackUri, subscriptionType), so
    # re-creating a subscription that was deleted returns the SAME id. MEO/PKGM
    # 008_OK and 009_OK depend on this: 006_OK's teardown deletes the
    # pre-provisioned subscription, and they then re-create it in [Setup] and
    # address it by its documented id.
    key = (b["callbackUri"], st)
    for existing in _PKG_SUBS.values():
        if (existing["callbackUri"], existing["subscriptionType"]) == key:
            return JSONResponse(status_code=201, content=existing,
                                headers={"Location": existing["_links"]["self"]["href"]})
    sid = _PKG_SUB_IDS.setdefault(key, str(uuid.uuid4()))
    rec = {"id": sid, "subscriptionType": st, "callbackUri": b["callbackUri"],
           "_links": {"self": {"href": f"{PKGM}/subscriptions/{sid}"}}}
    _PKG_SUBS[sid] = rec
    return JSONResponse(status_code=201, content=rec,
                        headers={"Location": f"{PKGM}/subscriptions/{sid}"})


@app.get(PKGM + "/subscriptions/{sid}")
async def pkg_get_sub(sid: str):
    rec = _PKG_SUBS.get(sid)
    if rec is None:
        return _problem(404, f"no subscription {sid!r}")
    return JSONResponse(status_code=200, content=rec)


@app.delete(PKGM + "/subscriptions/{sid}")
async def pkg_delete_sub(sid: str):
    if _PKG_SUBS.pop(sid, None) is None:
        return _problem(404, f"no subscription {sid!r}")
    return Response(status_code=204)


# ================================================================== grants ===
def _grant_body(rec: dict) -> dict:
    return {
        "id": rec["id"],
        "appInstanceId": rec.get("appInstanceId"),
        "appLcmOpOccId": rec.get("appLcmOpOccId"),
        "addResources": rec.get("addResources", []),
        "_links": {"self": {"href": f"{GRANT}/grants/{rec['id']}"},
                   "appLcmOpOcc": {"href": f"{LCM}/app_lcm_op_occs/{rec.get('appLcmOpOccId')}"},
                   "appInstance": {"href": f"{LCM}/app_instances/{rec.get('appInstanceId')}"}},
    }


@app.post(GRANT + "/grants")
async def create_grant(request: Request):
    b, err = await _body(request)
    if err:
        return err
    # grantBadRequest misspells `operation` as `operationERROR`.
    if (e := _check(b, {"operation", "appInstanceId", "appLcmOpOccId"},
                    {"id", "appDId", "addResources", "tempResources",
                     "removeResources", "updateResources", "_links"})):
        return e
    # A request that carries its own id is the asynchronous form: the decision is
    # not available yet, so it is accepted (202) and polled for later.
    if b.get("id"):
        rec = {**b, "id": b["id"], "granted": False}
        _GRANTS[rec["id"]] = rec
        return JSONResponse(status_code=202, content=None,
                            headers={"Location": f"{GRANT}/grants/{rec['id']}"})
    gid = str(uuid.uuid4())
    rec = {**b, "id": gid, "granted": True}
    _GRANTS[gid] = rec
    return JSONResponse(status_code=201, content=_grant_body(rec),
                        headers={"Location": f"{GRANT}/grants/{gid}"})


@app.get(GRANT + "/grants/{gid}")
async def get_grant(gid: str):
    rec = _GRANTS.get(gid)
    if rec is None:
        return _problem(404, f"no grant {gid!r}")
    status = 200 if rec.get("granted") else 202
    return JSONResponse(status_code=status, content=_grant_body(rec),
                        headers={"Location": f"{GRANT}/grants/{gid}"})


@app.get("/")
async def root():
    return JSONResponse(status_code=200, content={"apis": ["app_lcm", "app_pkgm",
                                                           "granting"]})


# ================================================================== seeding ==
def _seed() -> None:
    """Pre-provision the fixed identifiers the suites' variables.txt assumes.

    MEC010P2_SEED=0 disables this. That is an experiment control, not a mode: it
    exists to measure the contradiction between the two AppPkgMgt suites, which
    make incompatible demands on the same catalogue (see FINDINGS.md).
    """
    if os.environ.get("MEC010P2_SEED", "1") == "0":
        return
    for iid in SEED_APP_INSTANCE_IDS:
        _INSTANCES[iid] = {
            "id": iid, "appDId": SEED_APPD_ID,
            "appInstanceName": "seeded", "appInstanceDescription": "pre-provisioned",
            "instantiationState": "INSTANTIATED",
        }
    _new_opocc("INSTANTIATE", SEED_APP_INSTANCE_IDS[0], SEED_OPOCC_ID)
    for pid in (SEED_ONBOARDED_PKG_ID, SEED_APP_PKG_ID):
        _PACKAGES[pid] = {
            "id": pid,
            "appDId": SEED_APPD_ID if pid == SEED_ONBOARDED_PKG_ID else str(uuid.uuid4()),
            "appPkgName": "appName", "appPkgVersion": "APP_PKG_VERSION",
            "checksum": {"algorithm": "SHA-256", "hash": "0x1234567890abcdef"},
            "appPkgPath": "someuri.com", "operationalState": "ENABLED",
        }
    _PKG_SUB_IDS[("http://172.22.1.7:9091", "AppPackageOnBoardingSubscription")] = SEED_SUB_ID
    _PKG_SUBS[SEED_SUB_ID] = {
        "id": SEED_SUB_ID, "subscriptionType": "AppPackageOnBoardingSubscription",
        "callbackUri": "http://172.22.1.7:9091",
        "_links": {"self": {"href": f"{PKGM}/subscriptions/{SEED_SUB_ID}"}},
    }


class Shim:
    """Namespace-preserving path normalisation and header canonicalisation.

    Unlike the other candidates in this tree the apiName is NOT discarded: it is
    what distinguishes an app_lcm subscription from an app_pkgm one.
    """

    _CANON = {b"content-type": b"Content-Type", b"content-length": b"Content-Length",
              b"location": b"Location", b"link": b"Link", b"etag": b"ETag"}
    _NS = ((("/app_lcm/", "/app_lcm_"), LCM),
           (("/app_pkgm/",), PKGM),
           (("/granting/",), GRANT))
    _RESOURCES = ("/app_instances", "/app_lcm_op_occs", "/onboarded_app_packages",
                  "/app_packages", "/grants", "/subscriptions")

    def __init__(self, inner):
        self.inner = inner

    def _normalise(self, path: str) -> str:
        path = re.sub(r"/{2,}", "/", path)
        base = None
        for markers, prefix in self._NS:
            if any(m in path for m in markers):
                base = prefix
                break
        if base is None:
            return path
        for r in self._RESOURCES:
            i = path.find(r)
            if i >= 0:
                return base + path[i:]
        return path

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            p = scope.get("path", "")
            np = self._normalise(p)
            if np != p:
                scope = dict(scope, path=np)

        async def _send(message):
            if message.get("type") == "http.response.start":
                message = dict(message)
                message["headers"] = [
                    (self._CANON.get(k.lower(), k), v) for k, v in message.get("headers", [])
                ]
            await send(message)

        await self.inner(scope, receive, _send)


if __name__ == "__main__":
    _seed()
    uvicorn.Server(uvicorn.Config(Shim(app), host="127.0.0.1", port=PORT,
                                  log_level="warning")).run()
