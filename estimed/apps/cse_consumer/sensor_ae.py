#!/usr/bin/env python3
"""A oneM2M sensor AE packaged as a MEC application (test plan TD_MEC_REG_03).

Started by the platform agent (estimed/mec_app_deploy.py) as

    python3 -I -B sensor_ae.py --instance <instance.json>

instance.json is what the platform tells this instance: {"lcmInstanceId", "mec011", "cse"}. What the app IS -- its
App-ID, its originator, its resource names, who may read -- is in appd.json beside this file.

On start, in this order:
  1. Mp1  registers its instance with MEC 011 and offers a service that names its AE
  2. Mca  AE Create to the MN-CSE (ty=2, pc with api, its own originator); it needs rsc 2001 and AE-ID == originator
  3. Mca  its <ACP>: itself every operation, the named readers RETRIEVE, nobody else anything; put on the <AE>
  4. Mca  its baseline <container>, and one reading in it (a fixed value: there is no sensor behind this app)
  5. Mp1  confirm_ready -- only now
On SIGTERM (the termination request): confirm_termination, then it removes its service, its <AE> and its MEC 011
registration and exits 0. If a start step fails it removes what it had created and exits 3. It deletes an <AE> only
if that <AE> carries this instance's label: a second instance the CSE refused must leave the first one's AE alone.

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ALL, RETRIEVE = 63, 2                               # accessControlOperations
TY_ACP, TY_AE, TY_CNT, TY_CIN = 1, 2, 3, 4
READING = {"temperature_c": 21.5, "source": "fixed value, no sensor"}


class Stop(Exception):
    """The termination request arrived."""


class Failed(Exception):
    """A start step did not get the answer it needs."""


def _stop(*_):
    raise Stop


def call(method: str, url: str, body=None, headers=None):
    """One HTTP request -> (status, parsed body or None, response headers)."""
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                               headers={"Accept": "application/json", "Content-Type": "application/json",
                                        **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            status, raw, hdrs = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        status, raw, hdrs = e.code, e.read(), e.headers
    try:
        return status, (json.loads(raw) if raw else None), hdrs
    except ValueError:
        return status, None, hdrs


def onem2m(method: str, url: str, origin: str, ty: int | None = None, body=None):
    """One oneM2M request over the HTTP binding -> (response status code, parsed body)."""
    _, parsed, hdrs = call(method, url, body, {
        "X-M2M-Origin": origin, "X-M2M-RI": uuid.uuid4().hex[:12], "X-M2M-RVI": "4",
        "Content-Type": f"application/json;ty={ty}" if ty else "application/json"})
    return int(hdrs.get("X-M2M-RSC") or 0), parsed


def need(what: str, got, want) -> None:
    if got != want:
        raise Failed(f"{what}: got {got!r}, need {want!r}")
    print(f"{what}: {got}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    cfg = json.loads(Path(ap.parse_args().instance).read_text())
    desc = json.loads((Path(__file__).resolve().parent / "appd.json").read_text())
    o = desc["onem2m"]
    origin, ae_url, mine = o["originator"], f"{cfg['cse']}/{o['rn']}", f"mec:lcmInstanceId:{cfg['lcmInstanceId']}"
    support, services = f"{cfg['mec011']}/mec_app_support/v2", f"{cfg['mec011']}/mec_service_mgmt/v1"
    made = {"inst": None, "ser": None}

    def start() -> None:
        st, body, _ = call("POST", f"{support}/registrations",
                           {"appName": desc["appName"], "appInstanceId": cfg["lcmInstanceId"]})
        need("MEC 011 registration", st, 201)
        inst = made["inst"] = body["appInstanceId"]         # MEC 011 hands out its own identifier
        st, body, _ = call("POST", f"{services}/applications/{inst}/services", {
            "serName": desc["appName"], "version": desc["appSoftVersion"], "state": "ACTIVE", "serializer": "JSON",
            "transportInfo": {"id": cfg["lcmInstanceId"], "name": "oneM2M AE", "type": "REST_HTTP",
                              "protocol": "HTTP", "version": "1.1", "security": {},
                              "endpoint": {"uris": [ae_url]}}})
        need("MEC 011 service", st, 201)
        made["ser"] = body["serInstanceId"]
        rsc, body = onem2m("POST", cfg["cse"], origin, TY_AE, {"m2m:ae": {
            "rn": o["rn"], "api": o["api"], "rr": False, "srv": ["4"],
            "lbl": [f"mec:appInstanceId:{inst}", mine]}})
        need("AE Create rsc", rsc, 2001)
        need("AE-ID", body["m2m:ae"]["aei"], origin)
        rules = [{"acor": [origin], "acop": ALL}]
        if o["acp"]["readers"]:
            rules.append({"acor": o["acp"]["readers"], "acop": RETRIEVE})
        rsc, body = onem2m("POST", ae_url, origin, TY_ACP, {"m2m:acp": {
            "rn": o["acp"]["rn"], "pv": {"acr": rules}, "pvs": {"acr": [{"acor": [origin], "acop": ALL}]}}})
        need("ACP Create rsc", rsc, 2001)
        acpi = [body["m2m:acp"]["ri"]]
        rsc, _ = onem2m("PUT", ae_url, origin, None, {"m2m:ae": {"acpi": acpi}})
        need("AE acpi Update rsc", rsc, 2004)
        # "cr": null asks the CSE to record the creator
        rsc, _ = onem2m("POST", ae_url, origin, TY_CNT, {"m2m:cnt": {"rn": o["container"], "acpi": acpi, "cr": None}})
        need("container Create rsc", rsc, 2001)
        rsc, _ = onem2m("POST", f"{ae_url}/{o['container']}", origin, TY_CIN, {"m2m:cin": {
            "cnf": "application/json:0", "con": json.dumps(READING, sort_keys=True), "cr": None}})
        need("reading Create rsc", rsc, 2001)
        st, _, _ = call("POST", f"{support}/applications/{inst}/confirm_ready", {"indication": "READY"})
        need("MEC 011 confirm_ready", st, 204)

    def say_goodbye() -> None:
        if made["inst"]:
            call("POST", f"{support}/applications/{made['inst']}/confirm_termination",
                 {"operationAction": "TERMINATING"})

    def drop_service() -> None:
        if made["inst"] and made["ser"]:
            call("DELETE", f"{services}/applications/{made['inst']}/services/{made['ser']}")

    def drop_ae() -> None:
        rsc, body = onem2m("GET", ae_url, origin)
        if rsc == 2000 and mine in body["m2m:ae"].get("lbl", []):
            onem2m("DELETE", ae_url, origin)

    def deregister() -> None:
        if made["inst"]:
            call("DELETE", f"{support}/registrations/{made['inst']}")

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    code = 0
    try:
        start()
        print("ready; waiting for the termination request", flush=True)
        while True:
            signal.pause()
    except Stop:
        print("termination requested", flush=True)
    except (Failed, OSError, KeyError, TypeError, ValueError) as e:
        print(f"FAILED {type(e).__name__}: {e}", flush=True)
        code = 3
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)       # the goodbye is not interrupted a second time
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for step in (say_goodbye, drop_service, drop_ae, deregister):
            try:
                step()
            except (OSError, KeyError, TypeError) as e:
                print(f"leaving: {step.__name__} failed: {e}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
