#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""A federated-learning party packaged as a MEC application (test plan TD_MEC_FL_01, on the TD_MEC_REG_03 path).
One program, shipped byte for byte the same in three packages; the package's appd.json says which role it plays:

    orchestrator   the FL Orchestrator AE (FL_01's pre-condition: REG_03 has passed for it)
    tfc            the Trusted FL Client, registered on behalf of the constrained devices named in fl.represents
    proxy          the MEC proxy path: takes a configured device's plain HTTP/JSON records and writes them, as sent,
                   into the oneM2M tree under its own AE

Started by the platform agent (the main tree's estimed/mec_app_deploy.py) as

    python3 -I -B fl_app.py --instance <instance.json>       # {"lcmInstanceId", "mec011", "cse"}

On start, in this order (as estimed/apps/sensor_ae does, plus what the role needs):
  0. proxy only: bind the device listener (it answers 503 until step 9)
  1. Mp1  register with MEC 011; 2. Mp1  offer one service whose transportInfo.id is the MEC 010-2 instance id and
     whose endpoint names this AE (and, for the proxy, the device listener)
  3. Mca  AE Create to its CSE under its own originator; it needs rsc 2001 and AE-ID == originator
  4. Mca  its metadata <ACP> (itself every operation, the named readers fl.readerOps, nobody else anything), put on
     the <AE>; 5. its baseline <container>
  6. tfc: a binding record in that container: the devices it acts for and both instance ids
     proxy: its data <ACP>; per configured device a <container> and a capability <flexContainer> of class
     proxy-path; its configuration as a record in the baseline container
  9. Mp1  confirm_ready -- only now; the proxy then admits device records
On SIGTERM: confirm_termination, remove the service, the <AE> (only if it carries this instance's label) and the
MEC 011 registration, exit 0. A start step that fails removes what was made and exits 3.

What the proxy admits (check_record): a configured device id, Content-Type application/json, at most maxBytes, a
JSON object whose keys are all configured fields, with an integer t. It writes the body text unchanged as the
content of one <contentInstance> and asks the CSE to record itself as the creator. A device is known by the id in
the path; nothing authenticates it (any process that can reach the listener can post as a configured device).

The device side is plain HTTP/JSON, what a MicroPython board can send:
    POST <endpoint>/<deviceId>/data   Content-Type: application/json   {"t": ..., "battery_pct": ..., ...}
    -> 201 {"stored": "<cse>/<ae>/<device>/<cin>", "ri": ...} | 4xx {"refused": why} | 502 {"rsc": ...}

Standard library only. The training and the orchestration logic are not in here: in this lab they run in the
driver (fl_run.py) under the AEs' own originators.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ALL = 63                                            # accessControlOperations: all six
TY_ACP, TY_AE, TY_CNT, TY_CIN, TY_FCNT = 1, 2, 3, 4, 28
CAP_CND = "org.onem2m.management.moduleclass.dmCapability"


class Stop(Exception):
    """The termination request arrived."""


class Failed(Exception):
    """A start step did not get the answer it needs."""


def _stop(*_):
    raise Stop


# ------------------------------------------------------------------------------------------------ pure parts
def check_record(raw: bytes, ctype: str | None, device: dict | None) -> tuple[int, str]:
    """The proxy's admission rule for one device post -> (HTTP status to refuse with, why); (0, "ok") admits."""
    if device is None:
        return 403, "device not configured at this proxy"
    if (ctype or "").split(";", 1)[0].strip().lower() != "application/json":
        return 415, "Content-Type must be application/json"
    if len(raw) > int(device.get("maxBytes", 1024)):
        return 413, f"more than {device.get('maxBytes', 1024)} bytes"
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return 400, "not JSON"
    if not isinstance(obj, dict):
        return 400, "not a JSON object"
    extra = sorted(set(obj) - set(device.get("fields", ())))
    if extra:
        return 400, f"fields not configured for this device: {extra}"
    if not isinstance(obj.get("t"), int) or isinstance(obj.get("t"), bool):
        return 400, "t must be an integer"
    return 0, "ok"


def cin_body(text: str) -> dict:
    """The <contentInstance> the proxy creates for one admitted record: the text as sent, the creator recorded."""
    return {"m2m:cin": {"cnf": "application/json:0", "con": text, "cr": None}}


def profile_body(device_id: str, via: str) -> dict:
    """The capability profile of a proxy-path device: a dmCapability flexContainer; such a device does not train."""
    return {"mad:dmCay": {"rn": f"flCap-{device_id}", "cnd": CAP_CND, "name": "fl.localTraining", "attad": False,
                          "curSe": False, "lbl": ["fl:profile", "fl:role:device", "fl:class:proxy-path",
                                                  f"fl:device:{device_id}", f"fl:via:{via}", "fl:sim:true"]}}


def acp_body(rn: str, origin: str, readers: list[str], ops: int) -> dict:
    rules = [{"acor": [origin], "acop": ALL}] + ([{"acor": list(readers), "acop": ops}] if readers else [])
    return {"m2m:acp": {"rn": rn, "pv": {"acr": rules}, "pvs": {"acr": [{"acor": [origin], "acop": ALL}]}}}


# ------------------------------------------------------------------------------------------------ the wire
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


# ------------------------------------------------------------------------------------------------ the proxy
class _Devices(BaseHTTPRequestHandler):
    """POST /devices/<deviceId>/data. self.server.app holds: ready, devices, origin, ae_url, cse, rn."""
    timeout = 5

    def _answer(self, status: int, obj: dict) -> None:
        out = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_POST(self):  # noqa: N802
        app = self.server.app
        parts = self.path.split("?", 1)[0].strip("/").split("/")
        if len(parts) != 3 or parts[0] != "devices" or parts[2] != "data":
            return self._answer(404, {"refused": "no such path"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._answer(400, {"refused": "bad Content-Length"})
        dev = app["devices"].get(parts[1])
        if dev is None:                                   # nothing of an unknown device is read or forwarded
            print(f"refused {parts[1]}: 403 not configured", flush=True)
            return self._answer(403, {"refused": "device not configured at this proxy"})
        limit = int(dev.get("maxBytes", 1024))
        if n < 0 or n > limit:
            return self._answer(413, {"refused": f"more than {limit} bytes"})
        raw = self.rfile.read(n)
        if not app["ready"].is_set():
            return self._answer(503, {"refused": "not ready"})
        status, why = check_record(raw, self.headers.get("Content-Type"), dev)
        if status:
            print(f"refused {parts[1]}: {status} {why}", flush=True)
            return self._answer(status, {"refused": why})
        rsc, body = onem2m("POST", f"{app['ae_url']}/{parts[1]}", app["origin"], TY_CIN, cin_body(raw.decode("utf-8")))
        if rsc != 2001:
            return self._answer(502, {"rsc": rsc})
        cin = (body or {}).get("m2m:cin", {})
        return self._answer(201, {"stored": f"{app['cse']}/{app['rn']}/{parts[1]}/{cin.get('rn')}", "ri": cin.get("ri")})

    def do_GET(self):  # noqa: N802
        self._answer(405, {"refused": "POST only"})

    do_PUT = do_DELETE = do_PATCH = do_GET

    def log_message(self, *a):
        pass


# ------------------------------------------------------------------------------------------------ main
def main() -> int:  # noqa: C901, PLR0915
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    cfg = json.loads(Path(ap.parse_args().instance).read_text())
    desc = json.loads((Path(__file__).resolve().parent / "appd.json").read_text())
    o, f = desc["onem2m"], desc["fl"]
    role, origin, lcm = f["role"], o["originator"], cfg["lcmInstanceId"]
    cse_name = cfg["cse"].rstrip("/").rsplit("/", 1)[-1]
    ae_url, mine = f"{cfg['cse']}/{o['rn']}", f"mec:lcmInstanceId:{lcm}"
    support, services = f"{cfg['mec011']}/mec_app_support/v2", f"{cfg['mec011']}/mec_service_mgmt/v1"
    made = {"inst": None, "ser": None}
    devs = {d["deviceId"]: d for d in f.get("devices", [])} if role == "proxy" else {}
    srv, dev_url = None, None
    if role == "proxy":
        host, port = f.get("listen", "127.0.0.1:0").rsplit(":", 1)
        srv = ThreadingHTTPServer((host, int(port)), _Devices)
        srv.daemon_threads = True
        srv.app = {"ready": threading.Event(), "devices": devs, "origin": origin, "ae_url": ae_url, "cse": cse_name,
                   "rn": o["rn"]}
        dev_url = f"http://{srv.server_address[0]}:{srv.server_address[1]}/devices"
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()

    def start() -> None:
        st, body, _ = call("POST", f"{support}/registrations", {"appName": desc["appName"], "appInstanceId": lcm})
        need("MEC 011 registration", st, 201)
        inst = made["inst"] = body["appInstanceId"]
        st, body, _ = call("POST", f"{services}/applications/{inst}/services", {
            "serName": f["service"], "version": desc["appSoftVersion"], "state": "ACTIVE", "serializer": "JSON",
            "transportInfo": {"id": lcm, "name": "oneM2M AE", "type": "REST_HTTP", "protocol": "HTTP", "version": "1.1",
                              "security": {}, "endpoint": {"uris": [ae_url] + ([dev_url] if dev_url else [])}}})
        need("MEC 011 service", st, 201)
        made["ser"] = body["serInstanceId"]
        labels = [*f["labels"], *(f"fl:represents:{d}" for d in f.get("represents", ())),
                  f"mec:appInstanceId:{inst}", mine]
        rsc, body = onem2m("POST", cfg["cse"], origin, TY_AE, {"m2m:ae": {
            "rn": o["rn"], "api": o["api"], "rr": False, "srv": ["4"], "lbl": labels}})
        need("AE Create rsc", rsc, 2001)
        need("AE-ID", body["m2m:ae"]["aei"], origin)
        rsc, body = onem2m("POST", ae_url, origin, TY_ACP, acp_body(o["acp"]["rn"], origin, o["acp"]["readers"], f["readerOps"]))
        need("metadata ACP Create rsc", rsc, 2001)
        meta = [body["m2m:acp"]["ri"]]
        rsc, _ = onem2m("PUT", ae_url, origin, None, {"m2m:ae": {"acpi": meta}})
        need("AE acpi Update rsc", rsc, 2004)
        rsc, _ = onem2m("POST", ae_url, origin, TY_CNT, {"m2m:cnt": {"rn": o["container"], "acpi": meta, "cr": None}})
        need("baseline container Create rsc", rsc, 2001)
        base = f"{ae_url}/{o['container']}"
        if role == "tfc":
            rsc, _ = onem2m("POST", base, origin, TY_CIN, cin_body(json.dumps({"kind": "binding", "record": {
                "client": origin, "represents": list(f["represents"]), "lcmInstanceId": lcm, "mec011AppInstanceId": inst,
                "package": f"{desc['appName']} {desc['appSoftVersion']}", "sim": True}}, sort_keys=True)))
            need("binding record Create rsc", rsc, 2001)
        if role == "proxy":
            d = f["dataAcp"]
            rsc, body = onem2m("POST", ae_url, origin, TY_ACP, acp_body(d["rn"], origin, d["readers"], d["ops"]))
            need("data ACP Create rsc", rsc, 2001)
            data = [body["m2m:acp"]["ri"]]
            for dev in devs:
                rsc, _ = onem2m("POST", ae_url, origin, TY_CNT, {"m2m:cnt": {"rn": dev, "acpi": data, "cr": None}})
                need(f"device container {dev} Create rsc", rsc, 2001)
                pb = profile_body(dev, o["rn"])
                pb["mad:dmCay"]["acpi"] = meta
                rsc, _ = onem2m("POST", ae_url, origin, TY_FCNT, pb)
                need(f"device profile {dev} Create rsc", rsc, 2001)
            rsc, _ = onem2m("POST", base, origin, TY_CIN, cin_body(json.dumps({"kind": "proxy-config", "record": {
                "proxy": origin, "endpoint": dev_url, "lcmInstanceId": lcm, "mec011AppInstanceId": inst,
                "devices": [{k: v[k] for k in ("deviceId", "class", "fields", "maxBytes")} for v in devs.values()],
                "sim": True}}, sort_keys=True)))
            need("configuration record Create rsc", rsc, 2001)
        st, _, _ = call("POST", f"{support}/applications/{inst}/confirm_ready", {"indication": "READY"})
        need("MEC 011 confirm_ready", st, 204)
        if srv is not None:
            srv.app["ready"].set()

    def say_goodbye() -> None:
        if made["inst"]:
            call("POST", f"{support}/applications/{made['inst']}/confirm_termination", {"operationAction": "TERMINATING"})

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

    def close_listener() -> None:
        if srv is not None:
            srv.app["ready"].clear()
            srv.shutdown()
            srv.server_close()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    code = 0
    try:
        start()
        print(f"ready ({role}); waiting for the termination request", flush=True)
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
        for step in (close_listener, say_goodbye, drop_service, drop_ae, deregister):
            try:
                step()
            except (OSError, KeyError, TypeError) as e:
                print(f"leaving: {step.__name__} failed: {e}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
