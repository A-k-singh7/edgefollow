#!/usr/bin/env python3
"""The lab's MEC-IPE packaged as a MEC application: oneM2M TR-0086 deployment option A.

Option A (developer guide 5.2.2): the MEC-IPE runs as a MEC application on the MEC host, the IN-CSE is in the cloud,
and there is no MN-CSE on the edge. The IPE registers as an <AE> directly at the IN-CSE over Mca.

Started by the platform agent (estimed/mec_app_deploy.py) as

    python3 -I -B mec_ipe_app.py --instance <instance.json> --mec013 <MEC 013 root> --operator <originator>

instance.json is what the platform tells this instance: {"lcmInstanceId", "mec011", "cse"}. "cse" is the one CSE the
platform names; for option A that is the IN-CSE. mec_ipe.py and handover.py beside this file are the lab's own
(estimed/mec_ipe.py, estimed/handover.py), byte for byte; this file adds the MEC lifecycle around them and nothing
to what the IPE does.

On start, in this order:
  1. Mp1  registers its instance with MEC 011 and offers a service that names its <AE> at the CSE
  2. Mca  starts the IPE against that CSE: a notification listener on a port the system picks (the <AE>'s poa), then
          mec_ipe.Ipe.register() -- the <AE>, its two <ACP>s, three <container>s and two <subscription>s
  3. Mca  labels the <AE> with this instance's two identifiers and reads it back against appd.json
  4. Mp1  confirm_ready -- only now
On SIGTERM (the termination request): confirm_termination, removes its service, stops the report streams, deletes the
<AE> if its poa is this process, deregisters from MEC 011, exits 0. A start step that fails (mec_ipe refuses to
replace a live IPE, a CSE answer it does not expect) undoes what it made and exits 3. It never deletes an <AE> whose
poa is not its own, so a second instance leaves the first one's IPE alone.

The MEC 013 address is an argument: the platform's MEC 011 does not offer a location service to discover.

Standard library only, plus the two lab modules beside it.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))           # -I keeps the script's folder off sys.path; this puts the package's own back

import mec_ipe  # noqa: E402  the lab's IPE, carried byte for byte
from handover import _req  # noqa: E402


class Stop(Exception):
    """The termination request arrived."""


class Failed(Exception):
    """A start step did not get the answer it needs."""


def _stop(*_):
    raise Stop


def call(method: str, url: str, body=None):
    """One MEC REST call -> (status, parsed body or None)."""
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                               headers={"Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    try:
        return status, (json.loads(raw) if raw else None)
    except ValueError:
        return status, None


def need(what: str, got, want) -> None:
    if got != want:
        raise Failed(f"{what}: got {got!r}, need {want!r}")
    print(f"{what}: {got}", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    ap.add_argument("--mec013", required=True)
    ap.add_argument("--operator", action="append", required=True)
    args = ap.parse_args()
    cfg = json.loads(Path(args.instance).read_text())
    desc = json.loads((HERE / "appd.json").read_text())
    o = desc["onem2m"]
    host, _, cb = cfg["cse"].rstrip("/").rpartition("/")
    support, services = f"{cfg['mec011']}/mec_app_support/v2", f"{cfg['mec011']}/mec_service_mgmt/v1"
    mine = f"mec:lcmInstanceId:{cfg['lcmInstanceId']}"
    ipe = mec_ipe.Ipe((host, cb), 0, args.mec013, args.operator)
    made = {"inst": None, "ser": None, "srv": None}

    def own_poa() -> list[str]:
        return [f"http://127.0.0.1:{ipe.port}"]

    def start() -> None:
        # what the descriptor says the app is, against what the IPE code will register
        need("CSEBase", cb, o["mnCse"])
        need("originator", o["originator"], mec_ipe.IPE_ORIGIN)
        need("resource name", o["rn"], mec_ipe.IPE_NAME)
        st, body = call("POST", f"{support}/registrations",
                        {"appName": desc["appName"], "appInstanceId": cfg["lcmInstanceId"]})
        need("MEC 011 registration", st, 201)
        inst = made["inst"] = body["appInstanceId"]          # MEC 011 hands out its own identifier
        st, body = call("POST", f"{services}/applications/{inst}/services", {
            "serName": desc["appName"], "version": desc["appSoftVersion"], "state": "ACTIVE", "serializer": "JSON",
            "transportInfo": {"id": cfg["lcmInstanceId"], "name": "oneM2M MEC-IPE AE", "type": "REST_HTTP",
                              "protocol": "HTTP", "version": "1.1", "security": {},
                              "endpoint": {"uris": [f"{cfg['cse']}/{o['rn']}"]}}})
        need("MEC 011 service", st, 201)
        made["ser"] = body["serInstanceId"]
        srv = made["srv"] = mec_ipe.serve(ipe)               # listen before the CSE verifies the subscriptions' nu
        ipe.port = srv.server_address[1]
        ipe.register()                                       # SystemExit if refused, a live IPE among the reasons
        st, body = _req("GET", ipe.base, o["originator"])
        need("IPE AE read back", st, 200)
        ae = body["m2m:ae"]
        need("AE-ID", ae.get("aei"), o["originator"])
        need("App-ID", ae.get("api"), o["api"])
        need("poa", ae.get("poa"), own_poa())
        st, _ = _req("PUT", ipe.base, o["originator"], body={"m2m:ae": {
            "lbl": [*ae.get("lbl", []), f"mec:appInstanceId:{inst}", mine]}})
        need("AE label Update", st, 200)
        for rn in (o["acp"]["rn"], o["container"]):
            need(f"{rn} read back", _req("GET", f"{ipe.base}/{rn}", o["originator"])[0], 200)
        st, _ = call("POST", f"{support}/applications/{inst}/confirm_ready", {"indication": "READY"})
        need("MEC 011 confirm_ready", st, 204)

    def say_goodbye() -> None:
        if made["inst"]:
            call("POST", f"{support}/applications/{made['inst']}/confirm_termination",
                 {"operationAction": "TERMINATING"})

    def drop_service() -> None:
        if made["inst"] and made["ser"]:
            call("DELETE", f"{services}/applications/{made['inst']}/services/{made['ser']}")

    def drop_ipe() -> None:
        with ipe.lock:
            for stop in ipe.workers.values():
                stop.set()
        if made["srv"] is None:
            return
        st, body = _req("GET", ipe.base, o["originator"])
        if st == 200 and (body or {}).get("m2m:ae", {}).get("poa") == own_poa():
            ipe.deregister()                                 # this process's AE: streams stopped, AE deleted
        made["srv"].shutdown()
        made["srv"].server_close()

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
    except (Failed, SystemExit, OSError, KeyError, TypeError, ValueError) as e:
        print(f"FAILED {type(e).__name__}: {e}", flush=True)
        code = 3
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)        # the goodbye is not interrupted a second time
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for step in (say_goodbye, drop_service, drop_ipe, deregister):
            try:
                step()
            except (OSError, KeyError, TypeError, ValueError) as e:
                print(f"leaving: {step.__name__} failed: {e}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
