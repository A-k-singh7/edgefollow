#!/usr/bin/env python3
"""ESTIMED Hackathon #2 -- MEC Interworking Proxy Entity (MEC-IPE) for location.

oneM2M TR-0086 5.6.3 / 5.6.4: network-provided location (ETSI GS MEC 013) delivered
into the oneM2M resource tree. The IPE is an AE on an MN-CSE:

    <AE mec-ipe>            lbl role:mec-ipe, poa = this process
      ├── <ACP operator>        IN-side originators: CREATE contentInstances only
      ├── <ACP requesters>      any originator:      CREATE contentInstances only
      ├── <container ue-registry>        operator writes {"aeId", "ueIdentity"}
      ├── <container location>           5.6.3: operator requests {"ueIdentity",
      │                                   "notificationUri", "notificationPeriod"}
      └── <container location-requests>  5.6.4: device requests {"aeId",
                                          "targetContainer", "notificationPeriod"}

A device names only itself. Its UE identity comes from ue-registry, which only the
operator can write; a device that could name its own UE identity could read
anybody's location into its own container. A device request is honoured only if
the contentInstance's creator (cr) is the aeId it names, so it must be created with
"cr": null.

The IPE writes each report as a <contentInstance> into the target container, so
the target has to grant the IPE originator CREATE -- the device's own <ACP> decides
whether the IPE may write there at all. It must also grant the IPE RETRIEVE on that
container: the IPE writes only into a container whose parent is the requesting AE
(its pi is the AE-ID -- ACME gives an AE the AE-ID as its resource ID; a CSE that
does not is refused every request, fail-closed). Without it, a registered device could
have its own location written into another device's container (2026-10-29).

One IPE per CSE: a start is refused while the registered IPE's poa still answers; a
stale AE (its poa refuses connections) is replaced.

MEC 013 is read through its query API (GET /location/v3/queries/users?address=)
every notificationPeriod seconds. TR-0086 describes a MEC 013 subscription with a
callback instead; the local MEC 013 subscription candidate stores subscriptions but
never sends notifications, so polling is what actually delivers data here.

    python3 mec_ipe.py --edge a          # registers on MN-CSE-A, listens on :8410

Standard library only, like handover.py.
"""
from __future__ import annotations

import argparse
import json
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from handover import EDGE_A, EDGE_B, IN_CSE, _req

IPE_NAME = "mec-ipe"
IPE_ORIGIN = "Cmec-ipe"
MEC013 = "http://127.0.0.1:8101/location/v3"
OPERATOR_ORIGINATORS = ["CAdmin"]

TY_ACP, TY_AE, TY_CNT, TY_CIN, TY_SUB = 1, 2, 3, 4, 23
CREATE, RETRIEVE, UPDATE, DELETE, NOTIFY, DISCOVER = 1, 2, 4, 8, 16, 32
ALL = CREATE | RETRIEVE | UPDATE | DELETE | NOTIFY | DISCOVER

MIN_PERIOD = 1


def log(msg: str) -> None:
    print(f"[mec-ipe {datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def _answers(url: str) -> bool:
    """Does anything accept connections at url's host:port? A refused or timed-out connect means a stale AE."""
    try:
        host, _, port = url.split("://", 1)[1].split("/", 1)[0].rpartition(":")
        with socket.create_connection((host, int(port)), timeout=1):
            return True
    except (OSError, ValueError, IndexError):
        return False


class Ipe:
    def __init__(self, edge, port: int, mec013: str, operators: list[str]):
        self.host, self.cb = edge
        self.port = port
        self.mec013 = mec013.rstrip("/")
        self.operators = operators
        self.base = f"{self.host}/{self.cb}/{IPE_NAME}"
        self.workers: dict[tuple[str, str], threading.Event] = {}  # (owner, target) -> stop flag
        self.routes: dict[str, str] = {}                   # subscription ri -> container rn
        self.lock = threading.Lock()

    # --- oneM2M side -----------------------------------------------------------------

    def register(self) -> None:
        """Create the IPE AE and its tree. A stale AE from an earlier run is replaced; a live one is not."""
        st, body = _req("GET", self.base, IPE_ORIGIN)
        if st == 200 and any(_answers(u) for u in ((body or {}).get("m2m:ae") or {}).get("poa", [])):
            raise SystemExit(f"a live MEC-IPE already holds {self.base} (poa "
                             f"{body['m2m:ae']['poa']}); not replacing it")
        _req("DELETE", self.base, IPE_ORIGIN)
        st, body = _req("POST", f"{self.host}/{self.cb}", IPE_ORIGIN, ty=TY_AE, body={"m2m:ae": {
            "rn": IPE_NAME, "api": "Nestimed.mec-ipe", "rr": True, "srv": ["4"],
            "poa": [f"http://127.0.0.1:{self.port}"],
            "lbl": ["role:mec-ipe", "mec:service:location"]}})
        if st != 201:
            raise SystemExit(f"IPE AE registration refused: {st} {body}")

        def acp(rn, who):
            st, body = _req("POST", self.base, IPE_ORIGIN, ty=TY_ACP, body={"m2m:acp": {
                "rn": rn,
                "pv": {"acr": [{"acor": [IPE_ORIGIN], "acop": ALL},
                               {"acor": who, "acop": CREATE, "acod": [{"chty": [TY_CIN]}]}]},
                "pvs": {"acr": [{"acor": [IPE_ORIGIN], "acop": ALL}]}}})
            if st != 201:
                raise SystemExit(f"ACP {rn} refused: {st} {body}")
            return body["m2m:acp"]["ri"]

        operator = acp("operator", self.operators)
        requesters = acp("requesters", ["all"])
        for rn, acpi in (("ue-registry", operator), ("location", operator),
                         ("location-requests", requesters)):
            st, body = _req("POST", self.base, IPE_ORIGIN, ty=TY_CNT,
                            body={"m2m:cnt": {"rn": rn, "acpi": [acpi], "mni": 100}})
            if st != 201:
                raise SystemExit(f"container {rn} refused: {st} {body}")
        for rn in ("location", "location-requests"):
            st, body = _req("POST", f"{self.base}/{rn}", IPE_ORIGIN, ty=TY_SUB, body={"m2m:sub": {
                "rn": "ipe", "nu": [f"http://127.0.0.1:{self.port}/notify"], "enc": {"net": [3]}}})
            if st != 201:
                raise SystemExit(f"subscription on {rn} refused: {st} {body}")
            # ACME names the subscription in a notification's `sur` by its unstructured
            # id (/id-mn-a/subXXXX), not by path, so route on the ri it assigned.
            self.routes[body["m2m:sub"]["ri"]] = rn
        log(f"registered at {self.base}")

    def deregister(self) -> None:
        with self.lock:
            for stop in self.workers.values():
                stop.set()
        _req("DELETE", self.base, IPE_ORIGIN)
        log("deregistered")

    def ue_identity(self, ae_id: str) -> str | None:
        """The operator's mapping for this AE-ID; the newest registry entry wins."""
        st, body = _req("GET", f"{self.base}/ue-registry?fu=1&ty={TY_CIN}", IPE_ORIGIN)
        if st != 200 or not body:
            return None
        found = None
        for uri in body.get("m2m:uril", []):
            s, b = _req("GET", f"{self.host}/{uri}", IPE_ORIGIN)
            if s != 200 or not b:
                continue
            cin = b["m2m:cin"]
            try:
                entry = json.loads(cin["con"])
            except (ValueError, TypeError):
                continue
            if entry.get("aeId") == ae_id and (found is None or cin["ct"] > found[0]):
                found = (cin["ct"], entry.get("ueIdentity"))
        return found[1] if found else None

    # --- requests ----------------------------------------------------------------------

    def on_notification(self, note: dict) -> None:
        sgn = note.get("m2m:sgn", {})
        cin = sgn.get("nev", {}).get("rep", {}).get("m2m:cin")
        if not cin:
            return
        source = self.routes.get(sgn.get("sur", "").rsplit("/", 1)[-1])
        try:
            req = json.loads(cin["con"])
        except (ValueError, TypeError):
            log(f"ignored: content is not JSON ({source})")
            return
        if source == "location-requests":
            self.device_request(req, cin.get("cr"))
        elif source == "location":
            self.operator_request(req)
        else:
            log(f"ignored: notification from unknown subscription {sgn.get('sur')!r}")

    def device_request(self, req: dict, creator: str | None) -> None:
        """TR-0086 5.6.4: the device asks for its own network location."""
        ae_id = req.get("aeId")
        if not ae_id or creator != ae_id:
            log(f"refused: request names {ae_id!r} but was created by {creator!r}")
            return
        target = req.get("targetContainer")
        if not self.owned_by(target, ae_id):
            log(f"refused: {target!r} is not a container of {ae_id}")
            return
        ue = self.ue_identity(ae_id)
        if not ue:
            log(f"refused: no ue-registry entry for {ae_id}")
            return
        self.start(ae_id, ue, target, req.get("notificationPeriod"), req.get("count"))

    def owned_by(self, target, ae_id: str) -> bool:
        """Is target a container on this CSE directly under the AE ae_id? Read as the IPE (the device grants it
        RETRIEVE); its pi must be the requester's AE resource ID, which ACME makes the AE-ID."""
        if not isinstance(target, str) or not target.startswith(f"{self.cb}/"):
            return False
        st, body = _req("GET", f"{self.host}/{target}", IPE_ORIGIN)
        cnt = (body or {}).get("m2m:cnt") if st == 200 else None
        return isinstance(cnt, dict) and cnt.get("pi") == ae_id

    def operator_request(self, req: dict) -> None:
        """TR-0086 5.6.3: the IN-side operator names the UE directly."""
        self.start("operator", req.get("ueIdentity"), req.get("notificationUri"),
                   req.get("notificationPeriod"), req.get("count"))

    def start(self, owner, ue, target, period, count) -> None:
        """Start, replace or cancel the report stream `owner` has into `target`.

        Streams are keyed by (owner, target): a request can only replace or cancel
        the requester's own stream, never another device's stream into the same
        container.
        """
        if not ue or not target:
            log(f"refused: ueIdentity {ue!r}, target {target!r}")
            return
        key = (owner, target)
        with self.lock:
            if (old := self.workers.pop(key, None)) is not None:
                old.set()                                   # a new request replaces the old one
            if not period:                                  # period 0 / absent = cancel
                log(f"cancelled {owner}'s reports to {target}")
                return
            stop = threading.Event()
            self.workers[key] = stop
        period = max(MIN_PERIOD, float(period))
        threading.Thread(target=self.report_loop, args=(key, ue, period, count, stop),
                         daemon=True).start()
        log(f"reporting {ue} -> {target} every {period:g}s for {owner}"
            + (f", {count} times" if count else ""))

    def report_loop(self, key, ue, period, count, stop: threading.Event) -> None:
        target = key[1]
        sent = 0
        while not stop.is_set() and (not count or sent < count):
            fix = self.locate(ue)
            if fix is None:
                log(f"MEC 013 has no location for {ue}; retrying")
            else:
                st, body = _req("POST", f"{self.host}/{target}", IPE_ORIGIN, ty=TY_CIN, body={
                    "m2m:cin": {"cnf": "application/json:0", "con": json.dumps(fix)}})
                if st != 201:
                    log(f"stopped {target}: write refused {st} {(body or {}).get('m2m:dbg', '')}")
                    break
                sent += 1
            stop.wait(period)
        with self.lock:
            if self.workers.get(key) is stop:
                del self.workers[key]

    # --- MEC 013 side -----------------------------------------------------------------

    def locate(self, ue: str) -> dict | None:
        url = f"{self.mec013}/queries/users?address={urllib.request.quote(ue, safe=':')}"
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                users = json.loads(r.read()).get("user", [])
        except (OSError, ValueError):
            return None
        if not users:
            return None
        u = users[0]
        li = u.get("locationInfo", {})
        return {"lat": li.get("latitude"), "lon": li.get("longitude"),
                "zoneId": u.get("zoneId"), "accessPointId": u.get("accessPointId"),
                "ueIdentity": u.get("address"), "source": "MEC013",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")}


def serve(ipe: Ipe) -> ThreadingHTTPServer:
    class Notify(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("X-M2M-RSC", "2000")
            self.send_header("X-M2M-RI", self.headers.get("X-M2M-RI", ""))
            self.send_header("Content-Length", "0")
            self.end_headers()
            try:
                note = json.loads(raw) if raw else {}
            except ValueError:
                return
            if isinstance(note, dict):
                threading.Thread(target=ipe.on_notification, args=(note,), daemon=True).start()

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", ipe.port), Notify)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    # "in": TR-0086 5.2.4.6.1 option A -- no MN-CSE at the edge, the IPE registers directly with the IN-CSE over Mca.
    ap.add_argument("--edge", choices=("a", "b", "in"), default="a")
    ap.add_argument("--port", type=int, default=8410)
    ap.add_argument("--mec013", default=MEC013)
    ap.add_argument("--operator", action="append", default=None,
                    help="IN-side originator allowed to write ue-registry/location (repeatable)")
    args = ap.parse_args()
    ipe = Ipe({"a": EDGE_A, "b": EDGE_B, "in": IN_CSE}[args.edge], args.port, args.mec013,
              args.operator or OPERATOR_ORIGINATORS)
    srv = serve(ipe)                                      # listen before the CSE verifies the nu
    try:
        ipe.register()
    except SystemExit:
        srv.shutdown()
        raise
    done = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: done.set())
    done.wait()
    ipe.deregister()
    srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
