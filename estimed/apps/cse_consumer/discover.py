#!/usr/bin/env python3
"""A MEC application that finds its MN-CSE through MEC 011 service discovery (TR-0086 deployment option D), accepts it
only if the IN-CSE holds it, and runs the sensor AE on it.

Started by the platform agent (estimed/mec_app_deploy.py) as

    python3 -I -B discover.py --instance <instance.json>

instance.json is what the platform tells this instance: {"lcmInstanceId", "mec011", "cse"}. For this package "cse" is
the platform's address of the CSE the descriptor names in onem2m.mnCse, which here is the IN-CSE (cse-in): the
registrar the MN-CSE must be registered at. The MN-CSE's own address is never taken from the platform.

  1. Mp1  GET {mec011}/mec_service_mgmt/v1/services?ser_name=<appServiceRequired[0].serName>, i.e. onem2m-mn-cse
  2. takes the one ACTIVE service whose endpoint is the CSEBase URI of a CSE named onem2m.edgeCse
     (http://<host>:<port>/<name>, nothing after it). None, or more than one, and it exits 3 having created nothing
     anywhere and asked no CSE anything: it has not even registered with MEC 011.
  3. the IN check, before anything is created: the two reads of estimed/handover.py registered_mn, sent as its
     orchestrator sends them (originator CAdmin). The endpoint must answer 200 as a middle node (cst 2) with a CSE-ID,
     and the IN must answer 200 with a <remoteCSE> of that CSE-ID, cst 2. Otherwise, or if either does not answer, it
     exits 3, having created nothing.
  4. writes instance.discovered.json beside the platform's instance.json, "cse" being the endpoint it found, and
     execs sensor_ae.py on it (a byte-for-byte copy of estimed/apps/sensor_ae/sensor_ae.py). exec keeps the process,
     so the platform's termination request reaches the AE, which then leaves as it always does.

What remains open, plainly:
  * registration and service registration at our MEC 011 are unauthenticated: any local process can offer an
    onem2m-mn-cse service. A second ACTIVE one at a CSEBase of that name makes step 2 refuse, so a stray can still
    stop this consumer from starting (it is refused, not resolved: the consumer contacts no endpoint when two are
    offered).
  * step 3 is registered_mn's check and no more. It does not compare the IN's <remoteCSE> (its poa) with the
    endpoint, and urllib follows a redirect, as handover's reads do: a stray that answers with a CSE-ID the IN holds,
    or redirects the read to the CSE that has it, passes. Nothing authenticates either CSE or the originator CAdmin
    (plain HTTP; ACME takes the originator it is told).

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
READER = "CAdmin"                       # handover.ORCHESTRATOR: the originator registered_mn reads as


class Failed(Exception):
    """Discovery did not find exactly one MN-CSE, or the IN does not hold the one it found."""


def choose(listed, ser_name: str, cse_name: str) -> tuple[str, str]:
    """(endpoint, serInstanceId) of the one ACTIVE service `ser_name` whose endpoint is the CSEBase URI of a CSE named
    `cse_name`. None or several is refused: the AE registers to no CSE rather than to a guessed one."""
    hits = []
    for s in listed if isinstance(listed, list) else []:
        if not isinstance(s, dict) or s.get("serName") != ser_name or s.get("state") != "ACTIVE":
            continue
        ti = s.get("transportInfo")
        ep = ti.get("endpoint") if isinstance(ti, dict) else None
        uris = ep.get("uris") if isinstance(ep, dict) else None
        for u in uris if isinstance(uris, list) else []:
            if not isinstance(u, str):
                continue
            p = urllib.parse.urlsplit(u)
            try:
                port = p.port
            except ValueError:
                continue
            if p.scheme == "http" and p.hostname and port and p.path == f"/{cse_name}" and not (p.query or p.fragment):
                hits.append((u, s.get("serInstanceId")))
    if len(hits) != 1:
        raise Failed(f"MEC service {ser_name!r} at a CSEBase named {cse_name!r}: found {len(hits)}, need 1")
    return hits[0]


def retrieve(url: str) -> tuple[int, dict | None]:
    """One oneM2M RETRIEVE as READER -> (http status, parsed body or None), the request handover._req sends.
    No answer at all raises OSError."""
    r = urllib.request.Request(url, method="GET", headers={
        "X-M2M-Origin": READER, "X-M2M-RI": f"disc{uuid.uuid4().hex[:8]}", "X-M2M-RVI": "4",
        "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except ValueError:
            return e.code, None


def registered_mn(endpoint: str, in_base: str) -> tuple[bool, str]:
    """estimed/handover.py registered_mn, line for line, with the CSE given as its CSEBase URI and the IN as the
    platform names it: a middle node (cst 2) for which the IN holds a <remoteCSE>. (False, why) otherwise; no answer
    raises OSError, as there."""
    st, body = retrieve(endpoint)
    c = (body or {}).get("m2m:cb", {}) if st == 200 else {}
    if c.get("cst") != 2 or not isinstance(c.get("csi"), str):
        return False, f"{endpoint} answered {st} with cst {c.get('cst')!r}, not a middle node (2)"
    st, body = retrieve(f"{in_base}/{c['csi'].lstrip('/')}")
    r = (body or {}).get("m2m:csr", {}) if st == 200 else {}
    if r.get("csi") != c["csi"] or r.get("cst") != 2:
        return False, f"the IN holds no <remoteCSE> for {c['csi']} ({st})"
    return True, c["csi"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    path = Path(ap.parse_args().instance)
    cfg = json.loads(path.read_text())
    desc = json.loads((HERE / "appd.json").read_text())
    try:
        ser_name, cse_name = desc["appServiceRequired"][0]["serName"], desc["onem2m"]["edgeCse"]
        url = f"{cfg['mec011']}/mec_service_mgmt/v1/services?ser_name={urllib.parse.quote(ser_name)}"
        r = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                status, listed = resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            status, listed = e.code, None
        if status != 200:
            raise Failed(f"MEC 011 service discovery answered {status}")
        cse, ser = choose(listed, ser_name, cse_name)
        ok, why = registered_mn(cse, cfg["cse"])
        if not ok:
            raise Failed(f"{cse} is not an MN-CSE the IN-CSE holds: {why}")
        print(f"the IN-CSE holds {why}, which answers at {cse}", flush=True)
    except (Failed, OSError, AttributeError, KeyError, IndexError, TypeError, ValueError) as e:
        print(f"FAILED {type(e).__name__}: {e}", flush=True)
        return 3
    found = path.with_name("instance.discovered.json")
    found.write_text(json.dumps({"lcmInstanceId": cfg["lcmInstanceId"], "mec011": cfg["mec011"], "cse": cse,
                                 "serInstanceId": ser}))
    print(f"found {ser_name} {ser} at {cse}; running the sensor AE on it", flush=True)
    os.execv(sys.executable, [sys.executable, "-I", "-B", str(HERE / "sensor_ae.py"), "--instance", str(found)])
    return 0                                                # not reached


if __name__ == "__main__":
    sys.exit(main())
