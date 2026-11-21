#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""ESTIMED Hackathon #2 -- MEC-driven oneM2M edge continuity across MEC systems.

Step 4b: the MEC services decide *whether* to hand over and *where to*, and the
verified oneM2M handover from step 4a executes it.

    MEC 013 Location   :8101  where the vehicle is
    MEC 012 RNIS       :8085  radio conditions -> handover due
    MEC 040 Federation :8300  which peer MEC system, and its endpoint
    oneM2M             :8200/8201/8202  IN-CSE + two edge MN-CSEs

Why federation is the point. ESTIMED publishes six use cases (autonomous
vehicles, future home, industrial digital twins, metaverse smart shopping, smart
city, smart warehouse) and **none of them involves MEC federation, inter-MEC-system
communication, multi-operator scenarios or roaming**. Continuity across a journey
is exactly where an edge handover stops being intra-system, so MEC 040 is what
makes "continuous edge computing" honest rather than a single-operator demo.

Scope, stated plainly: MEC 040's ATS surface is `fed_resources/system_info`, i.e.
federation **discovery** -- which peer systems exist and how to reach them. It is
not app-instance transfer. This scenario uses it for what it is: the peer lookup
that tells the handover where to go.

    python3 scenario.py          # run once
    python3 scenario.py --json   # machine-readable result
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

from handover import (EDGE_A, EDGE_B, AE_NAME, add_sample, create_ae, edges_ok,
                      create_container, handover, read_samples, registered_edges,
                      reset)

LOCATION = "http://127.0.0.1:8101/location/v3"
RNIS = "http://127.0.0.1:8085/rni/v2"
# MEC 040 federation base. Override to point the handover at an external peer, e.g.
#   EDGEFOLLOW_FED_BASE=https://try-mec.etsi.org/<sbxid>/mep1/fed_enablement/v1
FED_BASE = os.environ.get("EDGEFOLLOW_FED_BASE",
                          "http://127.0.0.1:8300/fed_enablement/v1").rstrip("/")

# The RESOURCE NAME is not agreed across the ecosystem. Measured 2026-08-31 against
# ETSI's own published definition and its own live sandbox:
#
#   GS MEC 040 OpenAPI (v3.1.1)  ->  /fed_resources/system_info
#   ETSI ATS release 3.3.1       ->  /fed_resources/system_info
#   ETSI live sandbox            ->  /fed_resources/systems     (system_info 404s)
#
# ETSI's suite and ETSI's reference implementation disagree with each other, so a client
# that has to talk to both must tolerate both. The spec/ATS name is tried FIRST so the
# spec-conformant path is the default and the sandbox spelling is the fallback, never the
# other way round.
#
# NOTE: this tolerance belongs to the DEMO client only. The MEC 040 conformance candidate (scored against ETSI's
# test suite; not in this repository) stays exactly ATS-shaped -- do not port this there.
FED_RESOURCES = ("fed_resources/system_info", "fed_resources/systems")

# The cell the vehicle starts under, as the RNIS candidate knows it.
HOME_CELL = "6060606"


def _get(url: str) -> tuple[int, object]:
    try:
        with urllib.request.urlopen(urllib.request.Request(
                url, headers={"Accept": "application/json"}), timeout=10) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return 0, None


def locate_vehicle() -> dict | None:
    """MEC 013: the vehicle's current access point and zone."""
    st, body = _get(f"{LOCATION}/queries/users")
    if st != 200 or not isinstance(body, dict):
        return None
    users = body.get("user") or []
    return users[0] if users else None


def radio_conditions(cell_id: str = HOME_CELL) -> dict | None:
    """MEC 012: RAB information for the serving cell."""
    st, body = _get(f"{RNIS}/queries/rab_info?cell_id={cell_id}")
    return body if st == 200 and isinstance(body, dict) else None


def federated_systems() -> list[dict]:
    """MEC 040: the peer MEC systems this system can federate with.

    Tries each known resource name in turn and returns the first that serves a list.
    Returns [] if none do -- a peer that answers with the wrong shape is treated as no
    peer, rather than being coerced, so a federation failure stays visible.
    """
    for resource in FED_RESOURCES:
        st, body = _get(f"{FED_BASE}/{resource}")
        if st == 200 and isinstance(body, list):
            return _apply_system_map(body)
    return []


def _apply_system_map(systems: list[dict]) -> list[dict]:
    """Bridge a federation that knows its systems but not OUR edges.

    ETSI's MEC sandbox (try-mec.etsi.org) answers MEC 040 with SystemInfo carrying only
    systemId / systemName / systemProvider -- no `endpoint` (found 2026-09-28) -- and its
    systems are its own MEPs, which cannot know our oneM2M edges. EDGEFOLLOW_FED_SYSTEM_MAP
    ("<systemName>=<cse url>,...") supplies the endpoint for a named system ONLY when the
    federation gave none, and marks it `endpoint_source: local-map`, so a result can always
    say which half came from the federation (the peer DECISION) and which from us (WHERE).
    """
    raw = os.environ.get("EDGEFOLLOW_FED_SYSTEM_MAP", "")
    mapping = dict(kv.split("=", 1) for kv in raw.split(",") if "=" in kv)
    for s in systems:
        if not s.get("endpoint") and s.get("systemName") in mapping:
            s["endpoint"] = mapping[s["systemName"]]
            s["endpoint_source"] = "local-map"
    return systems


def federation_resource_in_use() -> str | None:
    """Which of the two resource names this FED_BASE actually serves (for the log)."""
    for resource in FED_RESOURCES:
        st, body = _get(f"{FED_BASE}/{resource}")
        if st == 200 and isinstance(body, list):
            return resource
    return None


def peer_for(current_endpoint: str, systems: list[dict]) -> dict | None:
    """The federated system that is NOT the one we are on.

    The endpoint attribute is what makes discovery actionable: it names where the
    peer system actually is, so the handover has somewhere to go.
    """
    for s in systems:
        ep = s.get("endpoint")
        if ep and ep.rstrip("/") != current_endpoint.rstrip("/"):
            return s
    return None


def main(as_json: bool = False) -> int:
    steps: list[tuple[str, bool, str]] = []

    def step(label: str, ok: bool, detail: str = "") -> None:
        steps.append((label, ok, detail))
        if not as_json:
            print(f"  {'PASS' if ok else 'FAIL'}  {label}")
            if detail:
                print(f"          {detail}")

    reset()

    # --- the vehicle is on edge A ------------------------------------------
    create_ae(EDGE_A)
    create_container(EDGE_A)
    samples = ["48.1351,11.5820", "48.1361,11.5835", "48.1372,11.5849"]
    for s in samples:
        add_sample(EDGE_A, s)
    on_a = read_samples(EDGE_A)
    step("vehicle attached to edge A with telemetry", on_a == samples,
         f"{len(on_a)} samples, edges at IN-CSE: {len(registered_edges())}")

    # --- MEC 013: where is it ----------------------------------------------
    user = locate_vehicle()
    step("MEC 013 Location reports the vehicle", user is not None,
         f"zone={user.get('zoneId')} ap={user.get('accessPointId')} "
         f"pos={user.get('locationInfo')}" if user else "no user returned")

    # --- MEC 012: is a handover due ----------------------------------------
    rab = radio_conditions()
    cell = None
    if rab:
        cui = (rab.get("cellUserInfo") or [{}])[0]
        cell = (cui.get("ecgi") or {}).get("cellId")
    step("MEC 012 RNIS reports the serving cell", cell == HOME_CELL,
         f"cellId={cell} requestId={rab.get('requestId') if rab else None}")

    # --- MEC 040: which peer system, and where ------------------------------
    systems = federated_systems()
    step("MEC 040 federation lists peer systems", len(systems) >= 2,
         "; ".join(f"{s.get('systemName') or s['systemId']}->{s.get('endpoint')}"
                   + (" [endpoint from local map]" if s.get("endpoint_source") == "local-map" else "")
                   for s in systems))

    peer = peer_for(EDGE_A[0], systems)
    step("MEC 040 selects the peer system to hand over to", peer is not None,
         f"{peer['systemId']} ({peer.get('systemProvider')}) at {peer.get('endpoint')}"
         if peer else "no peer with a different endpoint")

    # --- the endpoint federation gave us IS the destination -----------------
    target = None
    if peer:
        ep = peer["endpoint"].rstrip("/")
        # Federation says where AND what: an endpoint alone cannot be written to.
        # Falling back to the declared lab topology keeps a peer registered before
        # `cseName` existed resolvable, and leaves `target` None otherwise -- an
        # unresolvable peer must fail the step, not be guessed at.
        if peer.get("cseName"):
            target = (ep, peer["cseName"])
        else:
            for edge in (EDGE_A, EDGE_B):
                if edge[0].rstrip("/") == ep:
                    target = edge
    step("peer endpoint resolves to a reachable edge CSE", target is not None,
         f"{peer['endpoint']} -> {target[1]}" if target and peer else "unresolved")

    # --- execute the handover the MEC layer just decided -------------------
    moved = bool(target) and handover(EDGE_A, target, on_a)
    step("oneM2M subtree handed over to the peer edge", moved)

    after = read_samples(target) if target else []
    step("telemetry intact on the peer edge", after == samples,
         f"{len(after)} samples: {after}")

    gone = 0
    try:
        with urllib.request.urlopen(urllib.request.Request(
                f"{EDGE_A[0]}/{EDGE_A[1]}/{AE_NAME}",
                headers={"X-M2M-Origin": "Cvehicle01", "X-M2M-RI": "chk",
                         "X-M2M-RVI": "4"}), timeout=8) as r:
            gone = r.status
    except urllib.error.HTTPError as e:
        gone = e.code
    step("vehicle released from the origin edge", gone == 404, f"HTTP {gone}")

    step("IN-CSE still holds both edges", edges_ok(registered_edges()),
         str(registered_edges()))

    ok = all(s[1] for s in steps)
    if as_json:
        print(json.dumps({"result": "PASS" if ok else "FAIL",
                          "steps": [{"step": a, "ok": b, "detail": c}
                                    for a, b, c in steps]}, indent=2))
    else:
        passed = sum(1 for s in steps if s[1])
        print(f"\n  RESULT: {'PASS' if ok else 'FAIL'}  ({passed}/{len(steps)} steps)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main("--json" in sys.argv))
