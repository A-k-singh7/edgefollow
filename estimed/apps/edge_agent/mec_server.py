#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""EdgeFollow MEC MCP server: the MEC services the handover decision needs, as tools for an agent.

    python3 mec_server.py               # MCP over stdio; an MCP client starts it

Tools:
    federation_peers  MEC 040 (fed_resources/system_info): for each peer MEC system (at most MAX_PEERS), the lab edge
                      it names by endpoint AND CSE name, or "unknown"; nothing else of MEC 040's answer is returned
    edge_ready        MEC 011 (mec_service_mgmt/v1/services): does MEC 011 list an ACTIVE service onem2m-mn-cse whose
                      endpoint is that edge's CSEBase; our MEC 011 lists a service only after its app confirmed READY

Scope: loopback endpoints fixed here (MEC 040 :8300, MEC 011 :8091); every request has a total deadline and a size
cap, uses no proxy and follows no redirect (mcp_stdio.http_get_json). Only our own registration form counts for
edge_ready (serName onem2m-mn-cse), the same rule the oneM2M server's move uses. Replies carry only edge names,
booleans and counts: no text from MEC 040 or MEC 011 reaches the caller. The MEC services are this project's own.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HERE.parents[1]))

import handover                                              # noqa: E402
from mcp_stdio import Server, Tool, ToolError, harden_http, http_get_json   # noqa: E402

EDGES = {"edge-a": handover.EDGE_A, "edge-b": handover.EDGE_B}
FED = "http://127.0.0.1:8300/fed_enablement/v1/fed_resources/system_info"
MEC011_SERVICES = "http://127.0.0.1:8091/mec_service_mgmt/v1/services"
MAX_PEERS, DEADLINE_S = 16, 10.0


def mec011_lists_ready(edge: str, services=None) -> bool:
    """The edge's MN-CSE is an ACTIVE onem2m-mn-cse service in MEC 011 (our registration form only)."""
    host, cb = EDGES[edge]
    listed = services if services is not None else http_get_json(
        f"{MEC011_SERVICES}?ser_name={handover.EDGE_SERVICE}", "MEC 011", DEADLINE_S)
    if not isinstance(listed, list):
        raise ToolError("MEC 011 did not answer with a list")
    return any(handover._advertises(s, f"{host}/{cb}", cb, None) for s in listed)


class Platform:
    """The real backend: GETs to the lab's MEC services."""

    def systems(self) -> list:
        body = http_get_json(FED, "MEC 040", DEADLINE_S)
        if not isinstance(body, list):
            raise ToolError("MEC 040 did not answer with a list")
        return body

    def services(self) -> list:
        body = http_get_json(f"{MEC011_SERVICES}?ser_name={handover.EDGE_SERVICE}", "MEC 011", DEADLINE_S)
        if not isinstance(body, list):
            raise ToolError("MEC 011 did not answer with a list")
        return body


def edge_of(system) -> str:
    """The lab edge a MEC 040 system names, by endpoint AND CSE name; anything else is unknown."""
    if not isinstance(system, dict):
        return "unknown"
    ep, cse = system.get("endpoint"), system.get("cseName")
    for name, (host, cb) in EDGES.items():
        if isinstance(ep, str) and ep.rstrip("/") == host and cse == cb:
            return name
    return "unknown"


def make_tools(platform) -> list[Tool]:
    def federation_peers() -> dict:
        systems = platform.systems()
        return {"peers": [edge_of(s) for s in systems[:MAX_PEERS]], "not_shown": max(0, len(systems) - MAX_PEERS)}

    def edge_ready(edge: str) -> dict:
        listed = platform.services()
        return {"edge": edge, "ready": mec011_lists_ready(edge, listed), "services_listed": len(listed)}

    obj = lambda props, req=(): {"type": "object", "properties": props, "required": list(req),  # noqa: E731
                                 "additionalProperties": False}
    ro = {"readOnlyHint": True, "openWorldHint": False}
    return [
        Tool("federation_peers", "MEC 040: for each peer MEC system, the lab edge it names (or unknown).",
             obj({}), federation_peers, ro),
        Tool("edge_ready", "MEC 011: whether the edge's MN-CSE is listed as an ACTIVE onem2m-mn-cse service, i.e. "
             "its app instance confirmed READY.", obj({"edge": {"type": "string", "enum": list(EDGES)}}, ["edge"]),
             edge_ready, ro),
    ]


INSTRUCTIONS = "MEC side of EdgeFollow (MEC 040 federation, MEC 011 service registry). Read-only."


def main() -> None:
    harden_http()
    Server("edgefollow-mec", "1.2", make_tools(Platform()), INSTRUCTIONS).serve()


if __name__ == "__main__":
    main()
