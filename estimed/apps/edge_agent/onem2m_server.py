#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""EdgeFollow oneM2M MCP server: the lab's CSEs as a small set of tools for an agent or a language-model client.

    python3 onem2m_server.py            # MCP over stdio; an MCP client starts it

Tools (all inputs closed; no tool takes a URL, an originator or a path):
    list_edges        the edge MN-CSEs and whether the IN-CSE holds a <remoteCSE> for each
    vehicle_status    which edge holds the vehicle's AE, per edge the sample count and a digest of the samples, the
                      edges the IN-CSE routes the vehicle to (announced AE), and whether a handover transaction is open
    check_target      is this edge a handover target: a fixed reason code
    move_vehicle      the verified handover of handover.py, once per run id (see the rules below)
    journal_append    one entry of a run's journal, kept as a contentInstance on the IN-CSE
    journal_read      the journal's last entries for a run (each entry re-checked; malformed ones are skipped)

Rules held HERE, so they bind any client, a language model included:
  - The source of a move is not an argument: it is the one edge that holds the vehicle and that the IN-CSE routes
    to; with two, none, or an open handover transaction, nothing is touched.
  - The target must be ready: a middle node registered at the IN-CSE that MEC 011 lists as an ACTIVE
    onem2m-mn-cse service in this project's registration form (the same rule as the MEC server's edge_ready).
  - One move per run id: a run whose journal holds MOVING or an end state is refused.
  - The server writes the move's record itself: MOVING before it moves, then MOVED or MOVE_FAILED with the library's
    answer. Callers cannot write these three states. Any failure inside the move rolls back (handover.py).
  - Replies and journal entries carry only closed values: edge names, fixed state and reason codes, counts, digests,
    booleans and times. No text read from a CSE or a MEC service reaches the caller.
Rules that belong to the structured agent only (agent.py): choosing the target through MEC 040, checking that two
sources agree, validating the result against the CSEs, and settling a run.

Scope: the lab topology of handover.py (IN :8200, MN-A :8201, MN-B :8202; MEC 011 :8091; loopback only) and its
vehicle01. No proxy from the environment, no redirect followed; the MEC 011 read has a total deadline and a size cap.
The CSE requests use handover.py's per-read timeout (the CSEs are the lab's own loopback servers). The journal lives
in the IN-CSE's memory and keeps at most JOURNAL_MNI entries for all runs together: it survives a crash of the agent,
not a restart of the IN-CSE, and a run older than the last JOURNAL_MNI entries is forgotten.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HERE.parents[1]))                     # estimed/: handover.py

import handover                                              # noqa: E402
from mcp_stdio import Server, Tool, ToolError, harden_http   # noqa: E402
from mec_server import mec011_lists_ready                    # noqa: E402

EDGES = {"edge-a": handover.EDGE_A, "edge-b": handover.EDGE_B}
VEHICLES = (handover.AE_NAME,)
SERVER_STATES = ("MOVING", "MOVED", "MOVE_FAILED")           # written by move_vehicle only
CALLER_STATES = ("OBSERVED", "DECIDED", "COMPLETED", "ROLLED_BACK", "ABORTED", "INCONSISTENT")
STATES = CALLER_STATES + SERVER_STATES
ENDED = ("COMPLETED", "ROLLED_BACK", "ABORTED", "INCONSISTENT")
REASONS = ("", "no_single_serving_edge", "no_peer_held_by_in", "no_ready_candidate", "tool_failed_before_move",
           "move_refused", "moved", "not_moved", "move_error", "found_on_target", "found_on_source",
           "contradicted_by_cses", "state_unreadable")
KEYS = {"run", "state", "edge", "from", "samples", "digest", "reason", "t"}
RUN_ID = r"[a-z0-9][a-z0-9-]{0,39}"
DIGEST = r"([0-9a-f]{16})?"
JOURNAL_CNT, JOURNAL_MNI = "journal", 2000


def journal_ae() -> str:
    name = os.environ.get("EDGE_AGENT_JOURNAL", "edgeAgent")
    if not re.fullmatch(r"edgeAgent[A-Za-z0-9-]{0,32}", name):
        raise SystemExit("EDGE_AGENT_JOURNAL must start with 'edgeAgent' and be a plain name")
    return name


def digest(samples: list) -> str:
    return hashlib.sha256(json.dumps(samples, separators=(",", ":")).encode()).hexdigest()[:16]


def _status(st) -> int:
    return int(st) if isinstance(st, int) else -1


class Lab:
    """The real backend: handover.py against the lab CSEs. Every error message is fixed text plus closed values;
    any answer other than the expected ones is an error (fail closed), never "absent"."""

    def __init__(self, journal: str) -> None:
        self.journal, self.journal_origin = journal, f"C{journal}"
        self._csi: dict[str, str] = {}

    def edge_csi(self, edge: str) -> str:
        if edge not in self._csi:
            try:
                self._csi[edge] = handover._csi(EDGES[edge])
            except handover.Unreadable:
                raise ToolError(f"{edge}: the CSEBase is unreadable") from None
        return self._csi[edge]

    def registered_csis(self) -> set[str]:
        return {"/" + u.split("/", 1)[-1] for u in handover.registered_edges() if isinstance(u, str)}

    def ae_present(self, edge: str) -> bool:
        host, cb = EDGES[edge]
        st, _ = handover._req("GET", f"{host}/{cb}/{handover.AE_NAME}", handover.ORCHESTRATOR)
        if st not in (200, 404):
            raise ToolError(f"{edge}: reading the vehicle answered {_status(st)}")
        return st == 200

    def samples(self, edge: str) -> list:
        try:
            return handover.read_samples(EDGES[edge])
        except handover.Unreadable:
            raise ToolError(f"{edge}: the samples are unreadable") from None

    def route(self) -> list[str]:
        try:
            csis = handover.serving_edges()
        except handover.Unreadable:
            raise ToolError("the IN-CSE route is unreadable") from None
        names = {self.edge_csi(e): e for e in EDGES}
        return [names.get(c, "other") for c in csis]

    def transaction_open(self) -> bool:
        host, cb = handover.IN_CSE
        st, _ = handover._req("GET", f"{host}/{cb}/{handover.lock_name()}", handover.ORCHESTRATOR)
        if st not in (200, 404):
            raise ToolError(f"reading the handover transaction answered {_status(st)}")
        return st == 200

    def target_check(self, edge: str) -> str:
        ok, why = handover.registered_mn(EDGES[edge])
        if ok:
            return "ok"
        return "not_middle_node" if "middle node" in str(why) else "not_registered_at_in"

    def target_ready(self, edge: str) -> bool:
        return self.target_check(edge) == "ok" and mec011_lists_ready(edge)

    def move(self, src: str, dst: str) -> bool:
        with contextlib.redirect_stdout(io.StringIO()):
            return bool(handover.handover(EDGES[src], EDGES[dst], self.samples(src)))

    def _journal_ready(self) -> None:
        host, cb = handover.IN_CSE
        st, _ = handover._req("GET", f"{host}/{cb}/{self.journal}/{JOURNAL_CNT}", self.journal_origin)
        if st == 200:
            return
        if st != 404:
            raise ToolError(f"the journal answered {_status(st)}")
        st, _ = handover._req("POST", f"{host}/{cb}", self.journal_origin, ty=handover.TY_AE, body={
            "m2m:ae": {"rn": self.journal, "api": "Nedgefollow.agent", "rr": False, "srv": ["4"]}})
        if st in (403, 409):                                 # the name or the originator exists: it must be OURS
            s, b = handover._req("GET", f"{host}/{cb}/{self.journal}", self.journal_origin)
            if s != 200 or ((b or {}).get("m2m:ae") or {}).get("aei") != self.journal_origin:
                raise ToolError("the journal's name is held by another originator")
        elif st != 201:
            raise ToolError(f"creating the journal AE answered {_status(st)}")
        st, _ = handover._req("POST", f"{host}/{cb}/{self.journal}", self.journal_origin, ty=handover.TY_CNT,
                              body={"m2m:cnt": {"rn": JOURNAL_CNT, "mni": JOURNAL_MNI}})
        if st not in (201, 409):
            raise ToolError(f"creating the journal container answered {_status(st)}")

    def journal_append(self, entry: dict) -> None:
        self._journal_ready()
        host, cb = handover.IN_CSE
        st, _ = handover._req("POST", f"{host}/{cb}/{self.journal}/{JOURNAL_CNT}", self.journal_origin,
                              ty=handover.TY_CIN, body={"m2m:cin": {"cnf": "application/json:0",
                                                                    "con": json.dumps(entry, sort_keys=True)}})
        if st != 201:
            raise ToolError(f"writing the journal answered {_status(st)}")

    def journal_entries(self) -> list:
        try:
            cins = handover._cins(handover.IN_CSE, cnt=JOURNAL_CNT, ae=self.journal, origin=self.journal_origin,
                                  missing_ok=True)
        except handover.Unreadable:
            raise ToolError("the journal is unreadable") from None
        out = []
        for c in cins:
            con = c.get("con", "")
            try:
                out.append(json.loads(con) if isinstance(con, str) and len(con) <= 2000 else None)
            except (ValueError, RecursionError):
                out.append(None)
        return out


def entry_ok(e) -> bool:
    """A journal entry exactly as this server writes it (closed values only); anything else is skipped on reading."""
    def is_int(v, lo, hi):
        return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi
    return (isinstance(e, dict) and set(e) == KEYS
            and isinstance(e["run"], str) and re.fullmatch(RUN_ID, e["run"]) is not None
            and e["state"] in STATES and e["edge"] in ("", *EDGES) and e["from"] in ("", *EDGES)
            and is_int(e["samples"], -1, 10 ** 6)
            and isinstance(e["digest"], str) and re.fullmatch(DIGEST, e["digest"]) is not None
            and e["reason"] in REASONS
            and isinstance(e["t"], (int, float)) and not isinstance(e["t"], bool) and math.isfinite(e["t"]))


def make_tools(lab) -> list[Tool]:
    vehicle = {"type": "string", "enum": list(VEHICLES)}
    edge = {"type": "string", "enum": list(EDGES)}
    run_id = {"type": "string", "pattern": RUN_ID}

    def entries_of(run: str) -> tuple[list, int]:
        raw = lab.journal_entries()
        good = [e for e in raw if entry_ok(e)]
        return [e for e in good if e["run"] == run], len(raw) - len(good)

    def write(run: str, state: str, edge: str = "", src: str = "", samples: int = -1, dig: str = "",
              reason: str = "") -> dict:
        entry = {"run": run, "state": state, "edge": edge, "from": src, "samples": samples, "digest": dig,
                 "reason": reason, "t": round(time.time(), 3)}
        if not entry_ok(entry):
            raise ToolError("journal entry refused")
        lab.journal_append(entry)
        return entry

    def status(vehicle: str) -> dict:
        on = [e for e in EDGES if lab.ae_present(e)]
        held = {e: lab.samples(e) for e in on}
        return {"vehicle": vehicle, "on": on, "samples": {e: len(s) for e, s in held.items()},
                "digest": {e: digest(s) for e, s in held.items()}, "route": lab.route(),
                "transaction_open": lab.transaction_open()}

    def list_edges() -> dict:
        reg = lab.registered_csis()
        return {"edges": [{"edge": e, "registered_at_in": lab.edge_csi(e) in reg} for e in EDGES]}

    def check_target(edge: str) -> dict:
        code = lab.target_check(edge)
        return {"edge": edge, "is_target": code == "ok", "reason": code}

    def move_vehicle(vehicle: str, to_edge: str, run_id: str) -> dict:
        mine, _ = entries_of(run_id)
        if any(e["state"] == "MOVING" or e["state"] in ENDED for e in mine):
            raise ToolError("this run id has already moved or ended; one move per run id; nothing touched")
        s = status(vehicle)
        if len(s["on"]) != 1 or s["route"] != s["on"]:
            raise ToolError("no single serving edge; nothing touched")
        if s["transaction_open"]:
            raise ToolError("a handover transaction is already open; nothing touched")
        src = s["on"][0]
        if src == to_edge:
            raise ToolError("the vehicle is already on that edge; nothing touched")
        if not lab.target_ready(to_edge):
            raise ToolError("the target is not ready (registered middle node and an ACTIVE onem2m-mn-cse service in "
                            "MEC 011); nothing touched")
        write(run_id, "MOVING", to_edge, src)
        try:
            moved = lab.move(src, to_edge)
        except Exception:                                    # noqa: BLE001 -- recorded, then reported by type only
            write(run_id, "MOVE_FAILED", to_edge, src, reason="move_error")
            raise
        write(run_id, "MOVED" if moved else "MOVE_FAILED", to_edge, src, reason="moved" if moved else "not_moved")
        return {"vehicle": vehicle, "from": src, "to": to_edge, "moved": moved}

    def journal_append(run_id: str, state: str, edge: str = "", samples: int = -1, digest: str = "",
                       reason: str = "") -> dict:
        return {"written": write(run_id, state, edge, samples=samples, dig=digest, reason=reason)}

    def journal_read(run_id: str, limit: int = 20) -> dict:
        mine, skipped = entries_of(run_id)
        return {"run": run_id, "entries": mine[-limit:], "skipped_malformed": skipped}

    obj = lambda props, req=(): {"type": "object", "properties": props, "required": list(req),  # noqa: E731
                                 "additionalProperties": False}
    ro = {"readOnlyHint": True, "openWorldHint": False}
    return [
        Tool("list_edges", "The edge MN-CSEs of the lab and whether the IN-CSE holds a <remoteCSE> for each.",
             obj({}), list_edges, ro),
        Tool("vehicle_status", "Where the vehicle's AE is (edge names), per edge how many samples it holds and a "
             "digest of them, the edges the IN-CSE routes the vehicle to, and whether a handover transaction is open.",
             obj({"vehicle": vehicle}, ["vehicle"]), status, ro),
        Tool("check_target", "Whether an edge is a valid handover target (a middle node registered at the IN-CSE); "
             "reason is ok, not_middle_node or not_registered_at_in.", obj({"edge": edge}, ["edge"]), check_target, ro),
        Tool("move_vehicle", "Hand the vehicle over to to_edge, once per run_id. Refused unless exactly one edge "
             "serves it, no transaction is open, and the target is ready in MEC 011. Copies the AE, containers, "
             "samples, access policies and subscriptions, verifies, switches the route, releases the source; any "
             "failure rolls back. Records MOVING before, and MOVED or MOVE_FAILED after, in the run's journal.",
             obj({"vehicle": vehicle, "to_edge": edge, "run_id": run_id}, ["vehicle", "to_edge", "run_id"]),
             move_vehicle, {"destructiveHint": True, "idempotentHint": False, "openWorldHint": False}),
        Tool("journal_append", "Append one entry to a run's journal on the IN-CSE (MOVING, MOVED and MOVE_FAILED "
             "are written by move_vehicle only).",
             obj({"run_id": run_id, "state": {"type": "string", "enum": list(CALLER_STATES)},
                  "edge": {"type": "string", "enum": ["", *EDGES]},
                  "samples": {"type": "integer", "minimum": -1, "maximum": 10 ** 6},
                  "digest": {"type": "string", "pattern": DIGEST},
                  "reason": {"type": "string", "enum": list(REASONS)}}, ["run_id", "state"]),
             journal_append, {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False}),
        Tool("journal_read", "The last entries of one run, oldest first; closed values only. Malformed entries are "
             "skipped and counted.",
             obj({"run_id": run_id, "limit": {"type": "integer", "minimum": 1, "maximum": 50}}, ["run_id"]),
             journal_read, ro),
    ]


INSTRUCTIONS = ("oneM2M side of EdgeFollow. Read vehicle_status before and after move_vehicle; the move needs a run "
                "id, happens at most once per run id, records its own outcome, and rolls back on failure.")


def main() -> None:
    harden_http()
    Server("edgefollow-onem2m", "1.2", make_tools(Lab(journal_ae())), INSTRUCTIONS).serve()


if __name__ == "__main__":
    main()
