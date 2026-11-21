#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""EdgeFollow agent: follows a vehicle to a ready edge through two MCP servers, with its state kept in oneM2M.

    python3 agent.py --run-id run-1                 # vehicle01, MCP servers started here over stdio
    python3 agent.py --run-id run-1                 # again: the journal says the run ended; nothing is moved

A structured agent (fixed rules, no language model). Its steps, each a tool call on one of the two servers:

  1 RESUME    journal_read (oneM2M): a run with an end state is not run again; a run that reached MOVING goes
              straight to SETTLE and is never moved again
  2 OBSERVE   vehicle_status (oneM2M): exactly one edge holds the vehicle, the IN-CSE routes to it, no transaction
              is open; the sample count and digest go into the journal                         -> OBSERVED
  3 PEERS     federation_peers (MEC): the edges MEC 040 names, other than the source
  4 AGREE     list_edges (oneM2M): only a peer the IN-CSE also holds a <remoteCSE> for is a candidate
  5 READY     check_target (oneM2M) and edge_ready (MEC 011, polled up to --ready-timeout): the first candidate
              that passes both is the target                                                  -> DECIDED
  6 MOVE      move_vehicle (oneM2M), never retried. The server records MOVING before it moves and MOVED or
              MOVE_FAILED after. If the answer is lost, the run stays open (UNSETTLED)
  7 SETTLE    read the run's journal and the CSEs. No MOVING: the move was refused, nothing moved (ABORTED).
              MOVING without the server's outcome: UNSETTLED while a transaction is open or the server may still be
              working (MOVING + MOVE_TIMEOUT_S + SETTLE_MARGIN_S); after that, judged from the CSEs alone (right for
              a dead server; a server still moving after that long is judged too early).
              COMPLETED only if the target alone holds the vehicle with the samples seen in OBSERVED (count and
              digest), the route names it and no transaction is open, and the server did not record MOVE_FAILED;
              ROLLED_BACK only if the source alone still holds it, unchanged, and the server did not record MOVED;
              anything else is INCONSISTENT. The move tool's own answer is never the judge.

Errors: before the move, a failed tool ends the run as ABORTED. From the move on, nothing ends the run except
SETTLE: if a tool or the journal fails there, the agent exits (code 5) without an end state and the next run settles.
A server that dies or hangs during a read is restarted once and the read repeated. A server that was sent a move is
never stopped by this client (not on a lost answer, not on exit, not on Ctrl-C): later reads go to a fresh process
and the old one finishes (or rolls back) its move and exits. Servers run in their own session, so a Ctrl-C in the
terminal does not reach them.
Exit codes: 0 COMPLETED, 2 ABORTED, 3 ROLLED_BACK, 4 INCONSISTENT, 5 a tool failed outside a step (nothing ended),
6 UNSETTLED (run again later to settle).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import selectors
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
EDGES = ("edge-a", "edge-b")
TERMINAL = ("COMPLETED", "ROLLED_BACK", "ABORTED", "INCONSISTENT")
EXIT = {"COMPLETED": 0, "ABORTED": 2, "ROLLED_BACK": 3, "INCONSISTENT": 4, "UNSETTLED": 6}
READ_ONLY = {"list_edges", "vehicle_status", "check_target", "journal_read", "federation_peers", "edge_ready"}
PROTOCOLS = ("2025-11-25", "2025-06-18")
READ_TIMEOUT_S, MOVE_TIMEOUT_S, SETTLE_MARGIN_S = 60.0, 900.0, 60.0
MAX_ANSWER = 1 << 22


class Lost(Exception):
    """The server gave no answer (died, hung, or wrote something that is not a reply to this request)."""


class ToolFailed(Exception):
    def __init__(self, tool: str, why: str) -> None:
        super().__init__(f"{tool}: {why}")
        self.tool, self.why = tool, why


class McpClient:
    """One MCP server as a child process over stdio, in its own session (a terminal Ctrl-C does not reach it)."""

    def __init__(self, argv: list[str], env: dict | None = None, timeout: float = READ_TIMEOUT_S,
                 move_timeout: float = MOVE_TIMEOUT_S) -> None:
        self.argv, self.env, self.timeout, self.move_timeout = argv, env or {}, timeout, move_timeout
        self.proc: subprocess.Popen | None = None
        self.rid, self.buf, self.restarts = 0, b"", 0
        self.detached: list[subprocess.Popen] = []          # servers that were sent a move: never stopped
        self.inflight = False                                # a move was sent and its answer has not arrived
        self._start()

    def _start(self) -> None:
        self.proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=self.env,
                                     start_new_session=True)
        self.buf, self.inflight = b"", False
        res = self._rpc("initialize", {"protocolVersion": PROTOCOLS[1], "capabilities": {},
                                       "clientInfo": {"name": "edgefollow-agent", "version": "1.2"}}, self.timeout)
        if res.get("protocolVersion") not in PROTOCOLS:
            raise Lost("the server offered a protocol version this client does not speak")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, msg: dict) -> None:
        try:
            self.proc.stdin.write((json.dumps(msg) + "\n").encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise Lost(f"write: {type(e).__name__}") from None

    def _readline(self, deadline: float) -> bytes:
        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        try:
            while b"\n" not in self.buf:
                left = deadline - time.monotonic()
                if left <= 0 or not sel.select(left):
                    raise Lost("no answer in time")
                chunk = os.read(self.proc.stdout.fileno(), 65536)
                if not chunk:
                    raise Lost("the server closed its output")
                self.buf += chunk
                if len(self.buf) > MAX_ANSWER:
                    raise Lost("an answer longer than 4 MiB")
        finally:
            sel.close()
        line, _, self.buf = self.buf.partition(b"\n")
        return line

    def _rpc(self, method: str, params: dict, timeout: float) -> dict:
        self.rid += 1
        rid = self.rid
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while True:
            try:
                msg = json.loads(self._readline(deadline))
            except ValueError:
                raise Lost("a line that is not JSON") from None
            if not (isinstance(msg, dict) and msg.get("id") == rid and "method" not in msg):
                continue                                     # a notification, a server request or a stale reply
            if "error" in msg:
                raise ToolFailed(method, str((msg["error"] or {}).get("message"))[:300])
            if not isinstance(msg.get("result"), dict):
                raise Lost("a reply without a result")
            return msg["result"]

    def _detach(self) -> None:
        """Leave the current server to finish what it was sent (stdin closed: it exits after that); never signal it."""
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        self.detached.append(self.proc)
        self.proc = None

    def call(self, tool: str, args: dict) -> tuple[dict, bool]:
        if self.inflight:                                    # the last move's answer never came: use a fresh server
            self._detach()
            self._start()
        write = tool not in READ_ONLY
        if write:
            self.inflight = True                             # set BEFORE sending: an interrupt now must not stop it
        try:
            res = self._rpc("tools/call", {"name": tool, "arguments": args},
                            self.move_timeout if write else self.timeout)
        except Lost:
            if write or self.restarts >= 1:
                raise
            self.restarts += 1
            self._stop(self.proc)
            self._start()
            res = self._rpc("tools/call", {"name": tool, "arguments": args}, self.timeout)
        except ToolFailed:
            self.inflight = False                            # the server answered (with an error): nothing in flight
            raise
        self.inflight = False
        data = res.get("structuredContent")
        if not isinstance(data, dict):
            raise Lost(f"{tool}: no structured result")
        return data, bool(res.get("isError"))

    @staticmethod
    def _stop(proc: subprocess.Popen) -> None:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)

    def close(self) -> None:
        if self.proc is not None:
            if self.inflight:
                self._detach()
            else:
                self._stop(self.proc)
                self.proc = None
        for p in self.detached:                              # never signalled: they finish their move and exit
            try:
                p.wait(1)
            except subprocess.TimeoutExpired:
                pass


class Agent:
    def __init__(self, call: Callable[[str, str, dict], tuple[dict, bool]], vehicle: str, run_id: str,
                 ready_timeout: float = 10.0, poll: float = 0.5, log=print, clock=time.time) -> None:
        self.call, self.vehicle, self.run_id = call, vehicle, run_id
        self.ready_timeout, self.poll, self.log, self.clock = ready_timeout, poll, log, clock
        self.trace: list[tuple[str, str, bool]] = []

    def tool(self, server: str, name: str, **args) -> dict:
        data, is_error = self.call(server, name, args)
        self.trace.append((server, name, not is_error))
        if is_error:
            raise ToolFailed(name, str(data.get("error"))[:300])
        return data

    def journal(self, state: str, edge: str = "", samples: int = -1, digest: str = "", reason: str = "") -> None:
        self.tool("onem2m", "journal_append", run_id=self.run_id, state=state, edge=edge, samples=samples,
                  digest=digest, reason=reason)
        self.log(f"  journal {state:<12} {edge:<7} {reason}")

    def finish(self, state: str, edge: str = "", reason: str = "") -> str:
        self.journal(state, edge, reason=reason)
        return state

    def entries(self) -> list:
        return self.tool("onem2m", "journal_read", run_id=self.run_id, limit=50)["entries"]

    def status(self) -> dict:
        return self.tool("onem2m", "vehicle_status", vehicle=self.vehicle)

    def run(self) -> str:
        entries = self.entries()
        ended = [e for e in entries if e["state"] in TERMINAL]
        if ended:
            self.log(f"  run {self.run_id} already ended {ended[-1]['state']}; nothing to do")
            return ended[-1]["state"]
        if any(e["state"] == "MOVING" for e in entries):
            return self.settle()
        try:
            target = self.prepare()
        except (ToolFailed, Lost):
            return self.finish("ABORTED", reason="tool_failed_before_move")
        if target in TERMINAL:
            return target
        try:
            self.tool("onem2m", "move_vehicle", vehicle=self.vehicle, to_edge=target, run_id=self.run_id)
        except Lost:
            self.log("  the move's answer was lost; the run stays open; run the agent again later to settle it")
            return "UNSETTLED"
        except ToolFailed as e:
            self.log(f"  move answered an error: {e}")         # refused (no MOVING) or failed (MOVE_FAILED): SETTLE
        return self.settle()

    def prepare(self) -> str:
        """Steps 2-5. Returns the target edge, or an end state already written."""
        s = self.status()
        if len(s["on"]) != 1 or s["route"] != s["on"] or s["transaction_open"]:
            return self.finish("ABORTED", reason="no_single_serving_edge")
        src = s["on"][0]
        self.journal("OBSERVED", src, s["samples"][src], s["digest"][src])
        peers = self.tool("mec", "federation_peers")["peers"]
        registered = {e["edge"] for e in self.tool("onem2m", "list_edges")["edges"] if e["registered_at_in"]}
        candidates = [e for e in dict.fromkeys(peers) if e in EDGES and e != src and e in registered]
        if not candidates:
            return self.finish("ABORTED", src, reason="no_peer_held_by_in")
        target = next((e for e in candidates if self.tool("onem2m", "check_target", edge=e)["is_target"]
                       and self.wait_ready(e)), None)
        if target is None:
            return self.finish("ABORTED", src, reason="no_ready_candidate")
        self.journal("DECIDED", target)
        return target

    def wait_ready(self, edge: str) -> bool:
        end = time.monotonic() + self.ready_timeout
        while True:
            if self.tool("mec", "edge_ready", edge=edge)["ready"]:
                return True
            if time.monotonic() >= end:
                return False
            time.sleep(self.poll)

    @staticmethod
    def _holds(s: dict, edge: str, before: dict) -> bool:
        """Exactly this edge holds the vehicle with the samples seen before, routed there, no open transaction."""
        return (s["on"] == [edge] and s["route"] == [edge] and not s["transaction_open"]
                and s["samples"].get(edge) == before["n"] and s["digest"].get(edge) == before["d"])

    def settle(self) -> str:
        """Step 7: the run's end, from the server's record and the CSEs. Errors propagate: nothing ends the run here
        except a written end state."""
        entries = self.entries()
        obs = [e for e in entries if e["state"] == "OBSERVED"]
        mov = [e for e in entries if e["state"] == "MOVING"]
        out = [e for e in entries if e["state"] in ("MOVED", "MOVE_FAILED")]
        if not mov:
            return self.finish("ABORTED", reason="move_refused")
        s = self.status()
        if not out and (s["transaction_open"] or self.clock() < mov[-1]["t"] + MOVE_TIMEOUT_S + SETTLE_MARGIN_S):
            self.log("  the server has not recorded the move's outcome yet; the run stays open")
            return "UNSETTLED"
        if not obs or obs[-1]["samples"] < 0 or not obs[-1]["digest"]:
            return self.finish("INCONSISTENT", mov[-1]["edge"], reason="state_unreadable")
        src, target = mov[-1]["from"], mov[-1]["edge"]
        before = {"n": obs[-1]["samples"], "d": obs[-1]["digest"]}
        recorded = out[-1]["state"] if out else None
        if self._holds(s, target, before) and recorded != "MOVE_FAILED":
            return self.finish("COMPLETED", target, reason="moved" if recorded else "found_on_target")
        if self._holds(s, src, before) and recorded != "MOVED":
            return self.finish("ROLLED_BACK", src, reason="not_moved" if recorded else "found_on_source")
        return self.finish("INCONSISTENT", target, reason="contradicted_by_cses")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--vehicle", default="vehicle01")
    ap.add_argument("--run-id", required=True, help="lower-case letters, digits and '-', at most 40")
    ap.add_argument("--ready-timeout", type=float, default=10.0)
    ap.add_argument("--journal", default="edgeAgent", help="the journal AE's name on the IN-CSE (starts edgeAgent)")
    a = ap.parse_args(argv)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", a.run_id):
        ap.error("--run-id: lower-case letters, digits and '-', at most 40")
    py = [sys.executable, "-I", "-B"]
    servers = {"onem2m": McpClient(py + [str(HERE / "onem2m_server.py")], {"EDGE_AGENT_JOURNAL": a.journal}),
               "mec": McpClient(py + [str(HERE / "mec_server.py")])}
    log = lambda m: print(m, file=sys.stderr)                 # noqa: E731
    agent = Agent(lambda srv, tool, args: servers[srv].call(tool, args), a.vehicle, a.run_id,
                  a.ready_timeout, log=log)
    try:
        try:
            result = agent.run()
        except (ToolFailed, Lost) as e:                      # nothing ended: the next run settles
            log(f"  a tool failed outside a step: {e}")
            print(json.dumps({"run": a.run_id, "result": "TOOL_FAILED", "error": str(e)[:300]}))
            return 5
        print(json.dumps({"run": a.run_id, "result": result,
                          "calls": [f"{s}.{t}{'' if ok else ' (error)'}" for s, t, ok in agent.trace]}))
        return EXIT[result]
    finally:
        for c in servers.values():
            c.close()


if __name__ == "__main__":
    sys.exit(main())
