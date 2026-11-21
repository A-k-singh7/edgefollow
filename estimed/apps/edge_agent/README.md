# EdgeFollow agent and its two MCP servers

An agent that follows a vehicle to a ready edge. It reaches oneM2M and ETSI MEC only through two MCP servers, and
it keeps its own state in oneM2M, on the IN-CSE.

| Part | What it is |
| ---- | ---------- |
| `onem2m_server.py` | MCP server for the lab's CSEs: `list_edges`, `vehicle_status`, `check_target`, `move_vehicle`, `journal_append`, `journal_read` |
| `mec_server.py` | MCP server for the MEC services: `federation_peers` (MEC 040), `edge_ready` (MEC 011) |
| `mcp_stdio.py` | The MCP stdio layer both servers use (JSON-RPC 2.0, one message per line; protocol versions 2025-11-25 and 2025-06-18). Written here; no third-party package |
| `agent.py` | A structured agent: fixed rules, no language model. Its steps are in the file's docstring |

## The agent's steps

1. **Resume.** It reads the run's journal. A run with an end state is not run again. A run that reached MOVING
   goes straight to step 7, and is never moved again.
2. **Observe.** Exactly one edge must hold the vehicle, and the IN-CSE must route to that edge. The agent keeps the
   sample count and a digest of the samples.
3. **Peers.** MEC 040 lists the peer MEC systems.
4. **Agree.** A peer counts only if the IN-CSE also holds a `<remoteCSE>` for it. Two sources must agree.
5. **Ready.** The target must be a registered middle node, and MEC 011 must list its MN-CSE as an ACTIVE
   `onem2m-mn-cse` service.
6. **Move.** It calls `move_vehicle` once. The server records MOVING, moves (copy, verify, switch, release, or roll
   back), and records MOVED or MOVE_FAILED.
7. **Settle.** It reads the journal and the CSEs. Without MOVING, the move was refused (ABORTED). With MOVING but
   without the server's record, the run stays open (UNSETTLED) while a transaction is open or the server may still
   be working (16 minutes). Otherwise it compares the CSEs with the count and digest it saw in step 2: COMPLETED,
   ROLLED_BACK or INCONSISTENT. The move tool's own answer is never the judge.

The journal entries are `<contentInstance>` resources on the IN-CSE. They hold closed values only: the state, edge
names, a sample count, a digest, a reason code and a time. From the move on, nothing ends a run except step 7: if a
write fails there, the agent stops without an end state, and the next run settles.

```sh
python3 -I -B agent.py --run-id run-1    # exit 0 COMPLETED, 2 ABORTED, 3 ROLLED_BACK, 4 INCONSISTENT, 5 tool failed, 6 UNSETTLED
```

It needs the lab topology (IN :8200, MN-A :8201, MN-B :8202), MEC 040 on :8300 and MEC 011 on :8091.

## Rules held by the oneM2M server, for any client

These bind a language-model client exactly as they bind the agent:

- **Closed inputs.** Every argument is a name from a closed list (`edge-a`, `edge-b`, `vehicle01`, the journal
  states) or a short pattern. No tool takes a URL, an originator or a path. Arguments are checked against the
  schema before the tool runs.
- **The source of a move comes from the CSEs.** It is the one edge that holds the vehicle and that the IN-CSE routes
  to. With two edges, none, or an open handover transaction, nothing is touched.
- **The target must be ready.** It must be a registered middle node that MEC 011 lists as an ACTIVE `onem2m-mn-cse`
  service, in this project's registration form. The MEC server's `edge_ready` uses the same rule.
- **One move per run id.** The server refuses a run id whose journal already holds MOVING or an end state.
- **The server keeps the move's record.** It writes MOVING before it moves and MOVED or MOVE_FAILED after. A caller
  cannot write these three states.
- **Closed outputs.** Replies and journal entries carry only edge names, fixed state and reason codes, counts,
  digests, booleans and times. `federation_peers` returns edge names only. An unexpected failure is reported by its
  type only, never with text read from a CSE or a MEC service.

The agent's own rules apply to the agent only: the choice of target through MEC 040, the check that two sources
agree, the validation, and the resume. A language-model client can still move the vehicle once per new run id.

## Robustness

- One malformed message never stops a server. A message is read with a 1 MiB cap. Bytes that are not UTF-8 are
  replaced. Replies are strict JSON.
- Text a tool prints is captured, so stdout carries only protocol messages.
- The servers ignore proxy settings in the environment and follow no redirect.
- Every MEC request, in both servers, has a size cap and a total deadline set by a timer, so slow headers or a slow
  body cannot stretch it.
- The servers run in their own session, so a Ctrl-C in the terminal does not reach them.
- The client repeats a read once, after one restart of the server. It never repeats a move. It marks a move as in
  flight before it sends it, and never stops a server with a move in flight: not on a lost answer, not on exit, not
  on Ctrl-C. Later reads go to a fresh process, and the old one finishes its move and exits.

## Use the servers from an MCP client

Any MCP client can start the two servers over stdio. This is an example for a project `.mcp.json`; adjust the paths:

```json
{
  "mcpServers": {
    "edgefollow-onem2m": {"command": "python3", "args": ["-I", "-B", "/path/to/estimed/apps/edge_agent/onem2m_server.py"]},
    "edgefollow-mec": {"command": "python3", "args": ["-I", "-B", "/path/to/estimed/apps/edge_agent/mec_server.py"]}
  }
}
```

## Tests

`estimed/tests/test_edge_agent.py`:
- 121 offline tests (`-m "not lab"`) for the protocol, the closed inputs and outputs, the server's rules, the real
  `Lab` class against a fake CSE, the HTTP limits, every path of the agent, and the client's handling of servers that
  die, hang, answer late, send stale replies or requests, and of an interrupt during a move;
- 3 live tests on the lab (`-m lab`, under its lock): a completed move, a control in which the agent must abort, and a
  control in which a direct `move_vehicle` call is refused by the server.

Review history (2026-11-20): an independent review of the first version found a high and four medium defects, and 13
of its 16 planted faults not caught. The fixes were re-checked. The re-check closed those, but found three new medium
defects on the crash and resume paths. This version removes those paths by design (the server records the move, one
settle step, servers in their own session). A further independent re-check accepted this version: every earlier
finding closed, no new defect at medium or above. Its remaining test gaps were closed. 57 planted faults, each in its
own copy, are all caught.

## Limits

- The journal lives in the IN-CSE's memory and keeps at most 2000 entries for all runs together. It survives a crash
  of the agent, not a restart of the IN-CSE. A run older than the last 2000 entries is forgotten, and could run again.
- The CSE requests use `handover.py`, which has a per-read timeout but no total deadline. The CSEs are the lab's own
  loopback servers.
- A run whose server has not recorded the move's outcome after 16 minutes is judged from the CSEs alone. That is
  right for a server that died; a server that is still moving after 16 minutes is judged too early, and may then
  record MOVED after the run's end entry.
- The MEC services are this project's own implementations. `edge_ready` knows only this project's registration
  form, not the one ETSI's sandbox uses.
- The vehicle is the simulated `vehicle01` of `handover.py`. The runs with the real phones used a different driver.
- The agent decides by fixed rules. A language model can use the same tools, under the server's rules above, but no
  run with one is recorded here.
