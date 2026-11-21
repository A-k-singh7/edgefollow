# Handover failures: operator playbook

For the policy-driven handover of `estimed_poc/policy_run.py` (plan row A4; TD_MEC_OBS_02). The rule is
policy-driven, own modelling of the rule; no CMDH management object in the lab's CSE. The device is simulated.

One section per failure the engine can report; `estimed_poc/test_policy.py` fails if a code in
`policy_core.FAILURES` has no section here, or a section here has no code.

Where to look, for every failure:

| What | Where |
|---|---|
| diagnostic events, newest last | IN-CSE `cse-in/hoPolicy/events` (one contentInstance per event; `event` holds the code) |
| the rule in force | IN-CSE `cse-in/hoPolicy/rule/la` |
| an edge's MEC-side constraint | that edge's CSE, `<cse>/mecPolicy/constraint/la` |
| violations the MEC side holds against a served device | that edge's CSE, `<cse>/mecPolicy/violations` |
| which edge serves the device | IN-CSE, the announced AE labelled `aei:Cvehicle01` (its `lnk`) |
| an open handover transaction | IN-CSE `cse-in/ho-Cvehicle01` (labels `txn:`, `from:`, `to:`, `until:`) |

Read with `X-M2M-Origin: CAdmin`, `X-M2M-RVI: 4`. In all cases the device keeps posting to the source edge
unless a handover completed.

## Target registration refused (`target-registration-refused`)

**Seen:** an event `target-registration-refused` naming source and target; the library printed
`AE create on destination refused: <status>`.

**By itself:** the handover rolls back: nothing of the device is left on the target, the source AE gets back the
reachability (`rr`) it had, the transaction at the IN-CSE is closed, the device goes on posting to the source. The
engine waits a full dwell time before it tries again.

**Operator checks:** on the target, who holds the device's AE-ID or name (`GET <target>/vehicle01`, and any other
AE registered with originator `Cvehicle01`): ACME answers 403 when the originator is already registered there, 409
when the name is taken. On the source, `rr` of the AE is what it was. `cse-in/ho-Cvehicle01` answers 404.

## Target not ready (`target-not-ready`)

**Seen:** an event `target-not-ready`; the library printed `target not ready; handover not started, source
untouched`.

**By itself:** nothing is written anywhere; no transaction is opened. The engine tries again after a dwell time.

**Operator checks:** the target CSE answers (`GET <target>`), states `cst` 2, and the IN-CSE holds its
`<remoteCSE>` (`GET cse-in/<target CSE-ID>`). If the target is down for long, take it out of the rule's
`allowed_targets` or set its constraint to `admit: false`.

## Policy conflict (`policy-conflict`)

**Seen:** one event `policy-conflict` per episode with `handover_started: false`, the rule, the serving edge and
one reason per allowed target (`admit is not true`, a stated latency above the limit, `constraint unreadable or
incomplete`, `is the serving edge`).

**By itself:** no handover is started and no transaction is opened; the device stays on the source. The event is
not repeated while the same conflict lasts. If a target becomes permitted while the metric is still above the
threshold, the handover starts on the next sample.

**Operator checks:** which side should give way: widen the rule (`allowed_targets`, `threshold`) on the IN-CSE, or
change the edge's constraint on the edge. Check that each allowed target's constraint is readable; an unreadable
one forbids.

## Route not on the source (`route-not-on-source`)

**Seen:** an event `route-not-on-source`; the library printed `the IN-CSE routes Cvehicle01 to ..., not to the
source ... alone` or `the route changed while the transaction was opened`.

**By itself:** nothing is touched (in the second case the transaction that was just opened is closed again).

**Operator checks:** the announced AEs at the IN-CSE labelled `aei:Cvehicle01`: there must be exactly one, linking
to the source. A second one is a leftover registration on another edge; remove that AE on its edge.

## A handover transaction already open (`transaction-open`)

**Seen:** an event `transaction-open`; the library printed `another handover of Cvehicle01 is open: [labels]`.

**By itself:** the second handover is refused before any write. The first one goes on. The engine tries again
after a dwell time.

**Operator checks:** `cse-in/ho-Cvehicle01`: who holds it (`from:`, `to:`) and until when (`until:`, epoch
seconds). If the holder is dead, wait for `until:` (120 s after it was taken); only delete the resource by hand
when it is certain that no handover is running.

## An expired transaction (`transaction-expired`)

**Seen:** an event `transaction-expired` just before `handover-started`: a transaction whose `until:` has passed
was found at the IN-CSE.

**By itself:** the library removes the expired transaction once and opens its own; the handover then runs as
usual. The CSE also drops the resource at its expiration time.

**Operator checks:** why the earlier handover did not close its transaction (a crashed engine or driver). Check
the device is served by exactly one edge, and that no partial copy of it is left on the other edge.

## The rule cannot be read (`rule-invalid`)

**Seen:** an event `rule-invalid` with the reason (a missing field, a metric other than `ping_rtt_ms`, a threshold
that is not a positive number, an empty target list). Written once per rule version.

**By itself:** the engine acts as if there were no rule: no handover, no conflict.

**Operator checks:** `cse-in/hoPolicy/rule/la`; write a corrected rule as a new contentInstance.

## Handover failed for another reason (`handover-failed-other`)

**Seen:** an event `handover-failed-other` with the library's printed lines in `log`.

**By itself:** the library's rollback, as under target registration refused.

**Operator checks:** the `log` field: a copy that did not match, an access policy outside the AE, a child resource
the handover does not carry, or an unreachable target. Then the source as above: AE present, `rr` as before, no
transaction left.
