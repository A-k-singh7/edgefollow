#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline checks for the policy-driven handover core (policy_core.py) -- no CSE,
no MEC, no network. Policy-driven, own modelling of the rule; no CMDH management object in the lab's CSE.

Every expected value below is written by hand from the test descriptions (the ESTIMED test plan: TD_MEC_HO_04
and TD_MEC_OBS_02) or worked out in the comment beside it, never taken from policy_core.

Rows: a plain check prints PASS or FAIL. A CONTROL row states the planted fault as if it had gone through; it must
print FAIL, as in the live drivers, and the script fails if one does not.

    python3 estimed_poc/test_policy.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import policy_core as pc  # noqa: E402
except ImportError as _e:     # red-first: every row then fails by itself instead of the script dying on import
    _WHY = str(_e)

    class _Missing:
        def __getattr__(self, name):
            raise AttributeError(f"policy_core is not importable ({_WHY}); wanted {name}")
    pc = _Missing()

RESULTS: list[tuple[str, bool, str]] = []
CONTROLS: list[tuple[str, bool, str]] = []


def check(name, fn):
    try:
        ok, d = bool(fn()), ""
    except Exception as e:  # noqa: BLE001  a missing function or a crash is a FAIL row, with its reason
        ok, d = False, f"{type(e).__name__}: {e}"
    RESULTS.append((name, ok, d))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {d}" if d else ""))


def control(name, bad):
    """`bad` states the planted fault as having gone through. It must be False."""
    try:
        went_through, d = bool(bad()), ""
    except Exception as e:  # noqa: BLE001  a crash proves nothing: the control then counts as NOT failed
        went_through, d = True, f"did not run: {type(e).__name__}: {e}"
    CONTROLS.append((name, went_through, d))
    print(f"  {'PASS' if went_through else 'FAIL'}  CONTROL (must FAIL) {name}" + (f"  -- {d}" if d else ""))


def raises(fn, *exc):
    try:
        fn()
    except exc:
        return True
    return False


# ------------------------------------------------------------------------------------------------ fixtures
A, B, C, D, E = "/id-mn-a", "/id-mn-b", "/id-mn-c", "/id-mn-d", "/id-mn-e"
RULE = {"metric": "ping_rtt_ms", "threshold": 250, "dwell_s": 3, "allowed_targets": [B, C, D]}


def cons(**over):
    """Four candidate edges. B states the lowest latency of the allowed ones but does not admit; E states the lowest
    of all but the rule does not allow it. Of the two left, D (20 ms) is ahead of C (30 ms)."""
    c = {B: {"admit": False, "latency_limit_ms": 50, "latency_ms": 10},
         C: {"admit": True, "latency_limit_ms": 50, "latency_ms": 30},
         D: {"admit": True, "latency_limit_ms": 50, "latency_ms": 20},
         E: {"admit": True, "latency_limit_ms": 50, "latency_ms": 5}}
    for k, v in over.items():
        c[{"b": B, "c": C, "d": D, "e": E}[k]] = v
    return c


NONE_ADMITS = dict(c={"admit": False, "latency_limit_ms": 50, "latency_ms": 30},
                   d={"admit": True, "latency_limit_ms": 50, "latency_ms": 51})


def run(samples, rule=RULE, constraints=None, serving=A, engine=None):
    """Feed (time s, round trip ms or None) pairs to one engine; the list of decisions."""
    eng = engine or pc.Engine()
    return [eng.step(t, ms, rule, serving, cons() if constraints is None else constraints) for t, ms in samples]


def actions(decisions):
    return [d["action"] for d in decisions]


STIMULUS = [(0, 400), (1, 400), (2, 400), (3, 400)]          # above 250 ms from t = 0 to t = 3: 3 s, the dwell time


def main() -> int:
    print("== the rule [TD_MEC_HO_04 pre-test: a rule is configured (e.g. latency threshold)]")
    check("a rule with metric, threshold, dwell time and allowed targets is accepted and comes back with those four",
          lambda: pc.parse_rule(dict(RULE)) == {"metric": "ping_rtt_ms", "threshold": 250, "dwell_s": 3,
                                                "allowed_targets": [B, C, D]})
    for miss in ("metric", "threshold", "dwell_s", "allowed_targets"):
        check(f"a rule without {miss} is refused",
              lambda miss=miss: raises(lambda: pc.parse_rule({k: v for k, v in RULE.items() if k != miss}), ValueError))
    check("a rule on a metric the engine does not measure is refused",
          lambda: raises(lambda: pc.parse_rule({**RULE, "metric": "rsrp"}), ValueError))
    check("a threshold that is not a positive number is refused (0, -1, '250', True)",
          lambda: all(raises(lambda v=v: pc.parse_rule({**RULE, "threshold": v}), ValueError) for v in (0, -1, "250", True)))
    check("a negative dwell time is refused; 0 is accepted",
          lambda: raises(lambda: pc.parse_rule({**RULE, "dwell_s": -1}), ValueError)
          and pc.parse_rule({**RULE, "dwell_s": 0})["dwell_s"] == 0)
    check("allowed targets must be a non-empty list of CSE-IDs ('/...')",
          lambda: all(raises(lambda v=v: pc.parse_rule({**RULE, "allowed_targets": v}), ValueError)
                      for v in ([], B, ["id-mn-b"], [B, 7], None)))
    check("something that is not an object is refused", lambda: raises(lambda: pc.parse_rule([RULE]), ValueError))
    check("the record wording says what the rule is and is not",
          lambda: pc.RECORD_NOTE == "policy-driven, own modelling of the rule; no CMDH management object in the lab's CSE")

    print("== the MEC-side constraint of one edge [TD_MEC_HO_04 pre-test: MEC platform policy constraints are configured]")
    check("admit true and stated latency below the limit: permitted",
          lambda: pc.permits({"admit": True, "latency_limit_ms": 50, "latency_ms": 30})[0] is True)
    check("stated latency equal to the limit: permitted (the limit is the highest value allowed)",
          lambda: pc.permits({"admit": True, "latency_limit_ms": 50, "latency_ms": 50})[0] is True)
    check("stated latency above the limit: forbidden, and the reason names both numbers",
          lambda: (lambda r: r[0] is False and "51" in r[1] and "50" in r[1])(
              pc.permits({"admit": True, "latency_limit_ms": 50, "latency_ms": 51})))
    check("admit false: forbidden", lambda: (lambda r: r[0] is False and "admit" in r[1])(
        pc.permits({"admit": False, "latency_limit_ms": 50, "latency_ms": 10})))
    check("a constraint that could not be read (None) forbids: no answer is not 'allowed'",
          lambda: (lambda r: r[0] is False and "unreadable" in r[1])(pc.permits(None)))
    check("admit must be the boolean true: 'true', 1 and a missing admit forbid",
          lambda: all(pc.permits(c)[0] is False for c in (
              {"admit": "true", "latency_limit_ms": 50, "latency_ms": 10}, {"admit": 1, "latency_limit_ms": 50, "latency_ms": 10},
              {"latency_limit_ms": 50, "latency_ms": 10})))
    check("a constraint without its numbers forbids",
          lambda: all(pc.permits(c)[0] is False for c in (
              {"admit": True, "latency_ms": 10}, {"admit": True, "latency_limit_ms": 50},
              {"admit": True, "latency_limit_ms": "50", "latency_ms": 10}, {"admit": True, "latency_limit_ms": 50, "latency_ms": True})))

    print("== target selection, four candidates [TD_MEC_HO_04 step 3: target selection respects MEC platform policy]")
    check("the best allowed target (B, 10 ms) is forbidden, the next one (D, 20 ms) is taken, not C (30 ms)",
          lambda: pc.select_target(RULE, A, cons())[0] == D)
    check("E states the lowest latency of all but is not in the rule's allowed targets: never taken",
          lambda: pc.select_target({**RULE, "allowed_targets": [C]}, A, cons())[0] == C)
    check("D above its own limit as well: C is taken",
          lambda: pc.select_target(RULE, A, cons(d={"admit": True, "latency_limit_ms": 50, "latency_ms": 60}))[0] == C)
    check("the choice does not depend on the order the rule lists its targets in",
          lambda: pc.select_target({**RULE, "allowed_targets": [D, C, B]}, A, cons())[0] == D
          and pc.select_target({**RULE, "allowed_targets": [C, D, B]}, A, cons())[0] == D)
    check("equal stated latency: the lower CSE-ID is taken (C before D)",
          lambda: pc.select_target(RULE, A, cons(d={"admit": True, "latency_limit_ms": 50, "latency_ms": 30}))[0] == C)
    check("the serving edge is never a target, even when the rule lists it and it admits",
          lambda: (lambda t, why: t == C and "serving" in why[D])(*pc.select_target(RULE, D, cons())[:2]))
    check("an allowed target whose constraint is missing is forbidden",
          lambda: (lambda t, why: t == C and "unreadable" in why[D])(
              *pc.select_target(RULE, A, {k: v for k, v in cons().items() if k != D})[:2]))
    check("every allowed target forbidden: no target, and a reason for each of the three (and none for E)",
          lambda: (lambda t, why: t is None and sorted(why) == [B, C, D] and all(why.values()))(
              *pc.select_target(RULE, A, cons(**NONE_ADMITS))[:2]))
    check("reasons are given for the forbidden ones only when a target is found (B: admit; not C, D)",
          lambda: (lambda why: sorted(why) == [B] and "admit" in why[B])(pc.select_target(RULE, A, cons())[1]))
    control("a target forbidden by its MEC-side constraint (B: lowest latency, admit false) was chosen",
            lambda: pc.select_target(RULE, A, cons())[0] == B)
    control("a target outside the rule's allowed targets (E: lowest latency of all) was chosen",
            lambda: pc.select_target(RULE, A, cons())[0] == E)

    print("== the engine: threshold and dwell time [TD_MEC_HO_04 steps 1 and 2]")
    check("round trip above the threshold for the whole dwell time: nothing at 0, 1, 2 s, handover to D at 3 s",
          lambda: (lambda ds: actions(ds) == ["none", "none", "none", "handover"] and ds[3]["target"] == D)(run(STIMULUS)))
    check("the dwell time counts from the first sample above the threshold: 2.999 s is not enough, 3.0 s is",
          lambda: actions(run([(10, 400), (12.999, 400)])) == ["none", "none"]
          and actions(run([(10, 400), (13.0, 400)])) == ["none", "handover"])
    check("a round trip equal to the threshold (250 ms) does not count as above it",
          lambda: actions(run([(0, 250), (1, 250), (2, 250), (3, 250), (4, 250)])) == ["none"] * 5)
    check("one sample back below the threshold starts the dwell time again: 400 at 0-2 s, 100 at 2.5 s, 400 from 3 s "
          "gives the handover at 6 s, not before",
          lambda: actions(run([(0, 400), (1, 400), (2, 400), (2.5, 100), (3, 400), (4, 400), (5, 400), (6, 400)]))
          == ["none"] * 7 + ["handover"])
    check("a ping that was not answered (no sample) starts the dwell time again and triggers nothing",
          lambda: actions(run([(0, 400), (1, 400), (2, None), (3, 400), (4, 400), (5, 400)])) == ["none"] * 6)
    check("dwell time 0: the first sample above the threshold starts the handover",
          lambda: actions(run([(0, 251)], rule={**RULE, "dwell_s": 0})) == ["handover"])
    check("after a handover is started the dwell time starts again (no second start on the next sample)",
          lambda: actions(run(STIMULUS + [(4, 400), (5, 400)])) == ["none"] * 3 + ["handover", "none", "none"])
    check("no rule: nothing happens, and the decision says there is no rule",
          lambda: (lambda ds: actions(ds) == ["none"] * 4 and "no rule" in ds[3]["why"])(run(STIMULUS, rule=None)))
    check("a rule that cannot be parsed: nothing happens, reported as failure rule-invalid",
          lambda: (lambda ds: actions(ds) == ["none"] * 4 and ds[3].get("failure") == "rule-invalid")(
              run(STIMULUS, rule={**RULE, "threshold": "high"})))
    check("a rule that appears while the stimulus is already running still waits its own dwell time",
          lambda: (lambda e: actions(run([(0, 400), (1, 400), (2, 400), (3, 400)], rule=None, engine=e)
                                     + run([(4, 400), (6.9, 400), (7, 400)], engine=e))
                   == ["none"] * 6 + ["handover"])(pc.Engine()))
    check("a rule withdrawn and put back starts the dwell time again: rule at 0-1 s, none at 2 s, rule again from 3 s "
          "gives the handover at 6 s, not at 3 s",
          lambda: (lambda e: actions(run([(0, 400), (1, 400)], engine=e) + run([(2, 400)], rule=None, engine=e)
                                     + run([(3, 400), (5, 400), (6, 400)], engine=e)) == ["none"] * 5 + ["handover"])(pc.Engine()))
    control("the rule absent and the same stimulus started a handover",
            lambda: "handover" in actions(run(STIMULUS + [(4, 400), (5, 400), (6, 400)], rule=None)))
    control("a stimulus shorter than the dwell time (2 s of 3 s) triggered",
            lambda: "handover" in actions(run([(0, 400), (1, 400), (2, 400), (2.5, 100), (3.5, 100), (4.5, 100)])))

    print("== policy conflict [TD_MEC_OBS_02 steps 4 and 5; plan row A4: no handover, one event]")
    blocked = cons(**NONE_ADMITS)
    check("every allowed target forbidden when the dwell time is reached: the decision is 'conflict', with no target",
          lambda: (lambda ds: actions(ds) == ["none", "none", "none", "conflict"] and ds[3]["target"] is None
                   and sorted(ds[3]["reasons"]) == [B, C, D])(run(STIMULUS, constraints=blocked)))
    check("the conflict is reported once while it lasts: 4 further samples above the threshold give no second event",
          lambda: actions(run(STIMULUS + [(4, 400), (5, 400), (6, 400), (7, 400)], constraints=blocked)).count("conflict") == 1)
    check("when a target becomes permitted during the conflict the handover starts on the next sample",
          lambda: (lambda e: actions(run(STIMULUS + [(4, 400)], constraints=blocked, engine=e)
                                     + run([(5, 400)], engine=e)) == ["none"] * 3 + ["conflict", "none", "handover"])(pc.Engine()))
    check("a new episode (the round trip went back below the threshold in between) is reported again",
          lambda: actions(run(STIMULUS + [(4, 100), (5, 400), (8, 400)], constraints=blocked)).count("conflict") == 2)
    check("a conflict whose reasons changed (C: admit false -> above its limit) is reported again",
          lambda: (lambda e: actions(run(STIMULUS, constraints=blocked, engine=e) + run(
              [(4, 400)], constraints=cons(**{**NONE_ADMITS, "c": {"admit": True, "latency_limit_ms": 50, "latency_ms": 70}}),
              engine=e)).count("conflict") == 2)(pc.Engine()))
    check("the diagnostic event names the conflict, the serving edge, the rule and one reason per target, says that no "
          "handover was started and that the device is simulated",
          lambda: pc.conflict_event(RULE, A, {B: "x", C: "y", D: "z"}, "2026-11-18T20:00:00Z")
          == {"event": "policy-conflict", "handover_started": False, "serving": A, "rule": RULE,
                         "reasons": {B: "x", C: "y", D: "z"}, "at": "2026-11-18T20:00:00Z", "sim": True,
                         "note": "policy-driven, own modelling of the rule; no CMDH management object in the lab's CSE"})
    check("an event of a kind the playbook does not know is refused",
          lambda: raises(lambda: pc.event("something-else", "2026-11-18T20:00:00Z"), ValueError))
    check("every event carries sim: true and its time",
          lambda: pc.event("handover-completed", "2026-11-18T20:00:00Z", target=B)
          == {"event": "handover-completed", "at": "2026-11-18T20:00:00Z", "sim": True, "target": B})
    control("a conflict started a handover anyway",
            lambda: "handover" in actions(run(STIMULUS + [(4, 400), (5, 400), (6, 400), (7, 400)], constraints=blocked)))
    control("a conflict produced no diagnostic decision (nothing to record)",
            lambda: "conflict" not in actions(run(STIMULUS + [(4, 400)], constraints=blocked)))

    print("== the quantity: round trip of the ping command and its acknowledgement, from the CSE's creation times")
    # 20:05:02,021181 - 20:05:01,980492 = 0,040689 s = 40.689 ms
    check("20261118T200501,980492 -> 20261118T200502,021181 is 40.689 ms",
          lambda: abs(pc.rtt_ms("20261118T200501,980492", "20261118T200502,021181") - 40.689) < 1e-6)
    # 23:59:59,900000 -> next day 00:00:00,100000 = 0,2 s
    check("across midnight: 20261118T235959,900000 -> 20261119T000000,100000 is 200 ms",
          lambda: abs(pc.rtt_ms("20261118T235959,900000", "20261119T000000,100000") - 200.0) < 1e-6)
    check("a 3-digit fraction (tinyIoT writes ',980') reads as 980 ms, not 0.980 ms",
          lambda: abs(pc.rtt_ms("20261118T200501,000", "20261118T200501,980") - 980.0) < 1e-6)
    check("an acknowledgement stamped before its command is refused, not reported as a negative round trip",
          lambda: raises(lambda: pc.rtt_ms("20261118T200502,000000", "20261118T200501,000000"), ValueError))
    check("a malformed time is refused", lambda: raises(lambda: pc.rtt_ms("2026-11-18", "20261118T200501,000000"), ValueError))

    print("== after the handover: violations on the target [TD_MEC_HO_04 step 4]")
    ok_c = {"admit": True, "latency_limit_ms": 200, "latency_ms": 20}
    check("target admits and the device's round trip there (35 ms) is within the limit (200 ms): no violation",
          lambda: pc.violations(ok_c, 35.0) == [])
    check("round trip equal to the limit: no violation", lambda: pc.violations(ok_c, 200) == [])
    check("round trip above the limit (200.5 of 200 ms): one violation, naming the limit",
          lambda: (lambda v: len(v) == 1 and "200" in v[0])(pc.violations(ok_c, 200.5)))
    check("target no longer admits: one violation", lambda: len(pc.violations({**ok_c, "admit": False}, 35.0)) == 1)
    check("both broken: two violations",
          lambda: len(pc.violations({"admit": False, "latency_limit_ms": 1, "latency_ms": 20}, 35.0)) == 2)
    check("no round trip measured on the target counts as a violation (nothing measured is not 'within the limit')",
          lambda: len(pc.violations(ok_c, None)) == 1)
    check("a constraint that cannot be read counts as a violation", lambda: len(pc.violations(None, 35.0)) == 1)
    control("a handover completed with a constraint broken on the target (limit 1 ms, device round trip 35 ms) and no "
            "violation was raised", lambda: pc.violations({"admit": True, "latency_limit_ms": 1, "latency_ms": 20}, 35.0) == [])

    print("== naming a failed handover [TD_MEC_OBS_02: playbooks]")
    lib = (HERE.parent / "estimed" / "handover.py").read_text()
    check("the six failures the task names, and two more the code can report, each have a code",
          lambda: sorted(pc.FAILURES) == sorted([
              "target-registration-refused", "target-not-ready", "policy-conflict", "route-not-on-source",
              "transaction-open", "transaction-expired", "rule-invalid", "handover-failed-other"]))
    check("the library's own messages are named: AE create refused -> target-registration-refused",
          lambda: pc.classify_failure("     handover transaction ab12: /id-mn-a -> /id-mn-b\n"
                                      "    ! AE create on destination refused: 403\n") == "target-registration-refused")
    check("... target not ready", lambda: pc.classify_failure(
        "    ! target not ready; handover not started, source untouched\n") == "target-not-ready")
    check("... another handover open", lambda: pc.classify_failure(
        "    ! another handover of Cvehicle01 is open: ['txn:1', 'until:9']\n") == "transaction-open")
    check("... route not on the source (both messages)", lambda: pc.classify_failure(
        "    ! the IN-CSE routes Cvehicle01 to ['/id-mn-b'], not to the source /id-mn-a alone; nothing touched\n")
        == "route-not-on-source" == pc.classify_failure(
        "    ! the route changed while the transaction was opened; nothing touched\n"))
    check("... anything else, and an empty log, is handover-failed-other (never a guess)",
          lambda: pc.classify_failure("    ! destination telemetry does not match source\n") == "handover-failed-other"
          == pc.classify_failure(""))
    check("every message the classifier looks for is a message estimed/handover.py prints (the two cannot drift apart)",
          lambda: len(pc.LIBRARY_MESSAGES) == 5 and all(m in lib for m in pc.LIBRARY_MESSAGES))
    check("every message maps to a failure that has a code", lambda: set(pc.LIBRARY_MESSAGES.values()) <= set(pc.FAILURES))
    # until:1795000000 against now 1795000001: one second past
    check("a transaction whose 'until' label has passed is 'expired'; one still valid or without the label is 'open'",
          lambda: pc.lock_state(["txn:ab", "from:/id-mn-a", "to:/id-mn-b", "until:1795000000"], 1795000001.0) == "expired"
          and pc.lock_state(["txn:ab", "until:1795000000"], 1795000000.0) == "open"
          and pc.lock_state(["txn:ab", "until:1795000000"], 1794999999.0) == "open"
          and pc.lock_state(["txn:ab"], 1795000001.0) == "open" and pc.lock_state(None, 1795000001.0) == "open"
          and pc.lock_state(["until:soon"], 1795000001.0) == "open")

    print("== the operator playbook cannot fall behind the code")
    book = (HERE / "PLAYBOOK_FAILURES.md")
    text = eager_read(book)
    heads = re.findall(r"^## .*$", text, flags=re.M)
    sections = {m.group(1): body for m, body in (
        (re.search(r"`([a-z-]+)`", h), text.split(h, 1)[1].split("\n## ", 1)[0]) for h in heads) if m}
    for code in ("target-registration-refused", "target-not-ready", "policy-conflict", "route-not-on-source",
                 "transaction-open", "transaction-expired"):
        check(f"PLAYBOOK_FAILURES.md has a section for `{code}` with what is seen, what the system does by itself and "
              "what the operator checks",
              lambda code=code: all(lbl in sections[code] for lbl in ("**Seen:**", "**By itself:**", "**Operator checks:**")))
    check("... and for every failure code policy_core can report, no fewer and no more",
          lambda: sorted(sections) == sorted(pc.FAILURES) and len(heads) == len(sections))
    check("every event kind that names a failure is a failure code", lambda: set(pc.FAILURES) <= set(pc.EVENT_KINDS))
    check("the playbook does not call the rule CMDH (it says the rule is our own modelling)",
          lambda: pc.RECORD_NOTE in text and not re.search(r"CMDH (rule|policy)", text.replace(pc.RECORD_NOTE, "")))

    # What a run left on the CSEs (added 2026-11-19: on a freshly started lab the first announced registration makes
    # the CSE itself create an announced CSEBase, <cbA> ty 10005, on the IN-CSE for that edge; the run of 00:22 took
    # those two for its own leftovers and judged itself FAIL with 24 of 24 steps passed).
    before = {"IN": ["cse-in/CAdmin"], "MN-A": ["cse-mn-a/CAdmin"]}
    after = {"IN": ["cse-in/CAdmin", "cse-in/ex_cse-mn-a", "cse-in/ex_cse-mn-b", "cse-in/hoPolicy", "cse-in/ghost"],
             "MN-A": ["cse-mn-a/CAdmin"]}
    seen = {"cse-in/ex_cse-mn-a": {"ty": 10005, "children": 0},      # the CSE's own, empty
            "cse-in/ex_cse-mn-b": {"ty": 10005, "children": 1},      # still holds an announced resource: left
            "cse-in/hoPolicy": {"ty": 2, "children": 0}}             # an AE: left; "ghost" could not be read: left
    check("a new, empty announced CSEBase is the CSE's own and is named apart, not counted as left",
          lambda: pc.leftovers(before, after, seen) == (["IN: cse-in/ex_cse-mn-b", "IN: cse-in/ghost", "IN: cse-in/hoPolicy"],
                                                        ["IN: cse-in/ex_cse-mn-a"]))
    check("nothing new is nothing left", lambda: pc.leftovers(before, before, {}) == ([], []))
    check("a name that was there before is not left, whatever it is",
          lambda: pc.leftovers(after, after, seen) == ([], []))
    control("an announced CSEBase that still holds a resource was taken for the CSE's own",
            lambda: "IN: cse-in/ex_cse-mn-b" not in pc.leftovers(before, after, seen)[0])
    control("a new resource that could not be read was taken for the CSE's own",
            lambda: "IN: cse-in/ghost" not in pc.leftovers(before, after, seen)[0])
    control("a new AE was taken for the CSE's own",
            lambda: "IN: cse-in/hoPolicy" not in pc.leftovers(before, after, seen)[0])
    check("a child count that is not a number does not make a resource the CSE's own",
          lambda: pc.leftovers(before, after, {"cse-in/ex_cse-mn-a": {"ty": 10005, "children": None}})[1] == [])

    # Telemetry lost during the handover transitions (TD_MEC_OBS_01 step 3; added 2026-11-19). A post is [seconds, the
    # container, accepted]; accepted is None for a record the device still held when the run ended. A window is
    # [start, end, outcome] of one call of the library handover. Counted: the posts the device produced inside a window.
    posts = [[1.0, "radio", True], [2.0, "radio", True], [4.5, "radio", True], [6.0, "radio", False], [7.5, "ack", None],
             [8.0, "radio", True], [9.0, "radio", True]]
    check("posts produced inside the window are counted, both ends included; refused and never-delivered ones are lost",
          lambda: pc.loss_in_windows(posts, [[4.5, 8.0, "completed"]]) == {"numerator": 2, "denominator": 4})   # 4.5 6.0 7.5 8.0
    check("two windows are added up",
          lambda: pc.loss_in_windows(posts, [[0.5, 1.5, "rolled-back"], [4.5, 8.0, "completed"]]) == {"numerator": 2, "denominator": 5})
    check("no window, or no post inside one, gives no denominator",
          lambda: pc.loss_in_windows(posts, []) == {"numerator": 0, "denominator": 0}
          and pc.loss_in_windows(posts, [[2.5, 3.5, "completed"]]) == {"numerator": 0, "denominator": 0})
    check("a post inside two overlapping windows is counted once",
          lambda: pc.loss_in_windows(posts, [[5.0, 7.0, "x"], [5.5, 6.5, "y"]]) == {"numerator": 1, "denominator": 1})
    control("a record the device still held at the end of the run was counted as delivered",
            lambda: pc.loss_in_windows([[5.0, "radio", None]], [[4.0, 6.0, "completed"]])["numerator"] == 0)
    control("a post outside every window was counted",
            lambda: pc.loss_in_windows([[9.0, "radio", False]], [[4.0, 6.0, "completed"]])["denominator"] == 1)

    bad = [n for n, ok, _ in RESULTS if not ok]
    through = [n for n, went, _ in CONTROLS if went]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed; controls {len(CONTROLS)}, "
          f"all failed as they must: {bool(CONTROLS) and not through}")
    for n in through:
        print(f"  CONTROL DID NOT FAIL: {n}")
    return 1 if bad or through or not CONTROLS else 0


def eager_read(path: Path) -> str:
    try:
        return path.read_text()
    except OSError:
        return ""


if __name__ == "__main__":
    raise SystemExit(main())
