#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Policy-driven handover, the pure logic (TD_MEC_HO_04 and the policy-conflict
half of TD_MEC_OBS_02). No I/O here: policy_run.py does the oneM2M requests and hands this file what the CSEs
answered. Standard library only.

Policy-driven, own modelling of the rule; no CMDH management object in the lab's CSE. (ACME 2026.5.3 lists the names
cmdhPolicy .. cmdhLimits in its enumeration table, mgmtDefinition 1011-1020, but has no resource class for them: a
CREATE of <mgmtObj> with mgd 1011 at the IN-CSE answered 500, "1011 is not a valid ResourceTypes", probe of
2026-11-18.) So nothing here is a CMDH policy and the word is used only to say so.

  the rule        one JSON object, kept by policy_run.py as the latest <contentInstance> of a <container> on the
                  IN-CSE:  metric (only "ping_rtt_ms"), threshold (ms), dwell_s, allowed_targets (CSE-IDs)
  the constraint  one JSON object per edge, the MEC side's word on that edge:  admit (true / false),
                  latency_limit_ms (the highest latency the edge's platform accepts for a device it serves) and
                  latency_ms (the latency the edge states it offers now)
  the quantity    the round trip of the device's ping command: creation time of the command at the serving CSE to
                  creation time of the device's acknowledgement there (rtt_ms)
  the engine      Engine.step(): the round trip above the threshold for the whole dwell time starts a handover to
                  the permitted allowed target with the lowest stated latency; if every allowed target is forbidden
                  the decision is a conflict, reported once per episode, and no handover
"""
from __future__ import annotations

import calendar
import json
import re
import time

RECORD_NOTE = "policy-driven, own modelling of the rule; no CMDH management object in the lab's CSE"
METRIC = "ping_rtt_ms"

# Every failure the engine can report, by code. PLAYBOOK_FAILURES.md has one section per code (test_policy.py).
FAILURES = {
    "target-registration-refused": "the target MN-CSE refused the device's registration during the handover",
    "target-not-ready": "the target MN-CSE did not answer as a registered middle node; the handover was not started",
    "policy-conflict": "the rule asks for a handover and every allowed target is forbidden by its MEC-side constraint",
    "route-not-on-source": "the IN-CSE does not route the device to the source edge alone",
    "transaction-open": "another handover transaction of the same device is open at the IN-CSE",
    "transaction-expired": "a handover transaction past its validity time was found at the IN-CSE",
    "rule-invalid": "the rule resource holds something the engine cannot read as a rule",
    "handover-failed-other": "the handover failed and rolled back for a reason not named above",
}
EVENT_KINDS = (*FAILURES, "handover-started", "handover-completed")

# What estimed/handover.py prints when it stops, and the failure that names it. test_policy.py checks that each
# message is still in the library's source.
LIBRARY_MESSAGES = {
    "AE create on destination refused": "target-registration-refused",
    "target not ready": "target-not-ready",
    "another handover of": "transaction-open",
    "the IN-CSE routes": "route-not-on-source",
    "the route changed while the transaction was opened": "route-not-on-source",
}


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def parse_rule(obj) -> dict:
    """The rule's four fields, checked. ValueError says what is wrong."""
    if not isinstance(obj, dict):
        raise ValueError("the rule is not an object")
    for k in ("metric", "threshold", "dwell_s", "allowed_targets"):
        if k not in obj:
            raise ValueError(f"the rule has no {k}")
    if obj["metric"] != METRIC:
        raise ValueError(f"metric {obj['metric']!r}: the engine measures only {METRIC}")
    if not _number(obj["threshold"]) or obj["threshold"] <= 0:
        raise ValueError("threshold must be a positive number of milliseconds")
    if not _number(obj["dwell_s"]) or obj["dwell_s"] < 0:
        raise ValueError("dwell_s must be a number of seconds, 0 or more")
    t = obj["allowed_targets"]
    if not isinstance(t, list) or not t or not all(isinstance(c, str) and c.startswith("/") and len(c) > 1 for c in t):
        raise ValueError("allowed_targets must be a non-empty list of CSE-IDs ('/id-...')")
    return {"metric": METRIC, "threshold": obj["threshold"], "dwell_s": obj["dwell_s"], "allowed_targets": list(t)}


def permits(constraint) -> tuple[bool, str]:
    """The MEC side's answer for one edge: may a device be handed to it now? (ok, reason when not)."""
    c = constraint
    if not isinstance(c, dict) or not _number(c.get("latency_limit_ms")) or not _number(c.get("latency_ms")):
        return False, "constraint unreadable or incomplete"
    if c.get("admit") is not True:
        return False, "admit is not true"
    if c["latency_ms"] > c["latency_limit_ms"]:
        return False, f"stated latency {c['latency_ms']} ms is above its limit {c['latency_limit_ms']} ms"
    return True, ""


def select_target(rule: dict, serving: str, constraints: dict) -> tuple[str | None, dict, list]:
    """The target of a handover away from `serving`: an edge the rule allows AND its MEC-side constraint permits;
    of those the lowest stated latency, the CSE-ID breaking ties. Returns (target or None, {forbidden allowed
    target: reason}, permitted targets in order). The order of the rule's list plays no part."""
    why, ok = {}, []
    for csi in sorted(set(rule["allowed_targets"])):
        if csi == serving:
            why[csi] = "is the serving edge"
            continue
        yes, reason = permits(constraints.get(csi))
        if yes:
            ok.append((constraints[csi]["latency_ms"], csi))
        else:
            why[csi] = reason
    order = [csi for _, csi in sorted(ok)]
    return (order[0] if order else None), why, order


class Engine:
    """The policy engine's memory between samples: since when the round trip has been above the threshold, and
    which conflict it has already reported."""

    def __init__(self) -> None:
        self.since: float | None = None
        self.reported: str | None = None

    def step(self, now: float, sample_ms: float | None, rule_obj, serving: str, constraints: dict) -> dict:
        """One sample (None: the ping was not answered). Returns {"action": "none" | "handover" | "conflict",
        "target", "why", "reasons"} and, when the rule is unreadable, "failure"."""
        none = lambda why, **kw: {"action": "none", "target": None, "why": why, "reasons": {}, **kw}  # noqa: E731
        if rule_obj is None:
            self.since = self.reported = None
            return none("no rule")
        try:
            rule = parse_rule(rule_obj)
        except ValueError as e:
            self.since = self.reported = None
            return none(f"rule invalid: {e}", failure="rule-invalid")
        if sample_ms is None:
            self.since = None
            return none("no sample: the ping was not answered; the dwell time starts again")
        if sample_ms <= rule["threshold"]:
            self.since = self.reported = None
            return none(f"{sample_ms:.1f} ms is not above {rule['threshold']} ms")
        if self.since is None:
            self.since = now
        if now - self.since < rule["dwell_s"]:
            return none(f"above the threshold for {now - self.since:.1f} s of {rule['dwell_s']} s")
        target, why, _ = select_target(rule, serving, constraints)
        if target is not None:
            self.since = self.reported = None
            return {"action": "handover", "target": target, "reasons": why,
                    "why": f"{sample_ms:.1f} ms above {rule['threshold']} ms for {rule['dwell_s']} s"}
        key = json.dumps([rule, serving, why], sort_keys=True)
        if key == self.reported:
            return none("conflict already reported; it still holds")
        self.reported = key
        return {"action": "conflict", "target": None, "reasons": why,
                "why": "every allowed target is forbidden by its MEC-side constraint"}


def event(kind: str, at: str, **fields) -> dict:
    """One diagnostic record. Every record says it comes from a run with a simulated device."""
    if kind not in EVENT_KINDS:
        raise ValueError(f"unknown event kind {kind!r}")
    return {"event": kind, "at": at, "sim": True, **fields}


def conflict_event(rule: dict, serving: str, reasons: dict, at: str) -> dict:
    return event("policy-conflict", at, handover_started=False, serving=serving, rule=rule, reasons=dict(reasons),
                 note=RECORD_NOTE)


_CT = re.compile(r"^(\d{8})T(\d{6})(?:,(\d{1,9}))?$")


def _epoch_ns(ct: str) -> int:
    """Nanoseconds since the epoch, as an integer: a float of seconds this large is exact only to about 0.2 us."""
    m = _CT.match(ct) if isinstance(ct, str) else None
    if not m:
        raise ValueError(f"not a oneM2M time: {ct!r}")
    whole = calendar.timegm(time.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S"))
    return whole * 1_000_000_000 + int((m.group(3) or "0").ljust(9, "0"))


def rtt_ms(cmd_ct: str, ack_ct: str) -> float:
    """The round trip in ms from two creation times as one CSE recorded them (command, then acknowledgement)."""
    d = (_epoch_ns(ack_ct) - _epoch_ns(cmd_ct)) / 1_000_000
    if d < 0:
        raise ValueError(f"the acknowledgement ({ack_ct}) is stamped before its command ({cmd_ct})")
    return d


def violations(constraint, observed_rtt_ms: float | None) -> list[str]:
    """What the MEC side holds against a device now served by this edge (TD_MEC_HO_04 step 4): [] is none."""
    c = constraint
    if not isinstance(c, dict) or not _number(c.get("latency_limit_ms")):
        return ["the target's constraint cannot be read"]
    out = []
    if c.get("admit") is not True:
        out.append("the target serves a device although its admit flag is not true")
    if observed_rtt_ms is None:
        out.append("no device round trip was measured on the target")
    elif observed_rtt_ms > c["latency_limit_ms"]:
        out.append(f"device round trip {observed_rtt_ms:.1f} ms is above the target's limit {c['latency_limit_ms']} ms")
    return out


def lock_state(labels, now: float) -> str:
    """A handover transaction found at the IN-CSE: "expired" when its own `until:` label has passed, else "open"."""
    for lbl in labels if isinstance(labels, list) else []:
        if isinstance(lbl, str) and lbl.startswith("until:"):
            try:
                return "expired" if float(lbl[6:]) < now else "open"
            except ValueError:
                return "open"
    return "open"


ANNOUNCED_CSEBASE = 10005     # <cbA>: made by the CSE itself on the first announcement from an edge after a start


def leftovers(before: dict, after: dict, seen: dict) -> tuple[list[str], list[str]]:
    """(left, of_the_cse): the top-level names a CSE holds after the run and did not hold before it.

    `seen` maps such a name to what a read of it gave: {"ty": resource type, "children": how many resources it holds}.
    A new name is the CSE's own, and not a leftover of the run, only when it was read as an announced CSEBase that
    holds nothing. One that holds anything, any other type, and a name that could not be read are left."""
    left, own = [], []
    for node, names in after.items():
        for name in set(names) - set(before.get(node, names)):
            d = seen.get(name) or {}
            n = d.get("children")
            empty = isinstance(n, int) and not isinstance(n, bool) and n == 0
            (own if d.get("ty") == ANNOUNCED_CSEBASE and empty else left).append(f"{node}: {name}")
    return sorted(left), sorted(own)


def loss_in_windows(posts, windows) -> dict:
    """Records the device produced while a handover was running, and how many of them no CSE accepted.

    posts: [seconds, container, accepted], the time being when the device produced the record (before any hold);
    accepted is True, False (refused) or None (still held by the device when the run ended). windows: [start, end,
    outcome] of each call of the library handover, both ends included. A post inside two windows is counted once."""
    inside = [p for p in posts if any(w[0] <= p[0] <= w[1] for w in windows)]
    return {"numerator": sum(1 for p in inside if p[2] is not True), "denominator": len(inside)}


def classify_failure(log: str) -> str:
    """Name a failed handover from what the library printed. Anything unrecognised is handover-failed-other."""
    for msg, code in LIBRARY_MESSAGES.items():
        if msg in log:
            return code
    return "handover-failed-other"
