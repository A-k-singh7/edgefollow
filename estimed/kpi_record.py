#!/usr/bin/env python
"""One record format for every run, a KPI block, and an exporter (test plan
7.6.1.1, TD_MEC_OBS_01). Standard library only. Reads result files; touches no CSE, no MEC server, no device.

What it does
  normalise()      turns a results file of one of the four drivers into ONE format, estimed.run-record.v1:
                       fl            estimed_poc/fl_run.py           (record estimed.fl.sim-run.v1)
                       policy        estimed_poc/policy_run.py       (record estimed.policy-handover.sim-run.v1)
                       clean-rerun   estimed/clean_rerun.py rerun    (kind "rerun")
                       poc2          phone/estimed_poc2.py
                   A record already in the one format is taken as it is, so a later driver can write it directly.
  rejudge()        works the verdict out again from the stored rows and controls, and the KPIs again from the stored
                   lower-level data where the record holds it (the request trace, the round records, the events, the
                   per-test results). It reports every difference from what the record says.
  obs01()          the seven KPIs that TD_MEC_OBS_01 steps 1 to 4 name, each CAPTURED or NOT-CAPTURED. Only a record
                   that re-judges to its own stored PASS supplies a number.
  export()         step 5: the table as JSON, CSV and Markdown, with the SHA-256 of every record it was made from.
  verify_export()  an export against its records: the files still have those hashes and still give that table.

The verdict rule, the same for every kind: the run reached its end; at least one row passed and none failed; there
is at least one control and every control failed as it must; nothing of the run was left behind where the record
says what was left. A NOT-RUN row does not fail a run and is never counted as passed.

A rate is numerator / denominator with N = denominator, written to one decimal, half up, from exact arithmetic.

Limits, stated because the output will be read without this file
  - "Re-judged from stored data" means the data INSIDE the record. Somebody who alters the trace and the KPI block
    together, consistently, is not noticed. Nothing here is signed (no key is created on this PC). The export's
    hashes show only that the records are the files the export was made from.
  - Which KPI is recomputed and which is only carried is listed per record ("recomputed", "not_recomputed").
  - Two KPIs are DERIVED here and are in no driver's own KPI block: the handover failure/rollback rate (stored
    events of the policy run; its one failure is injected by that driver) and the telemetry loss rate (the simulated
    device's post counters over the WHOLE run, which contains the handover transitions; not windowed to them, and
    records that stayed on the source edge are not counted as lost).
  - The split of the FL rounds into "rounds" and "the control round" takes the LAST round as the control round, as
    fl_run.py runs it.
  - Every record of 2026-11-18 is of a SIMULATED device on one PC. Not a conformance claim.

    python estimed/kpi_record.py check   <results.json>
    python estimed/kpi_record.py export  <results.json> ... --out <dir>
    python estimed/kpi_record.py verify  <kpi_export_....json>
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import re
import sys
import time
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from fractions import Fraction
from pathlib import Path

FORMAT = "estimed.run-record.v1"
EXPORT_FORMAT = "estimed.kpi-export.v1"
RESULTS = ("PASS", "FAIL", "NA", "NOT-RUN")
EV01 = ("preregistration", "device_labels", "hashes", "raw", "rows", "controls", "kpi", "clock_offset", "not_shown")
NOTE = ("SIMULATED devices on one PC unless a row says otherwise; re-judged from the data stored in each record; "
        "nothing is signed; not a conformance claim")


class Unknown(ValueError):
    """The file is not a results file of a kind this module knows."""


# --- numbers --------------------------------------------------------------------------------------------------

def pct(numerator: int, denominator: int) -> str:
    """numerator / denominator as a percentage with one decimal, half up, from exact arithmetic."""
    if isinstance(numerator, bool) or isinstance(denominator, bool) or not isinstance(numerator, int) \
            or not isinstance(denominator, int):
        raise ValueError(f"a rate needs two whole numbers, got {numerator!r} / {denominator!r}")
    if denominator <= 0 or not 0 <= numerator <= denominator:
        raise ValueError(f"not a rate: {numerator} / {denominator}")
    f = Fraction(100 * numerator, denominator)
    return str((Decimal(f.numerator) / Decimal(f.denominator)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


_FACTORS = {("s", "ms"): Decimal(1000), ("bytes", "MB"): Decimal(1) / Decimal(1_000_000)}


def convert(value, unit_from: str, unit_to: str) -> str:
    """Exact change of unit; 1 MB is 1 000 000 bytes."""
    if unit_from == unit_to:
        return _plain(_dec(value))
    if (unit_from, unit_to) not in _FACTORS:
        raise ValueError(f"no conversion from {unit_from} to {unit_to}")
    return _plain(_dec(value) * _FACTORS[(unit_from, unit_to)])


def _dec(v) -> Decimal:
    if isinstance(v, bool) or v is None:
        raise ValueError(f"not a number: {v!r}")
    try:
        return Decimal(str(v))
    except InvalidOperation:
        raise ValueError(f"not a number: {v!r}") from None


def _plain(d: Decimal) -> str:
    d = d.normalize()
    return format(d if d != 0 else Decimal(0), "f")


def _same_number(a, b) -> bool:
    try:
        return _dec(a) == _dec(b)
    except ValueError:
        return False


# --- KPI entries ------------------------------------------------------------------------------------------------

def _rate(name, num, den, *, n=None, unit="%", value=None, sim, scope="", basis="stored only") -> dict:
    return {"name": name, "numerator": num, "denominator": den, "N": den if n is None else n, "unit": unit,
            "value": value if value is not None else _try_pct(num, den, unit), "sim": sim, "scope": scope, "basis": basis}


def _try_pct(num, den, unit) -> str:
    if unit != "%":
        return f"{num} of {den}"
    try:
        return pct(num, den)
    except ValueError:
        return "not a rate"


def _values(name, values, *, n, unit, sim, scope="", basis="stored only", value=None) -> dict:
    e = {"name": name, "values": [str(v) for v in values], "N": n, "unit": unit, "sim": sim, "scope": scope, "basis": basis}
    if value is not None:
        e["value"] = str(value)
    return e


def _value(name, value, *, unit, sim, n=1, scope="", basis="stored only") -> dict:
    return {"name": name, "value": str(value), "N": n, "unit": unit, "sim": sim, "scope": scope, "basis": basis}


# --- the four shapes into the one format ----------------------------------------------------------------------

def kind_of(doc) -> str:
    if not isinstance(doc, dict):
        raise Unknown("not a JSON object")
    if doc.get("format") == FORMAT:
        return "native"
    rec = doc.get("record")
    if rec == "estimed.fl.sim-run.v1":
        return "fl"
    if rec == "estimed.policy-handover.sim-run.v1":
        return "policy"
    if doc.get("kind") == "rerun" and "results" in doc and "result" in doc:
        return "clean-rerun"
    if "measurements" in doc and "steps" in doc and "verdict" in doc and "record" not in doc:
        return "poc2"
    raise Unknown(f"no known kind of results file (keys: {sorted(doc)[:8]})")


def _steps(doc) -> tuple[list, list]:
    rows, controls = [], []
    for s in doc.get("steps") or []:
        name = str(s.get("step", ""))
        if name.startswith("CONTROL"):
            controls.append({"control": name, "expected": "FAIL", "observed": "PASS" if s.get("pass") else "FAIL"})
        else:
            rows.append({"row": name, "result": "PASS" if s.get("pass") is True else "FAIL", "reason": str(s.get("detail") or "")})
    return rows, controls


def _not_run(doc) -> list:
    return [{"row": str(r.get("row", "")), "result": "NOT-RUN", "reason": str(r.get("reason") or "")}
            for r in doc.get("not_run") or []]


def _base(kind, doc, *, sim, verdict, file, sha256) -> dict:
    run = doc.get("run") or {}
    return {"format": FORMAT, "kind": kind,
            "source": {"file": file, "sha256": sha256, "record": doc.get("record") or doc.get("kind") or kind},
            "sim": sim, "device": str(doc.get("device", "")), "verdict": verdict, "aborted_at": doc.get("aborted_at"),
            "preregistration": doc.get("preregistration"), "device_labels": doc.get("device_labels"),
            "clock_offset": doc.get("clock_offset"), "hashes": run.get("files_sha256"),
            "commit": run.get("commit"), "uncommitted_paths": run.get("uncommitted_paths"),
            "rows": [], "controls": [], "kpi": [], "raw": None, "left_behind": None,
            "not_shown": doc.get("not_shown"), "ev01_missing": []}


def _finish(rec: dict) -> dict:
    rec["ev01_missing"] = [f for f in EV01 if not rec.get(f)]
    return rec


def _fl(doc, file, sha256) -> dict:
    rec = _base("fl", doc, sim=doc.get("sim") is True, verdict=doc.get("verdict"), file=file, sha256=sha256)
    rec["rows"], rec["controls"] = _steps(doc)
    rec["rows"] += _not_run(doc)
    rec["controls_listed"] = [{"control": c.get("control"), "observed": c.get("observed")} for c in doc.get("controls") or []]
    rec["left_behind"] = list((doc.get("cleanup") or {}).get("left_on_the_CSEs") or [])
    sim, k = rec["sim"], doc.get("kpi") or {}
    for name, r in (k.get("rates") or {}).items():
        rec["kpi"].append(_rate(name, r.get("numerator"), r.get("denominator"), n=r.get("N"), unit=r.get("unit", ""),
                                value=str(r.get("value")), sim=sim, scope=str(k.get("scope", ""))))
    t = k.get("fl_round_completion_time_s")
    if t:
        rec["kpi"].append(_values("fl_round_completion_time_s", t.get("values") or [], n=t.get("N"), unit=t.get("unit", ""),
                                  sim=sim, scope="one value per round, the control round left out"))
    b = k.get("edge_cloud_bytes")
    if b:
        e = _values("edge_cloud_bytes", b.get("values") or [], n=b.get("N"), unit=b.get("unit", ""), sim=sim,
                    value=b.get("total"), scope=str(b.get("counted", "")))
        e["total_MB"] = str(b.get("total_MB"))
        rec["kpi"].append(e)
    h = k.get("held_out_error")
    if h:
        rec["kpi"].append(_values("held_out_error", h.get("values") or [], n=h.get("N"), unit=h.get("unit", ""), sim=sim))
    rec["raw"] = {"trace": list((doc.get("raw") or {}).get("trace") or []),
                  "rounds": [{"round": r.get("round"), "selected": len(r.get("selected") or []),
                              "accepted": len((r.get("record") or {}).get("accepted") or []),
                              "quorum": (r.get("record") or {}).get("quorum"),
                              "bytes": r.get("bytes"), "time_s": r.get("time_s")} for r in doc.get("rounds") or []]}
    if not rec["raw"]["trace"] and not rec["raw"]["rounds"]:
        rec["raw"] = None
    return _finish(rec)


def _policy(doc, file, sha256) -> dict:
    rec = _base("policy", doc, sim=doc.get("sim") is True, verdict=doc.get("verdict"), file=file, sha256=sha256)
    rec["rows"], rec["controls"] = _steps(doc)
    rec["rows"] += _not_run(doc)
    rec["controls_listed"] = [{"control": c.get("control"), "observed": c.get("observed")} for c in doc.get("controls") or []]
    rec["left_behind"] = list((doc.get("cleanup") or {}).get("left_on_the_CSEs") or [])
    sim, raw = rec["sim"], doc.get("raw") or {}
    for name, v in (doc.get("kpi") or {}).items():
        if not isinstance(v, dict):
            continue
        if "values" in v:
            rec["kpi"].append(_values(name, v["values"], n=v.get("N"), unit=v.get("unit", ""), sim=sim))
        elif "numerator" in v:
            rec["kpi"].append(_rate(name, v.get("numerator"), v.get("denominator"), n=v.get("N"), unit=v.get("unit", ""), sim=sim,
                                    value=str(v["value"]) if "value" in v else None, scope=str(v.get("scope", ""))))
        elif "median" in v:
            rec["kpi"].append(_value(name, f"min {v.get('min')} / median {v.get('median')} / max {v.get('max')}",
                                     unit=v.get("unit", ""), n=v.get("N"), sim=sim))
        elif "value" in v:
            rec["kpi"].append(_value(name, v["value"], unit=v.get("unit", ""), n=v.get("N"), sim=sim))
    events = [e for e in raw.get("events_on_the_IN_CSE") or [] if isinstance(e, dict)]
    device = raw.get("device") if isinstance(raw.get("device"), dict) else None
    posts, windows = (raw.get("device_posts") or {}).get("posts"), raw.get("handover_windows")
    rec["raw"] = {"events": [{k: e.get(k) for k in ("event", "seconds", "rolled_back") if k in e} for e in events],
                  "device": device, "posts": posts, "windows": windows} if (events or device or posts) else None
    rec["kpi"] += _policy_derived(rec["raw"], sim)
    return _finish(rec)


def _policy_derived(raw, sim) -> list:
    out = []
    if not raw:
        return out
    started = sum(1 for e in raw["events"] if e.get("event") == "handover-started")
    rolled = sum(1 for e in raw["events"] if e.get("rolled_back") is True)
    if started and rolled <= started:
        out.append(_rate("handover_failure_rollback_rate", rolled, started, sim=sim,
                         scope="handovers the policy engine started; a failure here is one the driver injected",
                         basis="derived by the exporter from the stored events of the IN-CSE"))
    d = raw.get("device") or {}
    ok, bad = d.get("posts_accepted"), d.get("posts_failed")
    if isinstance(ok, int) and isinstance(bad, int) and not isinstance(ok, bool) and ok + bad > 0 and ok >= 0 and bad >= 0:
        out.append(_rate("telemetry_loss_rate", bad, ok + bad, sim=sim,
                         scope="device posts not accepted by a CSE, over the whole run, which contains the handover "
                               "transitions; not windowed to them; records that stayed on the source are not counted",
                         basis="derived by the exporter from the stored post counters of the simulated device"))
    return out


def _clean(doc, file, sha256) -> dict:
    rec = _base("clean-rerun", doc, sim=True, verdict=doc.get("result"), file=file, sha256=sha256)
    rec["device"] = "none: the scripted tests use the lab's simulated devices"
    rec["hashes"] = {k: v for k, v in (doc.get("provenance") or {}).items() if k.endswith("sha256")} or None
    rec["commit"] = (doc.get("manifest") or {}).get("commit")
    for s in doc.get("steps") or []:
        rec["rows"].append({"row": str(s.get("row", "")), "result": "PASS" if s.get("ok") is True else "FAIL",
                            "reason": str(s.get("detail") or "")})
    results = doc.get("results") or {}
    for td, r in results.items():
        rec["rows"].append({"row": f"{td}: {r.get('passed')} of {r.get('declared')} tests passed",
                            "result": "PASS" if r.get("ok") is True else "FAIL", "reason": "; ".join(r.get("problems") or [])})
    rec["rows"] += _not_run(doc)
    for c in doc.get("controls") or []:
        failed = c.get("failed_as_it_must") is True and c.get("passed") is False
        rec["controls"].append({"control": str(c.get("row", "")), "expected": "FAIL", "observed": "FAIL" if failed else "PASS"})
    k = ((doc.get("kpi") or {}).get("equal_by_construction") or {}).get("rerun") or {}
    for td, t in (k.get("tests_passed") or {}).items():
        rec["kpi"].append(_rate(f"tests_passed:{td}", t.get("numerator"), t.get("denominator"), n=t.get("N"),
                                value=str(t.get("value")), sim=True, scope="scripted tests of that test description"))
    c = k.get("cse_registration_success")
    if c:
        rec["kpi"].append(_rate("cse_registration_success_rate", c.get("numerator"), c.get("denominator"), n=c.get("N"),
                                value=str(c.get("value")), sim=True, scope="MN-CSEs registered at the IN-CSE"))
    t = ((doc.get("kpi") or {}).get("timings") or {}).get("empty_directory_to_last_test_description_s")
    if t is not None:
        rec["kpi"].append(_value("empty_directory_to_last_test_description_s", t, unit="s", sim=True))
    rec["raw"] = {"results": {td: {f: r.get(f) for f in ("declared", "ran", "passed", "failed", "error", "skipped")}
                              | {"ids": len(r.get("ids") or [])} for td, r in results.items()},
                  "per_cse": (c or {}).get("per_cse")} if results else None
    return _finish(rec)


def _poc2(doc, file, sha256) -> dict:
    m = doc.get("measurements") or {}
    sim = doc.get("device") == "sim" and m.get("device", "sim") == "sim"
    rec = _base("poc2", doc, sim=sim, verdict=doc.get("verdict"), file=file, sha256=sha256)
    rec["rows"], rec["controls"] = _steps(doc)
    for name in ("telemetry_pause_s", "pause_proof_s", "notification_gap_s", "handover_duration_s"):
        v = m.get(name)                  # the four the driver itself reports as measurements; period_s is a setting
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            rec["kpi"].append(_values(name, [v], n=1, unit="s", sim=sim,
                                      basis="stored only: the record holds no lower-level data to work it out from"))
    return _finish(rec)


_SHAPES = {"fl": _fl, "policy": _policy, "clean-rerun": _clean, "poc2": _poc2}


def normalise(doc, file: str | None = None, sha256: str | None = None) -> dict:
    kind = kind_of(doc)
    if kind == "native":
        rec = copy.deepcopy(doc)
        if file is not None:
            rec["source"] = {**(rec.get("source") or {}), "file": file, "sha256": sha256}
        return rec
    return _SHAPES[kind](doc, file, sha256)


def validate(rec) -> list[str]:
    """What is wrong with the FORM of a record in the one format."""
    out = []
    if not isinstance(rec, dict) or rec.get("format") != FORMAT:
        return [f"not a record of format {FORMAT}"]
    for f in ("kind", "sim", "verdict", "rows", "controls", "kpi"):
        if f not in rec:
            out.append(f"field {f} is missing")
    if rec.get("verdict") not in ("PASS", "FAIL"):
        out.append(f"verdict is {rec.get('verdict')!r}, not PASS or FAIL")
    if not isinstance(rec.get("sim"), bool):
        out.append("sim is not true or false")
    for r in rec.get("rows") or []:
        if r.get("result") not in RESULTS:
            out.append(f"row {r.get('row')!r}: result {r.get('result')!r} is not one of {', '.join(RESULTS)}")
        if r.get("result") in ("NA", "NOT-RUN") and not str(r.get("reason") or "").strip():
            out.append(f"row {r.get('row')!r}: {r.get('result')} without a reason")
    for c in rec.get("controls") or []:
        if c.get("expected") != "FAIL" or c.get("observed") not in ("PASS", "FAIL"):
            out.append(f"control {c.get('control')!r}: expected/observed are not FAIL and PASS or FAIL")
    for k in rec.get("kpi") or []:
        name = k.get("name")
        if not name:
            out.append("a KPI has no name")
        if isinstance(k.get("N"), bool) or not isinstance(k.get("N"), int) or k.get("N", -1) < 0:
            out.append(f"KPI {name}: N is missing or not a count")
        if not str(k.get("unit") or "").strip():
            out.append(f"KPI {name}: no unit")
        if "value" not in k and "values" not in k:
            out.append(f"KPI {name}: neither value nor values")
        if ("numerator" in k) != ("denominator" in k):
            out.append(f"KPI {name}: a numerator without a denominator, or the reverse")
    return out


# --- re-judging -----------------------------------------------------------------------------------------------

def _verdict(rec) -> str:
    rows, controls = rec.get("rows") or [], rec.get("controls") or []
    good = (rec.get("aborted_at") is None
            and any(r.get("result") == "PASS" for r in rows) and not any(r.get("result") == "FAIL" for r in rows)
            and bool(controls) and all(c.get("observed") == "FAIL" for c in controls)
            and not rec.get("left_behind"))
    return "PASS" if good else "FAIL"


_TRACE = re.compile(r"^(\d+) (\S+) (\S+) (\S+) ty=(\S+) -> (\d+) (\d+)B( edge-cloud)?(?: \| (.*))?$")


def _expect_fl(raw, problems) -> dict:
    exp = {}
    trace = raw.get("trace") or []
    if trace:
        parsed = [_TRACE.match(line) for line in trace]
        if not all(parsed):
            problems.append(f"{sum(1 for p in parsed if not p)} trace lines are not in the stated form")
        reg = [p for p in parsed if p and p.group(3) == "POST" and p.group(5) == "2"]
        if reg:
            exp["ae_registration_success_rate"] = {"numerator": sum(1 for p in reg if p.group(6) == "201"), "denominator": len(reg)}
    rounds = raw.get("rounds") or []
    for r in rounds:
        q = r.get("quorum") or {}
        if q.get("accepted") != r.get("accepted") or q.get("selected") != r.get("selected"):
            problems.append(f"round {r.get('round')}: the quorum line says {q.get('accepted')} of {q.get('selected')}, "
                            f"the lists hold {r.get('accepted')} of {r.get('selected')}")
    if rounds:
        for suffix, part in (("_with_control_round", rounds), ("", rounds[:-1])):
            if not part:
                continue
            exp["participant_success_rate" + suffix] = {"numerator": sum(r["accepted"] for r in part),
                                                        "denominator": sum(r["selected"] for r in part)}
            exp["round_completion_rate" + suffix] = {"numerator": sum(1 for r in part if (r.get("quorum") or {}).get("met") is True),
                                                     "denominator": len(part)}
        main = rounds[:-1]
        if main:
            try:
                exp["fl_round_completion_time_s"] = {"values": ["%.3f" % r["time_s"] for r in main], "N": len(main)}
                total = sum(r["bytes"] for r in main)
                exp["edge_cloud_bytes"] = {"values": [str(r["bytes"]) for r in main], "N": len(main), "value": str(total),
                                           "total_MB": convert(total, "bytes", "MB")}
            except (TypeError, KeyError, ValueError):
                problems.append("a round has no time or no byte count")
    return exp


def _expect_policy(raw, problems) -> dict:
    done = [e.get("seconds") for e in raw.get("events") or [] if e.get("event") == "handover-completed"]
    exp = {"handover_duration_s": {"values": [str(s) for s in done], "N": len(done)}} if done else {}
    for e in _policy_derived(raw, True):
        exp[e["name"]] = {"numerator": e["numerator"], "denominator": e["denominator"]}
    posts, windows = raw.get("posts"), raw.get("windows")
    if isinstance(posts, list) and isinstance(windows, list):
        inside = [p for p in posts if any(w[0] <= p[0] <= w[1] for w in windows)]      # both ends included, a post once
        if inside:
            exp["telemetry_loss_during_handover"] = {"numerator": sum(1 for p in inside if p[2] is not True), "denominator": len(inside)}
    return exp


def _expect_clean(raw, problems) -> dict:
    exp = {}
    for td, r in (raw.get("results") or {}).items():
        if not (r.get("declared") == r.get("ran") == r.get("ids")):
            problems.append(f"{td}: declared {r.get('declared')}, ran {r.get('ran')}, listed {r.get('ids')} tests")
        if r.get("failed") or r.get("error") or r.get("skipped"):
            problems.append(f"{td}: {r.get('failed')} failed, {r.get('error')} in error, {r.get('skipped')} skipped; "
                            "a skipped test is not a passed test")
        exp[f"tests_passed:{td}"] = {"numerator": r.get("passed"), "denominator": r.get("declared")}
    per = raw.get("per_cse")
    if isinstance(per, dict) and per:
        exp["cse_registration_success_rate"] = {"numerator": sum(1 for v in per.values() if v is True), "denominator": len(per)}
    return exp


_EXPECT = {"fl": _expect_fl, "policy": _expect_policy, "clean-rerun": _expect_clean}


def _compare(entry, exp, problems) -> None:
    name = entry["name"]
    for f in ("numerator", "denominator", "N"):
        if f in exp and entry.get(f) != exp[f]:
            problems.append(f"KPI {name}: {f} is {entry.get(f)!r} in the record, {exp[f]!r} from the stored data")
    for f in ("value", "total_MB"):
        if f in exp and not _same_number(entry.get(f), exp[f]):
            problems.append(f"KPI {name}: {f} is {entry.get(f)!r} in the record, {exp[f]!r} from the stored data")
    if "values" in exp:
        got = entry.get("values") or []
        if len(got) != len(exp["values"]) or not all(_same_number(a, b) for a, b in zip(got, exp["values"])):
            problems.append(f"KPI {name}: values are {got} in the record, {exp['values']} from the stored data")


def rejudge(rec: dict) -> dict:
    """The verdict and the KPIs again, from what the record itself stores."""
    problems = list(validate(rec))
    verdict = _verdict(rec)
    listed = rec.get("controls_listed")
    if listed is not None:
        mine = sorted((c["control"], c["observed"]) for c in rec.get("controls") or [])
        if sorted((str(c.get("control")), str(c.get("observed"))) for c in listed) != mine:
            problems.append("the record's list of controls does not agree with its control rows")
    for k in rec.get("kpi") or []:
        if "numerator" in k and "denominator" in k:
            num, den = k["numerator"], k["denominator"]
            ints = all(isinstance(x, int) and not isinstance(x, bool) for x in (num, den))
            if not ints or den <= 0 or not 0 <= num <= den:
                problems.append(f"KPI {k.get('name')}: {num!r} / {den!r} is not a rate")
                continue
            if k.get("N") != den:
                problems.append(f"KPI {k.get('name')}: N is {k.get('N')!r}, the denominator is {den}")
            if k.get("unit") == "%" and not _same_number(k.get("value"), pct(num, den)):
                problems.append(f"KPI {k.get('name')}: value {k.get('value')!r} is not {num} / {den} = {pct(num, den)} %")
        elif "values" in k and k.get("N") != len(k["values"]):
            problems.append(f"KPI {k.get('name')}: N is {k.get('N')!r} for {len(k['values'])} values")
    exp = {}
    if rec.get("raw") and rec.get("kind") in _EXPECT:
        try:
            exp = _EXPECT[rec["kind"]](rec["raw"], problems)
        except (TypeError, KeyError, AttributeError) as e:
            problems.append(f"the stored data cannot be read: {type(e).__name__}: {e}")
    by_name = {k.get("name"): k for k in rec.get("kpi") or []}
    for name, e in exp.items():
        if name in by_name:
            _compare(by_name[name], e, problems)
        else:
            problems.append(f"KPI {name} follows from the stored data and is not in the record")
    if rec.get("kind") == "policy" and "telemetry_loss_during_handover" in by_name and "telemetry_loss_during_handover" not in exp:
        problems.append("KPI telemetry_loss_during_handover is in the record and the posts and windows it follows from are not")
    if rec.get("sim") is not True and rec.get("ev01_missing"):
        problems.append("a device run lacks: " + ", ".join(rec["ev01_missing"]))
    names = [k.get("name") for k in rec.get("kpi") or []]
    return {"verdict": verdict, "stored": rec.get("verdict"), "same": verdict == rec.get("verdict"), "problems": problems,
            "recomputed": [n for n in names if n in exp], "not_recomputed": [n for n in names if n not in exp]}


# --- the table of TD_MEC_OBS_01 ---------------------------------------------------------------------------------

# (step, KPI as the test description words it, unit asked for, [(kind, KPI name in that kind's record)])
OBS01 = (
    ("1", "registration success rate", "%", (("fl", "ae_registration_success_rate"), ("clean-rerun", "cse_registration_success_rate"))),
    ("2", "handover completion latency", "ms", (("policy", "handover_duration_s"), ("poc2", "handover_duration_s"))),
    ("2", "handover failure/rollback rate", "%", (("policy", "handover_failure_rollback_rate"),)),
    ("3", "telemetry loss rate during handover", "%", (("policy", "telemetry_loss_during_handover"), ("policy", "telemetry_loss_rate"))),
    ("4", "FL round completion time", "s", (("fl", "fl_round_completion_time_s"),)),
    ("4", "FL participant success rate", "%", (("fl", "participant_success_rate_with_control_round"), ("fl", "participant_success_rate"))),
    ("4", "FL edge-cloud bandwidth", "MB", (("fl", "edge_cloud_bytes"),)),
)
_PRE = {"registration": "registration success rate", "handover": "handover completion latency", "fl_round": "FL round completion time"}


def _entry(rec, k, unit) -> dict:
    src = rec.get("source") or {}
    e = {"record_kind": rec["kind"], "record_file": src.get("file"), "record_sha256": src.get("sha256"), "name": k["name"],
         "numerator": k.get("numerator"), "denominator": k.get("denominator"), "N": k.get("N"), "unit": unit,
         "sim": rec.get("sim"), "scope": k.get("scope", ""), "basis": k.get("basis", "")}
    if "numerator" in k:
        e["value"] = k["value"]
    elif k["name"] == "edge_cloud_bytes":
        e["value"] = convert(k["value"], k["unit"], unit)
    else:
        e["value"] = "; ".join(convert(v, k["unit"], unit) if k["unit"] != unit else str(v) for v in k.get("values") or [k.get("value")])
    return e


def obs01(recs: list[dict]) -> dict:
    usable, refused, judged = [], [], []
    for rec in recs:
        j = rejudge(rec)
        judged.append(j)
        if j["same"] and not j["problems"] and j["verdict"] == "PASS":
            usable.append((rec, j))
        else:
            why = j["problems"] or ([f"judged {j['verdict']}, the record says {j['stored']}"] if not j["same"] else ["the run did not pass"])
            refused.append({"kind": rec.get("kind"), "file": (rec.get("source") or {}).get("file"), "why": why})
    rows = []
    for step, name, unit, sources in OBS01:
        entries = []
        for kind, kpi_name in sources:
            for rec, j in usable:
                if rec.get("kind") != kind:
                    continue
                for k in rec.get("kpi") or []:
                    if k.get("name") == kpi_name:
                        try:
                            e = _entry(rec, k, unit)
                        except ValueError:
                            continue
                        e["basis"] = e["basis"] if kpi_name not in j["recomputed"] or e["basis"].startswith("derived") \
                            else "recomputed from the data stored in the record"
                        entries.append(e)
        rows.append({"step": step, "kpi": name, "unit": unit, "status": "CAPTURED" if entries else "NOT-CAPTURED", "entries": entries})
    captured = {r["kpi"] for r in rows if r["status"] == "CAPTURED"}
    return {"rows": rows, "all_required_captured": len(captured) == len(rows), "refused": refused,
            "pre_test": {k: v in captured for k, v in _PRE.items()}}


# --- the export -------------------------------------------------------------------------------------------------

def load(path) -> tuple[dict, str]:
    data = Path(path).read_bytes()
    return json.loads(data), hashlib.sha256(data).hexdigest()


def _collect(paths) -> tuple[list, list]:
    recs, sources = [], []
    for p in paths:
        try:
            doc, sha = load(p)
            rec = normalise(doc, file=str(p), sha256=sha)
        except (OSError, ValueError) as e:
            sources.append({"file": str(p), "sha256": None, "kind": None, "problems": [f"cannot be read: {type(e).__name__}: {e}"]})
            continue
        j = rejudge(rec)
        counts = {r: sum(1 for x in rec["rows"] if x["result"] == r) for r in RESULTS}
        sources.append({"file": str(p), "sha256": sha, "kind": rec["kind"], "sim": rec["sim"], "device": rec["device"],
                        "verdict_stored": rec["verdict"], "verdict_rejudged": j["verdict"], "same": j["same"],
                        "problems": j["problems"], "rows": counts, "controls": len(rec["controls"]),
                        "recomputed": j["recomputed"], "not_recomputed": j["not_recomputed"],
                        "ev01_missing": rec["ev01_missing"], "commit": rec.get("commit"),
                        "uncommitted_paths": rec.get("uncommitted_paths"), "not_shown": rec.get("not_shown"),
                        "not_run": [x["row"] for x in rec["rows"] if x["result"] == "NOT-RUN"], "kpi": rec["kpi"]})
        recs.append(rec)
    return recs, sources


CSV_FIELDS = ("step", "kpi", "status", "value", "unit", "numerator", "denominator", "N", "sim", "basis", "scope",
              "record_kind", "name", "record_file", "record_sha256")


def _markdown(doc) -> str:
    t = doc["obs01"]
    sims = [s.get("sim") for s in doc["sources"] if s.get("kind")]
    label = "SIMULATED devices in every record" if sims and all(sims) else "NOT every record is of a simulated device: see the sim column"
    out = [f"# KPI export for TD_MEC_OBS_01 ({doc['stamp']})", "",
           f"{label}. Every number was worked out again from the data stored in its record unless the basis column "
           "says otherwise. Nothing is signed. This is not a conformance claim.", "",
           f"All seven KPIs of steps 1 to 4 captured: **{'yes' if t['all_required_captured'] else 'NO'}**. "
           f"Records refused: {len(t['refused'])}.", "",
           "| Step | KPI | Unit | Status | Value | n / d | N | Sim | Record | Basis |", "|---|---|---|---|---|---|---|---|---|---|"]
    for r in t["rows"]:
        if not r["entries"]:
            out.append(f"| {r['step']} | {r['kpi']} | {r['unit']} | NOT-CAPTURED | | | | | | no record supplies it |")
        for e in r["entries"]:
            nd = f"{e['numerator']} / {e['denominator']}" if e["numerator"] is not None else ""
            out.append(f"| {r['step']} | {r['kpi']} | {r['unit']} | CAPTURED | {e['value']} | {nd} | {e['N']} | "
                       f"{'yes' if e['sim'] else 'NO'} | {e['record_kind']} | {e['basis']} |")
    out += ["", "## Scope of each number", ""]
    for r in t["rows"]:
        for e in r["entries"]:
            if e["scope"]:
                out.append(f"- {r['kpi']} ({e['record_kind']}, {e['name']}): {e['scope']}")
    out += ["", "## Records", "", "| Kind | Stored | Re-judged | PASS | FAIL | NOT-RUN | Controls | Lacks (plan list) | SHA-256 | File |",
            "|---|---|---|---|---|---|---|---|---|---|"]
    for s in doc["sources"]:
        if not s.get("kind"):
            out.append(f"| unreadable | | | | | | | | | {s['file']} |")
            continue
        out.append(f"| {s['kind']} | {s['verdict_stored']} | {s['verdict_rejudged']} | {s['rows']['PASS']} | {s['rows']['FAIL']} | "
                   f"{s['rows']['NOT-RUN']} | {s['controls']} | {', '.join(s['ev01_missing']) or 'nothing'} | "
                   f"`{s['sha256'][:16]}` | {s['file']} |")
    for s in doc["sources"]:
        for p in s.get("problems") or []:
            out.append(f"\n- PROBLEM in {s['file']}: {p}")
    return "\n".join(out) + "\n"


def export(paths, out_dir, stamp: str | None = None) -> dict:
    """Write kpi_export_<stamp>.json, .csv and .md into out_dir; never over an existing file."""
    stamp = stamp or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    recs, sources = _collect(paths)
    table = obs01(recs)
    ok = table["all_required_captured"] and not table["refused"] and all(s.get("kind") for s in sources)
    doc = {"format": EXPORT_FORMAT, "stamp": stamp, "note": NOTE, "ok": ok,
           "exporter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "sources": sources, "obs01": table}
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {ext: out_dir / f"kpi_export_{stamp}.{ext}" for ext in ("json", "csv", "md")}
    for f in files.values():
        if f.exists():
            raise FileExistsError(str(f))
    with files["json"].open("x") as fh:
        json.dump(doc, fh, indent=1)
        fh.write("\n")
    with files["csv"].open("x", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in table["rows"]:
            head = {"step": r["step"], "kpi": r["kpi"], "status": r["status"], "unit": r["unit"]}
            for e in r["entries"] or [{}]:
                w.writerow({**e, **head})
    with files["md"].open("x") as fh:
        fh.write(_markdown(doc))
    return {"ok": ok, **files, "doc": doc}


def verify_export(path) -> list[str]:
    """An export against its records: same files (by SHA-256) and the same table from them."""
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        return [f"the export cannot be read: {type(e).__name__}: {e}"]
    if doc.get("format") != EXPORT_FORMAT:
        return [f"not an export of format {EXPORT_FORMAT}"]
    problems, paths = [], []
    for s in doc.get("sources") or []:
        try:
            _, sha = load(s["file"])
        except (OSError, ValueError) as e:
            problems.append(f"record {s.get('file')} cannot be read: {type(e).__name__}")
            continue
        if sha != s.get("sha256"):
            problems.append(f"record {s['file']}: sha256 is {sha[:16]}..., the export was made from {str(s.get('sha256'))[:16]}...")
        paths.append(s["file"])
    recs, _ = _collect(paths)
    if json.loads(json.dumps(obs01(recs))) != doc.get("obs01"):
        problems.append("the table in the export differs from what the records give now")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("record")
    e = sub.add_parser("export"); e.add_argument("records", nargs="+"); e.add_argument("--out", required=True); e.add_argument("--stamp")
    v = sub.add_parser("verify"); v.add_argument("export")
    a = ap.parse_args(argv)
    if a.cmd == "check":
        try:
            doc, sha = load(a.record)
            rec = normalise(doc, file=a.record, sha256=sha)
        except (OSError, ValueError) as ex:
            print(f"  cannot be read: {type(ex).__name__}: {ex}")
            return 1
        j = rejudge(rec)
        print(f"  {rec['kind']}  sha256 {sha[:16]}...  stored {j['stored']}, re-judged {j['verdict']}"
              f"{'' if rec['sim'] else '  (NOT simulated)'}")
        print(f"  recomputed from stored data: {', '.join(j['recomputed']) or 'none'}")
        print(f"  carried, not recomputed:     {', '.join(j['not_recomputed']) or 'none'}")
        if rec["ev01_missing"]:
            print(f"  lacks of the plan's list:    {', '.join(rec['ev01_missing'])}")
        for p in j["problems"]:
            print(f"  PROBLEM  {p}")
        good = j["same"] and not j["problems"]
        print(f"  {'the record holds' if good else 'THE RECORD DOES NOT HOLD'}")
        return 0 if good else 1
    if a.cmd == "export":
        out = export(a.records, a.out, a.stamp)
        t = out["doc"]["obs01"]
        for r in t["rows"]:
            vals = ", ".join(f"{x['value']} (N={x['N']}, {x['record_kind']})" for x in r["entries"])
            print(f"  step {r['step']}  {r['status']:<12}  {r['kpi']} [{r['unit']}]  {vals}")
        for r in t["refused"]:
            print(f"  REFUSED  {r['kind']} {r['file']}: {'; '.join(r['why'])}")
        for s in out["doc"]["sources"]:
            if not s.get("kind"):
                print(f"  UNREADABLE  {s['file']}: {'; '.join(s['problems'])}")
        print(f"  all seven KPIs captured: {t['all_required_captured']}; export ok: {out['ok']}")
        print(f"  {out['json']}\n  {out['csv']}\n  {out['md']}")
        return 0 if out["ok"] else 1
    problems = verify_export(a.export)
    for p in problems:
        print(f"  PROBLEM  {p}")
    print(f"  {'the export agrees with its records' if not problems else 'THE EXPORT DOES NOT AGREE WITH ITS RECORDS'}")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
