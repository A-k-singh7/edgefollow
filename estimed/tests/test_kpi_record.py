"""TD_MEC_OBS_01 (test plan 7.6.1.1): one record format for every run,
a KPI block (numerator, denominator, N, unit) and an exporter. Offline: no lab, no network, no file outside tmp_path.

The plan's proof for A5: "a record re-judged from its stored raw output gives the same verdict; an altered copy
fails". So each kind of record below is judged once as it is (the control: the judge does not refuse everything) and
then once per alteration, and every alteration must be reported.

The four records are small hand-made copies of the shapes the drivers wrote on 2026-11-18 (fl_run.py, policy_run.py,
clean_rerun.py, estimed_poc2.py). Every expected number is worked out in the comment beside it, none is taken from
kpi_record.

    /home/edgefollow/edgefollow-lab/.venv/bin/python -m pytest estimed/tests/test_kpi_record.py -q
"""
from __future__ import annotations

import copy
import csv
import hashlib
import json

import pytest

import kpi_record as kr


# --- the four shapes ----------------------------------------------------------------------------------------

def fl_record() -> dict:
    """Two rounds and a control round. Registrations: 3 of 3. Selected 2 + 3 + 2 = 7, accepted 2 + 2 + 1 = 5.
    Without the last (control) round: 4 of 5 = 80.0 %. With it: 5 of 7 = 71.428... -> 71.4 %.
    Rounds completed (quorum met): 2 of 2 = 100.0 %, with the control round 2 of 3 = 66.666... -> 66.7 %.
    Bytes: 1000 + 2500 = 3500 bytes = 0.0035 MB. Times 0.25 s and 4.5 s."""
    def rnd(n, selected, accepted, met, nbytes, secs):
        return {"round": n, "selected": [f"P{i}" for i in range(selected)], "time_s": secs, "bytes": nbytes,
                "record": {"accepted": [{"participantId": f"P{i}"} for i in range(accepted)],
                           "quorum": {"accepted": accepted, "met": met, "needed": 2, "selected": selected}}}
    return {
        "record": "estimed.fl.sim-run.v1", "device": "none: every source is simulated", "sim": True,
        "verdict": "PASS", "aborted_at": None,
        "preregistration": {"sha256": None, "go_phrase": None, "result": "NA", "reason": "host-only run"},
        "clock_offset": {"result": "NA", "reason": "one host"},
        "device_labels": {"flOrch": {"originator": "CflOrch", "sim": True}},
        "kpi": {"sim": True, "rates": {
            "participant_success_rate": {"numerator": 4, "denominator": 5, "N": 5, "unit": "%", "value": "80.0"},
            "participant_success_rate_with_control_round": {"numerator": 5, "denominator": 7, "N": 7, "unit": "%", "value": "71.4"},
            "round_completion_rate": {"numerator": 2, "denominator": 2, "N": 2, "unit": "%", "value": "100.0"},
            "round_completion_rate_with_control_round": {"numerator": 2, "denominator": 3, "N": 3, "unit": "%", "value": "66.7"},
            "ae_registration_success_rate": {"numerator": 3, "denominator": 3, "N": 3, "unit": "%", "value": "100.0"}},
            "fl_round_completion_time_s": {"values": ["0.250", "4.500"], "N": 2, "unit": "s"},
            "edge_cloud_bytes": {"values": [1000, 2500], "N": 2, "unit": "bytes", "total": 3500, "total_MB": "0.003500"}},
        "steps": [{"step": "the IN-CSE answers", "pass": True, "detail": ""},
                  {"step": "round 1 published a model", "pass": True, "detail": ""},
                  {"step": "CONTROL (must FAIL) a replayed update was accepted", "pass": False, "detail": "excluded"}],
        "controls": [{"control": "CONTROL (must FAIL) a replayed update was accepted", "expected": "FAIL", "observed": "FAIL"}],
        "not_run": [{"row": "signature of the update", "result": "NOT-RUN", "reason": "no key is created"}],
        "not_shown": ["a real device"],
        "rounds": [rnd(1, 2, 2, True, 1000, 0.25), rnd(2, 3, 2, True, 2500, 4.5), rnd(3, 2, 1, False, 900, 0.3)],
        "cleanup": {"flOrch": 200, "left_on_the_CSEs": []},
        "run": {"commit": "a" * 40, "uncommitted_paths": 0, "files_sha256": {"estimed_poc/fl_run.py": "b" * 64}},
        "raw": {"requests": 5, "trace": [
            "1 CAdmin GET cse-in ty=- -> 200 743B | topology check",
            "2 CAdmin GET cse-in/flOrch ty=- -> 404 54B",
            "3 CflOrch POST cse-in ty=2 -> 201 441B | register flOrch",
            "4 CflAgg POST cse-mn-a ty=2 -> 201 435B | register flAgg",
            "5 CflNat POST cse-mn-a ty=2 -> 201 427B edge-cloud | register flNat"]}}


def policy_record() -> dict:
    """Two handovers started, one rolled back, one completed in 9.81 s: rollback rate 1 of 2 = 50.0 %, latency 9810 ms.
    Device posts: 186 accepted, 0 failed: loss 0 of 186 = 0.0 %."""
    return {
        "record": "estimed.policy-handover.sim-run.v1", "device": "none: the device is simulated", "sim": True,
        "verdict": "PASS", "aborted_at": None,
        "preregistration": {"sha256": None, "go_phrase": None, "result": "NA", "reason": "host-only run"},
        "clock_offset": {"result": "NA", "reason": "one host"},
        "device_labels": {"vehicle01": {"originator": "Cvehicle01", "sim": True}},
        "kpi": {"sim": True,
                "handover_duration_s": {"values": [9.81], "N": 1, "unit": "s", "sim": True},
                "ping_round_trip_no_delay_ms": {"N": 5, "unit": "ms", "sim": True, "min": 7.5, "median": 8.4, "max": 8.5},
                "device_posts_during_conflict": {"numerator": 38, "denominator": 38, "N": 38,
                                                 "unit": "posts accepted by edge A", "sim": True}},
        "steps": [{"step": "step 2: the handover was started by the policy engine", "pass": True, "detail": ""},
                  {"step": "CONTROL (must FAIL) a conflict started a handover anyway", "pass": False, "detail": ""}],
        "controls": [{"control": "CONTROL (must FAIL) a conflict started a handover anyway", "expected": "FAIL", "observed": "FAIL"}],
        "not_run": [], "not_shown": ["a radio effect"],
        "cleanup": {"left_on_the_CSEs": []},
        "run": {"commit": "a" * 40, "uncommitted_paths": 0, "files_sha256": {"estimed_poc/policy_run.py": "c" * 64}},
        "raw": {"device": {"posts_accepted": 186, "posts_failed": 0, "commands_answered": 71},
                "events_on_the_IN_CSE": [
                    {"event": "policy-conflict", "handover_started": False},
                    {"event": "handover-started", "source": "/id-mn-a", "target": "/id-mn-b"},
                    {"event": "target-registration-refused", "seconds": 0.93, "rolled_back": True},
                    {"event": "handover-started", "source": "/id-mn-a", "target": "/id-mn-b"},
                    {"event": "handover-completed", "seconds": 9.81}]}}


def clean_record() -> dict:
    """Two test descriptions: 12 of 12 and 9 of 9 = 100.0 %. Both MN-CSEs registered: 2 of 2 = 100.0 %."""
    def res(td, n):
        return {"td": td, "ok": True, "problems": [], "declared": n, "ran": n, "ids": [f"t{i}" for i in range(n)],
                "passed": n, "failed": 0, "error": 0, "skipped": 0}
    def tp(n):
        return {"numerator": n, "denominator": n, "N": n, "value": 100.0, "ids": [f"t{i}" for i in range(n)]}
    half = {"tests_passed": {"TD_MEC_PF_01": tp(12), "TD_MEC_REG_01": tp(9)},
            "cse_registration_success": {"numerator": 2, "denominator": 2, "N": 2, "value": 100.0,
                                         "per_cse": {"cse-mn-a": True, "cse-mn-b": True}}}
    return {
        "kind": "rerun", "result": "PASS", "budget_s": {"value": 900.0},
        "provenance": {"script_sha256": "d" * 64, "runbook_sha256": "e" * 64},
        "manifest": {"commit": "a" * 40},
        "results": {"TD_MEC_PF_01": res("TD_MEC_PF_01", 12), "TD_MEC_REG_01": res("TD_MEC_REG_01", 9)},
        "kpi": {"equal_by_construction": {"reference": copy.deepcopy(half), "rerun": half},
                "timings": {"empty_directory_to_last_test_description_s": 29.293}},
        "steps": [{"row": "step 1: fresh copy made", "ok": True, "detail": ""}],
        "controls": [{"row": "CONTROL (must FAIL) a skipped test is counted as passed", "passed": False,
                      "failed_as_it_must": True, "detail": ""}],
        "not_run": [{"row": "a fresh VM", "result": "NOT-RUN", "reason": "no VM tool"}]}


def poc2_record() -> dict:
    return {
        "device": "sim", "verdict": "PASS", "aborted_at": None,
        "measurements": {"device": "sim", "telemetry_pause_s": 12.93, "notification_gap_s": 12.93,
                         "handover_duration_s": 20.33, "handover_txn": "96a7"},
        "run": {"commit": "a" * 40, "uncommitted_paths": 5, "files_sha256": {"phone/estimed_poc2.py": "f" * 64}},
        "steps": [{"step": "simulated vehicle posting on edge A", "pass": True, "detail": ""},
                  {"step": "CONTROL (must FAIL) a stranger read the vehicle", "pass": False, "detail": "HTTP 403"}]}


SHAPES = {"fl": fl_record, "policy": policy_record, "clean-rerun": clean_record, "poc2": poc2_record}


def judged(doc: dict) -> dict:
    return kr.rejudge(kr.normalise(doc))


def kpi(rec: dict, name: str) -> dict:
    hit = [k for k in rec["kpi"] if k["name"] == name]
    assert len(hit) == 1, (name, [k["name"] for k in rec["kpi"]])
    return hit[0]


# --- the kind of a record and the common format -------------------------------------------------------------

@pytest.mark.parametrize("kind", sorted(SHAPES))
def test_each_shape_is_recognised_and_becomes_the_one_format(kind):
    rec = kr.normalise(SHAPES[kind]())
    assert rec["format"] == "estimed.run-record.v1" and rec["kind"] == kind
    assert kr.validate(rec) == []
    assert rec["verdict"] == "PASS"


def test_a_record_of_no_known_shape_is_refused():
    with pytest.raises(kr.Unknown):
        kr.normalise({"hello": 1})
    with pytest.raises(kr.Unknown):
        kr.normalise({"kind": "reference", "result": "PASS"})      # the rerun's reference file is not a run record


def test_a_record_already_in_the_one_format_is_taken_as_it_is():
    rec = kr.normalise(policy_record())
    again = kr.normalise(json.loads(json.dumps(rec)))
    assert again == rec and again["kind"] == "policy"


def test_rows_are_pass_fail_or_not_run_and_controls_are_kept_apart():
    rec = kr.normalise(fl_record())
    assert [(r["row"], r["result"]) for r in rec["rows"]] == [
        ("the IN-CSE answers", "PASS"), ("round 1 published a model", "PASS"), ("signature of the update", "NOT-RUN")]
    assert rec["rows"][2]["reason"] == "no key is created"
    assert rec["controls"] == [{"control": "CONTROL (must FAIL) a replayed update was accepted",
                                "expected": "FAIL", "observed": "FAIL"}]


def test_sim_is_carried_and_a_poc2_record_says_so_by_its_device():
    assert kr.normalise(fl_record())["sim"] is True
    assert kr.normalise(poc2_record())["sim"] is True
    real = poc2_record(); real["device"] = real["measurements"]["device"] = "pixel"
    assert kr.normalise(real)["sim"] is False


def test_what_a_record_lacks_of_the_plan_s_list_is_named():
    """Plan section 9: preregistration, device labels, hashes, raw output, rows, controls, a KPI block with N, clock
    offset, what the run does not show."""
    assert kr.normalise(fl_record())["ev01_missing"] == []
    assert kr.normalise(poc2_record())["ev01_missing"] == [
        "preregistration", "device_labels", "raw", "clock_offset", "not_shown"]


def test_validate_refuses_a_malformed_record():
    rec = kr.normalise(policy_record())
    bad = copy.deepcopy(rec); bad["rows"][0]["result"] = "SKIPPED"
    assert any("SKIPPED" in p for p in kr.validate(bad))
    bad = copy.deepcopy(rec); bad["rows"].append({"row": "x", "result": "NOT-RUN", "reason": ""})
    assert any("reason" in p for p in kr.validate(bad))
    bad = copy.deepcopy(rec); del kpi(bad, "handover_duration_s")["N"]
    assert any("N" in p for p in kr.validate(bad))
    bad = copy.deepcopy(rec); kpi(bad, "handover_duration_s")["unit"] = ""
    assert any("unit" in p for p in kr.validate(bad))
    bad = copy.deepcopy(rec); del bad["verdict"]
    assert kr.validate(bad)


# --- numbers ------------------------------------------------------------------------------------------------

def test_a_rate_is_written_to_one_decimal_half_up_from_exact_arithmetic():
    assert kr.pct(2, 3) == "66.7"       # 66.666...
    assert kr.pct(1, 16) == "6.3"       # 6.25 exactly, half up
    assert kr.pct(0, 186) == "0.0"
    assert kr.pct(8, 8) == "100.0"


def test_a_rate_without_a_denominator_is_not_a_rate():
    with pytest.raises(ValueError):
        kr.pct(0, 0)
    with pytest.raises(ValueError):
        kr.pct(3, 2)                     # more successes than attempts


def test_unit_changes_are_exact():
    assert kr.convert("9.81", "s", "ms") == "9810"
    assert kr.convert(80831, "bytes", "MB") == "0.080831"      # 1 MB = 1 000 000 bytes
    assert kr.convert("20.33", "s", "ms") == "20330"
    with pytest.raises(ValueError):
        kr.convert(1, "s", "MB")


# --- the KPI block of each kind -----------------------------------------------------------------------------

def test_fl_kpis_carry_numerator_denominator_n_and_unit():
    rec = kr.normalise(fl_record())
    k = kpi(rec, "ae_registration_success_rate")
    assert (k["numerator"], k["denominator"], k["N"], k["unit"], k["value"]) == (3, 3, 3, "%", "100.0")
    k = kpi(rec, "participant_success_rate_with_control_round")
    assert (k["numerator"], k["denominator"], k["N"], k["value"]) == (5, 7, 7, "71.4")
    k = kpi(rec, "fl_round_completion_time_s")
    assert (k["values"], k["N"], k["unit"]) == (["0.250", "4.500"], 2, "s")
    k = kpi(rec, "edge_cloud_bytes")
    assert (k["value"], k["N"], k["unit"]) == ("3500", 2, "bytes")
    assert all(x["sim"] is True for x in rec["kpi"])


def test_policy_kpis_include_two_the_exporter_derives_from_the_stored_events_and_counters():
    rec = kr.normalise(policy_record())
    k = kpi(rec, "handover_failure_rollback_rate")
    assert (k["numerator"], k["denominator"], k["N"], k["unit"], k["value"]) == (1, 2, 2, "%", "50.0")
    assert k["basis"].startswith("derived")
    k = kpi(rec, "telemetry_loss_rate")
    assert (k["numerator"], k["denominator"], k["N"], k["unit"], k["value"]) == (0, 186, 186, "%", "0.0")
    assert "whole run" in k["scope"]
    assert kpi(rec, "handover_duration_s")["values"] == ["9.81"]


def test_a_policy_run_with_no_handover_has_no_rollback_rate():
    doc = policy_record(); doc["raw"]["events_on_the_IN_CSE"] = [{"event": "policy-conflict"}]
    doc["kpi"].pop("handover_duration_s")
    names = [k["name"] for k in kr.normalise(doc)["kpi"]]
    assert "handover_failure_rollback_rate" not in names


def test_clean_rerun_kpis_are_one_rate_per_test_description():
    rec = kr.normalise(clean_record())
    k = kpi(rec, "tests_passed:TD_MEC_PF_01")
    assert (k["numerator"], k["denominator"], k["N"], k["value"], k["unit"]) == (12, 12, 12, "100.0", "%")
    k = kpi(rec, "cse_registration_success_rate")
    assert (k["numerator"], k["denominator"], k["N"], k["value"]) == (2, 2, 2, "100.0")
    assert kpi(rec, "empty_directory_to_last_test_description_s")["value"] == "29.293"


def test_poc2_measurements_are_single_values_marked_as_stored_only():
    rec = kr.normalise(poc2_record())
    k = kpi(rec, "handover_duration_s")
    assert (k["values"], k["N"], k["unit"]) == (["20.33"], 1, "s")
    assert k["basis"].startswith("stored only")


# --- re-judging: the same verdict from what is stored, and an altered copy fails ----------------------------

@pytest.mark.parametrize("kind", sorted(SHAPES))
def test_control_an_unaltered_record_is_judged_as_it_was(kind):
    j = judged(SHAPES[kind]())
    assert j["verdict"] == "PASS" and j["same"] is True and j["problems"] == [], j


def test_a_failed_run_is_judged_fail_and_agrees_with_its_stored_verdict():
    doc = fl_record(); doc["steps"][1]["pass"] = False; doc["verdict"] = "FAIL"
    j = judged(doc)
    assert j["verdict"] == "FAIL" and j["same"] is True


def _set(path, value):
    def alter(doc):
        o = doc
        for p in path[:-1]:
            o = o[p]
        o[path[-1]] = value
    return alter


def _fl_drop_registration(doc):
    doc["raw"]["trace"][3] = "4 CflAgg POST cse-mn-a ty=2 -> 403 435B | register flAgg"


def _fl_drop_accepted(doc):
    doc["rounds"][0]["record"]["accepted"].pop()


def _policy_drop_rollback(doc):
    del doc["raw"]["events_on_the_IN_CSE"][2]


ALTERED = [
    ("fl", "a failed step under a PASS verdict", _set(("steps", 1, "pass"), False)),
    ("fl", "a control that went through", _set(("steps", 2, "pass"), True)),
    ("fl", "the list of controls says other than the steps", _set(("controls", 0, "observed"), "PASS")),
    ("fl", "no control at all", lambda d: (d["steps"].pop(), d["controls"].clear())),
    ("fl", "a run that stopped early", _set(("aborted_at",), "round 2")),
    ("fl", "something left on the CSEs", _set(("cleanup", "left_on_the_CSEs"), ["IN: flOrch"])),
    ("fl", "a FAIL verdict over rows that all pass", _set(("verdict",), "FAIL")),
    ("fl", "a numerator", _set(("kpi", "rates", "ae_registration_success_rate", "numerator"), 2)),
    ("fl", "a rate's value", _set(("kpi", "rates", "participant_success_rate_with_control_round", "value"), "99.0")),
    ("fl", "an N that is not the denominator", _set(("kpi", "rates", "round_completion_rate", "N"), 9)),
    ("fl", "a registration refused in the trace", _fl_drop_registration),
    ("fl", "an accepted update removed from a round", _fl_drop_accepted),
    ("fl", "a round's bytes", _set(("rounds", 1, "bytes"), 2501)),
    ("fl", "a round's time", _set(("rounds", 0, "time_s"), 0.35)),
    ("fl", "the total in megabytes", _set(("kpi", "edge_cloud_bytes", "total_MB"), "0.035")),
    ("policy", "a failed step under a PASS verdict", _set(("steps", 0, "pass"), False)),
    ("policy", "the handover's duration in the event", _set(("raw", "events_on_the_IN_CSE", 4, "seconds"), 1.0)),
    ("policy", "the handover's duration in the KPI block", _set(("kpi", "handover_duration_s", "values"), [1.0])),
    ("policy", "the N of the durations", _set(("kpi", "handover_duration_s", "N"), 3)),
    ("clean-rerun", "a step that is not ok", _set(("steps", 0, "ok"), False)),
    ("clean-rerun", "a control that passed", _set(("controls", 0, "passed"), True)),
    ("clean-rerun", "a control that did not fail as it must", _set(("controls", 0, "failed_as_it_must"), False)),
    ("clean-rerun", "a test description that is not ok", _set(("results", "TD_MEC_REG_01", "ok"), False)),
    ("clean-rerun", "a skipped test behind a full count", _set(("results", "TD_MEC_PF_01", "skipped"), 1)),
    ("clean-rerun", "a passed count", _set(("results", "TD_MEC_PF_01", "passed"), 11)),
    ("clean-rerun", "a numerator", _set(("kpi", "equal_by_construction", "rerun", "tests_passed", "TD_MEC_REG_01", "numerator"), 8)),
    ("clean-rerun", "an edge that did not register", _set(("kpi", "equal_by_construction", "rerun", "cse_registration_success", "per_cse", "cse-mn-b"), False)),
    ("poc2", "a failed step under a PASS verdict", _set(("steps", 0, "pass"), False)),
    ("poc2", "a control that went through", _set(("steps", 1, "pass"), True)),
    ("poc2", "a run that stopped early", _set(("aborted_at",), "setup")),
]


@pytest.mark.parametrize("kind,what,alter", ALTERED, ids=[f"{k}: {w}" for k, w, _ in ALTERED])
def test_an_altered_copy_fails(kind, what, alter):
    doc = SHAPES[kind]()
    alter(doc)
    j = judged(doc)
    assert j["same"] is False or j["problems"], f"altered ({what}) and nothing was reported: {j}"


def test_the_derived_rollback_rate_follows_the_stored_events():
    doc = policy_record(); _policy_drop_rollback(doc)
    k = kpi(kr.normalise(doc), "handover_failure_rollback_rate")
    assert (k["numerator"], k["denominator"]) == (0, 2)


def test_rejudge_says_which_kpis_it_recomputed_and_which_it_only_carried():
    j = judged(fl_record())
    assert "ae_registration_success_rate" in j["recomputed"] and "edge_cloud_bytes" in j["recomputed"]
    j = judged(policy_record())
    assert "handover_duration_s" in j["recomputed"]
    assert "ping_round_trip_no_delay_ms" in j["not_recomputed"]
    j = judged(poc2_record())
    assert j["recomputed"] == [] and "handover_duration_s" in j["not_recomputed"]


def test_a_device_run_that_lacks_part_of_the_plan_s_list_fails_and_a_simulated_one_only_lists_it():
    sim = judged(poc2_record())
    assert sim["problems"] == []
    real = poc2_record(); real["device"] = real["measurements"]["device"] = "pixel"
    j = judged(real)
    assert any("preregistration" in p for p in j["problems"])


# --- the table TD_MEC_OBS_01 asks for -------------------------------------------------------------------------

REQUIRED = [("1", "registration success rate", "%"), ("2", "handover completion latency", "ms"),
            ("2", "handover failure/rollback rate", "%"), ("3", "telemetry loss rate during handover", "%"),
            ("4", "FL round completion time", "s"), ("4", "FL participant success rate", "%"),
            ("4", "FL edge-cloud bandwidth", "MB")]


def all_four():
    return [kr.normalise(f()) for f in (fl_record, policy_record, clean_record, poc2_record)]


def row(table, name):
    hit = [r for r in table["rows"] if r["kpi"] == name]
    assert len(hit) == 1, (name, [r["kpi"] for r in table["rows"]])
    return hit[0]


def test_the_table_has_the_seven_kpis_of_steps_1_to_4_with_their_units():
    t = kr.obs01(all_four())
    assert [(r["step"], r["kpi"], r["unit"]) for r in t["rows"]] == REQUIRED
    assert all(r["status"] == "CAPTURED" for r in t["rows"]) and t["all_required_captured"] is True


def test_values_in_the_table_are_in_the_unit_the_test_description_names():
    t = kr.obs01(all_four())
    lat = row(t, "handover completion latency")["entries"]
    assert sorted(e["value"] for e in lat) == ["20330", "9810"] and all(e["N"] == 1 for e in lat)
    assert [e["value"] for e in row(t, "FL edge-cloud bandwidth")["entries"]] == ["0.0035"]
    e = row(t, "handover failure/rollback rate")["entries"][0]
    assert (e["numerator"], e["denominator"], e["N"], e["value"]) == (1, 2, 2, "50.0")
    e = row(t, "FL participant success rate")["entries"]
    assert [(x["numerator"], x["denominator"], x["value"]) for x in e] == [(5, 7, "71.4"), (4, 5, "80.0")]
    assert [x["value"] for x in row(t, "FL round completion time")["entries"]] == ["0.250; 4.500"]
    reg = row(t, "registration success rate")["entries"]
    assert sorted((x["record_kind"], x["numerator"], x["denominator"]) for x in reg) == [("clean-rerun", 2, 2), ("fl", 3, 3)]


def test_every_entry_names_its_record_and_whether_it_is_simulated():
    t = kr.obs01(all_four())
    for r in t["rows"]:
        for e in r["entries"]:
            assert e["sim"] is True and e["record_kind"] and e["basis"] and "N" in e


def test_a_kpi_no_record_supplies_is_not_captured_and_the_table_says_so():
    t = kr.obs01([kr.normalise(policy_record()), kr.normalise(clean_record())])
    assert row(t, "FL round completion time")["status"] == "NOT-CAPTURED"
    assert row(t, "FL round completion time")["entries"] == []
    assert row(t, "handover completion latency")["status"] == "CAPTURED"
    assert t["all_required_captured"] is False


def test_a_record_that_fails_its_re_judging_supplies_nothing():
    bad = fl_record(); bad["steps"][1]["pass"] = False            # verdict still says PASS
    t = kr.obs01([kr.normalise(bad), kr.normalise(policy_record())])
    assert row(t, "FL participant success rate")["status"] == "NOT-CAPTURED"
    assert t["refused"] and "fl" in t["refused"][0]["kind"]


def test_a_run_judged_fail_supplies_nothing_either():
    bad = fl_record(); bad["steps"][1]["pass"] = False; bad["verdict"] = "FAIL"
    t = kr.obs01([kr.normalise(bad)])
    assert row(t, "FL participant success rate")["status"] == "NOT-CAPTURED"


def test_the_pre_test_condition_is_read_off_the_records():
    """One registration test, one handover test and one FL round have been executed (test plan 7.6.1.1)."""
    assert kr.obs01(all_four())["pre_test"] == {"registration": True, "handover": True, "fl_round": True}
    assert kr.obs01([kr.normalise(clean_record())])["pre_test"] == {"registration": True, "handover": False, "fl_round": False}


# --- the export (step 5) and its own check --------------------------------------------------------------------

def write_all(tmp_path):
    paths = []
    for name, f in SHAPES.items():
        p = tmp_path / f"{name}.json"
        p.write_text(json.dumps(f()))
        paths.append(p)
    return paths


def test_the_export_is_written_as_json_csv_and_markdown(tmp_path):
    out = kr.export(write_all(tmp_path), tmp_path / "out", stamp="20261119T000000Z")
    assert out["ok"] is True
    doc = json.loads(out["json"].read_text())
    assert doc["format"] == "estimed.kpi-export.v1" and doc["obs01"]["all_required_captured"] is True
    assert len(doc["sources"]) == 4
    for s in doc["sources"]:
        assert s["sha256"] == hashlib.sha256((tmp_path / s["file"].rsplit("/", 1)[-1]).read_bytes()).hexdigest()
    rows = list(csv.DictReader(out["csv"].open(newline="")))
    assert {"step", "kpi", "status", "value", "unit", "numerator", "denominator", "N", "sim", "record_sha256"} <= set(rows[0])
    assert len(rows) == 10          # entries: 2 registration, 2 latency, 1 rollback, 1 loss, 1 time, 2 participant, 1 bandwidth
    md = out["md"].read_text()
    assert "| 2 | handover completion latency |" in md and "SIMULATED" in md and "not a conformance claim" in md


def test_a_not_captured_kpi_is_a_line_of_the_csv_and_the_export_is_not_ok(tmp_path):
    p = tmp_path / "policy.json"; p.write_text(json.dumps(policy_record()))
    out = kr.export([p], tmp_path / "out", stamp="20261119T000000Z")
    assert out["ok"] is False
    rows = list(csv.DictReader(out["csv"].open(newline="")))
    assert [r["kpi"] for r in rows if r["status"] == "NOT-CAPTURED"] == [
        "registration success rate", "FL round completion time", "FL participant success rate", "FL edge-cloud bandwidth"]


def test_control_an_export_checks_against_its_records(tmp_path):
    out = kr.export(write_all(tmp_path), tmp_path / "out", stamp="20261119T000000Z")
    assert kr.verify_export(out["json"]) == []


def test_an_export_whose_record_was_changed_afterwards_fails_its_check(tmp_path):
    paths = write_all(tmp_path)
    out = kr.export(paths, tmp_path / "out", stamp="20261119T000000Z")
    doc = fl_record(); doc["kpi"]["rates"]["ae_registration_success_rate"]["note"] = "x"      # one harmless-looking byte
    paths[0].write_text(json.dumps(doc))
    assert any("sha256" in p for p in kr.verify_export(out["json"]))


def test_an_export_whose_own_numbers_were_changed_fails_its_check(tmp_path):
    out = kr.export(write_all(tmp_path), tmp_path / "out", stamp="20261119T000000Z")
    doc = json.loads(out["json"].read_text())
    for r in doc["obs01"]["rows"]:
        if r["kpi"] == "handover failure/rollback rate":
            r["entries"][0]["value"] = "0.0"
    out["json"].write_text(json.dumps(doc))
    assert any("differs" in p for p in kr.verify_export(out["json"]))


def test_an_export_whose_record_is_gone_fails_its_check(tmp_path):
    paths = write_all(tmp_path)
    out = kr.export(paths, tmp_path / "out", stamp="20261119T000000Z")
    paths[1].unlink()
    assert any("cannot be read" in p for p in kr.verify_export(out["json"]))


def test_the_command_line_exits_0_only_when_every_record_holds_and_every_kpi_is_captured(tmp_path, capsys):
    paths = [str(p) for p in write_all(tmp_path)]
    assert kr.main(["export", *paths, "--out", str(tmp_path / "o1"), "--stamp", "20261119T000000Z"]) == 0
    assert kr.main(["export", paths[1], "--out", str(tmp_path / "o2"), "--stamp", "20261119T000000Z"]) == 1
    bad = fl_record(); bad["steps"][1]["pass"] = False
    (tmp_path / "bad.json").write_text(json.dumps(bad))
    assert kr.main(["check", str(tmp_path / "bad.json")]) == 1
    assert kr.main(["check", paths[0]]) == 0
    assert "PASS" in capsys.readouterr().out


def test_an_export_never_overwrites_an_earlier_one(tmp_path):
    paths = write_all(tmp_path)
    kr.export(paths, tmp_path / "out", stamp="20261119T000000Z")
    with pytest.raises(FileExistsError):
        kr.export(paths, tmp_path / "out", stamp="20261119T000000Z")


# --- added after the planted-fault run of 2026-11-19 (each of these was a fault no test above noticed) ----------

def test_a_step_with_no_outcome_is_a_failed_row():
    doc = fl_record(); del doc["steps"][1]["pass"]
    rec = kr.normalise(doc)
    assert rec["rows"][1]["result"] == "FAIL" and kr.rejudge(rec)["verdict"] == "FAIL"


def test_one_control_going_through_among_several_fails_the_run():
    doc = fl_record()
    doc["steps"].append({"step": "CONTROL (must FAIL) a poisoned update was accepted", "pass": True, "detail": ""})
    doc["controls"].append({"control": "CONTROL (must FAIL) a poisoned update was accepted", "expected": "FAIL", "observed": "PASS"})
    j = judged(doc)
    assert j["verdict"] == "FAIL" and j["same"] is False


def test_a_round_time_is_compared_to_the_millisecond():
    doc = fl_record(); doc["rounds"][0]["time_s"] = 0.2760549          # the record writes 0.276
    doc["kpi"]["fl_round_completion_time_s"]["values"][0] = "0.276"
    assert judged(doc)["problems"] == []
    doc["kpi"]["fl_round_completion_time_s"]["values"][0] = "0.28"
    assert any("fl_round_completion_time_s" in p for p in judged(doc)["problems"])


def test_n_must_be_the_number_of_values_also_where_nothing_is_recomputed():
    doc = fl_record(); doc["kpi"]["held_out_error"] = {"values": [89, 92, 84], "N": 2, "unit": "tenths of a degree C"}
    assert any("held_out_error" in p for p in judged(doc)["problems"])
    doc["kpi"]["held_out_error"]["N"] = 3
    assert judged(doc)["problems"] == []


def test_a_round_whose_quorum_line_disagrees_with_its_lists_is_reported():
    doc = fl_record(); doc["rounds"][0]["record"]["quorum"]["accepted"] = 3      # the list still holds 2
    assert any("round 1" in p for p in judged(doc)["problems"])


def test_a_test_description_that_ran_fewer_tests_than_it_declares_is_reported():
    doc = clean_record(); doc["results"]["TD_MEC_PF_01"]["ran"] = 11             # passed still says 12
    assert any("TD_MEC_PF_01" in p for p in judged(doc)["problems"])


def test_a_record_stored_as_fail_over_rows_that_pass_supplies_nothing():
    doc = fl_record(); doc["verdict"] = "FAIL"
    t = kr.obs01([kr.normalise(doc)])
    assert row(t, "FL participant success rate")["status"] == "NOT-CAPTURED" and t["refused"]


def test_a_passing_record_with_a_kpi_that_does_not_follow_from_its_data_supplies_nothing():
    doc = policy_record(); doc["kpi"]["handover_duration_s"]["values"] = [1.0]
    j = judged(doc)
    assert j["verdict"] == "PASS" and j["same"] is True and j["problems"]
    t = kr.obs01([kr.normalise(doc)])
    assert row(t, "handover completion latency")["status"] == "NOT-CAPTURED"
    assert row(t, "handover failure/rollback rate")["status"] == "NOT-CAPTURED" and t["refused"]


# --- telemetry lost during the handover transitions, windowed (the policy driver stores this since 2026-11-19) ------

def policy_record_windowed() -> dict:
    """Posts at 1.0, 5.0, 6.0, 7.0 fall inside the windows 0.4-1.3 and 4.5-8.0; the post at 9.0 does not.
    All four accepted: 0 of 4 lost = 0.0 %."""
    doc = policy_record()
    doc["raw"]["device_posts"] = {"posts": [[1.0, "radio", True], [5.0, "radio", True], [6.0, "radio", True],
                                            [7.0, "ack", True], [9.0, "radio", True]]}
    doc["raw"]["handover_windows"] = [[0.4, 1.3, "rolled-back"], [4.5, 8.0, "completed"]]
    doc["kpi"]["telemetry_loss_during_handover"] = {"numerator": 0, "denominator": 4, "N": 4, "unit": "%", "value": "0.0", "sim": True}
    return doc


def test_the_windowed_loss_rate_is_taken_from_the_record_and_recomputed_from_its_posts_and_windows():
    rec = kr.normalise(policy_record_windowed())
    k = kpi(rec, "telemetry_loss_during_handover")
    assert (k["numerator"], k["denominator"], k["N"], k["unit"], k["value"]) == (0, 4, 4, "%", "0.0")
    j = kr.rejudge(rec)
    assert j["problems"] == [] and "telemetry_loss_during_handover" in j["recomputed"]


WINDOWED = [
    ("a post inside a window turned into a refused one", _set(("raw", "device_posts", "posts", 1, 2), False)),
    ("a post still held at the end", _set(("raw", "device_posts", "posts", 2, 2), None)),
    ("a window made wider", _set(("raw", "handover_windows", 1, 1), 9.5)),
    ("a window removed", lambda d: d["raw"]["handover_windows"].pop()),
    ("the numerator", _set(("kpi", "telemetry_loss_during_handover", "numerator"), 1)),
    ("the value", _set(("kpi", "telemetry_loss_during_handover", "value"), "25.0")),
    ("the posts removed and the KPI kept", lambda d: d["raw"].pop("device_posts")),
]


@pytest.mark.parametrize("what,alter", WINDOWED, ids=[w for w, _ in WINDOWED])
def test_an_altered_windowed_loss_fails(what, alter):
    doc = policy_record_windowed()
    alter(doc)
    assert judged(doc)["problems"], what


def test_the_table_puts_the_windowed_loss_first_and_keeps_the_whole_run_figure_beside_it():
    t = kr.obs01([kr.normalise(policy_record_windowed())])
    e = row(t, "telemetry loss rate during handover")["entries"]
    assert [(x["name"], x["numerator"], x["denominator"]) for x in e] == [
        ("telemetry_loss_during_handover", 0, 4), ("telemetry_loss_rate", 0, 186)]


def test_a_stored_rate_value_of_the_policy_record_is_checked_not_rewritten():
    doc = policy_record(); doc["kpi"]["device_posts_during_conflict"].update(unit="%", value="50.0")     # 38 of 38 is 100.0
    assert any("device_posts_during_conflict" in p for p in judged(doc)["problems"])
