"""Offline checks for clean_rerun.py and RUNBOOK.md (TD_MEC_OBS_03) -- no CSE, no
network, no git: the runbook parser, the copy and its manifest on a small fixture tree, the run-directory rule, the
counting of test outcomes, the KPI comparison and the rule that only runbook commands are executed.

Every expected value is written by hand here (the SHA-256 of "abc" is the FIPS 180-2 example), none is taken from
clean_rerun. A test named *_control_* plants a fault and requires the code to refuse it.

    /home/edgefollow/edgefollow-lab/.venv/bin/python -B -m pytest -p no:cacheprovider estimed/tests/test_clean_rerun.py -q
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

import clean_rerun as cr

EST = Path(__file__).resolve().parent.parent
RUNBOOK = EST / "RUNBOOK.md"
SHA_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
TDS = ["TD_MEC_PF_01", "TD_MEC_REG_01", "TD_MEC_REG_02", "TD_MEC_REG_03", "TD_MEC_DEV_01"]

MINI = """# title

```sh
: runbook-step variables phase=variables && \\
export ROOT=/x/code && export OUT=/x/out
```

text

```sh
: runbook-step install-a phase=install && echo "$ROOT"
```

```sh
: runbook-step start phase=bootstrap && cd "$ROOT" && echo up
```

```sh
: runbook-step t1 phase=test td=TD_MEC_PF_01 tests=2 && \\
cd "$ROOT" && echo "$OUT/TD_MEC_PF_01.xml"
```

```sh
: runbook-step stop phase=shutdown && cd "$ROOT" && echo down
```

```text
an example of output, not a command
```
"""


# ---------------------------------------------------------------------------------------- the runbook parser
def test_parser_reads_steps_in_file_order_with_phase_and_td():
    rb = cr.parse_runbook(MINI)
    assert [(s.id, s.phase) for s in rb.steps] == [("variables", "variables"), ("install-a", "install"),
                                                   ("start", "bootstrap"), ("t1", "test"), ("stop", "shutdown")]
    assert rb.variables == {"ROOT": "/x/code", "OUT": "/x/out"}
    t1 = rb.steps[3]
    assert (t1.td, t1.tests) == ("TD_MEC_PF_01", 2)
    assert t1.command == ': runbook-step t1 phase=test td=TD_MEC_PF_01 tests=2 && \\\ncd "$ROOT" && echo "$OUT/TD_MEC_PF_01.xml"'
    assert [s.id for s in cr.plan(rb)] == ["start", "t1", "stop"], "variables and install blocks are not run"


@pytest.mark.parametrize("old, new, said", [
    (': runbook-step start phase=bootstrap && cd "$ROOT" && echo up', 'cd "$ROOT" && echo up', "no runbook-step marker"),
    ("runbook-step stop phase=shutdown", "runbook-step start phase=shutdown", "twice"),
    ("phase=bootstrap", "phase=warmup", "phase"),
    ('echo up\n', 'echo up\necho second line\n', "one command"),
    ('cd "$ROOT" && echo up', 'cd "$ROOT" && echo "$HOME_LAB"', "HOME_LAB"),
    ('cd "$ROOT" && echo up', 'cd "$ROOT" && echo ${SECRET}', "SECRET"),
    (" tests=2", "", "tests="),
    (" td=TD_MEC_PF_01", "", "td="),
    ("tests=2", "tests=0", "tests="),
    ("phase=shutdown", "phase=bootstrap", "order"),
    ('cd "$ROOT" && echo up', 'cd "$ROOT" ; echo up', "&&"),
    ('cd "$ROOT" && echo up', 'cd "$ROOT" && echo up || true', "&&"),
    ('cd "$ROOT" && echo up', 'cd "$ROOT" && echo up &', "&&"),
])
def test_parser_control_a_malformed_runbook_is_refused(old, new, said):
    assert old in MINI
    with pytest.raises(cr.RunbookError, match=re.escape(said)):
        cr.parse_runbook(MINI.replace(old, new, 1))


def test_parser_control_runbook_without_a_test_or_a_shutdown_step_is_refused():
    no_stop = MINI.replace(': runbook-step stop phase=shutdown && cd "$ROOT" && echo down', "")
    with pytest.raises(cr.RunbookError, match="shutdown"):
        cr.parse_runbook(no_stop.replace("```sh\n\n```", ""))


def test_the_shipped_runbook_parses_and_names_the_five_test_descriptions_in_order():
    rb = cr.parse_runbook(RUNBOOK.read_text())
    run = cr.plan(rb)
    assert [s.td for s in run if s.phase == "test"] == TDS
    assert [s.phase for s in run] == sorted((s.phase for s in run), key=["bootstrap", "test", "shutdown"].index)
    assert sum(s.phase == "bootstrap" for s in run) >= 2 and sum(s.phase == "shutdown" for s in run) == 1
    assert set(rb.variables) == {"ROOT", "RUN", "OUT", "VENV", "PY", "PYTHONDONTWRITEBYTECODE"}
    assert rb.variables["VENV"] == "/home/edgefollow/estimed-venv"                      # run_topology.sh's default
    assert rb.variables["PY"] == "/home/edgefollow/edgefollow-lab/.venv/bin/python"    # conftest.MEC_VENV_PY
    installs = [s for s in rb.steps if s.phase == "install"]
    assert len(installs) >= 2, "the commands that create both environments are in the runbook"
    assert any("requirements.txt" in s.command for s in installs)
    for s in run:
        if s.phase == "test":
            assert f'--junitxml="$OUT/{s.td}.xml"' in s.command, s.id
            assert "-k " not in s.command and " -m " not in s.command.replace("-B -m pytest", ""), "no selection by expression"


def test_every_test_the_runbook_names_exists_and_no_test_is_named_twice():
    rb = cr.parse_runbook(RUNBOOK.read_text())
    seen: list[str] = []
    for s in cr.plan(rb):
        if s.phase != "test":
            continue
        ids = re.findall(r"estimed/tests/[\w.]+\.py(?:::\w+)*", s.command)
        assert ids, s.id
        for nid in ids:
            path, _, func = nid.partition("::")
            src = (EST.parent / path).read_text()
            if func:
                assert re.search(rf"(?m)^def {func}\(", src), nid
            seen.append(nid)
    assert len(seen) == len(set(seen)), "a test listed under two test descriptions would be counted twice"
    whole = {n for n in seen if "::" not in n}
    assert not [n for n in seen if "::" in n and n.split("::")[0] in whole]


def test_the_script_holds_no_bootstrap_or_test_command_of_its_own():
    src = (EST / "clean_rerun.py").read_text()
    for word in ("run_topology", "stop_topology", "acmecse", "pytest", "pip ", "candidate.py", "venv"):
        assert word not in src, f"clean_rerun.py names {word!r}: commands belong in RUNBOOK.md"
    assert len(re.findall(r"subprocess\.(?:run|Popen|call|check_\w+)\(", src)) == 2, \
        "exactly two places start a process: git (read-only listing) and the runbook executor"
    assert "os.system" not in src and "shell=True" not in src


# ---------------------------------------------------------------------------------------- copy and manifest
@pytest.fixture
def tree(tmp_path):
    src = tmp_path / "src"
    for rel, data in {"estimed/a.py": b"abc", "estimed/conf/in.ini": b"x=1\n", "estimed/private_lab/big.bin": b"0" * 64,
                      "mec011/c.py": b"", "other/z.py": b"zz", "estimed/new_today.py": b"new"}.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_bytes(data)
    (src / "estimed" / "a.py").chmod(0o755)
    return src


def test_select_keeps_the_named_folders_and_drops_the_excluded_one():
    listed = ["estimed/a.py", "estimed/private_lab/big.bin", "estimedX/no.py", "mec011/c.py", "other/z.py",
              "estimed/private_lab_notes.md"]
    assert cr.select(listed, ["estimed", "mec011"], ["estimed/private_lab"]) == \
        ["estimed/a.py", "estimed/private_lab_notes.md", "mec011/c.py"]


def test_copy_holds_exactly_the_listed_files_and_the_manifest_says_what_they_are(tree, tmp_path):
    dest = tmp_path / "copy"
    files = ["estimed/a.py", "estimed/conf/in.ini", "estimed/new_today.py", "mec011/c.py"]
    man = cr.make_copy(tree, files, dest, max_bytes=1000)
    assert sorted(str(p.relative_to(dest)) for p in dest.rglob("*") if p.is_file()) == sorted(files)
    assert [f["path"] for f in man["files"]] == sorted(files)
    a = man["files"][0]
    assert (a["sha256"], a["bytes"], a["mode"]) == (SHA_ABC, 3, "755")
    assert (dest / "estimed" / "a.py").stat().st_mode & 0o777 == 0o755
    assert man["file_count"] == 4 and man["total_bytes"] == 3 + 4 + 3 + 0
    assert re.fullmatch(r"[0-9a-f]{64}", man["tree_sha256"])
    assert cr.verify_copy(dest, man) == []


def test_copy_control_destination_that_is_not_empty_is_refused(tree, tmp_path):
    dest = tmp_path / "copy"
    dest.mkdir()
    (dest / "old.py").write_text("old")
    with pytest.raises(cr.RerunError, match="not empty"):
        cr.make_copy(tree, ["estimed/a.py"], dest, max_bytes=1000)


def test_copy_control_more_bytes_than_the_limit_is_refused_before_anything_is_written(tree, tmp_path):
    dest = tmp_path / "copy"
    with pytest.raises(cr.RerunError, match="limit"):
        cr.make_copy(tree, ["estimed/a.py", "estimed/private_lab/big.bin"], dest, max_bytes=66)
    assert not dest.exists() or not any(dest.iterdir())


@pytest.mark.parametrize("bad", ["../outside.py", "/etc/hostname", "estimed/../../x"])
def test_copy_control_a_path_leaving_the_tree_is_refused(tree, tmp_path, bad):
    with pytest.raises(cr.RerunError, match="outside"):
        cr.make_copy(tree, [bad], tmp_path / "copy", max_bytes=1000)


def test_copy_control_a_symbolic_link_is_refused(tree, tmp_path):
    (tree / "estimed" / "link.py").symlink_to(tree / "other" / "z.py")
    with pytest.raises(cr.RerunError, match="link"):
        cr.make_copy(tree, ["estimed/link.py"], tmp_path / "copy", max_bytes=1000)


@pytest.mark.parametrize("plant, said", [
    (lambda d: (d / "estimed" / "a.py").write_bytes(b"abd"), "changed: estimed/a.py"),
    (lambda d: (d / "estimed" / "a.py").write_bytes(b""), "changed: estimed/a.py"),
    (lambda d: (d / "mec011" / "c.py").unlink(), "missing: mec011/c.py"),
    (lambda d: (d / "estimed" / "extra.py").write_text("x"), "extra: estimed/extra.py"),
    (lambda d: (d / "estimed" / "__pycache__").mkdir() or (d / "estimed" / "__pycache__" / "a.pyc").write_bytes(b"1"),
     "extra: estimed/__pycache__/a.pyc"),
    (lambda d: (d / "estimed" / "a.py").chmod(0o644), "mode: estimed/a.py"),
])
def test_copy_control_a_copy_changed_after_the_manifest_is_not_accepted(tree, tmp_path, plant, said):
    dest = tmp_path / "copy"
    man = cr.make_copy(tree, ["estimed/a.py", "mec011/c.py"], dest, max_bytes=1000)
    plant(dest)
    assert cr.verify_copy(dest, man) == [said]


def test_copy_control_a_manifest_edited_to_match_a_changed_file_is_not_accepted(tree, tmp_path):
    dest = tmp_path / "copy"
    man = cr.make_copy(tree, ["estimed/a.py", "mec011/c.py"], dest, max_bytes=1000)
    (dest / "estimed" / "a.py").write_bytes(b"abd")
    forged = copy.deepcopy(man)
    forged["files"][0]["sha256"] = "a52d159f262b2c6ddb724a61840befc36eb30c88877a4030b65cbe86298449c9"   # sha256("abd")
    assert any(p.startswith("tree_sha256") for p in cr.verify_copy(dest, forged))


# ---------------------------------------------------------------------------------------- the run directory
def test_run_directory_absent_or_empty_is_accepted(tmp_path):
    cr.require_empty_dir(tmp_path / "absent")
    (tmp_path / "empty").mkdir()
    cr.require_empty_dir(tmp_path / "empty")


@pytest.mark.parametrize("old", ["in/cse.pid", "mn-a/logs/cse.log", ".hidden"])
def test_run_directory_control_old_state_is_refused(tmp_path, old):
    run = tmp_path / "run"
    (run / old).parent.mkdir(parents=True, exist_ok=True)
    (run / old).write_text("1")
    with pytest.raises(cr.RerunError, match="not empty"):
        cr.require_empty_dir(run)


def test_run_directory_control_a_file_in_its_place_is_refused(tmp_path):
    (tmp_path / "run").write_text("")
    with pytest.raises(cr.RerunError, match="not a directory"):
        cr.require_empty_dir(tmp_path / "run")


# ---------------------------------------------------------------------------------------- counting test outcomes
def _junit(cases: list[tuple[str, str]], tests=None) -> str:
    body = "".join(f'<testcase classname="estimed.tests.t" name="{n}" time="0.01">{inner}</testcase>' for n, inner in cases)
    return (f'<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" '
            f'tests="{len(cases) if tests is None else tests}">{body}</testsuite></testsuites>')


class _Step:
    td, tests, id = "TD_MEC_PF_01", 2, "t1"


def _result(xml: str, tail="2 passed in 0.10s", rc=0):
    return cr.td_result(_Step, xml, tail, rc)


def test_outcomes_two_of_two_passed_is_a_pass():
    r = _result(_junit([("test_a", ""), ("test_b", "")]))
    assert r["ok"] is True and r["problems"] == []
    assert (r["passed"], r["declared"], r["ran"]) == (2, 2, 2)
    assert r["ids"] == ["estimed.tests.t::test_a", "estimed.tests.t::test_b"]


@pytest.mark.parametrize("xml, tail, rc, said", [
    (_junit([("test_a", ""), ("test_b", '<skipped message="no CSE"/>')]), "1 passed, 1 skipped in 0.10s", 0, "skipped"),
    (_junit([("test_a", ""), ("test_b", '<skipped type="pytest.xfail" message="known"/>')]), "1 passed, 1 xfailed in 0.1s", 0,
     "skipped"),
    (_junit([("test_a", ""), ("test_b", "")]), "2 passed, 3 deselected in 0.10s", 0, "deselected"),
    (_junit([("test_a", ""), ("test_b", "")]), "1 passed, 1 xpassed in 0.10s", 0, "xpassed"),
    (_junit([("test_a", "")]), "1 passed in 0.10s", 0, "1 ran, 2 declared"),
    (_junit([("test_a", ""), ("test_b", ""), ("test_c", "")]), "3 passed in 0.10s", 0, "3 ran, 2 declared"),
    (_junit([]), "no tests ran in 0.01s", 5, "0 ran, 2 declared"),
    (_junit([("test_a", ""), ("test_b", '<failure message="boom">x</failure>')]), "1 failed, 1 passed in 0.1s", 1, "failed"),
    (_junit([("test_a", ""), ("test_b", '<error message="fixture">x</error>')]), "1 passed, 1 error in 0.1s", 1, "error"),
    (_junit([("test_a", ""), ("test_b", "")]), "2 passed in 0.10s", 1, "exit status 1"),
    (_junit([("test_a", ""), ("test_a", "")]), "2 passed in 0.10s", 0, "twice"),
    ("", "2 passed in 0.10s", 0, "no result file"),
    ("<testsuites><testsuite", "2 passed in 0.10s", 0, "not readable"),
])
def test_outcomes_control_anything_but_every_declared_test_passing_is_a_failure(xml, tail, rc, said):
    r = _result(xml, tail, rc)
    assert r["ok"] is False
    assert any(said in p for p in r["problems"]), r["problems"]


def test_outcomes_control_a_skipped_test_is_not_in_the_passed_count():
    r = _result(_junit([("test_a", ""), ("test_b", "<skipped/>")]), "1 passed, 1 skipped in 0.1s")
    assert (r["passed"], r["skipped"]) == (1, 1)
    assert cr.kpi_rate(r["passed"], r["declared"]) == {"numerator": 1, "denominator": 2, "N": 2, "value": 50.0}


def test_planted_skip_turns_one_passing_test_of_a_real_shaped_result_file_into_a_skipped_one():
    # the runner writes a passing test as a self-closed element; the first live run's control replaced a closing tag
    # that is not there, planted nothing and so "passed" (2026-11-18)
    real = ('<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" tests="2">'
            '<testcase classname="estimed.tests.t" name="test_a" time="0.01" />'
            '<testcase classname="estimed.tests.t" name="test_b" time="0.01" /></testsuite></testsuites>')
    assert _result(real)["ok"] is True
    r = _result(cr.plant_skip(real), "")
    assert (r["ok"], r["passed"], r["skipped"], r["ran"]) == (False, 1, 1, 2)


def test_kpi_rate_with_nothing_to_count_has_no_value():
    assert cr.kpi_rate(0, 0) == {"numerator": 0, "denominator": 0, "N": 0, "value": None}


# ---------------------------------------------------------------------------------------- census and KPI comparison
def test_census_delta_counts_what_a_step_left_and_what_it_removed_by_kind():
    before = {"cse-in": {"/id-in/cse-in/CAdmin": 2, "/id-in/cse-in/old": 3}, "cse-mn-a": {"/id-mn-a/cse-mn-a/CAdmin": 2}}
    after = {"cse-in": {"/id-in/cse-in/CAdmin": 2}, "cse-mn-a": {"/id-mn-a/cse-mn-a/CAdmin": 2, "/id-mn-a/cse-mn-a/ae1": 2,
                                                                "/id-mn-a/cse-mn-a/ae1/c": 3, "/id-mn-a/cse-mn-a/acp": 1}}
    assert cr.census_delta(before, after) == {
        "cse-in": {"numerator": 0, "denominator": 1, "N": 1, "left": {}, "removed": {"3": 1}},
        "cse-mn-a": {"numerator": 3, "denominator": 4, "N": 4, "left": {"1": 1, "2": 1, "3": 1}, "removed": {}}}


def _kpis(passed=2, left=None, reg=2, seconds=1.0, ids=("m::test_a", "m::test_b"), n_after=7):
    return {"tests_passed": {"TD_MEC_PF_01": dict(cr.kpi_rate(passed, 2), ids=list(ids)),
                             "TD_MEC_DEV_01": dict(cr.kpi_rate(26, 26), ids=["m::test_c"])},
            "cse_registration_success": cr.kpi_rate(reg, 2),
            "resources_left": {"TD_MEC_PF_01": {"cse-in": {"numerator": sum((left or {}).values()), "denominator": n_after,
                                                           "N": n_after, "left": left or {}, "removed": {}}},
                               "TD_MEC_DEV_01": {"cse-in": {"numerator": 0, "denominator": n_after, "N": n_after, "left": {},
                                                            "removed": {}}}},
            "timings_s": {"TD_MEC_PF_01": seconds}}


def test_compare_equal_kpis_have_no_difference_whatever_the_timings_and_the_tree_size():
    assert cr.compare_kpis(_kpis(seconds=1.0, n_after=7), _kpis(seconds=9.5, n_after=40)) == []


@pytest.mark.parametrize("other, said", [
    (dict(passed=1), "tests_passed TD_MEC_PF_01"),
    (dict(ids=("m::test_a", "m::test_z")), "tests_passed TD_MEC_PF_01"),
    (dict(reg=1), "cse_registration_success"),
    (dict(left={"2": 1}), "resources_left TD_MEC_PF_01 cse-in"),
])
def test_compare_control_one_differing_count_is_a_difference(other, said):
    diff = cr.compare_kpis(_kpis(), _kpis(**other))
    assert len(diff) == 1 and diff[0].startswith(said), diff


def test_compare_control_the_same_number_left_but_of_another_kind_or_removed_is_a_difference():
    a, b, c = _kpis(left={"2": 1}), _kpis(left={"3": 1}), _kpis(left={"2": 1})
    assert [d[:35] for d in cr.compare_kpis(a, b)] == ["resources_left TD_MEC_PF_01 cse-in:"]
    c["resources_left"]["TD_MEC_PF_01"]["cse-in"]["removed"] = {"4": 2}
    assert [d[:35] for d in cr.compare_kpis(a, c)] == ["resources_left TD_MEC_PF_01 cse-in:"]


def test_compare_control_a_test_description_missing_on_one_side_is_a_difference():
    new = _kpis()
    del new["tests_passed"]["TD_MEC_DEV_01"]
    del new["resources_left"]["TD_MEC_DEV_01"]
    assert any(d.startswith("tests_passed TD_MEC_DEV_01") for d in cr.compare_kpis(_kpis(), new))
    assert any(d.startswith("tests_passed TD_MEC_DEV_01") for d in cr.compare_kpis(new, _kpis()))
    assert any(d.startswith("resources_left TD_MEC_DEV_01") for d in cr.compare_kpis(_kpis(), new))


def test_compare_control_an_empty_reference_is_a_difference():
    assert cr.compare_kpis({}, _kpis()) != []
    part = _kpis()
    del part["resources_left"]["TD_MEC_DEV_01"]                 # a census taken for fewer test descriptions than were run
    assert any(d.startswith("resources_left") for d in cr.compare_kpis(part, part))
    assert cr.compare_kpis({"tests_passed": {}, "cse_registration_success": cr.kpi_rate(2, 2), "resources_left": {}},
                           {"tests_passed": {}, "cse_registration_success": cr.kpi_rate(2, 2), "resources_left": {}}) != []


def test_timing_band_is_a_ratio_and_never_an_equality():
    assert cr.in_band(2.0, 2.9) is True and cr.in_band(2.0, 0.6) is True
    assert cr.in_band(2.0, 10.1) is False and cr.in_band(2.0, 0.3) is False
    assert cr.BAND == (0.2, 5.0)


# ---------------------------------------------------------------------------------------- only runbook commands run
def test_executor_runs_a_runbook_step_and_logs_it(tmp_path):
    rb = cr.parse_runbook(MINI)
    ex = cr.Executor(cr.plan(rb), env={"PATH": "/usr/bin:/bin", "ROOT": str(tmp_path), "OUT": "/o"}, cwd=tmp_path)
    r = ex.run(cr.plan(rb)[0])
    assert (r["rc"], r["stdout"].strip()) == (0, "up")
    assert [e["id"] for e in ex.log] == ["start"]


def test_executor_passes_only_the_given_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("LEAK_ME", "1")
    text = MINI.replace("echo up", "env")
    rb = cr.parse_runbook(text)
    ex = cr.Executor(cr.plan(rb), env={"PATH": "/usr/bin:/bin", "ROOT": str(tmp_path), "OUT": "/o"}, cwd=tmp_path)
    names = {line.split("=", 1)[0] for line in ex.run(cr.plan(rb)[0])["stdout"].splitlines()}
    assert "LEAK_ME" not in names and {"ROOT", "OUT"} <= names
    assert names <= {"PATH", "ROOT", "OUT", "PWD", "OLDPWD", "SHLVL", "_"}


def test_executor_control_a_command_that_is_not_in_the_runbook_is_not_executed(tmp_path):
    rb = cr.parse_runbook(MINI)
    ex = cr.Executor(cr.plan(rb), env={"PATH": "/usr/bin:/bin", "ROOT": str(tmp_path), "OUT": "/o"}, cwd=tmp_path)
    other = cr.parse_runbook(MINI.replace("echo up", f"touch {tmp_path}/planted"))
    with pytest.raises(cr.RerunError, match="not in the runbook"):
        ex.run(cr.plan(other)[0])                       # same id, another command
    with pytest.raises(cr.RerunError, match="not in the runbook"):
        ex.run(rb.steps[1])                             # an install block: in the file, not in the plan
    assert not (tmp_path / "planted").exists() and ex.log == []


def test_executed_log_matching_the_plan_has_no_problem():
    run = cr.plan(cr.parse_runbook(MINI))
    log = [{"id": s.id, "sha256": s.sha256, "rc": 0} for s in run]
    assert cr.check_executed(run, log) == []


@pytest.mark.parametrize("mangle, said", [
    (lambda log: log.pop(0), "not executed: start"),
    (lambda log: log.insert(1, {"id": "extra", "sha256": "0" * 64, "rc": 0}), "not in the runbook: extra"),
    (lambda log: log.reverse(), "order"),
    (lambda log: log.append(dict(log[0])), "more than once: start"),
    (lambda log: log[0].update(sha256="1" * 64), "not in the runbook: start"),
])
def test_executed_log_control_a_missing_foreign_or_reordered_command_is_reported(mangle, said):
    run = cr.plan(cr.parse_runbook(MINI))
    log = [{"id": s.id, "sha256": s.sha256, "rc": 0} for s in run]
    mangle(log)
    assert any(said in p for p in cr.check_executed(run, log)), cr.check_executed(run, log)


def test_runbook_without_its_bootstrap_steps_is_what_the_live_control_runs():
    rb = cr.parse_runbook(MINI)
    cut = cr.without_bootstrap(cr.plan(rb))
    assert [s.id for s in cut] == ["t1", "stop"]


# ---------------------------------------------------------------------------------------- the verdict
def test_verdict_needs_every_step_true_every_control_false_and_at_least_one_control():
    ok = [("copy made", True, ""), ("CONTROL (must FAIL) old state accepted", False, "")]
    assert cr.verdict(ok) is True
    assert cr.verdict(ok + [("CONTROL (must FAIL) skipped counted", True, "")]) is False
    assert cr.verdict(ok + [("tests pass", False, "")]) is False
    assert cr.verdict([("copy made", True, "")]) is False
    assert cr.verdict([]) is False
