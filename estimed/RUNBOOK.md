# Developer runbook: the oneM2M + MEC lab from nothing to TD_MEC_DEV_01

For the TR-0086 test plan, test description TD_MEC_OBS_03 (7.6.3.1): bootstrap the lab (TD_MEC_PF_01), run the
scripted tests for TD_MEC_REG_01, REG_02, REG_03 and DEV_01, shut down. One host, loopback only.

How to read it. Every command is in a fenced block. A block is ONE command chain joined by `&&` and starts with
`: runbook-step <id> phase=<phase>` (`:` does nothing in bash and zsh, so a block can be pasted as it is; a failed
command stops the block). `estimed/clean_rerun.py` reads this file and executes exactly the `bootstrap`, `test` and
`shutdown` blocks, in the order written here, and nothing else. It does not run the `variables` block (it sets ROOT,
RUN and OUT to its own new directories and takes the other values from here) and it does not run the `install`
blocks (not run by the rerun on this PC: the two environments are already installed and are only checked against the
versions named there).

Scope, plainly. What `clean_rerun.py` does on this PC is a rerun from a fresh copy of the code on the same host with
a new, empty run directory. It is not a run on a fresh virtual machine and not a fresh install of the environments.

## 0. Prerequisites

- Linux with `bash`, `curl`, `setsid` and `python3` (3.13 here) on the PATH. Root is needed once, for the first
  block of section 2, which installs the two packages `python3-venv` and `git`; ROOT (below) must be a git checkout,
  since `clean_rerun.py` lists the code's files with `git ls-files`. No container.
- Free TCP ports on 127.0.0.1: 8200, 8201, 8202 (the three CSEs), 8091 and 8092 (the MEC 011 and MEC 010-2
  candidates; the tests start and stop these two themselves).
- The code: this repository's folders `estimed/`, `mec011_appsupport/` and `mec010p2/`, under one directory,
  called ROOT below.
- Two Python environments at FIXED paths: `/home/edgefollow/estimed-venv` (the CSE) and
  `/home/edgefollow/edgefollow-lab/.venv` (the test runner and the MEC candidates). The paths are written into
  `estimed/tests/conftest.py` (`MEC_VENV_PY`) and `estimed/tests/test_lab_config.py` (`VENV`), so on another machine
  they must be created at these same paths.

## 1. Variables

Set these once in the shell you paste the other blocks into. ROOT is where the code is, RUN an EMPTY directory for
the CSEs' data, logs and pid files, OUT a directory for the test result files.

```sh
: runbook-step variables phase=variables && \
export ROOT=/home/edgefollow/estimed-lab/code && \
export RUN=/home/edgefollow/estimed-lab/run && \
export OUT=/home/edgefollow/estimed-lab/out && \
export VENV=/home/edgefollow/estimed-venv && \
export PY=/home/edgefollow/edgefollow-lab/.venv/bin/python && \
export PYTHONDONTWRITEBYTECODE=1
```

`PYTHONDONTWRITEBYTECODE=1` keeps Python from writing `__pycache__` into ROOT, so the code directory stays as
delivered.

## 2. Install the two environments (not run by the rerun on this PC)

```sh
: runbook-step install-system-packages phase=install root=yes && \
apt-get -o DPkg::Lock::Timeout=600 update && \
apt-get -o DPkg::Lock::Timeout=600 install -y python3-venv git
```

The CSE: ACME oneM2M CSE at the version `estimed/requirements.txt` pins.

```sh
: runbook-step install-cse-environment phase=install env=VENV && \
python3 -m venv "$VENV" && \
"$VENV/bin/pip" install -r "$ROOT/estimed/requirements.txt"
```

The test runner and the two MEC candidates' web framework. The three versions are the ones installed on this PC on
2026-11-18; what they pull in (starlette, pydantic and so on) is not pinned anywhere in this repository.

```sh
: runbook-step install-test-environment phase=install env=PY && \
python3 -m venv /home/edgefollow/edgefollow-lab/.venv && \
"$PY" -m pip install pytest==9.1.1 fastapi==0.139.0 uvicorn==0.51.0
```

## 3. Bootstrap (TD_MEC_PF_01)

Check the prerequisites.

```sh
: runbook-step check-prerequisites phase=bootstrap && \
test -x "$VENV/bin/acmecse" && test -x "$PY" && \
command -v bash curl setsid python3 >/dev/null && \
test -f "$ROOT/estimed/run_topology.sh" && test -f "$ROOT/mec011_appsupport/candidate.py" && \
test -f "$ROOT/mec010p2/candidate.py"
```

Make the run and output directories. The run directory must be empty: no node state is reused.

```sh
: runbook-step make-directories phase=bootstrap && \
mkdir -p "$RUN" "$OUT" && test -z "$(ls -A "$RUN")"
```

Start the IN-CSE and the two MN-CSEs. The script waits until each answers and until the IN-CSE holds exactly both
MN-CSEs, and exits non-zero otherwise. It reads VENV and RUN from the environment.

```sh
: runbook-step start-topology phase=bootstrap && \
cd "$ROOT" && bash estimed/run_topology.sh
```

Nothing else is started by hand: the MEC 011 candidate (:8091) and the MEC 010-2 candidate (:8092) are started by the
test fixtures when a test needs them and stopped when that test process ends.

## 4. The scripted tests

Each block runs the tests of one test description, named one by one (no `-k`, no markers), and writes
`$OUT/<TD>.xml`. `tests=<n>` in the marker is the number of tests the block must run; `clean_rerun.py` counts a
skipped, deselected or missing test as a failure. A test belongs to one block only.

TD_MEC_PF_01, platform health:

```sh
: runbook-step td-pf-01 phase=test td=TD_MEC_PF_01 tests=12 && \
cd "$ROOT" && "$PY" -B -m pytest -q -p no:cacheprovider --junitxml="$OUT/TD_MEC_PF_01.xml" \
estimed/tests/test_lab_config.py \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_1_5_plain_get_is_rejected \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_1_5_control_well_formed_get_reaches_the_in \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_3_4_mec011_checks \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_4_every_mn_reports_cst_2 \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_4_control_the_in_reports_cst_1 \
estimed/tests/test_tr0086_registration.py::test_5_2_every_csebase_is_reachable \
estimed/tests/test_tr0086_registration.py::test_5_2_control_unknown_csebase_is_not_found \
estimed/tests/test_tr0086_mec_app.py::test_5_2_mec011_api_answers
```

TD_MEC_REG_01, the MN-CSEs registered to the IN-CSE:

```sh
: runbook-step td-reg-01 phase=test td=TD_MEC_REG_01 tests=9 && \
cd "$ROOT" && "$PY" -B -m pytest -q -p no:cacheprovider --junitxml="$OUT/TD_MEC_REG_01.xml" \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_5_in_discovers_one_remotecse_per_mn \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_5_remotecse_is_named_after_the_cse_id \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_5_control_no_remotecse_under_the_csebase_name \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_5_reciprocal_remotecse_at_each_mn \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_5_in_reaches_each_mn_over_its_poa \
estimed/tests/test_tr0086_bringup.py::test_5_2_4_5_control_the_ins_admin_is_not_the_mns_admin \
estimed/tests/test_tr0086_registration.py::test_5_2_in_cse_holds_remotecse_for_each_mn \
estimed/tests/test_tr0086_registration.py::test_5_2_control_unregistered_csi_has_no_remotecse \
estimed/tests/test_tr0086_registration.py::test_5_2_each_mn_holds_remotecse_for_the_in
```

TD_MEC_REG_02, a MEC application onboarded and discoverable:

```sh
: runbook-step td-reg-02 phase=test td=TD_MEC_REG_02 tests=6 && \
cd "$ROOT" && "$PY" -B -m pytest -q -p no:cacheprovider --junitxml="$OUT/TD_MEC_REG_02.xml" \
estimed/tests/test_estimed_testplan.py::test_td_mec_reg_02_registered_app_is_discoverable \
estimed/tests/test_estimed_testplan.py::test_td_mec_reg_02_control_service_of_unknown_app_is_refused \
estimed/tests/test_estimed_testplan.py::test_td_mec_reg_02_control_incomplete_service_info_is_400
```

TD_MEC_REG_03, an AE deployed as a MEC application (as a process on this host; no container):

```sh
: runbook-step td-reg-03 phase=test td=TD_MEC_REG_03 tests=89 && \
cd "$ROOT" && "$PY" -B -m pytest -q -p no:cacheprovider --junitxml="$OUT/TD_MEC_REG_03.xml" \
estimed/tests/test_tr0086_mec_app_deploy.py \
estimed/tests/test_tr0086_mec_app.py::test_5_4_register_then_confirm_ready \
estimed/tests/test_tr0086_mec_app.py::test_5_4_control_confirm_ready_for_unknown_instance_is_404 \
estimed/tests/test_tr0086_mec_app.py::test_5_4_control_confirm_ready_after_deregistration_is_404 \
estimed/tests/test_tr0086_mec_app.py::test_5_4_confirm_ready_without_valid_indication_is_400 \
estimed/tests/test_tr0086_mec_app.py::test_5_4_confirm_termination_requires_operation_action \
estimed/tests/test_tr0086_mec_app.py::test_5_4_ae_carries_its_mec_app_instance \
estimed/tests/test_tr0086_mec_app.py::test_5_4_subscriber_may_read_output \
estimed/tests/test_tr0086_mec_app.py::test_5_4_subscriber_may_subscribe \
estimed/tests/test_tr0086_mec_app.py::test_5_4_control_subscriber_may_not_write \
estimed/tests/test_tr0086_mec_app.py::test_5_4_control_stranger_may_not_read \
estimed/tests/test_tr0086_mec_app.py::test_5_4_control_owner_still_may_write
```

TD_MEC_DEV_01, a device connected and its telemetry published:

```sh
: runbook-step td-dev-01 phase=test td=TD_MEC_DEV_01 tests=26 && \
cd "$ROOT" && "$PY" -B -m pytest -q -p no:cacheprovider --junitxml="$OUT/TD_MEC_DEV_01.xml" \
estimed/tests/test_tr0086_annex_a.py \
estimed/tests/test_tr0086_registration.py::test_5_3_ae_registration_assigns_aei \
estimed/tests/test_tr0086_registration.py::test_5_3_control_duplicate_registration_is_refused \
estimed/tests/test_tr0086_registration.py::test_5_3_control_api_without_n_or_r_prefix_is_refused \
estimed/tests/test_tr0086_registration.py::test_5_3_telemetry_round_trip_through_latest \
estimed/tests/test_tr0086_registration.py::test_5_3_control_latest_of_empty_container_is_not_found \
estimed/tests/test_tr0086_registration.py::test_5_3_control_cin_under_missing_container_is_not_found
```

## 5. Shutdown

Stops the three CSEs of this RUN directory and no other process.

```sh
: runbook-step stop-topology phase=shutdown && \
cd "$ROOT" && bash estimed/stop_topology.sh
```

## 6. The automated rerun

`clean_rerun.py` is not a runbook step; it is the program that follows this runbook. With the lab of the working
tree up, make the reference; then stop that lab, and rerun from a fresh copy:

```text
PY=/home/edgefollow/edgefollow-lab/.venv/bin/python
$PY -B estimed/clean_rerun.py reference --out <empty directory> --results <reference.json>
bash estimed/stop_topology.sh
$PY -B estimed/clean_rerun.py rerun --reference <reference.json>
bash estimed/run_topology.sh
```

On a fresh machine (TD_MEC_OBS_03) the reference record of the original execution is first copied to
`/home/edgefollow/vm-harness/reference.json`; the rerun is then this one block. It is in a `text` fence, so
`clean_rerun.py` itself does not read it; it runs from the home directory, so it changes into ROOT first.

```text
: runbook-step rerun phase=rerun && \
cd "$ROOT" && "$PY" -B estimed/clean_rerun.py rerun --reference /home/edgefollow/vm-harness/reference.json
```

The record is `/home/edgefollow/estimed-run/sim/clean_rerun_<UTC stamp>.json`. KPIs compared for equality: tests passed
per test description (with the test ids), MN-CSE registration, and the resources each test step left on each CSE
after its own clean-up, by resource type. Timings are reported with a band of 0.2 to 5 times the reference and are
never compared for equality. The budget for "empty directory to TD_MEC_DEV_01 passed" is 900 s; it is ours, the test
plan names none, and it does not include installing the environments.

Offline checks of the parser, the copy, the counting and the comparison:

```text
$PY -B -m pytest -p no:cacheprovider estimed/tests/test_clean_rerun.py -q
```
