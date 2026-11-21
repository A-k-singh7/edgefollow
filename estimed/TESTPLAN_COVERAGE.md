# TR-0086 test plan: what our lab tests cover (2026-10-29; rows of 2026-11-18 and 2026-11-19 marked)

Sources: the TR-0086 test plan (oneM2M TR-0086 "Developer Guide -- oneM2M and MEC Deployment Test Plan", rev 0.2.0,
our copy of 2026-10-19) and the developer guide draft on the TR-0086 device-registration branch of ESTIMED/WP6/TR-0086, read 2026-10-29. The test plan is ETSI's document; this file is only our map
onto it.

Scope of every status below: our lab -- ACME oneM2M CSE 2026.5.3 (one IN, two MN-CSEs on one host,
`estimed/run_topology.sh`) and our MEC candidates -- not a VM image and not the ETSI MEC Sandbox. COVERED means
`estimed/tests` exercises the TD's sequence there, each check with a control that must come out the other way. It is
not a conformance claim.

Rows updated on 2026-11-18 say so. Two kinds of evidence are new there and are named apart: tests in `estimed/tests`,
and demonstration runs under `estimed_poc/` and `phone/`, which are drivers
with their own checks and controls, not part of `estimed/tests`. Every such run used a SIMULATED device on one PC;
its results file lists what was not run and what it does not show. TR-0077 was read at v0.4.0 (2026-11-03).

Run (the location tests also need `mec013_look/candidate.py` on :8101; MEC 011 is started by conftest):

    bash estimed/run_topology.sh
    /home/edgefollow/edgefollow-lab/.venv/bin/python -m pytest estimed/tests -q

## The 18 test descriptions

| TD | Objective (short) | Status | Where |
|---|---|---|---|
| TD_MEC_PF_01 | Bootstrap and verify platform health | COVERED (one host, no VM) | `test_tr0086_bringup.py` (5.2.4.1.5 well-formed vs plain GET, 5.2.4.3.4 MEC 011 checks, 5.2.4.4 cst), `test_tr0086_registration.py::test_5_2_*`, `test_lab_config.py` |
| TD_MEC_REG_01 | Register the MN-CSE to the IN-CSE | COVERED | `test_tr0086_bringup.py::test_5_2_4_5_*` (ty=16 both ways, named by CSE-ID, IN reaches each MN over its poa), `test_tr0086_registration.py` |
| TD_MEC_REG_02 | Onboard a MEC application, verify discoverability | COVERED | `test_estimed_testplan.py::test_td_mec_reg_02_*` |
| TD_MEC_REG_03 | Deploy a new AE as a MEC application | COVERED (a process on one host, no container or VM) | 2026-11-18: `test_tr0086_mec_app_deploy.py` (76 tests): the package `apps/sensor_ae` is onboarded and instantiated through our MEC 010-2 candidate's lifecycle calls, `mec_app_deploy.py` checks the package digests and starts the workload as its own process; AE Create, ACP, baseline container and CRUD are read off the wire on Mca and Mp1. Earlier: `test_tr0086_mec_app.py::test_5_4_*`. Not done: a container, a sandbox, any isolation of the workload |
| TD_MEC_DEV_01 | Connect a device, publish telemetry | COVERED | `test_tr0086_registration.py::test_5_3_*`, `test_tr0086_annex_a.py` (the guide's GasTempSensorAE, on an MN and on the IN) |
| TD_MEC_DEV_02 | MEC 012/013 context subscription, notification to the AE | COVERED (simulated UE, as step 3 allows; branch run) | MEC 012 subscription create: ETSI ATS MEC012/SRV/RNIS 33/0 on our candidate. 2026-11-20, branch run `estimed_poc/dev02_run.py` (phone-branch `1bad294`, offline `test_dev02.py` 50 rows): steps 1-6 end to end: subscription 201 with Location, a simulated UE moves from cell A to B, one CellChangeNotification carrying the UE's associateId reaches the AE's poa, the AE's 204 is seen in the RNIS send log, latency 0.95-0.98 s against our own budget of 3.0 s fixed before the run, 7 controls; PASS 19 of 19 in four runs. The UE address is the UE's own claim; the RNIS is our candidate; one host. MEC 013 location delivered into oneM2M: `test_tr0086_location.py::test_5_6_*`. Not run: a real phone's cell change (app v20 reports no UE address) |
| TD_MEC_HO_01 | MN-CSE handover with AE identity continuity | COVERED | `test_tr0086_handover.py` (AE-ID kept, IN route, telemetry, ACPs, flexContainers, subscriptions) |
| TD_MEC_HO_02 | Subscription and downlink continuity | COVERED | `test_estimed_testplan.py::test_td_mec_ho_02_*`, `test_tr0086_handover.py::test_5_5_*subscri*` |
| TD_MEC_HO_03 | Staged cutover / dual attach | COVERED | `test_estimed_testplan.py::test_td_mec_ho_03_*`, `test_tr0086_handover.py::test_5_5_dual_attach_before_release` |
| TD_MEC_HO_04 | CMDH / policy-driven handover | PARTIAL (policy-driven, not CMDH) | 2026-11-18, branch run `estimed_poc/policy_run.py` (24 of 24 checks, 6 controls; offline `test_policy.py`): a rule held on the IN-CSE and a per-edge constraint decide and start the library handover by themselves; a forbidden target is not chosen; a violation is raised when the constraint is broken afterwards. Both the rule and the MEC-side constraint are OUR modelling: ACME 2026.5.3 answers 500 to a CREATE of `<mgmtObj>` mgd 1011 (cmdhPolicy), and no MEC API carries the constraint. Simulated device; the latency is a sleep injected on the host |
| TD_MEC_HO_05 | Orchestrator target selection and fallback | COVERED | `test_estimed_testplan.py::test_td_mec_ho_05_*` |
| TD_MEC_HO_06 | Target readiness gate | COVERED | `test_estimed_testplan.py::test_td_mec_ho_06_*`, including a target registered the way ETSI's sandbox registers its CSE |
| TD_MEC_FL_01 | Onboard FL clients | PARTIAL (all seven steps and the pre-condition run, on simulated devices) | 2026-11-20, branch run `estimed_poc/fl_run.py` (offline `test_fl.py` 532 rows, 55 controls): the orchestrator, the Trusted FL Client and a MEC proxy app each deployed through REG_03's MEC 010-2 path (pinned by SHA-256); the client registered at MEC 011 and at the MN-CSE on behalf of a simulated constrained device; a simulated non-oneM2M device's plain HTTP data bridged unchanged into the tree; the three classes enumerated only when MEC 010-2 shows the app instance started (strays refused); PASS 101 of 101 steps, 17 controls, in each mode. Simulated devices; processes on one host, no container; in two modes the orchestrator is on the IN-CSE, not the MN-CSE REG_03 names; MEC 011 and MEC 010-2 registration is unauthenticated in our candidates. Needs real devices of the three classes to pass |
| TD_MEC_FL_02 | One FL training round | PARTIAL (ten steps run on simulated sources, after FL_01's onboarding in the same run; FL_01 itself is PARTIAL) | 2026-11-18, branch run `estimed_poc/fl_run.py` (72 of 72 checks, 9 controls, 10 rows NOT-RUN; offline `test_fl.py`): three rounds and one control round, integer FedAvg recomputed by a second method, replayed, revoked and out-of-bound updates refused. Since 2026-11-20 (`2146646`) the rounds run after FL_01's seven steps in every mode, controls unchanged. No signature on an update (no key is created); no real device |
| TD_MEC_FL_03 | Compare FL deployment modes | PARTIAL | steps 1-6 run on 2026-11-20 with simulated sources (`estimed_poc/fl_run.py --compare`, record `records/sim/fl03_compare_20261120T025209.json`): centralised, hierarchical and edge-only each PASS; edge-cloud bytes per round 37,602/49,458/59,084, 31,387/41,229/47,505, 0/0/0 (an earlier run gave 37004/48860/58485 and 31354/41196/47472), counted at the client on one PC, not a network measurement; no mode difference can be read from the round times (set by the driver); steps 7-8 (the client as a MEC app during a handover) NOT-RUN; FL_01 and FL_02 run first in the same run since `2146646`, both PARTIAL (simulated devices) |
| TD_MEC_OBS_01 | Observability and KPI capture | COVERED (simulated devices on one PC; one handover per run) | 2026-11-19: `kpi_record.py` + `test_kpi_record.py` (89 offline tests): the result files of four runs are put into one record format, each record is judged again from the data it stores, and the seven KPIs of steps 1-4 are exported as JSON, CSV and Markdown with each record's SHA-256 (step 5). Export of 2026-11-19 from four fresh runs: all seven captured (`~/estimed-run/kpi/`). Limits: every device simulated; latency is N = 1 per run; the one failed handover behind the rollback rate is injected by the driver; the loss rate counts records produced during the two handover windows (0 of 24) and has never seen a loss live; nothing is signed, so a record altered consistently is not noticed. Earlier: PoC 2 on real phones 2026-10-29, not in this format |
| TD_MEC_OBS_02 | Failure and rollback playbooks | PARTIAL (the policy conflict is our modelling, see HO_04) | steps 1-3: `test_5_5_5_*`, `test_5_5_control_*`, HO_03 rollback, HO_05 fallback, and since 2026-11-18 `test_handover_before_offline.py` and `test_tr0086_handover.py::test_before_*` (single route at the IN, one handover transaction at a time, closed on every way out). Steps 4-6 and a written playbook: branch run `estimed_poc/policy_run.py` and `estimed_poc/PLAYBOOK_FAILURES.md` (one section per failure code, held by `test_policy.py`). Where we differ from the text: on rollback the source's `rr` is put back to what it WAS, not to TRUE (a device may register with rr = false, guide 5.3.3.1) |
| TD_MEC_OBS_03 | Reproducibility on a clean VM | COVERED (one run on a fresh VM on this PC; the runbook followed by a script) | 2026-11-20, `estimed/vm_rerun.py` (offline `test_vm_rerun.py` 350 tests), record `records/sim/vm_rerun_20261120T092249Z.json`: a fresh Debian 13 cloud image (SHA-512 equal to Debian's list before and after) under QEMU/KVM, user-mode network with restrict=on and ipv6=off, reaching only the harness's seed server and a proxy to the package servers; in the VM exactly the runbook's three install blocks (one as root, named in the runbook) and its rerun block; PF_01 12, REG_01 9, REG_02 6, REG_03 89 and DEV_01 26 tests all passed, KPIs equal to the reference run, 128.5 s from QEMU's start to DEV_01 passed against our own budget of 1800 s fixed in that commit before the run; 16 controls failed as they must. Before this run the runbook gained the root step (python3-venv and git, absent from the image) and the rerun block, from reading the image's package list and three reviews, not from a failed run. Not shown: a human following the runbook; another image or hypervisor; pinned dependencies (pip pulls them from PyPI); a second run |

Totals (2026-11-20, after the VM run): 13 COVERED, 5 PARTIAL, 0 NOT YET. (2026-11-20 earlier: 12 / 6 / 0, then 11 / 7 / 0; 2026-11-19: 11 / 6 / 1; 2026-11-18: 10 / 7 / 1. The line of 2026-10-29 read
10 / 3 / 5; its table held 9 / 4 / 5.)

The test plan's minimum passing set is PF_01, REG_01-03, DEV_01-02, HO_01-04, FL_01-02, OBS_01-02 and OBS_03. Of
these, four are PARTIAL here: HO_04, FL_01, FL_02, OBS_02. We do not meet the set.

## Device runs of 2026-11-19 (one sitting; no status above changes)

On 2026-11-19 a sitting with two phones (a Pixel 10a as the vehicle, a Nothing phone as the roadside sensor) ran
under a frozen page; its summary with the record hashes is `phone/SITTING_B_2026-11-19_SUMMARY.md`. The plan's rule is that a device result
counts only with runs from two sittings, so the statuses in the table above stay as they are. What ran, by test
description:

| Test description | Device run of 2026-11-19 | What it does not show |
|---|---|---|
| TD_MEC_HO_01 | handover of the vehicle phone, 4 runs, all PASS (3 at a 5 s period, 1 at 1 s) | a radio-triggered handover: the threshold was set so that the first real report fires |
| TD_MEC_HO_02 | in each run a command posted at the new edge was acknowledged by the phone there, the source took none after the release, and every new record on the new edge was notified once | a command from another party than the vehicle's owner; `<mgmtCmd>` |
| TD_MEC_HO_03 | the phone's own sequence numbers across both edges: none lost, none duplicated, in each run; telemetry pause 8.7 s at 5 s and 4.6 s at 1 s | dual attach; the stream is stopped for the move |
| TD_MEC_FL_01, TD_MEC_FL_02 | records captured from both phones (27 of 27 slots each), three rounds on them PASS 72 of 72 with 9 controls | a phone that registers, is notified or trains: a host bridge posted the records, so TD_MEC_FL_01 is not passed |
| TD_MEC_OBS_01 | the handover's times and the vehicle phone's runtime figures are in the run records | they are not in a KPI export: the KPI tool refuses a phone results file that lacks its device fields |

Also run with a phone that day, outside the 18 test descriptions: re-authentication at the target admitted on a real
signature by a key the phone attested on 2026-10-15 (10 steps, 7 controls); location samples with source, accuracy
and age, consent as an access policy and a stale-sample rule (9 steps, 4 controls); sensor sharing through our MEC
046 candidate (54 rows, 7 controls). Not run with a phone: TD_MEC_DEV_02's cell change, MEC 021, MEC 028.

## Guide procedures (2026-10 draft) with no test description

Each is a procedure the developer guide now asks for that the test plan (rev 0.2.0) has no TD for:

1. 5.2.4.1 the IN-CSE with TLS and HTTP Basic auth -- ours: `estimed/tests/test_tr0086_tls_basic_auth.py`, on
   private CSEs (the lab itself stays plain HTTP on loopback); the MEC flexContainer definitions (3 `.fcp` +
   1 `.rtp`) loaded at start-up -- not in our lab yet (stock ACME definitions).
2. 5.2.4.1.5 a plain GET is refused, a well-formed one reaches the IN -- ours: `test_tr0086_bringup.py`.
3. 5.2.4.3.4 MEC 011 verification checks (current_time, service list) -- ours: `test_tr0086_bringup.py`.
4. 5.2.4.4 cst == 2 for an MN-CSE -- ours: `test_tr0086_bringup.py`.
5. 5.2.4.5 the `<remoteCSE>` pair over Mcc, its naming and the poa rule -- ours: `test_tr0086_bringup.py`.
6. 5.2.4.6 MEC-IPE start-up sequence (6a option A on the IN, 6b on the MN, MEC 033 registration) -- ours: option A
   and B registration and the location relay in `test_tr0086_location.py`; our IPE does not run ETSI's sequence
   (MEC 011 confirm_ready, MEC 033) -- see the deep check of 2026-10-29.
7. 5.3 per-option registration targets and the 403/409 "already registered" reconnect rule -- partly:
   `test_5_3_control_duplicate_registration_is_refused`; Annex A runs on the IN (option A) and an MN.
8. 5.4 an AE deployed as a container in a sandbox scenario (ETSI ae-demo) -- ours since 2026-11-18: our own AE
   deployed as a process through MEC 010-2 lifecycle calls (`test_tr0086_mec_app_deploy.py`); no container, no sandbox.
9. 5.6 MEC 013 v3 prerequisite for the IPE -- ours uses /location/v3 throughout.
10. Annex A device workflow -- ours: `test_tr0086_annex_a.py` (20 runs: 10 tests on the MN and on the IN).
11. Annex B local MEC Sandbox installation -- not done.

## Where ACME 2026.5.3 differs from the guide's examples (for the TR's authors)

Measured on the lab, asserted as ACME behaves in the tests named:

- A.2.9: the subscription verification request's `sur` is the subscription's resource ID (`/<csi>/<ri>`), not the
  structured path shown, and it also carries `cr` (both asserted in
  `test_a_2_4_command_subscription_is_verified_before_it_exists`); its X-M2M-Origin is the CSE-ID (`/id-mn-a`), not
  the CSEBase name (measured 2026-10-29, not asserted: the test receiver records bodies only).
- A.2.5: the stored `mid` holds the members' resource IDs, not the structured paths posted
  (`test_a_2_8_latest_readings_of_all_members_in_one_request`).
- A.2.8: each aggregated `m2m:rsp` carries `rsc`/`rqi`/`rvi` but no `to` (optional in TS-0004); members are told
  apart by their content's `pi`. (`test_a_2_8_latest_readings_of_all_members_in_one_request`)
- A.2.4: a subscription whose callback cannot be reached fails at once (500, "Verification request failed"); it does
  not remain pending. (`test_a_2_4_control_unreachable_callback_creates_no_subscription`)
- 5.2.4.5: forwarded through the IN, the IN's CAdmin arrives at an MN as `/id-in/CAdmin` and is not that MN's admin:
  a forwarded RETRIEVE of the MN's CSEBase is 403 and a forwarded discovery returns an empty list. "Reachable" is shown
  on a resource whose policy grants the forwarded originator. (`test_5_2_4_5_in_reaches_each_mn_over_its_poa`)
