# Reproduce the numbers

Every number in the article comes from a record in `records/` or from a test in this repository. This page says,
for each one, how far you can reproduce it:

- **offline**: no lab at all; it runs anywhere with the lab environment installed;
- **with the lab**: the CSEs (`estimed/run_topology.sh`) and the MEC services (`estimed/mec_services.sh start`),
  no phones;
- **record only**: it needs the phones, ETSI's test suites, ETSI's hosted MEC Sandbox, a tinyIoT build or the
  original VM harness, or it is a timing of one PC; the record is published.

Commands assume the layout of the README (`PY=~/edgefollow-lab/.venv/bin/python`, `VENV=~/estimed-venv` for the CSE
environment, run from the repository root).
Run every lab command under the lab lock, as the lab's own tooling does, for example:
`flock -o ~/estimed-run/.live.lock $PY -B -m pytest -q estimed/tests/test_tr0086_option_a.py`.

## Offline

| Claim | How to reproduce |
| ----- | ---------------- |
| The MCP agent and its servers: 121 offline tests | `$PY -B -m pytest -q -m "not lab" estimed/tests/test_edge_agent.py` |
| The TLS front door: 139 tests, 91 of them controls | `mkdir -p ~/estimed-run/tmp && TMPDIR=~/estimed-run/tmp python3 -I -B phone/test_tls_front.py` (any temporary folder works except one under `/var`, which the test refuses) |
| The phone driver's own checks (trigger rule, scans, port check): 169 checks | `$PY -I -B phone/test_estimed_poc.py`, with `PY` the environment of `requirements/lab.txt` (it uses jsonschema, which the three packages of the README's quick start do not include; it reads three JSON schemas from ETSI's MEC test-suite repository, cloned at `~/etsi-forge-ats-reference`: https://forge.etsi.org/rep/mec) |
| The Sandbox driver's logic and its limits: 57 offline tests, 58 with its live test | `$PY -B -m pytest -q estimed/tests/test_sandbox_follow.py`; without the lab its one live test fails on purpose ("needs the lab lock"); with the lab, `flock -o ~/estimed-run/.live.lock $PY -B -m pytest -q estimed/tests/test_sandbox_follow.py` passes all 58 |
| The MEC services script | `$PY -B -m pytest -q estimed/tests/test_mec_services_sh.py` |
| The warning AE: the rule, the record shapes, the route record and the route keeper against an in-memory CSE: 70 tests | `$PY -B -m pytest -q --strict-markers -m "not live" estimed/tests/test_vru_warning.py` |
| The location service's MEC 013 zone list and single zone (`/queries/zones`, `/queries/zones/{zoneId}`): 20 tests | `$PY -B -m pytest -q mec013_look/test_candidate_zones.py` |
| The handover library's checks with a fake CSE, among them the IN-CSE's route before and after the move: 23 and 32 tests | `$PY -B -m pytest -q estimed/tests/test_handover_offline.py` (23) and `$PY -B -m pytest -q estimed/tests/test_handover_before_offline.py` (32) |
| The phone's zone in MEC 013's zone list, while its sample is fresh and never after (a simulated phone): 22 checks | `$PY -B phone/test_phone_mec013_zones.py` |
| The protocol harness's own logic (CoAP codec against RFC 7252 and CoAPthon, WebSocket and MQTT sizes, the byte-counting proxies, planted faults): 25 tests | `cd estimed/proto_bench && $VENV/bin/python3 -m unittest test_proto_bench.py` (the CSE environment has websockets and paho) |

## With the lab (no phones)

| Claim | How to reproduce |
| ----- | ---------------- |
| TR-0086 deployment option A: 21 tests | `$PY -B -m pytest -q estimed/tests/test_tr0086_option_a.py` |
| Options C and D: 101 tests (on a private IN-CSE) | `$PY -B -m pytest -q estimed/tests/test_tr0086_options_c_d.py` |
| TR-0086 5.2.4.1, TLS + Basic auth on private CSEs: 37 tests | `$PY -B -m pytest -q estimed/tests/test_tr0086_tls_basic_auth.py` (needs `openssl`) |
| Annex A: 20 test cases | the runbook's TD_MEC_DEV_01 block (`estimed/RUNBOOK.md`) |
| The handover with a simulated phone | `$PY phone/estimed_poc2.py --device sim` (writes a timestamped record; never over a phone record) |
| The handover on the live CSEs (TD_MEC_HO_01 to 03, the rollback, and the IN-CSE's route after the move): 44 tests | `$PY -B -m pytest -q estimed/tests/test_tr0086_handover.py` |
| The MCP agent on the lab: 3 tests | `$PY -B -m pytest -q -m lab estimed/tests/test_edge_agent.py` |
| The warning AE on the lab, through moves from edge A to edge B with a simulated vehicle and roadside sensor: 29 tests (the whole file: 99) | `$PY -B -m pytest -q --strict-markers estimed/tests/test_vru_warning.py` (its live tests refuse to run unless the lab lock is held) |
| Federated learning, three placements (bytes to the cloud, rounds) | `$PY estimed_poc/fl_run.py --compare` (simulated devices) |
| The handover policy, rollback and the diagnostic event | `$PY estimed_poc/policy_run.py` |

## Record only

| Claim | Record | Why only the record |
| ----- | ------ | ------------------- |
| The four handover runs with the real phones (16.5-16.6 s and 9.2 s, gap 8.7 s and 4.6 s, command answered in 0.51 s, 0 lost / 0 duplicated) | sitting B `poc2_run1` to `poc2_run4` | two phones and a frozen run page; the driver is `phone/estimed_poc2.py --device adb` |
| Federated learning with real phone captures | sitting B `fl_dev_*`, `fl_capture_1` | phone captures |
| MEC 013 subscriptions on a phone (18/18), EN 303 645 checks (13/13), re-authentication | sitting B logs and records | phones |
| A fresh Debian 13 VM: 142 of 142 tests in 128.5 s (2026-11-20) | `vm_rerun_20261120T092249Z.json` | `estimed/vm_rerun.py` needs a local Debian cloud image and the original paths |
| The cleaned code on a fresh Debian 13 VM (2026-11-21): 142 of 142 tests, onboarding at most 133 s of the 1800 s budget, all five OBS_03 steps PASS | `vm_rerun_20261121T054608Z.json` | the same |
| ETSI MEC test suites: 55 suites, 533 passed, 148 failed, 2 not run | `sweep_2026-11-19.txt` | ETSI's Robot test suites and the full set of MEC candidates, not all in this repository |
| The move driven by ETSI's hosted MEC Sandbox: completed in all 8 network scenarios (9 of 10 runs; the tenth correctly did not move); our MEC services and the Sandbox's on 38 endpoints (25 answer on both) | `records/sandbox/` | a Sandbox session of your own (`estimed/sandbox_follow.py` drives it); the address of ours is not published |
| The move between ACME and tinyIoT, both ways, and the full scenario 10 of 10 with tinyIoT as edge B | `records/tinyiot/2026-11-21/` (run 4; run 2 shows tinyIoT's failed announcement) | a tinyIoT build (commit c140495 with `records/tinyiot/tinyiot-lab.patch`) in the place of MN-CSE B; the drivers are in the record folder |
| One oneM2M workload over six bindings of one CSE (latency, bytes, setup cost, notification delay) | `records/proto/` | timings of one PC on loopback; `estimed/proto_bench/proto_bench.py` (with mosquitto) measures your own |

## What the numbers do not show

The records state their own limits. In short: one PC, USB instead of radio, the MEC services' radio and location
data come from the phones themselves, simulated learning devices, one sitting with the phones. See the README's
"Limits" and `records/README.md`.
