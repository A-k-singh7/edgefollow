# Records

The records are the results the article and the README cite. Each is a JSON or text file that a run wrote.

## What they are

| Records | What they show |
| ------- | -------------- |
| Sitting B: the four handover runs with the real phones (`poc2_run1` to `poc2_run4`) and the other phone runs of that sitting | every step, every control (which must fail), and the measurements: trigger to completed move, notification gap, command answered at the new edge, samples lost and duplicated |
| Simulated runs (`sim/`): federated learning (the FL_03 comparison and its three runs), the handover policy, the clean-rerun reference | the same drivers with simulated devices; TD_MEC_DEV_02 has no published record (its offline rows are `estimed_poc/test_dev02.py`) |
| The fresh-VM reruns (`vm_rerun_*.json`) | a Debian 13 VM followed the runbook to TD_MEC_DEV_01: 142 of 142 tests on 2026-11-20, and again with the cleaned code on 2026-11-21 (142 of 142, onboarding at most 133 s, all five OBS_03 steps PASS) |
| The ETSI MEC test suites (`sweep_*.txt`) | 55 suites run against this project's MEC services: 533 passed, 148 failed, 2 not run |
| The TLS front door (`test_tls_front_*.txt`) | 139 tests, 91 of them controls |
| ETSI's MEC Sandbox (`sandbox/`) | the move started by the Sandbox's MEC 013 zone change: 10 runs (`sandbox_follow_*.json`), one in each of its 8 network scenarios (also in `matrix/`) and two earlier ones; 9 moved, the tenth correctly did not (no zone change); and our MEC services compared with the Sandbox's on 38 endpoints (`ours/compare_final.json`); the Sandbox's address is `<sandbox>` |
| tinyIoT as edge B (`tinyiot/2026-11-21/`) | run 4: the move from ACME to tinyIoT and back, and the full scenario 10 of 10, with the driver scripts; run 2: tinyIoT's announcement failing without an error (the IN-CSE had no route after the first move) |
| Protocols (`proto/`) | one oneM2M workload over six bindings of one CSE: the publication copy of the record and its tables |

## Read them with these points in mind

- **Scrubbed for publication.** Real network identifiers (cell, TAC, network code), device serials and tags, the
  phone's distance to a published fixture point, and this PC's paths and names are replaced by placeholders such
  as `<cell-A>`. The structure and every measurement are unchanged.
- **Hashes are history.** Fields like `files_sha256` and commit ids name the files and commits of the private
  working tree at the time of the run. Some of those files changed later, and the scrub changed some bytes, so these
  hashes do not match the published files. They are kept as they were written; they are not "fixed".
- **One sitting.** The phone runs come from one sitting (app version 19). The project's own rule asks for two
  sittings before a device result counts as repeated.
- **Measurements, not approvals.** A pass in an ETSI test suite is a measurement of this project's implementation.
  It is not a conformance claim.
