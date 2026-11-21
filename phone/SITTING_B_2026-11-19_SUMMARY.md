# Sitting B, 2026-11-19: two phones, summary (sitting 1 of 2)

*Note (2026-11-21): the frozen page `PREREG_SITTING_B_2026-11-19_rev4.md` and `runtime_phoneA_1.json` named below are not published.*

Made from the result files in `~/estimed-run/sitting_b/`, not from terminal output. Frozen page:
`phone/PREREG_SITTING_B_2026-11-19_rev4.md`, body SHA-256 `6b10749058c77ab2...`, go typed by the author as `6b107490`.
Code: worktree commit `971d871`, all 19 pinned files equal at check-in. phone-A is a Pixel 10a (vehicle), phone-B a
Nothing phone (roadside sensor); both ran probe app version 19, in two different binaries. The lab is three ACME
CSEs and our own MEC candidates on one PC; the phones were reached through their USB cables.

**One sitting.** By the plan's rule a device row counts only with runs from two sittings, so nothing here changes
a row of `estimed/TESTPLAN_COVERAGE.md`. Not a conformance claim.

## Rows

| Row | What ran | Result | Record (SHA-256, first 16) |
|---|---|---|---|
| R2-capture | env records of both phones, 27 slots of 5 s | PASS: USABLE, self-check agrees | `fl_capture_1.json` `9a7d65c47a8eda1f` |
| R2-fl | three rounds and a control round on those records, behind a host bridge | PASS: 72 of 72 steps passed, 9 of 9 controls failed as they must | `fl_dev_20261119T174801.json` `e958c6af48a74748` |
| R2-sig | the capture's digest countersigned by a kept phone key | phone-B PASS (key attested 2026-10-15); phone-A NOT-RUN (no record under that alias) | same capture file |
| R1 run 1 | handover, rule latest, period 5 s | PASS: 53 of 53 steps passed, 11 of 11 controls failed as they must | `poc2_run1.json` `1f548154ab50f3e5` |
| R1 run 2 | handover, rule none, period 5 s | PASS: 53 of 53 steps passed, 11 of 11 controls failed as they must | `poc2_run2.json` `cb2c05c732803f95` |
| R1 run 3 | handover, rule latest, period 5 s | PASS: 53 of 53 steps passed, 11 of 11 controls failed as they must | `poc2_run3.json` `5a806562f9bc1040` |
| R1 run 4 | handover, rule latest, period 1 s | PASS: 55 of 55 steps passed, 11 of 11 controls failed as they must | `poc2_run4.json` `c41c270b4151492c` |
| R7 | read-only runtime sampler on phone-A beside R1 | PASS: 120 samples, checker agrees, nothing listed as not reported | `runtime_phoneA_1.json` `5a6c9823894c6c04` |
| R4 | location samples of phone-A: source, accuracy, age; consent; stale sample; export | PASS: 9 of 9 steps passed, 4 of 4 controls failed as they must | `loc_check_1.json` `e7d212df6aad6133` |
| R5 | re-authentication of phone-B at the target with a real signature over a transaction | PASS: 10 of 10 steps passed, 7 of 7 controls failed as they must | `reauth_1.json` `be040b060c855628` |
| R6 | sensor sharing through our MEC 046 candidate, phone-A | PASS: 54 of 54 rows passed, 7 control rows, 0 skipped | `mec046_1.json` `f5e44e5d1850da96` |

## The handover's measured values (reported, no pass rule beyond the driver's 60 s bound)

| Run | Period | Trigger to COMPLETED | Telemetry pause | Notification gap | Command acknowledged after | Sequence count |
|---|---|---|---|---|---|---|
| 1 | 5 s | 16.52 s | 8.72 s | 8.72 s | ping 0.51 s, period 0.52 s | counter restarted, lost 0, duplicated 0 |
| 2 | 5 s | 16.59 s | 8.7 s | 8.7 s | ping 0.51 s, period 0.52 s | counter restarted, lost 0, duplicated 0 |
| 3 | 5 s | 16.61 s | 8.71 s | 8.7 s | ping 0.51 s, period 0.51 s | counter restarted, lost 0, duplicated 0 |
| 4 | 1 s | 9.17 s | 4.6 s | 4.6 s | ping 0.51 s, period 0.52 s | counter restarted, lost 0, duplicated 0 |

Three values at 5 s are three values, not a rate. The trigger threshold was -44 dBm, chosen so that the first real
report fires: the runs show the mechanism on the phone's own reports, not a radio event. The commands were posted
by the vehicle's own originator from the host.

## Runtime figures of phone-A during R1 (reported, no pass rule)

| Figure | n | min | median | max | unit |
|---|---|---|---|---|---|
| cpu_total_pct | 120 | 2.207 | 9.855 | 55.609 | per cent of the time of all online CPUs |
| cpu_probe_pct | 120 | 0.0 | 0.0 | 1.41 | per cent of the time of all online CPUs |
| pss_kb | 120 | 12946 | 14096.0 | 31382 | kB |
| vmrss_kb | 120 | 121496 | 123066.0 | 133704 | kB |
| threads | 120 | 28 | 33.0 | 48 | threads |
| wakelock_count | 120 | 0 | 0.0 | 0 | wake locks |
| batt_temp_dc | 120 | 330 | 341.0 | 355 | tenths of a degree C |
| batt_level | 120 | 48 | 49.0 | 50 | per cent of full |
| thermal_status | 120 | 0 | 0.0 | 1 | Android thermal status 0..6 |

## R3, the existing suites on phone-A (no suite repeated)

| Suite | Exit code | Its own result line |
|---|---|---|
| test_phone_units | 0 | RESULT: 35/35 checks pass |
| test_phone_etsi | 1 | (none printed) |
| test_phone_mec013sub | 0 | RESULT: 18/18 checks pass |
| test_phone_onem2m | 0 | RESULT: 38/38 checks pass |
| phone_handover | 0 | RESULT: PASS  (14/14 steps) |
| test_phone_mec016 | 0 | RESULT: 13/13 checks pass |
| test_phone_mec021 | 2 | (none printed) |
| test_phone_mec033 | 0 | RESULT: 12/12 checks pass |
| test_phone_onem2m_ts | 1 | RESULT: 13/14 checks pass |
| test_en303645 | 0 | RESULT: 13/13 checks pass   (FINDING checks PASS when the shortfall is demonstrated) |

- `test_phone_etsi` stopped with a name lookup error on the PC after 34 passing rows; which address it wanted was not established.
- `test_phone_mec021` stopped at its precondition: phone-A had Wi-Fi switched on and was connected to no network. No check ran: NOT-RUN.
- `test_phone_onem2m_ts`: the one failing row is the suite's own finding row about the CSE's missing-data detection (the CSE's side).

## First time on a phone, in this sitting

The checks before a handover; the copy rule for position and Wi-Fi history; a command acknowledged at the new edge;
the phone's own sequence numbers across both edges; one notification per new record; a 1 s period; the location
checks; re-authentication admitted on a real signature; sensor sharing; the runtime sampler; the capture path for
federated learning.

## What the sitting does not show

- A second sitting. Until one exists, each row above is a dated run.
- A phone that registers, is notified or trains in federated learning: the host posted the records. TD_MEC_FL_01 is not passed.
- Who holds a phone; an authenticated originator; a fresh attestation (the record used is of 2026-10-15 and no longer verifies as of today).
- A device against the network for location; a radio-triggered handover; traffic over a radio link (everything went through USB).
- MEC 021 and MEC 028 with a phone.

## After the sitting, the same day

- Restore check: both phones' airplane mode, Wi-Fi, mobile data and location equal to check-in, Bluetooth off, no forward left.
- The probe app was updated in place to version 20 on both phones at the author's word (same signer, app files and first-install
  dates kept; `install_v20_20261119.txt`). phone-B's key of 2026-10-15 still signs afterwards, verified on the host against
  the attestation record's leaf key. No run has been made on version 20; a second sitting will run on it and must say so.
- Two more pages were frozen and NOT run: MEC 021 and MEC 028 (phone-A could not join the Wi-Fi network), and a run with
  phone-B reached over Wi-Fi. Both check for version 19 and need a revision before use.
