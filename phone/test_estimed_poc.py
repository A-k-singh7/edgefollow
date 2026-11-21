#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline controls for the ESTIMED PoC (2026-10-29) -- no phone, no CSE, no network.

  * the simulated phone (sim_phone.py) writes what the probe app writes, as the MEC services READ it: the same
    device_state / mec013_phone / mec012_phone code that serves the real Pixel must serve the simulation;
  * every simulated value says so (PLMN 001/01, "sim": true in each record), so a simulated run can never be
    mistaken for a phone run;
  * the handover trigger (estimed_poc2.decide) against hand-written TS 36.133 reported values;
  * a PoC run that stops early is a FAIL with its results written, never a crash or a short PASS.

Expected values are written from the standard, not computed with the code under test.

    python3 phone/test_estimed_poc.py
"""
from __future__ import annotations

import json
import re
import time
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402
import estimed_poc2 as poc  # noqa: E402
import mec012_phone as m12  # noqa: E402
import mec013_phone as m13  # noqa: E402
import sim_phone  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def main() -> int:
    print("== the simulated phone, read by the services that serve the real one")
    ph = sim_phone.SimPhone("http://127.0.0.1:1/none", origin="Csim", rn="phone", rsrp=-110, rsrq=-9,
                            ci=0x1A2B3C4, tac=4242)
    rec = ph.records(now_ms=1_800_000_000_000)
    check("one record per container the app posts", set(rec) == {"imu", "env", "loc", "radio", "wlan"}, sorted(rec))
    check("every record is marked simulated", all(r.get("sim") is True for r in rec.values()))
    cell = ds.serving_cell(rec["radio"])
    check("device_state finds the serving LTE cell", cell is not None and cell["ci"] == 0x1A2B3C4 and cell["tac"] == 4242,
          str(cell and {k: cell[k] for k in ("mcc", "mnc", "ci", "tac")}))
    check("PLMN is the ITU test network 001/01, never a real operator",
          cell is not None and (cell["mcc"], cell["mnc"]) == ("001", "01") and rec["radio"]["plmn"] == "00101")
    # TS 36.133 9.1.4: RSRP_k covers [-141 + k, -140 + k) dBm  ->  -110 dBm is RSRP_31
    body = m12.meas_rep_ue(rec["radio"])
    check("MEC 012 MeasRepUe: RSRP -110 dBm is reported value 31 (TS 36.133)", body is not None and body["rsrp"] == 31,
          str(body and body["rsrp"]))
    # TS 36.133 9.1.7: RSRQ_k covers [-20 + k/2, -19.5 + k/2) dB  ->  -9 dB is RSRQ_22
    check("MEC 012 MeasRepUe: RSRQ -9 dB is reported value 22", body is not None and body["rsrq"] == 22,
          str(body and body["rsrq"]))
    check("MEC 012 ecgi cellId is the 28-bit ECI as 7 hex digits", body is not None and body["ecgi"]["cellId"] == "1A2B3C4")
    u = m13.phone_user({"radio": rec["radio"], "loc": rec["loc"]})
    check("MEC 013 serves the simulated UE (zone tac4242, AP 1A2B3C4, a fix with accuracy)",
          u is not None and u["zoneId"] == "tac4242" and u["accessPointId"] == "1A2B3C4"
          and isinstance(u.get("locationInfo", {}).get("accuracy"), int), str(u and {k: u.get(k) for k in ("zoneId", "accessPointId")}))
    # GS MEC 013 v3.1.1 and v3.2.1 Table 6.2.2-1: UserInfo.timeStamp is mandatory. ETSI's ATS schema
    # (MEC013/SRV/UELOCLOOK/schemas/UserInfo.schema.json) requires `timestamp` instead and allows extra fields,
    # so the service carries both, equal; clients read the spec name first (deep check 2026-10-29).
    check("MEC 013 UserInfo carries the spec's timeStamp (Table 6.2.2-1), equal to the ATS schema's timestamp",
          u is not None and isinstance(u.get("timeStamp"), dict) and u.get("timeStamp") == u.get("timestamp"),
          str(u and {k: u.get(k) for k in ("timeStamp", "timestamp")}))
    fs = getattr(poc, "fix_seconds", None)
    check("the PoC reads a fix time by the spec name, by the ATS name, and None when neither is there",
          callable(fs) and fs({"timeStamp": {"seconds": 7, "nanoSeconds": 0}}) == 7
          and fs({"timestamp": {"seconds": 8, "nanoSeconds": 0}}) == 8 and fs({}) is None and fs(None) is None)
    src = (HERE / "estimed_poc2.py").read_text()
    direct, gets = src.count('["timestamp"]'), src.count('.get("timestamp"')
    check("no PoC code reads the fix time directly any more: only fix_seconds, whose ATS-name fallback is the one .get",
          direct == 0 and gets <= 1, f"{direct} subscript reads, {gets} .get reads")
    ph.set_signal(rsrp=-85, rsrq=-7)
    check("set_signal changes what MEC 012 reports (-85 dBm -> 56)", m12.meas_rep_ue(ph.records()["radio"])["rsrp"] == 56)
    ph.set_cell(ci=0x1A2B3C5, tac=4242)
    check("set_cell changes the serving cell MEC 013 reports",
          m13.phone_user({"radio": ph.records()["radio"], "loc": rec["loc"]})["accessPointId"] == "1A2B3C5")
    check("the Android 'unavailable' value never appears in a simulated record",
          str(ds.UNAVAILABLE) not in json.dumps(ph.records()))
    rsu = sim_phone.SimPhone("http://127.0.0.1:1/none", origin="Csim2", rn="rsu", cellular=False, wifi_aps=24)
    rr = rsu.records()
    check("a sensor without mobile service has no serving cell (MEC 013 does not serve it)",
          ds.serving_cell(rr["radio"]) is None and m13.phone_user({"radio": rr["radio"], "loc": rr["loc"]}) is None)
    check("the sensor's derived context: 24 Wi-Fi APs seen", poc.count_items(rr["wlan"]) == 24)

    print("== the handover trigger (TS 36.133 reported value -> dBm, then the threshold)")
    # value k means [-141 + k, -140 + k) dBm; decide() triggers when the WHOLE bin is below the threshold
    for idx, thr, want in ((31, -100, True), (40, -100, True), (41, -100, False), (56, -100, False),
                           (0, -141, False), (97, -44, False), (36, -80, True)):
        got = poc.decide(idx, thr)
        check(f"decide(RSRP_{idx}, threshold {thr} dBm) -> {'trigger' if want else 'stay'}", got == want, f"got {got}")
    check("CONTROL decide() refuses a missing report (None is never a trigger)", poc.decide(None, -100) is False)

    print("== the handover trigger on 5G NR (TS 38.133 V19.6.0 Table 10.1.6.1-1, L3 SS-RSRP column)")
    # RSRP_0 < -156; RSRP_k (1..125) = [-157 + k, -156 + k); RSRP_126 >= -31; RSRP_127 = 'Infinity' (network
    # thresholds only, "not for the purpose of measurement reporting") -> never a valid report
    for idx, thr, want in ((0, -157, False), (0, -156, True), (1, -156, False), (1, -155, True), (50, -100, True),
                           (56, -100, True), (57, -100, False), (125, -31, True), (126, -31, False), (126, 0, False),
                           (127, 0, False), (128, 0, False), (-1, 0, False)):
        got = poc.decide(idx, thr, "NR")
        check(f"decide(NR RSRP_{idx}, threshold {thr} dBm) -> {'trigger' if want else 'stay'}", got == want, f"got {got}")
    check("the NR bin of RSRP_50 is [-107, -106) dBm", poc.rsrp_bin(50, "NR") == (-107, -106), f"{poc.rsrp_bin(50, 'NR')}")
    check("the LTE bin of RSRP_31 is [-110, -109) dBm (unchanged)", poc.rsrp_bin(31, "LTE") == (-110, -109),
          f"{poc.rsrp_bin(31, 'LTE')}")
    check("LTE stays the default scale (old callers): decide(31, -100) triggers", poc.decide(31, -100) is True)
    check("CONTROL the LTE table misreads NR: NR RSRP_41..56 at -100 dBm must trigger, the LTE rule would stay",
          all(poc.decide(k, -100, "NR") and not poc.decide(k, -100, "LTE") for k in range(41, 57)))
    check("CONTROL an unknown RAT never triggers", poc.decide(10, -100, "5G") is False and poc.rsrp_bin(10, "5G") is None)
    check("CONTROL a bool is not a reported value on either scale",
          poc.decide(True, 0, "NR") is False and poc.decide(True, 0, "LTE") is False)
    check("the hold-window threshold is below every bin on both scales",
          not any(poc.decide(k, poc.HOLD_NEVER_DBM, r) for r, n in (("LTE", 97), ("NR", 126)) for k in range(n + 1)),
          f"HOLD_NEVER_DBM {poc.HOLD_NEVER_DBM}")

    print("== which RSRP in a MEC 012 MeasRepUe is the vehicle's own link (GS MEC 012 MeasRepUeNotification)")
    nr_sc = lambda v: {"nrCarrierFreq": 632628, "nrSCs": {"nrSCellInfo": [{"nrSCellGId": {"nrcellId": "1"}}], "nrSCellRsrp": v}}
    both = {"rsrp": 31, "newRadioMeasInfo": [nr_sc(50)], "newRadioMeasNeiInfo": [{"nrNCellRsrp": 5}]}
    check("EN-DC report: the LTE anchor decides", poc.serving_rsrp(both) == ("LTE", 31), f"{poc.serving_rsrp(both)}")
    nr_only = {"newRadioMeasInfo": [nr_sc(50), nr_sc(60), {"nrBNCs": {"nrBNCellRsrp": 120}}],
               "newRadioMeasNeiInfo": [{"nrNCellRsrp": 126}]}
    check("NR-only report: the strongest NR serving cell decides (neighbours and best-neighbour cells never count)",
          poc.serving_rsrp(nr_only) == ("NR", 60), f"{poc.serving_rsrp(nr_only)}")
    check("CONTROL RSRP_127 ('Infinity', thresholds only) is not a report: no bin, never the serving value",
          poc.rsrp_bin(127, "NR") is None and poc.serving_rsrp({"newRadioMeasInfo": [nr_sc(127)]}) == (None, None))
    check("CONTROL a report with only neighbour values has no serving RSRP",
          poc.serving_rsrp({"newRadioMeasNeiInfo": [{"nrNCellRsrp": 5}], "newRadioMeasInfo": [{"nrBNCs": {"nrBNCellRsrp": 5}}]})
          == (None, None))
    check("CONTROL junk shapes give no serving RSRP (no crash)",
          all(poc.serving_rsrp(b) == (None, None) for b in (None, [], {"rsrp": "31"}, {"newRadioMeasInfo": "x"},
                                                           {"newRadioMeasInfo": [{"nrSCs": []}]}, {"rsrp": True})))

    print("== 7.2: a trigger from an unauthorised source is ignored")
    exp = {"token": "t0k3n", "sub": "/rni/v2/subscriptions/sub-7", "cell": "1A2B3C4"}
    good = {"notificationType": "MeasRepUeNotification", "rsrp": 31, "ecgi": {"cellId": "1A2B3C4"},
            "_links": {"subscription": {"href": "/rni/v2/subscriptions/sub-7"}}}
    acc = lambda path, body: poc.accept_mec012(path, body, exp)
    check("our subscription's notification on our secret callback path is accepted", acc("/mec012/t0k3n", good))
    check("CONTROL a forged report on the bare path (no token) is refused", not acc("/mec012", good))
    check("CONTROL a forged report with a guessed token is refused", not acc("/mec012/guess", good))
    check("CONTROL a report for another subscription is refused",
          not acc("/mec012/t0k3n", {**good, "_links": {"subscription": {"href": "/rni/v2/subscriptions/sub-8"}}}))
    check("CONTROL a report for another cell is refused", not acc("/mec012/t0k3n", {**good, "ecgi": {"cellId": "0000001"}}))
    check("CONTROL another notification type is refused",
          not acc("/mec012/t0k3n", {**good, "notificationType": "CellChangeNotification"}))
    check("CONTROL a non-object body is refused", not acc("/mec012/t0k3n", ["MeasRepUeNotification"]))

    print("== the notification listener survives hostile clients (a stalled sender must not block the trigger)")
    import socket
    import threading
    import urllib.request as ur
    poc.MEC12.clear()
    poc.EXP12.clear()
    poc.EXP12.update(exp)
    srv = poc.make_listener(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    stall = socket.create_connection(("127.0.0.1", port))      # claims 1 MB, sends nothing more, keeps the socket open
    stall.sendall(b"POST /mec012/t0k3n HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\n")
    bad = socket.create_connection(("127.0.0.1", port))        # a non-numeric length
    bad.sendall(b"POST /mec012/t0k3n HTTP/1.1\r\nHost: x\r\nContent-Length: abc\r\n\r\n")
    t0 = time.time()
    try:
        ur.urlopen(ur.Request(f"http://127.0.0.1:{port}/mec012/t0k3n", data=json.dumps(good).encode(), method="POST",
                              headers={"Content-Type": "application/json"}), timeout=3).close()
        delivered = True
    except Exception as e:  # noqa: BLE001
        delivered = repr(e)
    check("a real report is accepted within 3 s while a stalled client and a malformed one are connected",
          delivered is True and len(poc.MEC12) == 1, f"delivered {delivered}, accepted {len(poc.MEC12)}, {time.time() - t0:.1f} s")
    nr_rep = {k: v for k, v in good.items() if k != "rsrp"} | {"newRadioMeasInfo": [nr_sc(50)]}
    ur.urlopen(ur.Request(f"http://127.0.0.1:{port}/mec012/t0k3n", data=json.dumps(nr_rep).encode(), method="POST",
                          headers={"Content-Type": "application/json"}), timeout=3).close()
    check("the listener records the serving link's RAT and value: an NR-only MeasRepUe is ('NR', 50)",
          len(poc.MEC12) == 2 and tuple(poc.MEC12[-1][1:3]) == ("NR", 50), f"{poc.MEC12[-1:]}")
    big = socket.create_connection(("127.0.0.1", port))
    big.sendall(b"POST /mec012/t0k3n HTTP/1.1\r\nHost: x\r\nContent-Length: 104857600\r\n\r\n" + b"{" * 1024)
    big.settimeout(5)
    try:
        resp = big.recv(64)
    except OSError:
        resp = b""
    check("CONTROL a body over the size cap is refused (413), not read", resp.startswith(b"HTTP/1.0 413") or
          resp.startswith(b"HTTP/1.1 413"), repr(resp[:40]))
    for sck in (stall, bad, big):
        sck.close()
    srv.shutdown()
    srv.server_close()
    poc.MEC12.clear()
    poc.EXP12.clear()

    print("== positions never reach the city: a scan of every shared record")
    hits = poc.scan_positions({"m2m:cin": {"con": json.dumps({"zoneId": "tac1", "rsrp_dbm_below": -109,
                                                              "wifi_aps_seen": 24, "edge": "cse-mn-a"})}})
    check("derived context (zone, signal bin, AP count, edge) has no position", hits == [], str(hits))
    for name, rec in (("lat/lon in a JSON string", {"con": json.dumps({"fix": {"lat": 48.1, "lon": 11.5}})}),
                      ("MEC 013 locationInfo", {"locationInfo": {"latitude": [48.1], "longitude": [11.5], "shape": 5}}),
                      ("a trajectory list", {"trajectory": [[48.1, 11.5], [48.2, 11.6]]}),
                      ("a key in any case", {"Latitude": 48.1})):
        check(f"CONTROL the scan finds {name}", poc.scan_positions(rec) != [], str(poc.scan_positions(rec)))
    check("words that only contain 'lat'/'lon' are not positions (below, latency, along)",
          poc.scan_positions({"below": 1, "latency_ms": 3, "along": "x", "plmn": "001"}) == [])
    # 2026-11-19: the run's own control ("the position scan missed a planted coordinate") planted the position of a
    # real place on the lab CSE. It now plants SCAN_CONTROL_RECORD, a declared fictitious point. The scan works by key
    # name, so it must still find the record, read back as a CSE answers ?rcn=4: the JSON text of a <cin>'s con.
    planted = getattr(poc, "SCAN_CONTROL_RECORD", None)
    check("the run's scan control plants a declared fictitious point: latitude 0.0, longitude 0.0, marked fictitious",
          json.dumps(planted, sort_keys=True) == '{"fix": {"fictitious": true, "lat": 0.0, "lon": 0.0}}',
          json.dumps(planted, sort_keys=True))
    back = poc.scan_positions({"m2m:cnt": {"rn": "scanControl", "m2m:cin": [{"con": json.dumps(planted, sort_keys=True)}]}})
    check("the scan finds that record as a CSE gives it back: its lat and its lon, inside the con text",
          back == ["m2m:cnt.m2m:cin[0].con.fix.lat", "m2m:cnt.m2m:cin[0].con.fix.lon"], str(back))
    src = (HERE / "estimed_poc2.py").read_text()
    i0, i1 = src.find('{"m2m:cnt": {"rn": "scanControl"}}'), src.find("the position scan missed a planted coordinate")
    block = src[i0:i1] if 0 < i0 < i1 else ""
    decimals = re.findall(r"\d+\.\d+", block)
    by_name = 'in_put("scanControl", SCAN_CONTROL_RECORD)' in block
    check("the run plants that record and no other: one in_put in the control, and no literal number with a decimal "
          "point between the container's creation and the control's row",
          block.count("in_put(") == 1 and by_name and decimals == [],
          f"{block.count('in_put(')} in_put, the record by name: {by_name}, {len(decimals)} decimal literals")

    print("== history copied at a handover: rule all / latest / none for loc and wlan")
    h = [{"con": "p1"}, {"con": "p2"}, {"con": "p3"}]
    check("rule all copies every instance of every container",
          all(poc.history_to_copy(c, h, "all") == h for c in ("imu", "env", "loc", "radio", "wlan")))
    check("rule latest copies only the newest position and the newest Wi-Fi record",
          poc.history_to_copy("loc", h, "latest") == [{"con": "p3"}] and poc.history_to_copy("wlan", h, "latest") == [{"con": "p3"}])
    check("rule none copies no position and no Wi-Fi record",
          poc.history_to_copy("loc", h, "none") == [] and poc.history_to_copy("wlan", h, "none") == [])
    check("rules latest and none leave imu, env and radio complete",
          all(poc.history_to_copy(c, h, r) == h for c in ("imu", "env", "radio") for r in ("latest", "none")))
    check("rule latest on an empty container copies nothing", poc.history_to_copy("loc", [], "latest") == [])
    try:
        poc.history_to_copy("loc", h, "newest")
        refused = False
    except ValueError:
        refused = True
    check("a rule that is not all, latest or none is refused", refused)
    # by hand: the source's history is p1 p2 p3. The target holds p3 (allowed by "latest"), n1 (new, posted after the
    # move) and p1 (old, not allowed) -> one record over the rule: p1.
    check("history scan: a record of the source's history beyond the rule is found, the allowed and the new are not",
          poc.history_over(["p1", "p2", "p3"], ["p3", "n1", "p1"], ["p3"]) == ["p1"])
    check("history scan: the allowed record twice on the target is one over (a second copy is history too)",
          poc.history_over(["p1", "p2", "p3"], ["p3", "p3"], ["p3"]) == ["p3"])
    check("history scan: rule none allows nothing", poc.history_over(["p1"], ["p1"], []) == ["p1"])
    check("CONTROL the history scan is not blind: a clean target gives no hit and a dirty one gives one",
          poc.history_over(["p1", "p2"], ["n1", "n2"], []) == [] and len(poc.history_over(["p1", "p2"], ["n1", "p2"], [])) == 1)

    print("== a device on the wrong district is flagged")
    where = {"phone": {"cse-mn-b"}, "rsu": {"cse-mn-a"}}           # CSEs on which each device's AE actually exists
    check("the registry matches where the AEs are: nothing flagged",
          poc.audit_devices({"phone": "cse-mn-b", "rsu": "cse-mn-a"}, where) == [])
    check("CONTROL a registry entry naming the old edge is flagged",
          poc.audit_devices({"phone": "cse-mn-a", "rsu": "cse-mn-a"}, where) == ["phone"])
    check("CONTROL a device registered on two edges at once is flagged",
          poc.audit_devices({"phone": "cse-mn-b"}, {"phone": {"cse-mn-a", "cse-mn-b"}}) == ["phone"])
    check("CONTROL a registered device with no AE anywhere is flagged", poc.audit_devices({"ghost": "cse-mn-a"}, {}) == ["ghost"])

    print("== a run that stops early is a FAIL with its results written")
    poc.STEPS.clear()
    poc.step("a passing step", True)
    try:
        poc.require("a precondition that fails", False, "the phone is not served")
        check("require() stops the run", False)
    except poc.Abort:
        check("require() stops the run", True)
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "r.json"
        poc.STEPS.clear()                     # every recorded step passed and the control failed: only the stop is wrong
        poc.step("a passing step", True)
        poc.step("CONTROL (must FAIL) a control that failed", False)
        ok = poc.finish(out, aborted_at="a precondition that fails", device="sim")
        rows = json.loads(out.read_text())
        check("finish() reports FAIL for an aborted run whose recorded steps all passed", ok is False)
        check("finish() writes the results file with the device and the stop reason",
              rows["device"] == "sim" and rows["aborted_at"] == "a precondition that fails" and len(rows["steps"]) == 2
              and rows["verdict"] == "FAIL")
        poc.STEPS.clear()
        poc.step("a passing step", True)
        poc.step("CONTROL (must FAIL) a control that failed", False)
        check("finish() reports PASS when every step passed and every control failed",
              poc.finish(out, aborted_at=None, device="sim") is True)
        run = json.loads(out.read_text()).get("run", {})
        check("the record carries what re-runs it: argv, cwd, commit, code SHA-256s, ACME version",
              isinstance(run.get("argv"), list) and run.get("cwd") and "commit" in run and "acme" in run
              and len(run.get("files_sha256", {}).get("phone/estimed_poc2.py", "")) == 64, str(sorted(run)))
        poc.STEPS.clear()
        poc.step("a passing step", True)
        check("CONTROL finish() refuses a run with no control", poc.finish(out, aborted_at=None, device="sim") is False)
    poc.STEPS.clear()

    print("== a run deletes every subscription it created (deep check 2026-10-29)")
    subs, reqs = getattr(poc, "SUBS", None), []
    real_req = poc.ho._req
    try:
        rn_of = lambda kw: ((kw.get("body") or {}).get("m2m:sub") or {}).get("rn")
        poc.ho._req = lambda m, url, origin, **kw: (reqs.append((m, url, origin)) or (409 if rn_of(kw) == "estimedS2" else 201), {})
        if isinstance(subs, list):
            subs.clear()
        poc.subscribe(poc.ho.EDGE_A, "estimedS1")
        poc.subscribe(poc.ho.EDGE_A, "estimedS2")          # 409: NOT created, so NOT recorded
        poc.rsu_subscribe("estimedS3")
        check("subscribe/rsu_subscribe record each subscription they created (201, not the 409), with its originator",
              isinstance(subs, list) and [(u.rsplit("/", 1)[-1], o) for u, o in subs] == [("estimedS1", poc.OWNER), ("estimedS3", poc.RSU_ORIGIN)],
              str(subs))
    finally:
        poc.ho._req = real_req
    cl = getattr(poc, "cleanup_subscriptions", None)
    if callable(cl) and isinstance(subs, list):
        dels, http_dels = [], []

        def fake_req(m, url, origin, **kw):
            dels.append((m, url.rsplit("/", 1)[-1], origin))
            if url.endswith("estimedS1"):
                raise OSError("connection refused")          # one failing DELETE must not stop the others
            return 200, {}
        poc.EXP12["sub"] = "/rni/v2/subscriptions/sub-7"     # our MEC 012 answers a RELATIVE href (seen 2026-10-29)
        out = cl(req=fake_req, http=lambda m, url, body=None: (http_dels.append((m, url)) or (204, {})))
        check("cleanup DELETEs every recorded oneM2M subscription with its own originator (newest first)",
              [(m, n, o) for m, n, o in dels] == [("DELETE", "estimedS3", poc.RSU_ORIGIN), ("DELETE", "estimedS1", poc.OWNER)],
              str(dels))
        check("... and the MEC 012 subscription by its _links.self.href, resolved against where it was created",
              http_dels == [("DELETE", "http://127.0.0.1:8402/rni/v2/subscriptions/sub-7")], str(http_dels))
        check("... a DELETE that raises is recorded, not fatal, and the list is cleared after",
              any("error" in str(v) for v in out.values()) and len(out) == 3 and subs == [], str(out))
        poc.EXP12.pop("sub", None)
    else:
        check("estimed_poc2.cleanup_subscriptions exists", False)
    src = (HERE / "estimed_poc2.py").read_text()
    fin = src[src.rfind("    finally:"):]
    check("the run's finally cleans up BEFORE it stops MEC 012 and the listener",
          0 <= fin.find("cleanup_subscriptions(") < fin.find("p.terminate()"), f"cleanup at {fin.find('cleanup_subscriptions(')}")

    print("== a service this run just started is waited for before it is asked (AB_11, 2026-10-29)")
    # AB_11: mec012_phone.py was started, only MEC 013 was waited for, and the PLMN query to :8402 got 'Connection
    # refused' at host load 9.3 -- a setup FAIL that had nothing to do with the phone or the S1 order.
    lis = getattr(poc, "listening", None)
    check("estimed_poc2 has listening(port, timeout_s)", callable(lis))
    if callable(lis):
        import socket
        import threading
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            free = probe.getsockname()[1]
        t0 = time.time()
        check("CONTROL a port nobody listens on is refused, within its bound", lis(free, 1.0) is False
              and time.time() - t0 < 3, f"{time.time() - t0:.1f} s")
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        late = srv.getsockname()[1]
        up = threading.Timer(0.8, srv.listen)           # the service comes up after the run first asks
        up.start()
        t0 = time.time()
        ok = lis(late, 5.0)
        dt = time.time() - t0
        up.join()                                       # never close the socket under the timer
        srv.close()
        check("a service that starts listening late is waited for, not refused (the AB_11 race)", ok and 0.6 < dt < 5,
              f"{ok} after {dt:.1f} s")
    src = (HERE / "estimed_poc2.py").read_text()
    i_wait, i_q = src.find("listening(8402"), src.find("/queries/rab_info")
    check("the first MEC 012 query (rab_info) comes after the wait for :8402", 0 < i_wait < i_q, f"wait at {i_wait}, query at {i_q}")

    print("== MEC 013 notification links: the spec's `subscription`, plus `self` where the ATS wants it (2026-10-29)")
    # GS MEC 013 v3.2.1 Table 6.4.5-1 and ETSI's sandbox (meep-loc-serv loc-serv.go:1425) link a periodic notification
    # under `subscription`; ETSI's ATS schema requires `self` there (and allows extra keys). Same split as timeStamp.
    import jsonschema
    import mec013sub_phone as m13s
    sent, real_post = [], m13s.ds.safe_post
    try:
        m13s.ds.safe_post = lambda url, body: sent.append(body) or True
        cb = {"callbackReference": {"notifyURL": "http://127.0.0.1:9/cb"}}
        m13s._post(cb, "s1", "users", {"notificationType": "UserLocationPeriodicNotification", "result": "SUCCESS"})
        m13s._post(cb, "s2", "users", {"notificationType": "UserLocationEventNotification",
                                        "userLocationEvent": "ENTERING_AREA_EVENT"})
    finally:
        m13s.ds.safe_post = real_post
    per, ev = (sent + [{}, {}])[:2]
    base = f"http://127.0.0.1:{m13s.PORT}/location/v3/subscriptions/users"
    check("a periodic notification links its subscription under `subscription` (Table 6.4.5-1)",
          (per.get("_links") or {}).get("subscription") == {"href": f"{base}/s1"}, str(per.get("_links")))
    check("... and under `self`, equal, as ETSI's ATS schema requires",
          (per.get("_links") or {}).get("self") == {"href": f"{base}/s1"}, str(per.get("_links")))
    ats = Path("/home/edgefollow/etsi-forge-ats-reference/MEC013/SRV/UELOCSUB/schemas/UserLocationPeriodicNotification.schema.json")
    schema = json.loads(ats.read_bytes().decode("cp1252"))        # ETSI saved this file in Windows-1252
    errs = [e.message for e in jsonschema.validators.validator_for(schema)(schema).iter_errors(per)]
    check("CONTROL the ATS's own schema still accepts the periodic notification", per and not errs, str(errs[:2]))
    check("CONTROL an event notification keeps `subscription` only", ev.get("_links") == {"subscription": {"href": f"{base}/s2"}},
          str(ev.get("_links")))

    print("== MEC 012 links are absolute URIs, as LinkType.href (format: uri) and ETSI's RNIS give them (2026-10-29)")
    from fastapi.testclient import TestClient
    import urllib.parse
    rn = TestClient(m12.cand.app, base_url="http://127.0.0.1:8402", raise_server_exceptions=False)
    msub = {"subscriptionType": "MeasRepUeSubscription", "callbackReference": "http://127.0.0.1:9/cb",
            "filterCriteriaAssocTri": {"trigger": [0]}}
    r = rn.post("/rni/v2/subscriptions", json=msub)
    href = ((r.json().get("_links") or {}).get("self") or {}).get("href") if r.status_code == 201 else None
    root = "http://127.0.0.1:8402/rni/v2/subscriptions"
    check("POST answers 201 with an absolute _links.self.href; Location (relative, as the ATS needs) resolves to it",
          r.status_code == 201 and str(href).startswith(root + "/")
          and urllib.parse.urljoin(str(r.request.url), r.headers.get("location") or "") == href,
          f"{r.status_code} {href} {r.headers.get('location')}")
    check("CONTROL Location stays the relative reference ETSI's ATS splits on '/' (RNIS 014_OK/015_OK broke on an absolute one)",
          (r.headers.get("location") or "").startswith("/rni/v2/subscriptions/"), str(r.headers.get("location")))
    lst = (rn.get("/rni/v2/subscriptions").json() or {}).get("_links") or {}
    check("the subscription list links absolutely too (self and every entry)",
          (lst.get("self") or {}).get("href") == root and href in [s.get("href") for s in lst.get("subscription") or []], str(lst)[:160])
    put = rn.put(urllib.parse.urlsplit(str(href)).path, json=msub) if href else None
    check("a PUT answers the same absolute self link", put is not None and put.status_code == 200 and str(href).startswith(root + "/")
          and put.json()["_links"]["self"]["href"] == href, put and f"{put.status_code} {put.text[:120]}")
    sid = str(href).rsplit("/", 1)[-1]
    got, real_post = [], ds.safe_post
    try:
        ds.safe_post = lambda url, body: got.append(body) or True
        m12._notify(m12.cand.SUBSCRIPTIONS.get(sid, {"_links": {"self": {}}, "callbackReference": ""}),
                    {"notificationType": "MeasRepUeNotification", "rsrp": 31, "ecgi": {"cellId": "1A2B3C4"}})
    finally:
        ds.safe_post = real_post
    note = (got + [{}])[0]
    check("its notifications name the subscription by that same absolute href", str(href).startswith(root + "/")
          and ((note.get("_links") or {}).get("subscription") or {}).get("href") == href, str(note.get("_links")))
    check("CONTROL ... which the PoC still accepts as its own report", poc.accept_mec012(
        "/mec012/t0k3n", note, {"token": "t0k3n", "sub": href, "cell": "1A2B3C4"}))
    check("... and still resolves for cleanup", urllib.parse.urljoin(poc.MEC12_SUBS, str(href)) == href)
    path = urllib.parse.urlsplit(str(href)).path
    check("CONTROL the absolute href addresses the subscription: GET 200, DELETE 204, then GET 404",
          [rn.get(path).status_code, rn.delete(path).status_code, rn.get(path).status_code] == [200, 204, 404])

    print("== B1 the vehicle is read from either MEC 013 user-list shape (2026-10-29)")
    # GS MEC 013 Table 7.4.3.1-2 answers a UserList ({"user": [...]}: the ATS's shape and ours); the spec's Annex B
    # example and ETSI's sandbox (meep-loc-serv loc-serv.go:2223) wrap it as {"userList": {...}}.
    uo = getattr(poc, "users_of", None)
    U = {"address": "acr:10.0.0.1", "zoneId": "zone01", "accessPointId": "poa1"}
    check("users_of reads the UserList shape (ours, the ATS's)", callable(uo) and uo({"resourceURL": "x", "user": [U]}) == [U])
    check("users_of reads the wrapped shape (ETSI's sandbox, the spec's example)",
          callable(uo) and uo({"userList": {"resourceURL": "x", "user": [U]}}) == [U])
    check("CONTROL users_of gives [] for no list, a non-object, a non-list user, and drops non-object entries",
          callable(uo) and uo({}) == [] and uo(["user"]) == [] and uo({"userList": {"user": "x"}}) == []
          and uo({"user": [U, "junk"]}) == [U])
    asked, real_get = [], poc.get_json
    try:
        poc.get_json = lambda url: asked.append(url) or {"userList": {"resourceURL": "x", "user": [U]}}
        got = poc.served_user(2) if callable(uo) else None
    finally:
        poc.get_json = real_get
    check("served_user finds the vehicle in ETSI's wrapped answer", got == U, f"{got} from {asked[:1]}")
    src = (HERE / "estimed_poc2.py").read_text()
    body_of = src[src.find("def users_of"):]
    body_of = body_of[:body_of.find("\ndef ", 1)]
    rest = src.replace(body_of, "")
    check("no other PoC code reads a user list directly (all through users_of)",
          'get("user")' not in rest and '["user"]' not in rest and "users_of(" in rest,
          f'{rest.count(chr(34) + "user" + chr(34))} direct "user" reads outside users_of')

    print("== B3 MEC endpoints, the vehicle's address and the callback are settings, not constants (2026-10-29)")
    cf = getattr(poc, "configure", None)
    check("defaults: this host's phone-backed services, the phone's address, the loopback listener",
          getattr(poc, "MEC013_BASE", None) == "http://127.0.0.1:8401/location/v3"
          and getattr(poc, "MEC012_BASE", None) == "http://127.0.0.1:8402/rni/v2"
          and poc.MEC12_SUBS == "http://127.0.0.1:8402/rni/v2/subscriptions"
          and getattr(poc, "CALLBACK_BASE", None) == f"http://127.0.0.1:{poc.LISTEN}"
          and getattr(poc, "UE_ADDRESS", None) == ds.PHONE_ADDRESS)
    if callable(cf):
        try:
            cf(mec013="https://sbx.example.org/sbx1/mep1/location/v3/", mec012="https://sbx.example.org/sbx1/mep1/rni/v2",
               ue="acr:10.100.0.1", callback="https://cb.example.org")
            check("a configured platform: the users query, MEC 012 subscriptions and cleanup all follow it",
                  poc.users_url() == "https://sbx.example.org/sbx1/mep1/location/v3/queries/users?address=acr%3A10.100.0.1"
                  and poc.MEC12_SUBS == "https://sbx.example.org/sbx1/mep1/rni/v2/subscriptions"
                  and urllib.parse.urljoin(poc.MEC12_SUBS, "/sbx1/mep1/rni/v2/subscriptions/7")
                  == "https://sbx.example.org/sbx1/mep1/rni/v2/subscriptions/7", poc.users_url())
            check("... the callback MEC 012 is given is that origin plus the secret path the listener checks",
                  poc.callback_url("t0k3n") == "https://cb.example.org/mec012/t0k3n", poc.callback_url("t0k3n"))
            check("... and MEC 012 names the vehicle by its bare address (acr: dropped, as ETSI's fixtures pair them)",
                  poc.mec012_ue() == "10.100.0.1", poc.mec012_ue())
            bad_cb = []
            for cb in ("https://cb.example.org/prefix", "ftp://cb.example.org", "cb.example.org", "https://cb.example.org/?q=1"):
                try:
                    cf(callback=cb)
                    bad_cb.append(cb)
                except ValueError:
                    pass
            check("CONTROL a callback with a path, query or non-http scheme is refused (the listener matches the path)",
                  bad_cb == [], f"accepted {bad_cb}")
        finally:
            cf()
        check("CONTROL configure() with nothing restores every default",
              poc.MEC013_BASE == "http://127.0.0.1:8401/location/v3" and poc.CALLBACK_BASE == f"http://127.0.0.1:{poc.LISTEN}"
              and poc.MEC12_SUBS == "http://127.0.0.1:8402/rni/v2/subscriptions" and poc.UE_ADDRESS == ds.PHONE_ADDRESS)
    else:
        check("estimed_poc2.configure exists", False)
    lit = [ln.strip()[:70] for ln in src.splitlines() if ("127.0.0.1:8401" in ln or "127.0.0.1:8402" in ln)
           and "LOCAL_MEC01" not in ln]
    check("no MEC endpoint is hard-coded outside the local defaults", lit == [], str(lit[:3]))
    check("the MEC 012 subscription's callback comes from callback_url, not a loopback literal",
          "callback_url(token)" in src and '"callbackReference": f"http://127.0.0.1' not in src)

    print("== B2 the vehicle's cell comes from MEC 012 rab_info, not from MEC 013's accessPointId (2026-10-29)")
    # ETSI's sandbox serves a point-of-attachment NAME as accessPointId (meep-loc-serv sbi getNetworkLocation) and
    # answers plmn_info only by app_ins_id (rnis.go validQueryParams); rab_info?ue_ipv4_address= names the UE's cell.
    ve = getattr(poc, "vehicle_ecgi", None)
    e1 = {"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "0000011"}
    e2 = {"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "0000022"}
    rab = {"appInstanceId": "a", "requestId": "r", "cellUserInfo": [
        {"ecgi": e1, "ueInfo": [{"associateId": [{"type": 1, "value": "10.100.0.2"}], "erabInfo": []}]},
        {"ecgi": e2, "ueInfo": [{"associateId": [{"type": 1, "value": "10.100.0.1"}], "erabInfo": []}]}]}
    check("vehicle_ecgi picks the cell whose ueInfo lists the vehicle (here the second of two)",
          callable(ve) and ve(rab, "10.100.0.1") == e2, str(callable(ve) and ve(rab, "10.100.0.1")))
    check("CONTROL vehicle_ecgi: a UE no cell lists, a non-object, a cell without PLMN -> None",
          callable(ve) and ve(rab, "10.100.0.9") is None and ve("rab", "10.100.0.1") is None
          and ve({"cellUserInfo": [{"ecgi": {"cellId": "0000022"}, "ueInfo": rab["cellUserInfo"][1]["ueInfo"]}]}, "10.100.0.1") is None)
    from fastapi.testclient import TestClient as _TC
    ue_bare = ds.PHONE_ADDRESS.removeprefix("acr:")
    snap0 = m12.LIVE["snap"]
    try:
        sim12 = sim_phone.SimPhone("http://127.0.0.1:1/none", origin="Csim", rn="phone", ci=0x1A2B3C4, tac=4242)
        m12.LIVE["snap"] = {"radio": sim12.records()["radio"]}
        c12 = _TC(m12.cand.app, base_url="http://127.0.0.1:8402", raise_server_exceptions=False)
        r = c12.get("/rni/v2/queries/rab_info", params={"ue_ipv4_address": ue_bare})
        mine = ve(r.json(), ue_bare) if callable(ve) and r.status_code == 200 else None
        check("our phone MEC 012 answers rab_info for the phone's address with its serving cell (PLMN + ECI)",
              mine == {"plmn": {"mcc": "001", "mnc": "01"}, "cellId": "1A2B3C4"}, f"{r.status_code} {mine}")
        r2 = c12.get("/rni/v2/queries/rab_info", params={"ue_ipv4_address": "10.9.9.9"})
        check("CONTROL another address does not get the phone's cell (nor is the phone named in the answer)",
              not (r2.status_code == 200 and ("1A2B3C4" in r2.text or ue_bare in r2.text)), f"{r2.status_code} {r2.text[:90]}")
    finally:
        m12.LIVE["snap"] = snap0
    check("the MeasRepUe filter is the ecgi from rab_info; no plmn_info query, no accessPointId as a cell",
          '"filterCriteriaAssocTri": {"ecgi": [ecgi]}' in src and "/queries/plmn_info" not in src
          and 'cell=u["accessPointId"]' not in src)

    print("== the city reads the vehicle's signal on edge B, never its positions or Wi-Fi (V04, 2026-10-29)")
    # The data-sources rule: positions never reach the city. The central IN-AE needs radio/la through the IN
    # (the retargeting step); one policy on all five containers also let it read loc and wlan.
    acr, city = getattr(poc, "edge_b_acr", None), f"/{poc.IN_CSI}/{poc.IN_ORIGIN}"
    grants = lambda rules: {o for r in rules for o in r["acor"]}  # noqa: E731
    check("the policy the city's container gets names the IN-AE (as the IN forwards it); the other one does not",
          callable(acr) and city in grants(acr(True)) and city not in grants(acr(False)))
    check("only radio is a city container", getattr(poc, "CITY_READS", None) == ("radio",), str(getattr(poc, "CITY_READS", None)))
    check("CONTROL the device's reader and owner keep their access on every container",
          callable(acr) and {poc.READER, poc.OWNER} <= grants(acr(False)) and {poc.READER, poc.OWNER} <= grants(acr(True)))
    src = (HERE / "estimed_poc2.py").read_text()
    check("on edge B each container gets the city policy only if it is in CITY_READS, and the AE never",
          "[ris[c in CITY_READS]]" in src and '{"m2m:ae": {"acpi": [ris[False]]}}' in src and "phoneCityAcp" in src)
    check("the run proves it: the IN-AE reading loc and wlan through the IN must be refused (403)",
          'for c in ("loc", "wlan"):' in src and "positions never reach the city" in src and "st_c == 403" in src)

    print("== the PoC rebuilds the vehicle on edge B only under a free name or its own AE (V01/W03, 2026-10-29)")
    own = getattr(poc, "ae_ours_or_absent", None)
    real_req = poc.ho._req
    answers = {}
    try:
        poc.ho._req = lambda m, url, origin, **kw: answers[url]
        verdicts = []
        for status, aei in ((404, None), (200, poc.OWNER), (200, "Cimpostor"), (403, None)):
            answers["http://b/cse/phone"] = (status, {"m2m:ae": {"aei": aei}} if status == 200 else {})
            verdicts.append(own("http://b/cse/phone", poc.OWNER)[0] if callable(own) else None)
    finally:
        poc.ho._req = real_req
    check("free (404) and our own AE are usable; another originator's AE and an unreadable one are not",
          verdicts == [True, True, False, False], str(verdicts))
    src = (HERE / "estimed_poc2.py").read_text()
    rebuild = src[src.find("src = {c: cins(ho.EDGE_A, c) for c in CNTS}"):src.find('require("AE + 5 containers rebuilt on B')]
    check("the rebuild checks the name before deleting or creating, and accepts only a 201 for the AE",
          0 < rebuild.find("ae_ours_or_absent(") < rebuild.find("ho.delete_ae(ho.EDGE_B") and "ok = st == 201" in rebuild,
          rebuild[:80])

    print("== the simulated phone reconnects only to its OWN AE (V02/W04, 2026-10-29)")
    # A refused create (409 name taken, or ACME's 403 'already registered') is a reconnect only when the AE under
    # that name carries the phone's own AE-ID; otherwise its containers, <pch> and command subscription would be
    # written into somebody else's AE, and every reading after it.

    class _Alive:
        def is_alive(self):
            return True

    def ensure(post_status, get_status, aei=None):
        calls = []
        ph = sim_phone.SimPhone("http://x/cse", origin="Csim", rn="phone")
        ph._poller = _Alive()                          # never start the poll thread here

        def fake(method, url, ty=0, body=None, timeout=5):
            calls.append((method, url))
            if method == "POST" and url == "http://x/cse":
                return post_status, {}
            if method == "GET" and url == "http://x/cse/phone":
                return get_status, ({"m2m:ae": {"rn": "phone", "aei": aei}} if get_status == 200 else {})
            return 201, {}
        ph._http = fake
        ok = ph._ensure_ae()
        writes = [(m, u) for m, u in calls if (m, u) not in (("POST", "http://x/cse"), ("GET", "http://x/cse/phone"))]
        return ok, writes, getattr(ph, "last_error", None)

    ok, writes, _ = ensure(409, 200, "Cother")
    check("409 and the name is held by another AE-ID: refused, nothing written into that AE", ok is False and writes == [],
          f"{ok} {writes[:3]}")
    ok, writes, _ = ensure(403, 200, "Cother")
    check("403 and the name is held by another AE-ID: refused, nothing written", ok is False and writes == [], f"{ok} {writes[:3]}")
    ok, writes, why = ensure(403, 404)
    check("403 and no AE under the name: refused, and the reason names both answers",
          ok is False and writes == [] and "403" in str(why) and "404" in str(why), f"{ok} {why!r}")
    ok, writes, _ = ensure(403, 200, "Csim")
    check("CONTROL the phone's own AE (403 = already registered, aei is ours) is reconnected: its 7 containers created",
          ok is True and sum(1 for m, u in writes if m == "POST" and u == "http://x/cse/phone") >= 7, f"{ok} {len(writes)}")
    ok, writes, _ = ensure(201, 404)
    check("CONTROL a fresh registration (201) proceeds", ok is True and len(writes) >= 7, f"{ok} {len(writes)}")

    print("== the phone's sequence numbers across both edges, commands, notifications (2026-11-19)")
    # Expected values are written by hand. A sample is (snr, t_ms): the phone's own counter and the tick's time.
    def fn(name):
        f = getattr(poc, name, None)
        return f if callable(f) else (lambda *a, **k: None)
    dgt_ms, samples_of, seq_account = fn("dgt_ms"), fn("samples_of"), fn("seq_account")
    records_per_sample, ack_of, notified = fn("records_per_sample"), fn("ack_of"), fn("notified")
    # 2026-11-19T00:00:00Z is 1795046400 (2026-01-01 is 1767225600, plus 322 days); 04:00:05 is 14405 s later
    check("dgt 20261119T040005,123000 is 1795060805123 ms; a text that is no dgt is None",
          dgt_ms("20261119T040005,123000") == 1795060805123 and dgt_ms("2026-11-19") is None and dgt_ms(None) is None,
          str(dgt_ms("20261119T040005,123000")))
    body = {"m2m:ts": {"m2m:tsi": [{"snr": 8, "dgt": "20261119T040005,123000", "con": "{}"},
                                   {"snr": 7, "dgt": "20261119T040000,123000", "con": "{}"},
                                   {"dgt": "20261119T040010,123000"}, {"snr": True, "dgt": "20261119T040015,123000"},
                                   {"snr": 9, "dgt": "soon"}]}}
    check("samples are read from a <timeSeries> oldest first; an instance without a number or a time is counted, not used",
          samples_of(body) == ([(7, 1795060800123), (8, 1795060805123)], 3) and samples_of({}) == ([], 0)
          and samples_of(None) == ([], 0), str(samples_of(body)))
    acc = seq_account([(3, 1000), (4, 6000), (5, 11000)], [(6, 25000), (7, 30000)], 5) or {}
    check("counter carried on, 3 4 5 then 6 7: nothing lost, nothing twice, 14 s = 2.8 periods without a sample",
          (acc.get("countable"), acc.get("counter"), acc.get("lost"), acc.get("duplicated"), acc.get("gap_s"),
           acc.get("gap_periods")) == (True, "continued", [], [], 14.0, 2.8), str(acc))
    check("the count names what each edge held: source 3 samples 3..5, target 2 samples 6..7",
          acc.get("source") == {"n": 3, "first": 3, "last": 5} and acc.get("target") == {"n": 2, "first": 6, "last": 7},
          f"{acc.get('source')} {acc.get('target')}")
    acc = seq_account([(40, 1000), (41, 6000)], [(0, 20000), (1, 25000)], 5) or {}
    check("counter started again at the target, 40 41 then 0 1: nothing lost",
          (acc.get("countable"), acc.get("counter"), acc.get("lost"), acc.get("duplicated")) == (True, "restarted", [], []), str(acc))
    acc = seq_account([(40, 1000), (41, 6000)], [(2, 20000), (3, 25000)], 5) or {}
    check("counter started again and the target's first number is 2: numbers 0 and 1 are lost at the target",
          acc.get("lost") == [{"where": "target, at the start", "snr": 0}, {"where": "target, at the start", "snr": 1}],
          str(acc.get("lost")))
    # The app's counter and, since 2026-11-19, the simulated phone's start again at 0 after a stop: the target then
    # holds numbers the source also holds, at other times. The two rows above have no number on both edges.
    acc = seq_account([(0, 1000), (1, 6000), (2, 11000)], [(0, 30000), (1, 35000), (2, 40000)], 5) or {}
    check("counter started again with numbers the source also holds, 0 1 2 then 0 1 2 at other times: nothing lost, "
          "nothing twice, 19 s = 3.8 periods without a sample",
          (acc.get("countable"), acc.get("counter"), acc.get("lost"), acc.get("duplicated"), acc.get("restarts"),
           acc.get("gap_s"), acc.get("gap_periods")) == (True, "restarted", [], [], [], 19.0, 3.8), str(acc))
    acc = seq_account([(0, 1000), (1, 6000), (2, 11000), (3, 16000), (4, 21000), (5, 26000)],
                      [(2, 60000), (3, 65000), (5, 75000)], 5) or {}
    check("counter started again, source 0..5, target 2 3 5: 0 and 1 are lost at the start of the target and 4 inside "
          "it, although the source holds those numbers",
          acc.get("lost") == [{"where": "target, at the start", "snr": 0}, {"where": "target, at the start", "snr": 1},
                              {"where": "target", "snr": 4}]
          and (acc.get("countable"), acc.get("counter"), acc.get("duplicated")) == (True, "restarted", []), str(acc))
    acc = seq_account([(0, 1000), (1, 6000), (2, 11000)], [(2, 30000), (3, 35000)], 5) or {}
    check("the target's first number is the source's last at another time (0 1 2 then 2 3): the counter started again, "
          "0 and 1 are lost at the target",
          acc.get("lost") == [{"where": "target, at the start", "snr": 0}, {"where": "target, at the start", "snr": 1}]
          and (acc.get("countable"), acc.get("counter"), acc.get("duplicated")) == (True, "restarted", []), str(acc))
    acc = seq_account([(3, 1000), (4, 6000), (6, 16000), (7, 21000)], [(8, 40000)], 5) or {}
    check("a hole inside the source's run (3 4 6 7): number 5 is lost at the source",
          acc.get("lost") == [{"where": "source", "snr": 5}] and acc.get("counter") == "continued", str(acc.get("lost")))
    acc = seq_account([(3, 1000), (4, 6000)], [(7, 30000), (8, 35000), (10, 45000)], 5) or {}
    check("counter carried on with numbers missing: 5 and 6 between the edges, 9 at the target",
          acc.get("lost") == [{"where": "between the edges", "snr": 5}, {"where": "between the edges", "snr": 6},
                              {"where": "target", "snr": 9}], str(acc.get("lost")))
    acc = seq_account([(3, 1000), (4, 6000)], [(4, 6000), (5, 11000)], 5) or {}
    check("one sample on both edges (same time): it is counted as duplicated, and not as a counter that started again",
          acc.get("duplicated") == [{"where": "both edges", "snr": 4}] and acc.get("lost") == []
          and acc.get("counter") == "continued", str(acc))
    acc = seq_account([(3, 1000), (3, 1000), (4, 6000)], [(5, 11000)], 5) or {}
    check("one sample twice on one edge: counted as duplicated at that edge",
          acc.get("duplicated") == [{"where": "source", "snr": 3}] and acc.get("lost") == [], str(acc))
    acc = seq_account([(3, 1000), (4, 6000)], [(0, 20000), (1, 25000), (0, 40000), (1, 45000)], 5) or {}
    check("the counter started again INSIDE one edge: not countable, and the place is named",
          acc.get("countable") is False and acc.get("restarts") == [{"where": "target", "after_snr": 1}], str(acc))
    for name, a_s, b_s in (("no sample at the target", [(3, 1000)], []), ("no sample at the source", [], [(0, 1000)])):
        acc = seq_account(a_s, b_s, 5) or {}
        check(f"{name}: not countable, never a clean count", acc.get("countable") is False, str(acc))
    recs = {"imu": [1000, 6000], "env": [1000, 6000], "loc": [1000, 6000, 6000], "radio": [1000, 6000], "wlan": [1000]}
    check("records per sample: every sample needs exactly one record in each of the five containers; 0 and 2 are named",
          records_per_sample([(3, 1000), (4, 6000)], recs) == [{"snr": 4, "cnt": "loc", "records": 2},
                                                                {"snr": 4, "cnt": "wlan", "records": 0}],
          str(records_per_sample([(3, 1000), (4, 6000)], recs)))
    check("records per sample: a record of an unnumbered time (copied history) is not counted against a sample",
          records_per_sample([(4, 6000)], {c: [500, 6000] for c in ("imu", "env", "loc", "radio", "wlan")}) == [],
          str(records_per_sample([(4, 6000)], {c: [500, 6000] for c in ("imu", "env", "loc", "radio", "wlan")})))
    check("records per sample: a container that is missing altogether fails every sample",
          records_per_sample([(4, 6000)], {"imu": [6000]}) == [{"snr": 4, "cnt": c, "records": 0}
                                                               for c in ("env", "loc", "radio", "wlan")], "")
    acks = [{"id": "a1", "cmd": "ping", "ok": True}, {"id": "b2", "cmd": "period", "ok": False}, "x", {"cmd": "ping"}]
    check("an acknowledgement is matched by its id alone; another id, a missing id or None finds nothing",
          ack_of(acks, "b2") == acks[1] and ack_of(acks, "zz") is None and ack_of(acks, None) is None
          and ack_of([], "a1") is None, str(ack_of(acks, "b2")))
    n = notified([1000, 6000, 11000], [1000, 6000, 6000]) or {}
    check("notifications against records: the record of t 11000 was never notified, the one of t 6000 twice",
          n == {"records": 3, "notifications": 3, "lost": [11000], "duplicated": [6000], "unknown": []}, str(n))
    n = notified([1000, 6000], [1000, 6000, 500]) or {}
    check("a notification for a record that is not in the list is named (unknown), and the clean case is clean",
          n.get("unknown") == [500] and notified([1000, 6000], [6000, 1000]) ==
          {"records": 2, "notifications": 2, "lost": [], "duplicated": [], "unknown": []}, str(n))
    pa = getattr(poc, "parse", None)
    try:
        per = (pa(["--device", "sim"]).period, pa(["--device", "sim", "--period", "1"]).period)
    except (AttributeError, SystemExit):
        per = None
    check("--period: 5 s unless given", per == (5, 1), str(per))
    refused = []
    for bad_p in ("0", "61", "1.5"):
        try:
            import contextlib
            import io
            with contextlib.redirect_stderr(io.StringIO()):
                pa(["--device", "sim", "--period", bad_p])
            refused.append(False)
        except SystemExit:
            refused.append(True)
    check("--period outside 1..60 s or not a whole number is refused (the app's own range)", refused == [True] * 3 and per == (5, 1),
          str(refused))

    # A leftover phone-backed MEC 013 on :8401 (from a killed run) once answered instead of the run's own instance,
    # which cannot bind; it never followed the move, and "MEC 013 now sourced from edge B" failed (2026-11-20).
    stale = getattr(poc, "stale_service_ports", None)
    check("a port of our phone-backed MEC 013/012 already held is found before the run",
          stale is not None and stale(lambda port: port == 8401) == [8401], "stale_service_ports missing" if stale is None else "")
    check("CONTROL with both ports free nothing is reported", stale is not None and stale(lambda port: False) == [])
    held_was = getattr(poc, "_port_held", None)
    rc, text, touched = None, "", []
    if stale is not None and held_was is not None:
        import contextlib
        import io

        class Touched(Exception):
            pass

        def trip(what):
            def f(*a, **k):
                touched.append(what)
                raise Touched(what)
            return f
        saved = (poc._port_held, poc.urllib.request.urlopen, poc.sim_setup, poc.ho._req)
        poc._port_held = lambda port: True
        poc.urllib.request.urlopen, poc.sim_setup, poc.ho._req = trip("urlopen"), trip("sim_setup"), trip("lab request")
        out_dir = tempfile.mkdtemp()
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                try:
                    rc = poc.main(["--device", "sim", "--results", str(Path(out_dir) / "never.json")])
                except Touched:
                    rc = "went on"
            text = out.getvalue()
        finally:
            poc._port_held, poc.urllib.request.urlopen, poc.sim_setup, poc.ho._req = saved
            import shutil
            shutil.rmtree(out_dir, ignore_errors=True)
    check("the run stops (exit 2) on the held ports themselves, before MEC 040, the lab or any device is touched",
          rc == 2 and "PRECONDITION: port(s) [8401, 8402] already held" in text and touched == [], f"rc {rc}, touched {touched}")
    if stale is not None:
        saved13 = poc.MEC013_BASE
        poc.MEC013_BASE = "http://192.0.2.1:9/location/v3"           # another platform's MEC 013: not ours to start
        try:
            check("a port is checked only for a service this run starts itself",
                  stale(lambda port: True) == [8402], str(stale(lambda port: True)))
        finally:
            poc.MEC013_BASE = saved13
    if held_was is not None:
        import socket as _s
        with _s.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen(1)
            port = srv.getsockname()[1]
            check("_port_held sees a listener on 127.0.0.1", held_was(port) is True)
        check("CONTROL _port_held reports a closed port as free", held_was(port) is False)

    bad = [n for n, ok, _ in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
