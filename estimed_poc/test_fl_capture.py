#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline checks for fl_capture.py -- no CSE, no phone, no network, no key made.

Expected counts are worked out by hand in the comments. The signature rows use two records a phone made on
2026-10-15 (an attestation and a signature by the same kept key); when those files are not on this disk the rows
are NOT-RUN and the script says so and fails: a skip is not a pass.

    python3 estimed_poc/test_fl_capture.py
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fl_capture as fc  # noqa: E402
import fl_core as fl  # noqa: E402

RESULTS, CONTROLS, NOT_RUN = [], [], []
SEAL = Path("/home/edgefollow/estimed-run/two_phone/20261015T102247Z/seal")


def check(name, fn):
    try:
        ok, d = bool(fn()), ""
    except Exception as e:  # noqa: BLE001
        ok, d = False, f"{type(e).__name__}: {e}"
    RESULTS.append((name, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {d}" if d else ""))


def control(name, bad):
    try:
        went, d = bool(bad()), ""
    except Exception as e:  # noqa: BLE001  a crash proves nothing
        went, d = True, f"did not run: {type(e).__name__}: {e}"
    CONTROLS.append((name, went))
    print(f"  {'PASS' if went else 'FAIL'}  CONTROL (must FAIL) {name}" + (f"  -- {d}" if d else ""))


def main() -> int:
    print("== slots")
    check("slot number: 0 -> 0, 2499 -> 0, 2500 -> 1, 7499 -> 1, 7500 -> 2",
          lambda: [fc.slot_of(t) for t in (0, 2499, 2500, 7499, 7500)] == [0, 0, 1, 1, 2])
    check("the capture's slot rule and fl_core's give the same slot for 20,000 times",
          lambda: all(fc.slot_of(t) * 5000 == fl.pairs([{"t": t, "temp_dc": 0, "pct": 0}, {"t": t + 5000, "temp_dc": 0, "pct": 0}],
                                                       align="slot")["samples"][0]["t"] for t in range(0, 60000, 3)))

    print("== expected counts from a table of filled slots")
    full = set(range(27))
    # by hand: phone-B misses slot 13. Round 1 (slots 0..8): both full, samples start in 0..7 -> 8 common windows,
    # 16 samples, nothing dropped. Round 2 (0..17): phone-A 17; phone-B loses the samples starting in 12 and 13 -> 15.
    # Round 3 (0..26): phone-A 26.
    check("phone-B without slot 13: round 1 16 (8 + 8), round 2 17 and 15, round 3 26",
          lambda: fc.expect({"flSrc1": full, "flSrc2": full - {13}}) == {
              "r1": {"n": 16, "per_source": {"flSrc1": 8, "flSrc2": 8}, "dropped_gap": 0, "dropped_unaligned": 0},
              "weights": {"1": {"P-TFC-AGG": 16}, "2": {"P-TFC-S1": 17, "P-TFC-S2": 15}, "3": {"P-TFC-S1": 26}}})
    # by hand (the simulated run's layout): phone-B misses slot 4. phone-A starts 0..7 (8); phone-B 0,1,2,5,6,7 (6);
    # common 6 -> 12 samples; 8 + 6 - 12 = 2 unused; one break in phone-B's rows. Round 2: 17 and 15. Round 3: 26.
    check("phone-B without slot 4: round 1 12 (6 + 6), 2 unused, 1 gap",
          lambda: fc.expect({"flSrc1": full, "flSrc2": full - {4}})["r1"]
          == {"n": 12, "per_source": {"flSrc1": 6, "flSrc2": 6}, "dropped_gap": 1, "dropped_unaligned": 2})
    check("the gate: 24 of 27 slots is enough, 23 is not",
          lambda: fc.gate({"flSrc1": full, "flSrc2": full - {20, 22, 24}}, fc.expect({"flSrc1": full, "flSrc2": full - {20, 22, 24}}), {}) == []
          and len(fc.gate({"flSrc1": full, "flSrc2": full - {20, 22, 24, 26}},
                          fc.expect({"flSrc1": full, "flSrc2": full - {20, 22, 24, 26}}), {})) == 1)
    check("the gate: 15.0 and 42.0 C are inside the range",
          lambda: fc.gate({"flSrc1": full, "flSrc2": full}, fc.expect({"flSrc1": full, "flSrc2": full}), {"flSrc1": [150, 420]}) == [])
    control("a capture with one record at 42.1 C passed the gate",
            lambda: not fc.gate({"flSrc1": full, "flSrc2": full}, fc.expect({"flSrc1": full, "flSrc2": full}), {"flSrc1": [300, 421]}))
    control("a capture with one record at 14.9 C passed the gate",
            lambda: not fc.gate({"flSrc1": full, "flSrc2": full}, fc.expect({"flSrc1": full, "flSrc2": full}), {"flSrc2": [149, 300]}))
    check("a hot phone (43 C and more) makes the built capture not usable, with the reason",
          lambda: (lambda c: c["usable"] is False and "battery temperature" in c["why_not"][0])(
              fc.build(fc.rehearsal_cins(temp_dc=(310, 430)), "rehearsal", "x")))
    # by hand: phone-A misses slot 7, so its round-1 samples start in 0..5. phone-B misses 1, 3 and 5, so its round-1
    # samples start in 6 and 7 only. No window is common: round 1 would have 0 samples, with 26 and 24 slots filled.
    control("a capture whose first round would have no sample passed the gate",
            lambda: not fc.gate({"flSrc1": full - {7}, "flSrc2": full - {1, 3, 5}},
                                fc.expect({"flSrc1": full - {7}, "flSrc2": full - {1, 3, 5}}), {}))

    print("== building a capture (the rehearsal records: probe-app shape, times off the grid)")
    cins = fc.rehearsal_cins()
    cap = fc.build(cins, "rehearsal", "2026-11-19T00:00:00Z")
    check("27 slots of phone-A, 26 of phone-B (slot 13 missing), 2 records of each outside the window",
          lambda: [(len(v["records"]), v["outside_the_window"], v["dropped_same_slot"], len(v["refused"]))
                   for v in cap["sources"].values()] == [(27, 2, 0, 0), (26, 2, 0, 0)])
    check("its expected counts are the hand-counted ones and it is usable",
          lambda: cap["expect"]["weights"] == {"1": {"P-TFC-AGG": 16}, "2": {"P-TFC-S1": 17, "P-TFC-S2": 15}, "3": {"P-TFC-S1": 26}}
          and cap["usable"] is True and cap["why_not"] == [])
    check("a kept record is the posted text, byte for byte",
          lambda: cap["sources"]["flSrc1"]["records"][0]["con"] == cins["flSrc1"][0]["con"])

    def by_core(upto, srcs, mode):          # the other method: fl_core on the kept records themselves
        per = {s: [fl.parse_env(r["con"], device=True) for r in cap["sources"][s]["records"] if r["slot"] < upto] for s in srcs}
        return len(fl.assemble(per, mode, align="slot")["samples"])
    check("two methods agree: fl_core on the records gives the capture's counts (16; 17, 15; 26)",
          lambda: [by_core(9, ("flSrc1", "flSrc2"), "aggregatedSources"), by_core(18, ("flSrc1",), "independentSources"),
                   by_core(18, ("flSrc2",), "independentSources"), by_core(27, ("flSrc1",), "independentSources")] == [16, 17, 15, 26])
    check("a capture agrees with itself", lambda: fc.check(cap) == [])
    check("the phone-B records start in the same slot although its clock runs 1.2 s later",
          lambda: cap["sources"]["flSrc2"]["records"][0]["slot"] == 0)
    two = copy.deepcopy(cins)
    two["flSrc1"].insert(1, {"con": json.dumps({**json.loads(cins["flSrc1"][0]["con"]), "t": json.loads(cins["flSrc1"][0]["con"])["t"] + 900}),
                             "ct": cins["flSrc1"][0]["ct"]})
    check("a second record in a slot is dropped and counted; the first is kept",
          lambda: (lambda c: (c["sources"]["flSrc1"]["dropped_same_slot"], c["sources"]["flSrc1"]["records"][0]["con"]))(
              fc.build(two, "rehearsal", "x")) == (1, cins["flSrc1"][0]["con"]))
    simmed = copy.deepcopy(cins)
    simmed["flSrc1"][3]["con"] = json.dumps({**json.loads(simmed["flSrc1"][3]["con"]), "sim": True})
    check("a record with a sim mark among a phone's records is refused with its reason, not kept",
          lambda: (lambda c: (len(c["sources"]["flSrc1"]["refused"]), len(c["sources"]["flSrc1"]["records"])))(
              fc.build(simmed, "device", "x")) == (1, 26))
    located = copy.deepcopy(cins)
    located["flSrc2"][0]["con"] = json.dumps({**json.loads(located["flSrc2"][0]["con"]), "lat": 1.0})   # the first one
    control("a record carrying a position was kept in a capture",
            lambda: any("lat" in r["con"] for r in fc.build(located, "device", "x")["sources"]["flSrc2"]["records"]))

    print("== an altered capture is noticed")
    def altered(fn):
        c = copy.deepcopy(cap)
        fn(c)
        return fc.check(c)
    control("one record's text changed and the capture still checked",
            lambda: not altered(lambda c: c["sources"]["flSrc1"]["records"][5].update(
                con=c["sources"]["flSrc1"]["records"][5]["con"].replace('"battery_pct": 80', '"battery_pct": 20'))))
    control("a record changed together with its SHA-256 and the capture still checked",
            lambda: not altered(lambda c: (lambda r: r.update(con=r["con"].replace('"battery_pct": 80', '"battery_pct": 20'),
                                                              con_sha256=fl.text_digest(r["con"].replace('"battery_pct": 80', '"battery_pct": 20'))))(
                c["sources"]["flSrc1"]["records"][5])))
    control("a record filed under another slot and the capture still checked",
            lambda: not altered(lambda c: c["sources"]["flSrc2"]["records"][20].update(slot=26)))
    # phone-B has no slot 13. Its slot-14 record refiled as 13, with the digest and the counts made to fit:
    # only the record's own time gives it away.
    def refile(c):
        recs = c["sources"]["flSrc2"]["records"]
        next(r for r in recs if r["slot"] == 14).update(slot=13)
        c["sources"]["flSrc2"]["digest"] = fc.source_digest("phone-B", c["slot0"], recs)
        c["expect"] = fc.expect({"flSrc1": set(range(27)), "flSrc2": {r["slot"] for r in recs}})
    control("a record refiled into an empty slot, digest and counts made to fit, and the capture still checked",
            lambda: not altered(refile))
    control("the expected counts raised and the capture still checked",
            lambda: not altered(lambda c: c["expect"]["weights"]["2"].update({"P-TFC-S2": 17})))
    control("a capture marked usable against its own slots still checked",
            lambda: not altered(lambda c: (c["sources"]["flSrc2"].update(records=c["sources"]["flSrc2"]["records"][:10]),
                                           c["sources"]["flSrc2"].update(digest=fc.source_digest("phone-B", c["slot0"], c["sources"]["flSrc2"]["records"])),
                                           c.update(expect=fc.expect({"flSrc1": set(range(27)), "flSrc2": set(range(10))})))))
    control("the two phones' labels swapped and the capture still checked",
            lambda: not altered(lambda c: (c["sources"]["flSrc1"].update(label="phone-B"), c["sources"]["flSrc2"].update(label="phone-A"))))

    print("== countersignature (records of 2026-10-15: one kept key per phone signed a challenge)")
    files = [SEAL / p / f for p in ("P1", "P2") for f in ("attest.json", "sign.json")]
    if not all(f.exists() for f in files):
        NOT_RUN.append("countersignature rows: the records of 2026-10-15 are not on this disk")
        print(f"  NOT-RUN  {NOT_RUN[-1]}")
    else:
        a1, s1, a2, s2 = (json.loads(f.read_text()) for f in files)
        src = lambda s: {"digest": s["challenge"], "countersignature": {"ok": True, "sig": s["sig"], "challenge": s["challenge"]}}  # noqa: E731
        check("a phone's signature verifies with the leaf key of its own attestation record (both phones)",
              lambda: fc.verify_sig(src(s1), a1)[0] and fc.verify_sig(src(s2), a2)[0])
        control("phone 1's signature verified with phone 2's key", lambda: fc.verify_sig(src(s1), a2)[0])
        control("a signature verified over another digest",
                lambda: fc.verify_sig({**src(s1), "digest": "00" * 32, "countersignature": {**src(s1)["countersignature"], "challenge": "00" * 32}}, a1)[0])
        control("a signature over a challenge that is not the source's digest verified",
                lambda: fc.verify_sig({**src(s1), "digest": "11" * 32}, a1)[0])
        control("a capture without a countersignature verified", lambda: fc.verify_sig({"digest": s1["challenge"]}, a1)[0])

    bad = [n for n, ok in RESULTS if not ok]
    alive = [n for n, went in CONTROLS if went]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed; controls {len(CONTROLS)}, all failed as they must: {not alive}; "
          f"NOT-RUN {len(NOT_RUN)}")
    return 1 if bad or alive or NOT_RUN else 0


if __name__ == "__main__":
    sys.exit(main())
