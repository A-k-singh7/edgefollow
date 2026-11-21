#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline checks for loc_check.py -- no CSE, no phone. Expected values are worked out by hand
in the comments. The coordinates below are round numbers chosen here; they are nobody's position.

    python3 phone/test_loc_check.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import estimed_poc2 as poc  # noqa: E402
import loc_check as lc  # noqa: E402

RESULTS, CONTROLS = [], []


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
    fused = {"lat": 10.0, "lon": 20.0, "acc_m": 12.0, "alt_m": 5.0, "age_s": 0.5, "t": 1}
    s1 = {"fused": fused, "t": 2}
    print("== quality")
    check("a complete fix: source, accuracy, age, nothing missing, and no coordinate in the line",
          lambda: lc.quality(s1) == [{"source": "fused", "acc_m": 12.0, "age_s": 0.5, "missing": []}])
    check("a record's own fields (t, sim) are not taken for sources",
          lambda: [q["source"] for q in lc.quality({**s1, "sim": True, "plantedBy": "x"})] == ["fused"])
    check("a sample without any fix gives no line", lambda: lc.quality({"t": 2}) == [])
    for name, fix, miss in (("no accuracy (the app writes null)", {**fused, "acc_m": None}, ["accuracy"]),
                            ("accuracy 0", {**fused, "acc_m": 0}, ["accuracy"]),
                            ("no age", {k: v for k, v in fused.items() if k != "age_s"}, ["age"]),
                            ("a negative age", {**fused, "age_s": -1}, ["age"]),
                            ("accuracy true (a boolean)", {**fused, "acc_m": True}, ["accuracy"]),
                            ("a longitude that is text", {**fused, "lon": "20"}, ["position"])):
        control(f"a fix with {name} counted as complete", lambda fix=fix: lc.quality({"fused": fix})[0]["missing"] == [])
        check(f"a fix with {name} is reported as missing {miss}", lambda fix=fix, miss=miss: lc.quality({"fused": fix})[0]["missing"] == miss)

    print("== distance")
    # by hand: one degree of latitude = pi/180 x 6,371,008.8 m = 111,195.08 m
    check("one degree of latitude is 111,195 m", lambda: round(lc.haversine_m(10.0, 20.0, 11.0, 20.0)) == 111195)
    # by hand: one degree of longitude on the equator is the same arc; at latitude 60 it is half: 55,597.5 m
    check("one degree of longitude: 111,195 m on the equator, 55,597 or 55,598 m at latitude 60",
          lambda: round(lc.haversine_m(0, 0, 0, 1)) == 111195 and round(lc.haversine_m(60, 0, 60, 1)) in (55597, 55598))
    check("the same point is 0 m away", lambda: lc.haversine_m(10, 20, 10, 20) == 0)

    print("== two sources in one sample")
    # by hand: 0.001 degree of latitude = 111.2 m. Accuracies 12 and 30 -> bound 3 x 42 = 126 m: agree.
    near = {"fused": fused, "network": {**fused, "lat": 10.001, "acc_m": 30.0}}
    check("111 m apart with accuracies 12 and 30 m (bound 126 m): compared, not flagged", lambda: lc.disagreements(near) == (1, []))
    # accuracies 12 and 20 -> bound 96 m < 111 m: flagged
    far = {"fused": fused, "network": {**fused, "lat": 10.001, "acc_m": 20.0}}
    check("111 m apart with accuracies 12 and 20 m (bound 96 m): flagged, distance and bound in metres",
          lambda: lc.disagreements(far) == (1, [{"a": "fused", "b": "network", "distance_m": 111, "bound_m": 96}]))
    check("one source alone is not compared", lambda: lc.disagreements(s1) == (0, []))
    check("a source older than 30 s is not compared",
          lambda: lc.disagreements({"fused": fused, "gps": {**fused, "lat": 11.0, "age_s": 31.0}}) == (0, []))
    check("an incomplete source is not compared",
          lambda: lc.disagreements({"fused": fused, "gps": {**fused, "lat": 11.0, "acc_m": None}}) == (0, []))
    check("three sources make three pairs", lambda: lc.disagreements({"a": fused, "b": fused, "c": fused})[0] == 3)
    p = lc.planted(s1)
    check("the planted fix is one degree of latitude from the best source and is marked",
          lambda: p["planted"]["lat"] == 11.0 and p["planted"]["lon"] == 20.0 and p["plantedBy"] == "loc_check.py" and p["fused"] == fused)
    check("near the pole the planted fix goes the other way (latitude stays valid)",
          lambda: lc.planted({"fused": {**fused, "lat": 89.5}})["planted"]["lat"] == 88.5)
    check("a sample without a complete fix cannot be planted on", lambda: lc.planted({"t": 1}) is None)
    control("a planted fix 111 km away was not flagged",
            lambda: not [x for x in lc.disagreements(p)[1] if "planted" in (x["a"], x["b"])])
    check("the flag for the planted fix states about 111,195 m against a bound of 66 m",
          lambda: lc.disagreements(p)[1] == [{"a": "fused", "b": "planted", "distance_m": 111195, "bound_m": 66}])

    print("== the summary that is written out")
    two = [{"fused": fused, "gps": {**fused, "acc_m": 4.0, "age_s": 2.0}}, {"fused": {**fused, "acc_m": 20.0}}, {"t": 3}]
    summ = lc.summary(two)
    check("3 samples, 1 without a fix; fused 2 fixes (accuracy 12 to 20), gps 1",
          lambda: summ["samples"] == 3 and summ["samples_without_a_fix"] == 1
          and [(e["source"], e["n"], e["acc_m"]["min"], e["acc_m"]["max"]) for e in summ["per_source"]] == [("fused", 2, 12.0, 20.0), ("gps", 1, 4.0, 4.0)])
    check("the summary holds no coordinate, although one source is called gps", lambda: poc.scan_positions(summ) == [])
    control("a sample itself passed the coordinate scan", lambda: poc.scan_positions(two[0]) == [])
    check("the flags hold no coordinate", lambda: poc.scan_positions({"flagged": lc.disagreements(p)[1]}) == [])

    bad = [n for n, ok in RESULTS if not ok]
    alive = [n for n, went in CONTROLS if went]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed; controls {len(CONTROLS)}, all failed as they must: {not alive}")
    return 1 if bad or alive else 0


if __name__ == "__main__":
    sys.exit(main())
