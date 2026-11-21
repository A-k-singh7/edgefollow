#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""What a position sample of the phone carries, and when it is not served.

The probe app posts one `loc` record per tick: one fix per location source it has (fused, gps, network, ...), each
with lat, lon, acc_m, age_s, t. This driver reads those records back through the reader's access policy and checks:

  quality   every fix of every sample names its source and has an accuracy and an age (N samples in a row)
  sources   when a sample has two fresh sources they agree within 3 x (accuracy + accuracy); disagreement is
            REPORTED for real samples, with no pass rule
            CONTROL: a fix planted 1 degree of latitude away (about 111 km) must be flagged
  consent   the position is served to the reader only while the device's originator grants it: after the owner takes
            the reader off the `loc` container the reader gets 403 there, device_state (what every phone-backed MEC
            service reads through) serves no position, and the radio container is still served
  stale     with the stream stopped, a sample older than device_state.MAX_SAMPLE_AGE_S (20 s) is not served as live
  export    the results file holds no coordinate (scanned; a planted one is found)

Not shown, and said so in the results file: the device against the network (the lab's MEC 013 serves the phone's
own fix); a mock location provider flagged by the phone (probe version 19 does not report it; the host can only see
that two sources disagree); consent as a user dialogue (here it is the oneM2M access policy the device's originator
sets). Not a conformance claim.

    python phone/loc_check.py --device sim            # needs estimed/run_topology.sh up
    MAIN=$PWD/phone/loc_check.py NAME=loc_check bash estimed_poc/run_poc2.sh --device adb --results <file>
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "estimed"))
import device_state as ds  # noqa: E402
import estimed_poc2 as poc  # noqa: E402
import handover as ho  # noqa: E402

FRESH_S = ds.FRESH_FIX_S        # 30 s: a fix older than this is not compared with another source
AGREE_FACTOR = 3.0              # two sources agree within 3 x (acc + acc); ours. Android's accuracy is a 68 % radius.
PLANT_DEG = 1.0                 # the planted fix: 1 degree of latitude from the phone's own, about 111 km
EARTH_M = 6_371_008.8
NOT_RUN: list[dict] = []


def fixes(sample: dict) -> dict:
    """source -> fix, for the entries of a loc record that are fixes (objects with a latitude)."""
    return {p: f for p, f in sample.items() if isinstance(f, dict) and "lat" in f}


def quality(sample: dict) -> list[dict]:
    """One line per fix: the source, the accuracy, the age, and what is missing. No coordinate leaves this function."""
    out = []
    for p, f in sorted(fixes(sample).items()):
        acc, age = f.get("acc_m"), f.get("age_s")
        missing = ([] if isinstance(p, str) and p else ["source"]) \
            + ([] if _num(acc) and acc > 0 else ["accuracy"]) + ([] if _num(age) and age >= 0 else ["age"]) \
            + ([] if _num(f.get("lat")) and _num(f.get("lon")) else ["position"])
        out.append({"source": p, "acc_m": acc if _num(acc) else None, "age_s": age if _num(age) else None, "missing": missing})
    return out


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    a, b = math.radians(lat1), math.radians(lat2)
    h = math.sin((b - a) / 2) ** 2 + math.cos(a) * math.cos(b) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 2 * EARTH_M * math.asin(math.sqrt(h))


def disagreements(sample: dict, factor: float = AGREE_FACTOR, fresh_s: float = FRESH_S) -> tuple[int, list[dict]]:
    """(pairs compared, pairs that disagree). A pair is two sources of one sample, both complete and fresh. They
    disagree when they are farther apart than factor x (acc + acc). Distances are whole metres; no coordinate."""
    ok = {q["source"]: fixes(sample)[q["source"]] for q in quality(sample) if not q["missing"] and q["age_s"] <= fresh_s}
    names, bad, n = sorted(ok), [], 0
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            n += 1
            d = haversine_m(ok[a]["lat"], ok[a]["lon"], ok[b]["lat"], ok[b]["lon"])
            bound = factor * (ok[a]["acc_m"] + ok[b]["acc_m"])
            if d > bound:
                bad.append({"a": a, "b": b, "distance_m": round(d), "bound_m": round(bound)})
    return n, bad


def summary(samples: list[dict]) -> dict:
    """What the results file says about N samples: per source the count and the spread of accuracy and age."""
    per: dict = {}
    for s in samples:
        for q in quality(s):
            e = per.setdefault(q["source"], {"n": 0, "acc_m": [], "age_s": [], "incomplete": 0})
            e["n"] += 1
            e["incomplete"] += bool(q["missing"])
            e["acc_m"] += [q["acc_m"]] if q["acc_m"] is not None else []
            e["age_s"] += [q["age_s"]] if q["age_s"] is not None else []
    spread = lambda v: None if not v else {"min": round(min(v), 1), "median": round(sorted(v)[len(v) // 2], 1), "max": round(max(v), 1)}  # noqa: E731
    return {"samples": len(samples), "samples_without_a_fix": sum(1 for s in samples if not fixes(s)),
            # a list, not an object keyed by source: "gps" as a key would read as a position to the export scan
            "per_source": [{"source": p, "n": e["n"], "incomplete": e["incomplete"], "acc_m": spread(e["acc_m"]),
                            "age_s": spread(e["age_s"])} for p, e in sorted(per.items())]}


def planted(sample: dict, deg: float = PLANT_DEG) -> dict | None:
    """The sample with one more source, `planted`, `deg` degrees of latitude away from the sample's best source."""
    good = [(q["acc_m"], q["source"]) for q in quality(sample) if not q["missing"]]
    if not good:
        return None
    base = fixes(sample)[min(good)[1]]
    lat = base["lat"] + deg if base["lat"] + deg <= 90 else base["lat"] - deg
    return {**sample, "planted": {"lat": lat, "lon": base["lon"], "acc_m": 10.0, "age_s": 0.0, "t": base.get("t")},
            "plantedBy": "loc_check.py"}


# ------------------------------------------------------------------------------------------------ the live part
A_URL, AE, OWNER, READER = poc.A_URL, poc.AE, poc.OWNER, poc.READER


def loc_cins(origin: str = READER) -> tuple[int, list[dict]]:
    st, body = ho._req("GET", f"{A_URL}/{AE}/loc?rcn=4", origin)
    return st, sorted((body or {}).get("m2m:cnt", {}).get("m2m:cin", []), key=lambda c: c["ct"]) if st == 200 else []


def not_run(row: str, reason: str) -> None:
    NOT_RUN.append({"row": row, "result": "NOT-RUN", "reason": reason})
    print(f"  NOT-RUN  {row}\n          {reason}")


def main(argv=None) -> int:  # noqa: C901, PLR0915  one timeline, like the neighbouring drivers
    ap = argparse.ArgumentParser(description="location samples: source, accuracy, age, consent, staleness (plan row B4)")
    ap.add_argument("--device", choices=("adb", "sim"), default="sim")
    ap.add_argument("--samples", type=int, default=6)
    ap.add_argument("--results")
    a = ap.parse_args(argv)
    if a.device == "adb" and not a.results:
        print("refused: a phone run needs --results (no default file is written over)")
        return 2
    results = a.results or str(poc.SIM_DIR / f"loc_check_sim_{time.strftime('%Y%m%dT%H%M%S')}.json")
    poc.STEPS.clear()
    NOT_RUN.clear()
    meas: dict = {"device": a.device, "rules": {"fresh_s": FRESH_S, "agree_factor": AGREE_FACTOR, "stale_s": ds.MAX_SAMPLE_AGE_S,
                                                "planted_deg": PLANT_DEG, "samples_wanted": a.samples}}
    aborted, devs, acpi0, plant_rn = None, {}, None, None
    try:
        devs = poc.sim_setup(False) if a.device == "sim" else {"phone": poc.AdbDevice()}
        dev = devs["phone"]
        st, _ = loc_cins()
        poc.require(f"the phone's AE is live on edge A and the reader may read its position container ({dev.word} device)",
                    st == 200, f"HTTP {st}")

        print("== quality: source, accuracy and age on every sample")
        t0, got = time.time(), []
        start_n = len(loc_cins()[1])
        while time.time() - t0 < a.samples * dev.period + 30 and len(got) < a.samples:
            time.sleep(1)
            got = loc_cins()[1][start_n:]
        samples = [json.loads(c["con"]) for c in got[:a.samples]]
        meas["quality"] = summ = summary(samples)
        with_fix = [s for s in samples if fixes(s)]
        poc.step(f"{a.samples} new position samples arrived in a row", len(samples) == a.samples, f"{len(samples)} arrived")
        if not with_fix:
            not_run("quality and sources", "no sample held a position fix (the phone has no fix here)")
        else:
            bad = [q for s in with_fix for q in quality(s) if q["missing"]]
            poc.step("every fix names its source and has an accuracy above 0 and an age",
                     not bad, f"{sum(e['n'] for e in summ['per_source'])} fixes from {[e['source'] for e in summ['per_source']]}; "
                     f"{summ['samples_without_a_fix']} samples without a fix; incomplete: {[(q['source'], q['missing']) for q in bad][:4]}")
            pairs, flagged = 0, []
            for s in with_fix:
                n, f = disagreements(s)
                pairs, flagged = pairs + n, flagged + f
            meas["sources"] = {"pairs_compared": pairs, "pairs_that_disagree": len(flagged), "flagged": flagged[:10],
                               "pass_rule": "none: reported"}
            print(f"  REPORT  two sources in one sample: {pairs} pairs compared, {len(flagged)} disagree (no pass rule)")
            plant = planted(with_fix[-1])
            st_p, made = ho._req("POST", f"{A_URL}/{AE}/loc", OWNER, ty=4,
                                 body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(plant)}})
            plant_rn = (made or {}).get("m2m:cin", {}).get("rn")
            st_r, back = ho._req("GET", f"{A_URL}/{AE}/loc/{plant_rn}", READER)
            read = json.loads((back or {}).get("m2m:cin", {}).get("con", "{}")) if st_r == 200 else {}
            n, f = disagreements(read)
            hit = [x for x in f if "planted" in (x["a"], x["b"])]
            poc.step("CONTROL (must FAIL) a fix planted about 111 km from the phone's own was not flagged",
                     not (st_p == 201 and st_r == 200 and hit),
                     f"planted HTTP {st_p}, read back HTTP {st_r}; flagged {[(x['distance_m'], x['bound_m']) for x in hit][:2]} (m, bound m)")
            st_d = ho._req("DELETE", f"{A_URL}/{AE}/loc/{plant_rn}", OWNER)[0]
            plant_rn = None if st_d == 200 else plant_rn
            poc.step("the planted record is removed from the phone's container", st_d == 200, f"HTTP {st_d}")

        print("== consent: the position is served only while the device's originator grants it")
        _, cnt = ho._req("GET", f"{A_URL}/{AE}/loc", OWNER)
        acpi0 = (cnt or {}).get("m2m:cnt", {}).get("acpi")
        own = {"m2m:acp": {"rn": "phoneOwnerOnlyAcp", "pv": {"acr": [{"acor": [OWNER], "acop": 63}]},
                           "pvs": {"acr": [{"acor": [OWNER], "acop": 63}]}}}
        st_a, b = ho._req("POST", A_URL, OWNER, ty=1, body=own)
        if st_a != 201:             # an earlier run's policy: reset its privileges, never reuse them as found
            st_a, b = ho._req("PUT", f"{A_URL}/phoneOwnerOnlyAcp", OWNER, body={"m2m:acp": {"pv": own["m2m:acp"]["pv"], "pvs": own["m2m:acp"]["pvs"]}})
        ri = (b or {}).get("m2m:acp", {}).get("ri")
        poc.require("the position container carries the reader's policy and an owner-only policy exists", bool(acpi0) and bool(ri),
                    f"acpi before {acpi0}; owner-only policy HTTP {st_a}")
        before = ho._req("GET", f"{A_URL}/{AE}/loc/la", READER)[0]
        st_w = ho._req("PUT", f"{A_URL}/{AE}/loc", OWNER, body={"m2m:cnt": {"acpi": [ri]}})[0]
        after = ho._req("GET", f"{A_URL}/{AE}/loc/la", READER)[0]
        snap = ds.snapshot()
        radio = ho._req("GET", f"{A_URL}/{AE}/radio/la", READER)[0]
        owner = ho._req("GET", f"{A_URL}/{AE}/loc/la", OWNER)[0]
        poc.step("CONTROL (must FAIL) the reader still got the position after the owner withdrew it",
                 not (before == 200 and st_w == 200 and after == 403 and snap.get("loc") is None),
                 f"reader before {before}, withdrawal HTTP {st_w}, reader after {after}; device_state: {str(snap.get('loc_ct'))[:60]}")
        poc.step("withdrawing the position leaves the radio data served and the owner's own access intact",
                 radio == 200 and owner == 200 and snap.get("radio") is not None, f"reader radio {radio}, owner position {owner}")
        st_g = ho._req("PUT", f"{A_URL}/{AE}/loc", OWNER, body={"m2m:cnt": {"acpi": acpi0}})[0]
        again = ho._req("GET", f"{A_URL}/{AE}/loc/la", READER)[0]
        if st_g == 200 and again == 200:
            acpi0 = None            # put back; nothing for the finally to do
        poc.step("granted again, the position is served again", st_g == 200 and again == 200 and ds.snapshot().get("loc") is not None,
                 f"grant HTTP {st_g}, reader {again}")

        print(f"== stale: a sample older than {ds.MAX_SAMPLE_AGE_S:.0f} s is not served as live")
        live0 = ds.snapshot().get("loc") is not None
        dev.stop()
        time.sleep(ds.MAX_SAMPLE_AGE_S + dev.period + 2)
        snap = ds.snapshot()
        poc.step("CONTROL (must FAIL) a position sample older than the limit was served as live",
                 not (live0 and snap.get("loc") is None and str(snap.get("loc_ct", "")).startswith("stale")),
                 f"served before the stop: {live0}; after {ds.MAX_SAMPLE_AGE_S + dev.period + 2:.0f} s: {str(snap.get('loc_ct'))[:70]}")
        dev.live(A_URL)
        t1, back_live = time.time(), False
        while time.time() - t1 < 40 and not back_live:
            time.sleep(1)
            back_live = ds.snapshot().get("loc") is not None
        poc.step("with the stream running again the position is served again", back_live, f"after {time.time() - t1:.0f} s")

        print("== export: no coordinate in the results")
        hits = poc.scan_positions(meas)
        poc.step("the measurements written to the results file hold no coordinate", not hits, str(hits[:3]))
        poc.step("CONTROL (must FAIL) the scan missed a coordinate planted in a copy of the measurements",
                 not poc.scan_positions({**meas, "fix": {"lat": 1.0, "lon": 2.0}}))
    except poc.Abort as e:
        aborted = str(e)
    except Exception as e:  # noqa: BLE001  an exception is a FAIL row, never a silent stop
        traceback.print_exc()
        poc.step("run completed without an exception", False, repr(e))
        aborted = "exception"
    finally:
        if plant_rn:
            ho._req("DELETE", f"{A_URL}/{AE}/loc/{plant_rn}", OWNER)
        if acpi0:                   # the withdrawal was not undone above: put the reader's policy back
            ho._req("PUT", f"{A_URL}/{AE}/loc", OWNER, body={"m2m:cnt": {"acpi": acpi0}})
        ho._req("DELETE", f"{A_URL}/phoneOwnerOnlyAcp", OWNER)
        meas["left_behind"] = {"owner_only_policy": ho._req("GET", f"{A_URL}/phoneOwnerOnlyAcp", OWNER)[0],
                               "reader_reads_position": ho._req("GET", f"{A_URL}/{AE}/loc/la", READER)[0]}
        if a.device == "sim":
            for d in devs.values():
                d.stop()
            ho.delete_ae(ho.EDGE_A, ae=AE, origin=OWNER)
    meas["not_run"] = NOT_RUN
    meas["not_shown"] = [
        "the device against the network: the lab's MEC 013 serves the phone's own fix",
        "a mock location provider flagged by the phone: probe version 19 does not report it; the host sees only that two sources disagree",
        "consent as a user dialogue: here it is the oneM2M access policy the device's originator sets, on a CSE that takes the originator header as given",
        "that the stated accuracy is true: it is the phone's own figure"]
    good = poc.finish(results, aborted_at=aborted, device=a.device, measurements=meas)
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
