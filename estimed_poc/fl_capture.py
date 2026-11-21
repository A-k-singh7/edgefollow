#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""The host bridge between two phones and the federated-learning driver.

The probe app posts its env record (light, proximity, battery charge, battery temperature, time) into its own AE on
MN-CSE-A every 5 s. This tool reads those records back from the CSE, keeps 27 slots of 5 s from each phone, and
writes ONE capture file. fl_run.py --sources <file> then posts them, unchanged, as the observations of its two data
sources flSrc1 and flSrc2. No other container of a phone is read: no position, no cell, no network name.

  capture    live: read /cse-mn-a/<ae>/env of both phones (their own originators), wait for 27 common slots, write
             the file; with --countersign ALIAS each phone signs the digest of its own records (probe mode `sign`,
             a key that already exists on the phone; this tool makes no key)
  rehearse   no phone: a capture of the same shape from a fixed integer rule, marked origin "rehearsal". It exists
             so that the device path can be run and judged before a sitting. It is never a device record.
  check      recompute a capture's slots, digests, counts and gate; exit 1 on any difference
  verify-sig check each countersignature against the leaf certificate of an attestation record on file

What the bridge is and is not: the phones' records are real and unchanged (each with its SHA-256); the two source AEs
of the FL run are registered by the host, and the host posts the records there. A phone does not take part in a
round. The counts in "expect" are worked out here on a table of filled slots, a second way from fl_core.pairs.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "estimed"))
import fl_core as fl  # noqa: E402

FORMAT = "estimed.fl.capture.v1"
PERIOD_MS, CHUNK, ROUNDS = 5000, 9, 3
SLOTS = CHUNK * ROUNDS                      # 27 slots = 135 s per phone
MIN_FILLED = 24                             # of 27, per phone (ours)
MIN_WEIGHT = 4                              # every participant of rounds 1 to 3 needs at least this many samples (ours)
TEMP_DC = (150, 420)                        # 15.0 to 42.0 C. Worked out offline on 2026-11-19: with fl_core's step size
#                                             the training settles up to about 42 C and runs away from about 43 C.
SOURCES = {"flSrc1": {"label": "phone-A", "ae": "phone", "origin": "Cphone-DEVC", "serial_env": "ANDROID_SERIAL"},
           "flSrc2": {"label": "phone-B", "ae": "rsu", "origin": "Crsu-NP2A", "serial_env": "RSU_SERIAL"}}
ADB = os.environ.get("ADB_BIN", str(Path.home() / "android-tools/platform-tools/adb"))
APP_DIR = "/sdcard/Android/data/org.edgefollow.probe/files"
OUT_DEVICE, OUT_REHEARSAL = Path("/home/edgefollow/estimed-run/sitting_b"), Path("/home/edgefollow/estimed-run/sim")


def slot_of(t_ms: int, period_ms: int = PERIOD_MS) -> int:
    """The slot NUMBER of a time: the nearest whole period, half up. (fl_core.pairs writes the same rule another way.)"""
    q, r = divmod(t_ms, period_ms)
    return q + (1 if 2 * r >= period_ms else 0)


def source_digest(label: str, slot0: int, records: list[dict]) -> str:
    """What a phone countersigns: its label, the first slot and, per kept record, the slot and the record's SHA-256."""
    return fl.digest({"format": FORMAT, "label": label, "slot0": slot0, "period_ms": PERIOD_MS,
                      "records": [[r["slot"], r["con_sha256"]] for r in records]})


def _parse(cins: list[dict]) -> tuple[list[dict], list[dict]]:
    """cins [{con, ct}] -> (usable rows with their absolute slot, refused rows with the reason). Order: record time."""
    ok, bad = [], []
    for c in cins:
        con = c.get("con")
        sha = fl.text_digest(con) if isinstance(con, str) else None
        try:
            if not isinstance(con, str):
                raise ValueError("the content is not text")
            r = fl.parse_env(con, device=True)
        except (ValueError, TypeError) as e:
            bad.append({"con_sha256": sha, "ct": c.get("ct"), "reason": str(e)})
            continue
        ok.append({"abs_slot": slot_of(r["t"]), "t": r["t"], "ct": c.get("ct"), "con": con, "con_sha256": sha})
    return sorted(ok, key=lambda r: r["t"]), bad


def expect(filled: dict) -> dict:
    """The sample counts the FL run must find, from a table {source: set of filled slot numbers 0..26}. A sample
    starts in slot k when k and k+1 are both filled. Round r sees slots 0 .. 9r-1.
      round 1  one participant for both sources: a window counts when BOTH sources have a sample starting in it
      round 2  each source its own participant;  round 3  flSrc1 alone (flSrc2 is revoked in that round)"""
    def starts(src, upto):
        return {k for k in range(upto - 1) if k in filled[src] and k + 1 in filled[src]}

    def breaks(src, upto):                  # neighbours in the kept rows that are not one slot apart
        have = sorted(k for k in filled[src] if k < upto)
        return sum(1 for a, b in zip(have, have[1:]) if b - a != 1)
    s1, s2 = starts("flSrc1", CHUNK), starts("flSrc2", CHUNK)
    both = s1 & s2
    return {"r1": {"n": 2 * len(both), "per_source": {"flSrc1": len(both), "flSrc2": len(both)},
                   "dropped_gap": breaks("flSrc1", CHUNK) + breaks("flSrc2", CHUNK),
                   "dropped_unaligned": len(s1) + len(s2) - 2 * len(both)},
            "weights": {"1": {"P-TFC-AGG": 2 * len(both)},
                        "2": {"P-TFC-S1": len(starts("flSrc1", 2 * CHUNK)), "P-TFC-S2": len(starts("flSrc2", 2 * CHUNK))},
                        "3": {"P-TFC-S1": len(starts("flSrc1", SLOTS))}}}


def temps_of(records: list[dict]) -> list[int]:
    return [fl.parse_env(r["con"], device=True)["temp_dc"] for r in records]


def gate(filled: dict, exp: dict, temps: dict) -> list[str]:
    """Why a capture cannot carry three rounds. Empty = usable. temps: {source: [tenths of a degree C, ...]}."""
    why = [f"{s}: battery temperature {min(t) / 10} to {max(t) / 10} C, outside {TEMP_DC[0] / 10} to {TEMP_DC[1] / 10} C"
           for s, t in sorted(temps.items()) if t and not (TEMP_DC[0] <= min(t) and max(t) <= TEMP_DC[1])]
    why += [f"{s}: {len(filled[s])} of {SLOTS} slots filled, fewer than {MIN_FILLED}" for s in sorted(filled) if len(filled[s]) < MIN_FILLED]
    why += [f"round {r}: {p} would have {n} samples, fewer than {MIN_WEIGHT}"
            for r, w in sorted(exp["weights"].items()) for p, n in sorted(w.items()) if n < MIN_WEIGHT]
    return why


def build(cins: dict, origin: str, made_at_utc: str, extra: dict | None = None) -> dict:
    """The capture from {source: [cin, ...]}. Slot 0 is the first slot in which BOTH phones have a record; from there
    27 slots are kept; in a slot the earliest record is kept and a later one counted."""
    if origin not in ("device", "rehearsal"):
        raise ValueError(f"origin {origin!r}")
    if set(cins) != set(SOURCES):
        raise ValueError(f"need exactly {sorted(SOURCES)}")
    parsed = {s: _parse(c) for s, c in cins.items()}
    firsts = [rows[0]["abs_slot"] for rows, _ in parsed.values() if rows]
    slot0 = max(firsts) if len(firsts) == len(SOURCES) else None
    out, filled = {}, {}
    for s, (rows, bad) in sorted(parsed.items()):
        kept, same, outside = [], 0, 0
        for r in rows:
            k = None if slot0 is None else r["abs_slot"] - slot0
            if k is None or not 0 <= k < SLOTS:
                outside += 1
            elif kept and kept[-1]["slot"] == k:
                same += 1
            else:
                kept.append({"slot": k, "ct": r["ct"], "con": r["con"], "con_sha256": r["con_sha256"]})
        ages = sorted(fl.ct_ms(r["ct"]) - json.loads(r["con"])["t"] for r in kept if isinstance(r["ct"], str))
        filled[s] = {r["slot"] for r in kept}
        out[s] = {"label": SOURCES[s]["label"], "ae": SOURCES[s]["ae"], "records": kept, "refused": bad,
                  "dropped_same_slot": same, "outside_the_window": outside,
                  "digest": source_digest(SOURCES[s]["label"], slot0 or 0, kept),
                  "cse_time_minus_record_time_ms": {"n": len(ages), "median": ages[len(ages) // 2] if ages else None,
                                                    "min": ages[0] if ages else None, "max": ages[-1] if ages else None},
                  "countersignature": None}
    exp = expect(filled)
    why = gate(filled, exp, {s: temps_of(v["records"]) for s, v in out.items()}) + (
        [] if slot0 is not None else ["a phone has no usable record"])
    return {"format": FORMAT, "origin": origin, "made_at_utc": made_at_utc, "period_ms": PERIOD_MS, "slots": SLOTS,
            "slot0": slot0, "sources": out, "expect": exp, "usable": not why, "why_not": why, **(extra or {})}


def check(cap: dict) -> list[str]:
    """Everything in a capture that can be worked out again, worked out again. Empty = it agrees with itself."""
    bad = []
    if not isinstance(cap, dict) or cap.get("format") != FORMAT or cap.get("origin") not in ("device", "rehearsal"):
        return ["not a capture of format " + FORMAT]
    if set(cap.get("sources", {})) != set(SOURCES) or not isinstance(cap.get("slot0"), int):
        return ["the two sources or the first slot are missing"]
    filled = {}
    for s, src in sorted(cap["sources"].items()):
        seen = []
        for r in src.get("records", []):
            try:
                rec = fl.parse_env(r["con"], device=True)
            except (ValueError, TypeError, KeyError) as e:
                bad.append(f"{s}: a kept record is not a device env record ({e})")
                continue
            if fl.text_digest(r["con"]) != r.get("con_sha256"):
                bad.append(f"{s} slot {r.get('slot')}: the record does not have its stated SHA-256")
            if slot_of(rec["t"]) - cap["slot0"] != r.get("slot"):
                bad.append(f"{s}: a record's time puts it in slot {slot_of(rec['t']) - cap['slot0']}, the file says {r.get('slot')}")
            seen.append(r.get("slot"))
        if seen != sorted(set(seen)) or any(not isinstance(k, int) or not 0 <= k < SLOTS for k in seen):
            bad.append(f"{s}: slots are not 0..{SLOTS - 1}, each once, in order")
        if src.get("label") != SOURCES[s]["label"]:
            bad.append(f"{s}: label {src.get('label')!r}")
        if src.get("digest") != source_digest(SOURCES[s]["label"], cap["slot0"], src.get("records", [])):
            bad.append(f"{s}: the digest of the records is not the stated one")
        filled[s] = {k for k in seen if isinstance(k, int)}
    if bad:
        return bad
    exp = expect(filled)
    if cap.get("expect") != exp:
        bad.append("the expected counts are not the ones the slots give")
    why = gate(filled, exp, {s: temps_of(v["records"]) for s, v in cap["sources"].items()})
    if cap.get("usable") is not (not why) or cap.get("why_not") != why:
        bad.append("the gate verdict is not the one the slots give")
    return bad


def verify_sig(src: dict, attest: dict) -> tuple[bool, str]:
    """A countersignature: ECDSA P-256 with SHA-256 over the 32 bytes of the source digest, checked with the public
    key of the leaf certificate of an attestation record. Says nothing about who holds the phone."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    cs = src.get("countersignature")
    if not isinstance(cs, dict) or cs.get("ok") is not True or not isinstance(cs.get("sig"), str):
        return False, "no countersignature in the capture"
    if cs.get("challenge") != src.get("digest"):
        return False, "the signed challenge is not this source's digest"
    try:
        pub = x509.load_der_x509_certificate(base64.b64decode(attest["chain"][0])).public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False, "the leaf key is not an EC key"
        pub.verify(base64.b64decode(cs["sig"]), bytes.fromhex(src["digest"]), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "the signature does not verify with this key"
    except (KeyError, IndexError, ValueError, TypeError) as e:
        return False, f"could not be checked: {type(e).__name__}: {e}"
    return True, f"verifies with the leaf key of alias {(attest.get('params') or {}).get('alias')!r}"


# ------------------------------------------------------------------------------------------------ the live part
def read_env(ae: str, origin: str) -> list[dict]:
    import handover as ho
    st, body = ho._req("GET", f"{ho.EDGE_A[0]}/{ho.EDGE_A[1]}/{ae}/env?rcn=4", origin)
    return (body or {}).get("m2m:cnt", {}).get("m2m:cin", []) if st == 200 else []


def adb_sign(serial: str, alias: str, digest_hex: str, wait_s: float = 20.0) -> dict:
    """Probe mode `sign` (no prompt): the phone signs the digest with a key it already holds under `alias`."""
    def sh(*a, t=20):
        return subprocess.run([ADB, "-s", serial, "shell", *a], capture_output=True, text=True, timeout=t)
    sh("rm", "-f", f"{APP_DIR}/sign.json", f"{APP_DIR}/done_sign")
    sh("am", "start", "-n", "org.edgefollow.probe/.Main", "-e", "mode", "sign", "-e", "alias", alias, "-e", "challenge", digest_hex)
    end = time.monotonic() + wait_s
    while time.monotonic() < end:
        r = sh(f"[ -f {APP_DIR}/done_sign ] && cat {APP_DIR}/sign.json")
        if r.returncode == 0 and r.stdout.strip():
            try:
                j = json.loads(r.stdout)
            except ValueError:
                return {"ok": False, "error": "sign.json is not JSON"}
            return {k: j.get(k) for k in ("ok", "alias", "challenge", "sig", "stage", "exception", "message")}
        time.sleep(0.5)
    return {"ok": False, "error": f"no answer from the phone in {wait_s:.0f} s"}


def cmd_capture(a) -> int:
    t_start = time.time()
    start_ms, deadline = int(t_start * 1000), time.monotonic() + a.wait_s
    cap = None
    while True:
        cins = {s: [c for c in read_env(d["ae"], d["origin"]) if isinstance(c.get("ct"), str) and fl.ct_ms(c["ct"]) >= start_ms]
                for s, d in SOURCES.items()}
        cap = build(cins, "device", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    {"capture_started_ms": start_ms, "waited_s": round(time.time() - t_start, 1),
                     "preregistration": {"sha256": a.prereg_sha256, "go_phrase": a.go}})
        n = {s: len(v["records"]) for s, v in cap["sources"].items()}
        last = {s: (v["records"][-1]["slot"] if v["records"] else -1) for s, v in cap["sources"].items()}
        print(f"  {time.time() - t_start:5.0f} s  kept {n}  last slot {last}", flush=True)
        if min(last.values()) >= SLOTS - 1 or time.monotonic() >= deadline:
            break
        time.sleep(5)
    if a.countersign:
        for s, d in SOURCES.items():
            serial = os.environ.get(d["serial_env"])
            cap["sources"][s]["countersignature"] = (adb_sign(serial, a.countersign, cap["sources"][s]["digest"]) if serial
                                                     else {"ok": False, "error": f"{d['serial_env']} is not set"})
            print(f"  countersignature {d['label']}: ok={cap['sources'][s]['countersignature'].get('ok')}")
    return write(cap, Path(a.out) if a.out else OUT_DEVICE / f"fl_capture_{time.strftime('%Y%m%dT%H%M%S')}.json")


def rehearsal_cins(temp_dc: tuple = (310, 335), skip: dict | None = None) -> dict:
    """Records of the probe app's env shape from a fixed integer rule; times off the grid by up to 0.9 s, the two
    'phones' started 1.2 s apart; slot 13 of the second one is missing unless `skip` says otherwise."""
    skip = {"flSrc2": {13}} if skip is None else skip
    t0, out = 1_800_000_000_000, {}
    for i, s in enumerate(sorted(SOURCES)):
        seed, rows = 7 + 5 * i, []
        for k in range(SLOTS + 2):
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
            if k in skip.get(s, ()):
                continue
            t = t0 + 1200 * i + k * PERIOD_MS + (seed >> 16) % 900
            con = json.dumps({"light": {"n": 5, "mean": [90.0 + k]}, "proximity": {"n": 0}, "battery_pct": 80 - k // 12 - i,
                              "battery_temp_c": (temp_dc[i] + (seed >> 8) % 4 + k // 6) / 10, "t": t})
            rows.append({"con": con, "ct": time.strftime("%Y%m%dT%H%M%S", time.gmtime((t + 40) / 1000)) + f",{(t + 40) % 1000:03d}000"})
        out[s] = rows
    return out


def cmd_rehearse(a) -> int:
    cap = build(rehearsal_cins(), "rehearsal", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                {"note": "made by the host from a fixed rule; no device took part"})
    return write(cap, Path(a.out) if a.out else OUT_REHEARSAL / f"fl_capture_rehearsal_{time.strftime('%Y%m%dT%H%M%S')}.json")


def write(cap: dict, path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "x") as f:              # never over an earlier capture
        json.dump(cap, f, indent=1)
    print(f"  capture: {path}\n  sha256:  {hashlib.sha256(path.read_bytes()).hexdigest()}")
    print(f"  RESULT: {'USABLE' if cap['usable'] else 'NOT USABLE'}  ({cap['origin']}; "
          + "; ".join(f"{v['label']} {len(v['records'])}/{SLOTS} slots, {len(v['refused'])} refused" for v in cap["sources"].values())
          + (f"; {cap['why_not']}" if cap["why_not"] else "") + ")")
    return 0 if cap["usable"] else 1


def cmd_check(a) -> int:
    bad = check(json.loads(Path(a.file).read_text()))
    print("\n".join(f"  DIFFERS  {b}" for b in bad) or "  the capture agrees with itself")
    return 1 if bad else 0


def cmd_verify_sig(a) -> int:
    cap, rc = json.loads(Path(a.file).read_text()), 0
    for s, path in (("flSrc1", a.attest_a), ("flSrc2", a.attest_b)):
        if not path:                        # no attestation record on file for this phone: nothing to check against
            print(f"  NOT-RUN  {cap['sources'][s]['label']}: no attestation record was given")
            continue
        ok, why = verify_sig(cap["sources"][s], json.loads(Path(path).read_text()))
        print(f"  {'PASS' if ok else 'FAIL'}  {cap['sources'][s]['label']}: {why}")
        rc |= not ok
    return int(rc)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--wait-s", type=float, default=240.0)
    c.add_argument("--countersign", metavar="ALIAS")
    c.add_argument("--prereg-sha256")
    c.add_argument("--go")
    c.add_argument("--out")
    c.set_defaults(fn=cmd_capture)
    r = sub.add_parser("rehearse")
    r.add_argument("--out")
    r.set_defaults(fn=cmd_rehearse)
    k = sub.add_parser("check")
    k.add_argument("file")
    k.set_defaults(fn=cmd_check)
    v = sub.add_parser("verify-sig")
    v.add_argument("file")
    v.add_argument("--attest-a")
    v.add_argument("--attest-b")
    v.set_defaults(fn=cmd_verify_sig)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
