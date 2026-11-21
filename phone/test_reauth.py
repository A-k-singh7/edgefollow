#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline checks for reauth.py -- no CSE, no phone, no key made.

The signature rows use records two phones made on 2026-10-15 and on 2026-10-29 (an attestation of a kept key and a
signature by that key over one challenge). No signature over a NEW message can be made here, so the rows that need
the target to admit use a stand-in verifier and say so; the real admission is first exercised with a phone. No
record of a software key or of an unlocked phone is on this disk and a leaf certificate cannot be re-signed here,
so the rows for such a record change the key description on its way out of the verifier's parser and say so. The
command-line rows call the driver with the lab and the phone cut off: stand-ins answer, no request is sent and adb
is not started. When the records are not on this disk the rows that need them are NOT-RUN and the script fails: a
skip is not a pass.

    python3 phone/test_reauth.py
"""
from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attest_verify_android as av  # noqa: E402
import reauth as ra  # noqa: E402

RESULTS, CONTROLS, NOT_RUN = [], [], []
D = Path("/home/edgefollow/estimed-run/two_phone/20261015T102247Z")
STATUS = D / "raw/google_attest_status_20261015T102247Z.json"
# The records of 2026-10-29: two phones, one alias on both. Their status list carries no fetch time inside and no
# stamp in its name, so the day is written here (the file's own time, read on 2026-11-19: 2026-10-29T12:27:20Z).
D29 = Path("/home/edgefollow/backups/var-tmp-evidence-2026-11-19/twophone-2026-10-29")
STATUS29 = D29 / "google_attest_status.json"
AS_OF29 = dt.datetime(2026, 10, 29, 12, 27, 20, tzinfo=dt.timezone.utc)
TODAY = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)
SIG_REASON = "the signature does not verify with the enrolled key over this transaction"


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


class _Lab(BaseException):
    """The driver went on towards the lab. Not an Exception, so the driver's own handlers do not swallow it."""


def run_main(argv, stop=lambda method, url: "/ho-" in url, as_error=False, lab=None):
    """reauth.main with the lab and the phone cut off. Every request goes to a stand-in that answers 200 (or what
    `lab` answers), and the run is stopped at the first request `stop` names: by default the first one for the
    transaction lock, whose name carries the originator. With as_error the stop is an ordinary error, so the driver
    ends its run and hands its measurements to the results writer, which is a stand-in too. The module that would
    run adb is replaced for the time of the call: its stand-in notes who was asked to sign and stops the run. No
    request leaves this process, adb is not started and no results file is written.
    -> code: the exit code, or None when the run was stopped; text: what was printed; origin: the originator the
    driver went on with, or None; requests: how many it made; meas: what the results writer was handed, or None;
    wrote: (originator, record) for each write into the registry's keys; asked: (serial, alias, digest) for each
    request to sign."""
    seen, out, got = [], io.StringIO(), SimpleNamespace(code=None, meas=None, wrote=[], asked=[])
    real_req, real_finish, real_fc = ra.ho._req, ra.poc.finish, sys.modules.get("fl_capture")

    def no_lab(method, url, origin, **kw):
        seen.append(url)
        if method == "POST" and url.endswith("/keys"):
            got.wrote.append((origin, json.loads(kw["body"]["m2m:cin"]["con"])))
        if stop(method, url):
            raise RuntimeError("stopped by the stand-in for the lab") if as_error else _Lab
        return lab(method, url, origin, kw.get("body")) if lab else (200, None)

    def no_file(path, **kw):
        got.meas = kw.get("measurements")
        return False

    def no_phone(serial, alias, digest, *a, **kw):
        got.asked.append((serial, alias, digest))
        raise _Lab
    ra.ho._req, ra.poc.finish, sys.modules["fl_capture"] = no_lab, no_file, SimpleNamespace(adb_sign=no_phone)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            got.code = ra.main(argv)
    except _Lab:
        pass
    except SystemExit as e:     # the argument parser's own exit: not the driver's refusal
        got.code = f"parser exit {e.code}"
    finally:
        ra.ho._req, ra.poc.finish = real_req, real_finish
        if real_fc is None:
            del sys.modules["fl_capture"]
        else:
            sys.modules["fl_capture"] = real_fc
    named = [u.rsplit("/ho-", 1)[1] for u in seen if "/ho-" in u]
    got.text, got.origin, got.requests = out.getvalue(), named[0] if named else None, len(seen)
    return got


def lab_in_memory():
    """A stand-in for the three CSEs that keeps what is created, just enough for the driver to get from its first
    request to the phone's signature: a create answers 201 (403 for the stranger), a read of the registry's keys
    gives back what was written, the transaction is read back by everyone but the target, the IN-CSE and both edges
    answer, and nothing else exists. It says nothing about the real CSEs."""
    kept = {}

    def answer(method, url, origin, body):
        path = url.partition("?")[0]
        if method == "POST":
            if origin == "Cstranger":
                return 403, None
            kind, attrs = next(iter(body.items()))
            kept[f"{path}/{attrs.get('rn', len(kept))}"] = attrs
            return 201, {kind: {**attrs, "ri": "ri-stand-in"}}
        if method == "DELETE":
            for u in [u for u in kept if u.startswith(path)]:
                del kept[u]
            return 200, None
        if path.endswith("/keys"):
            return 200, {"m2m:cnt": {"m2m:cin": [v for u, v in kept.items() if u.startswith(path + "/")]}}
        if "/ho-" in path:
            return (200, {"m2m:cnt": kept[path]}) if path in kept and origin != ra.TARGET_ORIGIN else (404, None)
        return (200, {}) if path in (ra.IN_URL, ra.poc.A_URL, ra.poc.B_URL) else (404, None)
    return answer


@contextlib.contextmanager
def leaf_says(alter):
    """While this is open the leaf's key description is changed by `alter` on its way out of the verifier's parser.
    This stands in for a record of a software key or of an unlocked phone; the chain, the status list, the challenge
    and both signature checks stay the real ones on the real record."""
    real = av.parse_key_description

    def parsed(ext):
        kd = copy.deepcopy(real(ext))
        alter(kd)
        return kd
    av.parse_key_description = parsed
    try:
        yield
    finally:
        av.parse_key_description = real


def enrol_as(alter, attest, status, as_of):
    with leaf_says(alter):
        return ra.enrol(attest, status, as_of, "Cdev", "x")


@contextlib.contextmanager
def verifier_not_asked():
    """While this is open whatever policy enrolment asks for is dropped on its way to the verifier, which then works
    under its default: it does not evaluate the security level, the lock state or the boot state."""
    real = av.Policy
    av.Policy = lambda **kw: real()
    try:
        yield
    finally:
        av.Policy = real


def other_key_rows(day, view, st, r1, s1, r2, s2):
    """The plan's control 'the other phone's key': two devices in one registry, real keys, real signatures. No
    signature over a NEW message can be made here, so the challenge a signature on file was made over stands in for
    the digest of the transaction: for that message it is a right signature by its own key. The key the target
    looks up and the ECDSA check are the real ones."""
    reg, v1, v2 = {"Cdev": r1, "Cdev2": r2}, view, {**view, "aeId": "Cdev2"}
    shown = lambda ae, v, s: ra.admit({"aeId": ae, "txn": "t1", "sig": s["sig"]}, v, reg, st(), 1000,  # noqa: E731
                                      verify=lambda leaf, ch, sig: ra.verify_sig(leaf, s["challenge"], sig))
    check(f"{day}: two devices enrolled, each is admitted with the signature of its own key",
          lambda: shown("Cdev", v1, s1) == (True, "admitted") and shown("Cdev2", v2, s2) == (True, "admitted"))
    control(f"{day}: device 1 was admitted with a right signature by device 2's key", lambda: shown("Cdev", v1, s2)[0])
    control(f"{day}: device 2 was admitted with a right signature by device 1's key", lambda: shown("Cdev2", v2, s1)[0])
    check(f"{day}: both refusals give the signature as the reason",
          lambda: shown("Cdev", v1, s2) == (False, SIG_REASON) and shown("Cdev2", v2, s1) == (False, SIG_REASON))


def main() -> int:
    print("== the message both sides build")
    m = ra.message("Cdev", "cse-a", "cse-b", "t1", 1800000000, "n1")
    # by hand: keys in alphabetical order, no spaces
    check("the message is the canonical text, written out by hand",
          lambda: m == b'{"aeId":"Cdev","nonce":"n1","purpose":"estimed.handover.reauth.v1","source":"cse-a","target":"cse-b","txn":"t1","validUntil":1800000000}')
    check("its digest is 64 hex digits and is SHA-256 of those bytes", lambda: ra.challenge_hex(m) == hashlib.sha256(m).hexdigest() and len(ra.challenge_hex(m)) == 64)
    for i, alt in enumerate((("Cdev2", "cse-a", "cse-b", "t1", 1800000000, "n1"), ("Cdev", "cse-x", "cse-b", "t1", 1800000000, "n1"),
                             ("Cdev", "cse-a", "cse-x", "t1", 1800000000, "n1"), ("Cdev", "cse-a", "cse-b", "t2", 1800000000, "n1"),
                             ("Cdev", "cse-a", "cse-b", "t1", 1800000001, "n1"), ("Cdev", "cse-a", "cse-b", "t1", 1800000000, "n2"))):
        control(f"a message that differs in field {i + 1} of 6 has the same digest", lambda alt=alt: ra.challenge_hex(ra.message(*alt)) == ra.challenge_hex(m))
    for name, args in (("an empty nonce", ("Cdev", "a", "b", "t", 1, "")), ("a valid-until that is not whole seconds", ("Cdev", "a", "b", "t", 1.5, "n")),
                       ("a valid-until that is true", ("Cdev", "a", "b", "t", True, "n")), ("a missing AE-ID", (None, "a", "b", "t", 1, "n"))):
        def built(args=args):
            try:
                return bool(ra.message(*args))
            except ValueError:
                return False
        control(f"a message with {name} was built", built)

    print("== the target's decision (a stand-in verifier: it accepts exactly the signature text 'sig-of:' + the digest)")
    stand_in = lambda leaf, ch, sig: sig == "sig-of:" + ch  # noqa: E731
    view = {"aeId": "Cdev", "source": "cse-a", "target": "cse-b", "txn": "t1", "validUntil": 2000}
    reg = {"Cdev": {"leaf_der_b64": "x"}}
    st = lambda: {"nonce": {"t1": "n1"}, "used": set()}  # noqa: E731
    sig = "sig-of:" + ra.challenge_hex(ra.message("Cdev", "cse-a", "cse-b", "t1", 2000, "n1"))
    req = {"aeId": "Cdev", "txn": "t1", "sig": sig}
    check("the right signature over the target's own view of the transaction is admitted",
          lambda: ra.admit(req, view, reg, st(), 1000, verify=stand_in) == (True, "admitted"))
    s2 = st()
    check("admission uses the nonce up: the same request a second time is refused",
          lambda: ra.admit(req, view, reg, s2, 1000, verify=stand_in)[0] and ra.admit(req, view, reg, s2, 1000, verify=stand_in) == (False, "the nonce was already used"))
    for name, r, v, g, s, now in (
            ("no signature", {**req, "sig": ""}, view, reg, st(), 1000),
            ("a request for another transaction than the open one", {**req, "txn": "t9"}, view, reg, st(), 1000),
            ("a request naming another AE-ID", {**req, "aeId": "Cother"}, view, reg, st(), 1000),
            ("the target equal to the source", req, {**view, "target": "cse-a"}, reg, st(), 1000),
            ("an AE-ID the registry does not hold", req, view, {}, st(), 1000),
            ("the valid-until reached (now = valid-until)", req, view, reg, st(), 2000),
            ("no nonce issued for the transaction", req, view, reg, {"nonce": {}, "used": set()}, 1000),
            ("a nonce already used", req, view, reg, {"nonce": {"t1": "n1"}, "used": {"n1"}}, 1000),
            ("a signature over another nonce", req, view, reg, {"nonce": {"t1": "n2"}, "used": set()}, 1000),
            ("a signature over another valid-until", req, {**view, "validUntil": 2001}, reg, st(), 1000),
            ("a signature over another source", req, {**view, "source": "cse-z"}, reg, st(), 1000),
            ("a valid-until that is text", req, {**view, "validUntil": "2000"}, reg, st(), 1000)):
        control(f"{name} was admitted", lambda r=r, v=v, g=g, s=s, now=now: ra.admit(r, v, g, s, now, verify=stand_in)[0])
    # a handover onto the source, signed correctly for exactly that (source = target = cse-a): still refused
    same = {**view, "target": "cse-a"}
    sig_same = "sig-of:" + ra.challenge_hex(ra.message("Cdev", "cse-a", "cse-a", "t1", 2000, "n1"))
    control("a handover onto the source with a right signature over it was admitted",
            lambda: ra.admit({**req, "sig": sig_same}, same, reg, st(), 1000, verify=stand_in)[0])
    check("a request without a signature is refused before any verifier is asked",
          lambda: ra.admit({**req, "sig": ""}, view, reg, st(), 1000, verify=lambda *a: True) == (False, "no signature was presented"))
    s3 = st()
    check("a refusal does not use the nonce up", lambda: not ra.admit({**req, "sig": "bad"}, view, reg, s3, 1000, verify=stand_in)[0] and s3["used"] == set())
    check("each refusal names its reason", lambda: ra.admit(req, view, {}, st(), 1000, verify=stand_in)[1] == "the registry holds no key for this AE-ID"
          and ra.admit(req, view, reg, st(), 2000, verify=stand_in)[1] == "the transaction is past its valid-until")

    print("== two devices enrolled (a stand-in verifier that knows the key: it accepts exactly 'sig-by:' + the enrolled key + ':' + the digest)")
    by_key = lambda leaf, ch, sig: sig == f"sig-by:{leaf}:{ch}"  # noqa: E731
    reg2 = {"Cdev": {"leaf_der_b64": "key-1"}, "Cdev2": {"leaf_der_b64": "key-2"}}
    view2 = {**view, "aeId": "Cdev2"}
    dg1, dg2 = (ra.challenge_hex(ra.message(ae, "cse-a", "cse-b", "t1", 2000, "n1")) for ae in ("Cdev", "Cdev2"))
    two = lambda ae, v, key, dg: ra.admit({"aeId": ae, "txn": "t1", "sig": f"sig-by:{key}:{dg}"}, v, reg2, st(), 1000, verify=by_key)  # noqa: E731
    check("each device is admitted with its own key over its own transaction",
          lambda: two("Cdev", view, "key-1", dg1) == (True, "admitted") and two("Cdev2", view2, "key-2", dg2) == (True, "admitted"))
    control("device 1 was admitted with device 2's key over the right message", lambda: two("Cdev", view, "key-2", dg1)[0])
    control("device 2 was admitted with device 1's key over the right message", lambda: two("Cdev2", view2, "key-1", dg2)[0])
    control("device 1 was admitted with what admits device 2 (its key over its own message)", lambda: two("Cdev", view, "key-2", dg2)[0])
    check("the reason given both times is the signature", lambda: two("Cdev", view, "key-2", dg1) == (False, SIG_REASON) and two("Cdev2", view2, "key-1", dg2) == (False, SIG_REASON))

    print("== the command line: the originator and label a key is enrolled under, and the phone asked to sign "
          "(the lab and the phone are cut off: stand-ins answer, nothing is sent)")
    base = ["--attest", "/nonexistent/attest.json", "--status", "/nonexistent/status.json"]
    modes = {"sim": ["--device", "sim"], "adb": ["--device", "adb", "--results", "/nonexistent/results.json"]}
    own = {"--origin": "Cvehicle-x", "--label": "phone-A", "--serial-env": "ANDROID_SERIAL"}       # another phone's own three
    rsu = {"--origin": "Crsu-NP2A", "--label": "phone-B", "--serial-env": "RSU_SERIAL"}            # the roadside phone's, by hand
    line = lambda mode, ae, opts, records=base: [*modes[mode], *records, *(["--ae", ae] if ae else []),  # noqa: E731
                                                 *(x for o, v in opts.items() if v is not None for x in (o, v))]
    check("with no --ae, or --ae rsu, and none of the three options the driver goes on as the roadside phone (originator Crsu-NP2A), sim and adb",
          lambda: all(run_main(line(m, ae, {})).origin == "Crsu-NP2A" for m in modes for ae in (None, "rsu")))
    check("another AE with its own --origin, --label and --serial-env goes on under that originator, sim and adb",
          lambda: all(run_main(line(m, "phone", own)).origin == "Cvehicle-x" for m in modes))
    check("the default AE with an --origin of its own goes on under that one; with a --label and --serial-env of its own it goes on as the roadside phone",
          lambda: run_main(line("sim", None, {"--origin": "Cother-x"})).origin == "Cother-x" and run_main(line("adb", "rsu", {"--origin": "Cother-x"})).origin == "Cother-x"
          and run_main(line("sim", "rsu", {"--label": "phone-Z", "--serial-env": "OTHER_SERIAL"})).origin == "Crsu-NP2A")
    wrong = [(f"{m}: --ae phone with {o} {how}", line(m, "phone", {**own, o: v}), {o})
             for m in modes for o in own for how, v in (("not given", None), ("given empty", ""), ("given as the roadside phone's", rsu[o]))]
    wrong += [(f"{m}: an AE of any other name with none of the three options", line(m, "truck", {}), set(own)) for m in modes]
    wrong += [(f"{m}: --ae phone with only --label of its own", line(m, "phone", {"--label": "phone-A"}), {"--origin", "--serial-env"}) for m in modes]
    for name, argv, _ in wrong:
        def went_on(argv=argv):
            g = run_main(argv)
            return not (g.code == 2 and g.origin is None and g.requests == 0 and not g.asked)
        control(f"{name} went on towards the lab", went_on)
    check("each of those is refused with exit 2 and one plain line, before any request",
          lambda: all(g.code == 2 and g.requests == 0 and g.text.startswith("refused: ") and g.text.count("\n") == 1 for g in (run_main(argv) for _, argv, _ in wrong)))
    named = lambda text: set(text.partition("needs its own ")[2].partition(";")[0].split(", "))  # noqa: E731
    check("and the line names each option that is lacking and none that is not",
          lambda: all(named(run_main(argv).text) == opts for _, argv, opts in wrong))

    print("== enrolment and real signatures (records of 2026-10-15)")
    files = [D / "seal" / p / f for p in ("P1", "P2") for f in ("attest.json", "sign.json")] + [STATUS]
    if not all(f.exists() for f in files):
        NOT_RUN.append("enrolment and signature rows: the records of 2026-10-15 are not on this disk")
        print(f"  NOT-RUN  {NOT_RUN[-1]}")
    else:
        a1, s1, a2, s2_, status = (json.loads(f.read_text()) for f in files)
        as_of, _ = av.status_fetch_time(STATUS, status)
        r1, why1 = ra.enrol(a1, status, as_of, "Cdev", "phone-B")
        r2, _ = ra.enrol(a2, status, as_of, "Cdev2", "phone-C")
        check("both records enrol as of the day they were made (kept key, no user binding, chain verifies)",
              lambda: r1 is not None and r2 is not None and r1["alias"] == "witness-20261015" and r1["attestation"] in ra.ENROL_OK)
        check("the registry record names the leaf certificate by its SHA-256 and holds no private part",
              lambda: r1["leaf_sha256"] == hashlib.sha256(__import__("base64").b64decode(a1["chain"][0])).hexdigest()
              and set(r1) == {"aeId", "label", "alias", "leaf_der_b64", "leaf_sha256", "attestation", "attestation_warnings", "verified_as_of",
                              "verified_as_of_source", "security_level", "keymint_security_level", "policy", "checks_made", "checks_warned",
                              "checks_not_asked", "checks_not_made"})
        check("each record holds the AE-ID and the label it was enrolled with, each under its own name",
              lambda: r1 is not None and r2 is not None and (r1["aeId"], r1["label"], r2["aeId"], r2["label"]) == ("Cdev", "phone-B", "Cdev2", "phone-C"))
        control("phone 1's record enrolled as of today (its intermediate certificate ran out on 2026-10-19)",
                lambda: ra.enrol(a1, status, TODAY, "Cdev", "x")[0] is not None)
        control("a record with another challenge than the one in its leaf certificate enrolled",
                lambda: ra.enrol({**a1, "challenge": "00" * 32}, status, as_of, "Cdev", "x")[0] is not None)
        control("a record whose key was not kept enrolled",
                lambda: ra.enrol({**a1, "params": {**a1["params"], "key_kept": False}}, status, as_of, "Cdev", "x")[0] is not None)
        control("a record whose key needs user authentication enrolled",
                lambda: ra.enrol({**a1, "params": {**a1["params"], "auth": "strong"}}, status, as_of, "Cdev", "x")[0] is not None)
        control("a record with phone 2's leaf certificate in phone 1's chain enrolled",
                lambda: ra.enrol({**a1, "chain": [a2["chain"][0], *a1["chain"][1:]]}, status, as_of, "Cdev", "x")[0] is not None)
        control("a record with phone 2's proof-of-possession signature in place of its own enrolled",
                lambda: ra.enrol({**a1, "pop_sig": a2["pop_sig"]}, status, as_of, "Cdev", "x")[0] is not None)
        control("a record without a proof-of-possession signature enrolled",
                lambda: ra.enrol({k: v for k, v in a1.items() if k != "pop_sig"}, status, as_of, "Cdev", "x")[0] is not None)

        def why_not(rec):
            try:
                got = ra.enrol(rec, status, as_of, "Cdev", "x")
            except Exception as e:  # noqa: BLE001  enrolment has to refuse, not raise
                return f"RAISED {type(e).__name__}"
            return "ENROLLED" if got[0] is not None else got[1]
        control("a record with only its leaf certificate in the chain enrolled", lambda: why_not({**a1, "chain": a1["chain"][:1]}) == "ENROLLED")
        check("it is refused, not raised on, and the reason says the chain and that the three needed checks were not evaluated",
              lambda: (lambda w: "chain_parse" in w and w.count(": not evaluated") == 3)(why_not({**a1, "chain": a1["chain"][:1]})))
        control("a record without a chain enrolled", lambda: ra.enrol({k: v for k, v in a1.items() if k != "chain"}, status, as_of, "Cdev", "x")[0] is not None)
        check("the signature on file verifies with the enrolled key over its own challenge (both phones)",
              lambda: ra.verify_sig(r1["leaf_der_b64"], s1["challenge"], s1["sig"]) and ra.verify_sig(r2["leaf_der_b64"], s2_["challenge"], s2_["sig"]))
        control("phone 1's signature verified with phone 2's key", lambda: ra.verify_sig(r2["leaf_der_b64"], s1["challenge"], s1["sig"]))
        control("a signature verified over another challenge", lambda: ra.verify_sig(r1["leaf_der_b64"], "00" * 32, s1["sig"]))
        control("a signature with one byte changed verified",
                lambda: ra.verify_sig(r1["leaf_der_b64"], s1["challenge"], s1["sig"][:-6] + ("A" if s1["sig"][-6] != "A" else "B") + s1["sig"][-5:]))
        control("text that is not a signature verified", lambda: ra.verify_sig(r1["leaf_der_b64"], s1["challenge"], "not base64 !"))
        # the real verifier in the decision: a real signature by the enrolled key, over an older challenge, shown for a new transaction
        control("a real signature by the enrolled key over an older challenge was admitted for a new transaction (real verifier)",
                lambda: ra.admit({"aeId": "Cdev", "txn": "t1", "sig": s1["sig"]}, view, {"Cdev": r1}, st(), 1000)[0])
        check("and the reason given is the signature, not something earlier",
              lambda: ra.admit({"aeId": "Cdev", "txn": "t1", "sig": s1["sig"]}, view, {"Cdev": r1}, st(), 1000)[1] == SIG_REASON)
        other_key_rows("2026-10-15", view, st, r1, s1, r2, s2_)

        print("== enrolment needs a hardware-backed key and a locked, verified-boot device (stand-in: the key description is changed after the parser)")
        hw, locked, booted = "not shown to be hardware-backed", "not shown to be locked", "not shown to have booted verified"
        lacking = (("the attestation was made at the Software level", lambda kd: kd.update(attestationSecurityLevel="Software"), {hw}),
                   ("the key itself is held at the Software level", lambda kd: kd.update(keyMintSecurityLevel="Software"), {hw}),
                   ("the device is not locked", lambda kd: kd["hardwareEnforced"]["rootOfTrust"].update(deviceLocked=False), {locked}),
                   ("the boot state is Unverified", lambda kd: kd["hardwareEnforced"]["rootOfTrust"].update(verifiedBootState="Unverified"), {booted}),
                   ("the boot state is SelfSigned", lambda kd: kd["hardwareEnforced"]["rootOfTrust"].update(verifiedBootState="SelfSigned"), {booted}),
                   ("lock and boot state are only software-enforced",
                    lambda kd: kd["softwareEnforced"].update(rootOfTrust=kd["hardwareEnforced"].pop("rootOfTrust")), {locked, booted}))
        check("with the stand-in in place and nothing changed the record enrols, so each refusal below is the change alone",
              lambda: enrol_as(lambda kd: None, a1, status, as_of)[0] is not None)
        for name, alter, _ in lacking:
            control(f"a record whose leaf certificate says {name} enrolled", lambda alter=alter: enrol_as(alter, a1, status, as_of)[0] is not None)
        check("each of those refusals says what is lacking, and nothing that is not",
              lambda: all({w for w in (hw, locked, booted) if w in enrol_as(alter, a1, status, as_of)[1]} == words for _, alter, words in lacking))
        check("the record holds the security level the leaf certificate gives for the attestation (TEE on both phones)",
              lambda: r1["security_level"] == "TrustedEnvironment" and r2["security_level"] == "TrustedEnvironment")
        check("and the level of the key itself (KeyMint), under its own name",
              lambda: r1.get("keymint_security_level") == "TrustedEnvironment" and r2.get("keymint_security_level") == "TrustedEnvironment")

        def unasked(attest):
            with verifier_not_asked():
                return ra.enrol(attest, status, as_of, "Cdev", "x")
        control("a good record enrolled although the verifier did not evaluate level, lock and boot state (stand-in: the policy is dropped on its way)",
                lambda: unasked(a1)[0] is not None or unasked(a2)[0] is not None)
        check("and the refusal then says of each of the three that it was not shown",
              lambda: all(w in unasked(a1)[1] for w in (hw, locked, booted)) and "not required" in unasked(a1)[1])
        levels = lambda att, key: (lambda r: r and (r["security_level"], r.get("keymint_security_level")))(  # noqa: E731
            enrol_as(lambda kd: kd.update(attestationSecurityLevel=att, keyMintSecurityLevel=key), a1, status, as_of)[0])
        check("a StrongBox key enrols too and each level is stored as read, under its own name (same stand-in: StrongBox for both, then for the key alone)",
              lambda: levels("StrongBox", "StrongBox") == ("StrongBox", "StrongBox")
              and levels("TrustedEnvironment", "StrongBox") == ("TrustedEnvironment", "StrongBox"))

        # the driver's own enrolment lines, with the lab cut off and the run stopped at its first write
        drive = lambda **kw: run_main(["--device", "sim", "--attest", str(files[0]), "--status", str(STATUS)],  # noqa: E731
                                      stop=lambda method, url: method == "POST", **kw)
        check("the driver enrols phone 1's record under that policy and says the levels and where the day came from (stopped at its first write)",
              lambda: (lambda g: g.code is None and g.origin == "Crsu-NP2A" and "day taken from: filename" in g.text
                       and "PASS  the attestation record verifies as of the day it was made, shows a hardware-backed key" in g.text
                       and "attestation level TrustedEnvironment, key level TrustedEnvironment" in g.text)(drive()))
        check("what the driver hands to its results file about the enrolment is the record without the certificate and the names "
              "(the same stop, as an error, so the run ends and reports)",
              lambda: (lambda e: r1 is not None and e == {k: v for k, v in {**r1, "verified_as_of_source": "filename"}.items()
                                                          if k not in ("aeId", "label", "leaf_der_b64")}
                       and len(e) == 13 and len(e["checks_not_made"]) == 7 and e["security_level"] == "TrustedEnvironment")(drive(as_error=True).meas["enrolment"]))

        def driver_wrote(alter):
            with leaf_says(alter):
                g = drive()
            return not (g.code == 1 and "FAIL  the attestation record verifies as of the day it was made" in g.text)
        control("the driver went on to write the registry from a record whose leaf certificate says Software level", lambda: driver_wrote(lacking[1][1]))
        control("the driver went on to write the registry from a record whose leaf certificate says the device is not locked", lambda: driver_wrote(lacking[2][1]))

        # where the key is enrolled: the record in the body of the driver's registry write (the run is stopped at that write)
        records = ["--attest", str(files[0]), "--status", str(STATUS)]
        wrote = lambda ae, opts, **kw: run_main(line("sim", ae, opts, records), stop=lambda method, url: method == "POST" and url.endswith("/keys"), **kw)  # noqa: E731
        check("the record in the driver's registry write holds the given originator as AE-ID and the given label (another AE; stopped at that write)",
              lambda: (lambda w: len(w) == 1 and w[0][0] == "CestimedReg" and (w[0][1]["aeId"], w[0][1]["label"]) == ("Cvehicle-x", "phone-A")
                       and w[0][1]["leaf_sha256"] == r1["leaf_sha256"])(wrote("phone", own).wrote))
        check("for the default AE it holds the roadside phone's originator and label, and a given --label in place of the default one",
              lambda: [(x["aeId"], x["label"]) for _, x in wrote(None, {}).wrote + wrote("rsu", {"--label": "phone-Z"}).wrote]
              == [("Crsu-NP2A", "phone-B"), ("Crsu-NP2A", "phone-Z")])
        control("the record in the registry write of a run for another AE holds the roadside phone's originator or label, or nothing was written",
                lambda: (lambda w: not w or any(x["aeId"] == "Crsu-NP2A" or x["label"] == "phone-B" for _, x in w))(wrote("phone", own).wrote))
        check("the label the driver hands to its results file is the given one, and phone-B for the default AE (the same stop, as an error)",
              lambda: [(g.meas or {}).get("label") for g in (wrote("phone", own, as_error=True), wrote(None, {}, as_error=True))] == ["phone-A", "phone-B"])

        def phone_run(ae, opts):
            """A phone run up to the signature: the lab stand-in keeps what is created, the phone stand-in notes who
            was asked and stops the run. The serials are stand-in words, in this process's environment for the call only."""
            with mock.patch.dict(os.environ, {"RSU_SERIAL": "roadside-stand-in", "REAUTH_TEST_SERIAL": "vehicle-stand-in"}):
                os.environ.pop("REAUTH_TEST_NOT_SET", None)
                return run_main(line("adb", ae, opts, records), stop=lambda method, url: False, lab=lab_in_memory())
        veh = {**own, "--serial-env": "REAUTH_TEST_SERIAL"}
        check("a phone run for another AE asks the phone its own --serial-env names to sign: once, the enrolled alias, a digest of 64 hex digits "
              "(stand-ins for the lab and the phone; stopped at that request)",
              lambda: (lambda q: len(q) == 1 and q[0][:2] == ("vehicle-stand-in", r1["alias"]) and len(q[0][2]) == 64)(phone_run("phone", veh).asked))
        check("the default run asks the phone $RSU_SERIAL names, and a default run with a --serial-env of its own the phone that one names",
              lambda: [[s for s, _, _ in g.asked] for g in (phone_run(None, {}), phone_run("rsu", {"--serial-env": "REAUTH_TEST_SERIAL"}))]
              == [["roadside-stand-in"], ["vehicle-stand-in"]])
        control("a phone run for another AE asked no phone to sign, or another one than its --serial-env names",
                lambda: (lambda q: not q or any(s != "vehicle-stand-in" for s, _, _ in q))(phone_run("phone", veh).asked))
        control("a phone run whose --serial-env names a variable that is not set asked a phone to sign, or did not stop at the missing serial",
                lambda: (lambda g: not (g.code == 1 and not g.asked and "FAIL  the phone's serial is given in $REAUTH_TEST_NOT_SET" in g.text))(
                    phone_run("phone", {**own, "--serial-env": "REAUTH_TEST_NOT_SET"})))

        print("== what the registry record says about its own enrolment")
        made = {"root_pinned", "root_self_signature", "root_validity", "chain_signatures", "intermediates_validity", "extension_only_in_leaf",
                "revocation", "key_description_parse", "challenge", "proof_of_possession", "hw_tee", "device_locked", "verified_boot_state",
                "software_enforced_auth"}                       # by hand, from the verifier's list of checks
        check("it lists the checks made by the verifier's names (14 for phone 1) and the policy they were made under",
              lambda: set(r1.get("checks_made") or []) == made and len(r1["checks_made"]) == 14 and r1.get("checks_warned") == []
              and r1.get("policy") == {"require_hw_tee": True, "require_locked_verified": True})
        check("phone 2's embedded root certificate had run out by that day: listed as a warning, not among the checks made",
              lambda: r2.get("checks_warned") == ["root_validity"] and set(r2.get("checks_made") or []) == made - {"root_validity"})
        check("what the policy does not ask for is listed apart (user authentication and its timeout)",
              lambda: r1.get("checks_not_asked") == ["user_auth", "auth_timeout"] and not set(r1["checks_made"]) & set(r1["checks_not_asked"]))
        control("the age of the status list is listed as a check made (the day of the check is the list's own day: its age is 0 every time)",
                lambda: "status_freshness" in r1["checks_made"] or "status_freshness" in r2["checks_made"])
        check("it says in plain sentences what enrolment could not check: freshness, the day itself, anything later, the record's own fields, "
              "the AE-ID, the app, the key's origin",
              lambda: (lambda nm: len(nm) == 7 and all(isinstance(x, str) and x for x in nm) and r2.get("checks_not_made") == nm
                       and "freshness" in nm[0] and "taken from the record itself" in nm[0] and "age is 0" in nm[1] and "after that day" in nm[2]
                       and "record's own fields" in nm[3] and "AE-ID" in nm[4] and "app" in nm[5] and "imported" in nm[6])(r1.get("checks_not_made") or []))
        check("the day of the check is stored with where it came from when the caller says so, and as not given otherwise",
              lambda: r1.get("verified_as_of_source", "absent") is None
              and ra.enrol(a1, status, as_of, "Cdev", "x", as_of_source="filename")[0]["verified_as_of_source"] == "filename")
        check("the record comes back equal from the JSON text the registry stores (the driver compares it after reading back)",
              lambda: r1 is not None and r2 is not None and json.loads(json.dumps(r1, sort_keys=True)) == r1 and json.loads(json.dumps(r2, sort_keys=True)) == r2)

        def policy_after_a_change():
            ra.enrol(a1, status, as_of, "Cdev", "x")[0]["policy"]["require_hw_tee"] = False      # a caller changes its own record
            again = ra.enrol(a1, status, as_of, "Cdev", "x")[0]
            return again is not None and again["policy"]
        check("the policy in a record is that record's own copy: changing it there changes nothing for the next enrolment",
              lambda: policy_after_a_change() == {"require_hw_tee": True, "require_locked_verified": True})

    print("== the records of 2026-10-29: two phones, one alias on both")
    files29 = [D29 / "seal-phone2" / p / f for p in ("P1", "P2") for f in ("attest.json", "sign.json")] + [STATUS29]
    if not all(f.exists() for f in files29):
        NOT_RUN.append("the rows on the records of 2026-10-29: they are not on this disk")
        print(f"  NOT-RUN  {NOT_RUN[-1]}")
    else:
        b1, t1, b2, t2, status29 = (json.loads(f.read_text()) for f in files29)
        q1, _ = ra.enrol(b1, status29, AS_OF29, "Cdev", "phone-A")
        q2, _ = ra.enrol(b2, status29, AS_OF29, "Cdev2", "phone-B")
        check("both records enrol as of that day under the stricter policy: one alias, two keys, TEE on both, no warning",
              lambda: q1 is not None and q2 is not None and q1["alias"] == q2["alias"] == "witness-20261029" and q1["leaf_sha256"] != q2["leaf_sha256"]
              and q1["security_level"] == q2["security_level"] == "TrustedEnvironment"
              and q1.get("keymint_security_level") == q2.get("keymint_security_level") == "TrustedEnvironment"
              and q1["attestation"] == q2["attestation"] == "PASS" and {"hw_tee", "device_locked", "verified_boot_state"} <= set(q1["checks_made"]) & set(q2["checks_made"]))
        control("phone 1's record of that day enrolled as of today (its intermediate certificate ran out on 2026-11-05)",
                lambda: ra.enrol(b1, status29, TODAY, "Cdev", "x")[0] is not None)
        control("phone 2's record of that day enrolled as of today (its intermediate certificate ran out on 2026-11-04)",
                lambda: ra.enrol(b2, status29, TODAY, "Cdev2", "x")[0] is not None)
        check("each signature on file verifies with its own phone's enrolled key over its own challenge",
              lambda: ra.verify_sig(q1["leaf_der_b64"], t1["challenge"], t1["sig"]) and ra.verify_sig(q2["leaf_der_b64"], t2["challenge"], t2["sig"]))
        other_key_rows("2026-10-29", view, st, q1, t1, q2, t2)

    bad = [n for n, ok in RESULTS if not ok]
    alive = [n for n, went in CONTROLS if went]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed; controls {len(CONTROLS)}, all failed as they must: {not alive}; NOT-RUN {len(NOT_RUN)}")
    return 1 if bad or alive or NOT_RUN else 0


if __name__ == "__main__":
    sys.exit(main())
