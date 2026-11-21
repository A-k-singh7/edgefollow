#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Re-authentication of a phone at the target edge of a handover.

  registry   an AE on the IN-CSE holds, per AE-ID, the public key of a key the phone made and attested
             (probe mode `attest`, a key kept on the phone under an alias). Enrolment here reads an attestation
             record ON FILE and checks its certificate chain as of the day the record was made. It refuses a record
             whose leaf certificate does not show a hardware-backed key (TEE or StrongBox) on a locked device that
             booted verified, and says why. The registry record lists the checks made and what enrolment could not
             check. No key is made, on the phone or on this PC.
  exchange   for one handover transaction (handover.take_lock: an identifier and a valid-until at the IN-CSE) the
             target issues a nonce; the phone signs SHA-256 over {AE-ID, source, target, transaction identifier,
             valid-until, nonce} with that key (probe mode `sign`, no prompt); the target builds the same message
             from ITS OWN view of the transaction and admits the phone only when the signature verifies with the
             registry's key. Admitted here means: the target lets the phone's AE be created. It is not the full
             handover; phone/estimed_poc2.py does not call this yet.
  controls   a signature by another key; the good signature shown for another transaction; the same signature
             shown twice; a transaction past its valid-until; an AE-ID the registry does not know; target = source;
             a stranger writing a key into the registry

--device sim: the simulated phone holds no key and none is made for it, so the admission itself is NOT-RUN; the
refusals run with a signature on file (a real signature by the enrolled key over an older challenge).
Not shown, and said so in the results file: who holds the phone; an authenticated originator (the lab CSEs take
the originator header as given, so the registry's access policy binds honest parties only); a key bound to the
user's presence (the alias used has no such binding); freshness of the attestation. Not a conformance claim.

    python phone/reauth.py --device sim --attest <attest.json> --status <status.json> --old-sign <sign.json>

The defaults are the roadside phone's (AE rsu: its originator, its label phone-B, its serial in $RSU_SERIAL). Any
other --ae needs its own --origin, --label and --serial-env, in a sim run too: the key in --attest is enrolled under
the originator and the label, and a phone run asks the phone the variable names to sign, so a default there would
put one phone's key under the other's name or ask the other phone.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "estimed"))
sys.path.insert(0, str(HERE.parent / "estimed_poc"))
import attest_verify_android as av  # noqa: E402
import estimed_poc2 as poc  # noqa: E402
import handover as ho  # noqa: E402

PURPOSE = "estimed.handover.reauth.v1"
REG_AE, REG_ORIGIN, TARGET_ORIGIN = "estimedReg", "CestimedReg", "CedgeB-admit"
IN_URL = f"{ho.IN_CSE[0]}/{ho.IN_CSE[1]}"
ENROL_OK = ("PASS", "PASS_WITH_WARNINGS")
RSU_AE, RSU_ORIGIN = "rsu", "Crsu-NP2A"        # the roadside phone: the only AE with defaults for the three options below
RSU_OWN = {"--origin": RSU_ORIGIN, "--label": "phone-B", "--serial-env": "RSU_SERIAL"}
ENROL_POLICY = {"require_hw_tee": True, "require_locked_verified": True}    # the rest is the verifier's default
ENROL_NEEDS = {"hw_tee": "the key is not shown to be hardware-backed (TEE or StrongBox)",
               "device_locked": "the device is not shown to be locked",
               "verified_boot_state": "the device is not shown to have booted verified"}
ENROL_NOT_MADE = (
    "freshness: the expected challenge is taken from the record itself, so the challenge check shows only that the "
    "leaf certificate carries the challenge the record names",
    "the day itself: verified_as_of is the day the status list is said to be fetched, and on that day its age is 0 "
    "every time, so the age of the list is not judged",
    "anything after that day: a later revocation, a later unlock of the device, whether the key still exists",
    "a kept key under this alias, without user binding: read from the record's own fields, not from the certificate",
    "that the key belongs to the device the AE-ID names: AE-ID and label are given by whoever enrols",
    "which app holds the key: the app identity in the certificate is not compared with anything",
    "that the key was made in the secure hardware and not imported: the origin in the certificate is not judged")
NOT_RUN: list[dict] = []


def message(ae_id: str, source: str, target: str, txn: str, valid_until: int, nonce: str) -> bytes:
    """The bytes both sides build. Sorted keys, no spaces; valid_until is whole epoch seconds."""
    for name, v in (("ae_id", ae_id), ("source", source), ("target", target), ("txn", txn), ("nonce", nonce)):
        if not isinstance(v, str) or not v:
            raise ValueError(f"{name} must be a non-empty string")
    if isinstance(valid_until, bool) or not isinstance(valid_until, int):
        raise ValueError("valid_until must be whole seconds")
    return json.dumps({"aeId": ae_id, "nonce": nonce, "purpose": PURPOSE, "source": source, "target": target,
                       "txn": txn, "validUntil": valid_until}, sort_keys=True, separators=(",", ":")).encode()


def challenge_hex(msg: bytes) -> str:
    """What the phone is asked to sign: the SHA-256 of the message, as 64 hex digits (probe mode `sign` signs the
    bytes of its challenge with ECDSA and SHA-256)."""
    return hashlib.sha256(msg).hexdigest()


def enrol(attest: dict, status: dict, as_of, ae_id: str, label: str, as_of_source: str | None = None) -> tuple[dict | None, str]:
    """A registry record from an attestation record, or (None, why not). The chain, the challenge inside the leaf
    and the record's own proof-of-possession signature are checked by attest_verify_android as of `as_of`, under
    ENROL_POLICY. Each check named in ENROL_NEEDS must have been made and passed: one that was not evaluated
    refuses too. The record says which checks were made and what could not be checked (ENROL_NOT_MADE)."""
    try:
        par = attest.get("params") or {}
        if attest.get("ok") is not True or par.get("key_kept") is not True or not par.get("alias"):
            return None, "the record does not say a key was made and kept under an alias"
        if par.get("auth") not in (None, "none"):
            return None, "the key is bound to user authentication; probe mode `sign` cannot use it"
        chain = [base64.b64decode(c, validate=True) for c in attest["chain"]]
        res = av.verify(chain, bytes.fromhex(attest["challenge"]), status, as_of, av.Policy(**ENROL_POLICY),
                        pop_sig=base64.b64decode(attest["pop_sig"]) if attest.get("pop_sig") else None, at=as_of)
    except (KeyError, ValueError, TypeError) as e:
        return None, f"the record could not be read: {type(e).__name__}: {e}"
    checks = res.get("checks") or {}
    lacks = [f"{why}: {(checks.get(n) or {}).get('detail', 'not evaluated')}" for n, why in ENROL_NEEDS.items()
             if (checks.get(n) or {}).get("ok") is not True]
    if res["verdict"] not in ENROL_OK or lacks:
        return None, "; ".join(([f"the attestation does not verify as of {as_of.isoformat()}: {res['failed']}"]
                                if res["verdict"] not in ENROL_OK else []) + lacks)
    kd = res.get("key_description") or {}
    return {"aeId": ae_id, "label": label, "alias": par["alias"], "leaf_der_b64": attest["chain"][0],
            "leaf_sha256": hashlib.sha256(chain[0]).hexdigest(), "attestation": res["verdict"],
            "attestation_warnings": res["warnings"], "verified_as_of": as_of.isoformat(),
            "verified_as_of_source": as_of_source, "security_level": kd.get("attestationSecurityLevel"),
            "keymint_security_level": kd.get("keyMintSecurityLevel"), "policy": dict(ENROL_POLICY),
            "checks_made": [n for n, c in checks.items() if c["ok"] is True and n != "status_freshness"],
            "checks_warned": [n for n, c in checks.items() if c["ok"] is False],
            "checks_not_asked": [n for n, c in checks.items() if c["ok"] is None],
            "checks_not_made": list(ENROL_NOT_MADE)}, "enrolled"


def verify_sig(leaf_der_b64: str, challenge: str, sig_b64: str) -> bool:
    """ECDSA P-256 with SHA-256 over the challenge's bytes, with the public key of the enrolled leaf certificate."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        pub = x509.load_der_x509_certificate(base64.b64decode(leaf_der_b64)).public_key()
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        pub.verify(base64.b64decode(sig_b64), bytes.fromhex(challenge), ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def admit(req: dict, view: dict, registry: dict, state: dict, now: float, verify=verify_sig) -> tuple[bool, str]:
    """The target's decision. req: what the phone side presents {aeId, txn, sig}. view: what the target itself read
    of the transaction {aeId, source, target, txn, validUntil}. registry: {aeId: record}. state: {"nonce": {txn:
    nonce the target issued}, "used": set of nonces already admitted on}. Nothing the phone side presents is used to
    build the message except the signature. Every refusal names its reason; the first that applies is returned."""
    if not isinstance(req, dict) or not isinstance(req.get("sig"), str) or not req.get("sig"):
        return False, "no signature was presented"
    if req.get("aeId") != view.get("aeId") or req.get("txn") != view.get("txn"):
        return False, "the request names another AE-ID or transaction than the one open at the IN-CSE"
    if view.get("source") == view.get("target"):
        return False, "the target is the source"
    rec = registry.get(view["aeId"])
    if rec is None:
        return False, "the registry holds no key for this AE-ID"
    if not isinstance(view.get("validUntil"), int) or now >= view["validUntil"]:
        return False, "the transaction is past its valid-until"
    nonce = state["nonce"].get(view["txn"])
    if nonce is None:
        return False, "the target issued no nonce for this transaction"
    if nonce in state["used"]:
        return False, "the nonce was already used"
    ch = challenge_hex(message(view["aeId"], view["source"], view["target"], view["txn"], view["validUntil"], nonce))
    if not verify(rec["leaf_der_b64"], ch, req["sig"]):
        return False, "the signature does not verify with the enrolled key over this transaction"
    state["used"].add(nonce)
    return True, "admitted"


# ------------------------------------------------------------------------------------------------ the live part
def not_run(row: str, reason: str) -> None:
    NOT_RUN.append({"row": row, "result": "NOT-RUN", "reason": reason})
    print(f"  NOT-RUN  {row}\n          {reason}")


def open_txn(origin: str) -> dict | None:
    """Open a handover transaction A -> B for `origin` and read it back as the target sees it."""
    a_csi, b_csi = ho.EDGE_A[1], ho.EDGE_B[1]
    txn = ho.take_lock(a_csi, b_csi, origin=origin)
    if not txn:
        return None
    st, b = ho._req("GET", f"{IN_URL}/{ho.lock_name(origin)}", TARGET_ORIGIN)
    if st != 200:               # the target has no read access of its own in this lab: read as the orchestrator
        st, b = ho._req("GET", f"{IN_URL}/{ho.lock_name(origin)}", ho.ORCHESTRATOR)
    lbl = dict(x.split(":", 1) for x in ((b or {}).get("m2m:cnt") or {}).get("lbl", []) if ":" in x)
    if st != 200 or lbl.get("txn") != txn:
        return None
    return {"aeId": origin, "source": lbl.get("from"), "target": lbl.get("to"), "txn": txn, "validUntil": int(float(lbl["until"]))}


def main(argv=None) -> int:  # noqa: C901, PLR0915  one timeline, like the neighbouring drivers
    ap = argparse.ArgumentParser(description="re-authentication at the target edge (plan row B2)")
    ap.add_argument("--device", choices=("adb", "sim"), default="sim")
    ap.add_argument("--attest", required=True, help="the attestation record on file of the phone's kept key")
    ap.add_argument("--status", required=True, help="the attestation status list fetched in the same session")
    ap.add_argument("--old-sign", help="sim: a sign.json on file by the same key (an older challenge), for the refusals")
    ap.add_argument("--ae", default=RSU_AE)
    ap.add_argument("--origin", help=f"the originator the key is enrolled under; only --ae {RSU_AE} has a default ({RSU_ORIGIN})")
    ap.add_argument("--label", help=f"the label in the registry record and the results; only --ae {RSU_AE} has a default ({RSU_OWN['--label']})")
    ap.add_argument("--serial-env", help="adb: the environment variable holding the phone's serial; "
                                         f"only --ae {RSU_AE} has a default ({RSU_OWN['--serial-env']})")
    ap.add_argument("--wrong-alias", default="ctl", help="adb: another key the same phone holds, for the wrong-key control")
    ap.add_argument("--results")
    a = ap.parse_args(argv)
    given = {"--origin": a.origin, "--label": a.label, "--serial-env": a.serial_env}
    lacking = [o for o, v in given.items() if not v or v == RSU_OWN[o]]
    if a.ae != RSU_AE and lacking:
        print(f"refused: --ae {a.ae} needs its own {', '.join(lacking)}; {RSU_ORIGIN}, {RSU_OWN['--label']} and ${RSU_OWN['--serial-env']} are those "
              f"of AE {RSU_AE} (the roadside phone): the key in --attest would be enrolled under that originator and label, and a phone run "
              "would ask the phone that variable names to sign")
        return 2
    a.origin, a.label, a.serial_env = a.origin or RSU_ORIGIN, a.label or RSU_OWN["--label"], a.serial_env or RSU_OWN["--serial-env"]
    if a.device == "adb" and not a.results:
        print("refused: a phone run needs --results")
        return 2
    results = a.results or str(poc.SIM_DIR / f"reauth_sim_{time.strftime('%Y%m%dT%H%M%S')}.json")
    poc.STEPS.clear()
    NOT_RUN.clear()
    meas: dict = {"device": a.device, "label": a.label, "purpose": PURPOSE}
    aborted, made_b, locked = None, False, False
    B_URL = poc.B_URL
    ae_b = f"{a.ae}Reauth"      # the name created on the target on admission: never the name of a live AE of the phone
    try:
        up = [ho._req("GET", u, "CAdmin")[0] for u in (IN_URL, poc.A_URL, B_URL)]
        poc.require("the IN-CSE and both edges answer", up == [200, 200, 200], str(up))
        ho._req("DELETE", f"{IN_URL}/{REG_AE}", REG_ORIGIN)
        ho.release_lock(origin=a.origin)
        ho._req("DELETE", f"{B_URL}/{ae_b}", a.origin)        # a leftover of an earlier run of this driver, by its own name

        print("== the registry on the IN-CSE, and enrolment from the attestation record on file")
        attest = json.loads(Path(a.attest).read_text())
        sp = Path(a.status)
        status = json.loads(sp.read_text())
        as_of, as_of_src = av.status_fetch_time(sp, status)
        rec, why = enrol(attest, status, as_of, a.origin, a.label, as_of_source=as_of_src)
        poc.require("the attestation record verifies as of the day it was made, shows a hardware-backed key on a locked device "
                    "that booted verified, and names a kept key without user binding", rec is not None,
                    why if rec is None else f"alias {rec['alias']}, {rec['attestation']}, as of {rec['verified_as_of']} (day taken from: "
                    f"{rec['verified_as_of_source']}), attestation level {rec['security_level']}, key level {rec['keymint_security_level']}")
        meas["enrolment"] = {k: rec[k] for k in ("alias", "leaf_sha256", "attestation", "attestation_warnings", "verified_as_of",
                                                 "verified_as_of_source", "security_level", "keymint_security_level", "policy",
                                                 "checks_made", "checks_warned", "checks_not_asked", "checks_not_made")}
        meas["attest_file_sha256"] = hashlib.sha256(Path(a.attest).read_bytes()).hexdigest()
        st = [ho._req("POST", IN_URL, REG_ORIGIN, ty=ho.TY_AE, body={"m2m:ae": {"rn": REG_AE, "api": "Nestimed.reg", "rr": False, "srv": ["4"]}})[0]]
        acp = {"m2m:acp": {"rn": "regAcp", "pv": {"acr": [{"acor": [REG_ORIGIN], "acop": 63}, {"acor": [TARGET_ORIGIN], "acop": 34}]},
                           "pvs": {"acr": [{"acor": [REG_ORIGIN], "acop": 63}]}}}
        s_acp, b = ho._req("POST", f"{IN_URL}/{REG_AE}", REG_ORIGIN, ty=ho.TY_ACP, body=acp)
        ri = (b or {}).get("m2m:acp", {}).get("ri")
        st += [s_acp, ho._req("POST", f"{IN_URL}/{REG_AE}", REG_ORIGIN, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": "keys", "acpi": [ri]}})[0],
               ho._req("POST", f"{IN_URL}/{REG_AE}/keys", REG_ORIGIN, ty=ho.TY_CIN,
                       body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(rec, sort_keys=True)}})[0]]
        s_rd, back = ho._req("GET", f"{IN_URL}/{REG_AE}/keys?rcn=4", TARGET_ORIGIN)
        registry = {r["aeId"]: r for r in (json.loads(c["con"]) for c in (back or {}).get("m2m:cnt", {}).get("m2m:cin", []))} if s_rd == 200 else {}
        poc.require("the registry holds the key and the target edge reads it back unchanged", st == [201] * 4 and registry.get(a.origin) == rec,
                    f"create {st}, read {s_rd}")
        s_x = ho._req("POST", f"{IN_URL}/{REG_AE}/keys", "Cstranger", ty=ho.TY_CIN,
                      body={"m2m:cin": {"cnf": "application/json:0", "con": json.dumps({**rec, "leaf_der_b64": "AAAA"})}})[0]
        poc.step("CONTROL (must FAIL) a stranger wrote a key into the registry", s_x == 201, f"HTTP {s_x}")

        print("== one handover transaction, the target's nonce, the phone's signature")
        view = open_txn(a.origin)
        locked = view is not None
        poc.require("a handover transaction is open at the IN-CSE and the target read its identifier and valid-until", locked, str(view and {k: view[k] for k in ("source", "target", "validUntil")}))
        state = {"nonce": {view["txn"]: secrets.token_hex(16)}, "used": set()}
        ch = challenge_hex(message(view["aeId"], view["source"], view["target"], view["txn"], view["validUntil"], state["nonce"][view["txn"]]))
        absent = ho._req("GET", f"{B_URL}/{ae_b}", a.origin)[0]
        ok0, why0 = admit({"aeId": a.origin, "txn": view["txn"], "sig": ""}, view, registry, state, time.time())
        poc.step("without a signature the target does not admit, and the phone's AE is not on the target", not ok0 and absent == 404, f"{why0}; AE on B HTTP {absent}")
        good = None
        if a.device == "adb":
            import fl_capture as fc
            serial = os.environ.get(a.serial_env)
            poc.require(f"the phone's serial is given in ${a.serial_env}", bool(serial))
            got = fc.adb_sign(serial, rec["alias"], ch)
            poc.require("the phone signed the transaction's digest with its kept key (probe mode sign, no prompt)",
                        got.get("ok") is True and got.get("challenge") == ch, str({k: got.get(k) for k in ("ok", "stage", "exception", "error")}))
            good = got["sig"]
            wrong = fc.adb_sign(serial, a.wrong_alias, ch)
            if wrong.get("ok") is True:
                okw, whyw = admit({"aeId": a.origin, "txn": view["txn"], "sig": wrong["sig"]}, view, registry, state, time.time())
                poc.step("CONTROL (must FAIL) a signature by another key of the same phone over the right digest was admitted", okw, whyw)
            else:
                not_run("the wrong-key control", f"the phone holds no usable key under alias {a.wrong_alias!r}: {wrong.get('exception') or wrong.get('error')}")
            ok1, why1 = admit({"aeId": a.origin, "txn": view["txn"], "sig": good}, view, registry, state, time.time())
            if ok1:
                made_b = ho._req("POST", B_URL, a.origin, ty=ho.TY_AE, body={"m2m:ae": {"rn": ae_b, "api": "Nprobe.phone", "rr": False, "srv": ["4"]}})[0] == 201
            poc.step("with the phone's signature over this transaction the target admits, and only then is the AE created on the target",
                     ok1 and made_b, f"{why1}; AE on B created: {made_b}")
            okr, whyr = admit({"aeId": a.origin, "txn": view["txn"], "sig": good}, view, registry, state, time.time())
            poc.step("CONTROL (must FAIL) the same signature shown a second time was admitted", okr, whyr)
        else:
            not_run("admission with the phone's signature, the wrong-key control and the replay control",
                    "the simulated phone holds no key and none is made on this PC")
            poc.require("a signature on file by the enrolled key is given for the refusals (--old-sign)", bool(a.old_sign))
            old = json.loads(Path(a.old_sign).read_text())
            good = old["sig"]
            poc.step("the signature on file is a real signature by the enrolled key (over its own, older challenge)",
                     verify_sig(rec["leaf_der_b64"], old["challenge"], good), f"alias {old.get('alias')}")
            oko, whyo = admit({"aeId": a.origin, "txn": view["txn"], "sig": good}, view, registry, state, time.time())
            poc.step("CONTROL (must FAIL) a real signature by the enrolled key over another challenge was admitted for this transaction", oko, whyo)

        print("== refusals")
        oke, whye = admit({"aeId": a.origin, "txn": view["txn"], "sig": good}, view, registry,
                          {"nonce": dict(state["nonce"]), "used": set()}, view["validUntil"] + 1)
        poc.step("CONTROL (must FAIL) a transaction past its valid-until was admitted", oke, whye)
        oku, whyu = admit({"aeId": a.origin, "txn": view["txn"], "sig": good}, view, {}, {"nonce": dict(state["nonce"]), "used": set()}, time.time())
        poc.step("CONTROL (must FAIL) an AE-ID the registry does not know was admitted", oku, whyu)
        oks, whys = admit({"aeId": a.origin, "txn": view["txn"], "sig": good}, {**view, "target": view["source"]}, registry,
                          {"nonce": dict(state["nonce"]), "used": set()}, time.time())
        poc.step("CONTROL (must FAIL) a handover onto the source was admitted", oks, whys)
        ho.release_lock(origin=a.origin)
        locked = False
        view2 = open_txn(a.origin)
        locked = view2 is not None
        poc.require("a second transaction can be opened after the first is closed", locked and view2["txn"] != view["txn"])
        state["nonce"][view2["txn"]] = secrets.token_hex(16)
        ok2, why2 = admit({"aeId": a.origin, "txn": view2["txn"], "sig": good}, view2, registry, state, time.time())
        poc.step("CONTROL (must FAIL) the signature made for the first transaction was admitted for a second one", ok2, why2)
    except poc.Abort as e:
        aborted = str(e)
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        poc.step("run completed without an exception", False, repr(e))
        aborted = "exception"
    finally:
        if locked:
            ho.release_lock(origin=a.origin)
        if made_b:
            ho._req("DELETE", f"{B_URL}/{ae_b}", a.origin)
        ho._req("DELETE", f"{IN_URL}/{REG_AE}", REG_ORIGIN)
        meas["left_behind"] = {"registry": ho._req("GET", f"{IN_URL}/{REG_AE}", "CAdmin")[0],
                               "transaction": ho._req("GET", f"{IN_URL}/{ho.lock_name(a.origin)}", "CAdmin")[0],
                               "ae_on_target": ho._req("GET", f"{B_URL}/{ae_b}", "CAdmin")[0]}
    poc.step("nothing is left behind: registry, transaction and the AE on the target are gone",
             set(meas["left_behind"].values()) == {404}, str(meas["left_behind"]))
    meas["not_run"] = NOT_RUN
    meas["not_shown"] = [
        "who holds the phone: the key used has no binding to a fingerprint or a screen lock",
        "an authenticated originator: the lab CSEs take the X-M2M-Origin header as given, so the registry's access policy "
        "and the 'target' role bind honest parties only",
        "a fresh attestation: the key was attested on the day of the record; its certificate chain is checked as of that day",
        "the full handover: admission here lets the AE be created on the target; the data move is phone/estimed_poc2.py, "
        "which does not call this yet",
        "that the app that signs is the app that was attested, beyond holding the key"]
    good_run = poc.finish(results, aborted_at=aborted, device=a.device, measurements=meas)
    return 0 if good_run else 1


if __name__ == "__main__":
    sys.exit(main())
