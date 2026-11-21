#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Controls for attest_verify_android.py -- offline, no phone, no network.

Synthetic negative controls: a fake 3-level chain (P-384 root -> P-256 intermediate -> P-256 leaf)
whose leaf carries a KeyDescription (OID 1.3.6.1.4.1.11129.2.1.17) encoded HERE with a
hand-written DER encoder (independent of the module's parser). A baseline chain passes a
strict policy with zero failed checks; each control then changes exactly one thing and must
fail exactly one named check (the test asserts the whole failed-set, not just "it failed").

Positive fixtures (real phones) are opt-in:
    ATTEST_RAW_DIR=~/estimed-run/two_phone/20261015T102247Z/raw python3 phone/test_attest_verify_android.py
Without it they print a NOT RUN line and are counted neither as pass nor as fail.
Output ends `N passed, M failed`.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import traceback
from contextlib import redirect_stdout
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    import attest_verify_android as av  # noqa: E402
    IMPORT_ERROR = None
except Exception as e:  # red run: module does not exist yet
    av = None
    IMPORT_ERROR = e

KD_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
UTC = dt.timezone.utc
AT = dt.datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
CHALLENGE = bytes.fromhex("a1" * 32)
MARKER = b"com.example.tamper.marker"


# ---------------- independent DER encoder (X.690) ----------------
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _ident(cls: int, cons: bool, num: int) -> bytes:
    first = (cls << 6) | (0x20 if cons else 0)
    if num < 31:
        return bytes([first | num])
    groups = []
    while True:
        groups.append(num & 0x7F)
        num >>= 7
        if not num:
            break
    groups.reverse()
    return bytes([first | 0x1F]) + bytes([g | 0x80 for g in groups[:-1]] + [groups[-1]])


def TLV(ident: bytes, content: bytes) -> bytes:
    return ident + _len(len(content)) + content


def INT(n: int) -> bytes:
    ln = max(1, (n.bit_length() + 8) // 8)
    return TLV(b"\x02", n.to_bytes(ln, "big", signed=True))


def ENUM(n: int) -> bytes:
    return TLV(b"\x0a", n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def OCT(b: bytes) -> bytes:
    return TLV(b"\x04", b)


def BOOL(v: bool) -> bytes:
    return TLV(b"\x01", b"\xff" if v else b"\x00")


NULL = b"\x05\x00"


def SEQ(*items: bytes) -> bytes:
    return TLV(b"\x30", b"".join(items))


def SET(*items: bytes) -> bytes:
    return TLV(b"\x31", b"".join(sorted(items)))


def EXP(tag: int, inner: bytes) -> bytes:
    return TLV(_ident(2, True, tag), inner)


def AUTHLIST(d: dict[int, bytes]) -> bytes:
    return SEQ(*[EXP(t, d[t]) for t in sorted(d)])


VB_KEY = bytes(range(32))
VB_HASH = bytes(range(32, 64))
APP_DIGEST = hashlib.sha256(b"signer").digest()


def root_of_trust(locked=True, state=0) -> bytes:
    return SEQ(OCT(VB_KEY), BOOL(locked), ENUM(state), OCT(VB_HASH))


def base_hw() -> dict[int, bytes]:
    return {
        1: SET(INT(2)),            # purpose SIGN
        2: INT(3),                 # algorithm EC
        3: INT(256),               # keySize
        5: SET(INT(4)),            # digest SHA-2-256
        10: INT(1),                # ecCurve P-256
        504: INT(2),               # userAuthType FINGERPRINT (= biometric)
        505: INT(10),              # authTimeout 10 s
        702: INT(0),               # origin GENERATED
        704: root_of_trust(),
        705: INT(160000),
        706: INT(202610),
        718: INT(20260305),
        719: INT(20260405),
    }


def base_sw() -> dict[int, bytes]:
    app = SEQ(SET(SEQ(OCT(MARKER), INT(7))), SET(OCT(APP_DIGEST)))
    return {701: INT(1760000000000), 709: OCT(app)}


def key_description(challenge=CHALLENGE, hw=None, sw=None, sec=1) -> bytes:
    hw = base_hw() if hw is None else hw
    sw = base_sw() if sw is None else sw
    return SEQ(INT(200), ENUM(sec), INT(200), ENUM(sec), OCT(challenge), OCT(b""), AUTHLIST(sw), AUTHLIST(hw))


# ---------------- synthetic chain ----------------
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, pub, signer, serial, nb, na, ca, ext=None, h=hashes.SHA256()):
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(pub).serial_number(serial).not_valid_before(nb).not_valid_after(na))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(KD_OID, ext), critical=False)
    return b.sign(signer, h)


NB = dt.datetime(2026, 1, 1, tzinfo=UTC)
NA = dt.datetime(2027, 1, 1, tzinfo=UTC)
ROOT_KEY = ec.generate_private_key(ec.SECP384R1())
INT_KEY = ec.generate_private_key(ec.SECP256R1())
LEAF_KEY = ec.generate_private_key(ec.SECP256R1())


def spki_sha256(pub) -> str:
    return hashlib.sha256(pub.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


TEST_PINS = {spki_sha256(ROOT_KEY.public_key()): {"name": "synthetic test root", "provenance": "generated in-test"}}


def make_chain(kd=None, root_key=ROOT_KEY, root_na=NA, int_na=NA):
    kd = key_description() if kd is None else kd
    root = _cert("Test Root", "Test Root", root_key.public_key(), root_key, 0x1001, NB, root_na, True, h=hashes.SHA384())
    inter = _cert("Test TEE Intermediate", "Test Root", INT_KEY.public_key(), root_key, 0xABCDEF0123, NB, int_na, True,
                  h=hashes.SHA384())
    leaf = _cert("Android Keystore Key", "Test TEE Intermediate", LEAF_KEY.public_key(), INT_KEY, 1,
                 dt.datetime(1970, 1, 1, tzinfo=UTC), dt.datetime(2048, 1, 1, tzinfo=UTC), False, ext=kd)
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    return [der(leaf), der(inter), der(root)]


def pop(challenge=CHALLENGE, key=LEAF_KEY) -> bytes:
    return key.sign(challenge, ec.ECDSA(hashes.SHA256()))


def strict_policy(**kw):
    p = dict(require_hw_tee=True, require_locked_verified=True, require_challenge=True,
             require_user_auth="biometric", max_auth_timeout=30, forbid_software_enforced_auth=True,
             expired_root="warn")
    p.update(kw)
    return av.Policy(**p)


def run(chain=None, challenge=CHALLENGE, status=None, policy=None, pop_sig=None, pins=None, at=AT,
        status_fetched_at=AT):
    return av.verify(chain if chain is not None else make_chain(),
                     expected_challenge=challenge,
                     status=status if status is not None else {"entries": {}},
                     status_fetched_at=status_fetched_at,
                     policy=policy if policy is not None else strict_policy(),
                     pop_sig=pop() if pop_sig is None else pop_sig,
                     at=at,
                     pinned_roots=TEST_PINS if pins is None else pins)


# ---------------- runner ----------------
RESULTS: list[tuple[str, bool, str]] = []
NOT_RUN: list[str] = []
TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


def expect_only(v, name):
    """The control must fail exactly the one named check, nothing else."""
    assert v["verdict"] == "FAIL", v["verdict"]
    assert v["failed"] == [name], f"failed={v['failed']} want=[{name!r}]"


# --- baseline ---
@test
def baseline_passes_strict_policy():
    v = run()
    assert v["verdict"] == "PASS", (v["verdict"], v["failed"], v["warnings"])
    assert v["failed"] == [] and v["warnings"] == []


@test
def keydescription_fields_decoded():
    kd = run()["key_description"]
    assert kd["attestationVersion"] == 200 and kd["keyMintVersion"] == 200
    assert kd["attestationSecurityLevel"] == "TrustedEnvironment" == kd["keyMintSecurityLevel"]
    assert kd["attestationChallenge"] == CHALLENGE.hex()
    hw, sw = kd["hardwareEnforced"], kd["softwareEnforced"]
    assert hw["purpose"] == ["SIGN"], hw["purpose"]
    assert hw["algorithm"] == "EC" and hw["ecCurve"] == "P_256"
    assert hw["userAuthType"] == 2 and hw["authTimeout"] == 10
    assert "noAuthRequired" not in hw
    rot = hw["rootOfTrust"]
    assert rot["deviceLocked"] is True and rot["verifiedBootState"] == "Verified"
    assert rot["verifiedBootKey"] == VB_KEY.hex() and rot["verifiedBootHash"] == VB_HASH.hex()
    assert hw["osVersion"] == 160000 and hw["osPatchLevel"] == 202610
    assert hw["vendorPatchLevel"] == 20260305 and hw["bootPatchLevel"] == 20260405
    app = sw["attestationApplicationId"]
    assert app["packages"] == [{"name": MARKER.decode(), "version": 7}], app
    assert app["signatureDigests"] == [APP_DIGEST.hex()]


@test
def flag_tags_506_to_509_decoded():
    hw = base_hw()
    for t in (506, 507, 508, 509):
        hw[t] = NULL
    d = run(make_chain(key_description(hw=hw)))["key_description"]["hardwareEnforced"]
    for k in ("allowWhileOnBody", "trustedUserPresenceRequired", "trustedConfirmationRequired",
              "unlockedDeviceRequired"):
        assert d.get(k) is True, k


@test
def default_pins_are_googles_two_root_keys():
    pins = av.PINNED_ROOTS
    assert set(pins) == {"feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae",
                         "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"}, set(pins)
    for meta in pins.values():
        assert meta.get("provenance"), meta


# --- negative controls: each breaks exactly one thing ---
@test
def ctrl_wrong_challenge():
    # attestation carries an old challenge; PoP is over the fresh one -> only the challenge check breaks
    v = run(make_chain(key_description(challenge=bytes.fromhex("b2" * 32))))
    expect_only(v, "challenge")


@test
def ctrl_cut_chain():
    leaf, _inter, root = make_chain()
    expect_only(run([leaf, root]), "chain_signatures")


@test
def ctrl_self_signed_non_google_root():
    # the same well-formed chain, but checked against Google's real pins
    expect_only(run(pins=av.PINNED_ROOTS), "root_pinned")


@test
def ctrl_self_signed_other_root_vs_test_pin():
    other = ec.generate_private_key(ec.SECP384R1())
    expect_only(run(make_chain(root_key=other)), "root_pinned")


@test
def ctrl_tampered_extension_byte():
    leaf, inter, root = make_chain()
    i = leaf.index(MARKER)
    bad = leaf[: i + len(MARKER) - 1] + b"s" + leaf[i + len(MARKER):]
    assert bad != leaf and len(bad) == len(leaf)
    expect_only(run([bad, inter, root]), "chain_signatures")


@test
def ctrl_revoked_serial():
    status = {"entries": {format(0xABCDEF0123, "x"): {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}
    expect_only(run(status=status), "revocation")


@test
def ctrl_auth_tags_only_software_enforced():
    hw, sw = base_hw(), base_sw()
    sw[504], sw[505] = hw.pop(504), hw.pop(505)
    v = run(make_chain(key_description(hw=hw, sw=sw)), policy=strict_policy(require_user_auth=None))
    expect_only(v, "software_enforced_auth")


@test
def ctrl_no_auth_required_when_biometric_required():
    hw = base_hw()
    hw[503] = NULL
    expect_only(run(make_chain(key_description(hw=hw))), "user_auth")


@test
def ctrl_auth_timeout_above_max():
    hw = base_hw()
    hw[505] = INT(3600)
    expect_only(run(make_chain(key_description(hw=hw))), "auth_timeout")


@test
def ctrl_device_unlocked():
    hw = base_hw()
    hw[704] = root_of_trust(locked=False)
    expect_only(run(make_chain(key_description(hw=hw))), "device_locked")


@test
def ctrl_verified_boot_unverified():
    hw = base_hw()
    hw[704] = root_of_trust(state=2)
    expect_only(run(make_chain(key_description(hw=hw))), "verified_boot_state")


@test
def ctrl_software_security_level():
    expect_only(run(make_chain(key_description(sec=0))), "hw_tee")


@test
def ctrl_pop_by_other_key():
    expect_only(run(pop_sig=pop(key=ec.generate_private_key(ec.SECP256R1()))), "proof_of_possession")


@test
def ctrl_expired_intermediate():
    expect_only(run(make_chain(int_na=dt.datetime(2026, 6, 1, tzinfo=UTC))), "intermediates_validity")


@test
def ctrl_biometric_with_password_fallback():
    hw = base_hw()
    hw[504] = INT(3)  # PASSWORD | FINGERPRINT: credential fallback is not "biometric only"
    expect_only(run(make_chain(key_description(hw=hw))), "user_auth")
    assert run(make_chain(key_description(hw=hw)), policy=strict_policy(require_user_auth="any"))["verdict"] == "PASS"


@test
def ctrl_duplicate_tag_rejected():
    # two osVersion entries: ambiguous -> parse must refuse, nothing downstream may "pick one"
    hw = base_hw()
    body = b"".join(EXP(t, hw[t]) for t in sorted(hw)) + EXP(705, INT(1))
    kd = SEQ(INT(200), ENUM(1), INT(200), ENUM(1), OCT(CHALLENGE), OCT(b""), AUTHLIST(base_sw()), SEQ(body))
    v = run(make_chain(kd))
    assert v["verdict"] == "FAIL" and "key_description_parse" in v["failed"], v["failed"]


# --- the expired-root policy (ASUS case), explicit and configurable ---
@test
def expired_root_pinned_key_warns_not_fails_not_silent():
    v = run(make_chain(root_na=dt.datetime(2026, 5, 24, tzinfo=UTC)))
    assert v["verdict"] == "PASS_WITH_WARNINGS", (v["verdict"], v["failed"])
    assert v["failed"] == []
    assert any("embedded root cert expired; key matches reissued root" in w for w in v["warnings"]), v["warnings"]
    assert v["checks"]["root_validity"]["ok"] is False


@test
def expired_root_policy_fail():
    v = run(make_chain(root_na=dt.datetime(2026, 5, 24, tzinfo=UTC)), policy=strict_policy(expired_root="fail"))
    expect_only(v, "root_validity")


@test
def stale_status_warns_and_can_fail():
    old = AT - dt.timedelta(days=30)
    v = run(status_fetched_at=old)
    assert v["verdict"] == "PASS_WITH_WARNINGS" and v["status_age_s"] == 30 * 86400, (v["verdict"], v.get("status_age_s"))
    expect_only(run(status_fetched_at=old, policy=strict_policy(stale_status="fail")), "status_freshness")


# --- CLI ---
@test
def cli_json_and_rc():
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        chain = make_chain()
        (d / "a.json").write_text(json.dumps({"chain": [base64.b64encode(c).decode() for c in chain],
                                              "pop_sig": base64.b64encode(pop()).decode(),
                                              "challenge": CHALLENGE.hex()}))
        (d / "c.txt").write_text(CHALLENGE.hex() + "\n")
        (d / "status_20261015T120000Z.json").write_text(json.dumps({"entries": {}}))
        args = [str(d / "a.json"), str(d / "c.txt"), str(d / "status_20261015T120000Z.json"),
                "--at", "2026-10-15T12:00:00Z", "--require-hw-tee", "--require-locked-verified"]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = av.main(args, pinned_roots=TEST_PINS)
        out = json.loads(buf.getvalue())
        assert rc == 0 and out["verdict"] == "PASS", (rc, out.get("failed"))
        assert out["status_fetched_at_source"] == "filename", out.get("status_fetched_at_source")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = av.main(args)  # real Google pins -> synthetic root is not trusted
        assert rc == 1 and json.loads(buf.getvalue())["failed"] == ["root_pinned"]


# --- positive fixtures: real phones (opt-in) ---
POLICY_REAL = dict(require_hw_tee=True, require_locked_verified=True, require_challenge=True)


def _real(serial):
    raw = Path(os.environ["ATTEST_RAW_DIR"]).expanduser()
    status = next(raw.glob("google_attest_status_*.json"))
    m = re.search(r"(\d{8}T\d{6}Z)", str(raw))
    at = dt.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC) if m else None
    return raw / f"attest_{serial}_sbfalse.json", raw / f"challenge_{serial}_sbfalse.txt", status, at


def _real_verify(serial, **kw):
    a, c, s, at = _real(serial)
    p = dict(POLICY_REAL)
    p.update(kw)
    return av.verify_files(a, c, s, av.Policy(**p), at=at)


@test
def real_nothing_keymint200_google2025_root():
    if not os.environ.get("ATTEST_RAW_DIR"):
        return "NOT RUN"
    v = _real_verify(os.environ.get("PHONE_B_SERIAL", ""))
    print(f"      verdict={v['verdict']} failed={v['failed']} warnings={v['warnings']}")
    assert v["verdict"] == "PASS", (v["failed"], v["warnings"])
    kd = v["key_description"]
    assert kd["keyMintVersion"] == 200 and kd["keyMintSecurityLevel"] == "TrustedEnvironment"
    assert v["checks"]["root_pinned"]["ok"] and v["checks"]["proof_of_possession"]["ok"]


@test
def real_asus_keymaster4_expired_2016_root():
    if not os.environ.get("ATTEST_RAW_DIR"):
        return "NOT RUN"
    v = _real_verify(os.environ.get("PHONE_C_SERIAL", ""))
    print(f"      verdict={v['verdict']} failed={v['failed']} warnings={v['warnings']}")
    assert v["verdict"] == "PASS_WITH_WARNINGS", (v["verdict"], v["failed"])
    assert any("embedded root cert expired; key matches reissued root" in w for w in v["warnings"])
    assert v["key_description"]["keyMintVersion"] == 4
    v2 = _real_verify(os.environ.get("PHONE_C_SERIAL", ""), expired_root="fail")
    assert v2["failed"] == ["root_validity"], v2["failed"]


@test
def real_wrong_challenge_fails():
    if not os.environ.get("ATTEST_RAW_DIR"):
        return "NOT RUN"
    a, _c, s, at = _real(os.environ.get("PHONE_B_SERIAL", ""))
    with tempfile.NamedTemporaryFile("w", suffix=".txt") as f:
        f.write("00" * 32)
        f.flush()
        v = av.verify_files(a, f.name, s, av.Policy(**POLICY_REAL), at=at)
    # the probe signed its own challenge, so a different expected challenge breaks both
    assert set(v["failed"]) == {"challenge", "proof_of_possession"}, v["failed"]


def main() -> int:
    if IMPORT_ERROR is not None:
        print(f"  (module import failed: {IMPORT_ERROR!r})")
    for fn in TESTS:
        name = fn.__name__
        if av is None:
            RESULTS.append((name, False, "module not importable"))
            print(f"  FAIL  {name}  -- module not importable")
            continue
        try:
            r = fn()
            if r == "NOT RUN":
                NOT_RUN.append(name)
                print(f"  NOT RUN  {name}  -- set ATTEST_RAW_DIR to the raw capture dir (a skip is not a pass)")
                continue
            RESULTS.append((name, True, ""))
            print(f"  PASS  {name}")
        except Exception as e:
            RESULTS.append((name, False, repr(e)))
            print(f"  FAIL  {name}  -- {e!r}")
            if os.environ.get("ATTEST_TEST_TB"):
                traceback.print_exc()
    p = sum(ok for _, ok, _ in RESULTS)
    f = len(RESULTS) - p
    print(f"\n{len(NOT_RUN)} NOT RUN; {p} passed, {f} failed")
    return 0 if f == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
