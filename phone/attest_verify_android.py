#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline Android Keystore / KeyMint key-attestation verifier.

    python3 phone/attest_verify_android.py ATTEST.json CHALLENGE.txt STATUS.json \
        [--at 2026-10-15T10:22:47Z] [--require-hw-tee] [--require-locked-verified] ...
    -> JSON verdict on stdout; rc 0 PASS, 2 PASS_WITH_WARNINGS, 1 FAIL, 64 usage/input error.

ATTEST.json is the probe app's capture: {"chain": [b64 DER leaf..root], "pop_sig": b64, ...}.
CHALLENGE.txt is the VERIFIER's own copy of the challenge (hex). The capture's "challenge"
field is only compared and warned about, never trusted. STATUS.json is Google's attestation
status list ({"entries": {hex_serial: {"status", "reason", ...}}}), fetched separately.
Nothing here touches the network or a device.

What is checked (each a named entry in verdict["checks"]; a control must break exactly one)
  root_pinned            sha256(SPKI) of the chain's last cert is one of PINNED_ROOTS. Trust is
                         in the KEY, not in the embedded root certificate.
  root_self_signature    the embedded root's self-signature verifies.
  root_validity          the embedded root CERT's validity at `at`, reported SEPARATELY from the
                         key pin. Policy.expired_root = "warn" (default) or "fail". With "warn" an
                         expired root whose key is pinned verifies as PASS_WITH_WARNINGS with
                         "embedded root cert expired; key matches reissued root (...)" -- never a
                         silent PASS. (ASUS Keymaster 4 ships the 2016 RSA root, expired
                         2026-05-24; Google re-issued the same key in a cert valid to 2042-03-15.)
  chain_signatures       every link: issuer name == parent subject and signature verifies.
  intermediates_validity every cert strictly between leaf and root is valid at `at`. (Leaf
                         validity is reported but not judged: KeyMint leaves carry 1970..2048 etc.)
  extension_only_in_leaf the KeyDescription extension appears in the leaf and nowhere else.
  revocation             no chain serial is REVOKED/SUSPENDED in the status JSON.
  status_freshness       age of the status JSON at `at` <= Policy.status_max_age_s
                         (Policy.stale_status = "warn" default | "fail"). The fetch time comes from
                         a "fetched_at" field, else a ...YYYYMMDDTHHMMSSZ... filename stamp, else
                         the file mtime -- the source is reported, since each is only a claim.
  key_description_parse  strict DER: no indefinite lengths, no out-of-bounds lengths, no trailing
                         bytes, no duplicate tags in an AuthorizationList.
  challenge              attestationChallenge == the verifier's challenge (constant-time compare).
  proof_of_possession    pop_sig is the leaf key's signature over the challenge bytes
                         (ECDSA-SHA256 / RSA-PKCS1v15-SHA256), as the probe produces it.
  hw_tee                 attestation- AND keyMint-SecurityLevel >= TrustedEnvironment
                         (or == StrongBox with require_strongbox).
  device_locked          hardwareEnforced.rootOfTrust.deviceLocked is true.
  verified_boot_state    hardwareEnforced.rootOfTrust.verifiedBootState == Verified.
  user_auth              require_user_auth: None | "any" (hw userAuthType != 0 and no
                         noAuthRequired anywhere) | "biometric" (hw userAuthType has the
                         FINGERPRINT(2) bit and NOT the PASSWORD(1) bit, no noAuthRequired).
  auth_timeout           hw authTimeout <= max_auth_timeout (absent = auth per operation = ok).
  software_enforced_auth any user-auth tag (503..509) that is in softwareEnforced but not in
                         hardwareEnforced fails: the OS, not the TEE, would be enforcing it.
Only hardwareEnforced values ever satisfy a policy requirement.

What attestation can NOT show (do not claim these from a PASS)
  * Finger vs face vs iris. userAuthType bit 2 is named FINGERPRINT for historical reasons; it
    means "any Class 3 (BIOMETRIC_STRONG) biometric the OEM enrolled". The modality is not
    attested.
  * Liveness / presentation-attack resistance. Not in the KeyDescription; it rests on the OEM's
    biometric class certification, which the chain does not carry.
  * The secure-user-id binding. Auth-bound keys are bound inside the TEE to the secure user IDs
    (USER_SECURE_ID, tag 502) of the enrolled credential/biometric set; that tag is not emitted
    in attestations, so you cannot see WHICH enrolment, which user, or whether a new
    enrolment invalidates the key. "userAuthType=2 in hardwareEnforced" says only that the TEE
    will demand some strong-biometric HardwareAuthToken.
  * That any authentication happened. The attestation describes the key's rules at generation;
    it is not evidence of a later use. Per-use evidence needs a signature made with the key.
  * Who holds the phone, or that the app is genuine beyond attestationApplicationId, which is
    softwareEnforced (asserted by Android, not by the TEE).
  * That the TEE/KeyMint implementation is free of bugs, or that the device stays locked and
    verified after the attestation. The status list revokes attestation KEYS (batch/RKP
    certs), not this app key.
  * Freshness beyond the challenge: replay protection is exactly as good as the verifier's
    challenge handling (one-time, unpredictable, bound to the session).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

KD_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
UTC = dt.timezone.utc

# ---------------------------------------------------------------- pinned Google root KEYS
# sha256 over the DER SubjectPublicKeyInfo. Two independent local copies agree on both:
#   (a) nl-wallet wallet_core/lib/android_attest/assets/google_hardware_attestation_root_{rsa,ec}_pubkey.pem
#       at nl-wallet commit 835b9754209c (2026-04-15);
#   (b) ~/evidence/phone_2026-09-27/attestation/google_attest_root.json (Google's published
#       root list, captured 2026-09-28; upstream = developer.android.com key-attestation "Root
#       certificate" / android.googleapis.com/attestation/root).
# Not re-fetched on 2026-10-15 (no network in that session). Re-pin only from Google's page.
PINNED_ROOTS: dict[str, dict[str, Any]] = {
    "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae": {
        "name": "Google Hardware Attestation Root (RSA-4096, subject serialNumber=f92009e853b6b045)",
        "reissued_cert": {"serial": "f1c172a699eaf51d", "not_before": "2022-03-20", "not_after": "2042-03-15"},
        "superseded_certs": [{"serial": "e8fa196314d2fa18", "not_before": "2016-05-26", "not_after": "2026-05-24"}],
        "provenance": "nl-wallet assets/google_hardware_attestation_root_rsa_pubkey.pem @835b9754 (2026-04-15) "
                      "== google_attest_root.json[0] captured 2026-09-28 (phone_2026-09-27 evidence)",
    },
    "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec": {
        "name": "Google Key Attestation CA1 (ECDSA P-384, C=US O=Google LLC OU=Android)",
        "reissued_cert": {"serial": "84a9d0297b0eb58ae7ff0e80de760605", "not_before": "2025-07-17",
                          "not_after": "2035-07-15"},
        "superseded_certs": [],
        "provenance": "nl-wallet assets/google_hardware_attestation_root_ec_pubkey.pem @835b9754 (2026-04-15) "
                      "== google_attest_root.json[1] captured 2026-09-28 (phone_2026-09-27 evidence)",
    },
}

SEC_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
BOOT_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
PURPOSE = {0: "ENCRYPT", 1: "DECRYPT", 2: "SIGN", 3: "VERIFY", 5: "WRAP_KEY", 6: "AGREE_KEY", 7: "ATTEST_KEY"}
ALGORITHM = {1: "RSA", 3: "EC", 32: "AES", 33: "TRIPLE_DES", 128: "HMAC"}
EC_CURVE = {0: "P_224", 1: "P_256", 2: "P_384", 3: "P_521", 4: "CURVE_25519"}
DIGEST = {0: "NONE", 1: "MD5", 2: "SHA1", 3: "SHA_2_224", 4: "SHA_2_256", 5: "SHA_2_384", 6: "SHA_2_512"}
PADDING = {1: "NONE", 2: "RSA_OAEP", 3: "RSA_PSS", 4: "RSA_PKCS1_1_5_ENCRYPT", 5: "RSA_PKCS1_1_5_SIGN", 64: "PKCS7"}
ORIGIN = {0: "GENERATED", 1: "DERIVED", 2: "IMPORTED", 3: "RESERVED", 4: "SECURELY_IMPORTED"}
AUTH_PASSWORD, AUTH_FINGERPRINT = 1, 2

# tag -> (name, kind); kind: int | intset | null | rot | appid | bytes
TAGS: dict[int, tuple[str, str]] = {
    1: ("purpose", "intset"), 2: ("algorithm", "int"), 3: ("keySize", "int"), 5: ("digest", "intset"),
    6: ("padding", "intset"), 10: ("ecCurve", "int"), 200: ("rsaPublicExponent", "int"),
    203: ("mgfDigest", "intset"), 303: ("rollbackResistance", "null"), 305: ("earlyBootOnly", "null"),
    400: ("activeDateTime", "int"), 401: ("originationExpireDateTime", "int"),
    402: ("usageExpireDateTime", "int"), 405: ("usageCountLimit", "int"),
    503: ("noAuthRequired", "null"), 504: ("userAuthType", "int"), 505: ("authTimeout", "int"),
    506: ("allowWhileOnBody", "null"), 507: ("trustedUserPresenceRequired", "null"),
    508: ("trustedConfirmationRequired", "null"), 509: ("unlockedDeviceRequired", "null"),
    600: ("allApplications", "null"), 701: ("creationDateTime", "int"), 702: ("origin", "int"),
    704: ("rootOfTrust", "rot"), 705: ("osVersion", "int"), 706: ("osPatchLevel", "int"),
    709: ("attestationApplicationId", "appid"), 710: ("attestationIdBrand", "bytes"),
    711: ("attestationIdDevice", "bytes"), 712: ("attestationIdProduct", "bytes"),
    713: ("attestationIdSerial", "bytes"), 714: ("attestationIdImei", "bytes"),
    715: ("attestationIdMeid", "bytes"), 716: ("attestationIdManufacturer", "bytes"),
    717: ("attestationIdModel", "bytes"), 718: ("vendorPatchLevel", "int"), 719: ("bootPatchLevel", "int"),
    720: ("deviceUniqueAttestation", "null"), 723: ("attestationIdSecondImei", "bytes"),
    724: ("moduleHash", "bytes"),
}
NAMED = {1: PURPOSE, 2: ALGORITHM, 5: DIGEST, 6: PADDING, 10: EC_CURVE, 203: DIGEST, 702: ORIGIN}
AUTH_TAGS = (503, 504, 505, 506, 507, 508, 509)


# ---------------------------------------------------------------- strict DER reader
class DerError(ValueError):
    pass


def _tlv(b: bytes, i: int, end: int) -> tuple[int, bool, int, bytes, int]:
    """One TLV at b[i:end] -> (class, constructed, tag number, content, next index)."""
    if i >= end:
        raise DerError("truncated: no tag")
    first = b[i]
    i += 1
    cls, cons, num = first >> 6, bool(first & 0x20), first & 0x1F
    if num == 0x1F:
        num = 0
        while True:
            if i >= end:
                raise DerError("truncated high tag")
            x = b[i]
            i += 1
            num = (num << 7) | (x & 0x7F)
            if not x & 0x80:
                break
            if num > 1 << 28:
                raise DerError("tag number too large")
    if i >= end:
        raise DerError("truncated: no length")
    ln = b[i]
    i += 1
    if ln == 0x80:
        raise DerError("indefinite length (BER) not allowed")
    if ln & 0x80:
        n = ln & 0x7F
        if n > 4 or i + n > end:
            raise DerError("bad long-form length")
        ln = int.from_bytes(b[i:i + n], "big")
        i += n
    if i + ln > end:
        raise DerError(f"length {ln} overruns its container")
    return cls, cons, num, b[i:i + ln], i + ln


def _children(b: bytes) -> list[tuple[int, bool, int, bytes]]:
    out, i = [], 0
    while i < len(b):
        cls, cons, t, v, i = _tlv(b, i, len(b))
        out.append((cls, cons, t, v))
    return out


def _single(b: bytes) -> tuple[int, bool, int, bytes]:
    cls, cons, t, v, j = _tlv(b, 0, len(b))
    if j != len(b):
        raise DerError("trailing bytes")
    return cls, cons, t, v


def _expect(node, tag: int, what: str, cons: bool = False) -> bytes:
    cls, c, t, v = node
    if cls != 0 or t != tag or c != cons:
        raise DerError(f"{what}: expected universal tag {tag}, got class {cls} tag {t}")
    return v


def _int(node, what="INTEGER", tag=2) -> int:
    v = _expect(node, tag, what)
    if not v:
        raise DerError(f"{what}: empty")
    return int.from_bytes(v, "big", signed=True)


def _authlist(content: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    seen: set[int] = set()
    for cls, cons, t, val in _children(content):
        if cls != 2 or not cons:
            raise DerError(f"AuthorizationList entry is not [n] EXPLICIT (class {cls} tag {t})")
        if t in seen:
            raise DerError(f"duplicate tag {t} in AuthorizationList")
        seen.add(t)
        inner = _single(val)
        name, kind = TAGS.get(t, (f"tag_{t}", "raw"))
        if kind == "int":
            x = _int(inner, name)
            out[name] = NAMED[t].get(x, x) if t in NAMED else x
        elif kind == "intset":
            vals = [_int(n, name) for n in _children(_expect(inner, 17, name, cons=True))]
            out[name] = [NAMED[t].get(x, x) for x in vals] if t in NAMED else vals
        elif kind == "null":
            if _expect(inner, 5, name) != b"":
                raise DerError(f"{name}: NULL with content")
            out[name] = True
        elif kind == "rot":
            rt = _children(_expect(inner, 16, name, cons=True))
            if len(rt) < 3:
                raise DerError("rootOfTrust: fewer than 3 fields")
            lk = _expect(rt[1], 1, "deviceLocked")
            if len(lk) != 1:
                raise DerError("deviceLocked: bad BOOLEAN")
            st = _int(rt[2], "verifiedBootState", tag=10)
            out[name] = {"verifiedBootKey": _expect(rt[0], 4, "verifiedBootKey").hex(),
                         "deviceLocked": lk != b"\x00",
                         "verifiedBootState": BOOT_STATE.get(st, st),
                         "verifiedBootHash": _expect(rt[3], 4, "verifiedBootHash").hex() if len(rt) > 3 else None}
        elif kind == "appid":
            seqv = _children(_expect(_single(_expect(inner, 4, name)), 16, name, cons=True))
            if len(seqv) != 2:
                raise DerError("attestationApplicationId: expected 2 fields")
            pkgs = []
            for p in _children(_expect(seqv[0], 17, "package_infos", cons=True)):
                f = _children(_expect(p, 16, "AttestationPackageInfo", cons=True))
                pkgs.append({"name": _expect(f[0], 4, "package_name").decode("utf-8", "replace"),
                             "version": _int(f[1], "version")})
            digs = [_expect(d, 4, "signature_digest").hex()
                    for d in _children(_expect(seqv[1], 17, "signature_digests", cons=True))]
            out[name] = {"packages": pkgs, "signatureDigests": digs}
        elif kind == "bytes":
            raw = _expect(inner, 4, name)
            try:
                out[name] = raw.decode("ascii") if raw.isascii() and raw.decode().isprintable() else raw.hex()
            except UnicodeDecodeError:
                out[name] = raw.hex()
        else:
            out[name] = val.hex()
    return out


def parse_key_description(ext_value: bytes) -> dict[str, Any]:
    """Decode the KeyDescription extension value (DER). Raises DerError on anything malformed."""
    f = _children(_expect(_single(ext_value), 16, "KeyDescription", cons=True))
    if len(f) < 8:
        raise DerError(f"KeyDescription: {len(f)} fields, need 8")
    asl, ksl = _int(f[1], "attestationSecurityLevel", 10), _int(f[3], "keyMintSecurityLevel", 10)
    return {
        "attestationVersion": _int(f[0], "attestationVersion"),
        "attestationSecurityLevel": SEC_LEVEL.get(asl, asl),
        "keyMintVersion": _int(f[2], "keyMintVersion"),
        "keyMintSecurityLevel": SEC_LEVEL.get(ksl, ksl),
        "attestationChallenge": _expect(f[4], 4, "attestationChallenge").hex(),
        "uniqueId": _expect(f[5], 4, "uniqueId").hex(),
        "softwareEnforced": _authlist(_expect(f[6], 16, "softwareEnforced", cons=True)),
        "hardwareEnforced": _authlist(_expect(f[7], 16, "hardwareEnforced", cons=True)),
    }


# ---------------------------------------------------------------- policy + verification
@dataclass
class Policy:
    require_hw_tee: bool = False
    require_strongbox: bool = False
    require_locked_verified: bool = False
    require_challenge: bool = True
    require_pop: bool = True
    require_user_auth: str | None = None          # None | "any" | "biometric"
    max_auth_timeout: int | None = None           # seconds
    forbid_software_enforced_auth: bool = True
    expired_root: str = "warn"                    # "warn" | "fail" (embedded root CERT outside validity)
    status_max_age_s: int = 86400
    stale_status: str = "warn"                    # "warn" | "fail"

    def __post_init__(self):
        if self.require_user_auth not in (None, "any", "biometric"):
            raise ValueError("require_user_auth must be None, 'any' or 'biometric'")
        if self.expired_root not in ("warn", "fail") or self.stale_status not in ("warn", "fail"):
            raise ValueError("expired_root / stale_status must be 'warn' or 'fail'")


def spki_sha256(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _valid_at(c: x509.Certificate, at: dt.datetime) -> bool:
    return c.not_valid_before_utc <= at <= c.not_valid_after_utc


def _span(c: x509.Certificate) -> str:
    return f"{c.not_valid_before_utc.date()}..{c.not_valid_after_utc.date()}"


def _verify_pop(pub, sig: bytes, msg: bytes) -> bool:
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except (InvalidSignature, ValueError):
        return False


class _Checks:
    def __init__(self):
        self.d: dict[str, dict[str, Any]] = {}
        self.extra_warnings: list[str] = []

    def add(self, name, ok, detail="", severity="fail", warning=None):
        self.d[name] = {"ok": ok, "severity": severity, "detail": detail}
        if ok is False and severity == "warn":
            self.extra_warnings.append(warning or f"{name}: {detail}")

    def skip(self, name, why):
        self.add(name, None, f"not evaluated: {why}")


def verify(chain_der: list[bytes], expected_challenge: bytes | None, status: dict | None,
           status_fetched_at: dt.datetime | None, policy: Policy, pop_sig: bytes | None = None,
           at: dt.datetime | None = None, pinned_roots: dict[str, dict] | None = None) -> dict[str, Any]:
    pins = PINNED_ROOTS if pinned_roots is None else pinned_roots
    at = at or dt.datetime.now(UTC)
    ck = _Checks()
    res: dict[str, Any] = {"verified_at": at.isoformat(), "policy": asdict(policy)}

    try:
        chain = [x509.load_der_x509_certificate(c) for c in chain_der]
        if len(chain) < 2:
            raise ValueError(f"chain has {len(chain)} cert(s), need >= 2")
    except Exception as e:  # noqa: BLE001 -- any parse failure is a verdict, not a crash
        ck.add("chain_parse", False, repr(e))
        return _finish(res, ck)
    leaf, root, mids = chain[0], chain[-1], chain[1:-1]
    res["chain"] = [{"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                     "serial": format(c.serial_number, "x"), "validity": _span(c),
                     "spki_sha256": spki_sha256(c)} for c in chain]

    # --- root: key pin (trust) and certificate validity (reported separately)
    pin = pins.get(spki_sha256(root))
    ck.add("root_pinned", pin is not None,
           f"pinned: {pin['name']}" if pin else f"root SPKI sha256 {spki_sha256(root)} is not a pinned Google key")
    try:
        root.verify_directly_issued_by(root)
        ck.add("root_self_signature", True, "ok")
    except Exception as e:  # noqa: BLE001
        ck.add("root_self_signature", False, f"embedded root self-signature: {e!r}")
    if _valid_at(root, at):
        ck.add("root_validity", True, f"embedded root cert valid {_span(root)}")
    else:
        what = "expired" if at > root.not_valid_after_utc else "not yet valid"
        if pin:
            ri = pin.get("reissued_cert")
            ri_s = f"{pin['name']}, reissued cert serial {ri['serial']} valid {ri['not_before']}..{ri['not_after']}" \
                if ri else pin["name"]
            msg = f"embedded root cert {what}; key matches reissued root ({ri_s}); embedded cert validity {_span(root)}"
        else:
            msg = f"embedded root cert {what} ({_span(root)}) and its key is not pinned"
        ck.add("root_validity", False, msg, severity=policy.expired_root, warning=msg)

    # --- every link
    bad_links = []
    for i in range(len(chain) - 1):
        try:
            chain[i].verify_directly_issued_by(chain[i + 1])
        except Exception as e:  # noqa: BLE001  (ValueError name mismatch, InvalidSignature, TypeError)
            bad_links.append(f"cert[{i}] <- cert[{i + 1}]: {type(e).__name__} {e}")
    ck.add("chain_signatures", not bad_links, "; ".join(bad_links) or f"{len(chain) - 1} links verify")

    expired = [f"cert[{i + 1}] {c.subject.rfc4514_string()} {_span(c)}" for i, c in enumerate(mids)
               if not _valid_at(c, at)]
    ck.add("intermediates_validity", not expired,
           "; ".join(expired) or f"{len(mids)} intermediate(s) valid at {at.isoformat()}")
    res["leaf_validity_informational"] = f"{_span(leaf)} ({'inside' if _valid_at(leaf, at) else 'outside'} at `at`)"

    has_ext = [i for i, c in enumerate(chain) if any(e.oid == KD_OID for e in c.extensions)]
    ck.add("extension_only_in_leaf", has_ext == [0], f"KeyDescription in cert index(es) {has_ext}")

    # --- revocation by serial
    try:
        entries = (status or {})["entries"]
        if not isinstance(entries, dict):
            raise TypeError("entries is not an object")
        revoked: dict[int, dict] = {}
        for k, v in entries.items():
            try:
                revoked[int(str(k).strip().lower(), 16)] = v
            except ValueError:
                continue
        hits = [f"cert[{i}] serial {format(c.serial_number, 'x')}: {revoked[c.serial_number]}"
                for i, c in enumerate(chain) if c.serial_number in revoked]
        ck.add("revocation", not hits, "; ".join(hits) or f"0 of {len(chain)} serials listed ({len(revoked)} entries)")
    except Exception as e:  # noqa: BLE001
        ck.add("revocation", False, f"status JSON unusable: {e!r}")

    if status_fetched_at is None:
        res["status_age_s"] = None
        ck.add("status_freshness", False, "status JSON fetch time unknown",
               severity=policy.stale_status, warning="status JSON age unknown")
    else:
        age = (at - status_fetched_at).total_seconds()
        res["status_age_s"] = age
        fresh = age <= policy.status_max_age_s
        ck.add("status_freshness", fresh, f"status JSON age {age:.0f}s (max {policy.status_max_age_s}s)",
               severity="fail" if fresh else policy.stale_status,
               warning=f"status JSON is {age / 86400:.1f} days old (max {policy.status_max_age_s}s)")

    # --- KeyDescription
    kd = None
    try:
        ext = leaf.extensions.get_extension_for_oid(KD_OID).value
        kd = parse_key_description(ext.value)
        ck.add("key_description_parse", True, "ok")
    except Exception as e:  # noqa: BLE001
        ck.add("key_description_parse", False, repr(e))
    res["key_description"] = kd

    # challenge + proof of possession
    if kd is None:
        ck.skip("challenge", "KeyDescription unparsed")
    elif policy.require_challenge:
        if expected_challenge is None:
            ck.add("challenge", False, "policy requires a challenge but none was supplied")
        else:
            ok = hmac.compare_digest(bytes.fromhex(kd["attestationChallenge"]), expected_challenge)
            ck.add("challenge", ok, "matches" if ok else
                   f"attested {kd['attestationChallenge']} != expected {expected_challenge.hex()}")
    else:
        ck.add("challenge", None, "not required by policy")
    if pop_sig is None or expected_challenge is None:
        ck.add("proof_of_possession", False if policy.require_pop else None,
               "no pop_sig/challenge supplied" + ("" if policy.require_pop else " (not required)"))
    else:
        ok = _verify_pop(leaf.public_key(), pop_sig, expected_challenge)
        ck.add("proof_of_possession", ok, "leaf key signed the challenge" if ok else
               "pop_sig does not verify under the leaf key over the expected challenge")

    if kd is None:
        for n in ("hw_tee", "device_locked", "verified_boot_state", "user_auth", "auth_timeout",
                  "software_enforced_auth"):
            ck.skip(n, "KeyDescription unparsed")
        return _finish(res, ck)
    hw, sw = kd["hardwareEnforced"], kd["softwareEnforced"]

    levels = (kd["attestationSecurityLevel"], kd["keyMintSecurityLevel"])
    if policy.require_strongbox:
        ck.add("hw_tee", levels == ("StrongBox", "StrongBox"), f"security levels {levels} (StrongBox required)")
    elif policy.require_hw_tee:
        ok = all(x in ("TrustedEnvironment", "StrongBox") for x in levels)
        ck.add("hw_tee", ok, f"security levels {levels}")
    else:
        ck.add("hw_tee", None, f"not required; security levels {levels}")

    rot = hw.get("rootOfTrust")
    if policy.require_locked_verified:
        if rot is None:
            ck.add("device_locked", False, "no rootOfTrust in hardwareEnforced")
            ck.add("verified_boot_state", False, "no rootOfTrust in hardwareEnforced")
        else:
            ck.add("device_locked", rot["deviceLocked"] is True, f"deviceLocked={rot['deviceLocked']}")
            ck.add("verified_boot_state", rot["verifiedBootState"] == "Verified",
                   f"verifiedBootState={rot['verifiedBootState']}")
    else:
        ck.add("device_locked", None, f"not required; rootOfTrust={rot and {k: rot[k] for k in ('deviceLocked', 'verifiedBootState')}}")
        ck.add("verified_boot_state", None, "not required")

    uat = hw.get("userAuthType")
    no_auth = bool(hw.get("noAuthRequired") or sw.get("noAuthRequired"))
    if policy.require_user_auth is None:
        ck.add("user_auth", None, f"not required; hw userAuthType={uat} noAuthRequired={no_auth}")
    else:
        why = []
        if no_auth:
            why.append("noAuthRequired present")
        if not isinstance(uat, int) or uat == 0:
            why.append("no hardware-enforced userAuthType")
        elif policy.require_user_auth == "biometric":
            if not uat & AUTH_FINGERPRINT:
                why.append(f"userAuthType={uat} lacks the biometric bit")
            if uat & AUTH_PASSWORD:
                why.append(f"userAuthType={uat} allows a PASSWORD fallback")
        ck.add("user_auth", not why, "; ".join(why) or f"hw userAuthType={uat} satisfies '{policy.require_user_auth}'")

    if policy.max_auth_timeout is None:
        ck.add("auth_timeout", None, f"not limited; hw authTimeout={hw.get('authTimeout')}")
    elif uat in (None, 0):
        ck.add("auth_timeout", None, "no hardware-enforced user auth; timeout not applicable")
    else:
        to = hw.get("authTimeout")
        ok = to is None or 0 <= to <= policy.max_auth_timeout
        ck.add("auth_timeout", ok, f"hw authTimeout={to if to is not None else 'absent (per-operation auth)'}"
                                   f" max={policy.max_auth_timeout}")

    sw_only = [TAGS[t][0] for t in AUTH_TAGS if TAGS[t][0] in sw and TAGS[t][0] not in hw]
    if policy.forbid_software_enforced_auth:
        ck.add("software_enforced_auth", not sw_only,
               f"auth tags only in softwareEnforced: {sw_only}" if sw_only else "no auth tag is software-only")
    else:
        ck.add("software_enforced_auth", None, f"not checked; software-only auth tags: {sw_only}")
    return _finish(res, ck)


def _finish(res: dict, ck: _Checks) -> dict:
    failed = [n for n, c in ck.d.items() if c["ok"] is False and c["severity"] == "fail"]
    warnings = list(ck.extra_warnings) + res.pop("_warnings", [])
    res["checks"] = ck.d
    res["failed"] = failed
    res["warnings"] = warnings
    res["verdict"] = "FAIL" if failed else ("PASS_WITH_WARNINGS" if warnings else "PASS")
    return res


# ---------------------------------------------------------------- files + CLI
_STAMP = re.compile(r"(\d{8}T\d{6}Z)")


def status_fetch_time(path: Path, status: dict) -> tuple[dt.datetime | None, str]:
    if isinstance(status, dict) and status.get("fetched_at"):
        return dt.datetime.fromisoformat(str(status["fetched_at"]).replace("Z", "+00:00")), "json"
    m = _STAMP.search(path.name)
    if m:
        return dt.datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC), "filename"
    return dt.datetime.fromtimestamp(path.stat().st_mtime, UTC), "mtime"


def verify_files(attest_path, challenge_path, status_path, policy: Policy, at: dt.datetime | None = None,
                 pinned_roots: dict | None = None) -> dict[str, Any]:
    attest_path, status_path = Path(attest_path), Path(status_path)
    cap = json.loads(attest_path.read_text())
    chain = [base64.b64decode(c, validate=True) for c in cap["chain"]]
    pop_sig = base64.b64decode(cap["pop_sig"]) if cap.get("pop_sig") else None
    expected = bytes.fromhex(Path(challenge_path).read_text().strip()) if challenge_path else None
    status = json.loads(status_path.read_text())
    fetched, src = status_fetch_time(status_path, status)
    res = verify(chain, expected, status, fetched, policy, pop_sig=pop_sig, at=at, pinned_roots=pinned_roots)
    res.update(attest_path=str(attest_path), status_path=str(status_path),
               status_fetched_at=fetched.isoformat() if fetched else None, status_fetched_at_source=src)
    if expected is not None and cap.get("challenge") and cap["challenge"].lower() != expected.hex():
        res["warnings"].append("capture JSON 'challenge' differs from the verifier's challenge file (file used)")
        if res["verdict"] == "PASS":
            res["verdict"] = "PASS_WITH_WARNINGS"
    return res


def _parse_at(s: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def main(argv: list[str] | None = None, pinned_roots: dict | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("attest_json")
    ap.add_argument("challenge_txt")
    ap.add_argument("status_json")
    ap.add_argument("--at", type=_parse_at, help="verification time (ISO-8601, default now)")
    ap.add_argument("--require-hw-tee", action="store_true")
    ap.add_argument("--require-strongbox", action="store_true")
    ap.add_argument("--require-locked-verified", action="store_true")
    ap.add_argument("--no-require-challenge", dest="require_challenge", action="store_false")
    ap.add_argument("--no-require-pop", dest="require_pop", action="store_false")
    ap.add_argument("--require-user-auth", choices=["any", "biometric"])
    ap.add_argument("--max-auth-timeout", type=int)
    ap.add_argument("--allow-software-enforced-auth", dest="forbid_sw", action="store_false")
    ap.add_argument("--expired-root", choices=["warn", "fail"], default="warn")
    ap.add_argument("--status-max-age", type=int, default=86400)
    ap.add_argument("--stale-status", choices=["warn", "fail"], default="warn")
    a = ap.parse_args(argv)
    pol = Policy(require_hw_tee=a.require_hw_tee, require_strongbox=a.require_strongbox,
                 require_locked_verified=a.require_locked_verified, require_challenge=a.require_challenge,
                 require_pop=a.require_pop, require_user_auth=a.require_user_auth,
                 max_auth_timeout=a.max_auth_timeout, forbid_software_enforced_auth=a.forbid_sw,
                 expired_root=a.expired_root, status_max_age_s=a.status_max_age, stale_status=a.stale_status)
    try:
        res = verify_files(a.attest_json, a.challenge_txt, a.status_json, pol, at=a.at, pinned_roots=pinned_roots)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(json.dumps({"verdict": "ERROR", "error": repr(e)}))
        return 64
    print(json.dumps(res, indent=1, default=str))
    return {"PASS": 0, "PASS_WITH_WARNINGS": 2}.get(res["verdict"], 1)


if __name__ == "__main__":
    sys.exit(main())
