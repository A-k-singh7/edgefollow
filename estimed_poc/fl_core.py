# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""The federated-learning core for the ESTIMED proof of
concept -- pure logic, no I/O. Records, a small integer model, aggregation, and every acceptance check as a
function of what a run observed. fl_run.py drives it against the lab's CSEs; test_fl.py checks it offline.

What it follows
  TR-0077 v0.4.0 clause 7.3.5.9.9   the minimal demonstration (two simulated sensor AEs, one MN-CSE, an IN-AE, a
                                    Trusted FL Client AE, one aggregator) and its eight acceptance checks: ac1..ac8
  test plan TD_MEC_FL_02            the ten steps of one round: fl02_1..fl02_10
  test plan TD_MEC_FL_01            the seven steps with simulated devices: the capability profile as a
                                    <flexContainer> (step 1), its discovery (step 2), the Trusted FL Client deployed
                                    as a MEC app (step 3, app_deployed) and registered at MEC 011 and at the MN-CSE
                                    on behalf of the constrained devices (step 4, fl01_4_*), the MEC proxy path
                                    (steps 5 and 6, fl01_5_proxy_path, fl01_6_*), the three classes enumerated
                                    (step 7, enumerate_candidates, fl01_7_*); TD_MEC_REG_03 for an app's AE (reg03_ae)
  review rows (federation_result)   a client that declines, readiness as six conditions, the orchestrator unable to
                                    grant itself access, a round below quorum, a version that was aggregated but not
                                    deployed, a package whose digest does not match: gov_*
The TR text was read through the fact reader's quotations (federation_result.json, reader "fl"); the attribute
lists in MVP_FIELDS are that reader's reading of tables the PDF extract scrambled.

OPEN DECISIONS -- defaults taken because no decision has been made; they are not facts about the project
  1. The model. A 3-weight linear model in Q8 fixed point (SCHEMA) that estimates the next battery temperature of a
     device from its current temperature and the charge it drained, trained by integer least-mean-squares steps.
     No float is used in training, in an update, in the aggregate or in any digest, so a checker can recompute
     every aggregate bit for bit (verify_round). The proof-of-concept plan's traffic model (numpy logistic
     regression on SUMO data) is the alternative; model quality is not what this shows.
  2. Keys. NO key material is created, stored or read. An update is bound to its round, its source and its data by
     SHA-256 digests (update_record), by the originator the CSE records as its creator, and by access control
     policies. That catches mix-ups and replays between honest parties; it does not stop a party that can write
     under a client's originator. The row NOT_RUN_SIGNATURE stays NOT-RUN until the ruling on lab keys.
  3. Sources. Every source is SIMULATED. Every record carries "sim": true, parse_env refuses a record without it,
     and a device class is worded "class represented by a simulated source" (CLASS_WORDING).

Thresholds the test plan leaves without a value (TD_MEC_FL_02 of the ESTIMED test plan) and that are ours: a round needs at
least QUORUM_MIN accepted updates and QUORUM_RATE of the selected participants; an update that is not there by the
deadline is left out and logged; an update is refused when any coordinate of its change exceeds UPDATE_BOUND. A
bound stops a gross outlier and nothing subtler: a wrong update inside the bound is accepted.

The six <fl...> resource types of the TR have no type numbers (TR lines 6573-6576 as reported), so every record
here is application data: JSON in a <contentInstance>, and the capability profile in two TS-0023 management module
classes the lab CSE already knows (mad:dmCay, mad:dmAgt). That mapping is ours. Not a conformance claim.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import math
import time
from decimal import Decimal, InvalidOperation
from fractions import Fraction

# ------------------------------------------------------------------------------------------------ constants
SCHEMA = "estimed.fl.int-linear.v1"
Q = 8                    # weights are Q8: real value = w / 256
LR_SHIFT = 6             # one training step adds round(error * feature / 64) to a weight
EPOCHS = 4               # local passes over a participant's samples in one round
N_W = 3                  # bias, temperature, drain
TEMP_REF_DC = 250        # temperatures are tenths of a degree C around 25.0 C
X_BIAS = 32              # the constant feature
DRAIN_UNIT = 32          # one point of battery drained in a period counts 32
UPDATE_BOUND = 1024      # an update may change a weight by at most this much (4.0 in real units)
PERIOD_MS = 5000         # the sampling period of sim_phone.py
QUORUM_MIN = 2
QUORUM_RATE = (2, 3)     # accepted / selected
PROCESSING_PROFILE = "estimed.fl.env-pairs.v1"    # the feature selection and time alignment of pairs() / assemble()
# Device records (fl_capture.py) are not on a time grid: the same features, aligned by slot.
PROFILES = {"exact": PROCESSING_PROFILE, "slot": "estimed.fl.env-slots.v1"}
ENV_KEYS = frozenset({"light", "proximity", "battery_pct", "battery_temp_c", "t"})   # LiveService.java's env record
SAMPLE_COUNT_METHOD = "aligned-pairs.v1"
WEIGHTING_BASIS = "effectiveSampleCount"
NOT_RUN_SIGNATURE = "signature of the update: not run, waits for a decision on lab keys"
CLASS_WORDING = {"fl-native": "FL-native class represented by a simulated source",
                 "fl-assisted": "constrained (FL-assisted) class represented by a simulated source",
                 "proxy-path": "MEC-native / non-oneM2M (proxy-path) class represented by a simulated source"}
DEVICE_CLASSES = ("fl-native", "fl-assisted", "proxy-path")     # TD_MEC_FL_01 step 7 of the test plan
PARTICIPANT_MODES = ("singleSource", "independentSources", "aggregatedSources")
# TR-0077 7.3.5.6 as reported (fact F13, TR lines 7070-7075): readiness is these six, and installation is none of them
READINESS_CONDITIONS = ("applicationRunning", "frameworkInitialized", "modelAccessible",
                        "credentialsAndCoordinatorConfigured", "authorizedLocalDataAccessible", "canAcceptTask")
READINESS_STATES = ("registered", "awaitingAuthorization", "preparing", "ready", "running", "blocked", "failed",
                    "retiring")
CONTRIBUTION_STATES = ("candidate", "authorized", "ready", "training", "submitted", "excluded", "revoked", "failed")
# Attributes the TR marks 'Yes' for a minimal demonstration, as the fact reader lists them (F15, F16, F30, F31) and
# the task record of 7.3.5.6 (F18). "use all attributes marked Yes above, with optional attributes omitted" (F39).
MVP_FIELDS = {
    "trustedFLClientProfile": ("clientAERef", "profileVersion", "executionHostRef", "hostingCSERef",
                               "clientOperatorRef", "executionDomainRef", "capabilityProfileRef",
                               "supportedParticipantModes", "supportedFrameworks", "maxSources", "dataAccessMethods",
                               "coordinatorRef", "activeOperationRefs", "readinessState"),
    "flParticipantProfile": ("participantId", "operationRef", "clientAERef", "participantMode", "datasetRef",
                             "datasetVersion", "sourceBindingRefs", "representedSourceCount", "effectiveSampleCount",
                             "sampleCountMethod", "overlapPolicyRef", "weightingPolicyRef", "trainingTaskRefs",
                             "contributionStatus"),
    "datasetProcessingPolicy": ("policyId", "policyVersion", "policyAuthorityRef", "processingPurpose",
                                "authorizedProcessorRefs", "allowedExecutionDomains", "allowedSourceRefs",
                                "permittedOperations", "permittedOutputClasses", "rawDataExportAllowed",
                                "temporaryRetentionDuration", "derivedDataRetentionRef", "expiryTime",
                                "revocationStatus"),
    "dataset": ("datasetVersion", "sourceDescriptorRefs", "processingProfileRef", "processingPolicyVersionRefs",
                "datasetProvenanceRef", "validSampleCount", "datasetLifecycleState", "retentionPolicyRef"),
    "task": ("taskId", "operationRef", "roundRef", "selectedClient", "modelRef", "trainingConfig",
             "dataSelectionPolicy", "deadline", "updateDestination", "statusTarget", "securityRefs"),
}
UPDATE_FIELDS = ("taskId", "operationRef", "round", "participantId", "clientAERef", "modelInDigest", "datasetRef",
                 "datasetVersion", "datasetDigest", "effectiveSampleCount", "delta", "sim", "updateDigest")
# Keys that mean an observation (sim_phone.py's record shapes) or a sample made from one.
RAW_KEYS = frozenset({"battery_temp_c", "battery_pct", "light", "proximity", "temp_dc", "pct", "samples", "accel",
                      "gyro", "mag", "rotvec", "fused", "lat", "lon", "cells", "neighbours", "ssid", "bssid"})
# Which side holds each control (TR 7.3.5.9.9 as reported, fact F38: a demonstration documents "which checks the
# CSE enforces versus the application").
ENFORCEMENT = (
    {"what": "who may read a source's observations", "enforced_by": "CSE",
     "how": "accessControlPolicy on the source's container; anyone else gets 403"},
    {"what": "who may change a source's access policy", "enforced_by": "CSE",
     "how": "the policy's selfPrivileges: the source and its authority"},
    {"what": "who may create an update at the aggregator", "enforced_by": "CSE",
     "how": "CREATE on the updates container for the registered clients, RETRIEVE for the aggregator alone"},
    {"what": "which originator wrote an update or a policy record", "enforced_by": "CSE",
     "how": "the creator attribute the CSE records; the lab CSE does not authenticate the originator header"},
    {"what": "that a capability profile is a flexContainer of a known specialisation", "enforced_by": "CSE",
     "how": "the CSE refuses an unknown specialisation or attribute (400)"},
    {"what": "what discovery returns to an originator", "enforced_by": "CSE",
     "how": "DISCOVERY privilege; metadata resources and observation containers carry different policies"},
    {"what": "purpose, operation, processor, execution domain and expiry of a data-use policy",
     "enforced_by": "application", "how": "authorize()"},
    {"what": "that a policy's authority is neither the requester nor the processor", "enforced_by": "application",
     "how": "authorize(), on the creator the CSE recorded"},
    {"what": "task, round, model and dataset binding of an update; replay; bound; deadline",
     "enforced_by": "application", "how": "check_update()"},
    {"what": "state of a source's policy when its update is accepted", "enforced_by": "application",
     "how": "check_update() on the policy record the aggregator read; the denied read itself is the CSE's"},
    {"what": "quorum before a model is published", "enforced_by": "application",
     "how": "close_round(), re-checked by verify_round()"},
    {"what": "readiness and a client's own decision to take part", "enforced_by": "application",
     "how": "select_participants()"},
    {"what": "package digest before activation, and which version is active", "enforced_by": "application",
     "how": "check_package(), deployment_view()"},
    {"what": "deletion of temporary copies", "enforced_by": "application",
     "how": "the client deletes; a read-back on the CSE (404) is the evidence"},
)


# ------------------------------------------------------------------------------------------------ digests, time
def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _no_float(o, path: str = "$") -> None:
    if isinstance(o, float):
        raise TypeError(f"float at {path}: a digested record holds integers, strings, booleans, lists, objects")
    if isinstance(o, dict):
        for k, v in o.items():
            if not isinstance(k, str):
                raise TypeError(f"non-string key at {path}")
            _no_float(v, f"{path}.{k}")
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            _no_float(v, f"{path}[{i}]")
    elif not (o is None or isinstance(o, (str, int))):
        raise TypeError(f"{type(o).__name__} at {path}")


def canon(o) -> bytes:
    """The one byte form a record is digested in: JSON, sorted keys, no spaces, ASCII. A float is refused."""
    _no_float(o)
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(o) -> str:
    return hashlib.sha256(canon(o)).hexdigest()


def text_digest(s: str) -> str:
    """SHA-256 of a string exactly as a CSE stores it (a contentInstance's con)."""
    return hashlib.sha256(s.encode()).hexdigest()


def ct_ms(ct: str) -> int:
    """A oneM2M creation time (UTC 'YYYYMMDDTHHMMSS[,ffffff]') as integer epoch milliseconds."""
    base, _, frac = ct.partition(",")
    return calendar.timegm(time.strptime(base, "%Y%m%dT%H%M%S")) * 1000 + int((frac + "000")[:3])


# ------------------------------------------------------------------------------------------------ data
def deci(v) -> int:
    """A reading in whole tenths, exactly. 25.3 -> 253. Decimal arithmetic on the number's text, no float
    arithmetic; a value that is not a whole tenth is refused, not rounded."""
    if isinstance(v, bool) or not isinstance(v, (int, float, str, Decimal)):
        raise TypeError(f"not a number: {v!r}")
    try:
        d = Decimal(str(v)) * 10
    except InvalidOperation as e:
        raise ValueError(f"not a number: {v!r}") from e
    if not d.is_finite() or d != d.to_integral_value():
        raise ValueError(f"{v!r} is not a whole tenth")
    return int(d)


def parse_env(con, device: bool = False) -> dict:
    """One env record of sim_phone.py's shape -> {t, temp_dc, pct}, integers. Feature selection: battery_temp_c,
    battery_pct and t are used, nothing else of the record. A record that does not say "sim": true is refused.

    device=True is the other case and only that: a record the probe app posted. It must NOT carry a sim mark, it may
    hold no key outside the app's env record (so a position or a network name cannot ride in), and its charge must
    be a real reading (the app writes -1 when it has none)."""
    r = json.loads(con, parse_float=Decimal) if isinstance(con, str) else con
    if device:
        if not isinstance(r, dict) or "sim" in r:
            raise ValueError("not a device env record (it carries a sim mark, or is not an object)")
        if set(r) - ENV_KEYS:
            raise ValueError(f"a device env record with keys outside the env shape: {sorted(set(r) - ENV_KEYS)}")
        if not _is_int(r.get("battery_pct")) or not 0 <= r["battery_pct"] <= 100:
            raise ValueError("battery_pct is not a reading between 0 and 100")
    elif not isinstance(r, dict) or r.get("sim") is not True:
        raise ValueError("not a simulated env record (no \"sim\": true)")
    if not _is_int(r.get("t")) or not _is_int(r.get("battery_pct")):
        raise ValueError("t and battery_pct must be integers")
    return {"t": r["t"], "temp_dc": deci(r.get("battery_temp_c")), "pct": r["battery_pct"]}


def pairs(records: list[dict], period_ms: int = PERIOD_MS, align: str = "exact") -> dict:
    """Time alignment inside one source: records ordered by t; a later record with a t already seen is dropped;
    two neighbours exactly one period apart make one sample: x = [temperature now, charge drained * DRAIN_UNIT],
    y = the next temperature (both temperatures as tenths around 25.0 C). Any other distance makes no sample.

    align="slot" (device records, whose times are a phone's clock and not a grid): a record's slot is its t rounded
    to the nearest whole period, half up; the first record of a slot is kept and a later one dropped; records in
    neighbouring slots make one sample, stamped with the first slot's start. The values of a record are not changed."""
    if align not in PROFILES:
        raise ValueError(f"alignment {align!r} is not one of {sorted(PROFILES)}")
    key = (lambda t: t) if align == "exact" else (lambda t: (t + period_ms // 2) // period_ms * period_ms)
    seen, rows, dup = set(), [], 0
    for r in sorted(records, key=lambda r: r["t"]):
        k = key(r["t"])
        if k in seen:
            dup += 1
            continue
        seen.add(k)
        rows.append((k, r))
    samples, gap = [], 0
    for (ka, a), (kb, b) in zip(rows, rows[1:]):
        if kb - ka != period_ms:
            gap += 1
            continue
        samples.append({"t": ka, "x": [a["temp_dc"] - TEMP_REF_DC, (a["pct"] - b["pct"]) * DRAIN_UNIT],
                        "y": b["temp_dc"] - TEMP_REF_DC})
    return {"samples": samples, "dropped_duplicate": dup, "dropped_gap": gap}


def assemble(per_source: dict, mode: str, period_ms: int = PERIOD_MS, align: str = "exact") -> dict:
    """A dataset from one source (singleSource, independentSources) or several (aggregatedSources). Alignment
    across sources: a window is used when EVERY source has a sample that starts in it, so each window counts once
    per source. Samples are ordered by (t, source)."""
    if mode not in PARTICIPANT_MODES or not per_source:
        raise ValueError(f"mode {mode!r} with {len(per_source)} source(s)")
    if mode != "aggregatedSources" and len(per_source) != 1:
        raise ValueError(f"{mode} takes one source per dataset; each source is its own participant")
    made = {s: pairs(r, period_ms, align) for s, r in sorted(per_source.items())}
    common = set.intersection(*({x["t"] for x in m["samples"]} for m in made.values()))
    samples = sorted(({"t": x["t"], "src": s, "x": x["x"], "y": x["y"]}
                      for s, m in made.items() for x in m["samples"] if x["t"] in common),
                     key=lambda x: (x["t"], x["src"]))
    return {"mode": mode, "align": align, "samples": samples,
            "per_source": {s: sum(1 for x in samples if x["src"] == s) for s in made},
            "dropped_unaligned": sum(len(m["samples"]) for m in made.values()) - len(samples),
            "dropped_gap": sum(m["dropped_gap"] for m in made.values()),
            "dropped_duplicate": sum(m["dropped_duplicate"] for m in made.values())}


def sim_series(seed: int, n: int, t0_ms: int, d0: int = 0, pct0: int = 90, period_ms: int = PERIOD_MS) -> list[dict]:
    """n SIMULATED env records in sim_phone.py's shape, one period apart on a simulated clock. The numbers come
    from a fixed integer rule chosen here (a load of 0..2 points per period warms the battery, half of the excess
    temperature is lost per period, +-0.1 C of noise); they describe no device. This is the simulator, not the
    update path: battery_temp_c is written as a float like sim_phone does, and parse_env reads it back exactly."""
    s, d, pct, out = seed & 0x7FFFFFFF, d0, pct0, []
    for k in range(n):
        out.append({"light": {"n": 5, "mean": [120.0], "last": [120.0]}, "proximity": {"n": 0},
                    "battery_pct": pct, "battery_temp_c": (TEMP_REF_DC + d) / 10, "t": t0_ms + k * period_ms,
                    "sim": True})
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
        load, noise = (s >> 16) % 3, (s >> 8) % 3 - 1
        d, pct = (d >> 1) + 6 * load + noise, pct - load
    return out


# ------------------------------------------------------------------------------------------------ the model
def _ints(v, n, what: str) -> None:
    if not isinstance(v, (list, tuple)) or (n is not None and len(v) != n) or not all(_is_int(x) for x in v):
        raise TypeError(f"{what} must be {n if n is not None else 'a list of'} integers, got {v!r}")


def rshift_round(a: int, s: int) -> int:
    """floor(a / 2**s + 1/2): division by a power of two, a half rounds up (towards plus infinity)."""
    return (a + (1 << (s - 1))) >> s


def predict(w, x) -> int:
    _ints(w, N_W, "weights")
    _ints(x, 2, "features")
    return rshift_round(w[0] * X_BIAS + w[1] * x[0] + w[2] * x[1], Q)


def train(w, samples: list[dict], epochs: int = 1) -> list[int]:
    """Integer least-mean-squares: for each sample in the given order, error = y - prediction, and each weight
    gains rshift_round(error * its feature, LR_SHIFT). Returns a new vector."""
    w = list(w)
    for _ in range(epochs):
        for s in samples:
            _ints([s["y"]], 1, "target")
            err = s["y"] - predict(w, s["x"])
            for j, xj in enumerate((X_BIAS, s["x"][0], s["x"][1])):
                w[j] += rshift_round(err * xj, LR_SHIFT)
    return w


def delta(w_new, w_old) -> list[int]:
    _ints(w_new, len(w_old), "weights")
    return [a - b for a, b in zip(w_new, w_old)]


def loss(w, samples: list[dict]) -> int:
    """Sum of absolute errors, in tenths of a degree."""
    return sum(abs(s["y"] - predict(w, s["x"])) for s in samples)


def model_body(w) -> dict:
    _ints(w, N_W, "weights")
    return {"schema": SCHEMA, "q": Q, "w": list(w)}


def model_digest(w) -> str:
    return digest(model_body(w))


def fedavg(w_global, contributions: list[tuple[list[int], int]]) -> list[int]:
    """FedAvg on changes: each weight gains the average of the participants' changes, weighted by their sample
    counts n, rounded half up: floor((2 * sum(n * d) + N) / (2 * N)) with N = sum(n). Integers throughout."""
    _ints(w_global, None, "the model")
    if not contributions:
        raise ValueError("no contribution")
    for d, n in contributions:
        _ints(d, len(w_global), "a change")
        if not _is_int(n):
            raise TypeError(f"a weight must be an integer sample count, got {n!r}")
        if n <= 0:
            raise ValueError(f"a weight must be positive, got {n}")
    den = sum(n for _, n in contributions)
    return [wj + (2 * sum(n * d[j] for d, n in contributions) + den) // (2 * den) for j, wj in enumerate(w_global)]


def quorum_needed(selected: int) -> int:
    """Accepted updates a round needs: at least QUORUM_MIN and QUORUM_RATE of the selected, rounded up."""
    num, den = QUORUM_RATE
    return max(QUORUM_MIN, -(-num * selected // den))


# ------------------------------------------------------------------------------------------------ records
def missing_fields(kind: str, record: dict) -> list[str]:
    return [f for f in MVP_FIELDS[kind] if f not in record]


def cap_fcnt(can_train: bool, enabled: bool, labels: list[str]) -> dict:
    """The capability part of a profile as a TS-0023 dmCapability flexContainer: attached = the participant can
    train locally, currentState = it does so now. Labels carry what discovery filters on."""
    return {"mad:dmCay": {"rn": "flCap", "cnd": "org.onem2m.management.moduleclass.dmCapability",
                          "name": "fl.localTraining", "attad": bool(can_train), "curSe": bool(enabled),
                          "lbl": list(labels)}}


def compute_fcnt(*, ram_total: int, ram_free: int, storage_total: int, storage_free: int, cpu_pct: int) -> dict:
    """The compute part as a TS-0023 dmAgent flexContainer. Units as used here: KiB and percent; state 1 stands
    for 'running'. TS-0023's own units and enumeration were not checked; the numbers are declared, not measured."""
    _ints([ram_total, ram_free, storage_total, storage_free, cpu_pct], 5, "compute figures")
    return {"mad:dmAgt": {"rn": "flCompute", "cnd": "org.onem2m.management.moduleclass.dmAgent", "state": 1,
                          "ramTl": ram_total, "ramAe": ram_free, "stoTl": storage_total, "stoAe": storage_free,
                          "cpuUe": cpu_pct}}


def capability_of(fcnt: dict) -> dict:
    """What selection needs from a capability flexContainer as a CSE returns it."""
    c = (fcnt or {}).get("mad:dmCay") or {}
    return {"canTrain": c.get("attad") is True, "enabled": c.get("curSe") is True}


def policy_record(source: str, authority: str, version: str, *, processors: list[str], domains: list[str],
                  expiry_ms: int, operations=("train",), status: str = "active") -> dict:
    """A datasetProcessingPolicy with every attribute of MVP_FIELDS. rawDataExportAllowed is false (the TR's
    default for a minimal demonstration, fact F30); expiryTime is epoch milliseconds."""
    return {"policyId": f"{source}-policy", "policyVersion": version, "policyAuthorityRef": authority,
            "processingPurpose": "fl-training", "authorizedProcessorRefs": list(processors),
            "allowedExecutionDomains": list(domains), "allowedSourceRefs": [source],
            "permittedOperations": list(operations), "permittedOutputClasses": ["model-update"],
            "rawDataExportAllowed": False, "temporaryRetentionDuration": "PT60S",
            "derivedDataRetentionRef": "model-lineage", "expiryTime": expiry_ms, "revocationStatus": status,
            "sim": True}


def authorize(sources: list[str], policies: dict, *, purpose: str, operation: str, processor: str, domain: str,
              requester: str, now_ms: int) -> dict:
    """The data-use decision for a dataset over `sources`. policies: {source: {"record": the latest policy record,
    "creator": the originator the CSE recorded for it}}. Every source must permit; one refusal refuses the dataset.
    The authority must be the record's creator and neither the requester (the orchestrator) nor the processor (the
    client): nobody grants itself access."""
    refs, refusals = [], {}
    for s in sources:
        entry = policies.get(s)
        if not entry:
            refusals[s] = ["no-policy"]
            refs.append(f"{s}-policy@none:deny")
            continue
        p, why = entry["record"], []
        if missing_fields("datasetProcessingPolicy", p):
            why = ["malformed"]
        else:
            if p["policyAuthorityRef"] != entry.get("creator"):
                why.append("authority-not-creator")
            if p["policyAuthorityRef"] in (requester, processor):
                why.append("authority-is-party")
            if p["revocationStatus"] != "active":
                why.append("revoked")
            if not _is_int(p["expiryTime"]) or p["expiryTime"] <= now_ms:
                why.append("expired")
            if p["processingPurpose"] != purpose:
                why.append("purpose")
            if operation not in p["permittedOperations"]:
                why.append("operation-not-permitted")
            if processor not in p["authorizedProcessorRefs"]:
                why.append("processor-not-authorized")
            if domain not in p["allowedExecutionDomains"]:
                why.append("domain-not-allowed")
            if s not in p["allowedSourceRefs"]:
                why.append("source-not-covered")
            if p["rawDataExportAllowed"] is not False:
                why.append("raw-export-allowed")
        refs.append(f"{p.get('policyId')}@{p.get('policyVersion')}:{'deny' if why else 'permit'}")
        if why:
            refusals[s] = why
    return {"authorized": bool(sources) and not refusals, "decisionRefs": refs, "refusals": refusals}


def dataset_record(dataset_id: str, version: str, assembled: dict, *, sources: list[str], provenance: list[dict],
                   policy_versions: list[str], state: str = "valid") -> dict:
    """What is published about a dataset: version, provenance and effective sample count, never a sample."""
    n = len(assembled["samples"])
    return {"datasetId": dataset_id, "datasetVersion": version, "sourceDescriptorRefs": list(sources),
            "processingProfileRef": PROFILES[assembled.get("align", "exact")], "processingPolicyVersionRefs": list(policy_versions),
            "datasetProvenanceRef": digest(provenance), "validSampleCount": n, "effectiveSampleCount": n,
            "sampleCountMethod": SAMPLE_COUNT_METHOD, "datasetDigest": digest(assembled["samples"]),
            "datasetLifecycleState": state, "retentionPolicyRef": "temporary copies deleted when the round closes",
            "participantMode": assembled["mode"],
            "dropped": {k: assembled[k] for k in ("dropped_unaligned", "dropped_gap", "dropped_duplicate")},
            "sim": True}


def tfc_profile(client: str, *, version: str, host: str, cse: str, operator: str, domain: str, capability_ref: str,
                max_sources: int, coordinator: str, operations: list[str], state: str) -> dict:
    if state not in READINESS_STATES:
        raise ValueError(f"unknown readiness state {state!r}")
    return {"clientAERef": client, "profileVersion": version, "executionHostRef": host, "hostingCSERef": cse,
            "clientOperatorRef": operator, "executionDomainRef": domain, "capabilityProfileRef": capability_ref,
            "supportedParticipantModes": list(PARTICIPANT_MODES), "supportedFrameworks": [SCHEMA],
            "maxSources": max_sources, "dataAccessMethods": ["retrieve of the source's container over Mca"],
            "coordinatorRef": coordinator, "activeOperationRefs": list(operations), "readinessState": state,
            "sim": True}


def participant_profile(participant_id: str, operation: str, client: str, mode: str, *, dataset_ref: str,
                        dataset_version: str, sources: list[str], effective_sample_count: int,
                        task_refs: list[str], status: str = "authorized") -> dict:
    """representedSourceCount is recorded and is NOT the participant's weight (fact F16); the weight is the
    effective sample count."""
    if mode not in PARTICIPANT_MODES or status not in CONTRIBUTION_STATES:
        raise ValueError(f"mode {mode!r}, status {status!r}")
    return {"participantId": participant_id, "operationRef": operation, "clientAERef": client,
            "participantMode": mode, "datasetRef": dataset_ref, "datasetVersion": dataset_version,
            "sourceBindingRefs": list(sources), "representedSourceCount": len(sources),
            "effectiveSampleCount": effective_sample_count, "sampleCountMethod": SAMPLE_COUNT_METHOD,
            "overlapPolicyRef": "a source's window is used once per dataset", "weightingPolicyRef": WEIGHTING_BASIS,
            "trainingTaskRefs": list(task_refs), "contributionStatus": status, "sim": True}


def task_id(operation: str, rnd: int, participant_id: str) -> str:
    return f"{operation}-r{rnd}-{participant_id}"


def task_record(operation: str, rnd: int, participant_id: str, client: str, *, model_ref: str, model_digest: str,
                binding_version: str, deadline_ms: int, update_destination: str, status_target: str) -> dict:
    return {"taskId": task_id(operation, rnd, participant_id), "operationRef": operation, "roundRef": rnd,
            "participantId": participant_id, "selectedClient": client, "modelRef": model_ref,
            "modelDigest": model_digest, "bindingVersion": binding_version,
            "trainingConfig": {"schema": SCHEMA, "epochs": EPOCHS, "lrShift": LR_SHIFT, "bound": UPDATE_BOUND},
            "dataSelectionPolicy": PROCESSING_PROFILE, "deadline": deadline_ms,
            "updateDestination": update_destination, "statusTarget": status_target,
            "securityRefs": {"binding": "SHA-256 digests, the CSE-recorded creator, access control policies",
                             "signature": NOT_RUN_SIGNATURE}, "sim": True}


def verify_task(task: dict, *, me: str, binding_version: str, model_body: dict) -> list[str]:  # noqa: A002
    """What a client checks before it trains: 'Task identity, binding version and model digest are verified
    before training' (TR 7.3.5.6 as reported, fact F18)."""
    why = []
    if task.get("taskId") != task_id(task.get("operationRef"), task.get("roundRef"), task.get("participantId")):
        why.append("task-id")
    if task.get("selectedClient") != me:
        why.append("not-my-task")
    if task.get("bindingVersion") != binding_version:
        why.append("binding-version")
    try:
        ok = digest(model_body) == task.get("modelDigest")
    except TypeError:
        ok = False
    if not ok:
        why.append("model-digest")
    return why


def update_record(task: dict, *, dataset_ref: str, dataset_version: str, dataset_digest: str,
                  effective_sample_count: int, delta: list[int]) -> dict:  # noqa: A002
    """A participant's update: the change to the model, bound to its task, round, input model and dataset.
    updateDigest is the SHA-256 of every other field. The fields are a closed set: nothing else rides along."""
    u = {"taskId": task["taskId"], "operationRef": task["operationRef"], "round": task["roundRef"],
         "participantId": task["participantId"], "clientAERef": task["selectedClient"],
         "modelInDigest": task["modelDigest"], "datasetRef": dataset_ref, "datasetVersion": dataset_version,
         "datasetDigest": dataset_digest, "effectiveSampleCount": effective_sample_count, "delta": list(delta),
         "sim": True}
    u["updateDigest"] = digest(u)
    return u


def _update_shape_ok(u) -> bool:
    if not isinstance(u, dict) or set(u) != set(UPDATE_FIELDS) or u["sim"] is not True:
        return False
    if not all(isinstance(u[k], str) for k in ("taskId", "operationRef", "participantId", "clientAERef",
                                               "modelInDigest", "datasetRef", "datasetVersion", "datasetDigest",
                                               "updateDigest")):
        return False
    if not _is_int(u["round"]) or not _is_int(u["effectiveSampleCount"]) or u["effectiveSampleCount"] <= 0:
        return False
    d = u["delta"]
    return isinstance(d, list) and len(d) == N_W and all(_is_int(x) for x in d)


def check_update(u, creator: str, created_ms: int, rd: dict, ctx: dict) -> list[str]:
    """The aggregator's objections to one update; [] means eligible.
    rd   the round: operationRef, round, modelDigest, deadline_ms, selected [participantId], tasks {taskId: task}
    ctx  what the aggregator read for itself: source_state {source: 'active' | ...}, datasets {(ref, version):
         {digest, n, state, sources}} as their publishers posted them, seen = update digests accepted before
    creator, created_ms   the originator and the creation time the CSE recorded for the contentInstance"""
    if not _update_shape_ok(u):
        return ["malformed"]
    why = []
    if digest({k: v for k, v in u.items() if k != "updateDigest"}) != u["updateDigest"]:
        why.append("digest-mismatch")
    task = rd["tasks"].get(u["taskId"])
    if task is None:
        why.append("unknown-task")
    elif task["participantId"] != u["participantId"] or task["selectedClient"] != u["clientAERef"]:
        why.append("wrong-participant")
    if creator != u["clientAERef"]:
        why.append("creator-mismatch")
    if u["round"] != rd["round"] or u["operationRef"] != rd["operationRef"]:
        why.append("wrong-round")
    if u["modelInDigest"] != rd["modelDigest"]:
        why.append("stale-model")
    if u["updateDigest"] in ctx.get("seen", ()):
        why.append("replay")
    if any(abs(x) > UPDATE_BOUND for x in u["delta"]):
        why.append("out-of-bound")
    if created_ms > rd["deadline_ms"]:
        why.append("late")
    ds = ctx["datasets"].get((u["datasetRef"], u["datasetVersion"]))
    if ds is None:
        why.append("unknown-dataset")
    else:
        if ds["state"] != "valid":
            why.append("dataset-invalid")
        if ds["digest"] != u["datasetDigest"] or ds["n"] != u["effectiveSampleCount"]:
            why.append("dataset-mismatch")
        if any(ctx["source_state"].get(s) != "active" for s in ds["sources"]):
            why.append("source-revoked")
    if u["participantId"] not in rd["selected"]:
        why.append("not-selected")
    return why


def close_round(rd: dict, submissions: list[dict], ctx: dict) -> dict:
    """Close a round over everything found in the updates container. submissions: [{update, creator,
    created_ms}]. Updates are taken in creation order; the first eligible one per task counts and anything after
    it for that task is a replay. Below quorum NO model is produced. The returned record holds what a checker
    needs to recompute the result (verify_round)."""
    seen = set(ctx.get("seen", ()))
    accepted, excluded, tasks_done = [], [], set()

    def order(s):
        u = s.get("update")
        return (s.get("created_ms", 0), str(u.get("updateDigest", "")) if isinstance(u, dict) else "")
    for s in sorted(submissions, key=order):
        u = s["update"]
        why = check_update(u, s["creator"], s["created_ms"], rd, {**ctx, "seen": seen})
        if not why and u["taskId"] in tasks_done:
            why = ["replay"]
        if why:
            excluded.append({"participantId": u.get("participantId") if isinstance(u, dict) else None,
                             "updateDigest": u.get("updateDigest") if isinstance(u, dict) else None, "reasons": why})
            continue
        tasks_done.add(u["taskId"])
        seen.add(u["updateDigest"])
        accepted.append({"participantId": u["participantId"], "updateDigest": u["updateDigest"],
                         "delta": list(u["delta"]), "n": u["effectiveSampleCount"], "created_ms": s["created_ms"]})
    accepted.sort(key=lambda a: a["participantId"])
    heard = {a["participantId"] for a in accepted} | {e["participantId"] for e in excluded}
    missing = [{"participantId": p, "reasons": ["no-update-by-deadline"]} for p in rd["selected"] if p not in heard]
    need = quorum_needed(len(rd["selected"]))
    met = len(accepted) >= need
    w_out = fedavg(rd["w"], [(a["delta"], a["n"]) for a in accepted]) if met else None
    return {"operationRef": rd["operationRef"], "round": rd["round"], "modelInDigest": rd["modelDigest"],
            "w_in": list(rd["w"]), "deadline_ms": rd["deadline_ms"], "selected": list(rd["selected"]),
            "accepted": accepted, "excluded": excluded, "missing": missing,
            "quorum": {"needed": need, "accepted": len(accepted), "selected": len(rd["selected"]), "met": met},
            "weightingBasis": WEIGHTING_BASIS, "state": "COMPLETED" if met else "FAILED_QUORUM", "w_out": w_out,
            "modelOutDigest": model_digest(w_out) if met else None, "seen": sorted(seen), "sim": True}


def exact_average(w_in, accepted: list[dict]) -> list[int]:
    """The checker's own arithmetic for the aggregate, written a second way on purpose: the weighted mean of the
    accepted changes as an exact fraction, plus one half, rounded down. fedavg() must give the same integers."""
    den = sum(a["n"] for a in accepted)
    return [wj + math.floor(Fraction(sum(a["n"] * a["delta"][j] for a in accepted), den) + Fraction(1, 2))
            for j, wj in enumerate(w_in)]


def verify_round(r: dict) -> list[str]:
    """A checker's objections to a round record, recomputed from the record alone; [] means it holds. This is
    where 'every aggregate can be recomputed bit for bit' is checked -- with exact_average(), not with the
    aggregator's own fedavg() -- and where a published model of a round below quorum, or an accepted update
    outside the bound or after the deadline, is reported."""
    bad = []
    if r.get("sim") is not True:
        bad.append("not-sim")
    acc, sel = r["accepted"], r["selected"]
    need = quorum_needed(len(sel))
    if r.get("quorum") != {"needed": need, "accepted": len(acc), "selected": len(sel), "met": len(acc) >= need}:
        bad.append("quorum-fields")
    published = r.get("w_out") is not None or r.get("modelOutDigest") is not None
    if len(acc) < need and (published or r.get("state") != "FAILED_QUORUM"):
        bad.append("below-quorum-published")
    if len(acc) >= need and (r.get("state") != "COMPLETED" or r.get("w_out") is None):
        bad.append("state")
    try:
        ok = r["modelInDigest"] == model_digest(r["w_in"])
        if r.get("w_out") is not None:
            ok = ok and r["w_out"] == exact_average(r["w_in"], acc) \
                and r.get("modelOutDigest") == model_digest(r["w_out"])
    except (TypeError, ValueError, KeyError, IndexError, ZeroDivisionError):
        ok = False
    if not ok:
        bad.append("aggregate-mismatch")
    if any(a["participantId"] not in sel for a in acc):
        bad.append("accepted-not-selected")
    if len({a["participantId"] for a in acc}) != len(acc) or len({a["updateDigest"] for a in acc}) != len(acc):
        bad.append("duplicate-accepted")
    if any(not isinstance(a.get("delta"), list) or any(not _is_int(x) or abs(x) > UPDATE_BOUND for x in a["delta"])
           for a in acc):
        bad.append("out-of-bound-accepted")
    if any(a.get("created_ms", 0) > r["deadline_ms"] for a in acc):
        bad.append("late-accepted")
    if {a["updateDigest"] for a in acc} & {e.get("updateDigest") for e in r.get("excluded", [])}:
        bad.append("accepted-and-excluded")
    return bad


def is_ready(conditions) -> bool:
    return isinstance(conditions, dict) and all(conditions.get(k) is True for k in READINESS_CONDITIONS)


def select_participants(candidates: list[dict]) -> dict:
    """Selection from discovered capability profiles. A candidate: participantId, clientAERef, discovered,
    capability {canTrain, enabled}, readiness {six conditions}, authorized (the data-use decision), decision
    ('accepted' | 'declined' | None: the client's own answer). 'A candidate may decline even when descriptors
    match' (TR as reported, fact F28): descriptors_match lists those with no objection but their own answer."""
    selected, rejected, match = [], {}, []
    for c in sorted(candidates, key=lambda c: c["participantId"]):
        pid, why = c["participantId"], []
        if c.get("discovered") is not True:
            why.append("not-discovered")
        cap = c.get("capability") or {}
        if cap.get("canTrain") is not True or cap.get("enabled") is not True:
            why.append("cannot-train")
        r = c.get("readiness") if isinstance(c.get("readiness"), dict) else {}
        off = [k for k in READINESS_CONDITIONS if r.get(k) is not True]
        if off:
            why.append(f"not-ready:{off[0]}")
        if c.get("authorized") is not True:
            why.append("not-authorized")
        if not why:
            match.append(pid)
        if c.get("decision") == "declined":
            why.append("declined")
        elif c.get("decision") != "accepted":
            why.append("no-decision")
        if why:
            rejected[pid] = why
        else:
            selected.append(pid)
    return {"selected": selected, "rejected": rejected, "descriptors_match": match}


def model_package(version: int, w, *, parent_digest: str, round_ref: int) -> dict:
    return {"packageId": f"pkg-v{version}", "modelVersion": version, "model": model_body(w),
            "modelDigest": model_digest(w), "parentDigest": parent_digest, "roundRef": round_ref, "sim": True}


def check_package(pkg: dict, published_digest: str | None) -> list[str]:
    """A target's objections before it activates a package: 'validates identity and integrity, and verifies
    compatibility' (TR 7.3.2.7 as reported, fact F20). published_digest is what the aggregator published for that
    version, read by the target itself."""
    m = pkg.get("model") if isinstance(pkg, dict) else None
    if (not isinstance(m, dict) or m.get("schema") != SCHEMA or m.get("q") != Q or not isinstance(m.get("w"), list)
            or len(m["w"]) != N_W or not all(_is_int(x) for x in m["w"])):
        return ["schema"]
    why = []
    if digest(m) != pkg.get("modelDigest"):
        why.append("digest-mismatch")
    if published_digest is None or pkg.get("modelDigest") != published_digest:
        why.append("not-published")
    return why


def deployment_view(published: dict, activations: list[dict]) -> dict:
    """published {version: digest the aggregator published}; activations, oldest first: what a target reported
    {modelVersion, modelDigest, verdict}. The active version is the latest activation that echoes the published
    digest of its version. A version that was aggregated and never activated is not active, whatever its number."""
    active, ever = None, set()
    for a in activations:
        v = a.get("modelVersion")
        if a.get("verdict") == "activated" and v in published and a.get("modelDigest") == published[v]:
            active = v
            ever.add(v)
    return {"aggregated": sorted(published), "active": active, "undeployed": sorted(set(published) - ever)}


def scan_raw(o, path: str = "$") -> list[str]:
    """Paths under which an observation, or a sample made from one, appears -- also inside JSON carried as a
    string (a contentInstance's con). [] means none."""
    out = []
    if isinstance(o, dict):
        for k, v in o.items():
            if k in RAW_KEYS:
                out.append(f"{path}.{k}")
            out += scan_raw(v, f"{path}.{k}")
    elif isinstance(o, (list, tuple)):
        for i, v in enumerate(o):
            out += scan_raw(v, f"{path}[{i}]")
    elif isinstance(o, str) and o[:1] in ("{", "["):
        try:
            out += scan_raw(json.loads(o), path + "<json>")
        except ValueError:
            pass
    return out


def kpi_rate(numerator: int, denominator: int, unit: str = "%") -> dict:
    """A rate with what it was counted from. N is the number of trials (the denominator); the value is a string
    with one decimal, rounded half up in integer arithmetic; with no trials there is no value."""
    if not _is_int(numerator) or not _is_int(denominator) or not 0 <= numerator <= denominator:
        raise ValueError(f"not a rate: {numerator!r} of {denominator!r}")
    if denominator == 0:
        return {"numerator": 0, "denominator": 0, "N": 0, "unit": unit, "value": None, "note": "no trials"}
    tenths = (2000 * numerator + denominator) // (2 * denominator)
    return {"numerator": numerator, "denominator": denominator, "N": denominator, "unit": unit,
            "value": f"{tenths // 10}.{tenths % 10}"}


# ------------------------------------------------------------------------------------------------ the checks
# Each takes what a run observed (a dict, described in its docstring) and returns (holds, detail). fl_run.py fills
# the dicts from the CSEs' answers; it decides nothing itself.
def _v(conds: list[tuple[bool, str]]) -> tuple[bool, str]:
    bad = [text for ok, text in conds if not ok]
    return not bad, ("not met: " + "; ".join(bad)) if bad else "ok"


def kpi_ok(block: dict) -> tuple[bool, str]:
    """TD_MEC_OBS_01 step 4 of the test plan, as far as federated learning goes: every rate carries its
    numerator, denominator, N and unit and its value follows from them; every list of values carries its N."""
    conds = [(block.get("sim") is True, "the block says sim: true"),
             (bool(block.get("rates")), "at least one rate")]
    for name, r in (block.get("rates") or {}).items():
        has = isinstance(r, dict) and all(k in r for k in ("numerator", "denominator", "N", "unit", "value"))
        conds.append((has, f"{name} has numerator, denominator, N, unit, value"))
        if has:
            try:
                want = kpi_rate(r["numerator"], r["denominator"], r["unit"])
                conds.append((r["N"] == want["N"] and r["value"] == want["value"], f"{name}: value and N follow"))
            except ValueError:
                conds.append((False, f"{name} is a rate"))
    for name in ("fl_round_completion_time_s", "edge_cloud_bytes"):
        v = block.get(name)
        conds.append((isinstance(v, dict) and isinstance(v.get("values"), list) and v.get("N") == len(v["values"])
                      and bool(v.get("unit")), f"{name} has values, their N and a unit"))
    return _v(conds)


def ac1_register_discover(o: dict) -> tuple[bool, str]:
    """TR 7.3.5.9.9 check 1: 'Register two Data Source AEs and the TFC AE; discover the source metadata and TFC
    capability without exporting observations during discovery'.
    o: registered {AE: status}, expect_sources, expect_tfc, found {sources, tfc}, payloads (every answer the
    orchestrator received while discovering)."""
    names = [*o["expect_sources"], o["expect_tfc"]]
    return _v([(len(o["expect_sources"]) == 2, "two data sources"),
               (all(o["registered"].get(n) == 201 for n in names), "the two sources and the client registered (201)"),
               (set(o["expect_sources"]) <= set(o["found"]["sources"]), "both sources' metadata found"),
               (o["expect_tfc"] in o["found"]["tfc"], "the client's capability found"),
               (scan_raw(o["payloads"]) == [], "no observation in what discovery returned")])


def ac2_policy_decision(o: dict) -> tuple[bool, str]:
    """Check 2: 'Create an authorized multi-source dataset definition, validate both source policies and record
    the decision references; demonstrate refusal when one policy denies training.'
    o: granted, denied (two authorize() results), n_sources, denied_dataset (must be None)."""
    g, d = o["granted"], o["denied"]
    return _v([(g["authorized"] is True, "the definition is authorised"),
               (len(set(g["decisionRefs"])) == o["n_sources"] >= 2 and all(r.endswith(":permit") for r in g["decisionRefs"]),
                "one permit reference per source policy"),
               (d["authorized"] is False, "the definition is refused when one policy denies"),
               (any("operation-not-permitted" in why for why in d["refusals"].values()),
                "the refusal names the policy that does not permit training"),
               (o["denied_dataset"] is None, "no dataset was assembled after the refusal")])


def ac3_dataset(o: dict) -> tuple[bool, str]:
    """Check 3: 'Assemble a dataset using explicit feature selection and time-alignment rules; publish version,
    provenance and effective sample count'. o: record, published (read back), samples, provenance, and align (the
    alignment the caller used; "exact" when not given)."""
    r = o["record"]
    return _v([(r.get("processingProfileRef") == PROFILES.get(o.get("align", "exact")), "the record names the rules that were used"),
               (bool(r.get("datasetVersion")), "a version"),
               (r.get("effectiveSampleCount") == r.get("validSampleCount") == len(o["samples"]) > 0,
                "the effective sample count is the number of aligned samples"),
               (r.get("datasetDigest") == digest(o["samples"]), "the dataset digest is the samples'"),
               (r.get("datasetProvenanceRef") == digest(o["provenance"]), "the provenance reference is the list's digest"),
               (o["published"] == r, "the published copy is the record"),
               (scan_raw(o["published"]) == [], "the published copy holds no observation")])


def ac4_aggregated(o: dict) -> tuple[bool, str]:
    """Check 4: 'Execute aggregatedSources mode and verify one participant/update is sent even though two sensors
    contribute; log weighting basis.' o: client, sources, profile, tasks and updates of that client in the round
    (updates as {participantId, creator}), round (the round record)."""
    p, r = o["profile"], o["round"]
    mine = [a for a in r.get("accepted", []) if a["participantId"] == p["participantId"]]
    return _v([(p.get("participantMode") == "aggregatedSources", "mode aggregatedSources"),
               (p.get("representedSourceCount") == len(p.get("sourceBindingRefs", [])) == o["sources"] >= 2,
                "two sources contribute"),
               (len([t for t in o["tasks"] if t["selectedClient"] == o["client"]]) == 1, "one participant (one task)"),
               (len([u for u in o["updates"] if u["creator"] == o["client"]]) == 1, "one update from the client"),
               (r.get("weightingBasis") == WEIGHTING_BASIS, "the weighting basis is logged"),
               (len(mine) == 1 and mine[0]["n"] == p["effectiveSampleCount"] != p["representedSourceCount"],
                "its weight is the effective sample count, not the source count")])


def ac5_independent(o: dict) -> tuple[bool, str]:
    """Check 5: 'Execute independentSources mode and verify separate task, participant and update identities (not
    a claim of statistical independence)'. o: client, tasks, profiles, updates of that client in the round."""
    t, p, u = o["tasks"], o["profiles"], o["updates"]
    pairs_ok = {(x["taskId"], x["participantId"]) for x in u} == {(x["taskId"], x["participantId"]) for x in t}
    return _v([(len(t) == len(p) == len(u) == 2, "two tasks, two participants, two updates"),
               (all(x["selectedClient"] == o["client"] for x in t), "one client AE"),
               (len({x["taskId"] for x in t}) == 2 and len({x["participantId"] for x in t}) == 2, "separate task identities"),
               (len({x["participantId"] for x in p}) == 2 and len({x["datasetRef"] for x in p}) == 2
                and all(x["participantMode"] == "independentSources" and x["representedSourceCount"] == 1 for x in p),
                "separate participants, one source and one dataset each"),
               (len({x["updateDigest"] for x in u}) == 2 and len({x["participantId"] for x in u}) == 2
                and len({x["datasetRef"] for x in u}) == 2 and pairs_ok, "separate update identities, each for its own task")])


def ac6_revocation(o: dict) -> tuple[bool, str]:
    """Check 6: 'Revoke one source mid-task; confirm future CSE reads are denied as applicable, the affected
    dataset is marked invalid and the active training update is excluded where still pending.'"""
    ex = [e for e in o["excluded"] if e["participantId"] == o["affected"]]
    return _v([(o["read_before"] == 200, "the client could read the source before"),
               (o["policy_state"] == "revoked", "the authority's policy record says revoked"),
               (o["read_after"] == 403, "the CSE denies the client's read afterwards (403)"),
               (o["dataset_state"] == "invalid", "the dataset is marked invalid"),
               (bool(ex) and all("source-revoked" in e["reasons"] for e in ex), "the pending update is excluded for it"),
               (o["affected"] not in o["accepted"], "and is not among the accepted")])


def ac7_relocation(o: dict) -> tuple[bool, str]:
    """Check 7: 'Simulate moving the TFC to a differently operated host; block data access until fresh
    authorization is approved'."""
    return _v([(o["read_before"] == 403, "the CSE denies the moved client's read (403)"),
               (o["binding_before"]["authorized"] is False, "the old policy does not cover the new host"),
               (o["fresh_policy_version"].isdigit() and o["old_policy_version"].isdigit()
                and int(o["fresh_policy_version"]) > int(o["old_policy_version"]), "a fresh policy version was issued"),
               (o["binding_after"]["authorized"] is True, "the fresh policy covers the new host"),
               (o["read_after"] == 200, "the read is allowed after it (200)")])


def ac8_retention(o: dict) -> tuple[bool, str]:
    """Check 8: 'Verify retention cleanup statuses for temporary copies and document any copies or model
    contributions that cannot be deleted or reversed.'"""
    return _v([(bool(o["temp_copies"]), "temporary copies were recorded"),
               (all(c.get("created") == 201 and c.get("readback") == 404 for c in o["temp_copies"]),
                "every temporary copy is gone on read-back (404)"),
               (o["accepted_from_revoked"] == 0 or bool(o["irreversible"]), "what cannot be undone is listed"),
               (all(i.get("what") and i.get("why") for i in o["irreversible"]), "each entry says what and why")])


def fl01_1_capability_fcnt(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 1: the capability profile 'via <flexContainer> or <mgmtObj>'. o: created {flCap,
    flCompute: status}, readback {flCap, flCompute: the CSE's answer}."""
    cap = (o["readback"].get("flCap") or {}).get("mad:dmCay") or {}
    agt = (o["readback"].get("flCompute") or {}).get("mad:dmAgt") or {}
    return _v([(o["created"].get("flCap") == 201 and o["created"].get("flCompute") == 201, "both created (201)"),
               (cap.get("ty") == 28 and cap.get("name") == "fl.localTraining" and isinstance(cap.get("attad"), bool)
                and isinstance(cap.get("curSe"), bool), "the capability is a flexContainer (type 28) with its flags"),
               (agt.get("ty") == 28, "the compute part is a flexContainer (type 28)")])


def fl01_2_discoverable(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 2: discoverable by the orchestrator. o: found [resource paths], expect."""
    return _v([(o["expect"] in o["found"], f"{o['expect']} is in the orchestrator's discovery result")])


def fl01_4_tfc_registered(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 4: the Trusted FL Client 'is registered to the MEC platform and to the oneM2M MN-CSE on
    behalf of the constrained device'."""
    return _v([(o["mec011_registration"] == 201 and bool(o["appInstanceId"]), "MEC 011 registered it as an app instance"),
               (o["listed_before_ready"] is False, "its service is not listed before it confirms ready"),
               (o["confirm_ready"] == 204, "confirm_ready accepted (204)"),
               (o["listed_after_ready"] is True, "its service is listed afterwards"),
               (o["ae"] == 201 and o["ae_label_instance"] == o["appInstanceId"], "its AE on the MN-CSE carries that instance id"),
               (bool(o["represents"]), "its profile names the sources it stands for")])


def fl01_7_enumerable(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 7: 'All three device classes are enumerable'. o: classes {name: [candidates]}."""
    c = o["classes"]
    return _v([(bool(c.get(k)), f"class {k} has a candidate") for k in DEVICE_CLASSES])


# TD_MEC_FL_01 on the TD_MEC_REG_03 path: an app deployed through our MEC 010-2 candidate by the main tree's
# platform agent, and what it sent on Mca and Mp1 read off the platform's relays (fl_platform.py).
OP_STATES_OK = ("PROCESSING", "COMPLETED")      # an instantiate MEC 010-2 has not failed (ours leaves it PROCESSING)


def lifecycle_order(lc: dict) -> bool:
    """The order as observed (fl_platform.Platform.evidence 'lifecycle'): exactly one instantiate request on the
    agent's wire to MEC 010-2, answered 202; that answer came before the workload's first POST on Mp1 (one
    monotonic clock); and the workload's process did not start before that answer (boot clock, compared at the
    resolution /proc gives, one tick of 1/CLK_TCK s)."""
    ins = lc.get("instantiate_on_wire") or []
    tick, hz, first = lc.get("process_start_tick"), lc.get("clk_tck"), lc.get("first_mp1_post_t_in")
    if len(ins) != 1 or ins[0][0] != 202 or not all(isinstance(x, (int, float)) for x in ins[0][1:3]):
        return False
    if not (_is_int(tick) and _is_int(hz) and hz > 0 and isinstance(first, (int, float))):
        return False
    return ins[0][1] < first and math.floor(ins[0][2] * hz) <= tick


def app_deployed(o: dict) -> tuple[bool, str]:
    """One package onboarded and instantiated through the MEC 010-2 lifecycle, its workload running from the
    platform's copy and listed at MEC 011. o: fl_platform.Platform.evidence(). MEC 010-2 (our candidate) completes
    no operation, so a successful instantiate stays PROCESSING there: the row says the state as read, takes
    'completed' only as the agent's own record, and takes the order (instantiate, then the process) from what was
    observed (lifecycle_order), not from either account."""
    pkg, inst, argv = o.get("package") or {}, o.get("instance") or {}, o.get("argv") or []
    ops = o.get("op_occs") or []
    state = ops[0][1] if len(ops) == 1 and len(ops[0]) == 2 else None
    return _v([(o.get("error") is None, f"no deployment error ({o.get('error')})"),
               (bool(o.get("checksum")) and o["checksum"] == o.get("descriptor_sha256") == (pkg.get("checksum") or {}).get("hash"),
                "the checksum held at app_pkgm is the SHA-256 of the package's descriptor"),
               ((pkg.get("operationalState"), pkg.get("usageState")) == ("ENABLED", "IN_USE"), "the package is ENABLED and IN_USE"),
               ((inst.get("instantiationState"), inst.get("appDId")) == ("INSTANTIATED", o.get("appDId")),
                "the instance of that package is INSTANTIATED at app_lcm"),
               (len(ops) == 1 and ops[0][0] == "INSTATIATE" and state in OP_STATES_OK,
                f"app_lcm holds one instantiate operation for it, not failed (state as read at MEC 010-2: {state})"),
               (o.get("agent_result") == "COMPLETED", "the agent's own record says it completed the instantiate"),
               (lifecycle_order(o.get("lifecycle") or {}), "observed order: MEC 010-2 answered the instantiate (202) "
                "before the process started (/proc) and before its first request on Mp1"),
               (o.get("pid_alive") is True, "the workload process is alive"),
               (argv[1:3] == ["-I", "-B"] and argv[3:4] == [f"{o.get('store')}/{o.get('program')}"],
                "it runs the program of the platform's copy, with -I -B"),
               (bool(o.get("program_sha256")) and o["program_sha256"] == o.get("expected_program_sha256"),
                "that program is the one the descriptor lists"),
               (o.get("listed") is True, "MEC 011 lists the app's service (it confirmed ready)")])


def reg03_ae(o: dict) -> tuple[bool, str]:
    """TD_MEC_REG_03 steps 2 to 6 for the AE a deployed app registered. o: origin, cse, cse_ri, rn, api; creates
    [the AE Creates on the app's wire: path, origin, status, rsc, aei]; ae, acp, container (the CSE's answers);
    readers, reader_ops, container_rn; mp1_posts [[segment, status]]; confirm_after_writes; mid, lcm; stranger
    [statuses of a stranger's reads]."""
    c, ae, acp, cnt = o["creates"], o.get("ae") or {}, o.get("acp") or {}, o.get("container") or {}
    me = o["origin"]
    want_pv = [{"acor": [me], "acop": 63}] + ([{"acor": list(o["readers"]), "acop": o["reader_ops"]}] if o["readers"] else [])
    return _v([(len(c) == 1, "exactly one AE Create on the app's own wire"),
               (bool(c) and (c[0]["path"], c[0]["origin"]) == (f"/{o['cse']}", me), "to the CSEBase, under its own originator"),
               (bool(c) and (c[0]["status"], c[0]["rsc"], c[0]["aei"]) == (201, 2001, me), "answered 2001 with AE-ID = originator"),
               ((ae.get("ty"), ae.get("rn"), ae.get("api"), ae.get("aei"), ae.get("pi")) == (2, o["rn"], o["api"], me, o["cse_ri"]),
                "the <AE> is under that CSEBase with its name, App-ID and AE-ID"),
               ({f"mec:appInstanceId:{o['mid']}", f"mec:lcmInstanceId:{o['lcm']}"} <= set(ae.get("lbl", [])),
                "the <AE> names both instance ids"),
               (bool(acp.get("ri")) and ae.get("acpi") == [acp["ri"]], "its access policy is the one it created"),
               ((acp.get("pv") or {}).get("acr") == want_pv, "that policy: itself everything, its readers their rights, nobody else"),
               ((acp.get("pvs") or {}).get("acr") == [{"acor": [me], "acop": 63}], "only it may change the policy"),
               ((cnt.get("ty"), cnt.get("rn"), cnt.get("cr"), cnt.get("acpi")) == (3, o["container_rn"], me, ae.get("acpi")),
                "the baseline <container> was created by the AE, under its policy"),
               (o["mp1_posts"][:2] == [["registrations", 201], ["services", 201]]
                and o["mp1_posts"][-1:] == [["confirm_ready", 204]], "Mp1: registered, offered its service, then confirmed ready"),
               (o["confirm_after_writes"] is True, "confirm_ready only after its oneM2M writes"),
               (bool(o["stranger"]) and all(s == 403 for s in o["stranger"]), "a stranger reads nothing (403)")])


def fl01_4_on_behalf(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 4, the 'on behalf of' half: the binding of the Trusted FL Client to the constrained
    devices, stated in the tree by the client itself. o: represents, ae_labels, sources {src: status}, binding,
    binding_creator, client, ae_cse, expect_cse, lcm, mid."""
    b, lab = o.get("binding") or {}, set(o["ae_labels"])
    return _v([(bool(o["represents"]), "the package names the devices it acts for"),
               (all(f"fl:represents:{s}" in lab for s in o["represents"]), "its <AE> names each of them"),
               (all(o["sources"].get(s) == 201 for s in o["represents"]), "each of them is registered at that CSE"),
               (o["ae_cse"] == o["expect_cse"], "the client's AE is on the CSE the devices are on"),
               ((b.get("client"), b.get("represents"), b.get("lcmInstanceId"), b.get("mec011AppInstanceId"))
                == (o["client"], list(o["represents"]), o["lcm"], o["mid"]), "its binding record names them and both instance ids"),
               (o["binding_creator"] == o["client"], "the client wrote that record itself (creator)")])


def fl01_5_proxy_path(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 5: the MEC proxy path configured. o: deployed (app_deployed's answer), origin, rn, lcm,
    devices, service (MEC 011's listing of it), config (its record) and config_creator, containers {dev: cnt},
    profiles {dev: fcnt}; data_acp (the proxy's data policy as the CSE answered a read of it) and what it must
    say, held by the driver: data_acp_rn, data_readers, data_ops."""
    ti = (o.get("service") or {}).get("transportInfo") or {}
    uris = (ti.get("endpoint") or {}).get("uris", [])
    cfg, acp = o.get("config") or {}, o.get("data_acp") or {}
    me = o["origin"]
    want_pv = [{"acor": [me], "acop": 63}] + ([{"acor": list(o["data_readers"]), "acop": o["data_ops"]}] if o["data_readers"] else [])
    conds = [(o["deployed"][0], f"the proxy app is deployed ({o['deployed'][1]})"),
             (ti.get("id") == o["lcm"] and any(u.startswith("http://") and u.rstrip("/").endswith("/devices") for u in uris),
              "MEC 011 lists its service with a device endpoint"),
             (cfg.get("proxy") == me and [d.get("deviceId") for d in cfg.get("devices", [])] == list(o["devices"])
              and bool(o["devices"]), "its configuration record names exactly the configured devices"),
             (o["config_creator"] == me, "the proxy wrote that record itself"),
             (bool(acp.get("ri")) and acp.get("rn") == o["data_acp_rn"], f"its data policy {o['data_acp_rn']} read back"),
             ((acp.get("pv") or {}).get("acr") == want_pv,
              "that data policy: the proxy every operation, its named readers their rights, nobody else anything"),
             ((acp.get("pvs") or {}).get("acr") == [{"acor": [me], "acop": 63}], "only the proxy may change it")]
    for d in o["devices"]:
        cnt, prof = o["containers"].get(d) or {}, o["profiles"].get(d) or {}
        lbl = set(prof.get("lbl", []))
        conds += [((cnt.get("ty"), cnt.get("rn"), cnt.get("cr")) == (3, d, me), f"{d}: a container made by the proxy"),
                  (bool(acp.get("ri")) and cnt.get("acpi") == [acp["ri"]], f"{d}: its container is under that data policy only"),
                  (prof.get("ty") == 28 and prof.get("attad") is False and {
                      "fl:profile", "fl:class:proxy-path", f"fl:device:{d}", f"fl:via:{o['rn']}"} <= lbl
                   and not any(x.startswith("fl:class:") and x != "fl:class:proxy-path" for x in lbl),
                   f"{d}: a proxy-path capability profile naming the device and the proxy")]
    return _v(conds)


def fl01_6_bridged(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 6: the device's data in the tree as sent. o: origin (the proxy), sent [texts as the
    device sent them], answers [the proxy's statuses], stored [the container's cins, oldest first], wire [the
    content the proxy sent the CSE]."""
    st = o["stored"]
    return _v([(bool(o["sent"]) and all(a == 201 for a in o["answers"]) and len(o["answers"]) == len(o["sent"]),
                "the proxy answered 201 to every record"),
               (len(st) == len(o["sent"]), f"{len(o['sent'])} records in the container"),
               ([c.get("con") for c in st] == list(o["sent"]), "each is the text as the device sent it, in order"),
               (all(c.get("ty") == 4 and c.get("cr") == o["origin"] for c in st), "each a contentInstance created by the proxy"),
               (list(o["wire"]) == list(o["sent"]), "and the proxy sent the CSE exactly that text")])


def fl01_6_refused(o: dict) -> tuple[bool, str]:
    """An unconfigured device at the proxy. o: answer (the proxy's status), creates (oneM2M Creates the proxy sent
    for it), before, after (the proxy's tree as its checker sees it)."""
    return _v([(o["answer"] == 403, f"the proxy refused it with 403 (got {o['answer']})"),
               (o["creates"] == 0, "the proxy sent nothing to the CSE for it"),
               (o["before"] == o["after"], "the proxy's tree is unchanged")])


def fl01_6_no_bypass(o: dict) -> tuple[bool, str]:
    """The device writes into the tree without the proxy. o: plain (its JSON posted to the container as plain
    HTTP), own_origin (a oneM2M Create under its own originator), before, after (records in the container)."""
    return _v([(400 <= o["plain"] < 500, f"its plain JSON is refused by the CSE (got {o['plain']})"),
               (400 <= o["own_origin"] < 500, f"its Create under its own originator is refused (got {o['own_origin']})"),
               (o["before"] == o["after"], "the container holds as many records as before")])


def _label(labels, key: str) -> list[str]:
    return [x.split(":", 2)[2] for x in labels if x.startswith(f"fl:{key}:")]


def _mec011_instance(service: dict) -> str | None:
    """The MEC 011 app instance that offers a listed service (its self link: .../applications/<id>/services/...)."""
    href = (((service or {}).get("_links") or {}).get("self") or {}).get("href") or ""
    return href.split("/applications/", 1)[1].split("/", 1)[0] if "/applications/" in href else None


def deployed_app(ae: str, cse: str, role: str, device: str, labels, services: list[dict], platform: dict) -> tuple[bool, str]:
    """Whether the <AE> at cse/ae is a MEC app of `role`, deployed through MEC 010-2 for `device`, by what the
    orchestrator read. MEC 011 alone proves nothing (our candidate lets any process register, offer a service
    under any instance id and confirm ready), so the instance is taken from MEC 010-2:
      1. the AE names one MEC 010-2 instance (mec:lcmInstanceId) and MEC 010-2 lists it as INSTANTIATED;
      2. MEC 010-2 holds one ENABLED package of that instance (by appDId), and its checksum there is the SHA-256 of
         a descriptor (platform['descriptors']) that names this AE (rn, CSE), this role, and the device (tfc:
         fl.represents; proxy: fl.devices);
      3. MEC 011 lists a service whose instance id (transportInfo.id) is that instance, whose endpoint is this AE,
         offered by the MEC 011 app instance this AE names (mec:appInstanceId).
    platform: {instances, packages: as MEC 010-2 lists them (fl_platform.mec010_view); descriptors: {SHA-256:
    descriptor}}. Returns (deployed, why not)."""
    lcm = _lcm(labels)
    if lcm is None:
        return False, "its AE names no single MEC 010-2 instance"
    inst = [i for i in platform.get("instances") or [] if i.get("id") == lcm]
    if len(inst) != 1 or inst[0].get("instantiationState") != "INSTANTIATED":
        return False, f"MEC 010-2 lists no INSTANTIATED instance {lcm}"
    pkgs = [p for p in platform.get("packages") or [] if p.get("appDId") == inst[0].get("appDId")]
    if len(pkgs) != 1 or pkgs[0].get("operationalState") != "ENABLED":
        return False, f"MEC 010-2 holds no single ENABLED package of instance {lcm}"
    desc = (platform.get("descriptors") or {}).get((pkgs[0].get("checksum") or {}).get("hash")) or {}
    o, f = desc.get("onem2m") or {}, desc.get("fl") or {}
    named = f.get("represents", []) if role == "tfc" else [d.get("deviceId") for d in f.get("devices", [])]
    if (o.get("rn"), o.get("mnCse"), f.get("role")) != (ae, cse, role) or device not in named:
        return False, f"the package of instance {lcm} does not name {ae} on {cse} as a {role} for {device}"
    mids = [x.split(":", 2)[2] for x in labels if x.startswith("mec:appInstanceId:")]
    if not any((s.get("transportInfo") or {}).get("id") == lcm and len(mids) == 1 and _mec011_instance(s) == mids[0]
               and any(u.rstrip("/").endswith(f"/{cse}/{ae}")
                       for u in ((s.get("transportInfo") or {}).get("endpoint") or {}).get("uris", []))
               for s in services):
        return False, f"MEC 011 lists no service of instance {lcm} whose endpoint is {cse}/{ae}, offered by the app it names"
    return True, "ok"


def enumerate_candidates(profiles: list[dict], apps: dict, services: list[dict], platform: dict) -> dict:
    """The orchestrator's candidate list for TD_MEC_FL_01 step 7, from what it read: the capability profiles its
    discovery returned (ref '<cse>/<ae>/<rn>', labels, attad), the labels of each AE holding one (apps), the
    services MEC 011 lists (only confirmed-ready instances are listed) and what MEC 010-2 lists (platform, see
    deployed_app). Rules:
      fl-native    a profile of that class whose holder can train (attad)
      fl-assisted  a constrained device (fl:device, else the holder) that a deployed Trusted FL Client represents
      proxy-path   a device (fl:device) whose profile names its proxy (fl:via) and is held by a deployed proxy app
    'Deployed' is deployed_app: an INSTANTIATED instance at MEC 010-2 of a package whose descriptor names the AE,
    and the MEC 011 listing of that instance with this AE as its endpoint. So neither an AE that copies another
    app's instance id nor one that registered itself at MEC 011 is taken for a deployed app. A profile of
    trusted-fl-client is a helper, not a device. Anything else is refused with its reason."""
    classes, via, refused, helpers = {k: [] for k in DEVICE_CLASSES}, {}, [], []
    for p in profiles:
        cse, ae = p["ref"].split("/")[:2]
        cls = _label(p["labels"], "class")
        dev = (_label(p["labels"], "device") or [ae])[0]
        if cls == ["trusted-fl-client"]:
            helpers.append(p["ref"])
            continue
        if len(cls) != 1 or cls[0] not in DEVICE_CLASSES:
            refused.append({"ref": p["ref"], "class": cls, "why": "not one of the three device classes"})
        elif cls[0] == "fl-native":
            if p.get("attad") is True:
                classes["fl-native"].append(ae)
            else:
                refused.append({"ref": p["ref"], "class": cls, "why": "an FL-native profile that cannot train"})
        elif cls[0] == "fl-assisted":
            tfc, nots = [], []
            for a, lab in sorted(apps.items()):
                if "fl:role:tfc" in lab and f"fl:represents:{dev}" in lab:
                    ok, why = deployed_app(a, cse, "tfc", dev, lab, services, platform)
                    (tfc if ok else nots).append(a if ok else f"{a}: {why}")
            if tfc:
                classes["fl-assisted"].append(dev)
                via[dev] = tfc[0]
            else:
                refused.append({"ref": p["ref"], "class": cls, "why": "no deployed Trusted FL Client represents it"
                                + (f" ({'; '.join(nots)})" if nots else "")})
        elif ae not in _label(p["labels"], "via"):
            refused.append({"ref": p["ref"], "class": cls, "why": "its profile does not name its holder as its proxy"})
        elif "fl:role:proxy" not in apps.get(ae, []):
            refused.append({"ref": p["ref"], "class": cls, "why": "its holder is not a proxy app"})
        else:
            ok, why = deployed_app(ae, cse, "proxy", dev, apps.get(ae, []), services, platform)
            if ok:
                classes["proxy-path"].append(dev)
                via[dev] = ae
            else:
                refused.append({"ref": p["ref"], "class": cls, "why": f"its proxy app is not deployed ({why})"})
    return {"classes": {k: sorted(v) for k, v in classes.items()}, "via": via, "refused": refused, "helpers": helpers}


def _lcm(labels) -> str | None:
    got = [x.split(":", 2)[2] for x in labels if x.startswith("mec:lcmInstanceId:")]
    return got[0] if len(got) == 1 else None


def fl01_7_candidates(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_01 step 7 with its controls' preconditions. o: classes (enumerate_candidates'), expect, refused,
    stray [refs that must be refused], found [what discovery returned], profiles {ref: labels as read},
    stray_listed {stray AE: whether MEC 011 lists the service it offered itself}."""
    refused = {r["ref"] for r in (o.get("refused") or [])}
    named = set(sum(o["classes"].values(), []))
    listed = o.get("stray_listed") or {}
    return _v([(fl01_7_enumerable({"classes": o["classes"]})[0], "each of the three classes has a candidate"),
               (o["classes"] == o["expect"], f"the candidates are the expected ones ({o['expect']})"),
               (all(s in o["found"] for s in o["stray"]), "every stray profile was discovered (so its refusal means something)"),
               (bool(listed) and all(v is True for v in listed.values()),
                "every stray that registered itself at MEC 011 is listed there (so MEC 011 alone would have taken it)"),
               (all(s in refused for s in o["stray"]), "every stray profile was refused"),
               (not named & {s.rsplit("/", 1)[-1] for s in o["stray"]}, "no stray is among the candidates"),
               (set(o["profiles"]) == set(o["found"]) and all("fl:profile" in o["profiles"][r] for r in o["found"]),
                "discovery returned capability profiles only, and each was read")])


def fl02_1_selection(o: dict) -> tuple[bool, str]:
    """TD_MEC_FL_02 step 1: selection 'based on capability profile discovery'. o: candidates, selected,
    discovered_refs, capability_refs {participantId: the profile it was judged by}."""
    return _v([(o["selected"] == select_participants(o["candidates"])["selected"], "the selection is the rule's"),
               (len(o["selected"]) >= 2, "at least two participants"),
               (all(o["capability_refs"].get(p) in o["discovered_refs"] for p in o["selected"]),
                "each selected participant's profile came from discovery")])


def fl02_2_notified(o: dict) -> tuple[bool, str]:
    """Step 2: 'Selected participants are notified via oneM2M subscription/notification'. o: selected_clients,
    not_selected (AE names), client_of {AE name: originator}, notifications [{endpoint, selectedClient, taskId}]."""
    n, of = o["notifications"], o["client_of"]
    return _v([(all(any(x["endpoint"] == c and x["selectedClient"] == of[c] for x in n) for c in o["selected_clients"]),
                "every selected client was notified of a task of its own"),
               (not any(x["endpoint"] == c or x["selectedClient"] == of[c] for x in n for c in o["not_selected"]),
                "no notification went to, or named, a client that was not selected")])


def _all_read(o: dict, who: list[str]) -> bool:
    return all(o["reads"].get(c, {}).get("status") == 200 and o["reads"][c].get("digest") == o["model_digest"] for c in who)


def fl02_3_distributed(o: dict) -> tuple[bool, str]:
    """Step 3: the model distributed 'via oneM2M <container>'. o: model_digest, published (status),
    selected_clients, reads {client: {status, digest of what it received}}."""
    return _v([(o["published"] == 201, "the model is a contentInstance in the orchestrator's container (201)"),
               (bool(o["selected_clients"]) and _all_read(o, o["selected_clients"]), "every selected client read that model")])


def fl02_4_training(o: dict) -> tuple[bool, str]:
    """Step 4: 'Each FL client receives the model and begins local training using private local data'. o:
    selected, clients [{participantId, verify (verify_task's answer), samples, status}]."""
    by = {c["participantId"]: c for c in o["clients"]}
    return _v([(all(p in by for p in o["selected"]), "every selected participant reported"),
               (all(c["verify"] == [] for c in by.values()), "task, binding version and model digest verified first"),
               (all(_is_int(c["samples"]) and c["samples"] > 0 for c in by.values()), "each trained on its own samples"),
               (all(c["status"] == 201 for c in by.values()), "each posted its status")])


def fl02_5_raw_stays(o: dict) -> tuple[bool, str]:
    """Step 5: 'Raw training data does not leave the FL client node.' o: central_payloads (everything this run
    put on the IN-CSE and into the aggregator's containers, and everything the orchestrator read), orch_raw_read."""
    found = scan_raw(o["central_payloads"])
    return _v([(found == [], f"no observation outside the clients ({found[:3]})"),
               (o["orch_raw_read"] == 403, "the orchestrator's own read of a source is refused (403)")])


def fl02_6_upload(o: dict) -> tuple[bool, str]:
    """Step 6: updates uploaded 'via <contentInstance> Create'. o: uploads [{participantId, status, ty, creator,
    clientAERef}]."""
    u = o["uploads"]
    return _v([(len(u) >= 2, "at least two updates"),
               (all(x["status"] == 201 and x["ty"] == 4 for x in u), "each is a contentInstance the CSE created (201)"),
               (all(x["creator"] == x["clientAERef"] for x in u), "the CSE recorded the client's own originator as creator")])


def fl02_7_collected(o: dict) -> tuple[bool, str]:
    """Step 7: 'FL Aggregator collects all submitted updates within the round timeout window.' o: posted,
    collected (update digests), round."""
    r = o["round"]
    return _v([(set(o["posted"]) <= set(o["collected"]), "the aggregator read every update that was posted"),
               ({a["updateDigest"] for a in r["accepted"]} <= set(o["collected"]), "what it accepted is among them"),
               (all(a["created_ms"] <= r["deadline_ms"] for a in r["accepted"]), "nothing accepted is past the deadline")])


def fl02_8_aggregate(o: dict) -> tuple[bool, str]:
    """Step 8: 'FL Aggregator combines updates (e.g., FedAvg) and produces an improved global model.' o: round,
    loss_before, loss_after (held-out error of the round's input and output model)."""
    problems = verify_round(o["round"])
    return _v([(problems == [], f"the round record recomputes ({problems})"),
               (o["round"].get("w_out") is not None, "a model was produced"),
               (o["loss_after"] < o["loss_before"], f"held-out error fell ({o['loss_before']} -> {o['loss_after']})")])


def fl02_9_redistributed(o: dict) -> tuple[bool, str]:
    """Step 9: the improved model redistributed 'to all participants'. o: model_digest, published, participants,
    reads."""
    return _v([(o["published"] == 201, "the new version is in the orchestrator's container (201)"),
               (bool(o["participants"]) and _all_read(o, o["participants"]), "every participant read that version")])


def fl02_10_completion(o: dict) -> tuple[bool, str]:
    """Step 10: 'Round completes with expected participation rate; stragglers are handled per configured
    policy.' The rate and the policy are ours (QUORUM_RATE; left out and logged). o: round."""
    r = o["round"]
    logged = {x["participantId"] for k in ("accepted", "excluded", "missing") for x in r[k] if k == "accepted" or x.get("reasons")}
    return _v([(r["state"] == "COMPLETED", "the round completed"),
               (len(r["accepted"]) * QUORUM_RATE[1] >= len(r["selected"]) * QUORUM_RATE[0], "participation at or above the stated rate"),
               (set(r["selected"]) <= logged, "every selected participant is accepted or logged with a reason")])


def gov_decline(o: dict) -> tuple[bool, str]:
    """'A client may accept or reject participation' / 'A candidate may decline even when descriptors match'
    (TR as reported, facts F10, F28). o: candidates, selected, decliner."""
    s = select_participants(o["candidates"])
    return _v([(s["rejected"].get(o["decliner"]) == ["declined"] and o["decliner"] in s["descriptors_match"],
                "its descriptors match and its own answer is the reason"),
               (o["decliner"] not in o["selected"], "it is not among the participants"),
               (o["selected"] == s["selected"], "the recorded selection is the rule's")])


def gov_readiness(o: dict) -> tuple[bool, str]:
    """Readiness by condition (fact F13). o: before, after {six conditions}, state_before, state_after."""
    six = set(READINESS_CONDITIONS)
    return _v([(six <= set(o["before"]) and six <= set(o["after"]), "all six conditions are reported"),
               (not is_ready(o["before"]) and o["state_before"] in READINESS_STATES and o["state_before"] != "ready",
                "not ready while a condition is false"),
               (is_ready(o["after"]) and o["state_after"] == "ready", "ready when all six hold")])


def gov_orch_no_self_grant(o: dict) -> tuple[bool, str]:
    """'None of the profiles allows an FL Orchestrator to grant itself source access' (TR line 7516 as reported).
    o: raw_read, acp_update (the CSE's answers to the orchestrator's own attempts)."""
    return _v([(o["raw_read"] == 403, "its read of a source's observations is refused (403)"),
               (o["acp_update"] == 403, "its change of the source's access policy is refused (403)")])


def gov_quorum(o: dict) -> tuple[bool, str]:
    """'a round below quorum must not publish a model'. o: round, versions_before,
    versions_after (model versions in the aggregator's container)."""
    r = o["round"]
    return _v([(r["quorum"]["met"] is False and r["state"] == "FAILED_QUORUM", "the round is below quorum and says so"),
               (r["w_out"] is None and r["modelOutDigest"] is None, "it produced no model"),
               (verify_round(r) == [], "the record holds"),
               (o["versions_after"] == o["versions_before"], "no new version in the aggregator's container")])


def gov_deploy(o: dict) -> tuple[bool, str]:
    """'an aggregated but undeployed version must not show as active'. o: published,
    activations, expect_active, not_active [versions], target_reports (optional: what the target says is active)."""
    v = deployment_view(o["published"], o["activations"])
    return _v([(v["active"] == o["expect_active"], f"active is {o['expect_active']} (view: {v['active']})"),
               (all(x in v["aggregated"] and x != v["active"] and x in v["undeployed"] for x in o["not_active"]),
                "the aggregated, undeployed version is not active"),
               (o.get("target_reports", v["active"]) == v["active"], "the target reports the same active version")])


def gov_package(o: dict) -> tuple[bool, str]:
    """A package whose digest does not match is refused by the target (the digest part). o:
    reasons (check_package's answer), target_verdict, active_before, active_after."""
    return _v([(bool(o["reasons"]), "the package check objects"),
               (o["target_verdict"] == "refused", "the target refused it"),
               (o["active_after"] == o["active_before"], "the active version did not move")])
