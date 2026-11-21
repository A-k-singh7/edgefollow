# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Live state of the real phone, read back from the oneM2M CSE it posts to.

The phone (probe app, LiveService) is a oneM2M AE `phone` on MN-CSE-A with containers
imu, env, loc, radio, wlan; each tick it posts one contentInstance per container. This
module reads the latest instance of each (`/la`) -- so every MEC value served from here
provably came off the device through oneM2M, not from a fixture.

It also holds the few unit conversions the ETSI data models require:

* RSRP / RSRQ in MEC 012 are Uint8 *reported values* (ETSI TS 136 133 mapping), not dBm:
  RSRP_idx = floor(dBm + 141) clamped to 0..97; RSRQ_idx = floor((dB + 20) * 2) clamped
  to 0..34.
* Ecgi.cellId is a 28-bit E-UTRAN cell identity; served as 7 upper-case hex digits.
* Android reports "unavailable" as Integer.MAX_VALUE (2147483647). Such fields are
  DROPPED, never forwarded as numbers.
"""
from __future__ import annotations

import calendar
import ipaddress
import json
import math
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CSE = os.environ.get("PHONE_CSE", "http://127.0.0.1:8201/cse-mn-a")
AE = os.environ.get("PHONE_AE", "phone")
ORIGIN = os.environ.get("PHONE_READER_ORIGIN", "CphoneReader")
UNAVAILABLE = 2**31 - 1
PHONE_ADDRESS = os.environ.get("PHONE_ADDRESS", "acr:phone-DEVC")
# The phone posts every 5 s; a container whose latest instance is older than this is
# treated as ABSENT (the app died, USB dropped, the phone moved to another CSE), never
# served as live.
MAX_SAMPLE_AGE_S = float(os.environ.get("PHONE_MAX_SAMPLE_AGE_S", "20"))


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "X-M2M-Origin": ORIGIN, "X-M2M-RI": f"rd{time.time_ns()}", "X-M2M-RVI": "4",
        "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=4) as r:
        return json.loads(r.read())


def latest(container: str) -> tuple[dict, str]:
    """Latest content of one container, plus its oneM2M creation time (ct)."""
    cin = _get(f"{CSE}/{AE}/{container}/la")["m2m:cin"]
    return json.loads(cin["con"]), cin.get("ct", "")


# Notification callbacks carry the phone's location and cell data, and the MEC APIs in this
# lab take subscriptions without client authentication. A subscriber-chosen callback URL is
# therefore an SSRF / exfiltration primitive unless delivery is restricted. Lab default:
# only the test sinks (127.0.0.1 / localhost, ports 8400-8499); extra origins via
# PHONE_CALLBACK_ALLOW="http://host:port,https://host:port". No redirects are followed.
_CB_PORTS = range(8400, 8500)
_CB_EXTRA = {o.strip().rstrip("/") for o in os.environ.get("PHONE_CALLBACK_ALLOW", "").split(",") if o.strip()}
REFUSED_CALLBACKS: list[str] = []


def callback_allowed(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    if f"{u.scheme}://{u.hostname}:{port}" in _CB_EXTRA:
        return True
    return u.hostname in ("127.0.0.1", "localhost") and port in _CB_PORTS


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
_POST_STATUS = threading.local()


def take_post_status() -> int | None:
    """The HTTP status the last safe_post in THIS thread received, then forgotten (read once). None: the callback
    was refused here, no answer came, or it was already taken (2026-11-20: a send log can tell 204 from 200)."""
    code = getattr(_POST_STATUS, "code", None)
    _POST_STATUS.code = None
    return code


def safe_post(url: str, body: dict, timeout: float = 3) -> bool:
    """Deliver a notification only to an allowed callback; never follow redirects. Returns and raises exactly as
    before; the status the callback answered is kept for take_post_status()."""
    _POST_STATUS.code = None
    if not callback_allowed(url):
        if len(REFUSED_CALLBACKS) < 1000:
            REFUSED_CALLBACKS.append(url)
        return False
    r = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                               headers={"Content-Type": "application/json"})
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            _POST_STATUS.code = resp.status
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:      # a non-2xx answer (and a refused redirect): raised as before
        _POST_STATUS.code = e.code
        raise


def ct_age_s(ct: str) -> float:
    """Seconds since a oneM2M creation time (UTC, 'YYYYMMDDTHHMMSS[,ffffff]')."""
    base, _, frac = ct.partition(",")
    t = calendar.timegm(time.strptime(base, "%Y%m%dT%H%M%S")) + (float("0." + frac) if frac else 0.0)
    return time.time() - t


def snapshot() -> dict:
    out = {}
    for c in ("imu", "env", "loc", "radio", "wlan"):
        try:
            val, ct = latest(c)
        except Exception as e:  # container empty / CSE down: report, never invent
            out[c], out[c + "_ct"] = None, f"unavailable: {e}"
            continue
        age = ct_age_s(ct)
        if age > MAX_SAMPLE_AGE_S:
            out[c], out[c + "_ct"] = None, f"stale: last sample {age:.0f} s old ({ct})"
            continue
        if c == "loc":  # a fix's age_s was measured when the phone posted; add the time since
            val = {p: (dict(f, age_s=f.get("age_s", 0) + age) if isinstance(f, dict) else f) for p, f in val.items()}
        out[c], out[c + "_ct"] = val, ct
    return out


def clean(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None and v != UNAVAILABLE}


def rsrp_index(dbm: int | None) -> int | None:
    if dbm is None or dbm == UNAVAILABLE:
        return None
    return max(0, min(97, math.floor(dbm + 141)))


def rsrq_index(db: int | None) -> int | None:
    if db is None or db == UNAVAILABLE:
        return None
    return max(0, min(34, math.floor((db + 20) * 2)))


def eci_hex(ci: int) -> str:
    return f"{ci & 0xFFFFFFF:07X}"


SERVING_FIELDS = ("mcc", "mnc", "ci", "tac")


def serving_cell(radio: dict | None) -> dict | None:
    """The registered LTE cell carrying every field the MEC models need. With several
    registered cells (dual SIM, carrier aggregation) the one on the channel Android
    reports as serving wins, then the lowest ECI -- never list order, which would turn a
    reordering into a fake cell change."""
    if not radio:
        return None
    regs = [clean(c) for c in radio.get("cells", []) if c.get("registered") and c.get("rat") == "LTE"]
    regs = [c for c in regs if all(c.get(k) is not None for k in SERVING_FIELDS)]
    if not regs:
        return None
    on_channel = [c for c in regs if c.get("earfcn") == radio.get("earfcn")]
    return min(on_channel or regs, key=lambda c: c["ci"])


def ue_ipv4(radio: dict | None) -> str | None:
    """The UE's own IPv4 address, IF the device reports one in its radio record (key "ue_ipv4"), as a dotted quad;
    otherwise None. MEC 012 associateId type 1 (UE_IPv4_ADDRESS) is filled from this and from nothing else
    (2026-11-20, TD_MEC_DEV_02). The probe app (v20) reports no address, so a real-phone run carries no associateId
    and an associateId filter matches nothing, as before. A value that is not exactly one IPv4 address (a name, an
    IPv6 address, a number, a list, padding) counts as no address: type 1 says what the value is."""
    v = (radio or {}).get("ue_ipv4")
    if not isinstance(v, str):
        return None
    try:
        return str(ipaddress.IPv4Address(v))
    except ValueError:
        return None


def neighbours(radio: dict | None) -> list[dict]:
    if not radio:
        return []
    return [clean(c) for c in radio.get("cells", []) if not c.get("registered")]


FRESH_FIX_S = 30.0


def best_fix(loc: dict | None) -> tuple[str, dict] | None:
    """The most accurate fix among fresh ones (age <= FRESH_FIX_S); if none is fresh,
    the newest. Never "GPS first": indoors a weak GNSS lock (~250 m) is worse than
    the network fix (~100 m)."""
    if not loc:
        return None
    fixes = [(p, f) for p, f in loc.items() if isinstance(f, dict) and f.get("lat") is not None]
    if not fixes:
        return None
    fresh = [(p, f) for p, f in fixes if f.get("age_s", 1e9) <= FRESH_FIX_S and f.get("acc_m") is not None]
    if fresh:
        return min(fresh, key=lambda pf: pf[1]["acc_m"])
    return min(fixes, key=lambda pf: pf[1].get("age_s", 1e9))
