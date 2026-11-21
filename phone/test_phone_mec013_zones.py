#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""The phone's zone in MEC 013 GET /queries/zones and /queries/zones/{zoneId} (2026-11-21) -- no phone, no CSE,
no network, no port.

mec013_phone.py serves the unmodified mec013_look candidate and keeps the phone in its USERS while the phone's
sample is fresh (device_state.MAX_SAMPLE_AGE_S). The candidate derives its zones from USERS on every request, so
the phone's zone tac<TAC> must be listed, and count the phone in numberOfUsers and its serving cell in
numberOfAccessPoints, exactly while the phone's user entry is served -- and never after.

What runs here is the wrapper's own code: its refresher() loop, for exactly one pass (its sleep is replaced by a
stop), over device_state.snapshot() whose CSE read (`latest`) answers with a SIMULATED phone's records
(sim_phone.SimPhone.records, the probe app's JSON shapes) stamped fresh or stale. The HTTP side is the candidate's
FastAPI app in this process (TestClient). Expected counts are written by hand.

    PYTHONDONTWRITEBYTECODE=1 /home/edgefollow/edgefollow-lab/.venv/bin/python phone/test_phone_mec013_zones.py
"""
from __future__ import annotations

import sys
import time
import types
from pathlib import Path

from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402
import mec013_phone as m13  # noqa: E402
import sim_phone  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []
CONTROLS = 0
Q = "/location/v3/queries"
FRESH_S, STALE_S = 3.0, ds.MAX_SAMPLE_AGE_S + 40.0


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def control(name, went_through, detail=""):
    """A control row: `name` says what must NOT have happened; the row passes when it did not."""
    global CONTROLS
    CONTROLS += 1
    check("CONTROL (must FAIL) " + name, not went_through, detail)


class _Stop(Exception):
    pass


def _stop(_s):
    raise _Stop


def one_refresh(phone: sim_phone.SimPhone, age_s: float, *, cse_down: bool = False) -> None:
    """One pass of mec013_phone.refresher() with the CSE answering this phone's records, `age_s` old."""
    recs = phone.records()
    ct = time.strftime("%Y%m%dT%H%M%S", time.gmtime(time.time() - age_s))

    def latest(container):
        if cse_down:
            raise OSError("CSE not answering (test)")
        return recs[container], ct

    saved = ds.latest, m13.time
    ds.latest, m13.time = latest, types.SimpleNamespace(sleep=_stop)
    try:
        m13.refresher()
    except _Stop:
        pass
    finally:
        ds.latest, m13.time = saved


def zones(c) -> dict[str, dict]:
    r = c.get(f"{Q}/zones")
    return {z["zoneId"]: z for z in r.json()["zoneList"]["zone"]} if r.status_code == 200 else {}


def phone_served(c) -> bool:
    return c.get(f"{Q}/users", params={"address": ds.PHONE_ADDRESS}).status_code == 200


def counts(z: dict | None) -> tuple | None:
    return None if z is None else (z["numberOfUsers"], z["numberOfAccessPoints"], z["numberOfUnserviceableAccessPoints"])


def main() -> int:
    c = TestClient(m13.cand.app, raise_server_exceptions=False)
    ph = sim_phone.SimPhone("http://127.0.0.1:9/unused", "CzoneTest", ci=0x1A2B3C4, tac=4242)   # SIMULATED, never started
    url = f"http://127.0.0.1:{m13.cand.PORT}{m13.cand.BASE}/queries/zones"
    base_users = dict(m13.cand.USERS)
    same_rule: list[tuple[str, bool, bool]] = []      # (step, phone user served, phone zone listed)

    def note(step, zone="tac4242"):
        same_rule.append((step, phone_served(c), zone in zones(c)))

    print("== before any refresh: the candidate's fixture zones only")
    z0 = zones(c)
    check("fixture zones only: zone001 (2 users, 2 APs) and zone002 (2 users, 1 AP)",
          {k: counts(v) for k, v in z0.items()} == {"zone001": (2, 2, 0), "zone002": (2, 1, 0)}, str(z0.keys()))
    control("the phone's zone was listed before the phone was ever merged", "tac4242" in z0)

    print("== phone sample fresh")
    one_refresh(ph, FRESH_S)
    note("fresh")
    zs = zones(c)
    check("precondition: the phone's user entry is served (fresh sample)", phone_served(c), m13.STATE["error"] or "")
    check("tac4242 listed: 1 user (the phone), 1 access point (its cell), 0 unserviceable",
          counts(zs.get("tac4242")) == (1, 1, 0), str(zs.get("tac4242")))
    one = c.get(f"{Q}/zones/tac4242")
    check("GET /queries/zones/tac4242 -> 200 {zoneInfo} equal to its list entry, resourceURL on the wrapper's port",
          one.status_code == 200 and one.json() == {"zoneInfo": zs.get("tac4242")}
          and zs.get("tac4242", {}).get("resourceURL") == f"{url}/tac4242", f"{one.status_code} {one.text[:160]}")
    check("the fixture zones are unchanged beside the phone's",
          {k: counts(v) for k, v in zs.items() if k != "tac4242"} == {"zone001": (2, 2, 0), "zone002": (2, 1, 0)})
    users = c.get(f"{Q}/users").json()["user"]
    check("users over all zones = UEs in /queries/users = 5 (4 fixture + the phone)",
          sum(z["numberOfUsers"] for z in zs.values()) == len(users) == 5, f"{len(users)} users")
    f = c.get(f"{Q}/zones", params={"zoneId": "tac4242"}).json()["zoneList"]
    check("?zoneId=tac4242 -> exactly the phone's zone", [z["zoneId"] for z in f["zone"]] == ["tac4242"]
          and f["resourceURL"] == f"{url}?zoneId=tac4242", str(f))

    print("== a second UE on another access point in the phone's zone: counts include the phone")
    m13.cand.USERS["acr:sim-peer"] = m13.cand._user_record("acr:sim-peer", "tac4242", "PEER01")
    check("tac4242: 2 users, 2 access points (phone's cell + the peer's)", counts(zones(c).get("tac4242")) == (2, 2, 0),
          str(zones(c).get("tac4242")))

    print("== phone sample stale (older than MAX_SAMPLE_AGE_S)")
    one_refresh(ph, STALE_S)
    check("the phone's user entry is gone (stale sample)", not phone_served(c))
    check("tac4242 still listed for the peer only: 1 user, 1 access point", counts(zones(c).get("tac4242")) == (1, 1, 0),
          str(zones(c).get("tac4242")))
    del m13.cand.USERS["acr:sim-peer"]
    note("stale")
    zs = zones(c)
    check("with the peer gone too: tac4242 not listed", "tac4242" not in zs, str(list(zs)))
    r = c.get(f"{Q}/zones/tac4242")
    check("GET /queries/zones/tac4242 -> 404 ProblemDetails", r.status_code == 404
          and r.headers.get("content-type", "").startswith("application/problem+json") and r.json().get("status") == 404,
          f"{r.status_code} {r.text[:120]}")
    check("users over all zones = 4 (the fixture UEs)", sum(z["numberOfUsers"] for z in zs.values()) == 4)

    print("== fresh again, then a cell change into another tracking area")
    one_refresh(ph, FRESH_S)
    note("fresh again")
    check("tac4242 back with the phone: 1 user, 1 access point", counts(zones(c).get("tac4242")) == (1, 1, 0))
    ph.set_cell(0x1A2B3C5, tac=4343)
    one_refresh(ph, FRESH_S)
    note("moved", "tac4343")
    zs = zones(c)
    check("after the move: tac4343 listed (1, 1), tac4242 not left behind",
          counts(zs.get("tac4343")) == (1, 1, 0) and "tac4242" not in zs, str(list(zs)))

    print("== CSE not answering, then the phone detached")
    one_refresh(ph, FRESH_S, cse_down=True)
    note("cse down", "tac4343")
    check("CSE down: phone's user entry and zone both gone", not phone_served(c) and "tac4343" not in zones(c))
    one_refresh(ph, FRESH_S)
    ph.set_attached(False)
    one_refresh(ph, FRESH_S)
    note("detached", "tac4343")
    check("detached (no registered cell): phone's user entry and zone both gone",
          not phone_served(c) and "tac4343" not in zones(c))
    check("at every step the phone's zone was listed exactly when its user entry was served",
          all(u == z for _, u, z in same_rule) and {u for _, u, _ in same_rule} == {True, False}, str(same_rule))

    print("== control: a wrapper that keeps serving the phone after its sample went stale")
    ph.set_attached(True)
    one_refresh(ph, FRESH_S)
    last = m13.STATE["last"]
    real = m13.phone_user
    m13.phone_user = lambda snap: real(snap) or last           # sticky: a stale snapshot still yields the old entry
    try:
        one_refresh(ph, STALE_S)
    finally:
        m13.phone_user = real
    control("a sticky wrapper's stale phone dropped out of the zone list (the stale check would not see it)",
            "tac4343" not in zones(c), str(list(zones(c))))
    one_refresh(ph, STALE_S)
    check("the real wrapper, same stale sample: zone gone again", "tac4343" not in zones(c))

    check("nothing left behind: USERS back to the 4 fixture UEs", m13.cand.USERS == base_users)

    passed = sum(ok for _, ok, _ in RESULTS)
    print(f"\nRESULT: {passed}/{len(RESULTS)} checks pass   (controls {CONTROLS}; skipped 0)")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
