#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""MEC 013 Location API with the REAL phone as a live UE.

The unmodified `mec013_look/candidate.py` is loaded as a module and served as-is (its
ATS fixture UEs stay, so the ATS can still be run against this process). One extra UE
is kept current from the phone's oneM2M containers:

    address        acr:phone-DEVC
    accessPointId  the serving LTE cell, as its 28-bit ECI in hex (e.g. 1A3122A)
    zoneId         the tracking area of that cell (tac<TAC>)
    locationInfo   the phone's best GNSS/network fix, as MEC 013 v3 requires it:
                   latitude/longitude ARRAYS, shape 5 (ellipsoid point with
                   uncertainty circle), accuracy = the fix's horizontal accuracy in m
    timestamp      the fix time (seconds / nanoSeconds)

If the phone has no current serving cell (or its samples are stale, see device_state),
the UE is REMOVED rather than served stale; without a fresh fix it is served without
locationInfo.

Zones (GET /queries/zones and /queries/zones/{zoneId}, GS MEC 013 clauses 7.7 / 7.8) need
nothing here: the candidate derives them from USERS on every request, so the phone's zone
tac<TAC> is listed -- the phone counted in numberOfUsers, its cell in numberOfAccessPoints --
exactly while the phone's UE is, and is gone (404 on its own resource) when it is not
(phone/test_phone_mec013_zones.py).

    PHONE_MEC013_PORT (default 8401)
"""
from __future__ import annotations

import importlib.util
import math
import os
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_state as ds  # noqa: E402

spec = importlib.util.spec_from_file_location("mec013_look_candidate", HERE.parent / "mec013_look" / "candidate.py")
cand = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cand)
cand.PORT = int(os.environ.get("PHONE_MEC013_PORT", "8401"))
MAX_FIX_AGE_S = float(os.environ.get("PHONE_MAX_FIX_AGE_S", "120"))
STATE = {"last": None, "error": None}


def phone_user(snap: dict) -> dict | None:
    """The phone as a MEC 013 UE. PRESENCE (access point, zone) comes from the serving
    cell alone; locationInfo is added only when a fix no older than MAX_FIX_AGE_S exists
    (UserInfo does not require it). Losing GNSS therefore never looks like leaving."""
    cell = ds.serving_cell(snap.get("radio"))
    if cell is None:
        return None
    user = {
        "address": ds.PHONE_ADDRESS,
        "accessPointId": ds.eci_hex(cell["ci"]),
        "zoneId": f"tac{cell['tac']}",
        "resourceURL": f"http://127.0.0.1:{cand.PORT}{cand.BASE}/queries/users?address={ds.PHONE_ADDRESS}",
    }
    fix = ds.best_fix(snap.get("loc"))
    if fix is not None and fix[1].get("age_s", 1e9) <= MAX_FIX_AGE_S:
        provider, f = fix
        t_ms = int(f["t"])
        loc = {"latitude": [f["lat"]], "longitude": [f["lon"]], "shape": 5}
        if f.get("acc_m") is not None:
            loc["accuracy"] = int(math.ceil(f["acc_m"]))
        user["locationInfo"] = loc
        user["contextLocationInfo"] = f"fix provider {provider}"
    else:
        t_ms = int(snap["radio"]["t"])  # no usable fix: time of the cell observation
    # GS MEC 013 v3.1.1/v3.2.1 Table 6.2.2-1 names it timeStamp (mandatory); ETSI's ATS schema
    # (MEC013/SRV/UELOCLOOK/schemas/UserInfo.schema.json) requires `timestamp` and allows extra fields -- an ATS-side
    # defect -- so both are served, equal, and spec clients and the ATS each find theirs (deep check 2026-10-29).
    user["timeStamp"] = {"seconds": t_ms // 1000, "nanoSeconds": (t_ms % 1000) * 1_000_000}
    user["timestamp"] = dict(user["timeStamp"])
    return user


def refresher() -> None:
    while True:
        try:
            u = phone_user(ds.snapshot())
            if u is None:
                cand.USERS.pop(ds.PHONE_ADDRESS, None)
            else:
                cand.USERS[ds.PHONE_ADDRESS] = u
            STATE["last"], STATE["error"] = u, None
        except Exception as e:
            cand.USERS.pop(ds.PHONE_ADDRESS, None)
            STATE["error"] = repr(e)
        time.sleep(2)


if __name__ == "__main__":
    threading.Thread(target=refresher, daemon=True).start()
    cand._serve(cand.app, cand.PORT)
