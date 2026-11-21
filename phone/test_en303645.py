#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""ETSI EN 303 645 (consumer IoT cyber security baseline) -- provisions checked against THIS
lab deployment: the phone + probe app + ACME oneM2M edge + the phone-backed MEC services.

An ASSESSMENT OF A LAB DEPLOYMENT, not a certification and not a TS 103 701 conformance
statement. Each check names the provision it probes; an expected failure is reported as
FINDING (the deployment falls short) rather than hidden. Provisions that do not apply to a
lab deployment (e.g. 5.3 update mechanisms of a shipped product) are not claimed.

Preconditions: topology up (MN-CSE-A in-memory), phone streaming to edge A with ACP.
Restarts MN-CSE-A once (5.9) and re-provisions the phone's read policy afterwards.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "estimed"))
import device_state as ds  # noqa: E402

PY = "/home/edgefollow/edgefollow-lab/.venv/bin/python"
ADB = str(Path.home() / "android-tools/platform-tools/adb")
C = "http://127.0.0.1:8201/cse-mn-a"
OWNER = "Cphone-DEVC"
RUN = Path.home() / "estimed-run" / "mn-a"
RESULTS: list[tuple[str, str, bool, str]] = []


def check(prov: str, name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((prov, name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  [{prov}] {name}" + (f"  -- {detail}" if detail else ""))
    return ok


def get(url: str, origin: str | None = None):
    h = {"Accept": "application/json"}
    if origin:
        h.update({"X-M2M-Origin": origin, "X-M2M-RI": f"e{time.time_ns()}", "X-M2M-RVI": "4"})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=h), timeout=5) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        return None, repr(e)


def listening() -> list[tuple[str, int]]:
    out = subprocess.run(["ss", "-ltnH"], capture_output=True, text=True).stdout.split("\n")
    socks = []
    for ln in out:
        parts = ln.split()
        if len(parts) >= 4:
            host, _, port = parts[3].rpartition(":")
            if port.isdigit():
                socks.append((host.strip("[]"), int(port)))
    return socks


def mn_a_pid() -> int | None:
    for ln in subprocess.run(["ps", "-eo", "pid,args"], capture_output=True, text=True).stdout.splitlines():
        if "acmecse" in ln and str(RUN) in ln:
            return int(ln.split()[0])
    return None


def main() -> int:
    ours = [8200, 8201, 8202, 8300, 8401, 8402, 8404, 8406, 8411, 8412, 8414]
    mec13 = subprocess.Popen([PY, str(HERE / "mec013_phone.py")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(5)
        print("== 5.1 no universal default passwords")
        s_str, _ = get(f"{C}/phone/loc/la", "Cstranger")
        s_adm, b = get(f"{C}/phone/loc/la", "CAdmin")
        check("5.1-1", "CONTROL an unknown originator cannot read the phone's location", s_str == 403, str(s_str))
        check("5.1-1", "FINDING anyone asserting the well-known admin originator 'CAdmin' reads the phone's precise location",
              s_adm == 200 and bool(b) and any(p in json.loads(b["m2m:cin"]["con"]) for p in ("gps", "network", "fused")),
              "ACME fullAccessAdmin=True, admin originator is a fixed string, never authenticated")

        print("== 5.5 communicate securely")
        s, _ = get(f"{C}/phone/radio/la", OWNER)
        check("5.5-1", "FINDING the oneM2M edge serves the phone's data over plain HTTP (no TLS)", s == 200 and C.startswith("http:"))
        req = urllib.request.Request(f"{C}/phone/radio", method="POST", data=json.dumps({"m2m:cin": {"con": "{}"}}).encode(),
                                     headers={"X-M2M-Origin": OWNER, "X-M2M-RI": "imp", "X-M2M-RVI": "4",
                                              "Content-Type": "application/json;ty=4"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                s_imp = r.status
        except urllib.error.HTTPError as e:
            s_imp = e.code
        check("5.5-5", "FINDING a local program can write AS the phone (originator asserted, not authenticated)", s_imp == 201, str(s_imp))
        mec_s, mec_b = get(f"http://127.0.0.1:8401/location/v3/queries/users?address={ds.PHONE_ADDRESS}")
        check("5.5-1", "FINDING the MEC Location API hands out the phone's location with NO client authentication",
              mec_s == 200 and mec_b["user"][0].get("locationInfo") is not None, "no OAuth2/mTLS on MEC 013 in this lab")
        check("5.5-1", "the QKD 014 SAE interface requires mutual TLS (evidence: test_phone_qkd cert-less/rogue controls)",
              json.loads((Path.home() / "estimed-run/phone_qkd_results.json").read_text()) and all(
                  r["pass"] for r in json.loads((Path.home() / "estimed-run/phone_qkd_results.json").read_text())
                  if "refused at the TLS layer" in r["check"] or "untrusted CA" in r["check"]))

        print("== 5.6 minimise exposed attack surfaces")
        exposed = [(h, p) for h, p in listening() if p in ours and h not in ("127.0.0.1", "::1")]
        check("5.6-1", "every lab service listens on loopback only", not exposed, str(exposed) if exposed else f"{len(ours)} ports checked")
        adb_on = subprocess.run([ADB, "shell", "settings", "get", "global", "adb_enabled"], capture_output=True, text=True).stdout.strip()
        check("5.6-4", "FINDING the phone runs with USB debugging (a debug interface) enabled", adb_on == "1",
              "required by this lab; a shipped device must not")

        print("== 5.4 / 6 sensitive parameters and personal data at rest")
        check("5.4-1", "the edge keeps the phone's data in memory only (no plaintext location store on disk)",
              "databaseType=memory" in (HERE.parent / "estimed/conf/mn-a.ini").read_text())
        _, cnt = get(f"{C}/phone/loc", OWNER)
        mni = (cnt or {}).get("m2m:cnt", {}).get("mni")
        check("6-4", "OBSERVATION location history retained on the edge (bounded by mni)", mni is not None,
              f"up to {mni} samples x 5 s = {mni * 5 / 3600 if mni else 0:.1f} h of precise location")

        print("== 5.11 make it easy for users to delete user data")
        s_del = None
        # Delete the phone's whole AE (all containers, all history) as its owner, then prove it is gone.
        req = urllib.request.Request(f"{C}/phone", method="DELETE", headers={
            "X-M2M-Origin": OWNER, "X-M2M-RI": "del", "X-M2M-RVI": "4", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                s_del = r.status
        except urllib.error.HTTPError as e:
            s_del = e.code
        s_after, _ = get(f"{C}/phone/loc/la", "CAdmin")
        check("5.11-1", "the device owner can erase ALL its data on the edge in one request (even the admin then finds none)",
              s_del == 200 and s_after == 404, f"DELETE {s_del}, afterwards {s_after}")

        print("== 5.9 resilience to outages")
        # the phone's stream re-registers itself? (it just lost its AE above -- same situation as a CSE restart)
        time.sleep(15)
        s_back, _ = get(f"{C}/phone/radio/la", OWNER)
        check("5.9-1", "after its data was erased, the phone re-establishes itself on the edge without help", s_back == 200, str(s_back))
        pid = mn_a_pid()
        if pid:
            os.kill(pid, signal.SIGTERM)
            time.sleep(4)
            cmd = ["/home/edgefollow/estimed-venv/bin/acmecse", "--headless", "--config", "acme.ini",
                   "--base-directory", str(RUN), "--log-level", "info"]
            subprocess.Popen(cmd, cwd=str(RUN), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, start_new_session=True)
            for _ in range(30):
                if get(f"{C}", OWNER)[0] in (200, 403):
                    break
                time.sleep(1)
        t_up = time.time()
        back = None
        for _ in range(45):
            time.sleep(2)
            s_r, b_r = get(f"{C}/phone/radio/la", OWNER)
            if s_r == 200 and ds.ct_age_s(b_r["m2m:cin"]["ct"]) < 10:
                back = time.time() - t_up
                break
        check("5.9-2", "after a real restart of the edge CSE (in-memory: everything lost) the phone recovers on its own",
              back is not None, f"fresh data {back:.0f} s after restart" if back is not None else "no fresh data in 90 s")
    finally:
        mec13.terminate()
        subprocess.run([PY, str(HERE / "onem2m_acp.py")], capture_output=True)

    fails = [r for r in RESULTS if not r[2]]
    print(f"\nRESULT: {len(RESULTS) - len(fails)}/{len(RESULTS)} checks pass"
          f"   (FINDING checks PASS when the shortfall is demonstrated)")
    Path("/home/edgefollow/estimed-run/en303645_results.json").write_text(
        json.dumps([{"provision": p, "check": n, "pass": ok, "detail": d} for p, n, ok, d in RESULTS], indent=1))
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
