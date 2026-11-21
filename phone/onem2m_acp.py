# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Grant the MEC-side reader RETRIEVE+DISCOVER on the phone AE via a oneM2M ACP,
then prove it with controls: reader may read, a stranger may not, reader may not delete."""
import json
import sys
import time
import urllib.request
import urllib.error
C = "http://127.0.0.1:8201/cse-mn-a"
OWNER, READER = "Cphone-DEVC", "CphoneReader"

def req(method, url, origin, body=None, ty=None):
    h = {"X-M2M-Origin": origin, "X-M2M-RI": f"a{time.time_ns()}", "X-M2M-RVI": "4",
         "Accept": "application/json"}
    if body is not None:
        h["Content-Type"] = f"application/json;ty={ty}" if ty else "application/json"
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=5) as x:
            return x.status, json.loads(x.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

acp = {"m2m:acp": {"rn": "phoneReadAcp",
       "pv": {"acr": [{"acor": [READER], "acop": 2 | 32}, {"acor": [OWNER], "acop": 63}]},
       "pvs": {"acr": [{"acor": [OWNER], "acop": 63}]}}}
code, b = req("POST", C, OWNER, acp, ty=1)
if code == 409:
    # Reset the privileges, not just reuse the policy: test_phone_mec033 flips the owner's
    # CREATE bit (acop 63 -> 62) and restores it in `finally`, which a SIGTERM skips. Found
    # 2026-09-28: an interrupted MEC 033 left 62 behind, the phone could create nothing, its
    # ensureAe() failed and it stopped posting -- every later suite then failed downstream.
    code, b = req("PUT", f"{C}/phoneReadAcp", OWNER, {"m2m:acp": {"pv": acp["m2m:acp"]["pv"]}})
print("ACP", code)
ri = b["m2m:acp"]["ri"]
print("AE acpi update", req("PUT", f"{C}/phone", OWNER, {"m2m:ae": {"acpi": [ri]}})[0])
# ACME does not inherit an AE's acpi into its containers; contentInstances follow
# their container, so each container carries the policy too.
for cnt in ("imu", "env", "loc", "radio", "wlan"):
    print(f"  cnt {cnt} acpi update", req("PUT", f"{C}/phone/{cnt}", OWNER, {"m2m:cnt": {"acpi": [ri]}})[0])
checks = [
    ("reader RETRIEVE radio/la", req("GET", f"{C}/phone/radio/la", READER)[0], 200),
    ("CONTROL stranger RETRIEVE", req("GET", f"{C}/phone/radio/la", "Cstranger")[0], 403),
    ("CONTROL reader DELETE container", req("DELETE", f"{C}/phone/radio", READER)[0], 403),
    ("owner still RETRIEVE", req("GET", f"{C}/phone/radio/la", OWNER)[0], 200),
]
bad = 0
for name, got, want in checks:
    ok = got == want
    bad += not ok
    print(f"  {'PASS' if ok else 'FAIL'}  {name}: {got} (want {want})")
sys.exit(1 if bad else 0)
