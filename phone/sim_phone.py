# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""A SIMULATED probe phone for the ESTIMED PoC (2026-10-29), so the PoC runs end to end without a phone.

It does what the probe app's LiveService does on the oneM2M side (probe_app/.../LiveService.java):
  ensureAe   AE <rn> with rr=false, containers imu env loc radio wlan cmd ack (mni 2000), a <pch> and the
             <cmd> subscription cmdSub whose nu is the originator (downlink through the pollingChannel);
             403/409 on the AE = already registered, reused if it resolves
  tick       one contentInstance per container every `period` s, in the app's JSON shapes
  radioTs    after the five records of a tick one <tsi> into <rn>/radioTs, as LiveService.postTs does: snr = the
             phone's own counter, dgt = the tick's time, con = {"seq", "rsrp"}. The phone never creates radioTs;
             where there is none the CSE answers 404 and nothing else changes
  downlink   long-polls <pch>/pcu; a new <cmd> instance {"cmd":"ping"|"period",...} is answered in <ack>
  live(cse)  a running instance switches CSE like the app's re-point (registers again on the new CSE)
  stop()     like the service being destroyed: the next live() registers again, on the same CSE too, and the
             phone's counter (the snr in radioTs) starts again at 0

Every value is SIMULATED and says so: each record carries "sim": true; PLMN 001/01 (the ITU test network),
operator "SIM"; the cell, the position and its accuracy are fixed numbers chosen here. Signal strength and serving
cell are set by the caller (set_signal / set_cell): that is what a trigger test needs and what a real phone cannot
be told. Not a phone -- no radio, no RRC, no GNSS: a run with it shows the PoC's mechanisms, never a device's.

Since 2026-11-20 (TD_MEC_DEV_02):
  ue_ipv4        a FICTITIOUS IPv4 address the simulated UE declares as its own, put in its radio record as
                 "ue_ipv4" while attached (mec012_phone then names the UE by it, MEC 012 associateId type 1). None
                 (the default) posts the record shape posted before; the probe app (v20) reports no address. Use a
                 documentation address (RFC 5737, e.g. 192.0.2.x): no network assigned it
  set_attached   False = detached: the radio record has no registered cell and no address (Android's
                 STATE_OUT_OF_SERVICE, 1); True = attached again, on whatever cell set_cell gave
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request

CNTS = ("imu", "env", "loc", "radio", "wlan")


class SimPhone:
    def __init__(self, cse: str, origin: str, rn: str = "phone", period: float = 5.0, *, rsrp: int = -95,
                 rsrq: int = -9, ci: int = 0x1A2B3C4, tac: int = 4242, earfcn: int = 6300,
                 lat: float = 48.1351, lon: float = 11.5820, acc_m: float = 12.0, wifi_aps: int = 6,
                 cellular: bool = True, ue_ipv4: str | None = None):
        self.cse, self.origin, self.rn, self.period = cse.rstrip("/"), origin, rn, period
        self.cellular = cellular          # False: no mobile service (the roadside sensor), no cell at all
        self.attached = True              # False: detached (set_attached), no registered cell for now
        self.ue_ipv4 = ue_ipv4            # the fictitious address it declares while attached; None: declares none
        self.rsrp, self.rsrq, self.ci, self.tac, self.earfcn = rsrp, rsrq, ci, tac, earfcn
        self.lat, self.lon, self.acc_m, self.wifi_aps = lat, lon, acc_m, wifi_aps
        self.seq, self.post_ok, self.post_fail, self.cmds = 0, 0, 0, 0
        self.ts_ok, self.ts_fail = 0, 0
        self._lock = threading.Lock()
        self._run = threading.Event()
        self._ae_ready = False
        self._ticker: threading.Thread | None = None
        self._poller: threading.Thread | None = None

    # ------------------------------------------------------------ what the caller controls
    def set_signal(self, rsrp: int, rsrq: int | None = None) -> None:
        with self._lock:
            self.rsrp = rsrp
            if rsrq is not None:
                self.rsrq = rsrq

    def set_cell(self, ci: int, tac: int | None = None) -> None:
        with self._lock:
            self.ci = ci
            if tac is not None:
                self.tac = tac

    def set_attached(self, attached: bool) -> None:
        """Detach (False) or attach again (True). The next record shows it; a detach is not a cell change."""
        with self._lock:
            self.attached = bool(attached)

    def live(self, cse: str | None = None) -> None:
        """Start posting; with a new CSE, switch to it (the app re-registers on the new CSE)."""
        with self._lock:
            if cse is not None and cse.rstrip("/") != self.cse:
                self.cse, self._ae_ready = cse.rstrip("/"), False
        if self._ticker is None or not self._ticker.is_alive():
            self._run.set()
            self._ticker = threading.Thread(target=self._tick_loop, name=f"sim-{self.rn}-tick", daemon=True)
            self._ticker.start()

    def stop(self) -> None:
        """Stop posting. Returns when the last post has finished: nothing is posted after this returns.

        The registration is forgotten, as when the app's service is destroyed: the next live() registers again
        (its own AE is reused) and starts the downlink poller again. Until 2026-11-19 the registration was kept
        and the poller dropped, so a phone stopped and started on the same CSE posted but took no command.

        The sample counter starts again at 0, as the app's does: LiveService.seq is a field of the service, and a
        service started after a stop is a new one. Until 2026-11-19 the counter carried on across stop(). A running
        phone that is only re-pointed (live() with another CSE, no stop) keeps its counter, as the app's does."""
        self._run.clear()
        if self._ticker is not None:
            self._ticker.join(timeout=self.period + 10)
        self.seq = 0                      # after the ticker has ended: a tick in flight still took the old number
        if self._poller is not None:
            self._poller.join(timeout=12)
            if self._poller.is_alive():
                # Still inside a request after the wait. The reference is kept: started again, _ensure_ae finds
                # this poller alive and starts no second one beside it; the next stop() waits for it again.
                self._ticker = None
            else:
                self._ticker = self._poller = None
        else:
            self._ticker = None
        self._ae_ready = False
        self.last_error: str | None = None          # why the last registration was refused

    # ------------------------------------------------------------ the records (the app's JSON shapes)
    def records(self, now_ms: int | None = None) -> dict:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        with self._lock:
            rsrp, rsrq, ci, tac, earfcn = self.rsrp, self.rsrq, self.ci, self.tac, self.earfcn
            lat, lon, acc, n_ap = self.lat, self.lon, self.acc_m, self.wifi_aps
            in_service, ue_ipv4 = self.cellular and self.attached, self.ue_ipv4
        axis = {"n": 25, "mean": [0.01, 0.02, 9.81], "last": [0.0, 0.0, 9.81]}
        imu = {"accel": axis, "gyro": {"n": 25, "mean": [0.0, 0.0, 0.0], "last": [0.0, 0.0, 0.0]},
               "mag": {"n": 25, "mean": [20.0, -5.0, -40.0], "last": [20.0, -5.0, -40.0]},
               "rotvec": {"n": 25, "mean": [0.0, 0.0, 0.0, 1.0], "last": [0.0, 0.0, 0.0, 1.0]}, "t": now}
        env = {"light": {"n": 5, "mean": [120.0], "last": [120.0]}, "proximity": {"n": 0},
               "battery_pct": 80, "battery_temp_c": 25.0, "t": now}
        loc = {"fused": {"lat": lat, "lon": lon, "acc_m": acc, "alt_m": 520.0, "age_s": 0.5, "t": now - 500},
               "t": now}
        serving = {"registered": True, "rat": "LTE", "mcc": "001", "mnc": "01", "ci": ci, "pci": 101, "tac": tac,
                   "earfcn": earfcn, "bw_khz": 20000, "rsrp": rsrp, "rsrq": rsrq, "rssnr": 10, "rssi": rsrp + 30,
                   "cqi": 9, "ta": 3, "dbm": rsrp, "level": 2}
        neighbour = {"registered": False, "rat": "LTE", "pci": 102, "earfcn": earfcn, "rsrp": rsrp - 6,
                     "rsrq": rsrq - 2}
        radio = ({"operator": "SIM", "plmn": "00101", "earfcn": earfcn, "state": 0, "bw_khz": [20000],
                  "cells": [serving, neighbour], "t": now} if in_service
                 else {"operator": "", "plmn": "", "state": 1, "cells": [], "t": now})
        if in_service and ue_ipv4 is not None:
            radio["ue_ipv4"] = ue_ipv4
        aps = [{"ssid": f"sim-ap-{i}", "bssid": f"02:00:00:00:00:{i:02x}", "rssi": -50 - 3 * i, "freq": 2412}
               for i in range(n_ap)]
        wlan = {"ssid": "\"sim-ap-0\"", "bssid": "02:00:00:00:00:00", "rssi": -50, "freq": 2412,
                "neighbours": aps, "t": now}
        out = {"imu": imu, "env": env, "loc": loc, "radio": radio, "wlan": wlan}
        for r in out.values():
            r["sim"] = True
        return out

    # ------------------------------------------------------------ oneM2M (LiveService.ensureAe / post)
    def _http(self, method: str, url: str, ty: int = 0, body=None, timeout: float = 5) -> tuple[int, dict]:
        h = {"X-M2M-Origin": self.origin, "X-M2M-RI": f"s{time.time_ns()}", "X-M2M-RVI": "4",
             "Accept": "application/json"}
        data = None
        if body is not None:
            h["Content-Type"] = f"application/json;ty={ty}" if ty else "application/json"
            data = json.dumps(body).encode()
        try:
            with urllib.request.urlopen(urllib.request.Request(url, data=data, method=method, headers=h),
                                        timeout=timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, (json.loads(raw) if raw else {})
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, OSError, ValueError):
            return 0, {}

    def _ensure_ae(self) -> bool:
        cse, rn = self.cse, self.rn
        ae, _ = self._http("POST", cse, 2, {"m2m:ae": {"rn": rn, "api": "Nprobe.phone", "rr": False, "srv": ["4"]}})
        ok = ae == 201
        if not ok:
            # A refused create (409: the name is taken; ACME's 403: this originator is already registered) is a
            # reconnect only to an AE carrying OUR AE-ID. Anyone else's AE would receive our containers, <pch>,
            # command subscription and every reading after them (deep check 2026-10-29).
            st, body = self._http("GET", f"{cse}/{rn}")
            aei = ((body or {}).get("m2m:ae") or {}).get("aei") if st == 200 else None
            if aei != self.origin:
                self.last_error = (f"AE create answered {ae}; GET {cse}/{rn} answered {st}"
                                   + (f" with aei {aei!r}, not ours ({self.origin!r})" if st == 200 else ""))
                return False
            ok = True
            self._http("PUT", f"{cse}/{rn}", 0, {"m2m:ae": {"rr": False}})
        for c in (*CNTS, "cmd", "ack"):
            r, _ = self._http("POST", f"{cse}/{rn}", 3, {"m2m:cnt": {"rn": c, "mni": 2000}})
            ok &= r in (201, 409)
        self._http("POST", f"{cse}/{rn}", 15, {"m2m:pch": {"rn": "pch"}})
        self._http("POST", f"{cse}/{rn}/cmd", 23, {"m2m:sub": {"rn": "cmdSub", "nu": [self.origin],
                                                              "enc": {"net": [3]}, "nct": 1}})
        if ok and (self._poller is None or not self._poller.is_alive()):
            self._poller = threading.Thread(target=self._poll_loop, name=f"sim-{rn}-pcu", daemon=True)
            self._poller.start()
        return ok

    def _post(self, cnt: str, con: dict) -> None:
        r, _ = self._http("POST", f"{self.cse}/{self.rn}/{cnt}", 4,
                          {"m2m:cin": {"cnf": "application/json:0", "con": json.dumps(con)}})
        if r == 201:
            self.post_ok += 1
        else:
            self.post_fail += 1
            if r == 404:              # registration gone -> register again on the next tick (403 = refused: never)
                self._ae_ready = False

    def _post_ts(self, radio: dict) -> None:
        """LiveService.postTs: the tick's sequence number as a <tsi>. A 404 (no radioTs here) is not a failure and
        does not touch the registration."""
        t_ms = radio["t"]
        dgt = time.strftime("%Y%m%dT%H%M%S", time.gmtime(t_ms // 1000)) + f",{t_ms % 1000:03d}000"
        cell = next((c for c in radio.get("cells", []) if c.get("registered")), None)
        con = {"seq": self.seq, "rsrp": cell.get("rsrp") if cell else None, "sim": True}
        r, _ = self._http("POST", f"{self.cse}/{self.rn}/radioTs", 30,
                          {"m2m:tsi": {"dgt": dgt, "snr": self.seq, "con": json.dumps(con)}})
        if r == 201:
            self.ts_ok += 1
        elif r != 404:
            self.ts_fail += 1

    def _tick_loop(self) -> None:
        while self._run.is_set():
            t0 = time.monotonic()
            if not self._ae_ready:
                self._ae_ready = self._ensure_ae()
            if self._ae_ready:
                recs, whole = self.records(), True
                for c, r in recs.items():
                    if not self._run.is_set():
                        whole = False
                        break
                    self._post(c, r)
                if whole:                 # a tick cut short by stop() is given no number: the next whole tick takes it
                    self._post_ts(recs["radio"])
                    self.seq += 1
            while self._run.is_set() and time.monotonic() - t0 < self.period:
                time.sleep(0.05)

    def _poll_loop(self) -> None:
        while self._run.is_set():
            st, rq = self._http("GET", f"{self.cse}/{self.rn}/pch/pcu", timeout=10)
            if st != 200 or not rq:
                time.sleep(0.5)
                continue
            rqi = _find(rq, "rqi")
            if isinstance(rqi, str):
                self._http("POST", f"{self.cse}/{self.rn}/pch/pcu", 0,
                           {"m2m:rsp": {"rsc": 2000, "rqi": rqi, "rvi": "4", "to": self.cse}})
            sgn = _find(rq, "m2m:sgn")
            if not isinstance(sgn, dict) or sgn.get("vrq"):
                continue
            cin = _find(sgn, "m2m:cin")
            if not isinstance(cin, dict):
                continue
            try:
                cmd = json.loads(cin.get("con", "{}"))
            except ValueError:
                continue
            ack = {"id": cmd.get("id"), "cmd": cmd.get("cmd"), "phone_t": int(time.time() * 1000), "sim": True}
            if cmd.get("cmd") == "ping":
                ack.update(ok=True, battery_pct=80)
            elif cmd.get("cmd") == "period":
                v = cmd.get("value")
                if isinstance(v, int) and 1 <= v <= 60:
                    self.period = v
                    ack.update(ok=True, period=v)
                else:
                    ack.update(ok=False, error="period out of range 1..60")
            else:
                ack.update(ok=False, error="unknown command")
            self.cmds += 1
            self._post("ack", ack)


def _find(o, key):
    """First value under `key` anywhere in a JSON tree (LiveService.find / findString)."""
    if isinstance(o, dict):
        if key in o:
            return o[key]
        for v in o.values():
            r = _find(v, key)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = _find(v, key)
            if r is not None:
                return r
    return None
