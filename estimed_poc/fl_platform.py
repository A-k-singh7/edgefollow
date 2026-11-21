# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""TD_MEC_FL_01 in fl_run.py: the MEC platform side, on the path TD_MEC_REG_03 took (main tree, 411125a).

    the platform agent   the main tree's estimed/mec_app_deploy.py, loaded by pinned SHA-256 (mec_pinned.py); it
                         checks each package's digests, onboards it at our MEC 010-2 candidate (:8092), creates
                         and instantiates the instance, starts the workload as a process of this user and waits
                         until MEC 011 lists it; terminate stops it. No second agent is written here.
    the packages         apps/fl_orch, apps/fl_tfc, apps/fl_proxy: one program (fl_app.py), three descriptors
    the relays           one recording relay in front of each CSE and in front of MEC 011, as in
                         estimed/tests/test_tr0086_mec_app_deploy.py: the agent gives the workloads the relays'
                         addresses, so what an app sent on Mca and on Mp1 is read off the wire, not taken from its
                         own account. A relay can hold a request (confirm_ready) until it is released. One more
                         relay in front of MEC 010-2 carries the agent's lifecycle calls, so the instantiate request
                         and its answer are read off the wire too (when, and with what status); each record has
                         the monotonic and the boot clock, and /proc gives the workload's start on the boot clock.
    the device           SimDevice: a simulated MEC-native / non-oneM2M device that speaks plain HTTP/JSON to the
                         proxy, as a MicroPython board would (device_body is json.dumps of the record, as bytes)

The workloads' own requests and the agent's MEC 010-2 calls do not go through fl_run's byte counter: the FL_03
bytes stay the driver's calls and the notifications, as defined there. Standard library only.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
APPS = HERE / "apps"
PACKAGES = {"fl_orch": APPS / "fl_orch", "fl_tfc": APPS / "fl_tfc", "fl_proxy": APPS / "fl_proxy"}
CSE_NAMES = ("cse-in", "cse-mn-a", "cse-mn-b")
CLK_TCK = os.sysconf("SC_CLK_TCK")          # the unit of a process's start time in /proc/<pid>/stat


def boot_clock() -> float:
    """Seconds on the boot clock, the clock /proc/<pid>/stat gives a process's start time on."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _json(raw: bytes):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return None


def http(method: str, url: str, body=None, timeout: float = 10):
    """One plain HTTP request -> (status, parsed body); status 0 when nothing answered."""
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                               headers={"Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, _json(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, _json(e.read())
    except OSError:
        return 0, None


# ------------------------------------------------------------------------------------------------ packages
def package_for(src: Path, cse: str, dst: Path) -> Path:
    """A copy of the package at dst whose descriptor names `cse` as its CSE; nothing else changes. When the
    package already names it, the copy is byte for byte the shipped package (the same checksum)."""
    if cse not in CSE_NAMES:
        raise ValueError(f"{cse!r} is not a CSE of this platform ({', '.join(CSE_NAMES)})")
    src, dst = Path(src), Path(dst)
    shutil.copytree(src, dst)
    d = json.loads((dst / "appd.json").read_text())
    if d["onem2m"]["mnCse"] != cse:
        d["onem2m"]["mnCse"] = cse
        (dst / "appd.json").write_text(json.dumps(d, indent=2) + "\n")
    return dst


# ------------------------------------------------------------------------------------------------ relays
class _Relay(BaseHTTPRequestHandler):
    def _relay(self):
        relay = self.server.relay
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        rec = {"n": None, "method": self.command, "path": self.path, "raw": raw.decode("utf-8", "replace"),
               "body": _json(raw), "headers": {k.lower(): v for k, v in self.headers.items()}, "status": None,
               "rsc": None, "reply": None, "t_in": time.monotonic(), "t_in_boot": boot_clock()}
        with relay.lock:
            rec["n"] = len(relay.seen)
            relay.seen.append(rec)
        if relay.hold is not None and relay.hold(rec):
            rec["held"] = True
            relay.release.wait(30)
        fwd = urllib.request.Request(relay.upstream + self.path, data=raw or None, method=self.command, headers={
            k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")})
        try:
            with urllib.request.urlopen(fwd, timeout=10) as r:
                status, hdrs, out = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            status, hdrs, out = e.code, e.headers, e.read()
        except OSError:
            status, hdrs, out = 502, {}, b""
        rsc = (dict(hdrs) if hdrs else {}).get("X-M2M-RSC")
        rec.update(status=status, rsc=int(rsc) if rsc and str(rsc).isdigit() else None, reply=_json(out),
                   t_out=time.monotonic(), t_out_boot=boot_clock())
        headers = [(k, v) for k, v in (hdrs.items() if hdrs else [])
                   if k.lower() not in ("transfer-encoding", "connection", "content-length", "date", "server")]
        try:
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        except OSError:
            pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _relay

    def log_message(self, *a):
        pass


class Relay:
    """A recording relay on 127.0.0.1:<free port> in front of `upstream`. hold(record) -> True keeps that request
    back until release is set (at most 30 s)."""

    def __init__(self, upstream: str, name: str):
        self.upstream, self.name, self.seen, self.lock = upstream.rstrip("/"), name, [], threading.Lock()
        self.hold, self.release = None, threading.Event()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Relay)
        self.srv.daemon_threads = True
        self.srv.relay = self
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def since(self, n: int) -> list[dict]:
        with self.lock:
            return list(self.seen[n:])

    def close(self) -> None:
        self.release.set()
        self.srv.shutdown()
        self.srv.server_close()


def ty_of(record: dict) -> int | None:
    """The resource type a Create names in its Content-Type (application/json;ty=<n>), exactly: ty=2 is not ty=28."""
    for part in record["headers"].get("content-type", "").split(";")[1:]:
        k, _, v = part.strip().partition("=")
        if k == "ty" and v.isdigit():
            return int(v)
    return None


def creates(records: list[dict], ty: int, origin: str | None = None) -> list[dict]:
    """The oneM2M Creates of resource type ty among relay records (optionally from one originator)."""
    return [r for r in records if r["method"] == "POST" and ty_of(r) == ty
            and (origin is None or r["headers"].get("x-m2m-origin") == origin)]


def mp1_posts(records: list[dict]) -> list[list]:
    """[last path segment, status] of each POST an app sent to MEC 011, in order."""
    return [[r["path"].split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1], r["status"]] for r in records if r["method"] == "POST"]


# ------------------------------------------------------------------------------------------------ the platform
def workloads(workdir: Path) -> list[int]:
    """pids of live processes with an argument under workdir (the agent's package store and instance folders)."""
    found, w = [], str(Path(workdir))
    for p in Path("/proc").glob("[0-9]*"):
        try:
            args = (p / "cmdline").read_bytes().decode(errors="replace").split("\0")
        except OSError:
            continue
        if any(a.startswith(f"{w}/") for a in args):
            found.append(int(p.name))
    return sorted(found)


def process_start_tick(pid) -> int | None:
    """When a live process started, in clock ticks (CLK_TCK per second) on the boot clock: field 22 of
    /proc/<pid>/stat. None when there is no such process."""
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text()
        return int(stat.rsplit(")", 1)[1].split()[19])      # the fields after the command name start at field 3
    except (OSError, TypeError, ValueError, IndexError):
        return None


def mec010_view(mec010: str) -> dict:
    """What MEC 010-2 itself lists (reads with no side effect): every app instance (app_lcm) and every package
    (app_pkgm), with the HTTP status of each read."""
    st_i, inst = http("GET", f"{mec010.rstrip('/')}/app_lcm/v1/app_instances")
    st_p, pkgs = http("GET", f"{mec010.rstrip('/')}/app_pkgm/v1/app_packages")
    keep_i, keep_p = ("id", "appDId", "instantiationState"), ("id", "appDId", "checksum", "operationalState", "usageState")
    return {"instances_status": st_i, "packages_status": st_p,
            "instances": [{k: i.get(k) for k in keep_i} for i in (inst if st_i == 200 and isinstance(inst, list) else [])
                          if isinstance(i, dict)],
            "packages": [{k: p.get(k) for k in keep_p} for p in (pkgs if st_p == 200 and isinstance(pkgs, list) else [])
                         if isinstance(p, dict)]}


def descriptor_index(paths) -> dict[str, dict]:
    """{SHA-256 of a descriptor file: the descriptor parsed from the same bytes} for each appd.json given. A
    descriptor counts for an instance only through the checksum MEC 010-2 holds for its package, so where the
    file comes from does not matter: one byte off and it matches no checksum."""
    out = {}
    for p in paths:
        raw = Path(p).read_bytes()
        out[hashlib.sha256(raw).hexdigest()] = json.loads(raw)
    return out


class Platform:
    """The pinned agent behind relays. cses: {CSE name: its real address (http://host:port/<name>)}."""

    def __init__(self, agent_mod, mec010: str, mec011: str, cses: dict[str, str], workdir: Path, grace: float = 5.0):
        self.mod, self.mec010, self.mec011, self.workdir = agent_mod, mec010.rstrip("/"), mec011.rstrip("/"), Path(workdir)
        self.relays = {name: Relay(u.rsplit("/", 1)[0], name) for name, u in cses.items()}
        self.relays["mec011"] = Relay(self.mec011, "mec011")
        self.relays["mec010"] = Relay(self.mec010, "mec010")       # the agent's lifecycle calls, on the wire
        self.agent = agent_mod.PlatformAgent(
            mec010=self.relays["mec010"].url, mec011=self.relays["mec011"].url,
            cses={name: f"{self.relays[name].url}/{name}" for name in cses}, workdir=self.workdir, grace=grace)
        self.deployed: dict[str, dict] = {}

    def descriptors(self) -> dict[str, dict]:
        """descriptor_index of the package copies this run handed to the agent (workdir/src/<key>/appd.json)."""
        return descriptor_index(sorted((self.workdir / "src").glob("*/appd.json")))

    def _mark(self) -> dict:
        return {k: len(r.seen) for k, r in self.relays.items()}

    def deploy(self, key: str, cse: str, *, at_hold=None, ready_timeout: float = 15.0) -> dict:
        """Onboard the package `key` (its descriptor naming `cse`), create its instance, instantiate it. With
        at_hold, the app's confirm_ready is held at the MEC 011 relay; at_hold(D) runs while it is held and its
        result is kept in D['at_hold']; then it is released. Returns D (D['error'] says why, if it failed)."""
        D = {"key": key, "cse": cse, "error": None, "mark": self._mark()}
        try:
            pkg = package_for(PACKAGES[key], cse, self.workdir / "src" / key)
            D["descriptor_sha256"] = self.mod.descriptor_digest(pkg)
            D["shipped_descriptor_sha256"] = self.mod.descriptor_digest(PACKAGES[key])
            D["desc"] = self.mod.verify_package(pkg)
            ob = self.agent.onboard(pkg)
            D.update(appPkgId=ob["appPkgId"], appDId=ob["appDId"], checksum=ob["checksum"], store=str(ob["store"]))
            D["lcmInstanceId"] = self.agent.create_instance(ob["appDId"], f"fl-{key}")
            D["before"] = self.lcm_state(D)
            if at_hold is None:
                D["run"] = self.agent.instantiate(D["lcmInstanceId"], ready_timeout=ready_timeout)
            else:
                D["run"], D["at_hold"] = self._held(D, at_hold, ready_timeout)
        except Exception as e:  # noqa: BLE001  the run reports it as a failed row
            D["error"] = f"{type(e).__name__}: {e}"
        D["records"] = {k: self.relays[k].since(n) for k, n in D["mark"].items()}
        self.deployed[key] = D
        return D

    def _held(self, D: dict, at_hold, ready_timeout: float):
        relay, out = self.relays["mec011"], {}
        relay.release.clear()
        relay.hold = lambda r: r["method"] == "POST" and r["path"].endswith("/confirm_ready")

        def go():
            try:
                out["run"] = self.agent.instantiate(D["lcmInstanceId"], ready_timeout=ready_timeout)
            except Exception as e:  # noqa: BLE001
                out["err"] = e
        t = threading.Thread(target=go, daemon=True)
        t.start()
        end, held = time.monotonic() + ready_timeout, None
        try:
            while time.monotonic() < end and t.is_alive():
                held = next((r for r in relay.since(D["mark"]["mec011"]) if r.get("held")), None)
                if held is not None:
                    break
                time.sleep(0.02)
            seen = at_hold(D) if held is not None else {"held": False}
        finally:
            relay.hold = None
            relay.release.set()
            t.join(ready_timeout + 5)
        if "err" in out:
            raise out["err"]
        if "run" not in out:
            raise TimeoutError("the instance did not become ready")
        return out["run"], seen

    # ---- what the platform says about an instance
    def lcm_state(self, D: dict) -> dict:
        st_i, inst = http("GET", f"{self.mec010}/app_lcm/v1/app_instances/{D.get('lcmInstanceId')}")
        st_p, pkg = http("GET", f"{self.mec010}/app_pkgm/v1/onboarded_app_packages/{D.get('appPkgId')}")
        st_o, occ = http("GET", f"{self.mec010}/app_lcm/v1/app_lcm_op_occs")
        return {"instance_status": st_i, "instance": inst if st_i == 200 else None, "package_status": st_p,
                "package": pkg if st_p == 200 else None,
                "op_occs": [[o["lcmOperation"], o["operationState"]] for o in (occ if st_o == 200 and isinstance(occ, list) else [])
                            if o.get("appInstanceId") == D.get("lcmInstanceId")]}

    def listed(self, lcm: str | None) -> list[dict]:
        """The services MEC 011 lists for an instance (it lists those of confirmed-ready instances only)."""
        st, body = http("GET", f"{self.mec011}/mec_service_mgmt/v1/services")
        return [s for s in (body if st == 200 and isinstance(body, list) else [])
                if lcm and (s.get("transportInfo") or {}).get("id") == lcm]

    def registered(self, mid: str | None) -> bool:
        """Whether MEC 011 still holds the app instance (a read with no side effect, as REG_03's test does)."""
        return bool(mid) and http("GET", f"{self.mec011}/mec_app_support/v2/applications/{mid}/dns_rules")[0] == 200

    def evidence(self, D: dict) -> dict:
        """The input of fl_core.app_deployed for one deployment, from MEC 010-2, MEC 011, /proc, the store and the
        relays. 'agent_result' is the agent's own record; 'op_occs' is what MEC 010-2 says (the candidate leaves a
        successful operation PROCESSING); 'lifecycle' is the order as observed: the instantiate request on the
        agent's wire to MEC 010-2 ([status, answered at (monotonic), answered at (boot clock)]), the workload's
        first POST on Mp1 (monotonic), its start from /proc (boot clock, CLK_TCK ticks)."""
        run, lcm = D.get("run") or {}, self.lcm_state(D)
        store, prog = D.get("store"), (D.get("desc") or {}).get("entryPoint", {}).get("file")
        pid = run.get("pid")
        rec, iid = D.get("records") or {}, D.get("lcmInstanceId")
        inst_calls = [[r["status"], r.get("t_out"), r.get("t_out_boot")] for r in rec.get("mec010", [])
                      if r["method"] == "POST" and iid and r["path"].split("?", 1)[0] == f"/app_lcm/v1/app_instances/{iid}/instantiate"]
        mp1 = [r.get("t_in") for r in rec.get("mec011", []) if r["method"] == "POST"]
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().decode().split("\0")[:-1] if pid else []
        except OSError:
            argv = []
        try:
            prog_sha = hashlib.sha256(Path(store, prog).read_bytes()).hexdigest() if store and prog else None
        except OSError:
            prog_sha = None
        return {"error": D.get("error"), "checksum": D.get("checksum"), "descriptor_sha256": D.get("descriptor_sha256"),
                "package": lcm["package"], "instance": lcm["instance"], "appDId": D.get("appDId"),
                "agent_result": self.agent.results.get(run.get("opOcc")), "op_occs": lcm["op_occs"],
                "pid_alive": bool(pid) and pid in workloads(self.workdir), "argv": argv, "store": store, "program": prog,
                "program_sha256": prog_sha,
                "expected_program_sha256": (D.get("desc") or {}).get("files", {}).get(prog),
                "listed": bool(self.listed(D.get("lcmInstanceId"))),
                "lifecycle": {"instantiate_on_wire": inst_calls, "first_mp1_post_t_in": mp1[0] if mp1 else None,
                              "process_start_tick": process_start_tick(pid) if pid else None, "clk_tck": CLK_TCK}}

    def stop(self, key: str) -> dict:
        """Terminate the instance (SIGTERM; the app says goodbye and removes its AE and registrations), delete it
        and offboard the package; what was left afterwards, as each part reports it."""
        D = self.deployed.get(key) or {}
        out, mark = {"key": key}, self._mark()
        lcm, mid = D.get("lcmInstanceId"), (D.get("run") or {}).get("mec011AppInstanceId")
        try:
            if (D.get("run") or {}).get("pid"):
                out["terminate"] = self.agent.terminate(lcm)
            if lcm in self.agent.instances:
                self.agent.delete_instance(lcm)
                out["instance_deleted"] = True
            if D.get("appPkgId") in self.agent.packages:
                self.agent.offboard(D["appPkgId"])
                out["package_offboarded"] = True
        except Exception as e:  # noqa: BLE001
            out["error"] = f"{type(e).__name__}: {e}"
        out["records"] = {k: self.relays[k].since(n) for k, n in mark.items()}
        out["after"] = {"instance_status": http("GET", f"{self.mec010}/app_lcm/v1/app_instances/{lcm}")[0] if lcm else None,
                        "package_status": http("GET", f"{self.mec010}/app_pkgm/v1/app_packages/{D.get('appPkgId')}")[0]
                        if D.get("appPkgId") else None,
                        "listed": bool(self.listed(lcm)), "registered": self.registered(mid),
                        "process": (D.get("run") or {}).get("pid") in workloads(self.workdir)}
        return out

    def close(self) -> dict:
        """Best effort: stop whatever is still running (the agent's own close), close the relays, remove the
        work folder. Returns what was left."""
        with contextlib.suppress(Exception):
            self.agent.close()
        left = {"processes": workloads(self.workdir), "instances": sorted(self.agent.instances),
                "packages": sorted(self.agent.packages)}
        for r in self.relays.values():
            with contextlib.suppress(Exception):
                r.close()
        shutil.rmtree(self.workdir, ignore_errors=True)
        left["workdir_exists"] = self.workdir.exists()
        return left


# ------------------------------------------------------------------------------------------------ the device
def device_body(rec: dict) -> bytes:
    """What a MicroPython board posts: json.dumps of its record, as bytes (ujson gives the same text)."""
    return json.dumps(rec).encode()


def device_endpoint(service: dict) -> str | None:
    """The device-facing URL a proxy publishes in its MEC 011 service (the URI ending in /devices)."""
    uris = ((service or {}).get("transportInfo") or {}).get("endpoint", {}).get("uris", [])
    return next((u for u in uris if u.rstrip("/").endswith("/devices")), None)


class SimDevice:
    """A simulated MEC-native / non-oneM2M device: plain HTTP/JSON, no oneM2M, no MEC API. A real board replaces
    it by sending the same request (device_body, Content-Type application/json) to the same endpoint."""

    def __init__(self, device_id: str):
        self.id, self.sent = device_id, []

    def post(self, endpoint: str, rec: dict, *, ctype: str = "application/json") -> tuple[int, dict | None, str]:
        body = device_body(rec)
        r = urllib.request.Request(f"{endpoint.rstrip('/')}/{self.id}/data", data=body, method="POST",
                                   headers={"Content-Type": ctype})
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                st, out = resp.status, _json(resp.read())
        except urllib.error.HTTPError as e:
            st, out = e.code, _json(e.read())
        except OSError:
            st, out = 0, None
        self.sent.append({"status": st, "body": body.decode()})
        return st, out, body.decode()
