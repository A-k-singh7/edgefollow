#!/usr/bin/env python3
"""Deploy a packaged oneM2M AE as a MEC application on this host (test plan TD_MEC_REG_03, step 1).

What stands in for the MEC platform here, plainly:

    mec010p2/candidate.py            GS MEC 010-2 package management (app_pkgm/v1) and lifecycle (app_lcm/v1) API.
                                     It keeps state and starts nothing.
    mec011_appsupport/candidate.py   GS MEC 011 application support and service registry, which the app talks to.
    PlatformAgent (this file)        does what a platform manager would on instantiate and terminate: checks the
                                     package against its descriptor, starts the workload as a process, stops it.

The workload is an ordinary process of the user running the agent. There is no container, no sandbox and no
isolation: the digests show that what runs is what was onboarded, nothing more. Not a conformance claim.

A package is a directory holding `appd.json` and the files it lists. The descriptor is our own JSON; a few field
names follow the AppD of MEC 010-2 (appName, appProvider, appSoftVersion, appDVersion), the rest are ours:

    entryPoint           runtime (only "python3"), file (one of `files`), args ("{instance}" becomes the path of
                         the instance configuration the agent writes)
    files                SHA-256 of EVERY file in the package except appd.json; a file that is not listed, a
                         listed file that is missing or differs, a symbolic link: all refused
    mecServicesRequired  the platform APIs the app calls; one the platform does not offer is refused
    onem2m               the MN-CSE it registers to (by CSEBase name; the agent knows the address), its App-ID,
                         its originator (C-prefixed, so the AE-ID it gets is the originator), the names of its
                         <AE>, <ACP> and baseline <container>, and who may read

The SHA-256 of appd.json is the package checksum given to app_pkgm at onboarding, so the one value held there
covers every file.

    python3 estimed/mec_app_deploy.py digests estimed/apps/sensor_ae [--write]

Standard library only.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

DESCRIPTOR = "appd.json"
RUNTIMES = {"python3": [sys.executable, "-I", "-B"]}      # -I: no environment, no script folder on sys.path
OFFERS = {"mec_app_support": "v2", "mec_service_mgmt": "v1"}
_STR = {"": ("appName", "appProvider", "appSoftVersion", "appDVersion"),
        "entryPoint": ("runtime", "file"),
        "onem2m": ("mnCse", "api", "originator", "rn", "container")}
_NAME = re.compile(r"[A-Za-z0-9_-]+\Z")                   # one path segment, nothing a URL would read otherwise


class DeployError(Exception):
    """The deployment step was refused or failed."""


class PackageError(DeployError):
    """The package is not what its descriptor says, or the descriptor is not one the platform can run."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def descriptor_digest(pkg: Path) -> str:
    """The package checksum: SHA-256 of the descriptor, which carries the digest of every other file."""
    return _sha256(Path(pkg) / DESCRIPTOR)


def package_files(pkg: Path) -> dict[str, str]:
    """SHA-256 of every file in the package except the descriptor, by its path relative to the package."""
    pkg, out = Path(pkg), {}
    for p in sorted(pkg.rglob("*")):
        rel = p.relative_to(pkg).as_posix()
        if p.is_symlink() or not (p.is_file() or p.is_dir()):
            raise PackageError(f"{rel}: a symbolic link or special file is not allowed in a package")
        if p.is_file() and rel != DESCRIPTOR:
            out[rel] = _sha256(p)
    return out


def _need(d, where: str, key: str, kind):
    if not isinstance(d, dict) or key not in d:
        raise PackageError(f"descriptor lacks {where}{key}")
    if not isinstance(d[key], kind) or (kind is str and not d[key]):
        raise PackageError(f"descriptor field {where}{key} is not a {'non-empty ' if kind is str else ''}"
                           f"{kind.__name__}")
    return d[key]


def verify_package(pkg: Path) -> dict:
    """The descriptor of a package that is exactly what the descriptor says; PackageError otherwise."""
    pkg = Path(pkg)
    try:
        desc = json.loads((pkg / DESCRIPTOR).read_text())
    except (OSError, ValueError) as e:
        raise PackageError(f"{pkg}/{DESCRIPTOR} is not a readable JSON descriptor: {e}") from None
    for where, keys in _STR.items():
        part = _need(desc, "", where, dict) if where else desc
        for k in keys:
            _need(part, where and where + ".", k, str)
    entry, o = desc["entryPoint"], desc["onem2m"]
    args = _need(entry, "entryPoint.", "args", list)
    acp = _need(o, "onem2m.", "acp", dict)
    readers = _need(acp, "onem2m.acp.", "readers", list)
    listed = _need(desc, "", "files", dict)
    needs = _need(desc, "", "mecServicesRequired", list)
    if not all(isinstance(a, str) for a in args):
        raise PackageError("descriptor field entryPoint.args is not a list of strings")
    if entry["runtime"] not in RUNTIMES:
        raise PackageError(f"entryPoint.runtime {entry['runtime']!r} is not offered (offered: {sorted(RUNTIMES)})")
    for n in needs:
        if not isinstance(n, dict) or not isinstance(n.get("serName"), str) or \
                OFFERS.get(n["serName"]) is None or OFFERS[n["serName"]] != n.get("version"):
            raise PackageError(f"mecServicesRequired: the platform does not offer {n!r} (offered: {OFFERS})")
    # the identity as the CSE will be asked to take it
    if not re.match(r"C[A-Za-z0-9_-]+\Z", o["originator"]):
        raise PackageError(f"onem2m.originator {o['originator']!r} is not a C-prefixed AE-ID stem")
    if not re.match(r"[NR][A-Za-z0-9._-]+\Z", o["api"]):
        raise PackageError(f"onem2m.api {o['api']!r} does not start with N or R")
    for k, v in (("rn", o["rn"]), ("container", o["container"]), ("acp.rn", _need(acp, "onem2m.acp.", "rn", str))):
        if not _NAME.match(v):
            raise PackageError(f"onem2m.{k} {v!r} is not a plain resource name")
    if not all(isinstance(r, str) and _NAME.match(r) for r in readers):
        raise PackageError("onem2m.acp.readers is not a list of plain originators")
    # the content against the descriptor
    actual = package_files(pkg)
    for rel in sorted(set(listed) | set(actual)):
        if rel not in actual:
            raise PackageError(f"{rel}: listed in the descriptor but not in the package")
        if rel not in listed:
            raise PackageError(f"{rel}: in the package but not listed in the descriptor")
        if listed[rel] != actual[rel]:
            raise PackageError(f"{rel}: SHA-256 {actual[rel]} is not the descriptor's {listed[rel]}")
    f = PurePosixPath(entry["file"])
    if f.is_absolute() or ".." in f.parts or entry["file"] not in listed:
        raise PackageError(f"entryPoint.file {entry['file']!r} is not one of the package's files")
    return desc


def command(desc: dict, store: Path, instance_cfg: Path) -> list[str]:
    """The workload's command line: the runtime the descriptor names, its program, its arguments."""
    entry = desc["entryPoint"]
    return [*RUNTIMES[entry["runtime"]], str(Path(store) / entry["file"]),
            *(a.replace("{instance}", str(instance_cfg)) for a in entry["args"])]


def _http(method: str, url: str, body=None, raw: bytes | None = None, ctype: str = "application/json"):
    """One REST call -> (status, parsed body or None, response headers). No answer at all is a DeployError."""
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Accept": "application/json", "Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            status, out, hdrs = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        status, out, hdrs = e.code, e.read(), e.headers
    except OSError as e:
        raise DeployError(f"{method} {url}: {e}") from None
    try:
        return status, (json.loads(out) if out else None), hdrs
    except ValueError:
        return status, None, hdrs


def _expect(want: int, method: str, url: str, **kw):
    status, body, hdrs = _http(method, url, **kw)
    if status != want:
        raise DeployError(f"{method} {url} answered {status}, not {want}: {body}")
    return body, hdrs


class PlatformAgent:
    """Drives the package and instance lifecycle through the MEC 010-2 candidate and does, on this host, what
    that candidate only records.

    What the candidate does and does not do (mec010p2/candidate.py, read 2026-11-18):
      * instantiate and terminate only flip instantiationState, at once, and create an operation occurrence in
        PROCESSING. Nothing is started or stopped; the agent does that.
      * no route completes an occurrence. The agent can report a FAILURE (POST .../app_lcm_op_occs/{id}/fail);
        a success stays PROCESSING there, so the agent keeps every result in `results` as well.
      * it says INSTANTIATED the moment it takes the call, before the workload is ready. If the workload then
        does not become ready the agent fails the occurrence and sends a terminate to take the state back.
      * app_lcm accepts any appDId and app_pkgm drops the uploaded content, so the agent creates instances only
        of packages it onboarded and runs its own copy, checked again each time against the checksum held at
        app_pkgm.
    The MEC 011 candidate hands out its own appInstanceId; the instance is matched there by the app_lcm instance
    id the app puts in its service's transportInfo.id. Ready means: MEC 011 lists that service, which it does
    only once the app has confirmed ready.
    """

    def __init__(self, mec010: str, mec011: str, cses: dict[str, str], workdir: Path, grace: float = 5.0):
        self.pkgm, self.lcm = f"{mec010.rstrip('/')}/app_pkgm/v1", f"{mec010.rstrip('/')}/app_lcm/v1"
        self.mec011, self.cses, self.workdir, self.grace = mec011.rstrip("/"), dict(cses), Path(workdir), grace
        self.packages: dict[str, dict] = {}    # appPkgId -> appDId, store (the platform's copy)
        self.instances: dict[str, dict] = {}   # app_lcm instance id -> pkg, proc, mec011 (its id there), dir
        self.results: dict[str, str] = {}      # operation occurrence id -> COMPLETED | FAILED

    # ---- packages (app_pkgm)
    def onboard(self, pkg_dir: Path) -> dict:
        """Check the package, hand it to app_pkgm with its checksum, enable it, keep the platform's own copy."""
        src = Path(pkg_dir)
        desc, checksum = verify_package(src), descriptor_digest(src)
        info, _ = _expect(201, "POST", f"{self.pkgm}/app_packages", body={
            "appPkgName": desc["appName"], "appPkgVersion": desc["appSoftVersion"],
            "appProvider": desc["appProvider"], "checksum": {"algorithm": "SHA-256", "hash": checksum},
            "appPkgPath": src.resolve().as_uri()})
        pid, store = info["id"], self.workdir / "packages" / info["id"]
        self.packages[pid] = {"appDId": info["appDId"], "store": store}
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as z:
            for rel in (DESCRIPTOR, *desc["files"]):
                (store / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src / rel, store / rel)
                z.write(store / rel, rel)
        _expect(202, "PUT", f"{self.pkgm}/app_packages/{pid}/package_content", raw=archive.getvalue(),
                ctype="application/zip")
        _expect(200, "PATCH", f"{self.pkgm}/app_packages/{pid}", body={"operationalState": "ENABLED"})
        return {"appPkgId": pid, "appDId": info["appDId"], "checksum": checksum, "store": store}

    def offboard(self, pid: str) -> None:
        """Disable and delete the package at app_pkgm and drop the platform's copy."""
        if pid not in self.packages:
            raise DeployError(f"unknown package {pid!r}")
        if any(i["pkg"] == pid for i in self.instances.values()):
            raise DeployError(f"package {pid} still has instances")
        _expect(200, "PATCH", f"{self.pkgm}/app_packages/{pid}", body={"operationalState": "DISABLED"})
        _expect(204, "DELETE", f"{self.pkgm}/app_packages/{pid}")
        shutil.rmtree(self.packages.pop(pid)["store"], ignore_errors=True)

    # ---- instances (app_lcm)
    def _inst(self, iid: str) -> dict:
        if iid not in self.instances:
            raise DeployError(f"unknown instance {iid!r}")
        return self.instances[iid]

    def create_instance(self, app_d_id: str, name: str) -> str:
        pid = next((p for p, rec in self.packages.items() if rec["appDId"] == app_d_id), None)
        if pid is None:
            raise DeployError(f"appDId {app_d_id!r} was not onboarded by this agent")
        info, _ = _expect(201, "POST", f"{self.lcm}/app_instances",
                          body={"appDId": app_d_id, "appInstanceName": name})
        self.instances[info["id"]] = {"pkg": pid, "proc": None, "mec011": None,
                                      "dir": self.workdir / "instances" / info["id"]}
        return info["id"]

    def instantiate(self, iid: str, ready_timeout: float = 10.0) -> dict:
        """Start the instance's workload and return once MEC 011 lists it as ready; DeployError otherwise, with
        the workload stopped and the failure recorded at app_lcm."""
        inst = self._inst(iid)
        if inst["proc"] is not None and inst["proc"].poll() is None:
            raise DeployError(f"instance {iid} is already running (pid {inst['proc'].pid})")
        pid = inst["pkg"]
        store = self.packages[pid]["store"]
        # Refused before the lifecycle call, like a request the API would not accept: nothing is recorded.
        info, _ = _expect(200, "GET", f"{self.pkgm}/app_packages/{pid}")
        if info["operationalState"] != "ENABLED":
            raise DeployError(f"package {pid} is {info['operationalState']} at app_pkgm")
        desc = verify_package(store)
        if descriptor_digest(store) != info["checksum"]["hash"]:
            raise PackageError(f"{store}/{DESCRIPTOR}: its SHA-256 is not the checksum app_pkgm was given")
        cse = self.cses.get(desc["onem2m"]["mnCse"])
        if cse is None:
            raise DeployError(f"this platform has no MN-CSE named {desc['onem2m']['mnCse']!r}")
        _, hdrs = _expect(202, "POST", f"{self.lcm}/app_instances/{iid}/instantiate", body={
            "selectedMECHostInfo": [{"hostName": "localhost", "hostId": {"host": "localhost"}}]})
        occ = hdrs["Location"].rsplit("/", 1)[-1]
        try:
            run = self._run(iid, inst, command(desc, store, inst["dir"] / "instance.json"), cse, ready_timeout)
        except BaseException:
            if inst["proc"] is not None:
                self._stop(inst)                        # no-op if it has gone; an interrupt must not leave it
            inst["proc"] = inst["mec011"] = None
            self._failed(occ)
            with contextlib.suppress(DeployError):      # the candidate said INSTANTIATED when it took the call
                _http("POST", f"{self.lcm}/app_instances/{iid}/terminate", body={"terminationType": "FORCEFUL"})
            raise
        self.results[occ] = "COMPLETED"
        return {**run, "opOcc": occ}

    def _run(self, iid: str, inst: dict, argv: list[str], cse: str, ready_timeout: float) -> dict:
        inst["dir"].mkdir(parents=True, exist_ok=True)
        (inst["dir"] / "instance.json").write_text(json.dumps({"lcmInstanceId": iid, "mec011": self.mec011,
                                                                "cse": cse}))
        log = inst["dir"] / "workload.log"
        with log.open("ab") as out:                    # env={}: the workload inherits nothing from this shell
            proc = inst["proc"] = subprocess.Popen(argv, cwd=inst["dir"], env={}, stdin=subprocess.DEVNULL,
                                                   stdout=out, stderr=subprocess.STDOUT)
        why, deadline = f"not listed as ready at MEC 011 within {ready_timeout} s", time.monotonic() + ready_timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                why = f"the workload exited with {proc.returncode} before it was ready"
                break
            inst["mec011"] = self._listed(iid)
            if inst["mec011"]:
                return {"pid": proc.pid, "argv": argv, "mec011AppInstanceId": inst["mec011"]}
            time.sleep(0.05)
        code, forced = self._stop(inst)
        raise DeployError(f"instance {iid}: {why}; stopped (exit {code}{', killed' if forced else ''}); "
                          f"its log ends: {log.read_bytes()[-300:].decode(errors='replace')!r}")

    def _listed(self, iid: str) -> str | None:
        """MEC 011's own id for the instance, once MEC 011 lists the instance's service."""
        status, body, _ = _http("GET", f"{self.mec011}/mec_service_mgmt/v1/services")
        for s in body if status == 200 and isinstance(body, list) else []:
            if (s.get("transportInfo") or {}).get("id") == iid:
                return s["_links"]["self"]["href"].split("/applications/", 1)[1].split("/", 1)[0]
        return None

    def _stop(self, inst: dict) -> tuple[int, bool]:
        """SIGTERM, and SIGKILL if it is still there after the grace period -> (exit code, had to be killed)."""
        proc, forced = inst["proc"], False
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(self.grace)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
                forced = True
        if (forced or proc.returncode != 0) and inst["mec011"]:    # it did not leave in order: deregister it
            with contextlib.suppress(DeployError):
                _http("DELETE", f"{self.mec011}/mec_app_support/v2/registrations/{inst['mec011']}")
        return proc.returncode, forced

    def _failed(self, occ: str) -> None:
        self.results[occ] = "FAILED"
        with contextlib.suppress(DeployError):
            _http("POST", f"{self.lcm}/app_lcm_op_occs/{occ}/fail")

    def terminate(self, iid: str) -> dict:
        """Ask the workload to stop (SIGTERM is the termination request here), wait, kill it if it stays."""
        inst = self._inst(iid)
        if inst["proc"] is None:
            raise DeployError(f"instance {iid} is not running")
        _, hdrs = _expect(202, "POST", f"{self.lcm}/app_instances/{iid}/terminate", body={
            "terminationType": "GRACEFUL", "gracefulTerminationTimeout": max(1, int(self.grace))})
        occ = hdrs["Location"].rsplit("/", 1)[-1]
        code, forced = self._stop(inst)
        inst["proc"] = inst["mec011"] = None
        if forced or code != 0:
            self._failed(occ)
        else:
            self.results[occ] = "COMPLETED"
        return {"exitCode": code, "forced": forced, "opOcc": occ}

    def delete_instance(self, iid: str) -> None:
        inst = self._inst(iid)
        _expect(204, "DELETE", f"{self.lcm}/app_instances/{iid}")       # app_lcm refuses while INSTANTIATED
        shutil.rmtree(inst["dir"], ignore_errors=True)
        del self.instances[iid]

    def close(self) -> None:
        """Stop every workload this agent started and take its instances and packages out again. Best effort."""
        for iid, inst in list(self.instances.items()):
            if inst["proc"] is not None:
                try:
                    self.terminate(iid)
                except DeployError:
                    self._stop(inst)
            with contextlib.suppress(DeployError):
                self.delete_instance(iid)
        for pid in list(self.packages):
            with contextlib.suppress(DeployError):
                self.offboard(pid)


def _digests(argv: list[str]) -> int:
    """`digests <package> [--write]`: compare the descriptor's file digests with the package; exit 1 if they
    differ, or with --write put the package's digests into the descriptor."""
    pkg, write = Path(argv[0]), "--write" in argv[1:]
    path = pkg / DESCRIPTOR
    desc, actual = json.loads(path.read_text()), package_files(pkg)
    same = desc.get("files") == actual
    for rel, digest in actual.items():
        print(f"{digest}  {rel}" + ("" if desc.get("files", {}).get(rel) == digest else "   <- not the descriptor's"))
    for rel in sorted(set(desc.get("files", {})) - set(actual)):
        print(f"{'(missing)':64}  {rel}   <- listed, not in the package")
    if write and not same:
        desc["files"] = actual
        path.write_text(json.dumps(desc, indent=2) + "\n")
        print(f"wrote {path}; package checksum is now {descriptor_digest(pkg)}")
    return 0 if same or write else 1


if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] != "digests":
        sys.exit("usage: mec_app_deploy.py digests <package directory> [--write]")
    sys.exit(_digests(sys.argv[2:]))
