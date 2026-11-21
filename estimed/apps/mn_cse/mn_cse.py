#!/usr/bin/env python3
"""A oneM2M MN-CSE packaged as a MEC application: TR-0086 deployment option C, and option D when the descriptor
declares the MEC service it produces (appServiceProduced).

Started by the platform agent (estimed/mec_app_deploy.py) as

    python3 -I -B mn_cse.py --instance <instance.json>

instance.json is what the platform tells this instance: {"lcmInstanceId", "mec011", "cse"}. For this package "cse"
is the CSEBase URI of the CSE it registers to over Mcc: the descriptor's onem2m.mnCse names that registrar (cse-in)
and the platform knows where it is. The MN-CSE itself is ACME, installed on the host and not part of the package
(TR-0086 5.2.3: "both the MN-CSE and the MEC platform processes are installed on the VM image"); the package carries
the CSE's configuration (mn-c.ini) and this supervisor.

On start, in this order:
  1. checks: the installed ACME is the release the descriptor names; the ini has no baseDirectory line; its cseName is
     the descriptor's onem2m.rn, its adminID onem2m.originator, its registrarCseName the registrar's name; nothing
     answers on the ini's port yet
  2. Mp1  registers its instance with MEC 011
  3. starts ACME as its child, with an empty environment and --base-directory <instance folder>/acme, where it writes
     the ini with the registrar's host and port filled in
  4. waits until its CSEBase answers as this CSE (csi, cst 2) and it holds its registrar's <remoteCSE>, which ACME
     creates once its registration at the registrar succeeded
  5. Mp1  offers its service (serName = appName, endpoint = its CSEBase URI); with appServiceProduced naming
     onem2m-mn-cse (option D) also that service, with the same endpoint and transportInfo.id
  6. Mp1  confirm_ready -- only now
On SIGTERM (the termination request): confirm_termination, removes its services, stops ACME with SIGINT, deregisters
from MEC 011 and exits 0, or 3 if ACME did not stop cleanly. SIGINT is ACME's graceful stop, in which it deletes its
<remoteCSE> at the registrar; ACME installs no SIGTERM handler, so SIGTERM would leave that <remoteCSE> behind. If a
start step fails it removes what it created and exits 3; if ACME dies while running, the same and exit 4.

Of the onem2m block, which mec_app_deploy requires of every package, this program uses mnCse (its registrar), rn (its
CSEBase name) and originator (the admin originator of its CSE, for its own readiness reads). api, acp and container
describe no resource: this package creates no AE.

Standard library only.
"""
from __future__ import annotations

import argparse
import configparser
import ctypes
import json
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

EDGE_SERVICE = "onem2m-mn-cse"          # the service name estimed/handover.py reads as a ready edge
READY_S, STOP_S = 30.0, 10.0            # up and registered within; stopped within
PR_SET_PDEATHSIG = 1                    # prctl(2)


class Stop(Exception):
    """The termination request arrived."""


class Failed(Exception):
    """A start step did not get what it needs."""


class Died(Exception):
    """ACME exited while running."""


def _stop(*_):
    raise Stop


def call(method: str, url: str, body=None, headers=None):
    """One HTTP request -> (status, parsed body or None, response headers)."""
    r = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), method=method,
                               headers={"Accept": "application/json", "Content-Type": "application/json",
                                        **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            status, raw, hdrs = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as e:
        status, raw, hdrs = e.code, e.read(), e.headers
    try:
        return status, (json.loads(raw) if raw else None), hdrs
    except ValueError:
        return status, None, hdrs


def retrieve(url: str, origin: str):
    """One oneM2M RETRIEVE -> (response status code, parsed body); (0, None) when nothing answers."""
    try:
        _, parsed, hdrs = call("GET", url, None, {"X-M2M-Origin": origin, "X-M2M-RI": uuid.uuid4().hex[:12],
                                                  "X-M2M-RVI": "4"})
    except OSError:
        return 0, None
    return int(hdrs.get("X-M2M-RSC") or 0), parsed


def need(what: str, got, want) -> None:
    if got != want:
        raise Failed(f"{what}: got {got!r}, need {want!r}")
    print(f"{what}: {got}", flush=True)


def acme_releases(program: Path) -> list[str]:
    """The acmecse releases installed beside `program` (<venv>/bin/acmecse), read from their dist-info folders."""
    root = Path(program).parent.parent
    return sorted(p.name[len("acmecse-"):-len(".dist-info")]
                  for p in root.glob("lib/python*/site-packages/acmecse-*.dist-info"))


def produced(desc: dict) -> list[dict]:
    """The services the descriptor says this instance produces besides its own: nothing (option C) or onem2m-mn-cse
    once, with a version (option D). Anything else is refused: this program offers nothing else."""
    p = desc.get("appServiceProduced", [])
    ok = isinstance(p, list) and len(p) <= 1 and all(
        isinstance(s, dict) and s.get("serName") == EDGE_SERVICE and isinstance(s.get("version"), str) and s["version"]
        for s in p)
    if not ok:
        raise Failed(f"appServiceProduced: this program produces {EDGE_SERVICE!r} once, with a version, or nothing; "
                     f"not {p!r}")
    return p


def render_ini(template: str, registrar: str, desc: dict) -> dict:
    """The ini ACME is started with, and the CSE's own facts read from it. `registrar` is the platform's address of
    the CSE named onem2m.mnCse (http://host:port/<name>); its host and port go into the ini."""
    o = desc["onem2m"]
    if re.search(r"(?mi)^\s*baseDirectory\s*=", template):
        raise Failed("the ini sets baseDirectory, which would override --base-directory for ACME's log path")
    for mark in ("@REGISTRAR_HOST@", "@REGISTRAR_PORT@"):
        if template.count(mark) != 1:
            raise Failed(f"the ini must hold {mark} exactly once")
    u = urllib.parse.urlsplit(registrar)
    try:
        port = u.port
    except ValueError:
        port = None
    if u.scheme != "http" or not u.hostname or not port or u.query or u.fragment or u.path != f"/{o['mnCse']}":
        raise Failed(f"registrar {registrar!r} is not http://<host>:<port>/{o['mnCse']}")
    text = template.replace("@REGISTRAR_HOST@", u.hostname).replace("@REGISTRAR_PORT@", str(port))
    ini = configparser.ConfigParser(interpolation=None)
    ini.read_string(text)
    b = ini["basic.config"]
    for key, want in (("cseType", "MN"), ("cseName", o["rn"]), ("adminID", o["originator"]),
                      ("registrarCseName", o["mnCse"])):
        if b.get(key) != want:
            raise Failed(f"ini {key}: got {b.get(key)!r}, need {want!r}")
    return {"text": text, "host": b["cseHost"], "port": int(b["httpPort"]),
            "base_url": f"http://{b['cseHost']}:{b['httpPort']}/{b['cseName']}", "csi": f"/{b['cseID']}",
            "admin": b["adminID"], "registrar_csr": f"{b['cseName']}/{b['registrarCseID']}"}


def _answers(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def _die_with_parent() -> None:
    """In ACME's process before it runs: should this supervisor die, even by SIGKILL, the kernel sends ACME SIGINT
    (its graceful stop), so a killed supervisor does not leave a CSE holding its port and its <remoteCSE>."""
    if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, int(signal.SIGINT), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG)")


def wait_up(acme: subprocess.Popen, cse: dict) -> None:
    """Return once the CSEBase answers as this CSE and the CSE holds its registrar's <remoteCSE>."""
    deadline = time.monotonic() + READY_S
    while time.monotonic() < deadline:
        if acme.poll() is not None:
            raise Failed(f"ACME exited with {acme.returncode} before it was up; see acme/logs and acme/stdout.log")
        rsc, body = retrieve(cse["base_url"], cse["admin"])
        cb = (body or {}).get("m2m:cb") or {} if isinstance(body, dict) else {}
        if rsc == 2000 and cb.get("csi") == cse["csi"] and cb.get("cst") == 2:
            rsc, body = retrieve(f"{cse['base_url']}?fu=1&ty=16", cse["admin"])
            if rsc == 2000 and isinstance(body, dict) and cse["registrar_csr"] in body.get("m2m:uril", []):
                print(f"CSEBase {cse['base_url']} answers as {cse['csi']} and holds {cse['registrar_csr']}", flush=True)
                return
        time.sleep(0.2)
    raise Failed(f"the CSE was not up and registered within {READY_S} s")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", required=True)
    cfg = json.loads(Path(ap.parse_args().instance).read_text())
    here = Path(__file__).resolve().parent
    desc = json.loads((here / "appd.json").read_text())
    lcm = cfg["lcmInstanceId"]
    support, services = f"{cfg['mec011']}/mec_app_support/v2", f"{cfg['mec011']}/mec_service_mgmt/v1"
    made = {"inst": None, "ser": [], "acme": None, "clean": True}

    def start() -> None:
        acme = desc["acme"]
        need("ACME release installed", acme_releases(Path(acme["program"])), [acme["release"]])
        cse = render_ini((here / acme["config"]).read_text(), cfg["cse"], desc)
        extra = produced(desc)
        if _answers(cse["host"], cse["port"]):
            raise Failed(f"{cse['host']}:{cse['port']} already answers before this CSE was started")
        st, body, _ = call("POST", f"{support}/registrations", {"appName": desc["appName"], "appInstanceId": lcm})
        need("MEC 011 registration", st, 201)
        inst = made["inst"] = body["appInstanceId"]         # MEC 011 hands out its own identifier
        base = Path.cwd() / "acme"
        base.mkdir()
        (base / "acme.ini").write_text(cse["text"])
        with (base / "stdout.log").open("wb") as out:       # env={}: ACME inherits nothing from this process
            made["acme"] = subprocess.Popen(
                [acme["program"], "--headless", "--config", "acme.ini", "--base-directory", str(base)], cwd=base,
                env={}, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT, preexec_fn=_die_with_parent)
        print(f"ACME started: pid {made['acme'].pid}, base directory {base}", flush=True)
        wait_up(made["acme"], cse)
        for name, version in ((desc["appName"], desc["appSoftVersion"]),
                              *((s["serName"], s["version"]) for s in extra)):
            st, body, _ = call("POST", f"{services}/applications/{inst}/services", {
                "serName": name, "version": version, "state": "ACTIVE", "serializer": "JSON",
                "transportInfo": {"id": lcm, "name": "oneM2M MN-CSE (Mca)", "type": "REST_HTTP", "protocol": "HTTP",
                                  "version": "1.1", "security": {}, "endpoint": {"uris": [cse["base_url"]]}}})
            need(f"MEC 011 service {name}", st, 201)
            made["ser"].append(body["serInstanceId"])
        st, _, _ = call("POST", f"{support}/applications/{inst}/confirm_ready", {"indication": "READY"})
        need("MEC 011 confirm_ready", st, 204)

    def run() -> None:
        while True:
            try:
                code = made["acme"].wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                continue
            raise Died(f"ACME exited with {code} while running")

    def say_goodbye() -> None:
        if made["inst"]:
            call("POST", f"{support}/applications/{made['inst']}/confirm_termination",
                 {"operationAction": "TERMINATING"})

    def drop_services() -> None:
        for ser in made["ser"]:
            call("DELETE", f"{services}/applications/{made['inst']}/services/{ser}")

    def stop_acme() -> None:
        a = made["acme"]
        if a is None or a.poll() is not None:
            return
        a.send_signal(signal.SIGINT)                        # graceful: ACME deletes its <remoteCSE> at the registrar
        try:
            a.wait(STOP_S)
        except subprocess.TimeoutExpired:
            a.kill()
            a.wait(5)
            made["clean"] = False
        made["clean"] = made["clean"] and a.returncode == 0
        print(f"ACME stopped: exit {a.returncode}", flush=True)

    def deregister() -> None:
        if made["inst"]:
            call("DELETE", f"{support}/registrations/{made['inst']}")

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    code = 0
    try:
        start()
        print("ready; waiting for the termination request", flush=True)
        run()
    except Stop:
        print("termination requested", flush=True)
    except Died as e:
        print(f"FAILED {e}", flush=True)
        code = 4
    except (Failed, OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as e:
        print(f"FAILED {type(e).__name__}: {e}", flush=True)
        code = 3
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)       # the goodbye is not interrupted a second time
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for step in (say_goodbye, drop_services, stop_acme, deregister):
            try:
                step()
            except (OSError, KeyError, TypeError, subprocess.SubprocessError) as e:
                print(f"leaving: {step.__name__} failed: {e}", flush=True)
    return 3 if code == 0 and not made["clean"] else code


if __name__ == "__main__":
    sys.exit(main())
