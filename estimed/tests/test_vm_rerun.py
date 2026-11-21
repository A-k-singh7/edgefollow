"""Offline checks for vm_rerun.py (TD_MEC_OBS_03 on a fresh virtual machine) -- no QEMU, no VM, no network beyond
servers this suite starts on 127.0.0.1 (an autouse guard refuses any other connection and the lab's ports): the
user-data (one user, password locked, no key, no sudo, byte for byte the harness's own, run.sh template pinned), the
seed and upload server (loopback only; refuses path components, oversize, overwrite, odd lengths and other methods;
read deadline; quota back on any failure), the allow-listing CONNECT proxy, the guestfwd relay, the QEMU line
(restrict=on, ipv6=off, exactly two guestfwd rules, every option's value pinned, refused otherwise), the base-image
copy into a private folder, the console and upload parsing, the five OBS_03 step verdicts (NOT-RUN is never PASS; no
summary is FAIL), clean_rerun's own verdict read on the host, step 2 judged on the host, step 5 on the host's clock,
the root step (only root=yes install blocks run as root; their exit codes on the console from root), the guest's
handling of the other install blocks and of the runbook's rerun block (run exactly as written from edgefollow's home), and
the code tarball built from a fixture git repository.

Every expected value is written here by hand (the SHA-256 and SHA-512 of "abc" are the FIPS 180-2 examples; the epoch
of 2026-11-20T10:00:30Z was taken from `date -u -d ... +%s`), none is taken from vm_rerun. A test named *_control_*
plants one fault and requires a refusal.

    python3 -I -B -m pytest -p no:cacheprovider estimed/tests/test_vm_rerun.py -q
    python3 -I -B estimed/tests/test_vm_rerun.py --plant <new directory> [--jobs N]   # single planted faults in COPIES
"""
from __future__ import annotations

import copy
import hashlib
import http.client
import importlib.util
import inspect
import itertools
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import tarfile
import threading
import time
import types
from pathlib import Path

import pytest

EST = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EST))
import clean_rerun as cr  # noqa: E402

_ALT = os.environ.get("VM_RERUN_UNDER_TEST")          # a planted-fault copy, see --plant below
if _ALT:
    _spec = importlib.util.spec_from_file_location("vm_rerun", _ALT)
    vr = importlib.util.module_from_spec(_spec)
    sys.modules["vm_rerun"] = vr
    _spec.loader.exec_module(vr)
else:
    import vm_rerun as vr  # noqa: E402

RUNBOOK = EST / "RUNBOOK.md"
SHA_ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
SHA512_ABC = ("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
IMAGE = "debian-13-genericcloud-amd64.qcow2"
TDS = ["TD_MEC_PF_01", "TD_MEC_REG_01", "TD_MEC_REG_02", "TD_MEC_REG_03", "TD_MEC_DEV_01"]
PLAN = [{"id": "install-a", "sha256": "1" * 64}, {"id": "install-b", "sha256": "2" * 64}]
SUMS = f"{SHA_ABC}  code.tar\n{SHA_ABC}  guest.py\n{SHA_ABC}  reference.json\n"
SEED_URL, PROXY_URL = "http://10.0.2.100:8080", "http://10.0.2.101:3128"
RELAY = "/usr/bin/python3 -I -B -S /p/relay.py"
ND = ("user,id=n0,restrict=on,ipv6=off,"                  # ipv6=off: pass 3, A (restrict=on does not stop IPv6 TCP)
      "guestfwd=tcp:10.0.2.100:8080-cmd:/usr/bin/python3 -I -B -S /p/relay.py 40123,"
      "guestfwd=tcp:10.0.2.101:3128-cmd:/usr/bin/python3 -I -B -S /p/relay.py 40124")
P, F, N = "PASS", "FAIL", "NOT-RUN"
LAB_PORTS = {8200, 8201, 8202, 8091, 8092, 8097, 8412, 8432, 8402, 8085, 5037}
# sha256 of RUN_SH_TEMPLATE as reviewed on 2026-11-20 (M7): a change to run.sh is a change to this pin, made on purpose.
# Changed 2026-11-20 pass 3 (C, an approved root step): the root-blocks line and its two progress lines added.
RUN_SH_TEMPLATE_SHA256 = "b3d9d348e7760393b3d2672a295ceca7c60021883ce6e05f04b3ccb5e23c07ff"
ROOT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
RERUN_HOST = ('\n```text\n: runbook-step rerun phase=rerun && \\\ncd "$ROOT" && "$PY" -B estimed/clean_rerun.py rerun '
              '--reference /home/edgefollow/vm-harness/reference.json\n```\n')      # the rerun block RUNBOOK.md section 6 ships
RERUN_BODY = RERUN_HOST.split("```text\n", 1)[1].split("\n```", 1)[0]
# sha256 of RERUN_BODY, from `printf '%s' '<its two lines>' | sha256sum` on 2026-11-20 (pass 3b), not from vm_rerun
RERUN_BODY_SHA256 = "ab93715f20184280e17e07173250f097ca0f91a9e422a4532bd8667ce2096888"
BUDGET_REASON_TEXT = (
    "ours, written 2026-11-20 before the first VM run; the test plan names no number. 900 s is the runbook's own "
    "budget for empty directory -> TD_MEC_DEV_01 passed with the environments already installed (33 s measured on "
    "this PC on 2026-11-18); the other 900 s are for what a clean VM adds: boot and cloud-init, fetching the code, "
    "and the install blocks downloading the CSE, the test runner and their dependencies from PyPI. Half an hour is "
    "one sitting for a developer onboarding.")
CR_CONTROLS = [                                           # clean_rerun.py's seven control rows, copied by hand
    "CONTROL (must FAIL) with the bootstrap steps taken out of the runbook, TD_MEC_PF_01 still passes",
    "CONTROL (must FAIL) a command that is not in the runbook was executed",
    "CONTROL (must FAIL) an executed-command log with one foreign entry is accepted",
    "CONTROL (must FAIL) a copy in which a file was changed after the manifest was written is accepted",
    "CONTROL (must FAIL) a run directory with old state is accepted",
    "CONTROL (must FAIL) a skipped test is counted as passed",
    "CONTROL (must FAIL) the KPI comparison passes when one test description's count differs",
]
POST_ROWS = ["the copy is unchanged after the tests (nothing was written into the code)",
             "after shutdown nothing of the copy's lab answers",
             "after the controls nothing of the copy's lab answers"]


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _shipped_with_rerun(new: str) -> str:
    """The shipped runbook with its one rerun block (RERUN_HOST) replaced by `new`: one exact replace that must match
    once, so a fixture never holds two rerun blocks and never edits anything else."""
    text = RUNBOOK.read_text()
    assert text.count(RERUN_HOST) == 1, "the shipped runbook holds the rerun block RERUN_HOST exactly once"
    return text.replace(RERUN_HOST, new, 1)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """M8: the suite never touches the network or the live lab. guest_probes' port check is answered here, and any
    connection to a non-loopback address or to one of the lab's ports, and any name lookup but loopback, fails."""
    monkeypatch.setattr(vr, "_listening", lambda port: False)
    real_connect, real_connect_ex, real_gai = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def check(addr):
        if isinstance(addr, tuple) and (addr[0] not in ("127.0.0.1", "::1") or addr[1] in LAB_PORTS):
            raise AssertionError(f"the offline suite tried to connect to {addr}")

    def connect(self, addr):
        check(addr)
        return real_connect(self, addr)

    def connect_ex(self, addr):
        check(addr)
        return real_connect_ex(self, addr)

    def gai(host, *a, **kw):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise AssertionError(f"the offline suite tried to look up {host!r}")
        return real_gai(host, *a, **kw)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", gai)


# ---------------------------------------------------------------------------------------- user-data
RERUN_CFG = {"id": "rerun", "sha256": "4" * 64}


def _cfg(plan=PLAN, root_ids=("install-a",), rerun=RERUN_CFG):
    return vr.guest_config(attempt=1, stamp="20261120T000000Z", code_root="/home/edgefollow/estimed-lab/code",
                           install_plan=plan, root_ids=list(root_ids), rerun=rerun)


def _ud(plan=PLAN) -> str:
    cfg = _cfg(plan)
    return vr.make_user_data(cfg, SUMS, vr.make_run_sh(cfg))


def _doc(text: str) -> dict:
    assert text.startswith("#cloud-config\n")
    return json.loads(text.split("\n", 1)[1])


def _text(doc: dict) -> str:
    return "#cloud-config\n" + json.dumps(doc, indent=1) + "\n"


def test_user_data_has_one_user_with_a_locked_password_no_key_and_no_sudo():
    text = _ud()
    doc = _doc(text)
    assert doc["users"] == [{"name": "edgefollow", "lock_passwd": True, "shell": "/bin/bash"}]
    assert doc["ssh_pwauth"] is False and doc["disable_root"] is True
    assert doc["ssh_genkeytypes"] == [] and doc["ssh_deletekeys"] is True, "no SSH host key is generated either"
    assert doc["package_update"] is False and doc["package_upgrade"] is False, "cloud-init installs nothing"
    for word in ("passwd:", "hashed_passwd", "plain_text_passwd", "chpasswd", "ssh_authorized_keys", "ssh_import_id",
                 "ssh_keys", "PRIVATE KEY", "packages", "sudo", "NOPASSWD"):
        assert word not in text, word
    assert vr.audit_user_data(text, _cfg(), SUMS) == []
    assert "no sudo" in vr.HARNESS_STEPS["create-user"]


def test_user_data_runs_only_the_listed_harness_steps():
    doc = _doc(_ud())
    assert doc["runcmd"] == [["bash", "/var/lib/vmrerun/run.sh"]]
    assert [f["path"] for f in doc["write_files"]] == ["/var/lib/vmrerun/run.sh", "/var/lib/vmrerun/config.json",
                                                      "/var/lib/vmrerun/sums.txt"]
    assert doc["power_state"]["mode"] == "poweroff"
    run_sh = doc["write_files"][0]["content"]
    tags = []
    for line in run_sh.splitlines():
        m = re.search(r"  # harness:([\w-]+)$", line)
        if m:
            tags.append(m.group(1))
        else:
            assert re.fullmatch(r"#!/bin/bash|#( .*)?|set -u|[A-Z]+=\S+|(say|stop)\(\) \{.*\}|", line), line
    assert set(tags) <= set(vr.HARNESS_STEPS)
    assert {"fetch", "check", "deliver", "guest", "summary"} <= set(tags)
    for word in ("pip", "venv", "acmecse", "pytest", "run_topology", "stop_topology", "apt", "dpkg", "ssh-keygen",
                 "sudo", "useradd", "0.0.0.0"):
        assert not re.search(rf"\b{re.escape(word)}", run_sh), word
    assert "runuser -u edgefollow -- env -i HOME=/home/edgefollow" in run_sh, "the runbook's blocks run as edgefollow, not as root"
    assert "SRV=http://10.0.2.100:8080\n" in run_sh and "id edgefollow" in run_sh
    root_lines = [ln for ln in run_sh.splitlines() if ln.endswith("# harness:root-blocks")]
    assert root_lines == ['env -i HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin '
                          'LANG=C.UTF-8 python3 -I -B "$H/guest.py" root --config "$H/config.json"  # harness:root-blocks'], \
        "one root line: the root step, which runs only the root=yes blocks"
    guest_lines = [ln for ln in run_sh.splitlines() if ln.endswith("# harness:guest")]
    assert len(guest_lines) == 1 and guest_lines[0].startswith("runuser -u edgefollow -- ") and " guest --config " in guest_lines[0]
    order = [m.group(1) for m in re.finditer(r"  # harness:([\w-]+)$", run_sh, re.M)]
    assert order.index("check") < order.index("root-blocks") < order.index("deliver") < order.index("guest")


def test_run_sh_template_is_pinned_by_its_sha256():
    assert hashlib.sha256(vr.RUN_SH_TEMPLATE.encode()).hexdigest() == RUN_SH_TEMPLATE_SHA256


@pytest.mark.parametrize("extra", [
    "FIX=$(ln${IFS}-sf${IFS}/bin/true${IFS}/usr/local/bin/git)\n",                   # a command inside an assignment
    "X=$(python3${IFS}-c${IFS}import\\${IFS}ensurepip)\n",
    "cp /bin/true /usr/local/bin/git  # harness:deliver\n",                           # a tagged line, any command
    "python3 -c 'import os;os.system(\"ap\"+\"t-get install -y git\")'  # harness:check\n",
    "say() { cp /bin/true /usr/local/bin/git; printf 'VMRERUN-PROGRESS %s\\n' \"$1\" > /dev/ttyS0; }\n",
])
def test_run_sh_control_any_line_that_is_not_the_harness_own_is_refused_byte_for_byte(extra):
    doc = _doc(_ud())
    doc["write_files"][0]["content"] += extra
    problems = vr.audit_user_data(_text(doc), _cfg(), SUMS)
    assert "run.sh is not the harness's own script, byte for byte" in problems, problems
    assert "user-data is not the harness's own, byte for byte" in problems


def test_user_data_install_plan_is_exactly_the_runbooks_install_blocks():
    rb = cr.parse_runbook(RUNBOOK.read_text())
    plan = vr.install_plan(rb)
    assert plan == [{"id": s.id, "sha256": s.sha256} for s in rb.steps if s.phase == "install"]
    assert len(plan) >= 2 and all(re.fullmatch(r"[0-9a-f]{64}", p["sha256"]) for p in plan)
    cfg = json.loads(_doc(_ud(plan=plan))["write_files"][1]["content"])
    assert cfg["install_plan"] == plan
    assert "section6_line" not in cfg and cfg["rerun_block"] == RERUN_CFG and cfg["root_block_ids"] == ["install-a"]
    assert cfg["code_root"] == rb.variables["ROOT"] == "/home/edgefollow/estimed-lab/code"
    assert (cfg["server"], cfg["proxy"]) == (SEED_URL, PROXY_URL)
    assert (cfg["apt_conf"], cfg["console"], cfg["guest_dir"]) == ("/var/lib/vmrerun/apt-proxy.conf", "/dev/ttyS0",
                                                                   "/var/lib/vmrerun")


def test_user_data_names_the_seed_server_and_the_proxy_only():
    assert set(re.findall(r"https?://[^\s\"'/\\]+", _ud())) == {SEED_URL, PROXY_URL}


def _plant_user(doc, k, v):
    doc["users"][0][k] = v


@pytest.mark.parametrize("plant, said", [
    (lambda d: _plant_user(d, "passwd", "$6$planted"), "password or key field"),
    (lambda d: _plant_user(d, "plain_text_passwd", "x"), "password or key field"),
    (lambda d: _plant_user(d, "lock_passwd", False), "users"),
    (lambda d: _plant_user(d, "sudo", "ALL=(ALL) NOPASSWD:ALL"), "password or key field: users.0.sudo"),
    (lambda d: _plant_user(d, "groups", "sudo"), "users"),
    (lambda d: _plant_user(d, "ssh_authorized_keys", ["ssh-ed25519 AAAA planted"]), "password or key field"),
    (lambda d: d.update(chpasswd={"expire": False}), "password or key field"),
    (lambda d: d.update(ssh_pwauth=True), "ssh_pwauth"),
    (lambda d: d["users"].append({"name": "second"}), "users"),
    (lambda d: d.update(ssh_genkeytypes=["ed25519"]), "ssh_genkeytypes"),
    (lambda d: d.update(packages=["python3-venv"]), "top-level key not allowed: packages"),
    (lambda d: d.update(bootcmd=[["true"]]), "top-level key not allowed: bootcmd"),
    (lambda d: d.update(package_update=True), "package_update"),
    (lambda d: d.update(runcmd=[["bash", "/var/lib/vmrerun/run.sh"], ["apt-get", "install", "-y", "git"]]), "runcmd"),
    (lambda d: d["write_files"][0].update(content=d["write_files"][0]["content"]
                                          + "apt-get install -y python3-venv  # harness:deliver\n"), "apt"),
    (lambda d: d["write_files"][0].update(content=d["write_files"][0]["content"] + "touch /planted\n"),
     "names no harness step"),
    (lambda d: d["write_files"][0].update(content=d["write_files"][0]["content"] + "true  # harness:extra\n"),
     "unknown harness step"),
    (lambda d: d["write_files"][1].update(content=json.dumps(dict(json.loads(d["write_files"][1]["content"]),
                                                                  install_plan=PLAN + [{"id": "x", "sha256": "3" * 64}]))),
     "install plan"),
    (lambda d: d["write_files"][1].update(content=json.dumps(dict(json.loads(d["write_files"][1]["content"]),
                                                                  proxy="http://10.0.2.2:8200"))), "the proxy"),
    (lambda d: d["write_files"][2].update(content=SUMS.replace(SHA_ABC, "0" * 64, 1)), "sums.txt"),
    (lambda d: d["write_files"][0].update(content=d["write_files"][0]["content"].replace("http://10.0.2.100:8080",
                                                                                         "http://192.0.2.1:80")),
     "URLs other than the seed server and the proxy"),
    (lambda d: d.update(power_state={"mode": "reboot"}), "power_state"),
    (lambda d: d["write_files"][1].update(content=json.dumps(dict(json.loads(d["write_files"][1]["content"]),
                                                                  rerun_block={"id": "rerun", "sha256": "5" * 64}))),
     "the rerun block"),
    (lambda d: d["write_files"][1].update(content=json.dumps(dict(json.loads(d["write_files"][1]["content"]),
                                                                  root_block_ids=["install-a", "install-b"]))),
     "root=yes install blocks"),
    (lambda d: d["write_files"][1].update(content=json.dumps(dict(json.loads(d["write_files"][1]["content"]),
                                                                  console="/tmp/x"))), "the console"),
])
def test_user_data_control_a_planted_fault_is_refused(plant, said):
    doc = _doc(_ud())
    plant(doc)
    problems = vr.audit_user_data(_text(doc), _cfg(), SUMS)
    assert any(said in p for p in problems), problems
    assert "user-data is not the harness's own, byte for byte" in problems


def test_user_data_control_a_code_root_with_shell_characters_or_another_server_is_refused():
    with pytest.raises(vr.VmError):
        vr.make_run_sh(vr.guest_config(attempt=1, stamp="s", code_root="/home/edgefollow/x; rm -rf ~", install_plan=PLAN))
    with pytest.raises(vr.VmError):
        vr.make_run_sh(dict(_cfg(), server="http://10.0.2.2:8200"))


# ---------------------------------------------------------------------------------------- the seed and upload server
@pytest.fixture
def server(tmp_path):
    made = []

    def make(cap=64, total_cap=200, max_files=10, read_timeout=10.0):
        s = vr.SeedServer({"user-data": b"#cloud-config\n{}\n", "meta-data": b"instance-id: x\n"}, tmp_path / "results",
                          cap=cap, total_cap=total_cap, max_files=max_files, read_timeout=read_timeout)
        s.start()
        made.append(s)
        return s
    yield make
    for s in made:
        s.stop()


def _req(srv, method, path, body=None, headers=None, length=True):
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
    c.putrequest(method, path, skip_accept_encoding=True)
    for k, v in (headers or {}).items():
        c.putheader(k, v)
    if body is not None and length and "Content-Length" not in (headers or {}):
        c.putheader("Content-Length", str(len(body)))
    c.endheaders(body)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def _raw_status(port: int, data: bytes, timeout: float = 5.0) -> int:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        buf = b""
        try:
            while b"\r\n" not in buf:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
    m = re.match(rb"HTTP/1\.[01] (\d{3})", buf)
    return int(m.group(1)) if m else 0


def _listing(srv):
    return sorted(p.name for p in srv.results_dir.iterdir())


def test_server_binds_the_loopback_address_only(server, tmp_path):
    s = server()
    assert s.server_address[0] == "127.0.0.1" and s.port > 0
    for host in ("0.0.0.0", "10.0.2.2", "::"):
        with pytest.raises(vr.VmError):
            vr.SeedServer({}, tmp_path / "other", host=host)


def test_server_serves_exactly_the_named_files(server):
    s = server()
    assert _req(s, "GET", "/user-data") == (200, b"#cloud-config\n{}\n")
    assert _req(s, "GET", "/meta-data") == (200, b"instance-id: x\n")
    for path in ("/vendor-data", "/../etc/passwd", "/user-data?x=1", "//user-data", "/up/", "/", "/results"):
        assert _req(s, "GET", path)[0] == 404, path


def test_server_takes_one_upload_into_the_results_folder_and_logs_the_guest_clock(server):
    s = server()
    assert _req(s, "PUT", "/up/guest.json", b"abc", headers={"X-Guest-Time": "1795168830.500"})[0] == 201
    assert _listing(s) == ["guest.json"]
    assert (s.results_dir / "guest.json").read_bytes() == b"abc"
    put = [e for e in s.log if e["method"] == "PUT"]
    assert len(put) == 1 and put[0]["status"] == 201 and put[0]["guest_time"] == 1795168830.5 and put[0]["bytes"] == 3


def test_server_does_not_serve_an_upload_back(server):
    s = server()
    _req(s, "PUT", "/up/guest.json", b"abc")
    assert _req(s, "GET", "/up/guest.json")[0] == 404 and _req(s, "GET", "/guest.json")[0] == 404


@pytest.mark.parametrize("path", ["/up/../x", "/up/a/b", "/up/%2e%2e%2fx", "/up/.hidden", "/up/", "/x.json",
                                  "/up/a?b=1", "/up/" + "a" * 101, "//up/x", "/UP/x", "/up/a..b", "/up/a%20b",
                                  "/up/-x"])
def test_server_control_an_upload_with_a_path_component_or_a_bad_name_is_refused(server, tmp_path, path):
    s = server()
    st, _ = _req(s, "PUT", path, b"abc")
    assert st >= 400, (path, st)
    assert _listing(s) == [] and sorted(p.name for p in tmp_path.iterdir()) == ["results"]


def test_server_control_an_oversize_upload_is_refused_and_nothing_is_written(server):
    s = server(cap=64)
    assert _req(s, "PUT", "/up/big.bin", b"x" * 65)[0] == 413
    assert _req(s, "PUT", "/up/ok.bin", b"x" * 64)[0] == 201
    assert _listing(s) == ["ok.bin"]


def test_server_control_an_upload_without_a_length_is_refused(server):
    s = server()
    st, _ = _req(s, "PUT", "/up/chunked.bin", b"3\r\nabc\r\n0\r\n\r\n", headers={"Transfer-Encoding": "chunked"},
                 length=False)
    assert st == 411 and _listing(s) == []


def test_server_control_a_second_upload_of_the_same_name_is_refused(server):
    s = server()
    assert _req(s, "PUT", "/up/a.txt", b"first")[0] == 201
    assert _req(s, "PUT", "/up/a.txt", b"second")[0] == 409
    assert (s.results_dir / "a.txt").read_bytes() == b"first"


def test_server_control_a_refused_overwrite_gives_its_quota_back(server):
    s = server(max_files=2)
    assert _req(s, "PUT", "/up/a.txt", b"1")[0] == 201
    assert _req(s, "PUT", "/up/a.txt", b"22")[0] == 409
    assert (s.count, s.received) == (1, 1), "the refused 409 still holds a file and two bytes of the quota"
    assert _req(s, "PUT", "/up/b.txt", b"3")[0] == 201


def test_server_control_a_stalled_upload_times_out_and_gives_its_quota_back(server):
    s = server(max_files=1, read_timeout=0.4)
    with socket.create_connection(("127.0.0.1", s.port), timeout=5) as c:
        c.sendall(b"PUT /up/slow.bin HTTP/1.1\r\nContent-Length: 50\r\n\r\nabc")
        t0, buf = time.time(), b""
        while b"\r\n" not in buf:
            chunk = c.recv(1024)
            if not chunk:
                break
            buf += chunk
    assert buf.startswith(b"HTTP/1.0 408") and time.time() - t0 < 3, buf
    assert (s.count, s.received) == (0, 0) and _listing(s) == []
    assert _req(s, "PUT", "/up/next.bin", b"x")[0] == 201


@pytest.mark.parametrize("headers", [
    b"Content-Length: 3\r\nContent-Length: 500\r\n",           # two lengths
    b"Content-Length: " + b"9" * 5000 + b"\r\n",               # over-long (once crashed the handler)
    b"Content-Length: 3" + b"0" * 12 + b"\r\n",
    b"Content-Length: \xc2\xb2\r\n",                           # a digit that is not ASCII
    b"Content-Length: +3\r\n",
    b"Content-Length: 0x3\r\n",
    b"Content-Length: -1\r\n",
])
def test_server_control_a_doubled_overlong_or_odd_content_length_is_refused(server, headers):
    s = server()
    assert _raw_status(s.port, b"PUT /up/cl.bin HTTP/1.1\r\n" + headers + b"\r\nabc") == 400
    assert _listing(s) == [] and (s.count, s.received) == (0, 0)
    assert _req(s, "PUT", "/up/after.bin", b"ok")[0] == 201, "the server still answers"


@pytest.mark.parametrize("method", ["DELETE", "POST", "PATCH", "OPTIONS", "HEAD"])
def test_server_control_other_methods_are_refused(server, method):
    s = server()
    _req(s, "PUT", "/up/a.txt", b"keep")
    st, _ = _req(s, method, "/up/a.txt" if method != "HEAD" else "/user-data", b"x" if method in ("POST", "PATCH") else None)
    assert st == 405, (method, st)
    assert (s.results_dir / "a.txt").read_bytes() == b"keep"


def test_server_control_uploads_beyond_the_count_or_the_total_are_refused(server):
    s = server(cap=64, total_cap=150, max_files=10)
    assert [_req(s, "PUT", f"/up/f{i}", b"x" * 60)[0] for i in range(3)] == [201, 201, 413]
    t = server(cap=64, total_cap=10_000, max_files=2)
    assert [_req(t, "PUT", f"/up/g{i}", b"y")[0] for i in range(3)] == [201, 201, 413]


def test_live_server_controls_fail_on_the_real_server_and_catch_one_that_answers_delete(server, monkeypatch):
    s = server()
    assert _req(s, "PUT", "/up/guest.json", b"g")[0] == 201
    assert [c["passed"] for c in vr.live_server_controls(s)] == [False, False, False]

    def delete(self):                                       # a planted server that deletes on request
        (self.server.results_dir / "guest.json").unlink()
        return self._done(200)
    monkeypatch.setattr(vr._Handler, "do_DELETE", delete)
    rows = vr.live_server_controls(s)
    assert rows[2]["row"] == "CONTROL (must FAIL) the seed server answered a DELETE" and rows[2]["passed"] is True


# ---------------------------------------------------------------------------------------- the allow-listing proxy
class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.server.burst:
            self.request.sendall(b"z" * self.server.burst)
        while True:
            data = self.request.recv(65536)
            if not data:
                break
            self.request.sendall(data)


class _Echo(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, burst=0):
        self.burst = burst
        super().__init__(("127.0.0.1", 0), _EchoHandler)
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]

    def stop(self):
        self.shutdown()
        self.server_close()


class _Everything:
    def __contains__(self, x):
        return True


@pytest.fixture
def proxy():
    made = []

    def make(burst=0, **kw):
        echo = _Echo(burst)
        calls = []

        def connect(host, port, timeout):
            calls.append((host, port))
            return socket.create_connection(("127.0.0.1", echo.port), timeout=timeout), "192.0.2.10"
        p = vr.AllowProxy(connect=connect, **kw)
        p.start()
        p.calls = calls
        made.append((p, echo))
        return p
    yield make
    for p, echo in made:
        p.stop()
        echo.stop()


def _tunnel(port: int, target: str, first: bytes = b"", raw: bytes | None = None):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(raw if raw is not None else f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode() + first)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return s, head.split(b"\r\n", 1)[0].decode("latin-1"), rest


def _wait_log(p, n, timeout=3.0):
    t = time.time()
    while len(p.log) < n and time.time() - t < timeout:
        time.sleep(0.02)
    return p.log


def test_proxy_allow_list_is_exactly_pypi_and_the_debian_archive():
    # pass 3: the image's apt sources are https://deb.debian.org/debian and .../debian-security (read from the image's
    # /etc/apt/mirrors on 2026-11-20), so deb.debian.org:80 and security.debian.org are not used and are gone
    assert vr.PROXY_ALLOW == frozenset({("pypi.org", 443), ("files.pythonhosted.org", 443), ("deb.debian.org", 443)})
    assert (vr.PROXY_ADDR, vr.PROXY_GUEST_PORT, vr.SEED_ADDR, vr.SEED_GUEST_PORT) == ("10.0.2.101", 3128,
                                                                                      "10.0.2.100", 8080)
    assert vr.PROXY_CONN_CAP > 0 and vr.PROXY_TOTAL_CAP >= vr.PROXY_CONN_CAP and vr.PROXY_IDLE_S <= 120


def test_proxy_binds_the_loopback_address_only():
    for bind in ("0.0.0.0", "10.0.2.2", "::"):
        with pytest.raises(vr.VmError):
            vr.AllowProxy(bind=bind)


def test_proxy_opens_an_allowed_tunnel_and_logs_its_bytes(proxy):
    p = proxy()
    s, line, rest = _tunnel(p.port, "pypi.org:443", b"ping")
    got = rest
    while len(got) < 4:
        got += s.recv(16)
    s.close()
    assert (line, got) == ("HTTP/1.1 200 Connection established", b"ping")
    e = _wait_log(p, 1)[0]
    assert p.calls == [("pypi.org", 443)]
    assert (e["status"], e["target"], e["bytes_up"], e["bytes_down"], e["end"]) == (200, "pypi.org:443", 4, 4, "eof")


@pytest.mark.parametrize("target, want", [
    ("example.com:443", 403), ("pypi.org:80", 403), ("files.pythonhosted.org:80", 403), ("deb.debian.org:22", 403),
    ("127.0.0.1:8200", 403), ("10.42.0.1:443", 403), ("localhost:5037", 403), ("pypi.org.evil.example:443", 403),
    ("evil.example:443", 403), ("[::1]:443", 400), ("pypi.org", 400), ("pypi.org:443/x", 400),
    ("evilpypi.org:443", 403), ("notdeb.debian.org:443", 403), ("x.files.pythonhosted.org:443", 403),   # C1: no suffix
    ("deb.debian.org:80", 403), ("security.debian.org:443", 403), ("security.debian.org:80", 403),       # dropped
])
def test_proxy_control_a_tunnel_off_the_allow_list_is_refused_and_logged(proxy, target, want):
    p = proxy()
    s, line, _ = _tunnel(p.port, target)
    s.close()
    assert line.startswith(f"HTTP/1.1 {want} "), line
    assert p.calls == [], "nothing was connected to"
    e = _wait_log(p, 1)[0]
    assert e["status"] == want and e["ip"] is None and e["why"]


@pytest.mark.parametrize("raw, want", [
    (b"GET http://pypi.org/simple/ HTTP/1.1\r\nHost: pypi.org\r\n\r\n", 405),
    (b"POST http://pypi.org/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 405),
    (b"GET / HTTP/1.1\r\n\r\n", 405),
    (b"connect pypi.org:443 HTTP/1.1\r\n\r\n", 405),
    (b"hello\r\n\r\n", 400),
    (b"CONNECT pypi.org:443 SPDY/3\r\n\r\n", 400),
])
def test_proxy_control_a_request_that_is_not_connect_is_refused_and_logged(proxy, raw, want):
    p = proxy()
    s, line, _ = _tunnel(p.port, "", raw=raw)
    s.close()
    assert line.startswith(f"HTTP/1.1 {want} "), line
    assert p.calls == [] and _wait_log(p, 1)[0]["status"] == want


def test_proxy_control_a_tunnel_over_its_byte_cap_is_cut(proxy):
    p = proxy(burst=1000, conn_cap=100)
    s, line, rest = _tunnel(p.port, "pypi.org:443")
    got = rest
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        got += chunk
    s.close()
    assert line.startswith("HTTP/1.1 200") and len(got) <= 100
    assert _wait_log(p, 1)[0]["end"].startswith("per-tunnel cap")


def test_proxy_control_the_run_caps_refuse_new_tunnels(proxy):
    p = proxy(max_conns=1)
    s1, l1, _ = _tunnel(p.port, "pypi.org:443")
    s2, l2, _ = _tunnel(p.port, "files.pythonhosted.org:443")
    s1.close()
    s2.close()
    assert l1.startswith("HTTP/1.1 200") and l2.startswith("HTTP/1.1 429")
    q = proxy(total_cap=10)
    s, line, _ = _tunnel(q.port, "pypi.org:443", b"x" * 50)
    s.settimeout(5)
    while s.recv(4096):
        pass
    s.close()
    s, line2, _ = _tunnel(q.port, "pypi.org:443")
    s.close()
    assert line.startswith("HTTP/1.1 200") and line2.startswith("HTTP/1.1 429")
    assert _wait_log(q, 2)[0]["end"].startswith("run total cap")


def test_proxy_control_a_silent_or_endless_request_head_is_dropped(proxy):
    p = proxy(head_timeout_s=0.3)
    with socket.create_connection(("127.0.0.1", p.port), timeout=5) as s:
        t0, buf = time.time(), b""
        while b"\r\n" not in buf:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
    assert buf.startswith(b"HTTP/1.1 408") and time.time() - t0 < 2
    s, line, _ = _tunnel(p.port, "", raw=b"CONNECT pypi.org:443 HTTP/1.1\r\nX: " + b"a" * 9000)
    s.close()
    assert line.startswith("HTTP/1.1 400") and p.calls == []


def test_connect_public_connects_to_the_address_it_checked_never_to_the_name_again(monkeypatch):
    # C2: a second lookup at connect time could answer 127.0.0.1 (rebinding); the socket gets the checked address
    lookups, tried = [], []

    def gai(host, port, *a, **k):
        lookups.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("151.101.0.223", port))]
    monkeypatch.setattr(socket, "getaddrinfo", gai)
    monkeypatch.setattr(socket.socket, "connect", lambda self, a: tried.append(a))
    s, ip = vr.connect_public("pypi.org", 443)
    s.close()
    assert (ip, tried, lookups) == ("151.101.0.223", [("151.101.0.223", 443)], ["pypi.org"])


def test_proxy_control_a_request_head_sent_one_byte_at_a_time_hits_the_total_deadline(proxy):
    # C6: the head deadline is for the whole head, not per recv; a trickle must not hold a thread past it
    p = proxy(head_timeout_s=0.6)
    with socket.create_connection(("127.0.0.1", p.port), timeout=5) as s:
        s.settimeout(0.2)
        t0, buf = time.time(), b""
        while time.time() - t0 < 4.0 and b"\r\n" not in buf:
            try:
                s.sendall(b"C")
            except OSError:
                break
            try:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
            except TimeoutError:
                pass
        took = time.time() - t0
    assert buf.startswith(b"HTTP/1.1 408") and took < 2.5, (buf, took)
    assert p.calls == []


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.42.0.5", "192.168.1.1", "169.254.1.1", "192.0.2.1", "::1",
                                  "fe80::1", "100.64.0.1"])
def test_connect_public_control_a_name_that_resolves_to_a_non_public_address_is_refused(monkeypatch, addr):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    sa = (addr, 443, 0, 0) if ":" in addr else (addr, 443)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                                                  ("151.101.0.223", 443)), (fam, socket.SOCK_STREAM, 6, "", sa)])
    tried = []
    monkeypatch.setattr(socket.socket, "connect", lambda self, a: tried.append(a))
    with pytest.raises(vr.VmError, match="not a public address"):
        vr.connect_public("pypi.org", 443)
    assert tried == [], "refused before any connection"


def test_live_proxy_controls_fail_on_the_real_proxy_and_catch_an_open_one(proxy):
    real = proxy()
    rows = vr.live_proxy_controls(real)
    assert len(rows) == 4 and [r["passed"] for r in rows] == [False, False, False, False], rows
    assert real.calls == []
    open_ = proxy(allow=_Everything())
    assert [r["passed"] for r in vr.live_proxy_controls(open_)] == [True, True, True, False]


# ---------------------------------------------------------------------------------------- the guestfwd relay
def _relay(tmp_path, port):
    path = tmp_path / "relay.py"
    info = vr.write_relay(path)
    a, b = socket.socketpair()
    p = subprocess.Popen([sys.executable, "-I", "-B", "-S", str(path), str(port)], stdin=b, stdout=b, stderr=b)
    b.close()
    return a, p, info


def test_relay_copies_bytes_both_ways_between_its_fd0_and_one_loopback_port(tmp_path):
    echo = _Echo()
    try:
        a, p, info = _relay(tmp_path, echo.port)
        a.sendall(b"hello relay")
        a.shutdown(socket.SHUT_WR)
        a.settimeout(5)
        got = b""
        while True:
            chunk = a.recv(4096)
            if not chunk:
                break
            got += chunk
        assert got == b"hello relay" and p.wait(5) == 0
        assert (tmp_path / "relay.py").stat().st_mode & 0o777 == 0o500 and info["sha256"] == _sha(vr.RELAY_SRC.encode())
    finally:
        echo.stop()


def test_relay_connects_to_the_address_127_0_0_1_not_to_a_name(tmp_path):
    # C3: "localhost" is a name (resolver, /etc/hosts, ::1 first); the relay must open 127.0.0.1 itself. The relay is
    # run as written, with socket.create_connection wrapped to note the address it is given
    echo = _Echo()
    try:
        info = vr.write_relay(tmp_path / "relay.py")
        seen = tmp_path / "seen.txt"
        wrap = (f"import socket, sys; real = socket.create_connection\n"
                f"def cc(addr, *a, **k):\n    open({str(seen)!r}, 'a').write(repr(addr) + '\\n'); return real(addr, *a, **k)\n"
                f"socket.create_connection = cc\nsys.argv = ['relay.py', '{echo.port}']\n"
                f"exec(compile(open({info['path']!r}).read(), 'relay.py', 'exec'))\n")
        a, b = socket.socketpair()
        p = subprocess.Popen([sys.executable, "-I", "-B", "-S", "-c", wrap], stdin=b, stdout=b, stderr=subprocess.DEVNULL)
        b.close()
        a.sendall(b"x")
        a.shutdown(socket.SHUT_WR)
        a.settimeout(5)
        assert a.recv(10) == b"x" and p.wait(5) == 0
        assert seen.read_text() == f"('127.0.0.1', {echo.port})\n"
    finally:
        echo.stop()


def test_relay_control_a_port_below_1024_is_refused_and_nothing_is_written_to_the_guest(tmp_path):
    a, p, _ = _relay(tmp_path, 22)
    assert p.wait(5) == 2
    a.settimeout(2)
    assert a.recv(100) == b"", "a refusal writes no traceback into the guest's connection"


def test_relay_command_is_one_plain_interpreter_and_path():
    assert vr.relay_command("/usr/bin/python3", "/srv/estimed-vm/x/relay.py") == \
        "/usr/bin/python3 -I -B -S /srv/estimed-vm/x/relay.py"
    for bad in ("/srv/a b/relay.py", "/srv/a,b/relay.py", "/srv/a:b/relay.py", "/srv/$(x)/relay.py"):
        with pytest.raises(vr.VmError):
            vr.relay_command("/usr/bin/python3", bad)


# ---------------------------------------------------------------------------------------- the base image and its folder
def _image(tmp_path, data=b"abc", sums=None):
    img = tmp_path / IMAGE
    img.write_bytes(data)
    s = tmp_path / "SHA512SUMS"
    s.write_text(sums if sums is not None else f"{'0' * 128}  debian-13-genericcloud-amd64.raw\n{SHA512_ABC}  {IMAGE}\n")
    return img, s


def test_base_image_check_accepts_the_digest_debian_lists(tmp_path):
    img, sums = _image(tmp_path)
    r = vr.check_base_image(img, sums)
    assert (r["sha512"], r["listed"], r["ok"]) == (SHA512_ABC, SHA512_ABC, True)


@pytest.mark.parametrize("data, sums", [
    (b"abd", None),                                                         # the image changed
    (b"abc", f"{'0' * 128}  debian-13-genericcloud-amd64.raw\n"),           # no line for it
    (b"abc", f"{SHA512_ABC}  {IMAGE}\n{SHA512_ABC}  {IMAGE}\n"),            # two lines for it
    (b"abc", f"{SHA512_ABC}  x{IMAGE}\n"),                                  # only a longer name
    (b"abc", f"{SHA512_ABC[:-1]}  {IMAGE}\n"),                              # not a SHA-512
])
def test_base_image_check_control_a_changed_or_unlisted_image_is_refused(tmp_path, data, sums):
    img, s = _image(tmp_path, data, sums)
    with pytest.raises(vr.VmError):
        vr.check_base_image(img, s)


def test_base_image_is_hashed_while_it_is_copied_into_the_private_folder(tmp_path):
    img, _ = _image(tmp_path)
    (tmp_path / "priv").mkdir()
    dst = tmp_path / "priv" / "base.qcow2"
    r = vr.copy_base_image(img, dst, SHA512_ABC)
    assert (r["sha512"], r["copy_read_back_sha512"], r["bytes"]) == (SHA512_ABC, SHA512_ABC, 3)
    assert dst.read_bytes() == b"abc" and dst.stat().st_mode & 0o777 == 0o400


def test_base_image_copy_control_a_wrong_digest_is_refused_and_leaves_no_copy(tmp_path):
    img, _ = _image(tmp_path, data=b"abd")
    (tmp_path / "priv").mkdir()
    with pytest.raises(vr.VmError, match="refused"):
        vr.copy_base_image(img, tmp_path / "priv" / "base.qcow2", SHA512_ABC)
    assert not (tmp_path / "priv" / "base.qcow2").exists()


def test_base_image_copy_control_an_existing_file_is_never_overwritten(tmp_path):
    img, _ = _image(tmp_path)
    (tmp_path / "base.qcow2").write_bytes(b"old")
    with pytest.raises(FileExistsError):
        vr.copy_base_image(img, tmp_path / "base.qcow2", SHA512_ABC)
    assert (tmp_path / "base.qcow2").read_bytes() == b"old"


def test_the_private_folder_is_on_the_root_filesystem_and_never_the_ntfs_disk():
    assert vr.PRIVATE_PARENT == Path("/srv/estimed-vm") and vr.LOCAL_FSTYPES == frozenset({"ext4", "xfs", "btrfs"})
    assert vr.MIN_FREE_PRIVATE_BYTES == 4 << 30
    assert vr.fs_type("/proc") == "proc" and vr.fs_type("/dev/shm") == "tmpfs"


def test_private_folder_of_this_user_0700_on_a_local_filesystem_with_room_is_accepted(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    os.chmod(d, 0o700)
    r = vr.check_private_dir(d, need_bytes=1)
    assert r["ok"] is True and r["why"] == "" and r["fstype"] in {"ext4", "xfs", "btrfs"}


@pytest.mark.parametrize("plant, said", [
    (lambda d, mp: os.chmod(d, 0o755), "mode 755, not 700"),
    (lambda d, mp: os.rmdir(d), "does not exist; make it once, as root: install -d -o edgefollow -g edgefollow -m 0700"),
    (lambda d, mp: (os.rmdir(d), d.parent.joinpath("real").mkdir(mode=0o700), d.symlink_to(d.parent / "real")),
     "not a directory (or is a symbolic link)"),
    (lambda d, mp: mp.setattr(vr, "fs_type", lambda p: "fuseblk"), "on 'fuseblk', not a local POSIX filesystem"),
    (lambda d, mp: mp.setattr(vr, "fs_type", lambda p: "tmpfs"), "on 'tmpfs', not a local POSIX filesystem"),
    (lambda d, mp: mp.setattr(vr, "MIN_FREE_PRIVATE_BYTES", 1 << 60), "MB are needed"),
])
def test_private_folder_control_a_folder_that_is_not_ours_0700_local_with_room_is_refused(tmp_path, monkeypatch,
                                                                                          plant, said):
    d = tmp_path / "p"
    d.mkdir()
    os.chmod(d, 0o700)
    plant(d, monkeypatch)
    r = vr.check_private_dir(d) if "MB are" in said else vr.check_private_dir(d, need_bytes=1)
    assert r["ok"] is False and said in r["why"], r


def test_private_folder_control_a_root_owned_folder_is_refused(tmp_path, monkeypatch):
    # C5: owned by root (uid 0) is not "this user's", even if mode and filesystem are right
    d = tmp_path / "p"
    d.mkdir()
    os.chmod(d, 0o700)
    real = os.lstat

    def lstat(path, *a, **k):
        st = real(path, *a, **k)
        if os.fspath(path) != os.fspath(d):
            return st
        f = list(st)
        f[4] = 0                                    # st_uid
        return os.stat_result(f)
    monkeypatch.setattr(vr.os, "lstat", lstat)
    r = vr.check_private_dir(d, need_bytes=1)
    assert r["ok"] is False and r["why"] == f"{d} belongs to uid 0, not to this user", r


def test_private_folder_control_a_relative_path_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "p").mkdir(mode=0o700)
    r = vr.check_private_dir("p", need_bytes=1)
    assert r["ok"] is False and "not an absolute path" in r["why"], r


def test_evidence_is_copied_without_the_disk_images(tmp_path):
    src, dst = tmp_path / "priv", tmp_path / "ntfs"
    (src / "results").mkdir(parents=True)
    for rel, data in {"base.qcow2": b"b", "overlay.qcow2": b"o", "record.json": b"{}", "results/guest.json": b"g"}.items():
        (src / rel).write_bytes(data)
    got = vr.copy_evidence(src, dst)
    assert [(e["path"], e["sha256"]) for e in got] == [("record.json", _sha(b"{}")), ("results/guest.json", _sha(b"g"))]
    assert sorted(p.relative_to(dst).as_posix() for p in dst.rglob("*") if p.is_file()) == ["record.json",
                                                                                           "results/guest.json"]


# ---------------------------------------------------------------------------------------- the QEMU command lines
QEMU_ARGV = ["/usr/bin/qemu-system-x86_64", "-name", "vm-x", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", "2",
             "-m", "4096", "-nographic", "-monitor", "none", "-serial", "file:/r/run1/serial.log", "-no-reboot",
             "-drive", "file=/r/run1/overlay.qcow2,if=virtio,format=qcow2", "-netdev", ND,
             "-device", "virtio-net-pci,netdev=n0", "-smbios", "type=1,serial=ds=nocloud;s=http://10.0.2.100:8080/",
             "-device", "virtio-rng-pci"]


def _argv():
    return vr.qemu_argv("/usr/bin/qemu-system-x86_64", Path("/r/run1/overlay.qcow2"), Path("/r/run1/serial.log"),
                        RELAY, 40123, 40124, "vm-x")


def test_netdev_is_user_mode_restrict_on_with_exactly_the_two_guestfwd_rules():
    assert vr.netdev_value(RELAY, 40123, 40124) == ND


def _audit(a, run_dir="/r/run1", name="vm-x", parent="/r"):
    return vr.audit_qemu_argv(a, RELAY, 40123, 40124, Path(run_dir), name, Path(parent))


def test_qemu_runs_the_overlay_only_with_kvm_restrict_on_and_no_port_forward():
    a = _argv()
    assert a == QEMU_ARGV
    assert _audit(a) == []
    assert IMAGE not in " ".join(a), "the base image is never handed to QEMU"


def _swap(a, old, new):
    return [new if x == old else x for x in a]


@pytest.mark.parametrize("mangle, said", [
    (lambda a: a + ["-virtfs", "local,path=/home/edgefollow,mount_tag=h,security_model=none"], "not allowed: -virtfs"),
    (lambda a: _swap(a, ND, ND.replace("restrict=on", "restrict=off")), "netdev line"),
    (lambda a: _swap(a, ND, ND + ",hostfwd=tcp:127.0.0.1:2222-:22"), "netdev line"),
    (lambda a: _swap(a, ND, ND + ",guestfwd=tcp:10.0.2.102:5037-cmd:/usr/bin/python3 -I -B -S /p/relay.py 5037"),
     "netdev line"),
    (lambda a: _swap(a, ND, ND.replace("relay.py 40123", "relay.py 8200")), "netdev line"),
    (lambda a: _swap(a, ND, ND.replace("10.0.2.100:8080", "10.0.2.100:8081")), "netdev line"),
    (lambda a: a + ["-nic", "user,model=virtio-net-pci"], "not allowed: -nic"),
    (lambda a: a + ["-netdev", "user,id=n1"], "-netdev given 2 times"),
    (lambda a: a + ["-device", "virtio-9p-pci,fsdev=f,mount_tag=h"], "devices"),
    (lambda a: a + ["-drive", "file=/d/base.qcow2,if=virtio,format=qcow2"], "-drive given 2 times"),
    (lambda a: _swap(a, "none", "stdio"), "monitor"),
    (lambda a: a + ["-chardev", "socket,id=c,host=127.0.0.1,port=5037"], "not allowed: -chardev"),
    (lambda a: _swap(a, "type=1,serial=ds=nocloud;s=http://10.0.2.100:8080/", "type=1,serial=ds=nocloud;s=http://10.0.2.2:8200/"),
     "-smbios"),
    # pass 3, A: the netdev line must say ipv6=off, and nothing may turn IPv6 back on
    (lambda a: _swap(a, ND, ND.replace("restrict=on,ipv6=off,", "restrict=on,")), "ipv6=off"),
    (lambda a: _swap(a, ND, ND.replace("ipv6=off", "ipv6=on")), "names 'ipv6=on'"),
    (lambda a: _swap(a, ND, ND + ",ipv6=on"), "ipv6=off and exactly the two guestfwd"),
    # C4: options are matched whole, never by prefix (-mem-path / -mtdblock are not -m)
    (lambda a: a + ["-mem-path", "/home/edgefollow/planted"], "QEMU option not allowed: -mem-path"),
    (lambda a: a + ["-mtdblock", "/home/edgefollow/planted-host-file"], "QEMU option not allowed: -mtdblock"),
    (lambda a: a + ["-monitorx", "stdio"], "QEMU option not allowed: -monitorx"),
    # second check's GAPs: the VALUES of -serial, -machine, -name and the drive are pinned
    (lambda a: _swap(a, "file:/r/run1/serial.log", "tcp:127.0.0.1:5037"), "QEMU -serial is 'tcp:127.0.0.1:5037'"),
    (lambda a: _swap(a, "file:/r/run1/serial.log", "unix:/run/user/1000/bus"), "QEMU -serial is 'unix:"),
    (lambda a: _swap(a, "file:/r/run1/serial.log", "file:/home/edgefollow/.bashrc"), "QEMU -serial is 'file:/home/edgefollow/.bashrc'"),
    (lambda a: _swap(a, "file:/r/run1/serial.log", "file:/r/run2/serial.log"), "QEMU -serial"),
    (lambda a: _swap(a, "q35,accel=kvm", "q35,accel=kvm,usb=on"), "QEMU -machine is 'q35,accel=kvm,usb=on'"),
    (lambda a: _swap(a, "q35,accel=kvm", "q35,accel=kvm,dumpdtb=/home/edgefollow/x"), "QEMU -machine"),
    (lambda a: _swap(a, "vm-x", "vm-x,process=sshd"), "QEMU -name is 'vm-x,process=sshd'"),
    (lambda a: _swap(a, "vm-x", "vm-y"), "QEMU -name"),
    (lambda a: _swap(a, "host", "max"), "QEMU -cpu"),
    (lambda a: _swap(a, "4096", "16384"), "QEMU -m"),
    (lambda a: _swap(a, "file=/r/run1/overlay.qcow2,if=virtio,format=qcow2",
                     "file=/run/media/edgefollow/data/estimed-vm-2026-11-20/debian-13-genericcloud-amd64.qcow2,if=virtio,"
                     "format=qcow2"), "the drive is not the overlay in the private run folder"),       # C12
    (lambda a: _swap(a, "file=/r/run1/overlay.qcow2,if=virtio,format=qcow2",
                     "file=/r/other/overlay.qcow2,if=virtio,format=qcow2"), "the drive is not the overlay in the private"),
    (lambda a: _swap(a, "file=/r/run1/overlay.qcow2,if=virtio,format=qcow2",
                     "file=/r/run1/overlay.qcow2,if=virtio,format=qcow2,readonly=off"), "the drive is not the overlay"),
])
def test_qemu_audit_control_any_other_option_or_netdev_line_is_refused(mangle, said):
    problems = _audit(mangle(_argv()))
    assert any(said in p for p in problems), problems
    assert "the QEMU command line is not the harness's, byte for byte" in problems


def test_qemu_audit_control_a_run_folder_outside_the_private_folder_is_refused():
    assert any("does not lie directly in the private folder" in p for p in _audit(_argv(), parent="/srv/estimed-vm"))
    assert any("does not lie directly in the private folder" in p for p in _audit(_argv(), parent="/"))


def test_the_overlay_is_made_on_top_of_the_base_copy_never_into_it():
    a = vr.qemu_img_argv("qemu-img", Path("/srv/estimed-vm/x/base.qcow2"), Path("/srv/estimed-vm/x/overlay.qcow2"))
    assert a == ["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", "/srv/estimed-vm/x/base.qcow2",
                 "/srv/estimed-vm/x/overlay.qcow2", "8G"]


def test_qemu_control_a_path_with_a_comma_or_a_space_is_refused():
    for bad in ("/r/a,b/overlay.qcow2", "/r/a b/overlay.qcow2", "/r/a:b/overlay.qcow2"):
        with pytest.raises(vr.VmError):
            vr.qemu_argv("qemu", Path(bad), Path("/r/serial.log"), RELAY, 1, 2, "vm")


def test_run_folder_is_new_every_time(tmp_path):
    d = vr.new_run_dir(tmp_path, "20261120T000000Z")
    assert d == tmp_path / "20261120T000000Z" and d.is_dir()
    with pytest.raises(vr.VmError):
        vr.new_run_dir(tmp_path, "20261120T000000Z")
    p = vr.new_private_run_dir(tmp_path, "20261120T000001Z")
    assert p.stat().st_mode & 0o777 == 0o700
    with pytest.raises(FileExistsError):
        vr.new_private_run_dir(tmp_path, "20261120T000001Z")


# ---------------------------------------------------------------------------------------- console and uploads
def test_console_holds_one_summary_among_the_boot_noise():
    text = ("[    0.000000] Linux version 6.12\r\nVMRERUN-PROGRESS harness-start\r\ncloud-init[512]: running\n"
            "VMRERUN-ROOT {\"blocks\": [{\"id\": \"install-system-packages\", \"sha256\": \"S\", \"rc\": 0}]}\r\n"
            "VMRERUN-PROGRESS guest-done 0\n[ 300.1] cloud-init[1]: VMRERUN-SUMMARY {\"attempt\": 1, \"a\": [1]}\r\n"
            "VMRERUN-ROOT not json\n[  301.2] reboot: Power down\n")
    c = vr.parse_console(text)
    assert c == {"summary": {"attempt": 1, "a": [1]}, "problems": [], "progress": ["harness-start", "guest-done 0"],
                 "root": [{"blocks": [{"id": "install-system-packages", "sha256": "S", "rc": 0}]},
                          {"unreadable": "VMRERUN-ROOT not json"}]}


@pytest.mark.parametrize("text, said", [
    ("boot\nVMRERUN-PROGRESS harness-start\n", "no summary line"),
    ("VMRERUN-SUMMARY {\"a\": 1}\nVMRERUN-SUMMARY {\"a\": 2}\n", "2 summary lines"),
    ("VMRERUN-SUMMARY {\"a\": 1\n", "not JSON"),
    ("VMRERUN-SUMMARY [1, 2]\n", "not an object"),
])
def test_console_control_no_two_or_a_broken_summary_is_not_a_summary(text, said):
    c = vr.parse_console(text)
    assert c["summary"] is None and any(said in p for p in c["problems"]), c


def _results(tmp_path, files=None):
    files = files if files is not None else {"cr_record.json": b'{"x": 1}', "install_a.txt": b"log"}
    d = tmp_path / "results"
    d.mkdir()
    ups = []
    for name, data in files.items():
        (d / name).write_bytes(data)
        ups.append({"name": name, "sha256": _sha(data), "bytes": len(data), "status": 201})
    g = json.dumps({"uploads": ups}).encode()
    (d / "guest.json").write_bytes(g)
    return d, {"guest_json_sha256": _sha(g)}


def test_uploads_are_verified_against_the_summary_and_the_guests_list(tmp_path):
    d, summary = _results(tmp_path)
    guest, rec, problems = vr.verify_uploads(summary, d)
    assert problems == [] and rec == {"x": 1} and [u["name"] for u in guest["uploads"]] == ["cr_record.json", "install_a.txt"]


@pytest.mark.parametrize("plant, said", [
    (lambda d, s: (d / "install_a.txt").write_bytes(b"lag"), "changed: install_a.txt"),
    (lambda d, s: (d / "install_a.txt").unlink(), "missing: install_a.txt"),
    (lambda d, s: (d / "planted.txt").write_bytes(b"x"), "extra: planted.txt"),
    (lambda d, s: s.update(guest_json_sha256="0" * 64), "guest.json is not the one"),
    (lambda d, s: (d / "guest.json").unlink(), "guest.json did not arrive"),
])
def test_uploads_control_a_changed_missing_or_extra_file_is_reported(tmp_path, plant, said):
    d, summary = _results(tmp_path)
    plant(d, summary)
    _, _, problems = vr.verify_uploads(summary, d)
    assert any(said in p for p in problems), problems


def test_uploads_control_a_changed_clean_rerun_record_is_not_used(tmp_path):
    d, summary = _results(tmp_path)
    (d / "cr_record.json").write_bytes(b'{"x": 2}')
    _, rec, problems = vr.verify_uploads(summary, d)
    assert rec is None and any("changed: cr_record.json" in p for p in problems)


# ---------------------------------------------------------------------------------------- clocks (step 5 is the host's)
def _cr_log(dev_started="2026-11-20T10:00:30Z", dev_seconds=10.25, with_dev=True):
    plan = [{"id": "td-pf-01", "phase": "test", "td": "TD_MEC_PF_01"}]
    if with_dev:
        plan.append({"id": "td-dev-01", "phase": "test", "td": "TD_MEC_DEV_01"})
    ex = [{"id": "td-pf-01", "started_utc": "2026-11-20T10:00:00Z", "seconds": 1.5},
          {"id": "td-dev-01", "started_utc": dev_started, "seconds": dev_seconds}]
    return {"provenance": {"plan": plan}, "executed": ex}


def test_dev01_end_is_its_start_in_the_clean_rerun_log_plus_its_duration():
    assert vr.dev01_end_epoch(_cr_log()) == 1795168830 + 10.25


def test_dev01_end_control_absent_when_the_block_is_not_in_the_plan_or_the_log():
    assert vr.dev01_end_epoch(_cr_log(with_dev=False)) is None
    rec = _cr_log()
    rec["executed"] = rec["executed"][:1]
    assert vr.dev01_end_epoch(rec) is None
    assert vr.dev01_end_epoch({}) is None


def test_clock_offset_is_the_median_of_guest_minus_host_over_the_uploads():
    log = [{"method": "PUT", "status": 201, "t_host": 100.0, "guest_time": 102.0},
           {"method": "PUT", "status": 201, "t_host": 200.0, "guest_time": 202.5},
           {"method": "PUT", "status": 201, "t_host": 300.0, "guest_time": 301.5},
           {"method": "GET", "status": 200, "t_host": 50.0, "guest_time": None},
           {"method": "PUT", "status": 400, "t_host": 60.0, "guest_time": None}]
    assert vr.clock_offset(log) == {"median_s": 2.0, "min_s": 1.5, "max_s": 2.5, "n": 3}
    assert vr.clock_offset(log[3:]) is None


def test_step_5_time_is_this_hosts_receipt_of_the_vms_record_never_the_vms_clock():
    log = [{"method": "PUT", "status": 201, "name": "install_a.txt", "t_host": 1100.0, "guest_time": 5.0},
           {"method": "PUT", "status": 201, "name": "cr_record.json", "t_host": 1612.34, "guest_time": 3.0},
           {"method": "PUT", "status": 409, "name": None, "t_host": 1700.0, "guest_time": 1.0}]
    assert vr.host_elapsed(log, 1000.0) == 612.4, "rounded UP to 0.1 s: an upper bound"
    assert vr.host_elapsed(log[:1], 1000.0) is None
    assert vr.host_elapsed(log + [log[1]], 1000.0) is None, "two records: which one is meant cannot be told"
    assert vr.host_elapsed(log, None) is None


# ---------------------------------------------------------------------------------------- clean_rerun's own verdict
def test_clean_reruns_control_and_post_test_rows_are_the_ones_clean_rerun_writes():
    src = (EST / "clean_rerun.py").read_text()
    assert list(vr.CR_CONTROL_ROWS) == CR_CONTROLS and list(vr.POST_TEST_ROWS) == POST_ROWS
    for row in CR_CONTROLS[1:] + POST_ROWS:
        assert f'"{row}"' in src, row
    assert '"CONTROL (must FAIL) with the bootstrap steps taken out of the runbook, {first.td} still passes"' in src
    assert 'f"shutdown step {s.id} from the runbook exits 0"' in src


def _good_cr_record():
    rows = ([{"row": f"step 1/2: bootstrap step {s} from the runbook exits 0", "ok": True}
             for s in ("check-prerequisites", "make-directories", "start-topology")]
            + [{"row": "pre-test: nothing of the lab is running (no CSE or MEC port answers)", "ok": True}]
            + [{"row": r, "ok": True} for r in POST_ROWS]
            + [{"row": "shutdown step stop-topology from the runbook exits 0", "ok": True}])
    return {"result": "PASS", "steps": rows,
            "controls": [{"row": n, "passed": False, "failed_as_it_must": True} for n in CR_CONTROLS]}


def _set_row(rec, name, ok):
    next(r for r in rec["steps"] if r["row"] == name)["ok"] = ok


def test_clean_reruns_own_verdict_in_the_vm_is_accepted_when_it_is_pass():
    assert vr.cr_verdict_problems(_good_cr_record(), ["stop-topology"]) == []


@pytest.mark.parametrize("plant, said", [
    (lambda r: r.update(result="FAIL"), "clean_rerun.py in the VM says 'FAIL', not PASS"),
    (lambda r: _set_row(r, POST_ROWS[0], False), "post-test row false: the copy is unchanged"),
    (lambda r: _set_row(r, "shutdown step stop-topology from the runbook exits 0", False),
     "post-test row false: shutdown step stop-topology"),
    (lambda r: r["steps"].remove(next(x for x in r["steps"] if x["row"] == POST_ROWS[1])),
     "post-test row missing: after shutdown nothing"),
    (lambda r: r["steps"].append({"row": POST_ROWS[2], "ok": True}), "post-test row there twice: after the controls"),
    (lambda r: _set_row(r, "pre-test: nothing of the lab is running (no CSE or MEC port answers)", False),
     "1 other row(s) of clean_rerun.py false"),
    (lambda r: r["controls"][1].update(passed=True, failed_as_it_must=False),
     "control did not fail as it must: CONTROL (must FAIL) a command that is not in the runbook was executed"),
    (lambda r: r["controls"][2].pop("failed_as_it_must"), "control did not fail as it must"),
    (lambda r: r["controls"].pop(4), "control missing: CONTROL (must FAIL) a run directory with old state"),
    (lambda r: r.update(controls=[]), "control missing"),
    (lambda r: r["controls"].append({"row": "CONTROL (must FAIL) planted", "passed": True}),
     "control did not fail as it must: CONTROL (must FAIL) planted"),
    (lambda r: r["controls"].append(dict(r["controls"][3])),                          # C8: a control row twice
     "control there twice: CONTROL (must FAIL) a copy in which a file was changed after the manifest was written"),
])
def test_clean_reruns_own_verdict_control_each_planted_fault_is_a_problem(plant, said):
    rec = _good_cr_record()
    plant(rec)
    problems = vr.cr_verdict_problems(rec, ["stop-topology"])
    assert any(said in p for p in problems), problems


# ---------------------------------------------------------------------------------------- the five OBS_03 steps
GOOD_CR = {"bootstrap_planned": 3, "bootstrap_rows": [True, True, True], "registration_ok": True,
           "only_runbook_ok": True, "stopped": None, "results": {td: True for td in TDS}, "executed_problems": [],
           "verdict_problems": []}


def _facts(**over):
    f = {"guest_reached": True, "harness_error": None, "guest_error": None, "install_plan": ["install-a", "install-b"],
         "installs": [{"id": "install-a", "rc": 0, "seconds": 30.0}, {"id": "install-b", "rc": 0, "seconds": 20.0}],
         "foreign_commands": [], "section6_started": True, "section6_rc": 0, "section6_tail": "", "missing_in_vm": [],
         "cr": copy.deepcopy(GOOD_CR), "kpi_diff": [], "dev01_elapsed_s": 600.0, "budget_s": 1800.0,
         "last_progress": None}
    f.update(over)
    return f


def _cr(**over):
    c = copy.deepcopy(GOOD_CR)
    c.update(over)
    return c


def _steps(f):
    steps = vr.obs03_steps(f)
    assert [s["step"] for s in steps] == [1, 2, 3, 4, 5] and all(s["why"] for s in steps)
    return steps


def _v(f):
    return tuple(s["verdict"] for s in _steps(f))


def test_steps_all_good_is_five_pass():
    assert _v(_facts()) == (P, P, P, P, P)


@pytest.mark.parametrize("over, want", [
    (dict(guest_reached=False, installs=[], section6_started=False, cr=None, kpi_diff=None, dev01_elapsed_s=None),
     (F, F, F, F, F)),                                                                 # no summary: FAIL, not NOT-RUN
    (dict(harness_error="sha256 of a delivered file", installs=[], section6_started=False, cr=None, kpi_diff=None),
     (N, N, N, N, N)),                                                                 # known not to have been tried
    (dict(installs=[{"id": "install-a", "rc": 1, "seconds": 3.0}], section6_started=False, cr=None, kpi_diff=None,
          dev01_elapsed_s=None), (F, F, N, N, N)),
    (dict(installs=[{"id": "install-a", "rc": 0, "seconds": 3.0}], section6_started=False, cr=None, kpi_diff=None,
          dev01_elapsed_s=None), (F, F, N, N, N)),
    (dict(cr=None, kpi_diff=None, dev01_elapsed_s=None), (F, F, F, F, F)),            # ran, but no record came back
    (dict(cr=_cr(bootstrap_rows=[True, False], results={}), kpi_diff=None, dev01_elapsed_s=None), (F, F, N, N, N)),
    (dict(cr=_cr(bootstrap_rows=[True, True]), dev01_elapsed_s=600.0), (F, F, P, P, P)),   # a bootstrap row missing
    (dict(cr=_cr(bootstrap_rows=[True, False, True])), (F, F, P, P, P)),               # a bootstrap row false (N14)
    (dict(cr=_cr(results={"TD_MEC_PF_01": False}), kpi_diff=["x"], dev01_elapsed_s=None), (F, F, F, F, N)),
    (dict(cr=_cr(registration_ok=False)), (P, F, P, P, P)),
    (dict(cr=_cr(only_runbook_ok=False)), (P, F, P, P, P)),
    (dict(cr=_cr(executed_problems=["not in the runbook: apt-get-install-git"])), (P, F, P, P, P)),   # M4
    (dict(cr=_cr(executed_problems=None)), (P, F, P, P, P)),                           # not checked is not clean
    (dict(foreign_commands=[{"kind": "shell", "argv": ["apt-get", "install", "python3-venv"]}]), (P, F, P, P, P)),
    (dict(foreign_commands=None), (P, F, P, P, P)),                                    # the command log did not come back
    (dict(cr=_cr(results={"TD_MEC_PF_01": True, "TD_MEC_REG_01": True, "TD_MEC_REG_02": False}), kpi_diff=["x"],
          dev01_elapsed_s=None), (P, P, F, F, N)),
    (dict(cr=_cr(results=dict({td: True for td in TDS}, TD_MEC_DEV_01=False)), kpi_diff=["x"]), (P, P, P, F, F)),
    (dict(kpi_diff=["tests_passed TD_MEC_REG_03: reference 89/89 against rerun 88/89"]), (P, P, P, F, P)),
    (dict(kpi_diff=None), (P, P, P, F, P)),                                            # not compared is not equal
    (dict(cr=_cr(verdict_problems=["clean_rerun.py in the VM says 'FAIL', not PASS"])), (P, P, P, F, P)),   # H2
    (dict(cr=_cr(verdict_problems=None)), (P, P, P, F, P)),
    (dict(dev01_elapsed_s=1800.5), (P, P, P, P, F)),
    (dict(dev01_elapsed_s=None), (P, P, P, P, F)),
])
def test_steps_control_each_failure_lands_on_its_step_and_later_ones_are_not_run(over, want):
    assert _v(_facts(**over)) == want


def test_steps_control_a_runbook_without_a_rerun_block_stops_after_the_install_blocks():
    steps = _steps(_facts(section6_started=False, section6_why="the runbook has no rerun block", cr=None, kpi_diff=None,
                          dev01_elapsed_s=None))
    assert tuple(s["verdict"] for s in steps) == (F, F, N, N, N)
    assert steps[0]["why"] == "the runbook's rerun block was not run: the runbook has no rerun block"
    assert steps[2]["why"] == "the runbook's rerun block was not run, so its bootstrap and test blocks were not reached"


def test_steps_control_a_root_result_that_did_not_come_back_is_a_fail_not_a_not_run():
    steps = _steps(_facts(installs=[], root_missing=True, section6_started=False, cr=None, kpi_diff=None,
                          dev01_elapsed_s=None, guest_error="VmError: the root step left no readable root_blocks.json"))
    assert tuple(s["verdict"] for s in steps) == (F, F, N, N, N)
    assert "whether the root=yes blocks ran is not known" in steps[0]["why"]


def test_steps_budget_boundary_is_inclusive():
    assert _v(_facts(dev01_elapsed_s=1800.0))[4] == P


def test_steps_control_no_summary_is_a_fail_that_names_the_last_line_this_host_saw():
    steps = _steps(_facts(guest_reached=False, installs=[], cr=None, last_progress="VMRERUN-PROGRESS guest-start"))
    assert {s["verdict"] for s in steps} == {F}
    assert "no summary came back" in steps[0]["why"] and "VMRERUN-PROGRESS guest-start" in steps[0]["why"]


def test_steps_control_a_section_6_that_printed_no_record_says_how_it_exited():
    steps = _steps(_facts(cr=None, kpi_diff=None, dev01_elapsed_s=None, section6_rc=2,
                          section6_tail="python: can't open file '/home/edgefollow/estimed/clean_rerun.py'"))
    assert "the rerun block exited 2" in steps[0]["why"] and "can't open file" in steps[0]["why"]


def test_steps_control_git_missing_in_the_vm_is_one_clear_reason():
    f = _facts(cr=_cr(bootstrap_planned=0, bootstrap_rows=[], results={},
                      stopped="FileNotFoundError: [Errno 2] No such file or directory: 'git'"),
               missing_in_vm=["git"], kpi_diff=None, dev01_elapsed_s=None)
    steps = _steps(f)
    assert tuple(s["verdict"] for s in steps) == (F, F, N, N, N)
    assert steps[0]["why"] == ("clean_rerun.py stopped before the bootstrap: FileNotFoundError: [Errno 2] No such file "
                               "or directory: 'git'; not on the VM's PATH: git (clean_rerun.py, which the rerun block "
                               "starts, lists the code's files with git; the runbook's prerequisites do not name it)")


def test_overall_is_pass_only_when_all_five_steps_pass():
    ctl = [{"row": "CONTROL x", "passed": False}]
    for combo in itertools.product([P, F, N], repeat=5):
        steps = [{"step": i + 1, "verdict": v} for i, v in enumerate(combo)]
        assert vr.overall(steps, ctl, []) is (combo == (P,) * 5), combo
    five = [{"step": i, "verdict": P} for i in range(1, 6)]
    assert vr.overall(five, [], []) is False, "no control"
    assert vr.overall(five, ctl + [{"row": "CONTROL y", "passed": True}], []) is False
    assert vr.overall(five, ctl, ["uploads: changed: guest.json"]) is False
    assert vr.overall(five[:4], ctl, []) is False


RUN_PLAN = [cr.Step(i, ph, f": {i}", _sha(f": {i}".encode()), (), td, n) for i, ph, td, n in [
    ("check-prerequisites", "bootstrap", None, None), ("make-directories", "bootstrap", None, None),
    ("start-topology", "bootstrap", None, None), *[(f"td-{k}", "test", td, 1) for k, td in enumerate(TDS)],
    ("stop-topology", "shutdown", None, None)]]


def _vm_record(results=None, boot=(True, True, True), reg=True, only=True, executed=None):
    rec = _good_cr_record()
    rec["steps"] = [r for r in rec["steps"] if not r["row"].startswith("step 1/2")]
    rec["steps"] += [{"row": f"step 1/2: bootstrap step {sid} from the runbook exits 0", "ok": ok}
                     for sid, ok in zip(["check-prerequisites", "make-directories", "start-topology"], boot)]
    rec["steps"] += [{"row": "step 2: after the runbook's bootstrap steps alone, every MN-CSE is registered both ways",
                      "ok": reg},
                     {"row": "step 2: the commands executed are the runbook's run steps, each once, in order, and "
                             "nothing else", "ok": only}]
    rec["provenance"] = {"plan": [{"id": s.id, "phase": s.phase, "td": s.td} for s in RUN_PLAN]}
    rec["results"] = results if results is not None else {td: {"ok": True} for td in TDS}
    rec["executed"] = executed if executed is not None else [{"id": s.id, "sha256": s.sha256} for s in RUN_PLAN]
    return rec


def _guest(plan, rerun=RERUN_CFG, extra=()):
    return {"installs": [{"id": p["id"], "rc": 0, "seconds": 1.0} for p in plan],
            "commands": [{"kind": "runbook", "id": p["id"], "sha256": p["sha256"]} for p in plan]
            + [{"kind": "runbook", "phase": "rerun", "id": rerun["id"], "sha256": rerun["sha256"]}] + list(extra),
            "section6": {"started": True, "rc": 0}, "probes": {"on_path": {"git": "/usr/bin/git"}}}


def _facts_of(summary=None, guest=None, rec=None, **kw):
    args = dict(install_plan=PLAN, rerun_expected=RERUN_CFG, kpi_diff=[], run_plan=RUN_PLAN, elapsed_s=600.0,
                budget_s=1800.0)
    args.update(kw)
    return vr.facts_of({"attempt": 1} if summary is None else summary, guest, rec, **args)


def test_facts_from_a_good_guest_log_and_record_are_five_pass():
    assert _v(_facts_of(guest=_guest(PLAN), rec=_vm_record())) == (P, P, P, P, P)


@pytest.mark.parametrize("g", [
    _guest(PLAN, extra=[{"kind": "runbook", "id": "install-system-packages", "sha256": "9" * 64}]),
    _guest(PLAN, rerun={"id": "rerun", "sha256": "5" * 64}),              # a rerun block the host did not deliver
    _guest(PLAN, rerun={"id": "rerun2", "sha256": "4" * 64}),
    _guest(PLAN, extra=[{"kind": "runbook", "phase": "rerun", "id": "rerun", "sha256": "4" * 64}]),   # run twice
    _guest(PLAN, extra=[{"kind": "runbook", "id": "install-a", "sha256": "1" * 64}]),                 # run twice
    _guest(PLAN, extra=[{"kind": "shell", "argv": ["apt-get", "install", "git"]}]),
])
def test_facts_control_a_command_outside_the_plan_in_the_guest_log_fails_step_2(g):
    steps = _steps(_facts_of(guest=g, rec=_vm_record()))
    assert steps[1]["verdict"] == F and "not a block of the delivered runbook" in steps[1]["why"], steps[1]


def test_facts_control_a_rerun_block_when_the_delivered_runbook_has_none_is_foreign():
    assert _v(_facts_of(guest=_guest(PLAN), rec=_vm_record(), rerun_expected=None))[1] == F


@pytest.mark.parametrize("executed, said", [
    ([{"id": s.id, "sha256": s.sha256} for s in RUN_PLAN[:3]] + [{"id": "apt-get-install-git", "sha256": "9" * 64}]
     + [{"id": s.id, "sha256": s.sha256} for s in RUN_PLAN[3:]], "not in the runbook: apt-get-install-git"),
    ([{"id": s.id, "sha256": s.sha256} for s in RUN_PLAN[1:]], "not executed: check-prerequisites"),
    ([{"id": s.id, "sha256": s.sha256} for s in RUN_PLAN[::-1]], "order"),
    ([{"id": s.id, "sha256": s.sha256} for s in RUN_PLAN] + [{"id": "stop-topology", "sha256": RUN_PLAN[-1].sha256}],
     "more than once: stop-topology"),
    ([{"id": s.id, "sha256": "0" * 64 if s.id == "td-2" else s.sha256} for s in RUN_PLAN], "not in the runbook: td-2"),
])
def test_facts_control_step_2_is_judged_here_from_the_vms_log_against_the_delivered_runbook(executed, said):
    steps = _steps(_facts_of(guest=_guest(PLAN), rec=_vm_record(executed=executed)))
    assert steps[1]["verdict"] == F and said in steps[1]["why"], steps[1]


def test_facts_control_a_clean_rerun_that_says_fail_in_the_vm_fails_step_4():
    rec = _vm_record()
    rec["result"] = "FAIL"
    steps = _steps(_facts_of(guest=_guest(PLAN), rec=rec))
    assert tuple(s["verdict"] for s in steps) == (P, P, P, F, P) and "says 'FAIL'" in steps[3]["why"]


def test_facts_control_no_guest_log_and_no_summary():
    s = {"attempt": 1, "installs": [{"id": p["id"], "rc": 0, "seconds": 1.0} for p in PLAN],
         "section6": {"started": True, "rc": 0}}
    assert _v(_facts_of(summary=s, guest=None, rec=_vm_record()))[1] == F, "a command log that did not arrive is not clean"
    assert vr.facts_of(None, None, None, install_plan=PLAN, rerun_expected=RERUN_CFG, kpi_diff=None, elapsed_s=None,
                       budget_s=1800.0)["guest_reached"] is False


def test_facts_control_a_bootstrap_row_that_failed_in_the_vm_fails_steps_1_and_2():
    assert _v(_facts_of(guest=_guest(PLAN), rec=_vm_record(boot=(True, True, False), results={})))[:3] == (F, F, N)
    assert _v(_facts_of(guest=_guest(PLAN), rec=_vm_record(boot=(True, False, True))))[:2] == (F, F)


def test_facts_name_a_command_missing_on_the_vms_path():
    g = _guest(PLAN)
    g["probes"]["on_path"] = {"bash": "/usr/bin/bash", "git": None}
    assert _facts_of(guest=g, rec=_vm_record())["missing_in_vm"] == ["git"]


# ---------------------------------------------------------------------------------------- the guest side
MINI = """# mini

```sh
: runbook-step variables phase=variables && \\
export ROOT=/x/code && export RUN=/x/run && export OUT=/x/out
```

```sh
: runbook-step install-a phase=install && touch "$OUT/a"
```

```sh
: runbook-step install-b phase=install && test -e "$OUT/never"
```

```sh
: runbook-step install-c phase=install && touch "$OUT/c"
```

```sh
: runbook-step start phase=bootstrap && cd "$ROOT"
```

```sh
: runbook-step t1 phase=test td=TD_MEC_PF_01 tests=1 && cd "$ROOT"
```

```sh
: runbook-step stop phase=shutdown && cd "$ROOT"
```
"""
MINI_RERUN = '```text\n: runbook-step rerun phase=rerun && \\\ncd "$ROOT" && test -d "$RUN"\n```\n'


def test_guest_install_plan_check_accepts_the_runbooks_own_blocks():
    rb = cr.parse_runbook(MINI)
    steps = vr.check_install_plan(rb, vr.install_plan(rb))
    assert [s.id for s in steps] == ["install-a", "install-b", "install-c"]


@pytest.mark.parametrize("mangle", [
    lambda p: p[0].update(sha256="0" * 64),
    lambda p: p.append({"id": "install-d", "sha256": "0" * 64}),
    lambda p: p.pop(),
    lambda p: p.reverse(),
])
def test_guest_control_an_install_plan_that_is_not_the_runbooks_is_refused(mangle):
    rb = cr.parse_runbook(MINI)
    plan = vr.install_plan(rb)
    mangle(plan)
    with pytest.raises(vr.VmError):
        vr.check_install_plan(rb, plan)


def test_guest_runs_the_install_blocks_in_order_and_stops_at_the_first_failure(tmp_path):
    rb = cr.parse_runbook(MINI)
    steps = vr.check_install_plan(rb, vr.install_plan(rb))
    ex = cr.Executor(steps, env={"PATH": "/usr/bin:/bin", "OUT": str(tmp_path)}, cwd=tmp_path)
    saved = []
    done, not_run = vr.run_installs(ex, steps, lambda sid, r: saved.append(sid))
    assert [(d["id"], d["rc"]) for d in done] == [("install-a", 0), ("install-b", 1)]
    assert not_run == ["install-c"] and saved == ["install-a", "install-b"]
    assert (tmp_path / "a").exists() and not (tmp_path / "c").exists()
    assert [e["id"] for e in ex.log] == ["install-a", "install-b"]


def test_guest_control_a_block_outside_the_executors_plan_is_not_run(tmp_path):
    rb = cr.parse_runbook(MINI)
    steps = vr.check_install_plan(rb, vr.install_plan(rb))
    ex = cr.Executor(steps[:1], env={"PATH": "/usr/bin:/bin", "OUT": str(tmp_path)}, cwd=tmp_path)
    with pytest.raises(cr.RerunError):
        vr.run_installs(ex, steps[1:2], lambda sid, r: None)


def test_the_shipped_runbook_has_one_root_block_first_and_it_installs_exactly_python3_venv_and_git():
    text = RUNBOOK.read_text()
    rb = cr.parse_runbook(text)
    installs = [s for s in rb.steps if s.phase == "install"]
    assert [s.id for s in installs] == ["install-system-packages", "install-cse-environment", "install-test-environment"]
    assert vr.root_block_ids(rb) == ["install-system-packages"]
    assert installs[0].command == (": runbook-step install-system-packages phase=install root=yes && \\\n"
                                   "apt-get -o DPkg::Lock::Timeout=600 update && \\\n"
                                   "apt-get -o DPkg::Lock::Timeout=600 install -y python3-venv git")
    assert vr.blocks_needing_root(rb) == [{"id": "install-system-packages", "phase": "install", "marker_root": True,
                                           "names": []}]
    assert text.count(RERUN_HOST) == 1, "section 6 holds the rerun block RERUN_HOST writes out, once"
    s = vr.rerun_block(text, rb, cr)
    assert (s.id, s.phase, s.command, s.sha256) == ("rerun", "rerun", RERUN_BODY, RERUN_BODY_SHA256), \
        "the shipped rerun block is RERUN_HOST's body exactly"
    assert _sha(RERUN_BODY.encode()) == RERUN_BODY_SHA256
    assert "Root is needed once" in text and "No root" not in text and "must be a git checkout" in text


@pytest.mark.parametrize("edit, want", [
    (lambda t: t.replace("install-a phase=install &&", "install-a phase=install root=yes &&"), ["install-a"]),
    (lambda t: t.replace("install-a phase=install &&", "install-a phase=install root=yes &&")
     .replace("install-b phase=install &&", "install-b phase=install root=yes &&"), ["install-a", "install-b"]),
    (lambda t: t, []),
])
def test_root_marked_install_blocks_are_the_root_steps_plan(edit, want):
    assert vr.root_block_ids(cr.parse_runbook(edit(MINI))) == want


@pytest.mark.parametrize("edit, said", [
    (lambda t: t.replace("install-b phase=install &&", "install-b phase=install root=yes &&"),
     "a root=yes block after an unmarked install block"),
    (lambda t: t.replace("install-a phase=install &&", "install-a phase=install root=no &&"), "root=no"),
    (lambda t: t.replace("install-a phase=install &&", "install-a phase=install root=true &&"), "root=true"),
    (lambda t: t.replace("start phase=bootstrap &&", "start phase=bootstrap root=yes &&"),
     "root=yes on a bootstrap block"),
    (lambda t: t.replace("t1 phase=test td=TD_MEC_PF_01 tests=1 &&", "t1 phase=test td=TD_MEC_PF_01 tests=1 root=yes &&"),
     "root=yes on a test block"),
])
def test_root_marks_control_another_value_another_phase_or_a_late_root_block_is_refused(edit, said):
    with pytest.raises(vr.VmError, match=said):
        vr.root_block_ids(cr.parse_runbook(edit(MINI)))


def test_blocks_that_name_a_root_command_without_the_marker_are_flagged_and_run_as_edgefollow():
    text = MINI.replace('install-b phase=install && test -e "$OUT/never"', 'install-b phase=install && sudo test -e "$OUT/never"')
    rb = cr.parse_runbook(text)
    assert vr.blocks_needing_root(rb) == [{"id": "install-b", "phase": "install", "marker_root": False, "names": ["sudo"]}]
    assert vr.root_block_ids(rb) == [], "a block is run as root by its marker only, never because it names sudo"


def test_the_rerun_block_is_found_in_a_fence_clean_rerun_does_not_read_and_is_kept_exactly():
    text = MINI + "\n" + MINI_RERUN
    rb = cr.parse_runbook(text)                      # clean_rerun's parser accepts the runbook and skips the block
    assert [s.id for s in rb.steps if s.id == "rerun"] == []
    s = vr.rerun_block(text, rb, cr)
    body = ': runbook-step rerun phase=rerun && \\\ncd "$ROOT" && test -d "$RUN"'
    assert (s.id, s.phase, s.command, s.sha256) == ("rerun", "rerun", body, _sha(body.encode()))
    assert vr.rerun_block(MINI + "\n```text\njust words\n```\n", rb, cr) is None


@pytest.mark.parametrize("block, said", [
    (MINI_RERUN + MINI_RERUN.replace("rerun phase=", "rerun2 phase="), "2 rerun blocks"),
    (MINI_RERUN.replace("rerun phase=rerun", "start phase=rerun"), "appears twice"),
    (MINI_RERUN.replace('test -d "$RUN"', 'test -d "$RUN"; touch /x'), "only &&"),
    (MINI_RERUN.replace('test -d "$RUN"', 'test -d "$RUN" | cat'), "only &&"),
    (MINI_RERUN.replace('test -d "$RUN"', 'test -d "$HOME"'), "uses $HOME"),
    (MINI_RERUN.replace("phase=rerun", "phase=rerun td=x"), "harness runs only phase=rerun"),
    (MINI_RERUN.replace("phase=rerun", "phase=test"), "harness runs only phase=rerun"),
    (MINI_RERUN.replace(" && \\\n", " && \n"), "not one command chain"),
    ("```json\n: runbook-step rerun phase=rerun &&\n```\n", "not one command chain"),
])
def test_the_rerun_block_control_a_block_that_breaks_clean_reruns_rules_is_refused(block, said):
    text = MINI + "\n" + block
    with pytest.raises(vr.VmError, match=re.escape(said)):
        vr.rerun_block(text, cr.parse_runbook(text), cr)


def test_the_rerun_block_control_in_a_shell_fence_clean_rerun_refuses_the_runbook():
    with pytest.raises(cr.RunbookError, match="phase must be one of"):
        cr.parse_runbook(MINI + "\n" + MINI_RERUN.replace("```text", "```sh"))


@pytest.mark.parametrize("raw, want", [("bootstrap_start-topology.txt", "bootstrap_start-topology.txt"),
                                       ("../x/y z", "x_y_z"), ("TD_MEC_PF_01.xml", "TD_MEC_PF_01.xml"),
                                       (".hidden", "hidden")])
def test_upload_names_are_one_plain_segment(raw, want):
    assert vr.safe_name(raw) == want and vr.NAME_RE.fullmatch(want)


def test_the_guest_and_the_root_step_start_no_process_of_their_own():
    for fn in (vr.run_installs, vr.guest_probes, vr.guest_main, vr.root_main, vr._root_copy):
        src = inspect.getsource(fn)
        assert not re.findall(r"subprocess\.(?:run|Popen|call|check_\w+)\(", src), fn.__name__
        assert "shell=True" not in src and "os.system" not in src, fn.__name__
    assert "cr.Executor(" in inspect.getsource(vr.root_main), "root blocks go through clean_rerun's Executor"
    assert inspect.getsource(vr.guest_main).count("cr.Executor(") == 2, "the unmarked install blocks and the rerun block"


def test_ipv6_addresses_are_read_from_the_kernel_table_and_only_loopback_and_link_local_pass(tmp_path):
    t = tmp_path / "if_inet6"
    t.write_text("00000000000000000000000000000001 01 80 10 80       lo\n"
                 "fe80000000000000505400fffe123456 02 40 20 80   enp0s2\n")
    addrs = vr.ipv6_addresses(t)
    assert addrs == [{"address": "::1", "interface": "lo"}, {"address": "fe80::5054:ff:fe12:3456", "interface": "enp0s2"}]
    assert vr.ipv6_problems(addrs) == [] and vr.ipv6_addresses(tmp_path / "missing") is None
    t.write_text(t.read_text() + "fec0000000000000505400fffe123456 02 40 00 00   enp0s2\n")
    p = vr.ipv6_problems(vr.ipv6_addresses(t))
    assert p == ["the VM holds IPv6 address(es) other than loopback and link-local: ['fec0::5054:ff:fe12:3456'] "
                 "(ipv6=off did not take)"]


# ---------------------------------------------------------------------------------------- the guest, end to end (no VM)
FAKE_PY = """#!/bin/bash
# stands in for "$PY -B estimed/clean_rerun.py rerun --reference <file>": like python, it needs estimed/clean_rerun.py
# under the folder it is started in; it notes that folder and its environment, writes a record, prints its path last
test "$1 $2 $3 $4" = "-B estimed/clean_rerun.py rerun --reference" || exit 9
test -f "$5" || exit 8
pwd -P > PWDFILE
env > ENVFILE
test -f estimed/clean_rerun.py || { echo "python: can't open file '$(pwd)/estimed/clean_rerun.py'" >&2; exit 2; }
mkdir -p SIM BASE/out
printf 'bootstrap log\\n' > BASE/bootstrap_start.txt
printf '{}' > BASE/manifest.json
printf '<testsuites/>' > BASE/out/TD_MEC_PF_01.xml
printf '{"result": "FAIL", "decoy": true}' > SIM/clean_rerun_20261119T000000Z.json
printf '{"result": "PASS", "directories": {"base": "BASE", "out": "BASE/out", "run": "BASE/run"}}' > SIM/clean_rerun_20261120T000000Z.json
echo SIM/clean_rerun_20261119T000000Z.json
echo "RESULT: PASS"
echo SIM/clean_rerun_20261120T000000Z.json
"""
ROOT_BLOCK = 'mkdir -p "$OUT" && env > "$OUT/root_env" && pwd -P > "$OUT/root_pwd"'


def _guest_world(tmp_path, monkeypatch, second_block='env > "$OUT/two"', rerun_body="DEFAULT", root_block=ROOT_BLOCK):
    """A fake VM folder layout: ROOT with the runbook and clean_rerun.py, the root step's folder (code.tar, config),
    edgefollow's harness folder and home, root's home, the console file; a seed server on 127.0.0.1 for the uploads."""
    t = types.SimpleNamespace()
    t.root, t.w, t.g, t.home, t.rhome, t.sim, t.base = (tmp_path / n for n in ("code", "w", "g", "home", "roothome",
                                                                                "sim", "crbase"))
    for d in (t.root / "estimed", t.w, t.g, t.home, t.rhome):
        d.mkdir(parents=True)
    (t.root / "estimed" / "clean_rerun.py").write_bytes((EST / "clean_rerun.py").read_bytes())
    t.py = tmp_path / "fakepy"
    t.py.write_text(FAKE_PY.replace("ENVFILE", str(tmp_path / "s6_env.txt")).replace("PWDFILE", str(tmp_path / "s6_pwd.txt"))
                    .replace("SIM", str(t.sim)).replace("BASE", str(t.base)))
    t.py.chmod(0o755)
    t.ref = tmp_path / "ref.json"
    t.ref.write_text("{}")
    if rerun_body == "DEFAULT":
        rerun_body = f'cd "$ROOT" && "$PY" -B estimed/clean_rerun.py rerun --reference {t.ref}'
    rb = (f"# fake\n\n```sh\n: runbook-step variables phase=variables && \\\nexport ROOT={t.root} && export RUN={tmp_path}/run "
          f"&& export OUT={tmp_path}/out && export PY={t.py}\n```\n\n"
          f"```sh\n: runbook-step install-sys phase=install root=yes && {root_block}\n```\n\n"
          f"```sh\n: runbook-step install-one phase=install env=PY && mkdir -p \"$OUT\" && touch \"$OUT/one\"\n```\n\n"
          f"```sh\n: runbook-step install-two phase=install && {second_block}\n```\n\n"
          "```sh\n: runbook-step start phase=bootstrap && cd \"$ROOT\"\n```\n\n"
          "```sh\n: runbook-step t1 phase=test td=TD_MEC_PF_01 tests=1 && cd \"$ROOT\"\n```\n\n"
          "```sh\n: runbook-step stop phase=shutdown && cd \"$ROOT\"\n```\n\n"
          + (f"```text\n: runbook-step rerun phase=rerun && \\\n{rerun_body}\n```\n" if rerun_body is not None else ""))
    (t.root / "estimed" / "RUNBOOK.md").write_text(rb)
    with tarfile.open(t.g / "code.tar", "w") as tar:                  # as build_code packs it: names relative to ROOT
        for rel in ("estimed", "estimed/RUNBOOK.md", "estimed/clean_rerun.py"):
            tar.add(t.root / rel, arcname=rel, recursive=False)
    t.srv = vr.SeedServer({}, tmp_path / "uploads")
    t.srv.start()
    parsed = cr.parse_runbook(rb)
    t.rerun = vr.rerun_block(rb, parsed, cr)
    t.cfg = vr.guest_config(attempt=1, stamp="s", code_root=str(t.root), install_plan=vr.install_plan(parsed),
                            root_ids=vr.root_block_ids(parsed),
                            rerun={"id": t.rerun.id, "sha256": t.rerun.sha256} if t.rerun else None)
    t.cfg.update(server=f"http://127.0.0.1:{t.srv.port}", harness_dir=str(t.w), guest_dir=str(t.g),
                 reference=str(t.ref), clean_rerun_results=str(t.sim), apt_conf=str(t.g / "apt-proxy.conf"),
                 console=str(tmp_path / "console.txt"))
    t.rb, t.parsed, t.tmp, t.out = rb, parsed, tmp_path, tmp_path / "out"
    t.write_cfg = lambda: [(d / "config.json").write_text(json.dumps(t.cfg)) for d in (t.w, t.g)]
    t.write_cfg()
    monkeypatch.setenv("HOME", str(t.home))
    monkeypatch.setenv("VMRERUN_SENTINEL", "the test process's own environment")
    monkeypatch.setattr(vr, "_listening", lambda port: False)        # M8: no probe of this host's lab ports
    monkeypatch.setattr(vr, "ROOT_BLOCK_ENV", dict(vr.ROOT_BLOCK_ENV, HOME=str(t.rhome)))   # root's home, in tmp_path

    def run(root_step=True):
        try:
            if root_step:
                assert vr.root_main(t.g / "config.json") == 0
            assert vr.guest_main(t.w / "config.json") == 0
        finally:
            t.srv.stop()
        t.summary = json.loads((t.w / "summary.json").read_text())
        t.guest, t.rec, t.problems = vr.verify_uploads(t.summary, t.srv.results_dir)
        t.console = vr.parse_console((tmp_path / "console.txt").read_text() if (tmp_path / "console.txt").exists() else "")
        return t
    t.run = run
    return t


def _env_file(path) -> dict:
    return {k: v for k, v in (ln.split("=", 1) for ln in Path(path).read_text().splitlines() if "=" in ln)
            if k not in ("PWD", "OLDPWD", "SHLVL", "_")}


def test_guest_end_to_end_root_step_install_blocks_and_rerun_block_and_uploads_the_host_verifies(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch).run()
    s = t.summary
    assert [(i["id"], i["rc"], i["as"]) for i in s["installs"]] == [("install-sys", 0, "root"), ("install-one", 0, "edgefollow"),
                                                                   ("install-two", 0, "edgefollow")]
    assert s["section6"] == {"started": True, "id": "rerun", "rc": 0, "tail": "", "why": None}
    assert s["cr_result"] == "PASS" and s["guest_error"] is None and s["uploads_refused"] == 0
    assert t.problems == [] and t.rec["result"] == "PASS"
    assert sorted(p.name for p in t.srv.results_dir.iterdir()) == [
        "cr_bootstrap_start.txt", "cr_manifest.json", "cr_out_TD_MEC_PF_01.xml", "cr_record.json", "guest.json",
        "install_install-one.txt", "install_install-two.txt", "root_blocks.json", "section6_output.txt"]
    assert t.guest["uploads"][0]["name"] == "cr_record.json", "the record goes first: its arrival times step 5"
    assert [(c["as"], c["id"]) for c in t.guest["commands"]] == [("root", "install-sys"), ("edgefollow", "install-one"),
                                                                ("edgefollow", "install-two"), ("edgefollow", "rerun")]
    f = vr.facts_of(s, t.guest, t.rec, install_plan=t.cfg["install_plan"], rerun_expected=t.cfg["rerun_block"],
                    kpi_diff=None, elapsed_s=None, budget_s=vr.BUDGET_S)
    assert f["foreign_commands"] == [] and f["section6_started"] is True
    assert len(t.console["root"]) == 1 and t.console["root"][0]["blocks"] == [
        {"id": "install-sys", "sha256": t.cfg["install_plan"][0]["sha256"], "rc": 0}]
    assert vr.root_console_problems(t.console, s, t.guest, t.cfg["install_plan"], t.cfg["root_block_ids"]) == []
    assert (t.out / "root_pwd").read_text().strip() == str(t.rhome), "root blocks run from root's home"
    assert (t.g / "apt-proxy.conf").read_text() == ('Acquire::http::Proxy "http://10.0.2.101:3128";\n'
                                                    'Acquire::https::Proxy "http://10.0.2.101:3128";\n')
    assert t.guest["probes"]["python3"] and "git" in t.guest["probes"]["on_path"] and t.guest["probes"]["lab_ports_listening"] == []
    assert vr.clock_offset(t.srv.log)["n"] == 9


def test_guest_takes_the_record_from_the_last_line_of_the_rerun_block_never_an_earlier_one(tmp_path, monkeypatch):
    # C9: the fake prints another record's path first; the record is the one on the last line
    t = _guest_world(tmp_path, monkeypatch).run()
    assert t.guest["clean_rerun"]["record"] == str(t.sim / "clean_rerun_20261120T000000Z.json")
    assert t.rec == {"result": "PASS", "directories": {"base": str(t.base), "out": str(t.base / "out"),
                                                       "run": str(t.base / "run")}}


def test_guest_runs_the_rerun_block_exactly_as_written_from_the_users_home_and_a_cd_inside_it_runs(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch).run()
    assert t.guest["section6"]["cwd"] == str(t.home), "the block starts in edgefollow's home"
    assert (tmp_path / "s6_pwd.txt").read_text().strip() == str(t.root), "the block's own cd \"$ROOT\" ran"
    assert t.guest["section6"]["sha256"] == t.rerun.sha256 == _sha(t.rerun.command.encode())
    assert t.rerun.command == (': runbook-step rerun phase=rerun && \\\ncd "$ROOT" && "$PY" -B estimed/clean_rerun.py '
                               f'rerun --reference {t.ref}')


def test_guest_control_a_rerun_block_without_a_cd_runs_from_home_and_the_harness_adds_none(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch, rerun_body=f'"$PY" -B estimed/clean_rerun.py rerun --reference {tmp_path}/ref.json')
    t.run()
    assert (tmp_path / "s6_pwd.txt").read_text().strip() == str(t.home)
    assert t.summary["section6"]["rc"] == 2 and "can't open file" in t.summary["section6"]["tail"]
    assert t.summary["cr_result"] is None and t.rec is None


def test_guest_a_changed_rerun_block_is_what_runs_and_its_sha_is_in_guest_json(tmp_path, monkeypatch):
    body = f'test -d "$ROOT" && cd "$ROOT" && "$PY" -B estimed/clean_rerun.py rerun --reference {tmp_path}/ref.json'
    t = _guest_world(tmp_path, monkeypatch, rerun_body=body).run()
    want = _sha(f": runbook-step rerun phase=rerun && \\\n{body}".encode())
    assert t.cfg["rerun_block"]["sha256"] == want
    assert [c["sha256"] for c in t.guest["commands"] if c.get("phase") == "rerun"] == [want]
    assert t.summary["cr_result"] == "PASS"


def test_guest_control_a_rerun_block_that_is_not_the_one_user_data_names_is_not_run(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch)
    t.cfg["rerun_block"] = {"id": "rerun", "sha256": "0" * 64}
    t.write_cfg()
    t.run()
    assert "rerun block is not the one user-data names" in t.summary["guest_error"]
    assert not (tmp_path / "s6_pwd.txt").exists() and t.summary["section6"]["started"] is False
    assert [c["as"] for c in t.guest["commands"]] == ["root"], "the root step had run; nothing as edgefollow"


def test_guest_control_a_runbook_without_a_rerun_block_stops_after_the_install_blocks(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch, rerun_body=None).run()
    assert t.cfg["rerun_block"] is None and len(t.summary["installs"]) == 3
    assert t.summary["section6"]["started"] is False and "has no rerun block" in t.summary["section6"]["why"]
    f = vr.facts_of(t.summary, t.guest, None, install_plan=t.cfg["install_plan"], rerun_expected=None, kpi_diff=None,
                    elapsed_s=None, budget_s=vr.BUDGET_S)
    assert _v(f) == (F, F, N, N, N)


def test_guest_every_block_gets_exactly_the_environment_harness_steps_lists(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch).run()
    var = {"ROOT": str(t.root), "RUN": f"{tmp_path}/run", "OUT": f"{tmp_path}/out", "PY": str(t.py)}
    proxy = {"HTTPS_PROXY": "http://10.0.2.101:3128", "https_proxy": "http://10.0.2.101:3128"}
    edgefollow = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(t.home), "LANG": "C.UTF-8"}
    root = {"PATH": ROOT_PATH, "HOME": str(t.rhome), "LANG": "C.UTF-8"}
    assert t.guest["install_env"] == _env_file(t.out / "two") == {**edgefollow, **var, **proxy}
    assert t.guest["rerun_env"] == _env_file(tmp_path / "s6_env.txt") == {**edgefollow, **var}
    assert t.guest["root_step"]["env"] == _env_file(t.out / "root_env") == {
        **root, **var, **proxy, "APT_CONFIG": str(t.g / "apt-proxy.conf")}
    assert "VMRERUN_SENTINEL" not in _env_file(t.out / "two")
    hs = vr.HARNESS_STEPS
    assert "PATH=/usr/local/bin:/usr/bin:/bin HOME=/home/edgefollow LANG=C.UTF-8 and every name the runbook's variables " \
           "block exports" in hs["guest"] and "HTTPS_PROXY and https_proxy" in hs["guest"]
    assert f"PATH={ROOT_PATH} HOME=/root LANG=C.UTF-8, every name the runbook's variables block exports, HTTPS_PROXY " \
           "and https_proxy (step proxy) and APT_CONFIG (step apt-proxy)" in hs["root-blocks"]
    assert "APT_CONFIG=/var/lib/vmrerun/apt-proxy.conf" in hs["apt-proxy"] and "rerun block runs without it" in hs["proxy"]
    names = set(re.findall(r"\b([A-Z][A-Z_]{2,})=", hs["guest"] + hs["root-blocks"]))
    assert names == {"PATH", "HOME", "LANG"}, "no other variable is named with a value"


def test_guest_root_step_runs_only_the_root_marked_blocks(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch).run()
    root = json.loads((t.g / "root_blocks.json").read_text())
    assert [b["id"] for b in root["blocks"]] == ["install-sys"] and root["not_run"] == [] and root["error"] is None
    assert set(root["logs"]) == {"install-sys"} and (t.out / "one").exists()
    assert "APT_CONFIG" not in _env_file(t.out / "two"), "an unmarked block never gets the root step's environment"
    assert (t.g / "rootcode" / "estimed" / "RUNBOOK.md").read_text() == t.rb, "root read the runbook from code.tar"
    assert (t.g / "rootcode").stat().st_mode & 0o777 == 0o700


def test_guest_control_a_failing_root_block_stops_the_unmarked_install_blocks(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch, root_block='test -e "$OUT/never"').run()
    assert [(i["id"], i["rc"]) for i in t.summary["installs"]] == [("install-sys", 1)]
    assert t.summary["install_not_run"] == ["install-one", "install-two"] and not (t.out / "one").exists()
    assert t.summary["section6"]["started"] is False and t.console["root"][0]["blocks"][0]["rc"] == 1
    f = vr.facts_of(t.summary, t.guest, None, install_plan=t.cfg["install_plan"], rerun_expected=t.cfg["rerun_block"],
                    kpi_diff=None, elapsed_s=None, budget_s=vr.BUDGET_S)
    steps = _steps(f)
    assert tuple(s["verdict"] for s in steps) == (F, F, N, N, N) and "install block install-sys exited 1" in steps[0]["why"]


def test_guest_control_no_root_result_runs_no_install_block(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch).run(root_step=False)
    assert t.summary["root_missing"] is True and t.summary["installs"] == [] and not t.out.exists()
    f = vr.facts_of(t.summary, t.guest, None, install_plan=t.cfg["install_plan"], rerun_expected=t.cfg["rerun_block"],
                    kpi_diff=None, elapsed_s=None, budget_s=vr.BUDGET_S)
    assert _v(f) == (F, F, N, N, N)
    assert vr.root_console_problems(t.console, t.summary, t.guest, t.cfg["install_plan"], t.cfg["root_block_ids"]) == [
        "console: 0 root-step lines, exactly one is written by the root step"]


def test_root_step_control_a_root_plan_that_is_not_the_runbooks_runs_nothing_and_says_so(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch)
    t.cfg["root_block_ids"] = []
    t.write_cfg()
    t.run()
    root = json.loads((t.g / "root_blocks.json").read_text())
    assert root["blocks"] == [] and "root=yes blocks ['install-sys'] are not the ones user-data names" in root["error"]
    assert not t.out.exists() and t.console["root"][0]["error"] == root["error"]


@pytest.mark.parametrize("line, guest_rows, said", [
    ({"blocks": [{"id": "install-sys", "sha256": "S", "rc": 0}]}, [("install-sys", "S", 1)], "differ"),
    ({"blocks": [{"id": "install-sys", "sha256": "0" * 64, "rc": 0}]}, None, "the root step ran ['install-sys']"),
    ({"blocks": [{"id": "install-x", "sha256": "S", "rc": 0}]}, None, "the root step ran ['install-x']"),
    ({"blocks": []}, [], "stopped after [] without a failed block or an error"),
])
def test_root_console_control_a_line_that_is_not_the_plan_or_not_guest_json_is_a_problem(line, guest_rows, said):
    plan = [{"id": "install-sys", "sha256": "S"}, {"id": "install-one", "sha256": "T"}]
    rows = guest_rows if guest_rows is not None else [(b["id"], b["sha256"], b["rc"]) for b in line["blocks"]]
    guest = {"installs": [{"id": i, "sha256": h, "rc": rc, "as": "root"} for i, h, rc in rows]}
    p = vr.root_console_problems({"root": [line]}, {"attempt": 1}, guest, plan, ["install-sys"])
    assert any(said in x for x in p), p
    two = vr.root_console_problems({"root": [line, line]}, {"attempt": 1}, guest, plan, ["install-sys"])
    assert two == ["console: 2 root-step lines, exactly one is written by the root step"]


def test_guest_end_to_end_control_a_failing_install_block_stops_before_the_rerun_block(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch, second_block='test -e "$OUT/never"').run()
    assert [(i["id"], i["rc"]) for i in t.summary["installs"]] == [("install-sys", 0), ("install-one", 0), ("install-two", 1)]
    assert t.summary["section6"]["started"] is False and t.summary["cr_result"] is None
    assert t.problems == [] and t.rec is None and [c["as"] for c in t.guest["commands"]] == ["root", "edgefollow", "edgefollow"]
    assert _v(vr.facts_of(t.summary, t.guest, t.rec, install_plan=t.cfg["install_plan"], rerun_expected=t.cfg["rerun_block"],
                          kpi_diff=None, elapsed_s=None, budget_s=vr.BUDGET_S)) == (F, F, N, N, N)


def test_guest_end_to_end_control_a_changed_install_block_runs_nothing_and_still_reports(tmp_path, monkeypatch):
    t = _guest_world(tmp_path, monkeypatch)
    t.cfg["install_plan"][1]["sha256"] = "0" * 64
    t.write_cfg()
    t.run()
    assert t.summary["installs"] == [] and "install blocks" in t.summary["guest_error"]
    assert t.problems == [] and t.guest["commands"] == [] and not t.out.exists()
    assert "install blocks" in json.loads((t.g / "root_blocks.json").read_text())["error"]


# ---------------------------------------------------------------------------------------- the host run, with a fake QEMU
FAKE_VM = r'''
import hashlib, http.client, importlib.util, io, json, os, re, shlex, socket, subprocess, sys, tarfile, tempfile, time
from datetime import datetime, timezone
from pathlib import Path
argv = sys.argv[1:]
serial = Path(argv[argv.index("-serial") + 1][len("file:"):])
overlay = Path(re.match(r"file=([^,]+),", argv[argv.index("-drive") + 1]).group(1))
fwd = dict(re.findall(r"guestfwd=tcp:([0-9.]+:[0-9]+)-cmd:([^,]+)", argv[argv.index("-netdev") + 1]))
mode = os.environ["FAKE_VM_MODE"]
SKEW = -100.0 if mode == "late" else 0.0          # "late": the VM's clock is 100 s behind and it is slow to report
relays = []


def now():
    return time.time() + SKEW


def utc(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def conn(addr):
    """What slirp does for a guestfwd rule with cmd: the program from the netdev line, the connection on its fd 0/1."""
    a, b = socket.socketpair()
    relays.append(subprocess.Popen(shlex.split(fwd[addr]), stdin=b, stdout=b, stderr=b))
    b.close()
    return a


def req(method, path, body=None):
    c = http.client.HTTPConnection("10.0.2.100", 8080, timeout=10)
    c.sock = conn("10.0.2.100:8080")
    c.request(method, path, body=body, headers={"X-Guest-Time": f"{now():.3f}"})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, data


def get(name):
    st, data = req("GET", "/" + name)
    assert st == 200, (name, st)
    return data


def put(name, data):
    st, _ = req("PUT", "/up/" + name, data)
    return {"name": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "status": st}


def tunnel(target, first=b""):
    s = conn("10.0.2.101:3128")
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode() + first)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return s, head.split(b"\r\n", 1)[0].decode(), rest


def say(line):
    with open(serial, "a") as f:
        f.write(line + "\r\n")


say("[    0.0] Linux version fake")
ud = json.loads(get("user-data").decode().split("\n", 1)[1])
cfg = json.loads(ud["write_files"][1]["content"])
tar = get("code.tar")
get("guest.py")
ref = json.loads(get("reference.json"))
say("VMRERUN-PROGRESS harness-start")
plan = cfg["install_plan"]
sha = {p["id"]: p["sha256"] for p in plan}
root_ids = cfg["root_block_ids"]
edgefollow_plan = [p for p in plan if p["id"] not in root_ids]
root_rc = 100 if mode == "root-fails" else 0
root_rows = [{"id": i, "sha256": sha[i], "rc": root_rc} for i in root_ids]
say("VMRERUN-PROGRESS root-start")                 # the root step writes its own line: only root may write ttyS0
if mode != "root-console-missing":
    shown = [dict(r, rc=1) for r in root_rows] if mode == "root-console-differs" else root_rows
    say("VMRERUN-ROOT " + json.dumps({"blocks": shown, "not_run": [], "error": None}))
say("VMRERUN-PROGRESS root-done 0")
probes = {"on_path": {"bash": "/usr/bin/bash", "git": None if mode == "no-git" else "/usr/bin/git"}, "uid": 1000,
          "groups": ["edgefollow", "sudo"] if mode == "admin-group" else ["edgefollow"],
          "ipv6_addresses": [{"address": "::1", "interface": "lo"},
                             {"address": "fe80::5054:ff:fe12:3456", "interface": "enp0s2"}]
          + ([{"address": "fec0::5054:ff:fe12:3456", "interface": "enp0s2"}] if mode == "ipv6-addr" else [])}
if mode == "pass":                 # the proxy, through its relay: an allowed tunnel echoes, a lab port is refused
    s, st, got = tunnel("pypi.org:443", b"ping")
    while len(got) < 4:
        chunk = s.recv(16)
        if not chunk:
            break
        got += chunk
    s.close()
    s2, st2, _ = tunnel("127.0.0.1:8200")
    s2.close()
    s3, st3, _ = tunnel("deb.debian.org:443")      # apt's tunnel from the root block
    s3.close()
    probes["proxy_seen"] = [st, got.decode(), st2, st3]
d = Path(tempfile.mkdtemp())
with tarfile.open(fileobj=io.BytesIO(tar)) as t:
    t.extractall(d, filter="data")
spec = importlib.util.spec_from_file_location("clean_rerun", d / "estimed" / "clean_rerun.py")
cr = importlib.util.module_from_spec(spec); sys.modules["clean_rerun"] = cr; spec.loader.exec_module(cr)
text = (d / "estimed" / "RUNBOOK.md").read_text()
rb = cr.parse_runbook(text)
# the environments, written here by hand (not taken from vm_rerun): what the guest reports it gave each block
edgefollow = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/edgefollow", "LANG": "C.UTF-8", **rb.variables}
env = dict(edgefollow, HTTPS_PROXY=cfg["proxy"], https_proxy=cfg["proxy"])
root_env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
            **rb.variables, "HTTPS_PROXY": cfg["proxy"], "https_proxy": cfg["proxy"], "APT_CONFIG": cfg["apt_conf"]}
if mode == "env-leak":
    env["LEAKED"] = "from the guest's own environment"
if mode == "root-env-leak":
    root_env["PYTHONPATH"] = "/tmp"
ups = []
guest = {"commands": [], "installs": [], "install_not_run": [], "section6": {"started": False}, "probes": probes,
         "runbook_sha256": "0" * 64 if mode == "guest-other-runbook" else hashlib.sha256(text.encode()).hexdigest(),
         "install_env": env, "rerun_env": None,
         "root_step": {"uid": 0, "blocks": [dict(r, seconds=4.0) for r in root_rows], "not_run": [], "error": None,
                       "env": root_env, "cwd": "/root"}}
guest["installs"] = [dict(r, seconds=4.0, **{"as": "root"}) for r in root_rows]
guest["commands"] = [{"kind": "runbook", "as": "root", "id": r["id"], "sha256": r["sha256"], "rc": r["rc"]} for r in root_rows]
rerun = cfg["rerun_block"]
if mode == "root-fails":
    guest["install_not_run"] = [p["id"] for p in edgefollow_plan]
elif mode == "install-fails":
    guest["installs"].append({"id": edgefollow_plan[0]["id"], "sha256": edgefollow_plan[0]["sha256"], "rc": 1, "seconds": 2.0,
                              "as": "edgefollow"})
    guest["install_not_run"] = [p["id"] for p in edgefollow_plan[1:]]
    guest["commands"].append({"kind": "runbook", "as": "edgefollow", "id": edgefollow_plan[0]["id"], "sha256": edgefollow_plan[0]["sha256"]})
    ups.append(put("install_x.txt", b"ensurepip is not available"))
elif rerun is None:
    guest["installs"] += [{"id": p["id"], "sha256": p["sha256"], "rc": 0, "seconds": 1.0, "as": "edgefollow"} for p in edgefollow_plan]
    guest["commands"] += [{"kind": "runbook", "as": "edgefollow", "id": p["id"], "sha256": p["sha256"]} for p in edgefollow_plan]
    guest["section6"] = {"started": False, "why": "the runbook has no rerun block (`: runbook-step <id> phase=rerun`)"}
else:
    guest["installs"] += [{"id": p["id"], "sha256": p["sha256"], "rc": 0, "seconds": 1.0, "as": "edgefollow"} for p in edgefollow_plan]
    guest["commands"] += ([{"kind": "runbook", "as": "edgefollow", "id": p["id"], "sha256": p["sha256"]} for p in edgefollow_plan]
                          + [{"kind": "runbook", "as": "edgefollow", "phase": "rerun", "id": rerun["id"],
                              "sha256": rerun["sha256"]}])
    guest["rerun_env"] = dict(edgefollow)
    guest["section6"] = {"started": True, "id": rerun["id"], "sha256": rerun["sha256"], "rc": 1 if mode == "no-git" else 0,
                         "cwd": "/home/edgefollow"}
    if mode == "no-git":
        rec = {"result": "FAIL", "steps": [{"row": "the rerun ran to its end", "ok": False,
                                            "detail": "FileNotFoundError: [Errno 2] No such file or directory: 'git'"}],
               "controls": [], "kpi": {"equal_by_construction": {"rerun": {}, "differences": ["tests_passed: nothing"]},
                                       "timings": {"empty_directory_to_last_test_description_s": None}}}
    else:
        files = []
        for p in sorted(x for x in d.rglob("*") if x.is_file() and not x.relative_to(d).as_posix().startswith(".git/")):
            b = p.read_bytes()
            files.append({"path": p.relative_to(d).as_posix(), "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b),
                          "mode": f"{p.stat().st_mode & 0o777:o}"})
        commit = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        kpi = {k: v for k, v in ref["kpi"].items() if k != "timings_s"}
        if mode == "kpi-differs":
            kpi["tests_passed"]["TD_MEC_REG_03"]["numerator"] -= 1
        if mode == "other-code":
            files[0]["sha256"] = "0" * 64
        steps = cr.plan(rb)
        rows = ([{"row": f"step 1/2: bootstrap step {s.id} from the runbook exits 0", "ok": True}
                 for s in steps if s.phase == "bootstrap"]
                + [{"row": "step 2: after the runbook's bootstrap steps alone, every MN-CSE is registered both ways", "ok": True},
                   {"row": "step 3: all five test descriptions were run", "ok": True},
                   {"row": "the copy is unchanged after the tests (nothing was written into the code)", "ok": mode != "cr-fail"}]
                + [{"row": f"shutdown step {s.id} from the runbook exits 0", "ok": True} for s in steps if s.phase == "shutdown"]
                + [{"row": "after shutdown nothing of the copy's lab answers", "ok": True},
                   {"row": "step 2: the commands executed are the runbook's run steps, each once, in order, and nothing else",
                    "ok": True},
                   {"row": "after the controls nothing of the copy's lab answers", "ok": True}])
        controls = [{"row": n, "passed": False, "failed_as_it_must": True} for n in json.loads(os.environ["FAKE_CR_CONTROLS"])]
        if mode == "cr-fail":
            controls[1] = dict(controls[1], passed=True, failed_as_it_must=False)
        t_end = now()
        executed = [{"id": s.id, "sha256": s.sha256, "rc": 0, "seconds": 0.5, "started_utc": utc(t_end - 0.5)} for s in steps]
        if mode == "foreign-executed":
            executed.insert(3, {"id": "apt-get-install-git", "sha256": "9" * 64, "rc": 0, "seconds": 9.0,
                                "started_utc": utc(t_end)})
        rec = {"result": "FAIL" if mode == "cr-fail" else "PASS",
               "manifest": {"tree_sha256": cr._tree_sha(files), "commit": commit},
               "provenance": {"runbook_sha256": "0" * 64 if mode == "other-runbook" else hashlib.sha256(text.encode()).hexdigest(),
                              "plan": [{"id": s.id, "phase": s.phase, "td": s.td, "sha256": s.sha256} for s in steps]},
               "steps": rows, "controls": controls,
               "results": {s.td: {"ok": True, "declared": s.tests, "ran": s.tests, "passed": s.tests, "failed": 0, "error": 0,
                                  "skipped": 0, "problems": []} for s in steps if s.phase == "test"},
               "executed": executed,
               "kpi": {"equal_by_construction": {"rerun": kpi, "differences": []},
                       "timings": {"per_test_description": {},
                                   "empty_directory_to_last_test_description_s": 0.5 if mode == "late" else 3.0}}}
    if mode == "late":
        time.sleep(1.5)
    ups.append(put("cr_record.json", json.dumps(rec).encode()))
if mode == "extra-upload":
    put("planted.txt", b"not in guest.json's list")
guest["uploads"] = ups
gu = put("guest.json", json.dumps(guest).encode())
say("VMRERUN-PROGRESS guest-done 0")
summary = {"attempt": cfg["attempt"], "installs": guest["installs"], "install_not_run": guest["install_not_run"],
           "section6": guest["section6"], "guest_json_sha256": gu["sha256"]}
if mode != "no-summary":
    say("[  12.3] cloud-init[1]: VMRERUN-SUMMARY " + json.dumps(summary))
say("[  13.0] reboot: Power down")
if mode == "base-changed":
    b = overlay.parent / "base.qcow2"
    os.chmod(b, 0o600)
    b.write_bytes(b.read_bytes() + b"changed")
for p in relays:
    p.wait(timeout=20)
'''


@pytest.fixture
def host_world(tmp_path, monkeypatch):
    """A fixture repository holding the shipped RUNBOOK.md and clean_rerun.py, a fake base image with its SUMS line, a
    reference that ran the runbook's test commands, a 0700 private folder, fake qemu / qemu-img / systemd-run, and the
    proxy's upstream answered by a local echo server: every path inside tmp_path, nothing leaves 127.0.0.1."""
    r = tmp_path / "repo"
    files = {"estimed/RUNBOOK.md": RUNBOOK.read_bytes(),         # the shipped runbook as it is, its rerun block included
             "estimed/clean_rerun.py": (EST / "clean_rerun.py").read_bytes(),
             "mec011_appsupport/candidate.py": b"c\n", "mec010p2/candidate.py": b"d\n"}
    for rel, data in files.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_bytes(data)
    env = dict(os.environ, **GIT_ENV)
    for cmd in (["init", "-q", "--template=", "-b", "main"], ["add", "-A"],
                ["-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "fixture"]):
        subprocess.run(["git", "-C", str(r), *cmd], env=env, check=True, capture_output=True)
    head = subprocess.run(["git", "-C", str(r), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    rb = cr.parse_runbook(RUNBOOK.read_text())
    tests = [s for s in cr.plan(rb) if s.phase == "test"]
    ref = {"result": "PASS", "commit": head,
           "provenance": {"utc": "2026-11-19T00:00:00Z",
                          "plan": [{"id": s.id, "phase": s.phase, "td": s.td, "sha256": s.sha256} for s in cr.plan(rb)]},
           "kpi": {"tests_passed": {s.td: dict(cr.kpi_rate(s.tests, s.tests), ids=[f"t::{i}" for i in range(s.tests)])
                                    for s in tests},
                   "cse_registration_success": cr.kpi_rate(2, 2),
                   "resources_left": {s.td: {"cse-in": {"numerator": 0, "denominator": 5, "N": 5, "left": {}, "removed": {}}}
                                      for s in tests},
                   "timings_s": {s.td: 1.0 for s in tests}}}
    (tmp_path / "ref.json").write_text(json.dumps(ref))
    vm = tmp_path / "vmdir"
    vm.mkdir()
    (vm / IMAGE).write_bytes(b"abc")
    (vm / "SHA512SUMS").write_text(f"{SHA512_ABC}  {IMAGE}\n")
    (tmp_path / "fake_vm.py").write_text(FAKE_VM)
    qemu = tmp_path / "qemu-system-x86_64"
    qemu.write_text(f"#!/bin/sh\ntouch {tmp_path / 'qemu_started'}\nexec {sys.executable} -I -B {tmp_path / 'fake_vm.py'} \"$@\"\n")
    img = tmp_path / "qemu-img"
    img.write_text('#!/bin/sh\nprev=""\nfor a; do [ "$a" = "8G" ] && touch "$prev"; prev=$a; done\n')
    sr = tmp_path / "systemd-run"
    sr.write_text('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
    for p in (qemu, img, sr):
        p.chmod(0o755)
    stage = tmp_path / "shm"
    stage.mkdir()
    priv = tmp_path / "priv"
    priv.mkdir()
    os.chmod(priv, 0o700)
    for name, val in {"VM_DIR": vm, "BASE_IMAGE": vm / IMAGE, "SUMS_FILE": vm / "SHA512SUMS", "RUNS_DIR": vm / "runs",
                      "RESULTS_DIR": tmp_path / "sim", "STAGE_PARENT": stage, "MIN_FREE_PRIVATE_BYTES": 1}.items():
        monkeypatch.setattr(vr, name, val)
    tools = {"qemu": str(qemu), "qemu_img": str(img), "systemd_run": str(sr)}
    monkeypatch.setattr(vr, "preflight", lambda dry_run: dict(tools))
    monkeypatch.setenv("FAKE_CR_CONTROLS", json.dumps(CR_CONTROLS))
    echo = _Echo()
    calls = []

    def fake_connect(host, port, timeout=15.0):
        calls.append((host, port))
        return socket.create_connection(("127.0.0.1", echo.port), timeout=timeout), "192.0.2.10"
    monkeypatch.setattr(vr, "connect_public", fake_connect)

    def run(mode, ref_over=None, refused=False, attempt=1, previous=None, why=None, private_dir=None):
        monkeypatch.setenv("FAKE_VM_MODE", mode)
        rp = tmp_path / "ref.json"
        if ref_over:
            rp = tmp_path / "ref_planted.json"
            rp.write_text(json.dumps(dict(ref, **ref_over)))
        args = vr.argparse.Namespace(attempt=attempt, repo=str(r), reference=str(rp), previous=previous, why=why,
                                     dry_run=False, private_dir=private_dir or str(priv))
        if refused:
            with pytest.raises(vr.VmError) as e:
                vr.cmd_run(args)
            return str(e.value)
        rc = vr.cmd_run(args)
        recs = sorted((tmp_path / "sim").glob("vm_rerun_*.json"))
        assert len(recs) == 1, recs
        return rc, json.loads(recs[0].read_text())
    def commit_runbook(text):
        (r / "estimed" / "RUNBOOK.md").write_text(text)
        for cmd in (["add", "-A"], ["-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "runbook"]):
            subprocess.run(["git", "-C", str(r), *cmd], env=env, check=True, capture_output=True)
    run.tmp, run.calls, run.priv, run.vm, run.tools, run.repo = tmp_path, calls, priv, vm, tools, r
    run.commit_runbook = commit_runbook
    yield run
    echo.stop()


def test_host_run_with_a_fake_vm_that_passes_makes_a_five_pass_record(host_world):
    rc, rec = host_world("pass")
    assert [s["verdict"] for s in rec["obs03_steps"]] == [P] * 5, rec["obs03_steps"]
    assert rc == 0 and rec["result"] == P and rec["integrity_problems"] == []
    assert rec["controls"] and not any(c["passed"] for c in rec["controls"])
    assert rec["kpi"]["differences_recomputed_here"] == [] and rec["base_image"]["unchanged"] is True
    assert rec["clean_rerun_in_vm"]["verdict_problems_read_here"] == []
    assert rec["clean_rerun_in_vm"]["executed_problems_checked_here"] == []
    assert rec["vm"]["watch"]["powered_off_by_itself"] is True and rec["harness"]["steps"] == vr.HARNESS_STEPS
    assert {b["phase"] for b in rec["blocks"]} == {"install", "rerun", "bootstrap", "test", "shutdown"}
    assert set(rec["tests_per_td"]) == set(TDS) and rec["does_not_show"] == vr.NOT_SHOWN
    assert not list(Path(vr.STAGE_PARENT).iterdir()), "the tmpfs stage is removed"
    assert rec["runbook"]["blocks_needing_root"] == [{"id": "install-system-packages", "phase": "install",
                                                      "marker_root": True, "names": []}]
    assert rec["budget"]["vm_rerun_committed_at_head"] is False
    root = rec["runbook"]["root_blocks"]
    assert [(b["id"], b["rc"], b["rc_in_guest_json"], b["as"], b["ran"]) for b in root] == [
        ("install-system-packages", 0, 0, "root", True)], root
    body = RERUN_HOST.split("```text\n", 1)[1].split("\n```", 1)[0]
    assert rec["runbook"]["rerun_block"] == {"id": "rerun", "sha256": _sha(body.encode()), "text": body}
    assert [(b["id"], b["as"]) for b in rec["blocks"] if b["phase"] in ("install", "rerun")] == [
        ("install-system-packages", "root"), ("install-cse-environment", "edgefollow"), ("install-test-environment", "edgefollow"),
        ("rerun", "edgefollow")]


def test_host_run_network_is_restrict_on_with_two_guestfwd_rules_and_the_proxy_says_what_it_did(host_world):
    rc, rec = host_world("pass")
    net = rec["vm"]["network"]
    netdev = rec["vm"]["argv"][rec["vm"]["argv"].index("-netdev") + 1]
    assert netdev == net["netdev"] and netdev.split(",")[:4] == ["user", "id=n0", "restrict=on", "ipv6=off"]
    assert [x.split("-cmd:")[0] for x in netdev.split(",")[4:]] == ["guestfwd=tcp:10.0.2.100:8080",
                                                                    "guestfwd=tcp:10.0.2.101:3128"]
    assert net["restrict"] is True and net["ipv6"] is False
    assert [g["in_vm"] for g in net["guestfwd"]] == ["10.0.2.100:8080", "10.0.2.101:3128"]
    closed = net["ipv6_closed"]
    assert "every IPv6 frame" in closed["unreachable_over_ipv6"] and "in6_enabled=0" in closed["how_shown"]
    assert "Control" in closed["how_shown"] and "QEMU itself was not run" in closed["not_shown"]
    assert net["proxy"]["allow"] == ["deb.debian.org:443", "files.pythonhosted.org:443", "pypi.org:443"]
    assert rec["guest"]["probes"]["proxy_seen"] == ["HTTP/1.1 200 Connection established", "ping", "HTTP/1.1 403 Forbidden",
                                                    "HTTP/1.1 200 Connection established"]
    log = net["proxy"]["log"]
    assert [(e["target"], e["status"]) for e in log if e["target"] in ("pypi.org:443", "127.0.0.1:8200")][:2] == [
        ("pypi.org:443", 200), ("127.0.0.1:8200", 403)]
    assert host_world.calls == [("pypi.org", 443), ("deb.debian.org", 443)], \
        "the refused requests, live controls included, connected to nothing"
    assert {c["row"] for c in rec["controls"] if "the proxy opened" in c["row"]} and \
        not any(c["passed"] for c in rec["controls"])
    assert net["given_to"] == {"install blocks": {"HTTPS_PROXY": PROXY_URL, "https_proxy": PROXY_URL},
                               "root=yes install blocks": {"HTTPS_PROXY": PROXY_URL, "https_proxy": PROXY_URL,
                                                           "APT_CONFIG": "/var/lib/vmrerun/apt-proxy.conf"},
                               "apt": "only in the root=yes blocks, through APT_CONFIG: 'Acquire::http::Proxy "
                                      "\"http://10.0.2.101:3128\";\\nAcquire::https::Proxy \"http://10.0.2.101:3128\";\\n'",
                               "rerun block": "nothing"}
    assert rec["harness"]["install_env_expected"]["HTTPS_PROXY"] == PROXY_URL and "proxy" in rec["harness"]["steps"]


def test_host_run_keeps_the_disk_images_private_and_copies_the_evidence_to_the_ntfs_folder(host_world):
    rc, rec = host_world("pass")
    priv = Path(rec["files"]["private_run_dir"])
    assert priv.parent == host_world.priv and priv.stat().st_mode & 0o777 == 0o700
    assert rec["base_image"]["path"] == str(priv / "base.qcow2") and rec["base_image"]["sha512"] == SHA512_ABC
    assert rec["base_image"]["sha512_after"] == SHA512_ABC and (priv / "base.qcow2").stat().st_mode & 0o777 == 0o400
    run_dir = Path(rec["files"]["evidence_copy"])
    assert run_dir.parent == host_world.vm / "runs"
    copied = sorted(p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file())
    assert "record.json" in copied and "results/guest.json" in copied and "serial.log" in copied
    assert "evidence.json" in copied and "base.qcow2" not in copied and "overlay.qcow2" not in copied
    assert (run_dir / "record.json").read_bytes() == (priv / "record.json").read_bytes()


def test_host_run_control_a_vm_whose_first_install_block_fails_makes_a_failed_record(host_world):
    rc, rec = host_world("install-fails")
    assert rc == 1 and rec["result"] == F
    assert [s["verdict"] for s in rec["obs03_steps"]] == [F, F, N, N, N]
    assert "install-cse-environment exited 1" in rec["obs03_steps"][0]["why"]
    assert rec["integrity_problems"] == [] and not any(c["passed"] for c in rec["controls"])


def test_host_run_control_a_vm_with_one_kpi_off_fails_step_4_only(host_world):
    rc, rec = host_world("kpi-differs")
    assert rc == 1 and [s["verdict"] for s in rec["obs03_steps"]] == [P, P, P, F, P]
    assert any(d.startswith("tests_passed TD_MEC_REG_03") for d in rec["kpi"]["differences_recomputed_here"])


def test_host_run_control_a_vm_that_ran_other_code_than_was_delivered_is_an_integrity_failure(host_world):
    rc, rec = host_world("other-code")
    assert rc == 1 and rec["result"] == F
    assert any("other code than the delivered tarball" in p for p in rec["integrity_problems"])


def test_host_run_control_a_failing_clean_rerun_record_in_the_vm_gives_fail(host_world):
    rc, rec = host_world("cr-fail")
    assert rc == 1 and rec["result"] == F and rec["clean_rerun_in_vm"]["result"] == "FAIL"
    assert [s["verdict"] for s in rec["obs03_steps"]] == [P, P, P, F, P]
    vp = rec["clean_rerun_in_vm"]["verdict_problems_read_here"]
    assert "clean_rerun.py in the VM says 'FAIL', not PASS" in vp
    assert "post-test row false: the copy is unchanged after the tests (nothing was written into the code)" in vp
    assert "control did not fail as it must: CONTROL (must FAIL) a command that is not in the runbook was executed" in vp


def test_host_run_control_a_foreign_command_in_the_vms_executed_log_fails_step_2(host_world):
    rc, rec = host_world("foreign-executed")
    assert rc == 1 and rec["obs03_steps"][1]["verdict"] == F
    assert "not in the runbook: apt-get-install-git" in rec["obs03_steps"][1]["why"]
    assert "apt-get-install-git" in [b["id"] for b in rec["blocks"]]


def test_host_run_control_another_runbook_in_the_vms_record_is_an_integrity_failure(host_world):
    rc, rec = host_world("other-runbook")
    assert rc == 1 and "the VM's clean_rerun read another RUNBOOK.md than the delivered one" in rec["integrity_problems"]


def test_host_run_control_another_runbook_read_by_the_guest_is_an_integrity_failure(host_world):
    rc, rec = host_world("guest-other-runbook")
    assert rc == 1 and "the guest read another RUNBOOK.md than the delivered one" in rec["integrity_problems"]


def test_host_run_control_step_5_uses_this_hosts_receipt_time_not_the_vms_clock(host_world, monkeypatch):
    monkeypatch.setattr(vr, "BUDGET_S", 1.0)
    rc, rec = host_world("late")
    b = rec["budget"]
    assert rec["obs03_steps"][4]["verdict"] == F and b["elapsed_s"] > 1.0 and b["clean_rerun_in_vm_t_last_s"] == 0.5
    put_cr = [e for e in rec["harness"]["server_log"] if e.get("name") == "cr_record.json"]
    assert len(put_cr) == 1 and b["elapsed_s"] >= 1.5
    assert b["guest_clock_offset"]["median_s"] < -99, "the VM's clock was 100 s behind"
    assert 0 <= b["guest_claim_s"] <= b["elapsed_s"] + 2, "the VM's claim, moved onto this host's clock, is consistent"


def test_host_run_step_5_in_a_good_run_is_within_the_budget_on_this_hosts_clock(host_world):
    rc, rec = host_world("pass")
    b = rec["budget"]
    assert 0 < b["elapsed_s"] <= b["value_s"] == 1800.0 and b["guest_clock_offset"]["n"] >= 2
    assert 0 <= b["guest_claim_s"] <= b["elapsed_s"] + 2
    assert b["console_guest_done_s"] is not None and b["elapsed_s"] <= b["console_guest_done_s"] + 1


def test_host_run_control_a_vm_that_sends_no_summary_is_a_fail_not_a_not_run(host_world):
    rc, rec = host_world("no-summary")
    assert rc == 1 and [s["verdict"] for s in rec["obs03_steps"]] == [F] * 5
    assert "VMRERUN-PROGRESS guest-done 0" in rec["obs03_steps"][0]["why"]


def test_host_run_control_an_upload_the_guest_did_not_list_is_an_integrity_failure(host_world):
    rc, rec = host_world("extra-upload")
    assert rc == 1 and "uploads: extra: planted.txt" in rec["integrity_problems"]


def test_host_run_control_a_base_copy_changed_during_the_run_is_an_integrity_failure(host_world):
    rc, rec = host_world("base-changed")
    assert rc == 1 and "the base image copy changed during the run" in rec["integrity_problems"]
    assert rec["base_image"]["unchanged"] is False


def test_host_run_control_git_missing_in_the_vm_gives_one_clear_reason_and_no_false_code_problem(host_world):
    rc, rec = host_world("no-git")
    assert rc == 1 and [s["verdict"] for s in rec["obs03_steps"]] == [F, F, N, N, N]
    assert "not on the VM's PATH: git" in rec["obs03_steps"][0]["why"]
    assert "No such file or directory: 'git'" in rec["obs03_steps"][0]["why"]
    assert rec["integrity_problems"] == [], "no 'other code' or 'another RUNBOOK.md' problem from a record that stopped early"


def test_host_run_control_install_blocks_given_another_environment_is_an_integrity_failure(host_world):
    rc, rec = host_world("env-leak")
    assert rc == 1 and any("another environment than the harness lists: extra ['LEAKED']" in p
                           for p in rec["integrity_problems"])


def test_host_run_control_edgefollow_with_an_admin_group_in_the_vm_is_an_integrity_failure(host_world):
    rc, rec = host_world("admin-group")
    assert rc == 1 and "the runbook's user in the VM has root or an admin group: ['sudo']" in rec["integrity_problems"]


def test_host_run_control_a_root_block_that_fails_stops_the_rest_and_the_record_lists_its_exit_code(host_world):
    rc, rec = host_world("root-fails")
    assert rc == 1 and [s["verdict"] for s in rec["obs03_steps"]] == [F, F, N, N, N]
    assert "install block install-system-packages exited 100" in rec["obs03_steps"][0]["why"]
    assert [(b["id"], b["rc"], b["ran"]) for b in rec["runbook"]["root_blocks"]] == [("install-system-packages", 100, True)]
    assert rec["integrity_problems"] == [], rec["integrity_problems"]


def test_host_run_control_guest_json_that_says_a_root_block_passed_when_root_wrote_otherwise_is_an_integrity_failure(
        host_world):
    rc, rec = host_world("root-console-differs")
    assert rc == 1 and rec["result"] == F
    assert any("on the console (written by root) and in guest.json (written by edgefollow) differ" in p
               for p in rec["integrity_problems"]), rec["integrity_problems"]
    assert rec["runbook"]["root_blocks"][0]["rc"] == 1 and rec["runbook"]["root_blocks"][0]["rc_in_guest_json"] == 0


def test_host_run_control_no_root_line_on_the_console_is_an_integrity_failure(host_world):
    rc, rec = host_world("root-console-missing")
    assert rc == 1 and "console: 0 root-step lines, exactly one is written by the root step" in rec["integrity_problems"]
    assert rec["runbook"]["root_blocks"][0]["ran"] is False


def test_host_run_control_root_blocks_given_another_environment_is_an_integrity_failure(host_world):
    rc, rec = host_world("root-env-leak")
    assert rc == 1 and any(p.startswith("the root blocks got another environment than the harness lists: extra "
                                        "['PYTHONPATH']") for p in rec["integrity_problems"])


def test_host_run_control_an_ipv6_address_in_the_vm_is_an_integrity_failure(host_world):
    rc, rec = host_world("ipv6-addr")
    assert rc == 1 and any("fec0::5054:ff:fe12:3456" in p and "ipv6=off did not take" in p
                           for p in rec["integrity_problems"])


def test_host_run_control_a_runbook_without_a_rerun_block_stops_after_the_install_blocks(host_world):
    host_world.commit_runbook(_shipped_with_rerun(""))             # the shipped runbook with its rerun block taken out
    rc, rec = host_world("pass")
    assert rc == 1 and rec["runbook"]["rerun_block"] is None
    assert [s["verdict"] for s in rec["obs03_steps"]] == [F, F, N, N, N]
    assert "the runbook's rerun block was not run: the runbook has no rerun block" in rec["obs03_steps"][0]["why"]
    assert rec["integrity_problems"] == []


def test_host_run_attempt_2_runs_the_changed_rerun_block_and_records_its_sha(host_world, tmp_path):
    prev = tmp_path / "attempt1.json"
    prev.write_text(json.dumps({"kind": "vm_rerun", "attempt": 1, "result": "FAIL", "obs03_steps": [
        {"step": n, "verdict": F, "why": "x"} for n in range(1, 6)]}))
    assert (host_world.repo / "estimed" / "RUNBOOK.md").read_text() == RUNBOOK.read_text(), "HEAD holds the shipped one"
    changed = RERUN_HOST.replace('cd "$ROOT" && "$PY" -B estimed/clean_rerun.py',
                                 'cd "$ROOT" && test -d "$ROOT/estimed" && "$PY" -B estimed/clean_rerun.py')
    assert changed != RERUN_HOST
    new = _shipped_with_rerun(changed)                              # the shipped block replaced, not a second one added
    assert new.count("test -d \"$ROOT/estimed\"") == 1 and new.count("phase=rerun &&") == 1
    (host_world.repo / "estimed" / "RUNBOOK.md").write_text(new)
    rc, rec = host_world("pass", attempt=2, previous=str(prev), why="attempt 1: the rerun block did not cd")
    body = new.split("```text\n: runbook-step rerun", 1)[1].split("\n```", 1)[0]
    want = _sha((": runbook-step rerun" + body).encode())
    assert want != RERUN_BODY_SHA256, "the block that runs is the changed one, not the one HEAD ships"
    assert rec["runbook"]["rerun_block"]["sha256"] == want and rec["runbook"]["diff_from_head"]
    assert [c["sha256"] for c in rec["guest"]["commands"] if c.get("phase") == "rerun"] == [want]
    assert rc == 0 and rec["obs03_steps"][1]["verdict"] == P, rec["obs03_steps"][1]


def test_host_run_control_a_relative_private_folder_is_refused_before_anything(host_world, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert "is not an absolute path: refused" in host_world("pass", refused=True, private_dir="priv")
    assert not (host_world.vm / "runs").exists() and not (host_world.tmp / "qemu_started").exists()


def test_host_run_control_a_reference_that_did_not_pass_is_refused(host_world):
    why = host_world("pass", ref_over={"result": "FAIL"}, refused=True)
    assert "the reference did not pass" in why and not (host_world.tmp / "qemu_started").exists()


@pytest.mark.parametrize("mangle, said", [
    (lambda a: a + ["-virtfs", "local,path=/home/edgefollow,mount_tag=h,security_model=none"], "not allowed: -virtfs"),
    (lambda a: [x.replace("restrict=on", "restrict=off") for x in a], "netdev line"),
    (lambda a: [x + ",hostfwd=tcp:127.0.0.1:2222-:22" if x.startswith("user,") else x for x in a], "netdev line"),
])
def test_host_run_control_a_qemu_line_that_differs_is_refused_and_qemu_is_never_started(host_world, monkeypatch,
                                                                                         mangle, said):
    real = vr.qemu_argv
    monkeypatch.setattr(vr, "qemu_argv", lambda *a, **k: mangle(real(*a, **k)))
    why = host_world("pass", refused=True)
    assert said in why and not (host_world.tmp / "qemu_started").exists()


def test_host_run_control_no_memory_capped_scope_is_refused_and_qemu_is_never_started(host_world, monkeypatch):
    monkeypatch.setattr(vr, "preflight", lambda dry_run: dict(host_world.tools, systemd_run=None))
    assert "no memory-capped scope" in host_world("pass", refused=True)
    assert not (host_world.tmp / "qemu_started").exists()


def test_host_run_control_a_private_folder_that_is_not_0700_is_refused_before_anything(host_world):
    os.chmod(host_world.priv, 0o755)
    assert "mode 755, not 700" in host_world("pass", refused=True)
    assert not (host_world.vm / "runs").exists() and not (host_world.tmp / "qemu_started").exists()


# ---------------------------------------------------------------------------------------- watching QEMU, preflight
def test_watch_kills_qemu_at_the_wall_clock_limit(tmp_path):
    p = subprocess.Popen(["sleep", "5"], start_new_session=True)
    t0 = time.time()
    w = vr.watch(p, tmp_path / "serial.log", t0, 0.5, 60.0)
    assert w["timed_out"] is True and w["killed"].startswith("wall-clock limit") and w["powered_off_by_itself"] is False
    assert time.time() - t0 < 4 and p.poll() is not None


def test_watch_kills_a_vm_that_does_not_power_off_after_its_summary(tmp_path):
    (tmp_path / "serial.log").write_text("VMRERUN-SUMMARY {\"attempt\": 1}\n")
    p = subprocess.Popen(["sleep", "5"], start_new_session=True)
    w = vr.watch(p, tmp_path / "serial.log", time.time(), 60.0, 0.5)
    assert w["killed"].startswith("no power-off after the summary") and w["timed_out"] is False
    assert [x["line"] for x in w["lines"]] == ["VMRERUN-SUMMARY {\"attempt\": 1}"]


def _preflight_world(monkeypatch, which=None, cap_works=True):
    monkeypatch.setattr(vr.shutil, "which", which or (lambda name, *a, **k: f"/fake/{name}"))
    monkeypatch.setattr(vr.os, "access", lambda p, m: True)
    monkeypatch.setattr(vr, "_meminfo", lambda k: 64 << 20)
    monkeypatch.setattr(vr.shutil, "disk_usage", lambda p: types.SimpleNamespace(free=1 << 40))
    monkeypatch.setattr(vr, "_memory_cap_works", lambda sr: cap_works)


def test_preflight_control_qemu_is_refused_when_the_memory_cap_does_not_work(monkeypatch):
    _preflight_world(monkeypatch, cap_works=False)
    with pytest.raises(vr.VmError, match="no QEMU runs without the cap"):
        vr.preflight(False)


def test_preflight_control_qemu_is_refused_without_systemd_run(monkeypatch):
    _preflight_world(monkeypatch, which=lambda name, *a, **k: None if name == "systemd-run" else f"/fake/{name}")
    with pytest.raises(vr.VmError, match="no QEMU runs without the cap"):
        vr.preflight(False)


def test_memory_cap_probe_reads_the_exit_status_of_systemd_run(tmp_path):
    good, bad = tmp_path / "good", tmp_path / "bad"
    good.write_text("#!/bin/sh\nexit 0\n")
    bad.write_text("#!/bin/sh\nexit 1\n")
    for p in (good, bad):
        p.chmod(0o755)
    assert vr._memory_cap_works(str(good)) is True and vr._memory_cap_works(str(bad)) is False
    assert vr._memory_cap_works(str(tmp_path / "missing")) is False


# ---------------------------------------------------------------------------------------- code delivery
GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@x",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@x", "GIT_AUTHOR_DATE": "2026-11-19T12:00:00+00:00",
           "GIT_COMMITTER_DATE": "2026-11-19T12:00:00+00:00"}
FIX = {"estimed/RUNBOOK.md": b"rb v1\n", "estimed/run.sh": b"#!/bin/sh\n", "estimed/private_lab/big.bin": b"x" * 10,
       "mec011_appsupport/candidate.py": b"c\n", "mec010p2/candidate.py": b"d\n", "other/z.py": b"z\n"}


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    for rel, data in FIX.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_bytes(data)
    (r / "estimed" / "run.sh").chmod(0o755)
    env = dict(os.environ, **GIT_ENV)
    for cmd in (["init", "-q", "--template=", "-b", "main"], ["add", "-A"],
                ["-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "fixture"]):
        subprocess.run(["git", "-C", str(r), *cmd], env=env, check=True, capture_output=True)
    return r


def _members(tar):
    with tarfile.open(tar) as t:
        return {m.name: m for m in t.getmembers()}, {m.name: t.extractfile(m).read() for m in t.getmembers() if m.isfile()}


ROOT_SET = ["estimed/RUNBOOK.md", "estimed/run.sh", "mec010p2/candidate.py", "mec011_appsupport/candidate.py"]


def test_code_tarball_is_head_of_the_root_set_as_a_one_commit_git_checkout(repo, tmp_path):
    (repo / "estimed" / "untracked.py").write_bytes(b"u")
    code = vr.build_code(repo, tmp_path / "stage", include=())
    members, data = _members(code["tar"])
    files = sorted(n for n in data if not n.startswith(".git/"))
    assert files == ROOT_SET
    assert any(n.startswith(".git/objects/") for n in members) and ".git/HEAD" in members
    assert all(data[p] == FIX[p] for p in ROOT_SET)
    assert members["estimed/run.sh"].mode & 0o777 == 0o755 and members["estimed/RUNBOOK.md"].mode & 0o777 == 0o644
    assert code["differences_from_head"] == [{"path": "estimed/untracked.py", "status": "untracked", "delivered": False}]
    assert code["sha256"] == _sha(Path(code["tar"]).read_bytes()) and code["file_count"] == 4
    want_tree = hashlib.sha256("".join(f"{_sha(FIX[p])}  {'755' if p.endswith('.sh') else '644'}  {p}\n"
                                       for p in ROOT_SET).encode()).hexdigest()
    assert code["tree_sha256"] == want_tree, "the tree hash clean_rerun's manifest will show inside the VM"
    out = tmp_path / "x"
    out.mkdir()
    with tarfile.open(code["tar"]) as t:
        t.extractall(out, filter="data")
    ls = subprocess.run(["git", "-C", str(out), "ls-files"], capture_output=True, text=True, env=dict(os.environ, **GIT_ENV))
    assert ls.stdout.split() == ROOT_SET, "inside the VM, git lists exactly the delivered files"
    st = subprocess.run(["git", "-C", str(out), "status", "--porcelain"], capture_output=True, text=True,
                        env=dict(os.environ, **GIT_ENV))
    assert st.stdout == "" and code["synthetic_commit"] == subprocess.run(
        ["git", "-C", str(out), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def test_code_tarball_for_attempt_2_carries_the_changed_runbook_and_says_so(repo, tmp_path):
    (repo / "estimed" / "RUNBOOK.md").write_bytes(b"rb v2\n")
    code = vr.build_code(repo, tmp_path / "stage", include=("estimed/RUNBOOK.md",))
    _, data = _members(code["tar"])
    assert data["estimed/RUNBOOK.md"] == b"rb v2\n"
    assert code["differences_from_head"] == [{"path": "estimed/RUNBOOK.md", "status": "modified", "delivered": True}]
    assert code["delivered_from_working_tree"] == ["estimed/RUNBOOK.md"]


def test_code_tarball_control_a_change_not_named_is_not_delivered(repo, tmp_path):
    (repo / "estimed" / "run.sh").write_bytes(b"#!/bin/sh\necho changed\n")
    code = vr.build_code(repo, tmp_path / "stage", include=("estimed/RUNBOOK.md",))
    _, data = _members(code["tar"])
    assert data["estimed/run.sh"] == FIX["estimed/run.sh"]
    assert code["differences_from_head"] == [{"path": "estimed/run.sh", "status": "modified", "delivered": False}]
    assert code["delivered_from_working_tree"] == []


def test_code_tarball_control_a_stage_that_is_not_new_is_refused(repo, tmp_path):
    (tmp_path / "stage").mkdir()
    (tmp_path / "stage" / "old").write_text("x")
    with pytest.raises(vr.VmError):
        vr.build_code(repo, tmp_path / "stage", include=())


def test_code_tarball_control_a_stage_that_does_not_keep_file_modes_is_refused(repo, tmp_path, monkeypatch):
    # the data disk is NTFS through fuse: every file reads 777, so git would record 100755 for HEAD's 100644 files
    monkeypatch.setattr(vr.Path, "chmod", lambda self, mode, **kw: os.chmod(self, 0o777))
    with pytest.raises(vr.VmError, match="file modes"):
        vr.build_code(repo, tmp_path / "stage", include=())


def test_code_tarball_of_this_repository_holds_the_runbooks_root_set_without_private_lab(tmp_path):
    code = vr.build_code(EST.parent, tmp_path / "stage", include=())
    _, data = _members(code["tar"])
    files = sorted(n for n in data if not n.startswith(".git/"))
    assert files and not [f for f in files if f.startswith("estimed/private_lab/")]
    assert {f.split("/")[0] for f in files} == {"estimed", "mec011_appsupport", "mec010p2"}
    assert {"estimed/RUNBOOK.md", "estimed/clean_rerun.py", "estimed/run_topology.sh", "mec011_appsupport/candidate.py",
            "mec010p2/candidate.py"} <= set(files)
    assert "estimed/vm_rerun.py" not in files or "estimed/vm_rerun.py" not in [d["path"] for d in code["differences_from_head"]]


# ---------------------------------------------------------------------------------------- what is written down before a run
def test_budget_is_fixed_at_1800_s_with_its_reason_written_before_the_first_vm_run():
    # pinned here: a change to the budget after a VM run shows as a failing test (commit vm_rerun.py before attempt 1)
    assert vr.BUDGET_S == 1800.0 and vr.BUDGET_REASON == BUDGET_REASON_TEXT
    assert vr.WALL_LIMIT_S > vr.BUDGET_S
    assert (vr.VCPUS, vr.MEM_MB, vr.MEMORY_CAP) == (2, 4096, "5G")


def test_the_record_says_what_it_does_not_show():
    text = " ".join(vr.NOT_SHOWN)
    for words in ("one VM type", "Debian 13", "KVM on this PC", "unpinned", "not a human", "not signature-checked",
                  "restrict=on", "upper bound", "unattended-upgrades", "systemd-timesyncd", "405",
                  "the rerun block ran from edgefollow's home directory, exactly as written", "re-hashed after the run",
                  "ipv6=off", "in6_enabled=0", "runs as edgefollow, the same user as the code under test",
                  "forge a consistent PASS", "https://deb.debian.org", "DPkg::Lock::Timeout",
                  "the harness alone recognises it"):
        assert words in text, words


# ---------------------------------------------------------------------------------------- planted faults (run by hand)
def _junit_counts(xml: Path) -> dict:
    import xml.etree.ElementTree as ET
    if not xml.is_file():
        return {"tests": 0, "failed": 0, "errors": 1}
    root = ET.parse(xml).getroot()
    cases = list(root.iter("testcase"))
    bad = [c.get("name") for c in cases if any(x.tag in ("failure", "error") for x in c)]
    errors = sum(int(s.get("errors", 0)) for s in root.iter("testsuite")) if not cases else 0
    return {"tests": len(cases), "failed": len(bad), "errors": errors, "names": bad}


def _run_suite(module: Path | None, xml: Path) -> dict:
    env = dict(os.environ)
    env.pop("VM_RERUN_UNDER_TEST", None)
    if module is not None:
        env["VM_RERUN_UNDER_TEST"] = str(module)
    tmp = xml.parent / f"{xml.stem}.tmp"            # pytest's temporary files next to the junit file, removed after
    p = subprocess.run([sys.executable, "-I", "-B", "-m", "pytest", "-p", "no:cacheprovider", "-q", str(Path(__file__)),
                        f"--junitxml={xml}", f"--basetemp={tmp}"], env=env, capture_output=True, text=True,
                       cwd=str(EST.parent), timeout=1800)
    (xml.parent / f"{xml.stem}.out.txt").write_text(p.stdout[-8000:] + p.stderr[-2000:])
    shutil.rmtree(tmp, ignore_errors=True)
    return _junit_counts(xml)


# (label, text in vm_rerun.py that occurs exactly once, what it is replaced with)
FAULTS = [                                                    # the builder's 19 (number 9 re-anchored to the netdev line)
    ("server takes a name with a path component", 'if not NAME_RE.fullmatch(name) or ".." in name:', "if False:"),
    ("server has no size cap", "if n > self.server.cap:", "if n > self.server.cap * 1000:"),
    ("server overwrites an earlier upload", "os.O_WRONLY | os.O_CREAT | os.O_EXCL", "os.O_WRONLY | os.O_CREAT"),
    ("server binds any address", 'if host != "127.0.0.1":', "if False:"),
    ("server answers DELETE", "do_DELETE = _refuse", "do_DELETE = do_GET"),
    ("base image digest not compared", "if got != want:", "if False:"),
    ("user-data unlocks the password", '"lock_passwd": True, "shell"', '"lock_passwd": False, "shell"'),
    ("user-data audit ignores password fields", "if _SECRETISH.search(str(k)) and k not in SAFE_KEYS:", "if False:"),
    ("QEMU forwards a host port", 'NETDEV_HEAD = ["user", f"id={NETDEV_ID}", "restrict=on", "ipv6=off"]',
     'NETDEV_HEAD = ["user", f"id={NETDEV_ID}", "restrict=on", "ipv6=off", "hostfwd=tcp:127.0.0.1:2222-:22"]'),
    ("NOT-RUN counts as PASS overall", 'all(s["verdict"] == PASS for s in steps)',
     'all(s["verdict"] in (PASS, NOT_RUN) for s in steps)'),
    ("budget compared the wrong way", "elif elapsed <= f[\"budget_s\"]:", "elif elapsed >= f[\"budget_s\"]:"),
    ("KPI difference ignored", 'kpi_ok = f["kpi_diff"] == []', "kpi_ok = True"),
    ("console takes the first of two summaries", "if len(found) > 1:", "if len(found) > 99:"),
    ("upload checksum not compared", "if _sha_file(p) != u.get(\"sha256\") or", "if False and _sha_file(p) != u.get(\"sha256\") or"),
    ("guest log foreign commands ignored", "foreign.append(c)", "pass"),
    ("install plan not checked", "if got != list(plan):", "if False:"),
    ("VM code not compared with the delivered tarball",
     'if m.get("tree_sha256") != code["tree_sha256"] or m.get("commit") != code["synthetic_commit"]:', "if False:"),
    ("stage that loses file modes accepted", "if probe.stat().st_mode & 0o777 != 0o644:", "if False:"),
    ("section 6 run after a failed install block",                # re-anchored: the rerun block after the installs
     'if all_done and all(d["rc"] == 0 for d in all_done) and not doc["install_not_run"]:', "if all_done:"),
]
REVIEWER_FAULTS = [                                           # the independent reviewer's 16, anchors unchanged
    ("N1 run.sh hides a command in an assignment line", "say harness-start  # harness:progress\n",
     "FIX=$(ln${IFS}-sf${IFS}/bin/true${IFS}/usr/local/bin/git)\nsay harness-start  # harness:progress\n"),
    ("N2 QEMU shares the host home with the VM (-virtfs)", '"-device", "virtio-rng-pci"]',
     '"-device", "virtio-rng-pci", "-virtfs", "local,path=/home/edgefollow,mount_tag=h,security_model=none"]'),
    ("N3 step 5 timed from clean_rerun's own start", "elapsed_s=elapsed, budget_s=BUDGET_S)",
     'elapsed_s=((((rec or {}).get("kpi") or {}).get("timings") or {}).get("empty_directory_to_last_test_description_s")), budget_s=BUDGET_S)'),
    ("N4 a FAILED reference is accepted", 'if ref.get("result") != "PASS" or [s.sha256', "if [s.sha256"),
    ("N5 upload integrity problems dropped", "        problems += up\n", "        problems += []\n"),
    ("N6 clock offset applied with the wrong sign", '- off["median_s"] - t0', '+ off["median_s"] - t0'),
    ("N7 wall-clock kill limit not enforced", "if now - t0 > limit:", "if now - t0 > limit * 1000:"),
    ("N8 base image not re-hashed after the run", 'if base_after != base["sha512"]:', "if False:"),
    ("N9 VM KPIs compared with themselves", 'kpi_diff = cr.compare_kpis(ref.get("kpi", {}), vm_kpi)',
     "kpi_diff = cr.compare_kpis(vm_kpi, vm_kpi)"),
    ("N10 (re-anchored: section 6 is a block now) a block in the guest log checked by its id only, not its SHA-256",
     'if c.get("kind") == "runbook" and key in allowed and key not in seen:',
     'if c.get("kind") == "runbook" and key[0] in {a for a, _ in allowed} and key not in seen:'),
    ("N11 live DELETE control made inert", '"passed": st != 405 or (had and not (d / "guest.json").exists()), "detail"',
     '"passed": False, "detail"'),
    ("N12 a refused overwrite keeps its quota", "                self.server.release(n)\n                return self._done(409)",
     "                return self._done(409)"),
    ("N13 install blocks get the guest's whole environment", 'ex = cr.Executor(edgefollow_steps, env, os.environ["HOME"])',
     'ex = cr.Executor(edgefollow_steps, dict(os.environ, **env), os.environ["HOME"])'),
    ("N14 step 1 ignores the values of the bootstrap rows", 'and all(cr["bootstrap_rows"])', "and True"),
    ("N15 the VM's runbook SHA-256 not compared",
     'if (rec.get("provenance") or {}).get("runbook_sha256") != _sha(rb_text.encode()):', "if False:"),
    ("N16 say() redefined to run a hidden command", "say() { printf 'VMRERUN-PROGRESS %s\\n' \"$1\" > /dev/ttyS0; }",
     "say() { cp /bin/true /usr/local/bin/git 2>/dev/null; printf 'VMRERUN-PROGRESS %s\\n' \"$1\" > /dev/ttyS0; }"),
]
NEW_FAULTS = [                                                # this pass's own mechanisms
    ("X1 netdev without restrict", 'NETDEV_HEAD = ["user", f"id={NETDEV_ID}", "restrict=on",',
     'NETDEV_HEAD = ["user", f"id={NETDEV_ID}", "restrict=off",'),
    ("X2 proxy opens any target", "if (host, port) not in srv.allow:", "if False:"),
    ("X3 proxy forwards requests that are not CONNECT", 'if method != "CONNECT":', "if False:"),
    ("X4 proxy connects to non-public addresses", "if not ip.is_global:", "if False:"),
    ("X5 clean_rerun's FAIL in the VM ignored", 'cr_ok = cr.get("verdict_problems") == []', "cr_ok = True"),
    ("X6 step 2 not judged from the VM's executed log", 'elif cr.get("executed_problems") != []:', "elif False:"),
    ("X7 section 6 run from ROOT, not from home", 'ex6 = cr.Executor([rerun], s6_env, os.environ["HOME"])',
     "ex6 = cr.Executor([rerun], s6_env, str(root))"),
    ("X8 section 6 given the proxy", "s6_env = cr.base_env(rb, places)",
     's6_env = dict(cr.base_env(rb, places), **proxy_env(cfg["proxy"]))'),
    ("X9 base copy digest not compared", "if digest != listed:", "if False:"),
    ("X10 private folder mode not checked", "if st.st_mode & 0o777 != 0o700:", "if False:"),
    ("X11 step 5 read from the guest's clock", 'hits = [e["t_host"] for e in log', 'hits = [e["guest_time"] for e in log'),
    ("X12 upload reads without a deadline", "self.timeout = self.server.read_timeout", "self.timeout = None"),
    ("X13 two Content-Length headers accepted", "if len(cls) > 1:", "if False:"),
    ("X14 QEMU started without the memory cap", "if not sr or not _memory_cap_works(sr):", "if False:"),
    ("X15 no summary read as NOT-RUN", "put(n, FAIL, why)                   # evidence",
     "put(n, NOT_RUN, why)                   # evidence"),
    ("X16 install environment not compared on the host",
     'if guest.get("installs") and guest.get("install_env") != want_env:', "if False:"),
    ("X17 admin group in the VM not flagged", "        if admin:\n", "        if False:\n"),
    ("X18 evidence not copied to the NTFS folder", "evidence = copy_evidence(priv, run_dir)", "evidence = []"),
]
CHECK2_FAULTS = [                                              # the second check's 12 (C9, C12 re-anchored)
    ("C1 proxy allow-list matches a name by suffix", "            if (host, port) not in srv.allow:\n",
     "            if (host, port) not in srv.allow and not any(host.endswith(h) and port == p for h, p in "
     "(srv.allow if isinstance(srv.allow, frozenset) else ())):\n"),
    ("C2 connect_public resolves again after the address check", "            s.connect(sa)\n",
     "            s.connect((host, port))\n"),
    ("C3 relay connects to 'localhost' by name", 'up = socket.create_connection(("127.0.0.1", port), timeout=10)',
     'up = socket.create_connection(("localhost", port), timeout=10)'),
    ("C4 QEMU audit matches options by prefix", "        elif a in QEMU_WITH_VALUE and i + 1 < len(argv):",
     "        elif any(a.startswith(k) for k in QEMU_WITH_VALUE) and i + 1 < len(argv):"),
    ("C5 private folder owned by root accepted", "    if st.st_uid != os.getuid():", "    if st.st_uid not in (os.getuid(), 0):"),
    ("C6 proxy head timeout per recv, no total deadline",
     '        left = deadline - time.monotonic()\n        if left <= 0:\n            return None, b"", "timeout"\n'
     '        sock.settimeout(left)\n', "        sock.settimeout(timeout)\n"),
    ("C7 step 5 timed from the first harness line", "    elapsed = host_elapsed(server.log, t0) if rec is not None else None",
     '    elapsed = host_elapsed(server.log, seen["lines"][0]["t_host"] if seen["lines"] else t0) if rec is not None else None'),
    ("C8 a control row there twice accepted",
     "        if len(hits) != 1:\n            p.append(f\"control {'missing' if not hits else 'there twice'}: {name}\")",
     "        if not hits:\n            p.append(f\"control missing: {name}\")"),
    ("C9 record from the first stdout line naming one",
     '                last = [ln for ln in out.splitlines() if ln.strip()][-1:] or [""]',
     '                last = [ln for ln in out.splitlines() if re.search(r"clean_rerun_\\d{8}T\\d{6}Z\\.json$", ln.strip())][:1] or [""]'),
    ("C10 bytes sent with the CONNECT head not charged",
     '    if rest:\n        why = srv.charge(e, "bytes_up", len(rest))\n        if why:\n            return why\n        up.sendall(rest)',
     "    if rest:\n        up.sendall(rest)"),
    ("C11 resolver check refuses non-public IPv4 only", "        if not ip.is_global:\n",
     "        if ip.version == 4 and not ip.is_global:\n"),
    ("C12 QEMU audit accepts any drive file", 'if drives != [f"file={run_dir}/overlay.qcow2,if=virtio,format=qcow2"]:',
     'if len(drives) != 1 or not re.fullmatch(r"file=/[^,]+,if=virtio,format=qcow2", drives[0]):'),
]
PASS3_FAULTS = [                                               # this pass's own mechanisms (A, B, C, the lows)
    ("Y1 netdev without ipv6=off", 'NETDEV_HEAD = ["user", f"id={NETDEV_ID}", "restrict=on", "ipv6=off"]',
     'NETDEV_HEAD = ["user", f"id={NETDEV_ID}", "restrict=on"]'),
    ("Y2 QEMU audit ignores the netdev's fourth option",
     'if parts[:4] != ["user", f"id={NETDEV_ID}", "restrict=on", "ipv6=off"] or parts[4:] != want_fwd:',
     'if parts[:3] != ["user", f"id={NETDEV_ID}", "restrict=on"] or parts[-2:] != want_fwd:'),
    ("Y3 the root step runs every install block", "        steps = [s for s in installs if is_root_block(s)]\n",
     "        steps = list(installs)\n"),
    ("Y4 root= with another value accepted", "        if a[ROOT_ATTR[0]] != ROOT_ATTR[1]:", "        if False:"),
    ("Y5 a root block after an unmarked install block accepted", "        if unmarked_seen:", "        if False:"),
    ("Y6 the rerun block matched by id, not by SHA-256",
     'if ({"id": rerun.id, "sha256": rerun.sha256} if rerun else None) != cfg["rerun_block"]:',
     'if (rerun.id if rerun else None) != (cfg["rerun_block"] or {}).get("id"):'),
    ("Y7 the root step's console line not compared", "    problems += root_console\n", "    problems += []\n"),
    ("Y8 check_private_dir accepts a relative path", "    if not p.is_absolute():\n", "    if False:\n"),
    ("Y9 cmd_run accepts a relative --private-dir", "    if not private_parent.is_absolute():\n", "    if False:\n"),
    ("Y10 the unmarked install blocks get APT_CONFIG", 'env = dict(s6_env, **proxy_env(cfg["proxy"]))',
     'env = dict(s6_env, **proxy_env(cfg["proxy"]), APT_CONFIG=cfg["apt_conf"])'),
    ("Y11 the VM's IPv6 addresses not checked", '        problems += ipv6_problems(probes.get("ipv6_addresses"))\n',
     "        problems += []\n"),
    ("Y12 a site-local IPv6 address (slirp's fec0::) accepted", "        if not (ip.is_loopback or ip.is_link_local):",
     "        if not (ip.is_loopback or ip.is_link_local or ip.is_site_local):"),
    ("Y13 the audit does not pin -serial", '    want = {"-serial": f"file:{run_dir}/serial.log", "-machine"',
     '    want = {"-machine"'),
    ("Y14 the root step runs a block whose text changed", '        installs = check_install_plan(rb, cfg["install_plan"])\n'
     '        ids = root_block_ids(rb)\n', '        installs = [s for s in rb.steps if s.phase == "install"]\n'
     '        ids = root_block_ids(rb)\n'),
    ("Y15 the root step reads edgefollow's copy of the runbook", '        est = _root_copy(h / "code.tar", h / "rootcode")',
     '        est = Path(cfg["code_root"]) / "estimed"'),
    ("Y16 a block run twice is not foreign", 'if c.get("kind") == "runbook" and key in allowed and key not in seen:',
     'if c.get("kind") == "runbook" and key in allowed:'),
    ("Y17 the audit takes any -name", '    if one.get("-name") != name or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(name)):',
     "    if False:"),
]
ALL_FAULTS = [("builder", *f) for f in FAULTS] + [("reviewer", *f) for f in REVIEWER_FAULTS] + \
    [("new", *f) for f in NEW_FAULTS] + [("check2", *f) for f in CHECK2_FAULTS] + [("pass3", *f) for f in PASS3_FAULTS]


def plant(outdir: Path, jobs: int = 1) -> int:
    from concurrent.futures import ThreadPoolExecutor
    outdir = Path(outdir)
    if not outdir.is_absolute():                   # every junit file goes under it: never into the tree by accident
        raise SystemExit(f"--plant needs an absolute folder, not {outdir}")
    outdir.mkdir(parents=True, exist_ok=False)
    src = (EST / "vm_rerun.py").read_text()
    base = _run_suite(None, outdir / "baseline.xml")
    lines = [f"baseline (no fault): {base['tests']} tests, {base['failed']} failed, {base['errors']} collection errors"]

    def one(i, group, label, old, new):
        if group == "unchanged":                    # run inside the same pool: a failure here is flakiness under load
            d = outdir / f"unchanged{i:02d}"
            d.mkdir()
            (d / "vm_rerun.py").write_text(src)
            r = _run_suite(d / "vm_rerun.py", d / "junit.xml")
            return r["failed"] == 0 and r["tests"] == base["tests"], \
                f"{i:2d}  unchanged copy under the same load: {r['tests']} tests, {r['failed']} failed {r['names'][:3]}"
        if src.count(old) != 1:
            return False, f"{i:2d}  {group:8s}  NOT PLANTED ({src.count(old)} matches)  {label}"
        d = outdir / f"fault{i:02d}"
        d.mkdir()
        (d / "vm_rerun.py").write_text(src.replace(old, new, 1))
        r = _run_suite(d / "vm_rerun.py", d / "junit.xml")
        ok = r["tests"] == base["tests"] and r["failed"] >= 1 and r["errors"] == 0
        return ok, (f"{i:2d}  {group:8s}  {'CAUGHT  ' if ok else 'SURVIVED'}  {label}  ({r['tests']} tests, "
                    f"{r['failed']} failed: {', '.join(n[:70] for n in r['names'][:2])})")
    todo = [(i, *f) for i, f in enumerate(ALL_FAULTS, 1)]
    todo[len(todo) // 2:len(todo) // 2] = [(0, "unchanged", "", "", "")]
    todo.append((99, "unchanged", "", "", ""))
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        results = list(pool.map(lambda a: one(*a), todo))
    flaky = [line for (ok, line), a in zip(results, todo) if a[1] == "unchanged" and not ok]
    results = [r for r, a in zip(results, todo) if a[1] != "unchanged"]
    caught = sum(ok for ok, _ in results)
    lines += [line for _, line in results]
    lines.append("unchanged copies under load: " + ("both 0 failed" if not flaky else "FLAKY: " + "; ".join(flaky)))
    for group in ("builder", "reviewer", "new", "check2", "pass3"):
        idx = [k for k, f in enumerate(ALL_FAULTS) if f[0] == group]
        lines.append(f"{group}: caught {sum(results[k][0] for k in idx)} of {len(idx)}")
    lines.append(f"caught {caught} of {len(ALL_FAULTS)}; a crash, fewer tests or no plant counts as not caught")
    (outdir / "plant_report.txt").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if caught == len(ALL_FAULTS) and base["failed"] == 0 and not flaky else 1


if __name__ == "__main__":
    if len(sys.argv) in (3, 5) and sys.argv[1] == "--plant":
        sys.exit(plant(Path(sys.argv[2]), int(sys.argv[4]) if len(sys.argv) == 5 and sys.argv[3] == "--jobs" else 1))
    print(__doc__)
    sys.exit(2)
