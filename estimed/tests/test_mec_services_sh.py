# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""estimed/mec_services.sh, offline: fake services on free loopback ports in temporary checkouts; nothing of the lab.

start records the service's own pid and the command it ran; status marks it ours; stop ends it and waits for it to
exit; a held port is left alone; one checkout's stop never touches another checkout's services or pid files; stop
works through a symlinked path and with another EDGEFOLLOW_PY; a process that does not exit keeps its pid file.
Every fake service is also killed in teardown by a scan of this test's own directory, so none can outlive a test.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "mec_services.sh"
FAKE = """import signal, socket, sys, time
mode = {mode!r}
if mode == "slow":
    signal.signal(signal.SIGTERM, lambda *a: (time.sleep(1.5), sys.exit(0)))
if mode == "stubborn":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", {port})); s.listen(4)
while True:
    c, _ = s.accept(); c.close()
"""


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def checkout(tmp: Path, name: str, ports: dict, mode: str = "plain") -> Path:
    root = tmp / name
    (root / "estimed").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "estimed" / "mec_services.sh")
    for svc, port in ports.items():
        (root / f"{svc}.py").write_text(FAKE.format(port=port, mode=mode))
    return root


def run(root: Path, cmd: str, run_dir: Path, ports: dict, py: str | None = sys.executable) -> str:
    env = {"PATH": os.environ["PATH"], "HOME": str(run_dir), "EDGEFOLLOW_RUN_DIR": str(run_dir),
           "EDGEFOLLOW_MEC_SERVICES": " ".join(f"{s}:{p}:{s}.py" for s, p in ports.items())}
    if py:
        env["EDGEFOLLOW_PY"] = py
    p = subprocess.run(["bash", str(root / "estimed" / "mec_services.sh"), cmd], capture_output=True, text=True,
                       env=env, timeout=60)
    return p.stdout + p.stderr


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def pid_dir(run_dir: Path, root: Path) -> Path:
    return run_dir / "mec" / hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:12]


def pid_of(run_dir: Path, root: Path, svc: str) -> int:
    return int((pid_dir(run_dir, root) / f"{svc}.pid").read_text().splitlines()[0])


@pytest.fixture
def setup(tmp_path):
    ports = {"svca": free_port(), "svcb": free_port()}
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    yield tmp_path, ports, run_dir
    base = str(tmp_path.resolve())
    for p in Path("/proc").iterdir():                      # every fake service started under this test's directory
        if not p.name.isdigit():
            continue
        try:
            cwd = os.readlink(p / "cwd")
            argv = (p / "cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if cwd.startswith(base) and any(a in (b"svca.py", b"svcb.py") for a in argv):
            os.kill(int(p.name), signal.SIGKILL)


def test_start_records_the_services_own_pid_and_command_and_stop_ends_it(setup):
    tmp, ports, run_dir = setup
    root = checkout(tmp, "a", ports)
    out = run(root, "start", run_dir, ports)
    assert out.count("started on") == 2, out
    for svc in ports:
        pid = pid_of(run_dir, root, svc)
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
        assert argv == [sys.executable.encode(), f"{svc}.py".encode()]
        assert (pid_dir(run_dir, root) / f"{svc}.pid").read_text().splitlines()[1:] == [sys.executable, f"{svc}.py"]
    assert run(root, "status", run_dir, ports).count("(ours)") == 2
    pids = [pid_of(run_dir, root, s) for s in ports]
    out = run(root, "stop", run_dir, ports)
    assert out.count("stopped (pid") == 2, out
    assert not any(alive(p) for p in pids) and not list(pid_dir(run_dir, root).glob("*.pid"))


def test_control_a_held_port_is_left_alone_never_marked_ours_and_never_stopped(setup):
    tmp, ports, run_dir = setup
    root = checkout(tmp, "a", ports)
    other = subprocess.Popen([sys.executable, "-c", FAKE.format(port=ports["svca"], mode="plain"), "svca.py"],
                             cwd=tmp)
    time.sleep(0.5)
    out = run(root, "start", run_dir, ports)
    assert "svca: :%d already in use; left alone" % ports["svca"] in out and "svcb: started" in out
    status = run(root, "status", run_dir, ports)
    assert "svca :%d up\n" % ports["svca"] in status and "svcb :%d up (ours)" % ports["svcb"] in status
    run(root, "stop", run_dir, ports)
    assert alive(other.pid)


def test_control_another_checkouts_stop_touches_neither_the_services_nor_their_pid_files(setup):
    tmp, ports, run_dir = setup
    first, second = checkout(tmp, "a", ports), checkout(tmp, "b", ports)
    run(first, "start", run_dir, ports)
    pids = [pid_of(run_dir, first, s) for s in ports]
    out = run(second, "stop", run_dir, ports)
    assert out.count("not running from this checkout") == 2 and all(alive(p) for p in pids)
    assert len(list(pid_dir(run_dir, first).glob("*.pid"))) == 2
    out = run(first, "stop", run_dir, ports)                      # the owner can still stop them
    assert out.count("stopped (pid") == 2 and not any(alive(p) for p in pids)


def test_control_a_pid_file_pointing_at_another_process_is_not_followed(setup):
    tmp, ports, run_dir = setup
    root = checkout(tmp, "a", ports)
    d = pid_dir(run_dir, root)
    d.mkdir(parents=True)
    impostor = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)", "svca.py"], cwd=root)
    (d / "svca.pid").write_text(f"{impostor.pid}\n{sys.executable}\nsvca.py\n")
    out = run(root, "stop", run_dir, {"svca": ports["svca"]})
    assert "runs something else now; left alone, stale pid file removed" in out and alive(impostor.pid)
    assert not (d / "svca.pid").exists()
    (d / "svca.pid").write_text(f"{impostor.pid}\n{sys.executable}\nsvca.py\n")   # a stale file must not block start
    out = run(root, "start", run_dir, {"svca": ports["svca"]})
    assert "svca: started on" in out and pid_of(run_dir, root, "svca") != impostor.pid and alive(impostor.pid)
    run(root, "stop", run_dir, {"svca": ports["svca"]})
    impostor.kill()


def test_start_does_not_start_a_second_copy_of_its_own_running_service(setup):
    tmp, ports, run_dir = setup
    root = checkout(tmp, "a", ports)
    run(root, "start", run_dir, ports)
    first = [pid_of(run_dir, root, s) for s in ports]
    out = run(root, "start", run_dir, ports)
    assert "started on" not in out and [pid_of(run_dir, root, s) for s in ports] == first
    run(root, "stop", run_dir, ports)


def test_stop_works_through_a_symlinked_path_and_with_another_interpreter_setting(setup):
    tmp, ports, run_dir = setup
    root = checkout(tmp, "a", ports)
    link = tmp / "link"
    link.symlink_to(root)
    run(link, "start", run_dir, ports)
    pids = [pid_of(run_dir, root, s) for s in ports]
    out = run(root, "stop", run_dir, ports, py=None)               # EDGEFOLLOW_PY unset at stop
    assert out.count("stopped (pid") == 2, out
    assert not any(alive(p) for p in pids)


def test_stop_waits_for_a_slow_service_so_start_works_right_after(setup):
    tmp, ports, run_dir = setup
    root = checkout(tmp, "a", ports, mode="slow")
    run(root, "start", run_dir, ports)
    old = [pid_of(run_dir, root, s) for s in ports]
    run(root, "stop", run_dir, ports)
    assert not any(alive(p) for p in old)
    out = run(root, "start", run_dir, ports)
    assert out.count("started on") == 2, out
    run(root, "stop", run_dir, ports)


def test_a_service_that_does_not_exit_keeps_its_pid_file_for_a_later_stop(setup):
    tmp, ports, run_dir = setup
    one = {"svca": ports["svca"]}
    root = checkout(tmp, "a", one, mode="stubborn")
    run(root, "start", run_dir, one)
    pid = pid_of(run_dir, root, "svca")
    out = run(root, "stop", run_dir, one)
    assert "did not exit within 10 s; its pid file is kept" in out and alive(pid)
    assert (pid_dir(run_dir, root) / "svca.pid").exists()
    os.kill(pid, signal.SIGKILL)
    time.sleep(0.3)
    out = run(root, "stop", run_dir, one)
    assert "not running from this checkout" in out and not (pid_dir(run_dir, root) / "svca.pid").exists()
