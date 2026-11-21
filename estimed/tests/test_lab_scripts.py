"""The lab's start and stop scripts tell the truth (lab fixes of 2026-10-29).

run_topology.sh exited 0 whatever happened -- a node that failed to start, or an IN holding only one edge -- and
matched registrations by substring; stop_topology.sh force-killed every acmecse process on the machine, another
lab's included. Each script is run here on a PRIVATE copy of the topology (the running lab's configs, ports shifted,
its own RUN directory and log folders) beside the running lab. Checked afterwards: the lab's three processes still
hold their ports, the IN still holds exactly both edges, and the lab's log files were neither rotated, truncated nor
written by the private nodes.

2026-11-20: (1) the running lab is found by the port it listens on, not by an assumed folder, so these tests run on
whatever ACME is deployed (they had failed when the lab ran ACME's development source from another folder);
(2) the private nodes had written into the LAB's log folders all along: each config's `baseDirectory=` line wins over
run_topology.sh's --base-directory for ACME's log path (`[logging] path=${basic.config:baseDirectory}/logs`), the
nodes share the lab's cseIDs and so its log file names, and their rotation rotated the lab's logs (a review run of
2026-11-20 showed it; such runs, about 9 KB per lab log each, pushed old lab logs out of ACME's 10-file window). The
private configs now carry no baseDirectory line, and the lab's log files are compared before and after.

Needs the lab up (bash estimed/run_topology.sh) and ports 8210-8212 and 8220-8222 free.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

import handover
from conftest import ESTIMED, IN_CSE, TY_CSR, req

NODES = ("in", "mn-a", "mn-b")
PRIVATE_PORT = re.compile(rb"127\.0\.0\.1:82[12][0-2]\b")      # a private node's address in a log line
FOLDER_LINES = re.compile(r"(?m)^(baseDirectory|initDirectory)=.*$")


def _ini_port(node: str) -> int:
    """The node's httpPort as the lab's own config (estimed/conf/<node>.ini) names it."""
    m = re.search(r"(?m)^httpPort=(\d+)\s*$", (ESTIMED / "conf" / f"{node}.ini").read_text())
    assert m, f"estimed/conf/{node}.ini names no httpPort"
    return int(m.group(1))


def _listener_pids(port: int) -> list[int]:
    """pids holding a LISTEN socket on TCP <port> (any address), from /proc/net/tcp{,6} and /proc/<pid>/fd. Only
    sockets in state 0A (LISTEN) count: an accepted connection on the same local port is not a listener."""
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            rows = Path(table).read_text().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            f = row.split()
            if len(f) > 9 and f[3] == "0A" and int(f[1].rsplit(":", 1)[1], 16) == port:
                inodes.add(f"socket:[{f[9]}]")
    found = []
    if not inodes:
        return found
    for p in Path("/proc").glob("[0-9]*"):
        try:
            fds = list((p / "fd").iterdir())
        except OSError:                              # not our process, or it ended
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
            except OSError:                          # this one fd closed meanwhile: skip it, not the whole process
                continue
            if target in inodes:
                found.append(int(p.name))
                break
    return found


def _lab_cse(node: str, port: int) -> dict:
    """The one acmecse process that listens on <port>, with its VENV and base directory; anything else fails.
    It is identified by its arguments (a `.../bin/acmecse` program and --base-directory): a process that merely
    carries such arguments would be taken for one (residual: these tests do not authenticate the lab)."""
    pids = _listener_pids(port)
    assert len(pids) == 1, (f"lab node {node}: {len(pids)} process(es) listen on :{port} ({pids}); exactly one acmecse "
                            "is expected" + ("; start the lab first" if not pids else ""))
    pid = pids[0]
    args = Path(f"/proc/{pid}/cmdline").read_bytes().decode(errors="replace").split("\0")
    acme = [a for a in args if a.endswith("/bin/acmecse")]
    assert len(acme) == 1, f"lab node {node}: :{port} is held by pid {pid}, which is not one acmecse: {args[:3]}"
    assert "--base-directory" in args, f"lab node {node}: pid {pid} was not started with --base-directory: {args}"
    base = Path(args[args.index("--base-directory") + 1])
    assert (base / "acme.ini").is_file(), f"lab node {node}: no acme.ini in its base directory {base}"
    return {"pid": pid, "port": port, "venv": Path(acme[0]).parent.parent, "base": base}


def _lab_cses() -> dict[str, dict]:
    """Each running lab CSE, found by the port it LISTENS on (8200-8202, from the lab's configs), not by where it was
    started from: the lab may run any ACME build from any VENV and RUN. Per node: pid, port, the acmecse program's
    VENV (the one run_topology.sh was given) and the --base-directory, whose acme.ini is the copy run_topology.sh
    made at the lab's start (as it is on disk now)."""
    return _one_venv({node: _lab_cse(node, _ini_port(node)) for node in NODES})


def _one_venv(lab: dict[str, dict]) -> dict[str, dict]:
    """The lab as given, if all its CSEs run from one VENV (one ACME); else fail."""
    venvs = {str(v["venv"]) for v in lab.values()}
    assert len(venvs) == 1, f"the lab's three CSEs run from different VENVs: {sorted(venvs)}"
    return lab


def _private_conf(tmp: Path, base: int, lab: dict[str, dict], allow: str | None = None) -> Path:
    """The running lab's configs (<base-directory>/acme.ini of each node) with ports 8200-8202 moved to base..base+2,
    WITHOUT the baseDirectory line (so ACME takes run_topology.sh's --base-directory, the private RUN, for its log
    folder: with the line kept, the private nodes logged into the lab's folders), and optionally the IN's registration
    allow-list. The deployed copy must equal estimed/conf/<node>.ini apart from the baseDirectory and initDirectory
    lines, so a drifted deployment is not silently tested in place of the repository's configs."""
    conf = tmp / "conf"
    conf.mkdir()
    for node in NODES:
        deployed = (lab[node]["base"] / "acme.ini").read_text()
        repo = (ESTIMED / "conf" / f"{node}.ini").read_text()
        assert FOLDER_LINES.sub("", deployed) == FOLDER_LINES.sub("", repo), \
            f"the lab's deployed {node} acme.ini differs from estimed/conf/{node}.ini beyond the two folder lines"
        text, n = re.subn(r"(?m)^baseDirectory=.*\n", "", deployed)
        assert n == 1, f"the lab's {node} acme.ini has {n} baseDirectory lines, expected 1"
        text = re.sub(r"\b820([0-2])\b", lambda m: str(base + int(m.group(1))), text)
        if allow is not None and node == "in":
            text, n = re.subn(r"(?m)^allowedCSROriginators=.*$", f"allowedCSROriginators={allow}", text)
            assert n == 1, "the lab's in acme.ini has no allowedCSROriginators line to restrict"
        (conf / f"{node}.ini").write_text(text)
    return conf


def _script(name: str, conf: Path, run: Path, venv: Path) -> subprocess.CompletedProcess:
    """Run a lab script on a private topology with the SAME ACME as the running lab (its VENV)."""
    env = dict(os.environ, CONF=str(conf), RUN=str(run), VENV=str(venv))
    return subprocess.run(["bash", str(ESTIMED / name)], env=env, capture_output=True, text=True, timeout=300)


def _acme_under(run: Path) -> list[int]:
    """acmecse processes whose arguments name `run` or a directory below it (run_topology.sh passes
    --base-directory <RUN>/<node>)."""
    found = []
    for p in Path("/proc").glob("[0-9]*"):
        try:
            args = (p / "cmdline").read_bytes().decode(errors="replace").split("\0")
        except OSError:
            continue
        if any(a.endswith("bin/acmecse") for a in args) and \
                any(a == str(run) or a.startswith(f"{run}/") for a in args):
            found.append(int(p.name))
    return found


def _private_nodes_ok(run: Path, venv: Path):
    """While the private topology runs: one acmecse per node under the private RUN, each <venv>/bin/acmecse, and each
    node's log file in the private RUN (<RUN>/<node>/logs). That the lab's own logs were not written is checked
    separately, by _logs_intact."""
    for node in NODES:
        pids = _acme_under(run / node)
        assert len(pids) == 1, f"private node {node}: {len(pids)} acmecse process(es) under {run / node}"
        args = Path(f"/proc/{pids[0]}/cmdline").read_bytes().decode(errors="replace").split("\0")
        assert f"{venv}/bin/acmecse" in args, f"private node {node} does not run the lab's ACME ({venv}): {args[:3]}"
        assert list((run / node / "logs").glob("*.log*")), f"private node {node} wrote no log under {run / node}/logs"


def _free(*ports):
    for port in ports:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                pytest.fail(f"something already listens on :{port}", pytrace=False)


def _log_state(lab: dict[str, dict]) -> dict[str, dict]:
    """Per lab log file: inode, size, and how many lines name a private node's address. Each node must have at least
    one log file, so an empty state cannot pass the comparison by having nothing to compare."""
    out = {}
    for node, v in lab.items():
        files = sorted((v["base"] / "logs").glob("*"))
        assert files, f"lab node {node} has no log file under {v['base'] / 'logs'}"
        for f in files:
            st = f.stat()
            out[str(f)] = {"ino": st.st_ino, "size": st.st_size, "private": len(PRIVATE_PORT.findall(f.read_bytes()))}
    return out


def _lab_intact(before: dict[str, dict], logs_before: dict[str, dict]):
    """The same lab processes still hold the same ports, the IN still holds exactly both edges, and every lab log
    file is the same file (same inode: not rotated), no shorter (not truncated) and names no private node more often
    than before (not written by the private topology)."""
    for node, v in before.items():
        assert Path(f"/proc/{v['pid']}").exists(), f"stopping a private topology killed the lab's {node}"
        assert _listener_pids(v["port"]) == [v["pid"]], f"the lab's {node} no longer holds :{v['port']}"
    st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}?fu=1&ty={TY_CSR}", "CAdmin")
    assert st == 200 and handover.edges_ok(body["m2m:uril"]), body
    _logs_intact(logs_before, _log_state(before))


def _logs_intact(logs_before: dict[str, dict], after: dict[str, dict]):
    """Every lab log file of `logs_before` is still there as the same file, no shorter, naming no private node more
    often, and no new file appeared in the lab's log folders. A lab node that rotates its own log during a test also
    fails here (stated; a 54 s run wrote 0 bytes to the lab's logs on 2026-11-20). The private-node count relies on
    ACME logging its listen address at info level (run_topology.sh's default LOGLEVEL); under LOGLEVEL=warn only the
    inode, size and new-file checks remain."""
    new = sorted(set(after) - set(logs_before))
    assert not new, f"new files appeared in the lab's log folders during the test: {new}"
    for f, s in logs_before.items():
        a = after.get(f)
        assert a is not None, f"lab log {f} is gone"
        assert a["ino"] == s["ino"], f"lab log {f} was rotated or replaced during the test"
        assert a["size"] >= s["size"], f"lab log {f} was truncated during the test"
        assert a["private"] == s["private"], \
            f"lab log {f} gained lines naming a private node: the private topology wrote into it"


def test_u01_a_half_registered_topology_fails_and_its_stop_spares_the_lab(topology, tmp_path):
    _free(8210, 8211, 8212)
    before = _lab_cses()
    logs_before = _log_state(before)
    venv = before["in"]["venv"]
    conf, run = _private_conf(tmp_path, 8210, before, allow="/id-mn-a"), tmp_path / "run"   # MN-B may not register
    try:
        r = _script("run_topology.sh", conf, run, venv)
        assert r.returncode != 0, r.stdout[-600:]
        assert "FAILED: the IN does not hold exactly the edges" in r.stdout, r.stdout[-600:]
        _private_nodes_ok(run, venv)
    finally:
        _script("stop_topology.sh", conf, run, venv)
    assert _acme_under(run) == [], "the private topology must be gone"
    _lab_intact(before, logs_before)


def test_u01_control_a_complete_topology_exits_zero(topology, tmp_path):
    _free(8220, 8221, 8222)
    before = _lab_cses()
    logs_before = _log_state(before)
    venv = before["in"]["venv"]
    conf, run = _private_conf(tmp_path, 8220, before), tmp_path / "run"
    try:
        r = _script("run_topology.sh", conf, run, venv)
        assert r.returncode == 0, r.stdout[-600:]
        assert "IN holds all edges" in r.stdout
        _private_nodes_ok(run, venv)
    finally:
        _script("stop_topology.sh", conf, run, venv)
    assert _acme_under(run) == []
    _lab_intact(before, logs_before)


def test_u01_control_the_lab_finder_refuses_a_port_not_held_by_acmecse(tmp_path):
    """CONTROL: a plain listener (this test process) is found by its port, then refused by _lab_cse as not acmecse;
    an accepted connection left on the port after its listener closed is not a listener (the LISTEN filter, not a
    skipped process, decides: the finder skips only an unreadable fd); a closed port is refused."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        assert _listener_pids(port) == [os.getpid()]
        with pytest.raises(AssertionError, match="not one acmecse"):
            _lab_cse("in", port)
        c = socket.create_connection(("127.0.0.1", port))
        conn, _ = s.accept()
    try:
        assert _listener_pids(port) == [], "an accepted connection was taken for a listener"
    finally:
        conn.close()
        c.close()
    with pytest.raises(AssertionError, match="0 process"):
        _lab_cse("in", port)


def test_u01_control_two_listeners_on_one_port_are_refused():
    """CONTROL: two processes listening on one port (SO_REUSEPORT) are refused, not the first one taken."""
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        child = subprocess.Popen([sys.executable, "-I", "-c",
                                  "import socket,sys,time; s=socket.socket(); "
                                  "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1); "
                                  f"s.bind(('127.0.0.1', {port})); s.listen(1); print('up', flush=True); time.sleep(20)"],
                                 stdout=subprocess.PIPE, text=True)
        try:
            assert child.stdout.readline().strip() == "up"
            assert sorted(_listener_pids(port)) == sorted([os.getpid(), child.pid])
            with pytest.raises(AssertionError, match="2 process"):
                _lab_cse("in", port)
        finally:
            child.kill()
            child.wait(5)


def test_u01_control_logs_intact_refuses_rotation_truncation_private_lines_and_new_files(tmp_path):
    """CONTROL (offline): _logs_intact accepts the lab appending to its own log and refuses a rotated, truncated,
    vanished log, a new file in the log folder, and a line naming any of the six private addresses; _log_state
    refuses a lab node with no log file at all."""
    lab = {"in": {"pid": os.getpid(), "port": 0, "venv": tmp_path, "base": tmp_path}}
    (tmp_path / "logs").mkdir()
    f = tmp_path / "logs" / "cse-x.log"
    with pytest.raises(AssertionError, match="has no log file"):
        _log_state(lab)

    def fresh(data: bytes) -> dict:
        for old in (tmp_path / "logs").glob("*"):
            old.unlink()
        f.write_bytes(data)
        return _log_state(lab)

    state = fresh(b"x" * 100)
    with f.open("ab") as out:
        out.write(b" the lab's own next line\n")
    _logs_intact(state, _log_state(lab))                       # positive: the lab appending to its own log is fine
    state = fresh(b"x" * 100)
    f.rename(f.with_name("cse-x.log.1"))
    f.write_bytes(b"y" * 10)                                   # what a rotation leaves under the old name
    with pytest.raises(AssertionError, match="new files appeared|rotated"):
        _logs_intact(state, _log_state(lab))
    state = fresh(b"x" * 100)
    f.with_name("cse-x.log.1").write_bytes(b"z")
    with pytest.raises(AssertionError, match="new files appeared"):
        _logs_intact(state, _log_state(lab))
    state = fresh(b"x" * 100)
    os.truncate(f, 10)
    with pytest.raises(AssertionError, match="truncated"):
        _logs_intact(state, _log_state(lab))
    for port in (8210, 8211, 8212, 8220, 8221, 8222):
        state = fresh(b"x" * 100)
        with f.open("ab") as out:
            out.write(f" listening on 127.0.0.1:{port}\n".encode())
        with pytest.raises(AssertionError, match="private node"):
            _logs_intact(state, _log_state(lab))
    state = fresh(b"x" * 100)
    f.unlink()
    f.with_name("other.log").write_bytes(b"x")
    with pytest.raises(AssertionError, match="new files appeared|is gone"):
        _logs_intact(state, _log_state(lab))
    state = fresh(b"x" * 100)
    tmp = f.with_name("cse-x.tmp")
    tmp.write_bytes(b"y" * 150)                                # a new inode while the old one still exists
    os.replace(tmp, f)                                         # replaced in place: same name, longer, no new name
    with pytest.raises(AssertionError, match="rotated or replaced"):
        _logs_intact(state, _log_state(lab))
    fresh(b"x" * 100)
    f.with_name("cse-x.log.1").write_bytes(b"old")
    state = _log_state(lab)
    f.with_name("cse-x.log.1").unlink()                        # an old log vanished, and no new file came
    with pytest.raises(AssertionError, match="is gone"):
        _logs_intact(state, _log_state(lab))
    (tmp_path / "b" / "logs").mkdir(parents=True)              # a second node with an empty log folder
    with pytest.raises(AssertionError, match="lab node mn-a has no log file"):
        _log_state({**lab, "mn-a": {"pid": 0, "port": 0, "venv": tmp_path, "base": tmp_path / "b"}})


def test_u01_control_lab_intact_refuses_a_lost_port_and_checks_the_logs(topology, tmp_path):
    """CONTROL (needs the lab up, for the IN query): _lab_intact refuses a pid that no longer holds its port, and,
    with the port held and the IN answering, still refuses a rotated log, so its log check cannot be dropped."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        free_port = s.getsockname()[1]
    with pytest.raises(AssertionError, match="no longer holds"):
        _lab_intact({"in": {"pid": os.getpid(), "port": free_port, "venv": tmp_path, "base": tmp_path}}, {})
    (tmp_path / "logs").mkdir()
    f = tmp_path / "logs" / "cse-x.log"
    f.write_bytes(b"x" * 100)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        held = {"in": {"pid": os.getpid(), "port": s.getsockname()[1], "venv": tmp_path, "base": tmp_path}}
        state = _log_state(held)
        f.rename(f.with_name("cse-x.log.1"))
        f.write_bytes(b"y" * 10)
        with pytest.raises(AssertionError, match="new files appeared|rotated"):
            _lab_intact(held, state)


def test_u01_control_the_finder_skips_only_an_unreadable_fd():
    """CONTROL: a free fd number below this process's listener (where listing /proc/self/fd puts its own, soon
    closed, fd) must not make the finder skip the whole process."""
    gap = os.open(os.devnull, os.O_RDONLY)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        os.close(gap)
        assert _listener_pids(s.getsockname()[1]) == [os.getpid()]


def test_u01_control_private_nodes_ok_needs_one_acme_and_one_log_per_node(tmp_path):
    """CONTROL: _private_nodes_ok accepts one <venv>/bin/acmecse with its own log per node, and refuses a node with
    no log, a node from another VENV and a missing node (stand-in processes that carry acmecse-like arguments)."""
    run, venv = tmp_path / "run", tmp_path / "venv"
    procs = {}

    def stand_in(node, v=venv):
        return subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)", f"{v}/bin/acmecse",
                                 "--base-directory", str(run / node)])
    try:
        for node in NODES:
            (run / node / "logs").mkdir(parents=True)
            (run / node / "logs" / "cse.log").write_text("x")
            procs[node] = stand_in(node)
        for _ in range(50):                                    # the stand-ins' argv is visible once exec has run
            if all(_acme_under(run / n) for n in NODES):
                break
            time.sleep(0.1)
        _private_nodes_ok(run, venv)                           # positive
        extra = stand_in("in")                                 # two acmecse for one node
        try:
            for _ in range(50):
                if len(_acme_under(run / "in")) == 2:
                    break
                time.sleep(0.1)
            with pytest.raises(AssertionError, match="private node in: 2 acmecse"):
                _private_nodes_ok(run, venv)
        finally:
            extra.kill()
            extra.wait(5)
        (run / "mn-a" / "logs" / "cse.log").unlink()
        with pytest.raises(AssertionError, match="private node mn-a wrote no log"):
            _private_nodes_ok(run, venv)
        (run / "mn-a" / "logs" / "cse.log").write_text("x")
        procs["mn-b"].kill(); procs["mn-b"].wait(5)
        procs["mn-b"] = stand_in("mn-b", tmp_path / "other-venv")
        for _ in range(50):
            if _acme_under(run / "mn-b"):
                break
            time.sleep(0.1)
        with pytest.raises(AssertionError, match="does not run the lab's ACME"):
            _private_nodes_ok(run, venv)
        procs["mn-b"].kill(); procs["mn-b"].wait(5)
        with pytest.raises(AssertionError, match="private node mn-b: 0 acmecse"):
            _private_nodes_ok(run, venv)
    finally:
        for p in procs.values():
            p.kill()
            p.wait(5)


def test_u01_control_the_live_tests_call_their_checks():
    """CONTROL: both live tests call _private_nodes_ok while the private topology runs and _lab_intact after it, so
    neither check can be dropped from them without this row failing (their behaviour has its own controls)."""
    import inspect
    for t in (test_u01_a_half_registered_topology_fails_and_its_stop_spares_the_lab,
              test_u01_control_a_complete_topology_exits_zero):
        src = inspect.getsource(t)
        try_part = src.split("    try:\n", 1)[1].split("    finally:\n", 1)[0]
        assert "_private_nodes_ok(run, venv)" in try_part, f"{t.__name__} does not check the private nodes"
        assert src.rstrip().endswith("_lab_intact(before, logs_before)"), f"{t.__name__} does not end with _lab_intact"


def test_u01_control_lab_cses_checks_one_acme(monkeypatch):
    """CONTROL: _lab_cses itself refuses a lab whose CSEs run from two VENVs (its _one_venv call cannot be dropped)."""
    monkeypatch.setattr(sys.modules[__name__], "_lab_cse", lambda node, port: {
        "pid": 1, "port": port, "venv": Path("/v/two" if node == "mn-b" else "/v/one"), "base": Path("/")})
    with pytest.raises(AssertionError, match="different VENVs"):
        _lab_cses()


def test_u01_control_one_acme_for_the_whole_lab(tmp_path):
    """CONTROL: a lab whose CSEs run from two VENVs is refused; one VENV is accepted."""
    one = {n: {"venv": Path("/v/one")} for n in NODES}
    assert _one_venv(one) is one
    two = dict(one, **{"mn-b": {"venv": Path("/v/two")}})
    with pytest.raises(AssertionError, match="different VENVs"):
        _one_venv(two)


def test_u01_control_private_conf_drops_the_base_directory_line_and_refuses_drift(tmp_path):
    """CONTROL: the private configs carry no baseDirectory line; a deployed config that differs from estimed/conf
    beyond the two folder lines is refused."""
    base = tmp_path / "lab"
    lab = {}
    for node in NODES:
        (base / node).mkdir(parents=True)
        repo = (ESTIMED / "conf" / f"{node}.ini").read_text()
        (base / node / "acme.ini").write_text(FOLDER_LINES.sub(lambda m: f"{m.group(1)}=/elsewhere/{node}", repo))
        lab[node] = {"base": base / node}
    (tmp_path / "a").mkdir()
    conf = _private_conf(tmp_path / "a", 8230, lab)
    for node in NODES:
        text = (conf / f"{node}.ini").read_text()
        assert not re.search(r"(?m)^baseDirectory=", text), f"{node}: the private config still names a baseDirectory"
        assert re.search(r"(?m)^httpPort=823[0-2]\s*$", text), f"{node}: the port was not moved to 8230-8232"
    (base / "mn-a" / "acme.ini").write_text((base / "mn-a" / "acme.ini").read_text() + "\nlogLevel=debug\n")
    (tmp_path / "b").mkdir()
    with pytest.raises(AssertionError, match="differs from estimed/conf"):
        _private_conf(tmp_path / "b", 8230, lab)


def test_u01_control_script_runs_the_labs_acme(monkeypatch, tmp_path):
    """CONTROL: _script hands the lab's VENV to the lab scripts (on the release lab the default VENV is the same
    folder, so only this row can show it is passed)."""
    seen = {}
    monkeypatch.setattr(subprocess, "run", lambda argv, env, **kw: seen.update(argv=argv, env=env) or
                        subprocess.CompletedProcess(argv, 0, "", ""))
    _script("run_topology.sh", tmp_path / "conf", tmp_path / "run", Path("/some/venv"))
    assert seen["env"]["VENV"] == "/some/venv" and seen["env"]["RUN"] == str(tmp_path / "run")
