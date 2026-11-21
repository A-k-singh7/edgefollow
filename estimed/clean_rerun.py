#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""TD_MEC_OBS_03 (test plan 7.6.3.1), as far as this PC allows: rerun the scripted tests for TD_MEC_PF_01, REG_01,
REG_02, REG_03 and DEV_01 from a FRESH COPY OF THE CODE ON THE SAME HOST with a new, empty run directory, taking every
command from RUNBOOK.md, and compare the KPIs with a reference run made from the working tree.

What it is not: no virtual machine and no container are used, and the two interpreter environments are the ones
already installed (checked against the versions the runbook names, not created). Both are NOT-RUN rows in the record.

    reference   run the runbook's test steps from the working tree against the lab as it stands; write the KPIs
    rerun       fresh copy + manifest -> the runbook's bootstrap, test and shutdown steps, in file order, from inside
                the copy -> KPIs against the reference -> time against the budget -> controls -> results JSON

This file holds no bootstrap command and no test command: the only shell text it executes is a block of RUNBOOK.md
(Executor.run), and the only other process it starts is git, read-only, to list the files of the working tree.

Rows: a plain row must be true. A CONTROL row states a planted fault as if it had gone through and must be false.
A NOT-RUN row is neither. The onboarding budget (step 5) is OURS: the test plan gives no number.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
FOLDERS = ["estimed", "mec011_appsupport", "mec010p2"]      # what the five test descriptions need (tests/conftest.py)
EXCLUDE = ["estimed/private_lab"]   # a folder of the author's own tree, large and unrelated to the lab (the published
                                    # repository has no such folder, so nothing is left out there)
MAX_COPY_BYTES = 50 * 1024 * 1024
MEC_PORTS = {"MEC 011 (started by the tests)": 8091, "MEC 010-2 (started by the tests)": 8092}
BUDGET_S = 900.0        # OURS, not the test plan's: empty directory -> TD_MEC_DEV_01 passed, environments already installed
BAND = (0.2, 5.0)       # a step's duration in the rerun, as a ratio to the reference; reported, never a pass condition
LAST_TD = "TD_MEC_DEV_01"
RUN_PHASES = ["bootstrap", "test", "shutdown"]
PHASES = ["variables", "install"] + RUN_PHASES
PLACE_VARS = {"ROOT", "RUN", "OUT"}                         # where things are; every other variable keeps the runbook's value
SHELL_TAGS = {"", "sh", "bash", "zsh", "shell", "console"}
ADMIN = "CAdmin"
STEP_TIMEOUT_S = 900


class RunbookError(Exception):
    pass


class RerunError(Exception):
    pass


# ------------------------------------------------------------------------------------------ the runbook
@dataclass(frozen=True)
class Step:
    id: str
    phase: str
    command: str            # the fenced block, exactly as written
    sha256: str
    attrs: tuple = ()
    td: str | None = None
    tests: int | None = None


@dataclass
class Runbook:
    steps: list = field(default_factory=list)
    variables: dict = field(default_factory=dict)


_MARK = re.compile(r"^: runbook-step ([\w-]+)((?:[ \t]+\w+=[\w.-]+)*)[ \t]+&&[ \t]+(\S.*)$")


def parse_runbook(text: str) -> Runbook:
    """Every fenced shell block must be ONE command chain that starts with `: runbook-step <id> phase=<phase> ... &&`
    (`:` is a no-op in bash and zsh, so the block can be pasted as it is). Blocks tagged otherwise (text, json) are
    not commands."""
    rb, seen, block, tag = Runbook(), set(), None, ""
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            if block is None:
                block, tag = [], line[3:].strip().lower()
                continue
            body, block = "\n".join(block), None
            if tag not in SHELL_TAGS:
                continue
            logical = body.replace("\\\n", "")
            m = _MARK.match(logical.strip()) if "\n" not in logical.strip() else None
            if "\n" in logical.strip():
                raise RunbookError(f"block ending at line {n}: a block is one command chain joined by &&, not several lines")
            if not m:
                raise RunbookError(f"block ending at line {n}: no runbook-step marker at its start")
            sid, attrs, rest = m.group(1), dict(a.split("=", 1) for a in m.group(2).split()), m.group(3)
            if sid in seen:
                raise RunbookError(f"step id {sid} appears twice")
            seen.add(sid)
            phase = attrs.get("phase")
            if phase not in PHASES:
                raise RunbookError(f"step {sid}: phase must be one of {PHASES}, got {phase!r}")
            if re.search(r"[;|&]", rest.replace("&&", "")):
                raise RunbookError(f"step {sid}: only && may join commands (no ';', '|', '||' or '&'), so a failed "
                                   f"command fails the block")
            td = tests = None
            if phase == "test":
                td = attrs.get("td")
                if not td:
                    raise RunbookError(f"step {sid}: a test step names its test description with td=")
                if not attrs.get("tests", "").isdigit() or int(attrs["tests"]) < 1:
                    raise RunbookError(f"step {sid}: a test step states how many tests it runs with tests=<n>, n >= 1")
                tests = int(attrs["tests"])
            if phase == "variables":
                for name, value in re.findall(r"export (\w+)=(\"[^\"]*\"|\S+)", rest):
                    rb.variables[name] = value.strip('"')
            rb.steps.append(Step(sid, phase, body.strip("\n"), hashlib.sha256(body.strip("\n").encode()).hexdigest(),
                                 tuple(sorted(attrs.items())), td, tests))
        elif block is not None:
            block.append(line)
    if block is not None:
        raise RunbookError("a fenced block is not closed")
    for s in rb.steps:
        for name in re.findall(r"\$\{?([A-Za-z_]\w*)", s.command):
            if name not in rb.variables:
                raise RunbookError(f"step {s.id} uses ${name}, which the variables block does not set")
    order = [RUN_PHASES.index(s.phase) for s in rb.steps if s.phase in RUN_PHASES]
    if order != sorted(order):
        raise RunbookError("order: bootstrap steps come first, then test steps, then shutdown")
    for need in RUN_PHASES:
        if not any(s.phase == need for s in rb.steps):
            raise RunbookError(f"the runbook has no {need} step")
    return rb


def plan(rb: Runbook) -> list:
    """The steps a rerun executes, in file order. The variables block and the install blocks are not among them."""
    return [s for s in rb.steps if s.phase in RUN_PHASES]


def without_bootstrap(steps: list) -> list:
    return [s for s in steps if s.phase != "bootstrap"]


class Executor:
    """The one place a runbook command is executed: a Step of the plan it was built with, as written, by bash, with
    the given environment and nothing else."""

    def __init__(self, steps: list, env: dict, cwd):
        self.allowed = {(s.id, s.sha256) for s in steps}
        self.env, self.cwd, self.log = dict(env), str(cwd), []

    def run(self, step: Step) -> dict:
        if (step.id, step.sha256) not in self.allowed or hashlib.sha256(step.command.encode()).hexdigest() != step.sha256:
            raise RerunError(f"step {step.id}: this command is not in the runbook's plan; nothing was executed")
        started, t0 = _utc(), time.monotonic()
        try:
            p = subprocess.run(["bash", "-c", step.command], env=self.env, cwd=self.cwd, capture_output=True, text=True,
                               stdin=subprocess.DEVNULL, timeout=STEP_TIMEOUT_S)
            rc, out, err = p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            rc, out, err = 124, str(e.stdout or ""), f"timed out after {STEP_TIMEOUT_S} s"
        seconds = round(time.monotonic() - t0, 3)
        self.log.append({"id": step.id, "sha256": step.sha256, "rc": rc, "seconds": seconds, "started_utc": started})
        return {"rc": rc, "stdout": out, "stderr": err, "seconds": seconds}


def check_executed(steps: list, log: list) -> list:
    """What the log of executed commands says against the plan: every step once, in order, and nothing else."""
    known, problems = {(s.id, s.sha256): i for i, s in enumerate(steps)}, []
    got = [(e["id"], e["sha256"]) for e in log]
    for key in got:
        if key not in known:
            problems.append(f"not in the runbook: {key[0]}")
    for s in steps:
        n = got.count((s.id, s.sha256))
        if n == 0:
            problems.append(f"not executed: {s.id}")
        elif n > 1:
            problems.append(f"more than once: {s.id}")
    seq = [known[k] for k in got if k in known]
    if seq != sorted(seq):
        problems.append("order: the steps were not executed in the runbook's order")
    return problems


# ------------------------------------------------------------------------------------------ copy and manifest
def _sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _tree_sha(files: list) -> str:
    return hashlib.sha256("".join(f"{f['sha256']}  {f['mode']}  {f['path']}\n" for f in files).encode()).hexdigest()


def select(paths: list, folders: list, exclude: list) -> list:
    def under(p, roots):
        return any(p == r or p.startswith(r + "/") for r in roots)
    return sorted({p for p in paths if under(p, folders) and not under(p, exclude)})


def require_empty_dir(path) -> None:
    p = Path(path)
    if p.is_symlink() or (p.exists() and not p.is_dir()):
        raise RerunError(f"{p} is not a directory")
    if p.exists() and any(p.iterdir()):
        raise RerunError(f"{p} is not empty: a rerun starts from a directory with nothing in it")


def make_copy(src, files: list, dest, max_bytes: int) -> dict:
    src, dest, todo, total = Path(src).resolve(), Path(dest), [], 0
    require_empty_dir(dest)
    for rel in sorted(set(files)):
        if Path(rel).is_absolute() or ".." in Path(rel).parts:
            raise RerunError(f"{rel} is outside the source tree")
        s = src / rel
        if any(q.is_symlink() for q in [s, *s.parents][:len(Path(rel).parts)]):
            raise RerunError(f"{rel} is or lies behind a symbolic link; the copy takes regular files only")
        if not s.is_file():
            raise RerunError(f"{rel} is not a regular file")
        total += s.stat().st_size
        todo.append((rel, s))
    if total > max_bytes:
        raise RerunError(f"the copy would hold {total} bytes, over the limit of {max_bytes}")
    out = []
    for rel, s in todo:
        d = dest / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        data, mode = s.read_bytes(), s.stat().st_mode & 0o777
        d.write_bytes(data)
        d.chmod(mode)
        out.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "mode": f"{mode:o}"})
    return {"files": out, "file_count": len(out), "total_bytes": sum(f["bytes"] for f in out), "tree_sha256": _tree_sha(out)}


def verify_copy(dest, manifest: dict) -> list:
    """Problems of the copy against its manifest: a changed, missing or extra file, a changed mode."""
    dest, problems = Path(dest), []
    if _tree_sha(manifest["files"]) != manifest["tree_sha256"] or len(manifest["files"]) != manifest["file_count"]:
        problems.append("tree_sha256: the manifest's entries are not the ones it was sealed with")
    listed = set()
    for f in manifest["files"]:
        p = dest / f["path"]
        listed.add(f["path"])
        if p.is_symlink() or not p.is_file():
            problems.append(f"missing: {f['path']}")
        elif _sha_file(p) != f["sha256"] or p.stat().st_size != f["bytes"]:
            problems.append(f"changed: {f['path']}")
        elif f"{p.stat().st_mode & 0o777:o}" != f["mode"]:
            problems.append(f"mode: {f['path']}")
    for p in sorted(dest.rglob("*")):
        rel = str(p.relative_to(dest))
        if (p.is_symlink() or not p.is_dir()) and rel not in listed:
            problems.append(f"extra: {rel}")
    return problems


def _git(repo: Path, *args: str) -> list:
    """Read-only git: the NUL-separated names an ls-files / diff prints, or the single line of rev-parse."""
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    if p.returncode != 0:
        raise RerunError(f"git {' '.join(args[:2])} failed: {p.stderr.strip()[:200]}")
    return [x for x in re.split(r"[\0\n]", p.stdout) if x]


def working_tree_files(repo: Path) -> dict:
    """The tracked files as they are in the working tree plus the untracked, not-ignored ones, for FOLDERS without
    EXCLUDE; and which of them differ from the commit."""
    tracked = select(_git(repo, "ls-files", "-z", "--", *FOLDERS), FOLDERS, EXCLUDE)
    untracked = select(_git(repo, "ls-files", "-z", "--others", "--exclude-standard", "--", *FOLDERS), FOLDERS, EXCLUDE)
    modified = select(_git(repo, "diff", "--name-only", "-z", "HEAD", "--", *FOLDERS), FOLDERS, EXCLUDE)
    deleted = [p for p in tracked if not (repo / p).is_file()]
    files = sorted(set(p for p in tracked if p not in deleted) | set(untracked))
    differs = ([{"path": p, "status": "deleted in the working tree", "sha256": None} for p in deleted]
               + [{"path": p, "status": "modified", "sha256": _sha_file(repo / p)} for p in modified if p not in deleted]
               + [{"path": p, "status": "untracked", "sha256": _sha_file(repo / p)} for p in untracked])
    return {"commit": _git(repo, "rev-parse", "HEAD")[0], "files": files, "differs_from_commit": sorted(differs, key=lambda d: d["path"])}


# ------------------------------------------------------------------------------------------ outcomes and KPIs
def kpi_rate(numerator: int, denominator: int) -> dict:
    return {"numerator": numerator, "denominator": denominator, "N": denominator,
            "value": round(100.0 * numerator / denominator, 2) if denominator else None}


def td_result(step, xml_text: str, tail: str, rc: int) -> dict:
    """One test step. It passes only if every declared test ran and passed: a skipped, deselected, expected-to-fail or
    missing test is a failure, never a pass."""
    problems, cases = [], []
    if not xml_text.strip():
        problems.append("no result file was written")
    else:
        try:
            for tc in ET.fromstring(xml_text).iter("testcase"):
                kinds = {c.tag for c in tc}
                outcome = ("error" if "error" in kinds else "failed" if "failure" in kinds
                           else "skipped" if "skipped" in kinds else "passed")
                cases.append((f"{tc.get('classname')}::{tc.get('name')}", outcome))
        except ET.ParseError as e:
            problems.append(f"result file not readable: {e}")
    ids = sorted(i for i, _ in cases)
    count = {k: sum(o == k for _, o in cases) for k in ("passed", "failed", "error", "skipped")}
    for k in ("failed", "error", "skipped"):
        if count[k]:
            problems.append(f"{count[k]} {k}: " + ", ".join(i.split("::")[-1] for i, o in cases if o == k)[:300])
    if len(ids) != len(set(ids)):
        problems.append("a test id appears twice in the result file")
    if len(cases) != step.tests:
        problems.append(f"{len(cases)} ran, {step.tests} declared")
    for word in ("deselected", "xpassed", "xfailed", "skipped"):
        if re.search(rf"\b{word}\b", tail) and not any(word in p for p in problems):
            problems.append(f"the runner's summary line says {word}: {tail.strip()[:120]}")
    if rc != 0:
        problems.append(f"exit status {rc}")
    return {"td": step.td, "step": step.id, "ok": not problems, "problems": problems, "declared": step.tests,
            "ran": len(cases), "ids": ids, "summary_line": tail.strip()[:200], **count}


def plant_skip(xml_text: str) -> str:
    """For the control: the same result file with its first test turned into a skipped one."""
    doc = ET.fromstring(xml_text)
    ET.SubElement(next(doc.iter("testcase")), "skipped")
    return ET.tostring(doc, encoding="unicode")


def census_delta(before: dict, after: dict) -> dict:
    """Per CSE: the resources present after a step that were not there before it (by kind = resource type), over the
    resources present after; and the ones that went away."""
    out = {}
    for cse in sorted(after):
        b, a = before.get(cse, {}), after[cse]
        left, removed = {}, {}
        for path in sorted(set(a) - set(b)):
            left[str(a[path])] = left.get(str(a[path]), 0) + 1
        for path in sorted(set(b) - set(a)):
            removed[str(b[path])] = removed.get(str(b[path]), 0) + 1
        out[cse] = {"numerator": sum(left.values()), "denominator": len(a), "N": len(a), "left": left, "removed": removed}
    return out


def compare_kpis(ref: dict, new: dict) -> list:
    """Differences in the quantities that are equal by construction. Timings and the size of the tree a step found
    (the census denominators) are not among them."""
    diff = []
    rt, nt = ref.get("tests_passed") or {}, new.get("tests_passed") or {}
    if not rt or not nt:
        diff.append("tests_passed: nothing to compare on at least one side")
    for td in sorted(set(rt) | set(nt)):
        a, b = rt.get(td), nt.get(td)
        if a is None or b is None or any(a.get(k) != b.get(k) for k in ("numerator", "denominator", "N", "ids")):
            diff.append(f"tests_passed {td}: reference {_short(a)} against rerun {_short(b)}")
    a, b = ref.get("cse_registration_success"), new.get("cse_registration_success")
    if a is None or b is None or any(a.get(k) != b.get(k) for k in ("numerator", "denominator", "N")):
        diff.append(f"cse_registration_success: reference {_short(a)} against rerun {_short(b)}")
    rl, nl = ref.get("resources_left") or {}, new.get("resources_left") or {}
    for td in sorted(set(rl) | set(nl)):
        for cse in sorted(set(rl.get(td) or {}) | set(nl.get(td) or {})):
            a, b = (rl.get(td) or {}).get(cse), (nl.get(td) or {}).get(cse)
            if a is None or b is None or any(a.get(k) != b.get(k) for k in ("numerator", "left", "removed")):
                diff.append(f"resources_left {td} {cse}: reference {_short(a)} against rerun {_short(b)}")
    if set(rl) != set(rt) or set(nl) != set(nt):
        diff.append("resources_left: not taken for the same test descriptions as tests_passed")
    return diff


def _short(k) -> str:
    if k is None:
        return "absent"
    return f"{k.get('numerator')}/{k.get('denominator')}" + (f" left {k['left']} removed {k['removed']}" if "left" in k else "")


def in_band(ref_s: float, new_s: float) -> bool:
    return bool(ref_s) and BAND[0] <= new_s / ref_s <= BAND[1]


def verdict(rows: list) -> bool:
    ctl = [ok for name, ok, _ in rows if name.startswith("CONTROL")]
    real = [ok for name, ok, _ in rows if not name.startswith("CONTROL")]
    return bool(real) and all(real) and bool(ctl) and not any(ctl)


# ------------------------------------------------------------------------------------------ the live lab (loopback only)
def _ini(conf: Path, key: str) -> str:
    m = re.search(rf"(?m)^{key}=(.*)$", conf.read_text())
    return m.group(1).strip() if m else ""


def cses_of(root: Path) -> list:
    out = []
    for conf in sorted((root / "estimed" / "conf").glob("*.ini")):
        out.append({"node": conf.stem, "name": _ini(conf, "cseName"), "csi": _ini(conf, "cseID"),
                    "port": int(_ini(conf, "httpPort")), "is_in": not _ini(conf, "registrarCseID")})
    return out


def _get(port: int, path: str):
    r = urllib.request.Request(f"http://127.0.0.1:{port}/{path}", headers={
        "X-M2M-Origin": ADMIN, "X-M2M-RI": f"census-{time.monotonic_ns()}", "X-M2M-RVI": "4", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except (OSError, ValueError) as e:
        return 0, {"error": str(e)}


def census(cses: list) -> dict:
    """Every resource below each CSEBase with its type, as the CSE's administrator sees it."""
    out = {}
    for c in cses:
        st, body = _get(c["port"], f"{c['name']}?fu=1&rcn=6")
        if st != 200 or "m2m:rrl" not in body:
            raise RerunError(f"census of {c['name']} on :{c['port']} failed: {st} {str(body)[:120]}")
        out[c["name"]] = {r["val"]: r["typ"] for r in body["m2m:rrl"].get("rrf", [])}
    return out


def registration(cses: list) -> dict:
    """MN-CSEs registered both ways (the IN lists <IN>/<MN id>, the MN lists <MN>/<IN id>) over the MN-CSEs configured."""
    inn = [c for c in cses if c["is_in"]]
    mns = [c for c in cses if not c["is_in"]]
    if len(inn) != 1:
        raise RerunError(f"the configuration has {len(inn)} IN-CSEs, expected one")
    _, at_in = _get(inn[0]["port"], f"{inn[0]['name']}?fu=1&ty=16")
    good, detail = 0, {}
    for mn in mns:
        _, at_mn = _get(mn["port"], f"{mn['name']}?fu=1&ty=16")
        both = (f"{inn[0]['name']}/{mn['csi']}" in at_in.get("m2m:uril", [])
                and f"{mn['name']}/{inn[0]['csi']}" in at_mn.get("m2m:uril", []))
        good += both
        detail[mn["name"]] = both
    return dict(kpi_rate(good, len(mns)), per_cse=detail)


def _listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tail(text: str) -> str:
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return lines[-1] if lines else ""


def environment_pins(rb: Runbook, root: Path) -> list:
    """For each install block that names its environment (env=VENV or env=PY): every name==version it installs, also
    through a -r file, against what that environment holds. The environments are read, not created."""
    out = []
    for s in rb.steps:
        env = dict(s.attrs).get("env")
        if s.phase != "install" or not env:
            continue
        text = s.command
        for ref in re.findall(r"-r[ \t]+\"?([^\s\"]+)", s.command):
            text += "\n" + Path(ref.replace("$ROOT", str(root))).read_text()
        base = Path(rb.variables[env]) if env == "VENV" else Path(rb.variables[env]).parent.parent
        for name, ver in sorted(set(re.findall(r"(?m)(?:^|[\s\"])([A-Za-z][\w.-]*)==([0-9][\w.]*)", text))):
            hits = list(base.glob(f"lib/python3*/site-packages/{name.replace('-', '_')}-{ver}.dist-info"))
            out.append({"environment": str(base), "package": name, "pinned": ver, "installed": len(hits) == 1})
    return out


# ------------------------------------------------------------------------------------------ the two runs
class Record:
    def __init__(self):
        self.rows, self.not_run = [], []

    def step(self, name: str, ok, detail: str = "") -> bool:
        ok = bool(ok)
        self.rows.append((name, ok, detail))
        tag = "ok  " if ok else "FAIL"
        if name.startswith("CONTROL"):
            tag = "FAIL (as it must)" if not ok else "PASSED -- THE CONTROL DID NOT CATCH IT"
        print(f"  {tag}  {name}" + (f"\n          {detail}" if detail else ""), flush=True)
        return ok

    def skip(self, name: str, reason: str):
        self.not_run.append({"row": name, "result": "NOT-RUN", "reason": reason})
        print(f"  NOT-RUN  {name}\n          {reason}", flush=True)


def run_tests(ex: Executor, steps: list, out: Path, cses: list, rec: Record | None) -> dict:
    """The test steps in order, a census of every CSE before and after each. Stops at the first step that fails."""
    results, left, timings = {}, {}, {}
    for s in steps:
        before = census(cses)
        r = ex.run(s)
        xml = out / f"{s.td}.xml"
        (out / f"{s.td}.stdout.txt").write_text(r["stdout"] + "\n--- stderr ---\n" + r["stderr"])
        res = td_result(s, xml.read_text() if xml.is_file() else "", _tail(r["stdout"]), r["rc"])
        results[s.td], timings[s.td] = res, r["seconds"]
        try:
            left[s.td] = census_delta(before, census(cses))
        except RerunError as e:
            res["ok"] = False
            res["problems"].append(str(e))
        if rec:
            rec.step(f"step 3/4: {s.td} -- every one of the {s.tests} declared tests ran and passed", res["ok"],
                     f"{res['passed']}/{res['declared']} passed, {res['ran']} ran, {r['seconds']} s"
                     + ("; " + "; ".join(res["problems"]) if res["problems"] else ""))
        if not res["ok"]:
            break
    return {"results": results, "resources_left": left, "timings_s": timings}


def kpis_of(run: dict, reg: dict) -> dict:
    return {"tests_passed": {td: dict(kpi_rate(r["passed"], r["declared"]), ids=r["ids"]) for td, r in run["results"].items()},
            "cse_registration_success": reg, "resources_left": run["resources_left"], "timings_s": run["timings_s"]}


def base_env(rb: Runbook, places: dict) -> dict:
    if set(places) != PLACE_VARS:
        raise RerunError("the places given are not exactly ROOT, RUN and OUT")
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": os.environ.get("HOME", "/"), "LANG": "C.UTF-8"}
    env.update(rb.variables)
    env.update({k: str(v) for k, v in places.items()})
    return env


def provenance(args, rb_path: Path, rb: Runbook) -> dict:
    return {"script": str(Path(__file__).resolve()), "script_sha256": _sha_file(Path(__file__).resolve()),
            "runbook": str(rb_path), "runbook_sha256": _sha_file(rb_path),
            "plan": [{"id": s.id, "phase": s.phase, "td": s.td, "sha256": s.sha256} for s in plan(rb)],
            "host": platform.node(), "kernel": platform.release(), "python_of_this_script": sys.version.split()[0],
            "argv": sys.argv[1:], "utc": _utc(), "what": "fresh copy on the same host; no virtual machine, no container"}


def cmd_reference(args) -> int:
    src = Path(args.source).resolve()
    rb_path = src / "estimed" / "RUNBOOK.md"
    rb = parse_runbook(rb_path.read_text())
    out = Path(args.out)
    require_empty_dir(out)
    out.mkdir(parents=True, exist_ok=True)
    steps = [s for s in plan(rb) if s.phase == "test"]
    cses = cses_of(src)
    print(f"reference run from the working tree {src} against the lab as it stands")
    ex = Executor(steps, base_env(rb, {"ROOT": src, "RUN": args.lab_run, "OUT": out}), src)
    reg = registration(cses)
    run = run_tests(ex, steps, out, cses, Record())
    ok = len(run["results"]) == len(steps) and all(r["ok"] for r in run["results"].values())
    tree = working_tree_files(src)
    doc = {"kind": "reference", "result": "PASS" if ok else "FAIL", "provenance": provenance(args, rb_path, rb),
           "commit": tree["commit"], "differs_from_commit": tree["differs_from_commit"], "kpi": kpis_of(run, reg),
           "results": run["results"], "executed": ex.log}
    Path(args.results).parent.mkdir(parents=True, exist_ok=True)
    Path(args.results).write_text(json.dumps(doc, indent=1) + "\n")
    print(f"reference: {'PASS' if ok else 'FAIL'} -- {args.results}")
    return 0 if ok else 1


def cmd_rerun(args) -> int:
    rec, src = Record(), Path(args.source).resolve()
    ref = json.loads(Path(args.reference).read_text())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = Path(args.base) / stamp
    root, run_dir, out = base / "copy", Path(args.run_dir) if args.run_dir else base / "run", base / "out"
    doc = {"kind": "rerun", "directories": {"base": str(base), "copy": str(root), "run": str(run_dir), "out": str(out)},
           "budget_s": {"value": args.budget, "whose": "ours; the test plan (7.6.3.1 step 5) names no number",
                        "covers": "empty directory -> copy -> bootstrap -> the five test steps, until TD_MEC_DEV_01 passed; "
                                  "the interpreter environments were already installed"}}
    ex = ctl_ex = None
    t0 = time.monotonic()
    kpi, t_last, ports_all = {}, None, {}
    try:
        print(f"fresh copy on the same host: {root}")
        base.mkdir(parents=True, exist_ok=False)
        tree = working_tree_files(src)
        man = make_copy(src, tree["files"], root, MAX_COPY_BYTES)
        man.update(commit=tree["commit"], source=str(src), folders=FOLDERS, excluded=EXCLUDE,
                   differs_from_commit=tree["differs_from_commit"], written_utc=_utc())
        (base / "manifest.json").write_text(json.dumps(man, indent=1) + "\n")
        doc["manifest"] = {k: man[k] for k in ("commit", "source", "folders", "excluded", "file_count", "total_bytes",
                                               "tree_sha256", "differs_from_commit")}
        doc["manifest"]["file"] = str(base / "manifest.json")
        rec.step("step 1: fresh copy made from the working tree, manifest written", True,
                 f"{man['file_count']} files, {man['total_bytes']} bytes, commit {man['commit'][:12]}, "
                 f"{len(man['differs_from_commit'])} files differ from it; tree {man['tree_sha256'][:16]}")
        rec.step("step 1: the copy is what the manifest says before anything runs", not (p := verify_copy(root, man)), "; ".join(p[:5]))

        rb_path = Path(args.runbook) if args.runbook else root / "estimed" / "RUNBOOK.md"
        rb = parse_runbook(rb_path.read_text())
        steps = plan(rb)
        doc["provenance"] = provenance(args, rb_path, rb)
        env = base_env(rb, {"ROOT": root, "RUN": run_dir, "OUT": out})
        doc["environment_given_to_every_step"] = env
        ex = Executor(steps, env, root)
        cses = cses_of(root)
        ports_all = {**{f"CSE {c['name']}": c["port"] for c in cses}, **MEC_PORTS}

        try:
            require_empty_dir(run_dir)
            why = ""
        except RerunError as e:
            why = str(e)
        rec.step("pre-test: the run directory is new or empty (no node state is reused)", not why, why or str(run_dir))
        busy = [f"{k} :{v}" for k, v in ports_all.items() if _listening(v)]
        rec.step("pre-test: nothing of the lab is running (no CSE or MEC port answers)", not busy, ", ".join(busy))
        pins = environment_pins(rb, root)
        doc["environments"] = pins
        rec.step("pre-test: the two installed environments hold the versions the runbook's install blocks name "
                 "(reused, not created)", bool(pins) and all(p["installed"] for p in pins) and len({p["environment"] for p in pins}) == 2,
                 ", ".join(f"{p['package']}=={p['pinned']}{'' if p['installed'] else ' MISSING'}" for p in pins))
        same = [s.sha256 for s in steps if s.phase == "test"] == [s["sha256"] for s in ref["provenance"]["plan"] if s["phase"] == "test"]
        rec.step("the reference ran the same test commands as this runbook holds", same and ref.get("result") == "PASS",
                 f"reference {ref.get('result')} of {ref['provenance']['utc']}")

        if verdict(rec.rows + [("CONTROL placeholder", False, "")]):
            boot_ok = True
            for s in steps:
                if s.phase != "bootstrap":
                    continue
                r = ex.run(s)
                (base / f"bootstrap_{s.id}.txt").write_text(r["stdout"] + "\n--- stderr ---\n" + r["stderr"])
                boot_ok = rec.step(f"step 1/2: bootstrap step {s.id} from the runbook exits 0", r["rc"] == 0,
                                   f"{r['seconds']} s; {_tail(r['stdout'])[:160]}")
                if not boot_ok:
                    break
            if boot_ok:
                reg = registration(cses)
                rec.step("step 2: after the runbook's bootstrap steps alone, every MN-CSE is registered both ways",
                         reg["numerator"] == reg["denominator"] > 0, f"{reg['numerator']}/{reg['denominator']}")
                run = run_tests(ex, [s for s in steps if s.phase == "test"], out, cses, rec)
                kpi = kpis_of(run, reg)
                doc["results"] = run["results"]
                if run["results"].get(LAST_TD, {}).get("ok"):
                    t_last = round(time.monotonic() - t0, 3)
                rec.step("step 3: all five test descriptions were run", len(run["results"]) == 5,
                         ", ".join(run["results"]))
                rec.step("the copy is unchanged after the tests (nothing was written into the code)",
                         not (p := verify_copy(root, man)), "; ".join(p[:5]))
    except (RerunError, RunbookError, OSError, KeyError, ValueError) as e:
        rec.step("the rerun ran to its end", False, f"{type(e).__name__}: {e}")
    finally:
        if ex is not None:
            for s in plan(rb):
                if s.phase == "shutdown":
                    r = ex.run(s)
                    rec.step(f"shutdown step {s.id} from the runbook exits 0", r["rc"] == 0, _tail(r["stdout"])[:160])
            time.sleep(1)
            busy = [f"{k} :{v}" for k, v in ports_all.items() if _listening(v)]
            rec.step("after shutdown nothing of the copy's lab answers", not busy, ", ".join(busy))

    if ex is not None:
        rec.step("step 2: the commands executed are the runbook's run steps, each once, in order, and nothing else",
                 not (p := check_executed(plan(rb), ex.log)), "; ".join(p))
        doc["executed"] = ex.log
    diff = compare_kpis(ref.get("kpi", {}), kpi)
    rec.step("step 4: the KPIs that are equal by construction are equal to the reference run's", not diff, "; ".join(diff)[:600])
    rec.step(f"step 5: empty directory to {LAST_TD} passed within the budget of {args.budget:.0f} s (ours)",
             t_last is not None and t_last <= args.budget, f"{t_last} s")
    timings = {td: {"reference_s": ref["kpi"]["timings_s"].get(td), "rerun_s": s,
                    "in_band": in_band(ref["kpi"]["timings_s"].get(td) or 0, s)} for td, s in kpi.get("timings_s", {}).items()}
    doc["kpi"] = {"equal_by_construction": {"reference": {k: v for k, v in ref.get("kpi", {}).items() if k != "timings_s"},
                                            "rerun": {k: v for k, v in kpi.items() if k != "timings_s"}, "differences": diff,
                                            "note": "the census denominators (resources on the CSE after the step) depend on "
                                                    "what the lab held before and are recorded, not compared"},
                  "timings": {"band_ratio_to_reference": list(BAND), "note": "reported, never compared for equality and "
                              "not a pass condition", "per_test_description": timings,
                              "empty_directory_to_last_test_description_s": t_last}}

    # ---- controls: each plants one fault and reports it as if it had gone through; each must come out false
    try:
        if ex is not None and kpi.get("tests_passed"):
            cut = without_bootstrap(plan(rb))
            ctl_out = base / "control_no_bootstrap"
            ctl_out.mkdir()
            ctl_ex = Executor(cut, dict(ex.env, OUT=str(ctl_out)), root)
            first = cut[0]
            r = ctl_ex.run(first)
            xml = ctl_out / f"{first.td}.xml"
            res = td_result(first, xml.read_text() if xml.is_file() else "", _tail(r["stdout"]), r["rc"])
            rec.step(f"CONTROL (must FAIL) with the bootstrap steps taken out of the runbook, {first.td} still passes", res["ok"],
                     f"{res['passed']}/{res['declared']} passed; " + "; ".join(res["problems"])[:240])
            for s in cut:
                if s.phase == "shutdown":
                    ctl_ex.run(s)
            doc["control_no_bootstrap_executed"] = ctl_ex.log

            foreign = Step("start-topology-by-hand", "bootstrap", ": not in the runbook", hashlib.sha256(b": not in the runbook").hexdigest())
            try:
                ex.run(foreign)
                ran = True
            except RerunError:
                ran = False
            rec.step("CONTROL (must FAIL) a command that is not in the runbook was executed", ran)
            rec.step("CONTROL (must FAIL) an executed-command log with one foreign entry is accepted",
                     not check_executed(plan(rb), ex.log + [{"id": foreign.id, "sha256": foreign.sha256, "rc": 0}]))

            victim = next(f["path"] for f in man["files"] if f["path"].endswith("conf/in.ini"))
            small = make_copy(root, [victim], base / "control_copy", MAX_COPY_BYTES)
            with open(base / "control_copy" / victim, "ab") as f:
                f.write(b"\n; changed after the manifest\n")
            p = verify_copy(base / "control_copy", small)
            shutil.rmtree(base / "control_copy")
            rec.step("CONTROL (must FAIL) a copy in which a file was changed after the manifest was written is accepted",
                     not p, "; ".join(p[:3]))

            try:
                require_empty_dir(run_dir)      # it now holds the logs and data of the run just made
                accepted = True
            except RerunError as e:
                accepted, why = False, str(e)
            rec.step("CONTROL (must FAIL) a run directory with old state is accepted", accepted, "" if accepted else why)

            first_test = next(s for s in plan(rb) if s.phase == "test")
            xml_text = plant_skip((out / f"{first_test.td}.xml").read_text())
            res = td_result(first_test, xml_text, "", 0)
            rec.step("CONTROL (must FAIL) a skipped test is counted as passed",
                     res["ok"] or res["passed"] == first_test.tests, f"{res['passed']}/{res['declared']} passed, {res['skipped']} skipped")

            off = json.loads(json.dumps(kpi))
            td = sorted(off["tests_passed"])[0]
            off["tests_passed"][td]["numerator"] -= 1
            d = compare_kpis(ref.get("kpi", {}), off)
            rec.step("CONTROL (must FAIL) the KPI comparison passes when one test description's count differs",
                     d == diff, "; ".join(x for x in d if x not in diff)[:240])
    except (RerunError, RunbookError, OSError, KeyError, ValueError, StopIteration) as e:
        rec.step("the controls ran to their end", False, f"{type(e).__name__}: {e}")
    if ports_all:
        busy = [f"{k} :{v}" for k, v in ports_all.items() if _listening(v)]
        rec.step("after the controls nothing of the copy's lab answers", not busy, ", ".join(busy))

    rec.skip("pre-test condition: a fresh VM with no prior oneM2M or MEC configuration",
             "this PC has no VM tool and containers are off; what ran is a fresh copy of the code on the same host with "
             "a new, empty run directory and no lab process running")
    rec.skip("a fresh install of the two interpreter environments (RUNBOOK.md install blocks)",
             "nothing is installed from the network here; both environments are the installed ones, checked against the "
             "versions the install blocks name")
    ok = verdict(rec.rows)
    doc.update(result="PASS" if ok else "FAIL", finished_utc=_utc(),
               steps=[{"row": n, "ok": o, "detail": d} for n, o, d in rec.rows if not n.startswith("CONTROL")],
               controls=[{"row": n, "passed": o, "failed_as_it_must": not o, "detail": d} for n, o, d in rec.rows if n.startswith("CONTROL")],
               not_run=rec.not_run, reference_file=str(Path(args.reference).resolve()))
    if ok and not args.keep and root.is_dir():
        shutil.rmtree(root)
        doc["copy_removed"] = True
    else:
        doc["copy_removed"] = False
    results = Path(args.results_dir) / f"clean_rerun_{stamp}.json"
    results.parent.mkdir(parents=True, exist_ok=True)
    results.write_text(json.dumps(doc, indent=1) + "\n")
    n_ctl = sum(n.startswith("CONTROL") for n, _, _ in rec.rows)
    print(f"\nRESULT: {'PASS' if ok else 'FAIL'} (fresh copy on the same host; steps "
          f"{sum(o for n, o, _ in rec.rows if not n.startswith('CONTROL'))}/{len(rec.rows) - n_ctl} ok; controls failed as they must "
          f"{sum(not o for n, o, _ in rec.rows if n.startswith('CONTROL'))}/{n_ctl}; NOT-RUN {len(rec.not_run)}; "
          f"{t_last} s of {args.budget:.0f} s; copy {'removed' if doc['copy_removed'] else 'KEPT at ' + str(root)})\n{results}")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("reference")
    a.add_argument("--source", default=str(HERE.parent))
    a.add_argument("--out", required=True, help="an empty directory for the result files of the test steps")
    a.add_argument("--results", required=True, help="the reference JSON to write")
    a.add_argument("--lab-run", default="/home/edgefollow/estimed-run")
    a.set_defaults(fn=cmd_reference)
    b = sub.add_parser("rerun")
    b.add_argument("--source", default=str(HERE.parent))
    b.add_argument("--reference", required=True)
    b.add_argument("--base", default="/home/edgefollow/estimed-run/clean")
    b.add_argument("--run-dir", default=None, help="default: <base>/<UTC stamp>/run")
    b.add_argument("--runbook", default=None, help="default: the copy's estimed/RUNBOOK.md")
    b.add_argument("--results-dir", default="/home/edgefollow/estimed-run/sim")
    b.add_argument("--budget", type=float, default=BUDGET_S)
    b.add_argument("--keep", action="store_true", help="keep the copy also after a PASS")
    b.set_defaults(fn=cmd_rerun)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
