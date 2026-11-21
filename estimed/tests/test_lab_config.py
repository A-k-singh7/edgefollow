"""The lab's own description matches what it runs (deep check 2026-10-29, two defects): the IN-CSE's database is
described as it is configured, and there is ONE ACME version -- the one installed in the venv run_topology.sh uses, the
pin in estimed/requirements.txt and the one the README names -- so a result can say which CSE build it ran on.
No topology needed: files only.

    /home/edgefollow/edgefollow-lab/.venv/bin/python -m pytest estimed/tests/test_lab_config.py -q
"""
from __future__ import annotations

import configparser
import glob
import re
from pathlib import Path

EST = Path(__file__).resolve().parent.parent
VENV = Path("/home/edgefollow/estimed-venv")             # run_topology.sh's VENV default


def _ini(name: str) -> configparser.ConfigParser:
    c = configparser.ConfigParser(interpolation=None)
    c.optionxform = str                              # ACME's keys are camelCase
    c.read(EST / "conf" / name)
    return c


def test_the_in_cse_database_is_described_as_it_is_configured():
    db = _ini("in.ini")["basic.config"]["databaseType"]
    head = [l for l in (EST / "run_topology.sh").read_text().splitlines()[:12] if re.match(r"#\s+IN-CSE\s+id-in\b", l)]
    assert db in ("memory", "tinydb", "postgresql"), db
    assert len(head) == 1, head
    if db == "memory":
        assert "durable" not in head[0] and "in-memory" in head[0], head[0]
    else:
        assert "durable" in head[0], head[0]


def test_one_acme_version_installed_pinned_and_documented():
    dist = glob.glob(str(VENV / "lib" / "python3*" / "site-packages" / "acmecse-*.dist-info"))
    assert len(dist) == 1, dist
    installed = re.search(r"acmecse-([0-9.]+)\.dist-info$", dist[0]).group(1)
    req = EST / "requirements.txt"
    assert req.exists(), "estimed/requirements.txt pins nothing: it does not exist"
    pin = re.search(r"^acmecse==([0-9.]+)\s*(#.*)?$", req.read_text(), re.M)
    assert pin and pin.group(1) == installed, (pin and pin.group(1), installed)
    named = re.findall(r"ACME oneM2M CSE (\d{4}\.\d+\.\d+)", (EST / "README.md").read_text())
    assert named and set(named) == {installed}, (named, installed)
