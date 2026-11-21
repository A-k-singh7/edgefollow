#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""TD_MEC_FL_01: the MEC platform of TD_MEC_REG_03, loaded by path from SOURCE_TREE and refused unless each
file's bytes hash to the SHA-256 pinned here. Nothing of it is copied.

    estimed/mec_app_deploy.py        the platform agent: checks a package's digests, onboards it at MEC 010-2,
                                     starts its workload as a process of this user, stops it
    mec010p2/candidate.py            our GS MEC 010-2 candidate (app_pkgm/v1, app_lcm/v1), served on :8092
    mec011_appsupport/candidate.py   our GS MEC 011 candidate (app support, service registry), served on the port
                                     given (district A: :8097)

Why by path and not a copy: (1) the agent relies on this MEC 010-2 candidate (a terminated instance is
NOT_INSTANTIATED again, a new package starts DISABLED, an instantiated instance cannot be deleted); (2) the MEC 011
candidate is loaded by path elsewhere too, so one convention; (3) a copy goes stale without a sound, while a pin
fails closed the moment a pinned file changes. The pins are the files as committed at SOURCE_COMMIT (test_fl.py
checks each pin against `git show` of that commit when that commit is in the repository's history).

A file is read once; the bytes that were hashed are the bytes that are executed (no second read).

    python mec_pinned.py serve mec010p2           # the candidate's own main: seeds, its path shim, :8092
    python mec_pinned.py serve mec011 8097        # the candidate's app behind its own shim on the given port
    python mec_pinned.py check                    # print each pin and whether the file matches (exit 1 if not)

The candidates need the lab interpreter (FastAPI, uvicorn); the agent is standard library only.
"""
from __future__ import annotations

import hashlib
import sys
import types
from pathlib import Path

SOURCE_TREE = Path(__file__).resolve().parent.parent
SOURCE_COMMIT = "411125a0c3ec9df9141fdea63ee4a745466405bc"
PINS = {
    "estimed/mec_app_deploy.py": "305eea0aa94fc73781ad5ec6f7d2622ca0e4af1772e57479b082acc379661896",
    "mec010p2/candidate.py": "eac38db2c40324d7bc0c6ac767d11ad7e7f5c07c002f66e63621c5c0e39003d0",
    "mec011_appsupport/candidate.py": "7701b3cc592024f0894a2891290cd78b21d0d920c92872929cb58f3e50283e59",
}
SERVE = {"mec010p2": "mec010p2/candidate.py", "mec011": "mec011_appsupport/candidate.py"}


class PinError(Exception):
    """A pinned file is missing, unpinned or not the bytes its pin names."""


def read_pinned(rel: str, tree: Path = SOURCE_TREE) -> bytes:
    """The bytes of tree/rel, only if their SHA-256 is PINS[rel]."""
    if rel not in PINS:
        raise PinError(f"{rel}: no pin for this file (pinned: {sorted(PINS)})")
    path = Path(tree) / rel
    try:
        data = path.read_bytes()
    except OSError as e:
        raise PinError(f"{path}: cannot be read ({e})") from None
    got = hashlib.sha256(data).hexdigest()
    if got != PINS[rel]:
        raise PinError(f"{path}: SHA-256 {got} is not the pinned {PINS[rel]} (commit {SOURCE_COMMIT[:7]}); "
                       "refusing to run it")
    return data


def load_module(rel: str, name: str, tree: Path = SOURCE_TREE) -> types.ModuleType:
    """tree/rel as module `name`, executed from the verified bytes."""
    data, path = read_pinned(rel, tree), Path(tree) / rel
    mod = types.ModuleType(name)
    mod.__file__ = str(path)
    sys.modules[name] = mod          # before exec: a dataclass or a self-import looks itself up there
    try:
        exec(compile(data, str(path), "exec"), mod.__dict__)  # noqa: S102  the bytes whose hash was checked
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return mod


def platform_agent(tree: Path = SOURCE_TREE) -> types.ModuleType:
    """estimed/mec_app_deploy.py of the main tree (PlatformAgent, verify_package, ...)."""
    return load_module("estimed/mec_app_deploy.py", "mec_app_deploy", tree)


def provenance(tree: Path = SOURCE_TREE) -> dict:
    """What a results record says about the platform code: path, pinned SHA-256, commit, per file."""
    return {rel: {"path": str(Path(tree) / rel), "sha256": h, "commit": SOURCE_COMMIT} for rel, h in PINS.items()}


def _serve(argv: list[str]) -> int:
    which = argv[0] if argv else ""
    if which not in SERVE:
        print(f"usage: mec_pinned.py serve {{{'|'.join(SERVE)}}} [port]", file=sys.stderr)
        return 2
    rel = SERVE[which]
    if which == "mec010p2":            # the candidate's own __main__: seeds, its path shim, port 8092
        data, path = read_pinned(rel), SOURCE_TREE / rel
        exec(compile(data, str(path), "exec"), {"__name__": "__main__", "__file__": str(path)})  # noqa: S102
        return 0
    port = int(argv[1])
    load_module(rel, "mec011_candidate")._serve(port)     # what its own main does for :8091, on `port`
    return 0


def _check() -> int:
    bad = 0
    for rel, h in PINS.items():
        try:
            read_pinned(rel)
            print(f"ok        {h}  {SOURCE_TREE / rel}")
        except PinError as e:
            bad += 1
            print(f"MISMATCH  {e}")
    return 1 if bad else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["serve"]:
        sys.exit(_serve(sys.argv[2:]))
    if sys.argv[1:2] == ["check"]:
        sys.exit(_check())
    sys.exit("usage: mec_pinned.py serve {mec010p2|mec011} [port] | check")
