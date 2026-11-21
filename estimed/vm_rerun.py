#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""TD_MEC_OBS_03 (test plan 7.6.3.1) on a FRESH VIRTUAL MACHINE: Debian's genericcloud image, copied into a private
folder of this user while its SHA-512 is compared with Debian's SHA512SUMS, booted under QEMU/KVM from a new overlay on
that copy; cloud-init creates one user (no password, no key, no sudo); the code arrives as a tarball; then EXACTLY
the RUNBOOK.md install blocks (as root only the ones marked root=yes, every other one as that user) and then, as that
user, the runbook's rerun block (`: runbook-step <id> phase=rerun`), each block as written. Results come back by HTTP
uploads to this host and as summary lines on the serial console; the VM powers itself off.

    run --attempt 1                                   the runbook as committed
    run --attempt 2 --previous <record> --why <text>  after attempt 1 failed: the runbook with ONE change in the
                                                      working tree (estimed/RUNBOOK.md), recorded with its diff
    run ... --dry-run                                 everything up to starting QEMU (no VM, no image copy)
    root --config <file>                              inside the VM only; run.sh starts it as root (root=yes blocks)
    guest --config <file>                             inside the VM only; run.sh starts it as the user

Network. QEMU user-mode networking with restrict=on and ipv6=off: the VM reaches nothing on this host, the LAN or the
internet except two guestfwd targets over IPv4, each bridged by a small relay to ONE port on this host's 127.0.0.1:
the seed and upload server (10.0.2.100:8080 in the VM) and an allow-listing CONNECT proxy (10.0.2.101:3128) that
opens tunnels to pypi.org:443, files.pythonhosted.org:443 and deb.debian.org:443 only, refuses and logs everything
else, and caps bytes and time. ipv6=off because restrict=on alone does not stop TCP over IPv6 in libslirp 4.9.5.
Only the install blocks are given the proxy (HTTPS_PROXY; apt in the root blocks through APT_CONFIG), as listed
harness steps; no runbook command is changed. QEMU is refused if its command line is not exactly this.

Every command that is not the runbook's is the harness's and is one of HARNESS_STEPS; the record lists them. The
harness installs nothing and fixes nothing: a runbook block that fails is a FAIL of the step it belongs to.

Verdicts: each of the five OBS_03 steps is PASS, FAIL or NOT-RUN. A step is NOT-RUN only when it is known not to have
been attempted; evidence that did not come back is a FAIL, never a pass. clean_rerun.py's own verdict inside the VM
(the program the rerun block starts) must be PASS, and step 2 is judged again on this host from the VM's
executed-command log against the runbook this host delivered. Step 5 is timed on this host's clock only. A CONTROL
row plants one fault and must come out false. The onboarding budget (step 5) is OURS: the test plan gives no number.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import importlib.util
import io
import ipaddress
import json
import math
import os
import platform
import re
import selectors
import shutil
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
VM_DIR = Path("/run/media/edgefollow/data/estimed-vm-2026-11-20")
BASE_IMAGE = VM_DIR / "debian-13-genericcloud-amd64.qcow2"
SUMS_FILE = VM_DIR / "SHA512SUMS"
RUNS_DIR = VM_DIR / "runs"                      # NTFS: the evidence is copied here after the run, nothing runs from here
STAGE_PARENT = Path("/dev/shm")                 # tmpfs: keeps file modes, which the NTFS data disk does not
# The base-image copy, the overlay, the uploads and the logs live in a 0700 folder of this user on a LOCAL POSIX
# filesystem. On this PC (2026-11-20): / has 25 GB free but no folder this user may write; /home has 1.6 GB free (it
# hit 0 B on 2026-11-05); /var 0.6 GB; /tmp 0.3 GB; /dev/shm is RAM and would be charged to QEMU's memory cap. So the
# folder is /srv/estimed-vm on /, made once by its owner's root shell:  sudo install -d -o edgefollow -g edgefollow -m 0700 /srv/estimed-vm
PRIVATE_PARENT = Path("/srv/estimed-vm")
LOCAL_FSTYPES = frozenset({"ext4", "xfs", "btrfs"})
MIN_FREE_PRIVATE_BYTES = 4 << 30                # 344 MB copy + an overlay that the install blocks grow to about 1-2 GB
RESULTS_DIR = Path("/home/edgefollow/estimed-run/sim")
REFERENCE_DEFAULT = RESULTS_DIR / "clean_rerun_reference_2026-11-19.json"

# Written 2026-11-20 BEFORE the first VM run, and not changed after it. It is fixed by the test that pins it; commit
# this file before attempt 1, so that the commit shows the budget was set before the run (the record says whether it was).
BUDGET_S = 1800.0
BUDGET_REASON = ("ours, written 2026-11-20 before the first VM run; the test plan names no number. 900 s is the "
                 "runbook's own budget for empty directory -> TD_MEC_DEV_01 passed with the environments already "
                 "installed (33 s measured on this PC on 2026-11-18); the other 900 s are for what a clean VM adds: boot "
                 "and cloud-init, fetching the code, and the install blocks downloading the CSE, the test runner and "
                 "their dependencies from PyPI. Half an hour is one sitting for a developer onboarding.")
WALL_LIMIT_S = 3000.0       # QEMU is killed after this; longer than the budget so a slow run is measured, not cut off
POWEROFF_GRACE_S = 300.0    # after the summary line, the VM has this long to power itself off
VCPUS, MEM_MB, DISK_SIZE = 2, 4096, "8G"
MEMORY_CAP = "5G"           # systemd-run scope around QEMU, so a runaway VM cannot push earlyoom onto other work
MIN_MEM_AVAILABLE_KB = 6 * 1024 * 1024
MIN_FREE_RUNS_BYTES = 1 << 30
USER = "edgefollow"
GUEST_DIR = "/var/lib/vmrerun"
RUN_SH = GUEST_DIR + "/run.sh"
CONFIG_PATH = GUEST_DIR + "/config.json"
SUMS_PATH = GUEST_DIR + "/sums.txt"
HARNESS_HOME = "/home/edgefollow/vm-harness"
CLEAN_RERUN_RESULTS = "/home/edgefollow/estimed-run/sim"   # clean_rerun.py's --results-dir default, inside the VM
MAX_UPLOAD_BYTES = 8 << 20
MAX_UPLOAD_TOTAL = 96 << 20
MAX_UPLOADS = 300
UPLOAD_READ_TIMEOUT_S = 60.0
GUEST_FILE_CAP = 4 << 20    # the guest sends the tail of a longer log and says so
UPLOAD_PREFIX = "/up/"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,12}")
SERVED = ("meta-data", "user-data", "vendor-data", "code.tar", "guest.py", "reference.json")
FETCHED = ("code.tar", "guest.py", "reference.json")
MARKER = "VMRERUN-SUMMARY "
PROGRESS = "VMRERUN-PROGRESS "
ROOT_MARKER = "VMRERUN-ROOT "         # written by the root step itself (root only may write the console, ttyS0)
CONSOLE = "/dev/ttyS0"
RERUN_PHASE = "rerun"                 # `: runbook-step <id> phase=rerun` in a fence clean_rerun.py does not read
ROOT_ATTR = ("root", "yes")           # `: runbook-step <id> phase=install root=yes`: the one block kind run as root
ROOT_RESULT = "root_blocks.json"
APT_CONF = GUEST_DIR + "/apt-proxy.conf"
# The environment of every runbook block in the VM is exactly one of these plus the names the runbook's variables
# block exports (clean_rerun.base_env); HARNESS_STEPS names them, and the tests hold the two together.
BLOCK_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/edgefollow", "LANG": "C.UTF-8"}
ROOT_BLOCK_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
                  "LANG": "C.UTF-8"}     # dpkg refuses to run as root without the sbin folders on PATH
INCLUDE_ON_ATTEMPT_2 = ("estimed/RUNBOOK.md",)
TDS = ["TD_MEC_PF_01", "TD_MEC_REG_01", "TD_MEC_REG_02", "TD_MEC_REG_03", "TD_MEC_DEV_01"]
LAST_TD = TDS[-1]
PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT-RUN"
ADMIN_GROUPS = frozenset({"sudo", "wheel", "adm", "admin", "root"})

# ---- the network the VM gets: QEMU user mode, restrict=on, exactly two guestfwd targets
NETDEV_ID = "n0"
SEED_ADDR, SEED_GUEST_PORT = "10.0.2.100", 8080       # guestfwd addresses: slirp refuses its host (.2) and DNS (.3)
PROXY_ADDR, PROXY_GUEST_PORT = "10.0.2.101", 3128
SEED_URL = f"http://{SEED_ADDR}:{SEED_GUEST_PORT}"
PROXY_URL = f"http://{PROXY_ADDR}:{PROXY_GUEST_PORT}"
# pip: pypi.org and files.pythonhosted.org. apt: the image's sources are https://deb.debian.org/debian and
# https://deb.debian.org/debian-security (its /etc/apt/mirrors/*.list and cloud.cfg's failsafe mirrors, read from the
# image on 2026-11-20), so apt opens CONNECT tunnels to deb.debian.org:443 and nothing else; no plain-HTTP forwarding.
PROXY_ALLOW = frozenset({("pypi.org", 443), ("files.pythonhosted.org", 443), ("deb.debian.org", 443)})
PROXY_CONN_CAP = 512 << 20          # bytes through one tunnel, both ways
PROXY_TOTAL_CAP = 2 << 30           # bytes through all tunnels of a run
PROXY_MAX_CONNS = 1000              # tunnels opened in a run
PROXY_IDLE_S = 60.0                 # a tunnel with nothing moving for this long is closed
PROXY_CONN_MAX_S = 1200.0           # a tunnel is closed after this long whatever it does
PROXY_HEAD_MAX = 8192
PROXY_HEAD_TIMEOUT_S = 10.0
PROXY_CONNECT_TIMEOUT_S = 15.0
PROXY_LOG_MAX = 5000

OBS03_TEXT = {
    1: "A developer with no prior VM configuration follows the runbooks to bootstrap the VM (TD_MEC_PF_01).",
    2: "Bootstrap completes without requiring steps outside the runbook.",
    3: "Developer runs automated scripts for TD_MEC_REG_01 through TD_MEC_DEV_01.",
    4: "All scripted tests pass and produce the same KPI results as the original execution.",
    5: "Total time from clean VM to passing TD_MEC_DEV_01 is within the target onboarding budget.",
}

def _env_text(fixed: dict) -> str:
    return " ".join(f"{k}={v}" for k, v in fixed.items())


HARNESS_STEPS = {
    "create-user": "cloud-init creates user edgefollow: password locked (none is set), no SSH key, no sudo and no admin "
                   "group; no other user is created",
    "no-ssh-keys": "cloud-init: password login off, root login off, the image's host keys deleted and none generated",
    "power-off": "cloud-init power_state: power off once the harness script has ended",
    "progress": "a progress line on the serial console",
    "probe-root": "read-only facts as root: edgefollow's password state and groups, the files in /etc/ssh, edgefollow's home "
                  "before delivery",
    "fetch": f"curl: code.tar, guest.py (this file) and reference.json from the host's seed server at {SEED_ADDR}:"
             f"{SEED_GUEST_PORT} (a guestfwd target)",
    "check": "sha256sum --check of the three fetched files against the SHA-256s written in user-data",
    "root-blocks": "as root (run.sh runs as root): vm_rerun.py root -- RUNBOOK.md and clean_rerun.py read from the "
                   "checked code.tar into a folder of root's; ONLY the install blocks marked root=yes, in the "
                   "runbook's order, each exactly as written through clean_rerun's Executor (bash -c, from /root), "
                   f"with exactly the environment {_env_text(ROOT_BLOCK_ENV)}, every name the runbook's variables "
                   "block exports, HTTPS_PROXY and https_proxy (step proxy) and APT_CONFIG (step apt-proxy); their "
                   "ids, SHA-256s and exit codes go to the serial console from root itself and to root_blocks.json. "
                   "No other block is run as root",
    "deliver": "as edgefollow: make ROOT (the runbook's variables-block value) and the harness folder, unpack code.tar "
               "into ROOT, copy the harness files (the guest reads the root step's root_blocks.json where root wrote "
               "it, mode 0644)",
    "guest": "as edgefollow: vm_rerun.py guest -- facts read in-process, then the install blocks NOT marked root=yes and "
             "then the runbook's rerun block, each exactly as written through clean_rerun's Executor (bash -c, from "
             "edgefollow's home: the harness adds no cd; a cd inside a block runs), with exactly the environment "
             f"{_env_text(BLOCK_ENV)} and every name the runbook's variables block exports (the install blocks also "
             "HTTPS_PROXY and https_proxy, step proxy); then the uploads. The guest driver itself starts with "
             "HOME USER LOGNAME PATH LANG only",
    "proxy": f"every install block's environment (root=yes or not), and nothing else's, gets HTTPS_PROXY and "
             f"https_proxy = {PROXY_URL}, this host's allow-listing CONNECT proxy: with restrict=on and ipv6=off the VM "
             "has no other way out. No runbook command is changed; the rerun block runs without it",
    "apt-proxy": f"the root blocks' environment, and nothing else's, gets APT_CONFIG={APT_CONF}, a file the root step "
                 f"writes: Acquire::http::Proxy and Acquire::https::Proxy = {PROXY_URL}. apt reaches the image's "
                 "https://deb.debian.org sources through CONNECT deb.debian.org:443",
    "network": "QEMU user-mode networking with restrict=on, ipv6=off and exactly two guestfwd rules (the seed server "
               "and the proxy, each through a relay to one port on this host's 127.0.0.1); no port forward into the VM",
    "summary": "the guest's summary as one line on the serial console",
}

NOT_SHOWN = [
    "one VM type: QEMU with KVM on this PC (i7-6700HQ), 2 vCPUs, 4 GB, an 8 GB overlay disk, user-mode networking "
    "with restrict=on",
    "one base image: the Debian 13 genericcloud amd64 cloud image; no other distribution or image was tried",
    "Debian's SHA512SUMS is not signature-checked: the image is compared with the SHA512SUMS file downloaded next to "
    "it from the same server; its OpenPGP signature (SHA512SUMS.sign) was not verified",
    "pip pulls the dependencies of the pinned packages unpinned from PyPI during the run; another day can resolve "
    "other versions, and a PyPI or network outage would fail the install blocks",
    "a script followed the runbook, not a human: it ran the blocks exactly as written and cannot misread the prose "
    "around them, so text a person would trip over is not tested",
    "the original execution (the reference) was made on this host from the working tree of 2026-11-18; the VM ran "
    "HEAD (see code.vs_reference_commit for the files that differ)",
    "the VM reached only the seed server and the allow-listing proxy (pypi.org:443, files.pythonhosted.org:443, "
    "deb.debian.org:443), both on this host through guestfwd over IPv4; it had no DNS (slirp's restricted mode drops "
    "it), so the proxy resolved names here and refused non-public addresses. A developer's VM with a full internet "
    "connection has none of these limits: a block that fetches from another host fails here",
    "IPv6 was off (ipv6=off): restrict=on alone let a crafted IPv6 SYN open host connections in libslirp 4.9.5. That "
    "ipv6=off closes it was shown with this host's libslirp run in-process (in6_enabled=0, the value QEMU's ipv6=off "
    "sets), not with QEMU, which was not installed when the harness was written; the VM's own list of IPv6 "
    "addresses is read in the run and an address other than loopback or link-local is an integrity problem",
    "apt is given the proxy only in the root-marked install blocks, through APT_CONFIG; the image's apt sources are "
    "https://deb.debian.org (read from the image), so apt uses CONNECT deb.debian.org:443. apt over http:// would get "
    "405 from this CONNECT-only proxy, and a mirror other than deb.debian.org would get 403",
    "unattended-upgrades and systemd-timesyncd are not disabled by any harness step: with restrict=on, ipv6=off and "
    "APT_CONFIG set only in the root blocks' environment neither can fetch or sync from the network, but they may "
    "still run and take CPU or the dpkg lock; the runbook's root block waits for the dpkg lock (DPkg::Lock::Timeout), "
    "and whether apt-get update also waits for the package-list lock with that option was not checked here",
    "the whole in-VM evidence chain but the root blocks' console line (the guest driver, clean_rerun.py, the uploads, "
    "summary.json) runs as edgefollow, the same user as the code under test: a program that lies could forge a "
    "consistent PASS inside the VM. This host checks what it can (hashes of the delivered code and runbook, the "
    "executed-command log against the delivered runbook, its own clock), not the honesty of what ran in the VM",
    "the VM's clock is used for no verdict: step 5's time is an upper bound, from QEMU's start to this host's receipt "
    "of the VM's clean_rerun record, so it also holds clean_rerun's shutdown and controls after TD_MEC_DEV_01",
    "the base image was copied, and hashed while copying, into a 0700 folder of this user on a local filesystem and "
    "re-hashed after the run; a process of this same user could change and restore the copy during the run, which "
    "the re-hash after it cannot see",
    "the rerun block ran from edgefollow's home directory, exactly as written: the harness adds no cd, and a cd inside "
    "the block runs. clean_rerun.py reads no phase=rerun block (its parser refuses any phase but variables, install, "
    "bootstrap, test and shutdown in a shell fence), so the block sits in a fence clean_rerun.py skips and the "
    "harness alone recognises it, with clean_rerun's marker and && rules",
    "clean_rerun.py's own two NOT-RUN rows are fixed text written for this PC; inside the VM both are covered by this "
    "record (the VM is fresh, and the install blocks were run)",
]

# clean_rerun.py's rows that come after the tests, and its controls: inside the VM each must be there and right
POST_TEST_ROWS = ("the copy is unchanged after the tests (nothing was written into the code)",
                  "after shutdown nothing of the copy's lab answers",
                  "after the controls nothing of the copy's lab answers")
CR_CONTROL_ROWS = (
    "CONTROL (must FAIL) with the bootstrap steps taken out of the runbook, TD_MEC_PF_01 still passes",
    "CONTROL (must FAIL) a command that is not in the runbook was executed",
    "CONTROL (must FAIL) an executed-command log with one foreign entry is accepted",
    "CONTROL (must FAIL) a copy in which a file was changed after the manifest was written is accepted",
    "CONTROL (must FAIL) a run directory with old state is accepted",
    "CONTROL (must FAIL) a skipped test is counted as passed",
    "CONTROL (must FAIL) the KPI comparison passes when one test description's count differs",
)
ROOT_WORDS = re.compile(r"(?<![\w.-])(sudo|su|doas|pkexec|runuser)(?![\w.-])")


class VmError(Exception):
    pass


def _clean_rerun(estimed_dir: Path | None = None):
    """clean_rerun.py, the runbook's own parser and executor: on this host the one next to this file, in the VM the one
    of the delivered code (named explicitly, never from sys.path)."""
    if estimed_dir is None and "clean_rerun" in sys.modules:
        return sys.modules["clean_rerun"]
    path = Path(estimed_dir or HERE) / "clean_rerun.py"
    spec = importlib.util.spec_from_file_location("clean_rerun", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["clean_rerun"] = mod
    spec.loader.exec_module(mod)
    return mod


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------------------------------ the base image
def listed_digest(sums_text: str, name: str) -> str:
    """The SHA-512 Debian's SHA512SUMS gives for exactly this file name; exactly one line must name it."""
    hits = []
    for line in sums_text.splitlines():
        m = re.fullmatch(r"([0-9a-f]{128}) [ *](\S+)", line.strip())
        if m and m.group(2) == name:
            hits.append(m.group(1))
    if len(hits) != 1:
        raise VmError(f"SHA512SUMS has {len(hits)} lines with a SHA-512 for {name}; exactly one is needed")
    return hits[0]


def check_base_image(image, sums) -> dict:
    """The image where it lies, against SHA512SUMS (the dry run; a real run copies it, see copy_base_image)."""
    image, sums = Path(image), Path(sums)
    want = listed_digest(sums.read_text(), image.name)
    got = _sha_file(image, "sha512")
    if got != want:
        raise VmError(f"{image} has SHA-512 {got[:16]}..., Debian's SHA512SUMS lists {want[:16]}...: refused")
    return {"path": str(image), "bytes": image.stat().st_size, "sha512": got, "listed": want, "ok": True,
            "sums_file": str(sums), "sums_sha512": _sha_file(sums, "sha512")}


def copy_base_image(src, dst, listed: str) -> dict:
    """Copies the image into the private folder, hashing the bytes as they are read and written (one pass, so what is
    hashed is what is written), refuses a copy whose SHA-512 is not the listed one, makes it read-only and reads it
    back once. QEMU's overlay is backed by this copy, never by the file on the NTFS disk."""
    src, dst = Path(src), Path(dst)
    h, n = hashlib.sha512(), 0
    fd = os.open(dst, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with open(src, "rb") as f, os.fdopen(fd, "wb") as out:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
                out.write(chunk)
                n += len(chunk)
            out.flush()
            os.fsync(out.fileno())
    except BaseException:
        dst.unlink(missing_ok=True)
        raise
    digest = h.hexdigest()
    if digest != listed:
        dst.unlink()
        raise VmError(f"{src} copied with SHA-512 {digest[:16]}..., Debian's SHA512SUMS lists {listed[:16]}...: refused")
    os.chmod(dst, 0o400)
    again = _sha_file(dst, "sha512")
    if again != digest:
        raise VmError(f"the copy {dst} does not read back as it was written")
    return {"source": str(src), "path": str(dst), "bytes": n, "sha512": digest, "listed": listed, "ok": True,
            "copy_read_back_sha512": again, "how": "hashed while copying, then read back once; mode 0400"}


# ------------------------------------------------------------------------------------------ the private folder
def fs_type(path) -> str | None:
    """The filesystem type of the mount holding `path`, from /proc/self/mountinfo (device number, longest mount point)."""
    p = os.path.realpath(path)
    st = os.stat(p)
    dev = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    best, kind = -1, None
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        left, sep, right = line.partition(" - ")
        f, r = left.split(), right.split()
        if not sep or len(f) < 5 or not r or f[2] != dev:
            continue
        mp = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), f[4])
        if (p == mp or p.startswith(mp.rstrip("/") + "/")) and len(mp) > best:
            best, kind = len(mp), r[0]
    return kind


def check_private_dir(path, need_bytes: int | None = None) -> dict:
    """The folder for the image copy, the overlay and the uploads: a directory (not a link) of this user, mode 0700,
    on a local POSIX filesystem, with room."""
    p = Path(path)
    need = MIN_FREE_PRIVATE_BYTES if need_bytes is None else need_bytes
    out = {"path": str(p), "ok": False, "why": "", "fstype": None, "free_bytes": None, "need_bytes": need}
    if not p.is_absolute():
        out["why"] = f"{p} is not an absolute path (a relative one would depend on where this program was started)"
        return out
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        out["why"] = (f"{p} does not exist; make it once, as root: install -d -o {USER} -g {USER} -m 0700 {p}")
        return out
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        out["why"] = f"{p} is not a directory (or is a symbolic link)"
        return out
    if st.st_uid != os.getuid():
        out["why"] = f"{p} belongs to uid {st.st_uid}, not to this user"
        return out
    if st.st_mode & 0o777 != 0o700:
        out["why"] = f"{p} has mode {st.st_mode & 0o777:o}, not 700"
        return out
    out["fstype"] = fs_type(p)
    if out["fstype"] not in LOCAL_FSTYPES:
        out["why"] = f"{p} is on {out['fstype']!r}, not a local POSIX filesystem ({', '.join(sorted(LOCAL_FSTYPES))})"
        return out
    out["free_bytes"] = shutil.disk_usage(p).free
    if out["free_bytes"] < need:
        out["why"] = f"{p} has {out['free_bytes'] >> 20} MB free, {need >> 20} MB are needed"
        return out
    out["ok"] = True
    return out


def new_private_run_dir(parent, stamp: str) -> Path:
    d = Path(parent) / stamp
    os.mkdir(d, 0o700)
    os.chmod(d, 0o700)
    return d


def copy_evidence(src_dir, dst_dir, skip=("base.qcow2", "overlay.qcow2")) -> list:
    """Every regular file of the private run folder but the disk images, to the NTFS run folder, with its SHA-256."""
    src_dir, dst_dir, out = Path(src_dir), Path(dst_dir), []
    for p in sorted(src_dir.rglob("*")):
        rel = p.relative_to(src_dir)
        if p.is_symlink() or not p.is_file() or rel.as_posix() in skip:
            continue
        d = dst_dir / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, d)
        out.append({"path": rel.as_posix(), "sha256": _sha_file(p), "bytes": p.stat().st_size})
    return out


# ------------------------------------------------------------------------------------------ code delivery
def _git(repo: Path, args: list, env: dict | None = None, text: bool = True):
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=text, stdin=subprocess.DEVNULL,
                       env=env, timeout=120)
    if p.returncode != 0:
        err = p.stderr if text else p.stderr.decode(errors="replace")
        raise VmError(f"git {' '.join(args[:2])} failed: {err.strip()[:200]}")
    return p.stdout


def _committed(repo: Path, rel: str) -> bool:
    """Whether `rel` is tracked and its working-tree bytes are HEAD's (read-only git)."""
    for args in (["ls-files", "--error-unmatch", "--", rel], ["diff", "--quiet", "HEAD", "--", rel]):
        if subprocess.run(["git", "-C", str(repo), *args], capture_output=True, stdin=subprocess.DEVNULL,
                          timeout=60).returncode != 0:
            return False
    return True


def _ls_tree(repo: Path, rev: str, cr, env=None) -> dict:
    out = {}
    for entry in _git(repo, ["ls-tree", "-r", "-z", "--full-tree", rev, "--", *cr.FOLDERS], env).split("\0"):
        if not entry:
            continue
        meta, path = entry.split("\t", 1)
        mode, kind, obj = meta.split()
        if kind == "blob" and cr.select([path], cr.FOLDERS, cr.EXCLUDE):
            out[path] = (mode, obj)
    return out


def build_code(repo, stage, include=()) -> dict:
    """The runbook's ROOT set (clean_rerun.FOLDERS without EXCLUDE) from `git archive HEAD`, the working-tree versions
    of the paths in `include` that differ from HEAD laid over it, as a git checkout with ONE commit holding exactly
    these files (section 6's clean_rerun.py lists the code's files with git), packed as one tarball. Every
    working-tree difference in the set is listed with whether it was delivered. The main repository is only read."""
    cr = _clean_rerun()
    repo, stage = Path(repo).resolve(), Path(stage)
    if stage.exists() and (not stage.is_dir() or any(stage.iterdir())):
        raise VmError(f"{stage} is not new: the code is staged in an empty folder")
    code = stage / "code"
    code.mkdir(parents=True)
    probe = stage / "mode-probe"
    probe.write_bytes(b"")
    probe.chmod(0o644)
    if probe.stat().st_mode & 0o777 != 0o644:
        raise VmError(f"{stage} is on a filesystem that does not keep file modes (NTFS through fuse reads 777); "
                      "stage the code on a POSIX filesystem")
    probe.unlink()
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"           # reading the main tree never refreshes its index
    head = _git(repo, ["rev-parse", "HEAD"]).strip()
    head_date = _git(repo, ["show", "-s", "--format=%cI", "HEAD"]).strip()
    tree = _ls_tree(repo, "HEAD", cr)
    if not tree or any(mode == "120000" for mode, _ in tree.values()):
        raise VmError("the ROOT set at HEAD is empty or holds a symbolic link")
    arch = _git(repo, ["archive", "--format=tar", "HEAD", "--", *cr.FOLDERS, *[f":(exclude){e}" for e in cr.EXCLUDE]],
                text=False)
    with tarfile.open(fileobj=io.BytesIO(arch)) as t:
        members = [m for m in t.getmembers() if m.isfile()]
        if any(m.issym() or m.islnk() for m in t.getmembers()):
            raise VmError("git archive holds a link")
        if sorted(m.name for m in members) != sorted(tree):
            raise VmError("git archive and git ls-tree disagree about the ROOT set")
        t.extractall(code, members=members, filter="data")
    wt = cr.working_tree_files(repo)
    diffs, delivered = [], []
    for d in wt["differs_from_commit"]:
        take = d["path"] in include and d["status"] == "modified"
        if take:
            (code / d["path"]).write_bytes((repo / d["path"]).read_bytes())
            delivered.append(d["path"])
        diffs.append({"path": d["path"], "status": d["status"], "delivered": take})
    genv = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(stage), "LANG": "C",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_AUTHOR_NAME": "vm_rerun harness", "GIT_AUTHOR_EMAIL": "vm_rerun@localhost",
            "GIT_COMMITTER_NAME": "vm_rerun harness", "GIT_COMMITTER_EMAIL": "vm_rerun@localhost",
            "GIT_AUTHOR_DATE": head_date, "GIT_COMMITTER_DATE": head_date}
    msg = (f"vm_rerun: {', '.join(cr.FOLDERS)} without {', '.join(cr.EXCLUDE)} from git archive {head[:12]}"
           + (f"; from the working tree: {', '.join(delivered)}" if delivered else ""))
    _git(code, ["init", "-q", "--template=", "-b", "main"], genv)
    _git(code, ["add", "-A", "-f"], genv)
    _git(code, ["-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "commit", "-q", "--no-verify", "-m", msg],
         genv)
    synthetic = _git(code, ["rev-parse", "HEAD"], genv).strip()
    staged = {}
    for entry in _git(code, ["ls-files", "-s", "-z"], genv).split("\0"):
        if entry:
            meta, path = entry.split("\t", 1)
            mode, obj, _ = meta.split()
            staged[path] = (mode, obj)
    if set(staged) != set(tree) or any(staged[p] != tree[p] for p in tree if p not in delivered) \
            or any(staged[p][0] != tree[p][0] for p in delivered):
        raise VmError("the delivered commit does not hold HEAD's blobs for the ROOT set")
    files = []
    for p in sorted(tree):
        data = (code / p).read_bytes()
        files.append({"path": p, "sha256": _sha(data), "bytes": len(data), "mode": f"{(code / p).stat().st_mode & 0o777:o}"})
    tar_path = stage / "code.tar"
    mtime = int(datetime.fromisoformat(head_date).timestamp())
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as t:
        for path in sorted(code.rglob("*")):
            if path.is_symlink():
                raise VmError(f"{path} is a symbolic link")
            ti = t.gettarinfo(str(path), arcname=path.relative_to(code).as_posix())
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            ti.mtime = mtime
            if path.is_file():
                with open(path, "rb") as f:
                    t.addfile(ti, f)
            else:
                t.addfile(ti)
    return {"tar": str(tar_path), "sha256": _sha_file(tar_path), "bytes": tar_path.stat().st_size, "head": head,
            "head_date": head_date, "synthetic_commit": synthetic, "folders": list(cr.FOLDERS),
            "excluded": list(cr.EXCLUDE), "file_count": len(files), "files": files, "tree_sha256": cr._tree_sha(files),
            "differences_from_head": diffs, "delivered_from_working_tree": delivered, "code_dir": str(code)}


# ------------------------------------------------------------------------------------------ user-data
def install_plan(rb) -> list:
    return [{"id": s.id, "sha256": s.sha256} for s in rb.steps if s.phase == "install"]


def is_root_block(step) -> bool:
    return dict(step.attrs).get(ROOT_ATTR[0]) == ROOT_ATTR[1]


def root_block_ids(rb) -> list:
    """The install blocks marked root=yes, in the runbook's order. Refused: root= with another value, root= on a block
    that is not an install block (clean_rerun.py runs those as its own user), and a root block after an unmarked
    install block (the root step runs before the unmarked ones, so it would change the runbook's order)."""
    ids, unmarked_seen = [], False
    for s in rb.steps:
        a = dict(s.attrs)
        if ROOT_ATTR[0] not in a:
            unmarked_seen = unmarked_seen or s.phase == "install"
            continue
        if a[ROOT_ATTR[0]] != ROOT_ATTR[1]:
            raise VmError(f"step {s.id}: root={a[ROOT_ATTR[0]]}; the only value is root=yes")
        if s.phase != "install":
            raise VmError(f"step {s.id}: root=yes on a {s.phase} block; only install blocks may be run as root")
        if unmarked_seen:
            raise VmError(f"step {s.id}: a root=yes block after an unmarked install block; the root blocks come first")
        ids.append(s.id)
    return ids


def blocks_needing_root(rb) -> list:
    """Runbook blocks marked root=yes (run as root by the root step) and blocks that name a command that gets root
    without the marker (run as edgefollow, who has no sudo: they fail as written). The record lists both."""
    return [{"id": s.id, "phase": s.phase, "marker_root": is_root_block(s),
             "names": sorted(set(ROOT_WORDS.findall(s.command)))}
            for s in rb.steps if s.phase != "variables" and (is_root_block(s) or ROOT_WORDS.search(s.command))]


def rerun_block(text: str, rb, cr):
    """The runbook's rerun block, or None: a fenced block whose info string is NOT one of clean_rerun.SHELL_TAGS (so
    clean_rerun.parse_runbook skips it: its parser refuses any phase but variables, install, bootstrap, test and
    shutdown, so it cannot carry this one) and whose body starts with `: runbook-step <id> phase=rerun`. The harness
    alone recognises it, with parse_runbook's own rules: clean_rerun._MARK, one command chain joined by && only, every
    $NAME set by the variables block, an id no other block has. A runbook-step marker with another phase in such a
    fence, or two rerun blocks, is refused."""
    blocks, block, tag = [], None, ""
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            if block is None:
                block, tag = [], line[3:].strip().lower()
                continue
            body, block = "\n".join(block), None
            logical = body.replace("\\\n", "").strip()
            if tag in cr.SHELL_TAGS or not logical.startswith(": runbook-step"):
                continue
            m = cr._MARK.match(logical) if "\n" not in logical else None
            if not m:
                raise VmError(f"block ending at line {n}: a runbook-step marker in a ```{tag} fence that is not one "
                              "command chain `: runbook-step <id> phase=rerun && ...`")
            sid, rest = m.group(1), m.group(3)
            attrs = dict(a.split("=", 1) for a in m.group(2).split())
            if attrs != {"phase": RERUN_PHASE}:
                raise VmError(f"block ending at line {n}: a ```{tag} fence holds `: runbook-step {sid}` with "
                              f"{attrs}; clean_rerun.py does not read it, and the harness runs only "
                              f"phase={RERUN_PHASE} (and nothing else in the marker) from such a fence")
            if re.search(r"[;|&]", rest.replace("&&", "")):
                raise VmError(f"step {sid}: only && may join commands (no ';', '|', '||' or '&')")
            for name in re.findall(r"\$\{?([A-Za-z_]\w*)", body):
                if name not in rb.variables:
                    raise VmError(f"step {sid} uses ${name}, which the variables block does not set")
            if sid in {s.id for s in rb.steps} or sid in {s.id for s in blocks}:
                raise VmError(f"step id {sid} appears twice")
            command = body.strip("\n")
            blocks.append(cr.Step(sid, RERUN_PHASE, command, hashlib.sha256(command.encode()).hexdigest(),
                                 tuple(sorted(attrs.items()))))
        elif block is not None:
            block.append(line)
    if len(blocks) > 1:
        raise VmError(f"the runbook has {len(blocks)} rerun blocks ({', '.join(s.id for s in blocks)}); one is run")
    return blocks[0] if blocks else None


def proxy_env(proxy_url: str) -> dict:
    return {"HTTPS_PROXY": proxy_url, "https_proxy": proxy_url}


def apt_proxy_conf(proxy_url: str) -> str:
    return f'Acquire::http::Proxy "{proxy_url}";\nAcquire::https::Proxy "{proxy_url}";\n'


def expected_install_env(rb, cfg: dict) -> dict:
    """The environment the unmarked install blocks get in the VM: clean_rerun's base_env with the runbook's own places,
    as edgefollow (HOME /home/edgefollow), plus the proxy (harness step `proxy`)."""
    return {**BLOCK_ENV, **rb.variables, **proxy_env(cfg["proxy"])}


def expected_rerun_env(rb) -> dict:
    return {**BLOCK_ENV, **rb.variables}


def expected_root_env(rb, cfg: dict) -> dict:
    """The environment of the root=yes blocks: root's PATH and HOME, the runbook's variables, the proxy, APT_CONFIG."""
    return {**ROOT_BLOCK_ENV, **rb.variables, **proxy_env(cfg["proxy"]), "APT_CONFIG": cfg["apt_conf"]}


def guest_config(attempt: int, stamp: str, code_root: str, install_plan: list, root_ids: list | None = None,
                 rerun: dict | None = None) -> dict:
    return {"attempt": attempt, "stamp": stamp, "server": SEED_URL, "proxy": PROXY_URL, "code_root": code_root,
            "harness_dir": HARNESS_HOME, "guest_dir": GUEST_DIR, "reference": HARNESS_HOME + "/reference.json",
            "install_plan": install_plan, "root_block_ids": list(root_ids or []), "rerun_block": rerun,
            "apt_conf": APT_CONF, "console": CONSOLE, "file_cap": GUEST_FILE_CAP,
            "clean_rerun_results": CLEAN_RERUN_RESULTS}


# The template's SHA-256 is pinned in tests/test_vm_rerun.py: a change to it is a change to the harness, made on purpose.
RUN_SH_TEMPLATE = r"""#!/bin/bash
# vm_rerun.py harness inside the VM, started once by cloud-init (runcmd) as root. Every command line names its
# HARNESS_STEPS entry. The runbook's install blocks marked root=yes are run by the root step (harness:root-blocks),
# as root; every other runbook block by the guest driver (harness:guest), as edgefollow.
set -u
H=__GUEST_DIR__
W=__HARNESS_HOME__
CODE=__CODE_ROOT__
SRV=__SERVER__
say() { printf 'VMRERUN-PROGRESS %s\n' "$1" > /dev/ttyS0; }
stop() { printf 'VMRERUN-SUMMARY {"attempt": __ATTEMPT__, "harness_error": "%s"}\n' "$1" > /dev/ttyS0; exit 0; }
say harness-start  # harness:progress
{ passwd -S edgefollow; id edgefollow; ls -l /etc/ssh; ls -A /home/edgefollow; } > "$H/probe_root.txt" 2>&1  # harness:probe-root
for f in code.tar guest.py reference.json; do curl -fsS --retry 5 --retry-connrefused --max-time 600 -o "$H/$f" "$SRV/$f" || stop "fetch $f"; done  # harness:fetch
cd "$H" && sha256sum --check --strict sums.txt > "$H/check.txt" 2>&1 || stop "sha256 of a fetched file"  # harness:check
say root-start  # harness:progress
env -i HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 python3 -I -B "$H/guest.py" root --config "$H/config.json"  # harness:root-blocks
say "root-done $?"  # harness:progress
runuser -u edgefollow -- mkdir -p "$W" "$CODE" || stop "mkdir"  # harness:deliver
runuser -u edgefollow -- tar -xf "$H/code.tar" -C "$CODE" || stop "unpack"  # harness:deliver
runuser -u edgefollow -- cp "$H/guest.py" "$H/reference.json" "$H/config.json" "$H/probe_root.txt" "$W/" || stop "copy"  # harness:deliver
say guest-start  # harness:progress
runuser -u edgefollow -- env -i HOME=/home/edgefollow USER=edgefollow LOGNAME=edgefollow PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8 python3 -I -B "$W/guest.py" guest --config "$W/config.json"  # harness:guest
say "guest-done $?"  # harness:progress
test -s "$W/summary.json" || stop "no summary"  # harness:summary
printf 'VMRERUN-SUMMARY %s\n' "$(head -c 60000 "$W/summary.json")" > /dev/ttyS0  # harness:summary
"""


def make_run_sh(cfg: dict) -> str:
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", cfg["code_root"]):
        raise VmError(f"code root {cfg['code_root']!r} is not a plain absolute path")
    if cfg["server"] != SEED_URL:
        raise VmError(f"server {cfg['server']!r} is not the seed server's guestfwd address {SEED_URL}")
    return (RUN_SH_TEMPLATE.replace("__GUEST_DIR__", GUEST_DIR).replace("__HARNESS_HOME__", HARNESS_HOME)
            .replace("__CODE_ROOT__", cfg["code_root"]).replace("__SERVER__", cfg["server"])
            .replace("__ATTEMPT__", str(int(cfg["attempt"]))))


def sums_text(shas: dict) -> str:
    return "".join(f"{shas[name]}  {name}\n" for name in FETCHED)


EXPECTED_USER = {"name": USER, "lock_passwd": True, "shell": "/bin/bash"}


def make_user_data(cfg: dict, sums: str, run_sh: str) -> str:
    doc = {"users": [dict(EXPECTED_USER)],
           "ssh_pwauth": False, "disable_root": True, "ssh_deletekeys": True, "ssh_genkeytypes": [],
           "package_update": False, "package_upgrade": False,
           "write_files": [{"path": RUN_SH, "permissions": "0700", "content": run_sh},
                           {"path": CONFIG_PATH, "permissions": "0644", "content": json.dumps(cfg, indent=1) + "\n"},
                           {"path": SUMS_PATH, "permissions": "0644", "content": sums}],
           "runcmd": [["bash", RUN_SH]],
           "power_state": {"mode": "poweroff", "delay": "now", "condition": True, "timeout": 60,
                           "message": "vm_rerun: the harness script has ended"}}
    return "#cloud-config\n" + json.dumps(doc, indent=1) + "\n"     # JSON is YAML: the audit below reads it back exactly


def make_meta_data(stamp: str) -> str:
    return f"instance-id: vmrerun-{stamp}\nlocal-hostname: estimed-vm\n"


ALLOWED_TOP = {"users", "ssh_pwauth", "disable_root", "ssh_deletekeys", "ssh_genkeytypes", "package_update",
               "package_upgrade", "write_files", "runcmd", "power_state"}
SAFE_KEYS = {"lock_passwd", "ssh_pwauth", "ssh_deletekeys", "ssh_genkeytypes"}
_SECRETISH = re.compile(r"pass|key|chpasswd|ssh_import|cert|token|secret|sudo", re.I)
RUN_SH_FORBIDDEN = ("pip", "venv", "acmecse", "pytest", "run_topology", "stop_topology", "apt", "dpkg", "ssh-keygen",
                    "chpasswd", "useradd", "usermod", "sudo", "0.0.0.0")
_STRUCTURAL = re.compile(r"#!/bin/bash|#( .*)?|set -u|[A-Z]+=\S+|(say|stop)\(\) \{.*\}|")


def audit_run_sh(run_sh: str) -> list:
    """A second look at run.sh's shape; the rule that decides is audit_user_data's byte-for-byte comparison."""
    problems, tags = [], set()
    for n, line in enumerate(run_sh.splitlines(), 1):
        m = re.search(r"  # harness:([\w-]+)$", line)
        if m:
            tags.add(m.group(1))
            if m.group(1) not in HARNESS_STEPS:
                problems.append(f"run.sh line {n}: unknown harness step {m.group(1)}")
        elif not _STRUCTURAL.fullmatch(line):
            problems.append(f"run.sh line {n}: a command that names no harness step: {line[:80]}")
    for word in RUN_SH_FORBIDDEN:
        if re.search(rf"\b{re.escape(word)}", run_sh):
            problems.append(f"run.sh names {word!r}: installing, user and key commands are not the harness's")
    for need in ("fetch", "check", "deliver", "guest", "summary"):
        if need not in tags:
            problems.append(f"run.sh has no {need} step")
    return problems


def audit_user_data(text: str, cfg: dict, sums: str) -> list:
    """Problems of a user-data against what this harness may do. The rule: user-data, run.sh, config.json and sums.txt
    are each the harness's own, byte for byte, made from `cfg` and `sums`. Then, read back: one user, password
    locked, no key, password or sudo field anywhere, cloud-init installing nothing, the runbook's own install blocks,
    only the seed server's and the proxy's URLs."""
    if not text.startswith("#cloud-config\n"):
        return ["user-data does not start with #cloud-config"]
    try:
        doc = json.loads(text.split("\n", 1)[1])
    except ValueError as e:
        return [f"user-data is not the JSON this harness writes: {e}"]
    if not isinstance(doc, dict):
        return ["user-data is not a mapping"]
    problems = []
    try:
        own_run_sh = make_run_sh(cfg)
    except VmError as e:
        own_run_sh = None
        problems.append(f"config: {e}")
    if own_run_sh is None or text != make_user_data(cfg, sums, own_run_sh):
        problems.append("user-data is not the harness's own, byte for byte")
    problems += [f"top-level key not allowed: {k}" for k in sorted(set(doc) - ALLOWED_TOP)]

    def walk(x, where):
        if isinstance(x, dict):
            for k, v in x.items():
                if _SECRETISH.search(str(k)) and k not in SAFE_KEYS:
                    problems.append(f"a password or key field: {where}{k}")
                walk(v, f"{where}{k}.")
        elif isinstance(x, list):
            for i, v in enumerate(x):
                walk(v, f"{where}{i}.")
    walk(doc, "")
    if doc.get("users") != [EXPECTED_USER]:
        problems.append(f"users: exactly one user {USER}, password locked, no key, no sudo; got {doc.get('users')!r}"[:300])
    for k, want in {"ssh_pwauth": False, "disable_root": True, "ssh_deletekeys": True, "package_update": False,
                    "package_upgrade": False}.items():
        if doc.get(k) is not want:
            problems.append(f"{k} must be {want}")
    if doc.get("ssh_genkeytypes") != []:
        problems.append("ssh_genkeytypes must be [] (no SSH key is generated)")
    if doc.get("runcmd") != [["bash", RUN_SH]]:
        problems.append(f"runcmd must be the harness script only, got {doc.get('runcmd')!r}"[:200])
    if (doc.get("power_state") or {}).get("mode") != "poweroff":
        problems.append("power_state must power the VM off")
    wf = doc.get("write_files") or []
    if [f.get("path") for f in wf] != [RUN_SH, CONFIG_PATH, SUMS_PATH]:
        problems.append(f"write_files must be run.sh, config.json and sums.txt, got {[f.get('path') for f in wf]}")
    else:
        run_sh, cfg_text, sums_got = (f.get("content", "") for f in wf)
        if run_sh != own_run_sh:
            problems.append("run.sh is not the harness's own script, byte for byte")
        problems += audit_run_sh(run_sh)
        if cfg_text != json.dumps(cfg, indent=1) + "\n":
            problems.append("config.json is not the harness's config, byte for byte")
        try:
            cfg_got = json.loads(cfg_text)
        except ValueError:
            cfg_got = {}
            problems.append("config.json is not JSON")
        if cfg_got.get("install_plan") != cfg.get("install_plan"):
            problems.append("config: the install plan is not the runbook's install blocks")
        if cfg_got.get("server") != SEED_URL:
            problems.append("config: the server is not the seed server")
        if cfg_got.get("proxy") != PROXY_URL:
            problems.append("config: the proxy is not the harness's proxy")
        if cfg_got.get("rerun_block") != cfg.get("rerun_block"):
            problems.append("config: the rerun block is not the runbook's")
        if cfg_got.get("root_block_ids") != cfg.get("root_block_ids"):
            problems.append("config: the root blocks are not the runbook's root=yes install blocks")
        if (cfg_got.get("apt_conf"), cfg_got.get("console"), cfg_got.get("guest_dir")) != (APT_CONF, CONSOLE, GUEST_DIR):
            problems.append("config: the apt proxy file, the console or the root step's folder is not the harness's")
        if sums_got != sums:
            problems.append("sums.txt is not the harness's, byte for byte")
        if not re.fullmatch(r"[0-9a-f]{64}  code\.tar\n[0-9a-f]{64}  guest\.py\n[0-9a-f]{64}  reference\.json\n", sums_got):
            problems.append("sums.txt does not name the three fetched files")
    urls = set(re.findall(r"https?://[^\s\"'/\\]+", text))
    if urls != {SEED_URL, PROXY_URL}:
        problems.append(f"URLs other than the seed server and the proxy: {sorted(urls)}")
    return problems


# ------------------------------------------------------------------------------------------ the seed and upload server
class _Handler(BaseHTTPRequestHandler):
    server_version = "vm_rerun"
    sys_version = ""
    protocol_version = "HTTP/1.0"          # one request per connection

    def setup(self):
        self.timeout = self.server.read_timeout     # every read of a request, its head and its body, has a deadline
        super().setup()

    def log_message(self, *args):
        pass

    def _send(self, code: int, body: bytes = b"", extra: dict | None = None):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass

    def _raw_path(self) -> str:
        """The path exactly as the request line has it: http.server rewrites a leading '//' to '/' in self.path."""
        parts = (self.requestline or "").split()
        return parts[1] if len(parts) == 3 else ""

    def _drain(self):
        """Read (and drop) up to 64 KiB of a refused request's body, for at most a second, so the client gets the
        status instead of a reset from a close with unread data."""
        cls = self.headers.get_all("Content-Length") or []
        if not cls and not self.headers.get("Transfer-Encoding"):
            return
        cl = cls[0].strip() if len(cls) == 1 else ""
        want, got = min(int(cl) if CONTENT_LENGTH_RE.fullmatch(cl) else 1 << 16, 1 << 16), 0
        try:
            self.connection.settimeout(1.0)
            while got < want:
                chunk = self.rfile.read1(want - got)
                if not chunk:
                    break
                got += len(chunk)
        except OSError:
            pass

    def _done(self, code: int, nbytes: int = 0, name: str | None = None, extra: dict | None = None, body: bytes = b""):
        try:
            gt = float(self.headers.get("X-Guest-Time", ""))
        except ValueError:
            gt = None
        self.server.note(self.command, self._raw_path(), code, nbytes, gt, name)
        self._send(code, body, extra)

    def _refused(self, code: int, extra: dict | None = None):
        self._drain()
        return self._done(code, extra=extra)

    def do_GET(self):
        raw = self._raw_path()
        name = raw[1:] if raw.startswith("/") else None
        if name in self.server.served:
            body = self.server.served[name]
            return self._done(200, len(body), name, body=body)
        return self._done(404)

    def do_PUT(self):
        raw = self._raw_path()
        if not raw.startswith(UPLOAD_PREFIX):
            return self._refused(403)
        name = raw[len(UPLOAD_PREFIX):]
        if not NAME_RE.fullmatch(name) or ".." in name:
            return self._refused(400)
        cls = self.headers.get_all("Content-Length") or []
        if self.headers.get("Transfer-Encoding") or not cls:
            return self._refused(411)
        if len(cls) > 1:
            return self._refused(400)               # two lengths: which one is meant cannot be told
        cl = cls[0].strip()
        if not CONTENT_LENGTH_RE.fullmatch(cl):
            return self._refused(400)               # not plain ASCII digits, or longer than 12 of them
        n = int(cl)
        if n > self.server.cap:
            return self._refused(413)
        if not self.server.reserve(n):
            return self._refused(413)
        try:
            data = self.rfile.read(n)
            if len(data) != n:
                self.server.release(n)
                return self._done(400)
            try:
                fd = os.open(self.server.results_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            except FileExistsError:
                self.server.release(n)
                return self._done(409)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except TimeoutError:
            self.server.release(n)
            return self._done(408)
        except OSError:
            self.server.release(n)
            return self._done(500)
        return self._done(201, n, name)

    def _refuse(self):
        return self._refused(405, extra={"Allow": "GET, PUT"})

    do_DELETE = _refuse
    do_POST = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = do_CONNECT = _refuse


class SeedServer(ThreadingHTTPServer):
    """cloud-init's NoCloud seed (meta-data, user-data, vendor-data) and the three fetched files, by exact name, GET only;
    and the VM's uploads, PUT /up/<one plain name> only, into ONE fixed folder, never overwriting, with a size cap per
    file and in total, one Content-Length of plain digits, a read deadline, and the quota given back on any failure.
    Bound to 127.0.0.1 only: the VM reaches it at 10.0.2.100:8080 through a guestfwd relay."""
    daemon_threads = True

    def __init__(self, served: dict, results_dir, host: str = "127.0.0.1", port: int = 0, cap: int = MAX_UPLOAD_BYTES,
                 total_cap: int = MAX_UPLOAD_TOTAL, max_files: int = MAX_UPLOADS,
                 read_timeout: float = UPLOAD_READ_TIMEOUT_S):
        if host != "127.0.0.1":
            raise VmError("the seed server binds 127.0.0.1 only")
        self.served = dict(served)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.cap, self.total_cap, self.max_files, self.read_timeout = cap, total_cap, max_files, read_timeout
        self.received = self.count = 0
        self.log, self.lock, self._thread = [], threading.Lock(), None
        super().__init__((host, port), _Handler)

    @property
    def port(self) -> int:
        return self.server_address[1]

    def reserve(self, n: int) -> bool:
        with self.lock:
            if self.count >= self.max_files or self.received + n > self.total_cap:
                return False
            self.count += 1
            self.received += n
            return True

    def release(self, n: int):
        with self.lock:
            self.count -= 1
            self.received -= n

    def note(self, method, path, status, nbytes, guest_time, name):
        with self.lock:
            self.log.append({"t_host": round(time.time(), 3), "method": method, "path": str(path)[:200],
                             "status": status, "bytes": nbytes, "guest_time": guest_time, "name": name})

    def start(self):
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread is not None:
            self.shutdown()
            self._thread = None
        self.server_close()


# ------------------------------------------------------------------------------------------ the allow-listing proxy
def connect_public(host: str, port: int, timeout: float = PROXY_CONNECT_TIMEOUT_S):
    """A TCP connection to host:port, resolved on THIS host, refused when any address the name resolves to is not a
    public one (loopback, the 10.42.0.x LAN, link-local, documentation ranges...)."""
    addrs = []
    for fam, _, _, _, sa in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        ip = ipaddress.ip_address(sa[0])
        if not ip.is_global:
            raise VmError(f"{host} resolves to {ip}, which is not a public address: refused")
        addrs.append((fam, sa))
    last = None
    for fam, sa in addrs:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(sa)
            return s, sa[0]
        except OSError as e:
            last = e
            s.close()
    raise VmError(f"no connection to {host}:{port}: {last}")


_REASONS = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 408: "Request Timeout",
            429: "Too Many Requests", 502: "Bad Gateway"}


def _read_head(sock, limit: int, timeout: float):
    deadline, buf = time.monotonic() + timeout, b""
    while b"\r\n\r\n" not in buf:
        left = deadline - time.monotonic()
        if left <= 0:
            return None, b"", "timeout"
        sock.settimeout(left)
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            return None, b"", "timeout"
        if not chunk:
            return None, b"", "closed before a whole request head"
        buf += chunk
        if len(buf) > limit:
            return None, b"", f"request head over {limit} bytes"
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head, rest, ""


class _ProxyHandler(socketserver.BaseRequestHandler):
    def _refuse(self, e: dict, status: int, why: str):
        e.update(status=status, why=why)
        try:
            self.request.sendall(f"HTTP/1.1 {status} {_REASONS.get(status, 'Refused')}\r\nContent-Length: 0\r\n"
                                 "Connection: close\r\n\r\n".encode())
        except OSError:
            pass

    def handle(self):
        srv, c = self.server, self.request
        t0 = time.time()
        e = {"t_host": round(t0, 3), "request": None, "target": None, "status": None, "why": "", "ip": None,
             "bytes_up": 0, "bytes_down": 0, "seconds": None, "end": None}
        up = None
        try:
            head, rest, why = _read_head(c, srv.head_max, srv.head_timeout_s)
            if head is None:
                return self._refuse(e, 408 if why == "timeout" else 400, why)
            line = head.split(b"\r\n", 1)[0].decode("latin-1")[:300]
            e["request"] = line
            parts = line.split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                return self._refuse(e, 400, "not an HTTP/1.x request line")
            method, target = parts[0], parts[1]
            if method != "CONNECT":
                return self._refuse(e, 405, f"{method[:20]} is not CONNECT: this proxy only opens allow-listed tunnels")
            m = re.fullmatch(r"([A-Za-z0-9.-]{1,253}):([0-9]{1,5})", target)
            if not m:
                return self._refuse(e, 400, "the CONNECT target is not host:port")
            host, port = m.group(1).lower(), int(m.group(2))
            e["target"] = f"{host}:{port}"
            if (host, port) not in srv.allow:
                return self._refuse(e, 403, "not on the allow-list")
            if not srv.admit():
                return self._refuse(e, 429, "the run's tunnel count or byte total is reached")
            try:
                up, e["ip"] = srv.connect(host, port, PROXY_CONNECT_TIMEOUT_S)
            except (VmError, OSError) as x:
                return self._refuse(e, 502, str(x)[:200])
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            e["status"] = 200
            e["end"] = _tunnel(srv, c, up, rest, e)
        except OSError as x:
            e["why"] = e["why"] or f"{type(x).__name__}: {x}"[:200]
        finally:
            if up is not None:
                up.close()
            e["seconds"] = round(time.time() - t0, 3)
            srv.note(e)


def _tunnel(srv, c, up, rest: bytes, e: dict) -> str:
    deadline = time.monotonic() + srv.conn_max_s
    for s in (c, up):
        s.settimeout(srv.idle_s)
    if rest:
        why = srv.charge(e, "bytes_up", len(rest))
        if why:
            return why
        up.sendall(rest)
    sel = selectors.DefaultSelector()
    sel.register(c, selectors.EVENT_READ, (up, "bytes_up"))
    sel.register(up, selectors.EVENT_READ, (c, "bytes_down"))
    open_ = 2
    try:
        while open_:
            left = deadline - time.monotonic()
            if left <= 0:
                return "deadline"
            events = sel.select(timeout=min(srv.idle_s, left))
            if not events:
                return "idle" if left > srv.idle_s else "deadline"
            for key, _ in events:
                dst, field = key.data
                data = key.fileobj.recv(65536)
                if not data:
                    sel.unregister(key.fileobj)
                    open_ -= 1
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                why = srv.charge(e, field, len(data))
                if why:
                    return why
                dst.sendall(data)
        return "eof"
    finally:
        sel.close()


class AllowProxy(socketserver.ThreadingTCPServer):
    """The VM's only way out: CONNECT tunnels to the allow-listed host:port pairs, the names resolved here and refused
    when not public; every other request refused and logged; per-tunnel and per-run byte caps, a tunnel count cap, an
    idle timeout and a lifetime per tunnel. Bound to 127.0.0.1 only: the VM reaches it at 10.0.2.101:3128 through a
    guestfwd relay."""
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, bind: str = "127.0.0.1", port: int = 0, allow=PROXY_ALLOW, conn_cap: int = PROXY_CONN_CAP,
                 total_cap: int = PROXY_TOTAL_CAP, max_conns: int = PROXY_MAX_CONNS, idle_s: float = PROXY_IDLE_S,
                 conn_max_s: float = PROXY_CONN_MAX_S, head_timeout_s: float = PROXY_HEAD_TIMEOUT_S,
                 head_max: int = PROXY_HEAD_MAX, connect=None):
        if bind != "127.0.0.1":
            raise VmError("the proxy binds 127.0.0.1 only")
        self.allow, self.conn_cap, self.total_cap, self.max_conns = allow, conn_cap, total_cap, max_conns
        self.idle_s, self.conn_max_s, self.head_timeout_s, self.head_max = idle_s, conn_max_s, head_timeout_s, head_max
        self.connect = connect or connect_public
        self.log, self.lock, self.conns, self.total, self.dropped, self._thread = [], threading.Lock(), 0, 0, 0, None
        super().__init__((bind, port), _ProxyHandler)

    @property
    def port(self) -> int:
        return self.server_address[1]

    def admit(self) -> bool:
        with self.lock:
            if self.conns >= self.max_conns or self.total >= self.total_cap:
                return False
            self.conns += 1
            return True

    def charge(self, e: dict, field: str, n: int) -> str:
        with self.lock:
            e[field] += n
            self.total += n
            if e["bytes_up"] + e["bytes_down"] > self.conn_cap:
                return f"per-tunnel cap of {self.conn_cap} bytes"
            if self.total > self.total_cap:
                return f"run total cap of {self.total_cap} bytes"
        return ""

    def note(self, e: dict):
        with self.lock:
            if len(self.log) < PROXY_LOG_MAX:
                self.log.append(e)
            else:
                self.dropped += 1

    def summary(self) -> dict:
        with self.lock:
            return {"tunnels": sum(e["status"] == 200 for e in self.log),
                    "refused": sum(e["status"] != 200 for e in self.log), "bytes": self.total,
                    "log_entries_dropped": self.dropped}

    def start(self):
        self._thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread is not None:
            self.shutdown()
            self._thread = None
        self.server_close()


# ------------------------------------------------------------------------------------------ QEMU
RELAY_SRC = r'''# vm_rerun.py guestfwd relay, written by the harness into its private run folder. QEMU starts one for each TCP
# connection the VM opens to a guestfwd address, with that connection on fd 0 and 1 (and 2). It connects to ONE port
# on this host's 127.0.0.1, the one on its command line, and copies bytes both ways until both sides have closed or
# nothing moved for 300 s. It writes nothing anywhere else.
import os, selectors, socket, sys
sys.stderr = open(os.devnull, "w")


def main():
    port = int(sys.argv[1])
    if not 1024 <= port <= 65535:
        return 2
    g = socket.socket(fileno=os.dup(0))
    up = socket.create_connection(("127.0.0.1", port), timeout=10)
    for s in (g, up):
        s.settimeout(300)
    sel = selectors.DefaultSelector()
    sel.register(g, selectors.EVENT_READ, up)
    sel.register(up, selectors.EVENT_READ, g)
    open_ = 2
    while open_:
        events = sel.select(timeout=300)
        if not events:
            return 3
        for key, _ in events:
            data = key.fileobj.recv(65536)
            if data:
                key.data.sendall(data)
                continue
            sel.unregister(key.fileobj)
            open_ -= 1
            try:
                key.data.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    return 0


try:
    rc = main()
except Exception:
    rc = 1
os._exit(rc)
'''


def write_relay(path) -> dict:
    path = Path(path)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(RELAY_SRC)
    os.chmod(path, 0o500)
    return {"path": str(path), "sha256": _sha_file(path)}


def relay_command(python: str, relay_path) -> str:
    cmd = f"{python} -I -B -S {relay_path}"
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+ -I -B -S /[A-Za-z0-9_./-]+", cmd):
        raise VmError(f"the relay command {cmd!r} holds characters QEMU or its argv parser would split on")
    return cmd


NETDEV_HEAD = ["user", f"id={NETDEV_ID}", "restrict=on", "ipv6=off"]    # ipv6=off: restrict=on does not stop IPv6 TCP
IPV6_CLOSED = {
    "setting": "ipv6=off in the netdev line (QEMU's option that turns IPv6 off; libslirp's in6_enabled=0)",
    "unreachable_over_ipv6": "everything: libslirp drops every IPv6 frame the VM sends and answers none (no router "
                             "advertisement, neighbour, DHCPv6 or DNS answer), so over IPv6 the VM reaches neither this "
                             "host ([::1], ::ffff:127.0.0.1) nor the LAN nor the IPv6 internet, on any port",
    "reachable_over_ipv4": f"only the two guestfwd targets {SEED_ADDR}:{SEED_GUEST_PORT} and {PROXY_ADDR}:"
                           f"{PROXY_GUEST_PORT} (restrict=on: the host alias 10.0.2.2 gets a reset, UDP is not delivered)",
    "how_shown": "2026-11-20, before any VM run: this host's libslirp 4.9.5 loaded in-process (no QEMU), configured from "
                 "the harness's netdev value (restricted=1, in6_enabled=0) with a guestfwd exec rule at 10.0.2.100; the "
                 "second check's frames were fed to it unchanged: an IPv6 SYN to fec0::2 from the crafted source "
                 "fec0:0:a00:264::1234, an IPv6 SYN to ::ffff:127.0.0.1, an IPv6 SYN from an ordinary source, IPv6 and "
                 "IPv4 UDP. None opened a connection on this host and no IPv6 frame drew any frame back. Control: the "
                 "netdev value before ipv6=off (in6_enabled=1) with the same frames opened host connections to [::1] "
                 "and 127.0.0.1. After the guest's ARP, an IPv4 SYN to 10.0.2.100 still drew slirp's SYN-ACK and one "
                 "to 10.0.2.2 a reset, in both configurations",
    "not_shown": "QEMU itself was not run (not installed on this host when this was written): that -netdev ipv6=off "
                 "reaches libslirp as in6_enabled=0 is taken from QEMU's documentation of the option, not observed "
                 "here; in the run the VM's own IPv6 addresses are read, and one other than loopback or link-local is "
                 "an integrity problem"}


def netdev_value(relay_cmd: str, seed_port: int, proxy_port: int) -> str:
    fwds = [f"guestfwd=tcp:{SEED_ADDR}:{SEED_GUEST_PORT}-cmd:{relay_cmd} {int(seed_port)}",
            f"guestfwd=tcp:{PROXY_ADDR}:{PROXY_GUEST_PORT}-cmd:{relay_cmd} {int(proxy_port)}"]
    return ",".join([*NETDEV_HEAD, *fwds])


def qemu_img_argv(qemu_img: str, base: Path, overlay: Path) -> list:
    return [qemu_img, "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay), DISK_SIZE]


def qemu_argv(qemu: str, overlay: Path, serial: Path, relay_cmd: str, seed_port: int, proxy_port: int,
              name: str) -> list:
    for p in (overlay, serial):
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", str(p)):
            raise VmError(f"{p}: a QEMU option value here holds only letters, digits and _ . / -")
    return [qemu, "-name", name, "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", str(VCPUS), "-m", str(MEM_MB),
            "-nographic", "-monitor", "none", "-serial", f"file:{serial}", "-no-reboot",
            "-drive", f"file={overlay},if=virtio,format=qcow2",
            "-netdev", netdev_value(relay_cmd, seed_port, proxy_port),
            "-device", f"virtio-net-pci,netdev={NETDEV_ID}",
            "-smbios", f"type=1,serial=ds=nocloud;s={SEED_URL}/",
            "-device", "virtio-rng-pci"]


QEMU_WITH_VALUE = {"-name", "-machine", "-cpu", "-smp", "-m", "-monitor", "-serial", "-drive", "-netdev", "-device",
                   "-smbios"}
QEMU_ALONE = {"-nographic", "-no-reboot"}


def audit_qemu_argv(argv: list, relay_cmd: str, seed_port: int, proxy_port: int, run_dir, name: str,
                    private_parent) -> list:
    """Problems of a QEMU command line against what this harness may start: only the listed options, each with the
    harness's VALUE (the serial log and the overlay are files in this run's folder, which lies directly in the 0700
    private folder; the machine, the name, CPU and memory as written); one netdev, user mode, restrict=on, ipv6=off and
    exactly the two guestfwd rules to the seed server's and the proxy's relays; the two devices; nothing that shares a
    host folder or forwards a port; and the whole line equal to the harness's, byte for byte."""
    problems, opts, i = [], [], 1
    while i < len(argv):
        a = argv[i]
        if a in QEMU_ALONE:
            opts.append((a, None))
            i += 1
        elif a in QEMU_WITH_VALUE and i + 1 < len(argv):
            opts.append((a, argv[i + 1]))
            i += 2
        else:
            problems.append(f"QEMU option not allowed: {a[:80]}")
            i += 1
    for k in QEMU_WITH_VALUE | QEMU_ALONE:
        n = sum(o == k for o, _ in opts)
        if n != (2 if k == "-device" else 1):
            problems.append(f"QEMU option {k} given {n} times")
    run_dir, private_parent = Path(run_dir), Path(private_parent)
    if not (run_dir.is_absolute() and private_parent.is_absolute() and run_dir.parent == private_parent
            and re.fullmatch(r"/[A-Za-z0-9_./-]+", str(run_dir)) and ".." not in run_dir.parts):
        problems.append(f"the run folder {run_dir} does not lie directly in the private folder {private_parent}")
    one = {k: v for k, v in opts if k != "-device"}
    want = {"-serial": f"file:{run_dir}/serial.log", "-machine": "q35,accel=kvm", "-cpu": "host",
            "-smp": str(VCPUS), "-m": str(MEM_MB), "-monitor": "none",
            "-smbios": f"type=1,serial=ds=nocloud;s={SEED_URL}/"}
    for k, v in want.items():
        if one.get(k) != v:
            problems.append(f"QEMU {k} is {str(one.get(k))[:120]!r}, not {v!r}")
    if one.get("-name") != name or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(name)):
        problems.append(f"QEMU -name is {str(one.get('-name'))[:120]!r}, not the plain run name {name!r}")
    nd = [v for k, v in opts if k == "-netdev"]
    parts = nd[0].split(",") if len(nd) == 1 else []
    want_fwd = [f"guestfwd=tcp:{SEED_ADDR}:{SEED_GUEST_PORT}-cmd:{relay_cmd} {int(seed_port)}",
                f"guestfwd=tcp:{PROXY_ADDR}:{PROXY_GUEST_PORT}-cmd:{relay_cmd} {int(proxy_port)}"]
    if parts[:4] != ["user", f"id={NETDEV_ID}", "restrict=on", "ipv6=off"] or parts[4:] != want_fwd:
        problems.append("the netdev line is not user mode with restrict=on, ipv6=off and exactly the two guestfwd "
                        f"rules: {nd}"[:400])
    if nd != [netdev_value(relay_cmd, seed_port, proxy_port)]:
        problems.append("the netdev line is not the harness's, byte for byte")
    if sorted(v for k, v in opts if k == "-device") != sorted([f"virtio-net-pci,netdev={NETDEV_ID}", "virtio-rng-pci"]):
        problems.append("QEMU devices are not exactly the network card and the random-number device")
    drives = [v for k, v in opts if k == "-drive"]
    if drives != [f"file={run_dir}/overlay.qcow2,if=virtio,format=qcow2"]:
        problems.append(f"the drive is not the overlay in the private run folder alone: {drives}"[:300])
    text = " ".join(map(str, argv))
    for word in ("hostfwd", "virtfs", "fsdev", "virtio-9p", "chardev", "smb=", "restrict=off", "ipv6=on", "tftp=",
                 "bootfile="):
        if word in text:
            problems.append(f"the QEMU command line names {word!r}")
    try:
        own = qemu_argv(argv[0] if argv else "", run_dir / "overlay.qcow2", run_dir / "serial.log", relay_cmd,
                        seed_port, proxy_port, name)
    except VmError as e:
        own = None
        problems.append(f"the harness's own QEMU line cannot be made for these values: {e}")
    if own is not None and list(argv) != own:
        problems.append("the QEMU command line is not the harness's, byte for byte")
    return problems


def new_run_dir(base, stamp: str) -> Path:
    d = Path(base) / stamp
    if d.exists():
        raise VmError(f"{d} exists: every run gets a new folder")
    d.mkdir(parents=True)
    return d


# ------------------------------------------------------------------------------------------ console and uploads
def parse_console(text: str) -> dict:
    """The summary line, the progress lines and the root step's line(s). The summary must be there once; how many root
    lines there must be is judged by root_console_problems."""
    found, progress, problems, roots = [], [], [], []
    for line in text.replace("\r", "").split("\n"):
        i = line.find(MARKER)
        if i >= 0:
            found.append(line[i + len(MARKER):])
        j = line.find(PROGRESS)
        if j >= 0:
            progress.append(line[j + len(PROGRESS):].strip())
        k = line.find(ROOT_MARKER)
        if k >= 0:
            try:
                r = json.loads(line[k + len(ROOT_MARKER):])
            except ValueError:
                r = None
            roots.append(r if isinstance(r, dict) else {"unreadable": line[k:k + 200]})
    summary = None
    if not found:
        problems.append("no summary line on the serial console")
    if len(found) > 1:
        problems.append(f"{len(found)} summary lines on the serial console: which one is meant cannot be told")
    elif len(found) == 1:
        try:
            summary = json.loads(found[0])
        except ValueError:
            problems.append("the summary line is not JSON")
        if summary is not None and not isinstance(summary, dict):
            summary = None
            problems.append("the summary line is not an object")
    return {"summary": summary, "problems": problems, "progress": progress, "root": roots}


def _root_rows(blocks) -> list:
    return [(b.get("id"), b.get("sha256"), b.get("rc")) for b in blocks or [] if isinstance(b, dict)]


def root_console_problems(console: dict, summary: dict | None, guest: dict | None, plan: list, root_ids: list) -> list:
    """The root blocks as root itself wrote them on the console against the plan and against guest.json (written by
    edgefollow): exactly one root line once the harness got past its checks; the blocks in it are the planned root blocks,
    in order, with the runbook's SHA-256s, stopping only after a failed one; guest.json says the same."""
    if summary is None or summary.get("harness_error"):
        return []
    lines = console.get("root") or []
    if len(lines) != 1:
        return [f"console: {len(lines)} root-step lines, exactly one is written by the root step"]
    line, problems = lines[0], []
    if "unreadable" in line:
        return ["console: the root-step line is not a JSON object"]
    sha = {p["id"]: p["sha256"] for p in plan}
    rows = _root_rows(line.get("blocks"))
    want_ids = list(root_ids)
    ran_ids = [r[0] for r in rows]
    if ran_ids != want_ids[:len(ran_ids)] or any(r[1] != sha.get(r[0]) for r in rows):
        problems.append(f"console: the root step ran {ran_ids}, the runbook's root blocks are {want_ids}")
    elif len(ran_ids) < len(want_ids) and not any(r[2] != 0 for r in rows) and not line.get("error"):
        problems.append(f"console: the root step stopped after {ran_ids} without a failed block or an error")
    if guest is not None:
        mine = [(i.get("id"), i.get("sha256"), i.get("rc")) for i in guest.get("installs") or [] if i.get("as") == "root"]
        if mine != rows:
            problems.append("the root blocks' exit codes on the console (written by root) and in guest.json (written "
                            f"by edgefollow) differ: {rows} against {mine}"[:300])
    return problems


def verify_uploads(summary: dict, results_dir) -> tuple:
    """guest.json must be the one the console summary names (SHA-256); every file guest.json lists as uploaded must be
    there with its SHA-256 and size; nothing else may be there. Returns (guest.json, the clean_rerun record, problems);
    the record only when it verified."""
    d, problems = Path(results_dir), []
    g = d / "guest.json"
    if not g.is_file():
        return None, None, ["uploads: guest.json did not arrive"]
    if _sha_file(g) != summary.get("guest_json_sha256"):
        return None, None, ["uploads: guest.json is not the one the console summary names"]
    try:
        guest = json.loads(g.read_text())
    except ValueError:
        return None, None, ["uploads: guest.json is not JSON"]
    listed, good = {}, set()
    for u in guest.get("uploads") or []:
        if u.get("status") == 201:
            listed[u.get("name")] = u
    for name, u in sorted(listed.items()):
        p = d / str(name)
        if not p.is_file():
            problems.append(f"uploads: missing: {name}")
        elif _sha_file(p) != u.get("sha256") or p.stat().st_size != u.get("bytes"):
            problems.append(f"uploads: changed: {name}")
        else:
            good.add(name)
    for p in sorted(d.iterdir()):
        if p.name != "guest.json" and p.name not in listed:
            problems.append(f"uploads: extra: {p.name}")
    rec = None
    if "cr_record.json" in good:
        try:
            rec = json.loads((d / "cr_record.json").read_text())
        except ValueError:
            problems.append("uploads: cr_record.json is not JSON")
    return guest, rec, problems


def dev01_end_epoch(cr_record: dict) -> float | None:
    """When the TD_MEC_DEV_01 block ended, on the VM's clock: its start in clean_rerun's log (whole seconds, UTC) plus
    its duration. Reported only: no verdict reads the VM's clock."""
    try:
        sid = next(p["id"] for p in cr_record["provenance"]["plan"] if p.get("td") == LAST_TD)
        e = next(e for e in cr_record["executed"] if e["id"] == sid)
        t = datetime.strptime(e["started_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
        return t + float(e["seconds"])
    except (KeyError, StopIteration, TypeError, ValueError):
        return None


def clock_offset(log: list) -> dict | None:
    """The VM's clock minus this host's, from every upload: the guest's send time against the host's receive time."""
    offs = sorted(e["guest_time"] - e["t_host"] for e in log
                  if e.get("method") == "PUT" and e.get("status") == 201 and isinstance(e.get("guest_time"), float))
    if not offs:
        return None
    mid = len(offs) // 2
    median = offs[mid] if len(offs) % 2 else (offs[mid - 1] + offs[mid]) / 2
    return {"median_s": round(median, 3), "min_s": round(offs[0], 3), "max_s": round(offs[-1], 3), "n": len(offs)}


def host_elapsed(log: list, t0: float | None) -> float | None:
    """Step 5's time, on THIS host's clock only: from QEMU's start (t0) to this host's receipt of the VM's clean_rerun
    record (cr_record.json, the guest's first upload; the record can only exist after TD_MEC_DEV_01 ended), rounded
    up to 0.1 s. An upper bound: it also holds clean_rerun's shutdown and controls."""
    hits = [e["t_host"] for e in log
            if e.get("method") == "PUT" and e.get("status") == 201 and e.get("name") == "cr_record.json"]
    if len(hits) != 1 or t0 is None:
        return None
    return math.ceil((hits[0] - t0) * 10) / 10


# ------------------------------------------------------------------------------------------ the five steps
BOOT_PREFIX = "step 1/2: bootstrap step "
REG_ROW = "step 2: after the runbook's bootstrap steps alone, every MN-CSE is registered both ways"
ONLY_ROW = "step 2: the commands executed are the runbook's run steps, each once, in order, and nothing else"
ENDED_ROW = "the rerun ran to its end"


def cr_verdict_problems(rec: dict, shutdown_ids: list) -> list:
    """clean_rerun.py's own verdict inside the VM, read on this host: its result is PASS, every post-test row is there
    once and true, every other row is true, and each of its controls is there and failed as it must."""
    p = []
    if rec.get("result") != PASS:
        p.append(f"clean_rerun.py in the VM says {rec.get('result')!r}, not PASS")
    rows = [r for r in rec.get("steps") or [] if isinstance(r, dict)]
    want = list(POST_TEST_ROWS) + [f"shutdown step {sid} from the runbook exits 0" for sid in shutdown_ids]
    for name in want:
        hits = [r for r in rows if r.get("row") == name]
        if len(hits) != 1 or hits[0].get("ok") is not True:
            p.append(f"post-test row {'missing' if not hits else 'there twice' if len(hits) > 1 else 'false'}: {name}")
    other = [str(r.get("row"))[:80] for r in rows if r.get("row") not in want and r.get("ok") is not True]
    if other:
        p.append(f"{len(other)} other row(s) of clean_rerun.py false: {'; '.join(other[:3])}")
    ctl = {}
    for c in rec.get("controls") or []:
        if isinstance(c, dict):
            ctl.setdefault(c.get("row"), []).append(c)
    for name in CR_CONTROL_ROWS:
        hits = ctl.get(name) or []
        if len(hits) != 1:
            p.append(f"control {'missing' if not hits else 'there twice'}: {name}")
        elif hits[0].get("passed") is not False or hits[0].get("failed_as_it_must") is not True:
            p.append(f"control did not fail as it must: {name}")
    for name, hits in ctl.items():
        if name not in CR_CONTROL_ROWS and any(h.get("passed") is not False for h in hits):
            p.append(f"control did not fail as it must: {str(name)[:120]}")
    return p


def facts_of(summary, guest, cr_record, *, install_plan, rerun_expected, kpi_diff, run_plan=None, elapsed_s,
             budget_s) -> dict:
    """What the run's evidence says, in the shape obs03_steps reads. guest is the verified guest.json (or None),
    cr_record the verified in-VM clean_rerun record (or None), rerun_expected the id and SHA-256 of the rerun block of
    the runbook THIS host delivered (None: it has none), run_plan the clean_rerun plan of that runbook: the VM's
    executed-command log is checked against it here."""
    src = guest if guest is not None else (summary or {})
    s6 = src.get("section6") or {}
    on_path = ((guest or {}).get("probes") or {}).get("on_path") or {}
    f = {"guest_reached": summary is not None, "harness_error": (summary or {}).get("harness_error"),
         "guest_error": src.get("guest_error"), "install_plan": [p["id"] for p in install_plan],
         "installs": [{"id": d.get("id"), "rc": d.get("rc"), "seconds": d.get("seconds")} for d in src.get("installs") or []],
         "root_missing": bool(src.get("root_missing")),
         "section6_started": bool(s6.get("started")), "section6_rc": s6.get("rc"), "section6_tail": s6.get("tail"),
         "section6_why": s6.get("why"),
         "missing_in_vm": [c for c in ("bash", "curl", "setsid", "python3", "git") if c in on_path and not on_path[c]],
         "foreign_commands": None, "cr": None, "kpi_diff": kpi_diff, "dev01_elapsed_s": elapsed_s, "budget_s": budget_s,
         "last_progress": None}
    if guest is not None:
        allowed = {(p["id"], p["sha256"]) for p in install_plan}
        if rerun_expected:
            allowed.add((rerun_expected["id"], rerun_expected["sha256"]))
        foreign, seen = [], set()
        for c in guest.get("commands") or []:
            key = (c.get("id"), c.get("sha256"))
            if c.get("kind") == "runbook" and key in allowed and key not in seen:
                seen.add(key)
                continue
            foreign.append(c)                   # not a block of the delivered runbook, or one run twice
        f["foreign_commands"] = foreign
    if cr_record is not None:
        rows = {r.get("row"): r for r in cr_record.get("steps") or [] if isinstance(r, dict)}
        plan = (cr_record.get("provenance") or {}).get("plan") or []
        shutdown_ids = ([s.id for s in run_plan if s.phase == "shutdown"] if run_plan is not None
                        else [p.get("id") for p in plan if p.get("phase") == "shutdown"])
        ended = rows.get(ENDED_ROW)
        f["cr"] = {"bootstrap_planned": sum(p.get("phase") == "bootstrap" for p in plan),
                   "bootstrap_rows": [bool(r.get("ok")) for n, r in rows.items() if str(n).startswith(BOOT_PREFIX)],
                   "registration_ok": (rows.get(REG_ROW) or {}).get("ok") is True,
                   "only_runbook_ok": (rows.get(ONLY_ROW) or {}).get("ok") is True,
                   "stopped": (ended or {}).get("detail") or "it did not run to its end" if ended and not ended.get("ok")
                   else None,
                   "results": {td: bool((r or {}).get("ok")) for td, r in (cr_record.get("results") or {}).items()},
                   "executed_problems": (_clean_rerun().check_executed(run_plan, cr_record.get("executed") or [])
                                         if run_plan is not None else None),
                   "verdict_problems": cr_verdict_problems(cr_record, shutdown_ids)}
    return f


def _missing_note(f: dict) -> str:
    m = f.get("missing_in_vm") or []
    if not m:
        return ""
    return (f"; not on the VM's PATH: {', '.join(m)}"
            + (" (clean_rerun.py, which the rerun block starts, lists the code's files with git; the runbook's "
               "prerequisites do not name it)" if "git" in m else ""))


def obs03_steps(f: dict) -> list:
    """The five steps of TD_MEC_OBS_03, each PASS, FAIL or NOT-RUN with its reason. A step is NOT-RUN only when it is
    known not to have been attempted; evidence that did not come back is a FAIL, never a pass."""
    out = []

    def put(n, verdict, why):
        out.append({"step": n, "text": OBS03_TEXT[n], "verdict": verdict, "why": why})
    inst, plan, cr = f["installs"], f["install_plan"], f["cr"]
    if not f["guest_reached"]:
        why = ("no summary came back from the VM, so what it did is not known"
               + (f"; the last harness line this host saw: {f['last_progress']}" if f.get("last_progress")
                  else "; this host saw no harness line from it"))
        for n in range(1, 6):
            put(n, FAIL, why)                   # evidence that did not come back is a FAIL, never NOT-RUN
        return out
    if f.get("root_missing") and not inst and not f["harness_error"]:
        why = ("the root step's result did not come back, so whether the root=yes blocks ran is not known"
               + (f": {f['guest_error']}" if f.get("guest_error") else ""))
        put(1, FAIL, why)                       # evidence that did not come back is a FAIL
        put(2, FAIL, why)
        for n in (3, 4, 5):
            put(n, NOT_RUN, "no install block ran as edgefollow, so the runbook's later steps were not reached")
        return out
    if f["harness_error"] or not inst:
        why = (f"the harness stopped before the runbook: {f['harness_error']}" if f["harness_error"] else
               "no runbook block was run" + (f": {f['guest_error']}" if f.get("guest_error") else ""))
        for n in range(1, 6):
            put(n, NOT_RUN, why)
        return out
    bad = next((d for d in inst if d["rc"] != 0), None)
    installs_ok = bad is None and [d["id"] for d in inst] == plan
    res = (cr or {}).get("results") or {}
    boot_ok = bool(cr) and cr["bootstrap_planned"] > 0 and len(cr["bootstrap_rows"]) == cr["bootstrap_planned"] \
        and all(cr["bootstrap_rows"])
    pf_ok = res.get(TDS[0]) is True
    if bad is not None:
        why1 = f"install block {bad['id']} exited {bad['rc']}"
    elif not installs_ok:
        why1 = f"install blocks run {[d['id'] for d in inst]}, the runbook has {plan}"
    elif not f["section6_started"]:
        why1 = "the runbook's rerun block was not run" + (
            f": {f['section6_why']}" if f.get("section6_why") else f": {f['guest_error']}" if f.get("guest_error") else "")
    elif cr is None:
        why1 = ("clean_rerun.py's record did not come back from the VM"
                + (f": the rerun block exited {f['section6_rc']}" if f.get("section6_rc") is not None else "")
                + (f" ({f['section6_tail']})" if f.get("section6_tail") else "") + _missing_note(f))
    elif not boot_ok:
        why1 = (f"clean_rerun.py stopped before the bootstrap: {cr['stopped']}{_missing_note(f)}"
                if cr.get("stopped") and not cr["bootstrap_rows"] else
                f"{sum(cr['bootstrap_rows'])} of {cr['bootstrap_planned']} bootstrap blocks exited 0{_missing_note(f)}")
    elif not pf_ok:
        why1 = "TD_MEC_PF_01 did not pass"
    else:
        why1 = ""
    put(1, PASS if not why1 else FAIL,
        why1 or "every install block and every bootstrap block exited 0, and TD_MEC_PF_01 passed")
    foreign = f["foreign_commands"]
    if why1:
        why2 = f"the runbook alone did not complete the bootstrap: {why1}"
    elif not cr["registration_ok"]:
        why2 = "after the bootstrap blocks the MN-CSEs were not registered both ways"
    elif not cr["only_runbook_ok"]:
        why2 = "clean_rerun.py logged a command that is not one of the runbook's run steps"
    elif cr.get("executed_problems") is None:
        why2 = "the VM's executed-command log was not checked on this host against the delivered runbook"
    elif cr.get("executed_problems") != []:
        why2 = ("the VM's executed-command log, checked on this host against the delivered runbook: "
                + "; ".join(cr["executed_problems"][:3]))
    elif foreign is None:
        why2 = "the guest's command log did not come back, so commands outside the runbook cannot be ruled out"
    elif foreign:
        why2 = (f"the guest started {len(foreign)} command(s) that are not a block of the delivered runbook (or one "
                "of them twice)")
    else:
        why2 = ""
    put(2, PASS if not why2 else FAIL, why2 or "only the runbook's blocks ran, besides the harness steps listed")
    if not installs_ok or not f["section6_started"]:
        why = ("the install blocks did not all succeed, so the runbook's later steps were not reached" if not installs_ok
               else "the runbook's rerun block was not run, so its bootstrap and test blocks were not reached")
        for n in (3, 4, 5):
            put(n, NOT_RUN, why)
        return out
    if cr is None:
        for n in (3, 4, 5):
            put(n, FAIL, "the rerun block was started but clean_rerun.py's record did not come back")
        return out
    if not res:
        why = "clean_rerun.py stopped before the test blocks (its bootstrap did not complete)"
        for n in (3, 4, 5):
            put(n, NOT_RUN, why)
        return out
    missing = [td for td in TDS if td not in res]
    put(3, PASS if not missing else FAIL, "all five test blocks were run" if not missing else
        f"not run: {', '.join(missing)} (clean_rerun.py stops at the first test block that fails)")
    failed = [td for td in TDS if res.get(td) is not True]
    kpi_ok = f["kpi_diff"] == []
    cr_ok = cr.get("verdict_problems") == []
    put(4, PASS if not failed and kpi_ok and cr_ok else FAIL,
        "every declared test passed, the KPIs equal the reference's, and clean_rerun.py's own verdict in the VM is PASS"
        if not failed and kpi_ok and cr_ok else
        "; ".join(([f"not passed: {', '.join(failed)}"] if failed else [])
                  + ([] if kpi_ok else ["KPIs not compared" if f["kpi_diff"] is None
                                        else f"{len(f['kpi_diff'])} KPI difference(s) from the reference"])
                  + ([] if cr_ok else ["clean_rerun.py's own verdict in the VM: "
                                       + "; ".join((cr.get("verdict_problems") or ["not read"])[:3])])))
    elapsed = f["dev01_elapsed_s"]
    if LAST_TD not in res:
        put(5, NOT_RUN, f"{LAST_TD} was never run")
    elif res[LAST_TD] is not True:
        put(5, FAIL, f"{LAST_TD} ran and did not pass, so there is no time to passing it")
    elif elapsed is None:
        put(5, FAIL, "the time to passing TD_MEC_DEV_01 could not be measured on this host")
    elif elapsed <= f["budget_s"]:
        put(5, PASS, f"at most {elapsed:.0f} s from QEMU's start to this host receiving the record of {LAST_TD} passed "
                     f"(this host's clock), budget {f['budget_s']:.0f} s")
    else:
        put(5, FAIL, f"{elapsed:.0f} s from QEMU's start to this host receiving the VM's record (this host's clock), "
                     f"over the budget of {f['budget_s']:.0f} s")
    return out


def overall(steps: list, controls: list, problems: list) -> bool:
    return (len(steps) == 5 and all(s["verdict"] == PASS for s in steps) and bool(controls)
            and not any(c["passed"] for c in controls) and not problems)


# ------------------------------------------------------------------------------------------ the guest (inside the VM)
def check_install_plan(rb, plan) -> list:
    """The runbook's install blocks, which must be exactly the ones user-data names (ids and SHA-256, in order)."""
    installs = [s for s in rb.steps if s.phase == "install"]
    got = [{"id": s.id, "sha256": s.sha256} for s in installs]
    if got != list(plan):
        raise VmError(f"the runbook's install blocks {[g['id'] for g in got]} are not the ones user-data names "
                      f"{[p.get('id') for p in plan]} (or their text changed)")
    return installs


def run_installs(ex, installs: list, save) -> tuple:
    """Each install block through clean_rerun's Executor (the one place a runbook command is executed), in order; after
    a block fails the later ones are not run, as a developer would stop."""
    done, not_run = [], []
    for s in installs:
        if done and done[-1]["rc"] != 0:
            not_run.append(s.id)
            continue
        t0 = time.time()
        r = ex.run(s)
        save(s.id, r)
        done.append({"id": s.id, "sha256": s.sha256, "rc": r["rc"], "seconds": r["seconds"],
                     "started_epoch": round(t0, 3), "ended_epoch": round(time.time(), 3)})
    return done, not_run


def safe_name(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", raw).lstrip("._-")[:100] or "unnamed"


def _listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ipv6_addresses(path="/proc/net/if_inet6") -> list | None:
    """The VM's IPv6 addresses from the kernel's table (None: the table is not there, IPv6 is off in the kernel)."""
    try:
        rows = Path(path).read_text().splitlines()
    except OSError:
        return None
    out = []
    for ln in rows:
        p = ln.split()
        if len(p) >= 6 and re.fullmatch(r"[0-9a-fA-F]{32}", p[0]):
            out.append({"address": str(ipaddress.IPv6Address(bytes.fromhex(p[0]))), "interface": p[5]})
    return out


def ipv6_problems(addrs) -> list:
    """With ipv6=off slirp sends no router advertisement, so the VM can hold loopback and link-local IPv6 addresses
    only; any other one (slirp's fec0::/64 or anything else) means ipv6=off did not take."""
    bad = []
    for a in addrs or []:
        try:
            ip = ipaddress.IPv6Address(str(a.get("address")))
        except (ValueError, AttributeError):
            bad.append(str(a)[:60])
            continue
        if not (ip.is_loopback or ip.is_link_local):
            bad.append(str(ip))
    return [f"the VM holds IPv6 address(es) other than loopback and link-local: {bad} (ipv6=off did not take)"] \
        if bad else []


def guest_probes(cfg: dict) -> dict:
    """Facts of the VM, read in-process by the edgefollow guest after the root step (no command is started): the
    interpreter, the commands the runbook's prerequisites name plus git and sudo, edgefollow's groups, whether venv can make
    an environment with pip, the IPv6 addresses, and that nothing of the lab is there yet."""
    import grp
    osr = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                osr[k] = v.strip('"')
    except OSError:
        pass
    mem = ""
    try:
        mem = next(ln for ln in Path("/proc/meminfo").read_text().splitlines() if ln.startswith("MemTotal"))
    except (OSError, StopIteration):
        pass
    groups = []
    for g in sorted(set(os.getgroups()) | {os.getgid()}):
        try:
            groups.append(grp.getgrgid(g).gr_name)
        except KeyError:
            groups.append(str(g))
    root_probe = Path(cfg["harness_dir"]) / "probe_root.txt"
    return {"python3": sys.version.split()[0], "executable": sys.executable,
            "os_release": {k: osr.get(k) for k in ("PRETTY_NAME", "VERSION_ID", "VERSION_CODENAME")},
            "kernel": platform.release(), "cpus": os.cpu_count(), "mem_total": mem, "uid": os.getuid(), "groups": groups,
            "on_path": {c: shutil.which(c, path="/usr/local/bin:/usr/bin:/bin")
                        for c in ("bash", "curl", "setsid", "python3", "git", "sudo")},
            "ensurepip_importable": importlib.util.find_spec("ensurepip") is not None,
            "venv_importable": importlib.util.find_spec("venv") is not None,
            "present_before_install": {p: os.path.exists(p) for p in ("/home/edgefollow/estimed-venv",
                                                                       "/home/edgefollow/edgefollow-lab",
                                                                       "/home/edgefollow/estimed-run")},
            "lab_ports_listening": [p for p in (8200, 8201, 8202, 8091, 8092) if _listening(p)],
            "ipv6_addresses": ipv6_addresses(),
            "ssh": {"edgefollow_ssh_dir": os.path.exists("/home/edgefollow/.ssh"),
                    "host_key_files": sorted(p.name for p in Path("/etc/ssh").glob("ssh_host_*"))},
            "root_probe": root_probe.read_text()[:4000] if root_probe.is_file() else None}


_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))     # the guest's own uploads never use a proxy


def _put(server: str, name: str, data: bytes, cap: int) -> dict:
    truncated = len(data) > cap
    if truncated:
        data = b"[the first %d bytes were cut by the guest]\n" % (len(data) - cap) + data[-cap:]
    req = urllib.request.Request(f"{server}{UPLOAD_PREFIX}{name}", data=data, method="PUT",
                                 headers={"Content-Type": "application/octet-stream", "X-Guest-Time": f"{time.time():.3f}"})
    try:
        with _NO_PROXY.open(req, timeout=120) as r:
            st = r.status
    except urllib.error.HTTPError as e:
        st = e.code
    except OSError:
        st = 0
    return {"name": name, "sha256": _sha(data), "bytes": len(data), "status": st, "truncated": truncated}


def _say(text: str):
    print(f"vm_rerun guest: {text}", flush=True)


def _log_text(r: dict, cap: int | None = None) -> str:
    text = f"rc={r['rc']} seconds={r['seconds']}\n--- stdout ---\n{r['stdout']}\n--- stderr ---\n{r['stderr']}"
    return text if cap is None or len(text) <= cap else f"[the first {len(text) - cap} characters were cut]\n" + text[-cap:]


def _root_copy(tar_path, dest) -> Path:
    """RUNBOOK.md and clean_rerun.py out of the checked code.tar into a NEW folder of root's (0700): the root step never
    reads a file edgefollow could have written."""
    dest = Path(dest)
    os.mkdir(dest, 0o700)
    want = {"estimed/RUNBOOK.md", "estimed/clean_rerun.py"}
    with tarfile.open(tar_path) as t:
        members = [m for m in t.getmembers() if m.name in want]
        if sorted(m.name for m in members) != sorted(want) or not all(m.isfile() for m in members):
            raise VmError("code.tar does not hold estimed/RUNBOOK.md and estimed/clean_rerun.py once each, as files")
        t.extractall(dest, members=members, filter="data")
    return dest / "estimed"


def root_main(cfg_path) -> int:
    """The root step (harness step root-blocks), started by run.sh as root before the code is delivered to edgefollow: ONLY
    the runbook's install blocks marked root=yes, in order, through clean_rerun's Executor (bash -c, as written), from
    root's home, with expected_root_env; it stops after a failed one, as a developer would. Their ids, SHA-256s and
    exit codes go to the console (only root may write it) and, with their output, to root_blocks.json, which the
    edgefollow guest reads and uploads. Always exits 0 after writing both, whatever broke."""
    cfg = json.loads(Path(cfg_path).read_text())
    h = Path(cfg["guest_dir"])
    res = {"kind": "vm_rerun_root", "uid": os.getuid(), "started_epoch": round(time.time(), 3), "runbook_sha256": None,
           "blocks": [], "not_run": [], "error": None, "env": None, "cwd": None, "logs": {}}
    try:
        est = _root_copy(h / "code.tar", h / "rootcode")
        cr = _clean_rerun(est)
        text = (est / "RUNBOOK.md").read_text()
        res["runbook_sha256"] = _sha(text.encode())
        rb = cr.parse_runbook(text)
        installs = check_install_plan(rb, cfg["install_plan"])
        ids = root_block_ids(rb)
        if ids != cfg["root_block_ids"]:
            raise VmError(f"the runbook's root=yes blocks {ids} are not the ones user-data names {cfg['root_block_ids']}")
        steps = [s for s in installs if is_root_block(s)]
        if steps:
            fd = os.open(cfg["apt_conf"], os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(apt_proxy_conf(cfg["proxy"]))       # harness step apt-proxy
        env = expected_root_env(rb, cfg)
        res["env"], res["cwd"] = env, ROOT_BLOCK_ENV["HOME"]
        ex = cr.Executor(steps, env, ROOT_BLOCK_ENV["HOME"])
        done, not_run = run_installs(ex, steps, lambda sid, r: res["logs"].__setitem__(
            sid, _log_text(r, cfg["file_cap"])))
        res["blocks"] = [dict(d, **{"as": "root"}) for d in done]
        res["not_run"] = not_run
    except Exception as e:                  # the console line and the file still go out
        res["error"] = f"{type(e).__name__}: {e}"[:600]
    res["ended_epoch"] = round(time.time(), 3)
    try:
        fd = os.open(h / ROOT_RESULT, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(res, indent=1) + "\n")
    except OSError as e:
        res["error"] = (res["error"] or "") + f"; {ROOT_RESULT} not written: {e}"[:200]
    line = {"blocks": [{"id": b["id"], "sha256": b["sha256"], "rc": b["rc"]} for b in res["blocks"]],
            "not_run": res["not_run"], "error": res["error"]}
    try:
        with open(cfg["console"], "a") as c:
            c.write(ROOT_MARKER + json.dumps(line, separators=(",", ":")) + "\n")
    except OSError:
        pass
    return 0


def guest_main(cfg_path) -> int:
    """The edgefollow guest (harness step guest): the install blocks NOT marked root=yes, after the root step's ones
    succeeded, then the runbook's rerun block, each through clean_rerun's Executor exactly as written, from edgefollow's
    home; then the uploads and the summary. Every runbook block it runs is one the host named in config.json by id and
    SHA-256."""
    cfg = json.loads(Path(cfg_path).read_text())
    w, root = Path(cfg["harness_dir"]), Path(cfg["code_root"])
    doc = {"kind": "vm_rerun_guest", "attempt": cfg["attempt"], "started_epoch": round(time.time(), 3),
           "started_utc": _utc(), "uptime_at_start_s": None, "commands": [], "installs": [], "install_not_run": [],
           "section6": {"started": False}, "uploads": [], "guest_error": None, "runbook_sha256": None,
           "install_env": None, "rerun_env": None, "root_step": None, "root_missing": False}
    files = []                                              # (upload name, path) in the order they are sent

    def keep(name: str, text: str):
        p = w / name
        p.write_text(text)
        files.append((name, p))
    try:
        doc["uptime_at_start_s"] = float(Path("/proc/uptime").read_text().split()[0])
        doc["probes"] = guest_probes(cfg)
        rp = Path(cfg["guest_dir"]) / ROOT_RESULT              # read first: what root ran is reported whatever follows
        try:
            rres = json.loads(rp.read_text())
        except (OSError, ValueError):
            rres = None
        if not isinstance(rres, dict):
            doc["root_missing"] = True
            raise VmError(f"the root step left no readable {ROOT_RESULT}; no install block is run")
        files.append((ROOT_RESULT, rp))
        doc["root_step"] = {k: rres.get(k) for k in ("uid", "blocks", "not_run", "error", "env", "cwd",
                                                      "runbook_sha256")}
        root_done = [{k: b.get(k) for k in ("id", "sha256", "rc", "seconds", "started_epoch", "ended_epoch")}
                     | {"as": "root"} for b in rres.get("blocks") or [] if isinstance(b, dict)]
        doc["installs"] = list(root_done)
        doc["commands"] += [{"kind": "runbook", "as": "root", "id": b["id"], "sha256": b["sha256"], "rc": b["rc"],
                             "seconds": b["seconds"]} for b in root_done]
        root_ok = (not rres.get("error") and not rres.get("not_run") and all(b["rc"] == 0 for b in root_done)
                   and [b["id"] for b in root_done] == cfg["root_block_ids"])
        _say("root blocks: " + (", ".join(f"{b['id']} rc={b['rc']}" for b in root_done) or "none")
             + (f"; error: {rres['error']}" if rres.get("error") else ""))
        cr = _clean_rerun(root / "estimed")
        text = (root / "estimed" / "RUNBOOK.md").read_text()
        doc["runbook_sha256"] = _sha(text.encode())
        rb = cr.parse_runbook(text)
        installs = check_install_plan(rb, cfg["install_plan"])
        if root_block_ids(rb) != cfg["root_block_ids"]:
            raise VmError("the runbook's root=yes blocks are not the ones user-data names")
        if rb.variables.get("ROOT") != str(root):
            raise VmError(f"the code was delivered to {root}, the runbook's ROOT is {rb.variables.get('ROOT')}")
        rerun = rerun_block(text, rb, cr)
        if ({"id": rerun.id, "sha256": rerun.sha256} if rerun else None) != cfg["rerun_block"]:
            raise VmError("the runbook's rerun block is not the one user-data names (or its text changed)")
        places = {k: rb.variables[k] for k in sorted(cr.PLACE_VARS)}
        s6_env = cr.base_env(rb, places)
        env = dict(s6_env, **proxy_env(cfg["proxy"]))          # harness step `proxy`: the install blocks only
        edgefollow_steps = [s for s in installs if not is_root_block(s)]
        ex = cr.Executor(edgefollow_steps, env, os.environ["HOME"])
        doc["install_env"] = dict(ex.env)
        if root_ok:
            _say(f"install blocks as edgefollow: {', '.join(s.id for s in edgefollow_steps)}")
            done, not_run = run_installs(ex, edgefollow_steps, lambda sid, r: keep(
                f"install_{safe_name(sid)}.txt", _log_text(r)))
        else:
            done, not_run = [], [s.id for s in edgefollow_steps]
        doc["installs"] += [dict(d, **{"as": "edgefollow"}) for d in done]
        doc["install_not_run"] = list(rres.get("not_run") or []) + not_run
        doc["commands"] += [{"kind": "runbook", "as": "edgefollow", "id": e["id"], "sha256": e["sha256"], "rc": e["rc"],
                             "seconds": e["seconds"]} for e in ex.log]
        _say("install blocks: " + ", ".join(f"{d['id']} rc={d['rc']} {d['seconds']}s" for d in doc["installs"])
             + (f"; not run: {', '.join(doc['install_not_run'])}" if doc["install_not_run"] else ""))
        all_done = doc["installs"]
        if all_done and all(d["rc"] == 0 for d in all_done) and not doc["install_not_run"]:
            if rerun is None:
                doc["section6"] = {"started": False, "why": "the runbook has no rerun block (`: runbook-step <id> "
                                   f"phase={RERUN_PHASE} && ...` in a fence clean_rerun.py does not read, such as "
                                   "```text)"}
            else:
                ex6 = cr.Executor([rerun], s6_env, os.environ["HOME"])
                doc["rerun_env"] = dict(ex6.env)
                t0 = time.time()
                doc["section6"] = {"started": True, "id": rerun.id, "sha256": rerun.sha256, "cwd": os.environ["HOME"],
                                   "cwd_is": "edgefollow's home: the rerun block runs exactly as written, the harness adds "
                                             "no cd", "timeout_s": cr.STEP_TIMEOUT_S, "started_epoch": round(t0, 3)}
                _say(f"rerun block {rerun.id} ({rerun.sha256[:12]})")
                r = ex6.run(rerun)
                rc, out, err = r["rc"], r["stdout"], r["stderr"]
                doc["commands"] += [{"kind": "runbook", "as": "edgefollow", "phase": RERUN_PHASE, "id": e["id"],
                                     "sha256": e["sha256"], "rc": e["rc"], "seconds": e["seconds"]} for e in ex6.log]
                tail = [ln for ln in err.splitlines() if ln.strip()][-1:] or [""]
                doc["section6"].update(rc=rc, ended_epoch=round(time.time(), 3), seconds=r["seconds"],
                                       tail=tail[0][:200])
                keep("section6_output.txt", f"rc={rc}\n--- stdout ---\n{out}\n--- stderr ---\n{err}")
                last = [ln for ln in out.splitlines() if ln.strip()][-1:] or [""]
                _say(f"rerun block exit {rc}: {last[0][:160]}")
                if re.fullmatch(re.escape(cfg["clean_rerun_results"]) + r"/clean_rerun_\d{8}T\d{6}Z\.json", last[0].strip()):
                    rec_path = Path(last[0].strip())
                    rec = json.loads(rec_path.read_text())
                    files.insert(0, ("cr_record.json", rec_path))   # sent first: its arrival times step 5 on the host
                    doc["clean_rerun"] = {"record": str(rec_path), "result": rec.get("result")}
                    dirs = rec.get("directories") or {}
                    base, out_dir, run_dir = (Path(dirs.get(k, "/nonexistent")) for k in ("base", "out", "run"))
                    for p in sorted(base.glob("bootstrap_*.txt")) + sorted(base.glob("manifest.json")):
                        files.append((f"cr_{safe_name(p.name)}", p))
                    for p in sorted(out_dir.glob("*")):
                        if p.is_file():
                            files.append((f"cr_out_{safe_name(p.name)}", p))
                    if rec.get("result") != "PASS":
                        for node in ("in", "mn-a", "mn-b"):
                            for p in [run_dir / node / "stdout.log", *sorted((run_dir / node / "logs").glob("*.log"))]:
                                if p.is_file():
                                    files.append((f"cse_{node}_{safe_name(p.name)}", p))
                else:
                    doc["clean_rerun"] = {"record": None, "result": None}
        else:
            doc["section6"] = {"started": False, "why": "an install block failed or was not run; the runbook's later "
                                                        "steps need what the install blocks make"}
    except Exception as e:                  # the record says what broke; the uploads and the summary still go out
        doc["guest_error"] = f"{type(e).__name__}: {e}"[:600]
        _say(f"error: {doc['guest_error']}")
    for name, p in files:
        try:
            doc["uploads"].append(_put(cfg["server"], name, p.read_bytes(), cfg["file_cap"]))
        except OSError as e:
            doc["uploads"].append({"name": name, "status": None, "error": str(e)[:200]})
    doc["finished_epoch"] = round(time.time(), 3)
    gbytes = (json.dumps(doc, indent=1) + "\n").encode()
    g = _put(cfg["server"], "guest.json", gbytes, len(gbytes) + 1)
    s6 = doc["section6"]
    summary = {"attempt": cfg["attempt"], "guest_error": doc["guest_error"], "root_missing": doc["root_missing"],
               "installs": [{"id": d["id"], "rc": d["rc"], "seconds": d["seconds"], "as": d.get("as")}
                            for d in doc["installs"]],
               "install_not_run": doc["install_not_run"],
               "section6": {"started": s6.get("started", False), "id": s6.get("id"), "rc": s6.get("rc"),
                            "tail": s6.get("tail"), "why": s6.get("why")},
               "cr_result": (doc.get("clean_rerun") or {}).get("result"), "uploads": len(doc["uploads"]),
               "uploads_refused": sum(u.get("status") != 201 for u in doc["uploads"]),
               "guest_json_sha256": g["sha256"], "guest_json_bytes": g["bytes"], "guest_json_status": g["status"],
               "epoch": round(time.time(), 3)}
    (w / "summary.json").write_text(json.dumps(summary, separators=(",", ":")))
    _say(f"done: {json.dumps(summary, separators=(',', ':'))[:300]}")
    return 0


# ------------------------------------------------------------------------------------------ the host run
def _meminfo(key: str) -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith(key + ":"):
            return int(line.split()[1])
    return 0


def _memory_cap_works(sr: str) -> bool:
    try:
        return subprocess.run([sr, "--user", "--scope", "--quiet", "-p", f"MemoryMax={MEMORY_CAP}", "-p",
                               "MemorySwapMax=0", "--", "true"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def preflight(dry_run: bool) -> dict:
    t = {"qemu": shutil.which("qemu-system-x86_64"), "qemu_img": shutil.which("qemu-img"), "systemd_run": None}
    if dry_run:
        return t
    if not t["qemu"] or not t["qemu_img"]:
        raise VmError("qemu-system-x86_64 / qemu-img are not installed (this harness installs nothing)")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise VmError("/dev/kvm is not readable and writable for this user")
    if _meminfo("MemAvailable") < MIN_MEM_AVAILABLE_KB:
        raise VmError(f"MemAvailable {_meminfo('MemAvailable')} kB is under {MIN_MEM_AVAILABLE_KB} kB: a 4 GB VM would "
                      "push earlyoom onto other work")
    if shutil.disk_usage(VM_DIR).free < MIN_FREE_RUNS_BYTES:
        raise VmError(f"under {MIN_FREE_RUNS_BYTES >> 30} GB free on {VM_DIR}")
    sr = shutil.which("systemd-run")
    if not sr or not _memory_cap_works(sr):
        raise VmError(f"systemd-run cannot put QEMU into a scope capped at {MEMORY_CAP} here: refused, no QEMU runs "
                      "without the cap")
    t["systemd_run"] = sr
    t["qemu_version"] = subprocess.run([t["qemu"], "--version"], capture_output=True, text=True,
                                       timeout=30).stdout.splitlines()[:1]
    return t


def _stop_proc(proc) -> str:
    for sig, wait in ((signal.SIGTERM, 30), (signal.SIGKILL, 30)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return "gone"
        try:
            proc.wait(wait)
            return sig.name
        except subprocess.TimeoutExpired:
            continue
    return "unkillable"


def watch(proc, serial: Path, t0: float, limit: float, grace: float) -> dict:
    """Waits for QEMU to end, reading the serial log as it grows and stamping each harness line with this host's clock;
    kills QEMU at the wall-clock limit, or when the VM has not powered off `grace` seconds after its summary."""
    seen, buf, pos, t_summary, killed = [], "", 0, None, None
    while True:
        rc = proc.poll()
        try:
            with open(serial, "rb") as f:
                f.seek(pos)
                chunk = f.read()
                pos += len(chunk)
        except FileNotFoundError:
            chunk = b""
        if chunk:
            buf += chunk.decode("utf-8", "replace")
            *lines, buf = buf.split("\n")
            now = time.time()
            for ln in lines:
                for tag in (PROGRESS, MARKER, ROOT_MARKER):
                    i = ln.find(tag)
                    if i >= 0:
                        seen.append({"t_host": round(now, 3), "since_vm_start_s": round(now - t0, 1),
                                     "line": (tag + ln[i + len(tag):].strip())[:160]})
                        print(f"  [{now - t0:7.1f} s] {seen[-1]['line'][:150]}", flush=True)
                        if tag == MARKER and t_summary is None:
                            t_summary = now
        if rc is not None:
            break
        now = time.time()
        if now - t0 > limit:
            killed = "wall-clock limit: " + _stop_proc(proc)
            break
        if t_summary and now - t_summary > grace:
            killed = "no power-off after the summary: " + _stop_proc(proc)
            break
        time.sleep(1.0)
    return {"lines": seen, "exit_rc": proc.returncode, "ended_host": round(time.time(), 3), "killed": killed,
            "timed_out": bool(killed and killed.startswith("wall-clock")), "powered_off_by_itself": killed is None}


def _http(port: int, method: str, path: str, body: bytes | None = None, headers: dict | None = None) -> int:
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.putrequest(method, path, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        if body is not None and "Content-Length" not in (headers or {}):
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        st = c.getresponse().status
        c.close()
        return st
    except OSError:
        return 0


def live_server_controls(server: SeedServer) -> list:
    """Three planted requests against the live server after the VM has ended: each must be refused."""
    rows, d = [], server.results_dir
    before = sorted(p.name for p in d.iterdir())
    st = _http(server.port, "PUT", "/up/../escape", b"x")
    after = sorted(p.name for p in d.iterdir())
    rows.append({"row": "CONTROL (must FAIL) the seed server took an upload whose name has a path component",
                 "passed": not (400 <= st < 500) or after != before or (d.parent / "escape").exists(), "detail": f"HTTP {st}"})
    st = _http(server.port, "PUT", "/up/oversize.bin", None, {"Content-Length": str(server.cap + 1)})
    rows.append({"row": "CONTROL (must FAIL) the seed server took an upload over its size cap",
                 "passed": st != 413 or (d / "oversize.bin").exists(), "detail": f"HTTP {st}"})
    had = (d / "guest.json").exists()
    st = _http(server.port, "DELETE", "/up/guest.json")
    rows.append({"row": "CONTROL (must FAIL) the seed server answered a DELETE",
                 "passed": st != 405 or (had and not (d / "guest.json").exists()), "detail": f"HTTP {st}"})
    return rows


def _proxy_ask(port: int, raw: bytes) -> str:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=20) as s:
            s.sendall(raw)
            buf = b""
            while b"\r\n" not in buf:
                chunk = s.recv(1024)
                if not chunk:
                    break
                buf += chunk
        return buf.split(b"\r\n", 1)[0].decode("latin-1")
    except OSError as e:
        return f"error: {e}"


PROXY_CONTROLS = (
    ("a tunnel to a host not on the allow-list (example.invalid:443)", b"CONNECT example.invalid:443 HTTP/1.1\r\n\r\n", 403),
    ("a tunnel to an allowed host on another port (pypi.org:80)", b"CONNECT pypi.org:80 HTTP/1.1\r\n\r\n", 403),
    ("a tunnel to an address literal (192.0.2.1:443)", b"CONNECT 192.0.2.1:443 HTTP/1.1\r\n\r\n", 403),
    ("a plain GET through it (not CONNECT)", b"GET http://pypi.org/ HTTP/1.1\r\nHost: pypi.org\r\n\r\n", 405),
)


def live_proxy_controls(proxy: AllowProxy) -> list:
    """Four planted requests against the live proxy after the VM has ended: each must be refused with its status."""
    rows = []
    for label, raw, want in PROXY_CONTROLS:
        line = _proxy_ask(proxy.port, raw)
        m = re.match(r"HTTP/1\.1 (\d{3}) ", line + " ")
        st = int(m.group(1)) if m else 0
        rows.append({"row": f"CONTROL (must FAIL) the proxy opened {label}", "passed": st != want, "detail": line[:80]})
    return rows


def verdict_controls(facts: dict, ref_kpi: dict, vm_kpi: dict | None, summary: dict | None, results_dir: Path,
                     rec: dict | None = None, run_plan: list | None = None) -> list:
    cr, rows = _clean_rerun(), []
    f = copy.deepcopy(facts)
    if f.get("cr"):
        f["cr"]["results"].pop(LAST_TD, None)
    v5 = obs03_steps(f)[4]["verdict"]
    rows.append({"row": "CONTROL (must FAIL) with TD_MEC_DEV_01 taken out of the VM's results, step 5 is PASS",
                 "passed": v5 == PASS, "detail": v5})
    f = copy.deepcopy(facts)
    f["dev01_elapsed_s"] = f["budget_s"] + 1.0
    v5 = obs03_steps(f)[4]["verdict"]
    rows.append({"row": "CONTROL (must FAIL) step 5 is PASS when this host received the record 1 s after the budget",
                 "passed": v5 == PASS, "detail": v5})
    planted = [{"step": n, "verdict": NOT_RUN if n == 3 else PASS} for n in range(1, 6)]
    rows.append({"row": "CONTROL (must FAIL) the verdict is PASS with step 3 NOT-RUN and the other four PASS",
                 "passed": overall(planted, [{"passed": False}], []), "detail": ""})
    base = vm_kpi if vm_kpi and vm_kpi.get("tests_passed") else ref_kpi
    off = copy.deepcopy(base)
    td = sorted(off["tests_passed"])[0]
    off["tests_passed"][td]["numerator"] -= 1
    d = cr.compare_kpis(ref_kpi, off)
    rows.append({"row": f"CONTROL (must FAIL) the KPI comparison finds nothing when {td}'s count is one less "
                        f"({'the VM' if base is vm_kpi else 'the reference'} against the reference)",
                 "passed": d == cr.compare_kpis(ref_kpi, base), "detail": "; ".join(d)[:200]})
    if summary is not None:
        _, _, p = verify_uploads(dict(summary, guest_json_sha256="0" * 64), results_dir)
        rows.append({"row": "CONTROL (must FAIL) the uploads verify against a summary naming another guest.json",
                     "passed": not p, "detail": "; ".join(p)[:200]})
    if rec is not None and run_plan is not None:
        sd = [s.id for s in run_plan if s.phase == "shutdown"]
        real = cr_verdict_problems(rec, sd)
        p = cr_verdict_problems(dict(copy.deepcopy(rec), result="PLANTED-FAIL"), sd)
        rows.append({"row": "CONTROL (must FAIL) the VM's clean_rerun record with its result set to FAIL is accepted",
                     "passed": not [x for x in p if x not in real], "detail": "; ".join(p)[:200]})
        real = cr.check_executed(run_plan, rec.get("executed") or [])
        p = cr.check_executed(run_plan, (rec.get("executed") or []) + [{"id": "planted-by-hand", "sha256": "0" * 64}])
        rows.append({"row": "CONTROL (must FAIL) the VM's executed-command log with one foreign entry is accepted here",
                     "passed": not [x for x in p if x not in real], "detail": "; ".join(p)[:200]})
    for k, n in (("executed_problems", 2), ("verdict_problems", 4)):
        f = copy.deepcopy(facts)
        if f.get("cr"):
            f["cr"][k] = [f"planted: one {k.split('_')[0]} problem"]
        v = obs03_steps(f)[n - 1]["verdict"]
        rows.append({"row": f"CONTROL (must FAIL) step {n} is PASS with one planted {k.replace('_', ' ')[:-1]}",
                     "passed": v == PASS, "detail": v})
    return rows


def _tests_per_td(rec: dict | None) -> dict:
    out = {}
    for td, r in ((rec or {}).get("results") or {}).items():
        out[td] = {k: r.get(k) for k in ("ok", "declared", "ran", "passed", "failed", "error", "skipped")}
        out[td]["problems"] = (r.get("problems") or [])[:3]
    return out


def _kpi_brief(k: dict | None) -> dict:
    k = k or {}
    return {"tests_passed": {td: [v.get("numerator"), v.get("denominator")] for td, v in (k.get("tests_passed") or {}).items()},
            "cse_registration_success": [(k.get("cse_registration_success") or {}).get("numerator"),
                                         (k.get("cse_registration_success") or {}).get("denominator")]}


def network_record(relay_cmd: str, relay: dict | None, seed_port: int, proxy: AllowProxy | None) -> dict:
    return {"netdev": netdev_value(relay_cmd, seed_port, proxy.port if proxy else 0),
            "guestfwd": [{"in_vm": f"{SEED_ADDR}:{SEED_GUEST_PORT}", "on_host": f"127.0.0.1:{seed_port}",
                          "what": "the seed and upload server"},
                         {"in_vm": f"{PROXY_ADDR}:{PROXY_GUEST_PORT}",
                          "on_host": f"127.0.0.1:{proxy.port if proxy else 0}", "what": "the allow-listing proxy"}],
            "relay": dict(relay or {}, cmd=relay_cmd),
            "proxy": {"allow": sorted(f"{h}:{p}" for h, p in PROXY_ALLOW), "methods": ["CONNECT"],
                      "caps": {"bytes_per_tunnel": PROXY_CONN_CAP, "bytes_per_run": PROXY_TOTAL_CAP,
                               "tunnels_per_run": PROXY_MAX_CONNS, "idle_s": PROXY_IDLE_S,
                               "tunnel_lifetime_s": PROXY_CONN_MAX_S, "head_bytes": PROXY_HEAD_MAX,
                               "head_timeout_s": PROXY_HEAD_TIMEOUT_S},
                      "resolves": "on this host; a name that resolves to a non-public address is refused",
                      "summary": proxy.summary() if proxy else None, "log": list(proxy.log) if proxy else []},
            "given_to": {"install blocks": proxy_env(PROXY_URL),
                         "root=yes install blocks": dict(proxy_env(PROXY_URL), APT_CONFIG=APT_CONF),
                         "apt": f"only in the root=yes blocks, through APT_CONFIG: {apt_proxy_conf(PROXY_URL)!r}",
                         "rerun block": "nothing"},
            "restrict": True, "ipv6": False, "ipv6_closed": IPV6_CLOSED,
            "statement": "restrict=on and ipv6=off: over IPv4 the VM reaches nothing on this host, its LAN or the "
                         "internet except the two guestfwd targets; over IPv6 it reaches nothing at all; slirp's "
                         "restricted mode gives it no DNS; no port of this host is forwarded into the VM"}


def cmd_run(args) -> int:
    cr = _clean_rerun()
    attempt, repo = args.attempt, Path(args.repo).resolve()
    os.environ["GIT_OPTIONAL_LOCKS"] = "0"
    private_parent = Path(args.private_dir)
    if not private_parent.is_absolute():
        raise VmError(f"--private-dir {args.private_dir!r} is not an absolute path: refused")
    tools = preflight(args.dry_run)
    private = check_private_dir(private_parent)
    if not args.dry_run and not private["ok"]:
        raise VmError(f"the private folder: {private['why']}")
    sums_bytes = SUMS_FILE.read_bytes()
    listed = listed_digest(sums_bytes.decode("utf-8", "replace"), BASE_IMAGE.name)
    ref_path = Path(args.reference)
    ref_bytes = ref_path.read_bytes()
    ref = json.loads(ref_bytes)
    rb_diff = _git(repo, ["diff", "HEAD", "--", "estimed/RUNBOOK.md"])
    previous = None
    if attempt == 1 and rb_diff:
        raise VmError("attempt 1 runs the runbook as committed, and estimed/RUNBOOK.md differs from HEAD")
    if attempt == 2:
        if not rb_diff or not args.previous or not args.why:
            raise VmError("attempt 2 needs a changed estimed/RUNBOOK.md, --previous <attempt-1 record> and --why")
        pdoc = json.loads(Path(args.previous).read_text())
        if pdoc.get("kind") != "vm_rerun" or pdoc.get("attempt") != 1 or pdoc.get("result") != "FAIL":
            raise VmError("--previous is not a failed attempt-1 record of this harness")
        previous = {"file": str(Path(args.previous).resolve()), "sha256": _sha_file(args.previous),
                    "result": pdoc["result"], "obs03_steps": [{k: s[k] for k in ("step", "verdict", "why")}
                                                              for s in pdoc["obs03_steps"]]}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = new_run_dir(RUNS_DIR, stamp)
    print(f"vm_rerun attempt {attempt}{' (dry run)' if args.dry_run else ''}: evidence folder {run_dir}", flush=True)
    stage = Path(tempfile.mkdtemp(prefix=f"vm_rerun_stage_{stamp}_",
                                  dir=STAGE_PARENT if STAGE_PARENT.is_dir() else None))
    try:
        code = build_code(repo, stage / "s", INCLUDE_ON_ATTEMPT_2 if attempt == 2 else ())
        rb_text = (Path(code["code_dir"]) / "estimed" / "RUNBOOK.md").read_text()
        tar_bytes = Path(code["tar"]).read_bytes()
    finally:
        shutil.rmtree(stage)                         # this run's own staging folder; the tarball is kept below
    code.update(tar="served/code.tar", staged_in=f"{stage} (tmpfs; removed once the tarball was written)")
    if attempt == 2 and code["delivered_from_working_tree"] != list(INCLUDE_ON_ATTEMPT_2):
        raise VmError("attempt 2: the changed RUNBOOK.md was not delivered")
    try:
        rb = cr.parse_runbook(rb_text)
    except cr.RunbookError as e:
        raise VmError(f"RUNBOOK.md: {e}" + (f" (a phase={RERUN_PHASE} block goes in a fence clean_rerun.py does not "
                                           "read, such as ```text)" if f"'{RERUN_PHASE}'" in str(e) else "")) from e
    run_plan = cr.plan(rb)
    if ref.get("result") != "PASS" or [s.sha256 for s in cr.plan(rb) if s.phase == "test"] != \
            [s["sha256"] for s in ref["provenance"]["plan"] if s["phase"] == "test"]:
        raise VmError("the reference did not pass, or it ran other test commands than the delivered runbook holds")
    plan = install_plan(rb)
    root_ids = root_block_ids(rb)
    root_blocks = blocks_needing_root(rb)
    rerun = rerun_block(rb_text, rb, cr)
    rerun_cfg = {"id": rerun.id, "sha256": rerun.sha256} if rerun else None
    guest_src = Path(__file__).resolve().read_bytes()
    cfg = guest_config(attempt, stamp, rb.variables["ROOT"], plan, root_ids, rerun_cfg)
    run_sh = make_run_sh(cfg)
    shas = {"code.tar": code["sha256"], "guest.py": _sha(guest_src), "reference.json": _sha(ref_bytes)}
    sums = sums_text(shas)
    ud = make_user_data(cfg, sums, run_sh)
    problems = audit_user_data(ud, cfg, sums)
    if problems:
        raise VmError("user-data refused by its own audit: " + "; ".join(problems))
    served = {"meta-data": make_meta_data(stamp).encode(), "user-data": ud.encode(), "vendor-data": b"",
              "code.tar": tar_bytes, "guest.py": guest_src, "reference.json": ref_bytes}
    committed = _committed(repo, "estimed/vm_rerun.py")
    priv = private_parent / stamp
    relay_cmd = relay_command(sys.executable, priv / "relay.py")
    if args.dry_run:
        base = check_base_image(BASE_IMAGE, SUMS_FILE)          # in place: a dry run copies nothing
        argv = qemu_argv(tools["qemu"] or "qemu-system-x86_64", priv / "overlay.qcow2", priv / "serial.log", relay_cmd,
                         40001, 40002, f"estimed-vm-{stamp}")
        qp = audit_qemu_argv(argv, relay_cmd, 40001, 40002, priv, f"estimed-vm-{stamp}", private_parent)
        if qp:
            raise VmError("the QEMU command line is not the harness's own: " + "; ".join(qp))
        (run_dir / "served").mkdir()
        for name, data in served.items():
            (run_dir / "served" / name).write_bytes(data)
        prep = {"stamp": stamp, "attempt": attempt, "run_dir": str(run_dir), "user_data_sha256": _sha(served["user-data"]),
                "install_plan": plan, "root_block_ids": root_ids, "rerun_block": dict(rerun_cfg, text=rerun.command)
                if rerun else None, "blocks_needing_root": root_blocks,
                "code": {k: v for k, v in code.items() if k != "files"}, "base_image": base, "tools": tools,
                "private_folder": private, "qemu_argv_with_placeholder_ports": argv,
                "vm_rerun_committed_at_head": committed}
        (run_dir / "dry_run.json").write_text(json.dumps(prep, indent=1) + "\n")
        print(f"dry run: user-data and QEMU line audited clean, {len(plan)} install blocks ({len(root_ids)} as root: "
              f"{', '.join(root_ids) or 'none'}), rerun block "
              f"{rerun.id + ' ' + rerun.sha256[:12] if rerun else 'NONE: the VM would stop after the install blocks'}, "
              f"code {code['file_count']} files ({code['sha256'][:16]}), private folder "
              f"{'ok' if private['ok'] else 'NOT ok: ' + private['why']}, nothing booted -- {run_dir / 'dry_run.json'}")
        return 0
    if not committed:
        print("NOTE: estimed/vm_rerun.py is not committed as it is: the record cannot show that its budget was fixed "
              "before this run", flush=True)
    priv = new_private_run_dir(private_parent, stamp)
    base = copy_base_image(BASE_IMAGE, priv / "base.qcow2", listed)
    base.update(sums_file=str(SUMS_FILE), sums_sha512=hashlib.sha512(sums_bytes).hexdigest())
    (priv / "SHA512SUMS").write_bytes(sums_bytes)
    relay = write_relay(priv / "relay.py")
    (priv / "served").mkdir()
    for name, data in served.items():
        (priv / "served" / name).write_bytes(data)
    server = SeedServer(served, priv / "results")
    proxy = AllowProxy()
    overlay, serial = priv / "overlay.qcow2", priv / "serial.log"
    qemu_proc, t0, seen, argv, controls = None, None, None, None, []
    try:
        p = subprocess.run(qemu_img_argv(tools["qemu_img"], priv / "base.qcow2", overlay), capture_output=True,
                           text=True, timeout=120)
        if p.returncode != 0:
            raise VmError(f"qemu-img create failed: {p.stderr.strip()[:200]}")
        argv = qemu_argv(tools["qemu"], overlay, serial, relay_cmd, server.port, proxy.port, f"estimed-vm-{stamp}")
        qp = audit_qemu_argv(argv, relay_cmd, server.port, proxy.port, priv, f"estimed-vm-{stamp}", private_parent)
        if qp:
            raise VmError("the QEMU command line is not the harness's own, QEMU not started: " + "; ".join(qp))
        if not tools.get("systemd_run"):
            raise VmError("no memory-capped scope for QEMU: refused, QEMU not started")
        argv = [tools["systemd_run"], "--user", "--scope", "--quiet", "-p", f"MemoryMax={MEMORY_CAP}", "-p",
                "MemorySwapMax=0", "--", *argv]
        server.start()
        proxy.start()
        t0 = time.time()
        with open(priv / "qemu.log", "wb") as qlog:
            qemu_proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=qlog, stderr=subprocess.STDOUT,
                                         start_new_session=True)
            print(f"QEMU started (pid {qemu_proc.pid}); wall-clock limit {WALL_LIMIT_S:.0f} s", flush=True)
            seen = watch(qemu_proc, serial, t0, WALL_LIMIT_S, POWEROFF_GRACE_S)
        qemu_proc = None
        controls = live_server_controls(server) + live_proxy_controls(proxy)
    finally:
        if qemu_proc is not None and qemu_proc.poll() is None:
            _stop_proc(qemu_proc)
        server.stop()
        proxy.stop()

    problems = []
    console = parse_console(serial.read_text(errors="replace") if serial.is_file() else "")
    summary = console["summary"]
    problems += [f"console: {p}" for p in console["problems"]]
    guest = rec = None
    if summary is not None and not summary.get("harness_error"):
        guest, rec, up = verify_uploads(summary, server.results_dir)
        problems += up
    base_after = _sha_file(priv / "base.qcow2", "sha512")
    if base_after != base["sha512"]:
        problems.append("the base image copy changed during the run")
    if rec is not None:
        m = rec.get("manifest")
        if m is not None:                    # no manifest: clean_rerun.py stopped before its copy; step 1 says why
            if m.get("tree_sha256") != code["tree_sha256"] or m.get("commit") != code["synthetic_commit"]:
                problems.append("the VM's clean_rerun copied other code than the delivered tarball")
        if rec.get("provenance") is not None:
            if (rec.get("provenance") or {}).get("runbook_sha256") != _sha(rb_text.encode()):
                problems.append("the VM's clean_rerun read another RUNBOOK.md than the delivered one")
    want_env = expected_install_env(rb, cfg)
    if guest is not None:
        if guest.get("runbook_sha256") != _sha(rb_text.encode()):
            problems.append("the guest read another RUNBOOK.md than the delivered one")
        if guest.get("installs") and guest.get("install_env") != want_env:
            got_env = guest.get("install_env") or {}
            problems.append("the install blocks got another environment than the harness lists: "
                            f"extra {sorted(set(got_env) - set(want_env))}, missing {sorted(set(want_env) - set(got_env))}, "
                            f"changed {sorted(k for k in set(got_env) & set(want_env) if got_env[k] != want_env[k])}"[:400])
        for what, got_env, want in (("the rerun block", guest.get("rerun_env"), expected_rerun_env(rb)),
                                    ("the root blocks", (guest.get("root_step") or {}).get("env"),
                                     expected_root_env(rb, cfg))):
            if got_env is not None and got_env != want:
                problems.append(f"{what} got another environment than the harness lists: extra "
                                f"{sorted(set(got_env) - set(want))}, missing {sorted(set(want) - set(got_env))}, "
                                f"changed {sorted(k for k in set(got_env) & set(want) if got_env[k] != want[k])}"[:400])
        probes = guest.get("probes") or {}
        admin = sorted(set(probes.get("groups") or []) & ADMIN_GROUPS) + (["uid 0"] if probes.get("uid") == 0 else [])
        if admin:
            problems.append(f"the runbook's user in the VM has root or an admin group: {admin}")
        problems += ipv6_problems(probes.get("ipv6_addresses"))
    root_console = root_console_problems(console, summary, guest, plan, root_ids)
    problems += root_console
    vm_kpi = ((rec or {}).get("kpi") or {}).get("equal_by_construction", {}).get("rerun") if rec else None
    kpi_diff = cr.compare_kpis(ref.get("kpi", {}), vm_kpi) if vm_kpi is not None else None
    elapsed = host_elapsed(server.log, t0) if rec is not None else None
    off = clock_offset(server.log)
    dev_end = dev01_end_epoch(rec) if rec else None
    # reported only: what the VM's own log says, put on this host's clock with the offset measured at the uploads
    guest_claim = round(dev_end + 1.0 - off["median_s"] - t0, 1) if dev_end is not None and off else None
    done_lines = [x for x in seen["lines"] if x["line"].startswith(PROGRESS + "guest-done")]
    upper = done_lines[0]["since_vm_start_s"] if done_lines else None
    facts = facts_of(summary, guest, rec, install_plan=plan, rerun_expected=rerun_cfg, kpi_diff=kpi_diff,
                     run_plan=run_plan, elapsed_s=elapsed, budget_s=BUDGET_S)
    facts["last_progress"] = seen["lines"][-1]["line"] if seen["lines"] else None
    steps = obs03_steps(facts)
    controls += verdict_controls(facts, ref.get("kpi", {}), vm_kpi, summary, server.results_dir, rec, run_plan)
    ok = overall(steps, controls, problems)
    phase = {p["id"]: p["phase"] for p in ((rec or {}).get("provenance") or {}).get("plan") or []}
    src = guest or summary or {}
    s6 = src.get("section6") or {}
    blocks = ([{"where": "VM: the root step (as root)" if d.get("as") == "root" else "VM: vm_rerun guest (as edgefollow)",
                "id": d["id"], "phase": "install", "as": d.get("as"), "rc": d["rc"], "seconds": d["seconds"]}
               for d in src.get("installs") or []]
              + [{"where": "VM", "id": i, "phase": "install", "rc": None, "not_run": True}
                 for i in src.get("install_not_run") or []]
              + ([{"where": "VM: vm_rerun guest (as edgefollow)", "id": s6.get("id"), "phase": RERUN_PHASE, "as": "edgefollow",
                   "rc": s6.get("rc"), "seconds": s6.get("seconds")}] if s6.get("started") else [])
              + [{"where": "VM: clean_rerun.py (started by the rerun block)", "id": e.get("id"),
                  "phase": phase.get(e.get("id")), "rc": e.get("rc"), "seconds": e.get("seconds"),
                  "started_utc": e.get("started_utc")}
                 for e in (rec or {}).get("executed") or []])
    on_console = {r[0]: r for r in _root_rows(((console.get("root") or [{}])[0] or {}).get("blocks"))} \
        if len(console.get("root") or []) == 1 else {}
    in_guest = {d.get("id"): d for d in src.get("installs") or [] if d.get("as") == "root"}
    root_record = [{"id": i, "sha256": next(p["sha256"] for p in plan if p["id"] == i), "as": "root",
                    "rc": (on_console.get(i) or (None, None, None))[2], "rc_written_by": "root, on the console",
                    "rc_in_guest_json": (in_guest.get(i) or {}).get("rc"), "seconds": (in_guest.get(i) or {}).get("seconds"),
                    "ran": i in on_console} for i in root_ids]
    code_vs_ref = cr.select(_git(repo, ["diff", "--name-only", ref["commit"], "HEAD", "--", *cr.FOLDERS]).split(),
                            cr.FOLDERS, cr.EXCLUDE)
    record = {
        "kind": "vm_rerun", "td": "TD_MEC_OBS_03", "attempt": attempt, "result": PASS if ok else FAIL, "stamp": stamp,
        "started_utc": datetime.fromtimestamp(t0, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "finished_utc": _utc(),
        "obs03_steps": steps,
        "budget": {"value_s": BUDGET_S, "reason": BUDGET_REASON, "vm_rerun_committed_at_head": committed,
                   "from": "QEMU process start, this host's clock",
                   "to": "this host's receipt of the VM's clean_rerun record (cr_record.json, the guest's first upload; "
                         "it can only exist after TD_MEC_DEV_01 ended), this host's clock",
                   "is": "an upper bound: it also holds clean_rerun's shutdown and controls; the VM's clock is not used",
                   "elapsed_s": elapsed, "console_guest_done_s": upper,
                   "guest_claim_s": guest_claim, "guest_claim_is": "the VM's own log of the td-dev-01 block (whole-second "
                   "start plus 1 s plus its duration) moved onto this host's clock with the offset at the uploads; "
                   "reported, never compared", "guest_clock_offset": off,
                   "clean_rerun_in_vm_t_last_s": (((rec or {}).get("kpi") or {}).get("timings") or {}).get(
                       "empty_directory_to_last_test_description_s")},
        "base_image": dict(base, sha512_after=base_after, unchanged=base_after == base["sha512"],
                           debian_build="see SHA512SUMS and debian-13-genericcloud-amd64.json in " + str(VM_DIR),
                           signature="SHA512SUMS was not signature-checked"),
        "vm": {"argv": argv, "tools": tools, "memory_cap": MEMORY_CAP, "overlay": str(overlay),
               "overlay_bytes_after": overlay.stat().st_size if overlay.exists() else None, "serial_log": str(serial),
               "wall_limit_s": WALL_LIMIT_S, "watch": {k: v for k, v in seen.items() if k != "lines"},
               "harness_lines": seen["lines"], "vm_seconds": round(seen["ended_host"] - t0, 1),
               "network": network_record(relay_cmd, relay, server.port, proxy)},
        "code": {k: v for k, v in code.items() if k not in ("files", "code_dir")}
                | {"vs_reference_commit": {"reference_commit": ref.get("commit"), "files_differing_at_head": code_vs_ref}},
        "runbook": {"sha256": _sha(rb_text.encode()), "install_plan": plan,
                    "rerun_block": dict(rerun_cfg, text=rerun.command) if rerun else None,
                    "rerun_cwd": "edgefollow's home; the block runs exactly as written (the harness adds no cd)",
                    "root_blocks": root_record, "blocks_needing_root": root_blocks,
                    "root": "only the install blocks marked root=yes ran as root (the root step, started by run.sh); "
                            "every other runbook block ran as edgefollow, who has no sudo",
                    "root_console_problems": root_console,
                    "diff_from_head": rb_diff or None, "why_changed": args.why if attempt == 2 else None},
        "harness": {"steps": HARNESS_STEPS, "user_data_sha256": _sha(served["user-data"]),
                    "user_data_file": "served/user-data", "run_sh_template_sha256": _sha(RUN_SH_TEMPLATE.encode()),
                    "guest_driver_sha256": _sha(guest_src), "seed_server": f"127.0.0.1:{server.port}",
                    "install_env_expected": want_env, "rerun_env_expected": expected_rerun_env(rb),
                    "root_env_expected": expected_root_env(rb, cfg), "apt_proxy_conf": apt_proxy_conf(PROXY_URL),
                    "server_log": server.log},
        "guest": {k: (guest or {}).get(k) for k in ("probes", "installs", "install_not_run", "section6", "guest_error",
                                                    "commands", "uptime_at_start_s", "runbook_sha256", "install_env",
                                                    "rerun_env", "root_step", "root_missing")}
        if guest else {"summary": summary},
        "blocks": blocks,
        "tests_per_td": _tests_per_td(rec),
        "kpi": {"reference_file": str(ref_path.resolve()), "reference_sha256": _sha(ref_bytes),
                "reference_commit": ref.get("commit"), "reference_utc": (ref.get("provenance") or {}).get("utc"),
                "reference": _kpi_brief(ref.get("kpi")), "vm": _kpi_brief(vm_kpi) if vm_kpi else None,
                "differences_recomputed_here": kpi_diff,
                "differences_in_vm": ((rec or {}).get("kpi") or {}).get("equal_by_construction", {}).get("differences")
                if rec else None,
                "timings_s": {td: {"reference": (ref.get("kpi") or {}).get("timings_s", {}).get(td), "vm": v.get("rerun_s")}
                              for td, v in ((((rec or {}).get("kpi") or {}).get("timings") or {})
                                            .get("per_test_description") or {}).items()},
                "compared": "tests passed per test description (with the ids), MN-CSE registration, resources left per "
                            "CSE by type; timings are reported, never compared"},
        "clean_rerun_in_vm": {"result": (rec or {}).get("result"), "rows": (rec or {}).get("steps"),
                              "controls": (rec or {}).get("controls"), "not_run": (rec or {}).get("not_run"),
                              "verdict_problems_read_here": (facts.get("cr") or {}).get("verdict_problems"),
                              "executed_problems_checked_here": (facts.get("cr") or {}).get("executed_problems"),
                              "note": "its NOT-RUN rows are fixed text written for this PC"} if rec else None,
        "controls": controls,
        "integrity_problems": problems,
        "console_problems": console["problems"],
        "previous_attempt": previous,
        "does_not_show": NOT_SHOWN,
        "files": {"private_run_dir": str(priv), "evidence_copy": str(run_dir),
                  "kept_only_in_the_private_folder": ["base.qcow2", "overlay.qcow2"], "uploads": "results/"},
    }
    text = json.dumps(record, indent=1, default=str) + "\n"
    (priv / "record.json").write_text(text)
    evidence = copy_evidence(priv, run_dir)
    (run_dir / "evidence.json").write_text(json.dumps({"from": str(priv), "files": evidence}, indent=1) + "\n")
    out = RESULTS_DIR / f"vm_rerun_{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print("\nTD_MEC_OBS_03 on a fresh VM, attempt", attempt)
    for s in steps:
        print(f"  step {s['step']}: {s['verdict']:7s} {s['why'][:150]}")
    for c in controls:
        print(f"  {'FAIL (as it must)' if not c['passed'] else 'PASSED -- THE CONTROL DID NOT CATCH IT'}  {c['row']}")
    for p in problems:
        print(f"  PROBLEM  {p}")
    print(f"RESULT: {PASS if ok else FAIL}; time to {LAST_TD} (this host's clock, upper bound): {elapsed} s of "
          f"{BUDGET_S:.0f} s\n{out}\nevidence: {run_dir} (disk images stay in {priv})")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--attempt", type=int, choices=[1, 2], required=True)
    r.add_argument("--previous", default=None, help="attempt 2: the attempt-1 record")
    r.add_argument("--why", default=None, help="attempt 2: why the runbook changed, from attempt 1's record")
    r.add_argument("--reference", default=str(REFERENCE_DEFAULT))
    r.add_argument("--repo", default=str(REPO))
    r.add_argument("--private-dir", default=str(PRIVATE_PARENT),
                   help="a 0700 folder of this user on a local POSIX filesystem with room (default %(default)s)")
    r.add_argument("--dry-run", action="store_true")
    r.set_defaults(fn=cmd_run)
    g = sub.add_parser("guest")
    g.add_argument("--config", required=True)
    g.set_defaults(fn=lambda a: guest_main(a.config))
    o = sub.add_parser("root")
    o.add_argument("--config", required=True)
    o.set_defaults(fn=lambda a: root_main(a.config))
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except VmError as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
