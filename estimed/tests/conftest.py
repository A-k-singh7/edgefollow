"""Shared fixtures for the ESTIMED oneM2M + MEC tests.

The tests run against the LIVE local stack, never a mock:

    bash estimed/run_topology.sh                 # IN :8200, MN-A :8201, MN-B :8202 (ACME)
    mec011_appsupport/candidate.py               # MEC 011 :8091 (started here if absent)

Run with the venv that has pytest (the oneM2M client here is stdlib-only):

    /home/edgefollow/edgefollow-lab/.venv/bin/python -m pytest estimed/tests -q

A missing CSE is an ERROR, not a skip: in this repo a skipped test is not a passing
test, and a suite that silently skips everything reads as green.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ESTIMED = Path(__file__).resolve().parents[1]
REPO = ESTIMED.parent
sys.path.insert(0, str(ESTIMED))

import handover  # noqa: E402  the implementation under test

IN_CSE = handover.IN_CSE
EDGE_A = handover.EDGE_A
EDGE_B = handover.EDGE_B
CSI = {IN_CSE: "id-in", EDGE_A: "id-mn-a", EDGE_B: "id-mn-b"}

MEC011 = os.environ.get("ESTIMED_MEC011", "http://127.0.0.1:8091/mec_app_support/v2").rstrip("/")
MEC_VENV_PY = "/home/edgefollow/edgefollow-lab/.venv/bin/python"

TY_ACP, TY_AE, TY_CNT, TY_CIN, TY_CSEBASE, TY_SUB, TY_CSR = 1, 2, 3, 4, 5, 23, 16


def req(method: str, url: str, origin: str, *, ty: int | None = None,
        body: dict | None = None) -> tuple[int, dict | None, dict]:
    """One oneM2M request. Returns (http status, parsed body, response headers).

    Same wire shape as handover._req, plus the headers: the oneM2M result code
    (X-M2M-RSC) is the assertion that matters, the HTTP status only maps it.
    """
    data = json.dumps(body).encode() if body is not None else None
    ct = f"application/json;ty={ty}" if ty else "application/json"
    r = urllib.request.Request(url, data=data, method=method, headers={
        "X-M2M-Origin": origin,
        "X-M2M-RI": f"t-{uuid.uuid4().hex[:12]}",
        "X-M2M-RVI": "4",
        "Accept": "application/json",
        "Content-Type": ct,
    })
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None), dict(resp.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = None
        return e.code, parsed, dict(e.headers)


def rsc(headers: dict) -> int | None:
    """The oneM2M Response Status Code from the HTTP binding header."""
    v = {k.lower(): v for k, v in headers.items()}.get("x-m2m-rsc")
    return int(v) if v else None


def http(method: str, url: str, body: dict | None = None) -> tuple[int, dict | None]:
    """A plain REST call (MEC APIs)."""
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return e.code, None


def _port_open(host: str, port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


@pytest.fixture(scope="session")
def topology():
    """All three CSEs answer as what they are, and the IN holds exactly both edges -- TR-0086 5.2 precondition.

    The docstring said "the IN holds both edges" while only the CSEBases were fetched: a half-registered lab let
    every live test run on it (lab fixes of 2026-10-29)."""
    for edge, cst in ((IN_CSE, 1), (EDGE_A, 2), (EDGE_B, 2)):
        st, body, h = req("GET", f"{edge[0]}/{edge[1]}", "CAdmin")
        if st != 200 or rsc(h) != 2000 or (body or {}).get("m2m:cb", {}).get("cst") != cst:
            pytest.fail(f"CSE {edge[1]} at {edge[0]} answered {st}/{rsc(h)} with cst "
                        f"{(body or {}).get('m2m:cb', {}).get('cst')!r}, not {cst}; start estimed/run_topology.sh first",
                        pytrace=False)
    st, body, _ = req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}?fu=1&ty={TY_CSR}", "CAdmin")
    if st != 200 or not handover.edges_ok((body or {}).get("m2m:uril", [])):
        pytest.fail(f"the IN does not hold exactly id-mn-a and id-mn-b: {st} {body}", pytrace=False)
    return {"in": IN_CSE, "a": EDGE_A, "b": EDGE_B}


@pytest.fixture(scope="session")
def mec011():
    """The MEC 011 candidate. Reused if running, otherwise started for the session."""
    proc = None
    if _port_open("127.0.0.1", 8091):
        # Reuse only if it IS MEC 011: the MEC lab binds MEC 048 to this port, and a
        # foreign service answering here once failed 15 tests for the wrong reason.
        st, body = http("GET", f"{MEC011}/timing/current_time")
        if st != 200 or "seconds" not in (body or {}):
            pytest.fail(f":8091 is held by something that is not MEC 011 (timing/current_time "
                        f"-> {st}); stop it or set ESTIMED_MEC011", pytrace=False)
    else:
        proc = subprocess.Popen(
            [MEC_VENV_PY, str(REPO / "mec011_appsupport" / "candidate.py")],
            cwd=str(REPO), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        for _ in range(50):
            if _port_open("127.0.0.1", 8091):
                break
            time.sleep(0.2)
        else:
            proc.kill()
            pytest.fail("MEC 011 candidate did not come up on :8091", pytrace=False)
    yield MEC011
    if proc is not None:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def ae(topology):
    """A fresh device AE name + originator on edge A, removed from every CSE afterwards."""
    name = f"tr86-{uuid.uuid4().hex[:8]}"
    origin = f"C{name}"
    yield name, origin
    for edge in (EDGE_A, EDGE_B):
        req("DELETE", f"{edge[0]}/{edge[1]}/{name}", origin)
        req("DELETE", f"{edge[0]}/{edge[1]}/{name}", "CAdmin")


@pytest.fixture
def vehicle(topology):
    """handover.py's own vehicle (its handover() takes no AE name), cleared before and after."""
    handover.reset()
    yield handover.AE_NAME, handover.AE_ORIGIN
    handover.reset()


class _Receiver(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            body = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            body = None
        self.server.got.append(body)
        self.send_response(200)
        self.send_header("X-M2M-RSC", "2000")
        self.send_header("X-M2M-RI", self.headers.get("X-M2M-RI", ""))
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def receiver():
    """A notification endpoint. Answers 2000 to everything, including verification."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    srv.got = []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}/notify"

    def wait_for(pred, timeout=8.0):
        end = time.time() + timeout
        while time.time() < end:
            hits = [n for n in srv.got if n and pred(n)]
            if hits:
                return hits
            time.sleep(0.1)
        return []

    srv.wait_for = wait_for
    yield srv
    srv.shutdown()


def notified_cin(note: dict) -> dict | None:
    """The contentInstance carried by a oneM2M notification, if any."""
    sgn = (note or {}).get("m2m:sgn", {})
    rep = sgn.get("nev", {}).get("rep", {})
    return rep.get("m2m:cin")


def pytest_configure(config):
    # test_edge_agent.py marks its tests that need the lab CSEs and MEC services `lab` (deselect them offline with
    # -m "not lab"); registered here so pytest does not warn "Unknown pytest.mark.lab" and --strict-markers accepts it.
    config.addinivalue_line("markers", "lab: needs the lab CSEs and MEC services; run under the lab lock")
