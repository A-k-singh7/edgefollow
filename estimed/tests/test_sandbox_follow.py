# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""sandbox_follow.py: the oneM2M handover driven by a MEC 013 zone change (ETSI's hosted sandbox in a real run).

Offline: the sandbox URL allow-list; the decision logic (arm only in zone A, an unmapped zone starts nothing, too few
polls in A start nothing, one move at the first poll in zone B, no move without a zone change); the MEC 013 reader in
both response shapes; the URL (a capability) never in an error or in the record.
Live (the lab, under its lock): a loopback stand-in for the sandbox's MEC 013 moves the UE from zone A to zone B; the
script moves the simulated vehicle A -> B on the real lab and leaves the lab clean.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ESTIMED = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ESTIMED))

import sandbox_follow as sf                                  # noqa: E402

SECRET = "sbxSECRET123"


# --- the allow-list -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("url", [f"https://try-mec.etsi.org/{SECRET}/mep1/location/v3", "http://127.0.0.1:9/location/v3",
                                 "https://try-mec.etsi.org:443/x"])
def test_base_accepts_etsi_sandbox_or_loopback(url):
    assert sf.check_base(url) == url.rstrip("/")


@pytest.mark.parametrize("url", ["", "http://try-mec.etsi.org/x/location/v3", "https://try-mec.etsi.org.evil.example/x",
                                 "https://evil.example/try-mec.etsi.org/x", "https://user:pw@try-mec.etsi.org/x",
                                 "https://try-mec.etsi.org/x?redirect=1", "ftp://127.0.0.1/x",
                                 "http://192.0.2.1/location/v3", f"https://try-mec.etsi.org/{SECRET}/location/v3 ",
                                 f"https://try-mec.etsi.org/{SECRET} /location/v3", "https://try-mec.etsi.org/x\n",
                                 "https://try-mec.etsi.org/x\x7f", "https://try-mec.etsi.org:22/x",
                                 "https://try-mec.etsi.org:8443/x", "https://x.etsi.org/x", "https://notetsi.org/x",
                                 "https://evil-try-mec.etsi.org/x", "http://127.0.0.2/x", "http://127.1.2.3/x"])
def test_control_base_refuses_any_other_target(url):
    with pytest.raises(SystemExit):
        sf.check_base(url)


# --- the decision logic ---------------------------------------------------------------------------------------------

class Script:
    """A zone sequence served one poll at a time, a fake clock that advances by the period, and a move recorder."""

    def __init__(self, zones, move_ok=True):
        self.zones, self.i, self.now, self.moves, self.move_ok = list(zones), 0, 0.0, 0, move_ok

    def fetch(self):
        z = self.zones[min(self.i, len(self.zones) - 1)]
        self.i += 1
        if z == "ERR":
            raise OSError("MEC 013 answered 503")
        return None if z is None else {"zone": z, "poa": f"poa-{z}"}

    def move(self):
        self.moves += 1
        return {"ok": self.move_ok}

    def run(self, **kw):
        args = dict(zone_a="zA", zone_b="zB", period=2.0, wait_start_s=30.0, max_s=60.0, hold_polls=3,
                    clock=lambda: self.now, sleep=self.tick)
        args.update(kw)
        return sf.follow(self.fetch, self.move, **args)

    def tick(self, s):
        self.now += s


def test_one_move_at_the_first_poll_in_zone_b():
    s = Script(["zA", "zA", "zA", "zA", "zB", "zB"])
    r = s.run()
    assert r["result"] == "COMPLETED" and s.moves == 1
    assert r["zone_change"] == {"last_in_a_t": 6.0, "first_in_b_t": 8.0, "poa_b": "poa-zB"}


def test_control_a_ue_that_starts_in_zone_b_arms_only_after_it_was_in_zone_a():
    s = Script(["zB", "zB", "zA", "zA", "zA", "zB"])
    r = s.run()
    assert r["result"] == "COMPLETED" and s.moves == 1 and r["zone_change"]["first_in_b_t"] == 10.0


def test_control_an_unmapped_zone_or_a_missing_report_starts_nothing():
    s = Script(["zA", "zA", "zA", "zC", None, "zA", "zB"])
    r = s.run()
    assert r["result"] == "COMPLETED" and s.moves == 1
    assert [x["zone"] for x in r["ignored"]] == ["zC", None]


def test_control_too_few_polls_in_zone_a_start_nothing():
    s = Script(["zA", "zA", "zB"])
    r = s.run(hold_polls=3)
    assert r["result"] == "ABORTED" and s.moves == 0
    assert not any(x["step"].startswith("the UE entered zone B") for x in r["steps"])      # the record says no move


def test_a_failed_poll_after_arming_is_a_missing_report_not_the_end():
    s = Script(["zA", "zA", "ERR", "zA", "zA", "zB"])
    r = s.run()
    assert r["result"] == "COMPLETED" and s.moves == 1 and r["failed_polls"] == 1
    assert len(r["polls"]) == 6                                                        # every poll is kept


def test_control_too_many_failed_polls_in_a_row_end_the_run_with_its_record():
    s = Script(["zA"] + ["ERR"] * (sf.MAX_FAILED_POLLS + 1))
    r = s.run()
    assert r["result"] == "ABORTED" and s.moves == 0 and r["failed_polls"] == sf.MAX_FAILED_POLLS + 1
    assert len(r["polls"]) >= 1 and r["steps"][-1]["ok"] is False


def test_exactly_the_limit_of_failed_polls_in_a_row_is_still_tolerated():
    s = Script(["zA", "zA", "zA"] + ["ERR"] * sf.MAX_FAILED_POLLS + ["zA", "zB"])
    r = s.run(max_s=200.0)
    assert r["result"] == "COMPLETED" and s.moves == 1


def test_the_failed_poll_count_is_in_a_row_not_in_total():
    s = Script(["zA", "zA", "zA"] + ["ERR", "zA"] * (sf.MAX_FAILED_POLLS + 2) + ["zB"])
    r = s.run(max_s=500.0)
    assert r["result"] == "COMPLETED" and r["failed_polls"] == sf.MAX_FAILED_POLLS + 2


def test_control_no_zone_change_no_move():
    s = Script(["zA"] * 100)
    r = s.run(max_s=20.0)
    assert r["result"] == "NO_ZONE_CHANGE" and s.moves == 0


def test_control_never_in_zone_a_never_armed():
    s = Script(["zB"] * 100)
    r = s.run(wait_start_s=10.0)
    assert r["result"] == "ABORTED" and s.moves == 0


def test_control_a_ue_not_reported_aborts_before_anything():
    s = Script([None, "zA"])
    assert s.run()["result"] == "ABORTED" and s.moves == 0


def test_a_failed_move_is_failed_not_completed():
    s = Script(["zA", "zA", "zA", "zB"], move_ok=False)
    assert s.run()["result"] == "FAILED" and s.moves == 1


# --- the MEC 013 reader against a local server ----------------------------------------------------------------------

class Fake013:
    """A loopback MEC 013 users query. `zone_at(t)` gives the zone t seconds after start; shape 'sandbox' wraps the
    list in userList like ETSI's sandbox."""

    def __init__(self, zone_at, shape="sandbox", ue="10.100.0.1", status=200):
        self.zone_at, self.shape, self.ue, self.status, self.t0 = zone_at, shape, ue, status, time.monotonic()
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.end_headers()
                    return
                zone = outer.zone_at(time.monotonic() - outer.t0)
                users = [{"address": outer.ue, "zoneId": zone, "accessPointId": f"poa-{zone}"}]
                body = {"userList": {"user": users}} if outer.shape == "sandbox" else {"user": users}
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *a):
                pass
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}/{SECRET}/location/v3"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.mark.parametrize("shape", ["sandbox", "flat"])
def test_reader_takes_zone_and_poa_in_both_shapes(shape):
    f = Fake013(lambda t: "zone01", shape=shape)
    try:
        assert sf.http_fetch(f.base, "10.100.0.1") == {"zone": "zone01", "poa": "poa-zone01"}
    finally:
        f.close()


def test_control_reader_ignores_another_ue():
    f = Fake013(lambda t: "zone01", ue="10.100.0.9")
    try:
        assert sf.http_fetch(f.base, "10.100.0.1") is None
    finally:
        f.close()


def test_reader_errors_never_carry_the_url():
    f = Fake013(lambda t: "zone01", status=500)
    try:
        with pytest.raises(OSError) as e:
            sf.http_fetch(f.base, "10.100.0.1")
        assert SECRET not in str(e.value) and "127.0.0.1" not in str(e.value)
    finally:
        f.close()


class Raw:
    """A loopback server that answers every request with fixed raw bytes, and records each request line."""

    def __init__(self, raw: bytes):
        import socket
        self.raw, self.seen = raw, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            with c:
                self.seen.append(c.recv(4096).split(b"\r\n", 1)[0])
                c.sendall(self.raw)

    def close(self):
        self.sock.close()


@pytest.mark.parametrize("raw", [b"HTTP/1.1 garbage\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n{}",
                                 b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xff\xfe"])
def test_an_unusable_answer_is_an_oserror_without_the_url(raw):
    r = Raw(raw)
    try:
        with pytest.raises(OSError) as e:
            sf.http_fetch(f"http://127.0.0.1:{r.port}/{SECRET}/location/v3", "10.100.0.1", timeout=3)
        assert SECRET not in str(e.value)
    finally:
        r.close()


def test_a_redirect_is_never_followed():
    target = Raw(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    hop = Raw(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:%d/x\r\nContent-Length: 0\r\n\r\n" % target.port)
    try:
        with pytest.raises(OSError, match="answered 302"):
            sf.http_fetch(f"http://127.0.0.1:{hop.port}/{SECRET}/location/v3", "10.100.0.1", timeout=3)
        assert target.seen == []
    finally:
        hop.close()
        target.close()


def test_a_proxy_from_the_environment_is_never_used():
    """In a fresh process whose environment names a proxy before the module is imported."""
    proxy = Raw(b"HTTP/1.1 502 Bad\r\nContent-Length: 0\r\n\r\n")
    f = Fake013(lambda t: "zone01")
    code = (f"import sys; sys.path.insert(0, {str(ESTIMED)!r}); import sandbox_follow as sf; "
            f"print(sf.http_fetch({f.base!r}, '10.100.0.1'))")
    try:
        p = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True, timeout=30,
                           env={"http_proxy": f"http://127.0.0.1:{proxy.port}", "HTTP_PROXY": f"http://127.0.0.1:{proxy.port}",
                                "no_proxy": "", "NO_PROXY": ""})
        assert "zone01" in p.stdout, (p.stdout, p.stderr)
        assert proxy.seen == []
    finally:
        f.close()
        proxy.close()


def test_a_404_means_the_ue_is_not_reported():
    f = Fake013(lambda t: "zone01", status=404)
    try:
        assert sf.http_fetch(f.base, "10.100.0.1") is None
    finally:
        f.close()


def test_an_unreachable_base_is_an_oserror_without_the_url():
    port = Raw(b"").port                                     # bound, then closed below: nothing listens
    with pytest.raises(OSError) as e:
        sf.http_fetch(f"http://127.0.0.1:9/{SECRET}/location/v3", "10.100.0.1", timeout=3)
    assert SECRET not in str(e.value) and "127.0.0.1" not in str(e.value) and port


def test_the_record_holds_no_url_when_the_first_poll_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_MEC013", f"http://127.0.0.1:9/{SECRET}/location/v3")
    monkeypatch.setenv("EDGEFOLLOW_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(sf, "lab_prepare", lambda: {"ok": True})
    monkeypatch.setattr(sf, "lab_reset", lambda: None)
    out = tmp_path / "rec.json"
    assert sf.main(["--ue", "10.100.0.1", "--zone-a", "a", "--zone-b", "b", "--results", str(out)]) == 1
    rec = json.loads(out.read_text())
    assert rec["result"] == "ABORTED" and "error" in rec and SECRET not in out.read_text()


def test_a_zone_longer_than_the_limit_is_no_report_not_a_truncated_one():
    f = Fake013(lambda t: "z" * (sf.MAX_ZONE + 1))
    try:
        assert sf.http_fetch(f.base, "10.100.0.1") is None
    finally:
        f.close()
    f = Fake013(lambda t: "z" * sf.MAX_ZONE)                  # the limit itself is a valid zone
    try:
        got = sf.http_fetch(f.base, "10.100.0.1")
        assert got["zone"] == "z" * sf.MAX_ZONE                   # the poa is only recorded, cut to the same limit
        assert got["poa"] == ("poa-" + "z" * sf.MAX_ZONE)[:sf.MAX_ZONE]
    finally:
        f.close()


def test_an_answer_over_the_size_cap_is_refused():
    big = b"[" + b"0," * (sf.MAX_BODY // 2) + b"0]"
    r = Raw(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(big) + big)
    try:
        with pytest.raises(OSError, match="too large"):
            sf.http_fetch(f"http://127.0.0.1:{r.port}/{SECRET}/location/v3", "10.100.0.1", timeout=5)
    finally:
        r.close()


def test_one_total_deadline_covers_a_slow_answer():
    import socket as _s
    srv = _s.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def drip():
        c, _ = srv.accept()
        with c:
            c.recv(4096)
            for b in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Slow: " + b"y" * 40 + b"\r\n\r\n{}":
                try:
                    c.sendall(bytes([b]))
                except OSError:
                    return
                time.sleep(0.2)
    threading.Thread(target=drip, daemon=True).start()
    t0 = time.monotonic()
    try:
        with pytest.raises(OSError, match="too slow"):
            sf.http_fetch(f"http://127.0.0.1:{srv.getsockname()[1]}/{SECRET}/location/v3", "10.100.0.1", timeout=1.0)
        assert time.monotonic() - t0 < 2.5
    finally:
        srv.close()


@pytest.mark.parametrize("url", [f"https://try-mec.etsi.org:{SECRET}/mep1/location/v3", f"https://[{SECRET}]/location/v3"])
def test_a_malformed_url_is_refused_without_echoing_it(capsys, url):
    with pytest.raises(SystemExit) as e:
        sf.check_base(url)
    assert SECRET not in str(e.value) and SECRET not in capsys.readouterr().err


def test_the_poll_deadline_is_an_oserror_even_when_it_fires_late():
    assert issubclass(sf._Deadline, OSError)


def test_the_lab_is_reset_even_when_the_record_cannot_be_written(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv("SANDBOX_MEC013", "http://127.0.0.1:9/x")
    monkeypatch.setenv("EDGEFOLLOW_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(sf, "lab_prepare", lambda: calls.append("prepare") or {"ok": False})
    monkeypatch.setattr(sf, "lab_reset", lambda: calls.append("reset"))
    with pytest.raises(SystemExit):                       # an unwritable directory is refused before the lab
        sf.main(["--ue", "u", "--zone-a", "a", "--zone-b", "b", "--results", str(tmp_path / "no" / "r.json")])
    assert calls == []
    monkeypatch.setattr(sf.Path, "write_text", lambda self, *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        sf.main(["--ue", "u", "--zone-a", "a", "--zone-b", "b", "--results", str(tmp_path / "r.json")])
    assert calls == ["prepare", "reset"]


def test_the_run_holds_the_lab_lock_in_its_run_dir_for_its_whole_duration(tmp_path, monkeypatch):
    import fcntl
    seen = []
    lockfile = tmp_path / ".live.lock"

    def lab_prepare():
        with open(lockfile, "a") as other:               # while the lab is touched, nobody else can take the lock
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen.append("free")
                fcntl.flock(other, fcntl.LOCK_UN)
            except OSError:
                seen.append("held")
        return {"ok": False}
    monkeypatch.setenv("SANDBOX_MEC013", "http://127.0.0.1:9/x")
    monkeypatch.setenv("EDGEFOLLOW_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(sf, "lab_prepare", lab_prepare)
    monkeypatch.setattr(sf, "lab_reset", lambda: seen.append("reset"))
    sf.main(["--ue", "u", "--zone-a", "a", "--zone-b", "b", "--results", str(tmp_path / "r.json")])
    assert seen == ["held", "reset"] and lockfile.exists()


def test_lab_lock_held_is_checked_and_a_busy_lock_is_announced(tmp_path, monkeypatch, capsys):
    import fcntl
    monkeypatch.setenv("SANDBOX_MEC013", "http://127.0.0.1:9/x")
    monkeypatch.setenv("EDGEFOLLOW_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(sf, "lab_prepare", lambda: {"ok": False})
    monkeypatch.setattr(sf, "lab_reset", lambda: None)
    args = ["--ue", "u", "--zone-a", "a", "--zone-b", "b", "--results", str(tmp_path / "r.json")]
    with pytest.raises(SystemExit):                       # "held", but nobody holds it
        sf.main(args + ["--lab-lock", "held"])
    with open(tmp_path / ".live.lock", "a") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX)
        assert sf.main(args + ["--lab-lock", "held"]) == 1          # held by someone: goes ahead
        calls = []
        real = sf.fcntl.flock
        monkeypatch.setattr(sf.fcntl, "flock", lambda f, op: calls.append(op) if op == fcntl.LOCK_EX else real(f, op))
        sf.main(args)                                                # busy: says so, then waits (stubbed)
        assert calls == [fcntl.LOCK_EX] and "waiting for the lab lock" in capsys.readouterr().err


def test_a_missing_run_dir_is_refused_before_the_lab(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setenv("SANDBOX_MEC013", "http://127.0.0.1:9/x")
    monkeypatch.setenv("EDGEFOLLOW_RUN_DIR", str(tmp_path / "nope"))
    monkeypatch.setattr(sf, "lab_prepare", lambda: calls.append("prepare") or {"ok": False})
    with pytest.raises(SystemExit):
        sf.main(["--ue", "u", "--zone-a", "a", "--zone-b", "b", "--results", str(tmp_path / "r.json")])
    assert calls == []


def test_record_never_holds_the_sandbox_url(tmp_path, monkeypatch, capsys):
    f = Fake013(lambda t: "zA" if t < 1.0 else "zB")
    monkeypatch.setenv("SANDBOX_MEC013", f.base)
    monkeypatch.setenv("EDGEFOLLOW_RUN_DIR", str(tmp_path))
    monkeypatch.setattr(sf, "lab_prepare", lambda: {"ok": True})
    monkeypatch.setattr(sf, "lab_move", lambda: {"ok": True})
    monkeypatch.setattr(sf, "lab_reset", lambda: None)
    out = tmp_path / "rec.json"
    try:
        rc = sf.main(["--ue", "10.100.0.1", "--zone-a", "zA", "--zone-b", "zB", "--period", "0.2",
                      "--hold-polls", "2", "--max-s", "10", "--results", str(out)])
    finally:
        f.close()
    text = out.read_text()
    assert rc == 0 and json.loads(text)["result"] == "COMPLETED"
    assert SECRET not in text and SECRET not in capsys.readouterr().out and json.loads(text)["mec013"] == "<sandbox>"


# --- live: the lab, under its lock ----------------------------------------------------------------------------------

def _require_lab_lock():
    """The live test runs only while someone holds the lab lock (run the module under
    `flock -o /home/edgefollow/estimed-run/.live.lock ...`): if this process can take it, nobody holds it -> refuse."""
    import fcntl
    with open(Path.home() / "estimed-run" / ".live.lock", "a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return
        fcntl.flock(f, fcntl.LOCK_UN)
    pytest.fail("the live test needs the lab lock: run this module under flock -o .../.live.lock", pytrace=False)


def test_live_zone_change_moves_the_vehicle_and_leaves_the_lab_clean(topology, tmp_path):
    _require_lab_lock()     # topology only reads the lab; nothing is written before this check
    import handover as ho
    f = Fake013(lambda t: "zone01" if t < 4.0 else "zone02")
    out = tmp_path / "rec.json"
    try:
        p = subprocess.run([sys.executable, "-I", "-B", str(ESTIMED / "sandbox_follow.py"), "--ue", "10.100.0.1",
                            "--zone-a", "zone01", "--zone-b", "zone02", "--period", "0.5", "--hold-polls", "3",
                            "--max-s", "60", "--results", str(out), "--lab-lock", "held"],
                           env={"SANDBOX_MEC013": f.base}, capture_output=True, text=True, timeout=180)
    finally:
        f.close()
    rec = json.loads(out.read_text())
    assert p.returncode == 0 and rec["result"] == "COMPLETED", (p.stdout, p.stderr, rec)
    assert rec["move"]["moved"] is True and rec["move"]["samples_on_b"] == len(sf.SAMPLES)
    assert rec["move"]["route"] == ["/id-mn-b"] and rec["move"]["edge_a_status"] == 404
    assert SECRET not in out.read_text() + p.stdout + p.stderr
    for edge in (ho.EDGE_A, ho.EDGE_B):                       # left clean
        assert ho._req("GET", f"{edge[0]}/{edge[1]}/{ho.AE_NAME}", ho.ORCHESTRATOR)[0] == 404
