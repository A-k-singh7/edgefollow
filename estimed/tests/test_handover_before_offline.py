"""What must hold BEFORE a handover starts, without a lab (written 2026-11-18 against TR-0077 v0.4.0, branch
SDS-2026-0081, clause 7.2.4.2: "An AE ... SHALL be in exactly one ... serving state", "concurrent authoritative
serving associations SHALL NOT exist", "On rollback, source association SHALL be restored").

Each test states one precondition and requires that a handover which does not meet it returns False and writes
NOTHING, on either edge. They were written before any change to handover.py; the result of that first run is in
the commit that adds them.

P1  the target is another edge than the source. (Ours: neither TR-0077 nor TR-0086 states it.)
P2  the source's reachability is put back to what it WAS, and the target's copy starts with the device's value.
    OURS, AND NOT WHAT THE TEXTS SAY: TR-0077 Table 7.2.4.2.3-1 and TR-0086 5.5.5 both say the source is restored
    "to TRUE", and both assume rr = true in steady state. TR-0086 5.3.3.1 lets a device register with rr = false
    ("true if the device accepts downlink notifications"), and our simulated phone does. For such a device the
    texts' rollback changes what the device registered. A question for the project channel, not a settled rule.
P3  the IN-CSE routes the AE-ID to exactly one edge, and that edge is the source. (Our check for the gap that
    TR-0077 7.2.2.5 names: nothing enforces a single registration.)
P4  one handover of an AE-ID at a time: a transaction with an identifier and a validity time is opened at the IN-CSE
    before the first write (TR-0077 7.2.4.4 names both; the TR gives no mechanism) and closed on every way out.
P5  (added 2026-11-21, after the handover.py change it tests; against HEAD's handover.py its five tests fail) the
    IN-CSE routes the AE-ID to the target before the source is released, and to the target alone after it (TR-0086
    5.5.4 Step 5.3); after the release nothing is rolled back.

    /home/edgefollow/edgefollow-lab/.venv/bin/python -m pytest estimed/tests/test_handover_before_offline.py -q
"""
from __future__ import annotations

import time
import urllib.error

import pytest

import handover
from test_handover_offline import FakeCse

SRC, DST, IN = handover.EDGE_A, handover.EDGE_B, handover.IN_CSE
AE = handover.AE_NAME
SRC_AE, DST_AE = f"{SRC[0]}/{SRC[1]}/{AE}", f"{DST[0]}/{DST[1]}/{AE}"
MUTATING = ("POST", "PUT", "DELETE")


class Before(FakeCse):
    """FakeCse plus the source AE's own rr and the bodies of every write."""

    def __init__(self, src_rr=True, **kw):
        super().__init__(**kw)
        self.src_rr = src_rr
        self.bodies: list[tuple[str, str, dict | None]] = []

    def __call__(self, method, url, origin, *, ty=None, body=None):
        self.bodies.append((method, url, body))
        st, reply = super().__call__(method, url, origin, ty=ty, body=body)
        if method == "GET" and url == SRC_AE and st == 200:
            reply["m2m:ae"]["rr"] = self.src_rr
        return st, reply

    def writes(self, prefix: str):
        return [(m, u, b) for m, u, b in self.bodies if m in MUTATING and u.startswith(prefix)]

    def rr_puts(self, url: str) -> list[bool]:
        return [b["m2m:ae"]["rr"] for m, u, b in self.bodies
                if m == "PUT" and u == url and b and "rr" in b.get("m2m:ae", {})]


@pytest.fixture
def before(monkeypatch):
    def install(**kw):
        f = Before(**kw)
        monkeypatch.setattr(handover, "_req", f)
        return f
    return install


# --- P1: the target is another edge -----------------------------------------------------------------------

def test_p1_a_handover_to_the_source_itself_is_refused_before_any_write(before):
    f = before()
    assert handover.handover(SRC, SRC, []) is False
    assert f.writes(SRC[0]) == [], "the source was written to, or released, by a handover onto itself"


def test_p1_the_same_cse_under_another_address_is_refused_before_any_write(before):
    """Two addresses, one CSE: the target states the source's own CSE-ID."""
    f = before(dst_csi="/id-mn-a")
    assert handover.handover(SRC, DST, []) is False
    assert f.writes(SRC[0]) == [] and f.writes(DST[0]) == []


# --- P2: reachability is the device's, not the handover's --------------------------------------------------

def test_p2_a_failed_handover_leaves_an_unreachable_device_unreachable(before):
    """A device that polls (rr = false, a <pollingChannel>) is the normal case for a phone. After a refused
    target the source must read as it did before: the last word on rr is false, not true."""
    f = before(src_rr=False, dst_create=403)
    assert handover.handover(SRC, DST, []) is False
    assert (f.rr_puts(SRC_AE) or [False])[-1] is False, f.rr_puts(SRC_AE)


def test_p2_control_a_failed_handover_makes_a_reachable_device_reachable_again(before):
    f = before(src_rr=True, dst_create=403)
    assert handover.handover(SRC, DST, []) is False
    assert f.rr_puts(SRC_AE)[-1] is True


def test_p2_the_target_copy_starts_with_the_devices_own_reachability(before):
    f = before(src_rr=False)
    assert handover.handover(SRC, DST, []) is True
    made = [b["m2m:ae"] for m, u, b in f.bodies if m == "POST" and u == f"{DST[0]}/{DST[1]}" and b and "m2m:ae" in b]
    assert len(made) == 1 and made[0]["rr"] is False, made


# --- P3: the IN-CSE routes the AE-ID to the source, and to nothing else -------------------------------------

def test_p3_control_the_in_routes_to_the_source_and_the_handover_runs(before):
    f = before(route=["id-mn-a"])
    assert handover.handover(SRC, DST, []) is True
    assert ("DELETE", SRC_AE) in f.calls


def test_p3_a_source_that_is_not_the_serving_edge_is_refused_and_the_serving_copy_is_kept(before):
    """The vehicle is served by B (the IN says so) and A holds a leftover registration. A handover A -> B would
    take B's AE for "our own stale copy" and delete it: the serving registration and its data."""
    f = before(route=["id-mn-b"], dst_ae=handover.AE_ORIGIN)
    assert handover.handover(SRC, DST, []) is False
    assert f.writes(DST[0]) == [], f.writes(DST[0])
    assert f.writes(SRC[0]) == [], f.writes(SRC[0])


@pytest.mark.parametrize("route", [["id-mn-a", "id-mn-b"], []], ids=["two-serving-edges", "no-route-at-the-IN"])
def test_p3_an_ae_the_in_does_not_route_to_exactly_one_edge_is_refused(before, route):
    f = before(route=route, dst_ae=handover.AE_ORIGIN if len(route) == 2 else None)
    assert handover.handover(SRC, DST, []) is False
    assert f.writes(DST[0]) == [] and f.writes(SRC[0]) == []


# --- P4: one handover of an AE-ID at a time -----------------------------------------------------------------

LOCK_URL = f"{IN[0]}/{IN[1]}/{handover.lock_name()}"


def _labels(until: float) -> list[str]:
    return ["txn:other", "from:/id-mn-a", "to:/id-mn-b", f"until:{until:.0f}"]


def test_p4_a_second_handover_of_the_same_ae_is_refused_and_writes_nothing(before):
    f = before(lock=_labels(time.time() + 60))
    assert handover.handover(SRC, DST, []) is False
    assert f.writes(SRC[0]) == [] and f.writes(DST[0]) == []
    assert ("DELETE", LOCK_URL) not in f.calls, "the other handover's transaction was closed by the one refused"


def test_p4_a_transaction_past_its_validity_time_does_not_block(before):
    f = before(lock=_labels(time.time() - 1))
    assert handover.handover(SRC, DST, []) is True
    assert f.lock is None, "the transaction of a finished handover is still open"


def test_p4_the_transaction_is_open_during_the_handover_and_names_both_ends(before):
    f = before()
    seen = []
    plain = handover.set_reachability
    handover_set = lambda *a, **kw: (seen.append(list(f.lock or [])), plain(*a, **kw))[1]  # noqa: E731
    import pytest as _p
    mp = _p.MonkeyPatch()
    mp.setattr(handover, "set_reachability", handover_set)
    try:
        assert handover.handover(SRC, DST, []) is True
    finally:
        mp.undo()
    held = seen[0]
    assert any(l.startswith("txn:") and len(l) > 8 for l in held) and "from:/id-mn-a" in held and "to:/id-mn-b" in held
    assert handover._until(held) > time.time(), held
    assert f.lock is None


def test_p4_a_failed_handover_closes_its_transaction(before):
    f = before(dst_create=403)
    assert handover.handover(SRC, DST, []) is False
    assert f.lock is None


def test_p4_a_handover_refused_before_its_first_write_opens_no_transaction(before):
    f = before(route=["id-mn-b"], dst_ae=handover.AE_ORIGIN)
    assert handover.handover(SRC, DST, []) is False
    assert not [c for c in f.calls if c == ("POST", f"{IN[0]}/{IN[1]}")]


def test_p4_an_unreadable_route_stops_the_handover(before):
    f = before(refuse={f"{IN[1]}?fu=1&ty=10002&lbl=aei:{handover.AE_ORIGIN}": 403})
    assert handover.handover(SRC, DST, []) is False
    assert f.writes(SRC[0]) == [] and f.writes(DST[0]) == []


def test_p4_a_route_that_changes_while_the_transaction_is_opened_stops_the_handover(before):
    """The route is read before the transaction is ours; another handover may have finished in between."""
    f = before(route_after_lock=["id-mn-b"])
    assert handover.handover(SRC, DST, []) is False
    assert f.writes(SRC[0]) == [] and f.writes(DST[0]) == []
    assert f.lock is None, "the transaction was left open"


# --- P5: the IN-CSE routes the AE-ID to the target before the source is released (added 2026-11-21) ----------------
# tinyIoT as MN-B, after a restart, answered the vehicle's AE CREATE 201 and announced nothing: a move A -> B returned
# True with the IN routing the vehicle to no edge, and the way back was refused by P3. TR-0086 5.5.4 Step 5.3 has the
# IN route the AE-ID to the target; the release of the source now waits for it (handover.ROUTE_TIMEOUT_S). The live
# twins are in test_tr0086_handover.py.

@pytest.fixture
def short_route_wait(monkeypatch):
    monkeypatch.setattr(handover, "ROUTE_TIMEOUT_S", 0.2, raising=False)   # raising=False: the control on HEAD runs


def test_p5_a_target_that_does_not_announce_the_ae_is_rolled_back_and_the_source_kept(before, short_route_wait, capsys):
    f = before(announce=False)
    out = []
    assert handover.handover(SRC, DST, [], outcome=out) is False
    assert out == [handover.NOT_MOVED]
    assert ("DELETE", SRC_AE) not in f.calls, "the source was released while the IN routed nothing to the target"
    assert ("DELETE", DST_AE) in f.calls, "the target's copy was left behind"
    assert f.route == ["id-mn-a"] and f.lock is None
    assert f.rr_puts(SRC_AE)[-1] is True
    assert "the target did not announce the AE to the IN-CSE" in capsys.readouterr().out


def test_p5_nothing_but_the_ae_is_written_to_a_target_that_does_not_announce_it(before, short_route_wait):
    """No access policy, container, sample or subscription goes to a target the IN does not route to."""
    f = before(announce=False, children={"": {handover.TY_CNT: [handover.CONTAINER]}})
    assert handover.handover(SRC, DST, []) is False
    assert [(m, u) for m, u, _ in f.writes(DST[0])] == [("POST", f"{DST[0]}/{DST[1]}"), ("DELETE", DST_AE)]


def test_p5_control_a_target_that_announces_within_the_bound_moves(before):
    """A CSE that announces a few reads late is waited for, not refused."""
    f = before(announce_after=3)
    assert handover.handover(SRC, DST, []) is True
    assert f.route == ["id-mn-b"] and ("DELETE", SRC_AE) in f.calls


@pytest.mark.parametrize("after", [["id-mn-a", "id-mn-b"], []], ids=["source-still-routed", "target-route-lost"])
def test_p5_a_route_other_than_the_target_alone_after_the_release_is_inconsistent_not_success(
        before, short_route_wait, capsys, after):
    """After the release the target holds the only copy: the move is not a success, and nothing is rolled back (a
    delete on the target would lose the vehicle; the source's reachability is not put back)."""
    f = before(route_after_release=after)
    out = []
    assert handover.handover(SRC, DST, [], outcome=out) is False
    assert out == [handover.INCONSISTENT]
    later = f.calls[f.calls.index(("DELETE", SRC_AE)):]
    assert ("DELETE", DST_AE) not in later, "the rollback deleted the target's copy, the only one"
    assert f.rr_puts(SRC_AE) == [False], f.rr_puts(SRC_AE)
    assert f.lock is None
    assert "INCONSISTENT" in capsys.readouterr().out


# --- P5, review round (2026-11-21): the release itself fails, what is not a success, and what stops a ranked list ----
# The rollback's lists used to be emptied only after the source's DELETE answered: a DELETE that timed out after the
# source had deleted the AE (ACME answers only after its de-announcement at the IN, and our read timeout is 10 s) went
# to the rollback, which deleted the target's copy too. Nothing is rolled back once that DELETE is sent.

OTHER = ("http://127.0.0.1:8203", "cse-mn-c")


def _release_then(exc, monkeypatch, apply=True):
    """The source's DELETE: carried out by the source (apply) and then answered with `exc` instead of a status."""
    real = handover.delete_ae

    def delete(edge, *a, **kw):
        if edge != SRC:
            return real(edge, *a, **kw)
        if apply:
            real(edge, *a, **kw)
        raise exc

    monkeypatch.setattr(handover, "delete_ae", delete)


class _Device:
    def __init__(self, on_hold=None):
        self.on_hold, self.resumed = on_hold, []

    def hold(self):
        if self.on_hold:
            self.on_hold()

    def resume(self, edge):
        self.resumed.append(edge)


def test_p5_a_source_delete_carried_out_but_unanswered_is_not_rolled_back_and_counts_once_the_source_is_gone(
        before, monkeypatch, capsys):
    """No answer to the DELETE: the target is never deleted; the source is read again, and gone with the IN routing
    to the target alone is a move."""
    f = before()
    _release_then(TimeoutError("timed out"), monkeypatch)
    out = []
    assert handover.handover(SRC, DST, [], outcome=out) is True
    assert out == [handover.MOVED]
    assert ("DELETE", DST_AE) not in f.calls, "the target's copy, the only one, was deleted"
    assert ("GET", SRC_AE) in f.calls[f.calls.index(("DELETE", SRC_AE)):], "the source was not read again"
    text = capsys.readouterr().out
    assert "no longer holds the AE" in text and "destination unreachable" not in text


def test_p5_a_source_delete_that_never_arrived_is_inconsistent_and_not_rolled_back(
        before, monkeypatch, short_route_wait, capsys):
    """The DELETE never reached the source: two copies, routed to both. Not a success, and still nothing is deleted on
    the target (a DELETE that never arrived cannot be told from one still in progress) and the source is not made
    reachable again (the device was resumed on the target)."""
    f = before()
    _release_then(ConnectionResetError("reset"), monkeypatch, apply=False)
    out = []
    assert handover.handover(SRC, DST, [], outcome=out) is False
    assert out == [handover.INCONSISTENT]
    assert ("DELETE", DST_AE) not in f.calls
    assert f.rr_puts(SRC_AE) == [False], f.rr_puts(SRC_AE)
    assert f.lock is None
    text = capsys.readouterr().out
    assert "INCONSISTENT" in text and "may still hold the AE" in text and "destination unreachable" not in text


def test_p5_a_transaction_the_in_cannot_close_does_not_undo_the_move(before, monkeypatch, capsys):
    """release_lock() fails after the source deleted the AE: the IN routes to the target alone and the source is gone,
    so the move stands; the target is never deleted and the transaction is said to expire at its et."""
    f = before()

    def unreachable(*a, **kw):
        raise urllib.error.URLError("[Errno 111] Connection refused")

    monkeypatch.setattr(handover, "release_lock", unreachable)
    out = []
    assert handover.handover(SRC, DST, [], outcome=out) is True
    assert out == [handover.MOVED] and ("DELETE", DST_AE) not in f.calls
    assert f.lock is not None
    text = capsys.readouterr().out
    assert "the handover transaction was not closed" in text and "destination unreachable" not in text


@pytest.mark.parametrize("where", ["source-delete", "release-lock"])
def test_p5_an_interrupt_during_the_release_never_deletes_the_target(before, monkeypatch, where):
    """timeout -s INT (or Ctrl-C) while the source's DELETE or the transaction's close is in flight, the source already
    gone: the interrupt is raised on, and nothing on the target is deleted."""
    f = before()
    if where == "source-delete":
        _release_then(KeyboardInterrupt(), monkeypatch)
    else:
        def interrupted(*a, **kw):
            raise KeyboardInterrupt

        monkeypatch.setattr(handover, "release_lock", interrupted)    # no transaction was open: take_lock never calls it
    with pytest.raises(KeyboardInterrupt):
        handover.handover(SRC, DST, [])
    assert ("DELETE", SRC_AE) in f.calls and ("DELETE", DST_AE) not in f.calls
    if where == "source-delete":
        assert f.lock is None, "the transaction was left open"


def test_p5_a_refused_source_delete_is_not_a_success_even_when_the_in_routes_to_the_target_alone(
        before, monkeypatch, capsys):
    """The IN already routes to the target alone, but the source answered its DELETE 500 and still holds the AE."""
    f = before()
    real = handover.delete_ae

    def refused(edge, *a, **kw):
        if edge != SRC:
            return real(edge, *a, **kw)
        f.route = ["id-mn-b"]                    # the source withdrew its announcement and kept the AE
        return 500, None

    monkeypatch.setattr(handover, "delete_ae", refused)
    out = []
    assert handover.handover(SRC, DST, [], outcome=out) is False
    assert out == [handover.INCONSISTENT] and ("DELETE", DST_AE) not in f.calls
    assert "may still hold the AE" in capsys.readouterr().out


def test_p5_a_route_to_both_and_to_another_edge_is_refused_before_the_release(
        before, monkeypatch, short_route_wait, capsys):
    """DUAL_ATTACH is the source and the target and no other edge: a third registration of the AE-ID that appears
    with the target's stops the move before the release."""
    f = before()
    real = handover.create_ae

    def with_stray(edge, *a, **kw):
        answer = real(edge, *a, **kw)
        if edge == DST:
            f.route.append("id-mn-z")
        return answer

    monkeypatch.setattr(handover, "create_ae", with_stray)
    assert handover.handover(SRC, DST, []) is False
    assert ("DELETE", SRC_AE) not in f.calls and ("DELETE", DST_AE) in f.calls
    assert "not to the source and the target alone" in capsys.readouterr().out


def test_p5_the_route_is_read_again_at_the_release_not_only_after_the_targets_create(before, short_route_wait):
    """The target's announcement disappears while the device is held for the last copy: the move stops before the
    release and the device resumes on the source (offline twin of the live test)."""
    f = before()
    dev = _Device(on_hold=lambda: f.route.remove("id-mn-b"))
    assert handover.handover(SRC, DST, [], device=dev) is False
    assert dev.resumed == [SRC]
    assert ("DELETE", SRC_AE) not in f.calls and ("DELETE", DST_AE) in f.calls


def test_p5_any_other_exception_before_the_release_is_rolled_back_and_raised_on(before):
    """A target that answers an access policy CREATE 201 without m2m:acp (KeyError) once left the transaction open, the
    source unreachable and a partial copy on the target."""
    f = before(children={"": {handover.TY_ACP: ["policy"]}})
    with pytest.raises(KeyError):
        handover.handover(SRC, DST, [])
    assert ("DELETE", DST_AE) in f.calls and ("DELETE", SRC_AE) not in f.calls
    assert f.rr_puts(SRC_AE)[-1] is True and f.lock is None


def _ranked(monkeypatch, first_outcome):
    tried = []

    def one(src, dst, samples, outcome=None, **kw):
        tried.append(dst)
        outcome.append(first_outcome if dst == DST else handover.NOT_MOVED)
        return False

    monkeypatch.setattr(handover, "handover", one)
    cands = [{"edge": DST, "trust": 1.0, "latency_ms": 1, "load": 0.0},
             {"edge": OTHER, "trust": 0.5, "latency_ms": 1, "load": 0.0}]
    return handover.handover_ranked(SRC, cands, []), tried


def test_p5_handover_ranked_stops_after_an_inconsistent_outcome(monkeypatch):
    (edge, attempts), tried = _ranked(monkeypatch, handover.INCONSISTENT)
    assert edge is None and tried == [DST] and attempts == [(DST, False)]


def test_p5_control_handover_ranked_tries_the_next_candidate_after_a_rollback(monkeypatch):
    (edge, attempts), tried = _ranked(monkeypatch, handover.NOT_MOVED)
    assert edge is None and tried == [DST, OTHER]
