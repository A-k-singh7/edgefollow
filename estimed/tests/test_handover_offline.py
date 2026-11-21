"""handover.py without a lab: a fake _req serves a small source tree (a review of 2026-10-29; T01 and V01/W03 are its items).

T01  every read the handover depends on fails CLOSED. A child the orchestrator can list but not read, an AE or
     policy list it cannot read, or a discovery that is refused, stops the handover -- it used to shrink the copy
     silently, return True and then delete the source, the only complete copy.
V01  a target AE name held by ANOTHER originator is refused before anything is written there (a 409 used to count
     as success, and the subtree went under the squatter's AE); the rollback deletes on the target only what this
     handover created.

    /home/edgefollow/edgefollow-lab/.venv/bin/python -m pytest estimed/tests/test_handover_offline.py -q
"""
from __future__ import annotations

import pytest

import handover

SRC, DST = handover.EDGE_A, handover.EDGE_B
AE = handover.AE_NAME


class FakeCse:
    """Answers handover._req for SRC (a vehicle with the given children) and DST (empty unless told otherwise).

    children: {parent path under the AE ("" = the AE): {ty: [child rn, ...]}}; refuse: {(method, url-without-host)
    or url-without-host: status} answered instead of the normal reply."""

    def __init__(self, children=None, refuse=None, dst_ae=None, dst_create=201, dst_cst=2, dst_registered=True,
                 route=("id-mn-a",), lock=None, dst_csi="/id-mn-b", route_after_lock=None, announce=True,
                 announce_after=0, route_after_release=None):
        self.dst_cst, self.dst_registered = dst_cst, dst_registered
        self.route = list(route)             # the CSE-IDs the IN links the AE-ID to (one announced AE each)
        self.lock = lock                     # None: no handover transaction is open at the IN; else its labels
        self.dst_csi = dst_csi               # the CSE-ID the target states for itself
        self.route_after_lock = route_after_lock   # the route the IN gives once a transaction has been opened
        # Announcement, as the lab's CSEs do it: an AE the target creates is added to the route (after `announce_after`
        # more reads of it), and a deleted AE leaves it; unless announce is False (tinyIoT after a restart answered 201
        # and announced nothing, 2026-11-21). route_after_release: the route once the source AE is deleted.
        self.announce, self.announce_after, self.pending = announce, announce_after, None
        self.route_after_release = route_after_release
        self.src_gone = False                # the source AE was deleted: reading it answers 404
        self.children = children or {}
        self.refuse = refuse or {}
        self.dst_ae = dst_ae                 # None: no AE on the target; else its aei
        self.dst_create = dst_create
        self.calls: list[tuple[str, str]] = []

    def __call__(self, method, url, origin, *, ty=None, body=None):
        self.calls.append((method, url))
        host_rel = url.split("://", 1)[1].split("/", 1)[1]
        for key in ((method, host_rel), host_rel):
            if key in self.refuse:
                return self.refuse[key], None
        on_dst = url.startswith(DST[0])
        path, _, query = host_rel.partition("?")
        if url.startswith(handover.IN_CSE[0]):
            in_cb, lock = handover.IN_CSE[1], f"{handover.IN_CSE[1]}/{handover.lock_name()}"
            if method == "GET" and path == in_cb and "lbl=aei:" in query:
                if self.pending is not None:
                    if self.pending == 0:
                        self.route.append(self.dst_csi.strip("/"))
                        self.pending = None
                    else:
                        self.pending -= 1
                return 200, {"m2m:uril": [f"{in_cb}/annc{i}" for i in range(len(self.route))]}
            if method == "GET" and path.startswith(f"{in_cb}/annc"):
                return 200, {"m2m:aeA": {"lnk": f"/{self.route[int(path.rsplit('annc', 1)[1])]}/ri-ae"}}
            if method == "POST" and path == in_cb:
                if self.lock is not None:
                    return 409, None
                self.lock = body["m2m:cnt"]["lbl"]
                if self.route_after_lock is not None:
                    self.route = list(self.route_after_lock)
                return 201, {"m2m:cnt": {"rn": handover.lock_name(), "ri": "ri-lock"}}
            if path == lock and method == "GET":
                return (404, None) if self.lock is None else (200, {"m2m:cnt": {"rn": handover.lock_name(), "lbl": self.lock}})
            if path == lock and method == "DELETE":
                self.lock = None
                return 200, {}
        if method == "GET" and not on_dst and url.startswith(SRC[0]) and path == SRC[1]:
            return 200, {"m2m:cb": {"rn": SRC[1], "csi": "/id-mn-a", "cst": 2}}
        if method == "GET" and query:
            if on_dst:
                return 200, {"m2m:uril": []}
            rel = path[len(f"{SRC[1]}/{AE}"):].lstrip("/")
            want = None
            for part in query.split("&"):
                if part.startswith("ty="):
                    want = int(part[3:])
            kids = self.children.get(rel, {})
            names = [rn for ty_, rns in kids.items() if want in (None, ty_) for rn in rns]
            return 200, {"m2m:uril": [f"{path}/{rn}" for rn in names]}
        if method == "GET" and url.startswith(handover.IN_CSE[0]) and path == f"{handover.IN_CSE[1]}/{self.dst_csi.strip('/')}":
            return (200, {"m2m:csr": {"csi": self.dst_csi, "cst": 2}}) if self.dst_registered else (404, None)
        if method == "GET" and on_dst and path == DST[1]:
            return 200, {"m2m:cb": {"rn": DST[1], "csi": self.dst_csi, "cst": self.dst_cst}}
        if method == "GET":
            if path == f"{SRC[1]}/{AE}" and not on_dst:
                if self.src_gone:
                    return 404, None
                return 200, {"m2m:ae": {"rn": AE, "aei": handover.AE_ORIGIN, "api": "Nestimed.vehicle", "srv": ["4"],
                                        "poa": ["http://127.0.0.1:9/vehicle"]}}
            if path == f"{DST[1]}/{AE}" and on_dst:
                return (404, None) if self.dst_ae is None else (200, {"m2m:ae": {"rn": AE, "aei": self.dst_ae}})
            parent, _, leaf = path.rpartition("/")
            if parent.endswith(f"/{handover.CONTAINER}"):
                return 200, {"m2m:cin": {"rn": leaf, "ri": f"ri-{leaf}", "con": leaf, "ct": "20261029T000000,000000"}}
            return 200, {"m2m:cnt": {"rn": leaf, "ri": f"ri-{leaf}", "acpi": []}}
        if method == "POST" and on_dst and ty == handover.TY_AE:
            if self.dst_create == 201 and self.announce:
                self.pending = self.announce_after
            return self.dst_create, ({"m2m:ae": {"rn": AE, "aei": handover.AE_ORIGIN}} if self.dst_create == 201 else None)
        if method == "POST":
            return 201, {"m2m:cnt": {"rn": "x", "ri": "ri-x"}}
        if method == "DELETE" and path == f"{DST[1]}/{AE}" and on_dst:
            self.pending = None
            self.route = [c for c in self.route if c != self.dst_csi.strip("/")]
        if method == "DELETE" and path == f"{SRC[1]}/{AE}" and not on_dst:
            self.route = (list(self.route_after_release) if self.route_after_release is not None
                          else [c for c in self.route if c != "id-mn-a"])
            self.src_gone = True
        return 200, {}

    def writes_to_dst(self):
        return [(m, u) for m, u in self.calls if m in ("POST", "PUT", "DELETE") and u.startswith(DST[0])]


@pytest.fixture
def fake(monkeypatch):
    def install(**kw):
        f = FakeCse(**kw)
        monkeypatch.setattr(handover, "_req", f)
        return f
    return install


# --- T01: reads fail closed ------------------------------------------------------------

def test_t01_listed_but_unreadable_child_is_an_error(fake):
    fake(children={"": {handover.TY_CNT: ["telemetry", "commands"]}}, refuse={f"{SRC[1]}/{AE}/commands": 403})
    with pytest.raises(handover.Unreadable, match="commands"):
        handover._children(SRC, AE, handover.TY_CNT, handover.ORCHESTRATOR)


def test_t01_refused_discovery_is_an_error_not_no_children(fake):
    fake(refuse={("GET", f"{SRC[1]}/{AE}?fu=1&ty={handover.TY_CNT}&lvl=1"): 403})
    with pytest.raises(handover.Unreadable):
        handover._children(SRC, AE, handover.TY_CNT, handover.ORCHESTRATOR)


@pytest.mark.parametrize("reader", [lambda: handover.read_ae(SRC), lambda: handover.read_acpi(SRC, AE)],
                         ids=["read_ae", "read_acpi"])
def test_t01_unreadable_ae_is_an_error_not_empty_attributes(fake, reader):
    fake(refuse={("GET", f"{SRC[1]}/{AE}"): 403})
    with pytest.raises(handover.Unreadable):
        reader()


def test_t01_unreadable_content_instance_is_an_error(fake):
    fake(children={handover.CONTAINER: {handover.TY_CIN: ["c1", "c2"]}},
         refuse={f"{SRC[1]}/{AE}/{handover.CONTAINER}/c2": 403})
    with pytest.raises(handover.Unreadable):
        handover._cins(SRC, handover.CONTAINER)


def test_t01_control_readable_children_are_all_returned(fake):
    fake(children={"": {handover.TY_CNT: ["telemetry", "commands"]}})
    assert sorted(c["rn"] for c in handover._children(SRC, AE, handover.TY_CNT, handover.ORCHESTRATOR)) == \
        ["commands", "telemetry"]


def test_t01_handover_stops_before_touching_anything(fake):
    f = fake(children={"": {handover.TY_CNT: ["telemetry", "commands"]}}, refuse={f"{SRC[1]}/{AE}/commands": 403})
    assert handover.handover(SRC, DST, []) is False
    assert f.writes_to_dst() == [], "nothing may be written on the target"
    assert ("DELETE", f"{SRC[0]}/{SRC[1]}/{AE}") not in f.calls, "the source must never be released"


# --- V01/W03: the target AE name is ours or absent -------------------------------------

def test_v01_name_held_by_another_originator_is_refused_before_any_write(fake):
    f = fake(dst_ae="Cimpostor")
    assert handover.handover(SRC, DST, []) is False
    assert f.writes_to_dst() == [], f.writes_to_dst()
    assert ("DELETE", f"{SRC[0]}/{SRC[1]}/{AE}") not in f.calls


@pytest.mark.parametrize("status", [409, 403], ids=["409-name-taken", "403-already-registered"])
def test_v01_a_refused_create_is_not_success_and_nothing_of_theirs_is_deleted(fake, status):
    f = fake(dst_create=status)
    assert handover.handover(SRC, DST, []) is False
    dst_ae = f"{DST[0]}/{DST[1]}/{AE}"
    after = f.calls[f.calls.index(("POST", f"{DST[0]}/{DST[1]}")):]
    assert ("DELETE", dst_ae) not in after, "the rollback deleted an AE this handover did not create"
    assert not [c for c in after if c[0] in ("POST", "PUT") and c[1].startswith(dst_ae)]


def test_v01_control_absent_target_name_moves(fake):
    f = fake()
    assert handover.handover(SRC, DST, []) is True
    assert ("DELETE", f"{SRC[0]}/{SRC[1]}/{AE}") in f.calls


def test_v01_control_our_own_stale_copy_is_replaced(fake):
    f = fake(dst_ae=handover.AE_ORIGIN)
    assert handover.handover(SRC, DST, []) is True
    assert ("DELETE", f"{DST[0]}/{DST[1]}/{AE}") in f.calls


# --- R1/R2: the lab is what it claims, and a target is a registered MN (lab fixes of 2026-10-29) ---------

@pytest.mark.parametrize("uril,ok", [
    (["cse-in/id-mn-a", "cse-in/id-mn-b"], True),
    (["cse-in/id-mn-b", "cse-in/id-mn-a"], True),
    (["cse-in/id-mn-a"], False),
    (["cse-in/id-mn-a", "cse-in/id-mn-ab"], False),            # two entries, one a lookalike: len()==2 passed this
    (["cse-in/id-mn-a", "cse-in/id-mn-b", "cse-in/id-mn-zz"], False),
], ids=["both", "both-any-order", "one-missing", "lookalike", "one-extra"])
def test_r1_the_in_holds_exactly_the_two_edges(uril, ok):
    assert handover.edges_ok(uril) is ok


@pytest.mark.parametrize("kw", [{"dst_cst": 1}, {"dst_cst": 3}, {"dst_registered": False}],
                         ids=["target-is-an-IN", "target-is-an-ASN", "target-not-held-by-the-IN"])
def test_r2_a_target_that_is_not_a_registered_mn_is_refused_before_any_write(fake, kw):
    f = fake(**kw)
    assert handover.handover(SRC, DST, []) is False
    assert f.writes_to_dst() == [], f.writes_to_dst()
    assert ("DELETE", f"{SRC[0]}/{SRC[1]}/{AE}") not in f.calls


@pytest.mark.parametrize("kw", [{"dst_cst": 1}, {"dst_registered": False}], ids=["target-is-an-IN", "not-held-by-the-IN"])
def test_r2_the_readiness_gate_refuses_it_too(fake, kw):
    fake(**kw)
    assert handover.target_ready(DST) is False


def test_r2_control_a_registered_mn_is_ready(fake):
    fake()
    assert handover.target_ready(DST) is True
