#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""Offline checks for the federated-learning core (fl_core.py, plan row A3, phase P5) -- no CSE, no MEC, no network.

Every expected value below is written by hand from the documents or worked out on paper in the comment beside it
(digests: `printf '%s' '<canonical json>' | sha256sum`; the epoch: `date -u -d`), never taken from fl_core.
One oracle is written a second way on purpose: the FedAvg cross-check uses fractions.Fraction, fl_core uses
integer floor division.

Sources: TR-0077 v0.4.0 clause 7.3 as reported by the fact reader in federation_result.json (facts F13, F15-F18,
F28-F32, F37-F44, with the TR line numbers given there), the ESTIMED test plan (TD_MEC_FL_01, TD_MEC_FL_02,
TD_MEC_FL_03, TD_MEC_OBS_01), the PoC plan's rules on quorum, deployment and package digests, phone/sim_phone.py lines 88-89 (the env record).

The TD_MEC_FL_03 rows at the end check fl_run.py's placement table, byte counter, round time, comparison table
and record, still offline: the byte counter is fed a fake socket (or one whose connection is refused), and main()
is called either with every network function replaced by one that stops it, or on a fake network that answers
every request 200 and with finish() replaced, so nothing reaches a CSE and no file is written.

Rows: a plain check prints PASS or FAIL. A CONTROL row states the planted fault as if it had gone through
("... was accepted"); it must print FAIL, as in the live drivers, and the script fails if one does not.

    python3 estimed_poc/test_fl.py
"""
from __future__ import annotations

import contextlib
import copy
import io
import socket
import sys
import time
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))


class _Missing:
    def __init__(self, mod, why):
        self._mod, self._why = mod, why

    def __getattr__(self, name):
        raise AttributeError(f"{self._mod} is not importable ({self._why}); wanted {name}")


try:
    import fl_core as fl  # noqa: E402
except ImportError as _e:     # red-first: every row then fails by itself instead of the script dying on import
    fl = _Missing("fl_core", str(_e))
try:
    import fl_run as fr  # noqa: E402  the driver: imported, never run against a CSE here
except Exception as _e:  # noqa: BLE001
    fr = _Missing("fl_run", f"{type(_e).__name__}: {_e}")
try:
    import mec_pinned as mp  # noqa: E402  TD_MEC_FL_01: the REG_03 platform path, loaded by pinned SHA-256
except Exception as _e:  # noqa: BLE001
    mp = _Missing("mec_pinned", f"{type(_e).__name__}: {_e}")
try:
    import fl_platform as fp  # noqa: E402  TD_MEC_FL_01: packages, relays, the simulated proxy-path device
except Exception as _e:  # noqa: BLE001
    fp = _Missing("fl_platform", f"{type(_e).__name__}: {_e}")

RESULTS: list[tuple[str, bool, str]] = []
CONTROLS: list[tuple[str, bool, str]] = []


def check(name, fn, detail=""):
    try:
        ok, d = bool(fn()), detail
    except Exception as e:  # noqa: BLE001  a missing function or a crash is a FAIL row, with its reason
        ok, d = False, f"{type(e).__name__}: {e}"
    RESULTS.append((name, ok, d))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {d}" if d else ""))


def control(name, bad):
    """`bad` states the planted fault as having gone through. It must be False."""
    try:
        went_through, d = bool(bad()), ""
    except Exception as e:  # noqa: BLE001  a crash proves nothing: the control then counts as NOT failed
        went_through, d = True, f"did not run: {type(e).__name__}: {e}"
    CONTROLS.append((name, went_through, d))
    print(f"  {'PASS' if went_through else 'FAIL'}  CONTROL (must FAIL) {name}" + (f"  -- {d}" if d else ""))


class _Broken:
    """Stands in for a fixture that could not be built: any use of it raises, so the rows that need it FAIL."""

    def __init__(self, why):
        object.__setattr__(self, "_why", why)

    def _boom(self, *a, **k):
        raise RuntimeError(f"fixture not built: {self._why}")
    __getitem__ = __getattr__ = __iter__ = __call__ = __len__ = __contains__ = _boom


def eager(fn, n=1):
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        b = _Broken(f"{type(e).__name__}: {e}")
        return b if n == 1 else (b,) * n


def raises(fn, *exc):
    try:
        fn()
    except exc:
        return True
    return False


# ------------------------------------------------------------------------------------------------ fixtures
D_W000 = "591cd2c3964fe9f9ad86b3ba2edfb6bdeb753353b03ab1d3d1aae430d62656ef"   # sha256sum of the model body, w [0,0,0]
D_W9 = "8abc705b9b3e0ad92fb45652e50151a128d54a5e68ef75afc4031047e49c397d"     # ... w [9,23,30]
A = {"t": 0, "x": [40, 64], "y": 30}        # 4.0 C above 25.0 C, 2 points drained (2 * 32), next value 3.0 C above
B = {"t": 5000, "x": [-20, 0], "y": -12}
TFC, NAT, DEC, ORCH, AGG = "CflTfc", "CflNat", "CflDec", "CflOrch", "CflAgg"
DEADLINE = 1_795_029_400_000
W_IN = [10, 20, 30]


def ready(**off):
    return {c: c not in off for c in ("applicationRunning", "frameworkInitialized", "modelAccessible",
                                      "credentialsAndCoordinatorConfigured", "authorizedLocalDataAccessible",
                                      "canAcceptTask")}


def cand(pid, client, **kw):
    c = {"participantId": pid, "clientAERef": client, "discovered": True,
         "capability": {"canTrain": True, "enabled": True}, "readiness": ready(), "decision": "accepted",
         "authorized": True}
    c.update(kw)
    return c


def policy(source="flSrc1", authority="CflAuthA", **kw):
    p = {"policyId": f"{source}-policy", "policyVersion": "1", "policyAuthorityRef": authority,
         "processingPurpose": "fl-training", "authorizedProcessorRefs": [TFC],
         "allowedExecutionDomains": ["edge-a"], "allowedSourceRefs": [source], "permittedOperations": ["train"],
         "permittedOutputClasses": ["model-update"], "rawDataExportAllowed": False,
         "temporaryRetentionDuration": "PT60S", "derivedDataRetentionRef": "model-lineage",
         "expiryTime": DEADLINE + 1_000_000, "revocationStatus": "active", "sim": True}
    p.update(kw)
    return {"record": p, "creator": authority}


def auth(policies, sources=("flSrc1", "flSrc2"), **kw):
    a = {"purpose": "fl-training", "operation": "train", "processor": TFC, "domain": "edge-a", "requester": ORCH,
         "now_ms": DEADLINE}
    a.update(kw)
    return fl.authorize(list(sources), policies, **a)


def world():
    """One round, three selected participants, hand-made: P-A and P-C behind the Trusted FL Client, P-B native."""
    model_d = fl.model_digest(W_IN)
    tasks, datasets = {}, {}
    for pid, client, ds, n, srcs in (("P-A", TFC, "ds-A", 3, ["flSrc1"]), ("P-B", NAT, "ds-B", 1, ["flNat"]),
                                     ("P-C", TFC, "ds-C", 2, ["flSrc2"])):
        t = fl.task_record("op-1", 2, pid, client, model_ref="cse-in/flOrch/model/v1", model_digest=model_d,
                           binding_version=f"{pid}-binding@1", deadline_ms=DEADLINE,
                           update_destination="cse-mn-a/flAgg/updates", status_target=f"status/{pid}")
        tasks[t["taskId"]] = t
        datasets[(ds, "2")] = {"digest": fl.digest([pid, "samples"]), "n": n, "state": "valid", "sources": srcs}
    rd = {"operationRef": "op-1", "round": 2, "modelDigest": model_d, "w": list(W_IN), "deadline_ms": DEADLINE,
          "selected": ["P-A", "P-B", "P-C"], "tasks": tasks}
    ctx = {"source_state": {"flSrc1": "active", "flSrc2": "active", "flNat": "active"}, "datasets": datasets,
           "seen": set()}
    return rd, ctx


def upd(rd, ctx, pid, delta, *, ds=None, created=DEADLINE - 1000, creator=None):
    task = next(t for t in rd["tasks"].values() if t["participantId"] == pid)
    ds = ds or {"P-A": "ds-A", "P-B": "ds-B", "P-C": "ds-C"}[pid]
    d = ctx["datasets"][(ds, "2")]
    u = fl.update_record(task, dataset_ref=ds, dataset_version="2", dataset_digest=d["digest"],
                         effective_sample_count=d["n"], delta=delta)
    return {"update": u, "creator": creator or task["selectedClient"], "created_ms": created}


def reasons(sub, rd, ctx):
    return fl.check_update(sub["update"], sub["creator"], sub["created_ms"], rd, ctx)


# ------------------------------------------------------------------------------------------------ TD_MEC_FL_03
LAB_IN, LAB_A, LAB_B = "http://127.0.0.1:8200/cse-in", "http://127.0.0.1:8201/cse-mn-a", "http://127.0.0.1:8202/cse-mn-b"
LAB_MEC = "http://127.0.0.1:8097"
CIN, CA, CB = "cse-in", "cse-mn-a", "cse-mn-b"
URLS = {CIN: LAB_IN, CA: LAB_A, CB: LAB_B}
MODES3 = ("centralised", "hierarchical", "edge-only")


class _FakeSock:
    """The far end of one TCP connection: keeps every byte it was sent (and the monotonic time the first one came),
    answers with the bytes it was given."""

    def __init__(self, reply: bytes):
        self.got, self.reply, self.when = bytearray(), reply, None

    def sendall(self, b):
        if self.when is None:
            self.when = time.monotonic_ns()
        self.got += bytes(b)

    def setsockopt(self, *a):
        pass

    def settimeout(self, *a):
        pass

    def makefile(self, mode="rb", *a, **k):
        return io.BufferedReader(io.BytesIO(self.reply))

    def close(self):
        pass


@contextlib.contextmanager
def fake_net(reply: bytes):
    """Every new TCP connection in this block goes to one _FakeSock; nothing leaves the process."""
    sock, real = _FakeSock(reply), socket.create_connection
    socket.create_connection = lambda *a, **k: sock
    try:
        yield sock
    finally:
        socket.create_connection = real


@contextlib.contextmanager
def refused_net():
    """Every new TCP connection in this block is refused, as at a closed port; nothing leaves the process."""
    real = socket.create_connection

    def refuse(*a, **k):
        raise ConnectionRefusedError(111, "Connection refused")
    socket.create_connection = refuse
    try:
        yield
    finally:
        socket.create_connection = real


class _Stop(BaseException):
    """Raised by the stand-in network functions: main() stops at its first attempt to send anything."""


def first_contact(argv):
    """main(argv) with rq and mec replaced: (exit code or 'sent', what was set up at the first send, stderr)."""
    seen, err = {}, io.StringIO()

    def stop(*a, **k):
        if not seen:
            seen.update(mode=fr.MODE, orch=fr.url("flOrch"), agg=fr.url("flAgg"), first=a[:2])
        raise _Stop()
    names = ("rq", "mec", "compare")          # compare too: no test may start the three live runs
    saved = {n: getattr(fr, n, None) for n in names}
    for n in names:
        setattr(fr, n, stop)
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = fr.main(argv)
    except SystemExit as e:
        code = e.code
    except _Stop:
        code = "sent"
    finally:
        for n in names:
            setattr(fr, n, saved[n])
        fr.set_mode("hierarchical")
    return code, seen, err.getvalue()


def leftover_run(mode):
    """main(--mode <mode>) on a fake network that answers every request 200, so every place an AE of an earlier run
    could be left looks taken: main removes the 'leftovers', finds them still there and stops (Abort); mec, compare
    and finish are replaced, so nothing is started and no file is written. Returns (the calls main logged, every
    byte it handed to the socket)."""
    names, saved = ("mec", "compare", "finish"), {}

    def stop(*a, **k):
        raise _Stop()
    for n in names:
        saved[n] = getattr(fr, n, None)
        setattr(fr, n, stop)
    before = len(fr.CALLS)
    try:
        with fake_net(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}") as s, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                fr.main(["--mode", mode])
            except _Stop:
                pass
    finally:
        for n in names:
            setattr(fr, n, saved[n])
        fr.set_mode("hierarchical")
    return fr.CALLS[before:], bytes(s.got)


def call(party, url, sent, received, rnd=0, method="GET", ty=None, status=200, t0=0, t1=0):
    return {"party": party, "url": url, "method": method, "ty": ty, "status": status, "sent": sent,
            "received": received, "round": rnd, "t0": t0, "t1": t1, "body": 0}


def fl03_rows() -> None:  # noqa: C901, PLR0915
    print("== TD_MEC_FL_03: where each party sits, by mode [TD_MEC_FL_03]")
    # by hand from the test plan: centralised = the aggregator at the cloud IN-CSE (line 654); hierarchical = a local
    # aggregator at the edge MN-CSE (line 656); edge-only = the orchestrator and the aggregator both at the edge
    # (line 658). The plan moves only the aggregator for the first two, so the orchestrator stays in the cloud.
    move = {"centralised": (CIN, CIN), "hierarchical": (CIN, CA), "edge-only": (CA, CA)}      # (flOrch, flAgg)
    # today's placement, copied by hand from fl_run.py at 39f611d: HOME = {"flOrch": IN, "flTfc2": B}, all else on A
    today = {"flOrch": CIN, "flAgg": CA, "flSrc1": CA, "flSrc2": CA, "flTfc": CA, "flNat": CA, "flDec": CA, "flTfc2": CB}
    stay = {k: v for k, v in today.items() if k not in ("flOrch", "flAgg")} | {"CflAuthA": CA, "CflAuthB": CA}
    check("the three mode names are the plan's, in its order", lambda: fr.MODES == ("centralised", "hierarchical", "edge-only"))
    for m, (o, g) in move.items():
        check(f"{m}: the orchestrator on {o}, the aggregator on {g}",
              lambda m=m, o=o, g=g: (fr.placement(m)["flOrch"], fr.placement(m)["flAgg"]) == (o, g))
        check(f"{m}: sources, clients, the two authorities and the moved client stay where they are",
              lambda m=m: {k: v for k, v in fr.placement(m).items() if k not in ("flOrch", "flAgg")} == stay)
    check("hierarchical is today's placement, AE for AE", lambda: {k: fr.placement("hierarchical")[k] for k in today} == today)
    check("a mode name outside the three is refused by the table", lambda: raises(lambda: fr.placement("central"), ValueError))

    def addresses(mode):
        fr.set_mode(mode)
        try:
            return {ae: fr.url(ae) for ae in today}
        finally:
            fr.set_mode("hierarchical")
    check("hierarchical gives today's addresses: flOrch on the IN-CSE, flTfc2 on MN-CSE-B, every other AE on MN-CSE-A",
          lambda: addresses("hierarchical") == {ae: f"{URLS[c]}/{ae}" for ae, c in today.items()})
    check("centralised: the aggregator's updates container is on the IN-CSE",
          lambda: addresses("centralised")["flAgg"] == f"{LAB_IN}/flAgg" and addresses("centralised")["flOrch"] == f"{LAB_IN}/flOrch")
    check("edge-only: the orchestrator's AE is on MN-CSE-A, the IN-CSE holds no AE of ours",
          lambda: addresses("edge-only")["flOrch"] == f"{LAB_A}/flOrch"
          and not [u for u in addresses("edge-only").values() if u.startswith(LAB_IN)])

    def targets(mode):
        fr.set_mode(mode)
        try:
            return fr.task_targets("flNat", 3), fr.coordinator_ref()
        finally:
            fr.set_mode("hierarchical")
    # today's task strings (fl_run.py at 39f611d): model_ref cse-in/flOrch/model/v<v>, update_destination
    # cse-mn-a/flAgg/updates, status_target cse-mn-a/<ae>/flStatus; coordinator cse-in/flOrch
    check("hierarchical: the task names today's model, update destination and status target; the coordinator is today's",
          lambda: targets("hierarchical") == (("cse-in/flOrch/model/v3", "cse-mn-a/flAgg/updates", "cse-mn-a/flNat/flStatus"),
                                              "cse-in/flOrch"))
    check("centralised: the task sends the update to the IN-CSE",
          lambda: targets("centralised") == (("cse-in/flOrch/model/v3", "cse-in/flAgg/updates", "cse-mn-a/flNat/flStatus"),
                                             "cse-in/flOrch"))
    check("edge-only: the task's model and update destination and the coordinator are all on MN-CSE-A",
          lambda: targets("edge-only") == (("cse-mn-a/flOrch/model/v3", "cse-mn-a/flAgg/updates", "cse-mn-a/flNat/flStatus"),
                                           "cse-mn-a/flOrch"))

    def spots(mode):
        fr.set_mode(mode)
        try:
            return fr.spots()
        finally:
            fr.set_mode("hierarchical")
    owners = ("flOrch", "flAgg", "flTfc", "flTfc2", "flNat", "flDec", "flSrc1", "flSrc2")      # OWNER's order at 39f611d
    check("hierarchical looks for leftovers exactly where today's run looked (the same eight requests)",
          lambda: spots("hierarchical") == [(ae, f"{URLS[today[ae]]}/{ae}") for ae in owners])
    check("centralised also looks on MN-CSE-A, edge-only also on the IN-CSE, for the two parties that move",
          lambda: {("flOrch", f"{LAB_A}/flOrch"), ("flAgg", f"{LAB_A}/flAgg")} <= set(spots("centralised"))
          and {("flOrch", f"{LAB_IN}/flOrch"), ("flAgg", f"{LAB_IN}/flAgg")} <= set(spots("edge-only")))
    def discovery_to(mode):
        """What discover() sends in `mode` (rq replaced by a recorder; nothing is sent)."""
        sent, saved = [], fr.rq

        def record(method, to, origin, **k):
            sent.append((method, to, origin))
            return 200, {"m2m:uril": []}
        fr.rq = record
        fr.set_mode(mode)
        try:
            fr.discover()
        finally:
            fr.rq = saved
            fr.set_mode("hierarchical")
        return sent
    check("the orchestrator's discovery is sent where the clients sit (MN-CSE-A, ty=28 flexContainers by label) in "
          "every mode, wherever the orchestrator itself is",
          lambda: all(discovery_to(m) == [("GET", f"{LAB_A}?fu=1&ty=28&lbl=fl:profile", "CflOrch")] for m in MODES3))
    control("the aggregator stayed at the edge in centralised mode", lambda: fr.placement("centralised")["flAgg"] != CIN)
    control("the orchestrator stayed on the IN-CSE in edge-only mode", lambda: fr.placement("edge-only")["flOrch"] == CIN)

    print("== TD_MEC_FL_03: --mode on the command line (main() is stopped at its first send; nothing reaches a CSE)")
    for m, (o, g) in move.items():
        check(f"main --mode {m}: before anything is sent, the orchestrator and the aggregator are where {m} puts them",
              lambda m=m, o=o, g=g: (lambda r: r[0] == "sent" and r[1]["mode"] == m
                                     and r[1]["orch"].startswith(URLS[o] + "/") and r[1]["agg"].startswith(URLS[g] + "/"))(first_contact(["--mode", m])))
    check("main without --mode runs hierarchical", lambda: first_contact([])[1].get("mode") == "hierarchical")
    check("--compare together with --mode, or with --sources, is refused (exit 2)",
          lambda: first_contact(["--compare", "--mode", "edge-only"])[0] == 2 and first_contact(["--compare", "--sources", "x.json"])[0] == 2)
    # --compare writes four files of its own (three run files and the comparison record), so one --out path names
    # none of them: the combination means nothing and is refused, like --sources, --prereg-sha256 and --go
    check("--compare together with --out, --prereg-sha256 or --go is refused (exit 2) before anything is sent",
          lambda: all((lambda r: r[0] == 2 and r[1] == {})(first_contact(["--compare", *extra]))
                      for extra in (["--out", "x.json"], ["--prereg-sha256", "ab" * 32], ["--go", "abababab"])))
    bad = eager(lambda: first_contact(["--mode", "central"]))
    control("a mode name outside the three was accepted (exit 2 expected, before anything is sent)",
            lambda: not (bad[0] == 2 and bad[1] == {} and "invalid choice" in bad[2]))

    print("== TD_MEC_FL_03: the byte counter at the socket (fl_run.py module text: request line + headers + body, "
          "status line + headers + body)")

    def metered(send, reply):
        m = {"sent": 0, "received": 0}
        with fake_net(reply) as s:
            c = fr._MeteredConn("127.0.0.1", 8201, meter=m)
            send(c)
            c.getresponse().read()
        return m, bytes(s.got)
    # Example 1, by hand:  "GET /cse-mn-a/flNat HTTP/1.1\r\n"  3+1+15+1+8+2 = 30
    #                      "X-M2M-Origin: CflOrch\r\n"         12+2+7+2     = 23
    #                      "\r\n"                                             2   -> 55 sent
    #                      "HTTP/1.1 200 OK\r\n"               15+2         = 17
    #                      "Content-Length: 2\r\n"             17+2         = 19
    #                      "\r\n" "{}"                         2+2          =  4  -> 40 received
    ex1 = eager(lambda: metered(lambda c: (c.putrequest("GET", "/cse-mn-a/flNat", skip_host=True, skip_accept_encoding=True),
                                           c.putheader("X-M2M-Origin", "CflOrch"), c.endheaders()),
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"), 2)
    check("example 1: a GET with one header and a 2-byte answer counts 55 sent and 40 received (by hand)",
          lambda: ex1[0] == {"sent": 55, "received": 40}, f"{ex1[0]}" if not isinstance(ex1[0], _Broken) else "")
    check("example 1: the 55 are the bytes the socket was given",
          lambda: ex1[1] == b"GET /cse-mn-a/flNat HTTP/1.1\r\nX-M2M-Origin: CflOrch\r\n\r\n")
    # Example 2, by hand:  "POST /cse-in/flAgg/updates HTTP/1.1\r\n"  4+1+21+1+8+2 = 37
    #                      "Content-Length: 7\r\n"                     17+2          = 19
    #                      "\r\n" + '{"a":1}'                          2+7           =  9  -> 65 sent
    #                      "HTTP/1.1 201 Created\r\n"                  20+2          = 22
    #                      "X-M2M-RSC: 2001\r\n"                       15+2          = 17
    #                      "Content-Length: 0\r\n" "\r\n"              19+2          = 21  -> 60 received
    ex2 = eager(lambda: metered(lambda c: (c.putrequest("POST", "/cse-in/flAgg/updates", skip_host=True, skip_accept_encoding=True),
                                           c.putheader("Content-Length", "7"), c.endheaders(message_body=b'{"a":1}')),
                                b"HTTP/1.1 201 Created\r\nX-M2M-RSC: 2001\r\nContent-Length: 0\r\n\r\n"), 2)
    check("example 2: a POST with a 7-byte body and a 201 without a body counts 65 sent and 60 received (by hand)",
          lambda: ex2[0] == {"sent": 65, "received": 60}, f"{ex2[0]}" if not isinstance(ex2[0], _Broken) else "")
    control("the header lines were left out of the count (only bodies counted: 7 sent, 0 received)",
            lambda: ex2[0]["sent"] <= 7 or ex2[0]["received"] == 0)

    # Example 3: the driver's own rq() over the full urllib path. The reply, by hand: 17 + "Content-Type:
    # application/json\r\n" (12+2+16+2 = 32) + 19 + 2 + 2 = 72 bytes.
    reply3 = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"

    def ex3():
        fr.set_mode("hierarchical")
        with fake_net(reply3) as s:
            st, _ = fr.rq("GET", f"{LAB_A}/flNat", "CflOrch", why="offline test")
        return st, fr.CALLS[-1], bytes(s.got)
    st3, c3, got3 = eager(ex3, 3)
    check("example 3: through rq() the answer counts 72 bytes received (by hand) and the request is every byte sent",
          lambda: st3 == 200 and c3["received"] == 72 and c3["sent"] == len(got3) > 0)
    check("example 3: what was sent is today's request line and X-M2M headers (urllib title-cases them: X-M2M-Rvi), and "
          "urllib's own headers are counted too",
          lambda: got3.startswith(b"GET /cse-mn-a/flNat HTTP/1.1\r\n") and b"X-M2M-Origin: CflOrch\r\n" in got3
          and b"X-M2M-Rvi: 4\r\n" in got3 and b"Host: 127.0.0.1:8201\r\n" in got3 and got3.endswith(b"\r\n\r\n")
          and c3["sent"] > 30 + 23)
    check("example 3: the call is the orchestrator's, sent to MN-CSE-A",
          lambda: (c3["party"], fr.where(c3["url"])) == ("flOrch", (CA, CA, False)))

    def timed():
        fr.set_mode("hierarchical")
        with fake_net(reply3) as s:
            fr.rq("GET", f"{LAB_A}/flNat", "CflOrch", why="offline test: when the clock is read")
        return fr.CALLS[-1], s.when
    tc, tw = eager(timed, 2)
    check("a call's start time (t0, the round time's start) is read before its first byte reaches the socket, its end "
          "time (t1) after the answer", lambda: isinstance(tw, int) and tc["t0"] <= tw <= tc["t1"],
          "" if isinstance(tc, _Broken) else f"t0 {tc['t0']}, first byte {tw}, t1 {tc['t1']}")

    # A connection that is refused (a closed port) sends nothing: the meter must stay at 0. Before the fix the
    # request's length was added before the connect, so the driver's 3 refused MEC 011 liveness probes counted
    # 642 bytes (the reviewer's live count) that never went anywhere.
    def refused_conn():
        m = {"sent": 0, "received": 0}
        with refused_net():
            c = fr._MeteredConn("127.0.0.1", 8097, meter=m)
            try:
                c.request("GET", "/mec_app_support/v2/timing/current_time", headers={"Accept": "application/json"})
            except ConnectionRefusedError:
                return m
        return None
    check("a request to a closed port (connection refused) adds no bytes: 0 sent, 0 received",
          lambda: refused_conn() == {"sent": 0, "received": 0}, str(eager(refused_conn)))

    def refused_mec():
        before = len(fr.CALLS)
        with refused_net():
            sts = [fr.mec("GET", "/mec_app_support/v2/timing/current_time", who=None)[0] for _ in range(3)]
        return sts, fr.CALLS[before:]
    rm_st, rm_calls = eager(refused_mec, 2)
    check("three refused MEC 011 probes through the driver's own mec(): each logged with status 0 and 0 bytes, so the "
          "MEC 011's per-CSE bytes are 0 (by hand)",
          lambda: rm_st == [0, 0, 0] and [(c["status"], c["sent"], c["received"]) for c in rm_calls] == [(0, 0, 0)] * 3
          and fr.tally(rm_calls, [], fr.placement("hierarchical"))["per_cse"]["mec011-a"]["bytes"] == 0)

    # Example 4: the listener's count of one notification, by hand: "POST /fl/flTfc HTTP/1.1\r\n" 4+1+9+1+8+2 = 25,
    # "Content-Length: 2\r\n" 19, "\r\n" 2, "{}" 2 -> 48 received; the answer is every byte written back.
    class _Peer:
        def __init__(self, data):
            self.data, self.out = data, bytearray()

        def makefile(self, mode, *a, **k):
            return io.BufferedReader(io.BytesIO(self.data))

        def sendall(self, b):
            self.out += bytes(b)

        def settimeout(self, *a):
            pass

    def ex4():
        peer, before = _Peer(b"POST /fl/flTfc HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}"), len(fr.NOTIFY_LOG)
        fr._Notify(peer, ("127.0.0.1", 1), None)
        return fr.NOTIFY_LOG[before:], bytes(peer.out)
    n4, out4 = eager(ex4, 2)
    check("example 4: a notification at the listener counts 48 bytes received (by hand) and its answer as written",
          lambda: len(n4) == 1 and n4[0]["endpoint"] == "flTfc" and n4[0]["received"] == 48
          and n4[0]["sent"] == len(out4) > 0 and out4.startswith(b"HTTP/1.0 200 ") and b"X-M2M-RSC: 2000\r\n" in out4)

    print("== TD_MEC_FL_03: edge-cloud or not, by the placement of the caller and the CSE it calls")
    H = "hierarchical"

    def ec(party, url, mode=H):
        return fr.classify(party, url, fr.placement(mode))["edge_cloud"]
    check("an edge party calling its own MN-CSE is not edge-cloud (flTfc reads flSrc1 on cse-mn-a)",
          lambda: ec("flTfc", f"{LAB_A}/flSrc1/env?rcn=4") is False)
    check("a call between two edge parties on two edge CSEs is not edge-cloud (flTfc2 on cse-mn-b reads cse-mn-a)",
          lambda: ec("flTfc2", f"{LAB_A}/flSrc1/env/la") is False)
    check("an edge party calling the IN-CSE is edge-cloud (flTfc reads the model on cse-in)",
          lambda: ec("flTfc", f"{LAB_IN}/flOrch/model/v0") is True)
    check("a cloud party calling an edge CSE is edge-cloud (hierarchical: flOrch discovers on cse-mn-a)",
          lambda: ec("flOrch", f"{LAB_A}?fu=1&ty=28&lbl=fl:profile") is True)
    check("the same discovery in edge-only mode does not cross (flOrch is on cse-mn-a)",
          lambda: ec("flOrch", f"{LAB_A}?fu=1&ty=28&lbl=fl:profile", "edge-only") is False)
    check("the aggregator reading the tasks on cse-in crosses in hierarchical mode and not in centralised mode",
          lambda: ec("flAgg", f"{LAB_IN}/flOrch/tasks?rcn=4") is True
          and ec("flAgg", f"{LAB_IN}/flOrch/tasks?rcn=4", "centralised") is False)
    check("a call sent to the IN-CSE and retargeted to MN-CSE-A: sent to cse-in, target cse-mn-a, edge-cloud",
          lambda: fr.classify("flOrch", f"{LAB_IN.rsplit('/', 1)[0]}/~/id-mn-a/cse-mn-a/flNat/flCap", fr.placement(H))
          == {"sent_to": CIN, "target": CA, "retargeted": True, "edge_cloud": True})
    check("the harness (CAdmin, party None) is never edge-cloud", lambda: ec(None, LAB_IN) is False and ec(None, LAB_A) is False)
    check("the MEC 011 of district A is at the edge: the client's registration there does not cross",
          lambda: ec("flTfc", f"{LAB_MEC}/mec_app_support/v2/registrations") is False)
    check("an address that is not one of the lab's endpoints is refused, not guessed",
          lambda: raises(lambda: fr.classify("flTfc", "http://127.0.0.1:9999/cse-in", fr.placement(H)), ValueError))
    # TS-0004's HTTP binding: SP-relative /~/<CSE-ID>/..., absolute /_/<SP-ID>/<CSE-ID>/...; the CSE-ID of an
    # absolute address is the segment AFTER the SP-ID
    check("an absolute address sent to the IN-CSE (/_/<SP-ID>/id-mn-a/...) is read at the segment after the SP-ID: "
          "retargeted to cse-mn-a; /_/ without an SP-ID is refused; /~/id-in/... is the IN-CSE itself",
          lambda: fr.where("http://127.0.0.1:8200/_/m2m.lab.example/id-mn-a/cse-mn-a/flNat/flCap") == (CIN, CA, True)
          and raises(lambda: fr.where("http://127.0.0.1:8200/_/id-mn-a/cse-mn-a/flNat"), ValueError)
          and fr.where("http://127.0.0.1:8200/~/id-in/cse-in/flOrch") == (CIN, CIN, False))

    def as_origin(origin, to):
        fr.set_mode(H)
        with fake_net(reply3):
            fr.rq("GET", to, origin, why="offline test: who the counter says this is")
        return fr.CALLS[-1]
    # the authorities have no AE; they sit with their sources on MN-CSE-A (fl_run.py module text, PLACE)
    au = eager(lambda: as_origin("CflAuthB", f"{LAB_IN}/flOrch/ops"))
    check("a domain authority is a party at the edge, not the harness: CflAuthB's call to the IN-CSE is its own and "
          "crosses; CflAuthA's to MN-CSE-A does not",
          lambda: (au["party"], au["edge_cloud"]) == ("CflAuthB", True) and ec("CflAuthA", f"{LAB_A}/flSrc1/flPolicy") is False
          and fr.PARTY.get("CflAuthA") == "CflAuthA")

    # An originator in no table must not become the harness (which is never edge-cloud): it is a named party
    # 'unmapped:<originator>', counted at the CSE it was sent to, listed, and it fails the FL_03 step.
    st_call = eager(lambda: as_origin("CflStranger", f"{LAB_IN}/flOrch/model/v0"))
    check("an originator in no table is logged as the party 'unmapped:CflStranger', its side unknown (not the harness)",
          lambda: (st_call["party"], st_call["edge_cloud"]) == ("unmapped:CflStranger", None))
    check("CAdmin is the harness and nothing else is: party_of('CAdmin') is None, party_of('CflOrch') is flOrch",
          lambda: fr.party_of("CAdmin") is None and fr.party_of("CflOrch") == "flOrch"
          and fr.party_of("CflNobody") == "unmapped:CflNobody")
    um_call = call("unmapped:CflStranger", f"{LAB_IN}/flOrch/model/v0", 60, 40, 1)
    tu = eager(lambda: fr.tally([um_call, call(None, LAB_IN, 30, 20, 0)], [], fr.placement(H)))
    # by hand: the stranger's 100 bytes at cse-in, listed as unmapped; the harness's 50 bytes at cse-in; edge-cloud 0
    check("the tally lists the unmapped call (1 call, 100 bytes, by name), counts it at cse-in, not in the harness's "
          "bytes and not as edge-cloud (by hand: cse-in 150, of them harness 50)",
          lambda: tu["unmapped"] == {"calls": 1, "bytes": 100, "parties": ["unmapped:CflStranger"]}
          and (tu["per_cse"][CIN]["bytes"], tu["per_cse"][CIN]["harness_bytes"]) == (150, 50)
          and tu["edge_cloud"]["total"] == 0)
    control("a call between two edge parties was counted as edge-cloud", lambda: ec("flTfc2", f"{LAB_A}/flSrc1/env/la"))

    print("== TD_MEC_FL_03: totals from a hand-made log of calls and one notification")
    # sizes are request + response bytes; edge-cloud per mode worked out by hand in the last three columns (H/C/E)
    calls = [call("flTfc", f"{LAB_A}/flSrc1/env?rcn=4", 100, 50, 1),                       # 150  -    -    -
             call("flTfc", f"{LAB_IN}/flOrch/model/v0", 120, 380, 1),                      # 500  yes  yes  yes
             call("flOrch", f"{LAB_A}?fu=1&ty=28&lbl=fl:profile", 200, 136, 1),            # 336  yes  yes  -
             call("flOrch", "http://127.0.0.1:8200/~/id-mn-a/cse-mn-a/flNat/flCap", 90, 410, 2),   # 500 retargeted: yes x3
             call(None, LAB_IN, 80, 743, 0),                                                # 823  harness, never
             call("flTfc2", f"{LAB_A}/flSrc1/env/la", 70, 30, 0),                          # 100  -    -    -
             call("flAgg", f"{LAB_IN}/flOrch/tasks?rcn=4", 100, 400, 1),                   # 500  yes  -    yes
             call("flTfc", f"{LAB_MEC}/mec_app_support/v2/registrations", 150, 250, 0, "POST")]   # 400  -  -  -
    notes = [{"endpoint": "flTfc", "received": 900, "sent": 60, "round": 1}]               # 960 from flOrch's CSE: yes yes -
    # hierarchical: calls 500 + 336 + 500 + 500 = 1836; notification 960; total 2796
    # centralised:  calls 500 + 336 + 500       = 1336; notification 960; total 2296
    # edge-only:    calls 500 + 500 + 500       = 1500; notification   0; total 1500
    # per CSE the call was sent to (any mode): cse-mn-a 150 + 336 + 100 = 586 (3 calls); cse-in 500 + 500 + 823 + 500
    #   = 2323 (4 calls, 823 of them the harness); mec011-a 400 (1); cse-mn-b 0. All calls 3309.
    T = {m: eager(lambda m=m: fr.tally(calls, notes, fr.placement(m))) for m in MODES3}
    for m, (cb, nb, tot) in (("hierarchical", (1836, 960, 2796)), ("centralised", (1336, 960, 2296)), ("edge-only", (1500, 0, 1500))):
        check(f"{m}: edge-cloud bytes {cb} of calls + {nb} of notifications = {tot} (by hand)",
              lambda m=m, cb=cb, nb=nb, tot=tot: (T[m]["edge_cloud"]["calls_bytes"], T[m]["edge_cloud"]["notifications_bytes"],
                                                  T[m]["edge_cloud"]["total"]) == (cb, nb, tot))
    check("bytes per CSE the calls were sent to: cse-in 2323 (823 of them the harness), cse-mn-a 586, cse-mn-b 0, "
          "mec011-a 400 (by hand)",
          lambda: {k: (v["calls"], v["bytes"], v["harness_bytes"]) for k, v in T[H]["per_cse"].items()}
          == {CIN: (4, 2323, 823), CA: (3, 586, 0), CB: (0, 0, 0), "mec011-a": (1, 400, 0)})
    check("the per-CSE bytes add up to the bytes of all calls (3309), so no call is counted at two CSEs",
          lambda: sum(v["bytes"] for v in T[H]["per_cse"].values()) == T[H]["calls"]["bytes"] == 3309)
    check("the retargeted call is counted once: 1 call, 500 bytes, at cse-in only",
          lambda: T[H]["retargeted"] == {"calls": 1, "bytes": 500})
    check("the notification is counted at the CSE that sent it (hierarchical: cse-in 960; edge-only: cse-mn-a 960)",
          lambda: T[H]["per_cse"][CIN]["notification_bytes"] == 960 and T["edge-only"]["per_cse"][CA]["notification_bytes"] == 960
          and T["edge-only"]["per_cse"][CIN]["notification_bytes"] == 0)
    one = [calls[3]]
    control("a retargeted call was not counted exactly once (500 bytes, at one CSE)",
            lambda: (lambda t: t["edge_cloud"]["total"] != 500 or sum(v["bytes"] for v in t["per_cse"].values()) != 500)(
                fr.tally(one, [], fr.placement(H))))
    control("the harness's own calls were counted as edge-cloud",
            lambda: fr.tally([calls[4]], [], fr.placement(H))["edge_cloud"]["total"] != 0)

    print("== TD_MEC_FL_03: round time from the round's own log [first task sent .. the 201 for the new global model]")
    # one round, hierarchical, times in ns on one monotonic clock
    rlog = [call("flOrch", f"{LAB_A}?fu=1&ty=28&lbl=fl:profile", 1, 1, 1, t0=1_000_000_000, t1=1_010_000_000),
            call("flOrch", f"{LAB_IN}/flOrch/tasks", 1, 1, 1, "POST", 23, 201, 1_050_000_000, 1_060_000_000),   # subscription
            call("flOrch", f"{LAB_IN}/flOrch/ops", 1, 1, 1, "POST", 4, 201, 1_100_000_000, 1_110_000_000),      # binding
            call("flOrch", f"{LAB_IN}/flOrch/tasks", 1, 1, 1, "POST", 4, 201, 1_250_000_000, 1_260_000_000),    # first task
            call("flOrch", f"{LAB_IN}/flOrch/tasks", 1, 1, 1, "POST", 4, 201, 1_300_000_000, 1_310_000_000),
            call("flAgg", f"{LAB_A}/flAgg/models", 1, 1, 1, "POST", 4, 201, 1_400_000_000, 1_430_000_000),
            call("flOrch", f"{LAB_IN}/flOrch/model", 1, 1, 1, "POST", 4, 201, 1_450_000_000, 1_499_999_999),    # new model
            call("flTfc", f"{LAB_IN}/flOrch/model/v1", 1, 1, 1, t0=1_500_000_000, t1=1_510_000_000)]
    # by hand: 1_499_999_999 - 1_250_000_000 = 249_999_999 ns = 249_999 us (whole microseconds, rounded down).
    # From the discovery it would be 499_999; from the subscription 449_999; to the aggregator's 201, 180_000.
    rt = eager(lambda: fr.round_time_us(fr.round_marks(rlog, 1, fr.placement(H))))
    check("round time = first task sent .. 201 for the redistributed model: 249999 us (by hand)", lambda: rt == 249_999)
    check("the marks name the first task, the aggregator's model and the redistributed model",
          lambda: fr.round_marks(rlog, 1, fr.placement(H)) == {"task_published": 1_250_000_000,
                                                               "model_aggregated": 1_430_000_000,
                                                               "model_published": 1_499_999_999})
    check("a round whose new model was not published (no 201) has no round time",
          lambda: fr.round_time_us(fr.round_marks(rlog[:6] + [{**rlog[6], "status": 403}], 1, fr.placement(H))) is None)
    check("the marks are looked up where this mode puts the orchestrator: the same log read as edge-only finds none",
          lambda: fr.round_time_us(fr.round_marks(rlog, 1, fr.placement("edge-only"))) is None)
    check("calls of another round are not used", lambda: fr.round_time_us(fr.round_marks(rlog, 2, fr.placement(H))) is None)
    check("median: of three the middle one; of four the mean of the middle two, rounded down; of none, nothing",
          lambda: fr.median_us([4_533_000, 249_999, 449_000]) == 449_000 and fr.median_us([1, 2, 3, 10]) == 2
          and fr.median_us([]) is None)
    check("seconds shown to the millisecond, rounded down: 249999 us -> '0.249', 4533000 us -> '4.533'",
          lambda: (fr.fmt_s(249_999), fr.fmt_s(4_533_000), fr.fmt_s(None)) == ("0.249", "4.533", None))
    control("the round time was taken from the orchestrator's discovery, not from the first task", lambda: int(rt) == 499_999)
    control("the round time was taken from the subscription on the task container", lambda: int(rt) == 449_999)

    print("== TD_MEC_FL_03: one run's block, and the comparison of the three (calls AND notifications)")

    def round_log(rnd, start, dur, ec_bytes, mode=H):
        """A hand-made round: a first task at `start`, the new model's 201 `dur` ns later, one edge-cloud read."""
        p = fr.placement(mode)
        o = URLS[p["flOrch"]]
        out = [call("flOrch", f"{o}/flOrch/tasks", 1, 1, rnd, "POST", 4, 201, start, start + 1)]
        if dur is not None:
            out.append(call("flOrch", f"{o}/flOrch/model", 1, 1, rnd, "POST", 4, 201, start + dur - 1, start + dur))
        out.append(call("flTfc", f"{LAB_IN}/flOrch/model/v0", ec_bytes - 10, 10, rnd))   # edge -> cse-in: crosses
        return out

    def round_notes(rnd, nbytes):
        """One task notification of the round to flTfc (on cse-mn-a), sent by the CSE that holds the orchestrator's
        <tasks>: nbytes - 20 read at the listener, 20 written back."""
        return [{"endpoint": "flTfc", "kind": "task", "received": nbytes - 20, "sent": 20, "round": rnd}]
    # Rounds 1-3 take 0.250, 4.531 and 0.448 s; round 4 publishes no model. Calls: edge-cloud 1000, 2000, 3000, 400,
    # and the orchestrator's 2 + 2 bytes on its own CSE (round 4: 2). One notification per round, 100, 200, 300, 40
    # bytes, from cse-in (hierarchical: the orchestrator's CSE) to flTfc on cse-mn-a, so each one crosses.
    # By hand: edge-cloud per round 1000+100 = 1100, 2200, 3300, 440; rounds 1-3 6600; whole run 6400 of calls +
    # 640 of notifications = 7040. At cse-in: calls 4 + 4 + 4 + 2 + 6400 = 6414 bytes, notifications 640.
    b4 = ((10**9, 250_000_000, 1000, 100), (2 * 10**9, 4_531_000_000, 2000, 200), (9 * 10**9, 448_000_000, 3000, 300),
          (10**10, None, 400, 40))
    blog = eager(lambda: [c for r, (s, d, b, _) in enumerate(b4, 1) for c in round_log(r, s, d, b)])
    bnotes = [n for r, (_, _, _, nb) in enumerate(b4, 1) for n in round_notes(r, nb)]
    blk = eager(lambda: fr.fl03_block("hierarchical", blog, bnotes, [1, 2, 3, 4]))
    check("block: per round time in us (round 4 none), and the median of rounds 1-3 is 0.448 s",
          lambda: [r["time_us"] for r in blk["rounds"]] == [250_000, 4_531_000, 448_000, None]
          and blk["round_time"]["median_us"] == 448_000 and blk["round_time"]["median_s"] == "0.448" and blk["round_time"]["N"] == 3)
    check("block: edge-cloud bytes per round 1100, 2200, 3300, 440 with the notifications in them (by hand); rounds 1-3 "
          "together 6600",
          lambda: blk["edge_cloud_bytes"]["per_round"] == [1100, 2200, 3300, 440] and blk["edge_cloud_bytes"]["rounds_1_to_3"] == 6600
          and [r["edge_cloud_notification_bytes"] for r in blk["rounds"]] == [100, 200, 300, 40])
    check("block: whole run 6400 edge-cloud bytes of calls + 640 of notifications = 7040; cse-in 6414 bytes of calls and "
          "640 of notifications (by hand)",
          lambda: tuple(blk["edge_cloud_bytes"]["whole_run"][k] for k in ("calls_bytes", "notifications_bytes", "total"))
          == (6400, 640, 7040) and (blk["bytes_per_cse"][CIN]["bytes"], blk["bytes_per_cse"][CIN]["notification_bytes"]) == (6414, 640))
    check("block: names the mode, carries the placement table and the written definitions",
          lambda: blk["mode"] == "hierarchical" and blk["placement"] == fr.placement("hierarchical")
          and {"bytes", "edge_cloud", "retargeted", "notifications", "round_time", "caveat"} <= set(blk["definitions"]))
    check("block: says it is bytes counted at the client on one PC and that loopback time says little about latency",
          lambda: "not a network measurement" in blk["definitions"]["caveat"] and "latency" in blk["definitions"]["caveat"])

    def has_lines(lines):
        """(the one-PC bandwidth line, the round-time line) are among `lines`."""
        bw = any(x.startswith("bandwidth on a network") and "one PC" in x and "loopback" in x for x in lines)
        rt = any(x.startswith("a difference in round time between the modes") and "4.0 s" in x and "0.25 s" in x
                 and "loopback" in x for x in lines)
        return bw, rt
    check("block: its not_shown says the bytes are no bandwidth measurement on a network (one PC, loopback)",
          lambda: has_lines(blk["not_shown"])[0])
    check("block: its not_shown says no difference between the modes can be read from the round times, and why (round "
          "2's 4.0 s window, the aggregator's 0.25 s poll, one host over loopback)", lambda: has_lines(blk["not_shown"])[1])

    # TD_MEC_FL_03: steps 1-2 centralised, 3-4 hierarchical, 5-6 edge-only
    check("the FL_03 step numbers are the plan's: centralised 1-2, hierarchical 3-4, edge-only 5-6, in the block and in "
          "the two step labels",
          lambda: fr.FL03_STEPS == {"centralised": (1, 2), "hierarchical": (3, 4), "edge-only": (5, 6)}
          and all(fr.fl03_block(m, [], [], [])["steps"] == list(n)
                  and [lab.split("]")[0] for lab, _, _ in fr.fl03_steps(fr.fl03_block(m, [], [], []))]
                  == [f"[FL_03 step {n[0]}", f"[FL_03 step {n[1]}"]
                  for m, n in (("centralised", (1, 2)), ("hierarchical", (3, 4)), ("edge-only", (5, 6)))))
    check("the two FL_03 steps pass on the hand-made block (three timed rounds, every call's party known)",
          lambda: [ok for _, ok, _ in fr.fl03_steps(blk)] == [True, True])
    blk_u = eager(lambda: fr.fl03_block("hierarchical", blog + [um_call], bnotes, [1, 2, 3, 4]))
    check("an unmapped originator's call in the log fails the FL_03 recording step, which names it; the block lists it",
          lambda: blk_u["unmapped"]["parties"] == ["unmapped:CflStranger"] and fr.fl03_steps(blk_u)[1][1] is False
          and "unmapped:CflStranger" in fr.fl03_steps(blk_u)[1][2])
    control("an unmapped originator's call was hidden (counted as the harness's, or the FL_03 step still passed)",
            lambda: tu["unmapped"]["calls"] != 1 or tu["per_cse"][CIN]["harness_bytes"] != 50 or fr.fl03_steps(blk_u)[1][1])

    def run_of(mode, times, ecs, verdict="PASS"):
        log = [c for r, (d, b) in enumerate(zip(times + [None], ecs + [400]), 1) for c in round_log(r, r * 10**10, d, b, mode)]
        log += [call("flTfc", f"{LAB_MEC}/mec_app_support/v2/registrations", 150, 250, 0, "POST"), call(None, LAB_B, 30, 47, 0)]
        notes = [n for r, nb in enumerate((100, 200, 300, 40), 1) for n in round_notes(r, nb)]
        return {"mode": mode, "verdict": verdict, "file": f"fl_sim_{mode}.json", "exit": 0, "sha256": "0" * 64,
                "fl03": fr.fl03_block(mode, log, notes, [1, 2, 3, 4])}
    # By hand, per mode. Every run: the orchestrator's calls on its own CSE 4 + 4 + 4 + 2 = 14 bytes; flTfc's reads on
    # cse-in (edge -> cloud, they cross in every mode) ecs + 400; flTfc's MEC 011 registration 400 (edge to edge);
    # a harness call to cse-mn-b 77; notifications 100 + 200 + 300 + 40 = 640 from the orchestrator's CSE to flTfc on
    # cse-mn-a, which cross in centralised and hierarchical (cse-in) and not in edge-only (cse-mn-a).
    #                 per round, 1-3        1-3    whole run          cse-in              cse-mn-a      mn-b  mec011
    #  centralised    1600 2700 3800        8100   7900 + 640 = 8540  14+7900+640 = 8554  0             77    400
    #  hierarchical   1100 2200 3300        6600   6400 + 640 = 7040  14+6400+640 = 7054  0             77    400
    #  edge-only      10 10 10              30     430 + 0 = 430      430                 14+640 = 654  77    400
    runs = eager(lambda: [run_of("edge-only", [100_000_000, 4_100_000_000, 120_000_000], [10, 10, 10]),
                          run_of("centralised", [300_000_000, 4_600_000_000, 500_000_000], [1500, 2500, 3500]),
                          run_of("hierarchical", [250_000_000, 4_531_000_000, 448_000_000], [1000, 2000, 3000])])
    tab = eager(lambda: fr.fl03_compare(runs))
    check("comparison: one row per mode, in the plan's order, each with exactly the stated columns",
          lambda: [r["mode"] for r in tab["rows"]] == ["centralised", "hierarchical", "edge-only"]
          and all(list(r) == list(fr.FL03_COLUMNS) for r in tab["rows"]) and tab["columns"] == list(fr.FL03_COLUMNS))
    check("comparison: where the two parties sat, the round times and the edge-cloud bytes are each run's own",
          lambda: [(r["orchestrator"], r["aggregator"], r["round_time_s"], r["median_round_time_s"], r["edge_cloud_bytes_rounds_1_to_3"])
                   for r in tab["rows"]] == [(CIN, CIN, ["0.300", "4.600", "0.500"], "0.500", 8100),
                                             (CIN, CA, ["0.250", "4.531", "0.448"], "0.448", 6600),
                                             (CA, CA, ["0.100", "4.100", "0.120"], "0.120", 30)])
    check("comparison: edge-cloud bytes per round, rounds 1-3 and whole run, notifications in them, per mode (by hand)",
          lambda: [(r["edge_cloud_bytes_per_round"], r["edge_cloud_bytes_rounds_1_to_3"], r["edge_cloud_bytes_whole_run"])
                   for r in tab["rows"]] == [([1600, 2700, 3800], 8100, 8540), ([1100, 2200, 3300], 6600, 7040), ([10, 10, 10], 30, 430)])
    check("comparison: bytes per CSE, calls and notifications together (by hand): cse-in 8554 / 7054 / 430, cse-mn-a "
          "0 / 0 / 654, cse-mn-b 77, mec011-a 400",
          lambda: [(r["bytes_cse_in"], r["bytes_cse_mn_a"], r["bytes_cse_mn_b"], r["bytes_mec011_a"]) for r in tab["rows"]]
          == [(8554, 0, 77, 400), (7054, 0, 77, 400), (430, 654, 77, 400)])
    check("comparison: two runs of one mode, a mode missing, or a block of another mode are refused",
          lambda: raises(lambda: fr.fl03_compare(runs[:2] + [runs[0]]), ValueError)
          and raises(lambda: fr.fl03_compare(runs[:2]), ValueError)
          and raises(lambda: fr.fl03_compare(runs[:2] + [{**runs[2], "fl03": runs[0]["fl03"]}]), ValueError))
    check("comparison: a run that wrote no block still has its row, with nothing measured in it",
          lambda: (lambda t: t["rows"][1]["round_time_s"] is None and t["rows"][1]["run_verdict"] == "FAIL")(
              fr.fl03_compare(runs[:2] + [{**runs[2], "verdict": "FAIL", "fl03": None}])))
    check("the result of TD_MEC_FL_03 is PARTIAL when all three runs passed, FAIL when one did not",
          lambda: fr.fl03_verdict(tab) == "PARTIAL"
          and fr.fl03_verdict(fr.fl03_compare(runs[:2] + [{**runs[2], "verdict": "FAIL"}])) == "FAIL")

    def without_median(b):
        b = copy.deepcopy(b)
        b["round_time"]["median_s"] = None
        return b
    check("the result is FAIL when all three runs passed but a cell is empty: a passed run with no block, or one whose "
          "block has no median",
          lambda: fr.fl03_verdict(fr.fl03_compare(runs[:2] + [{**runs[2], "fl03": None}])) == "FAIL"
          and fr.fl03_verdict(fr.fl03_compare(runs[:2] + [{**runs[2], "fl03": without_median(runs[2]["fl03"])}])) == "FAIL")
    rec = eager(lambda: fr.fl03_compare_record(runs))
    check("the comparison record: PARTIAL, this table, the three runs, and in not_shown the bandwidth line and the "
          "round-time line; a refused table gives FAIL and says why",
          lambda: rec["verdict"] == "PARTIAL" and rec["table"] == tab and [r["mode"] for r in rec["runs"]] == [r["mode"] for r in runs]
          and has_lines(rec["not_shown"]) == (True, True)
          and (lambda r2: r2["verdict"] == "FAIL" and "missing" in r2["table_refused"])(fr.fl03_compare_record(runs[:2])))
    check("steps 7 and 8 are listed as NOT-RUN with a reason",
          lambda: any("steps 7 and 8" in r["row"] and r["result"] == "NOT-RUN" and r["reason"] for r in fr.FL03_NOT_RUN))
    control("TD_MEC_FL_03 was called more than PARTIAL although every source is simulated and steps 7-8 did not run",
            lambda: fr.fl03_verdict(tab) not in ("PARTIAL", "FAIL"))

    print("== TD_MEC_FL_03: the KPI block's numbers (run_round) against the FL_03 block's (fl03_block): two code paths")

    def kpi_run():
        """run_round for rounds 1-3 with _round replaced by a stub that logs the hand-made rounds above (b4); then
        the FL_03 block from the same log. CALLS and NOTIFY_LOG are put back afterwards."""
        saved = fr.CALLS[:], fr.NOTIFY_LOG[:], fr._round

        def stub(S, rnd, mode, **kw):
            s, d, b, nb = b4[rnd - 1]
            fr.CALLS.extend(round_log(rnd, s, d, b))
            fr.NOTIFY_LOG.extend(round_notes(rnd, nb))
            return {"round": rnd}
        fr.CALLS.clear()
        fr.NOTIFY_LOG.clear()
        fr._round = stub
        try:
            fr.set_mode("hierarchical")
            three = [fr.run_round({}, r, "independentSources") for r in (1, 2, 3)]
            return three, fr.fl03_block("hierarchical", fr.CALLS, fr.NOTIFY_LOG, [1, 2, 3])
        finally:
            fr.CALLS[:], fr.NOTIFY_LOG[:], fr._round = saved
    three, f3k = eager(kpi_run, 2)
    check("run_round's own numbers (what the KPI block reports): edge-cloud bytes 1100, 2200, 3300 and round times "
          "0.250, 4.531, 0.448 s (by hand, as in the block above)",
          lambda: [R["bytes"] for R in three] == [1100, 2200, 3300] and [R["time_s"] for R in three] == ["0.250", "4.531", "0.448"])
    kpi = eager(lambda: fr.kpi_rounds(three, f3k))
    check("the KPI entries built from them agree with the FL_03 block built from the whole log (kpi_vs_fl03 finds "
          "nothing); total 6600",
          lambda: fr.kpi_vs_fl03(kpi, f3k) == [] and kpi["edge_cloud_bytes"]["values"] == [1100, 2200, 3300]
          and kpi["edge_cloud_bytes"]["total"] == 6600 and kpi["fl_round_completion_time_s"]["values"] == ["0.250", "4.531", "0.448"])
    control("a KPI block with cumulative bytes (1100, 3300, 6600) was taken as agreeing with the FL_03 block",
            lambda: not fr.kpi_vs_fl03({**kpi, "edge_cloud_bytes": {**kpi["edge_cloud_bytes"], "values": [1100, 3300, 6600],
                                                                     "total": 11000}}, f3k))

    print("== TD_MEC_FL_03: leftovers of an earlier run are removed as the harness (main on a fake network, nothing sent)")
    lo_calls, lo_bytes = eager(lambda: leftover_run("centralised"), 2)
    dels = eager(lambda: [c for c in lo_calls if c["method"] == "DELETE"])
    # by hand: centralised looks in 10 places, the 8 AEs where it puts them and flOrch and flAgg also on cse-mn-a
    # (where the other modes put them); every one answers 200 here, so 10 DELETEs follow
    check("leftover removal (centralised, every place answered 200): 10 DELETEs, flOrch on cse-mn-a among them (by hand)",
          lambda: len(dels) == 10 and f"{LAB_A}/flOrch" in [c["url"] for c in dels])
    check("each leftover DELETE is counted as the harness's (party None), none as edge-cloud, so a crashed earlier run "
          "adds nothing to the whole-run edge-cloud bytes",
          lambda: all(c["party"] is None and c["edge_cloud"] is False for c in dels)
          and fr.tally(dels, [], fr.placement("centralised"))["edge_cloud"]["total"] == 0)
    check("on the wire the leftover DELETE still goes under the AE's own originator (no admin rights used to remove it)",
          lambda: any(h.startswith(b"DELETE /cse-mn-a/flOrch HTTP/1.1\r\n") and b"X-M2M-Origin: CflOrch\r\n" in h
                      for h in lo_bytes.split(b"\r\n\r\n")))

# ------------------------------------------------------------------------------------------------ TD_MEC_FL_01
# The REG_03 platform path, as committed in the main tree at 411125a and loaded from there by path. The three
# hashes were taken by hand on 2026-11-20 with
#   git -C /home/edgefollow/edgefollow show 411125a:<path> | sha256sum      (and sha256sum of the file in that tree)
# which gave the same value both ways for each file.
MAIN_TREE = Path(__file__).resolve().parent.parent
COMMIT_411 = "411125a0c3ec9df9141fdea63ee4a745466405bc"
PINS_BY_HAND = {"estimed/mec_app_deploy.py": "305eea0aa94fc73781ad5ec6f7d2622ca0e4af1772e57479b082acc379661896",
                "mec010p2/candidate.py": "eac38db2c40324d7bc0c6ac767d11ad7e7f5c07c002f66e63621c5c0e39003d0",
                "mec011_appsupport/candidate.py": "7701b3cc592024f0894a2891290cd78b21d0d920c92872929cb58f3e50283e59"}
APPS = Path(__file__).resolve().parent / "apps"
# What each package must say, by hand from the plan of this row (and, for the readers, from fl_run.SPEC: the
# orchestrator's and the client's metadata policy name exactly these originators, RETRIEVE + DISCOVERY = 34)
PKG_BY_HAND = {
    "fl_orch": dict(appName="estimed-fl-orchestrator", originator="CflOrch", rn="flOrch", mnCse="cse-in",
                    container="ops", readers=["CflTfc", "CflTfc2", "CflNat", "CflDec", "CflAgg"], role="orchestrator",
                    service="fl-orchestrator"),
    "fl_tfc": dict(appName="estimed-fl-trusted-client", originator="CflTfc", rn="flTfc", mnCse="cse-mn-a",
                   container="flMeta", readers=["CflOrch", "CflAgg", "CflAuthA", "CflAuthB"], role="tfc",
                   service="trusted-fl-client"),
    "fl_proxy": dict(appName="estimed-fl-proxy-path", originator="CflProxy", rn="flProxy", mnCse="cse-mn-a",
                     container="flConfig", readers=["CflOrch", "CflProxyCheck"], role="proxy", service="fl-proxy-path"),
}
DEV_FIELDS = ["t", "battery_pct", "battery_temp_c", "light", "proximity", "sim"]     # sim_series' record keys


def _app_module(pkg="fl_proxy"):
    """The package's program as a module (its top level only defines; nothing is started)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(f"fl_app_{pkg}", APPS / pkg / "fl_app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sha(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()


def fl01_rows() -> None:  # noqa: C901, PLR0915
    import json
    import shutil
    import subprocess
    import tempfile

    print("== TD_MEC_FL_01: the REG_03 platform path is the main tree's at 411125a, loaded by pinned SHA-256")
    check("the pins are the three hashes taken by hand, of the files at commit 411125a",
          lambda: mp.PINS == PINS_BY_HAND and mp.SOURCE_COMMIT == COMMIT_411 and mp.SOURCE_TREE == MAIN_TREE)

    def git_blob(rel):
        r = subprocess.run(["git", "-C", str(MAIN_TREE), "show", f"{COMMIT_411[:7]}:{rel}"], capture_output=True)
        return _sha(r.stdout) if r.returncode == 0 else f"git exit {r.returncode}"
    have_411 = subprocess.run(["git", "-C", str(MAIN_TREE), "cat-file", "-e", f"{COMMIT_411}^{{commit}}"],
                              capture_output=True).returncode == 0
    for rel, want in PINS_BY_HAND.items():
        check(f"{rel}: the file the run will load hashes to its pin",
              lambda rel=rel, want=want: _sha(mp.read_pinned(rel)) == want)
        if have_411:
            check(f"{rel}: the blob at 411125a hashes to its pin", lambda rel=rel, want=want: git_blob(rel) == want)
        else:   # published tree: that private commit is not in this history -- reported, never counted as a pass
            print(f"  NOT-RUN  {rel}: the blob at 411125a hashes to its pin  -- commit 411125a is not in this "
                  "repository's history")

    def changed_copy(rel, change):
        d = Path(tempfile.mkdtemp(prefix="fl01-pin-"))
        (d / rel).parent.mkdir(parents=True)
        b = (MAIN_TREE / rel).read_bytes()
        (d / rel).write_bytes(change(b))
        return d
    one_byte = eager(lambda: changed_copy("estimed/mec_app_deploy.py", lambda b: b[:-1] + bytes([b[-1] ^ 1])))
    same = eager(lambda: changed_copy("estimed/mec_app_deploy.py", lambda b: b))
    check("a copy with one byte changed is refused, and the refusal names the file and both hashes",
          lambda: (lambda e: isinstance(e, mp.PinError) and "mec_app_deploy.py" in str(e) and PINS_BY_HAND[
              "estimed/mec_app_deploy.py"][:16] in str(e))(_raised(lambda: mp.read_pinned("estimed/mec_app_deploy.py", tree=one_byte))))
    check("... while an unchanged copy elsewhere is accepted (the pin is on the bytes, not on the path)",
          lambda: _sha(mp.read_pinned("estimed/mec_app_deploy.py", tree=same)) == PINS_BY_HAND["estimed/mec_app_deploy.py"])
    check("a missing file and a file that has no pin are refused",
          lambda: isinstance(_raised(lambda: mp.read_pinned("mec010p2/candidate.py", tree=same)), mp.PinError)
          and isinstance(_raised(lambda: mp.read_pinned("estimed/handover.py")), mp.PinError))
    control("a platform agent with one byte changed was loaded (anything but a PinError counts as loaded)",
            lambda: not isinstance(_raised(lambda: mp.load_module("estimed/mec_app_deploy.py", "mad_changed", tree=one_byte)),
                                   mp.PinError))
    mad = eager(lambda: mp.platform_agent())
    check("the loaded platform agent is the REG_03 one: PlatformAgent, verify_package, the python3 runtime with -I -B",
          lambda: hasattr(mad, "PlatformAgent") and hasattr(mad, "verify_package")
          and mad.RUNTIMES["python3"][1:] == ["-I", "-B"] and mad.__file__ == str(MAIN_TREE / "estimed/mec_app_deploy.py"))
    check("the provenance the record carries: path, SHA-256 and commit of each pinned file",
          lambda: mp.provenance() == {rel: {"path": str(MAIN_TREE / rel), "sha256": h, "commit": COMMIT_411}
                                      for rel, h in PINS_BY_HAND.items()})
    for d in (one_byte, same):
        if isinstance(d, Path):
            shutil.rmtree(d, ignore_errors=True)

    print("== TD_MEC_FL_01: the three packages (FL Orchestrator, Trusted FL Client, MEC proxy path)")
    for pkg, want in PKG_BY_HAND.items():
        def desc_ok(pkg=pkg, want=want):
            d = mad.verify_package(APPS / pkg)
            o, f = d["onem2m"], d["fl"]
            return ((d["appName"], o["originator"], o["rn"], o["mnCse"], o["container"], o["acp"]["rn"], o["acp"]["readers"],
                     f["role"], f["service"], f["readerOps"], d["entryPoint"]["file"])
                    == (want["appName"], want["originator"], want["rn"], want["mnCse"], want["container"], "flMetaAcp",
                        want["readers"], want["role"], want["service"], 34, "fl_app.py"))
        check(f"{pkg}: the pinned agent's verify_package accepts it, and it says what this row needs (by hand)", desc_ok)
    progs = eager(lambda: {p: (APPS / p / "fl_app.py").read_bytes() for p in PKG_BY_HAND})
    check("one program in three packages: the three fl_app.py are byte for byte the same, each listed by its digest",
          lambda: len(set(progs.values())) == 1 and all(
              json.loads((APPS / p / "appd.json").read_text())["files"] == {"fl_app.py": _sha(progs[p])} for p in progs))
    check("the Trusted FL Client package names the two constrained sources it acts for; the proxy configures one "
          "device, devPx1, with the simulated record's fields and a 1024-byte limit",
          lambda: json.loads((APPS / "fl_tfc/appd.json").read_text())["fl"]["represents"] == ["flSrc1", "flSrc2"]
          and json.loads((APPS / "fl_proxy/appd.json").read_text())["fl"]["devices"] == [
              {"deviceId": "devPx1", "class": "proxy-path", "fields": DEV_FIELDS, "maxBytes": 1024}]
          and json.loads((APPS / "fl_proxy/appd.json").read_text())["fl"]["dataAcp"] == {
              "rn": "flDataAcp", "readers": ["CflProxyCheck"], "ops": 34})
    check("the packages' readers and names are the driver's: SPEC's metadata readers and OWNER's originators",
          lambda: PKG_BY_HAND["fl_orch"]["readers"] == fr.SPEC["flOrch"]["meta"][0][0]
          and PKG_BY_HAND["fl_tfc"]["readers"] == fr.SPEC["flTfc"]["meta"][0][0]
          and (fr.OWNER["flOrch"], fr.OWNER["flTfc"], fr.FL01_OWNER["flProxy"]) == ("CflOrch", "CflTfc", "CflProxy"))

    def stdlib_only():
        import ast
        tree = ast.parse(progs["fl_proxy"])
        names = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
                {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
        return names - {"__future__"} <= sys.stdlib_module_names
    check("the program uses the standard library only (the workload runs with python3 -I -B and no environment)", stdlib_only)

    def materialised(pkg, cse):
        d = Path(tempfile.mkdtemp(prefix="fl01-pkg-"))
        try:
            out = fp.package_for(APPS / pkg, cse, d / pkg)
            got = mad.verify_package(out)
            return (got["onem2m"]["mnCse"], got["files"], mad.descriptor_digest(out),
                    sorted(x.name for x in out.iterdir()))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    shipped = eager(lambda: {p: _sha((APPS / p / "appd.json").read_bytes()) for p in PKG_BY_HAND})
    m_edge = eager(lambda: materialised("fl_orch", "cse-mn-a"))
    m_tfc = eager(lambda: materialised("fl_tfc", "cse-mn-a"))
    check("package_for sets only the CSE: the orchestrator for edge-only names cse-mn-a, keeps its file digests, "
          "verifies, and so has another checksum than the shipped descriptor",
          lambda: m_edge[0] == "cse-mn-a" and m_edge[1] == json.loads((APPS / "fl_orch/appd.json").read_text())["files"]
          and m_edge[2] != shipped["fl_orch"] and m_edge[3] == ["appd.json", "fl_app.py"])
    check("... and for the CSE the package already names, the copy is byte for byte the shipped package (same checksum)",
          lambda: m_tfc[0] == "cse-mn-a" and m_tfc[2] == shipped["fl_tfc"])
    check("package_for refuses a CSE name the platform does not know",
          lambda: isinstance(_raised(lambda: fp.package_for(APPS / "fl_tfc", "cse-elsewhere", Path("/nonexistent/x"))), ValueError))

    print("== TD_MEC_FL_01 steps 5-6: the proxy's admission rule for a device's plain HTTP/JSON record")
    app = eager(_app_module)
    dev = {"deviceId": "devPx1", "class": "proxy-path", "fields": DEV_FIELDS, "maxBytes": 1024}
    J = "application/json"
    check("a configured device, a JSON object of its fields with an integer t: admitted (0)",
          lambda: app.check_record(b'{"t": 1, "battery_pct": 90, "sim": true}', J, dev)[0] == 0
          and app.check_record(b'{"t": 1}', "application/json; charset=utf-8", dev)[0] == 0)
    check("exactly 1024 bytes is admitted, 1025 is refused with 413 before the body is parsed",
          lambda: app.check_record(b'{"t": 1}' + b" " * 1016, J, dev)[0] == 0
          and app.check_record(b" " * 1025, J, dev)[0] == 413)
    for what, raw, ctype, want in (("not JSON", b"{t:1}", J, 400), ("a JSON array", b"[1]", J, 400),
                                   ("a field that is not configured (a position)", b'{"t": 1, "gps": [48.1, 11.5]}', J, 400),
                                   ("t missing", b'{"battery_pct": 90}', J, 400), ("t a string", b'{"t": "1"}', J, 400),
                                   ("t a boolean", b'{"t": true}', J, 400), ("not UTF-8", b'{"t": 1, "x": "\xff"}', J, 400),
                                   ("another content type", b'{"t": 1}', "text/plain", 415)):
        check(f"refused: {what} ({want})", lambda raw=raw, ctype=ctype, want=want: app.check_record(raw, ctype, dev)[0] == want)
    check("a device that is not configured at the proxy is refused with 403, whatever it sends",
          lambda: app.check_record(b'{"t": 1}', J, None) == (403, "device not configured at this proxy"))
    control("an unconfigured device's record was admitted by the proxy's rule",
            lambda: app.check_record(b'{"t": 1}', J, None)[0] == 0)
    check("what the proxy writes is the body as sent: con is the text, unchanged, and the CSE is asked to record the "
          "creator", lambda: app.cin_body('{"t": 1,  "sim": true}') == {"m2m:cin": {
              "cnf": "application/json:0", "con": '{"t": 1,  "sim": true}', "cr": None}})
    check("the device-profile flexContainer: a dmCapability that cannot train, labelled with the class, the device and "
          "the proxy it goes through",
          lambda: app.profile_body("devPx1", "flProxy") == {"mad:dmCay": {
              "rn": "flCap-devPx1", "cnd": "org.onem2m.management.moduleclass.dmCapability", "name": "fl.localTraining",
              "attad": False, "curSe": False, "lbl": ["fl:profile", "fl:role:device", "fl:class:proxy-path",
                                                      "fl:device:devPx1", "fl:via:flProxy", "fl:sim:true"]}})
    rec0 = {"t": 1_800_000_000_000, "battery_pct": 90, "sim": True}
    check("the simulated device sends what a MicroPython board would: json.dumps of its record, as bytes",
          lambda: fp.device_body(rec0) == b'{"t": 1800000000000, "battery_pct": 90, "sim": true}')
    svc = {"serName": "fl-proxy-path", "transportInfo": {"id": "L2", "endpoint": {"uris": [
        "http://127.0.0.1:5001/cse-mn-a/flProxy", "http://127.0.0.1:6001/devices"]}}}
    check("the device-facing endpoint is the one the proxy publishes at MEC 011 (the URI ending in /devices)",
          lambda: fp.device_endpoint(svc) == "http://127.0.0.1:6001/devices" and fp.device_endpoint(
              {"transportInfo": {"endpoint": {"uris": ["http://127.0.0.1:5001/cse-mn-a/flProxy"]}}}) is None)

    print("== TD_MEC_FL_01: a deployed app, as the platform shows it [step 3; REG_03 step 1]")
    C64, A64 = "c" * 64, "a" * 64
    dep = {"error": None, "checksum": C64, "descriptor_sha256": C64,
           "package": {"operationalState": "ENABLED", "usageState": "IN_USE", "checksum": {"algorithm": "SHA-256", "hash": C64}},
           "instance": {"instantiationState": "INSTANTIATED", "appDId": "d-1"}, "appDId": "d-1", "agent_result": "COMPLETED",
           "op_occs": [["INSTATIATE", "PROCESSING"]], "pid_alive": True,
           "argv": ["/py", "-I", "-B", "/w/packages/p1/fl_app.py", "--instance", "/w/instances/i1/instance.json"],
           "store": "/w/packages/p1", "program": "fl_app.py", "program_sha256": A64, "expected_program_sha256": A64,
           "listed": True,
           # by hand: the instantiate answered 202 at t 10.0 s (monotonic) = 500.000 s (boot clock); the workload's first
           # POST on Mp1 at 10.2 s; its process started at tick 50001 of 100 per second = 500.01 s, not before 500.00
           "lifecycle": {"instantiate_on_wire": [[202, 10.0, 500.0]], "first_mp1_post_t_in": 10.2,
                         "process_start_tick": 50001, "clk_tck": 100}}
    check("onboarded with its checksum, enabled and in use, instantiated through MEC 010-2 (its operation PROCESSING "
          "there, as our candidate leaves it), the agent's own record COMPLETED, the observed order instantiate -> "
          "process -> Mp1, the workload alive and started from the platform's copy, listed at MEC 011",
          lambda: fl.app_deployed(dep)[0])
    check("the row says the MEC 010-2 operation state as read there, not the agent's word for it",
          lambda: "state as read at MEC 010-2: FAILED" in fl.app_deployed({**dep, "op_occs": [["INSTATIATE", "FAILED"]]})[1]
          and "the agent's own record" in fl.app_deployed({**dep, "agent_result": None})[1])
    lc = dep["lifecycle"]
    for what, change in (("no instantiate on the agent's wire to MEC 010-2 (the workload started by hand)",
                          {**lc, "instantiate_on_wire": []}),
                         ("the instantiate refused (409)", {**lc, "instantiate_on_wire": [[409, 10.0, 500.0]]}),
                         ("two instantiate requests", {**lc, "instantiate_on_wire": [[202, 10.0, 500.0]] * 2}),
                         ("the process started a tick before MEC 010-2 answered", {**lc, "process_start_tick": 49999}),
                         ("the workload spoke on Mp1 before the instantiate was answered", {**lc, "first_mp1_post_t_in": 9.9}),
                         ("no start time in /proc (the process is gone)", {**lc, "process_start_tick": None}),
                         ("no clock unit", {**lc, "clk_tck": 0})):
        check(f"... not deployed with {what}", lambda change=change: not fl.app_deployed({**dep, "lifecycle": change})[0])
    check("... while a start in the same 10 ms tick as the answer is taken (the resolution /proc gives)",
          lambda: fl.app_deployed({**dep, "lifecycle": {**lc, "process_start_tick": 50000}})[0]
          and not fl.app_deployed({**dep, "lifecycle": {**lc, "instantiate_on_wire": [[202, 10.0, 500.5]]}})[0])
    control("an app the agent says it instantiated, with no instantiate on its wire to MEC 010-2, was taken as deployed",
            lambda: fl.app_deployed({**dep, "lifecycle": {**lc, "instantiate_on_wire": []}})[0])
    for what, change in (("a deployment error", {"error": "refused"}), ("another checksum at app_pkgm", {"checksum": "b" * 64}),
                         ("the package disabled", {"package": {**dep["package"], "operationalState": "DISABLED"}}),
                         ("the package not in use", {"package": {**dep["package"], "usageState": "NOT_IN_USE"}}),
                         ("the instance not instantiated", {"instance": {**dep["instance"], "instantiationState": "NOT_INSTANTIATED"}}),
                         ("an instance of another package", {"instance": {**dep["instance"], "appDId": "d-2"}}),
                         ("the agent's operation failed", {"agent_result": "FAILED"}),
                         ("no instantiate operation at MEC 010-2 (the lifecycle was bypassed)", {"op_occs": []}),
                         ("the instantiate FAILED at MEC 010-2", {"op_occs": [["INSTATIATE", "FAILED"]]}),
                         ("two operations at MEC 010-2", {"op_occs": [["INSTATIATE", "PROCESSING"]] * 2}),
                         ("the workload gone", {"pid_alive": False}),
                         ("a program from outside the platform's copy", {"argv": [*dep["argv"][:3], "/opt/elsewhere/fl_app.py", *dep["argv"][4:]]}),
                         ("a runtime without -I", {"argv": ["/py", "-B", "-B", *dep["argv"][3:]]}),
                         ("a program whose digest is not the shipped one", {"program_sha256": "b" * 64}),
                         ("not listed at MEC 011", {"listed": False})):
        check(f"... not deployed with {what}", lambda change=change: not fl.app_deployed({**dep, **change})[0])

    print("== TD_MEC_REG_03 for an app's AE: steps 2 to 6, read off the wire and the CSE")
    r3 = {"origin": "CflOrch", "cse": "cse-in", "cse_ri": "id-in", "rn": "flOrch", "api": "Nestimed.fl",
          "creates": [{"path": "/cse-in", "origin": "CflOrch", "status": 201, "rsc": 2001, "aei": "CflOrch"}],
          "ae": {"ty": 2, "rn": "flOrch", "api": "Nestimed.fl", "aei": "CflOrch", "pi": "id-in", "acpi": ["acp1"],
                 "lbl": ["fl:participant", "fl:role:orchestrator", "fl:sim:true", "mec:appInstanceId:M1", "mec:lcmInstanceId:L1"]},
          "acp": {"ri": "acp1", "pv": {"acr": [{"acor": ["CflOrch"], "acop": 63}, {"acor": ["CflTfc"], "acop": 34}]},
                  "pvs": {"acr": [{"acor": ["CflOrch"], "acop": 63}]}},
          "readers": ["CflTfc"], "reader_ops": 34, "container_rn": "ops",
          "container": {"ty": 3, "rn": "ops", "cr": "CflOrch", "acpi": ["acp1"]},
          "mp1_posts": [["registrations", 201], ["services", 201], ["confirm_ready", 204]],
          "confirm_after_writes": True, "mid": "M1", "lcm": "L1", "stranger": [403, 403, 403]}
    check("one AE Create from the workload to the CSE, 2001, aei the originator; the AE with both instance ids, its "
          "least-privilege ACP, the baseline container it created; Mp1 in order, ready only after its writes; a "
          "stranger reads nothing", lambda: fl.reg03_ae(r3)[0])
    for what, change in (("no AE Create on the workload's wire (the driver made the AE)", {"creates": []}),
                         ("two AE Creates", {"creates": r3["creates"] * 2}),
                         ("the Create under another originator", {"creates": [{**r3["creates"][0], "origin": "CAdmin"}]}),
                         ("rsc 2000", {"creates": [{**r3["creates"][0], "rsc": 2000}]}),
                         ("another AE-ID", {"creates": [{**r3["creates"][0], "aei": "Cother"}]}),
                         ("the AE on another CSE", {"ae": {**r3["ae"], "pi": "id-mn-a"}}),
                         ("no lcm instance id on the AE", {"ae": {**r3["ae"], "lbl": r3["ae"]["lbl"][:-1]}}),
                         ("the AE governed by another policy", {"ae": {**r3["ae"], "acpi": ["acp2"]}}),
                         ("readers given every right", {"acp": {**r3["acp"], "pv": {"acr": [{"acor": ["CflOrch"], "acop": 63},
                                                                                          {"acor": ["CflTfc"], "acop": 63}]}}}),
                         ("a reader too many", {"acp": {**r3["acp"], "pv": {"acr": [{"acor": ["CflOrch"], "acop": 63},
                                                                                    {"acor": ["CflTfc", "Cx"], "acop": 34}]}}}),
                         ("another originator may change the policy (pvs)", {"acp": {**r3["acp"], "pvs": {"acr": [
                             {"acor": ["CflOrch", "Cx"], "acop": 63}]}}}),
                         ("no self-privileges read back", {"acp": {k: v for k, v in r3["acp"].items() if k != "pvs"}}),
                         ("the baseline container created by someone else", {"container": {**r3["container"], "cr": "CAdmin"}}),
                         ("no confirm_ready", {"mp1_posts": r3["mp1_posts"][:2]}),
                         ("ready before its writes", {"confirm_after_writes": False}),
                         ("a stranger read something", {"stranger": [403, 200, 403]})):
        check(f"... fails with {what}", lambda change=change: not fl.reg03_ae({**r3, **change})[0])
    control("an app's policy that another originator may change was taken for REG_03's least-privilege policy",
            lambda: fl.reg03_ae({**r3, "acp": {**r3["acp"], "pvs": {"acr": [{"acor": ["CflOrch", "Cx"], "acop": 63}]}}})[0])

    print("== TD_MEC_FL_01 step 4: registered at the MN-CSE on behalf of the constrained devices")
    ob = {"represents": ["flSrc1", "flSrc2"], "lcm": "L1", "mid": "M1", "ae_cse": "cse-mn-a", "expect_cse": "cse-mn-a",
          "ae_labels": ["fl:participant", "fl:role:tfc", "fl:sim:true", "fl:represents:flSrc1", "fl:represents:flSrc2",
                        "mec:appInstanceId:M1", "mec:lcmInstanceId:L1"],
          "sources": {"flSrc1": 201, "flSrc2": 201}, "binding_creator": "CflTfc", "client": "CflTfc",
          "binding": {"client": "CflTfc", "represents": ["flSrc1", "flSrc2"], "lcmInstanceId": "L1",
                      "mec011AppInstanceId": "M1", "sim": True}}
    check("the client's AE names each source it acts for and both instance ids; the sources are registered there; the "
          "client itself wrote the binding record", lambda: fl.fl01_4_on_behalf(ob)[0])
    for what, change in (("a source not named on the AE", {"ae_labels": [x for x in ob["ae_labels"] if x != "fl:represents:flSrc2"]}),
                         ("a source not registered", {"sources": {"flSrc1": 201, "flSrc2": 404}}),
                         ("the binding naming one source", {"binding": {**ob["binding"], "represents": ["flSrc1"]}}),
                         ("the binding naming another instance", {"binding": {**ob["binding"], "lcmInstanceId": "L9"}}),
                         ("the binding written by someone else", {"binding_creator": "CAdmin"}),
                         ("the AE on another CSE than the sources'", {"ae_cse": "cse-mn-b"})):
        check(f"... fails with {what}", lambda change=change: not fl.fl01_4_on_behalf({**ob, **change})[0])

    print("== TD_MEC_FL_01 steps 5 and 6: the MEC proxy path")
    p5 = {"deployed": (True, "ok"), "origin": "CflProxy", "rn": "flProxy", "lcm": "L2", "devices": ["devPx1"],
          "service": svc, "config_creator": "CflProxy",
          "config": {"proxy": "CflProxy", "devices": [{"deviceId": "devPx1", "class": "proxy-path"}],
                     "endpoint": "http://127.0.0.1:6001/devices", "lcmInstanceId": "L2"},
          "containers": {"devPx1": {"ty": 3, "rn": "devPx1", "cr": "CflProxy", "acpi": ["acpD"]}},
          "profiles": {"devPx1": {"ty": 28, "attad": False, "lbl": ["fl:profile", "fl:role:device", "fl:class:proxy-path",
                                                                    "fl:device:devPx1", "fl:via:flProxy", "fl:sim:true"]}},
          # by hand: the proxy's data policy as the CSE answers a read of it: the proxy everything (63), its checker
          # RETRIEVE + DISCOVERY (34), only the proxy may change it; what it must say is the driver's (FL01_APPS)
          "data_acp": {"ri": "acpD", "rn": "flDataAcp", "pv": {"acr": [{"acor": ["CflProxy"], "acop": 63},
                                                                      {"acor": ["CflProxyCheck"], "acop": 34}]},
                       "pvs": {"acr": [{"acor": ["CflProxy"], "acop": 63}]}},
          "data_acp_rn": "flDataAcp", "data_readers": ["CflProxyCheck"], "data_ops": 34}
    p5["service"] = {**svc, "transportInfo": {**svc["transportInfo"], "id": "L2"}}
    check("step 5: the proxy app is deployed, publishes a device endpoint at MEC 011, states its configuration in the "
          "tree, holds a container and a proxy-path profile per configured device, and its data policy, read back, is "
          "what it must be and governs the device container", lambda: fl.fl01_5_proxy_path(p5)[0])
    dacp = p5["data_acp"]
    for what, change in (("its data policy not readable (404)", {"data_acp": None}),
                         ("a data policy of another name", {"data_acp": {**dacp, "rn": "flMetaAcp"}}),
                         ("the device given a way around the proxy (all may create)", {"data_acp": {**dacp, "pv": {"acr": [
                             {"acor": ["CflProxy"], "acop": 63}, {"acor": ["CflProxyCheck", "all"], "acop": 35}]}}}),
                         ("the checker given every right", {"data_acp": {**dacp, "pv": {"acr": [
                             {"acor": ["CflProxy"], "acop": 63}, {"acor": ["CflProxyCheck"], "acop": 63}]}}}),
                         ("the orchestrator among the data readers", {"data_acp": {**dacp, "pv": {"acr": [
                             {"acor": ["CflProxy"], "acop": 63}, {"acor": ["CflProxyCheck", "CflOrch"], "acop": 34}]}}}),
                         ("another originator may change the data policy", {"data_acp": {**dacp, "pvs": {"acr": [
                             {"acor": ["CflProxy", "CdevPx1"], "acop": 63}]}}}),
                         ("the device container under another policy", {"containers": {"devPx1": {
                             **p5["containers"]["devPx1"], "acpi": ["acpMeta"]}}}),
                         ("the device container under two policies", {"containers": {"devPx1": {
                             **p5["containers"]["devPx1"], "acpi": ["acpD", "acpMeta"]}}}),
                         ("a proxy-path profile that claims it can train", {"profiles": {"devPx1": {
                             **p5["profiles"]["devPx1"], "attad": True}}})):
        check(f"... step 5 fails with {what}", lambda change=change: not fl.fl01_5_proxy_path({**p5, **change})[0])
    control("a proxy data policy that lets anyone create in the device container was taken as configured",
            lambda: fl.fl01_5_proxy_path({**p5, "data_acp": {**dacp, "pv": {"acr": [
                {"acor": ["CflProxy"], "acop": 63}, {"acor": ["CflProxyCheck", "all"], "acop": 35}]}}})[0])
    control("a proxy-path profile that can train was taken for the proxy path's",
            lambda: fl.fl01_5_proxy_path({**p5, "profiles": {"devPx1": {**p5["profiles"]["devPx1"], "attad": True}}})[0])
    for what, change in (("the app not deployed", {"deployed": (False, "not listed")}),
                         ("no device endpoint published", {"service": {**svc, "transportInfo": {"id": "L2", "endpoint": {"uris": [
                             "http://127.0.0.1:5001/cse-mn-a/flProxy"]}}}}),
                         ("the service of another instance", {"service": {**svc, "transportInfo": {**svc["transportInfo"], "id": "L9"}}}),
                         ("a configuration naming no device", {"config": {**p5["config"], "devices": []}}),
                         ("the configuration written by someone else", {"config_creator": "CAdmin"}),
                         ("no container for the device", {"containers": {}}),
                         ("the device container made by someone else", {"containers": {"devPx1": {"ty": 3, "rn": "devPx1", "cr": "CAdmin"}}}),
                         ("a profile of another class", {"profiles": {"devPx1": {**p5["profiles"]["devPx1"], "lbl": [
                             "fl:profile", "fl:class:fl-native", "fl:device:devPx1", "fl:via:flProxy"]}}}),
                         ("a profile that does not name the proxy", {"profiles": {"devPx1": {**p5["profiles"]["devPx1"], "lbl": [
                             "fl:profile", "fl:class:proxy-path", "fl:device:devPx1"]}}})):
        check(f"... step 5 fails with {what}", lambda change=change: not fl.fl01_5_proxy_path({**p5, **change})[0])
    sent = ['{"t": 1, "battery_pct": 90, "sim": true}', '{"t": 5001, "battery_pct": 89, "sim": true}']
    b6 = {"origin": "CflProxy", "sent": sent, "answers": [201, 201], "wire": list(sent),
          "stored": [{"ty": 4, "con": sent[0], "cr": "CflProxy"}, {"ty": 4, "con": sent[1], "cr": "CflProxy"}]}
    check("step 6: every record the device sent is in the tree as sent, in order, created by the proxy",
          lambda: fl.fl01_6_bridged(b6)[0])
    resorted = '{"battery_pct": 90, "sim": true, "t": 1}'          # the same values, keys sorted: not as sent
    for what, change in (("one record re-serialised", {"stored": [{**b6["stored"][0], "con": resorted}, b6["stored"][1]]}),
                         ("the two in the other order", {"stored": b6["stored"][::-1]}),
                         ("one answer 403", {"answers": [201, 403]}),
                         ("one created by someone else", {"stored": [b6["stored"][0], {**b6["stored"][1], "cr": "CAdmin"}]}),
                         ("one missing", {"stored": b6["stored"][:1]}),
                         ("the proxy sent the CSE something else than it stored", {"wire": [sent[0], resorted]})):
        check(f"... step 6 fails with {what}", lambda change=change: not fl.fl01_6_bridged({**b6, **change})[0])
    control("a record the proxy re-serialised (same values, keys in another order) was taken as the data as sent",
            lambda: fl.fl01_6_bridged({**b6, "stored": [{**b6["stored"][0], "con": resorted}, b6["stored"][1]], "wire": [resorted, sent[1]]})[0])
    rf = {"answer": 403, "creates": 0, "before": ["a", "b"], "after": ["a", "b"]}
    check("an unconfigured device: the proxy answers 403, sends nothing to the CSE, and the proxy's tree is unchanged",
          lambda: fl.fl01_6_refused(rf)[0] and not fl.fl01_6_refused({**rf, "answer": 502})[0]
          and not fl.fl01_6_refused({**rf, "creates": 1})[0] and not fl.fl01_6_refused({**rf, "after": ["a", "b", "c"]})[0])
    nb = {"plain": 400, "own_origin": 403, "before": 3, "after": 3}
    check("without the proxy the device writes nothing: its plain JSON and its oneM2M Create under its own originator "
          "are both refused, and the container holds as many records as before",
          lambda: fl.fl01_6_no_bypass(nb)[0] and not fl.fl01_6_no_bypass({**nb, "own_origin": 201})[0]
          and not fl.fl01_6_no_bypass({**nb, "plain": 201})[0] and not fl.fl01_6_no_bypass({**nb, "after": 4})[0]
          and not fl.fl01_6_no_bypass({**nb, "plain": 0})[0])

    print("== TD_MEC_FL_01 step 7: the orchestrator enumerates candidates of the three classes")
    P = lambda ae, rn, lbl, attad=False: {"ref": f"cse-mn-a/{ae}/{rn}", "labels": ["fl:profile", *lbl], "attad": attad}  # noqa: E731
    profiles = [P("flNat", "flCap", ["fl:role:client", "fl:class:fl-native", "fl:sim:true"], True),
                P("flDec", "flCap", ["fl:role:client", "fl:class:fl-native", "fl:sim:true"], True),
                P("flSrc1", "flCap", ["fl:role:data-source", "fl:class:fl-assisted", "fl:sim:true"]),
                P("flSrc2", "flCap", ["fl:role:data-source", "fl:class:fl-assisted", "fl:sim:true"]),
                P("flTfc", "flCap", ["fl:role:tfc", "fl:class:trusted-fl-client", "fl:sim:true"], True),
                P("flProxy", "flCap-devPx1", ["fl:role:device", "fl:class:proxy-path", "fl:device:devPx1", "fl:via:flProxy"]),
                P("flStray", "flCap-other", ["fl:class:fl-other", "fl:device:devOther"], True),
                P("flStray", "flCap-src3", ["fl:class:fl-assisted", "fl:device:flSrc3"]),
                P("flStray", "flCap-ghost", ["fl:class:proxy-path", "fl:device:devGhost", "fl:via:flStray"])]
    stray = ["cse-mn-a/flStray/flCap-other", "cse-mn-a/flStray/flCap-src3", "cse-mn-a/flStray/flCap-ghost"]
    apps = {"flTfc": ["fl:participant", "fl:role:tfc", "fl:represents:flSrc1", "fl:represents:flSrc2",
                      "mec:appInstanceId:M1", "mec:lcmInstanceId:L1"],
            "flProxy": ["fl:proxy", "fl:role:proxy", "mec:appInstanceId:M2", "mec:lcmInstanceId:L2"],
            "flStray": ["fl:role:proxy", "fl:role:tfc", "fl:represents:flSrc3", "mec:lcmInstanceId:L2"],   # claims L2
            "flNat": ["fl:participant"], "flDec": ["fl:participant"], "flSrc1": [], "flSrc2": []}
    S = lambda lcm, mid, *uris, name="s": {"serName": name, "transportInfo": {"id": lcm, "endpoint": {"uris": list(uris)}},  # noqa: E731
                                          "_links": {"self": {"href": f"/mec_service_mgmt/v1/applications/{mid}/services/x"}}}
    services = [S("L1", "M1", "http://r:1/cse-mn-a/flTfc", name="trusted-fl-client"),
                S("L2", "M2", "http://r:1/cse-mn-a/flProxy", "http://127.0.0.1:6001/devices", name="fl-proxy-path")]
    # What MEC 010-2 lists (by hand): the client's instance L1 and the proxy's L2, INSTANTIATED, each of an ENABLED
    # package whose checksum there is the SHA-256 of the shipped descriptor (both packages name cse-mn-a as shipped)
    raw_t, raw_p = (eager(lambda k=k: (APPS / k / "appd.json").read_bytes()) for k in ("fl_tfc", "fl_proxy"))
    H_T, H_P = (eager(lambda r=r: _sha(r)) for r in (raw_t, raw_p))
    plat7 = eager(lambda: {
        "instances": [{"id": "L0", "appDId": "d-orch", "instantiationState": "INSTANTIATED"},
                      {"id": "L1", "appDId": "d-tfc", "instantiationState": "INSTANTIATED"},
                      {"id": "L2", "appDId": "d-px", "instantiationState": "INSTANTIATED"}],
        "packages": [{"id": "p-t", "appDId": "d-tfc", "checksum": {"algorithm": "SHA-256", "hash": H_T}, "operationalState": "ENABLED"},
                     {"id": "p-p", "appDId": "d-px", "checksum": {"algorithm": "SHA-256", "hash": H_P}, "operationalState": "ENABLED"}],
        "descriptors": {H_T: json.loads(raw_t), H_P: json.loads(raw_p)}})
    want_classes = {"fl-native": ["flDec", "flNat"], "fl-assisted": ["flSrc1", "flSrc2"], "proxy-path": ["devPx1"]}
    en = eager(lambda: fl.enumerate_candidates(profiles, apps, services, plat7))
    E7 = lambda prof=None, ap=None, sv=None, pl=None: fl.enumerate_candidates(  # noqa: E731
        profiles if prof is None else prof, apps if ap is None else ap, services if sv is None else sv, plat7 if pl is None else pl)
    named7 = lambda e: sum(e["classes"].values(), [])  # noqa: E731
    check("by hand: FL-native flDec and flNat; FL-assisted flSrc1 and flSrc2 (through flTfc); proxy-path devPx1 "
          "(through flProxy); the Trusted FL Client is a helper, not a device",
          lambda: en["classes"] == want_classes and en["via"] == {"flSrc1": "flTfc", "flSrc2": "flTfc", "devPx1": "flProxy"}
          and en["helpers"] == ["cse-mn-a/flTfc/flCap"])
    check("the three stray profiles are refused, each for its reason (the copied instance L2 is the proxy package's at "
          "MEC 010-2, and that descriptor names flProxy, not flStray)",
          lambda: {r["ref"]: r["why"] for r in en["refused"]} == {
              "cse-mn-a/flStray/flCap-other": "not one of the three device classes",
              "cse-mn-a/flStray/flCap-src3": "no deployed Trusted FL Client represents it (flStray: the package of instance "
                                             "L2 does not name flStray on cse-mn-a as a tfc for flSrc3)",
              "cse-mn-a/flStray/flCap-ghost": "its proxy app is not deployed (the package of instance L2 does not name "
                                              "flStray on cse-mn-a as a proxy for devGhost)"})
    control("a device of none of the three classes was enumerated", lambda: "devOther" in named7(E7()))
    control("a constrained device no deployed Trusted FL Client represents was enumerated",
            lambda: "flSrc3" in E7()["classes"]["fl-assisted"])
    control("a proxy-path device whose holder only claims a deployed instance (the endpoint MEC 011 lists is another AE's) "
            "was enumerated", lambda: "devGhost" in E7()["classes"]["proxy-path"])
    # The reviewer's two strays (2026-11-20, stray7.py), each registered at MEC 011 by itself and listed there:
    # (b) an invented instance id Lfake that MEC 010-2 never saw; (c) the proxy's L2, copied, with its own service
    selfp = P("flStray2", "flCap-self", ["fl:class:proxy-path", "fl:device:devSelf", "fl:via:flStray2"])
    apps_b = {**apps, "flStray2": ["fl:role:proxy", "mec:lcmInstanceId:Lfake", "mec:appInstanceId:M4"]}
    svc_b = [*services, S("Lfake", "M4", "http://anything/cse-mn-a/flStray2")]
    apps_c = {**apps, "flStray": ["fl:role:proxy", "fl:role:tfc", "fl:represents:flSrc3", "mec:lcmInstanceId:L2",
                                  "mec:appInstanceId:M3"]}
    svc_c = [*services, S("L2", "M3", "http://anything/cse-mn-a/flStray")]
    check("stray (b): self-registered at MEC 011 under an instance id it made up, listed there with its own AE as the "
          "endpoint; MEC 010-2 lists no such instance, so it is refused",
          lambda: (lambda e: "devSelf" not in named7(e) and e["classes"] == want_classes and {r["ref"]: r["why"] for r in e["refused"]}[
              "cse-mn-a/flStray2/flCap-self"] == "its proxy app is not deployed (MEC 010-2 lists no INSTANTIATED instance Lfake)")(
              E7([*profiles, selfp], apps_b, svc_b)))
    check("stray (c): copies the proxy's instance id L2 and offers its own MEC 011 service under it, naming itself and "
          "the MEC 011 instance it names; L2's package names flProxy, so neither its device nor flSrc3 is taken",
          lambda: (lambda e: not {"devGhost", "flSrc3"} & set(named7(e)) and e["classes"] == want_classes)(
              E7(None, apps_c, svc_c)))
    control("a stray self-registered at MEC 011 under a made-up instance id (never through MEC 010-2) was enumerated",
            lambda: "devSelf" in named7(E7([*profiles, selfp], apps_b, svc_b)))
    control("a stray that copies the proxy's instance id and offers its own MEC 011 service under it was enumerated",
            lambda: bool({"devGhost", "flSrc3"} & set(named7(E7(None, apps_c, svc_c)))))
    check("... and the MEC 011 listing alone is not enough: with the same strays and MEC 010-2 listing nothing, no app "
          "is deployed, so no constrained or proxy-path device is enumerated (FL-native ones still are)",
          lambda: (lambda e: e["classes"] == {"fl-native": ["flDec", "flNat"], "fl-assisted": [], "proxy-path": []})(
              E7([*profiles, selfp], {**apps_b, **{"flStray": apps_c["flStray"]}}, [*svc_b, svc_c[-1]],
                 {**plat7, "instances": [], "packages": []})))
    pl = plat7
    for what, pl_x, ap_x, sv_x, lost in (
            ("the proxy's instance NOT_INSTANTIATED at MEC 010-2",
             {**pl, "instances": [{**i, "instantiationState": "NOT_INSTANTIATED"} if i["id"] == "L2" else i for i in pl["instances"]]},
             None, None, "proxy-path"),
            ("the proxy's instance missing at MEC 010-2", {**pl, "instances": [i for i in pl["instances"] if i["id"] != "L2"]},
             None, None, "proxy-path"),
            ("the proxy's package DISABLED", {**pl, "packages": [{**p, "operationalState": "DISABLED"} if p["id"] == "p-p" else p
                                                                for p in pl["packages"]]}, None, None, "proxy-path"),
            ("the client's package checksum not the SHA-256 of any descriptor known",
             {**pl, "packages": [{**p, "checksum": {"hash": "0" * 64}} if p["id"] == "p-t" else p for p in pl["packages"]]},
             None, None, "fl-assisted"),
            ("the proxy package's descriptor naming another device",
             {**pl, "descriptors": {**pl["descriptors"], H_P: {**pl["descriptors"][H_P], "fl": {
                 **pl["descriptors"][H_P]["fl"], "devices": [{"deviceId": "devPx2"}]}}}}, None, None, "proxy-path"),
            ("the client's descriptor of another role",
             {**pl, "descriptors": {**pl["descriptors"], H_T: {**pl["descriptors"][H_T], "fl": {
                 **pl["descriptors"][H_T]["fl"], "role": "proxy"}}}}, None, None, "fl-assisted"),
            ("the proxy's AE naming another MEC 011 instance than the one that offers its service", None,
             {**apps, "flProxy": ["fl:proxy", "fl:role:proxy", "mec:appInstanceId:M9", "mec:lcmInstanceId:L2"]}, None, "proxy-path"),
            ("the proxy's service listed with another AE as its endpoint", None, None,
             [services[0], S("L2", "M2", "http://r:1/cse-mn-a/flOther", "http://127.0.0.1:6001/devices")], "proxy-path"),
            ("the proxy's service gone from MEC 011 (not ready)", None, None, services[:1], "proxy-path"),
            ("the client's service gone from MEC 011", None, None, services[1:], "fl-assisted")):
        check(f"... {lost} not enumerated with {what}",
              lambda pl_x=pl_x, ap_x=ap_x, sv_x=sv_x, lost=lost: (lambda e: e["classes"][lost] == [] and all(
                  e["classes"][k] == want_classes[k] for k in want_classes if k != lost))(E7(None, ap_x, sv_x, pl_x)))
    check("the client's descriptor naming flSrc1 only: flSrc2 is not enumerated through it, flSrc1 still is (the "
          "device must be in the package MEC 010-2 holds, not only on the AE's labels)",
          lambda: E7(None, None, None, {**pl, "descriptors": {**pl["descriptors"], H_T: {**pl["descriptors"][H_T], "fl": {
              **pl["descriptors"][H_T]["fl"], "represents": ["flSrc1"]}}}})["classes"] == {**want_classes, "fl-assisted": ["flSrc1"]})
    check("an FL-native profile that cannot train is refused, not enumerated",
          lambda: (lambda e: e["classes"]["fl-native"] == ["flDec"] and {r["ref"]: r["why"] for r in e["refused"]}[
              "cse-mn-a/flNat/flCap"] == "an FL-native profile that cannot train")(
              E7([P("flNat", "flCap", ["fl:class:fl-native"], False), *profiles[1:]])))
    control("an FL-native profile that cannot train was enumerated",
            lambda: "flNat" in E7([P("flNat", "flCap", ["fl:class:fl-native"], False), *profiles[1:]])["classes"]["fl-native"])
    for what, lbl in (("that names no proxy", ["fl:class:proxy-path", "fl:device:devPx3"]),
                      ("that names another AE as its proxy", ["fl:class:proxy-path", "fl:device:devPx3", "fl:via:flOther"])):
        check(f"a proxy-path profile held by the deployed proxy {what} is refused: it must name its holder (fl:via)",
              lambda lbl=lbl: (lambda e: "devPx3" not in named7(e) and {r["ref"]: r["why"] for r in e["refused"]}[
                  "cse-mn-a/flProxy/flCap-devPx3"] == "its profile does not name its holder as its proxy")(
                  E7([*profiles, P("flProxy", "flCap-devPx3", lbl)])))
    control("a proxy-path profile that does not name its proxy was enumerated",
            lambda: "devPx3" in named7(E7([*profiles, P("flProxy", "flCap-devPx3", ["fl:class:proxy-path", "fl:device:devPx3"])])))
    check("a profile with two class labels is refused, not taken for either",
          lambda: E7([P("flNat", "flCap", ["fl:class:fl-native", "fl:class:proxy-path"], True)])[
              "classes"] == {"fl-native": [], "fl-assisted": [], "proxy-path": []})
    o7 = {"classes": want_classes, "expect": want_classes, "refused": en.get("refused") if isinstance(en, dict) else None,
          "stray": stray, "found": [p["ref"] for p in profiles], "profiles": {p["ref"]: p["labels"] for p in profiles},
          "stray_listed": {"flStray": True, "flStray2": True}}
    check("step 7: the three classes as expected, each stray profile was discovered and refused, each stray was listed "
          "at MEC 011, and discovery returned capability profiles only", lambda: fl.fl01_7_candidates(o7)[0])
    for what, change in (("a class missing", {"classes": {**want_classes, "proxy-path": []}}),
                         ("one more candidate than expected", {"classes": {**want_classes, "fl-native": ["flDec", "flNat", "flX"]}}),
                         # found and profiles both without the ghost, so that only the 'discovered' condition can fail
                         ("a stray not discovered (its control would prove nothing)", {"found": [p["ref"] for p in profiles[:-1]],
                                                                                        "profiles": {p["ref"]: p["labels"] for p in profiles[:-1]}}),
                         ("a stray enumerated", {"refused": [r for r in o7["refused"] or [] if not r["ref"].endswith("ghost")]}),
                         ("a stray not listed at MEC 011 (MEC 011 alone would not have taken it either)",
                          {"stray_listed": {"flStray": True, "flStray2": False}}),
                         ("no stray listing read", {"stray_listed": {}}),
                         ("discovery returned a resource without the profile label",
                          {"profiles": {**o7["profiles"], "cse-mn-a/flNat/flCompute": []}, "found": [*o7["found"], "cse-mn-a/flNat/flCompute"]})):
        check(f"... step 7 fails with {what}", lambda change=change: not fl.fl01_7_candidates({**o7, **change})[0])

    print("== TD_MEC_FL_01 in the driver: names, expectations, verdict, what it does not show")
    check("the proxy and the two stray AEs of the fixture have their own originators and are not in OWNER (so the "
          "leftover places of the three modes stay as they were)",
          lambda: fr.FL01_OWNER == {"flProxy": "CflProxy", "flStray": "CflStray", "flStray2": "CflStray2"}
          and not set(fr.FL01_OWNER) & set(fr.OWNER) and fr.STRAYS == ("flStray", "flStray2"))
    check("the live fixture holds the strays of the offline rows: flStray copies the proxy's id (three profiles: none of "
          "the classes, flSrc3, devGhost), flStray2 made its own up (devSelf); one CONTROL per stray device",
          lambda: {ae: sorted(v) for ae, v in fr.FL01_STRAY.items()} == {
              "flStray": ["flCap-ghost", "flCap-other", "flCap-src3"], "flStray2": ["flCap-self"]}
          and "fl:via:flStray2" in fr.FL01_STRAY["flStray2"]["flCap-self"]
          and sorted(fr.STRAY_DEVICES) == ["devGhost", "devOther", "devSelf", "flSrc3"])
    check("the classes the run must enumerate are written in the driver, by hand: the same as above",
          lambda: fr.FL01_EXPECT == want_classes)
    # by hand: what each app's AE must look like is the driver's (FL01_APPS), not read from the package; a package
    # that widened its own policy would otherwise check itself (planted fault L13, 2026-11-20, survived before this)
    check("what each deployed app must have made is held by the driver, by hand: originators, names, App-IDs, baseline "
          "containers, readers with RETRIEVE + DISCOVERY (34), the client's two sources, the proxy's one device",
          lambda: fr.FL01_APPS == {
              "fl_orch": {"ae": "flOrch", "origin": "CflOrch", "api": "Nestimed.fl", "container": "ops",
                          "readers": ["CflTfc", "CflTfc2", "CflNat", "CflDec", "CflAgg"], "ops": 34},
              "fl_tfc": {"ae": "flTfc", "origin": "CflTfc", "api": "Nestimed.fl", "container": "flMeta",
                         "readers": ["CflOrch", "CflAgg", "CflAuthA", "CflAuthB"], "ops": 34, "represents": ["flSrc1", "flSrc2"]},
              "fl_proxy": {"ae": "flProxy", "origin": "CflProxy", "api": "Nestimed.flproxy", "container": "flConfig",
                           "readers": ["CflOrch", "CflProxyCheck"], "ops": 34, "devices": ["devPx1"],
                           "data_acp": {"rn": "flDataAcp", "readers": ["CflProxyCheck"], "ops": 34}}})
    check("... and each shipped package says the same (else the clean run could not pass)",
          lambda: all((lambda d, x: (d["onem2m"]["originator"], d["onem2m"]["rn"], d["onem2m"]["api"], d["onem2m"]["container"],
                                     d["onem2m"]["acp"]["readers"], d["fl"]["readerOps"]) == (
              x["origin"], x["ae"], x["api"], x["container"], x["readers"], x["ops"]))(
              json.loads((APPS / k / "appd.json").read_text()), fr.FL01_APPS[k]) for k in ("fl_orch", "fl_tfc", "fl_proxy")))
    steps = {f"step {i}": True for i in range(1, 8)} | {"pre-condition REG_03 (orchestrator)": True}
    check("FL_01's verdict: PARTIAL when every step and the pre-condition passed (the devices are simulated), FAIL "
          "when one did not or is missing; never PASS",
          lambda: fr.fl01_verdict(steps) == "PARTIAL" and fr.fl01_verdict({**steps, "step 6": False}) == "FAIL"
          and fr.fl01_verdict({k: v for k, v in steps.items() if k != "step 3"}) == "FAIL")
    control("TD_MEC_FL_01 was called PASS with simulated devices", lambda: fr.fl01_verdict(steps) == "PASS")
    check("the record says what this does not show: simulated devices, processes on one host without a container, "
          "our own MEC candidates, not a conformance claim",
          lambda: all(any(w in line for line in fr.FL01_NOT_SHOWN) for w in (
              "simulated", "one host", "no container", "our own MEC", "not a conformance claim")))
    # by hand, the caveats this row's review asked for (2026-11-20): each must stay in what the record does not show
    for what, words in (("the orchestrator's AE on the IN-CSE in centralised and hierarchical mode, not REG_03 as worded",
                         ("its AE registers to the IN-CSE (MEC_CFG_03), not to an MN-CSE", "not a REG_03 pass")),
                        ("REG_01 and REG_02 not re-run", ("TD_MEC_REG_01 and TD_MEC_REG_02", "not re-run here")),
                        ("MEC 011 registration unauthenticated in our candidate",
                         ("registration at our MEC 011 candidate is unauthenticated", "takes 'deployed' from MEC 010-2")),
                        ("MEC 010-2 unauthenticated too", ("an authenticated MEC 010-2", "not who did it")),
                        ("the instantiate left PROCESSING at MEC 010-2; 'completed' the agent's record",
                         ("leaves it PROCESSING", "the agent's own record", "observed"))):
        check(f"not_shown says: {what}", lambda words=words: any(all(w in line for w in words) for line in fr.FL01_NOT_SHOWN))

    print("== TD_MEC_FL_01 pre-condition: what holds when the orchestrator's AE is on cse-in [REG_03 names the MN-CSE]")
    check("REG_03 rows for an AE on cse-in are named as REG_03's procedure on cse-in, not REG_03; on an MN-CSE they are REG_03",
          lambda: fr.reg03_tag("cse-in") == "REG_03 procedure on cse-in (not the MN-CSE the test plan names)"
          and fr.reg03_tag("cse-mn-a") == "REG_03")
    check("the pre-condition's value on cse-in says what holds and cannot be read as a REG_03 pass; on an MN-CSE it is "
          "a pass there; both name REG_01 and REG_02 as not re-run",
          lambda: fr.reg03_scope("cse-in", True).startswith("PASS for REG_03's procedure on cse-in, not REG_03 as worded")
          and fr.reg03_scope("cse-mn-a", True) == "PASS on cse-mn-a, the MN-CSE REG_03 names; REG_01 and REG_02 not re-run here"
          and "REG_01 and REG_02 not re-run here" in fr.reg03_scope("cse-in", True)
          and (fr.reg03_scope("cse-in", False), fr.reg03_scope("cse-in", None)) == ("FAIL", "NOT-RUN"))
    blk = eager(lambda: {c: fr.fl01_block({"steps": {k: True for k in fr.FL01_STEPS}, "pre_condition": {
        "orchestrator_cse": c, "holds": fr.reg03_scope(c, True), **fr.REG_PRE}}) for c in ("cse-in", "cse-mn-a")})
    check("the record's fl01.steps carry that value for the pre-condition, PASS for the seven steps, and fl01 names "
          "REG_01 and REG_02 with their status",
          lambda: blk["cse-in"]["steps"]["pre-condition REG_03 (orchestrator)"] == fr.reg03_scope("cse-in", True)
          and blk["cse-mn-a"]["steps"]["pre-condition REG_03 (orchestrator)"] == fr.reg03_scope("cse-mn-a", True)
          and all(blk["cse-in"]["steps"][f"step {i}"] == "PASS" for i in range(1, 8))
          and set(blk["cse-in"]["pre_condition"]) >= {"TD_MEC_REG_01", "TD_MEC_REG_02", "orchestrator_cse"}
          and blk["cse-in"]["verdict"] == "PARTIAL")
    control("the pre-condition with the orchestrator's AE on cse-in was recorded as a plain REG_03 PASS",
            lambda: blk["cse-in"]["steps"]["pre-condition REG_03 (orchestrator)"] == "PASS")

    def coverage_says():
        # the status REG_PRE cites, read from the main tree's coverage table (read only): the row of each, COVERED
        rows = {ln.split("|")[1].strip(): ln.split("|")[3].strip() for ln in (MAIN_TREE / "estimed/TESTPLAN_COVERAGE.md")
                .read_text().splitlines() if ln.startswith("| TD_MEC_REG_0")}
        return rows.get("TD_MEC_REG_01") == "COVERED" and rows.get("TD_MEC_REG_02") == "COVERED"
    check("REG_PRE: REG_01 and REG_02 are named not re-run here and COVERED in the main tree's coverage table, which "
          "says so", lambda: all(v.startswith("not re-run here; COVERED in the main tree's estimed/TESTPLAN_COVERAGE.md")
                                 for v in fr.REG_PRE.values()) and sorted(fr.REG_PRE) == ["TD_MEC_REG_01", "TD_MEC_REG_02"]
          and coverage_says())
    check("FL_03 steps 7 and 8 stay NOT-RUN, and the reason no longer says the client is not deployed as a MEC app",
          lambda: (lambda r: r["result"] == "NOT-RUN" and "not deployed as a MEC app" not in r["reason"]
                   and "handover" in r["reason"])(next(x for x in fr.FL03_NOT_RUN if "steps 7 and 8" in x["row"])))


def fl01_wiring_rows() -> None:  # noqa: C901, PLR0915
    """TD_MEC_FL_01's observation wiring, offline: the pinned loader, the relay, /proc, the platform's evidence, the
    driver's readers of the wire and of the CSE, and what each app's own program sends when it starts, each on
    stand-ins or recorded fixtures written here by hand (no CSE, no MEC). Inside this process: two loopback servers
    (a stand-in upstream behind a Relay) and the proxy role's device listener; one sleeping child process. Nothing
    leaves this host. These rows exist because 11 of 14 planted faults in this wiring survived the suite before
    (review 2026-11-20, P1-P14)."""
    import json
    import math
    import os
    import shutil
    import signal
    import subprocess
    import tempfile
    import threading
    import types
    import urllib.request
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    print("== TD_MEC_FL_01: the pinned loader runs the bytes whose hash it checked, read once [planted fault P9]")

    def swapped_load():
        rel = "estimed/mec_app_deploy.py"
        d = Path(tempfile.mkdtemp(prefix="fl01-swap-"))
        (d / rel).parent.mkdir(parents=True)
        (d / rel).write_bytes((MAIN_TREE / rel).read_bytes())
        real = mp.read_pinned

        def read_then_swap(r, tree=None):
            data = real(r, tree)
            (Path(tree) / r).write_bytes(b"SWAPPED = True\n")     # the file changes after its hash was checked
            return data
        mp.read_pinned = read_then_swap
        try:
            return mp.load_module(rel, "fl01_swap_probe", tree=d), (d / rel).read_bytes()
        finally:
            mp.read_pinned = real
            sys.modules.pop("fl01_swap_probe", None)
            shutil.rmtree(d, ignore_errors=True)
    sw_mod, sw_file = eager(swapped_load, 2)
    check("a file swapped on disk between its hash check and exec is not run: the module is the pinned bytes "
          "(PlatformAgent), the swapped text never ran, and the swap did happen",
          lambda: hasattr(sw_mod, "PlatformAgent") and not hasattr(sw_mod, "SWAPPED") and sw_file == b"SWAPPED = True\n")
    control("the file swapped in after the hash check was run", lambda: getattr(sw_mod, "SWAPPED", False) is True)

    print("== TD_MEC_FL_01: the relay's reading of what an app sent [planted fault P11]")
    H = lambda ct, o=None: {"method": "POST", "headers": {"content-type": ct, **({"x-m2m-origin": o} if o else {})}}  # noqa: E731
    recs = [H("application/json;ty=28", "CflProxy"), H("application/json;ty=2", "CflProxy"), H("application/json; ty=4", "Cx"),
            {**H("application/json;ty=2"), "method": "GET"}, H("application/json"), H("application/json;ty=2x")]
    check("ty_of reads the resource type exactly: ty=28 is 28, not 2; ty=2 is 2; none or a malformed one is None",
          lambda: [fp.ty_of(r) for r in recs] == [28, 2, 4, 2, None, None])
    check("creates() picks the POSTs of one type (and originator): a flexContainer Create is no AE Create",
          lambda: fp.creates(recs, 2) == [recs[1]] and fp.creates(recs, 28) == [recs[0]]
          and fp.creates(recs, 4, "CflProxy") == [] and fp.creates(recs, 4, "Cx") == [recs[2]])
    control("a flexContainer Create (ty=28) was read as an AE Create (ty=2)", lambda: recs[0] in fp.creates(recs, 2))

    class _Up(BaseHTTPRequestHandler):
        def _do(self):
            got = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            out = json.dumps({"echo": got.decode(), "path": self.path, "origin": self.headers.get("X-M2M-Origin")}).encode()
            self.send_response(201 if self.command == "POST" else 200)
            self.send_header("X-M2M-RSC", "2001" if self.command == "POST" else "2000")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        do_GET = do_POST = _do

        def log_message(self, *a):
            pass

    def relay_run():
        up = ThreadingHTTPServer(("127.0.0.1", 0), _Up)
        up.daemon_threads = True
        threading.Thread(target=up.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        relay = fp.Relay(f"http://127.0.0.1:{up.server_address[1]}/", "cse-x")
        try:
            body = b'{"m2m:ae": {"rn": "flX"}}'
            with urllib.request.urlopen(urllib.request.Request(f"{relay.url}/cse-x", data=body, method="POST", headers={
                    "X-M2M-Origin": "CflX", "Content-Type": "application/json;ty=2"}), timeout=5) as resp:
                first = (resp.status, resp.headers.get("X-M2M-RSC"), json.loads(resp.read()))
            relay.hold, out = (lambda rec: rec["path"].endswith("/confirm_ready")), {}

            def held_call():
                with urllib.request.urlopen(urllib.request.Request(f"{relay.url}/a/confirm_ready", data=b"{}", method="POST",
                                                                   headers={"Content-Type": "application/json"}), timeout=10) as r2:
                    out.update(status=r2.status, t=time.monotonic())
            t = threading.Thread(target=held_call, daemon=True)
            t.start()
            end = time.monotonic() + 5
            while time.monotonic() < end and not any(x.get("held") for x in relay.since(0)):
                time.sleep(0.01)
            time.sleep(0.1)
            waiting, t_rel = t.is_alive() and "status" not in out, time.monotonic()
            relay.release.set()
            t.join(5)
            return {"first": first, "body": body.decode(), "seen": relay.since(0), "waiting": waiting, "held": out, "t_rel": t_rel}
        finally:
            relay.close()
            up.shutdown()
            up.server_close()
    rr = eager(relay_run)
    check("a Relay forwards a request unchanged and records it: method, path, originator, ty=2, the body as sent, the "
          "upstream's status, X-M2M-RSC and reply, answered after it came in (both clocks)",
          lambda: (lambda s0: rr["first"] == (201, "2001", {"echo": rr["body"], "path": "/cse-x", "origin": "CflX"})
                   and (s0["n"], s0["method"], s0["path"], s0["headers"].get("x-m2m-origin"), fp.ty_of(s0), s0["raw"])
                   == (0, "POST", "/cse-x", "CflX", 2, rr["body"]) and (s0["status"], s0["rsc"]) == (201, 2001)
                   and s0["reply"]["path"] == "/cse-x" and s0["t_in"] <= s0["t_out"] and s0["t_in_boot"] <= s0["t_out_boot"])(rr["seen"][0]))
    check("a held request (confirm_ready) waits at the relay until it is released, then goes through",
          lambda: rr["waiting"] is True and rr["held"]["status"] == 201 and rr["held"]["t"] >= rr["t_rel"]
          and rr["seen"][1].get("held") is True)

    print("== TD_MEC_FL_01: the workload's process, read from /proc [planted fault P2]")
    wd = Path(tempfile.mkdtemp(prefix="fl01-wl-"))
    t_before = eager(lambda: fp.boot_clock())
    child = eager(lambda: subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)",
                                            str(wd / "instances" / "i1" / "instance.json")], stdin=subprocess.DEVNULL))
    check("workloads(): the live process with an argument under the work folder is found, this process is not, and "
          "nothing is found under another folder",
          lambda: child.pid in fp.workloads(wd) and os.getpid() not in fp.workloads(wd) and child.pid not in fp.workloads(wd / "x"))
    check("process_start_tick(): the child's start on the boot clock, in ticks, not before it was started nor after now",
          lambda: isinstance(fp.process_start_tick(child.pid), int)
          and math.floor(t_before * fp.CLK_TCK) <= fp.process_start_tick(child.pid) <= math.floor(fp.boot_clock() * fp.CLK_TCK))

    print("== TD_MEC_FL_01: what the platform says about a deployed app (evidence, listed, registered) [P1, P2, P14]")
    M10, M11 = "http://mec010.test", "http://mec011.test"
    store = wd / "packages" / "p1"
    prog = b"print('the program')\n"
    eager(lambda: (store.mkdir(parents=True), (store / "fl_app.py").write_bytes(prog)))
    SV = lambda lcm, mid: {"serName": "s", "transportInfo": {"id": lcm, "endpoint": {"uris": [f"http://r/cse-mn-a/{mid}"]}},  # noqa: E731
                           "_links": {"self": {"href": f"/mec_service_mgmt/v1/applications/{mid}/services/S"}}}
    answers = {   # by hand: what MEC 010-2 and MEC 011 answer about instance L1 (and another one, L9)
        ("GET", f"{M10}/app_lcm/v1/app_instances/L1"): (200, {"id": "L1", "appDId": "d-1", "instantiationState": "INSTANTIATED"}),
        ("GET", f"{M10}/app_pkgm/v1/onboarded_app_packages/P1"): (200, {
            "id": "P1", "appDId": "d-1", "checksum": {"hash": "c" * 64}, "operationalState": "ENABLED", "usageState": "IN_USE"}),
        ("GET", f"{M10}/app_lcm/v1/app_lcm_op_occs"): (200, [
            {"appInstanceId": "L1", "lcmOperation": "INSTATIATE", "operationState": "PROCESSING"},
            {"appInstanceId": "L9", "lcmOperation": "TERMINATE", "operationState": "PROCESSING"}]),
        ("GET", f"{M11}/mec_service_mgmt/v1/services"): (200, [SV("L9", "M9"), SV("L1", "M1")]),
        ("GET", f"{M11}/mec_app_support/v2/applications/M1/dns_rules"): (200, []),
        ("GET", f"{M10}/app_lcm/v1/app_instances"): (200, [
            {"id": "L1", "appDId": "d-1", "instantiationState": "INSTANTIATED", "appName": "x", "_links": {}}, "not a dict"]),
        ("GET", f"{M10}/app_pkgm/v1/app_packages"): (200, [{"id": "P1", "appDId": "d-1", "checksum": {"hash": "c" * 64},
                                                           "operationalState": "ENABLED", "usageState": "IN_USE", "appName": "x"}])}
    asked = []

    def on_stand_ins(fn, extra=None):
        real, table = fp.http, {**answers, **(extra or {})}

        def http(method, url, body=None, timeout=10):
            asked.append((method, url))
            return table.get((method, url), (404, None))
        fp.http = http
        try:
            return fn()
        finally:
            fp.http = real

    def stand_in_platform():
        pl = object.__new__(fp.Platform)
        pl.mod, pl.mec010, pl.mec011, pl.workdir, pl.relays, pl.deployed = None, M10, M11, wd, {}, {}
        pl.agent = types.SimpleNamespace(results={"occ-1": "COMPLETED"})
        return pl
    pl = eager(stand_in_platform)
    D1 = {"lcmInstanceId": "L1", "appPkgId": "P1", "appDId": "d-1", "checksum": "c" * 64, "descriptor_sha256": "c" * 64,
          "store": str(store), "desc": {"entryPoint": {"file": "fl_app.py"}, "files": {"fl_app.py": _sha(prog)}},
          "run": {"pid": child.pid if isinstance(child, subprocess.Popen) else None, "opOcc": "occ-1"}, "error": None,
          "records": {"mec010": [{"method": "POST", "path": "/app_lcm/v1/app_instances/L9/instantiate", "status": 202,
                                  "t_out": 0.5, "t_out_boot": 1.5},
                                 {"method": "POST", "path": "/app_lcm/v1/app_instances/L1/instantiate", "status": 202,
                                  "t_out": 1.0, "t_out_boot": 2.0}],
                      "mec011": [{"method": "GET", "path": "/mec_service_mgmt/v1/services", "t_in": 0.9},
                                 {"method": "POST", "path": "/mec_app_support/v2/registrations", "t_in": 1.1}]}}
    ev = eager(lambda: on_stand_ins(lambda: pl.evidence(D1)))
    check("evidence(), by hand: MEC 010-2's instance, package and its one operation (PROCESSING), the agent's own record, "
          "MEC 011 lists it, the process alive under the work folder with its argv from /proc, the program's digest, the "
          "instantiate of L1 on the agent's wire, the first Mp1 POST, the start tick",
          lambda: (ev["instance"]["instantiationState"], ev["package"]["checksum"]["hash"], ev["op_occs"], ev["agent_result"])
          == ("INSTANTIATED", "c" * 64, [["INSTATIATE", "PROCESSING"]], "COMPLETED")
          and ev["listed"] is True and ev["pid_alive"] is True
          and ev["argv"][-1] == str(wd / "instances" / "i1" / "instance.json")
          and ev["program_sha256"] == ev["expected_program_sha256"] == _sha(prog)
          and {k: v for k, v in ev["lifecycle"].items() if k != "process_start_tick"} == {
              "instantiate_on_wire": [[202, 1.0, 2.0]], "first_mp1_post_t_in": 1.1, "clk_tck": fp.CLK_TCK}
          and ev["lifecycle"]["process_start_tick"] == fp.process_start_tick(child.pid))
    no_l1 = {("GET", f"{M11}/mec_service_mgmt/v1/services"): (200, [SV("L9", "M9")])}
    ev2 = eager(lambda: on_stand_ins(lambda: pl.evidence(D1), no_l1))
    ev3 = eager(lambda: on_stand_ins(lambda: pl.evidence({**D1, "run": {"pid": os.getpid(), "opOcc": "occ-1"}})))
    check("... 'listed' is MEC 011's answer: with L1's service not listed it is False", lambda: ev2["listed"] is False)
    check("... 'pid_alive' is /proc's answer: a live process that is not under the work folder is not the workload",
          lambda: ev3["pid_alive"] is False and ev["pid_alive"] is True)
    control("an app whose service MEC 011 does not list was taken as listed", lambda: ev2["listed"] is not False)
    control("a live process outside the platform's work folder was taken for the app's workload", lambda: ev3["pid_alive"] is not False)
    check("listed() gives the services of that instance only; registered() asks MEC 011 for the instance",
          lambda: on_stand_ins(lambda: pl.listed("L1") == [SV("L1", "M1")] and pl.listed("L7") == [] and pl.listed(None) == []
                               and pl.registered("M1") is True and pl.registered("M9") is False and pl.registered(None) is False))
    control("listed() gave a service of another instance", lambda: on_stand_ins(lambda: pl.listed("L7") != []))
    check("mec010_view(): what MEC 010-2 itself lists, the fields step 7 reads, statuses kept; nothing when it fails",
          lambda: on_stand_ins(lambda: fp.mec010_view(M10)) == {
              "instances_status": 200, "packages_status": 200,
              "instances": [{"id": "L1", "appDId": "d-1", "instantiationState": "INSTANTIATED"}],
              "packages": [{"id": "P1", "appDId": "d-1", "checksum": {"hash": "c" * 64}, "operationalState": "ENABLED",
                            "usageState": "IN_USE"}]}
          and on_stand_ins(lambda: fp.mec010_view("http://elsewhere.test")) == {
              "instances_status": 404, "packages_status": 404, "instances": [], "packages": []})
    with contextlib.suppress(Exception):
        child.kill()
        child.wait(5)
    check("... and once the process has gone, workloads() and process_start_tick() no longer find it",
          lambda: child.pid not in fp.workloads(wd) and fp.process_start_tick(child.pid) is None)

    def index_two():
        d = Path(tempfile.mkdtemp(prefix="fl01-idx-"))
        b1, b2 = b'{"onem2m": {"rn": "flX"}}', b'{"onem2m": {"rn": "flX"} }'
        (d / "a").mkdir()
        (d / "b").mkdir()
        (d / "a/appd.json").write_bytes(b1)
        (d / "b/appd.json").write_bytes(b2)
        try:
            return fp.descriptor_index([d / "a/appd.json", d / "b/appd.json"]), _sha(b1), _sha(b2)
        finally:
            shutil.rmtree(d, ignore_errors=True)
    idx, h1, h2 = eager(index_two, 3)
    check("descriptor_index(): each descriptor under the SHA-256 of its bytes, parsed from those bytes; one space more "
          "is another key", lambda: idx == {h1: {"onem2m": {"rn": "flX"}}, h2: {"onem2m": {"rn": "flX"}}} and h1 != h2)
    shutil.rmtree(wd, ignore_errors=True)

    print("== TD_MEC_FL_01 in the driver: an app's wire (app_wire), its AE (reg03_obs), step 7 (enumerate_fl01)")
    R = lambda method, path, origin=None, ty=None, status=None, rsc=None, reply=None, body=None, t_in=0.0, t_out=0.0: {  # noqa: E731
        "method": method, "path": path, "headers": {**({"x-m2m-origin": origin} if origin else {}),
                                                    "content-type": f"application/json;ty={ty}" if ty else "application/json"},
        "status": status, "rsc": rsc, "reply": reply, "body": body, "raw": json.dumps(body) if body else "",
        "t_in": t_in, "t_out": t_out}
    Dw = {"key": "fl_proxy", "cse": "cse-mn-a", "lcmInstanceId": "L2", "records": {
        "cse-mn-a": [R("POST", "/cse-mn-a", "CflProxy", 2, 201, 2001, {"m2m:ae": {"aei": "CflProxy"}}, t_in=1.0, t_out=1.05),
                     R("POST", "/cse-mn-a/flProxy", "CflProxy", 1, 201, 2001, t_in=1.1, t_out=1.15),
                     R("PUT", "/cse-mn-a/flProxy", "CflProxy", None, 200, 2004, t_in=1.2, t_out=1.25),
                     R("POST", "/cse-mn-a/flProxy", "CflProxy", 3, 201, 2001, body={"m2m:cnt": {"rn": "flConfig"}}, t_in=1.3, t_out=1.35),
                     R("POST", "/cse-mn-a", "CAdmin", 2, 201, 2001, {"m2m:ae": {"aei": "CAdmin"}}, t_in=1.4, t_out=1.45),
                     R("GET", "/cse-mn-a/flProxy", "CflProxy", None, 200, 2000, t_in=1.6, t_out=1.65)],
        "mec011": [R("POST", "/mec_app_support/v2/registrations", status=201, reply={"appInstanceId": "M2"}, t_in=0.5),
                   R("GET", "/mec_service_mgmt/v1/services", status=200, t_in=0.6),
                   R("POST", "/mec_service_mgmt/v1/applications/M2/services", status=201, t_in=0.7),
                   R("POST", "/mec_app_support/v2/applications/M2/confirm_ready", status=204, t_in=1.5)]}}
    w = eager(lambda: fr.app_wire(Dw, "CflProxy"))
    check("app_wire(), by hand: its one AE Create (the CAdmin one is not its), its writes, Mp1 registrations -> services "
          "-> confirm_ready, MEC 011's id for it, confirm_ready after the answer to its last write",
          lambda: w["creates"] == [{"path": "/cse-mn-a", "origin": "CflProxy", "status": 201, "rsc": 2001, "aei": "CflProxy"}]
          and w["mp1_posts"] == [["registrations", 201], ["services", 201], ["confirm_ready", 204]] and w["mid"] == "M2"
          and (w["registration"], w["confirm_ready"], w["confirm_after_writes"]) == (201, 204, True)
          and w["writes"] == [["POST", "/cse-mn-a", 201], ["POST", "/cse-mn-a/flProxy", 201], ["PUT", "/cse-mn-a/flProxy", 200],
                              ["POST", "/cse-mn-a/flProxy", 201]])
    early = copy.deepcopy(Dw)
    early["records"]["mec011"][-1]["t_in"] = 1.3          # before the answer to its container Create (1.35)
    check("... confirm_ready sent before the answer to its last write is not 'after its writes'",
          lambda: fr.app_wire(early, "CflProxy")["confirm_after_writes"] is False)
    control("a confirm_ready sent before the app's last write was answered was taken as after its writes",
            lambda: fr.app_wire(early, "CflProxy")["confirm_after_writes"] is not False)

    def with_rq(answer, fn, mec_answer=None):
        seen, real, real_mec = [], fr.rq, fr.mec

        def rq(method, to, origin, *, ty=None, body=None, why="", harness=False):
            seen.append({"method": method, "to": to, "origin": origin, "harness": harness})
            return answer(method, to, origin)
        fr.rq = rq
        if mec_answer is not None:
            fr.mec = lambda method, path, body=None, who="flTfc": (seen.append({"mec": (method, path, who)}), mec_answer)[1]
        try:
            return fn(), seen
        finally:
            fr.rq, fr.mec = real, real_mec
    acp_m = {"ri": "acpM", "pv": {"acr": [{"acor": ["CflProxy"], "acop": 63}, {"acor": ["CflOrch", "CflProxyCheck"], "acop": 34}]},
             "pvs": {"acr": [{"acor": ["CflProxy"], "acop": 63}]}}
    tree = {f"{LAB_A}/flProxy": {"m2m:ae": {"ty": 2, "rn": "flProxy", "api": "Nestimed.flproxy", "aei": "CflProxy", "pi": "id-mn-a",
                                           "acpi": ["acpM"], "lbl": ["fl:proxy", "mec:appInstanceId:M2", "mec:lcmInstanceId:L2"]}},
            f"{LAB_A}/flProxy/flMetaAcp": {"m2m:acp": acp_m},
            f"{LAB_A}/flProxy/flConfig": {"m2m:cnt": {"ty": 3, "rn": "flConfig", "cr": "CflProxy", "acpi": ["acpM"]}}}
    owner_only = lambda m, to, o: (200, tree[to]) if o == "CflProxy" and to in tree else (403, None)  # noqa: E731
    r3o, r3seen = eager(lambda: with_rq(owner_only, lambda: fr.reg03_obs(Dw, w)), 2)
    check("reg03_obs(), by hand: the app's AE, policy and baseline container read under its own originator (the "
          "harness's: no party of FL_03), three reads by a stranger, and what they must say is the driver's (FL01_APPS)",
          lambda: [(s["to"], s["origin"], s["harness"]) for s in r3seen] == [
              (f"{LAB_A}/flProxy", "CflProxy", True), (f"{LAB_A}/flProxy/flMetaAcp", "CflProxy", True),
              (f"{LAB_A}/flProxy/flConfig", "CflProxy", True), (f"{LAB_A}/flProxy", "CflStranger", True),
              (f"{LAB_A}/flProxy/flConfig", "CflStranger", True), (f"{LAB_A}/flProxy/flMetaAcp", "CflStranger", True)]
          and (r3o["origin"], r3o["cse_ri"], r3o["rn"], r3o["api"], r3o["readers"], r3o["reader_ops"], r3o["container_rn"],
               r3o["mid"], r3o["lcm"], r3o["stranger"]) == ("CflProxy", "id-mn-a", "flProxy", "Nestimed.flproxy",
                                                           ["CflOrch", "CflProxyCheck"], 34, "flConfig", "M2", "L2", [403, 403, 403])
          and r3o["acp"] == acp_m and fl.reg03_ae(r3o)[0])
    r3x, _ = eager(lambda: with_rq(lambda m, to, o: (200, tree[to]) if to in tree else (404, None), lambda: fr.reg03_obs(Dw, w)), 2)
    check("... and with a CSE that lets a stranger read, the row built from it fails", lambda: not fl.reg03_ae(r3x)[0])

    # step 7 as the driver does it, on a recorded world: discovery and reads under CflOrch, MEC 011's listing, and
    # MEC 010-2's own lists (the reviewer's strays (b) and (c) are in it, both listed at MEC 011)
    Pw = lambda lbl, attad=False: {"ty": 28, "lbl": ["fl:profile", *lbl], "attad": attad}  # noqa: E731
    world = {"cse-mn-a/flNat/flCap": Pw(["fl:class:fl-native"], True), "cse-mn-a/flDec/flCap": Pw(["fl:class:fl-native"], True),
             "cse-mn-a/flSrc1/flCap": Pw(["fl:class:fl-assisted"]), "cse-mn-a/flSrc2/flCap": Pw(["fl:class:fl-assisted"]),
             "cse-mn-a/flTfc/flCap": Pw(["fl:class:trusted-fl-client"], True),
             "cse-mn-a/flProxy/flCap-devPx1": Pw(["fl:class:proxy-path", "fl:device:devPx1", "fl:via:flProxy"]),
             "cse-mn-a/flStray/flCap-ghost": Pw(["fl:class:proxy-path", "fl:device:devGhost", "fl:via:flStray"]),
             "cse-mn-a/flStray2/flCap-self": Pw(["fl:class:proxy-path", "fl:device:devSelf", "fl:via:flStray2"])}
    labels = {"flNat": [], "flDec": [], "flSrc1": [], "flSrc2": [],
              "flTfc": ["fl:role:tfc", "fl:represents:flSrc1", "fl:represents:flSrc2", "mec:appInstanceId:M1", "mec:lcmInstanceId:L1"],
              "flProxy": ["fl:role:proxy", "mec:appInstanceId:M2", "mec:lcmInstanceId:L2"],
              "flStray": ["fl:role:proxy", "mec:lcmInstanceId:L2", "mec:appInstanceId:M3"],
              "flStray2": ["fl:role:proxy", "mec:lcmInstanceId:Lfake", "mec:appInstanceId:M4"]}
    SW = lambda lcm, mid, ae: {"serName": "s", "transportInfo": {"id": lcm, "endpoint": {"uris": [f"http://r/cse-mn-a/{ae}"]}},  # noqa: E731
                               "_links": {"self": {"href": f"/mec_service_mgmt/v1/applications/{mid}/services/S"}}, "state": "ACTIVE"}
    listing = [SW("L1", "M1", "flTfc"), SW("L2", "M2", "flProxy"), SW("L2", "M3", "flStray"), SW("Lfake", "M4", "flStray2")]

    def world_answer(m, to, o):
        path = to.split("/", 3)[3]
        if "?fu=1" in path:
            return 200, {"m2m:uril": sorted(world)}
        if path in world:
            return 200, {"mad:dmCay": world[path]}
        ae = path.split("/")[1] if path.count("/") == 1 else None
        return (200, {"m2m:ae": {"lbl": labels[ae]}}) if ae in labels else (404, None)
    raw_t, raw_p = (eager(lambda k=k: (APPS / k / "appd.json").read_bytes()) for k in ("fl_tfc", "fl_proxy"))
    descs = eager(lambda: {_sha(raw_t): json.loads(raw_t), _sha(raw_p): json.loads(raw_p)})
    m10_lists = lambda inst_state="INSTANTIATED": {  # noqa: E731
        ("GET", f"{fr.MEC010}/app_lcm/v1/app_instances"): (200, [
            {"id": "L1", "appDId": "d-t", "instantiationState": "INSTANTIATED"},
            {"id": "L2", "appDId": "d-p", "instantiationState": inst_state}]),
        ("GET", f"{fr.MEC010}/app_pkgm/v1/app_packages"): (200, [
            {"id": "p-t", "appDId": "d-t", "checksum": {"hash": _sha(raw_t)}, "operationalState": "ENABLED"},
            {"id": "p-p", "appDId": "d-p", "checksum": {"hash": _sha(raw_p)}, "operationalState": "ENABLED"}])}

    def step7(inst_state="INSTANTIATED"):
        fr.set_mode("hierarchical")
        asked.clear()
        E, seen = with_rq(world_answer, lambda: on_stand_ins(lambda: fr.enumerate_fl01(descs), m10_lists(inst_state)), (200, listing))
        return E, seen, list(asked)
    E7d, seen7, asked7 = eager(step7, 3)
    check("enumerate_fl01(), by hand: the three classes, and both strays refused with MEC 010-2's reason; every read "
          "under CflOrch; MEC 011's listing read by flOrch; MEC 010-2's two lists read from MEC 010-2 itself",
          lambda: E7d["enumerated"]["classes"] == {"fl-native": ["flDec", "flNat"], "fl-assisted": ["flSrc1", "flSrc2"],
                                                   "proxy-path": ["devPx1"]}
          and {r["ref"]: r["why"] for r in E7d["enumerated"]["refused"]} == {
              "cse-mn-a/flStray/flCap-ghost": "its proxy app is not deployed (the package of instance L2 does not name "
                                              "flStray on cse-mn-a as a proxy for devGhost)",
              "cse-mn-a/flStray2/flCap-self": "its proxy app is not deployed (MEC 010-2 lists no INSTANTIATED instance Lfake)"}
          and all(s["origin"] == "CflOrch" for s in seen7 if "origin" in s)
          and [s["mec"] for s in seen7 if "mec" in s] == [("GET", "/mec_service_mgmt/v1/services", "flOrch")]
          and asked7 == [("GET", f"{fr.MEC010}/app_lcm/v1/app_instances"), ("GET", f"{fr.MEC010}/app_pkgm/v1/app_packages")]
          and len(E7d["mec010"]["instances"]) == 2 and E7d["services"][2]["_links"]["self"]["href"].split("/")[4] == "M3")
    check("... both strays are listed at MEC 011 in that world (stray_listed), so MEC 011 alone would have taken them",
          lambda: fr.stray_listed(E7d["services"], "flStray") and fr.stray_listed(E7d["services"], "flStray2")
          and not fr.stray_listed(E7d["services"][:2], "flStray2"))
    E7n, _, _ = eager(lambda: step7("NOT_INSTANTIATED"), 3)
    check("... and the driver reads 'deployed' from MEC 010-2: with L2 NOT_INSTANTIATED there, devPx1 is not enumerated",
          lambda: E7n["enumerated"]["classes"]["proxy-path"] == [] and E7n["enumerated"]["classes"]["fl-assisted"] == ["flSrc1", "flSrc2"])
    control("a stray listed at MEC 011 (self-registered, or under the proxy's copied id) was enumerated by the driver's step 7",
            lambda: bool({"devGhost", "devSelf"} & set(sum(E7d["enumerated"]["classes"].values(), []))))

    print("== TD_MEC_FL_01: what each app's own program sends when it starts, on a stand-in wire [P8; L3]")

    def app_start(pkg):
        mod, seen = _app_module(pkg), []

        def call(method, url, body=None, headers=None):
            h = dict(headers or {})
            seen.append({"method": method, "url": url, "body": copy.deepcopy(body), "headers": h})
            if url.endswith("/confirm_ready"):
                raise mod.Stop()                  # what start() sent up to confirm_ready is all these rows need
            if "X-M2M-Origin" not in h:
                if method == "POST" and url.endswith("/registrations"):
                    return 201, {"appInstanceId": "M1"}, {}
                return (201, {"serInstanceId": "S1"}, {}) if method == "POST" and url.endswith("/services") else (204, None, {})
            ty = h.get("Content-Type", "").partition("ty=")[2]
            if method == "POST" and ty == "2":
                return 201, {"m2m:ae": {"aei": h["X-M2M-Origin"]}}, {"X-M2M-RSC": "2001"}
            if method == "POST" and ty == "1":
                n = sum(1 for s in seen if s["headers"].get("Content-Type", "").endswith(";ty=1"))
                return 201, {"m2m:acp": {"ri": f"acp{n}"}}, {"X-M2M-RSC": "2001"}
            if method == "PUT":
                return 200, {}, {"X-M2M-RSC": "2004"}
            if method == "GET":
                return 200, {"m2m:ae": {"lbl": []}}, {"X-M2M-RSC": "2000"}
            return 201, {}, {"X-M2M-RSC": "2001"}
        mod.call = call
        d = Path(tempfile.mkdtemp(prefix="fl01-app-"))
        (d / "instance.json").write_text(json.dumps({"lcmInstanceId": "L1", "mec011": "http://mec011.test",
                                                     "cse": "http://cse.test/cse-mn-a"}))
        argv, sig = sys.argv, (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
        sys.argv = ["fl_app.py", "--instance", str(d / "instance.json")]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                code = mod.main()
        finally:
            sys.argv = argv
            signal.signal(signal.SIGTERM, sig[0])
            signal.signal(signal.SIGINT, sig[1])
            shutil.rmtree(d, ignore_errors=True)
        return code, seen
    of_ty = lambda seen, ty: [s for s in seen if s["headers"].get("Content-Type", "").endswith(f";ty={ty}")]  # noqa: E731
    tfc_code, tfc_seen = eager(lambda: app_start("fl_tfc"), 2)
    check("the Trusted FL Client's AE Create, from its own program, by hand: under CflTfc to its CSE, labelled with each "
          "device it acts for and both instance ids; its binding record names them; it left in order (exit 0)",
          lambda: of_ty(tfc_seen, 2)[0]["url"] == "http://cse.test/cse-mn-a" and of_ty(tfc_seen, 2)[0]["body"] == {
              "m2m:ae": {"rn": "flTfc", "api": "Nestimed.fl", "rr": False, "srv": ["4"], "lbl": [
                  "fl:participant", "fl:role:tfc", "fl:sim:true", "fl:represents:flSrc1", "fl:represents:flSrc2",
                  "mec:appInstanceId:M1", "mec:lcmInstanceId:L1"]}}
          and of_ty(tfc_seen, 2)[0]["headers"]["X-M2M-Origin"] == "CflTfc" and tfc_code == 0
          and json.loads(of_ty(tfc_seen, 4)[0]["body"]["m2m:cin"]["con"]) == {"kind": "binding", "record": {
              "client": "CflTfc", "represents": ["flSrc1", "flSrc2"], "lcmInstanceId": "L1", "mec011AppInstanceId": "M1",
              "package": "estimed-fl-trusted-client 0.1.0", "sim": True}})
    control("the Trusted FL Client's AE was created without the devices it acts for",
            lambda: not any(x.startswith("fl:represents:") for x in of_ty(tfc_seen, 2)[0]["body"]["m2m:ae"]["lbl"]))
    px_code, px_seen = eager(lambda: app_start("fl_proxy"), 2)
    check("the proxy's data policy as its own program creates it, by hand: flDataAcp under its AE, the proxy every "
          "operation, CflProxyCheck RETRIEVE + DISCOVERY, only the proxy may change it; the device container is put "
          "under it alone (what step 5 then reads back from the CSE)",
          lambda: of_ty(px_seen, 1)[1]["url"] == "http://cse.test/cse-mn-a/flProxy" and of_ty(px_seen, 1)[1]["body"] == {
              "m2m:acp": {"rn": "flDataAcp", "pv": {"acr": [{"acor": ["CflProxy"], "acop": 63},
                                                           {"acor": ["CflProxyCheck"], "acop": 34}]},
                          "pvs": {"acr": [{"acor": ["CflProxy"], "acop": 63}]}}}
          and [c["body"] for c in of_ty(px_seen, 3) if c["body"]["m2m:cnt"]["rn"] == "devPx1"] == [
              {"m2m:cnt": {"rn": "devPx1", "acpi": ["acp2"], "cr": None}}] and px_code == 0)


def _raised(fn):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return e
    return None


def main() -> int:  # noqa: C901, PLR0915  one flat list of rows, like test_p2.py
    print("== canonical form and digests (the binding of an update to round, source and data is SHA-256 over these)")
    check("canonical JSON: sorted keys, no spaces", lambda: fl.canon({"b": [2, 3], "a": 1}) == b'{"a":1,"b":[2,3]}')
    check("digest = SHA-256 of the canonical form (sha256sum of {\"a\":1,\"b\":[2,3]})",
          lambda: fl.digest({"b": [2, 3], "a": 1}) == "efbd0040190fb0871831e606c581f8a66db79d8e2bb836745a70051306956070")
    check("a float anywhere in a digested record is refused (no floats in the update path)",
          lambda: raises(lambda: fl.canon({"w": [1, 2.0]}), TypeError))
    check("model digest of w [0,0,0] (sha256sum of the body)", lambda: fl.model_digest([0, 0, 0]) == D_W000)
    check("model digest of w [9,23,30]", lambda: fl.model_digest([9, 23, 30]) == D_W9)
    check("CSE creation time to epoch ms: 20261118T191538,424092 = 1795029338424 (date -u -d)",
          lambda: fl.ct_ms("20261118T191538,424092") == 1_795_029_338_424)
    check("creation time without a fraction", lambda: fl.ct_ms("20261118T191538") == 1_795_029_338_000)

    print("== telemetry to integer features (sim_phone.py env record; tenths of a degree, exact)")
    check("25.0 -> 250, '25.3' -> 253, Decimal 24.9 -> 249, 25 -> 250",
          lambda: [fl.deci(25.0), fl.deci("25.3"), fl.deci(Decimal("24.9")), fl.deci(25)] == [250, 253, 249, 250])
    check("a value that is not a whole tenth is refused, not rounded",
          lambda: raises(lambda: fl.deci(25.37), ValueError))
    check("a boolean is not a temperature", lambda: raises(lambda: fl.deci(True), ValueError, TypeError))
    check("env record parsed to integers",
          lambda: fl.parse_env('{"battery_pct": 80, "battery_temp_c": 25.0, "t": 0, "sim": true}')
          == {"t": 0, "temp_dc": 250, "pct": 80})
    check("an env record that does not say sim: true is refused (no row may read as a real device)",
          lambda: raises(lambda: fl.parse_env('{"battery_pct": 80, "battery_temp_c": 25.0, "t": 0}'), ValueError))

    print("== feature selection and time alignment [TR 7.3.5.9.9 check 3, fact F41, TR lines 7843-7844]")
    recs = [{"t": 0, "temp_dc": 250, "pct": 90}, {"t": 5000, "temp_dc": 254, "pct": 89},
            {"t": 10000, "temp_dc": 252, "pct": 89}, {"t": 15000, "temp_dc": 260, "pct": 87}]
    # by hand: (0->5000) x = [250-250, (90-89)*32] = [0, 32], y = 254-250 = 4; (5000->10000) x = [4, 0], y = 2;
    #          (10000->15000) x = [2, 64], y = 10
    check("consecutive records one period apart make one sample each",
          lambda: fl.pairs(recs)["samples"] == [{"t": 0, "x": [0, 32], "y": 4}, {"t": 5000, "x": [4, 0], "y": 2},
                                                {"t": 10000, "x": [2, 64], "y": 10}])
    check("records out of order give the same samples (ordered by t)",
          lambda: fl.pairs(list(reversed(recs)))["samples"] == fl.pairs(recs)["samples"])
    gap = [recs[0], recs[1], recs[3]]
    check("a gap makes no sample and is counted",
          lambda: (lambda p: (len(p["samples"]), p["dropped_gap"]))(fl.pairs(gap)) == (1, 1))
    dup = [recs[0], recs[1], {"t": 5000, "temp_dc": 300, "pct": 10}, recs[2]]
    check("a second record with the same t is dropped (the first is kept) and counted",
          lambda: (lambda p: (p["samples"], p["dropped_duplicate"]))(fl.pairs(dup))
          == ([{"t": 0, "x": [0, 32], "y": 4}, {"t": 5000, "x": [4, 0], "y": 2}], 1))
    b_recs = [{"t": 5000, "temp_dc": 270, "pct": 60}, {"t": 10000, "temp_dc": 268, "pct": 60},
              {"t": 15000, "temp_dc": 262, "pct": 59}, {"t": 20000, "temp_dc": 262, "pct": 59}]
    # by hand: source a has samples at t 0, 5000, 10000; source b at 5000, 10000, 15000. Used: 5000 and 10000 from
    # each (4 samples); not used: a's t=0 and b's t=15000 (2).
    check("aggregatedSources: a window is used only if every source has it; ordered by (t, source)",
          lambda: (lambda d: ([(s["t"], s["src"]) for s in d["samples"]], d["dropped_unaligned"], d["per_source"]))(
              fl.assemble({"a": recs, "b": b_recs}, "aggregatedSources"))
          == ([(5000, "a"), (5000, "b"), (10000, "a"), (10000, "b")], 2, {"a": 2, "b": 2}))
    check("aggregatedSources keeps each source's own features (b at 5000: x [20, 0], y 18)",
          lambda: fl.assemble({"a": recs, "b": b_recs}, "aggregatedSources")["samples"][1]
          == {"t": 5000, "src": "b", "x": [20, 0], "y": 18})
    check("singleSource / independentSources: one source, all its samples",
          lambda: len(fl.assemble({"a": recs}, "independentSources")["samples"]) == 3)
    check("independentSources with two sources in one dataset is refused (each source is its own participant)",
          lambda: raises(lambda: fl.assemble({"a": recs, "b": b_recs}, "independentSources"), ValueError))
    check("the simulated series has the shape of sim_phone's env record and says sim: true",
          lambda: (lambda r: set(r) == {"light", "proximity", "battery_pct", "battery_temp_c", "t", "sim"}
                   and r["sim"] is True and r["t"] == 7000)(fl.sim_series(seed=1, n=3, t0_ms=7000)[0]))
    check("the simulated series is repeatable and one period apart",
          lambda: fl.sim_series(seed=5, n=6, t0_ms=0) == fl.sim_series(seed=5, n=6, t0_ms=0)
          and [r["t"] for r in fl.sim_series(seed=5, n=3, t0_ms=0)] == [0, 5000, 10000])

    print("== device records behind a host bridge (fl_capture.py): no sim mark, times not on a grid")
    dev = '{"light": {"n": 5, "mean": [88.5]}, "proximity": {"n": 0}, "battery_pct": 71, "battery_temp_c": 31.5, "t": 1000}'
    check("a device env record (the probe app's shape, no sim mark) is parsed when the caller says device",
          lambda: fl.parse_env(dev, device=True) == {"t": 1000, "temp_dc": 315, "pct": 71})
    check("without device=True the same record is still refused",
          lambda: raises(lambda: fl.parse_env(dev), ValueError))
    control("a record marked sim: true was taken as a device record",
            lambda: not raises(lambda: fl.parse_env('{"battery_pct": 80, "battery_temp_c": 25.0, "t": 0, "sim": true}', device=True), ValueError))
    control("a device record carrying a key outside the env shape (a position) was taken",
            lambda: not raises(lambda: fl.parse_env('{"battery_pct": 80, "battery_temp_c": 25.0, "t": 0, "lat": 1.5}', device=True), ValueError))
    control("a device record with an unknown charge (-1) was taken",
            lambda: not raises(lambda: fl.parse_env('{"battery_pct": -1, "battery_temp_c": 25.0, "t": 0}', device=True), ValueError))
    # by hand, period 5000, slot(t) = (t + 2500) // 5000: 1000 -> 0; 6200 -> 1; 10900 -> 2; 12400 -> 2 (second in
    # its slot, dropped); 21000 -> 4 (slot 3 is empty: a gap).
    #   slot 0 -> 1: t 0,    x = [300-250, (90-89)*32] = [50, 32], y = 304-250 = 54
    #   slot 1 -> 2: t 5000, x = [54, 0],                          y = 302-250 = 52
    drec = [{"t": 1000, "temp_dc": 300, "pct": 90}, {"t": 6200, "temp_dc": 304, "pct": 89},
            {"t": 10900, "temp_dc": 302, "pct": 89}, {"t": 12400, "temp_dc": 999, "pct": 10},
            {"t": 21000, "temp_dc": 310, "pct": 88}]
    check("slot alignment: records in neighbouring slots make one sample, stamped with the slot's start",
          lambda: (lambda p: (p["samples"], p["dropped_duplicate"], p["dropped_gap"]))(fl.pairs(drec, align="slot"))
          == ([{"t": 0, "x": [50, 32], "y": 54}, {"t": 5000, "x": [54, 0], "y": 52}], 1, 1))
    check("slot alignment: the slot border is half a period (2499 -> slot 0, 2500 -> slot 1)",
          lambda: [s["t"] for s in fl.pairs([{"t": 2499, "temp_dc": 250, "pct": 50}, {"t": 2500, "temp_dc": 250, "pct": 50}],
                                            align="slot")["samples"]] == [0])
    check("exact alignment is unchanged: the same records make no sample (no two are one period apart)",
          lambda: (lambda p: (p["samples"], p["dropped_gap"]))(fl.pairs(drec)) == ([], 4))
    # source e: slots 1, 2, 3 -> samples at 5000 and 10000. With drec (samples at 0 and 5000) only 5000 is common.
    erec = [{"t": 4100, "temp_dc": 270, "pct": 60}, {"t": 9000, "temp_dc": 268, "pct": 60}, {"t": 14900, "temp_dc": 262, "pct": 59}]
    check("aggregatedSources on slots: two phones with different clocks share the window both have",
          lambda: (lambda d: ([(s["t"], s["src"]) for s in d["samples"]], d["dropped_unaligned"]))(
              fl.assemble({"d": drec, "e": erec}, "aggregatedSources", align="slot")) == ([(5000, "d"), (5000, "e")], 2))
    check("an alignment name that is not known is refused",
          lambda: raises(lambda: fl.pairs(drec, align="nearest"), ValueError))
    check("the dataset record names the alignment that was used",
          lambda: fl.dataset_record("ds", "1", fl.assemble({"d": drec}, "independentSources", align="slot"), sources=["d"],
                                    provenance=[], policy_versions=["v"])["processingProfileRef"] == "estimed.fl.env-slots.v1"
          and fl.dataset_record("ds", "1", fl.assemble({"a": recs}, "independentSources"), sources=["a"], provenance=[],
                                policy_versions=["v"])["processingProfileRef"] == "estimed.fl.env-pairs.v1")

    slot_ds = fl.assemble({"d": drec}, "independentSources", align="slot")
    slot_rec = fl.dataset_record("ds", "1", slot_ds, sources=["d"], provenance=[], policy_versions=["v"])
    check("check 3 accepts a slot-aligned dataset when told the alignment",
          lambda: fl.ac3_dataset({"record": slot_rec, "published": slot_rec, "samples": slot_ds["samples"], "provenance": [],
                                  "align": "slot"})[0])
    control("check 3 passed a dataset record that names the grid rules although slots were used",
            lambda: fl.ac3_dataset({"record": {**slot_rec, "processingProfileRef": "estimed.fl.env-pairs.v1"},
                                    "published": {**slot_rec, "processingProfileRef": "estimed.fl.env-pairs.v1"},
                                    "samples": slot_ds["samples"], "provenance": [], "align": "slot"})[0])
    control("check 3 passed a slot-aligned record when the caller used the grid rules",
            lambda: fl.ac3_dataset({"record": slot_rec, "published": slot_rec, "samples": slot_ds["samples"], "provenance": []})[0])

    print("== the integer model: Q8 weights, round half up, no floats")
    # rshift_round(a, s) = floor(a / 2^s + 1/2)
    check("rounding: 31/64 -> 0, 32/64 -> 1, -32/64 -> 0, -33/64 -> -1, 1200/64 -> 19",
          lambda: [fl.rshift_round(v, 6) for v in (31, 32, -32, -33, 1200)] == [0, 1, 0, -1, 19])
    # predict = rshift_round(w0*32 + w1*x_temp + w2*x_drain, 8); w [9,23,30], A: 288 + 920 + 1920 = 3128 -> 12
    check("prediction on A with w [9,23,30] = 12", lambda: fl.predict([9, 23, 30], A["x"]) == 12)
    # B: 288 - 460 + 0 = -172 -> floor(-172/256 + 1/2) = -1
    check("prediction on B with w [9,23,30] = -1", lambda: fl.predict([9, 23, 30], B["x"]) == -1)
    # one pass from w [0,0,0]:
    #  A: prediction 0, error 30; steps rshift_round(30 * [32,40,64], 6) = [15, 19, 30]          -> w [15,19,30]
    #  B: 15*32 - 19*20 = 100 -> prediction 0, error -12; steps rshift_round(-12 * [32,-20,0], 6) = [-6, 4, 0]
    #                                                                                              -> w [9,23,30]
    check("one training pass over A then B from w [0,0,0] gives [9,23,30]",
          lambda: fl.train([0, 0, 0], [A, B]) == [9, 23, 30])
    check("training does not change its input", lambda: (lambda w: (fl.train(w, [A, B]), w)[1])([0, 0, 0]) == [0, 0, 0])
    # second pass, A then B: A predicted 12, error 18, steps [9, 11, 18] -> [18,34,48]; B: 576 - 680 = -104 ->
    #  prediction 0, error -12, steps [-6, 4, 0] -> [12,38,48]
    check("two passes over A then B give [12,38,48]", lambda: fl.train([0, 0, 0], [A, B], epochs=2) == [12, 38, 48])
    # B then A: first pass also ends at [9,23,30]; second pass B: prediction -1, error -11, steps [-5, 3, 0] ->
    #  [4,26,30]; A: 128 + 1040 + 1920 = 3088 -> prediction 12, error 18, steps [9, 11, 18] -> [13,37,48]
    check("sample order matters and is the given order: two passes over B then A give [13,37,48]",
          lambda: fl.train([0, 0, 0], [B, A], epochs=2) == [13, 37, 48])
    check("the update is the difference to the model it started from",
          lambda: fl.delta([9, 23, 30], [1, 3, 30]) == [8, 20, 0])
    # loss = sum |y - prediction|: w [0,0,0] -> 30 + 12 = 42; w [9,23,30] -> |30-12| + |-12-(-1)| = 18 + 11 = 29
    check("held-out error (sum of absolute errors): 42 before, 29 after",
          lambda: (fl.loss([0, 0, 0], [A, B]), fl.loss([9, 23, 30], [A, B])) == (42, 29))
    check("a float weight or feature is refused", lambda: raises(lambda: fl.predict([9, 23.0, 30], A["x"]), TypeError)
          and raises(lambda: fl.train([0, 0, 0], [{"t": 0, "x": [1.5, 0], "y": 1}]), TypeError))

    print("== aggregation: FedAvg weighted by effective sample count [FL_02 step 8]")
    # w_in [10,20,30]; P-A delta [4,-6,1] n 3; P-B delta [-2,9,0] n 1; per coordinate round_half_up(sum(n*d) / 4):
    #  10/4 = 2.5 -> 3;  -9/4 = -2.25 -> -2;  3/4 = 0.75 -> 1   => [13, 18, 31]
    contrib = [([4, -6, 1], 3), ([-2, 9, 0], 1)]
    check("weighted average by hand: [13, 18, 31]", lambda: fl.fedavg(W_IN, contrib) == [13, 18, 31])
    check("a negative half rounds up: -10/4 = -2.5 -> -2", lambda: fl.fedavg([0], [([-10], 1), ([0], 3)]) == [-2])

    def oracle(w, cs):       # the same rule written with exact fractions
        den = sum(n for _, n in cs)
        return [wj + int((Fraction(sum(n * d[j] for d, n in cs), den) + Fraction(1, 2)).__floor__())
                for j, wj in enumerate(w)]
    many = [([7, -300, 55], 12), ([-91, 4, 1024], 17), ([3, 3, -3], 26), ([-1024, 1, 0], 5)]
    check("agrees with an exact-fraction oracle on four contributions",
          lambda: fl.fedavg([5, -7, 100], many) == oracle([5, -7, 100], many))
    acc = lambda cs: [{"delta": d, "n": n} for d, n in cs]  # noqa: E731
    check("the checker's own recompute (exact fractions, written a second way) gives the hand values too",
          lambda: fl.exact_average(W_IN, acc(contrib)) == [13, 18, 31] and fl.exact_average([0], acc([([-10], 1), ([0], 3)])) == [-2])
    check("... and agrees with the aggregator's integer arithmetic on four contributions",
          lambda: fl.exact_average([5, -7, 100], acc(many)) == fl.fedavg([5, -7, 100], many) == oracle([5, -7, 100], many))
    check("the weight is the sample count, not one per participant (equal weights would give [11, 22, 31])",
          lambda: fl.fedavg(W_IN, contrib) != [11, 22, 31])
    check("no contribution, or a weight that is not a positive integer, is refused",
          lambda: raises(lambda: fl.fedavg(W_IN, []), ValueError)
          and raises(lambda: fl.fedavg(W_IN, [([1, 1, 1], 0)]), ValueError)
          and raises(lambda: fl.fedavg(W_IN, [([1, 1, 1], 1.0)]), TypeError, ValueError))
    # threshold stated by us (the test plan gives none): at least 2 updates and 2/3 of the selected
    check("quorum needed: selected 1..6 -> 2, 2, 2, 3, 4, 4",
          lambda: [fl.quorum_needed(n) for n in (1, 2, 3, 4, 5, 6)] == [2, 2, 2, 3, 4, 4])

    print("== records carry the attributes the TR marks 'Yes' for a minimal demonstration [facts F15, F16, F18, F30, F31]")
    want = {
        "trustedFLClientProfile": ("clientAERef", "profileVersion", "executionHostRef", "hostingCSERef",
                                   "clientOperatorRef", "executionDomainRef", "capabilityProfileRef",
                                   "supportedParticipantModes", "supportedFrameworks", "maxSources",
                                   "dataAccessMethods", "coordinatorRef", "activeOperationRefs", "readinessState"),
        "flParticipantProfile": ("participantId", "operationRef", "clientAERef", "participantMode", "datasetRef",
                                 "datasetVersion", "sourceBindingRefs", "representedSourceCount",
                                 "effectiveSampleCount", "sampleCountMethod", "overlapPolicyRef",
                                 "weightingPolicyRef", "trainingTaskRefs", "contributionStatus"),
        "datasetProcessingPolicy": ("policyId", "policyVersion", "policyAuthorityRef", "processingPurpose",
                                    "authorizedProcessorRefs", "allowedExecutionDomains", "allowedSourceRefs",
                                    "permittedOperations", "permittedOutputClasses", "rawDataExportAllowed",
                                    "temporaryRetentionDuration", "derivedDataRetentionRef", "expiryTime",
                                    "revocationStatus"),
        "dataset": ("datasetVersion", "sourceDescriptorRefs", "processingProfileRef", "processingPolicyVersionRefs",
                    "datasetProvenanceRef", "validSampleCount", "datasetLifecycleState", "retentionPolicyRef"),
        "task": ("taskId", "operationRef", "roundRef", "selectedClient", "modelRef", "trainingConfig",
                 "dataSelectionPolicy", "deadline", "updateDestination", "statusTarget", "securityRefs"),
    }
    for kind, fields in want.items():
        check(f"{kind}: the field list is the documents' list ({len(fields)} attributes)",
              lambda k=kind, f=fields: set(f) <= set(fl.MVP_FIELDS[k]) and len(fl.MVP_FIELDS[k]) >= len(f))
    check("a policy record with every attribute has nothing missing",
          lambda: fl.missing_fields("datasetProcessingPolicy", policy()["record"]) == [])
    check("a policy record without revocationStatus is reported",
          lambda: fl.missing_fields("datasetProcessingPolicy",
                                    {k: v for k, v in policy()["record"].items() if k != "revocationStatus"})
          == ["revocationStatus"])
    rd, ctx = eager(world, 2)
    t_a = eager(lambda: next(t for t in rd["tasks"].values() if t["participantId"] == "P-A"))
    check("a task record has every attribute, names its round and says sim: true",
          lambda: fl.missing_fields("task", t_a) == [] and t_a["roundRef"] == 2 and t_a["sim"] is True
          and t_a["taskId"] == "op-1-r2-P-A")
    check("a Trusted FL Client profile has every attribute, says sim: true and refuses an unknown readiness state",
          lambda: (lambda mk: fl.missing_fields("trustedFLClientProfile", mk("ready")) == [] and mk("ready")["sim"] is True
                   and mk("ready")["clientAERef"] == TFC and raises(lambda: mk("installed"), ValueError))(
              lambda state: fl.tfc_profile(TFC, version="1", host="h", cse="cse-mn-a", operator="op", domain="edge-a",
                                           capability_ref="cse-mn-a/flTfc/flCap", max_sources=2,
                                           coordinator="cse-in/flOrch", operations=["op-1"], state=state)))
    check("readiness state names are the TR's eight [fact F15, TR lines 6911-6963]",
          lambda: set(fl.READINESS_STATES) == {"registered", "awaitingAuthorization", "preparing", "ready", "running",
                                               "blocked", "failed", "retiring"})
    check("contribution status names are the TR's eight [fact F16, TR lines 6988-7011]",
          lambda: set(fl.CONTRIBUTION_STATES) == {"candidate", "authorized", "ready", "training", "submitted",
                                                  "excluded", "revoked", "failed"})

    print("== capability profile as a flexContainer [FL_01 step 1]")
    # the lab CSE knows these TS-0023 management module classes (acmecse/init/mad-mc.fcp): dmCapability has
    # name, attached (attad), currentState (curSe); dmAgent has state, ramTl/ramAe, stoTl/stoAe, cpuUe, powSs
    check("capability: a mad:dmCay flexContainer named flCap with the capability name and both flags",
          lambda: fl.cap_fcnt(True, False, ["fl:role:client"]) == {"mad:dmCay": {
              "rn": "flCap", "cnd": "org.onem2m.management.moduleclass.dmCapability", "name": "fl.localTraining",
              "attad": True, "curSe": False, "lbl": ["fl:role:client"]}})
    check("compute: a mad:dmAgt flexContainer named flCompute, integers only",
          lambda: fl.compute_fcnt(ram_total=8192, ram_free=4096, storage_total=64000, storage_free=32000, cpu_pct=10)
          == {"mad:dmAgt": {"rn": "flCompute", "cnd": "org.onem2m.management.moduleclass.dmAgent", "state": 1,
                            "ramTl": 8192, "ramAe": 4096, "stoTl": 64000, "stoAe": 32000, "cpuUe": 10}})
    check("read back from the CSE (with its own attributes added) it gives the candidate's capability",
          lambda: fl.capability_of({"mad:dmCay": {"rn": "flCap", "name": "fl.localTraining", "attad": True,
                                                  "curSe": True, "ri": "x", "ty": 28, "st": 0}})
          == {"canTrain": True, "enabled": True})
    check("a source that cannot train reads as such", lambda: fl.capability_of(fl.cap_fcnt(False, False, []))
          == {"canTrain": False, "enabled": False})
    check("FL_01 step 1: both flexContainers created (201) and read back as type 28",
          lambda: fl.fl01_1_capability_fcnt({"created": {"flCap": 201, "flCompute": 201}, "readback": {
              "flCap": {"mad:dmCay": {"ty": 28, "name": "fl.localTraining", "attad": True, "curSe": True}},
              "flCompute": {"mad:dmAgt": {"ty": 28, "ramTl": 1, "cpuUe": 1}}}})[0])
    check("FL_01 step 1 fails when the profile is a contentInstance (type 4), which is what the designs had",
          lambda: not fl.fl01_1_capability_fcnt({"created": {"flCap": 201, "flCompute": 201}, "readback": {
              "flCap": {"m2m:cin": {"ty": 4, "con": "{}"}}, "flCompute": {"mad:dmAgt": {"ty": 28}}}})[0])
    check("FL_01 step 2: the orchestrator's discovery returns the profile",
          lambda: fl.fl01_2_discoverable({"found": ["cse-mn-a/flNat/flCap"], "expect": "cse-mn-a/flNat/flCap"})[0]
          and not fl.fl01_2_discoverable({"found": [], "expect": "cse-mn-a/flNat/flCap"})[0])
    f4 = {"mec011_registration": 201, "appInstanceId": "i-1", "listed_before_ready": False, "confirm_ready": 204,
          "listed_after_ready": True, "ae": 201, "ae_label_instance": "i-1", "represents": ["flSrc1", "flSrc2"]}
    check("FL_01 step 4: the Trusted FL Client is a MEC 011 app instance, listed only after confirm_ready, and an "
          "AE carrying that instance id [FL_01 step 4]", lambda: fl.fl01_4_tfc_registered(f4)[0])
    for k, v in (("listed_after_ready", False), ("listed_before_ready", True), ("ae_label_instance", "i-2"),
                 ("represents", []), ("confirm_ready", 404)):
        check(f"FL_01 step 4 fails with {k} = {v!r}", lambda k=k, v=v: not fl.fl01_4_tfc_registered({**f4, k: v})[0])
    check("FL_01 step 7 needs all three device classes; two are not enough",
          lambda: not fl.fl01_7_enumerable({"classes": {"fl-native": ["flNat"], "fl-assisted": ["flSrc1"],
                                                        "proxy-path": []}})[0]
          and fl.fl01_7_enumerable({"classes": {"fl-native": ["a"], "fl-assisted": ["b"], "proxy-path": ["c"]}})[0])

    print("== readiness is six separate conditions; installed is not ready [fact F13, TR lines 7070-7075, 7096]")
    check("the six conditions are the TR's", lambda: set(fl.READINESS_CONDITIONS) == set(ready()))
    check("all six true -> ready", lambda: fl.is_ready(ready()) is True)
    for c in ready():
        check(f"{c} false -> not ready", lambda c=c: fl.is_ready(ready(**{c: 1})) is False)
    check("a condition that is missing, or truthy but not True, does not count",
          lambda: fl.is_ready({k: v for k, v in ready().items() if k != "canAcceptTask"}) is False
          and fl.is_ready({**ready(), "modelAccessible": "yes"}) is False)
    check("governance row: awaiting authorization, then ready",
          lambda: fl.gov_readiness({"before": ready(authorizedLocalDataAccessible=1), "after": ready(),
                                    "state_before": "awaitingAuthorization", "state_after": "ready"})[0]
          and not fl.gov_readiness({"before": ready(), "after": ready(), "state_before": "ready",
                                    "state_after": "ready"})[0])

    print("== selection: discovered, able, ready, authorised and willing [FL_02 step 1; facts F10, F28]")
    cands = [cand("P-A", TFC), cand("P-B", NAT), cand("P-D", DEC, decision="declined")]
    check("the willing candidates are selected, in a repeatable order",
          lambda: fl.select_participants(list(reversed(cands)))["selected"] == ["P-A", "P-B"])
    check("the one that declines is not selected and its only reason is the decline (its descriptors match)",
          lambda: (lambda s: s["rejected"] == {"P-D": ["declined"]} and "P-D" in s["descriptors_match"])(
              fl.select_participants(cands)))
    for label, kw, why, match in (
            ("no answer yet", {"decision": None}, "no-decision", ["P-X"]),
            ("cannot train", {"capability": {"canTrain": False, "enabled": False}}, "cannot-train", []),
            ("training switched off", {"capability": {"canTrain": True, "enabled": False}}, "cannot-train", []),
            ("not found by discovery", {"discovered": False}, "not-discovered", []),
            ("policy does not authorise it", {"authorized": False}, "not-authorized", []),
            ("one readiness condition false", {"readiness": ready(modelAccessible=1)}, "not-ready:modelAccessible", [])):
        check(f"not selected: {label}",
              lambda kw=kw, why=why, match=match: fl.select_participants([cand("P-X", NAT, **kw)]) ==
              {"selected": [], "rejected": {"P-X": [why]}, "descriptors_match": match})
    check("FL_02 step 1: the recorded selection is the rule's, from discovered profiles, at least two",
          lambda: fl.fl02_1_selection({"candidates": cands, "selected": ["P-A", "P-B"],
                                       "discovered_refs": ["a/flCap", "b/flCap", "d/flCap"],
                                       "capability_refs": {"P-A": "a/flCap", "P-B": "b/flCap"}})[0])
    check("FL_02 step 1 fails when a profile used for selection was not found by discovery",
          lambda: not fl.fl02_1_selection({"candidates": cands, "selected": ["P-A", "P-B"],
                                           "discovered_refs": ["a/flCap"],
                                           "capability_refs": {"P-A": "a/flCap", "P-B": "b/flCap"}})[0])
    check("governance row: a client declines although its descriptors match [TR lines 5836-5841, 7230-7240]",
          lambda: fl.gov_decline({"candidates": cands, "selected": ["P-A", "P-B"], "decliner": "P-D"})[0])
    control("a client that declined although its descriptors match was counted as participating",
            lambda: "P-D" in fl.select_participants(cands)["selected"])
    control("the decline row accepts a round whose selection contains the decliner",
            lambda: fl.gov_decline({"candidates": cands, "selected": ["P-A", "P-B", "P-D"], "decliner": "P-D"})[0])

    print("== policy decision [TR 7.3.5.9.9 check 2, fact F40 (TR lines 7838-7842); fact F29, F30]")
    pols = {"flSrc1": policy("flSrc1", "CflAuthA"), "flSrc2": policy("flSrc2", "CflAuthB")}
    check("both policies permit: authorised, one decision reference per policy",
          lambda: (lambda d: d["authorized"] is True and d["decisionRefs"] ==
                   ["flSrc1-policy@1:permit", "flSrc2-policy@1:permit"] and d["refusals"] == {})(auth(pols)))
    deny = {**pols, "flSrc2": policy("flSrc2", "CflAuthB", permittedOperations=["aggregate-statistics"])}
    check("one policy does not permit training: the whole definition is refused, with the source and the reason",
          lambda: (lambda d: d["authorized"] is False and d["refusals"] == {"flSrc2": ["operation-not-permitted"]}
                   and d["decisionRefs"] == ["flSrc1-policy@1:permit", "flSrc2-policy@1:deny"])(auth(deny)))
    for label, kw, why in (
            ("revoked", {"revocationStatus": "revoked"}, "revoked"),
            ("expired", {"expiryTime": DEADLINE}, "expired"),
            ("another purpose", {"processingPurpose": "analytics"}, "purpose"),
            ("another processor", {"authorizedProcessorRefs": ["CflOther"]}, "processor-not-authorized"),
            ("another execution domain", {"allowedExecutionDomains": ["edge-b"]}, "domain-not-allowed"),
            ("another source", {"allowedSourceRefs": ["flSrc9"]}, "source-not-covered"),
            ("raw export allowed", {"rawDataExportAllowed": True}, "raw-export-allowed"),
            ("an attribute missing", {"revocationStatus": None}, "malformed")):
        def one(kw=kw, why=why):
            p = policy("flSrc1", "CflAuthA", **kw)
            if why == "malformed":
                del p["record"]["revocationStatus"]
            return auth({"flSrc1": p}, sources=("flSrc1",))["refusals"] == {"flSrc1": [why]}
        check(f"refused: {label}", one)
    check("refused: no policy for a source",
          lambda: auth({"flSrc1": pols["flSrc1"]})["refusals"] == {"flSrc2": ["no-policy"]})
    check("refused: the record names an authority other than the originator the CSE recorded as its creator",
          lambda: auth({"flSrc1": {"record": policy()["record"], "creator": "CflSrc1"}}, sources=("flSrc1",))["refusals"]
          == {"flSrc1": ["authority-not-creator"]})
    control("the orchestrator granted itself access with a policy it wrote [TR line 7516]",
            lambda: auth({"flSrc1": policy("flSrc1", ORCH)}, sources=("flSrc1",))["authorized"])
    control("the Trusted FL Client granted itself access with a policy it wrote",
            lambda: auth({"flSrc1": policy("flSrc1", TFC)}, sources=("flSrc1",))["authorized"])
    check("check 2: an authorised definition with two decision references, and a refusal when one policy denies",
          lambda: fl.ac2_policy_decision({"granted": auth(pols), "denied": auth(deny), "n_sources": 2,
                                          "denied_dataset": None})[0])
    check("check 2 fails if a dataset was assembled after the refusal",
          lambda: not fl.ac2_policy_decision({"granted": auth(pols), "denied": auth(deny), "n_sources": 2,
                                              "denied_dataset": {"datasetVersion": "1"}})[0])
    check("check 2 fails if the 'denied' case was in fact authorised",
          lambda: not fl.ac2_policy_decision({"granted": auth(pols), "denied": auth(pols), "n_sources": 2,
                                              "denied_dataset": None})[0])
    check("governance row: the orchestrator's own read and its own change of the policy are both refused (403)",
          lambda: fl.gov_orch_no_self_grant({"raw_read": 403, "acp_update": 403})[0])
    control("the orchestrator read a source's raw data by itself (the row accepts a 200 answer)",
            lambda: fl.gov_orch_no_self_grant({"raw_read": 200, "acp_update": 403})[0])
    control("the orchestrator changed a source's access policy by itself (the row accepts a 200 answer)",
            lambda: fl.gov_orch_no_self_grant({"raw_read": 403, "acp_update": 200})[0])

    print("== dataset record [TR 7.3.5.9.9 check 3; fact F31]")
    asm = eager(lambda: fl.assemble({"a": recs, "b": b_recs}, "aggregatedSources"))
    prov = [{"source": "a", "t": 0, "con_sha256": "00"}, {"source": "b", "t": 5000, "con_sha256": "01"}]

    def ds_rec():
        return fl.dataset_record("ds-agg", "1", asm, sources=["a", "b"], provenance=prov,
                                 policy_versions=["a-policy@1", "b-policy@1"])
    check("the record has every attribute, the version, the rules' name and says sim: true",
          lambda: (lambda r: fl.missing_fields("dataset", r) == [] and r["datasetVersion"] == "1"
                   and r["processingProfileRef"] == fl.PROCESSING_PROFILE and r["sim"] is True
                   and r["datasetLifecycleState"] == "valid")(ds_rec()))
    check("effective sample count is the number of aligned samples (4, counted by hand above)",
          lambda: ds_rec()["effectiveSampleCount"] == 4 and ds_rec()["validSampleCount"] == 4)
    check("provenance reference is the digest of the list of source records used",
          lambda: ds_rec()["datasetProvenanceRef"] == fl.digest(prov))
    check("the published record carries no observation", lambda: fl.scan_raw(ds_rec()) == [])
    o3 = lambda **kw: {"record": ds_rec(), "published": ds_rec(), "samples": asm["samples"], "provenance": prov, **kw}  # noqa: E731
    check("check 3 passes on a record that matches what was assembled and published", lambda: fl.ac3_dataset(o3())[0])
    check("check 3 fails when the published count differs from the assembled samples",
          lambda: not fl.ac3_dataset(o3(samples=asm["samples"][:3]))[0])
    check("check 3 fails when the provenance list does not hash to the published reference",
          lambda: not fl.ac3_dataset(o3(provenance=prov[:1]))[0])
    check("check 3 fails when the copy on the CSE differs from the record",
          lambda: not fl.ac3_dataset(o3(published={**ds_rec(), "datasetVersion": "2"}))[0])

    print("== an update and the aggregator's checks [FL_02 steps 6-8; fact F26 (TR lines 7305-7314), F27]")
    rd, ctx = eager(world, 2)
    good = eager(lambda: upd(rd, ctx, "P-A", [4, -6, 1]))
    check("an update record names its task, round, model, dataset and sample count and says sim: true",
          lambda: (lambda u: u["taskId"] == "op-1-r2-P-A" and u["round"] == 2 and u["modelInDigest"] == rd["modelDigest"]
                   and u["participantId"] == "P-A" and u["clientAERef"] == TFC and u["datasetRef"] == "ds-A"
                   and u["effectiveSampleCount"] == 3 and u["delta"] == [4, -6, 1] and u["sim"] is True)(good["update"]))
    check("its digest covers every other field",
          lambda: good["update"]["updateDigest"]
          == fl.digest({k: v for k, v in good["update"].items() if k != "updateDigest"}))
    check("a well-bound update in time from its own originator has no objection", lambda: reasons(good, rd, ctx) == [])

    def tamper(field, value):
        s = copy.deepcopy(good)
        s["update"][field] = value
        return s

    def rebound(**over):
        """An update whose digest is right for its altered content (the sender recomputed it)."""
        s = copy.deepcopy(good)
        s["update"].update(over)
        s["update"]["updateDigest"] = fl.digest({k: v for k, v in s["update"].items() if k != "updateDigest"})
        return s
    check("a changed weight without a new digest: digest-mismatch",
          lambda: reasons(tamper("delta", [4, -6, 2]), rd, ctx) == ["digest-mismatch"])
    check("a changed sample count without a new digest: digest-mismatch",
          lambda: "digest-mismatch" in reasons(tamper("effectiveSampleCount", 300), rd, ctx))
    check("an inflated sample count WITH a matching digest is still caught: it is not the published dataset's",
          lambda: reasons(rebound(effectiveSampleCount=300), rd, ctx) == ["dataset-mismatch"])
    check("another dataset digest: dataset-mismatch",
          lambda: reasons(rebound(datasetDigest=fl.digest("other")), rd, ctx) == ["dataset-mismatch"])
    check("a dataset nobody published: unknown-dataset",
          lambda: reasons(rebound(datasetRef="ds-none"), rd, ctx) == ["unknown-dataset"])
    check("written by another originator than the task's client: creator-mismatch",
          lambda: reasons({**good, "creator": NAT}, rd, ctx) == ["creator-mismatch"])
    check("an update for this round's task that names the previous model: stale-model",
          lambda: reasons(rebound(modelInDigest=D_W000), rd, ctx) == ["stale-model"])
    check("this round's task but another round number: wrong-round",
          lambda: reasons(rebound(round=1), rd, ctx) == ["wrong-round"])
    check("another operation: wrong-round", lambda: reasons(rebound(operationRef="op-9"), rd, ctx) == ["wrong-round"])
    check("a task that is not in this round: unknown-task",
          lambda: reasons(rebound(taskId="op-1-r2-P-Z"), rd, ctx) == ["unknown-task"])
    check("the task of another participant: wrong-participant",
          lambda: reasons(rebound(taskId="op-1-r2-P-C"), rd, ctx) == ["wrong-participant"])
    check("one millisecond after the deadline: late; at the deadline: in time",
          lambda: reasons({**good, "created_ms": DEADLINE + 1}, rd, ctx) == ["late"]
          and reasons({**good, "created_ms": DEADLINE}, rd, ctx) == [])
    check("at the bound (1024) accepted, one beyond it refused, on either side",
          lambda: reasons(upd(rd, ctx, "P-A", [1024, -1024, 0]), rd, ctx) == []
          and reasons(upd(rd, ctx, "P-A", [0, 1025, 0]), rd, ctx) == ["out-of-bound"]
          and reasons(upd(rd, ctx, "P-A", [-1025, 0, 0]), rd, ctx) == ["out-of-bound"])
    check("the stated bound is 1024 per coordinate (4.0 in real units at Q8)", lambda: fl.UPDATE_BOUND == 1024)
    check("an update digest seen before: replay",
          lambda: reasons(good, rd, {**ctx, "seen": {good["update"]["updateDigest"]}}) == ["replay"])
    check("a participant that was not selected: not-selected",
          lambda: reasons(good, {**rd, "selected": ["P-B", "P-C"]}, ctx) == ["not-selected"])
    check("the dataset marked invalid: dataset-invalid",
          lambda: reasons(good, rd, {**ctx, "datasets": {**ctx["datasets"], ("ds-A", "2"): {
              **ctx["datasets"][("ds-A", "2")], "state": "invalid"}}}) == ["dataset-invalid"])
    check("a source of the dataset revoked at acceptance: source-revoked",
          lambda: reasons(good, rd, {**ctx, "source_state": {**ctx["source_state"], "flSrc1": "revoked"}})
          == ["source-revoked"])
    check("a source the aggregator has no state for counts as not active",
          lambda: reasons(good, rd, {**ctx, "source_state": {}}) == ["source-revoked"])
    for label, mut in (("an extra field (raw rows ride along)", lambda u: u.update(rows=[{"battery_pct": 80}])),
                       ("a float weight", lambda u: u.update(delta=[4.0, -6, 1])),
                       ("two weights instead of three", lambda u: u.update(delta=[4, -6])),
                       ("a boolean weight", lambda u: u.update(delta=[True, -6, 1])),
                       ("no sim flag", lambda u: u.pop("sim")),
                       ("sim: false", lambda u: u.update(sim=False)),
                       ("a sample count of zero", lambda u: u.update(effectiveSampleCount=0)),
                       ("a missing field", lambda u: u.pop("datasetDigest"))):
        def one(mut=mut):
            s = copy.deepcopy(good)
            mut(s["update"])
            return reasons(s, rd, ctx) == ["malformed"]
        check(f"malformed: {label}", one)
    check("an update carries no observation (the fields are a closed set)", lambda: fl.scan_raw(good["update"]) == [])

    print("== closing a round [FL_02 steps 7, 8, 10; 'a round below quorum must not publish a model']")
    subs = eager(lambda: [upd(rd, ctx, "P-A", [4, -6, 1]), upd(rd, ctx, "P-B", [-2, 9, 0])])
    res = lambda s=None, r=None, c=None: fl.close_round(r or rd, subs if s is None else s, c or ctx)  # noqa: E731
    check("two of three in time: completed, model [13, 18, 31] (by hand above), the third logged as missing",
          lambda: (lambda r: r["state"] == "COMPLETED" and r["w_out"] == [13, 18, 31]
                   and r["modelOutDigest"] == fl.model_digest([13, 18, 31])
                   and [a["participantId"] for a in r["accepted"]] == ["P-A", "P-B"]
                   and r["missing"] == [{"participantId": "P-C", "reasons": ["no-update-by-deadline"]}]
                   and r["quorum"] == {"needed": 2, "accepted": 2, "selected": 3, "met": True})(res()))
    check("the record logs the weighting basis and each weight, and says sim: true",
          lambda: (lambda r: r["weightingBasis"] == "effectiveSampleCount" and [a["n"] for a in r["accepted"]] == [3, 1]
                   and r["sim"] is True)(res()))
    check("the round's record recomputes: verify_round has no objection", lambda: fl.verify_round(res()) == [])
    check("the order in which updates are read does not change the result",
          lambda: res(list(reversed(subs)))["w_out"] == [13, 18, 31])
    late = eager(lambda: [subs[0], {**subs[1], "created_ms": DEADLINE + 5}])
    check("a straggler after the deadline is excluded and logged; one update left: below quorum, NO model",
          lambda: (lambda r: r["state"] == "FAILED_QUORUM" and r["w_out"] is None and r["modelOutDigest"] is None
                   and r["excluded"] == [{"participantId": "P-B", "updateDigest": subs[1]["update"]["updateDigest"],
                                          "reasons": ["late"]}]
                   and r["quorum"] == {"needed": 2, "accepted": 1, "selected": 3, "met": False})(res(late)))
    control("a round below quorum still published a model", lambda: res(late)["w_out"] is not None)

    def planted(**kw):
        r = copy.deepcopy(res(late))
        r.update(kw)
        return r
    check("a below-quorum record that carries a model is reported by the checker",
          lambda: "below-quorum-published" in fl.verify_round(planted(
              state="COMPLETED", w_out=[14, 14, 31], modelOutDigest=fl.model_digest([14, 14, 31]))))
    control("the checker let through a record of a round below quorum that publishes a model",
            lambda: fl.verify_round(planted(state="COMPLETED", w_out=[14, 14, 31],
                                            modelOutDigest=fl.model_digest([14, 14, 31]))) == [])
    check("governance row: below quorum means FAILED_QUORUM, no model, no new version on the CSE",
          lambda: fl.gov_quorum({"round": res(late), "versions_before": ["v1"], "versions_after": ["v1"]})[0]
          and not fl.gov_quorum({"round": res(late), "versions_before": ["v1"], "versions_after": ["v1", "v2"]})[0]
          and not fl.gov_quorum({"round": res(), "versions_before": ["v1"], "versions_after": ["v1"]})[0])
    poisoned = eager(lambda: [subs[0], subs[1], upd(rd, ctx, "P-C", [0, 100000, 0])])
    check("a poisoned update (outside the bound) is excluded with its reason; the round completes without it",
          lambda: (lambda r: r["w_out"] == [13, 18, 31] and r["excluded"][0]["participantId"] == "P-C"
                   and r["excluded"][0]["reasons"] == ["out-of-bound"])(res(poisoned)))
    control("a poisoned update (outside the stated bound) was accepted",
            lambda: "P-C" in [a["participantId"] for a in res(poisoned)["accepted"]])
    control("the checker let through a record whose accepted update is outside the bound",
            lambda: (lambda r: (r["accepted"][0].update(delta=[4, 5000, 1]), fl.verify_round(r))[1])(
                copy.deepcopy(res())) == [])
    # replay: P-A's update of round 1, read again in round 2 (same bytes, same originator)
    def round1():
        tasks = [fl.task_record("op-1", 1, p, c, model_ref="cse-in/flOrch/model/v0", model_digest=D_W000,
                                binding_version=f"{p}-binding@1", deadline_ms=DEADLINE - 60_000,
                                update_destination="cse-mn-a/flAgg/updates", status_target=f"status/{p}")
                 for p, c in (("P-A", TFC), ("P-B", NAT), ("P-C", TFC))]
        rd1 = {**rd, "round": 1, "modelDigest": D_W000, "w": [0, 0, 0], "deadline_ms": DEADLINE - 60_000,
               "tasks": {t["taskId"]: t for t in tasks}}
        ctx1 = {**ctx, "datasets": {(k[0], "1"): v for k, v in ctx["datasets"].items()}}
        mk = lambda t, ds, n, d, who: {"update": fl.update_record(  # noqa: E731
            t, dataset_ref=ds, dataset_version="1", dataset_digest=ctx1["datasets"][(ds, "1")]["digest"],
            effective_sample_count=n, delta=d), "creator": who, "created_ms": DEADLINE - 61_000}
        old = mk(tasks[0], "ds-A", 3, [9, 9, 9], TFC)
        return ctx1, old, fl.close_round(rd1, [old, mk(tasks[1], "ds-B", 1, [1, 1, 1], NAT)], ctx1)
    ctx1, old, r1 = eager(round1, 3)
    replayed = eager(lambda: [subs[0], subs[1], {**old, "created_ms": DEADLINE - 500}])
    # the aggregator of round 2 knows the digests round 1 accepted and both rounds' published datasets
    ctx_seen = eager(lambda: {**ctx, "seen": set(r1["seen"]), "datasets": {**ctx["datasets"], **ctx1["datasets"]}})
    check("round 1 accepted that update (so the replay below is of a once-valid update)",
          lambda: "P-A" in [a["participantId"] for a in r1["accepted"]]
          and old["update"]["updateDigest"] in r1["seen"])
    check("an earlier round's update sent again is excluded: wrong round, stale model, unknown task, and seen before",
          lambda: (lambda r: r["excluded"] == [{"participantId": "P-A", "updateDigest": old["update"]["updateDigest"],
                                                "reasons": ["unknown-task", "wrong-round", "stale-model",
                                                            "replay"]}]
                   and r["w_out"] == [13, 18, 31])(res(replayed, c=ctx_seen)))
    control("a replayed update (an earlier round's update sent again) was accepted",
            lambda: old["update"]["updateDigest"] in [a["updateDigest"] for a in res(replayed, c=ctx_seen)["accepted"]])
    check("the same update twice in one round counts once; the copy is a replay",
          lambda: (lambda r: len(r["accepted"]) == 2 and r["excluded"][0]["reasons"] == ["replay"]
                   and r["w_out"] == [13, 18, 31])(res([subs[0], subs[1], copy.deepcopy(subs[0])])))
    check("a second, different update for a task that already has one is a replay too (one update per task)",
          lambda: (lambda r: r["excluded"][0]["reasons"] == ["replay"] and r["w_out"] == [13, 18, 31])(
              res([subs[0], subs[1], upd(rd, ctx, "P-A", [1, 1, 1], created=DEADLINE - 10)])))
    check("the digests a round accepted are handed on, so a later round can refuse them",
          lambda: res()["seen"] == sorted(s["update"]["updateDigest"] for s in subs))
    revoked_ctx = eager(lambda: {**ctx, "source_state": {**ctx["source_state"], "flSrc2": "revoked"}})
    three = eager(lambda: [subs[0], subs[1], upd(rd, ctx, "P-C", [5, 5, 5])])
    check("an update whose source was revoked before acceptance is excluded; the others still make the quorum",
          lambda: (lambda r: r["excluded"] == [{"participantId": "P-C", "updateDigest": three[2]["update"]["updateDigest"],
                                                "reasons": ["source-revoked"]}] and r["w_out"] == [13, 18, 31])(
              res(three, c=revoked_ctx)))
    control("an update from a revoked source was accepted",
            lambda: "P-C" in [a["participantId"] for a in res(three, c=revoked_ctx)["accepted"]])
    # all three accepted, weights 3, 1, 2: (12-2+10)/6 = 3.33 -> 3; (-18+9+10)/6 = 0.17 -> 0; (3+0+10)/6 = 2.17 -> 2
    check("with all three accepted the model is [13, 20, 32] (so the exclusion above changed the result)",
          lambda: res(three)["w_out"] == [13, 20, 32] and len(res(three)["accepted"]) == 3)
    # the bound and the deadline alone, in records that are otherwise consistent
    # delta [4, 5000, 1] n 3 with [-2, 9, 0] n 1: (15000+9)/4 = 3752.25 -> 3752 => [13, 3772, 31]
    def consistent(mut, w_out):
        r = copy.deepcopy(res())
        mut(r)
        r.update(w_out=w_out, modelOutDigest=fl.model_digest(w_out))
        return fl.verify_round(r)
    check("the checker reports an accepted update outside the bound even when the average was recomputed to fit",
          lambda: consistent(lambda r: r["accepted"][0].update(delta=[4, 5000, 1]), [13, 3772, 31]) == ["out-of-bound-accepted"])
    check("the checker reports an accepted update that is later than the deadline",
          lambda: consistent(lambda r: r["accepted"][0].update(created_ms=DEADLINE + 1), [13, 18, 31]) == ["late-accepted"])
    check("the checker reports an update that is listed as accepted and as excluded",
          lambda: consistent(lambda r: r["excluded"].append({"participantId": "P-A", "reasons": ["late"],
                                                             "updateDigest": r["accepted"][0]["updateDigest"]}),
                             [13, 18, 31]) == ["accepted-and-excluded"])
    for label, mut, why in (
            ("a model that is not the weighted average", lambda r: r.update(w_out=[13, 18, 32]), "aggregate-mismatch"),
            ("a model digest that is not the model's", lambda r: r.update(modelOutDigest=D_W9), "aggregate-mismatch"),
            ("an input digest that is not the input model's", lambda r: r.update(modelInDigest=D_W9), "aggregate-mismatch"),
            ("a weight changed after the fact", lambda r: r["accepted"][0].update(n=30), "aggregate-mismatch"),
            ("an accepted participant that was not selected", lambda r: r.update(selected=["P-A", "P-C"]),
             "accepted-not-selected"),
            ("one participant accepted twice", lambda r: r["accepted"].append(dict(r["accepted"][0])), "duplicate-accepted"),
            ("quorum numbers that are not the record's", lambda r: r["quorum"].update(accepted=3), "quorum-fields"),
            ("a completed state without a model", lambda r: r.update(w_out=None, modelOutDigest=None), "state"),
            ("no sim flag", lambda r: r.pop("sim"), "not-sim")):
        def one(mut=mut, why=why):
            r = copy.deepcopy(res())
            mut(r)
            return why in fl.verify_round(r)
        check(f"the checker reports {label}", one)

    print("== the two multi-source modes [TR 7.3.5.9.9 checks 4 and 5, facts F41, F42, F17]")
    def profile(pid, mode, ds, srcs, n, tasks):
        return fl.participant_profile(pid, "op-1", TFC, mode, dataset_ref=ds, dataset_version="1", sources=srcs,
                                      effective_sample_count=n, task_refs=tasks)
    p_agg = lambda: profile("P-AGG", "aggregatedSources", "ds-agg", ["flSrc1", "flSrc2"], 12, ["op-1-r1-P-AGG"])  # noqa: E731
    check("a participant profile has every attribute; the source count is recorded but is not the weight",
          lambda: (lambda p: fl.missing_fields("flParticipantProfile", p) == [] and p["representedSourceCount"] == 2
                   and p["effectiveSampleCount"] == 12 and p["weightingPolicyRef"] == "effectiveSampleCount"
                   and p["sim"] is True)(p_agg()))
    o4 = lambda **kw: {"client": TFC, "sources": 2, "profile": p_agg(), "tasks": [{"participantId": "P-AGG", "selectedClient": TFC}],  # noqa: E731
                       "updates": [{"participantId": "P-AGG", "creator": TFC}],
                       "round": {"weightingBasis": "effectiveSampleCount",
                                 "accepted": [{"participantId": "P-AGG", "n": 12}, {"participantId": "P-B", "n": 8}]}, **kw}
    check("check 4: two sources, ONE participant and ONE update from the Trusted FL Client, weight = sample count",
          lambda: fl.ac4_aggregated(o4())[0])
    check("check 4 fails with two updates from the client",
          lambda: not fl.ac4_aggregated(o4(updates=[{"participantId": "P-AGG", "creator": TFC}] * 2))[0])
    check("check 4 fails when the weight used was the source count",
          lambda: not fl.ac4_aggregated(o4(round={"weightingBasis": "effectiveSampleCount",
                                                  "accepted": [{"participantId": "P-AGG", "n": 2}]}))[0])
    check("check 4 fails when the weighting basis was not logged",
          lambda: not fl.ac4_aggregated(o4(round={"accepted": [{"participantId": "P-AGG", "n": 12}]}))[0])
    check("check 4 fails when one source is counted as the dataset's only source",
          lambda: not fl.ac4_aggregated(o4(profile=profile("P-AGG", "aggregatedSources", "ds-agg", ["flSrc1"], 12, [])))[0])
    i5 = lambda **kw: {  # noqa: E731
        "client": TFC,
        "tasks": [{"taskId": "op-1-r2-P-S1", "participantId": "P-S1", "selectedClient": TFC},
                  {"taskId": "op-1-r2-P-S2", "participantId": "P-S2", "selectedClient": TFC}],
        "profiles": [profile("P-S1", "independentSources", "ds-s1", ["flSrc1"], 17, ["op-1-r2-P-S1"]),
                     profile("P-S2", "independentSources", "ds-s2", ["flSrc2"], 14, ["op-1-r2-P-S2"])],
        "updates": [{"taskId": "op-1-r2-P-S1", "participantId": "P-S1", "updateDigest": "d1", "datasetRef": "ds-s1"},
                    {"taskId": "op-1-r2-P-S2", "participantId": "P-S2", "updateDigest": "d2", "datasetRef": "ds-s2"}], **kw}
    check("check 5: one client AE, two participants with their own task, dataset and update identities",
          lambda: fl.ac5_independent(i5())[0])
    check("check 5 fails when both updates name one participant",
          lambda: not fl.ac5_independent(i5(updates=[{**u, "participantId": "P-S1"} for u in i5()["updates"]]))[0])
    check("check 5 fails when both participants share one dataset",
          lambda: not fl.ac5_independent(i5(updates=[{**u, "datasetRef": "ds-s1"} for u in i5()["updates"]]))[0])
    check("check 5 fails when the two updates are the same bytes",
          lambda: not fl.ac5_independent(i5(updates=[{**u, "updateDigest": "d1"} for u in i5()["updates"]]))[0])

    print("== revocation, relocation, retention [TR 7.3.5.9.9 checks 6, 7, 8, facts F42, F43, F32, F33]")
    o6 = {"read_before": 200, "read_after": 403, "policy_state": "revoked", "dataset_state": "invalid", "affected": "P-S2",
          "excluded": [{"participantId": "P-S2", "reasons": ["source-revoked"]}], "accepted": ["P-S1", "P-B"]}
    check("check 6: reads denied after the revocation, dataset invalid, the pending update excluded",
          lambda: fl.ac6_revocation(o6)[0])
    for k, v in (("read_after", 200), ("dataset_state", "valid"), ("excluded", []), ("accepted", ["P-S1", "P-S2"]),
                 ("policy_state", "active"), ("read_before", 403)):
        check(f"check 6 fails with {k} = {v!r}", lambda k=k, v=v: not fl.ac6_revocation({**o6, k: v})[0])
    moved = dict(processor="CflTfc2", domain="edge-b")
    fresh = {"flSrc1": policy("flSrc1", "CflAuthA", policyVersion="2", authorizedProcessorRefs=[TFC, "CflTfc2"],
                              allowedExecutionDomains=["edge-a", "edge-b"])}
    check("a moved client is not covered by the old policy: another processor and another domain",
          lambda: auth({"flSrc1": pols["flSrc1"]}, sources=("flSrc1",), **moved)["refusals"]
          == {"flSrc1": ["processor-not-authorized", "domain-not-allowed"]})
    o7 = lambda **kw: {"read_before": 403, "binding_before": auth({"flSrc1": pols["flSrc1"]}, sources=("flSrc1",), **moved),  # noqa: E731
                       "old_policy_version": "1", "fresh_policy_version": "2", "read_after": 200,
                       "binding_after": auth(fresh, sources=("flSrc1",), **moved), **kw}
    check("check 7: blocked at the new host (403 and no binding) until a fresh policy version approves it",
          lambda: fl.ac7_relocation(o7())[0])
    for k, v in (("read_before", 200), ("read_after", 403), ("fresh_policy_version", "1")):
        check(f"check 7 fails with {k} = {v!r}", lambda k=k, v=v: not fl.ac7_relocation(o7(**{k: v}))[0])
    check("check 7 fails when the old policy already covered the new host (nothing was blocked)",
          lambda: not fl.ac7_relocation(o7(binding_before=auth(fresh, sources=("flSrc1",), **moved)))[0])
    o8 = {"temp_copies": [{"ref": "flTfc/flTmp/ds-s1-1", "created": 201, "deleted": 200, "readback": 404},
                          {"ref": "flTfc/flTmp/ds-s2-1", "created": 201, "deleted": 200, "readback": 404}],
          "accepted_from_revoked": 2,
          "irreversible": [{"what": "model v1", "why": "the aggregate cannot be separated into its contributions"},
                           {"what": "model v2", "why": "the aggregate cannot be separated into its contributions"}]}
    check("check 8: every temporary copy deleted and gone on read-back; what cannot be undone is listed",
          lambda: fl.ac8_retention(o8)[0])
    check("check 8 fails while one temporary copy still answers",
          lambda: not fl.ac8_retention({**o8, "temp_copies": [{**o8["temp_copies"][0], "readback": 200}]})[0])
    check("check 8 fails when accepted contributions of a revoked source exist and nothing is listed as irreversible",
          lambda: not fl.ac8_retention({**o8, "irreversible": []})[0])
    check("check 8 fails when no temporary copy was ever recorded (nothing was checked)",
          lambda: not fl.ac8_retention({**o8, "temp_copies": []})[0])

    print("== discovery without observations; raw data stays [TR 7.3.5.9.9 check 1, fact F40; FL_02 step 5, line 624]")
    check("an env record is found by the scan, also inside a contentInstance's con string",
          lambda: fl.scan_raw({"m2m:cin": {"con": '{"battery_pct": 80, "battery_temp_c": 25.0}'}}) != []
          and fl.scan_raw([{"x": 1}, {"deep": [{"battery_temp_c": 25.0}]}]) != [])
    check("assembled samples count as observations too", lambda: fl.scan_raw({"samples": [{"t": 0, "x": [0, 32], "y": 4}]}) != [])
    check("labels, digests and counts are not observations",
          lambda: fl.scan_raw({"lbl": ["fl:role:data-source"], "effectiveSampleCount": 12, "datasetDigest": "ab"}) == [])
    o1 = {"registered": {"flSrc1": 201, "flSrc2": 201, "flTfc": 201}, "expect_sources": ["flSrc1", "flSrc2"],
          "expect_tfc": "flTfc", "found": {"sources": ["flSrc1", "flSrc2"], "tfc": ["flTfc"]},
          "payloads": [{"m2m:uril": ["cse-mn-a/flSrc1/flCap"]}, {"mad:dmCay": {"name": "fl.localTraining"}}]}
    check("check 1: three registrations, both sources and the client found, nothing observed in what came back",
          lambda: fl.ac1_register_discover(o1)[0])
    check("check 1 fails when a discovery answer carried an observation",
          lambda: not fl.ac1_register_discover({**o1, "payloads": [{"con": '{"battery_pct": 80}'}]})[0])
    check("check 1 fails when one source was not found",
          lambda: not fl.ac1_register_discover({**o1, "found": {"sources": ["flSrc1"], "tfc": ["flTfc"]}})[0])
    check("check 1 fails when a registration was refused",
          lambda: not fl.ac1_register_discover({**o1, "registered": {**o1["registered"], "flTfc": 403}})[0])
    check("FL_02 step 5: nothing observed at the centre or at the aggregator, and the orchestrator's read is refused",
          lambda: fl.fl02_5_raw_stays({"central_payloads": [good["update"], {"w": [1, 2, 3]}], "orch_raw_read": 403})[0])
    check("FL_02 step 5 fails on one raw row at the centre",
          lambda: not fl.fl02_5_raw_stays({"central_payloads": [{"battery_temp_c": 25.0}], "orch_raw_read": 403})[0])
    check("FL_02 step 5 fails when the orchestrator can read the source",
          lambda: not fl.fl02_5_raw_stays({"central_payloads": [], "orch_raw_read": 200})[0])

    print("== the other steps of TD_MEC_FL_02")
    n2 = {"selected_clients": ["flTfc", "flNat"], "not_selected": ["flDec"],
          "notifications": [{"endpoint": "flTfc", "selectedClient": TFC, "taskId": "t1"},
                            {"endpoint": "flNat", "selectedClient": NAT, "taskId": "t2"}],
          "client_of": {"flTfc": TFC, "flNat": NAT, "flDec": DEC}}
    check("step 2: every selected client was notified of its own task; nobody else was", lambda: fl.fl02_2_notified(n2)[0])
    check("step 2 fails when one selected client got nothing",
          lambda: not fl.fl02_2_notified({**n2, "notifications": n2["notifications"][:1]})[0])
    check("step 2 fails when the one that declined was notified of a task",
          lambda: not fl.fl02_2_notified({**n2, "notifications": n2["notifications"] + [
              {"endpoint": "flDec", "selectedClient": DEC, "taskId": "t3"}]})[0])
    d3 = {"model_digest": D_W9, "published": 201, "selected_clients": ["flTfc", "flNat"],
          "reads": {"flTfc": {"status": 200, "digest": D_W9}, "flNat": {"status": 200, "digest": D_W9}}}
    check("step 3: the model is in the container and each selected client read the same bytes", lambda: fl.fl02_3_distributed(d3)[0])
    check("step 3 fails when one client's copy has another digest",
          lambda: not fl.fl02_3_distributed({**d3, "reads": {**d3["reads"], "flNat": {"status": 200, "digest": D_W000}}})[0])
    check("step 3 fails when one selected client did not read it",
          lambda: not fl.fl02_3_distributed({**d3, "reads": {"flTfc": d3["reads"]["flTfc"]}})[0])
    check("before training a client checks task identity, binding version and model digest [fact F18, TR 7049-7059]",
          lambda: fl.verify_task(t_a, me=TFC, binding_version="P-A-binding@1", model_body=fl.model_body(W_IN)) == [])
    check("... another client's task: not-my-task",
          lambda: fl.verify_task(t_a, me=NAT, binding_version="P-A-binding@1", model_body=fl.model_body(W_IN)) == ["not-my-task"])
    check("... an older binding: binding-version",
          lambda: fl.verify_task(t_a, me=TFC, binding_version="P-A-binding@2", model_body=fl.model_body(W_IN)) == ["binding-version"])
    check("... a model that is not the one the task names: model-digest",
          lambda: fl.verify_task(t_a, me=TFC, binding_version="P-A-binding@1", model_body=fl.model_body([9, 23, 30])) == ["model-digest"])
    check("... a task whose identifier does not match its content: task-id",
          lambda: fl.verify_task({**t_a, "roundRef": 3}, me=TFC, binding_version="P-A-binding@1",
                                 model_body=fl.model_body(W_IN)) == ["task-id"])
    c4 = {"clients": [{"participantId": "P-A", "verify": [], "samples": 3, "status": 201},
                      {"participantId": "P-B", "verify": [], "samples": 1, "status": 201}], "selected": ["P-A", "P-B"]}
    check("step 4: each selected participant verified its task and trained on its own samples", lambda: fl.fl02_4_training(c4)[0])
    check("step 4 fails when one trained on nothing, or trained although its task did not verify",
          lambda: not fl.fl02_4_training({**c4, "clients": [c4["clients"][0], {**c4["clients"][1], "samples": 0}]})[0]
          and not fl.fl02_4_training({**c4, "clients": [c4["clients"][0], {**c4["clients"][1], "verify": ["model-digest"]}]})[0])
    u6 = {"uploads": [{"participantId": "P-A", "status": 201, "creator": TFC, "clientAERef": TFC, "ty": 4},
                      {"participantId": "P-B", "status": 201, "creator": NAT, "clientAERef": NAT, "ty": 4}]}
    check("step 6: each update is a contentInstance the CSE created and recorded under the client's own originator",
          lambda: fl.fl02_6_upload(u6)[0])
    check("step 6 fails when the CSE recorded another creator, or the create was refused, or there is only one",
          lambda: not fl.fl02_6_upload({"uploads": [u6["uploads"][0], {**u6["uploads"][1], "creator": TFC}]})[0]
          and not fl.fl02_6_upload({"uploads": [u6["uploads"][0], {**u6["uploads"][1], "status": 403}]})[0]
          and not fl.fl02_6_upload({"uploads": u6["uploads"][:1]})[0])
    c7 = eager(lambda: {"posted": [s["update"]["updateDigest"] for s in subs],
                        "collected": [s["update"]["updateDigest"] for s in subs] + ["d0"], "round": res()})
    check("step 7: every update posted in time was read by the aggregator, and none accepted is past the deadline",
          lambda: fl.fl02_7_collected(c7)[0])
    check("step 7 fails when the aggregator missed a posted update",
          lambda: not fl.fl02_7_collected({**c7, "collected": c7["collected"][:1]})[0])
    check("step 7 fails when an accepted update is later than the deadline",
          lambda: (lambda r: (r["accepted"][0].update(created_ms=DEADLINE + 1), not fl.fl02_7_collected({**c7, "round": r})[0])[1])(
              copy.deepcopy(res())))
    check("step 8: the aggregate recomputes and the held-out error went down",
          lambda: fl.fl02_8_aggregate({"round": res(), "loss_before": 42, "loss_after": 29})[0])
    check("step 8 fails when the error did not go down, or the record does not recompute",
          lambda: not fl.fl02_8_aggregate({"round": res(), "loss_before": 42, "loss_after": 42})[0]
          and not fl.fl02_8_aggregate({"round": {**res(), "w_out": [0, 0, 0]}, "loss_before": 42, "loss_after": 29})[0])
    d9 = eager(lambda: {"model_digest": res()["modelOutDigest"], "published": 201, "participants": ["flTfc", "flNat"],
                        "reads": {c: {"status": 200, "digest": fl.model_digest([13, 18, 31])} for c in ("flTfc", "flNat")}})
    check("step 9: the new version is in the container and ALL participants read it, the straggler too",
          lambda: fl.fl02_9_redistributed(d9)[0])
    check("step 9 fails when one participant did not get it",
          lambda: not fl.fl02_9_redistributed({**d9, "reads": {"flTfc": d9["reads"]["flTfc"]}})[0])
    check("step 10: completed at 2 of 3 (the stated rate is 2/3) and the straggler is logged with a reason",
          lambda: fl.fl02_10_completion({"round": res()})[0])
    check("step 10 fails for a round below quorum", lambda: not fl.fl02_10_completion({"round": res(late)})[0])
    check("step 10 fails when a selected participant is neither accepted nor logged",
          lambda: not fl.fl02_10_completion({"round": {**res(), "missing": []}})[0])

    print("== delivery is separate from aggregation [fact F19, F20]")
    pub = eager(lambda: {1: fl.model_digest([13, 18, 31]), 2: fl.model_digest([14, 19, 31])})
    pkg = lambda v, w: fl.model_package(v, w, parent_digest=D_W000, round_ref=v)  # noqa: E731
    check("a package carries the model, its digest, its parent and says sim: true",
          lambda: (lambda p: p["modelVersion"] == 1 and p["model"] == fl.model_body([13, 18, 31])
                   and p["modelDigest"] == pub[1] and p["parentDigest"] == D_W000 and p["sim"] is True)(pkg(1, [13, 18, 31])))
    check("a sound package of a published version has no objection", lambda: fl.check_package(pkg(1, [13, 18, 31]), pub[1]) == [])

    def bad_pkg():
        p = pkg(1, [13, 18, 31])
        p["model"]["w"] = [13, 18, 99]          # the weights changed, the stated digest did not
        return p
    check("a package whose content does not hash to its stated digest: digest-mismatch",
          lambda: fl.check_package(bad_pkg(), pub[1]) == ["digest-mismatch"])
    control("a model package whose digest does not match was accepted", lambda: fl.check_package(bad_pkg(), pub[1]) == [])
    check("a self-consistent package of a model the aggregator never published: not-published",
          lambda: fl.check_package(pkg(1, [13, 18, 99]), pub[1]) == ["not-published"])
    check("another schema, or two weights: schema",
          lambda: (lambda p: (p["model"].update(schema="other"), fl.check_package(p, pub[1]))[1])(pkg(1, [13, 18, 31]))[0] == "schema"
          and (lambda p: (p["model"].update(w=[13, 18]), fl.check_package(p, pub[1]))[1])(pkg(1, [13, 18, 31]))[0] == "schema")
    act = lambda v, verdict="activated", d=None: {"modelVersion": v, "modelDigest": d or pub[v], "verdict": verdict}  # noqa: E731
    check("nothing activated: no active version", lambda: fl.deployment_view(pub, [])["active"] is None)
    check("v1 activated, v2 aggregated but not deployed: active is 1, and 2 is listed as undeployed",
          lambda: fl.deployment_view(pub, [act(1)]) == {"aggregated": [1, 2], "active": 1, "undeployed": [2]})
    control("a model version that was aggregated but not deployed shows as active",
            lambda: fl.deployment_view(pub, [act(1)])["active"] == 2)
    check("a refused activation changes nothing", lambda: fl.deployment_view(pub, [act(1), act(2, "refused")])["active"] == 1)
    check("an activation echo with a digest the aggregator did not publish does not count",
          lambda: fl.deployment_view(pub, [act(1), act(2, d=D_W9)])["active"] == 1)
    check("the latest valid activation wins, and a rollback to 1 is visible",
          lambda: fl.deployment_view(pub, [act(1), act(2)])["active"] == 2
          and fl.deployment_view(pub, [act(1), act(2), act(1)])["active"] == 1)
    g5 = eager(lambda: {"published": pub, "activations": [act(1)], "expect_active": 1, "not_active": [2]})
    check("governance row: the aggregated, undeployed version is not the active one", lambda: fl.gov_deploy(g5)[0])
    check("... and the row fails if the target reports it active without a deployment",
          lambda: not fl.gov_deploy({**g5, "target_reports": 2})[0])
    g6 = {"reasons": ["digest-mismatch"], "target_verdict": "refused", "active_before": 1, "active_after": 1}
    check("governance row: the target refuses the bad package and its active version does not move",
          lambda: fl.gov_package(g6)[0])
    check("... and the row fails if the target activated it",
          lambda: not fl.gov_package({**g6, "target_verdict": "activated", "active_after": 2})[0]
          and not fl.gov_package({**g6, "reasons": []})[0])

    print("== KPI block: every rate with numerator, denominator and N [TD_MEC_OBS_01 step 4]")
    check("6 of 8 = 75.0 %", lambda: fl.kpi_rate(6, 8) == {"numerator": 6, "denominator": 8, "N": 8, "unit": "%", "value": "75.0"})
    check("2 of 3 = 66.7 %, 1 of 3 = 33.3 % (round half up, integer arithmetic)",
          lambda: (fl.kpi_rate(2, 3)["value"], fl.kpi_rate(1, 3)["value"]) == ("66.7", "33.3"))
    check("no trials: no value, N 0, and it says why", lambda: (lambda r: r["value"] is None and r["N"] == 0 and r["note"])(fl.kpi_rate(0, 0)))
    check("a numerator above its denominator is refused", lambda: raises(lambda: fl.kpi_rate(4, 3), ValueError))
    blk = eager(lambda: {"sim": True, "rates": {"participant_success_rate": fl.kpi_rate(6, 8)},
                         "fl_round_completion_time_s": {"values": ["0.412", "4.031", "0.398"], "N": 3, "unit": "s"},
                         "edge_cloud_bytes": {"values": [100, 120, 110], "N": 3, "unit": "bytes", "total": 330}})
    check("a block whose rates all carry numerator, denominator, N and unit is accepted", lambda: fl.kpi_ok(blk)[0])
    check("a rate without its N is refused",
          lambda: not fl.kpi_ok({**blk, "rates": {"x": {"numerator": 1, "denominator": 2, "unit": "%", "value": "50.0"}}})[0])
    check("a rate whose value is not its numerator over its denominator is refused",
          lambda: not fl.kpi_ok({**blk, "rates": {"x": {**fl.kpi_rate(6, 8), "value": "80.0"}}})[0])
    check("a list of values whose N is not its length is refused",
          lambda: not fl.kpi_ok({**blk, "fl_round_completion_time_s": {"values": ["1"], "N": 3, "unit": "s"}})[0])
    check("a block that does not say sim: true is refused", lambda: not fl.kpi_ok({k: v for k, v in blk.items() if k != "sim"})[0])

    print("== what the CSE enforces and what the application enforces [fact F38, TR lines 7830-7833]")
    check("the table names each control once, on one side",
          lambda: all(r["enforced_by"] in ("CSE", "application") and r["what"] for r in fl.ENFORCEMENT)
          and len({r["what"] for r in fl.ENFORCEMENT}) == len(fl.ENFORCEMENT) >= 8)
    check("the wording for a simulated class is the plan's", lambda: all(
        v.endswith("class represented by a simulated source") for v in fl.CLASS_WORDING.values()))
    check("the signature of an update is a NOT-RUN row, named as such",
          lambda: fl.NOT_RUN_SIGNATURE == "signature of the update: not run, waits for a decision on lab keys")

    fl03_rows()
    fl01_rows()
    fl01_wiring_rows()

    bad = [n for n, ok, _ in RESULTS if not ok]
    through = [n for n, went, _ in CONTROLS if went]
    print(f"\n{len(RESULTS) - len(bad)} passed, {len(bad)} failed; controls {len(CONTROLS)}, "
          f"all failed as they must: {bool(CONTROLS) and not through}")
    for n in through:
        print(f"  CONTROL DID NOT FAIL: {n}")
    return 1 if bad or through or not CONTROLS else 0


if __name__ == "__main__":
    raise SystemExit(main())
