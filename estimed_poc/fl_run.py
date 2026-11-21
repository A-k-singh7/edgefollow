#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ashish Kumar Singh
"""The federated-learning driver. It builds the minimal
demonstration of TR-0077 v0.4.0 clause 7.3.5.9.9 on the lab's CSEs with SIMULATED sources, runs three rounds and one
control round, and writes a results JSON. Every decision is fl_core's; this file does the oneM2M and MEC requests
and hands fl_core what the CSEs answered.

  on MN-CSE-A   flSrc1, flSrc2   data sources that cannot train (simulated), two administrative domains: their
                                 observations (sim_phone.py's env record) sit in <env>, readable by nobody but the
                                 source until the source's authority grants the Trusted FL Client
                flTfc            the Trusted FL Client: trains for flSrc1 and flSrc2; a MEC 011 application instance
                flNat            a client that trains on its own data (simulated); also the inference target
                flDec            a client whose descriptors match and that declines
                flAgg            the aggregator: <updates> (clients may CREATE, nobody but flAgg may read), <models>
                                 (in hierarchical mode, the default; see TD_MEC_FL_03 below for the other two)
  on the IN-CSE flOrch           the orchestrator: <ops>, <tasks> (with one subscription per selected client),
                                 <model> (distribution), <deploy> (packages) (hierarchical and centralised mode)
  on MN-CSE-B   flTfc2           the Trusted FL Client 'moved' to a host of another operator (check 7)

  round 1  aggregatedSources: flTfc is ONE participant for two sources, plus flNat          -> model v1, deployed
  round 2  independentSources: flTfc is two participants; flNat drops out; a round-1 update is sent again
                                                                                            -> model v2, NOT deployed
  round 3  independentSources: flSrc2 is revoked while its update is pending                -> model v3, deployed
  round 4  a control round, not one of the three: one update is outside the bound, so the round is below quorum
                                                                                            -> no model

No role acts as the CSE admin: CAdmin is used for the topology check and to confirm the cleanup, nothing else.
Not shown, and said so in the results file: a real device, an authenticated originator (the lab CSEs take the
X-M2M-Origin header as given), a signature on anything, more than one PC. Not a conformance claim.

    python estimed_poc/fl_run.py      # needs estimed/run_topology.sh up; starts and stops its own MEC 011 on :8097

With --sources <capture file of fl_capture.py>: the observations of flSrc1 and flSrc2 are then the
records two phones posted (or, for a capture marked "rehearsal", records the host made in the same shape). The host
posts them, unchanged, into the two source AEs: a host bridge stands in for the devices. They are read with
parse_env(device=True) and aligned by slot; the counts the rounds must find come from the capture file, where they
were worked out a second way. flNat, flDec, the held-out set and every other party stay simulated.

TD_MEC_FL_03 (ESTIMED test plan, 7.5.3): the same run in three deployment modes, and a comparison of round time and
edge-cloud bytes. Written down before anything was measured.

    python estimed_poc/fl_run.py --mode centralised | hierarchical | edge-only     # one mode; default hierarchical
    python estimed_poc/fl_run.py --compare     # the three, one after another, each a full run that cleans up after
                                               # itself; then one comparison record (fl03_compare_<time>.json)

  Where each party sits (PLACE, built from STAY and MOVE below; every step that names a CSE reads it):
                    flOrch     flAgg      flSrc1 flSrc2 flTfc flNat flDec, CflAuthA CflAuthB   flTfc2
    centralised     cse-in     cse-in     cse-mn-a                                             cse-mn-b
    hierarchical    cse-in     cse-mn-a   cse-mn-a  (today's placement: the same requests as before this mode
                                                     existed, up to clock values, request ids and how often the
                                                     aggregator polls for updates)
    edge-only       cse-mn-a   cse-mn-a   cse-mn-a                                             cse-mn-b
  Only the orchestrator and the aggregator move. Data sources, clients and the two domain authorities (which have
  no AE of their own and act on their source's resources) stay at the edge in every mode. Every access policy is
  the same in every mode: it names originators, not CSEs. cse-in is the cloud; cse-mn-a, cse-mn-b and the MEC 011
  of district A are the edge.

  Bytes. Every HTTP request the driver sends and every response it receives is counted at the client side as it
  goes over the socket: the request line, the header lines, the blank line and the body once the socket has taken
  them (a request whose connection is refused counts 0); the status line, the header lines, the blank line and the
  body as read from it. Each call is attributed to (the party that makes it, the CSE it is sent to); the party is
  found from the originator (X-M2M-Origin). An originator that is in no table is not taken for the harness: it is
  the party 'unmapped:<originator>', counted at the CSE it was sent to, listed in the FL_03 block, and it makes the
  FL_03 recording step fail.
  A call is an edge-cloud call when it joins the two sides: a party at the edge calls the IN-CSE, or a party in
  the cloud calls an edge CSE. A call sent to the IN-CSE with an SP-relative address of an edge CSE
  (/~/id-mn-a/...) is retargeted by the IN-CSE to that edge: it is one call, its bytes as the client counted them
  are added ONCE to the edge-cloud bytes and once to the IN-CSE (the CSE it was sent to), and the IN-CSE's own
  hop to the edge, which the client does not see, is not counted. This driver sends no retargeted call; the rule
  is there for a deployment that routes through the IN-CSE and is tested offline. Notifications are counted too:
  each request a CSE sends to a client's endpoint (/fl/<client>) and the listener's answer, as read and written
  at the listener, attributed to (the CSE that holds the orchestrator's task container, the client); it is
  edge-cloud when that CSE and the client are on different sides. The harness's own calls (CAdmin: topology,
  leftover and cleanup checks; the removal of a leftover AE of an earlier run, which goes under that AE's own
  originator so that no admin right is used; the MEC 011 liveness and listing probes) are counted per CSE and
  never as edge-cloud. Edge-cloud bytes of a round = calls and notifications made inside run_round (discovery to the
  deletion of the temporary copies); bytes per CSE are for the whole run. On one PC over loopback this is bytes
  counted at the client, not a network measurement: no packet was captured, nothing below HTTP (TCP, IP, TLS)
  is in it, and 'edge' and 'cloud' are ports on one host.

  Round time: wall time (time.monotonic_ns) from just before the round's first task is sent to the orchestrator's
  <tasks> container to the 201 for the new global model in the orchestrator's <model> container (the
  redistribution), in whole microseconds; the median is over the rounds of one run that published a model (1 to
  3; the control round 4 publishes none and has no round time). On loopback this says little about real latency.
  The times are set by the driver, not by the placement (round 2 lasts its window because a client drops out; the
  aggregator polls every AGG_POLL_S; every call is on one host), so no difference between the modes can be read
  from them, and not_shown says so.

  TD_MEC_FL_03 steps 7 and 8 (hybrid handover + FL, MEC_CFG_04, the FL client as a MEC app) are NOT-RUN: the
  Trusted FL Client is deployed as a MEC app (below) but on this host, not an edge VM, and no handover runs during
  a round. Every data source is simulated, so TD_MEC_FL_03 is at most PARTIAL.

TD_MEC_FL_01 (ESTIMED test plan, 7.5.1), run first in every mode, so that TD_MEC_FL_02's pre-condition holds in
the run. The MEC platform is TD_MEC_REG_03's (loaded by path and pinned by SHA-256 in mec_pinned.py): its platform agent
estimed/mec_app_deploy.py, our MEC 010-2 candidate on :8092 and our MEC 011 candidate (here district A's, :8097),
each loaded from the main tree by path and refused unless it hashes to its pin (mec_pinned.py; why by path and not
a copy is said there). Three packages (apps/, one program fl_app.py, three descriptors) go through that lifecycle:
onboard (the digests checked), create the instance, instantiate (the workload is a process of this user, started
from the platform's copy; ready = MEC 011 lists it), terminate. Recording relays in front of every CSE and MEC 011
(fl_platform.py) show what each app sent on Mca and Mp1.

  pre-condition  TD_MEC_REG_03 for the FL Orchestrator AE: the orchestrator package, its AE on the CSE the
                 placement names (cse-in in centralised and hierarchical mode, as MEC_CFG_03 puts it; cse-mn-a in
                 edge-only, for which the run writes a copy of the package naming that CSE). REG_03 itself says
                 "register it to the MN-CSE"; the two agree only in edge-only mode, so on cse-in the rows are named
                 "REG_03 procedure on cse-in (not the MN-CSE the test plan names)" and fl01.steps says the same
                 (reg03_scope). REG_03's own pre-conditions, REG_01 and REG_02, are not re-run here (REG_PRE: the
                 main tree's coverage table has them COVERED; a NOT-RUN row says so).
                 MEC 010-2 completes no operation: the instantiate stays PROCESSING there, and the row says that
                 state as read; 'completed' is the agent's own record; the order (MEC 010-2 answered the
                 instantiate, then the process started, then it spoke on Mp1) is read off a relay in front of
                 MEC 010-2 and /proc (fl_core.lifecycle_order)
  steps 1, 2     flNat (simulated FL-native device) registers its capability profile as two <flexContainer>s and
                 the orchestrator discovers it (as before)
  steps 3, 4     the Trusted FL Client package, deployed; its confirm_ready is held at the relay while the run
                 checks that MEC 011 does not list it yet; its AE on MN-CSE-A names flSrc1 and flSrc2 (the
                 simulated constrained devices) and both instance ids, and its baseline container holds the
                 binding record it wrote itself
  steps 5, 6     the MEC proxy package: a device listener (plain HTTP/JSON), its configuration (devPx1) in the
                 descriptor and as a record in the tree, a container and a proxy-path profile per device; the
                 simulated device devPx1 posts DEVICE_SERIES records to the endpoint the proxy published at MEC 011;
                 each must be in flProxy/devPx1 as sent, created by the proxy. Controls: an unconfigured device is
                 refused by the proxy; the device's own writes to the CSE (plain JSON; a Create under its own
                 originator) are refused; the orchestrator cannot read the bridged data
  step 7         the orchestrator discovers the capability profiles, reads each and its holder's AE, asks MEC 011
                 which instances are listed and MEC 010-2 which instances are INSTANTIATED of which package, and
                 enumerates candidates by fl_core.enumerate_candidates: a class counts through an app only if MEC
                 010-2 holds its instance INSTANTIATED, of a package whose descriptor (matched by the checksum MEC
                 010-2 holds) names that AE, and MEC 011 lists that instance with this AE as its endpoint (MEC 011
                 alone takes anyone). Controls: four stray profiles on two stray AEs, each registered at MEC 011
                 by itself and listed there: flStray copies the proxy's instance id and offers its own service under
                 it (a class that is none of the three; a constrained device no deployed client represents; a
                 proxy-path device), flStray2 made up its instance id (a proxy-path device). They are discovered
                 and not enumerated; both, with their MEC 011 registrations, are removed before round 1
  then           FL_02's ten steps and every row and control below, unchanged; the apps keep running through the
                 four rounds and are terminated in the cleanup, each checked to have removed its AE and its MEC 011
                 registration, and the platform to hold no instance, package or process of the run

  Who acts: the apps register themselves (AE, policy, baseline container, MEC 011 registration and service). The
  rest of the orchestrator's and the client's trees (the second policy, the other containers, the capability
  profile) and all orchestration and training stay in this driver, under the same originators, as before. The
  calls of the proxy's checker (CflProxyCheck), of the proxy's owner reading back its policies, of the stray
  fixture (CflStray, CflStray2, and their MEC 011 calls), of a stranger and of the device's bypass attempts are
  counted as the harness's; the apps' own requests and the agent's MEC 010-2 calls go through the relays and the
  agent, not through this driver's byte counter (fl01.relay_requests says how many), and neither do the
  orchestrator's two MEC 010-2 reads in step 7 (MEC 010-2 is not one of the FL_03 endpoints).
  What changes in the FL_03 numbers: from round 1 on the orchestrator's discovery also returns the proxy's
  device profile; the driver no longer sends the AE Creates of flOrch and flTfc, nor the Trusted FL Client's MEC
  011 registration, service and cleanup; it sends the reads and checks of FL_01 instead.

  Not shown (FL01_NOT_SHOWN): real devices; a container, a VM, isolation; any MEC platform but our candidates;
  that the apps do the training or the orchestration; an authenticated device or originator; an authenticated MEC
  011 or MEC 010-2; REG_03 as worded on cse-in; REG_01 and REG_02. TD_MEC_FL_01 comes out PARTIAL at most
  (fl01_verdict): every device is simulated.
"""
from __future__ import annotations

import functools
import hashlib
import http.client
import json
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "phone"))
sys.path.insert(0, str(HERE.parent / "estimed"))
import fl_capture as fc  # noqa: E402
import fl_core as fl  # noqa: E402
import fl_platform as fp  # noqa: E402  TD_MEC_FL_01: packages, relays, the simulated proxy-path device
import mec_pinned as mp  # noqa: E402  TD_MEC_FL_01: the REG_03 platform code, by pinned SHA-256
import handover as ho  # noqa: E402  the CSE addresses and resource type numbers; rq() has the wire shape of ho._req
from estimed_poc2 import STEPS, Abort, require, run_record, step  # noqa: E402

PY = "/home/edgefollow/edgefollow-lab/.venv/bin/python"
IN, A, B = (f"{h}/{c}" for h, c in (ho.IN_CSE, ho.EDGE_A, ho.EDGE_B))
ADMIN = "CAdmin"
ORCH, AGG, TFC, TFC2, NAT, DEC = "CflOrch", "CflAgg", "CflTfc", "CflTfc2", "CflNat", "CflDec"
OWNER = {"flOrch": ORCH, "flAgg": AGG, "flTfc": TFC, "flTfc2": TFC2, "flNat": NAT, "flDec": DEC,
         "flSrc1": "CflSrc1", "flSrc2": "CflSrc2"}
AUTH = {"flSrc1": "CflAuthA", "flSrc2": "CflAuthB"}          # one authority per administrative domain
DOMAIN = {"flSrc1": "lab-domain-A", "flSrc2": "lab-domain-B"}
MEC011 = "http://127.0.0.1:8097"                             # district A's MEC 011 port in orchestrator.py

# TD_MEC_FL_03: where each party sits (module text). PLACE is the one table every step reads; HOME is its AE half
# as addresses. Only flOrch and flAgg move; the rest stays at the edge in every mode.
MODES = ("centralised", "hierarchical", "edge-only")
CIN, CA, CB, CMEC = ho.IN_CSE[1], ho.EDGE_A[1], ho.EDGE_B[1], "mec011-a"
CSE_URL = {CIN: IN, CA: A, CB: B}
ENDPOINTS = {ho.IN_CSE[0]: CIN, ho.EDGE_A[0]: CA, ho.EDGE_B[0]: CB, MEC011: CMEC}   # where a call is sent, by address
SIDE = {CIN: "cloud", CA: "edge", CB: "edge", CMEC: "edge"}
CSI = {"id-in": CIN, "id-mn-a": CA, "id-mn-b": CB}          # the CSE-IDs an SP-relative (retargeted) address names
STAY = {"flSrc1": CA, "flSrc2": CA, "flTfc": CA, "flNat": CA, "flDec": CA, "flTfc2": CB,
        **{a: CA for a in AUTH.values()}}                    # the authorities: no AE, they act on their source's resources
MOVE = {"centralised": {"flOrch": CIN, "flAgg": CIN}, "hierarchical": {"flOrch": CIN, "flAgg": CA},
        "edge-only": {"flOrch": CA, "flAgg": CA}}
FL03_STEPS = {"centralised": (1, 2), "hierarchical": (3, 4), "edge-only": (5, 6)}
PARTY = {**{o: ae for ae, o in OWNER.items()}, **{a: a for a in AUTH.values()}}   # originator -> party; CAdmin: none
UNMAPPED = "unmapped:"                                       # + an originator in no table (party_of)
MODE, PLACE, HOME = "hierarchical", {}, {}                  # set by set_mode(), below the helpers
LISTEN = 8462                                                # the lab's notification range is loopback 8400-8499
OP = "op-fl-1"
ALL, RD, CRD, CREATE = 63, 34, 35, 1                         # acop: everything; RETRIEVE+DISCOVERY; +CREATE; CREATE
ROUND_TIMEOUT_S = 4.0
AGG_POLL_S = 0.25              # how often the aggregator looks for updates while a round's window is open
RESULTS_DIR = Path("/home/edgefollow/estimed-run/sim")

# The simulated telemetry: a fixed clock start and one fixed rule per source (fl_core.sim_series), CHUNK records
# per source before each of the three rounds. flSrc2 never posts its record 4, which leaves a gap.
T0, CHUNK = 1_800_000_000_000, 9
SERIES = {"flSrc1": (11, 0, 90), "flSrc2": (22, 20, 95), "flNat": (33, 8, 85), "flDec": (55, 12, 80)}   # seed, d0, pct0
SKIP = {"flSrc2": {4}}
HELD_OUT = (44, 4, 92, 40)     # the aggregator's evaluation series: 40 records, 39 samples, simulated like the rest
# Sample counts counted by hand from that layout (a source with k records in a row gives k-1 samples):
#  round 1  flSrc1 records 0..8 -> windows 0..7; flSrc2 records 0..3, 5..8 -> windows 0,1,2,5,6,7 (one gap);
#           both have 0,1,2,5,6,7 -> 6 + 6 = 12 samples, 2 of flSrc1's windows unused; flNat 9 records -> 8
#  round 2  flSrc1 18 records -> 17; flSrc2 17 records, one gap -> 15
#  round 3  flSrc1 27 -> 26; flNat 27 -> 26 (flSrc2: 26 records, one gap -> 24, excluded)
#  round 4  no new records: flSrc1 26, flNat 26
EXPECT_N = {1: {"P-NAT": 8, "P-TFC-AGG": 12}, 2: {"P-TFC-S1": 17, "P-TFC-S2": 15}, 3: {"P-NAT": 26, "P-TFC-S1": 26},
            4: {"P-NAT": 26}}
EXPECT_R1 = {"n": 12, "per_source": {"flSrc1": 6, "flSrc2": 6}, "dropped_gap": 1, "dropped_unaligned": 2}

# TD_MEC_FL_01 (module text). The proxy and the stray-profile fixture are not in OWNER, so the places FL_03 looks
# for leftovers stay as they were; they always sit on MN-CSE-A (their packages and the fixture say so).
MEC010 = "http://127.0.0.1:8092"                             # our MEC 010-2 candidate, as REG_03 runs it
FL01_OWNER = {"flProxy": "CflProxy", "flStray": "CflStray", "flStray2": "CflStray2"}
FL01_URL = {ae: f"{A}/{ae}" for ae in FL01_OWNER}
STRAYS = ("flStray", "flStray2")   # the step-7 fixture: two AEs that register themselves at MEC 011, never at MEC 010-2
PROXY_CSE = CA                    # the proxy package names cse-mn-a; the device and the proxy are at the edge
CHECKER = "CflProxyCheck"        # the proxy's named reader: the harness reads the bridged data under it
DEVICE_ID, UNKNOWN_DEVICE, DEVICE_ORIGIN = "devPx1", "devPx9", "CdevPx1"
DEVICE_SERIES = (66, 3, 88, 3)   # seed, d0, pct0, records: what the simulated proxy-path device posts
STRANGER = "CflStranger"         # REG_03 step 4's control: an originator nobody named
FL01_EXPECT = {"fl-native": ["flDec", "flNat"], "fl-assisted": ["flSrc1", "flSrc2"], "proxy-path": ["devPx1"]}
FL01_STRAY = {   # AE -> rn -> labels of the profiles each stray holds during step 7 (each must be refused)
    # flStray copies the proxy's MEC 010-2 instance id onto its AE and offers its own MEC 011 service under that id
    "flStray": {
        "flCap-other": ["fl:profile", "fl:role:device", "fl:class:fl-other", "fl:device:devOther", "fl:sim:true"],
        "flCap-src3": ["fl:profile", "fl:role:data-source", "fl:class:fl-assisted", "fl:device:flSrc3", "fl:sim:true"],
        "flCap-ghost": ["fl:profile", "fl:role:device", "fl:class:proxy-path", "fl:device:devGhost", "fl:via:flStray",
                        "fl:sim:true"]},
    # flStray2 registers itself at MEC 011 under an instance id it made up (MEC 010-2 never saw it)
    "flStray2": {
        "flCap-self": ["fl:profile", "fl:role:device", "fl:class:proxy-path", "fl:device:devSelf", "fl:via:flStray2",
                       "fl:sim:true"]}}
STRAY_DEVICES = {"devOther": "a device of none of the three classes",
                 "flSrc3": "a constrained device that no deployed Trusted FL Client represents (its holder copies the "
                           "proxy's instance id and offers its own MEC 011 service under it)",
                 "devGhost": "a proxy-path device whose holder copies the proxy's MEC 010-2 instance id and offers its own "
                             "MEC 011 service under it, naming itself",
                 "devSelf": "a proxy-path device whose holder registered itself at MEC 011 under an instance id it made up, "
                            "never through MEC 010-2"}
FL01_STEPS = ("pre-condition REG_03 (orchestrator)", *(f"step {i}" for i in range(1, 8)))
WORK_ROOT = Path("/home/edgefollow/estimed-run/fl01-work")         # the platform agent's store; removed by the cleanup
FL01_NOT_SHOWN = [
    "a real device of any class: flNat, flSrc1, flSrc2 and devPx1 are simulated; the proxy-path device is a function "
    "of this driver that sends plain HTTP/JSON, as a MicroPython board would",
    "a container, a VM or isolation: each app is an ordinary process of this user on one host, started by the platform "
    "agent with python3 -I -B and no environment; no container and no sandbox",
    "a MEC platform other than our own MEC candidates: MEC 010-2 and MEC 011 are the main tree's candidates, which the "
    "test plan's platform is not, and the platform agent is ours; not a conformance claim",
    "that the apps train or orchestrate: they register (AE, policy, baseline container, MEC 011 registration and "
    "service) and the proxy bridges data; discovery, selection, training and aggregation run in this driver under the "
    "apps' originators",
    "an authenticated device or originator: the proxy knows a device by the id in the path, and the CSEs take "
    "X-M2M-Origin as given, so a process that sends X-M2M-Origin: CflProxy is taken for the proxy",
    "that the proxy-path device takes part in a round: it is enumerated as a candidate (step 7) and no client trains "
    "on its data in rounds 1 to 4",
    "REG_03 as the test plan words it for the orchestrator in centralised and hierarchical mode: the orchestrator's "
    "workload is a MEC app on this host, its AE registers to the IN-CSE (MEC_CFG_03), not to an MN-CSE; those rows are "
    "named 'REG_03 procedure on cse-in' and fl01.steps says the same, so they are not a REG_03 pass",
    "TD_MEC_REG_01 and TD_MEC_REG_02, REG_03's own pre-conditions: not re-run here (COVERED in the main tree's "
    "estimed/TESTPLAN_COVERAGE.md; fl01.pre_condition)",
    "an authenticated MEC 011 registration: registration at our MEC 011 candidate is unauthenticated; any process that "
    "reaches it registers, offers a service under any instance id and confirms ready, and it then lists that service "
    "(two strays in step 7 do exactly that); so step 7 takes 'deployed' from MEC "
    "010-2 (an INSTANTIATED instance of a package whose descriptor names the AE) and uses MEC 011 only for the listing "
    "of that instance",
    "an authenticated MEC 010-2: our candidate takes any caller too; step 7 shows that a package naming the AE was "
    "onboarded and instantiated there (its descriptor matched by the checksum MEC 010-2 holds), not who did it",
    "that the instantiate operation completed at MEC 010-2: our candidate completes none and leaves it PROCESSING (the "
    "state as read is in fl01.deployed); 'completed' is the agent's own record, and the order 'instantiate, then the "
    "process' is observed on the agent's wire and in /proc",
]
REG_PRE = {     # TD_MEC_REG_03's own pre-conditions, as the main tree's coverage table states them; not re-run here
    "TD_MEC_REG_01": "not re-run here; COVERED in the main tree's estimed/TESTPLAN_COVERAGE.md (test_tr0086_bringup.py "
                     "test_5_2_4_5_*, test_tr0086_registration.py)",
    "TD_MEC_REG_02": "not re-run here; COVERED in the main tree's estimed/TESTPLAN_COVERAGE.md "
                     "(test_estimed_testplan.py::test_td_mec_reg_02_*)"}


def reg03_tag(cse: str) -> str:
    """The name of a REG_03 row for an AE on `cse`. REG_03 registers the AE 'to the MN-CSE'; on cse-in the run does
    REG_03's procedure on the IN-CSE, which the test plan does not name there, and the row says so."""
    return "REG_03" if cse != CIN else "REG_03 procedure on cse-in (not the MN-CSE the test plan names)"


def reg03_scope(cse: str | None, passed) -> str:
    """fl01.steps' value for the pre-condition: what holds, said so that it cannot be read as a REG_03 pass when the
    orchestrator's AE is on cse-in."""
    if passed is None:
        return "NOT-RUN"
    if passed is not True:
        return "FAIL"
    if cse == CIN:
        return ("PASS for REG_03's procedure on cse-in, not REG_03 as worded: the test plan registers the AE to the "
                "MN-CSE, MEC_CFG_03 puts the orchestrator at the IN-CSE; REG_01 and REG_02 not re-run here")
    return f"PASS on {cse}, the MN-CSE REG_03 names; REG_01 and REG_02 not re-run here"


RUN_FILES_FL = ("estimed_poc/fl_core.py", "estimed_poc/fl_run.py", "estimed_poc/test_fl.py", "estimed_poc/fl_capture.py",
                "estimed_poc/fl_platform.py", "estimed_poc/mec_pinned.py",
                *(f"estimed_poc/apps/{p}/{f}" for p in ("fl_orch", "fl_tfc", "fl_proxy") for f in ("appd.json", "fl_app.py")))


def fl01_verdict(steps: dict) -> str:
    """TD_MEC_FL_01: PARTIAL when the pre-condition and the seven steps all passed (every device is simulated, so
    no more), FAIL otherwise. Never PASS."""
    return "PARTIAL" if all(steps.get(k) is True for k in FL01_STEPS) else "FAIL"


TRACE: list[str] = []           # one line per request: who, what, where, the CSE's answer
NOTES: list[dict] = []          # task notifications as the listener received them
ORCH_SEEN: list = []            # every body the orchestrator received (scanned for observations)
CALLS: list[dict] = []          # every request the driver sent (oneM2M and MEC 011), counted at the socket
NOTIFY_LOG: list[dict] = []     # every request the listener received, counted at the socket
ROUND = 0                       # the round run_round is in; 0 outside a round
NOT_RUN: list[dict] = []
DEV: dict | None = None         # --sources: the capture whose records stand for flSrc1 and flSrc2
DEV_SRC = ("flSrc1", "flSrc2")
_n = 0


def is_dev(src: str) -> bool:
    return DEV is not None and src in DEV_SRC


def posted_by() -> str:
    return "the host bridge posted the captured records" if DEV else "the simulated sources posted their records"


# ------------------------------------------------------------------------------------------------ TD_MEC_FL_03
def placement(mode: str) -> dict[str, str]:
    """Party -> the CSE it sits on in `mode`. A name outside MODES is refused."""
    if mode not in MOVE:
        raise ValueError(f"unknown mode {mode!r}; the modes are {', '.join(MODES)}")
    return {**STAY, **MOVE[mode]}


def set_mode(mode: str) -> None:
    global MODE, PLACE, HOME
    PLACE = placement(mode)
    MODE, HOME = mode, {ae: CSE_URL[PLACE[ae]] for ae in OWNER}


def addr(ae: str, *path: str, place: dict) -> str:
    return "/".join([CSE_URL[place[ae]], ae, *path])


def url(ae: str, *path: str) -> str:
    return "/".join([HOME[ae], ae, *path])


def task_targets(ae: str, version: int) -> tuple[str, str, str]:
    """What a task names: the model to train from, where the update goes, where the client reports."""
    return f"{PLACE['flOrch']}/flOrch/model/v{version}", f"{PLACE['flAgg']}/flAgg/updates", f"{PLACE[ae]}/{ae}/flStatus"


def coordinator_ref() -> str:
    return f"{PLACE['flOrch']}/flOrch"


def spots() -> list[tuple[str, str]]:
    """Where an AE of an earlier run may be left. Hierarchical looks only where it puts its AEs, the eight places
    the run looked before the modes existed. The other two also look on every CSE another mode puts the
    orchestrator or the aggregator on."""
    out = [(ae, url(ae)) for ae in OWNER]
    if MODE != "hierarchical":
        out += [(ae, f"{CSE_URL[c]}/{ae}") for ae in ("flOrch", "flAgg")
                for c in sorted({MOVE[m][ae] for m in MODES} - {PLACE[ae]})]
    return out


def where(to: str) -> tuple[str, str, bool]:
    """(the endpoint a call is sent to, the CSE it is meant for, retargeted?). An SP-relative address on the IN-CSE
    (/~/id-mn-a/...) or an absolute one (/_/<SP>/id-mn-a/...) names another CSE: the IN-CSE retargets it there."""
    for base, name in ENDPOINTS.items():
        if to == base or to.startswith((base + "/", base + "?")):
            break
    else:
        raise ValueError(f"not one of the lab's endpoints: {to}")
    seg = to[len(base):].split("?", 1)[0].strip("/").split("/")
    if name != CMEC and seg[0] in ("~", "_"):
        csi = seg[1] if seg[0] == "~" and len(seg) > 1 else seg[2] if len(seg) > 2 else ""
        if csi not in CSI:
            raise ValueError(f"an address that names no CSE of the lab: {to}")
        return name, CSI[csi], CSI[csi] != name
    return name, name, False


def party_of(origin: str | None) -> str | None:
    """The party an originator stands for (module text: Bytes). CAdmin is the harness (None), and nothing else is:
    an originator in no table becomes the named party 'unmapped:<originator>', which no placement has, so its
    calls are counted and listed, never edge-cloud and never the harness's, and they fail the FL_03 step."""
    if origin == ADMIN:
        return None
    return PARTY.get(origin, f"{UNMAPPED}{origin}")


def classify(party: str | None, to: str, place: dict) -> dict:
    """Edge-cloud or not (module text: Bytes): the caller's side, the side of the CSE the call is sent to and the
    side of the CSE it is meant for; any two different sides make it an edge-cloud call, counted once however
    often it crosses. The harness (party None) is never edge-cloud. A party the placement does not know (an
    unmapped originator) has no side: edge_cloud is None, and tally lists the call as unmapped."""
    sent_to, target, retargeted = where(to)
    if party is not None and party not in place:
        return {"sent_to": sent_to, "target": target, "retargeted": retargeted, "edge_cloud": None}
    sides = set() if party is None else {SIDE[place[party]], SIDE[sent_to], SIDE[target]}
    return {"sent_to": sent_to, "target": target, "retargeted": retargeted, "edge_cloud": len(sides) > 1}


def tally(calls: list[dict], notes: list[dict], place: dict) -> dict:
    """Bytes of calls (request + response, as counted at the socket) and of notifications, in total, edge-cloud,
    retargeted, unmapped and per CSE. A call is counted at the CSE it was sent to, once; a notification at the CSE
    that holds the orchestrator's task container (the one that sends it). A call of a party the placement does not
    know is counted at its CSE and under 'unmapped' (with the party's name), not as the harness's."""
    per = {c: {"calls": 0, "bytes": 0, "harness_bytes": 0, "notification_bytes": 0} for c in SIDE}
    ec = {"calls_n": 0, "calls_bytes": 0, "notifications_n": 0, "notifications_bytes": 0, "total": 0}
    um, um_names = {"calls": 0, "bytes": 0, "parties": []}, set()
    out = {"calls": {"n": 0, "bytes": 0}, "edge_cloud": ec, "retargeted": {"calls": 0, "bytes": 0},
           "notifications": {"n": 0, "bytes": 0}, "unmapped": um, "per_cse": per}
    for c in calls:
        k, b = classify(c["party"], c["url"], place), c["sent"] + c["received"]
        per[k["sent_to"]]["calls"] += 1
        per[k["sent_to"]]["bytes"] += b
        per[k["sent_to"]]["harness_bytes"] += b if c["party"] is None else 0
        out["calls"]["n"] += 1
        out["calls"]["bytes"] += b
        if k["edge_cloud"] is None:
            um["calls"] += 1
            um["bytes"] += b
            um_names.add(c["party"])
        if k["retargeted"]:
            out["retargeted"]["calls"] += 1
            out["retargeted"]["bytes"] += b
        if k["edge_cloud"]:
            ec["calls_n"] += 1
            ec["calls_bytes"] += b
    sender = place["flOrch"]
    for n in notes:
        b, rcv = n["received"] + n["sent"], place.get(n["endpoint"])
        per[sender]["notification_bytes"] += b
        out["notifications"]["n"] += 1
        out["notifications"]["bytes"] += b
        if rcv is not None and SIDE[rcv] != SIDE[sender]:
            ec["notifications_n"] += 1
            ec["notifications_bytes"] += b
    ec["total"] = ec["calls_bytes"] + ec["notifications_bytes"]
    um["parties"] = sorted(um_names)
    return out


def round_marks(calls: list[dict], rnd: int, place: dict) -> dict:
    """From the round's own calls: when the first task was sent to the orchestrator's <tasks> (a contentInstance,
    not the subscription), when the aggregator's model and the orchestrator's redistributed model got their 201."""
    mine = [c for c in calls if c["round"] == rnd and c["method"] == "POST" and c["ty"] == ho.TY_CIN]
    pick = lambda u, who, ok: next((c for c in mine if c["url"] == u and c["party"] == who and c["status"] in ok), None)  # noqa: E731
    out = {}
    for key, u, who, ok, t in (("task_published", addr("flOrch", "tasks", place=place), "flOrch", range(0, 1000), "t0"),
                               ("model_aggregated", addr("flAgg", "models", place=place), "flAgg", (201,), "t1"),
                               ("model_published", addr("flOrch", "model", place=place), "flOrch", (201,), "t1")):
        c = pick(u, who, ok)
        if c is not None:
            out[key] = c[t]
    return out


def round_time_us(marks: dict) -> int | None:
    s, e = marks.get("task_published"), marks.get("model_published")
    return None if s is None or e is None or e < s else (e - s) // 1000


def median_us(values: list) -> int | None:
    v = sorted(x for x in values if x is not None)
    if not v:
        return None
    h = len(v) // 2
    return v[h] if len(v) % 2 else (v[h - 1] + v[h]) // 2


def fmt_s(us: int | None) -> str | None:
    return None if us is None else f"{us // 1_000_000}.{us % 1_000_000 // 1000:03d}"


FL03_DEFINITIONS = {
    "bytes": "every HTTP request the driver sends and every response it receives, counted at the client side as they "
             "go over the socket: request line + header lines + blank line + body once the socket has taken them (a "
             "request whose connection is refused counts 0); status line + header lines + blank line + body as read "
             "from it. Each call is attributed to (the party that makes it, found from X-M2M-Origin; the endpoint it "
             "is sent to)",
    "edge_cloud": "a call that joins the two sides: a party at the edge calling the IN-CSE, or a party in the cloud "
                  "calling an edge CSE (cse-mn-a, cse-mn-b, the MEC 011 of district A); plus the notifications a CSE "
                  "on one side sends to a client's endpoint on the other",
    "retargeted": "a call sent to the IN-CSE with an SP-relative or absolute address of an edge CSE: one call, its "
                  "bytes as the client counted them added once to edge-cloud and once to the IN-CSE; the IN-CSE's own "
                  "hop to the edge is not seen by the client and not counted. This driver sends none",
    "notifications": "each request a CSE sends to /fl/<client> and the listener's answer, as read and written at the "
                     "listener; attributed to (the CSE holding the orchestrator's <tasks>, the client)",
    "harness": "CAdmin's topology, leftover and cleanup checks, the removal of a leftover AE of an earlier run (sent "
               "under that AE's own originator, so no admin right is used) and the MEC 011 liveness and listing "
               "probes: counted per CSE, never edge-cloud",
    "unmapped": "a call whose originator is in no table: not the harness; counted at the CSE it was sent to, listed "
                "by name, never edge-cloud (its side is not known), and it makes the FL_03 recording step fail",
    "per_cse": "whole run: calls by the endpoint they were sent to, notifications by the CSE that sent them",
    "round_bytes": "the calls and notifications made inside run_round, from the orchestrator's discovery to the "
                   "deletion of the temporary copies",
    "round_time": "time.monotonic_ns from just before the round's first task is sent to the orchestrator's <tasks> "
                  "to the 201 for the new global model in the orchestrator's <model> (the redistribution), in whole "
                  "microseconds; a round that published no model has none",
    "median": "over the rounds of one run that have a round time; of an even number, the mean of the middle two, "
              "rounded down",
    "caveat": "one PC, loopback: this is bytes counted at the client, not a network measurement (no packet capture, "
              "nothing below HTTP, 'edge' and 'cloud' are ports on one host); the round time on loopback says little "
              "about real latency",
}
FL03_NOT_RUN = [
    {"row": "TD_MEC_FL_03 steps 7 and 8: hybrid handover + FL (MEC_CFG_04), the FL Client hosted as a MEC app, one "
            "round during or right after a handover", "result": "NOT-RUN",
     "reason": "not built: the Trusted FL Client is deployed as a MEC app through our MEC 010-2 candidate (TD_MEC_FL_01 "
               "step 3), but as a process on this host, not on an edge VM, its training still runs in this driver, "
               "and no handover runs during a round"},
    {"row": "TD_MEC_FL_03 pre-condition: TD_MEC_FL_02 has passed for at least one mode, with real devices",
     "result": "NOT-RUN",
     "reason": "TD_MEC_FL_02's ten steps run in each mode on top of TD_MEC_FL_01's onboarding in the same run, but "
               "every device is simulated, so TD_MEC_FL_01 and TD_MEC_FL_02 are PARTIAL, not passed"},
    {"row": "TD_MEC_FL_03 pre-condition: aggregation at the MEC (an aggregator as a MEC app)", "result": "NOT-RUN",
     "reason": "the edge aggregator is an AE on MN-CSE-A, not a MEC application"},
]
FL03_NOT_SHOWN = [
    "TD_MEC_FL_03 as a whole: at most PARTIAL, because every data source is simulated and steps 7 and 8 did not run",
    "bandwidth on a network: the bytes are counted at the client on one PC over loopback, not captured on a link; "
    "'edge' and 'cloud' are ports on one host",
    "latency: a round time on loopback says little about a round over a real edge-cloud link",
    f"a difference in round time between the modes: none can be read from these round times, because the driver sets "
    f"them, not the placement. Round 2 lasts its {ROUND_TIMEOUT_S} s window, since a client drops out and the aggregator "
    f"waits for the deadline, looking for updates every {AGG_POLL_S} s; rounds 1 and 3 are the driver's own calls made "
    "one after another on one host over loopback, with no link between 'edge' and 'cloud' to make a call to the IN-CSE "
    "slower than one to an MN-CSE. Round times that agree across the modes are therefore expected",
    "that the edge-cloud numbers are a finding about the modes: for the same simulated work they follow from where "
    "the table puts the two parties; the run shows the counting and that each mode runs with its controls holding",
]
FL03_COLUMNS = ("mode", "orchestrator", "aggregator", "run_verdict", "round_time_s", "median_round_time_s",
                "edge_cloud_bytes_per_round", "edge_cloud_bytes_rounds_1_to_3", "edge_cloud_bytes_whole_run",
                "bytes_cse_in", "bytes_cse_mn_a", "bytes_cse_mn_b", "bytes_mec011_a", "results_file")


def fl03_block(mode: str, calls: list[dict], notes: list[dict], rounds: list[int]) -> dict:
    """One run's TD_MEC_FL_03 record: placement, per-round time and edge-cloud bytes, bytes per CSE, definitions."""
    place, per_round = placement(mode), []
    for r in rounds:
        marks = round_marks(calls, r, place)
        t = tally([c for c in calls if c["round"] == r], [n for n in notes if n["round"] == r], place)
        us = round_time_us(marks)
        per_round.append({"round": r, "marks_ns": marks, "time_us": us, "time_s": fmt_s(us),
                          "edge_cloud_bytes": t["edge_cloud"]["total"], "edge_cloud_calls": t["edge_cloud"]["calls_n"],
                          "edge_cloud_notification_bytes": t["edge_cloud"]["notifications_bytes"],
                          "calls": t["calls"]["n"], "bytes": t["calls"]["bytes"] + t["notifications"]["bytes"],
                          "unmapped_calls": t["unmapped"]["calls"]})
    timed = [x["time_us"] for x in per_round if x["time_us"] is not None]
    whole = tally(calls, notes, place)
    return {"td": "TD_MEC_FL_03", "mode": mode, "steps": list(FL03_STEPS[mode]), "placement": place, "sides": dict(SIDE),
            "rounds": per_round,
            "round_time": {"values_us": timed, "values_s": [fmt_s(u) for u in timed], "N": len(timed),
                           "median_us": median_us(timed), "median_s": fmt_s(median_us(timed)),
                           "untimed_rounds": [x["round"] for x in per_round if x["time_us"] is None]},
            "edge_cloud_bytes": {"per_round": [x["edge_cloud_bytes"] for x in per_round],
                                 "rounds_1_to_3": sum(x["edge_cloud_bytes"] for x in per_round if x["round"] in (1, 2, 3)),
                                 "whole_run": whole["edge_cloud"], "unit": "bytes"},
            "bytes_per_cse": whole["per_cse"], "all_calls": whole["calls"], "notifications": whole["notifications"],
            "retargeted": whole["retargeted"], "unmapped": whole["unmapped"], "definitions": FL03_DEFINITIONS,
            "not_shown": list(FL03_NOT_SHOWN)}


def fl03_steps(f3: dict) -> list[tuple[str, bool, str]]:
    """The run's two TD_MEC_FL_03 rows (FL03_STEPS[mode]), from its block: (label, passed, detail). The second
    fails while any call's party is unknown (an unmapped originator), and names it."""
    mode, place = f3["mode"], f3["placement"]
    s1, s2 = FL03_STEPS[mode]
    r13 = [x for x in f3["rounds"] if x["round"] in (1, 2, 3)]
    um = f3["unmapped"]
    return [
        (f"[FL_03 step {s1}] {mode} mode (orchestrator on {place['flOrch']}, aggregator on {place['flAgg']}): rounds 1 "
         "to 3 each ran to a published model", len(r13) == 3 and all(x["time_us"] is not None for x in r13),
         f"round times {[x['time_s'] for x in r13]} s; the control round "
         f"{[x['round'] for x in f3['rounds'] if x['time_us'] is None]} published none, as it must"),
        (f"[FL_03 step {s2}] round completion time and edge-cloud bytes recorded for {mode} mode, every call's party known",
         len(r13) == 3 and all(isinstance(x["time_us"], int) and isinstance(x["edge_cloud_bytes"], int) for x in r13)
         and f3["round_time"]["median_us"] is not None and um["calls"] == 0,
         f"median {f3['round_time']['median_s']} s over {f3['round_time']['N']} rounds; edge-cloud bytes per round "
         f"{f3['edge_cloud_bytes']['per_round']} (rounds 1-3: {f3['edge_cloud_bytes']['rounds_1_to_3']}); bytes counted at "
         "the client on one PC, not a network measurement"
         + (f"; UNMAPPED originators, {um['calls']} calls, {um['bytes']} bytes: {', '.join(um['parties'])}" if um["calls"] else ""))]


def kpi_rounds(three: list[dict], f3: dict) -> dict:
    """The KPI block's round time and edge-cloud bytes, from run_round's own numbers (R["time_s"], R["bytes"]) of
    rounds 1 to 3; the median is the FL_03 block's. kpi_vs_fl03 checks the two paths against each other."""
    mb = sum(R["bytes"] for R in three)
    return {
        "fl_round_completion_time_s": {"values": [R["time_s"] for R in three], "N": len(three), "unit": "s",
                                       "from": "just before the round's first task is sent to the orchestrator's <tasks>",
                                       "to": "the 201 for the new global model in the orchestrator's <model>",
                                       "mode": f3["mode"], "median": f3["round_time"]["median_s"],
                                       "note": f"round 2 waits for its {ROUND_TIMEOUT_S} s window because one client drops "
                                               "out; the times are set by the driver, not by the placement (not_shown)"},
        "edge_cloud_bytes": {"values": [R["bytes"] for R in three], "N": len(three), "unit": "bytes", "total": mb,
                             "total_MB": f"{mb // 1_000_000}.{mb % 1_000_000:06d}", "mode": f3["mode"],
                             "counted": "fl03.definitions: request line, headers and body of every call that joins the "
                                        "edge and the cloud, and of every notification that does, counted at the client "
                                        "and at the listener; one PC, loopback, not a network measurement"}}


def kpi_vs_fl03(kpi: dict, f3: dict) -> list[str]:
    """Where the KPI block (run_round's per-round counts) and the FL_03 block (fl03_block's, from the whole log)
    disagree on rounds 1 to 3: the mode, the round times, the edge-cloud bytes per round and their total. Empty
    when they agree."""
    r13 = [x for x in f3["rounds"] if x["round"] in (1, 2, 3)]
    t, b = kpi.get("fl_round_completion_time_s") or {}, kpi.get("edge_cloud_bytes") or {}
    pairs = (("mode", (t.get("mode"), b.get("mode")), (f3["mode"], f3["mode"])),
             ("round times", t.get("values"), [x["time_s"] for x in r13]),
             ("edge-cloud bytes per round", b.get("values"), [x["edge_cloud_bytes"] for x in r13]),
             ("edge-cloud bytes of rounds 1 to 3", b.get("total"), f3["edge_cloud_bytes"]["rounds_1_to_3"]))
    return [f"{what}: KPI {k}, FL_03 {f}" for what, k, f in pairs if k != f]


def fl03_compare(runs: list[dict]) -> dict:
    """The comparison table: one row per mode in MODES order. runs: [{mode, verdict, file, fl03}], one per mode."""
    by = {}
    for r in runs:
        if r["mode"] not in MOVE or r["mode"] in by:
            raise ValueError(f"a mode twice, or not a mode: {r['mode']!r}")
        if r.get("fl03") is not None and r["fl03"].get("mode") != r["mode"]:
            raise ValueError(f"the {r['mode']} run carries a block of mode {r['fl03'].get('mode')!r}")
        by[r["mode"]] = r
    if set(by) != set(MODES):
        raise ValueError(f"missing: {sorted(set(MODES) - set(by))}")
    rows = []
    for m in MODES:
        r, b = by[m], by[m].get("fl03")
        place = (b or {}).get("placement") or placement(m)
        row = dict.fromkeys(FL03_COLUMNS)
        row.update(mode=m, orchestrator=place["flOrch"], aggregator=place["flAgg"], run_verdict=r.get("verdict") or "FAIL",
                   results_file=r.get("file"))
        if b:
            first3 = [x for x in b["rounds"] if x["round"] in (1, 2, 3)]
            row.update(round_time_s=[x["time_s"] for x in first3], median_round_time_s=b["round_time"]["median_s"],
                       edge_cloud_bytes_per_round=[x["edge_cloud_bytes"] for x in first3],
                       edge_cloud_bytes_rounds_1_to_3=b["edge_cloud_bytes"]["rounds_1_to_3"],
                       edge_cloud_bytes_whole_run=b["edge_cloud_bytes"]["whole_run"]["total"])
            for c, v in b["bytes_per_cse"].items():
                row["bytes_" + c.replace("-", "_")] = v["bytes"] + v["notification_bytes"]
        rows.append(row)
    return {"columns": list(FL03_COLUMNS), "rows": rows}


def fl03_verdict(table: dict) -> str:
    """PARTIAL at most: every source is simulated and steps 7-8 are NOT-RUN. FAIL unless all three runs passed and
    every cell of the table was measured."""
    rows = table["rows"]
    ok = len(rows) == len(MODES) and all(r["run_verdict"] == "PASS" and all(r[k] is not None for k in FL03_COLUMNS)
                                         for r in rows)
    return "PARTIAL" if ok else "FAIL"


set_mode("hierarchical")        # the default; main() sets the mode it is given


# ------------------------------------------------------------------------------------------------ the wire
class _Counted:
    """A file object that adds the length of what is read through it (or written to it) to meter[key]."""

    def __init__(self, f, meter: dict, key: str):
        self._f, self._meter, self._key = f, meter, key

    def _add(self, b):
        self._meter[self._key] += len(b)
        return b

    def read(self, *a):
        return self._add(self._f.read(*a))

    def read1(self, *a):
        return self._add(self._f.read1(*a))

    def readline(self, *a):
        return self._add(self._f.readline(*a))

    def readinto(self, b):
        n = self._f.readinto(b)
        self._meter[self._key] += n or 0
        return n

    def write(self, b):
        n = self._f.write(b)
        self._meter[self._key] += n if isinstance(n, int) else len(b)
        return n

    def __getattr__(self, name):
        return getattr(self._f, name)


class _MeteredResponse(http.client.HTTPResponse):
    def __init__(self, sock, *a, meter: dict, **k):
        super().__init__(sock, *a, **k)
        self.fp = _Counted(self.fp, meter, "received")      # status line, headers and body all come through fp


class _MeteredConn(http.client.HTTPConnection):
    """An HTTP connection that counts every byte the socket took from it and every byte its response reads."""

    def __init__(self, *a, meter: dict, **k):
        super().__init__(*a, **k)
        self.meter = meter
        self.response_class = functools.partial(_MeteredResponse, meter=meter)

    def send(self, data):
        super().send(data)          # connects first if need be: a refused connection raises here and counts nothing
        self.meter["sent"] += len(data) if isinstance(data, (bytes, bytearray)) else 0


class _MeteredHandler(urllib.request.HTTPHandler):
    def __init__(self, meter: dict):
        super().__init__()
        self.meter = meter

    def http_open(self, req):
        return self.do_open(functools.partial(_MeteredConn, meter=self.meter), req)


def _send(r: urllib.request.Request, timeout: float) -> tuple[int, bytes, dict, int, int]:
    """One request through urllib's usual path (the same bytes urlopen sends), counted: status, body, meter, the
    monotonic time just before sending and just after the answer was read."""
    m = {"sent": 0, "received": 0}
    t0 = time.monotonic_ns()
    try:
        with urllib.request.build_opener(_MeteredHandler(m)).open(r, timeout=timeout) as x:
            st, raw = x.status, x.read()
    except urllib.error.HTTPError as e:
        st, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        st, raw = 0, b""
    return st, raw, m, t0, time.monotonic_ns()


def _log_call(party, method: str, to: str, ty, status: int, m: dict, body_len: int, t0: int, t1: int) -> dict:
    c = {"n": len(CALLS) + 1, "party": party, "method": method, "url": to, "ty": ty, "status": status, "sent": m["sent"],
         "received": m["received"], "body": body_len, "round": ROUND, "t0": t0, "t1": t1, **classify(party, to, PLACE)}
    CALLS.append(c)
    return c


def rq(method: str, to: str, origin: str, *, ty: int | None = None, body: dict | None = None,
       why: str = "", harness: bool = False) -> tuple[int, dict | None]:
    """One oneM2M request (the wire shape of handover._req), traced and counted (module text: Bytes). harness:
    the call is the harness's in the count whatever originator it goes under (the removal of a leftover AE)."""
    global _n
    _n += 1
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(to, data=data, method=method, headers={
        "X-M2M-Origin": origin, "X-M2M-RI": f"fl{_n}", "X-M2M-RVI": "4", "Accept": "application/json",
        "Content-Type": f"application/json;ty={ty}" if ty else "application/json"})
    st, raw, m, t0, t1 = _send(r, 10)
    try:
        parsed = json.loads(raw) if raw else None
    except ValueError:
        parsed = None
    c = _log_call(None if harness else party_of(origin), method, to, ty, st, m, len(data or b""), t0, t1)
    if origin == ORCH and method == "GET" and parsed is not None:
        ORCH_SEEN.append(parsed)
    TRACE.append(f"{_n} {origin} {method} {to.split('/', 3)[-1]} ty={ty or '-'} -> {st} {m['sent']}+{m['received']}B"
                 + (" edge-cloud" if c["edge_cloud"] else "") + (f" retargeted to {c['target']}" if c["retargeted"] else "")
                 + (" harness" if harness else "") + (" UNMAPPED originator" if c["edge_cloud"] is None else "")
                 + (f" | {why}" if why else ""))
    return st, parsed


def acr(*pairs) -> dict:
    return {"acr": [{"acor": list(who), "acop": op} for who, op in pairs]}


def post(ae: str, cnt: str, origin: str, obj, *, rn: str | None = None, cr: bool = False, why: str = "") -> tuple[int, dict]:
    """Create a contentInstance. cr asks the CSE to record the creator."""
    c = {"cnf": "application/json:0", "con": obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True)}
    if rn:
        c["rn"] = rn
    if cr:
        c["cr"] = None
    st, b = rq("POST", url(ae, cnt), origin, ty=ho.TY_CIN, body={"m2m:cin": c}, why=why)
    return st, (b or {}).get("m2m:cin", {})


def cins(ae: str, cnt: str, origin: str, why: str = "") -> list[dict]:
    st, b = rq("GET", url(ae, cnt) + "?rcn=4", origin, why=why)
    return sorted((b or {}).get("m2m:cnt", {}).get("m2m:cin", []), key=lambda c: (c["ct"], c["ri"])) if st == 200 else []


def get(ae: str, *path: str, origin: str, why: str = "") -> tuple[int, dict | None]:
    """A resource by name; for a contentInstance the parsed content."""
    st, b = rq("GET", url(ae, *path), origin, why=why)
    if st == 200 and b and "m2m:cin" in b:
        return st, json.loads(b["m2m:cin"]["con"])
    return st, b


def records(ae: str, cnt: str, origin: str, kind: str) -> list[dict]:
    """The records of one kind in a mixed container ({"kind", "record"}), oldest first."""
    out = []
    for c in cins(ae, cnt, origin, why=f"{kind} records"):
        v = json.loads(c["con"])
        if v.get("kind") == kind:
            out.append(v["record"])
    return out


def mec(method: str, path: str, body=None, who: str | None = "flTfc") -> tuple[int, object]:
    """One MEC 011 request, counted like rq (who: the party; None for the harness's probes). Not numbered in the
    oneM2M request identifiers."""
    r = urllib.request.Request(MEC011 + path, data=None if body is None else json.dumps(body).encode(), method=method,
                               headers={"Content-Type": "application/json", "Accept": "application/json"})
    st, raw, m, t0, t1 = _send(r, 5)
    c = _log_call(who, method, MEC011 + path, None, st, m, len(r.data or b""), t0, t1)
    TRACE.append(f"mec {who or 'harness'} {method} {path} -> {st} {m['sent']}+{m['received']}B"
                 + (" edge-cloud" if c["edge_cloud"] else ""))
    if not 200 <= st < 300:
        return st, {}
    try:
        return st, (json.loads(raw) if raw else {})
    except ValueError:
        return 0, {}


class _Notify(BaseHTTPRequestHandler):
    """The clients' notification endpoints, /fl/<client AE>. Like estimed_poc2._Notify: bounded body, 200 with
    X-M2M-RSC 2000, a verification request is answered and not recorded as a task. Every request is counted at
    the socket (NOTIFY_LOG): request line, headers and body as read, the answer as written."""
    timeout = 5

    def setup(self):
        super().setup()
        self._m = {"received": 0, "sent": 0}
        self.rfile, self.wfile = _Counted(self.rfile, self._m, "received"), _Counted(self.wfile, self._m, "sent")

    def _counted(self, rnd, kind: str) -> None:
        NOTIFY_LOG.append({"endpoint": self.path.rsplit("/", 1)[-1] if self.path.startswith("/fl/") else self.path,
                           "kind": kind, "round": ROUND if rnd is None else rnd, **self._m})
        self._m["received"] = self._m["sent"] = 0           # a next request on the same connection starts at 0

    def do_POST(self):  # noqa: N802
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= 64 * 1024:
            self.send_response(400)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self._counted(None, "refused")
            return
        body = self.rfile.read(n)
        sgn = {}
        try:
            sgn = json.loads(body or b"{}").get("m2m:sgn", {})
            con = (sgn.get("nev", {}).get("rep", {}).get("m2m:cin") or {}).get("con")
            task = json.loads(con) if con and not sgn.get("vrq") else None
        except (ValueError, AttributeError):
            task = None
        is_task = isinstance(task, dict) and "taskId" in task and self.path.startswith("/fl/")
        if is_task:
            NOTES.append({"endpoint": self.path.rsplit("/", 1)[-1], "taskId": task["taskId"],
                          "selectedClient": task.get("selectedClient"), "round": task.get("roundRef"), "bytes": n,
                          "task": task})
        self.send_response(200)
        self.send_header("X-M2M-RSC", "2000")
        self.send_header("Content-Length", "0")
        self.end_headers()
        self._counted(task.get("roundRef") if is_task else None,
                      "task" if is_task else "verification" if isinstance(sgn, dict) and sgn.get("vrq") else "other")

    def log_message(self, *a):
        pass


# ------------------------------------------------------------------------------------------------ building blocks
SPEC = {   # role, class, who may read the metadata, extra rights on the data policy, containers (meta | data)
    "flSrc1": dict(role="data-source", cls="fl-assisted", meta=[([AUTH["flSrc1"]], CRD), ([ORCH, TFC, TFC2, AGG], RD)],
                   data_pvs=[AUTH["flSrc1"]], cnts={"env": "data", "flMeta": "meta", "flPolicy": "meta"}, cap=(False, False)),
    "flSrc2": dict(role="data-source", cls="fl-assisted", meta=[([AUTH["flSrc2"]], CRD), ([ORCH, TFC, TFC2, AGG], RD)],
                   data_pvs=[AUTH["flSrc2"]], cnts={"env": "data", "flMeta": "meta", "flPolicy": "meta"}, cap=(False, False)),
    "flNat": dict(role="client", cls="fl-native", meta=[([ORCH, AGG], RD)],
                  cnts={"env": "data", "flMeta": "meta", "flStatus": "meta"}, cap=(True, True)),
    "flDec": dict(role="client", cls="fl-native", meta=[([ORCH, AGG], RD)],
                  cnts={"env": "data", "flMeta": "meta", "flStatus": "meta"}, cap=(True, True)),
    "flTfc": dict(role="tfc", cls="trusted-fl-client", meta=[([ORCH, AGG, *AUTH.values()], RD)],
                  cnts={"flMeta": "meta", "flStatus": "meta", "flTmp": "data"}, cap=(True, True)),
    "flAgg": dict(role="aggregator", meta=[([ORCH, TFC, NAT, DEC], RD)], data_pv=[([TFC, NAT], CREATE)],
                  cnts={"updates": "data", "models": "meta", "rounds": "meta"}),
    "flOrch": dict(role="orchestrator", meta=[([TFC, TFC2, NAT, DEC, AGG], RD)],
                   cnts={"ops": "meta", "tasks": "meta", "model": "meta", "deploy": "meta"}),
    "flTfc2": dict(role="tfc", cls="trusted-fl-client", meta=[([ORCH, AUTH["flSrc1"]], RD)], cnts={"flMeta": "meta"}),
}
# TD_MEC_FL_01: what each deployed app's AE must look like, held here and not read from its package (the package
# says what the app will do; this says what it must have done): REG_03 steps 2-6, FL_01 steps 4 and 5, the cleanup.
FL01_APPS = {
    "fl_orch": {"ae": "flOrch", "origin": ORCH, "api": "Nestimed.fl", "container": "ops", "readers": SPEC["flOrch"]["meta"][0][0],
                "ops": RD},
    "fl_tfc": {"ae": "flTfc", "origin": TFC, "api": "Nestimed.fl", "container": "flMeta", "readers": SPEC["flTfc"]["meta"][0][0],
               "ops": RD, "represents": ["flSrc1", "flSrc2"]},
    "fl_proxy": {"ae": "flProxy", "origin": FL01_OWNER["flProxy"], "api": "Nestimed.flproxy", "container": "flConfig",
                 "readers": [ORCH, CHECKER], "ops": RD, "devices": [DEVICE_ID],
                 "data_acp": {"rn": "flDataAcp", "readers": [CHECKER], "ops": RD}},     # the device containers' policy
}
COMPUTE = {"data-source": dict(ram_total=256, ram_free=64, storage_total=4096, storage_free=1024, cpu_pct=5),
           "client": dict(ram_total=8_388_608, ram_free=4_194_304, storage_total=134_217_728, storage_free=67_108_864, cpu_pct=10),
           "tfc": dict(ram_total=16_777_216, ram_free=8_388_608, storage_total=268_435_456, storage_free=134_217_728, cpu_pct=10)}


def make_ae(ae: str, extra_labels: tuple = (), adopt: dict | None = None) -> dict:
    """An AE by its own originator, its two access policies, its containers and (for a participant) its capability
    profile as two flexContainers. Returns the statuses.
    adopt (TD_MEC_FL_01): the AE was registered by a deployed app, which also made the metadata policy, put it on
    the AE and made its baseline container; adopt = {ae, acpi, container, container_status}, the statuses the app
    got as its relay saw them. The driver then makes the rest, under the same originator."""
    s, me, out = SPEC[ae], OWNER[ae], {}
    if adopt is None:
        out["ae"], _ = rq("POST", HOME.get(ae, A), me, ty=ho.TY_AE, why=f"register {ae}", body={"m2m:ae": {
            "rn": ae, "api": "Nestimed.fl", "rr": False, "srv": ["4"],
            "lbl": ["fl:participant", f"fl:role:{s['role']}", "fl:sim:true", *extra_labels]}})
    else:
        out["ae"] = adopt["ae"]
    acpi = {}
    for name, pv, pvs in (("meta", [([me], ALL), *s["meta"]], [([me], ALL)]),
                          ("data", [([me], ALL), *s.get("data_pv", [])], [([me, *s.get("data_pvs", [])], ALL)])):
        rn = f"fl{name.capitalize()}Acp"
        if adopt is not None and name == "meta":
            st, b = rq("GET", url(ae, rn), me, why=f"{ae}: the metadata policy its app made")
        else:
            st, b = rq("POST", url(ae), me, ty=ho.TY_ACP, why=f"{ae} access policy ({name})",
                       body={"m2m:acp": {"rn": rn, "pv": acr(*pv), "pvs": acr(*pvs)}})
        out[rn], acpi[name] = st, [(b or {}).get("m2m:acp", {}).get("ri")]
    if adopt is None:
        out["acpi"], _ = rq("PUT", url(ae), me, body={"m2m:ae": {"acpi": acpi["meta"]}}, why=f"{ae}: metadata policy on the AE")
    else:
        out["acpi"] = adopt["acpi"]
    for c, kind in s["cnts"].items():
        if adopt is not None and c == adopt["container"]:
            out[c] = adopt["container_status"]
            continue
        out[c], _ = rq("POST", url(ae), me, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": c, "acpi": acpi[kind]}}, why=f"{ae}/{c}")
    if "cap" in s:
        labels = ["fl:profile", f"fl:role:{s['role']}", f"fl:class:{s['cls']}", "fl:sim:true"]
        for body in (fl.cap_fcnt(*s["cap"], labels), fl.compute_fcnt(**COMPUTE[s["role"]])):
            inner = next(iter(body.values()))
            inner["acpi"] = acpi["meta"]
            out[inner["rn"]], _ = rq("POST", url(ae), me, ty=ho.TY_FCNT, body=body, why=f"{ae}/{inner['rn']} (capability profile)")
    return out


def post_chunk(S: dict, k0: int, k1: int) -> int:
    """The simulated sources post records k0..k1-1 of their series into their own <env>. Returns how many failed."""
    bad = 0
    for src in SERIES:
        if is_dev(src):             # the phone's own text, unchanged; an empty slot stays empty
            for r in DEV["sources"][src]["records"]:
                if k0 <= r["slot"] < k1:
                    st, _ = post(src, "env", OWNER[src], r["con"], why="a captured device observation, posted by the host bridge")
                    bad += st != 201
            continue
        for k in range(k0, k1):
            if k in SKIP.get(src, ()):
                continue
            st, _ = post(src, "env", OWNER[src], json.dumps(S["series"][src][k]), why="a simulated observation")
            bad += st != 201
    return bad


def read_env(src: str, reader: str) -> tuple[int, list[dict], list[dict], list[dict]]:
    """A source's observations as `reader` gets them: status, parsed records, provenance entries, the raw cins."""
    st, b = rq("GET", url(src, "env") + "?rcn=4", reader, why="observations for training")
    raw = (b or {}).get("m2m:cnt", {}).get("m2m:cin", []) if st == 200 else []
    recs = [fl.parse_env(c["con"], device=is_dev(src)) for c in raw]
    prov = sorted(({"source": src, "t": r["t"], "con_sha256": fl.text_digest(c["con"])} for r, c in zip(recs, raw)),
                  key=lambda p: p["t"])
    return st, recs, prov, raw


def read_policies(reader: str) -> dict:
    """The latest policy record of each source and the creator the CSE recorded for it, as `reader` sees them."""
    out = {}
    for src in AUTH:
        st, b = rq("GET", url(src, "flPolicy", "la"), reader, why="latest data-use policy")
        if st == 200 and b:
            out[src] = {"record": json.loads(b["m2m:cin"]["con"]), "creator": b["m2m:cin"].get("cr")}
    return out


def policy_refs(pol: dict, sources: list[str]) -> list[str]:
    return [f"{pol[s]['record']['policyId']}@{pol[s]['record']['policyVersion']}" if s in pol else f"{s}-policy@none"
            for s in sources]


def decide(pol: dict, sources: list[str], processor: str = TFC, domain: str = "edge-a") -> dict:
    return fl.authorize(sources, pol, purpose="fl-training", operation="train", processor=processor, domain=domain,
                        requester=ORCH, now_ms=int(time.time() * 1000))


def issue_policy(src: str, version: str, **kw) -> int:
    rec = fl.policy_record(src, AUTH[src], version, expiry_ms=int(time.time() * 1000) + 3_600_000,
                           **{"processors": [TFC], "domains": ["edge-a"], **kw})
    return post(src, "flPolicy", AUTH[src], rec, cr=True, why=f"policy {version} by the authority of {DOMAIN[src]}")[0]


def set_readers(src: str, readers: list[str]) -> int:
    """The source's authority sets who may read its observations (the CSE-enforced half of a policy)."""
    pv = [([OWNER[src]], ALL)] + ([(readers, RD)] if readers else [])
    return rq("PUT", url(src, "flDataAcp"), AUTH[src], body={"m2m:acp": {"pv": acr(*pv)}},
              why=f"{DOMAIN[src]} authority sets the readers of {src}/env")[0]


def statuses(ae: str, reader: str) -> dict:
    out = {}
    for c in cins(ae, "flStatus", reader, why="client status"):
        v = json.loads(c["con"])
        out[v["kind"]] = v["record"]
    return out


def observe_readiness(ae: str, data_probe: tuple[str, str]) -> dict:
    """The six conditions, each from something that was tried just now (TR 7.3.5.6 as reported, fact F13)."""
    me = OWNER[ae]
    a, b = {"t": 0, "x": [40, 64], "y": 30}, {"t": 5000, "x": [-20, 0], "y": -12}
    return {"applicationRunning": True,                                              # this process answers
            "frameworkInitialized": fl.train([0, 0, 0], [a, b]) == [9, 23, 30],     # the trainer's known answer
            "modelAccessible": rq("GET", url("flOrch", "model", "v0"), me, why="readiness: model")[0] == 200,
            "credentialsAndCoordinatorConfigured": rq("GET", url("flOrch", "ops", "la"), me, why="readiness: coordinator")[0] == 200,
            "authorizedLocalDataAccessible": rq("GET", url(*data_probe, "la"), me, why="readiness: data")[0] == 200,
            "canAcceptTask": True}


def post_readiness(ae: str, cond: dict, state: str) -> int:
    return post(ae, "flStatus", OWNER[ae], {"kind": "readiness", "record": {"conditions": cond, "state": state, "sim": True}})[0]


def participants(mode: str) -> list[dict]:
    tfc = ([{"pid": "P-TFC-AGG", "sources": ["flSrc1", "flSrc2"], "ds": "ds-agg"}] if mode == "aggregatedSources" else
           [{"pid": "P-TFC-S1", "sources": ["flSrc1"], "ds": "ds-s1"}, {"pid": "P-TFC-S2", "sources": ["flSrc2"], "ds": "ds-s2"}])
    return ([{**p, "client": TFC, "ae": "flTfc", "own": False, "mode": mode} for p in tfc]
            + [{"pid": f"P-{ae[2:].upper()}", "sources": [ae], "ds": f"ds-{ae[2:].lower()}", "client": OWNER[ae], "ae": ae,
                "own": True, "mode": "singleSource"} for ae in ("flNat", "flDec")])


def discover() -> tuple[list[str], list]:
    """The orchestrator's discovery of capability profiles by label, and everything it received on the way."""
    got = []
    st, b = rq("GET", f"{HOME['flNat']}?fu=1&ty={ho.TY_FCNT}&lbl=fl:profile", ORCH,     # where the clients sit
               why="discovery: capability profiles by label")
    found = sorted((b or {}).get("m2m:uril", [])) if st == 200 else []
    got.append(b)
    return found, got


def candidates(mode: str) -> tuple[list[dict], dict, list[str], list[dict]]:
    """The orchestrator's candidate list, built from what it can read: discovery, each capability flexContainer,
    each client's own status, and the sources' policies."""
    found, _ = discover()
    pol, plan, cands, refs = read_policies(ORCH), participants(mode), [], {}
    for p in plan:
        ref = f"{PLACE[p['ae']]}/{p['ae']}/flCap"
        st, cap = rq("GET", url(p["ae"], "flCap"), ORCH, why="capability profile")
        stat = statuses(p["ae"], ORCH)
        p["policyVersions"] = ["own-data"] if p["own"] else policy_refs(pol, p["sources"])
        cands.append({"participantId": p["pid"], "clientAERef": p["client"], "discovered": ref in found,
                      "capability": fl.capability_of(cap) if st == 200 else {},
                      "readiness": (stat.get("readiness") or {}).get("conditions", {}),
                      "decision": (stat.get("decision") or {}).get("decision"),
                      "authorized": True if p["own"] else decide(pol, p["sources"])["authorized"]})
        refs[p["pid"]] = ref
    return cands, refs, found, plan


def binding_of(p: dict, rnd: int, versions: list[str]) -> dict:
    return {"participantId": p["pid"], "clientAERef": p["client"], "mode": p["mode"], "sources": p["sources"],
            "policyVersions": versions, "operationRef": OP, "round": rnd}


def model_versions() -> list[str]:
    return [json.loads(c["con"])["modelRef"] for c in cins("flAgg", "models", AGG, why="model versions")]


# ------------------------------------------------------------------------------------------------ one round
def run_round(S: dict, rnd: int, mode: str, **kw) -> dict:
    """One round, end to end (_round), with every call and notification in it tagged with the round; then the
    round's time and edge-cloud bytes, from that log (module text: Round time, Bytes)."""
    global ROUND
    ROUND = rnd
    try:
        R = _round(S, rnd, mode, **kw)
        R["marks_ns"] = round_marks(CALLS, rnd, PLACE)
        R["time_us"] = round_time_us(R["marks_ns"])
        R["time_s"] = fmt_s(R["time_us"])
        R["bytes"] = tally([c for c in CALLS if c["round"] == rnd], [n for n in NOTIFY_LOG if n["round"] == rnd],
                           PLACE)["edge_cloud"]["total"]
        return R
    finally:
        ROUND = 0


def _round(S: dict, rnd: int, mode: str, *, dropout: tuple = (), poison: tuple = (), replay: bool = False,
           revoke: str | None = None) -> dict:
    """One round, end to end. Returns what was observed; the caller turns it into rows."""
    R = {"round": rnd, "mode": mode, "clients": [], "uploads": [], "reads": {}, "reads_after": {}, "temp": []}
    # the orchestrator: discovery, selection, binding, tasks, notification
    R["candidates"], R["capability_refs"], R["discovered"], plan = candidates(mode)
    sel = fl.select_participants(R["candidates"])
    R["selection"], R["selected"] = sel, sel["selected"]
    chosen = [p for p in plan if p["pid"] in sel["selected"]]
    v, w = S["version"], S["w"]
    deadline = int(time.time() * 1000) + int(ROUND_TIMEOUT_S * 1000)
    for ae in sorted({p["ae"] for p in chosen} - set(S["subs"])):
        st, _ = rq("POST", url("flOrch", "tasks"), ORCH, ty=ho.TY_SUB, why=f"subscription that notifies {ae}", body={
            "m2m:sub": {"rn": f"flSub-{ae}", "nu": [f"http://127.0.0.1:{LISTEN}/fl/{ae}"], "enc": {"net": [3]}, "nct": 1}})
        require(f"round {rnd}: subscription on the task container for {ae}", st == 201, f"HTTP {st}")
        S["subs"].append(ae)
    R["tasks"] = []
    for p in chosen:
        b = binding_of(p, rnd, p["policyVersions"])
        post("flOrch", "ops", ORCH, {"kind": "binding", "record": b}, why="the orchestrator commits the binding")
        model_ref, destination, status_target = task_targets(p["ae"], v)
        task = fl.task_record(OP, rnd, p["pid"], p["client"], model_ref=model_ref,
                              model_digest=fl.model_digest(w), binding_version=fl.digest(b)[:16], deadline_ms=deadline,
                              update_destination=destination, status_target=status_target)
        st, _ = post("flOrch", "tasks", ORCH, task, rn=task["taskId"], why="task")
        require(f"round {rnd}: task {task['taskId']} posted", st == 201, f"HTTP {st}")
        R["tasks"].append(task)

    def notified(p):
        return next((n for n in NOTES if n["endpoint"] == p["ae"] and n["taskId"] == fl.task_id(OP, rnd, p["pid"])), None)
    t_end = time.time() + 5
    while time.time() < t_end and not all(notified(p) for p in chosen):
        time.sleep(0.05)
    R["notifications"] = [{k: n[k] for k in ("endpoint", "taskId", "selectedClient", "bytes")} for n in NOTES if n["round"] == rnd]

    # the clients: each acts under its own originator on what it was notified of
    pol_tfc = read_policies(TFC)
    for p in chosen:
        me, note = p["client"], notified(p)
        if p["pid"] in dropout or note is None:
            R["clients"].append({"participantId": p["pid"], "dropped": True,
                                 "why": "simulated dropout: no answer after the notification" if note else "not notified"})
            continue
        task = note["task"]
        st_m, mrec = get("flOrch", "model", f"v{v}", origin=me, why="the model the task names")
        body = (mrec or {}).get("model", {})
        R["reads"][p["ae"]] = {"status": st_m, "digest": fl.digest(body) if st_m == 200 else None}
        versions = ["own-data"] if p["own"] else policy_refs(pol_tfc, p["sources"])
        verify = fl.verify_task(task, me=me, binding_version=fl.digest(binding_of(p, rnd, versions))[:16], model_body=body)
        log = {"participantId": p["pid"], "verify": verify, "samples": 0, "status": None, "read": {}}
        R["clients"].append(log)
        if verify:
            continue
        per, prov = {}, []
        for s in p["sources"]:
            st_d, recs, pr, _ = read_env(s, me)
            log["read"][s] = st_d
            per[s], prov = recs, prov + pr
        asm = fl.assemble(per, p["mode"], align="slot" if DEV else "exact")
        ds = fl.dataset_record(p["ds"], str(rnd), asm, sources=p["sources"], provenance=prov, policy_versions=versions)
        st_ds, _ = post(p["ae"], "flMeta", me, {"kind": "dataset", "record": ds}, why="dataset record (no samples)")
        if not p["own"]:        # the Trusted FL Client holds other parties' data: a temporary copy, deleted later
            rn = f"{p['ds']}-v{rnd}"
            st_t, _ = post("flTfc", "flTmp", TFC, {"kind": "temporary-copy", "dataset": p["ds"], "samples": asm["samples"]},
                           rn=rn, why="temporary copy inside the edge domain")
            R["temp"].append({"ref": f"flTfc/flTmp/{rn}", "dataset": p["ds"], "created": st_t})
        w_local = fl.train(body["w"], asm["samples"], epochs=task["trainingConfig"]["epochs"])
        d = fl.delta(w_local, body["w"])
        if p["pid"] in poison:      # the planted fault: a change far outside the stated bound
            d = [d[0], d[1] + 50 * fl.UPDATE_BOUND, d[2]]
        u = fl.update_record(task, dataset_ref=p["ds"], dataset_version=str(rnd), dataset_digest=ds["datasetDigest"],
                             effective_sample_count=ds["effectiveSampleCount"], delta=d)
        st_u, cin = post("flAgg", "updates", me, u, cr=True, why="model update")
        prof = fl.participant_profile(p["pid"], OP, me, p["mode"], dataset_ref=p["ds"], dataset_version=str(rnd),
                                      sources=p["sources"], effective_sample_count=ds["effectiveSampleCount"],
                                      task_refs=[task["taskId"]], status="submitted")
        post(p["ae"], "flMeta", me, {"kind": "participant", "record": prof}, why="participant profile")
        log.update(samples=len(asm["samples"]), dataset=ds, dataset_status=st_ds, assembled=asm, provenance=prov, profile=prof,
                   status=post(p["ae"], "flStatus", me, {"kind": "training", "record": {
                       "taskId": task["taskId"], "state": "submitted", "sampleCount": len(asm["samples"]), "sim": True}})[0])
        R["uploads"].append({"participantId": p["pid"], "status": st_u, "ty": cin.get("ty"), "creator": cin.get("cr"),
                             "clientAERef": me, "updateDigest": u["updateDigest"], "taskId": u["taskId"],
                             "datasetRef": u["datasetRef"], "con": cin.get("con")})
    if replay:                      # the planted fault: the client's round-1 update, the same bytes, sent again
        st_r, _ = post("flAgg", "updates", TFC, S["old_update"]["con"], cr=True, why="CONTROL: a round-1 update sent again")
        R["replayed"] = {"status": st_r, "updateDigest": S["old_update"]["updateDigest"]}
    if revoke:                      # the source's authority revokes while the update is pending at the aggregator
        p = next(x for x in chosen if x["sources"] == [revoke])
        before = next(c for c in R["clients"] if c["participantId"] == p["pid"])["read"][revoke]
        n = int(pol_tfc[revoke]["record"]["policyVersion"]) + 1
        st_p = issue_policy(revoke, str(n), status="revoked")
        st_a = set_readers(revoke, [])
        after, _ = rq("GET", url(revoke, "env", "la"), TFC, why="the client's read after the revocation")
        ds = next(c for c in R["clients"] if c["participantId"] == p["pid"])["dataset"]
        st_i, _ = post("flTfc", "flMeta", TFC, {"kind": "dataset", "record": {**ds, "datasetLifecycleState": "invalid"}},
                       why="the client marks the dataset invalid")
        R["revocation"] = {"source": revoke, "affected": p["pid"], "policy": st_p, "acp": st_a, "read_before": before,
                           "read_after": after, "invalid_posted": st_i, "policy_version": str(n)}

    # the aggregator: waits for an update per task or for the deadline, then closes on what it reads itself
    want = len([c for c in R["clients"] if not c.get("dropped") and not c["verify"]])
    while True:
        new = [c for c in cins("flAgg", "updates", AGG, why="collect updates") if c["ri"] not in S["agg_read"]]
        if len(new) >= want + bool(replay) and want == len(chosen) or time.time() * 1000 > deadline + 200:
            break
        time.sleep(AGG_POLL_S)
    S["agg_read"] |= {c["ri"] for c in new}
    subs = []
    for c in new:
        try:
            u = json.loads(c["con"])
        except ValueError:
            u = None
        subs.append({"update": u, "creator": c.get("cr"), "created_ms": fl.ct_ms(c["ct"])})
    R["collected"] = [s["update"].get("updateDigest") for s in subs if isinstance(s["update"], dict)]
    pol_agg = read_policies(AGG)
    state = {s: "active" if e["record"].get("revocationStatus") == "active" and e["creator"] == AUTH[s] else "revoked"
             for s, e in pol_agg.items()}
    state.update(flNat="active", flDec="active")         # a client's own data: no third party's policy applies
    datasets = {}
    for ae in ("flTfc", "flNat"):
        for d in records(ae, "flMeta", AGG, "dataset"):  # a later record of the same version replaces an earlier one
            datasets[(d["datasetId"], d["datasetVersion"])] = {"digest": d["datasetDigest"], "n": d["effectiveSampleCount"],
                                                               "state": d["datasetLifecycleState"], "sources": d["sourceDescriptorRefs"]}
    tasks = [t for t in (json.loads(c["con"]) for c in cins("flOrch", "tasks", AGG, why="this round's tasks")) if t["roundRef"] == rnd]
    _, m_in = get("flOrch", "model", f"v{v}", origin=AGG, why="the round's input model")
    rd = {"operationRef": OP, "round": rnd, "modelDigest": fl.digest(m_in["model"]), "w": m_in["model"]["w"],
          "deadline_ms": tasks[0]["deadline"], "selected": [t["participantId"] for t in tasks],
          "tasks": {t["taskId"]: t for t in tasks}}
    rec = fl.close_round(rd, subs, {"source_state": state, "datasets": datasets, "seen": S["seen"]})
    S["seen"] = set(rec["seen"])
    R["source_state"] = state
    post("flAgg", "rounds", AGG, rec, rn=f"r{rnd}", why="round record")
    R["versions_before"] = model_versions()
    if rec["w_out"] is not None:
        R["loss_before"], R["loss_after"] = fl.loss(rec["w_in"], S["held"]), fl.loss(rec["w_out"], S["held"])
        R["agg_published"], _ = post("flAgg", "models", AGG, rn=f"v{v + 1}", why="aggregated model", obj={
            "modelRef": f"v{v + 1}", "version": v + 1, "model": fl.model_body(rec["w_out"]), "modelDigest": rec["modelOutDigest"],
            "parentDigest": rec["modelInDigest"], "round": rnd, "weightingBasis": rec["weightingBasis"],
            "contributions": [{k: a[k] for k in ("participantId", "updateDigest", "n")} for a in rec["accepted"]],
            "evaluation": {"heldOutSamples": len(S["held"]), "errorBefore": R["loss_before"], "errorAfter": R["loss_after"], "sim": True},
            "sim": True})
    R["versions_after"] = model_versions()

    # the orchestrator: reads the round record, re-checks it, and redistributes a completed round's model
    _, R["record"] = get("flAgg", "rounds", f"r{rnd}", origin=ORCH, why="round record")
    R["verify"] = fl.verify_round(R["record"])
    if R["record"]["state"] == "COMPLETED" and not R["verify"]:
        _, m = get("flAgg", "models", f"v{v + 1}", origin=ORCH, why="aggregated model")
        if fl.digest(m["model"]) == R["record"]["modelOutDigest"]:
            R["redistributed"], _ = post("flOrch", "model", ORCH, rn=f"v{v + 1}", why="redistribution", obj={
                "version": v + 1, "model": m["model"], "modelDigest": m["modelDigest"], "round": rnd, "sim": True})
            S["version"], S["w"] = v + 1, m["model"]["w"]
            S["published"][v + 1] = m["modelDigest"]
            for ae in ("flTfc", "flNat"):       # all participants of the operation, a straggler too
                st, got = get("flOrch", "model", f"v{v + 1}", origin=OWNER[ae], why="the new model")
                R["reads_after"][ae] = {"status": st, "digest": fl.digest(got["model"]) if st == 200 else None}
    # retention: the Trusted FL Client deletes this round's temporary copies; the read-back is the evidence
    for t in R["temp"]:
        t["deleted"], _ = rq("DELETE", f"{HOME['flTfc']}/{t['ref']}", TFC, why="retention: delete the temporary copy")
        t["readback"], _ = rq("GET", f"{HOME['flTfc']}/{t['ref']}", TFC, why="retention: read back")
    S["temp"] += R["temp"]
    S["rounds"].append(R)
    return R


def deploy(S: dict, version: int, *, tamper: bool = False) -> dict:
    """Delivery, separate from aggregation: the orchestrator posts a package; the target (flNat, simulated) reads
    it, reads the digest the aggregator published for that version, checks, and reports what it did."""
    pkg = fl.model_package(version, S["models"][version], parent_digest=S["parents"][version], round_ref=version)
    rn = pkg["packageId"] + ("-bad" if tamper else "")
    if tamper:                      # the planted fault: the content changes, the stated digest does not
        pkg["model"]["w"][2] += 1
    st_p, _ = post("flOrch", "deploy", ORCH, pkg, rn=rn, why="model package")
    _, got = get("flOrch", "deploy", rn, origin=NAT, why="the target fetches the package")
    st_a, pub = get("flAgg", "models", f"v{got['modelVersion']}", origin=NAT, why="the digest the aggregator published")
    why = fl.check_package(got, pub["modelDigest"] if st_a == 200 else None)
    act = {"target": "flNat", "packageRef": rn, "packageId": got["packageId"], "modelVersion": got["modelVersion"],
           "modelDigest": fl.digest(got["model"]) if "schema" not in why else None, "verdict": "refused" if why else "activated",
           "reasons": why, "previousVersion": S["target_active"], "sim": True}
    st_s, _ = post("flNat", "flStatus", NAT, {"kind": "activation", "record": act}, why="activation report")
    if not why:
        S["target_active"] = got["modelVersion"]
    return {"posted": st_p, "reported": st_s, "activation": act, "reasons": why}


def view(S: dict) -> tuple[dict, dict, list]:
    """The orchestrator's view of what is aggregated and what is active, from what it reads on the CSEs."""
    pub = {m["version"]: m["modelDigest"]
           for m in (json.loads(c["con"]) for c in cins("flAgg", "models", ORCH, why="published versions"))}
    acts = records("flNat", "flStatus", ORCH, "activation")
    return fl.deployment_view(pub, acts), pub, acts


def row(tag: str, text: str, verdict: tuple[bool, str], detail: str = "") -> bool:
    ok, why = verdict
    return step(f"[{tag}] {text}", ok, (detail + "; " if detail and not ok else detail if ok else "") + ("" if ok else why))


def not_run(rowname: str, reason: str) -> None:
    NOT_RUN.append({"row": rowname, "result": "NOT-RUN", "reason": reason})
    print(f"  NOT-RUN  {rowname}\n          {reason}")


# ------------------------------------------------------------------------------------------------ TD_MEC_FL_01
CSE_RI = {c: ri for ri, c in CSI.items()}           # cse-in -> id-in, the ri of each CSEBase


def ae_cse(obs: dict) -> str | None:
    """The CSE an <AE> sits on, from its parent (the CSEBase ri) as the CSE answered it."""
    return CSI.get((obs.get("ae") or {}).get("pi"))


def start_pinned(which: str, *args: str, log: Path) -> subprocess.Popen:
    """One of the main tree's MEC candidates, served by mec_pinned.py (refused there unless it hashes to its pin)."""
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as out:
        return subprocess.Popen([PY, "-B", str(HERE / "mec_pinned.py"), "serve", which, *args], stdin=subprocess.DEVNULL,
                                stdout=out, stderr=subprocess.STDOUT)


def stop_proc(p: subprocess.Popen | None) -> str:
    if p is None:
        return "not started by this run"
    p.terminate()
    try:
        p.wait(5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(5)
        return "started by this run, killed"
    return "started by this run and stopped"


def wait_for(pred, timeout: float = 15.0, every: float = 0.1) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(every)
    return False


def app_wire(D: dict, origin: str) -> dict:
    """What one app sent while it was deployed, read off the relays: its AE Create, its Mca writes, its Mp1 posts,
    and whether confirm_ready came after the last of its writes."""
    rec = D.get("records") or {}
    mca = [r for r in rec.get(D.get("cse"), []) if r["headers"].get("x-m2m-origin") == origin]
    mp1 = [r for r in rec.get("mec011", []) if r["method"] != "GET"]
    reg = next((r for r in mp1 if r["method"] == "POST" and r["path"].endswith("/registrations")), None)
    conf = next((r for r in mp1 if r["path"].endswith("/confirm_ready")), None)
    writes = [r for r in mca if r["method"] in ("POST", "PUT")]
    return {"creates": [{"path": r["path"], "origin": origin, "status": r["status"], "rsc": r["rsc"],
                         "aei": ((r["reply"] or {}).get("m2m:ae") or {}).get("aei")} for r in fp.creates(mca, ho.TY_AE)],
            "mp1_posts": fp.mp1_posts(mp1), "mid": ((reg or {}).get("reply") or {}).get("appInstanceId"),
            "registration": (reg or {}).get("status"), "confirm_ready": (conf or {}).get("status"),
            "confirm_after_writes": conf is not None and bool(writes) and conf["t_in"] > max(w.get("t_out", 0) for w in writes),
            "writes": [[r["method"], r["path"], r["status"]] for r in writes], "mca": mca}


def adopt_of(w: dict, container: str) -> dict:
    """make_ae's adopt argument: the statuses the app got for its AE, its acpi update and its baseline container."""
    put = next((s for m, _, s in w["writes"] if m == "PUT"), 0)
    cnt = next((r["status"] for r in fp.creates(w["mca"], ho.TY_CNT)
                if ((r["body"] or {}).get("m2m:cnt") or {}).get("rn") == container), 0)
    return {"ae": w["creates"][0]["status"] if w["creates"] else 0, "acpi": put, "container": container, "container_status": cnt}


def reg03_obs(D: dict, w: dict) -> dict:
    """fl_core.reg03_ae's input for one app: its wire, and its AE, policy and baseline container as its own
    originator reads them; three reads by a stranger (counted as the harness's). What they must say is FL01_APPS."""
    x = FL01_APPS[D["key"]]          # what it must have made: the driver's, not the package's own statement
    me, base, acp_rn = x["origin"], f"{CSE_URL[D['cse']]}/{x['ae']}", "flMetaAcp"
    h = me not in PARTY             # the proxy is no party of the FL_03 table: reading under it is the harness's
    _, a = rq("GET", base, me, why="REG_03 step 4: the app's AE, as its owner reads it", harness=h)
    _, p = rq("GET", f"{base}/{acp_rn}", me, why="REG_03 step 4: the app's access policy", harness=h)
    _, c = rq("GET", f"{base}/{x['container']}", me, why="REG_03 step 5: the app's baseline container", harness=h)
    stranger = [rq("GET", u, STRANGER, why="REG_03 step 4, control: a stranger reads", harness=True)[0]
                for u in (base, f"{base}/{x['container']}", f"{base}/{acp_rn}")]
    return {"origin": me, "cse": D["cse"], "cse_ri": CSE_RI[D["cse"]], "rn": x["ae"], "api": x["api"],
            "creates": w["creates"], "ae": (a or {}).get("m2m:ae"), "acp": (p or {}).get("m2m:acp"),
            "container": (c or {}).get("m2m:cnt"), "readers": list(x["readers"]),
            "reader_ops": x["ops"], "container_rn": x["container"], "mp1_posts": w["mp1_posts"],
            "confirm_after_writes": w["confirm_after_writes"], "mid": w["mid"], "lcm": D.get("lcmInstanceId"),
            "stranger": stranger}


def kinds(base: str, origin: str, kind: str, harness: bool = False) -> list[tuple[dict, str | None]]:
    """(record, creator) of each contentInstance of one kind in a container at base, oldest first."""
    st, b = rq("GET", f"{base}?rcn=4", origin, why=f"{kind} records", harness=harness)
    out = []
    for c in sorted((b or {}).get("m2m:cnt", {}).get("m2m:cin", []) if st == 200 else [], key=lambda c: (c["ct"], c["ri"])):
        try:
            v = json.loads(c["con"])
        except ValueError:
            continue
        if isinstance(v, dict) and v.get("kind") == kind:
            out.append((v.get("record"), c.get("cr")))
    return out


def enumerate_fl01(descriptors: dict) -> dict:
    """TD_MEC_FL_01 step 7 as the orchestrator does it: the discovery of every round, each profile and its
    holder's AE read under CflOrch, MEC 011's listing (which shows confirmed-ready instances only) and MEC
    010-2's own lists of instances and packages (fl_platform.mec010_view; like the agent's MEC 010-2 calls, these
    two reads do not go through the FL_03 byte counter). descriptors: {SHA-256: descriptor} of the run's own
    package copies; one counts for an instance only if MEC 010-2 holds its SHA-256 as that package's checksum."""
    found, _ = discover()
    profiles, holders = [], {}
    for ref in found:
        cse, ae, rn = (ref.split("/") + ["", "", ""])[:3]
        st, b = rq("GET", f"{CSE_URL.get(cse, A)}/{ae}/{rn}", ORCH, why="FL_01 step 7: a discovered profile")
        inner = next(iter((b or {}).values()), {}) if st == 200 and isinstance(b, dict) else {}
        profiles.append({"ref": ref, "labels": inner.get("lbl", []), "attad": inner.get("attad"), "ty": inner.get("ty")})
        holders.setdefault(ae, cse)
    apps = {}
    for ae, cse in holders.items():
        st, b = rq("GET", f"{CSE_URL.get(cse, A)}/{ae}", ORCH, why="FL_01 step 7: the AE holding a profile")
        apps[ae] = ((b or {}).get("m2m:ae") or {}).get("lbl", []) if st == 200 else []
    st, services = mec("GET", "/mec_service_mgmt/v1/services", who="flOrch")
    services = [{"serName": s.get("serName"), "transportInfo": s.get("transportInfo"), "_links": s.get("_links")}
                for s in (services if isinstance(services, list) else []) if isinstance(s, dict)]
    view = fp.mec010_view(MEC010)
    platform = {"instances": view["instances"], "packages": view["packages"], "descriptors": descriptors}
    return {"found": found, "profiles": profiles, "apps": apps, "services_status": st, "services": services,
            "mec010": view, "descriptors": {h: {"rn": (d.get("onem2m") or {}).get("rn"), "mnCse": (d.get("onem2m") or {}).get(
                "mnCse"), "role": (d.get("fl") or {}).get("role")} for h, d in descriptors.items()},
            "enumerated": fl.enumerate_candidates(profiles, apps, services, platform)}


def stray_mec011(ae: str, lcm: str) -> dict:
    """A stray registers itself at MEC 011, never through MEC 010-2: a registration, one service whose instance id
    (transportInfo.id) is `lcm` and whose endpoint names its AE, confirm_ready; MEC 011 then lists it. Counted as
    the harness's. Returns the statuses and the id MEC 011 gave it."""
    st_r, b = mec("POST", "/mec_app_support/v2/registrations", {"appName": f"stray-{ae}", "appInstanceId": lcm}, who=None)
    mid = (b or {}).get("appInstanceId")
    st_s, _ = mec("POST", f"/mec_service_mgmt/v1/applications/{mid}/services", {
        "serName": f"fl-stray-{ae}", "version": "0.1.0", "state": "ACTIVE", "serializer": "JSON",
        "transportInfo": {"id": lcm, "name": "oneM2M AE", "type": "REST_HTTP", "protocol": "HTTP", "version": "1.1",
                          "security": {}, "endpoint": {"uris": [FL01_URL[ae]]}}}, who=None)
    st_c, _ = mec("POST", f"/mec_app_support/v2/applications/{mid}/confirm_ready", {"indication": "READY"}, who=None)
    return {"registration": st_r, "service": st_s, "confirm_ready": st_c, "mid": mid, "lcm": lcm}


def make_stray(lcm_copied: str | None) -> dict:
    """The step-7 fixture, two AEs on MN-CSE-A (under CflStray and CflStray2, counted as the harness's) holding
    profiles the orchestrator may discover and must not enumerate (FL01_STRAY). Each registers itself at MEC 011
    first (stray_mec011) and names on its AE the instance id it gave there and the id MEC 011 gave it back:
    flStray the proxy's MEC 010-2 instance id (copied), flStray2 one it made up. So MEC 011 lists both, each with
    its own AE as the endpoint; only MEC 010-2 tells them from a deployed app."""
    import uuid
    out = {}
    for ae, lcm in (("flStray", lcm_copied), ("flStray2", f"stray-{uuid.uuid4()}")):
        me, u, o = FL01_OWNER[ae], FL01_URL[ae], {}
        o["mec011"] = stray_mec011(ae, str(lcm))
        o["ae"] = rq("POST", A, me, ty=ho.TY_AE, why=f"FL_01 step 7 fixture: the stray AE {ae}", harness=True, body={"m2m:ae": {
            "rn": ae, "api": "Nestimed.fl", "rr": False, "srv": ["4"],
            "lbl": ["fl:role:proxy", *(["fl:role:tfc", "fl:represents:flSrc3"] if ae == "flStray" else []), "fl:sim:true",
                    f"mec:lcmInstanceId:{lcm}", f"mec:appInstanceId:{o['mec011']['mid']}"]}})[0]
        o["acp"], b = rq("POST", u, me, ty=ho.TY_ACP, why="the stray AE's policy: the orchestrator may discover", harness=True,
                         body={"m2m:acp": {"rn": "flMetaAcp", "pv": acr(([me], ALL), ([ORCH], RD)), "pvs": acr(([me], ALL))}})
        ri = [(b or {}).get("m2m:acp", {}).get("ri")]
        o["acpi"], _ = rq("PUT", u, me, body={"m2m:ae": {"acpi": ri}}, why="the stray AE's policy on the AE", harness=True)
        for rn, lbl in FL01_STRAY[ae].items():
            o[rn], _ = rq("POST", u, me, ty=ho.TY_FCNT, why=f"FL_01 step 7 fixture: profile {rn}", harness=True, body={
                "mad:dmCay": {"rn": rn, "cnd": "org.onem2m.management.moduleclass.dmCapability", "name": "fl.localTraining",
                              "attad": rn == "flCap-other", "curSe": False, "lbl": lbl, "acpi": ri}})
        out[ae] = o
    return out


def remove_strays(stray: dict) -> dict:
    """Take the step-7 fixture out: each stray's MEC 011 registration (its service goes with it) and its AE, each
    by its own hand (counted as the harness's). Returns {ae: {mec011: status, ae: status}}."""
    out = {}
    for ae in STRAYS:
        mid = ((stray.get(ae) or {}).get("mec011") or {}).get("mid")
        out[ae] = {"mec011": mec("DELETE", f"/mec_app_support/v2/registrations/{mid}", who=None)[0] if mid else None,
                   "ae": rq("DELETE", FL01_URL[ae], FL01_OWNER[ae], why="FL_01 step 7 fixture removed", harness=True)[0]}
    return out


def strays_left() -> list[str]:
    """The stray AEs still on MN-CSE-A or still listed at MEC 011 (harness reads)."""
    _, svc = mec("GET", "/mec_service_mgmt/v1/services", who=None)
    svc = svc if isinstance(svc, list) else []
    return [ae for ae in STRAYS if rq("GET", FL01_URL[ae], ADMIN, why="is the stray fixture still there")[0] == 200
            or stray_listed(svc, ae)]


def stray_listed(services: list[dict], ae: str) -> bool:
    """Whether MEC 011's listing holds a service whose endpoint names the stray's AE."""
    return any(u.rstrip("/").endswith(f"/{CA}/{ae}")
               for s in services for u in ((s.get("transportInfo") or {}).get("endpoint") or {}).get("uris", []))


def plain_post(to: str, body: bytes) -> int:
    """The proxy-path device posting its JSON straight to the CSE, as plain HTTP (no oneM2M header). Counted as
    the harness's (a control)."""
    r = urllib.request.Request(to, data=body, method="POST", headers={"Content-Type": "application/json",
                                                                      "Accept": "application/json"})
    st, _, m, t0, t1 = _send(r, 10)
    _log_call(None, "POST", to, None, st, m, len(body), t0, t1)
    TRACE.append(f"device {DEVICE_ID} POST {to.split('/', 3)[-1]} plain HTTP -> {st} {m['sent']}+{m['received']}B harness"
                 " | FL_01 control: the device writes to the CSE without the proxy")
    return st


# ------------------------------------------------------------------------------------------------ the run
def load_sources(path: str, prereg_sha256: str | None, go: str | None) -> str | None:
    """--sources: take a capture only if it agrees with itself and passed its own gate. Returns why not, or None."""
    global DEV, EXPECT_R1, EXPECT_N
    raw = Path(path).read_bytes()
    cap = json.loads(raw)
    bad = fc.check(cap)
    if bad:
        return "the capture does not agree with itself: " + "; ".join(bad[:3])
    if not cap["usable"]:
        return "the capture did not pass its gate: " + "; ".join(cap["why_not"])
    if cap["origin"] == "device" and not (prereg_sha256 and go and prereg_sha256.startswith(go) and len(go) == 8):
        return "a device capture needs --prereg-sha256 and --go (the first 8 hex digits of that hash)"
    w = cap["expect"]["weights"]
    DEV = {**cap, "file": str(Path(path).resolve()), "file_sha256": hashlib.sha256(raw).hexdigest(),
           "prereg": {"sha256": prereg_sha256, "go_phrase": go}}
    EXPECT_R1 = cap["expect"]["r1"]
    EXPECT_N = {1: {"P-NAT": 8, **w["1"]}, 2: dict(w["2"]), 3: {"P-NAT": 26, **w["3"]}, 4: {"P-NAT": 26}}
    return None


def parse_args(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="the federated-learning driver (simulated sources, or --sources); "
                                             "TD_MEC_FL_03 deployment modes")
    ap.add_argument("--sources", help="a capture file of fl_capture.py: its records stand for flSrc1 and flSrc2")
    ap.add_argument("--prereg-sha256", help="SHA-256 of the frozen preregistration's body (device captures)")
    ap.add_argument("--go", help="the go phrase: the first 8 hex digits of that hash")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--mode", choices=MODES, default="hierarchical",
                   help="where the orchestrator and the aggregator sit (module text); default: hierarchical, today's")
    g.add_argument("--compare", action="store_true",
                   help="run the three modes one after another, then write one comparison record")
    ap.add_argument("--out", help="write the results file here instead of under its default name")
    a = ap.parse_args(argv)
    if a.compare and (a.sources or a.out or a.prereg_sha256 or a.go):
        ap.error("--compare runs the three modes on simulated sources and names its own files")
    return a


def configure(argv=None):
    """The command line, and the mode applied (set_mode) before anything is sent."""
    a = parse_args(argv)
    if not a.compare:
        set_mode(a.mode)
    return a


def main(argv=None) -> int:  # noqa: C901, PLR0912, PLR0915  one timeline, like the neighbouring drivers
    a = configure(argv)
    if a.compare:
        return compare()
    STEPS.clear()
    stamp = time.strftime('%Y%m%dT%H%M%S')
    tag = stamp if MODE == "hierarchical" else f"{MODE}_{stamp}"      # the default keeps today's file name
    results = RESULTS_DIR / f"fl_sim_{tag}.json"
    if a.sources:
        why = load_sources(a.sources, a.prereg_sha256, a.go)
        if why:
            print(f"refused: {why}")
            return 2
        results = (fc.OUT_DEVICE / f"fl_dev_{tag}.json" if DEV["origin"] == "device"
                   else RESULTS_DIR / f"fl_rehearsal_{tag}.json")
        print(f"== sources: {DEV['origin']} capture {DEV['file']} (sha256 {DEV['file_sha256'][:16]}...)")
    if a.out:
        results = Path(a.out)
    S = {"series": {s: fl.sim_series(seed, 3 * CHUNK, T0, d0, pct0) for s, (seed, d0, pct0) in SERIES.items()},
         "held": fl.pairs([fl.parse_env(r) for r in fl.sim_series(HELD_OUT[0], HELD_OUT[3], T0, HELD_OUT[1], HELD_OUT[2])])["samples"],
         "version": 0, "w": [0, 0, 0], "models": {0: [0, 0, 0]}, "parents": {}, "published": {}, "subs": [], "seen": set(),
         "agg_read": set(), "temp": [], "rounds": [], "target_active": None, "made": [], "cleanup": {}, "extra": {}}
    aborted, srv, mec_proc, inst = None, None, None, None
    mec010_proc, plat, mad = None, None, None
    work = WORK_ROOT / f"{stamp}-{MODE}"
    X = S["extra"]
    F1: dict[str, bool] = {}            # TD_MEC_FL_01: the pre-condition and each step -> passed
    X["fl01"] = FL1 = {"steps": F1, "deployed": {}, "device": {}, "enumeration": None, "stray": None}
    try:
        print(f"== the lab; mode {MODE}: orchestrator on {PLACE['flOrch']}, aggregator on {PLACE['flAgg']}, sources and "
              f"clients on {PLACE['flSrc1']} [TD_MEC_FL_03]")
        up = {c: rq("GET", u, ADMIN, why="topology check")[0] for c, u in (("IN", IN), ("MN-A", A), ("MN-B", B))}
        require("the IN-CSE and both MN-CSEs answer", set(up.values()) == {200}, str(up))
        named = lambda ae, u: ae if u == url(ae) else f"{ae} on {where(u)[0]}"  # noqa: E731
        left = [(ae, u) for ae, u in spots() if rq("GET", u, ADMIN, why="leftover check")[0] == 200]
        for ae, u in left:          # an earlier run that died: its AEs carry our names and go by their own originator;
            rq("DELETE", u, OWNER[ae], why="remove a leftover of an earlier run", harness=True)   # counted as the harness's
        X["leftovers_removed"] = [named(ae, u) for ae, u in left]
        require("no AE of an earlier run is left under our names", all(rq("GET", u, ADMIN)[0] == 404 for _, u in spots()),
                f"removed first: {X['leftovers_removed']}" if left else "none found")
        left1 = [ae for ae, u in FL01_URL.items() if rq("GET", u, ADMIN, why="leftover check (FL_01 names)")[0] == 200]
        for ae in left1:            # an app of an earlier run that died, or the stray fixture: by its own originator
            rq("DELETE", FL01_URL[ae], FL01_OWNER[ae], why="remove a leftover of an earlier run", harness=True)
        X["leftovers_removed"] += [f"{ae} (FL_01)" for ae in left1]
        require(f"no AE of an earlier run is left under the FL_01 names ({', '.join(FL01_URL)})",
                all(rq("GET", u, ADMIN)[0] == 404 for u in FL01_URL.values()), f"removed first: {left1}" if left1 else "none found")

        print("== the MEC platform of TD_MEC_REG_03: the main tree's agent and candidates, by pinned SHA-256")
        try:
            pins = {rel: hashlib.sha256(mp.read_pinned(rel)).hexdigest() for rel in mp.PINS}
            mad, why_pin = mp.platform_agent(), ""
        except mp.PinError as e:
            pins, why_pin = {}, str(e)
        require(f"the platform agent, the MEC 010-2 and the MEC 011 candidate are the files of commit "
                f"{mp.SOURCE_COMMIT[:7]} in {mp.SOURCE_TREE} (each hashes to its pin)", pins == mp.PINS and mad is not None,
                why_pin or ", ".join(f"{Path(r).name} {h[:12]}" for r, h in pins.items()))
        busy = {"mec011 :8097": mec("GET", "/mec_app_support/v2/timing/current_time", who=None)[0],
                "mec010-2 :8092": fp.http("GET", f"{MEC010}/", timeout=2)[0]}
        require("no MEC 011 on :8097 and no MEC 010-2 on :8092 is running that this run did not start (its code could "
                "not be held to the pins)", not any(busy.values()), str(busy))
        work.mkdir(parents=True, exist_ok=False)
        mec_proc = start_pinned("mec011", MEC011.rsplit(":", 1)[1], log=work / "logs" / "mec011.log")
        mec010_proc = start_pinned("mec010p2", log=work / "logs" / "mec010p2.log")
        wait_for(lambda: mec("GET", "/mec_app_support/v2/timing/current_time", who=None)[0] == 200)
        st, body = mec("GET", "/mec_app_support/v2/timing/current_time", who=None)
        require("the MEC 011 candidate answers (app support and service registry)", st == 200 and "seconds" in (body or {}),
                f"{MEC011}: HTTP {st}; started by this run from the pinned file")
        wait_for(lambda: "app_lcm" in ((fp.http("GET", f"{MEC010}/", timeout=2)[1] or {}).get("apis") or []))
        st10, b10 = fp.http("GET", f"{MEC010}/", timeout=2)
        require("the MEC 010-2 candidate answers (app_pkgm, app_lcm)", st10 == 200 and "app_lcm" in ((b10 or {}).get("apis") or []),
                f"{MEC010}: HTTP {st10}; started by this run from the pinned file")
        srv = ThreadingHTTPServer(("127.0.0.1", LISTEN), _Notify)
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        plat = fp.Platform(mad, MEC010, MEC011, {CIN: IN, CA: A, CB: B}, work / "platform")

        print(f"== TD_MEC_REG_03 for the FL Orchestrator AE [TD_MEC_FL_01 pre-condition]: its package through MEC 010-2, "
              f"its AE on {PLACE['flOrch']}")
        Do = plat.deploy("fl_orch", PLACE["flOrch"])
        ev_o, w_o = plat.evidence(Do), app_wire(Do, ORCH)
        FL1["deployed"]["fl_orch"] = {"evidence": ev_o, "wire": {k: v for k, v in w_o.items() if k != "mca"}}
        tag = reg03_tag(PLACE["flOrch"])
        FL1["pre_condition"] = {"orchestrator_cse": PLACE["flOrch"], "reg03_names": "the MN-CSE", **REG_PRE}
        ok1 = row(f"{tag} step 1, orchestrator", "the FL Orchestrator package was onboarded with its checksum, instantiated "
                  "through MEC 010-2 and runs from the platform's copy; MEC 011 lists it", fl.app_deployed(ev_o),
                  f"package {str(Do.get('checksum'))[:16]} (shipped {str(Do.get('shipped_descriptor_sha256'))[:16]}), lcm "
                  f"{Do.get('lcmInstanceId')}, pid {(Do.get('run') or {}).get('pid')}; MEC 010-2 operation as read there "
                  f"{ev_o['op_occs']}, the agent's record {ev_o['agent_result']}; error {Do.get('error')}")
        require("the FL Orchestrator app registered its AE (the run needs it from here on)", bool(w_o["creates"])
                and w_o["creates"][0]["status"] == 201, Do.get("error") or str(w_o["creates"]))
        r3o = reg03_obs(Do, w_o)
        ok2 = row(f"{tag} steps 2-6, orchestrator", f"the app's own AE Create to {PLACE['flOrch']} (2001, AE-ID = CflOrch), "
                  "the AE with both instance ids and its least-privilege policy, the baseline container it created; Mp1 in "
                  "order, ready only after its writes; a stranger reads nothing", fl.reg03_ae(r3o),
                  f"wire {w_o['creates']}; Mp1 {w_o['mp1_posts']}; stranger {r3o['stranger']}")
        step("CONTROL (must FAIL) a stranger read the orchestrator's AE, its container or its policy",
             any(s == 200 for s in r3o["stranger"]), f"HTTP {r3o['stranger']}")
        u_s = url("flOrch", "flScratch")
        crud = [rq("POST", url("flOrch"), ORCH, ty=ho.TY_CNT, body={"m2m:cnt": {"rn": "flScratch"}}, why="REG_03 step 6: create")[0],
                rq("GET", u_s, ORCH, why="REG_03 step 6: retrieve")[0],
                rq("PUT", u_s, ORCH, body={"m2m:cnt": {"lbl": ["updated"]}}, why="REG_03 step 6: update")[0],
                rq("DELETE", u_s, ORCH, why="REG_03 step 6: delete")[0], rq("GET", u_s, ORCH, why="REG_03 step 6: gone")[0]]
        ok3 = step(f"[{tag} step 6, orchestrator] the AE may create, retrieve, update and delete under its own subtree",
                   crud == [201, 200, 200, 200, 404], f"HTTP {crud}")
        F1["pre-condition REG_03 (orchestrator)"] = ok1 and ok2 and ok3
        FL1["pre_condition"]["holds"] = reg03_scope(PLACE["flOrch"], F1["pre-condition REG_03 (orchestrator)"])
        made = {"flOrch": make_ae("flOrch", adopt=adopt_of(w_o, "ops"))}
        S["adopted"] = ["flOrch"]

        print("== registration: every party as an AE; the Trusted FL Client as a MEC app [TD_MEC_FL_01 step 3] (all "
              "sources simulated)")
        for ae in ("flAgg", "flSrc1", "flSrc2"):
            made[ae] = make_ae(ae)
            S["made"].append(ae)

        def tfc_held(D):            # while the client's confirm_ready is held at the MEC 011 relay
            w = app_wire({**D, "records": {k: plat.relays[k].since(n) for k, n in D["mark"].items()}}, TFC)
            return {"listed": bool(plat.listed(D["lcmInstanceId"])), "registered": plat.registered(w["mid"]),
                    "ae": rq("GET", url("flTfc"), ORCH, why="FL_01 step 4: the client's AE while its confirm_ready is held")[0],
                    "held": True}
        Dt = plat.deploy("fl_tfc", PLACE["flTfc"], at_hold=tfc_held)
        ev_t, w_t = plat.evidence(Dt), app_wire(Dt, TFC)
        FL1["deployed"]["fl_tfc"] = {"evidence": ev_t, "wire": {k: v for k, v in w_t.items() if k != "mca"},
                                     "at_hold": Dt.get("at_hold")}
        require("the Trusted FL Client app registered its AE (the run needs it from here on)", bool(w_t["creates"])
                and w_t["creates"][0]["status"] == 201, Dt.get("error") or str(w_t["creates"]))
        inst = w_t["mid"]
        made["flTfc"] = make_ae("flTfc", adopt=adopt_of(w_t, "flMeta"))
        S["adopted"].append("flTfc")
        for ae in ("flNat", "flDec"):
            made[ae] = make_ae(ae)
            S["made"].append(ae)
        made = {ae: made[ae] for ae in ("flOrch", "flAgg", "flSrc1", "flSrc2", "flTfc", "flNat", "flDec")}
        bad = {ae: m for ae, m in made.items() if any(v not in (200, 201) for k, v in m.items())}
        require("seven AEs, each with two access policies, its containers and (participants) its capability profile",
                not bad, f"not created: {bad}" if bad else ", ".join(f"{ae} on {HOME.get(ae, A).rsplit('/', 1)[1]}" for ae in made))
        step(f"[FL_03] {MODE} mode: the orchestrator and the aggregator are registered where the placement table puts "
             "them; sources and clients where they always are", made["flOrch"]["ae"] == 201 and made["flAgg"]["ae"] == 201
             and all(HOME[ae] == CSE_URL[placement(MODE)[ae]] for ae in made),
             f"flOrch on {PLACE['flOrch']} (HTTP {made['flOrch']['ae']}), flAgg on {PLACE['flAgg']} (HTTP {made['flAgg']['ae']})")
        for src in AUTH:
            post(src, "flMeta", OWNER[src], {"kind": "descriptor", "record": {
                "sourceRef": src, "deviceClass": fl.CLASS_WORDING["fl-assisted"], "administrativeDomain": DOMAIN[src],
                "modality": "device telemetry", "schema": "sim_phone.py env record", "approximateSampleCount": CHUNK - 1,
                "freshness": "one record per 5 s on a simulated clock", "permittedPurpose": "fl-training", "locality": "edge-a",
                "nativeTraining": False, "sim": True} | ({} if not DEV else {
                    "schema": "probe app env record (LiveService.java)", "freshness": "one record per 5 s on the phone's clock",
                    "sim": False, "dataOrigin": DEV["origin"], "deviceLabel": DEV["sources"][src]["label"],
                    "bridge": "the host registered this AE and posts the captured records"})}, why="data suitability description")
        require(f"{posted_by()} (first 9 slots) into the sources' own containers", post_chunk(S, 0, CHUNK) == 0)
        post("flOrch", "ops", ORCH, {"kind": "operation", "record": {
            "operationRef": OP, "purpose": "fl-training", "schema": fl.SCHEMA, "sim": True}})
        st, _ = post("flOrch", "model", ORCH, rn="v0", why="initial global model",
                     obj={"version": 0, "model": fl.model_body(S["w"]), "modelDigest": fl.model_digest(S["w"]), "round": 0, "sim": True})
        require("an initial global model is provisioned (v0, all weights 0)", st == 201, f"HTTP {st}")
        cond0 = observe_readiness("flTfc", ("flSrc1", "env"))
        post_readiness("flTfc", cond0, "awaitingAuthorization")
        post("flTfc", "flMeta", TFC, {"kind": "tfc-profile", "mec011AppInstanceId": inst, "represents": list(AUTH),
                                      "record": fl.tfc_profile(
            TFC, version="1", host="edge-a-host (this PC)", cse=PLACE["flTfc"], operator="lab-operator-A", domain="edge-a",
            capability_ref=f"{PLACE['flTfc']}/flTfc/flCap", max_sources=2, coordinator=coordinator_ref(), operations=[OP],
            state="awaitingAuthorization")})

        print("== discovery [TR-0077 7.3.5.9.9 check 1; TD_MEC_FL_01 steps 1, 2, 4]")
        found, payloads = discover()
        roles = {}
        for u in found:
            ae = u.split("/")[1]
            for part in ("flCap", "flCompute"):
                st, b = rq("GET", url(ae, part), ORCH, why="discovery: read a profile")
                payloads.append(b)
                if part == "flCap" and st == 200:
                    roles[ae] = next((x.split(":", 2)[2] for x in b["mad:dmCay"].get("lbl", []) if x.startswith("fl:role:")), None)
            if roles.get(ae) == "data-source":
                payloads.append(rq("GET", url(ae, "flMeta", "la"), ORCH, why="discovery: source metadata")[1])
        o1 = {"registered": {ae: made[ae]["ae"] for ae in ("flSrc1", "flSrc2", "flTfc")}, "expect_sources": ["flSrc1", "flSrc2"],
              "expect_tfc": "flTfc", "payloads": payloads,
              "found": {"sources": [a for a, r in roles.items() if r == "data-source"], "tfc": [a for a, r in roles.items() if r == "tfc"]}}
        row("check 1", "two data sources and the Trusted FL Client registered; the orchestrator discovered the sources' "
            "metadata and the client's capability, and nothing it received holds an observation", fl.ac1_register_discover(o1),
            f"discovery by label returned {len(found)} profiles: {', '.join(u.split('/')[1] for u in found)}")
        _, obs = rq("GET", f"{HOME['flSrc1']}?fu=1&ty={ho.TY_CIN}", ORCH, why="discovery of contentInstances by the orchestrator")
        leak = [u for u in (obs or {}).get("m2m:uril", []) if "/env/" in u]
        step("the orchestrator's discovery lists none of the observations", not leak, f"{len(leak)} observation paths visible to it")
        _, rb_cap = rq("GET", url("flNat", "flCap"), NAT)
        _, rb_agt = rq("GET", url("flNat", "flCompute"), NAT)
        F1["step 1"] = row("FL_01 step 1", "the capability profile of the FL-native class (represented by a simulated source) is two "
            "<flexContainer> resources", fl.fl01_1_capability_fcnt({"created": {k: made["flNat"][k] for k in ("flCap", "flCompute")},
                                                                    "readback": {"flCap": rb_cap, "flCompute": rb_agt}}),
            "mad:dmCay (dmCapability) and mad:dmAgt (dmAgent), TS-0023 classes the CSE knows; the mapping is ours")
        st_bad, _ = rq("POST", url("flNat"), NAT, ty=ho.TY_FCNT, why="a specialisation the CSE does not know",
                       body={"est:flCap": {"rn": "flCustom", "cnd": "org.estimed.fl.capability", "canTrain": True}})
        step("the CSE refuses a capability flexContainer of a specialisation it does not know (400)", st_bad == 400, f"HTTP {st_bad}")
        F1["step 2"] = row("FL_01 step 2", "that profile is discoverable by the orchestrator for client selection",
                           fl.fl01_2_discoverable({"found": found, "expect": f"{PLACE['flNat']}/flNat/flCap"}))

        print("== TD_MEC_FL_01 steps 3 and 4: the Trusted FL Client as a MEC app, on behalf of the constrained devices")
        F1["step 3"] = row("FL_01 step 3", "the Trusted FL Client package was onboarded with its checksum, instantiated "
                           "through MEC 010-2 and runs from the platform's copy; MEC 011 lists it", fl.app_deployed(ev_t),
                           f"package {str(Dt.get('checksum'))[:16]}, lcm {Dt.get('lcmInstanceId')}, pid "
                           f"{(Dt.get('run') or {}).get('pid')}, MEC 011 {inst}; MEC 010-2 operation as read there "
                           f"{ev_t['op_occs']}, the agent's record {ev_t['agent_result']}; error {Dt.get('error')}")
        r3t = reg03_obs(Dt, w_t)
        lbl_t = (r3t["ae"] or {}).get("lbl", [])
        held = Dt.get("at_hold") or {}
        ok4a = row("FL_01 step 4", "it is registered to the MEC platform (MEC 011 registration and service; listed only once "
                   "the held confirm_ready was let through) and to MN-CSE-A (its own AE Create, carrying the instance id)",
                   fl.fl01_4_tfc_registered({
                       "mec011_registration": w_t["registration"], "appInstanceId": inst,
                       "listed_before_ready": held.get("listed") if held.get("held") else None, "confirm_ready": w_t["confirm_ready"],
                       "listed_after_ready": bool(plat.listed(Dt.get("lcmInstanceId"))), "ae": made["flTfc"]["ae"],
                       "ae_label_instance": next((x.split(":", 2)[2] for x in lbl_t if x.startswith("mec:appInstanceId:")), None),
                       "represents": FL01_APPS["fl_tfc"]["represents"]}),
                   f"while confirm_ready was held: listed {held.get('listed')}, registered {held.get('registered')}, AE "
                   f"{held.get('ae')}; Mp1 {w_t['mp1_posts']}")
        ok4b = row("REG_03 steps 2-6, Trusted FL Client", "its AE Create on its own wire (2001), its policy and baseline "
                   "container, ready only after its writes; a stranger reads nothing", fl.reg03_ae(r3t),
                   f"wire {w_t['creates']}; stranger {r3t['stranger']}")
        binding = kinds(url("flTfc", "flMeta"), ORCH, "binding")
        ok4c = row("FL_01 step 4", "on behalf of the constrained devices: its AE names flSrc1 and flSrc2, which are registered "
                   "on the same CSE, and it wrote the binding record itself", fl.fl01_4_on_behalf({
                       "represents": FL01_APPS["fl_tfc"]["represents"], "ae_labels": lbl_t,
                       "sources": {s: made[s]["ae"] for s in AUTH}, "binding": binding[0][0] if binding else None,
                       "binding_creator": binding[0][1] if binding else None, "client": TFC,
                       "ae_cse": ae_cse(r3t), "expect_cse": PLACE["flSrc1"], "lcm": Dt.get("lcmInstanceId"), "mid": inst}),
                   f"labels {[x for x in lbl_t if x.startswith(('fl:represents', 'mec:'))]}; binding {binding[0][0] if binding else None}")
        F1["step 4"] = ok4a and ok4b and ok4c

        print("== TD_MEC_FL_01 steps 5 and 6: the MEC proxy path for a MEC-native / non-oneM2M device (simulated)")
        Dp = plat.deploy("fl_proxy", PROXY_CSE)
        ev_p, w_p = plat.evidence(Dp), app_wire(Dp, FL01_OWNER["flProxy"])
        FL1["deployed"]["fl_proxy"] = {"evidence": ev_p, "wire": {k: v for k, v in w_p.items() if k != "mca"}}
        dep_p = fl.app_deployed(ev_p)
        r3p = reg03_obs(Dp, w_p)
        ok5a = row("REG_03 steps 2-6, proxy", "the proxy app's own AE Create on MN-CSE-A (2001), its policy and baseline "
                   "container, ready only after its writes; a stranger reads nothing", fl.reg03_ae(r3p),
                   f"wire {w_p['creates']}; error {Dp.get('error')}")
        _, svcs = mec("GET", "/mec_service_mgmt/v1/services?ser_name=fl-proxy-path", who=None)
        svc = next((s for s in (svcs if isinstance(svcs, list) else [])
                    if (s.get("transportInfo") or {}).get("id") == Dp.get("lcmInstanceId")), None)
        endpoint = fp.device_endpoint(svc)
        px, CK = FL01_URL["flProxy"], CHECKER
        cfg = kinds(f"{px}/flConfig", CK, "proxy-config", harness=True)
        cnt_st, cnt = rq("GET", f"{px}/{DEVICE_ID}", CK, why="FL_01 step 5: the device's container", harness=True)
        _, prof = rq("GET", f"{px}/flCap-{DEVICE_ID}", CK, why="FL_01 step 5: the device's profile", harness=True)
        want_d = FL01_APPS["fl_proxy"]["data_acp"]
        dacp_st, dacp = rq("GET", f"{px}/{want_d['rn']}", FL01_OWNER["flProxy"], harness=True,
                           why="FL_01 step 5: the proxy's data policy, read back under its owner (only it may read it)")
        dacp = (dacp or {}).get("m2m:acp") if dacp_st == 200 else None
        FL1["deployed"]["fl_proxy"]["data_acp"] = {"status": dacp_st, "read": dacp, "must_be": want_d}
        F1["step 5"] = row("FL_01 step 5", "the proxy path is configured: the proxy app is deployed, publishes its device "
                           "endpoint at MEC 011, states its configuration in the tree and holds a container and a proxy-path "
                           "profile for devPx1; its data policy, read back, gives only its checker RETRIEVE + DISCOVERY and "
                           "governs the device container", fl.fl01_5_proxy_path({
                               "deployed": dep_p, "origin": FL01_OWNER["flProxy"], "rn": "flProxy",
                               "lcm": Dp.get("lcmInstanceId"), "devices": FL01_APPS["fl_proxy"]["devices"], "service": svc,
                               "config": cfg[0][0] if cfg else None, "config_creator": cfg[0][1] if cfg else None,
                               "containers": {DEVICE_ID: (cnt or {}).get("m2m:cnt")} if cnt_st == 200 else {},
                               "profiles": {DEVICE_ID: (prof or {}).get("mad:dmCay")}, "data_acp": dacp,
                               "data_acp_rn": want_d["rn"], "data_readers": want_d["readers"], "data_ops": want_d["ops"]}),
                           f"endpoint {endpoint}; data policy {dacp_st} pv {((dacp or {}).get('pv') or {}).get('acr')}; "
                           f"deployed: {dep_p[1]}") and ok5a
        dev, recs = fp.SimDevice(DEVICE_ID), fl.sim_series(DEVICE_SERIES[0], DEVICE_SERIES[3], T0, DEVICE_SERIES[1], DEVICE_SERIES[2])
        m_cse = len(plat.relays[CA].seen)
        answers = [dev.post(endpoint, r) if endpoint else (0, None, fp.device_body(r).decode()) for r in recs]
        _, got = rq("GET", f"{px}/{DEVICE_ID}?rcn=4", CK, why="FL_01 step 6: the bridged records", harness=True)
        stored = sorted((got or {}).get("m2m:cnt", {}).get("m2m:cin", []), key=lambda c: (c["ct"], c["ri"]))
        wire6 = [((r["body"] or {}).get("m2m:cin") or {}).get("con") for r in fp.creates(
            plat.relays[CA].since(m_cse), ho.TY_CIN, FL01_OWNER["flProxy"]) if r["path"].endswith(f"/flProxy/{DEVICE_ID}")]
        FL1["device"] = {"id": DEVICE_ID, "endpoint": endpoint, "sent": [a[2] for a in answers],
                         "answers": [[a[0], a[1]] for a in answers], "stored": [{k: c.get(k) for k in ("ri", "ct", "cr", "con")} for c in stored]}
        ok6a = row("FL_01 step 6", "the proxy path bridged the device's data into the tree: each of its records is in "
                   "flProxy/devPx1 as the device sent it, in order, created by the proxy",
                   fl.fl01_6_bridged({"origin": FL01_OWNER["flProxy"], "sent": [a[2] for a in answers],
                                      "answers": [a[0] for a in answers], "stored": stored, "wire": wire6}),
                   f"{len(answers)} records posted to {endpoint}: {[a[0] for a in answers]}; {len(stored)} in the container")
        tree = lambda: sorted((rq("GET", f"{px}?fu=1", CK, why="the proxy's tree", harness=True)[1] or {}).get("m2m:uril", []))  # noqa: E731
        before, m_cse = tree(), len(plat.relays[CA].seen)
        st_u, ans_u, _ = fp.SimDevice(UNKNOWN_DEVICE).post(endpoint, recs[0]) if endpoint else (0, None, "")
        sent_u = [r for r in plat.relays[CA].since(m_cse) if r["method"] in ("POST", "PUT") and UNKNOWN_DEVICE in r["path"] + r["raw"]]
        after = tree()
        ok6b = row("FL_01 step 6", "an unconfigured device is refused by the proxy: 403, nothing sent to the CSE, the proxy's "
                   "tree unchanged", fl.fl01_6_refused({"answer": st_u, "creates": len(sent_u), "before": before, "after": after}),
                   f"{UNKNOWN_DEVICE}: HTTP {st_u} {ans_u}; tree {len(before)} -> {len(after)} resources")
        step(f"CONTROL (must FAIL) the record of an unconfigured device ({UNKNOWN_DEVICE}) was accepted by the proxy or "
             "reached the tree", 200 <= st_u < 300 or bool(sent_u) or before != after, f"HTTP {st_u}; {len(sent_u)} writes")
        cni = lambda: ((rq("GET", f"{px}/{DEVICE_ID}", CK, why="records in the device container", harness=True)[1] or {})  # noqa: E731
                       .get("m2m:cnt") or {}).get("cni")
        n0, body0 = cni(), fp.device_body(recs[0])
        st_plain = plain_post(f"{px}/{DEVICE_ID}", body0)
        st_own, _ = rq("POST", f"{px}/{DEVICE_ID}", DEVICE_ORIGIN, ty=ho.TY_CIN, harness=True,
                       why="FL_01 control: the device's own Create, bypassing the proxy",
                       body={"m2m:cin": {"cnf": "application/json:0", "con": body0.decode()}})
        n1 = cni()
        ok6c = row("FL_01 step 6", "without the proxy the device writes nothing into the tree: its plain JSON and its Create "
                   "under its own originator are both refused by the CSE", fl.fl01_6_no_bypass(
                       {"plain": st_plain, "own_origin": st_own, "before": n0, "after": n1}),
                   f"plain HTTP {st_plain}, as {DEVICE_ORIGIN} HTTP {st_own}; records {n0} -> {n1}")
        step("CONTROL (must FAIL) the device wrote into the tree without the proxy", 200 <= st_plain < 300 or 200 <= st_own < 300
             or n0 != n1, f"HTTP {st_plain}, {st_own}; records {n0} -> {n1}")
        st_oread, _ = rq("GET", f"{px}/{DEVICE_ID}/la", ORCH, why="the orchestrator tries to read the bridged data")
        step("CONTROL (must FAIL) the orchestrator read the bridged device's records", st_oread == 200, f"HTTP {st_oread}")
        F1["step 6"] = ok6a and ok6b and ok6c

        print("== TD_MEC_FL_01 step 7: the orchestrator enumerates the candidates of the three classes")
        FL1["stray"] = make_stray(Dp.get("lcmInstanceId"))
        E = FL1["enumeration"] = enumerate_fl01(plat.descriptors())
        en = E["enumerated"]
        stray_refs = [f"{CA}/{ae}/{rn}" for ae in STRAYS for rn in FL01_STRAY[ae]]
        listed_s = {ae: stray_listed(E["services"], ae) for ae in STRAYS}
        F1["step 7"] = row("FL_01 step 7", "all three device classes are enumerable by the orchestrator as candidates: "
                           "FL-native flDec and flNat, the constrained flSrc1 and flSrc2 behind the deployed Trusted FL "
                           "Client, devPx1 behind the deployed proxy; 'deployed' read from MEC 010-2 (INSTANTIATED, of a "
                           "package whose descriptor names the AE) and from MEC 011's listing of that instance",
                           fl.fl01_7_candidates({
                               "classes": en["classes"], "expect": FL01_EXPECT, "refused": en["refused"], "stray": stray_refs,
                               "found": E["found"], "profiles": {p["ref"]: p["labels"] for p in E["profiles"]},
                               "stray_listed": listed_s}),
                           f"{en['classes']} via {en['via']}; refused {[(r['ref'].rsplit('/', 1)[1], r['why']) for r in en['refused']]}; "
                           f"strays listed at MEC 011 {listed_s}; MEC 010-2 lists {len(E['mec010']['instances'])} instances; "
                           f"stray fixture {FL1['stray']}")
        named = sum(en["classes"].values(), [])
        for dev, what in STRAY_DEVICES.items():
            step(f"CONTROL (must FAIL) {what} was enumerated", dev in named, str(en["classes"]))
        FL1["stray_removed"] = remove_strays(FL1["stray"])
        still = strays_left()
        step("the stray fixture is removed before round 1: both AEs (200) and their MEC 011 registrations (204); "
             "neither AE is on the CSE and MEC 011 lists neither (its profiles and services must not reach a round)",
             all(v == {"mec011": 204, "ae": 200} for v in FL1["stray_removed"].values()) and not still,
             f"{FL1['stray_removed']}; still there {still}")
        FL1["verdict"] = fl01_verdict(F1)
        step(f"[FL_02 pre-condition] TD_MEC_FL_01 ran in this run before round 1: the pre-condition ({tag} for the FL "
             "Orchestrator AE) and its seven steps passed, with simulated devices", FL1["verdict"] == "PARTIAL",
             ", ".join(f"{k}: {'PASS' if v else 'FAIL'}" for k, v in F1.items()) + f"; TD_MEC_FL_01 {FL1['verdict']}; "
             f"pre-condition: {FL1['pre_condition']['holds']}")

        print("== policy decision [check 2]; readiness by condition; nobody grants itself access")
        st1, st2 = issue_policy("flSrc1", "1"), issue_policy("flSrc2", "1", operations=("aggregate-statistics",))
        require("each domain's authority posted a policy record for its source", (st1, st2) == (201, 201), f"HTTP {st1}, {st2}")
        definition = {"datasetId": "ds-agg", "sources": ["flSrc1", "flSrc2"], "processor": TFC, "purpose": "fl-training",
                      "mode": "aggregatedSources", "sim": True}
        denied = decide(read_policies(ORCH), definition["sources"])
        post("flOrch", "ops", ORCH, {"kind": "decision", "record": {"definition": definition, "decision": denied}})
        tfc_read_denied, _ = rq("GET", url("flSrc2", "env", "la"), TFC, why="the client's read while the definition is refused")
        st2b = issue_policy("flSrc2", "2")
        granted = decide(read_policies(ORCH), definition["sources"])
        post("flOrch", "ops", ORCH, {"kind": "decision", "record": {"definition": definition, "decision": granted}})
        row("check 2", "a two-source dataset definition is authorised with one decision reference per source policy; while "
            "one policy did not permit training it was refused and nothing was assembled",
            fl.ac2_policy_decision({"granted": granted, "denied": denied, "n_sources": 2,
                                    "denied_dataset": None if tfc_read_denied == 403 else {"read": tfc_read_denied}}),
            f"refused: {denied['refusals']} (the client's read then: HTTP {tfc_read_denied}); after {DOMAIN['flSrc2']}'s policy 2 "
            f"(HTTP {st2b}): {granted['decisionRefs']}")
        st_x, _ = rq("PUT", url("flSrc2", "flDataAcp"), AUTH["flSrc1"], why="domain A's authority tries to open domain B's source",
                     body={"m2m:acp": {"pv": acr(([OWNER["flSrc2"]], ALL), ([TFC], RD))}})
        step("the two sources are two domains: the authority of one cannot open the other's source (403)", st_x == 403, f"HTTP {st_x}")
        g = [set_readers(s, [TFC]) for s in AUTH]
        require("each authority opened its own source to the Trusted FL Client on the CSE", g == [200, 200], f"HTTP {g}")
        cond1 = observe_readiness("flTfc", ("flSrc1", "env"))
        post_readiness("flTfc", cond1, "ready")
        row("readiness", "the Trusted FL Client is not ready while its data condition is false, and ready when all six hold",
            fl.gov_readiness({"before": cond0, "after": cond1, "state_before": "awaitingAuthorization", "state_after": "ready"}),
            "false before the grant: " + ", ".join(k for k, v in cond0.items() if not v))
        st_or, _ = rq("GET", url("flSrc1", "env", "la"), ORCH, why="the orchestrator tries to read observations")
        st_oa, _ = rq("PUT", url("flSrc1", "flDataAcp"), ORCH, why="the orchestrator tries to grant itself access",
                      body={"m2m:acp": {"pv": acr(([OWNER["flSrc1"]], ALL), ([TFC, ORCH], RD))}})
        st_or2, _ = rq("GET", url("flSrc1", "env", "la"), ORCH, why="the orchestrator reads again after its attempt")
        row("self-grant", "the orchestrator can neither read a source's observations nor change the source's access policy",
            fl.gov_orch_no_self_grant({"raw_read": st_or, "acp_update": st_oa}),
            f"read {st_or}, policy change {st_oa}, read again {st_or2}")
        step("CONTROL (must FAIL) the orchestrator read a source's raw data by itself", 200 in (st_or, st_or2),
             f"HTTP {st_or}, then {st_or2}")
        step("CONTROL (must FAIL) the orchestrator granted itself access to a source", st_oa == 200, f"HTTP {st_oa}")

        print("== the clients answer the invitation")
        for ae, answer in (("flTfc", "accepted"), ("flNat", "accepted"), ("flDec", "declined")):
            if ae != "flTfc":
                post_readiness(ae, observe_readiness(ae, (ae, "env")), "ready")
            rq("GET", url("flOrch", "ops", "la"), OWNER[ae], why="the client reads the operation")
            post(ae, "flStatus", OWNER[ae], {"kind": "decision", "record": {"operationRef": OP, "decision": answer, "sim": True}})
        X["invited"], X["accepted_invitations"] = 3, 2

        print("== round 1, aggregatedSources [checks 3, 4; TD_MEC_FL_02 steps 1 to 10]")
        r1 = run_round(S, 1, "aggregatedSources")
        rec = r1["record"]
        step("[FL_01] round 1's discovery returned no profile of the step-7 fixture (it was removed before the round)",
             not [u for u in r1["discovered"] if "/flStray/" in u], f"{len(r1['discovered'])} profiles discovered")
        S["models"][1], S["parents"][1] = rec["w_out"], rec["modelInDigest"]
        client_of = {ae: OWNER[ae] for ae in ("flTfc", "flNat", "flDec")}
        sel_aes = sorted({p["ae"] for p in participants("aggregatedSources") if p["pid"] in r1["selected"]})
        row("FL_02 step 1", "the orchestrator selected the participants from discovered capability profiles",
            fl.fl02_1_selection({"candidates": r1["candidates"], "selected": r1["selected"], "discovered_refs": r1["discovered"],
                                 "capability_refs": r1["capability_refs"]}),
            f"selected {r1['selected']}; not selected {r1['selection']['rejected']}")
        row("decline", "a client whose descriptors match declined and is not a participant",
            fl.gov_decline({"candidates": r1["candidates"], "selected": r1["selected"], "decliner": "P-DEC"}),
            f"P-DEC: {r1['selection']['rejected'].get('P-DEC')}; descriptors match for {r1['selection']['descriptors_match']}")
        step("CONTROL (must FAIL) a client that declined although its descriptors match was counted as participating",
             "P-DEC" in r1["selected"] or "P-DEC" in [a["participantId"] for a in rec["accepted"]], f"participants {r1['selected']}")
        row("FL_02 step 2", "each selected client was notified of its task through a subscription on the task container",
            fl.fl02_2_notified({"selected_clients": sel_aes, "not_selected": ["flDec"], "client_of": client_of,
                                "notifications": r1["notifications"]}),
            f"{len(r1['notifications'])} notifications at {sorted({n['endpoint'] for n in r1['notifications']})}; every subscriber "
            "of the one task container gets every task and takes its own")
        row("FL_02 step 3", "the global model was distributed in the orchestrator's <container> and each selected client read it",
            fl.fl02_3_distributed({"model_digest": rec["modelInDigest"], "published": 201, "selected_clients": sel_aes,
                                   "reads": r1["reads"]}),
            f"v0 {rec['modelInDigest'][:16]}")
        row("FL_02 step 4", "each client verified task identity, binding version and model digest, then trained on its own samples",
            fl.fl02_4_training({"selected": r1["selected"], "clients": r1["clients"]}),
            ", ".join(f"{c['participantId']}: {c['samples']} samples" for c in r1["clients"]))
        tfc1 = next(c for c in r1["clients"] if c["participantId"] == "P-TFC-AGG")
        _, raw_own = rq("GET", url("flSrc1", "env") + "?rcn=4", OWNER["flSrc1"], why="the source reads its own observations")
        step("the scan sees observations where they are (the source's own container), so an empty result elsewhere means something",
             len(fl.scan_raw(raw_own)) >= CHUNK, f"{len(fl.scan_raw(raw_own))} hits in flSrc1/env")
        def central():      # every contentInstance this run put into the orchestrator's and the aggregator's containers
            return ([json.loads(c["con"]) for cnt in ("ops", "tasks", "model", "deploy") for c in cins("flOrch", cnt, ORCH)]
                    + [json.loads(c["con"]) for cnt in ("updates", "models", "rounds") for c in cins("flAgg", cnt, AGG)])
        cen = central()
        row("FL_02 step 5", f"no observation is in the orchestrator's containers ({PLACE['flOrch']}), in the aggregator's "
            f"containers ({PLACE['flAgg']}) or in anything the orchestrator received, and the orchestrator's own read is refused",
            fl.fl02_5_raw_stays({"central_payloads": [cen, ORCH_SEEN], "orch_raw_read": st_or}),
            f"scanned {len(cen)} contentInstances and {len(ORCH_SEEN)} answers; 'node' here is a resource tree, all on one PC")
        row("FL_02 step 6", "each update is a <contentInstance> created at the aggregator under the client's own originator",
            fl.fl02_6_upload({"uploads": r1["uploads"]}), ", ".join(f"{u['participantId']} by {u['creator']}" for u in r1["uploads"]))
        st_peek, _ = rq("GET", url("flAgg", "updates") + "?rcn=4", TFC, why="a client tries to read the others' updates")
        step("a client can create an update and cannot read the updates container (403)", st_peek == 403, f"HTTP {st_peek}")
        row("FL_02 step 7", "the aggregator collected every posted update inside the round's time window",
            fl.fl02_7_collected({"posted": [u["updateDigest"] for u in r1["uploads"]], "collected": r1["collected"], "round": rec}),
            f"{len(r1['collected'])} read, window {ROUND_TIMEOUT_S} s")
        row("FL_02 step 8", "the aggregate (FedAvg by sample count) recomputes bit for bit and its held-out error is lower",
            fl.fl02_8_aggregate({"round": rec, "loss_before": r1["loss_before"], "loss_after": r1["loss_after"]}),
            f"w {rec['w_in']} -> {rec['w_out']}; held-out error {r1['loss_before']} -> {r1['loss_after']} tenths of a degree over "
            f"{len(S['held'])} simulated samples")
        row("FL_02 step 9", "the orchestrator redistributed the new model and every participant read it",
            fl.fl02_9_redistributed({"model_digest": rec["modelOutDigest"], "published": r1.get("redistributed"),
                                     "participants": ["flTfc", "flNat"], "reads": r1["reads_after"]}),
            f"v1 {str(rec['modelOutDigest'])[:16]}")
        row("FL_02 step 10", "the round completed at or above the stated participation rate (2/3, at least 2)",
            fl.fl02_10_completion({"round": rec}),
            f"accepted {rec['quorum']['accepted']} of {rec['quorum']['selected']}; no straggler in this round")
        _, pub_ds = rq("GET", url("flTfc", "flMeta") + "?rcn=4", ORCH, why="the published dataset record")
        pub_rec = next((json.loads(c["con"])["record"] for c in (pub_ds or {}).get("m2m:cnt", {}).get("m2m:cin", [])
                        if json.loads(c["con"]).get("kind") == "dataset"), None)
        row("check 3", "the dataset was assembled by the stated feature selection and time alignment; version, provenance and "
            "effective sample count are published, the samples are not",
            fl.ac3_dataset({"record": tfc1["dataset"], "published": pub_rec, "samples": tfc1["assembled"]["samples"],
                            "provenance": tfc1["provenance"], "align": "slot" if DEV else "exact"}),
            f"ds-agg version 1, rules {tfc1['dataset']['processingProfileRef']}, {tfc1['dataset']['effectiveSampleCount']} samples from "
            f"{len(tfc1['provenance'])} source records")
        a1 = tfc1["assembled"]
        step("the assembled dataset is the one counted " + ("a second way in the capture file" if DEV else "by hand from the series' layout"),
             {"n": len(a1["samples"]), "per_source": a1["per_source"], "dropped_gap": a1["dropped_gap"],
              "dropped_unaligned": a1["dropped_unaligned"]} == EXPECT_R1,
             f"{len(a1['samples'])} samples {a1['per_source']}, {a1['dropped_gap']} gap, {a1['dropped_unaligned']} windows unused")
        row("check 4", "aggregatedSources: ONE participant and ONE update from the Trusted FL Client although two sources "
            "contribute; the weighting basis is logged and is the sample count",
            fl.ac4_aggregated({"client": TFC, "sources": 2, "profile": tfc1["profile"], "tasks": r1["tasks"],
                               "updates": r1["uploads"], "round": rec}),
            f"weights {[(a['participantId'], a['n']) for a in rec['accepted']]} by {rec['weightingBasis']}")
        S["old_update"] = next(u for u in r1["uploads"] if u["participantId"] == "P-TFC-AGG")

        def weights_row(R):
            got = {a["participantId"]: a["n"] for a in R["record"]["accepted"]}
            step(f"round {R['round']}: the weights are the sample counts counted " + ("a second way in the capture file" if DEV else "by hand"), got == EXPECT_N[R["round"]], str(got))
        weights_row(r1)
        d1 = deploy(S, 1)
        v1, _, _ = view(S)
        step("delivery: the target checked package v1 against the digest the aggregator published, activated it and echoed "
             "version and digest", d1["activation"]["verdict"] == "activated" and v1["active"] == 1
             and d1["activation"]["modelDigest"] == S["published"][1],
             f"active version {v1['active']}; echo {str(d1['activation']['modelDigest'])[:16]}")

        print("== round 2, independentSources; flNat drops out; a round-1 update is sent again [check 5]")
        require(f"{posted_by()} (the next 9 slots)", post_chunk(S, CHUNK, 2 * CHUNK) == 0)
        r2 = run_round(S, 2, "independentSources", dropout=("P-NAT",), replay=True)
        rec = r2["record"]
        S["models"][2], S["parents"][2] = rec["w_out"], rec["modelInDigest"]
        step("round 2 completed and its record recomputes", rec["state"] == "COMPLETED" and r2["verify"] == [],
             f"{rec['state']}, checker: {r2['verify'] or 'no objection'}; w {rec['w_in']} -> {rec['w_out']}; held-out error "
             f"{r2.get('loss_before')} -> {r2.get('loss_after')} (recorded, not a pass condition)")
        mine = [c for c in r2["clients"] if c["participantId"].startswith("P-TFC")]
        row("check 5", "independentSources: one client AE, two participants with separate task, dataset and update identities "
            "(separate identities, not a claim of statistical independence)",
            fl.ac5_independent({"client": TFC, "tasks": [t for t in r2["tasks"] if t["selectedClient"] == TFC],
                                "profiles": [c["profile"] for c in mine],
                                "updates": [u for u in r2["uploads"] if u["clientAERef"] == TFC]}),
            ", ".join(f"{t['taskId']}" for t in r2["tasks"] if t["selectedClient"] == TFC))
        row("FL_02 step 10", "with one client dropping out the round still completed at the stated rate, and the straggler is "
            "left out and logged", fl.fl02_10_completion({"round": rec}),
            f"accepted {rec['quorum']['accepted']} of {rec['quorum']['selected']}; missing {rec['missing']}")
        step("the client that dropped out posted nothing, and still received the new model",
             rec["missing"] == [{"participantId": "P-NAT", "reasons": ["no-update-by-deadline"]}]
             and r2["reads_after"].get("flNat", {}).get("status") == 200, f"flNat read v2: {r2['reads_after'].get('flNat')}")
        rep = [e for e in rec["excluded"] if e["updateDigest"] == r2["replayed"]["updateDigest"]]
        step("the round-1 update that was sent again is excluded with its reasons", r2["replayed"]["status"] == 201 and len(rep) == 1
             and {"wrong-round", "stale-model", "replay"} <= set(rep[0]["reasons"]), f"created {r2['replayed']['status']}; {rep}")
        step("CONTROL (must FAIL) a replayed update (an earlier round's update sent again) was accepted",
             r2["replayed"]["updateDigest"] in [a["updateDigest"] for a in rec["accepted"]], f"excluded: {[e['reasons'] for e in rep]}")
        weights_row(r2)
        v2, pub, acts = view(S)
        row("deployment", "version 2 is aggregated and redistributed but not deployed: the active version is still 1",
            fl.gov_deploy({"published": pub, "activations": acts, "expect_active": 1, "not_active": [2],
                           "target_reports": S["target_active"]}),
            f"aggregated {v2['aggregated']}, undeployed {v2['undeployed']}, active {v2['active']}")
        step("CONTROL (must FAIL) a model version that was aggregated but not deployed shows as active", v2["active"] == 2
             or S["target_active"] == 2, f"active {v2['active']}, the target reports {S['target_active']}")
        dbad = deploy(S, 2, tamper=True)
        v2b, _, _ = view(S)
        row("package", "the target refused a package whose content does not hash to its stated digest; the active version did not move",
            fl.gov_package({"reasons": dbad["reasons"], "target_verdict": dbad["activation"]["verdict"], "active_before": v2["active"],
                            "active_after": v2b["active"]}), f"{dbad['reasons']}; active {v2b['active']}")
        step("CONTROL (must FAIL) a model package whose digest does not match was activated",
             dbad["activation"]["verdict"] == "activated" or v2b["active"] == 2,
             f"verdict {dbad['activation']['verdict']}, active {v2b['active']}")

        print("== round 3, independentSources; flSrc2 is revoked while its update is pending [check 6]")
        require(f"{posted_by()} (the next 9 slots)", post_chunk(S, 2 * CHUNK, 3 * CHUNK) == 0)
        r3 = run_round(S, 3, "independentSources", revoke="flSrc2")
        rec, rv = r3["record"], r3["revocation"]
        S["models"][3], S["parents"][3] = rec["w_out"], rec["modelInDigest"]
        step("round 3 completed and its record recomputes", rec["state"] == "COMPLETED" and r3["verify"] == [],
             f"{rec['state']}, checker: {r3['verify'] or 'no objection'}; w {rec['w_in']} -> {rec['w_out']}; held-out error "
             f"{r3.get('loss_before')} -> {r3.get('loss_after')} (recorded, not a pass condition)")
        ds_now = [d for d in records("flTfc", "flMeta", ORCH, "dataset") if (d["datasetId"], d["datasetVersion"]) == ("ds-s2", "3")]
        row("check 6", "after the revocation the CSE denies the client's read, the dataset is marked invalid and the pending "
            "update is excluded", fl.ac6_revocation({
                "read_before": rv["read_before"], "read_after": rv["read_after"], "affected": rv["affected"],
                "policy_state": read_policies(AGG)["flSrc2"]["record"]["revocationStatus"],
                "dataset_state": ds_now[-1]["datasetLifecycleState"] if ds_now else None, "excluded": rec["excluded"],
                "accepted": [a["participantId"] for a in rec["accepted"]]}),
            f"policy {rv['policy_version']} by {AUTH['flSrc2']} (HTTP {rv['policy']}), readers cleared (HTTP {rv['acp']}); read "
            f"{rv['read_before']} -> {rv['read_after']}; excluded {[(e['participantId'], e['reasons']) for e in rec['excluded']]}")
        step("CONTROL (must FAIL) an update from a revoked source was accepted",
             rv["affected"] in [a["participantId"] for a in rec["accepted"]], f"accepted {[a['participantId'] for a in rec['accepted']]}")
        weights_row(r3)
        d3 = deploy(S, 3)
        v3, _, _ = view(S)
        step("delivery: model version before -> deployment status -> active version after", d3["activation"]["previousVersion"] == 1
             and d3["activation"]["verdict"] == "activated" and v3["active"] == 3 and v3["undeployed"] == [2],
             f"{d3['activation']['previousVersion']} -> {d3['activation']['verdict']} -> {v3['active']}; never deployed: "
             f"{v3['undeployed']}")

        print("== round 4, a control round: one update outside the bound, so the round is below quorum")
        r4 = run_round(S, 4, "independentSources", poison=("P-TFC-S1",))
        rec = r4["record"]
        step("the revoked source's participant is not selected any more, for the policy's reason",
             r4["selection"]["rejected"].get("P-TFC-S2") == ["not-authorized"], str(r4["selection"]["rejected"]))
        bad_u = [e for e in rec["excluded"] if e["participantId"] == "P-TFC-S1"]
        step("the update outside the bound is excluded with its reason", len(bad_u) == 1 and bad_u[0]["reasons"] == ["out-of-bound"],
             f"bound {fl.UPDATE_BOUND} per weight; {bad_u}")
        step("CONTROL (must FAIL) a poisoned update (outside the stated bound) was accepted",
             "P-TFC-S1" in [a["participantId"] for a in rec["accepted"]], f"accepted {[a['participantId'] for a in rec['accepted']]}")
        row("quorum", "a round below quorum says so and publishes no model", fl.gov_quorum(
            {"round": rec, "versions_before": r4["versions_before"], "versions_after": r4["versions_after"]}),
            f"accepted {rec['quorum']['accepted']} of {rec['quorum']['selected']}, needed {rec['quorum']['needed']}: {rec['state']}; "
            f"versions at the aggregator {r4['versions_after']}")
        step("CONTROL (must FAIL) a round below quorum still published a model", rec["w_out"] is not None
             or r4["versions_after"] != r4["versions_before"] or S["version"] != 3 or "redistributed" in r4,
             f"global model still v{S['version']}; aggregator holds {r4['versions_after']}")
        weights_row(r4)

        print("== the Trusted FL Client moved to a host of another operator [check 7]")
        made["flTfc2"] = make_ae("flTfc2")
        S["made"].append("flTfc2")
        post("flTfc2", "flMeta", TFC2, {"kind": "tfc-profile", "represents": ["flSrc1"], "record": fl.tfc_profile(
            TFC2, version="2", host="edge-b-host (this PC)", cse=PLACE["flTfc2"], operator="lab-operator-B", domain="edge-b",
            capability_ref="none", max_sources=1, coordinator=coordinator_ref(), operations=[OP], state="awaitingAuthorization")})
        pol_old = read_policies(ORCH)
        rb, _ = rq("GET", url("flSrc1", "env", "la"), TFC2, why="the moved client's read before a fresh authorisation")
        bind_b = decide(pol_old, ["flSrc1"], processor=TFC2, domain="edge-b")
        fresh = str(int(pol_old["flSrc1"]["record"]["policyVersion"]) + 1)
        st_f = issue_policy("flSrc1", fresh, processors=[TFC, TFC2], domains=["edge-a", "edge-b"])
        st_g = set_readers("flSrc1", [TFC, TFC2])
        ra, _ = rq("GET", url("flSrc1", "env", "la"), TFC2, why="the moved client's read after it")
        row("check 7", "at the other operator's host the client is blocked (the CSE denies the read and the old policy does not "
            "cover it) until the source's authority approves a fresh policy version",
            fl.ac7_relocation({"read_before": rb, "binding_before": bind_b,
                               "old_policy_version": pol_old["flSrc1"]["record"]["policyVersion"], "fresh_policy_version": fresh,
                               "binding_after": decide(read_policies(ORCH), ["flSrc1"], processor=TFC2, domain="edge-b"),
                               "read_after": ra}),
            f"flTfc2 registered on {PLACE['flTfc2']} (HTTP {made['flTfc2']['ae']}): registration alone opened nothing; read {rb}, "
            f"{bind_b['refusals']}; policy {fresh} (HTTP {st_f}, readers {st_g}); read {ra}. The move is simulated: a second AE, "
            "no process moved")

        print("== retention [check 8]")
        from_revoked = [(R["round"], a["participantId"]) for R in S["rounds"] for a in R["record"]["accepted"]
                        if R["record"]["w_out"] is not None and a["participantId"] in ("P-TFC-AGG", "P-TFC-S2")]
        irreversible = [{"what": f"model v{n} (round {n}) and every version built on it",
                         "why": f"it is a weighted average that includes the update of {pid}, trained on flSrc2's data before the "
                                "revocation; an average cannot be separated into its contributions"} for n, pid in from_revoked]
        irreversible += [{"what": "the update records of those rounds at the aggregator and the published dataset records "
                                  "(digests, counts, provenance digests)",
                          "why": "kept as the lineage a checker needs to recompute the aggregates; they hold weight changes and "
                                 "digests, no observation, and the run's cleanup removes them from the CSEs with everything else"},
                         {"what": "copies outside this run's reach", "why": "none were made by this run; a client that kept its own "
                                  "copy offline could not be made to delete it (TR 7.3.5.8.4 as reported, fact F32)"}]
        X["retention"] = {"temp_copies": S["temp"], "accepted_from_revoked": len(from_revoked), "irreversible": irreversible}
        row("check 8", "every temporary copy the Trusted FL Client made is deleted and gone on read-back; what cannot be deleted "
            "or reversed is listed", fl.ac8_retention(X["retention"]),
            f"{len(S['temp'])} temporary copies, read-back {sorted({t.get('readback') for t in S['temp']})}; {len(irreversible)} "
            f"entries that cannot be undone, {len(from_revoked)} of them accepted contributions of the revoked source")

        print("== at the end: observations, KPI block")
        cen = central()
        row("FL_02 step 5", "after all four rounds: still no observation at the centre, at the aggregator or in what the "
            "orchestrator received", fl.fl02_5_raw_stays({"central_payloads": [cen, ORCH_SEEN], "orch_raw_read": rq(
                "GET", url("flSrc2", "env", "la"), ORCH, why="the orchestrator's read at the end")[0]}),
            f"scanned {len(cen)} contentInstances and {len(ORCH_SEEN)} answers")
        three, allr = S["rounds"][:3], S["rounds"]
        count = lambda rs, k: sum(len(R["record"][k]) for R in rs)  # noqa: E731
        mb = sum(R["bytes"] for R in three)
        f3 = fl03_block(MODE, CALLS, NOTIFY_LOG, [R["round"] for R in allr])
        X["kpi"] = {
            "sim": True, "scope": "rounds 1 to 3; the control round is given separately; every source is simulated",
            "rates": {
                "participant_success_rate": fl.kpi_rate(count(three, "accepted"), count(three, "selected")),
                "participant_success_rate_with_control_round": fl.kpi_rate(count(allr, "accepted"), count(allr, "selected")),
                "round_completion_rate": fl.kpi_rate(sum(R["record"]["state"] == "COMPLETED" for R in three), len(three)),
                "round_completion_rate_with_control_round": fl.kpi_rate(sum(R["record"]["state"] == "COMPLETED" for R in allr), len(allr)),
                "update_exclusion_rate": fl.kpi_rate(count(three, "excluded"), count(three, "excluded") + count(three, "accepted")),
                "invitation_acceptance_rate": fl.kpi_rate(X["accepted_invitations"], X["invited"]),
                "ae_registration_success_rate": fl.kpi_rate(sum(m["ae"] == 201 for m in made.values()), len(made))},
            **kpi_rounds(three, f3),
            "held_out_error": {"values": [R.get("loss_after") for R in three], "N": len(three), "unit": "tenths of a degree C, summed "
                               f"over {len(S['held'])} simulated samples", "before_round_1": three[0].get("loss_before")}}
        s1, s2 = FL03_STEPS[MODE]
        print(f"== TD_MEC_FL_03 steps {s1} and {s2}: {MODE} mode")
        for label, ok, detail in fl03_steps(f3):
            step(label, ok, detail)
        off = kpi_vs_fl03(X["kpi"], f3)
        step("the KPI block's round times and edge-cloud bytes (run_round's counts) are the FL_03 block's (fl03_block's, "
             "from the whole log), round by round", not off, "; ".join(off) or f"rounds 1-3: {X['kpi']['edge_cloud_bytes']['values']} "
             f"bytes, {X['kpi']['fl_round_completion_time_s']['values']} s, on both paths")
        whole = f3["all_calls"]
        unanswered = [c for c in CALLS if not c["status"]]
        step("the byte counter saw every call whole: each request that went out is longer than its body (headers are "
             "in), each answer that came is not empty",
             all(c["sent"] > c["body"] for c in CALLS if c["status"] or c["sent"])
             and all(c["received"] > 0 for c in CALLS if c["status"]),
             f"{whole['n']} calls, {whole['bytes']} bytes; {f3['notifications']['n']} notifications, {f3['notifications']['bytes']} "
             f"bytes; {len(unanswered)} calls got no answer (a refused connection counts 0 bytes): "
             f"{sum(c['sent'] + c['received'] for c in unanswered)} bytes")
        step("the bytes per CSE add up to the bytes of all calls and notifications (none counted twice)",
             sum(v["bytes"] for v in f3["bytes_per_cse"].values()) == whole["bytes"]
             and sum(v["notification_bytes"] for v in f3["bytes_per_cse"].values()) == f3["notifications"]["bytes"],
             ", ".join(f"{k} {v['bytes'] + v['notification_bytes']}" for k, v in f3["bytes_per_cse"].items()))
        row("TD_MEC_OBS_01 step 4", "the KPI block has round completion time, participant success rate and edge-cloud bytes, "
            "every rate with numerator, denominator and N", fl.kpi_ok(X["kpi"]),
            "; ".join(f"{k} {v['numerator']}/{v['denominator']} = {v['value']} % (N {v['N']})" for k, v in X["kpi"]["rates"].items())
            + f"; round times {X['kpi']['fl_round_completion_time_s']['values']} s; {mb} bytes")

        not_run(fl.NOT_RUN_SIGNATURE, "no key material is created, stored or read by this code; binding is by digests, the "
                "CSE-recorded creator and access control policies")
        not_run("TD_MEC_FL_01 pre-condition: at least one FL-native, one constrained and one MEC-native DEVICE available",
                "the three classes are represented by simulated devices (flNat; flSrc1 and flSrc2; devPx1); the seven steps "
                "ran on them, so TD_MEC_FL_01 is PARTIAL (fl01.verdict), and so is TD_MEC_FL_02's pre-condition")
        not_run("TD_MEC_REG_01 and TD_MEC_REG_02 (TD_MEC_REG_03's own pre-conditions)",
                "; ".join(f"{k}: {v}" for k, v in REG_PRE.items()))
        not_run("TD_MEC_FL_03: comparison of deployment modes (step 9)",
                f"this run is one mode, {MODE} (orchestrator on {PLACE['flOrch']}, aggregator on {PLACE['flAgg']}); the "
                "three are compared in the record --compare writes")
        for nr in FL03_NOT_RUN:
            not_run(nr["row"], nr["reason"])
        not_run("any row with a real device", "every source is simulated; whether a simulated device meets TD_MEC_FL_01 is an "
                "open question to the organisers")
        not_run("a gate against a wrong update inside the bound", "not built; the bound stops a gross outlier and nothing subtler")
        not_run("recompute of a client's update from its dataset by a second implementation",
                "not built; the aggregate is recomputed, a client's own training step is not")
    except Abort as e:
        aborted = str(e)
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        step("run completed without an exception", False, repr(e))
        aborted = f"exception: {e!r}"
    finally:
        C = S["cleanup"]
        for ae in S["subs"]:
            C[f"sub flSub-{ae}"] = rq("DELETE", url("flOrch", "tasks", f"flSub-{ae}"), ORCH, why="cleanup")[0]
        for ae in reversed(S["made"]):
            C[ae] = rq("DELETE", url(ae), OWNER[ae], why="cleanup: the AE and everything under it")[0]
        if FL1.get("stray") is not None and strays_left():     # by what the CSE and MEC 011 show, not by the record
            C["strays"] = remove_strays(FL1["stray"])
            C["strays_left_after"] = strays_left()
        if plat is not None:
            print("== cleanup: each app is told to stop through MEC 010-2 and must leave in order [TD_MEC_FL_01]")
            for key, ae in (("fl_proxy", "flProxy"), ("fl_tfc", "flTfc"), ("fl_orch", "flOrch")):
                D = plat.deployed.get(key) or {}
                origin = FL01_APPS[key]["origin"]
                out = plat.stop(key) if D else {"after": {}, "records": {}}
                where_ae = f"{CSE_URL[D['cse']]}/{ae}" if D.get("cse") in CSE_URL else url(ae) if ae in OWNER else FL01_URL[ae]
                ae_st = rq("GET", where_ae, ADMIN, why="cleanup check: the app's AE")[0]
                own_del = [r["rsc"] for r in out["records"].get(D.get("cse"), []) if r["method"] == "DELETE"
                           and r["headers"].get("x-m2m-origin") == origin and r["path"] == f"/{D.get('cse')}/{ae}"]
                term, aft = out.get("terminate") or {}, out["after"]
                C[f"app {key}"] = {"terminate": term, "own_ae_delete_rsc": own_del, "ae_after": ae_st, "after": aft,
                                   "error": out.get("error")}
                step(f"[cleanup] {key}: told to stop through MEC 010-2, the app left in order: exit 0, it deleted its own AE "
                     "(gone), MEC 011 neither lists nor holds it, its process is gone, and MEC 010-2 holds neither its "
                     "instance nor its package",
                     bool(D) and D.get("error") is None and (term.get("exitCode"), term.get("forced")) == (0, False)
                     and own_del == [2002] and ae_st == 404 and aft.get("listed") is False and aft.get("registered") is False
                     and aft.get("process") is False and (aft.get("instance_status"), aft.get("package_status")) == (404, 404)
                     and out.get("error") is None,
                     f"{'not deployed' if not D else ''} exit {term.get('exitCode')} forced {term.get('forced')}; own AE "
                     f"delete rsc {own_del}; AE now {ae_st}; after {aft}; {out.get('error') or ''}")
                if ae_st == 200:            # the app did not take its AE with it: removed under its own originator
                    C[f"{ae} removed by the driver, its app did not"] = rq("DELETE", where_ae, origin, why="cleanup",
                                                                          harness=True)[0]
            FL1["relay_requests"] = {k: len(r.seen) for k, r in plat.relays.items()}
            left_p = plat.close()
            C["platform_left"] = {k: v for k, v in left_p.items() if v}
            step("[cleanup] nothing of the platform is left: no workload process, no instance or package at the agent, "
                 "the agent's work folder removed", not C["platform_left"], str(left_p))
        C["left_on_the_CSEs"] = [ae if u == url(ae) else f"{ae} on {where(u)[0]}" for ae, u in spots()
                                 if rq("GET", u, ADMIN, why="cleanup check")[0] != 404]
        C["left_on_the_CSEs"] += [ae for ae, u in FL01_URL.items() if rq("GET", u, ADMIN, why="cleanup check")[0] != 404]
        C["mec011_process"] = stop_proc(mec_proc)
        C["mec010_process"] = stop_proc(mec010_proc)
        if work.exists():
            C["platform_logs_tail"] = {p.name: p.read_bytes()[-400:].decode(errors="replace")
                                       for p in sorted((work / "logs").glob("*.log"))} if aborted else {}
            shutil.rmtree(work, ignore_errors=True)
        C["work_folder_removed"] = not work.exists()
        if srv is not None:
            srv.shutdown()
            srv.server_close()
    return 0 if finish(results, S, aborted) else 1


def compare() -> int:
    """--compare: the three modes one after another, each as its own process (`--mode <m> --out <file>`), each a
    full run that cleans up after itself; then one comparison record. Exit 0 only when TD_MEC_FL_03 comes out
    PARTIAL (all three runs passed); it cannot come out higher."""
    stamp, runs = time.strftime('%Y%m%dT%H%M%S'), []
    for m in MODES:
        out = RESULTS_DIR / f"fl_sim_{m}_{stamp}.json"
        print(f"\n######## --compare: {m}", flush=True)
        rc = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--mode", m, "--out", str(out)]).returncode
        rec = json.loads(out.read_text()) if out.exists() else {}
        runs.append({"mode": m, "exit": rc, "verdict": rec.get("verdict", "FAIL"), "file": str(out) if out.exists() else None,
                     "sha256": hashlib.sha256(out.read_bytes()).hexdigest() if out.exists() else None, "fl03": rec.get("fl03")})
    record = fl03_compare_record(runs)
    table, refused, verdict = record["table"], record["table_refused"], record["verdict"]
    run = run_record()
    run.pop("mec", None)
    for f in RUN_FILES_FL:
        run["files_sha256"][f] = hashlib.sha256((HERE.parent / f).read_bytes()).hexdigest()
    path = RESULTS_DIR / f"fl03_compare_{stamp}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({**record, "run": run}, indent=1, default=str))
    print(f"\n== TD_MEC_FL_03 comparison ({verdict}; every source simulated; bytes counted at the client on one PC)")
    if refused:
        print(f"  no table: {refused}")
    w = max(len(c) for c in FL03_COLUMNS)
    for c in FL03_COLUMNS:
        print(f"  {c:<{w}}  " + "  |  ".join(str(r[c]) for r in table["rows"]))
    print(f"  results: {path}")
    return 0 if verdict == "PARTIAL" else 1


def fl03_compare_record(runs: list[dict]) -> dict:
    """The comparison record --compare writes, without its 'run' part (the command, commit and file hashes):
    runs as compare() collects them ({mode, exit, verdict, file, sha256, fl03}). A table that cannot be built
    (a mode missing or twice, a block of another mode) gives no table, FAIL, and the reason."""
    try:
        table, refused = fl03_compare(runs), None
    except ValueError as e:     # e.g. a run whose block is of another mode: no table, and the record says why
        table, refused = {"columns": list(FL03_COLUMNS), "rows": []}, str(e)
    return {
        "record": "estimed.fl.fl03-compare.v1", "td": "TD_MEC_FL_03", "sim": True,
        "device": "none: every source is simulated", "verdict": "FAIL" if refused else fl03_verdict(table),
        "table_refused": refused,
        "verdict_scope": "PARTIAL at most: steps 1 to 6 and 9 ran on simulated sources on one PC; steps 7 and 8 are "
                         "NOT-RUN. FAIL when one of the three runs did not pass or left a cell of the table empty.",
        "steps": {"1-2": "the centralised run", "3-4": "the hierarchical run", "5-6": "the edge-only run",
                  "7-8": "NOT-RUN (not_run)", "9": "this table"},
        "table": table, "runs": [{k: r.get(k) for k in ("mode", "exit", "verdict", "file", "sha256")} for r in runs],
        "placement": {m: placement(m) for m in MODES}, "sides": SIDE, "definitions": FL03_DEFINITIONS,
        "not_run": FL03_NOT_RUN, "not_shown": list(FL03_NOT_SHOWN)}


def fl01_block(F: dict) -> dict:
    """The record's TD_MEC_FL_01 part: the steps and their verdict, the platform code by pin, what each app was
    deployed as and sent, the device's records, the enumeration; what it does not show."""
    steps, pre = F.get("steps") or {}, F.get("pre_condition") or {}
    first = FL01_STEPS[0]
    return {"td": "TD_MEC_FL_01", "verdict": fl01_verdict(steps),
            "verdict_scope": "PARTIAL at most: the pre-condition and the seven steps ran with simulated devices of the "
                             "three classes, on one host; FAIL when one of them did not pass or did not run. In centralised "
                             "and hierarchical mode the pre-condition is REG_03's procedure on cse-in, not REG_03 as worded "
                             "(steps and pre_condition say which)",
            "steps": {k: (reg03_scope(pre.get("orchestrator_cse"), steps.get(k) if k in steps else None) if k == first
                          else "PASS" if steps.get(k) else "FAIL" if k in steps else "NOT-RUN") for k in FL01_STEPS},
            "pre_condition": pre or {"holds": "NOT-RUN", **REG_PRE},
            "platform": {"code": mp.provenance(), "mec010": MEC010, "mec011": MEC011,
                         "note": "loaded from the main tree by path; refused unless each file hashes to its pin"},
            "deployed": F.get("deployed"), "device": F.get("device"), "enumeration": F.get("enumeration"),
            "expected_classes": FL01_EXPECT, "stray_fixture": F.get("stray"), "stray_removed": F.get("stray_removed"),
            "relay_requests": F.get("relay_requests"),
            "class_wording": fl.CLASS_WORDING, "not_shown": list(FL01_NOT_SHOWN)}


def finish(path: Path, S: dict, aborted: str | None) -> bool:
    """Verdict and results file, by the neighbours' rule (estimed_poc2.finish): PASS needs the run to reach its end,
    every step to pass and every control (at least one) to fail as it must. NOT-RUN rows are neither."""
    ctl = [(s_, o) for s_, o, _ in STEPS if s_.startswith("CONTROL")]
    real = [(s_, o) for s_, o, _ in STEPS if not s_.startswith("CONTROL")]
    ok = sum(1 for _, o in real if o)
    clean = (not S["cleanup"].get("left_on_the_CSEs") and not S["cleanup"].get("platform_left")
             and S["cleanup"].get("work_folder_removed", True))
    good = aborted is None and ok == len(real) and bool(ctl) and not any(o for _, o in ctl) and clean
    print(f"\n  RESULT: {'PASS' if good else 'FAIL'}  ({ok}/{len(real)} steps; controls {len(ctl)}, all failed as they must: "
          f"{bool(ctl) and not any(o for _, o in ctl)}; NOT-RUN {len(NOT_RUN)}; cleanup complete: {clean}; "
          + ("SIMULATED sources" if not DEV else f"sources: {DEV['origin']} capture behind a host bridge; every other party simulated") + ")"
          + (f"; STOPPED after: {aborted}" if aborted else ""))
    f3 = fl03_block(MODE, CALLS, NOTIFY_LOG, [R["round"] for R in S["rounds"]])
    print(f"  FL_03 {MODE}: round times {f3['round_time']['values_s']} s, median {f3['round_time']['median_s']}; edge-cloud "
          f"bytes per round {f3['edge_cloud_bytes']['per_round']}, whole run {f3['edge_cloud_bytes']['whole_run']['total']} "
          "(counted at the client, one PC)")
    run = run_record()
    run.pop("mec", None)        # the phone drivers' MEC addresses; this run uses none of them
    for f in RUN_FILES_FL:
        run["files_sha256"][f] = hashlib.sha256((HERE.parent / f).read_bytes()).hexdigest()
    exe = Path(sys.executable).resolve()
    run["python"] = {"version": sys.version.split()[0], "executable": str(exe), "sha256": hashlib.sha256(exe.read_bytes()).hexdigest()}
    X = S["extra"]
    strip = lambda R: {k: v for k, v in R.items() if k not in ("clients", "uploads", "tasks")} | {  # noqa: E731
        "clients": [{k: v for k, v in c.items() if k not in ("assembled", "provenance")} for c in R["clients"]],
        "uploads": [{k: v for k, v in u.items() if k != "con"} for u in R["uploads"]],
        "task_ids": [t["taskId"] for t in R["tasks"]]}
    path.parent.mkdir(parents=True, exist_ok=True)
    head = {"record": "estimed.fl.sim-run.v1", "device": "none: every source is simulated", "sim": True,
            "verdict_scope": "the rows that ran, on simulated sources; see not_run and not_shown. TD_MEC_FL_01: fl01.verdict "
                             "(PARTIAL at most: every device is simulated).",
            "preregistration": {"sha256": None, "go_phrase": None, "result": "NA",
                                "reason": "a host-only run with simulated sources; no preregistration was frozen for it"}}
    if DEV:
        real = DEV["origin"] == "device"
        head = {"record": "estimed.fl.dev-run.v1" if real else "estimed.fl.rehearsal-run.v1",
                "device": ("phone-A and phone-B: their captured env records, posted by a host bridge" if real else
                           "none: the two sources' records were made by the host in the probe app's shape (a rehearsal)"),
                "sim": False if real else True,
                "verdict_scope": "the rows that ran. The observations of flSrc1 and flSrc2 come from the capture file; a phone "
                                 "did not register, was not notified and did not train. Every other party is simulated. "
                                 "TD_MEC_FL_01: fl01.verdict (PARTIAL at most).",
                "preregistration": ({**DEV["prereg"], "result": "given on the command line"} if real else
                                    {"sha256": None, "go_phrase": None, "result": "NA", "reason": "a rehearsal: no device took part"}),
                "sources_capture": {"file": DEV["file"], "sha256": DEV["file_sha256"], "origin": DEV["origin"],
                                    "made_at_utc": DEV["made_at_utc"], "slot0": DEV["slot0"], "expect": DEV["expect"],
                                    "per_source": {s: {k: (len(v[k]) if isinstance(v[k], list) else v[k]) for k in (
                                        "label", "records", "refused", "dropped_same_slot", "outside_the_window", "digest",
                                        "cse_time_minus_record_time_ms", "countersignature")}
                                        for s, v in DEV["sources"].items()}},
                "sim_flag_note": "\"sim\": true inside a record of this run says the party that wrote it is a thread of the "
                                 "driver; the phones' observations carry no such mark"}
    path.write_text(json.dumps({
        **head, "verdict": "PASS" if good else "FAIL", "aborted_at": aborted, "mode": MODE,
        "clock_offset": {"result": "NA", "reason": "every party is a thread of one process on one host; times are that host's "
                                                   "clock and the CSEs' creation times on the same host"},
        "device_labels": {ae: {"originator": OWNER[ae], "cse": HOME.get(ae, A).rsplit("/", 1)[1], "role": SPEC[ae]["role"],
                               "sim": True, "class": fl.CLASS_WORDING.get(SPEC[ae].get("cls"), "not a device")}
                          for ae in OWNER},
        "open_decisions": [
            "the model: a 3-weight integer (Q8) linear model on simulated battery telemetry was taken as the default; the "
            "proof-of-concept plan's traffic model is the alternative",
            "keys: none are created, stored or read; an update is bound by SHA-256 digests, the CSE-recorded creator and access "
            "control policies; signatures wait for the ruling on lab keys",
            ("sources: simulated; no real device took part" if not DEV else
             f"sources: flSrc1 and flSrc2 carry a {DEV['origin']} capture behind a host bridge; flNat, flDec and the held-out set are simulated"),
            f"thresholds of ours: quorum at least {fl.QUORUM_MIN} updates and {fl.QUORUM_RATE[0]}/{fl.QUORUM_RATE[1]} of the selected; "
            f"round window {ROUND_TIMEOUT_S} s; bound {fl.UPDATE_BOUND} per weight"],
        "kpi": X.get("kpi", {}), "fl03": f3, "fl01": fl01_block(X.get("fl01") or {}), "enforcement": list(fl.ENFORCEMENT), "retention": X.get("retention", {}),
        "steps": [{"step": s_, "pass": o, "detail": d} for s_, o, d in STEPS],
        "controls": [{"control": s_, "expected": "FAIL", "observed": "PASS" if o else "FAIL", "detail": d}
                     for s_, o, d in STEPS if s_.startswith("CONTROL")],
        "not_run": NOT_RUN,
        "not_shown": [
            ("a real device of any class: every source, client and target is simulated inside this driver's process" if not
             (DEV and DEV["origin"] == "device") else
             "a device taking part in a round: the phones produced the observations and nothing else; registration, policy, "
             "notification, training and upload are done by threads of this driver; every client and target is simulated"),
            "an authenticated originator: the lab CSEs take the X-M2M-Origin header as given, over plain HTTP on loopback, so "
            "'the CSE recorded this creator' holds between honest parties and binds nobody who lies about its originator",
            "a signature on an update, a policy, a package or this record",
            "separate machines or networks: 'edge', 'centre', 'domain A / B' and 'another operator's host' are resource trees "
            "and originator names on one PC; 'raw data does not leave' says which trees and originators hold observations",
            "that the simulated numbers resemble a device: they follow a fixed integer rule chosen in fl_core.sim_series",
            "model quality: the held-out set is simulated too, and a later round may not lower the held-out error",
            "protection against what an update or a digest gives away about the data it was made from",
            "removal of an accepted contribution from an aggregate (listed under retention as not reversible)",
            "a wrong update inside the bound being caught",
            "the TR's own wording checked by this run's author: the TR extract could not be opened in this session, so the "
            "eight checks and the attribute lists follow the fact reader's quotations in federation_result.json",
            "agreement with any test suite: this is a demonstration of mechanisms, not a conformance claim",
            *FL03_NOT_SHOWN, *FL01_NOT_SHOWN],
        "rounds": [strip(R) for R in S["rounds"]], "cleanup": S["cleanup"], "run": run,
        "raw": {"requests": _n, "mec011_requests": sum(c["url"].startswith(MEC011) for c in CALLS),
                "leftovers_removed_at_start": X.get("leftovers_removed"),
                "trace_format": "n originator operation target ty=type -> HTTP status, bytes sent + bytes received as "
                                "counted at the socket (fl03.definitions.bytes), 'edge-cloud' if counted as such | purpose; "
                                "'mec <party> ...' for a MEC 011 call",
                "trace": TRACE, "notifications": NOTIFY_LOG}},
        indent=1, default=str))
    print(f"  results: {path}")
    return good


if __name__ == "__main__":
    sys.exit(main())
