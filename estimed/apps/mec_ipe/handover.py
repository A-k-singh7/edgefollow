#!/usr/bin/env python3
"""ESTIMED Hackathon #2 -- oneM2M edge handover.

Step 4a of the prototype: move a vehicle's oneM2M subtree from one edge CSE to
another and prove nothing is lost. No MEC involvement yet, deliberately -- if this
fails, the fault is in the oneM2M half and nowhere else.

    IN-CSE   cse-in    :8200   durable record; both edges register here
    MN-CSE-A cse-mn-a  :8201   vehicle starts here
    MN-CSE-B cse-mn-b  :8202   vehicle ends here

The tree moved is what a vehicle actually produces:

    <AE vehicle01>
      └── <container telemetry>
            └── <contentInstance> ...      position samples

Every container under the AE moves (telemetry, a downlink `commands` container, ...),
with its access policies and subscriptions.

Only the standard library is used, so this runs under any interpreter.
"""
from __future__ import annotations

import json
import secrets
import sys
import time
import urllib.error
import urllib.request
from typing import Callable, Protocol

IN_CSE = ("http://127.0.0.1:8200", "cse-in")
EDGE_A = ("http://127.0.0.1:8201", "cse-mn-a")
EDGE_B = ("http://127.0.0.1:8202", "cse-mn-b")

AE_NAME = "vehicle01"
AE_ORIGIN = "Cvehicle01"
CONTAINER = "telemetry"

# The AE is announced to the IN-CSE so the IN always holds one entry routing the
# AE-ID to the serving MN-CSE (TR-0086 5.5.4 Step 5.3). The label carries the AE-ID
# so a consumer can find the serving edge by discovery at the IN.
IN_CSI = "/id-in"

# The orchestrator (TR-0086 5.5.4 Step 2: "the orchestrator or source MN-CSE") reads
# the vehicle's whole subtree. The vehicle's own identity is not enough: it cannot
# even discover a <subscription> a dashboard created on its telemetry, so a handover
# run as the vehicle silently left every third-party subscriber behind.
ORCHESTRATOR = "CAdmin"

# oneM2M resource types
TY_ACP, TY_AE, TY_CNT, TY_CIN, TY_SUB, TY_FCNT = 1, 2, 3, 4, 23, 28

# What the handover carries under each kind of parent. Anything else found there -- a <group>, a
# <pollingChannel>, a nested <container>, the <flexContainerInstance> history of a versioned
# flexContainer -- stops the handover before it touches anything; it was once left behind silently.
CARRIED = {"ae": {TY_ACP, TY_CNT, TY_SUB, TY_FCNT}, "cnt": {TY_CIN, TY_SUB}, "fcnt": {TY_SUB, TY_FCNT}}

# <subscription> attributes a consumer set and the target must reproduce. Everything
# else (ri, ct, cr, ...) is assigned by the CSE that hosts the copy.
SUB_COPY = ("rn", "nu", "enc", "exc", "nct", "su", "ln", "lbl")
ACP_COPY = ("rn", "pv", "pvs", "lbl")
CNT_COPY = ("mni", "mbs", "mia", "lbl")
# A <flexContainer>'s attributes are its specialization's (TS-0023 cod:*, ETSI's mec:*), so it is copied
# whole except what the hosting CSE assigns; acpi is remapped like a container's.
FCNT_ASSIGNED = ("ri", "pi", "ty", "ct", "lt", "st", "et", "cs", "cr", "cni", "cbs", "acpi")
# <AE> attributes the device set. Without its poa the target cannot deliver downlink
# notifications to the device at all (TD_MEC_HO_02).
# rr is the device's own choice (a device that polls registers with rr = false) and is carried like the rest.
AE_COPY = ("api", "srv", "poa", "apn", "rr")

# How long a handover may hold the transaction lock at the IN-CSE before the CSE drops it (TR-0077 v0.4.0
# 7.2.4.4: "a handover transaction identifier" and "the validity time of the registration-point-change request").
TXN_VALIDITY_S = 120.0

# How long a handover waits for the IN-CSE to route the AE-ID to the target (the target's announced AE, TR-0086 5.5.4
# Step 5.3) before it gives up and rolls back, and how often it reads the route meanwhile. Both lab CSEs announce
# inside the CREATE (ACME in AnnounceableResource.activate; tinyIoT forwards the <aeA> before it answers): measured on
# the lab 2026-11-21, 60 of 60 AE CREATEs were routed and 60 of 60 DELETEs unrouted at the FIRST read of the IN after
# the answer, and so were 10 of 10 handovers. A CREATE took at most 22 ms and that read at most 8 ms (a review the same
# night measured CREATE + read at 21.5 ms at most). The bound is about 60 times CREATE + read, for a CSE that announces
# later. A target that answered 201 and announced nothing (tinyIoT after a restart, 2026-11-21) once made a move
# report success with the IN routing the vehicle to no edge.
ROUTE_TIMEOUT_S = 2.0
ROUTE_POLL_S = 0.05

# handover(outcome=[...]) end states. NOT_MOVED: refused or rolled back, the source still serves the vehicle.
# INCONSISTENT: the source's release was sent, and the IN's route or the source's answer does not show the vehicle on
# the target alone; nothing is rolled back (the target may hold the only copy).
MOVED, NOT_MOVED, INCONSISTENT = "MOVED", "NOT_MOVED", "INCONSISTENT"

# The service a ready edge advertises in its MEC platform's Mp1 registry (TD_MEC_HO_06).
EDGE_SERVICE = "onem2m-mn-cse"

_ri = 0


class Unreadable(Exception):
    """A read the handover depends on was refused or failed. The handover stops, source kept: a shorter list or an
    empty attribute set here once made it copy a partial subtree, report success and delete the source, the only
    complete copy (deep check 2026-10-29)."""


class _Inconsistent(Exception):
    """Raised by _handover after the source's release when the move cannot be shown complete (see INCONSISTENT)."""


def _req(method: str, url: str, origin: str, *, ty: int | None = None,
         body: dict | None = None) -> tuple[int, dict | None]:
    """One oneM2M request. Returns (http status, parsed body or None)."""
    global _ri
    _ri += 1
    data = json.dumps(body).encode() if body is not None else None
    ct = f"application/json;ty={ty}" if ty else "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers={
        "X-M2M-Origin": origin,
        "X-M2M-RI": f"drv{_ri}",
        "X-M2M-RVI": "4",
        "Accept": "application/json",
        "Content-Type": ct,
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw) if raw else None
        except json.JSONDecodeError:
            return e.code, None


def create_ae(edge, name=AE_NAME, origin=AE_ORIGIN, **attrs):
    host, cb = edge
    return _req("POST", f"{host}/{cb}", origin, ty=TY_AE, body={
        "m2m:ae": {"rn": name, "api": "Nestimed.vehicle", "rr": True, "srv": ["4"], **attrs,
                   "lbl": [f"aei:{origin}"], "at": [IN_CSI], "aa": ["lbl"]}})


def read_ae(edge, ae=AE_NAME) -> dict:
    """The <AE> attributes the target must reproduce (AE_COPY)."""
    host, cb = edge
    st, body = _req("GET", f"{host}/{cb}/{ae}", ORCHESTRATOR)
    if st != 200 or not body:
        raise Unreadable(f"{cb}/{ae}: {st}")
    a = body.get("m2m:ae", {})
    return {k: a[k] for k in AE_COPY if k in a}


def set_reachability(edge, value: bool, ae=AE_NAME, origin=AE_ORIGIN):
    host, cb = edge
    return _req("PUT", f"{host}/{cb}/{ae}", origin, body={"m2m:ae": {"rr": value}})


def _children(edge, parent: str, ty: int, origin: str) -> list[dict]:
    """Direct children of one type, fully retrieved, as `origin` sees them."""
    host, cb = edge
    st, body = _req("GET", f"{host}/{cb}/{parent}?fu=1&ty={ty}&lvl=1", origin)
    if st != 200:
        raise Unreadable(f"{cb}/{parent} (discovery of ty={ty}): {st}")
    out = []
    for uri in (body or {}).get("m2m:uril", []):
        s, b = _req("GET", f"{host}/{uri}", origin)
        if s != 200 or not b:
            raise Unreadable(f"{uri}: {s}")
        out.append(next(iter(b.values())))
    return out


def read_containers(edge, ae=AE_NAME) -> list[tuple[str, dict, list[str]]]:
    """Every <container> under the AE: (rn, attributes to re-create, acpi)."""
    return sorted((c["rn"], {k: c[k] for k in CNT_COPY if k in c}, c.get("acpi", []))
                  for c in _children(edge, ae, TY_CNT, ORCHESTRATOR))


def read_subscriptions(edge, ae=AE_NAME, origin=AE_ORIGIN) -> list[tuple[str, dict, str]]:
    """Every <subscription> on the AE and on each of its containers: (parent, attributes, owner).

    Read as the orchestrator so third-party subscriptions are seen at all. The owner
    is the recorded creator (cr) when the subscriber asked for one; otherwise the AE
    if the AE itself can see the subscription (it made it), else the orchestrator.
    """
    found = []
    for parent in ([ae] + [f"{ae}/{rn}" for rn, _, _ in read_containers(edge, ae)]
                   + [f"{ae}/{path}" for path, _, _, _ in read_flexcontainers(edge, ae)]):
        own = {s["ri"] for s in _children(edge, parent, TY_SUB, origin)}
        for sub in _children(edge, parent, TY_SUB, ORCHESTRATOR):
            attrs = {k: sub[k] for k in SUB_COPY if k in sub}
            if sub.get("cr"):
                attrs["cr"] = None                     # ask the target to record the creator again
                owner = sub["cr"]
            else:
                owner = origin if sub["ri"] in own else ORCHESTRATOR
            found.append((parent, attrs, owner))
    return sorted(found, key=lambda p: (p[0], p[1]["rn"]))


def read_flexcontainers(edge, ae=AE_NAME) -> list[tuple[str, str, dict, list[str]]]:
    """Every <flexContainer> under the AE, nested ones too (TS-0023 devices hold their modules as children),
    parents first: (path under the AE, specialization such as "cod:bat", attributes to re-create, acpi)."""
    host, cb = edge
    found, todo = [], [""]
    while todo:
        rel = todo.pop(0)
        st, body = _req("GET", f"{host}/{cb}/{ae}{'/' + rel if rel else ''}?fu=1&ty={TY_FCNT}&lvl=1", ORCHESTRATOR)
        if st != 200:
            raise Unreadable(f"{cb}/{ae}/{rel} (discovery of flexContainers): {st}")
        for uri in (body or {}).get("m2m:uril", []):
            s, b = _req("GET", f"{host}/{uri}", ORCHESTRATOR)
            if s != 200 or not b:
                raise Unreadable(f"{uri}: {s}")
            key, f = next(iter(b.items()))
            path = f"{rel}/{f['rn']}" if rel else f["rn"]
            found.append((path, key, {k: v for k, v in f.items() if k not in FCNT_ASSIGNED}, f.get("acpi", [])))
            todo.append(path)
    return found


def _uncarried(edge, cnts, fcnts, ae=AE_NAME) -> list[str]:
    """Children in the vehicle's subtree the handover would not carry (see CARRIED), as resource paths.

    Each parent's whole child list is compared with what discovery by the carried types finds; a parent
    whose children cannot be listed counts as uncarried, so a failed read never passes as "nothing left".
    """
    host, cb = edge

    def kids(path, ty=None):
        st, body = _req("GET", f"{host}/{cb}/{path}?fu=1&lvl=1" + (f"&ty={ty}" if ty else ""), ORCHESTRATOR)
        return set(body.get("m2m:uril", [])) if st == 200 and body is not None else None

    left = []
    parents = ([(ae, CARRIED["ae"])] + [(f"{ae}/{rn}", CARRIED["cnt"]) for rn, _, _ in cnts]
               + [(f"{ae}/{path}", CARRIED["fcnt"]) for path, _, _, _ in fcnts])
    for path, types in parents:
        found = [kids(path)] + [kids(path, ty) for ty in sorted(types)]
        if any(f is None for f in found):
            left.append(f"{path} (children not listable)")
            continue
        left += sorted(found[0] - set().union(*found[1:]))
    return left


def _flex_matches(dst, want: list[tuple[str, str, dict, list[str]]]) -> bool:
    """dst holds exactly these flexContainers with these attributes (acpi is remapped, so not compared)."""
    have = sorted((p, k, a) for p, k, a, _ in read_flexcontainers(dst))
    if have != sorted((p, k, a) for p, k, a, _ in want):
        print("    ! destination flexContainers do not match source")
        return False
    return True


def _sync_flex(src, dst, fcnts) -> bool:
    """Bring every flexContainer on dst to src's state now: a device may update a module while it moves.

    Only changed (or removed) attributes are written, so nothing notifies for an update that did not happen.
    Written as the orchestrator: a module's own policy need not grant its device the right to update it.
    """
    now = read_flexcontainers(src)
    if sorted((p, k) for p, k, _, _ in now) != sorted((p, k) for p, k, _, _ in fcnts):
        print("    ! source flexContainers changed during the move")
        return False
    host, cb = dst
    on_dst = {p: a for p, _, a, _ in read_flexcontainers(dst)}
    for path, key, attrs, _ in now:
        cur = on_dst.get(path, {})
        upd = {k: v for k, v in attrs.items() if cur.get(k) != v and k not in ("rn", "cnd")}
        upd |= {k: None for k in cur.keys() - attrs.keys() if k not in ("rn", "cnd")}
        if upd:
            st, _ = _req("PUT", f"{host}/{cb}/{AE_NAME}/{path}", ORCHESTRATOR, body={key: upd})
            if st != 200:
                print(f"    ! flexContainer {path} not brought up to date on destination: {st}")
                return False
    return _flex_matches(dst, now)


def create_subscription(edge, parent: str, attrs: dict, origin=AE_ORIGIN):
    host, cb = edge
    return _req("POST", f"{host}/{cb}/{parent}", origin, ty=TY_SUB, body={"m2m:sub": attrs})


def read_acps(edge, ae=AE_NAME, origin=AE_ORIGIN) -> list[tuple[str, dict]]:
    """<accessControlPolicy> resources under the AE: (old ri, attributes to re-create)."""
    return [(a["ri"], {k: a[k] for k in ACP_COPY if k in a})
            for a in _children(edge, ae, TY_ACP, ORCHESTRATOR)]


def read_acpi(edge, path: str) -> list[str]:
    host, cb = edge
    st, body = _req("GET", f"{host}/{cb}/{path}", ORCHESTRATOR)
    if st != 200 or not body:
        raise Unreadable(f"{cb}/{path}: {st}")
    return next(iter(body.values())).get("acpi", [])


def create_container(edge, ae=AE_NAME, name=CONTAINER, origin=AE_ORIGIN, **attrs):
    host, cb = edge
    return _req("POST", f"{host}/{cb}/{ae}", origin, ty=TY_CNT,
                body={"m2m:cnt": {"rn": name, **attrs}})


def add_sample(edge, value: str, ae=AE_NAME, cnt=CONTAINER, origin=AE_ORIGIN,
               cnf: str | None = "text/plain:0"):
    host, cb = edge
    cin = {"con": value} | ({"cnf": cnf} if cnf else {})
    return _req("POST", f"{host}/{cb}/{ae}/{cnt}", origin, ty=TY_CIN, body={"m2m:cin": cin})


def read_samples(edge, ae=AE_NAME, cnt=CONTAINER, origin=AE_ORIGIN) -> list[str]:
    """Every contentInstance under the container, oldest first.

    Sorted here by creationTime, then stateTag: the discovery result's order is the
    CSE's choice. ACME lists oldest first, tinyIoT newest first, and relying on the
    former made an ACME -> tinyIoT handover fail on a correct copy.
    """
    return [c["con"] for c in _cins(edge, cnt, ae, origin, missing_ok=True)]


def _cins(edge, cnt=CONTAINER, ae=AE_NAME, origin=AE_ORIGIN, missing_ok=False) -> list[dict]:
    """Every <contentInstance> of one container, oldest first (see read_samples). An absent container is [] only
    when missing_ok; any other refusal raises Unreadable."""
    host, cb = edge
    st, body = _req("GET", f"{host}/{cb}/{ae}/{cnt}?fu=1&ty={TY_CIN}", origin)
    if st == 404 and missing_ok:
        return []
    if st != 200:
        raise Unreadable(f"{cb}/{ae}/{cnt} (discovery of contentInstances): {st}")
    found = []
    for uri in (body or {}).get("m2m:uril", []):
        s, b = _req("GET", f"{host}/{uri}", origin)
        if s != 200 or not b:
            raise Unreadable(f"{uri}: {s}")
        found.append(b["m2m:cin"])
    return sorted(found, key=_creation_order)


def _creation_order(cin: dict) -> tuple[str, int]:
    """Sort key: ct with its fraction padded (ACME gives 6 digits, tinyIoT 3), then st."""
    whole, _, frac = cin["ct"].partition(",")
    return f"{whole},{frac.ljust(9, '0')}", int(cin.get("st", 0))


def registered_edges() -> list[str]:
    """remoteCSE (ty=16) entries the IN-CSE holds."""
    host, cb = IN_CSE
    st, body = _req("GET", f"{host}/{cb}?fu=1&ty=16", "CAdmin")
    return body.get("m2m:uril", []) if st == 200 and body else []


def edges_ok(uril, want=("id-mn-a", "id-mn-b")) -> bool:
    """The IN holds exactly these edges -- not merely two entries (a lookalike CSE-ID passed len() == 2)."""
    return sorted(uril) == sorted(f"{IN_CSE[1]}/{c}" for c in want)


def registered_mn(dst) -> tuple[bool, str]:
    """TR-0086 5.2.4.7: a handover target is a middle node (cst 2) for which the IN holds a <remoteCSE>. An IN, an
    ASN, or an MN the IN does not know is never a target (lab-reliability batch, 2026-10-29)."""
    host, cb = dst
    st, body = _req("GET", f"{host}/{cb}", ORCHESTRATOR)
    c = (body or {}).get("m2m:cb", {}) if st == 200 else {}
    if c.get("cst") != 2 or not isinstance(c.get("csi"), str):
        return False, f"{cb} answered {st} with cst {c.get('cst')!r}, not a middle node (2)"
    st, body = _req("GET", f"{IN_CSE[0]}/{IN_CSE[1]}/{c['csi'].lstrip('/')}", ORCHESTRATOR)
    r = (body or {}).get("m2m:csr", {}) if st == 200 else {}
    if r.get("csi") != c["csi"] or r.get("cst") != 2:
        return False, f"the IN holds no <remoteCSE> for {c['csi']} ({st})"
    return True, c["csi"]


def _csi(edge) -> str:
    """The CSE-ID an edge states for itself. Unreadable is an error, not an empty answer."""
    host, cb = edge
    st, body = _req("GET", f"{host}/{cb}", ORCHESTRATOR)
    csi = ((body or {}).get("m2m:cb") or {}).get("csi") if st == 200 else None
    if not isinstance(csi, str) or not csi.strip("/"):
        raise Unreadable(f"{cb}: {st}, no CSE-ID")
    return "/" + csi.strip("/")


def serving_edges(origin=AE_ORIGIN) -> list[str]:
    """The CSE-IDs the IN-CSE routes this AE-ID to: the link of every announced AE that carries its label.

    Exactly one entry, the source, is the precondition of a handover (TR-0077 v0.4.0 7.2.4.2.3: "concurrent
    authoritative serving associations SHALL NOT exist"; 7.2.2.5 says nothing enforces it). A leftover registration
    on another edge was once taken for the serving one. Anything unreadable raises: no route is not "free to move".
    """
    host, cb = IN_CSE
    st, body = _req("GET", f"{host}/{cb}?fu=1&ty=10002&lbl=aei:{origin}", ORCHESTRATOR)
    if st != 200 or not isinstance(body, dict):
        raise Unreadable(f"{cb}: route of {origin}: {st}")
    edges = []
    for uri in body.get("m2m:uril", []):
        s, b = _req("GET", f"{host}/{uri}", ORCHESTRATOR)
        lnk = ((b or {}).get("m2m:aeA") or {}).get("lnk") if s == 200 else None
        if not isinstance(lnk, str) or not lnk.strip("/"):
            raise Unreadable(f"{uri}: {s}, no link")
        edges.append("/" + lnk.strip("/").split("/")[0])
    return sorted(edges)


def _wait_route(want: list[str]) -> list[str]:
    """Read the IN-CSE's route for the AE-ID until it is `want`, for up to ROUTE_TIMEOUT_S; the last route read."""
    end = time.monotonic() + ROUTE_TIMEOUT_S
    while (route := serving_edges()) != want and time.monotonic() < end:
        time.sleep(ROUTE_POLL_S)
    return route


def _routed_to_both(src_csi: str, dst_csi: str) -> bool:
    """DUAL_ATTACH at the IN: the AE-ID is routed to the source and to the target, and to no other edge."""
    want = sorted({src_csi, dst_csi})
    if (route := _wait_route(want)) == want:
        return True
    if dst_csi not in route:
        print(f"    ! the target did not announce the AE to the IN-CSE (it routes {AE_ORIGIN} to "
              f"{route or 'no edge'}); source kept")
    else:
        print(f"    ! the IN-CSE routes {AE_ORIGIN} to {route}, not to the source and the target alone; source kept")
    return False


def lock_name(origin=AE_ORIGIN) -> str:
    return f"ho-{origin}"


def _stamp(epoch: float) -> str:
    return time.strftime("%Y%m%dT%H%M%S", time.gmtime(epoch)) + ",000000"


def _until(labels) -> float | None:
    for lbl in labels if isinstance(labels, list) else []:
        if isinstance(lbl, str) and lbl.startswith("until:"):
            try:
                return float(lbl[6:])
            except ValueError:
                return None
    return None


def take_lock(src_csi: str, dst_csi: str, validity_s: float = TXN_VALIDITY_S, origin=AE_ORIGIN) -> str | None:
    """Open the handover transaction: one named resource at the IN-CSE, so a second handover of the same AE-ID
    meets a name that is taken. Returns the transaction identifier, or None when another handover holds it.

    The name is the lock (a CREATE of a taken name is refused by the CSE); the labels say who holds it and until
    when; `et` lets the CSE drop it if the orchestrator dies. A lock whose own `until` has passed is removed and
    taken once. Not closed: a CSE that neither honours `et` nor refuses a duplicate name gives no lock at all, and
    whoever may delete under the IN-CSE's base can remove one.
    """
    host, cb = IN_CSE
    for attempt in (0, 1):
        txn, until = secrets.token_hex(8), time.time() + validity_s
        st, _ = _req("POST", f"{host}/{cb}", ORCHESTRATOR, ty=TY_CNT, body={"m2m:cnt": {
            "rn": lock_name(origin), "et": _stamp(until),
            "lbl": [f"txn:{txn}", f"from:{src_csi}", f"to:{dst_csi}", f"until:{until:.0f}"]}})
        if st == 201:
            return txn
        if st != 409:
            raise Unreadable(f"{cb}/{lock_name(origin)}: lock create answered {st}")
        s, b = _req("GET", f"{host}/{cb}/{lock_name(origin)}", ORCHESTRATOR)
        held = ((b or {}).get("m2m:cnt") or {}).get("lbl") if s == 200 else None
        if s == 404:
            continue                                        # released between our two requests: try once more
        if s != 200:
            raise Unreadable(f"{cb}/{lock_name(origin)}: {s}")
        until_held = _until(held)
        if attempt == 0 and until_held is not None and until_held < time.time():
            release_lock(origin)                            # its own validity time has passed
            continue
        print(f"    ! another handover of {origin} is open: {held}")
        return None
    return None


def release_lock(origin=AE_ORIGIN) -> None:
    host, cb = IN_CSE
    _req("DELETE", f"{host}/{cb}/{lock_name(origin)}", ORCHESTRATOR)


def delete_ae(edge, ae=AE_NAME, origin=AE_ORIGIN):
    host, cb = edge
    return _req("DELETE", f"{host}/{cb}/{ae}", origin)


def reset() -> None:
    """Clear the vehicle from both edges so a run does not depend on the last one.

    Without this the driver passes once and fails afterwards: the destination
    still holds the AE from the previous run, the replayed samples append to the
    existing container, and the comparison against the source fails. A scenario
    driver has to establish its own preconditions.
    """
    for edge in (EDGE_A, EDGE_B):
        delete_ae(edge)
    release_lock()                                         # a transaction a failed run left open


class Device(Protocol):
    """The publishing side of the vehicle, as the orchestrator drives it (TD_MEC_HO_03).

    hold() returns once no write is in flight; samples produced while held are kept.
    resume(edge) points the device at `edge` and sends what it kept, in order.
    """

    def hold(self) -> None: ...
    def resume(self, edge) -> None: ...


def target_ready(dst, services: str | None = None) -> bool:
    """TD_MEC_HO_06: may the vehicle be handed to dst now?

    The target MN-CSE must answer. When the target's MEC platform is given (its Mp1
    service registry, e.g. http://127.0.0.1:8091/mec_service_mgmt/v1), the edge must
    also advertise an ACTIVE service that IS that CSE (see _advertises); our MEC 011 lists
    a service only after its app instance confirmed READY.
    """
    host, cb = dst
    try:
        st, body = _req("GET", f"{host}/{cb}", ORCHESTRATOR)
        if st != 200 or not registered_mn(dst)[0]:
            return False
        if services is None:
            return True
        csi = ((body or {}).get("m2m:cb") or {}).get("csi")
        r = urllib.request.Request(f"{services.rstrip('/')}/services", headers={"Accept": "application/json"})
        with urllib.request.urlopen(r, timeout=10) as resp:
            listed = json.loads(resp.read() or b"[]")
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(listed, list) and any(_advertises(s, f"{host}/{cb}", cb, csi) for s in listed)


def _advertises(s, me: str, cb: str, csi) -> bool:
    """Is MEC service `s` the CSE whose CSEBase URL is `me`? Two registrations count:

      ours          serName EDGE_SERVICE, an endpoint URI equal to the CSEBase URL;
      ETSI's sandbox (meep-acme-mn-cse MECSupport.py, STF_685) serName the CSE's resource name, serCategory.id
                    its CSE-ID, and the endpoint the CSE's HTTP root -- a URI the CSEBase URL lies directly under.
    Only ACTIVE services count. The root must be the CSEBase's parent on a path boundary, so neither a string
    prefix (":820" of ":8202") nor another CSE's root is taken for this one (B4, 2026-10-29).
    """
    if not isinstance(s, dict) or s.get("state") != "ACTIVE":
        return False
    uris = ((s.get("transportInfo") or {}).get("endpoint") or {}).get("uris")
    uris = [u for u in uris if isinstance(u, str)] if isinstance(uris, list) else []
    if s.get("serName") == EDGE_SERVICE:
        return me in uris
    cat = s.get("serCategory") if isinstance(s.get("serCategory"), dict) else {}
    same_cse = (s.get("serName") == cb and isinstance(csi, str) and isinstance(cat.get("id"), str)
                and cat["id"].lstrip("/") == csi.lstrip("/") != "")
    return same_cse and any(f"{u.rstrip('/')}/{cb}" == me for u in uris)


def handover(src, dst, samples: list[str], *, device: Device | None = None,
             ready: Callable[[tuple], bool] | None = None, ready_timeout: float = 0.0,
             poll: float = 0.2, outcome: list | None = None) -> bool:
    """Move the vehicle from src to dst along the TR-0086 5.5.3 state model.

        ATTACHED(src) -> HANDOVER_PREP -> DUAL_ATTACH -> ATTACHED(dst)

    `ready` is the readiness gate (TD_MEC_HO_06), e.g. lambda e: target_ready(e, url).
    It is polled for up to `ready_timeout` seconds; a target that never becomes ready
    means False with nothing touched, the vehicle still served by src.

    `samples` is the caller's view of src telemetry and must be what src holds. With a
    `device` publishing throughout, samples it writes to src during the move are
    copied too, then the device is held for the last copy and resumed on dst.

    Any failure, including an unreachable dst, is FAILED/ROLLBACK: the partial copy
    on dst is removed, src reachability is restored, the device resumes on src, and
    False is returned. Any other exception before the release is rolled back the same
    way and then raised on. The source is released only after dst holds the verified
    subtree and every subscription and the IN-CSE routes the AE-ID to dst (as well
    as to src; ROUTE_TIMEOUT_S), so a failure never strands the vehicle.

    From the moment the source's DELETE is sent nothing is rolled back: dst may hold
    the only copy. True needs the IN to route the AE-ID to dst alone and the source
    to be gone (its DELETE answered 200, or a re-read answers 404); otherwise an
    "! INCONSISTENT" line says what was seen and False is returned, the vehicle left
    on dst. `outcome`, if given, gets MOVED, NOT_MOVED or INCONSISTENT appended.
    """
    note = outcome.append if outcome is not None else (lambda state: None)
    if src == dst:
        print("    ! the target is the source; nothing touched")
        note(NOT_MOVED)
        return False
    if ready is not None and not _wait_ready(dst, ready, ready_timeout, poll):
        print("    ! target not ready; handover not started, source untouched")
        note(NOT_MOVED)
        return False
    held, made, was, lock = [], [], [], []
    undo = lambda: _rollback(src, dst, device if held else None, created=bool(made),  # noqa: E731
                             restore=was[0] if was else None, locked=bool(lock))
    try:
        if _handover(src, dst, samples, device, held, made, was, lock):
            note(MOVED)
            return True
    except _Inconsistent:
        note(INCONSISTENT)
        return False
    except Unreadable as e:
        print(f"    ! cannot read {e}; handover not completed")
    except OSError as e:                                   # URLError: dst unreachable
        print(f"    ! destination unreachable: {e}")
    except BaseException:
        # A malformed answer (KeyError, ValueError), a device error, timeout -s INT: once left the transaction open,
        # the source unreachable and a partial copy on the target. Rolled back like any failure, then raised on.
        undo()
        raise
    undo()
    note(NOT_MOVED)
    return False


def _wait_ready(dst, ready, timeout: float, poll: float) -> bool:
    end = time.monotonic() + timeout
    while True:
        try:
            if ready(dst):
                return True
        except OSError:
            pass
        if time.monotonic() >= end:
            return False
        time.sleep(poll)


def rank(candidates: list[dict]) -> list[dict]:
    """TD_MEC_HO_05 ranking: trust first, then latency, then load; the edge breaks ties.

    Each candidate is {"edge": (host, cb), "trust": 0..1, "latency_ms": ..., "load": 0..1}.
    The order depends only on those values, never on the order they were given in.
    """
    return sorted(candidates, key=lambda c: (-c["trust"], c["latency_ms"], c["load"], c["edge"]))


def handover_ranked(src, candidates: list[dict], samples: list[str], **kw) -> tuple[tuple | None, list]:
    """Try ranked candidates in order until one accepts (TD_MEC_HO_05).

    A refused target rolls back like any failed handover (NOT_MOVED), so the next one
    starts from an intact source. An INCONSISTENT outcome ends the list: the source was
    already released, so no further candidate is tried from it.
    Returns (serving edge or None, [(edge, accepted), ...]).
    """
    attempts = []
    for c in rank([c for c in candidates if c["edge"] != src]):
        out = []
        ok = handover(src, c["edge"], samples, outcome=out, **kw)
        attempts.append((c["edge"], ok))
        if ok:
            return c["edge"], attempts
        if INCONSISTENT in out:
            print("    ! the move left the vehicle INCONSISTENT; no further candidate is tried")
            break
    return None, attempts


def _handover(src, dst, samples: list[str], device: Device | None, held: list, made: list, was: list,
              lock: list) -> bool:
    ok, why = registered_mn(dst)                      # also for callers without the readiness gate
    if not ok:
        print(f"    ! not a handover target: {why}; nothing touched")
        return False
    src_csi, dst_csi = _csi(src), why
    if src_csi == dst_csi:                            # the same CSE under another address
        print(f"    ! the target is the source ({src_csi}); nothing touched")
        return False
    # Before anything is written: the IN-CSE routes this AE-ID to the source and to nothing else.
    route = serving_edges()
    if route != [src_csi]:
        print(f"    ! the IN-CSE routes {AE_ORIGIN} to {route or 'no edge'}, not to the source {src_csi} alone; "
              "nothing touched")
        return False
    subs = read_subscriptions(src)
    acps = read_acps(src)
    ae_attrs = read_ae(src)
    ae_acpi = read_acpi(src, AE_NAME)
    cnts = read_containers(src)
    fcnts = read_flexcontainers(src)
    carried = {ri for ri, _ in acps}
    # An <ACP> outside the vehicle's subtree (e.g. one at the CSEBase) does not exist on
    # the target. Moving without it would silently change who may read the data.
    foreign = [ri for ri in ae_acpi + [r for _, _, acpi in cnts for r in acpi] + [r for *_, acpi in fcnts for r in acpi]
               if ri.rsplit("/", 1)[-1] not in carried]
    if foreign:
        print(f"    ! access policies outside the AE cannot be carried: {foreign}")
        return False
    if left := _uncarried(src, cnts, fcnts):
        print(f"    ! the handover cannot carry {left}; source untouched")
        return False
    # What src holds now; anything it gains later is copied as it arrives (_catch_up).
    base = {rn: _cins(src, rn) for rn, _, _ in cnts}
    if [c["con"] for c in base.get(CONTAINER, [])][:len(samples)] != samples:
        print("    ! samples given are not what the source holds")
        return False
    # The name on the target must be free or this vehicle's own stale copy. A 409 once counted as success and the
    # subtree went under whatever AE held the name, another originator's included (deep check 2026-10-29).
    owner = _owner(dst)
    if owner not in (None, AE_ORIGIN):
        print(f"    ! the target already holds {AE_NAME} for {owner!r}; nothing written there")
        return False

    # One handover of this AE-ID at a time: the transaction is opened at the IN-CSE before the first write, and
    # the route is read again under it (it was read before the lock was ours).
    txn = take_lock(src_csi, dst_csi)
    if txn is None:
        return False
    lock.append(txn)
    print(f"     handover transaction {txn}: {src_csi} -> {dst_csi}")
    if serving_edges() != [src_csi]:
        print("    ! the route changed while the transaction was opened; nothing touched")
        return False

    # HANDOVER_PREP: the source stops delivering downlink to the AE (rr=false; ACME then
    # drops it unless the AE has a <pollingChannel>). What arrives here is caught up below.
    # What the device registered is remembered: a device that polls has rr = false all along, and a rollback
    # puts back that value, not "true" (TR-0077 Table 7.2.4.2.3-1 and TR-0086 5.5.5 say "restored to TRUE" and
    # assume a reachable device; raised with the authors, 2026-11-18).
    was.append(ae_attrs.get("rr", True) is not False)
    st, _ = set_reachability(src, False)
    if st != 200:
        print(f"    ! could not mark source unreachable: {st}")
        return False

    # DUAL_ATTACH. Our own stale registration at the destination is replaced, not appended to. Only a 201 is ours:
    # a 409 means the name is taken, ACME's 403 that this originator is already registered there.
    if owner == AE_ORIGIN:
        delete_ae(dst)
    st, _ = create_ae(dst, **ae_attrs)
    if st != 201:
        print(f"    ! AE create on destination refused: {st}")
        return False
    made.append(True)
    # The CREATE asked the target to announce the AE to the IN (at/aa). A 201 does not say it did: nothing else is
    # written to the target, and no subscriber is told anything from it, until the IN routes the AE-ID there.
    if not _routed_to_both(src_csi, dst_csi):
        return False
    # Security context first: the target's ACPs must exist before anything refers to them.
    host, cb = dst
    new_ri = {}
    for old, attrs in acps:
        st, body = _req("POST", f"{host}/{cb}/{AE_NAME}", AE_ORIGIN, ty=TY_ACP,
                        body={"m2m:acp": attrs})
        if st != 201:
            print(f"    ! access policy {attrs['rn']} not re-created: {st}")
            return False
        new_ri[old] = body["m2m:acp"]["ri"]
    remap = lambda acpi: [new_ri[ri.rsplit("/", 1)[-1]] for ri in acpi]  # noqa: E731
    if ae_acpi:
        st, _ = _req("PUT", f"{host}/{cb}/{AE_NAME}", AE_ORIGIN,
                     body={"m2m:ae": {"acpi": remap(ae_acpi)}})
        if st != 200:
            print(f"    ! AE access policy not applied on destination: {st}")
            return False
    for rn, attrs, acpi in cnts:
        st, _ = create_container(dst, name=rn, **attrs)
        if st != 201:
            print(f"    ! container {rn} create on destination failed: {st}")
            return False
        if acpi:
            st, _ = _req("PUT", f"{host}/{cb}/{AE_NAME}/{rn}", AE_ORIGIN,
                         body={"m2m:cnt": {"acpi": remap(acpi)}})
            if st != 200:
                print(f"    ! container {rn} access policy not applied on destination: {st}")
                return False
    for path, key, attrs, acpi in fcnts:                   # parents first, as read_flexcontainers lists them
        parent = path.rpartition("/")[0]
        st, _ = _req("POST", f"{host}/{cb}/{AE_NAME}" + (f"/{parent}" if parent else ""), AE_ORIGIN,
                     ty=TY_FCNT, body={key: attrs})
        if st != 201:
            print(f"    ! flexContainer {path} create on destination failed: {st}")
            return False
        if acpi:
            st, _ = _req("PUT", f"{host}/{cb}/{AE_NAME}/{path}", AE_ORIGIN, body={key: {"acpi": remap(acpi)}})
            if st != 200:
                print(f"    ! flexContainer {path} access policy not applied on destination: {st}")
                return False
    if not _flex_matches(dst, fcnts):
        return False
    copied = {rn: set() for rn in base}
    expected = {rn: [] for rn in base}
    if not _copy(dst, base, copied, expected):
        return False
    if not _matches(dst, expected):
        return False

    # Subscriptions after the replayed history, so it is not notified a second time. Each
    # is re-created AS ITS OWNER: the target re-checks that subscriber against the carried
    # ACPs, and the subscriber still owns (and may delete) its subscription afterwards.
    # Those addressed to the AE itself come first: src dropped everything it would have
    # sent them since HANDOVER_PREP, so the catch-up below must notify them from dst.
    # Everyone else heard those events from src and is subscribed only after it.
    to_ae = lambda a: any(n == AE_ORIGIN or n in ae_attrs.get("poa", []) for n in a["nu"])  # noqa: E731
    first = [s for s in subs if to_ae(s[1])]
    if not _subscribe(dst, first):
        return False
    for _ in range(5):                                     # drain while the device runs
        if not (n := _catch_up(src, dst, copied, expected)):
            break
        if n < 0:
            return False
    if device is not None:
        device.hold()
        held.append(True)
    if _catch_up(src, dst, copied, expected) < 0 or not _matches(dst, expected) or not _sync_flex(src, dst, fcnts):
        return False
    if not _subscribe(dst, [s for s in subs if not to_ae(s[1])]):
        return False
    if read_subscriptions(dst) != subs:
        print("    ! destination subscriptions do not match source")
        return False

    # Read again at the last moment before the release: the target's announcement must still be there.
    if not _routed_to_both(src_csi, dst_csi):
        return False

    # ATTACHED(dst). The device publishes to dst before src is released, so nothing it
    # produces meets a missing AE. Releasing the AE also withdraws its announcement at
    # the IN. Not closed: a command written to src after the last catch-up and before
    # this release is lost; writers route by the IN, which names dst from here on.
    if device is not None:
        device.resume(dst)
    # From the moment the source's DELETE is sent there is nothing to roll back to: ACME de-announces at the IN before
    # it removes the AE (and still serves it meanwhile), then answers, so a DELETE without an answer may have deleted
    # the source and the target's copy may be the only one. The rollback's lists are emptied BEFORE it is sent (no
    # delete on dst, no reachability or device put back on src); what follows is reported, never rolled back.
    del held[:], made[:], was[:]
    try:
        st, _ = delete_ae(src)
    except Exception as e:                                 # noqa: BLE001 -- no answer, or a garbled one: decided below
        st = f"no answer ({e!r})"
    try:
        release_lock()
    except Exception as e:                                 # noqa: BLE001
        print(f"    ! the handover transaction was not closed ({e!r}); the IN-CSE drops it at its et, "
              f"{TXN_VALIDITY_S:.0f} s after it was opened")
    lock.clear()
    try:
        route = _wait_route([dst_csi])
    except Exception as e:                                 # noqa: BLE001
        route = f"unreadable ({e!r})"
    gone = st == 200 or _absent(src)
    if route == [dst_csi] and gone:
        if st != 200:
            print(f"     the source's DELETE answered {st}; read again, the source no longer holds the AE")
        return True
    print(f"    ! INCONSISTENT: after the source's release (DELETE answered {st}; the source "
          f"{'no longer holds' if gone else 'may still hold'} the AE) the IN-CSE routes {AE_ORIGIN} to "
          f"{route or 'no edge'}; the vehicle stays on the target {dst_csi}, nothing rolled back")
    raise _Inconsistent


def _copy(dst, cins: dict[str, list[dict]], copied: dict[str, set], expected: dict[str, list]) -> bool:
    """Write each not-yet-copied src <contentInstance> to dst, keeping con and cnf."""
    for rn, items in cins.items():
        for c in items:
            if c["ri"] in copied[rn]:
                continue
            st, _ = add_sample(dst, c["con"], cnt=rn, cnf=c.get("cnf"))
            if st != 201:
                print(f"    ! {rn} replay failed: {st}")
                return False
            copied[rn].add(c["ri"])
            expected[rn].append(c["con"])
    return True


def _catch_up(src, dst, copied, expected) -> int:
    """Copy what src gained since the last pass. Returns how many, or -1 on failure."""
    before = sum(map(len, copied.values()))
    if not _copy(dst, {rn: _cins(src, rn) for rn in copied}, copied, expected):
        return -1
    return sum(map(len, copied.values())) - before


def _matches(dst, expected: dict[str, list]) -> bool:
    """dst starts with exactly what was copied, per container (writers may append to dst)."""
    for rn, want in expected.items():
        if [c["con"] for c in _cins(dst, rn)][:len(want)] != want:
            print(f"    ! destination {rn} does not match source")
            return False
    return True


def _subscribe(dst, subs) -> bool:
    for parent, attrs, owner in subs:
        st, _ = create_subscription(dst, parent, attrs, origin=owner)
        if st != 201:
            print(f"    ! subscription {parent}/{attrs['rn']} not re-created: {st}")
            return False
    return True


def _absent(edge, ae=AE_NAME) -> bool:
    """The edge answers that it holds no AE of this name (404). Any other answer, or none, is not "absent"."""
    host, cb = edge
    try:
        return _req("GET", f"{host}/{cb}/{ae}", ORCHESTRATOR)[0] == 404
    except Exception:                                      # noqa: BLE001
        return False


def _owner(edge, ae=AE_NAME) -> str | None:
    """The AE-ID of the AE holding the name `ae` on edge, or None if the name is free."""
    host, cb = edge
    st, body = _req("GET", f"{host}/{cb}/{ae}", ORCHESTRATOR)
    if st == 404:
        return None
    if st != 200 or not body:
        raise Unreadable(f"{cb}/{ae}: {st}")
    return body.get("m2m:ae", {}).get("aei")


def _rollback(src, dst, device: Device | None = None, created: bool = True, restore: bool | None = True,
              locked: bool = False) -> None:
    """FAILED/ROLLBACK: drop the partial copy, give the source back the reachability it had, close the transaction.

    restore is what the source's rr was before HANDOVER_PREP, or None when this handover never changed it."""
    steps = [lambda: delete_ae(dst)] if created else []                                             # only what WE made
    if restore is not None:
        steps.append(lambda: set_reachability(src, restore))
    if locked:
        steps.append(release_lock)
    if device is not None:
        steps.append(lambda: device.resume(src))
    for step in steps:
        try:
            step()
        except OSError:
            pass


def main() -> int:
    ok = True
    reset()

    print("1. edges registered at the IN-CSE")
    edges = registered_edges()
    print(f"     {edges}")
    ok &= edges_ok(edges)

    print("2. vehicle joins edge A")
    st, _ = create_ae(EDGE_A);       print(f"     AE        HTTP {st}"); ok &= st in (201, 409)
    st, _ = create_container(EDGE_A);print(f"     container HTTP {st}"); ok &= st in (201, 409)
    samples = ["48.1351,11.5820", "48.1361,11.5835", "48.1372,11.5849"]
    for s in samples:
        st, _ = add_sample(EDGE_A, s); ok &= st == 201
    print(f"     {len(samples)} position samples written")

    print("3. subtree readable on edge A")
    before = read_samples(EDGE_A)
    print(f"     {before}")
    ok &= before == samples

    print("4. handover A -> B")
    moved = handover(EDGE_A, EDGE_B, before)
    print(f"     {'done' if moved else 'FAILED'}")
    ok &= moved

    print("5. subtree readable on edge B, and gone from A")
    after = read_samples(EDGE_B)
    print(f"     on B: {after}")
    ok &= after == samples
    st, _ = _req("GET", f"{EDGE_A[0]}/{EDGE_A[1]}/{AE_NAME}", AE_ORIGIN)
    print(f"     on A: HTTP {st} (404 expected)")
    ok &= st == 404

    print("6. IN-CSE still holds both edges")
    edges = registered_edges()
    print(f"     {edges}")
    ok &= edges_ok(edges)

    print(f"\n  RESULT: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
