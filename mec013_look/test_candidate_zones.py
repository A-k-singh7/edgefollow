"""GS MEC 013 v3.1.1 zones queries on the location candidate (2026-11-21).

    GET /location/v3/queries/zones            clause 7.7, query zoneId 0..N (table 7.7.3.1-1) -> {"zoneList": ZoneList}
    GET /location/v3/queries/zones/{zoneId}   clause 7.8, no query (table 7.8.3.1-1)            -> {"zoneInfo": ZoneInfo}

No ETSI ATS suite and no device test calls these; ETSI's hosted MEC Sandbox answers them, ours did not.
Expected values are written by hand from the spec and from the candidate's four fixture UEs, NOT computed with
the candidate's own helpers, so a wrong formula in the candidate cannot also be "right" here:

    ZoneInfo members (OMA ZonalPresence via clause 6.2.1; LocationAPI.yaml v3.1.1 ZoneInfo: all five required)
    fixture: zone001 = acr:10.0.0.3 on ap01 + acr:10.0.0.4 on ap02 -> 2 access points, 2 users
             zone002 = acr:10.0.0.1 + acr:10.0.0.2, both on ap03    -> 1 access point,  2 users

The key names and nesting are the ones ETSI's sandbox returned on 2026-11-21 (zoneList{resourceURL, zone[]},
zoneInfo{...}). Where the sandbox and we differ, both answers are allowed and the tests pin ours:
  * unknown zone: 404 carries ProblemDetails 0..1 (table 7.8.3.1-2); the sandbox sends an empty body, we send
    the optional ProblemDetails;
  * a zoneId filter matching nothing: zone is 0..N; the sandbox answers 200 with a zoneList that has resourceURL
    and no `zone` member at all, we send `zone: []`.

In-process (FastAPI TestClient), no port, no stack, a fresh candidate module per test:

    PYTHONDONTWRITEBYTECODE=1 /home/edgefollow/edgefollow-lab/.venv/bin/python -m pytest -p no:cacheprovider \
        mec013_look/test_candidate_zones.py -q
"""
from __future__ import annotations

import importlib.util
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

CANDIDATE = Path(__file__).with_name("candidate.py")
Q = "/location/v3/queries"
ROOT = "http://127.0.0.1:8101/location/v3/queries/zones"
ZONE_INFO_KEYS = {"zoneId", "numberOfAccessPoints", "numberOfUnserviceableAccessPoints", "numberOfUsers",
                  "resourceURL"}
FIXTURE_ZONES = {
    "zone001": {"zoneId": "zone001", "numberOfAccessPoints": 2, "numberOfUnserviceableAccessPoints": 0,
                "numberOfUsers": 2, "resourceURL": f"{ROOT}/zone001"},
    "zone002": {"zoneId": "zone002", "numberOfAccessPoints": 1, "numberOfUnserviceableAccessPoints": 0,
                "numberOfUsers": 2, "resourceURL": f"{ROOT}/zone002"},
}
# Every route the candidate served before the zones were added (read from the file on 2026-11-21).
ROUTES_BEFORE = {("GET", "/")} | {
    (m, f"/location/v3/subscriptions/{c}{tail}")
    for c in ("area", "distance", "users", "zones")
    for m, tail in (("POST", ""), ("GET", ""), ("GET", "/{sub_id}"), ("DELETE", "/{sub_id}"))
} | {("GET", "/location/v3/queries/users")}
ROUTES_ADDED = {("GET", "/location/v3/queries/zones"), ("GET", "/location/v3/queries/zones/{zone_id}")}


@pytest.fixture
def cand():
    spec = importlib.util.spec_from_file_location(f"mec013_look_{uuid.uuid4().hex[:8]}", CANDIDATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def client(cand):
    return TestClient(cand.app, raise_server_exceptions=False)


def disagreements(zone_list: dict, users: list[dict]) -> list[str]:
    """Where a ZoneList and a full UserList disagree; [] when they agree. Independent of the candidate's code."""
    out = []
    by_zone: dict[str, list[dict]] = {}
    for u in users:
        by_zone.setdefault(u["zoneId"], []).append(u)
    listed = {z["zoneId"]: z for z in zone_list["zone"]}
    if len(listed) != len(zone_list["zone"]):
        out.append("a zoneId is listed twice")
    if set(listed) != set(by_zone):
        out.append(f"zones {sorted(listed)} != zones of the users {sorted(by_zone)}")
    for zid, z in listed.items():
        mine = by_zone.get(zid, [])
        if z["numberOfUsers"] != len(mine):
            out.append(f"{zid}: numberOfUsers {z['numberOfUsers']} != {len(mine)} users")
        aps = {u["accessPointId"] for u in mine}
        if z["numberOfAccessPoints"] != len(aps):
            out.append(f"{zid}: numberOfAccessPoints {z['numberOfAccessPoints']} != {len(aps)} access points")
        if not 0 <= z["numberOfUnserviceableAccessPoints"] <= z["numberOfAccessPoints"]:
            out.append(f"{zid}: unserviceable outside 0..numberOfAccessPoints")
    return out


# ------------------------------------------------------------------ the list
def test_list_is_the_fixture_zones_with_hand_written_counts(client):
    r = client.get(f"{Q}/zones")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert set(body) == {"zoneList"}
    assert set(body["zoneList"]) == {"zone", "resourceURL"}
    assert body["zoneList"]["resourceURL"] == ROOT
    assert body["zoneList"]["zone"] == [FIXTURE_ZONES["zone001"], FIXTURE_ZONES["zone002"]]


def test_every_zone_info_has_exactly_the_spec_members_with_their_types(client):
    for z in client.get(f"{Q}/zones").json()["zoneList"]["zone"]:
        assert set(z) == ZONE_INFO_KEYS
        assert isinstance(z["zoneId"], str) and z["zoneId"]
        for k in ("numberOfAccessPoints", "numberOfUnserviceableAccessPoints", "numberOfUsers"):
            assert type(z[k]) is int and z[k] >= 0, k          # unsignedInt; bool is not an int here
        assert z["resourceURL"] == f"{ROOT}/{z['zoneId']}"


def test_counts_agree_with_queries_users(client):
    zl = client.get(f"{Q}/zones").json()["zoneList"]
    users = client.get(f"{Q}/users").json()["user"]
    assert disagreements(zl, users) == []
    assert sum(z["numberOfUsers"] for z in zl["zone"]) == len(users)
    for z in zl["zone"]:   # and zone by zone through the users query's own zoneId filter
        mine = client.get(f"{Q}/users", params={"zoneId": z["zoneId"]}).json()["user"]
        assert z["numberOfUsers"] == len(mine)
        assert z["numberOfAccessPoints"] == len({u["accessPointId"] for u in mine})


def test_control_the_consistency_check_catches_a_wrong_zone_list(client):
    """The check above must be able to fail: each tampering of the real answer is caught."""
    zl = client.get(f"{Q}/zones").json()["zoneList"]
    users = client.get(f"{Q}/users").json()["user"]

    def tampered(f):
        z = {"resourceURL": zl["resourceURL"], "zone": [dict(x) for x in zl["zone"]]}
        f(z)
        return disagreements(z, users)

    assert tampered(lambda z: z["zone"][0].update(numberOfUsers=z["zone"][0]["numberOfUsers"] + 1))
    assert tampered(lambda z: z["zone"][1].update(numberOfAccessPoints=2))
    assert tampered(lambda z: z["zone"][0].update(numberOfUnserviceableAccessPoints=3))
    assert tampered(lambda z: z["zone"].pop())
    assert tampered(lambda z: z["zone"].append(dict(z["zone"][0])))
    assert tampered(lambda z: z["zone"].append(dict(z["zone"][0], zoneId="zone999")))


def test_zones_follow_users_at_request_time(cand, client):
    """Derived from USERS on every request, not a second inventory: a UE added or removed shows at once."""
    cand.USERS["acr:10.9.9.1"] = cand._user_record("acr:10.9.9.1", "zone777", "ap77")
    assert client.get(f"{Q}/zones/zone777").json()["zoneInfo"] == {
        "zoneId": "zone777", "numberOfAccessPoints": 1, "numberOfUnserviceableAccessPoints": 0,
        "numberOfUsers": 1, "resourceURL": f"{ROOT}/zone777"}
    cand.USERS["acr:10.9.9.2"] = cand._user_record("acr:10.9.9.2", "zone777", "ap77")   # same access point
    cand.USERS["acr:10.9.9.3"] = cand._user_record("acr:10.9.9.3", "zone777", "ap78")
    z = client.get(f"{Q}/zones/zone777").json()["zoneInfo"]
    assert (z["numberOfUsers"], z["numberOfAccessPoints"]) == (3, 2)
    assert disagreements(client.get(f"{Q}/zones").json()["zoneList"], client.get(f"{Q}/users").json()["user"]) == []
    for a in ("acr:10.9.9.1", "acr:10.9.9.2", "acr:10.9.9.3"):
        del cand.USERS[a]
    assert client.get(f"{Q}/zones/zone777").status_code == 404
    assert [z["zoneId"] for z in client.get(f"{Q}/zones").json()["zoneList"]["zone"]] == ["zone001", "zone002"]


def test_resource_urls_name_the_port_the_module_serves_on(cand, client):
    """phone/mec013_phone.py sets cand.PORT after import; zone URLs must follow it."""
    cand.PORT = 8401
    zl = client.get(f"{Q}/zones").json()["zoneList"]
    assert zl["resourceURL"] == "http://127.0.0.1:8401/location/v3/queries/zones"
    assert zl["zone"][0]["resourceURL"] == "http://127.0.0.1:8401/location/v3/queries/zones/zone001"


# ------------------------------------------------------------------ the zoneId filter
def test_filter_one_zone(client):
    zl = client.get(f"{Q}/zones", params={"zoneId": "zone002"}).json()["zoneList"]
    assert zl["zone"] == [FIXTURE_ZONES["zone002"]]
    assert zl["resourceURL"] == f"{ROOT}?zoneId=zone002"          # self-referring, as ETSI's sandbox gives it


def test_filter_is_repeatable(client):
    r = client.get(f"{Q}/zones", params=[("zoneId", "zone002"), ("zoneId", "zone001")])
    assert r.status_code == 200
    assert [z["zoneId"] for z in r.json()["zoneList"]["zone"]] == ["zone001", "zone002"]
    assert r.json()["zoneList"]["resourceURL"] == f"{ROOT}?zoneId=zone002&zoneId=zone001"


def test_filter_repeating_a_zone_lists_it_once(client):
    zl = client.get(f"{Q}/zones", params=[("zoneId", "zone001"), ("zoneId", "zone001")]).json()["zoneList"]
    assert zl["zone"] == [FIXTURE_ZONES["zone001"]]


def test_filter_unknown_beside_known_keeps_the_known(client):
    r = client.get(f"{Q}/zones", params=[("zoneId", "zone001"), ("zoneId", "nosuchzone")])
    assert r.status_code == 200
    assert r.json()["zoneList"]["zone"] == [FIXTURE_ZONES["zone001"]]


def test_filter_matching_nothing_is_200_with_an_empty_list(client):
    """ZoneList.zone is 0..N; 404 is for a URI that maps to no resource (table 7.7.3.1-2), and this one does.
    ETSI's sandbox answers the same request 200 with resourceURL and NO `zone` member (2026-11-21); both are
    allowed, we send `zone: []`."""
    r = client.get(f"{Q}/zones", params={"zoneId": "nosuchzone"})
    assert r.status_code == 200
    assert r.json() == {"zoneList": {"zone": [], "resourceURL": f"{ROOT}?zoneId=nosuchzone"}}


def test_unknown_query_parameter_on_the_list_is_400_problem_details(client):
    r = client.get(f"{Q}/zones", params={"zone": "zone001"})
    assert r.status_code == 400
    assert r.headers["content-type"].startswith("application/problem+json")
    assert r.json()["status"] == 400 and isinstance(r.json()["detail"], str)


# ------------------------------------------------------------------ the single zone
def test_single_zone_is_wrapped_zone_info_equal_to_its_list_entry(client):
    r = client.get(f"{Q}/zones/zone001")
    assert r.status_code == 200
    assert r.json() == {"zoneInfo": FIXTURE_ZONES["zone001"]}
    listed = {z["zoneId"]: z for z in client.get(f"{Q}/zones").json()["zoneList"]["zone"]}
    for zid in listed:
        assert client.get(f"{Q}/zones/{zid}").json()["zoneInfo"] == listed[zid]


def test_unknown_zone_is_404_with_a_problem_details_body(client):
    """Table 7.8.3.1-2 gives ProblemDetails 0..1 for 404: ETSI's sandbox sends an empty body, we send the optional
    ProblemDetails. Both are allowed; this pins ours."""
    r = client.get(f"{Q}/zones/nosuchzone")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/problem+json")
    body = r.json()
    assert body["status"] == 404 and isinstance(body["detail"], str) and body["detail"]
    assert set(body) <= {"type", "title", "status", "detail", "instance"}


def test_zone_id_with_a_space_has_resource_urls_that_lead_back_to_it(cand, client):
    """resourceURL is a URI (anyURI): a raw space is not allowed in one (RFC 3986), so "zone 1" must be escaped,
    and following each URL as given must reach the same zone / the same filtered list."""
    cand.USERS["acr:10.9.9.4"] = cand._user_record("acr:10.9.9.4", "zone 1", "ap 9")
    z = {z["zoneId"]: z for z in client.get(f"{Q}/zones").json()["zoneList"]["zone"]}["zone 1"]
    assert z["resourceURL"] == f"{ROOT}/zone%201"
    r = client.get(z["resourceURL"])
    assert r.status_code == 200 and r.json() == {"zoneInfo": z}
    zl = client.get(f"{Q}/zones", params={"zoneId": "zone 1"}).json()["zoneList"]
    assert " " not in zl["resourceURL"] and zl["zone"] == [z]
    assert client.get(zl["resourceURL"]).json() == {"zoneList": zl}


def test_no_500_while_a_thread_adds_and_removes_a_ue(cand, client):
    """Regression 2026-11-21: query_users iterated USERS live, and a reviewer got HTTP 500 ("dictionary changed size
    during iteration") 11 of 1,500 times while another thread added and removed a UE -- what mec013_phone's refresher
    does. 1,000 GETs, no 500. The writer yields after each change, as the refresher's time.sleep does: an add and a
    pop with no yield between them almost never interleave with a request (measured 0 of 600 GETs at every setting
    tried), while with the yield, 200 filler UEs and a 1 us switch interval a candidate iterating USERS live gave
    424 of 600 GETs as 500 (2026-11-21)."""
    for i in range(200):
        a = f"acr:10.8.0.{i}"
        cand.USERS[a] = cand._user_record(a, "zfill", f"apf{i % 10}")
    stop, flips = threading.Event(), [0]
    ue = cand._user_record("acr:10.9.9.9", "zone001", "ap01")

    def churn():
        while not stop.is_set():
            cand.USERS["acr:10.9.9.9"] = ue
            time.sleep(0)
            cand.USERS.pop("acr:10.9.9.9", None)
            time.sleep(0)
            flips[0] += 1

    codes: list[int] = []
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    t = threading.Thread(target=churn, daemon=True)
    t.start()
    try:
        for _ in range(500):
            codes.append(client.get(f"{Q}/users", params={"zoneId": "zone001"}).status_code)
            codes.append(client.get(f"{Q}/zones").status_code)
    finally:
        stop.set()
        t.join(5)
        sys.setswitchinterval(old)
    assert flips[0] > 100, flips            # the churn really ran beside the requests
    assert codes.count(500) == 0, f"{codes.count(500)} of {len(codes)} GETs were 500"
    assert set(codes) == {200}


def test_query_parameter_on_the_single_zone_is_400(client):
    r = client.get(f"{Q}/zones/zone001", params={"zoneId": "zone001"})
    assert r.status_code == 400
    assert r.headers["content-type"].startswith("application/problem+json")


# ------------------------------------------------------------------ controls: nothing else changed
def test_control_route_table_is_the_old_one_plus_the_two_zone_queries(cand):
    fastapi_own = ("/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc")
    routes = {(m, r.path) for r in cand.app.routes if r.path not in fastapi_own
              for m in getattr(r, "methods", ()) if m != "HEAD"}
    assert routes == ROUTES_BEFORE | ROUTES_ADDED


def test_control_users_query_unchanged(client):
    users = client.get(f"{Q}/users").json()
    assert users["resourceURL"] == "http://127.0.0.1:8101/location/v3/queries/users"
    assert [(u["address"], u["zoneId"], u["accessPointId"]) for u in users["user"]] == [
        ("acr:10.0.0.3", "zone001", "ap01"), ("acr:10.0.0.4", "zone001", "ap02"),
        ("acr:10.0.0.1", "zone002", "ap03"), ("acr:10.0.0.2", "zone002", "ap03")]
    assert client.get(f"{Q}/users", params={"zoneId": "nosuchzone"}).status_code == 404   # tolerance 2/3 kept
    assert client.get(f"{Q}/users", params={"addr": "x"}).status_code == 400


def test_control_zone_subscriptions_unchanged(client):
    """/subscriptions/zones is a different resource from /queries/zones: its CRUD and 404-on-empty stay."""
    assert client.get("/location/v3/subscriptions/zones").status_code == 404
    r = client.post("/location/v3/subscriptions/zones", json={"subscriptionType": "ZoneStatusSubscription",
                                                               "zoneId": "zone001"})
    assert r.status_code == 201 and r.headers["location"].startswith("/subscriptions/zones/")
    sid = r.headers["location"].split("/")[3]
    assert client.get(f"/location/v3/subscriptions/zones/{sid}").json()["zoneId"] == "zone001"
    assert client.delete(f"/location/v3/subscriptions/zones/{sid}").status_code == 204
    assert client.get("/location/v3/subscriptions/zones").status_code == 404
