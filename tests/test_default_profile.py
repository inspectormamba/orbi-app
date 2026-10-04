import time
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from orbi import config
from orbi.parental import desired_blocks, effective_profile, is_randomized_mac, name_match_profile
from orbi.web import create_app

from .conftest import SAT_MAC

NOW = datetime(2026, 9, 28, 22, 0)  # Monday 10 pm: bedtime
KIDS = {"id": 1, "name": "Kids", "paused_until": None, "allow_until": None}
HOME = {"id": 2, "name": "Home & adults", "paused_until": None, "allow_until": None}
BEDTIME = {"profile_id": 1, "label": "Bedtime", "days": "0123456", "start": "21:00", "end": "07:00", "enabled": 1}


def test_unassigned_devices_follow_the_default():
    devices = [{"mac": "A", "profile_id": 2}, {"mac": "B", "profile_id": None, "online": 1},
               {"mac": "OLD", "profile_id": None, "online": 0, "last_seen": NOW.timestamp() - 30 * 86400},
               {"mac": "PC", "profile_id": None, "online": 1}]
    assert desired_blocks([KIDS, HOME], [BEDTIME], devices, NOW, {"PC"}) == {}  # no default set
    got = desired_blocks([KIDS, HOME], [BEDTIME], devices, NOW, {"PC"}, default_profile_id=1)
    assert got == {"B": "Kids: Bedtime (default profile)"}  # stale and protected devices are left alone
    assert effective_profile({"profile_id": 2}, 1, NOW) == 2


def test_name_matching_and_private_addresses():
    named = [{"router_name": "Jamess-MacBook-Pro", "profile_id": 1}, {"router_name": "Jamess-MacBook-Pro", "profile_id": 1},
             {"router_name": "iPhone", "profile_id": 1}, {"router_name": "Living-Room", "profile_id": 2},
             {"router_name": "Living-Room", "profile_id": None}]
    assert name_match_profile("jamess-macbook-pro", named) == 1
    assert name_match_profile("iPhone", named) is None  # generic names never auto-assign
    assert name_match_profile("Living-Room", named) is None  # ambiguous
    assert name_match_profile("Nobody", named) is None
    assert is_randomized_mac("3E:08:71:90:3D:B3") and not is_randomized_mac("C4:8E:8F:A2:47:0E")


def new_device(monitor, mac, name):
    monitor.router.devs.append(monitor.router._dev(mac, name, "192.168.1.150", SAT_MAC))
    monitor.scan()


def test_new_address_matching_by_name_is_held_with_profile_preselected(monitor):
    monitor.scan()  # baseline (hold_new_devices is off: a name match is held regardless, since names are spoofable)
    pid = monitor.store.x("INSERT INTO profiles(name, created) VALUES('James', ?)", (time.time(),))
    monitor.store.x("UPDATE devices SET profile_id=? WHERE mac='AA:00:00:00:00:01'", (pid,))  # kid-phone
    new_device(monitor, "3E:00:00:00:00:99", "kid-phone")
    row = monitor.store.one("SELECT profile_id, manual_block, held FROM devices WHERE mac='3E:00:00:00:00:99'")
    assert (row["profile_id"], row["manual_block"], row["held"]) == (pid, 1, 1)
    ev = monitor.store.q("SELECT title, detail FROM events WHERE kind='new_device'")[-1]
    assert "came back with a new address (private address)" in ev["title"] and "Blocked until you approve it" in ev["detail"]
    monitor.enforce()
    assert "3E:00:00:00:00:99" in monitor.router.blocked


def test_hold_new_devices_until_approved(monitor):
    monitor.scan()
    config.save({"hold_new_devices": True})
    new_device(monitor, "3E:00:00:00:00:77", "mystery-tablet")
    monitor.enforce()
    assert "3E:00:00:00:00:77" in monitor.router.blocked
    assert monitor.store.one("SELECT held FROM devices WHERE mac='3E:00:00:00:00:77'")["held"] == 1
    assert monitor.notes[-1][0] == "New device waiting for approval"


@pytest.fixture
def client(monitor):
    monitor.scan()
    c = TestClient(create_app(monitor))
    c.post("/api/setup", json={"pin": "246810"})
    return c


def test_default_profile_api_flow(client, monitor):
    kids = client.post("/api/profiles", json={"name": "Kids"}).json()["id"]
    client.post(f"/api/profiles/{kids}/rules", json={"label": "Grounded", "days": "0123456", "start": "00:00", "end": "00:00"})
    assert client.get("/api/family/settings").json()["unassigned"] == 3
    # protect the house first: move today's devices into an unrestricted profile
    home = client.post("/api/profiles", json={"name": "Home & adults"}).json()["id"]
    assert client.post("/api/family/assign-unassigned", json={"profile_id": home}).json()["moved"] == 3
    r = client.put("/api/family/settings", json={"default_profile_id": kids, "hold_new_devices": False}).json()
    assert r["default_profile_id"] == kids and r["unassigned"] == 0
    assert monitor.router.blocked == set()  # nothing existing got caught
    # a phone that changed its address shows up as new and inherits Kids' rules
    new_device(monitor, "3E:00:00:00:00:55", "Phone")
    monitor.enforce()
    assert "3E:00:00:00:00:55" in monitor.router.blocked
    dev = next(d for d in client.get("/api/devices").json() if d["mac"] == "3E:00:00:00:00:55")
    assert dev["profile"] is None and dev["default_profile"]["name"] == "Kids" and dev["randomized"]
    assert "(default profile)" in dev["block_reason"]
    # deleting the default profile releases its inherited devices
    client.delete(f"/api/profiles/{kids}")
    assert client.get("/api/family/settings").json()["default_profile_id"] is None
    assert monitor.router.blocked == set()


def test_approving_a_held_device(client, monitor):
    client.put("/api/family/settings", json={"default_profile_id": None, "hold_new_devices": True})
    new_device(monitor, "3E:00:00:00:00:66", "visitor")
    monitor.enforce()
    dev = next(d for d in client.get("/api/devices").json() if d["mac"] == "3E:00:00:00:00:66")
    assert dev["held"] and dev["blocked"]
    client.post("/api/devices/3E:00:00:00:00:66/block", json={"blocked": False})
    dev = next(d for d in client.get("/api/devices").json() if d["mac"] == "3E:00:00:00:00:66")
    assert not dev["held"] and not dev["blocked"] and "3E:00:00:00:00:66" not in monitor.router.blocked
