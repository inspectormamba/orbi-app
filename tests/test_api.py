import pytest
from fastapi.testclient import TestClient

from orbi import config
from orbi.web import create_app


@pytest.fixture
def client(monitor):
    monitor.scan()
    return TestClient(create_app(monitor))


def setup_pin(client, pin="246810"):
    r = client.post("/api/setup", json={"pin": pin})
    assert r.status_code == 200, r.text


def test_requires_login(client):
    assert client.get("/api/status").status_code == 401
    assert client.get("/api/session").json()["pin_set"] is False
    assert client.post("/api/setup", json={"pin": "123"}).status_code == 400  # too short
    setup_pin(client)
    assert client.get("/api/status").status_code == 200
    assert client.post("/api/setup", json={"pin": "999999"}).status_code == 409  # can't redo setup


def test_login_and_lockout(client):
    setup_pin(client)
    client.post("/api/logout")
    client.cookies.clear()
    assert client.get("/api/devices").status_code == 401
    for _ in range(5):
        assert client.post("/api/login", json={"pin": "000000"}).status_code == 401
    r = client.post("/api/login", json={"pin": "246810"})
    assert r.status_code == 429 and "Try again" in r.json()["detail"]


def test_multiple_pins(client):
    setup_pin(client, "246810")
    # add a second PIN using the first as authorization
    assert client.post("/api/settings/pins", json={"current": "246810", "new": "092619", "label": "Spare"}).status_code == 200
    assert client.post("/api/settings/pins", json={"current": "092619", "new": "092619"}).status_code == 409  # already accepted
    assert [e["label"] for e in client.get("/api/settings/pins").json()["extra"]] == ["Spare"]
    client.post("/api/logout")
    client.cookies.clear()
    # both the original and the added PIN log in
    assert client.post("/api/login", json={"pin": "092619"}).status_code == 200
    client.post("/api/logout")
    assert client.post("/api/login", json={"pin": "246810"}).status_code == 200
    assert client.post("/api/login", json={"pin": "000000"}).status_code == 401  # others still rejected
    # removing it revokes access
    assert client.delete("/api/settings/pins/Spare").status_code == 200
    client.post("/api/logout")
    client.cookies.clear()
    assert client.post("/api/login", json={"pin": "092619"}).status_code == 401


def test_status_and_devices(client):
    setup_pin(client)
    st = client.get("/api/status").json()
    assert st["info"]["model"] == "RBR750" and st["dns_filter"] == "CleanBrowsing Adult filter"
    assert st["devices_online"] == 3
    devs = client.get("/api/devices").json()
    phone = next(d for d in devs if d["name"] == "kid-phone")
    assert phone["ap"] == "Garage Satellite" and phone["online"] and not phone["blocked"]
    tv = next(d for d in devs if d["name"] == "tv")
    assert tv["ap"] == "Router"


def test_block_unblock_and_rename(client, monitor):
    setup_pin(client)
    mac = "AA:00:00:00:00:03"
    assert client.post(f"/api/devices/{mac}/block", json={"blocked": True}).status_code == 200
    assert mac in monitor.router.blocked
    dev = next(d for d in client.get("/api/devices").json() if d["mac"] == mac)
    assert dev["blocked"] and dev["block_reason"] == "Blocked manually"
    client.post(f"/api/devices/{mac}/block", json={"blocked": False})
    assert mac not in monitor.router.blocked
    assert not next(d for d in client.get("/api/devices").json() if d["mac"] == mac)["blocked"]
    client.patch(f"/api/devices/{mac}", json={"alias": "Living room TV"})
    assert any(d["name"] == "Living room TV" for d in client.get("/api/devices").json())
    assert client.post("/api/devices/08:BF:B8:39:2E:5D/block", json={"blocked": True}).status_code in (400, 404)


def test_family_flow(client, monitor):
    setup_pin(client)
    pid = client.post("/api/profiles", json={"name": "Ethan", "emoji": "🧒"}).json()["id"]
    client.patch("/api/devices/AA:00:00:00:00:01", json={"profile_id": pid})
    client.post(f"/api/profiles/{pid}/pause", json={"minutes": None})
    assert "AA:00:00:00:00:01" in monitor.router.blocked
    prof = client.get("/api/profiles").json()[0]
    assert prof["paused"] and prof["state"]["reason"] == "Paused" and prof["devices"][0]["mac"] == "AA:00:00:00:00:01"
    note = client.post("/api/devices/AA:00:00:00:00:01/block", json={"blocked": False}).json()["note"]
    assert "Still blocked by Ethan: Paused" in note
    client.post(f"/api/profiles/{pid}/resume", json={})
    assert "AA:00:00:00:00:01" not in monitor.router.blocked
    # an all-day schedule blocks; extra time lifts it; cancelling extra time re-blocks
    r = client.post(f"/api/profiles/{pid}/rules", json={"label": "Grounded", "days": "0123456", "start": "00:00", "end": "00:00"})
    rid = r.json()["id"]
    assert "AA:00:00:00:00:01" in monitor.router.blocked
    client.post(f"/api/profiles/{pid}/bonus", json={"minutes": 30})
    assert "AA:00:00:00:00:01" not in monitor.router.blocked
    assert client.get("/api/profiles").json()[0]["state"]["reason"] == "Extra time"
    client.post(f"/api/profiles/{pid}/bonus/cancel", json={})
    assert "AA:00:00:00:00:01" in monitor.router.blocked
    client.delete(f"/api/rules/{rid}")
    assert "AA:00:00:00:00:01" not in monitor.router.blocked
    assert client.post(f"/api/profiles/{pid}/rules", json={"start": "25:00", "end": "07:00"}).status_code == 400
    assert client.post(f"/api/profiles/{pid}/rules", json={"start": "21:00", "end": "07:00", "days": ""}).status_code == 400
    client.post(f"/api/profiles/{pid}/pause", json={"minutes": 15})
    client.delete(f"/api/profiles/{pid}")
    assert monitor.router.blocked == set()  # deleting a profile releases its devices


def test_controls_and_settings(client, monitor):
    setup_pin(client)
    assert client.post("/api/guest", json={"enabled": True}).json()["enabled"] is True
    assert client.post("/api/router/reboot", json={}).status_code == 400
    assert client.post("/api/router/reboot", json={"confirm": True}).status_code == 200
    assert ("reboot",) in monitor.router.calls
    assert client.patch("/api/settings", json={"speedtest_daily_at": "7pm"}).status_code == 400
    s = client.patch("/api/settings", json={"scan_interval": 5, "speedtest_daily_at": ""}).json()
    assert s["scan_interval"] == 60 and s["speedtest_daily_at"] == ""
    assert client.post("/api/settings/pin", json={"current": "nope", "new": "1234567"}).status_code == 401
    assert client.post("/api/settings/pin", json={"current": "246810", "new": "1357911"}).status_code == 200
    assert client.get("/api/status").status_code == 200  # this device got a fresh session
    acc = client.get("/api/access").json()
    assert acc["urls"] and acc["qr_svg"].startswith("<?xml") or "<svg" in acc["qr_svg"]


def test_web_app_served(client):
    assert "Orbi Control" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/manifest.webmanifest").json()["short_name"] == "Orbi"


def test_pin_change_removes_extra_pins(client):
    setup_pin(client, "246810")
    client.post("/api/settings/pins", json={"current": "246810", "new": "092619", "label": "Spare"})
    assert client.post("/api/settings/pin", json={"current": "246810", "new": "a long passphrase"}).status_code == 200
    assert client.get("/api/settings/pins").json()["extra"] == []
    client.post("/api/logout")
    client.cookies.clear()
    assert client.post("/api/login", json={"pin": "092619"}).status_code == 401
    assert client.post("/api/login", json={"pin": "a long passphrase"}).status_code == 200


def test_logout_revokes_a_copied_session(client):
    setup_pin(client)
    token = client.cookies.get("orbi_session")
    client.post("/api/logout")
    client.cookies.clear()
    client.cookies.set("orbi_session", token)
    assert client.get("/api/devices").status_code == 401


def test_lockout_counts_simultaneous_guesses(client):
    from concurrent.futures import ThreadPoolExecutor
    setup_pin(client)
    client.post("/api/logout")
    client.cookies.clear()
    with ThreadPoolExecutor(20) as pool:
        codes = list(pool.map(lambda _: client.post("/api/login", json={"pin": "000000"}).status_code, range(40)))
    assert codes.count(401) == 5 and codes.count(429) == 35


def test_lockout_is_house_wide():
    from orbi.auth import Throttle
    t = Throttle()
    for i in range(Throttle.HOUSE):  # 4 guesses each from many addresses stays under the per-client limit
        assert t.attempt(f"192.168.1.{i // 4 + 10}") == 0
    assert t.attempt("192.168.1.200") > 0  # a fresh address is locked out too


def test_router_host_must_be_a_private_ip(client):
    setup_pin(client)
    for bad in ("evil.example.com", "8.8.8.8", "127.0.0.1", "0.0.0.0"):
        assert client.patch("/api/settings", json={"router_host": bad}).status_code == 400, bad
    assert client.patch("/api/settings", json={"router_host": "192.168.1.1"}).status_code == 200


def test_new_router_address_needs_the_password_again(client, monkeypatch):
    setup_pin(client)
    config.save({"router_password_enc": "x"})
    client.patch("/api/settings", json={"router_host": "192.168.1.1"})  # unchanged: kept
    assert config.load()["router_password_enc"] == "x"
    client.patch("/api/settings", json={"router_host": "192.168.1.66"})
    assert config.load()["router_password_enc"] == ""  # never sent to the new address


def test_file_api_is_gone(client):
    setup_pin(client)
    assert client.get("/api/files/list").status_code in (404, 405)
    assert client.put("/api/files/settings", json={"enabled": True, "pin": "246810"}).status_code in (404, 405)


def test_web_app_has_no_duplicate_functions():
    """A second top-level function with the same name silently replaces the first in the browser
    (that once broke editing family schedules)."""
    import collections
    import re
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "web" / "app.js").read_text("utf-8")
    names = re.findall(r"^(?:async )?function (\w+)\s*\(", src, re.M)
    names += re.findall(r"^(?:const|let) (\w+)\s*=", src, re.M)
    dupes = [n for n, c in collections.Counter(names).items() if c > 1]
    assert not dupes, f"defined more than once in web/app.js: {dupes}"
