"""Break-in detection on the PIN page (orbi/guard.py)."""
import logging

import pytest
from fastapi.testclient import TestClient

from orbi import config
from orbi.guard import scripted_agent as REAL_SCRIPTED_AGENT
from orbi.web import create_app

BROWSER = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
KID_IP, KID_MAC = "192.168.1.21", "AA:00:00:00:00:02"  # kid-tablet in the fake router


@pytest.fixture
def armed(monkeypatch):
    """Detection as shipped (conftest switches it off for the other tests)."""
    monkeypatch.setattr("orbi.guard.FAST", (3, 2.0))
    monkeypatch.setattr("orbi.guard.THROUGH_LOCKOUT", (6, 10.0))
    monkeypatch.setattr("orbi.guard.PROBE", (30, 60.0))
    monkeypatch.setattr("orbi.guard.scripted_agent", REAL_SCRIPTED_AGENT)


@pytest.fixture
def clock(monkeypatch):
    t = [1_800_000_000.0]
    monkeypatch.setattr("orbi.guard.time.time", lambda: t[0])
    return t


@pytest.fixture
def app(monitor, monkeypatch):
    monitor.scan()
    monkeypatch.setattr("orbi.monitor.arp_mac", lambda ip: {KID_IP: KID_MAC}.get(ip))
    app = create_app(monitor)
    parent = TestClient(app, client=("127.0.0.1", 50000))
    assert parent.post("/api/setup", json={"pin": "246810"}).status_code == 200
    return app


def kid(app, agent=BROWSER):
    return TestClient(app, client=(KID_IP, 50000), headers={"user-agent": agent})


def parent(app):
    c = TestClient(app, client=("127.0.0.1", 50000))
    assert c.post("/api/login", json={"pin": "246810"}).status_code == 200
    return c


def test_wrong_pins_are_recorded_and_typos_erased_on_sign_in(app, armed, clock):
    k = kid(app)
    for guess in ("111111", "246811"):
        assert k.post("/api/login", json={"pin": guess}).status_code == 401
        clock[0] += 5  # typing speed
    rows = parent(app).get("/api/security").json()["attempts"]
    assert [(r["guess"], r["outcome"], r["mac"], r["automated"]) for r in rows] == [
        ("246811", "wrong", KID_MAC, 0), ("111111", "wrong", KID_MAC, 0)]
    assert rows[0]["device"] == "kid-tablet" and "iPhone" in rows[0]["agent"]
    # the stored guess is encrypted, not plain text
    raw = app.state.guard.store.q("SELECT guess FROM pin_attempts")
    assert all(r["guess"] and "246811" not in r["guess"] for r in raw)
    # the same device then gets in: those were its owner's typos of the real PIN, so they're erased
    assert k.post("/api/login", json={"pin": "246810"}).status_code == 200
    assert [r["guess"] for r in parent(app).get("/api/security").json()["attempts"]] == [None, None]
    assert not app.state.guard.bans()


def test_fast_guessing_is_a_program_and_gets_shut_out(app, armed, clock, monitor, fake_router, caplog):
    caplog.set_level(logging.INFO)
    k = kid(app)
    for guess in ("000001", "000002", "000003"):
        k.post("/api/login", json={"pin": guess})
        clock[0] += 0.2
    ev = monitor.store.one("SELECT * FROM events WHERE kind='pin_attack'")
    assert ev and ev["severity"] == "error" and "too fast for a person" in ev["detail"] and ev["mac"] == KID_MAC
    assert "Break-in attempt on Orbi Control" in [n[0] for n in monitor.notes]
    # banned from the whole app, even with the right PIN
    r = k.post("/api/login", json={"pin": "246810"})
    assert r.status_code == 403 and "shut out" in r.json()["detail"]
    assert k.get("/api/session").status_code == 403
    # and blocked at the router
    monitor.enforce()
    assert KID_MAC in fake_router.blocked
    # this PC still works, and the guesses never reach the app log
    p = parent(app)
    assert p.get("/api/security").json()["bans"][0]["mac"] == KID_MAC
    assert "000002" not in caplog.text
    # unblocking the device in Devices lets it use the app again
    assert p.post(f"/api/devices/{KID_MAC}/block", json={"blocked": False}).status_code == 200
    assert kid(app).get("/api/session").status_code == 200


def test_non_browser_client_is_a_program(app, armed, clock, monitor):
    kid(app, agent="python-requests/2.32").post("/api/login", json={"pin": "123456"})
    assert "from a program, not a web browser (python-requests" in monitor.store.one("SELECT detail FROM events WHERE kind='pin_attack'")["detail"]
    assert REAL_SCRIPTED_AGENT("curl/8.9.1") and REAL_SCRIPTED_AGENT("") and not REAL_SCRIPTED_AGENT(BROWSER)


def test_guessing_through_the_lockout_is_a_program(app, armed, clock, monitor):
    k = kid(app)
    for i in range(11):  # 5 wrong, then 6 more into the lockout, slow enough to pass as typing
        k.post("/api/login", json={"pin": f"00000{i % 10}"})
        clock[0] += 1.5
    ev = monitor.store.one("SELECT * FROM events WHERE kind='pin_attack'")
    assert ev and "straight through the lockout" in ev["detail"]


def test_probing_pages_without_signing_in(app, armed, clock, monitor):
    k = kid(app)
    for _ in range(29):
        assert k.get("/api/devices").status_code == 401
    assert k.get("/api/settings").status_code == 401  # the 30th trips it
    assert k.get("/api/devices").status_code == 403
    assert "without signing in" in monitor.store.one("SELECT detail FROM events WHERE kind='pin_attack'")["detail"]


def test_ban_follows_the_device_not_the_address(app, armed, clock, monkeypatch):
    k = kid(app, agent="curl/8.9.1")
    k.post("/api/login", json={"pin": "123456"})
    assert k.get("/api/session").status_code == 403
    # later, the router gives that address to a different device: it isn't shut out
    monkeypatch.setattr("orbi.monitor.arp_mac", lambda ip: "AA:00:00:00:00:03")
    app.state.guard.monitor._arp_cache.clear()
    assert kid(app).get("/api/session").status_code == 200


def test_router_block_can_be_switched_off(app, armed, clock, monitor, fake_router):
    config.save({"block_pin_attackers": False})
    kid(app, agent="curl/8.9.1").post("/api/login", json={"pin": "123456"})
    monitor.enforce()
    assert KID_MAC not in fake_router.blocked
    assert kid(app).get("/api/session").status_code == 403  # still shut out of the app
    p = parent(app)
    assert p.delete(f"/api/security/bans/{KID_IP}").status_code == 200
    assert kid(app).get("/api/session").status_code == 200


def test_this_pc_is_never_shut_out(app, armed, clock):
    c = TestClient(app, client=("127.0.0.1", 50000), headers={"user-agent": "curl/8.9.1"})
    for _ in range(4):
        c.post("/api/login", json={"pin": "000000"})
    assert not app.state.guard.bans()
    assert c.post("/api/login", json={"pin": "246810"}).status_code == 200
