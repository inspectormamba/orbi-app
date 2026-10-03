import threading
import time

import orbi.monitor as monitor_mod
from orbi import auth, parental

from .conftest import SAT_MAC


def add_profile(m, name="Kid", paused=None):
    return m.store.x("INSERT INTO profiles(name, paused_until, created) VALUES(?,?,?)", (name, paused, time.time()))


def test_scan_records_devices_and_baselines_quietly(monitor):
    monitor.scan()
    assert len(monitor.store.q("SELECT * FROM devices WHERE online=1")) == 3
    assert monitor.store.q("SELECT * FROM events WHERE kind='new_device'") == []  # first scan is the baseline
    monitor.router.devs.append(monitor.router._dev("BB:00:00:00:00:09", "stranger", "192.168.1.99", SAT_MAC))
    monitor.scan()
    ev = monitor.store.q("SELECT * FROM events WHERE kind='new_device'")
    assert len(ev) == 1 and "stranger" in ev[0]["title"]
    assert monitor.notes[-1][0] == "New device on your network"
    monitor.router.devs.pop()
    monitor.scan()
    assert monitor.store.one("SELECT online FROM devices WHERE mac='BB:00:00:00:00:09'")["online"] == 0


def test_satellite_offline_needs_two_misses(monitor):
    monitor.scan()
    sats = monitor.router.sats
    monitor.router.sats = []
    monitor.scan()
    assert not monitor.store.q("SELECT * FROM events WHERE kind='satellite'")
    monitor.scan()
    ev = monitor.store.q("SELECT * FROM events WHERE kind='satellite'")
    assert len(ev) == 1 and "offline" in ev[0]["title"]
    assert monitor.state["satellites"][0]["online"] is False
    monitor.router.sats = sats
    monitor.scan()
    assert "back online" in monitor.store.q("SELECT title FROM events WHERE kind='satellite' ORDER BY id DESC")[0]["title"]


def test_enforce_pause_blocks_and_resume_unblocks(monitor):
    r = monitor.router
    monitor.scan()
    pid = add_profile(monitor, paused=parental.FOREVER)
    monitor.store.x("UPDATE devices SET profile_id=? WHERE mac IN ('AA:00:00:00:00:01','AA:00:00:00:00:02')", (pid,))
    monitor.enforce()
    assert r.ac and r.blocked == {"AA:00:00:00:00:01", "AA:00:00:00:00:02"}
    assert r.calls[0] == ("allow", "08:BF:B8:39:2E:5D")  # this PC is explicitly allowed before AC goes on
    assert ("enable_ac",) in r.calls
    monitor.store.x("UPDATE profiles SET paused_until=NULL WHERE id=?", (pid,))
    monitor.enforce()
    assert r.blocked == set()
    assert monitor.store.q("SELECT * FROM applied_blocks") == []


def test_enforce_never_touches_blocks_it_did_not_make(monitor):
    r = monitor.router
    r.blocked.add("AA:00:00:00:00:03")  # blocked by someone in the Orbi app
    monitor.scan()
    monitor.enforce()
    assert "AA:00:00:00:00:03" in r.blocked
    assert not [c for c in r.calls if c[0] == "allow" and c[1] == "AA:00:00:00:00:03"]


def test_protected_device_is_never_blocked(monitor):
    monitor.store.x("INSERT INTO devices(mac, manual_block) VALUES('08:BF:B8:39:2E:5D', 1)")
    monitor.enforce()
    assert "08:BF:B8:39:2E:5D" not in monitor.router.blocked


def test_self_heals_drift_and_access_control_off(monitor):
    r = monitor.router
    monitor.scan()
    monitor.store.x("UPDATE devices SET manual_block=1 WHERE mac='AA:00:00:00:00:01'")
    monitor.enforce()
    assert "AA:00:00:00:00:01" in r.blocked
    r.blocked.clear()  # e.g. router reset or someone unblocked it in the Orbi app
    monitor.scan()
    monitor.enforce()
    assert "AA:00:00:00:00:01" in r.blocked
    r.ac = False  # Access Control switched off elsewhere
    monitor.scan()
    monitor.enforce()
    assert r.ac is True
    assert monitor.store.q("SELECT * FROM events WHERE title LIKE 'Access Control was turned off%'")


def test_enforce_reports_router_errors(monitor):
    monitor.scan()
    monitor.store.x("UPDATE devices SET manual_block=1 WHERE mac='AA:00:00:00:00:01'")
    monitor.router.ac = True
    monitor.router.fail = True
    monitor.enforce()
    assert "router offline" in monitor.state["enforce_error"]
    assert monitor.store.q("SELECT * FROM applied_blocks") == []  # nothing recorded as applied
    monitor.router.fail = False
    monitor.enforce()
    assert monitor.state["enforce_error"] is None and "AA:00:00:00:00:01" in monitor.router.blocked


def test_outage_lifecycle(monitor, monkeypatch):
    up = {"internet": True}
    monkeypatch.setattr(monitor_mod, "tcp_ok", lambda host, port, timeout=3.0: (5.0 if (up["internet"] or host.startswith("192.168")) else None))
    monitor.check_health()
    assert monitor.state["internet"] is True
    up["internet"] = False
    monitor.check_health()
    assert monitor.state["internet"] is True and not monitor.state["outage_id"]  # one miss is a blip
    monitor.check_health()
    assert monitor.state["internet"] is False and monitor.state["outage_id"]
    ev = monitor.store.one("SELECT * FROM events WHERE kind='outage'")
    assert ev["end_ts"] is None and "internet provider" in ev["detail"]
    up["internet"] = True
    monitor.check_health()
    ev = monitor.store.one("SELECT * FROM events WHERE kind='outage'")
    assert monitor.state["internet"] is True and ev["end_ts"] is not None and "Back after" in ev["detail"]
    assert [n[0] for n in monitor.notes] == ["Internet is down", "Internet is back"]


def test_speedtest_runs_and_records(monitor, monkeypatch):
    monkeypatch.setattr(monitor_mod.time, "sleep", lambda s: None)
    assert monitor.start_speedtest()
    assert not monitor.start_speedtest()  # only one at a time
    for t in threading.enumerate():
        if t.name == "speedtest-run":
            t.join(5)
    row = monitor.store.one("SELECT * FROM speedtests")
    assert row and row["down"] == 900.0 and monitor.state["speedtest"]["error"] is None


def test_pin_and_sessions(tmp_config):
    stored = auth.hash_pin("123456")
    assert auth.check_pin("123456", stored) and not auth.check_pin("123457", stored)
    token = auth.make_session()
    assert auth.valid_session(token)
    assert not auth.valid_session(token[:-1] + ("0" if token[-1] != "0" else "1"))
    assert not auth.valid_session("garbage")
    auth.rotate_secret()
    assert not auth.valid_session(token)


def test_throttle_escalates():
    t = auth.Throttle()
    for _ in range(4):
        t.failure("1.2.3.4")
    assert t.wait_seconds("1.2.3.4") == 0
    t.failure("1.2.3.4")
    assert 55 <= t.wait_seconds("1.2.3.4") <= 60
    t.failure("1.2.3.4")
    assert t.wait_seconds("1.2.3.4") > 100
    assert t.wait_seconds("5.6.7.8") == 0
    t.success("1.2.3.4")
    assert t.wait_seconds("1.2.3.4") == 0


def test_daily_speedtest_window(monitor, monkeypatch):
    from datetime import datetime
    started = []
    monkeypatch.setattr(monitor, "start_speedtest", lambda trigger="manual": started.append(trigger) or True)
    monitor.speedtest_tick(datetime(2026, 9, 30, 19, 52))  # app started long after 04:00: no surprise test
    monitor.speedtest_tick(datetime(2026, 10, 1, 3, 59))
    assert started == []
    monitor.speedtest_tick(datetime(2026, 10, 1, 4, 0))
    monitor.speedtest_tick(datetime(2026, 10, 1, 4, 30))  # only once per day
    assert started == ["scheduled"]
    monitor.speedtest_tick(datetime(2026, 10, 2, 5, 30))  # PC woke at 5:30: still within the catch-up window
    assert started == ["scheduled", "scheduled"]
