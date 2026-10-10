import threading
import time

import orbi.monitor as monitor_mod
from orbi import auth, parental

from .conftest import ROUTER_MAC, SAT_MAC


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


def test_satellite_offline_detected_by_direct_probe(monitor):
    monitor.scan()
    reachable = {"192.168.1.38": True}
    orig = monitor_mod.tcp_ok
    monitor_mod.tcp_ok = lambda host, port, timeout=3.0: 1.0 if reachable.get(host, True) else None
    try:
        reachable["192.168.1.38"] = False
        monitor.check_satellites()
        assert not monitor.store.q("SELECT * FROM events WHERE kind='satellite'")
        monitor.check_satellites()
        ev = monitor.store.q("SELECT * FROM events WHERE kind='satellite'")
        assert len(ev) == 1 and "offline" in ev[0]["title"]
        assert monitor.notes[-1][0] == "Orbi satellite offline"
        assert monitor.state["satellites"][0]["online"] is False
        monitor.check_satellites()  # no repeat alert while it stays down
        assert len(monitor.store.q("SELECT * FROM events WHERE kind='satellite'")) == 1
        reachable["192.168.1.38"] = True
        monitor.check_satellites()
        assert monitor.notes[-1][0] == "Satellite back online"
        assert monitor.store.get("satellites", {})[SAT_MAC]["online"] is True
    finally:
        monitor_mod.tcp_ok = orig


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
    release = threading.Event()  # hold the test open so "one at a time" is checked while it's really running
    poll = monitor.router.speedtest_poll
    monkeypatch.setattr(monitor.router, "speedtest_poll", lambda: release.wait(5) and poll())
    assert monitor.start_speedtest()
    assert not monitor.start_speedtest()  # only one at a time
    release.set()
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
    for _ in range(5):
        assert t.attempt("1.2.3.4") == 0  # each attempt counts as a miss until success()
    assert 55 <= t.wait_seconds("1.2.3.4") <= 60
    assert t.attempt("1.2.3.4") > 0  # locked: refused without being checked
    t._state["1.2.3.4"]["until"] = 0  # let the lockout expire
    assert t.attempt("1.2.3.4") == 0
    assert t.wait_seconds("1.2.3.4") > 100  # doubled
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


def test_idle_sessions_sign_out(tmp_config, monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    token = auth.make_session()
    now[0] += 29 * 60
    assert auth.valid_session(token, touch=True)  # used: the 30 minutes start again
    now[0] += 29 * 60
    assert auth.valid_session(token)
    now[0] += 2 * 60  # 31 minutes since it was last used
    assert not auth.valid_session(token, touch=True)
    now[0] -= 30 * 60  # and it stays signed out
    assert not auth.valid_session(token)


def test_throttle_misses_expire(monkeypatch):
    now = [1_000_000.0]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    t = auth.Throttle()
    for day in range(40):  # a typo a day from various devices never locks anyone out
        ip = f"192.168.1.{day % 5 + 10}"
        assert t.attempt(ip) == 0
        t.failure(ip)
        now[0] += 86400
    assert t.wait_seconds("192.168.1.99") == 0


def test_house_lockout_spares_this_pc_and_success_does_not_relock():
    t = auth.Throttle()
    for i in range(auth.Throttle.HOUSE + 6):
        ip = f"192.168.1.{i // 4 + 10}"
        if t.attempt(ip) == 0:
            t.failure(ip)
    assert t.wait_seconds("192.168.1.200") > 0  # other devices are locked out house-wide
    assert t.wait_seconds("127.0.0.1") == 0  # the PC itself isn't
    before = t._state["*"]["until"]
    assert t.attempt("127.0.0.1") == 0
    t.success("127.0.0.1")
    assert t._state["*"]["until"] == before  # signing in correctly doesn't extend anyone's lockout


def test_removing_an_extra_pin_signs_out_its_sessions(tmp_config):
    main, spare = auth.make_session(""), auth.make_session("Spare")
    auth.revoke_pin_sessions("Spare")
    assert auth.valid_session(main) and not auth.valid_session(spare)


def test_backhaul_kind():
    from orbi.router import backhaul_kind
    assert [backhaul_kind(v) for v in ("wired", "Wired", "5GHz", "2.4GHz", "", None, "???")] == \
        ["wired", "wired", "wireless", "wireless", None, None, None]


def test_satellite_dropping_to_wireless_backhaul_alerts(monitor, fake_router):
    sat = fake_router.sats[0]
    sat["backhaul"] = "wired"
    monitor.scan()
    sat["backhaul"] = "5GHz"
    monitor.scan()  # one scan could be a blip while it re-links
    assert monitor.notes == [] and monitor.state["satellites"][0]["backhaul_kind"] == "wired"
    monitor.scan()
    assert monitor.notes == [("Satellite lost its wired link", "Garage Satellite switched to wireless backhaul (5GHz)")]
    s = monitor.state["satellites"][0]
    assert s["backhaul_kind"] == "wireless" and s["usually_wired"]
    ev = monitor.store.q("SELECT * FROM events WHERE kind='satellite'")
    assert len(ev) == 1 and ev[0]["severity"] == "warn"
    monitor.scan()  # still wireless: no repeat alert
    assert len(monitor.notes) == 1
    sat["backhaul"] = "wired"
    monitor.scan()
    monitor.scan()
    assert monitor.notes[-1] == ("Satellite wired again", "Garage Satellite is using its Ethernet backhaul again")


def test_wireless_satellite_blip_is_ignored(monitor, fake_router):
    sat = fake_router.sats[0]
    sat["backhaul"] = "wired"
    monitor.scan()
    sat["backhaul"] = "5GHz"
    monitor.scan()
    sat["backhaul"] = "wired"
    monitor.scan()
    assert monitor.notes == [] and not monitor.store.q("SELECT * FROM events WHERE kind='satellite'")



def _pc_cut_off(monitor, monkeypatch, up):
    monkeypatch.setattr(monitor_mod, "tcp_ok", lambda host, port, timeout=3.0: 5.0 if (up["pc"] or host.startswith("192.168")) else None)


def test_vpn_drop_is_not_an_outage(monitor, monkeypatch):
    up = {"pc": True}
    _pc_cut_off(monitor, monkeypatch, up)
    monkeypatch.setattr(monitor_mod, "house_online", lambda host: True)
    monkeypatch.setattr(monitor_mod, "internet_route", lambda host: {"vpn": True, "local_ip": "10.8.0.2"})
    monkeypatch.setattr(monitor_mod, "adapter_name", lambda ip: "WireGuard Tunnel")
    monitor.check_health()
    up["pc"] = False
    monitor.check_health()
    monitor.check_health()
    assert monitor.state["internet"] is True and not monitor.state["outage_id"]
    ev = monitor.store.one("SELECT * FROM events WHERE kind='pc_offline'")
    assert ev["title"] == "Your VPN dropped; the internet is fine" and "WireGuard Tunnel (10.8.0.2)" in ev["detail"]
    assert not monitor.store.q("SELECT * FROM events WHERE kind='outage'")
    assert monitor.store.one("SELECT MIN(internet) AS m FROM checks")["m"] == 1  # uptime isn't charged for it
    up["pc"] = True
    monitor.check_health()
    assert monitor.store.one("SELECT * FROM events WHERE kind='pc_offline'")["end_ts"] is not None
    assert [n[0] for n in monitor.notes] == ["Your VPN dropped; the internet is fine", "This PC is back online"]


def test_pc_only_drop_without_vpn(monitor, monkeypatch):
    up = {"pc": False}
    _pc_cut_off(monitor, monkeypatch, up)
    monkeypatch.setattr(monitor_mod, "house_online", lambda host: True)
    monitor.check_health()
    monitor.check_health()
    assert monitor.notes[0][0] == "This PC lost internet; the rest of the house is online"


def test_outage_reports_router_restart_and_new_ip(monitor, monkeypatch, fake_router):
    up = {"pc": True}
    _pc_cut_off(monitor, monkeypatch, up)
    monitor.scan()
    monitor.check_health()
    up["pc"] = False
    monitor.check_health()
    monitor.check_health()
    assert monitor.state["outage_id"]
    fake_router.wan = lambda: {"link_up": True, "ip": "5.6.7.8", "dns": []}
    fake_router.uptime = lambda: "00:02:10"
    up["pc"] = True
    monitor.check_health()
    ev = monitor.store.one("SELECT * FROM events WHERE kind='outage'")
    assert "router restarted" in ev["detail"] and "1.2.3.4 → 5.6.7.8" in ev["detail"]


def test_uptime_seconds():
    assert monitor_mod.uptime_seconds("2 days 07:21:36") == 2 * 86400 + 7 * 3600 + 21 * 60 + 36
    assert monitor_mod.uptime_seconds("1 day 00:00:05") == 86405
    assert monitor_mod.uptime_seconds("00:02:10") == 130
    assert monitor_mod.uptime_seconds("soon") is None


def test_only_real_upstream_answers_count():
    import dns.message
    import dns.rcode
    import dns.rrset
    q = dns.message.make_query("orbi-check-abc.example.com", "A")
    made_up = dns.message.make_response(q)
    made_up.set_rcode(dns.rcode.NXDOMAIN)  # a router answering by itself has no SOA for the zone
    assert not monitor_mod.upstream_answered(made_up)
    real = dns.message.make_response(q)
    real.set_rcode(dns.rcode.NXDOMAIN)
    real.authority.append(dns.rrset.from_text("example.com.", 3600, "IN", "SOA",
                                              "ns.icann.org. noc.dns.icann.org. 2025 7200 3600 1209600 3600"))
    assert monitor_mod.upstream_answered(real)
    nodata = dns.message.make_response(q)  # what example.com really returns today: no records, plus its SOA
    nodata.authority.append(dns.rrset.from_text("example.com.", 1800, "IN", "SOA",
                                                "elliott.ns.cloudflare.com. dns.cloudflare.com. 2416 10000 2400 604800 1800"))
    assert monitor_mod.upstream_answered(nodata)
    assert not monitor_mod.upstream_answered(dns.message.make_response(q))  # empty NOERROR, no SOA
    failed = dns.message.make_response(q)
    failed.set_rcode(dns.rcode.SERVFAIL)
    assert not monitor_mod.upstream_answered(failed)


def _lease(store, ip, mac, ts):
    store.x("INSERT INTO router_log(ts,kind,source,text) VALUES(?,?,?,?)",
            (ts, f"DHCP IP: ({ip})", "", f"[DHCP IP: ({ip})] to MAC address {mac}, Thursday"))


def test_alert_when_a_device_takes_another_devices_address(monitor, fake_router):
    """A laptop sets its address by hand to the Echo's: the router's DHCP gave that address to someone else."""
    import time as _t
    monitor.scan()
    _lease(monitor.store, "192.168.1.20", "AA:00:00:00:00:01", _t.time() - 3600)  # kid-phone's lease
    fake_router.devs.append(fake_router._dev("AA:00:00:00:00:09", "Echo-Spot", "192.168.1.20", ROUTER_MAC))
    monitor.scan()  # seen, but the router log hasn't been read since: maybe it just got a lease
    assert not monitor.store.q("SELECT * FROM events WHERE kind='address'")
    monitor.state["log_ingested"] = _t.time() + 1
    monitor.scan()
    monitor.scan()  # once a day, not every scan
    ev = monitor.store.q("SELECT * FROM events WHERE kind='address'")
    assert len(ev) == 1 and ev[0]["title"].endswith("is using kid-phone's address") and ev[0]["mac"] == "AA:00:00:00:00:09"
    assert ev[0]["severity"] == "error"


def test_no_address_alert_for_a_fresh_lease(monitor, fake_router):
    """The router handed the address on: the latest lease names the new device."""
    import time as _t
    monitor.scan()
    _lease(monitor.store, "192.168.1.20", "AA:00:00:00:00:01", _t.time() - 7200)
    _lease(monitor.store, "192.168.1.20", "AA:00:00:00:00:09", _t.time() - 60)
    fake_router.devs[0]["ip"] = "192.168.1.30"  # kid-phone moved on to another address
    _lease(monitor.store, "192.168.1.30", "AA:00:00:00:00:01", _t.time() - 30)
    fake_router.devs.append(fake_router._dev("AA:00:00:00:00:09", "new-phone", "192.168.1.20", ROUTER_MAC))
    monitor.state["log_ingested"] = _t.time() + 1
    monitor.scan()
    monitor.state["log_ingested"] = _t.time() + 2
    monitor.scan()
    assert not monitor.store.q("SELECT * FROM events WHERE kind='address'")


def test_reports_credit_a_borrowed_address_to_the_device_using_it(monitor, fake_router):
    """The weekly report blamed the real Echo for what a fake one did from its address."""
    import time as _t
    from orbi import report
    now = _t.time()
    monitor.scan()
    _lease(monitor.store, "192.168.1.20", "AA:00:00:00:00:01", now - 7200)  # kid-phone's lease
    fake_router.devs.append(fake_router._dev("AA:00:00:00:00:09", "Echo-Spot", "192.168.1.20", ROUTER_MAC))
    monitor.scan()
    monitor.scan()  # the same stay: one sighting, not two
    assert len(monitor.store.q("SELECT * FROM address_sightings")) == 1
    for ts in (now - 5400, now - 60):  # before the fake turned up, and while it was there
        monitor.store.x("INSERT INTO router_log(ts,kind,source,text) VALUES(?,?,?,?)",
                        (ts, "service blocked: Block-External-DNS-2", "192.168.1.20", f"[service blocked: Block-External-DNS-2] {ts}"))
    rep = report.build(monitor.store, {"AA:00:00:00:00:01", "AA:00:00:00:00:09"}, now - 86400)["devices"]
    assert rep["AA:00:00:00:00:09"]["bypass"] == {"Block-External-DNS-2": 1}
    assert rep["AA:00:00:00:00:01"]["bypass"] == {"Block-External-DNS-2": 1}
