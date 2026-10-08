"""Later bedtime, per-profile reports, IoT/Guest Wi-Fi alerts, firmware alerts, settings backups, reservations and UPnP."""
import json
from datetime import datetime

import pytest

from orbi import parental, report
from orbi.routerui import parse_log

from .test_advanced import FakeUI, client, wait_job  # noqa: F401  (fixture/helpers)

BEDTIME = {"profile_id": 1, "label": "Bedtime", "days": "0123456", "start": "21:00", "end": "07:00", "enabled": 1}
HOMEWORK = {"profile_id": 1, "label": "Homework", "days": "0123456", "start": "16:00", "end": "18:00", "enabled": 1}
LATE = {"date": "2026-10-07", "minutes": 60}


# ---------- later bedtime tonight ----------
def test_later_bedtime_moves_only_tonights_evening_start():
    at = lambda s: datetime.fromisoformat(s)
    assert parental.rule_active(BEDTIME, at("2026-10-07 21:30"))
    assert not parental.rule_active(BEDTIME, at("2026-10-07 21:30"), LATE)  # an hour later tonight
    assert parental.rule_active(BEDTIME, at("2026-10-07 22:00"), LATE)
    assert parental.rule_active(BEDTIME, at("2026-10-08 06:59"), LATE)  # the morning end doesn't move
    assert not parental.rule_active(BEDTIME, at("2026-10-08 07:00"), LATE)
    assert parental.rule_active(BEDTIME, at("2026-10-08 21:30"), LATE)  # tomorrow night is normal again
    assert parental.rule_active(HOMEWORK, at("2026-10-07 16:30"), LATE)  # afternoon schedules aren't touched
    st = parental.profile_state({"late": LATE}, [BEDTIME], at("2026-10-07 20:00"))
    assert not st["blocked"] and st["until"] == at("2026-10-07 22:00")


def test_late_night_date_and_attach():
    assert parental.late_night_date(datetime(2026, 10, 8, 1, 30)) == "2026-10-07"  # still last night
    assert parental.late_night_date(datetime(2026, 10, 7, 15, 0)) == "2026-10-07"
    ps = parental.with_late([{"id": 1}, {"id": 2}], {"1": LATE, "2": {"date": "2026-10-01", "minutes": 30}}, datetime(2026, 10, 7, 20))
    assert ps[0]["late"] == LATE and "late" not in ps[1]


def test_late_bedtime_api(client):
    pid = client.post("/api/profiles", json={"name": "Kid"}).json()["id"]
    assert client.post("/api/family/late-bedtime", json={"minutes": 60}).status_code == 400  # nobody has a schedule yet
    client.post(f"/api/profiles/{pid}/rules", json={"label": "Bedtime", "days": "0123456", "start": "21:00", "end": "07:00"})
    assert client.post("/api/family/late-bedtime", json={"minutes": 5}).status_code == 400
    assert client.post("/api/family/late-bedtime", json={"minutes": 90}).status_code == 200
    assert client.get("/api/family/late-bedtime").json()[str(pid)]["minutes"] == 90
    assert client.get("/api/profiles").json()[0]["late_minutes"] == 90
    assert client.delete("/api/family/late-bedtime").status_code == 200
    assert client.get("/api/family/late-bedtime").json() == {}


# ---------- per-profile report ----------
LOG = """[site blocked: chatgpt] from source 192.168.1.20 Wednesday, Oct 07,2026 16:00:02
[site blocked: chatgpt] from source 192.168.1.20 Wednesday, Oct 07,2026 16:00:01
[service blocked: Block-DoT-853] from source 192.168.1.20 Wednesday, Oct 07,2026 15:00:00
[service blocked: Block-VPN-OpenVPN] from source 192.168.1.20 Wednesday, Oct 07,2026 14:00:00
[site blocked: tiktok] from source 192.168.1.20 Wednesday, Oct 07,2026 10:00:00
[DHCP IP: (192.168.1.20)] to MAC address AA:00:00:00:00:01, Wednesday, Oct 07,2026 09:00:00
[site blocked: tiktok] from source 192.168.1.20 Wednesday, Oct 07,2026 08:00:00
[DHCP IP: (192.168.1.20)] to MAC address BB:00:00:00:00:99, Wednesday, Oct 07,2026 07:00:00
"""


def _ingest(store, text):
    for r in parse_log(text):
        store.x("INSERT OR IGNORE INTO router_log(ts,kind,source,text) VALUES(?,?,?,?)", (r["ts"], r["kind"], r["source"], r["text"]))


def test_report_maps_addresses_to_devices_over_time(monitor):
    monitor.scan()
    _ingest(monitor.store, LOG)
    rep = report.build(monitor.store, {"AA:00:00:00:00:01"}, datetime(2026, 10, 7).timestamp())
    d = rep["devices"]["AA:00:00:00:00:01"]
    # 08:00's tiktok was another device (192.168.1.20 belonged to BB:... until 09:00)
    assert d["sites"] == {"chatgpt": 2, "tiktok": 1} and d["bypass"] == {"Block-DoT-853": 1} and d["vpn"] == {"Block-VPN-OpenVPN": 1}
    assert report.summary(rep).startswith("Blocked sites 3× (chatgpt 2, tiktok 1)")


def test_report_api(client, monitor):
    pid = client.post("/api/profiles", json={"name": "Kid"}).json()["id"]
    client.patch("/api/devices/AA:00:00:00:00:01", json={"profile_id": pid})
    _ingest(monitor.store, LOG)
    r = client.get(f"/api/profiles/{pid}/report?days=90").json()
    assert r["devices"][0]["name"] == "kid-phone" and r["totals"]["sites"] == 3


def test_weekly_reports_once_a_week(monitor, monkeypatch):
    monitor.scan()
    pid = monitor.store.x("INSERT INTO profiles(name, created) VALUES('Kid', 0)")
    monitor.store.x("INSERT INTO rules(profile_id,label,days,start,end,enabled) VALUES(?,?,?,?,?,1)", (pid, "Bedtime", "0123456", "21:00", "07:00"))
    monitor.store.x("UPDATE devices SET profile_id=? WHERE mac='AA:00:00:00:00:01'", (pid,))
    _ingest(monitor.store, LOG)
    monkeypatch.setattr(monitor, "backup_router", lambda: {})
    sunday = datetime(2026, 10, 11, 18, 30)
    monkeypatch.setattr("orbi.monitor.time.time", lambda: datetime(2026, 10, 11, 18, 30).timestamp())
    monitor._weekly_tick(sunday)
    monitor._weekly_tick(sunday)
    ev = monitor.store.q("SELECT * FROM events WHERE kind='report'")
    assert len(ev) == 1 and ev[0]["title"] == "Weekly report: Kid" and "chatgpt 2" in ev[0]["detail"]


# ---------- kids' devices on the IoT / Guest Wi-Fi ----------
def test_alert_when_restricted_device_joins_iot(monitor, fake_router):
    pid = monitor.store.x("INSERT INTO profiles(name, created) VALUES('Kid', 0)")
    monitor.store.x("INSERT INTO rules(profile_id,label,days,start,end,enabled) VALUES(?,?,?,?,?,1)", (pid, "Bedtime", "0123456", "21:00", "07:00"))
    adult = monitor.store.x("INSERT INTO profiles(name, created) VALUES('Adults', 0)")
    monitor.scan()
    monitor.store.x("UPDATE devices SET profile_id=? WHERE mac='AA:00:00:00:00:01'", (pid,))
    monitor.store.x("UPDATE devices SET profile_id=? WHERE mac='AA:00:00:00:00:02'", (adult,))
    fake_router.devs[0].update(ssid="Home-IoT", connection="2.4GHz - IoT")
    fake_router.devs[1].update(ssid="Home-IoT", connection="2.4GHz - IoT")
    monitor.scan()
    monitor.scan()  # still there: no repeat
    ev = monitor.store.q("SELECT * FROM events WHERE kind='network_join'")
    assert [e["title"] for e in ev] == ["kid-phone joined the IoT Wi-Fi"] and ev[0]["severity"] == "warn"
    fake_router.devs[0].update(ssid="Guest", connection="5GHz")  # FakeRouter's guest network
    monitor.scan()
    assert monitor.store.q("SELECT title FROM events WHERE kind='network_join' ORDER BY id")[-1]["title"] == "kid-phone joined the Guest Wi-Fi"


# ---------- firmware ----------
def test_firmware_alert_once_per_version(monitor, fake_router):
    fake_router.firmware_update = lambda: {"current": "V7.2.8.8", "available": "V7.2.9.1"}
    monitor.check_firmware()
    monitor.check_firmware()
    ev = monitor.store.q("SELECT * FROM events WHERE kind='firmware'")
    assert len(ev) == 1 and ev[0]["title"] == "Router firmware V7.2.9.1 is available"
    assert [n[0] for n in monitor.notes].count("Router firmware update") == 1


# ---------- settings backup ----------
def test_backup_keeps_the_last_eight(monitor, monkeypatch, tmp_config):
    import orbi.routerui as rui
    monkeypatch.setattr(rui, "fetch_backup", lambda host, pw, user, model: b"\x00cfg" * 600)
    stamps = iter(range(20))
    monkeypatch.setattr("orbi.monitor.datetime", type("D", (), {"now": staticmethod(lambda: datetime(2026, 10, 1, 0, next(stamps)))}))
    for _ in range(10):
        monitor.backup_router()
    files = sorted((tmp_config / "router-backups").glob("*.cfg"))
    assert len(files) == 8 and files[-1].name == "NETGEAR_RBR750-2026-10-01_0009.cfg"
    assert monitor.store.get("router_backup")["size"] == 2400


def test_backup_api(client, monkeypatch):
    import orbi.routerui as rui
    monkeypatch.setattr(rui, "fetch_backup", lambda host, pw, user, model: b"x" * 2048)
    assert client.post("/api/router-backup", json={}).status_code == 200
    assert wait_job(client, "backup")["error"] is None
    assert len(client.get("/api/router-backup").json()["files"]) == 1


# ---------- reservations and UPnP ----------
def test_reservation_api(client):
    for bad in ({"ip": "8.8.8.8", "mac": "AA:BB:CC:11:22:33"}, {"ip": "192.168.1.1", "mac": "AA:BB:CC:11:22:33"},
                {"ip": "192.168.1.50", "mac": "nope"}, {"ip": "192.168.1.50", "mac": "AA:BB:CC:11:22:33", "name": "<b>"}):
        assert client.post("/api/reservations", json=bad).status_code == 400, bad
    assert client.post("/api/reservations", json={"ip": "192.168.1.50", "mac": "aa-bb-cc-11-22-33", "name": "Kid laptop"}).status_code == 200
    assert wait_job(client, "reservation")["error"] is None
    assert FakeUI.calls[0] == ("add_reservation", "192.168.1.50", "AA:BB:CC:11:22:33", "Kid laptop")
    client.put("/api/reservations/2", json={"expected_mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.51", "mac": "AA:BB:CC:11:22:33", "name": "Kid laptop"})
    wait_job(client, "reservation")
    client.delete("/api/reservations/2?mac=AA:BB:CC:11:22:33")
    wait_job(client, "reservation")
    assert [c[0] for c in FakeUI.calls] == ["add_reservation", "edit_reservation", "delete_reservation"]


def test_upnp_api(client):
    assert client.put("/api/upnp", json={"enabled": False}).status_code == 200
    assert wait_job(client, "upnp")["error"] is None
    assert FakeUI.calls == [("upnp", False)]
    assert client.get("/api/events?kind=action").json()[0]["title"] == "UPnP turned off"



# ---------- security review (2026-10-07) ----------
def test_text_sent_to_router_pages_cant_break_out(client):
    for body in ({"enabled": True, "ssid": 'Home"<script>', "band": "2.4"},
                 {"enabled": True, "ssid": "Home", "band": "2.4", "password": 'abc"defgh</'}):
        assert client.put("/api/iot", json=body).status_code == 400, body
    for body in ({"enabled": True, "provider": "No-IP", "host": "home.ddns.net", "user": 'me"<x>'},
                 {"enabled": True, "provider": "No-IP", "host": "home.ddns.net", "user": "me", "password": "pa`ss"}):
        assert client.put("/api/ddns", json=body).status_code == 400, body
    assert client.post("/api/reservations", json={"ip": "192.168.1.50", "mac": "AA:BB:CC:11:22:33", "name": 'x"y'}).status_code == 400


def test_backup_file_name_ignores_odd_model_names(monitor, monkeypatch, tmp_config):
    import orbi.routerui as rui
    monkeypatch.setattr(rui, "fetch_backup", lambda host, pw, user, model: b"x" * 2048)
    monitor.state["info"] = {"model": "..\\..\\evil/RBR750"}
    info = monitor.backup_router()
    assert info["file"].startswith("NETGEAR_evilRBR750-") and (tmp_config / "router-backups" / info["file"]).exists()


def test_loosening_actions_notify(client, monitor):
    pid = client.post("/api/profiles", json={"name": "Kid"}).json()["id"]
    client.post(f"/api/profiles/{pid}/rules", json={"label": "Bedtime", "days": "0123456", "start": "21:00", "end": "07:00"})
    client.post("/api/family/late-bedtime", json={"minutes": 60})
    client.put("/api/upnp", json={"enabled": True})
    wait_job(client, "upnp")
    assert {"Later bedtime tonight", "UPnP turned on"} <= {n[0] for n in monitor.notes}
    ev = client.get("/api/events?kind=parental").json()[0]
    assert ev["severity"] == "warn" and "by " in ev["detail"]  # recorded with who did it


def test_every_api_endpoint_requires_sign_in(client):
    """Regression guard: new endpoints must sit behind the sign-in check (only session/login/setup are open)."""
    from orbi.web import OPEN_PATHS
    client.cookies.clear()
    checked = 0
    for r in client.app.routes:
        path = getattr(r, "path", "")
        if not path.startswith("/api/") or path in OPEN_PATHS:
            continue
        for method in r.methods - {"HEAD", "OPTIONS"}:
            url = re_sub_params(path)
            assert client.request(method, url, json={}).status_code == 401, (method, path)
            checked += 1
    assert checked > 60


def re_sub_params(path: str) -> str:
    import re
    return re.sub(r"\{(\w+)\}", lambda m: {"pid": "1", "index": "0", "rid": "1"}.get(m.group(1), "x"), path)
