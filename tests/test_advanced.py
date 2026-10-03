import time

import pytest
from fastapi.testclient import TestClient

from orbi import filtering
from orbi.routerui import parse_log, parse_rule_rows, parse_schedule
from orbi.web import create_app

LOG = """[Admin login] from source 192.168.1.58, Wednesday, Sep 30,2026 22:04:50
[service blocked: Block-VPN-OpenVPN] from source 192.168.1.20 Wednesday, Sep 30,2026 22:04:15
[DHCP IP: (192.168.1.28)] to MAC address 78:28:CA:C3:8C:BA, Wednesday, Sep 30,2026 21:41:38
[Admin login failure] from source 192.168.1.99, Wednesday, Sep 30,2026 21:30:00
 Thursday, Jun 26,981883 09:00:00
"""


def test_parse_log():
    rows = parse_log(LOG)
    assert [r["kind"] for r in rows] == ["Admin login", "service blocked: Block-VPN-OpenVPN", "DHCP IP: (192.168.1.28)", "Admin login failure"]
    assert rows[1]["source"] == "192.168.1.20"
    assert rows[2]["source"] == ""
    assert time.localtime(rows[0]["ts"]).tm_hour == 22


def test_parse_rules_and_schedule():
    rows = [["", "#", "Service Type", "Port", "IP"], ["", "1", "Block External DNS", "53", "192.168.1.2 - 192.168.1.15"],
            ["", "2", "Block-VPN-WireGuard", "51820", "all"], ["Help", "Center"]]
    assert parse_rule_rows(rows) == [{"name": "Block External DNS", "port": "53", "ips": "192.168.1.2 - 192.168.1.15"},
                                     {"name": "Block-VPN-WireGuard", "port": "51820", "ips": "all"}]
    weekdays = {"schedule_day": str(2 + 4 + 8 + 16 + 32), "schedule_starthour": "8", "schedule_startminute": "0",
                "schedule_endhour": "15", "schedule_endminute": "30"}
    assert parse_schedule(weekdays) == {"days": "01234", "all_day": False, "start": "08:00", "end": "15:30"}
    everyday = {"schedule_day": "127", "checkboxNamehours": "checkboxValue", "schedule_endhour": "23", "schedule_endminute": "59"}
    assert parse_schedule(everyday) == {"days": "0123456", "all_day": True, "start": "00:00", "end": "00:00"}


def test_provider_detection():
    assert filtering.provider_for(["94.140.14.15", "94.140.15.16"]) == "adguard_family"
    assert filtering.provider_for(["185.228.168.10"]) == "cleanbrowsing_adult"
    assert filtering.provider_for(["8.8.8.8"]) is None


def test_log_ingestion_alerts_once(monitor):
    monitor.scan()  # kid-phone is 192.168.1.20
    batches = [parse_log(LOG)]
    monitor.log_fetcher = lambda: batches[-1]
    monitor.ingest_router_log()  # first run: backlog only
    assert monitor.store.q("SELECT * FROM events WHERE kind IN ('vpn_attempt','admin_fail')") == []
    newer = """[service blocked: Block-VPN-OpenVPN] from source 192.168.1.20 Wednesday, Sep 30,2026 23:00:01
[service blocked: Block-VPN-WireGuard] from source 192.168.1.20 Wednesday, Sep 30,2026 23:00:05
[Admin login failure] from source 192.168.1.99, Wednesday, Sep 30,2026 23:01:00
"""
    batches.append(parse_log(newer + LOG))
    monitor.ingest_router_log()
    vpn = monitor.store.q("SELECT * FROM events WHERE kind='vpn_attempt'")
    assert len(vpn) == 1 and vpn[0]["title"] == "kid-phone tried to use a VPN" and vpn[0]["mac"] == "AA:00:00:00:00:01"
    assert len(monitor.store.q("SELECT * FROM events WHERE kind='admin_fail'")) == 1
    assert {n[0] for n in monitor.notes} >= {"VPN attempt blocked", "Router login failed"}
    monitor.ingest_router_log()  # same log again: nothing new
    assert len(monitor.store.q("SELECT * FROM events WHERE kind='vpn_attempt'")) == 1
    assert monitor.store.one("SELECT COUNT(*) c FROM router_log")["c"] == 7


class FakeUI:
    calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read_all(self):
        return {"wan": {"type": "dhcp", "ip": "1.2.3.4", "gateway": "1.2.3.1", "netmask": "255.255.255.0", "dns_mode": "manual",
                        "dns": ["94.140.14.15", "94.140.15.16"], "isp_dns": ["74.40.74.40"], "mac": "X"},
                "lan": {"ip": "192.168.1.1", "netmask": "255.255.255.0", "dhcp_enabled": True, "dhcp_start": "192.168.1.2",
                        "dhcp_end": "192.168.1.254", "reservations": []},
                "block_services": {"mode": "always", "rules": [{"name": "Block-VPN-OpenVPN", "port": "1194", "ips": "all"}]},
                "block_sites": {"mode": "never", "keywords": [], "trusted_ip": None},
                "schedule": {"days": "0123456", "all_day": True, "start": "00:00", "end": "00:00"},
                "vpn": {"enabled": True, "protocol": "udp", "port": "12973", "port_tap": "12974"}, "upnp": []}

    def set_schedule(self, days, start, end):
        FakeUI.calls.append(("schedule", days, start, end))

    def set_block_sites(self, mode, keywords):
        FakeUI.calls.append(("sites", mode, tuple(keywords)))


def wait_job(client, name):
    for _ in range(100):
        j = client.get(f"/api/jobs/{name}").json()
        if not j["running"]:
            return j
        time.sleep(0.05)
    raise AssertionError("job never finished")


@pytest.fixture
def client(monitor):
    monitor.scan()
    monitor.ui_factory = FakeUI
    FakeUI.calls = []
    c = TestClient(create_app(monitor))
    c.post("/api/setup", json={"pin": "246810"})
    return c


def test_advanced_and_siteblock(client):
    first = client.get("/api/advanced").json()
    assert first["data"] is None or first["data"]["vpn"]["enabled"]
    wait_job(client, "advanced")
    adv = client.get("/api/advanced").json()
    assert adv["data"]["vpn"]["port"] == "12973" and adv["data"]["uptime"] is not None
    assert client.put("/api/siteblock", json={"mode": "always", "keywords": []}).status_code == 400
    assert client.put("/api/siteblock", json={"mode": "always", "keywords": ["tik tok!"]}).status_code == 400
    assert client.put("/api/siteblock", json={"mode": "perschedule", "keywords": ["tiktok"], "days": "", "start": "08:00", "end": "15:00"}).status_code == 400
    r = client.put("/api/siteblock", json={"mode": "perschedule", "keywords": ["TikTok", "roblox", "tiktok"], "days": "40123", "start": "08:00", "end": "15:00"})
    assert r.status_code == 200
    assert wait_job(client, "siteblock")["error"] is None
    assert FakeUI.calls[:2] == [("schedule", "01234", "08:00", "15:00"), ("sites", "perschedule", ("roblox", "tiktok"))]


def test_filtering_endpoints(client, monitor, monkeypatch):
    monkeypatch.setattr(filtering, "apply_provider", lambda host, pw, key: {"ok": True, "confirmed": True, "provider": key})
    monitor.state["wan"] = {"dns": ["185.228.168.10", "185.228.169.11"]}
    assert client.get("/api/filtering").json()["current"] == "cleanbrowsing_adult"
    assert client.post("/api/filtering", json={"provider": "nope"}).status_code == 400
    assert client.post("/api/filtering", json={"provider": "adguard_family"}).status_code == 200
    j = wait_job(client, "filtering")
    assert j["error"] is None and j["result"]["confirmed"]
    assert client.get("/api/events?kind=action").json()[0]["title"] == "Content filter changed to AdGuard Family"


def test_routerlog_endpoint(client, monitor):
    monitor.log_fetcher = lambda: parse_log(LOG)
    monitor.ingest_router_log()
    rows = client.get("/api/routerlog?kind=dhcp").json()["rows"]
    assert len(rows) == 1 and "78:28:CA:C3:8C:BA" in rows[0]["text"]
    blocked = client.get("/api/routerlog?kind=blocked").json()["rows"]
    assert blocked[0]["device"] == "kid-phone"
    assert len(client.get("/api/routerlog?q=192.168.1.99").json()["rows"]) == 1
