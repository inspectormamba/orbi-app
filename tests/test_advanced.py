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
                "vpn": {"enabled": True, "protocol": "udp", "port": "12973", "port_tap": "12974"}, "upnp": [],
                "iot": {"enabled": True, "ssid": "Home-IoT", "band": "2.4", "security": "WPA2-PSK"}}

    def set_schedule(self, days, start, end):
        FakeUI.calls.append(("schedule", days, start, end))

    def set_block_sites(self, mode, keywords):
        FakeUI.calls.append(("sites", mode, tuple(keywords)))

    def add_rule(self, name, protocol, start, end, applies):
        FakeUI.calls.append(("add_rule", name, protocol, start, end, applies))

    def edit_rule(self, index, expected, name, protocol, start, end, applies):
        FakeUI.calls.append(("edit_rule", index, expected, name, protocol, start, end, applies))

    def delete_rule(self, index, expected):
        FakeUI.calls.append(("delete_rule", index, expected))

    def set_rules_mode(self, mode):
        FakeUI.calls.append(("rules_mode", mode))

    def read_iot(self):
        return {"enabled": True, "ssid": "Home-IoT", "band": "2.4", "security": "WPA2-PSK"}

    def set_iot(self, enabled, ssid, band, security, password=None):
        FakeUI.calls.append(("iot", enabled, ssid, band, security, password))
        return {"enabled": enabled, "ssid": ssid, "band": band, "security": security}


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


def test_changes_say_who_made_them(client):
    assert client.post("/api/login", json={"pin": "246810"}).status_code == 200
    r = client.put("/api/siteblock", json={"mode": "always", "keywords": ["tiktok"]})
    assert r.status_code == 200 and wait_job(client, "siteblock")["error"] is None
    events = client.get("/api/events?kind=action").json()
    blocking = next(e for e in events if e["title"] == "Whole-house blocking updated")
    assert "by Device at testclient" in blocking["detail"]  # set inside a background job, still attributed
    assert any(e["title"] == "Signed in to Orbi Control" for e in events)


def test_loosened_blocking_alerts(monitor):
    monitor._watch_block_sites({"mode": "always", "keywords": ["chatgpt.com", "openai.com", "tiktok"]})
    monitor._watch_block_sites({"mode": "always", "keywords": ["chatgpt.com", "openai.com", "tiktok", "roblox"]})
    assert monitor.notes == []  # adding sites is not an alert
    monitor._watch_block_sites({"mode": "always", "keywords": ["roblox", "tiktok"]})
    assert monitor.notes == [("Blocked sites were unblocked", "No longer blocked: chatgpt.com, openai.com")]
    monitor._watch_block_sites({"mode": "never", "keywords": ["roblox", "tiktok"]})
    assert monitor.notes[-1] == ("Blocked sites were unblocked", "No longer blocked: roblox, tiktok")
    ev = monitor.store.q("SELECT * FROM events WHERE kind='block_loosened'")
    assert len(ev) == 2 and all(e["severity"] == "warn" for e in ev)


def test_filter_turned_off_alerts(monitor):
    monitor._watch_filter(["1.1.1.3", "1.0.0.3"])
    monitor._watch_filter(["1.1.1.3", "1.0.0.3"])
    assert monitor.notes == []
    monitor._watch_filter(["74.40.74.40", "74.40.74.41"])
    assert monitor.notes == [("Content filter turned off", "The router no longer uses Cloudflare for Families")]



def test_firewall_rule_api(client):
    bad = [
        {"name": "x!", "port_start": 25},  # name
        {"name": "Mail", "port_start": 0},  # port
        {"name": "Mail", "port_start": 30, "port_end": 20},  # backwards range
        {"name": "Mail", "port_start": 25, "protocol": "ICMP"},
        {"name": "Mail", "port_start": 25, "applies": "single", "ip": "8.8.8.8"},  # not on the LAN
        {"name": "Mail", "port_start": 25, "applies": "range", "ip": "192.168.1.50", "ip_end": "192.168.1.20"},
    ]
    for body in bad:
        assert client.post("/api/firewall/rules", json=body).status_code == 400, body
    r = client.post("/api/firewall/rules", json={"name": "Block-Minecraft", "protocol": "TCP", "port_start": 25565, "applies": "range",
                                                 "ip": "192.168.1.20", "ip_end": "192.168.1.40"})
    assert r.status_code == 200 and wait_job(client, "firewall")["error"] is None
    assert FakeUI.calls[0] == ("add_rule", "Block-Minecraft", "TCP", 25565, 25565, {"type": "range", "start": "192.168.1.20", "end": "192.168.1.40"})
    r = client.put("/api/firewall/rules/4", json={"expected_name": "Block-VPN-WireGuard", "name": "Block-VPN-WireGuard", "protocol": "UDP",
                                                  "port_start": 51820, "applies": "all"})
    assert r.status_code == 200 and wait_job(client, "firewall")["error"] is None
    assert ("edit_rule", 4, "Block-VPN-WireGuard", "Block-VPN-WireGuard", "UDP", 51820, 51820, {"type": "all"}) in FakeUI.calls
    assert client.delete("/api/firewall/rules/2?name=Block-DoT-853").status_code == 200 and wait_job(client, "firewall")["error"] is None
    assert ("delete_rule", 2, "Block-DoT-853") in FakeUI.calls
    assert client.put("/api/firewall/mode", json={"mode": "sometimes"}).status_code == 400
    assert client.put("/api/firewall/mode", json={"mode": "never"}).status_code == 200 and wait_job(client, "firewall")["error"] is None
    titles = [e["title"] for e in client.get("/api/events?kind=action").json()]
    assert {"Firewall rule added: Block-Minecraft", "Firewall rule changed: Block-VPN-WireGuard", "Firewall rule deleted: Block-DoT-853",
            "Firewall rules turned off"} <= set(titles)


def test_iot_api(client):
    assert client.put("/api/iot", json={"enabled": True, "ssid": "", "band": "2.4"}).status_code == 400
    assert client.put("/api/iot", json={"enabled": True, "ssid": "Gadgets", "band": "6"}).status_code == 400
    assert client.put("/api/iot", json={"enabled": True, "ssid": "Gadgets", "password": "short"}).status_code == 400
    r = client.put("/api/iot", json={"enabled": True, "ssid": "Gadgets", "band": "both", "security": "WPA2-PSK", "password": "correct horse"})
    assert r.status_code == 200 and wait_job(client, "iot")["error"] is None
    assert FakeUI.calls[0] == ("iot", True, "Gadgets", "both", "WPA2-PSK", "correct horse")
    ev = client.get("/api/events?kind=action").json()[0]
    assert ev["title"] == "IoT Wi-Fi updated" and "new password" in ev["detail"] and "correct horse" not in ev["detail"]
    assert client.put("/api/iot", json={"enabled": False}).status_code == 200 and wait_job(client, "iot")["error"] is None
    assert FakeUI.calls[-1][:2] == ("iot", False)
    assert client.get("/api/advanced").json()["data"]["iot"]["ssid"] == "Home-IoT"  # whatever the router reports, re-read after


def test_loosened_firewall_rules_alert(monitor):
    rules = [{"name": "Block-DoT-853", "port": "853", "ips": "all"}, {"name": "Block-VPN-WireGuard", "port": "51820", "ips": "all"}]
    monitor._watch_block_services({"mode": "always", "rules": rules})
    monitor._watch_block_services({"mode": "always", "rules": rules + [{"name": "New", "port": "1", "ips": "all"}]})
    assert monitor.notes == []
    monitor._watch_block_services({"mode": "always", "rules": [rules[0], {"name": "Block-VPN-WireGuard", "port": "51820", "ips": "192.168.1.58"}]})
    assert monitor.notes[-1] == ("Firewall rules loosened", "Block-VPN-WireGuard now only applies to 192.168.1.58; Removed: New (port 1)")
    monitor._watch_block_services({"mode": "never", "rules": [rules[0]]})
    assert "Firewall rules turned off (Never)" in monitor.notes[-1][1]


def test_protection_rules_widen_ours_and_leave_partial_user_rules(monkeypatch):
    from orbi.routerui import RouterUI
    rules = [{"name": "Block External DNS", "port": "53", "ips": "192.168.1.2 - 192.168.1.15"},
             {"name": "Block External DNS 2", "port": "53", "ips": "192.168.1.17 - 192.168.1.254"},
             {"name": "Block-DoT-853", "port": "853", "ips": "all"},
             {"name": "Block-VPN-OpenVPN", "port": "1194", "ips": "all"},
             {"name": "Block-VPN-WireGuard", "port": "51820", "ips": "192.168.1.58"}]
    ui = RouterUI.__new__(RouterUI)
    calls = []
    monkeypatch.setattr(ui, "read_block_services", lambda: {"mode": "always", "rules": [dict(r) for r in rules]}, raising=False)
    monkeypatch.setattr(ui, "edit_rule", lambda *a: calls.append(("edit",) + a), raising=False)
    monkeypatch.setattr(ui, "add_rule", lambda *a: calls.append(("add",) + a), raising=False)
    changed = ui.ensure_protection_rules()
    assert calls == [("edit", 4, "Block-VPN-WireGuard", "Block-VPN-WireGuard", "UDP", 51820, 51820, {"type": "all"})]
    assert changed == ["Block-VPN-WireGuard (now covers every device)"]


def test_rule_ips_text():
    from orbi.routerui import rule_ips_text
    assert rule_ips_text({"type": "all"}) == "all"
    assert rule_ips_text({"type": "single", "ip": "192.168.1.58"}) == "192.168.1.58"
    assert rule_ips_text({"type": "range", "start": "192.168.1.2", "end": "192.168.1.15"}) == "192.168.1.2 - 192.168.1.15"



def test_devices_show_their_wifi_network(client, monitor, fake_router):
    fake_router.devs[0].update(ssid="Home", connection="5GHz")
    fake_router.devs[1].update(ssid="Home-IoT", connection="2.4GHz - IoT")
    fake_router.devs[2].update(ssid="", connection="wired")
    visitor = fake_router._dev("AA:00:00:00:00:09", "visitor", "192.168.1.90", "C8:9E:43:C2:E3:33", "2.4GHz")
    visitor["ssid"] = "Guest"  # FakeRouter's guest network is called "Guest"
    fake_router.devs.append(visitor)
    monitor.scan()
    nets = {d["name"]: d["network"] for d in client.get("/api/devices").json()}
    assert nets == {"kid-phone": "main", "kid-tablet": "iot", "tv": "wired", "visitor": "guest"}


def test_iot_card_reads_the_router_on_its_own(client, monitor):
    first = client.get("/api/iot").json()
    assert first["iot"] is None or first["iot"]["ssid"] == "Home-IoT"
    wait_job(client, "iot_read")
    assert client.get("/api/iot").json()["iot"] == {"enabled": True, "ssid": "Home-IoT", "band": "2.4", "security": "WPA2-PSK"}
