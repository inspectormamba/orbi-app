import json
import socket
import struct
import time
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from orbi import lanwatch
from orbi.web import create_app
from .conftest import ROUTER_MAC

XID = b"\x01\x02\x03\x04"


def offer_packet(server="192.168.1.1", gateway="192.168.1.1", offered="192.168.1.58", xid=XID, op=2, kind=2):
    header = struct.pack("!BBBB4sHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, socket.inet_aton(offered),
                         b"\0" * 4, b"\0" * 4, b"\0" * 16, b"\0" * 64, b"\0" * 128)
    opts = bytes([53, 1, kind, 54, 4]) + socket.inet_aton(server) + bytes([3, 4]) + socket.inet_aton(gateway) + bytes([255])
    return header + lanwatch.MAGIC + opts


# ---------- DHCP packets ----------
def test_discover_is_a_broadcast_request_for_this_pcs_hardware_address():
    pkt = lanwatch.build_discover(bytes.fromhex("08BFB8392E5D"), XID)
    assert pkt[0] == 1 and pkt[4:8] == XID and pkt[10:12] == b"\x80\x00"  # BOOTREQUEST, our id, reply by broadcast
    assert pkt[28:34] == bytes.fromhex("08BFB8392E5D") and pkt[236:240] == lanwatch.MAGIC
    assert pkt[240:243] == bytes([53, 1, 1])  # DHCPDISCOVER


def test_parse_offer_reads_server_gateway_and_address():
    assert lanwatch.parse_offer(offer_packet(server="192.168.1.99", gateway="192.168.1.99", offered="10.0.0.5"), XID) == {
        "offered": "10.0.0.5", "server": "192.168.1.99", "gateway": "192.168.1.99"}


@pytest.mark.parametrize("pkt", [offer_packet(xid=b"\x09\x09\x09\x09"), offer_packet(op=1), offer_packet(kind=5), b"\x02" * 100])
def test_parse_offer_ignores_other_packets(pkt):
    assert lanwatch.parse_offer(pkt, XID) is None


# ---------- upload rates ----------
def test_upload_rates_handle_the_routers_daily_reset_and_gaps():
    rows = [{"ts": 0, "today_up": 1000, "yesterday_up": 5}, {"ts": 900, "today_up": 1100, "yesterday_up": 5},
            # the router's day ended: 1150 was the finished day's total, 30 MB since
            {"ts": 1800, "today_up": 30, "yesterday_up": 1150},
            {"ts": 1800 + 7200, "today_up": 900, "yesterday_up": 1150},  # PC asleep for 2 h: no rate
            {"ts": 1800 + 8100, "today_up": 1000, "yesterday_up": 1150}]
    assert lanwatch.upload_rates(rows, 900) == [(900, 400.0), (1800, 320.0), (9900, 400.0)]


def test_spike_line_waits_for_enough_history():
    now = time.time()
    rates = [(now - 3 * 86400 + i * 900, 400.0) for i in range(3 * 96)]
    assert lanwatch.spike_line(rates, now) is None  # still learning
    rates = [(now - 8 * 86400 + i * 900, 400.0) for i in range(8 * 96)]
    line = lanwatch.spike_line(rates, now)
    assert line["usual"] == 400.0 and line["line"] == 1600.0 and line["days"] == 8
    assert lanwatch.spike_line([(now - 8 * 86400 + i * 900, 10.0) for i in range(8 * 96)], now)["line"] == lanwatch.SPIKE_FLOOR


# ---------- upload spike alert ----------
def seed_traffic(monitor, start, end, per_reading=100.0):
    """Traffic Meter snapshots every 15 min, with today_up restarting at local midnight like the router's."""
    t, total, yesterday, day = start, 0.0, 0.0, datetime.fromtimestamp(start).date()
    while t <= end:
        if datetime.fromtimestamp(t).date() != day:
            day, yesterday, total = datetime.fromtimestamp(t).date(), total, 0.0
        total += per_reading
        monitor.store.x("INSERT INTO traffic(ts,data) VALUES(?,?)", (t, json.dumps({"today_up": total, "yesterday_up": yesterday})))
        t += 900
    return t, total, yesterday


def add_reading(monitor, t, today_up, yesterday_up):
    monitor.store.x("INSERT INTO traffic(ts,data) VALUES(?,?)", (t, json.dumps({"today_up": today_up, "yesterday_up": yesterday_up})))
    monitor.check_upload_spike(t)


def spikes(monitor):
    return monitor.store.q("SELECT * FROM events WHERE kind='upload_spike' ORDER BY ts")


def test_sustained_upload_spike_alerts_once_and_closes_when_it_ends(monitor):
    monitor.scan()  # devices online, for the "online now" list
    end = time.time() - 6 * 900
    t, total, yesterday = seed_traffic(monitor, end - 8 * 86400, end)
    t = end
    for _ in range(3):  # 2 GB per 15 min = 8 GB/h, against a usual 400 MB/h
        t += 900
        total += 2000
        add_reading(monitor, t, total, yesterday)
    ev = spikes(monitor)
    assert len(ev) == 1 and ev[0]["end_ts"] is None and ev[0]["severity"] == "warn"
    assert ev[0]["title"] == "Unusual upload from the house: 6.0 GB in 45 min"
    assert "20x this house's usual" in ev[0]["detail"] and "kid-phone" in ev[0]["detail"]
    assert monitor.notes[-1][0] == "Unusual upload"

    t += 900
    total += 2000
    add_reading(monitor, t, total, yesterday)  # still going: no second alert
    assert len(spikes(monitor)) == 1 and len([n for n in monitor.notes if n[0] == "Unusual upload"]) == 1

    t += 900
    total += 100
    add_reading(monitor, t, total, yesterday)  # back to normal
    ev = spikes(monitor)[0]
    assert ev["end_ts"] and "Ended after 1h" in ev["detail"] and "8.0 GB uploaded in all" in ev["detail"]


def test_short_burst_and_learning_period_dont_alert(monitor):
    end = time.time() - 4 * 900
    _, total, yesterday = seed_traffic(monitor, end - 8 * 86400, end)
    t = end
    for extra in (2000, 2000, 100):  # 30 minutes high, then normal: a phone backing up photos
        t += 900
        total += extra
        add_reading(monitor, t, total, yesterday)
    assert spikes(monitor) == []


def test_no_alert_while_still_learning(monitor):
    end = time.time() - 4 * 900
    _, total, yesterday = seed_traffic(monitor, end - 2 * 86400, end)
    t = end
    for _ in range(3):
        t += 900
        total += 5000
        add_reading(monitor, t, total, yesterday)
    assert spikes(monitor) == []


def test_this_pcs_share_is_reported(monitor, monkeypatch):
    monkeypatch.setattr("orbi.lanwatch.local_ip_for", lambda host: "192.168.1.58")
    sent = iter([0, 1_900_000_000, 3_800_000_000, 5_700_000_000])
    monkeypatch.setattr("orbi.lanwatch.adapter", lambda ip: {"sent_bytes": next(sent)})
    end = time.time() - 5 * 900
    _, total, yesterday = seed_traffic(monitor, end - 8 * 86400, end)
    monitor._pc_sent_mb()  # first counter reading
    t = end
    for _ in range(3):
        t += 900
        total += 2000
        add_reading(monitor, t, total, yesterday)
    assert "This PC sent 5.7 GB of it." in spikes(monitor)[0]["detail"]


# ---------- fake router: ARP ----------
def gateway_alerts(monitor):
    return monitor.store.q("SELECT * FROM events WHERE kind='fake_router' ORDER BY ts")


def test_device_answering_as_the_router_is_named_and_alerted(monitor, monkeypatch):
    monitor.scan()
    monitor.check_gateway()
    assert monitor.store.get("gateway_mac") == ROUTER_MAC and gateway_alerts(monitor) == []

    monkeypatch.setattr("orbi.routercert.gateway_mac", lambda host: "AA:00:00:00:00:01")  # kid-phone
    monitor.check_gateway()
    assert gateway_alerts(monitor) == []  # one reading isn't enough
    monitor.check_gateway()
    monitor.check_gateway()
    ev = gateway_alerts(monitor)
    assert len(ev) == 1 and ev[0]["severity"] == "error" and ev[0]["title"] == "kid-phone is pretending to be the router"
    assert ev[0]["mac"] == "AA:00:00:00:00:01" and monitor.notes[-1][0] == "Fake router on your network"

    monkeypatch.setattr("orbi.routercert.gateway_mac", lambda host: ROUTER_MAC)
    monitor.check_gateway()
    ev = gateway_alerts(monitor)[0]
    assert ev["end_ts"] and ev["detail"].endswith("The real router is answering again.")


def test_router_reported_address_wins_over_a_spoofer_seen_first(monitor, monkeypatch):
    monkeypatch.setattr("orbi.routercert.gateway_mac", lambda host: "02:66:66:66:66:66")
    monitor.check_gateway()  # no satellites known yet: the first address seen is taken
    assert monitor.store.get("gateway_mac") == "02:66:66:66:66:66"
    monitor.scan()  # satellites say their parent, the router, is ROUTER_MAC
    monitor.check_gateway()
    monitor.check_gateway()
    assert monitor.store.get("gateway_mac") == ROUTER_MAC
    assert gateway_alerts(monitor)[0]["title"] == "Another device is answering as the router"


def test_trusting_a_replacement_router(monitor, monkeypatch):
    monitor.check_gateway()  # no satellites: first seen is ROUTER_MAC
    monkeypatch.setattr("orbi.routercert.gateway_mac", lambda host: "C8:9E:43:99:99:99")
    monitor.check_gateway()
    monitor.check_gateway()
    assert len(gateway_alerts(monitor)) == 1
    assert monitor.trust_gateway() == "C8:9E:43:99:99:99"
    assert gateway_alerts(monitor)[0]["end_ts"] and monitor.store.get("gateway_mac") == "C8:9E:43:99:99:99"
    monitor.check_gateway()
    monitor.check_gateway()
    assert len(gateway_alerts(monitor)) == 1
    assert monitor.store.one("SELECT * FROM events WHERE kind='action' AND title LIKE 'New router%'")


# ---------- fake router: DHCP ----------
@pytest.fixture
def on_lan(monkeypatch):
    monkeypatch.setattr("orbi.lanwatch.local_ip_for", lambda host: "192.168.1.58")
    monkeypatch.setattr("orbi.lanwatch.adapter", lambda ip: {"mac": "08:BF:B8:39:2E:5D", "dhcp_enabled": True, "dhcp_server": "192.168.1.1"})
    orbi_offer = {"offered": "192.168.1.58", "server": "192.168.1.1", "gateway": "192.168.1.1"}
    answers = {"rounds": [], "default": {"192.168.1.1": orbi_offer}}

    def servers(ip, mac, timeout=4.0):
        return answers["rounds"].pop(0) if answers["rounds"] else dict(answers["default"])
    monkeypatch.setattr("orbi.lanwatch.dhcp_servers", servers)
    return answers


def rogue_alerts(monitor):
    return monitor.store.q("SELECT * FROM events WHERE kind='rogue_dhcp'")


def test_only_the_orbi_answering_is_fine(monitor, on_lan):
    r = monitor.check_dhcp()
    assert list(r["servers"]) == ["192.168.1.1"] and r["pc_server"] == "192.168.1.1" and r["error"] is None
    assert rogue_alerts(monitor) == [] and monitor.store.get("dhcp_watch")["servers"]


def test_second_dhcp_server_is_named_and_alerted_once_a_day(monitor, on_lan, monkeypatch):
    monitor.scan()
    monkeypatch.setattr("orbi.monitor.arp_mac", lambda ip: "AA:00:00:00:00:03")  # the "tv"
    on_lan["default"]["192.168.1.99"] = {"offered": "10.0.0.5", "server": "192.168.1.99", "gateway": "192.168.1.99"}
    monitor.check_dhcp()
    ev = rogue_alerts(monitor)
    assert len(ev) == 1 and ev[0]["severity"] == "error" and ev[0]["title"] == "Another device is handing out addresses: tv"
    assert "offering 10.0.0.5 with 192.168.1.99 as the router" in ev[0]["detail"] and ev[0]["mac"] == "AA:00:00:00:00:03"
    monitor.check_dhcp()
    assert len(rogue_alerts(monitor)) == 1


def test_a_single_stray_answer_isnt_alerted(monitor, on_lan):
    orbi = dict(on_lan["default"])
    on_lan["rounds"] = [{**orbi, "192.168.1.99": {"offered": "10.0.0.5", "server": "192.168.1.99", "gateway": None}}, orbi]
    monitor.check_dhcp()
    assert rogue_alerts(monitor) == []


def test_this_pc_leased_from_another_server(monitor, on_lan, monkeypatch):
    monkeypatch.setattr("orbi.lanwatch.adapter", lambda ip: {"mac": "08:BF:B8:39:2E:5D", "dhcp_enabled": True, "dhcp_server": "192.168.1.77"})
    monitor.check_dhcp()
    ev = rogue_alerts(monitor)
    assert len(ev) == 1 and "This PC got its address (192.168.1.58) from Device at 192.168.1.77" in ev[0]["detail"]


def test_off_the_home_network_nothing_is_probed(monitor, monkeypatch):
    monkeypatch.setattr("orbi.lanwatch.local_ip_for", lambda host: "10.8.0.2")
    monkeypatch.setattr("orbi.lanwatch.dhcp_servers", lambda *a, **k: pytest.fail("must not probe another network"))
    assert monitor.check_dhcp()["error"] == "This PC isn't on the home network"


# ---------- API ----------
@pytest.fixture
def client(monitor):
    monitor.scan()
    c = TestClient(create_app(monitor))
    assert c.post("/api/setup", json={"pin": "246810"}).status_code == 200
    return c


def test_lanwatch_api(client, monitor, monkeypatch):
    monitor.check_gateway()
    r = client.get("/api/lanwatch").json()
    assert r["gateway"] == {"expected": ROUTER_MAC, "alert": None} and r["upload"]["learning_days"] == lanwatch.MIN_HISTORY_DAYS
    monkeypatch.setattr("orbi.routercert.gateway_mac", lambda host: "AA:00:00:00:00:02")
    monitor.check_gateway()
    monitor.check_gateway()
    assert client.get("/api/lanwatch").json()["gateway"]["alert"]["title"] == "kid-tablet is pretending to be the router"
    r = client.post("/api/lanwatch/trust-router")
    assert r.status_code == 200 and r.json()["gateway"]["alert"] is None
