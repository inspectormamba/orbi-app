from orbi import vpnlog
from orbi.routerui import parse_log

from .test_advanced import client, wait_job  # noqa: F401  (fixtures/helpers)

# Real line formats from an RBR750 (V7.2.8.8), including the router's "reomote" typo.
LOG = """[OpenVPN, connection successfully] from remote IP address:198.51.100.7 Wednesday, Oct 07,2026 16:09:50
[OpenVPN, connection successfully] from remote IP address:198.51.100.7 Wednesday, Oct 07,2026 16:06:07
[OpenVPN, connection drop] from remote IP address:198.51.100.24 Wednesday, Oct 07,2026 16:02:36
[OpenVPN, connection successfully] from remote IP address:198.51.100.24 Wednesday, Oct 07,2026 14:41:00
[OpenVPN, connection successfully] from remote IP address:198.51.100.24 Wednesday, Oct 07,2026 14:30:00
[OpenVPN, connection fail] from reomote IP address:203.0.113.9 Wednesday, Oct 07,2026 03:10:00
[OpenVPN, connection fail] from reomote IP address:203.0.113.9 Wednesday, Oct 07,2026 03:09:00
[OpenVPN, connection fail] from reomote IP address:192.168.1.32 Friday, Oct 02,2026 12:21:45
[OpenVPN, connection fail] from reomote IP address:192.168.1.32 Friday, Oct 02,2026 12:21:35
"""


def test_parsed_kinds():
    rows = parse_log(LOG)
    assert {r["kind"] for r in rows} == {"OpenVPN, connection successfully", "OpenVPN, connection drop", "OpenVPN, connection fail"}
    assert vpnlog.event_of(rows[0]["kind"], rows[0]["text"]) == ("connect", "198.51.100.7")
    assert vpnlog.event_of(rows[-1]["kind"], rows[-1]["text"]) == ("fail", "192.168.1.32")
    assert vpnlog.event_of("service blocked: Block-VPN-OpenVPN", "x") is None


def test_sessions_and_failures():
    out = vpnlog.summarize(parse_log(LOG))
    newest, earlier = out["sessions"]
    assert newest["ip"] == "198.51.100.7" and newest["reconnects"] == 1 and newest["end"] is None  # still on, or not logged
    assert earlier["ip"] == "198.51.100.24" and earlier["reconnects"] == 1 and earlier["end"] - earlier["start"] == 92 * 60 + 36
    outside, inside = out["failures"]
    assert (outside["ip"], outside["count"], outside["inside"]) == ("203.0.113.9", 2, False)
    assert (inside["ip"], inside["count"], inside["inside"]) == ("192.168.1.32", 2, True)


def test_long_gap_starts_a_new_session():
    rows = [{"ts": 0, "kind": "OpenVPN, connection successfully", "text": "from remote IP address:1.2.3.4"},
            {"ts": vpnlog.SESSION_GAP + 1, "kind": "OpenVPN, connection successfully", "text": "from remote IP address:1.2.3.4"}]
    assert len(vpnlog.summarize(rows)["sessions"]) == 2


def test_live_vpn_events(monitor):
    monitor.scan()
    batches = [parse_log("[Admin login] from source 192.168.1.58, Wednesday, Oct 07,2026 01:00:00\n")]
    monitor.log_fetcher = lambda: batches[-1]
    monitor.ingest_router_log()  # first read: history only
    batches.append(parse_log(LOG))
    monitor.ingest_router_log()
    titles = [(e["title"], e["detail"], e["severity"]) for e in monitor.store.q(
        "SELECT * FROM events WHERE kind LIKE 'vpn_%' AND kind != 'vpn_attempt' ORDER BY ts")]
    assert titles == [
        ("Failed attempt to connect to the home VPN", "from 203.0.113.9", "warn"),  # once per burst; inside fails aren't news
        ("Connected to the home VPN", "from 198.51.100.24", "info"),  # 14:30 and 14:41 are one session
        ("Disconnected from the home VPN", "from 198.51.100.24", "info"),
        ("Connected to the home VPN", "from 198.51.100.7", "info"),
    ]
    assert [n[0] for n in monitor.notes] == ["Failed VPN connection"]


def test_vpn_log_api(client, monitor):
    from orbi.routerui import parse_log as p
    for r in p(LOG):
        monitor.store.x("INSERT OR IGNORE INTO router_log(ts,kind,source,text) VALUES(?,?,?,?)", (r["ts"], r["kind"], r["source"], r["text"]))
    r = client.get("/api/vpn-log?days=90").json()
    assert [s["ip"] for s in r["sessions"]] == ["198.51.100.7", "198.51.100.24"]
    assert r["failures"][1]["device"]  # inside attempts name the device (or its address)
