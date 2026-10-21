import http.server
import threading

import pytest
from fastapi.testclient import TestClient

from orbi import vulnscan
from orbi.web import create_app


# ---------- web pages: is it a login that works over plain http? ----------
PAGES = {
    "/plain": (200, {}, "<title>HDHomeRun Main Menu</title>"),
    "/form": (200, {}, '<title>Camera</title><form><input type="password" name="p"></form>'),
    "/basic": (401, {"WWW-Authenticate": 'Basic realm="printer"'}, ""),
    "/to-https": (302, {"Location": "https://127.0.0.1/"}, ""),
    "/to-login": (302, {"Location": "/login.html"}, ""),
    "/login.html": (200, {}, "<title>MediaSrv&nbsp;-&nbsp;Synology&nbsp;NAS</title>"),
    "/js-https": (200, {}, '<script>window.location.href = "https://192.168.1.5:5001/";</script><title>Admin login</title>'),
}


@pytest.fixture(scope="module")
def web():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            status, hdr, body = PAGES[H.root if self.path == "/" else self.path]
            self.send_response(status)
            for k, v in hdr.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield H, srv.server_address[1]
    srv.shutdown()


@pytest.mark.parametrize("root,login,https", [("/plain", False, False), ("/form", True, False), ("/basic", True, False),
                                              ("/to-https", False, True), ("/to-login", True, False), ("/js-https", True, True)])
def test_http_probe(web, root, login, https):
    H, port = web
    H.root = root
    r = vulnscan.http_probe("127.0.0.1", port, False)
    assert r["login"] is login and r["to_https"] is https


def test_http_probe_reads_titles_and_survives_closed_ports():
    assert vulnscan.http_probe("127.0.0.1", 1, False) == {"error": "ConnectionRefusedError"}


# ---------- UPnP descriptions and product names ----------
SYNOLOGY = "<root><device><manufacturer>Synology</manufacturer><modelName>DS220j</modelName><modelNumber>DS220j 7.4-90080</modelNumber></device></root>"
SONOS = ("<root><device><manufacturer>Sonos, Inc.</manufacturer><modelName>Sonos One</modelName><modelNumber>S13</modelNumber>"
         "<softwareVersion>97.2-81220</softwareVersion></device></root>")
ORBI = "<root><device><manufacturer>NETGEAR, Inc.</manufacturer><modelName>AX4200</modelName><modelNumber>RBR750</modelNumber></device></root>"


def test_parse_description():
    assert vulnscan.parse_description(SYNOLOGY) == {"maker": "Synology", "model": "DS220j", "model_number": "DS220j 7.4-90080", "firmware": "7.4-90080"}
    assert vulnscan.parse_description(SONOS)["firmware"] == "97.2-81220"
    assert "firmware" not in vulnscan.parse_description(ORBI, "OpenWRT/15.05.1 UPnP/1.1 MiniUPnPd/2.2.2")
    assert vulnscan.parse_description("<manufacturer>Sonos, Inc.</manufacturer>", "Linux UPnP/1.0 Sonos/86.10-81100 (ZPS12)")["firmware"] == "86.10-81100"


def test_cpe_for():
    assert vulnscan.cpe_for(vulnscan.parse_description(SYNOLOGY)) == "cpe:2.3:o:synology:diskstation_manager"
    assert vulnscan.cpe_for({**vulnscan.parse_description(ORBI), "firmware": "V7.2.8.8"}) == "cpe:2.3:o:netgear:rbr750_firmware"
    assert vulnscan.cpe_for({"maker": "NETGEAR", "model_number": "RBS750", "firmware": "V7.2.8.8"}) == "cpe:2.3:o:netgear:rbs750_firmware"
    assert vulnscan.cpe_for(vulnscan.parse_description(SONOS)) == "cpe:2.3:o:sonos:one_firmware"
    assert vulnscan.cpe_for(vulnscan.parse_description(ORBI)) is None  # no firmware version: nothing to look up


# ---------- which vulnerabilities apply to this version ----------
CPE = "cpe:2.3:o:synology:diskstation_manager"


def entry(id, score=9.8, **rule):
    return {"id": id, "score": score, "summary": f"{id} lets an attacker in.", "rules": [{"criteria": f"{CPE}:*:*:*:*:*:*:*:*", **rule}]}


ENTRIES = [
    entry("CVE-OLD", versionEndExcluding="7.2-64570-4"),
    entry("CVE-RANGE", versionStartIncluding="7.4", versionEndExcluding="7.4-90100"),
    entry("CVE-NOFIX", versionStartIncluding="7.3"),
    entry("CVE-LOW", score=5.3, versionStartIncluding="7.0", versionEndExcluding="8.0"),
    entry("CVE-LOW-EXPLOITED", score=5.3, versionStartIncluding="7.0", versionEndExcluding="8.0"),
    {"id": "CVE-EXACT", "score": 8.1, "summary": "", "rules": [{"criteria": f"{CPE}:7.4-90080:*:*:*:*:*:*:*"}]},
    {"id": "CVE-OTHER-EXACT", "score": 8.1, "summary": "", "rules": [{"criteria": f"{CPE}:7.2:*:*:*:*:*:*:*"}]},
]


def test_known_vulns_keeps_serious_ones_for_this_version():
    calls = []
    cache = {}
    fetch = lambda cpe: calls.append(cpe) or ENTRIES  # noqa: E731
    got = vulnscan.known_vulns(CPE, "7.4-90080", cache, {"CVE-LOW-EXPLOITED"}, fetch=fetch, now=1000.0)
    assert [v["id"] for v in got] == ["CVE-LOW-EXPLOITED", "CVE-RANGE", "CVE-NOFIX", "CVE-EXACT"]
    assert got[0]["exploited"] and got[1]["fixed"] == "7.4-90100" and got[2]["fixed"] is None
    vulnscan.known_vulns(CPE, "7.4-90080", cache, set(), fetch=fetch, now=1000.0 + 86400)
    assert calls == [CPE]  # cached for a week
    vulnscan.known_vulns(CPE, "7.4-90080", cache, set(), fetch=fetch, now=1000.0 + 8 * 86400)
    assert calls == [CPE, CPE]


def test_vuln_findings_wording():
    v = vulnscan.known_vulns(CPE, "7.4-90080", {}, set(), fetch=lambda c: ENTRIES)
    f = vulnscan.vuln_findings({"firmware": "7.4-90080"}, v)[0]
    assert f["severity"] == "warn" and f["title"] == "Firmware 7.4-90080 has 3 known serious vulnerabilities"
    assert f["fix"].startswith("Update the firmware to 7.4-90100 or later")
    f = vulnscan.vuln_findings({"firmware": "7.4-90080"}, vulnscan.known_vulns(CPE, "7.4-90080", {}, {"CVE-LOW-EXPLOITED"}, fetch=lambda c: ENTRIES))[0]
    assert f["severity"] == "bad" and "actively using" in f["title"]
    assert vulnscan.vuln_findings({"firmware": "9.0"}, vulnscan.known_vulns(CPE, "9.0", {}, set(), fetch=lambda c: ENTRIES[:2])) == []


def test_kev_list_is_cached_and_survives_a_failed_download(tmp_path):
    f = tmp_path / "kev.json"
    assert vulnscan.kev_ids(f, fetch=lambda url: {"vulnerabilities": [{"cveID": "CVE-1"}]}) == {"CVE-1"}
    assert vulnscan.kev_ids(f, fetch=lambda url: pytest.fail("cached for a day")) == {"CVE-1"}
    import os
    os.utime(f, (0, 0))
    assert vulnscan.kev_ids(f, fetch=lambda url: (_ for _ in ()).throw(OSError("offline"))) == {"CVE-1"}


# ---------- findings from ports ----------
def test_port_findings():
    keys = lambda fs: {f["key"]: f["severity"] for f in fs}  # noqa: E731
    assert keys(vulnscan.port_findings([21, 23, 32764], {})) == {"ftp": "warn", "telnet": "bad", "backdoor:32764": "bad"}
    probes = {80: {"login": True, "to_https": False}, 8080: {"login": True, "to_https": True}, 443: {"login": True, "to_https": False},
              9000: {"login": False, "to_https": False}}
    assert keys(vulnscan.port_findings([80, 443, 8080, 9000], probes)) == {"http-login:80": "warn"}
    assert keys(vulnscan.port_findings([80], {80: {"login": True}}, orbi=True)) == {"http-login:80": "info"}


# ---------- the daily check in the monitor ----------
@pytest.fixture
def house(monitor, monkeypatch):
    monitor.scan()  # kid-phone .20, kid-tablet .21, tv .22 online; Garage Satellite .38
    state = {"open": {"192.168.1.22": [5000]}, "probe": {"login": True, "to_https": False, "title": "Synology"}}
    monkeypatch.setattr("orbi.exposure.scan", lambda ips, ports=None, timeout=0.8: {ip: list(state["open"].get(ip, [])) for ip in ips})
    monkeypatch.setattr("orbi.vulnscan.http_probe", lambda ip, port, tls, timeout=4.0: dict(state["probe"]))
    return state


def device_events(monitor):
    return monitor.store.q("SELECT * FROM events WHERE kind='device_check' ORDER BY id")


def test_first_check_summarises_then_new_problems_alert_and_fixes_are_noted(monitor, house):
    monitor.check_devices()
    ev = device_events(monitor)
    assert len(ev) == 1 and ev[0]["title"] == "Device check found 1 problem" and ev[0]["severity"] == "warn"
    assert "tv: Its login page works without encryption (http, port 5000)" in ev[0]["detail"]
    found = monitor.store.get("vulnscan")
    assert {"router", "AA:00:00:00:00:03"} <= set(found) and found["router"]["name"] == "The Orbi router"

    house["open"]["192.168.1.21"] = [23]
    monitor.check_devices()
    ev = device_events(monitor)
    assert ev[-1]["title"] == "kid-tablet: Telnet is on (unencrypted remote login)" and ev[-1]["severity"] == "error"
    assert ev[-1]["mac"] == "AA:00:00:00:00:02" and monitor.notes[-1] == ("kid-tablet: security problem", "Telnet is on (unencrypted remote login)")

    house["open"]["192.168.1.21"] = []
    monitor.check_devices()
    assert device_events(monitor)[-1]["title"] == "kid-tablet: fixed - Telnet is on (unencrypted remote login)"
    assert len(device_events(monitor)) == 3  # the tv's unchanged problem isn't repeated


def test_orbi_http_admin_is_a_note_not_an_alert(monitor, house):
    house["open"] = {"192.168.1.1": [80], "192.168.1.38": [80]}
    monitor.check_devices()
    assert device_events(monitor)[0]["title"].startswith("Device check: no problems found")
    found = monitor.store.get("vulnscan")
    assert found["router"]["findings"][0]["severity"] == "info"


def test_router_firmware_is_looked_up(monitor, house, monkeypatch):
    house["open"] = {}
    monitor.state["info"] = {"model": "RBR750", "firmware": "V7.2.8.8"}
    asked = []
    rule = {"criteria": "cpe:2.3:o:netgear:rbr750_firmware:*:*:*:*:*:*:*:*", "versionEndExcluding": "7.2.9.1"}
    monkeypatch.setattr("orbi.vulnscan.nvd_entries", lambda cpe: asked.append(cpe) or [{"id": "CVE-2026-1", "score": 9.8, "summary": "x", "rules": [rule]}])
    monkeypatch.setattr("orbi.vulnscan.kev_ids", lambda path, fetch=None: {"CVE-2026-1"})
    monitor.check_devices()
    assert "cpe:2.3:o:netgear:rbr750_firmware" in asked and "cpe:2.3:o:netgear:rbs750_firmware" in asked
    ev = device_events(monitor)[0]
    assert ev["severity"] == "error" and "The Orbi router: Firmware V7.2.8.8 has a flaw attackers are actively using" in ev["detail"]
    assert "cpe:2.3:o:netgear:rbr750_firmware" in monitor.store.get("nvd_cache")


# ---------- API ----------
@pytest.fixture
def client(monitor, house):
    c = TestClient(create_app(monitor))
    assert c.post("/api/setup", json={"pin": "246810"}).status_code == 200
    return c


def test_vulnscan_api(client, monitor):
    r = client.get("/api/vulnscan").json()
    assert r["enabled"] is False and r["ts"] is None
    assert client.post("/api/vulnscan/scan").status_code == 400
    assert client.put("/api/vulnscan", json={"enabled": True}).json()["enabled"] is True
    import time
    for _ in range(100):
        if not (monitor.jobs.get("vulnscan") or {}).get("running"):
            break
        time.sleep(0.05)
    r = client.get("/api/vulnscan").json()
    assert r["job"]["error"] is None, r["job"]
    assert r["ts"] and r["devices"][0]["findings"][0]["key"] == "http-login:5000"  # worst first
    assert monitor.store.one("SELECT * FROM events WHERE kind='action' AND title='Device check turned on'")
