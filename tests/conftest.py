import pytest

from orbi import config
from orbi.monitor import Monitor
from orbi.router import RouterError
from orbi.store import Store

ROUTER_MAC = "C8:9E:43:00:00:01"
SAT_MAC = "C8:9E:43:C4:3B:94"


class FakeRouter:
    """In-memory stand-in for RouterClient with the same method surface."""

    def __init__(self):
        self.ac = False
        self.blocked: set[str] = set()
        self.calls: list[tuple] = []
        self.fail = False
        self.last_error = None
        self.sats = [{"mac": SAT_MAC, "ip": "192.168.1.38", "name": "Garage Satellite", "model": "RBS750", "firmware": "V7",
                      "signal": 42.0, "backhaul": "5GHz", "backhaul_status": "2", "parent_mac": ROUTER_MAC, "hop": "0"}]
        self.devs = [
            self._dev("AA:00:00:00:00:01", "kid-phone", "192.168.1.20", SAT_MAC),
            self._dev("AA:00:00:00:00:02", "kid-tablet", "192.168.1.21", ROUTER_MAC),
            self._dev("AA:00:00:00:00:03", "tv", "192.168.1.22", ROUTER_MAC, "wired"),
        ]
        self.guest = False
        self.speed_polls = 0

    @staticmethod
    def _dev(mac, name, ip, ap, conn="5GHz"):
        return {"mac": mac, "ip": ip, "name": name, "connection": conn, "signal": 60.0, "link_rate": 400.0, "blocked": False,
                "model": "", "ssid": "Home", "ap_mac": ap}

    def _check(self):
        if self.fail:
            raise RouterError("router offline")

    def info(self):
        self._check()
        return {"model": "RBR750", "serial": "X", "firmware": "V7.2.8.8"}

    def wan(self):
        self._check()
        return {"link_up": True, "ip": "1.2.3.4", "dns": ["185.228.168.10"]}

    def system(self):
        return {"cpu": 10.0, "memory": 50.0}

    def satellites(self):
        self._check()
        return [dict(s) for s in self.sats]

    def devices(self):
        self._check()
        return [{**d, "blocked": d["mac"] in self.blocked} for d in self.devs]

    def access_control_enabled(self):
        self._check()
        return self.ac

    def enable_access_control(self):
        self._check()
        self.calls.append(("enable_ac",))
        self.ac = True

    def set_blocked(self, mac, blocked):
        self._check()
        self.calls.append(("block" if blocked else "allow", mac))
        (self.blocked.add if blocked else self.blocked.discard)(mac)

    def traffic(self):
        return {"today_down": 1000.0, "today_up": 100.0, "month_down": 5000.0}

    def guest_wifi(self):
        return {"enabled": self.guest, "ssid": "Guest", "password": "pw"}

    def set_guest_wifi(self, enabled):
        self.guest = enabled

    def start_speedtest(self):
        self.speed_polls = 0

    def speedtest_poll(self):
        self.speed_polls += 1
        return None if self.speed_polls < 2 else {"down": 900.0, "up": 800.0, "ping": 3.0}

    def firmware_update(self):
        return {"current": "V7.2.8.8", "available": None}

    def reboot(self):
        self.calls.append(("reboot",))

    def uptime(self):
        return "2 days 07:21:36"

    def wifi(self):
        return [{"band": "5 GHz", "ssid": "Home", "enabled": True, "status": "Up", "channel": "48", "mode": "1201M",
                 "security": "WPA2/WPA3-Personal", "broadcast": True, "mac": ""}]


@pytest.fixture(autouse=True)
def quiet_guard(monkeypatch):
    """Tests fire PINs and requests faster than any person, from a client called "testclient": switch the
    break-in detection off unless a test turns it back on (tests/test_guard.py)."""
    monkeypatch.setattr("orbi.guard.FAST", (10**6, 1.0))
    monkeypatch.setattr("orbi.guard.THROUGH_LOCKOUT", (10**6, 1.0))
    monkeypatch.setattr("orbi.guard.PROBE", (10**6, 1.0))
    monkeypatch.setattr("orbi.guard.scripted_agent", lambda agent: False)


@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "SETTINGS_FILE", tmp_path / "settings.json")
    return tmp_path


@pytest.fixture
def fake_router():
    return FakeRouter()


@pytest.fixture
def monitor(tmp_config, fake_router, monkeypatch):
    monkeypatch.setattr("orbi.monitor.local_macs", lambda: {"08:BF:B8:39:2E:5D"})
    # Never query the real router or network from tests; individual tests override these.
    monkeypatch.setattr("orbi.monitor.house_online", lambda host: False)
    monkeypatch.setattr("orbi.monitor.internet_route", lambda host: {"vpn": False, "local_ip": "192.168.1.58"})
    monkeypatch.setattr("orbi.monitor.adapter_name", lambda ip: "")
    monkeypatch.setattr("orbi.routercert.gateway_mac", lambda host: ROUTER_MAC)
    monkeypatch.setattr("orbi.monitor.arp_mac", lambda ip: None)
    store = Store(tmp_config / "orbi.db")
    notes = []
    m = Monitor(store, notify=lambda t, msg: notes.append((t, msg)), router_factory=lambda: fake_router,
                ui_factory=lambda: (_ for _ in ()).throw(AssertionError("tests must not open the real router UI")),
                log_fetcher=lambda: [])
    m.notes = notes
    m.reload_router()
    return m
