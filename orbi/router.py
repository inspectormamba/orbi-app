"""Thread-safe access to the Orbi's local SOAP API (via pynetgear).

The Orbi handles one admin session at a time and some calls take 10-20 s, so every
call goes through a single lock. pynetgear re-logs-in on expired sessions; on top of
that, failed calls are retried once with a fresh login.
"""
import logging
import threading
import time
import warnings

import urllib3
from pynetgear import Netgear

warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)  # router uses a self-signed cert
log = logging.getLogger("orbi.router")


class RouterError(Exception):
    pass


def norm_mac(mac: str) -> str:
    m = "".join(c for c in str(mac).upper() if c in "0123456789ABCDEF")
    return ":".join(m[i:i + 2] for i in range(0, 12, 2)) if len(m) == 12 else str(mac).upper()


def backhaul_kind(conn_type: str | None) -> str | None:
    """'wired' or 'wireless' from a satellite's BHConnType ("wired", "5GHz", "2.4GHz" on an RBR750); None if unknown."""
    v = (conn_type or "").strip().lower()
    if any(k in v for k in ("ghz", "wireless", "wifi", "wi-fi")):
        return "wireless"
    if v in ("wired", "ethernet") or "ether" in v:
        return "wired"
    return None


def _attached_devices_full(ng) -> list[dict] | None:
    """GetAttachDevice2 with every field the router sends: pynetgear drops the router's own identification of each
    device (DeviceBrand, DeviceTypeV2) and whether its name was typed in by someone (NameUserSet)."""
    from pynetgear import const as c, helpers as h
    ok, resp = ng._make_request(c.SERVICE_DEVICE_INFO, c.GET_ATTACHED_DEVICES_2)
    if not ok:
        return None
    ok, node = h.find_node(resp.text, ".//GetAttachDevice2Response/NewAttachDevice")
    if not ok:
        return None
    return [{f.tag: (f.text or "").strip() for f in d} for d in node.findall("Device")]


UNKNOWN_BRANDS = {"", "unknown", "not included in current license"}


def router_date(text: str | None) -> float | None:
    """The router's dates as timestamps: "2026_02.24_02:04:17" (firmware) or "Thursday, 17 Aug 2023 06:30:18"."""
    from datetime import datetime
    for fmt in ("%Y_%m.%d_%H:%M:%S", "%A, %d %b %Y %H:%M:%S"):
        try:
            return datetime.strptime((text or "").strip(), fmt).timestamp()
        except ValueError:
            pass
    return None


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


class RouterClient:
    def __init__(self, host: str, password: str, user: str = "admin"):
        self.host, self.user, self.password = host, user, password
        self._lock = threading.Lock()
        self._ng = None
        self.last_ok = None
        self.last_error = None

    def _connect(self):
        from . import routercert
        try:
            routercert.check(self.host)  # before any password is sent
        except routercert.CertificateChanged as e:
            raise RouterError(str(e)) from e
        ng = Netgear(password=self.password, host=self.host, user=self.user, port=443, ssl=True)
        # Every SOAP request (login included) goes over a connection that must present the pinned certificate.
        pinned = routercert.session(self.host)
        ng._post_request = lambda headers, message: pinned.post(ng.soap_url, headers=headers, data=message, timeout=30)
        ng.attached_devices_full = lambda: _attached_devices_full(ng)
        # HTTPS on 443 only: pynetgear's login_try_port() falls back to plain HTTP (ports 5000/80),
        # which would send the admin password across the LAN unencrypted.
        if not ng.login():
            raise RouterError("Could not log in to the router over HTTPS (check the admin password)")
        return ng

    def call(self, method: str, *args, attempts: int = 2, bool_result: bool = False):
        """Run a pynetgear method. None (and False, unless the method returns a boolean)
        counts as a failure and is retried with a fresh login."""
        with self._lock:
            err = None
            for attempt in range(attempts):
                try:
                    if self._ng is None:
                        self._ng = self._connect()
                    result = getattr(self._ng, method)(*args)
                    if result is None or (result is False and not bool_result):
                        raise RouterError(f"{method} returned no data")
                    self.last_ok, self.last_error = time.time(), None
                    return result
                except Exception as e:  # network errors, auth errors, empty responses
                    err = e
                    self._ng = None  # force a fresh login next time
                    if "security certificate changed" in str(e):
                        break  # retrying won't help, and the user needs to see why
                    log.warning("%s failed (attempt %d): %s", method, attempt + 1, e)
                    if attempt + 1 < attempts:
                        time.sleep(2)
            self.last_error = str(err)
            raise err if isinstance(err, RouterError) else RouterError(f"{method}: {err}")

    # ---- reads ----
    def info(self) -> dict:
        i = self.call("get_info")
        return {"model": i.get("ModelName"), "serial": i.get("SerialNumber"), "firmware": i.get("Firmwareversion"),
                # not shown in Netgear's app or pages:
                "first_use": router_date(i.get("FirstUseDate")), "firmware_installed": router_date(i.get("FirmwareLastUpdate")),
                "firmware_checked": router_date(i.get("FirmwareLastChecked")), "firmware_auto": (i.get("FirmwareDLmethod") or "").upper() != "MANUAL"
                if i.get("FirmwareDLmethod") else None}

    def devices(self) -> list[dict]:
        out = []
        for d in self.call("attached_devices_full"):
            brand = d.get("DeviceBrand", "")
            out.append({
                "mac": norm_mac(d.get("MAC", "")), "ip": d.get("IP"), "name": d.get("Name", ""), "connection": d.get("ConnectionType", ""),
                "signal": _num(d.get("SignalStrength")), "link_rate": _num(d.get("Linkspeed")), "blocked": d.get("AllowOrBlock") == "Block",
                "model": d.get("DeviceModel", ""), "ssid": d.get("SSID", ""), "ap_mac": norm_mac(d["ConnAPMAC"]) if d.get("ConnAPMAC") else "",
                # the router's own identification, independent of the name the device gives itself
                "brand": "" if brand.lower() in UNKNOWN_BRANDS else brand,
                "category": "" if d.get("DeviceTypeV2", "").upper() in ("", "GENERIC") else d["DeviceTypeV2"].upper(),
                "name_user_set": d.get("NameUserSet") == "true",
            })
        return out

    def satellites(self) -> list[dict]:
        out = []
        for s in self.call("get_satellites") or []:
            out.append({
                "mac": norm_mac(s.get("MAC", "")), "ip": s.get("IP"), "name": s.get("DeviceName") or s.get("ModelName"),
                "model": s.get("ModelName"), "firmware": s.get("FWVersion"), "signal": _num(s.get("SignalStrength")),
                "backhaul": s.get("BHConnType") or "", "backhaul_kind": backhaul_kind(s.get("BHConnType")),
                "backhaul_status": s.get("BHConnStatus"),
                "parent_mac": norm_mac(s.get("ParentMac", "")), "hop": s.get("Hop"),
            })
        return out

    def wan(self) -> dict:
        link = self.call("check_ethernet_link")
        w = self.call("get_wan_ip_con_info")
        return {
            "link_up": link.get("NewEthernetLinkStatus") == "Up", "ip": w.get("NewExternalIPAddress"),
            "dns": (w.get("NewDNSServers") or "").split(),
        }

    def system(self) -> dict:
        s = self.call("get_system_info")
        return {"cpu": _num(s.get("NewCPUUtilization")), "memory": _num(s.get("NewMemoryUtilization"))}

    def uptime(self) -> str:
        from pynetgear import helpers as h
        with self._lock:
            try:
                if self._ng is None:
                    self._ng = self._connect()
                _, resp = self._ng._make_request("urn:NETGEAR-ROUTER:service:DeviceInfo:1", "GetSysUpTime", check=False)
                ok, node = h.find_node(resp.text, ".//SysUpTime")
                return node.text.strip() if ok and node is not None and node.text else ""
            except Exception:
                self._ng = None
                return ""

    def wifi(self) -> list[dict]:
        out = []
        for band, method in (("2.4 GHz", "get_2g_info"), ("5 GHz", "get_5g_info")):
            try:
                w = self.call(method, attempts=1)
            except RouterError:
                continue
            out.append({"band": band, "ssid": w.get("NewSSID"), "enabled": w.get("NewEnable") == "1", "status": w.get("NewStatus"),
                        "channel": w.get("NewChannel"), "mode": w.get("NewWirelessMode"), "security": w.get("NewWPAEncryptionModes"),
                        "broadcast": w.get("NewSSIDBroadcast") == "1", "mac": norm_mac(w.get("NewWLANMACAddress") or "")})
        return out

    def traffic(self) -> dict:
        t = self.call("get_traffic_meter")
        first = lambda v: v[0] if isinstance(v, (list, tuple)) else v  # noqa: E731 - week/month are [total, avg]
        avg = lambda v: v[1] if isinstance(v, (list, tuple)) and len(v) > 1 else None  # noqa: E731
        return {  # megabytes
            "today_down": first(t.get("NewTodayDownload")), "today_up": first(t.get("NewTodayUpload")),
            "yesterday_down": first(t.get("NewYesterdayDownload")), "yesterday_up": first(t.get("NewYesterdayUpload")),
            "week_down": first(t.get("NewWeekDownload")), "week_up": first(t.get("NewWeekUpload")),
            "week_avg_down": avg(t.get("NewWeekDownload")), "week_avg_up": avg(t.get("NewWeekUpload")),
            "month_down": first(t.get("NewMonthDownload")), "month_up": first(t.get("NewMonthUpload")),
            "month_avg_down": avg(t.get("NewMonthDownload")), "month_avg_up": avg(t.get("NewMonthUpload")),
            "last_month_down": first(t.get("NewLastMonthDownload")), "last_month_up": first(t.get("NewLastMonthUpload")),
            "last_month_avg_down": avg(t.get("NewLastMonthDownload")), "last_month_avg_up": avg(t.get("NewLastMonthUpload")),
        }

    def guest_wifi(self) -> dict:
        info = self.call("get_2g_guest_access_network_info")
        enabled = self.call("get_2g_guest_access_enabled", bool_result=True)
        return {"enabled": bool(enabled), "ssid": info.get("NewSSID"), "password": info.get("NewKey")}

    def firmware_update(self) -> dict:
        f = self.call("check_new_firmware")
        return {"current": f.get("CurrentVersion"), "available": f.get("NewVersion")}

    # ---- actions ----
    def set_blocked(self, mac: str, blocked: bool):
        self.call("allow_block_device", norm_mac(mac), "Block" if blocked else "Allow")

    def access_control_enabled(self) -> bool:
        return self.call("get_block_device_enable_status", bool_result=True) is True

    def enable_access_control(self):
        self.call("set_block_device_enable", True)

    def set_guest_wifi(self, enabled: bool):
        self.call("set_2g_guest_access_enabled", enabled)

    def start_speedtest(self):
        self.call("set_speed_test_start")

    def speedtest_poll(self) -> dict | None:
        """One status check (pynetgear's own call loops for up to a minute while holding
        the session). Returns None while the test runs (ResponseCode 1), else the result."""
        from pynetgear import const as c, helpers as h
        with self._lock:
            try:
                if self._ng is None:
                    self._ng = self._connect()
                _, response = self._ng._make_request(c.SERVICE_ADVANCED_QOS, c.GET_SPEED_TEST_RESULT, check=False)
            except Exception as e:
                self._ng = None
                raise RouterError(f"speed test status: {e}")
        if response is None or response.status_code != 200:
            raise RouterError("speed test status: bad response")
        ok, code = h.find_node(response.text, ".//ResponseCode")
        if ok and code.text in ("1", "001"):
            return None
        vals = {}
        for key in ("NewOOKLADownlinkBandwidth", "NewOOKLAUplinkBandwidth", "AveragePing"):
            found, node = h.find_node(response.text, f".//{key}")
            vals[key] = _num(node.text) if found else None
        return {"down": vals["NewOOKLADownlinkBandwidth"], "up": vals["NewOOKLAUplinkBandwidth"], "ping": vals["AveragePing"]}

    def reboot(self):
        self.call("reboot", attempts=1)
