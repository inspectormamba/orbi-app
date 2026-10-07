"""Background service: health checks, scans, speed tests, and parental-control enforcement.

Every loop runs in its own thread, catches its own errors, and is restarted by a
supervisor if it ever dies, so one bad router response can't stop monitoring.
"""
import contextvars
import json
import logging
import re
import secrets
import socket
import threading
import time
from datetime import datetime, timedelta

from . import config, parental
from .router import RouterClient, RouterError, backhaul_kind, norm_mac
from .store import Store

log = logging.getLogger("orbi.monitor")

INTERNET_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)]


def tcp_ok(host, port, timeout=3.0):
    t = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return (time.perf_counter() - t) * 1000
    except OSError:
        return None


def internet_route(router_host: str) -> dict:
    """Which local address this PC uses to reach the internet, and whether that differs from the one
    it uses to reach the router. A different one means internet traffic leaves through another
    adapter, which in practice is a VPN."""
    def source(dest):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as so:
            so.connect((dest, 53))  # a UDP connect only picks the route; nothing is sent
            return so.getsockname()[0]
    try:
        lan, out = source(router_host), source("1.1.1.1")
    except OSError:
        return {"vpn": False, "local_ip": None}
    return {"vpn": lan != out, "local_ip": out}


def adapter_name(ip: str) -> str:
    """Windows' name for the network adapter that has this address (e.g. "WireGuard Tunnel"), or ""."""
    import subprocess
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", f"(Get-NetIPAddress -IPAddress '{ip}' -ErrorAction Stop).InterfaceAlias"],
                             capture_output=True, text=True, timeout=15, creationflags=0x08000000).stdout  # CREATE_NO_WINDOW
    except Exception:
        return ""
    return out.strip().splitlines()[0] if out.strip() else ""


def upstream_answered(response, zone: str = "example.com.") -> bool:
    """True if a reply to a made-up name under `zone` really came from the internet: either an answer, or
    "no such name"/"no records" carrying the zone's own SOA record, which a router can't make up by itself.
    (example.com answers a made-up name with NOERROR, no records and its SOA.)"""
    import dns.rcode
    import dns.rdatatype
    if response.rcode() == dns.rcode.NOERROR and response.answer:
        return True
    return response.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) and any(
        rr.rdtype == dns.rdatatype.SOA and rr.name.to_text().lower() == zone for rr in response.authority)


def house_online(router_host: str) -> bool:
    """Asks the router to look up a made-up name under example.com. Only the internet can answer that,
    so an answer means the router itself is online, whatever a VPN on this PC is doing."""
    import dns.message
    import dns.query
    for _ in range(2):
        try:
            q = dns.message.make_query(f"orbi-check-{secrets.token_hex(6)}.example.com", "A")
            if upstream_answered(dns.query.udp(q, router_host, timeout=3)):
                return True
        except Exception:
            pass
    return False


def uptime_seconds(text: str | None) -> int | None:
    """'2 days 07:21:36' or '07:21:36' -> seconds."""
    m = re.fullmatch(r"(?:(\d+)\s*days?\s*)?(\d+):(\d{2}):(\d{2})", (text or "").strip())
    if not m:
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


def local_macs() -> set[str]:
    """MACs of this PC's adapters, so the app never blocks the machine it runs on."""
    import subprocess
    try:
        out = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=10,
                             creationflags=0x08000000).stdout  # CREATE_NO_WINDOW
    except Exception:
        return set()
    return {norm_mac(line.split(",")[0].strip('"')) for line in out.splitlines() if line.strip()}


class Monitor:
    def __init__(self, store: Store, notify=lambda title, msg: None, router_factory=None, ui_factory=None, log_fetcher=None):
        self.store = store
        self.notify = notify
        self._router_factory = router_factory or self._default_router
        self.ui_factory = ui_factory or self._default_ui
        self.log_fetcher = log_fetcher or self._default_log_fetcher
        self.jobs: dict[str, dict] = {}
        self.advanced = {"data": None, "ts": None}
        self.router: RouterClient | None = None
        self.stop_event = threading.Event()
        self.wake_enforcer = threading.Event()
        self._enforce_lock = threading.Lock()
        self.threads: dict[str, threading.Thread] = {}
        self.state = {
            "internet": None, "router": None, "latency_ms": None, "last_check": None, "outage_id": None, "pc_offline_id": None,
            "router_down_id": None, "last_scan": None, "scan_error": None, "satellites": [], "wan": {},
            "system": {}, "info": {}, "speedtest": {"running": False, "error": None}, "enforce_error": None,
            "access_control": None,
        }
        self._fails = 0
        self._router_fails = 0
        self._pc_fails = 0
        self._missing_sats: dict[str, int] = {}
        self._backhaul_changes: dict[str, tuple[str, int]] = {}  # mac -> (new kind, scans seen in a row)
        self.protected = local_macs()

    # ---- router ----
    def _default_router(self):
        s = config.load()
        pw = config.router_password(s)
        return RouterClient(s["router_host"], pw, s["router_user"]) if pw else None

    def _default_ui(self):
        from .routerui import RouterUI
        s = config.load()
        return RouterUI(s["router_host"], config.router_password(s), s["router_user"])

    def _default_log_fetcher(self):
        from .routerui import fetch_log
        s = config.load()
        return fetch_log(s["router_host"], config.router_password(s), s["router_user"])

    def reload_router(self):
        self.router = self._router_factory()
        self.wake_enforcer.set()

    def protected_macs(self) -> set[str]:
        return self.protected | {norm_mac(m) for m in config.load().get("protected_macs", [])}

    # ---- lifecycle ----
    def start(self):
        self.reload_router()
        loops = {"health": self.health_loop, "scan": self.scan_loop, "enforce": self.enforce_loop,
                 "traffic": self.traffic_loop, "speedtest": self.speedtest_schedule_loop, "maintenance": self.maintenance_loop,
                 "routerlog": self.routerlog_loop, "updates": self.update_loop}
        self._loops = loops
        for name in loops:
            self._spawn(name)
        threading.Thread(target=self._supervise, name="supervisor", daemon=True).start()

    def _spawn(self, name):
        def runner():
            while not self.stop_event.is_set():
                try:
                    self._loops[name]()
                    return
                except Exception:
                    log.exception("loop %s crashed; restarting in 10s", name)
                    self.stop_event.wait(10)
        t = threading.Thread(target=runner, name=name, daemon=True)
        self.threads[name] = t
        t.start()

    def _supervise(self):
        while not self.stop_event.wait(30):
            for name, t in list(self.threads.items()):
                if not t.is_alive():
                    log.error("thread %s died; restarting", name)
                    self._spawn(name)

    def stop(self):
        self.stop_event.set()
        self.wake_enforcer.set()

    def _every(self, seconds_fn, body):
        while not self.stop_event.is_set():
            try:
                body()
            except Exception:
                log.exception("%s iteration failed", threading.current_thread().name)
            self.stop_event.wait(seconds_fn())

    # ---- health ----
    def health_loop(self):
        self._every(lambda: config.load()["health_interval"], self.check_health)

    def check_health(self):
        s = config.load()
        router_ms = tcp_ok(s["router_host"], 443, 2.5) or tcp_ok(s["router_host"], 80, 2.5)
        lat = [ms for ms in (tcp_ok(h, p) for h, p in INTERNET_TARGETS) if ms is not None]
        pc_ok = bool(lat)
        # When this PC can't get out, ask the router whether *it* can: if so, the house is online and
        # only this PC (usually its VPN) dropped, which isn't an internet outage.
        internet = pc_ok or (router_ms is not None and house_online(s["router_host"]))
        now = time.time()
        self.store.x("INSERT INTO checks(ts,internet,router,latency_ms) VALUES(?,?,?,?)",
                     (now, int(internet), int(router_ms is not None), min(lat) if lat else None))
        st = self.state
        st.update(last_check=now, latency_ms=min(lat) if lat else None, router=router_ms is not None)

        # Router reachability from this PC (2 misses in a row before declaring it down).
        self._router_fails = 0 if router_ms is not None else self._router_fails + 1
        if self._router_fails >= 2 and not st["router_down_id"]:
            st["router_down_id"] = self.store.event("router_down", "Router unreachable from this PC", severity="error",
                                                    detail="Check the router's power, or this PC's network cable/adapter.")
            self.notify("Orbi router unreachable", "This PC can't reach the router.")
        elif router_ms is not None and st["router_down_id"]:
            self._close(st["router_down_id"], "Router reachable again")
            st["router_down_id"] = None

        # Internet outage (2 misses in a row, so a single dropped probe isn't an outage).
        self._fails = 0 if internet else self._fails + 1
        if self._fails >= 2 and not st["outage_id"]:
            cause = self._outage_cause()
            st["outage_wan_ip"] = (st["wan"] or {}).get("ip")
            st["outage_id"] = self.store.event("outage", "Internet down", detail=cause, severity="error",
                                               ts=now - self._fails * s["health_interval"])
            self.notify("Internet is down", cause)
        elif internet and st["outage_id"]:
            ev = self.store.one("SELECT * FROM events WHERE id=?", (st["outage_id"],))
            dur = now - ev["ts"]
            found = self._outage_aftermath(dur)
            self._close(st["outage_id"], f"{ev['detail']} {found} Back after {fmt_duration(dur)}.".replace("  ", " ").strip())
            self.notify("Internet is back", f"Outage lasted {fmt_duration(dur)}. {found}".strip())
            st["outage_id"] = None
        st["internet"] = st["outage_id"] is None  # a single missed probe doesn't count as offline

        # Only this PC lost the internet (2 misses in a row): say why, without calling it an outage.
        self._pc_fails = self._pc_fails + 1 if (internet and not pc_ok) else 0
        if self._pc_fails >= 2 and not st["pc_offline_id"]:
            title, detail, note = self._pc_offline_cause(s["router_host"])
            st["pc_offline_id"] = self.store.event("pc_offline", title, detail=detail, severity="warn",
                                                   ts=now - self._pc_fails * s["health_interval"])
            self.notify(title, note)
        elif pc_ok and st["pc_offline_id"]:
            ev = self.store.one("SELECT * FROM events WHERE id=?", (st["pc_offline_id"],))
            dur = now - ev["ts"]
            self._close(st["pc_offline_id"], f"{ev['detail']} Back after {fmt_duration(dur)}.")
            self.notify("This PC is back online", f"It was cut off for {fmt_duration(dur)}")
            st["pc_offline_id"] = None

        # Satellites: only meaningful while this PC can reach the router itself.
        if router_ms is not None:
            self.check_satellites()

    def check_satellites(self):
        """Probes each known satellite directly, so a dropped one is noticed within a couple of
        health checks instead of waiting for the slower device scan."""
        known = self.store.get("satellites", {})
        if not known:
            return
        for s in known.values():
            up = bool(s.get("ip")) and (tcp_ok(s["ip"], 443, 2.5) is not None or tcp_ok(s["ip"], 80, 2.5) is not None)
            if up:
                self._missing_sats.pop(s["mac"], None)
                if not s.get("online", True):
                    s["online"] = True
                    self._sat_back(s)
            else:
                self._sat_missed(s)
        self.store.put("satellites", known)
        self.state["satellites"] = list(known.values())

    def _sat_missed(self, s):
        """Counts a miss (router scan or direct probe); two in a row marks the satellite offline."""
        if not s.get("online", True):
            return
        self._missing_sats[s["mac"]] = self._missing_sats.get(s["mac"], 0) + 1
        if self._missing_sats[s["mac"]] >= 2:
            s["online"] = False
            s["devices"] = 0
            self.store.event("satellite", f"{s['name']} went offline", severity="error", mac=s["mac"])
            self.notify("Orbi satellite offline", f"{s['name']} lost its connection to the router.")

    def _sat_back(self, s):
        self.store.event("satellite", f"{s['name']} is back online", mac=s["mac"])
        self.notify("Satellite back online", s["name"])

    def _outage_cause(self) -> str:
        if not self.router:
            return ""
        try:
            wan = self.router.wan()
            self.state["wan"] = wan
            return "Router is up but its internet (WAN) cable/modem link is down." if not wan["link_up"] else \
                "Router and modem link are up; the problem is likely with your internet provider."
        except RouterError:
            return "The router isn't responding either."

    def _pc_offline_cause(self, router_host):
        """(title, detail, notification) for when the router is online but this PC isn't."""
        route = internet_route(router_host)
        if route["vpn"]:
            name = adapter_name(route["local_ip"]) or "a VPN"
            return ("Your VPN dropped; the internet is fine",
                    f"The router is still online, but this PC sends its internet traffic through {name} ({route['local_ip']}), "
                    "and that stopped working. Reconnect the VPN, or check with whoever runs it.",
                    "The house internet is fine; reconnect your VPN.")
        return ("This PC lost internet; the rest of the house is online",
                "The router is still online, so the problem is on this PC: its network adapter or cable, a firewall or "
                "security app, a proxy, or a VPN's kill switch blocking traffic.",
                "The rest of the house is online; the problem is on this PC.")

    def _outage_aftermath(self, duration: float) -> str:
        """What the router says about an outage once it's over: did it restart, did the public IP change?"""
        if not self.router:
            return ""
        found = []
        try:
            secs = uptime_seconds(self.router.uptime())
            if secs is not None and secs < duration + 300:
                found.append("The router restarted during it (power cut, crash or firmware update).")
            wan = self.router.wan()
            self.state["wan"] = wan
            before = self.state.get("outage_wan_ip")
            if before and wan.get("ip") and wan["ip"] != before:
                found.append(f"Your public IP changed ({before} → {wan['ip']}), so the modem or your provider reset the connection.")
        except RouterError:
            pass
        return " ".join(found)

    def _close(self, event_id, detail):
        self.store.close_event(event_id, detail=detail)

    # ---- device & satellite scans ----
    def scan_loop(self):
        self._every(lambda: config.load()["scan_interval"], self.scan)

    def scan(self):
        if not self.router:
            return
        try:
            if not self.state["info"]:
                self.state["info"] = self.router.info()
            self.state["wan"] = self.router.wan()
            self._watch_filter(self.state["wan"].get("dns"))
            self.state["system"] = self.router.system()
            sats = self.router.satellites()
            devices = self.router.devices()
            self.state["access_control"] = self.router.access_control_enabled()
        except RouterError as e:
            self.state["scan_error"] = str(e)
            return
        self.state.update(scan_error=None, last_scan=time.time())
        self._update_satellites(sats, devices)
        self._update_devices(devices)
        self._verify_blocks(devices)

    def _update_satellites(self, sats, devices):
        counts = {}
        for d in devices:
            counts[d["ap_mac"]] = counts.get(d["ap_mac"], 0) + 1
        known = self.store.get("satellites", {})
        seen = {s["mac"] for s in sats}
        for s in sats:
            s["devices"] = counts.get(s["mac"], 0)
            prev = known.get(s["mac"], {})
            was_offline = s["mac"] in known and not prev.get("online", True)
            s.setdefault("backhaul_kind", backhaul_kind(s.get("backhaul")))
            s["usually_wired"] = prev.get("usually_wired", False) or s["backhaul_kind"] == "wired"
            s["backhaul_kind"] = self._settled_backhaul(s, prev)
            known[s["mac"]] = {**s, "online": True}
            if was_offline:
                self._sat_back(known[s["mac"]])
            self._missing_sats.pop(s["mac"], None)
        for mac, s in known.items():
            if mac not in seen:
                self._sat_missed(s)
        self.store.put("satellites", known)
        router_mac = self._router_mac(sats)
        self.state["satellites"] = list(known.values())
        self.state["router_devices"] = counts.get(router_mac, 0) if router_mac else None

    def _settled_backhaul(self, s, prev) -> str | None:
        """Reports a wired <-> wireless backhaul switch once two scans in a row agree (a satellite
        rebooting or re-linking can show the other type briefly). Returns the backhaul type to keep."""
        now, before = s["backhaul_kind"], prev.get("backhaul_kind")
        if not before or not now or now == before:
            self._backhaul_changes.pop(s["mac"], None)
            return now or before
        kind, seen = self._backhaul_changes.get(s["mac"], (now, 0))
        seen = seen + 1 if kind == now else 1
        if seen < 2:
            self._backhaul_changes[s["mac"]] = (now, seen)
            return before
        self._backhaul_changes.pop(s["mac"], None)
        if now == "wireless":
            band = f" ({s['backhaul']})" if s.get("backhaul") else ""
            self.store.event("satellite", f"{s['name']} switched to wireless backhaul",
                             detail=f"It was connected by cable and now links to the router over Wi-Fi{band}, so it's slower. "
                                    "Check the Ethernet cable and the switch port, then reboot the satellite.",
                             severity="warn", mac=s["mac"])
            self.notify("Satellite lost its wired link", f"{s['name']} switched to wireless backhaul{band}")
        else:
            self.store.event("satellite", f"{s['name']} is back on wired backhaul", mac=s["mac"])
            self.notify("Satellite wired again", f"{s['name']} is using its Ethernet backhaul again")
        return now

    def _router_mac(self, sats):
        parents = {s["parent_mac"] for s in sats if s.get("parent_mac")}
        return next(iter(parents), None)

    def _update_devices(self, devices):
        now = time.time()
        first_scan = self.store.get("first_scan_done", False)
        alert_new = config.load()["alert_new_devices"]
        online = set()
        for d in devices:
            mac = d["mac"]
            online.add(mac)
            row = self.store.one("SELECT mac FROM devices WHERE mac=?", (mac,))
            snap = json.dumps(d)
            if row:
                self.store.x("UPDATE devices SET router_name=?, model=COALESCE(NULLIF(?,''),model), last_seen=?, last_ip=?, online=1, snapshot=? WHERE mac=?",
                             (d["name"], d["model"], now, d["ip"], snap, mac))
            else:
                self.store.x("INSERT INTO devices(mac,router_name,model,first_seen,last_seen,last_ip,online,snapshot) VALUES(?,?,?,?,?,?,1,?)",
                             (mac, d["name"], d["model"], now, now, d["ip"], snap))
                if first_scan:
                    self._handle_new_device(d, alert_new)
        if online:
            marks = ",".join("?" * len(online))
            self.store.x(f"UPDATE devices SET online=0 WHERE online=1 AND mac NOT IN ({marks})", tuple(online))
        if not first_scan:
            self.store.put("first_scan_done", True)

    def _handle_new_device(self, d, alert):
        """A never-seen MAC. If its name matches devices in a profile, it's probably that person's device
        with a new private address, but a name is easy to fake (rename a phone to match a parent's laptop),
        so it's held for approval with that profile pre-selected rather than joined automatically."""
        mac, label = d["mac"], d["name"] or d["model"] or d["mac"]
        settings = config.load()
        named = self.store.q("SELECT router_name, profile_id FROM devices WHERE mac != ? AND router_name != ''", (mac,))
        pid = parental.name_match_profile(d["name"], named)
        private = " (private address)" if parental.is_randomized_mac(mac) else ""
        # Muted MACs are still recorded as events (audit trail is kept) but raise no notification.
        muted = norm_mac(mac) in {norm_mac(m) for m in settings.get("mute_new_device_macs", [])}
        if pid is not None and mac not in self.protected:
            pname = self.store.one("SELECT name FROM profiles WHERE id=?", (pid,))["name"]
            self.store.x("UPDATE devices SET profile_id=?, manual_block=1, held=1 WHERE mac=?", (pid, mac))
            self.store.event("new_device", f"{label} came back with a new address{private}",
                             detail=f"Blocked until you approve it (it'll go in {pname}) · {d['ip']} · {mac}", severity="warn", mac=mac)
            if not muted:
                self.notify("Known device, new address?", f"{label} looks like {pname}'s device. Approve it in Devices.")
        elif settings.get("hold_new_devices") and mac not in self.protected:
            self.store.x("UPDATE devices SET manual_block=1, held=1 WHERE mac=?", (mac,))
            self.store.event("new_device", f"New device held: {label}{private}",
                             detail=f"Blocked until you approve it in Devices · {d['ip']} · {mac} · {d['connection']}", severity="warn", mac=mac)
            if not muted:
                self.notify("New device waiting for approval", f"{label} ({d['ip']}) is blocked until you approve it")
        elif alert:
            default = self.default_profile_id()
            dname = self.store.one("SELECT name FROM profiles WHERE id=?", (default,))["name"] if default else None
            self.store.event("new_device", f"New device joined: {label}{private}",
                             detail=f"{d['ip']} · {mac} · {d['connection']}" + (f" · follows {dname} (default)" if dname else ""),
                             severity="warn", mac=mac)
            if not muted:
                self.notify("New device on your network", f"{label} ({d['ip']})")
        self.wake_enforcer.set()

    # ---- parental controls / blocking ----
    def enforce_loop(self):
        while not self.stop_event.is_set():
            try:
                self.enforce()
            except Exception:
                log.exception("enforce failed")
            self.wake_enforcer.wait(20)
            self.wake_enforcer.clear()

    def desired(self, now=None) -> dict[str, str]:
        profiles = self.store.q("SELECT * FROM profiles")
        rules = self.store.q("SELECT * FROM rules")
        devices = self.store.q("SELECT mac, profile_id, manual_block, online, last_seen FROM devices")
        return parental.desired_blocks(profiles, rules, devices, now or datetime.now(), self.protected_macs(),
                                       self.default_profile_id())

    def default_profile_id(self):
        pid = config.load().get("default_profile_id")
        return pid if pid is not None and self.store.one("SELECT id FROM profiles WHERE id=?", (pid,)) else None

    def enforce(self):
        """Make the router's block list match what profiles and manual blocks want.
        Only devices this app blocked are ever unblocked by it."""
        if not self.router:
            return
        with self._enforce_lock:
            self._enforce()

    def _enforce(self):
        want = self.desired()
        applied = {r["mac"]: r for r in self.store.q("SELECT * FROM applied_blocks")}
        to_block = [m for m in want if m not in applied]
        to_unblock = [m for m in applied if m not in want]
        if not to_block and not to_unblock:
            self.state["enforce_error"] = None
            return
        errors = []
        try:
            ac_on = self.router.access_control_enabled() if to_block else True
        except RouterError as e:
            self.state["enforce_error"] = f"router not responding: {e}"
            return
        if not ac_on:
            # Access Control must be on for blocks to take effect. With the Orbi's default
            # "allow new devices" policy, turning it on doesn't affect anything else; this PC
            # is explicitly allowed first as a safety net.
            for mac in self.protected:
                try:
                    self.router.set_blocked(mac, False)
                except RouterError:
                    pass
            self.router.enable_access_control()
            self.store.event("parental", "Turned on the router's Access Control", detail="Needed to block devices.")
        for mac in to_block:
            try:
                self.router.set_blocked(mac, True)
                self.store.x("INSERT OR REPLACE INTO applied_blocks(mac,reason,since) VALUES(?,?,?)", (mac, want[mac], time.time()))
                self.mark_blocked(mac, True)
                self.store.event("block", f"Blocked {self.device_label(mac)}", detail=want[mac], mac=mac)
            except RouterError as e:
                errors.append(f"block {mac}: {e}")
        for mac in to_unblock:
            try:
                self.router.set_blocked(mac, False)
                self.store.x("DELETE FROM applied_blocks WHERE mac=?", (mac,))
                self.mark_blocked(mac, False)
                self.store.event("block", f"Unblocked {self.device_label(mac)}", detail=applied[mac]["reason"], mac=mac)
            except RouterError as e:
                errors.append(f"unblock {mac}: {e}")
        self.state["enforce_error"] = "; ".join(errors) or None

    def _verify_blocks(self, devices):
        """Self-heal: if the router's view drifts from ours (router reset, someone changed
        it in the Orbi app), re-apply on the next enforce pass."""
        want = self.desired()
        drift = False
        if want and self.state["access_control"] is False:
            # Access Control was turned off elsewhere (e.g. the Orbi app): blocks aren't enforced.
            self.store.x("DELETE FROM applied_blocks")
            self.store.event("parental", "Access Control was turned off outside this app; turning it back on",
                             severity="warn")
            self.wake_enforcer.set()
            return
        for d in devices:
            if d["mac"] in want and not d["blocked"]:
                self.store.x("DELETE FROM applied_blocks WHERE mac=?", (d["mac"],))
                drift = True
        if drift:
            self.wake_enforcer.set()

    def mark_blocked(self, mac, blocked: bool):
        """Keep the cached router view current until the next scan confirms it."""
        self.store.x("UPDATE devices SET snapshot=json_set(COALESCE(NULLIF(snapshot,''),'{}'),'$.blocked',json(?)) WHERE mac=?",
                     ("true" if blocked else "false", mac))

    def device_label(self, mac):
        r = self.store.one("SELECT alias, router_name, model FROM devices WHERE mac=?", (mac,))
        return (r and (r["alias"] or r["router_name"] or r["model"])) or mac

    # ---- traffic ----
    def traffic_loop(self):
        self._every(lambda: config.load()["traffic_interval"], self.record_traffic)

    def record_traffic(self):
        if self.router:
            self.store.x("INSERT INTO traffic(ts,data) VALUES(?,?)", (time.time(), json.dumps(self.router.traffic())))

    # ---- speed tests ----
    def start_speedtest(self, trigger="manual") -> bool:
        st = self.state["speedtest"]
        if st["running"] or not self.router:
            return False
        st.update(running=True, error=None, started=time.time())
        threading.Thread(target=self._run_speedtest, args=(trigger,), name="speedtest-run", daemon=True).start()
        return True

    def _run_speedtest(self, trigger):
        st = self.state["speedtest"]
        try:
            self.router.start_speedtest()
            time.sleep(8)
            deadline = time.time() + 150
            result = None
            while time.time() < deadline and not self.stop_event.is_set():
                result = self.router.speedtest_poll()
                if result:
                    break
                time.sleep(4)
            if not result or result.get("down") is None:
                raise RouterError("The router didn't return a result in time")
            self.store.x("INSERT INTO speedtests(ts,down,up,ping,trigger) VALUES(?,?,?,?,?)",
                         (time.time(), result["down"], result["up"], result["ping"], trigger))
        except Exception as e:
            st["error"] = str(e)
            log.warning("speed test failed: %s", e)
        finally:
            st["running"] = False

    def speedtest_schedule_loop(self):
        self._every(lambda: 30, self.speedtest_tick)

    def speedtest_tick(self, now: datetime | None = None):
        """Run the daily test at its time; if the PC was asleep, catch up within 2 hours, never later."""
        at = config.load().get("speedtest_daily_at")
        if not at:
            return
        now = now or datetime.now()
        h, m = map(int, at.split(":"))
        due = now.replace(hour=h, minute=m, second=0, microsecond=0)
        key = now.strftime("%Y-%m-%d")
        if due <= now < due + timedelta(hours=2) and self.store.get("speedtest_last_day") != key:
            self.store.put("speedtest_last_day", key)
            self.start_speedtest("scheduled")

    # ---- router log: blocked VPN attempts, failed admin logins, DHCP history ----
    def routerlog_loop(self):
        self.stop_event.wait(45)  # let the first scan finish first
        self._every(lambda: config.load()["log_interval"], self.ingest_router_log)

    def ingest_router_log(self):
        if not self.router:
            return
        entries = self.log_fetcher()
        first_run = not self.store.one("SELECT 1 AS x FROM router_log LIMIT 1")
        new = []
        for e in reversed(entries):  # oldest first
            before = self.store.db.total_changes
            self.store.x("INSERT OR IGNORE INTO router_log(ts,kind,source,text) VALUES(?,?,?,?)", (e["ts"], e["kind"], e["source"], e["text"]))
            if self.store.db.total_changes > before:
                new.append(e)
        if first_run:
            return  # the backlog is history, not news
        mine = {d["last_ip"] for d in self.store.q("SELECT last_ip FROM devices WHERE mac IN (%s)" % ",".join("?" * len(self.protected)),
                                                   tuple(self.protected))} if self.protected else set()
        alerted = set()
        for e in new:
            kind = e["kind"]
            if kind.startswith("service blocked: Block-VPN"):
                who = self.device_by_ip(e["source"])
                key = ("vpn", e["source"])
                if key in alerted or self._recent_alert("vpn_attempt", e["source"], 3600):
                    continue
                alerted.add(key)
                self.store.event("vpn_attempt", f"{who} tried to use a VPN", detail=f"Blocked by the router ({kind.split(': ', 1)[1]}) · {e['source']}",
                                 severity="warn", mac=self.mac_by_ip(e["source"]), ts=e["ts"])
                self.notify("VPN attempt blocked", f"{who} tried to connect to a VPN")
            elif kind == "Admin login failure" and e["source"] not in mine:
                if not config.load().get("alert_admin_login_failures", True):
                    continue  # failed-login logging disabled: no event, no notification
                if self._recent_alert("admin_fail", e["source"], 3600):
                    continue
                self.store.event("admin_fail", "Failed login to the router's admin page", detail=f"From {self.device_by_ip(e['source'])} ({e['source']})",
                                 severity="error", mac=self.mac_by_ip(e["source"]), ts=e["ts"])
                self.notify("Router login failed", f"Someone at {e['source']} tried to log in to the Orbi admin page")

    def _recent_alert(self, kind, source, seconds):
        return self.store.one("SELECT 1 AS x FROM events WHERE kind=? AND detail LIKE ? AND ts > ?",
                              (kind, f"%{source}%", time.time() - seconds)) is not None

    def device_by_ip(self, ip):
        r = self.store.one("SELECT alias, router_name, model, mac FROM devices WHERE last_ip=? ORDER BY last_seen DESC LIMIT 1", (ip,))
        return (r and (r["alias"] or r["router_name"] or r["model"] or r["mac"])) or f"Device at {ip}"

    def mac_by_ip(self, ip):
        r = self.store.one("SELECT mac FROM devices WHERE last_ip=? ORDER BY last_seen DESC LIMIT 1", (ip,))
        return r["mac"] if r else ""

    # ---- slow router changes run as background jobs the UI can poll ----
    def run_job(self, name: str, fn) -> bool:
        job = self.jobs.get(name)
        if job and job["running"]:
            return False
        self.jobs[name] = {"running": True, "started": time.time(), "result": None, "error": None}

        def work():
            try:
                self.jobs[name]["result"] = fn()
            except Exception as e:
                log.exception("job %s failed", name)
                self.jobs[name]["error"] = str(e)
            finally:
                self.jobs[name]["running"] = False
                self.jobs[name]["finished"] = time.time()
        ctx = contextvars.copy_context()  # so events from the job still say who asked for it
        threading.Thread(target=ctx.run, args=(work,), name=f"job-{name}", daemon=True).start()
        return True

    def refresh_advanced(self):
        with self.ui_factory() as ui:
            data = ui.read_all()
        if self.router:
            data["uptime"] = self.router.uptime()
            data["wifi"] = self.router.wifi()
        self.advanced = {"data": data, "ts": time.time()}
        self._watch_block_sites(data.get("block_sites"))
        return data

    def _watch_block_sites(self, now):
        """Alert when whole-house blocking gets weaker (sites removed or blocking turned off), however it happened."""
        if not now:
            return
        before = self.store.get("block_sites_last")
        self.store.put("block_sites_last", {"mode": now.get("mode"), "keywords": sorted(now.get("keywords") or [])})
        if not before or before.get("mode") == "never":
            return
        was = set(before.get("keywords") or [])
        removed = sorted(was if now.get("mode") == "never" else was - set(now.get("keywords") or []))
        weaker = removed or (before.get("mode") == "always" and now.get("mode") == "perschedule")
        if not weaker:
            return
        what = f"No longer blocked: {', '.join(removed)}" if removed else "Changed from always on to a schedule"
        self.store.event("block_loosened", "Whole-house blocking was loosened", detail=what, severity="warn")
        self.notify("Blocked sites were unblocked", what)

    def _watch_filter(self, dns):
        """Alert when the router's DNS stops pointing at a family filter (or switches to a different one)."""
        from .filtering import PROVIDERS, provider_for
        if not dns:
            return
        now, before = provider_for(dns), self.store.get("filter_last")
        self.store.put("filter_last", now or "")
        if before and now != before:
            name = PROVIDERS[now]["name"] if now else f"no filtering ({', '.join(dns)})"
            self.store.event("filter_changed", "Content filter changed", detail=f"{PROVIDERS[before]['name']} → {name}",
                             severity="warn" if not now else "info")
            if not now:
                self.notify("Content filter turned off", f"The router no longer uses {PROVIDERS[before]['name']}")

    # ---- app updates ----
    def update_loop(self):
        self.stop_event.wait(60)  # let startup settle first
        self._every(lambda: 12 * 3600, self.check_updates)

    def check_updates(self, force: bool = False) -> dict:
        from . import updater
        if not force and not config.load()["check_updates"]:
            return self.state.get("update") or {}
        st = updater.check()
        self.state["update"] = st
        if st["available"] and not st["git_checkout"] and self.store.get("update_notified") != st["latest"]:
            self.store.put("update_notified", st["latest"])
            self.store.event("update", f"Orbi Control {st['latest']} is available", detail="More → Updates")
            self.notify("Update available", f"Orbi Control {st['latest']} is ready to install (More → Updates).")
        return st

    def maintenance_loop(self):
        self._every(lambda: 6 * 3600, self.store.prune)


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s}s" if s and m < 10 else f"{m}m"
    h, m = divmod(m, 60)
    if h < 48:
        return f"{h}h {m}m"
    return f"{h // 24}d {h % 24}h"
