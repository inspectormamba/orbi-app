"""HTTP API + the web app (served to this PC's browser and phones on the home network)."""
import io
import os
import re
import tempfile
import socket
import time
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, config, files, parental
from .monitor import Monitor, fmt_duration
from .router import RouterClient, RouterError, norm_mac

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
OPEN_PATHS = {"/api/session", "/api/login", "/api/setup"}
DNS_FILTERS = {  # what each family DNS service enforces was verified by querying them directly
    "185.228.168.168": "CleanBrowsing Family filter", "185.228.169.168": "CleanBrowsing Family filter",
    "185.228.168.10": "CleanBrowsing Adult filter", "185.228.169.11": "CleanBrowsing Adult filter",
    "185.228.168.9": "CleanBrowsing Security filter", "185.228.169.9": "CleanBrowsing Security filter",
    "208.67.222.123": "OpenDNS FamilyShield", "208.67.220.123": "OpenDNS FamilyShield",
    "1.1.1.3": "Cloudflare for Families", "1.0.0.3": "Cloudflare for Families",
    "94.140.14.15": "AdGuard Family", "94.140.15.16": "AdGuard Family",
}
HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class PinBody(BaseModel):
    pin: str


class SetupBody(BaseModel):
    pin: str
    router_password: str | None = None


class DevicePatch(BaseModel):
    alias: str | None = None
    profile_id: int | None = Field(default=None)
    clear_profile: bool = False


class BlockBody(BaseModel):
    blocked: bool


class ProfileBody(BaseModel):
    name: str
    emoji: str = ""


class MinutesBody(BaseModel):
    minutes: int | None = None  # None = until resumed


class RuleBody(BaseModel):
    label: str = "Bedtime"
    days: str = "0123456"
    start: str
    end: str
    enabled: bool = True


class EnabledBody(BaseModel):
    enabled: bool


class ConfirmBody(BaseModel):
    confirm: bool = False


class SettingsPatch(BaseModel):
    health_interval: int | None = None
    scan_interval: int | None = None
    speedtest_daily_at: str | None = None
    alert_new_devices: bool | None = None
    alert_admin_login_failures: bool | None = None
    mute_new_device_macs: list[str] | None = None
    router_host: str | None = None


class PasswordBody(BaseModel):
    password: str


class FamilySettings(BaseModel):
    default_profile_id: int | None = None
    hold_new_devices: bool = False


class AssignBody(BaseModel):
    profile_id: int


class ProviderBody(BaseModel):
    provider: str


class SiteBlockBody(BaseModel):
    mode: str  # never | always | perschedule
    keywords: list[str] = []
    days: str = "0123456"
    start: str = "00:00"
    end: str = "00:00"


class FileAccessBody(BaseModel):
    enabled: bool
    pin: str = ""


class FileOpBody(BaseModel):
    path: str
    name: str = ""
    recursive: bool = False


class PinChange(BaseModel):
    current: str
    new: str


class ExtraPinBody(BaseModel):
    current: str
    new: str
    label: str = ""


def iso(dt):
    return dt.isoformat(timespec="minutes") if dt else None


def create_app(monitor: Monitor) -> FastAPI:
    store = monitor.store
    throttle = auth.Throttle()
    app = FastAPI(title="Orbi Control", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path not in OPEN_PATHS:
            if not auth.valid_session(request.cookies.get(auth.COOKIE)):
                return JSONResponse({"detail": "Sign in required"}, status_code=401)
        response = await call_next(request)
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def router() -> RouterClient:
        if not monitor.router:
            raise HTTPException(409, "Router password not set yet (Settings)")
        return monitor.router

    def set_cookie(resp: Response):
        resp.set_cookie(auth.COOKIE, auth.make_session(), max_age=auth.SESSION_DAYS * 86400, httponly=True, samesite="strict")

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "?"

    # ---------- session ----------
    @app.get("/api/session")
    def session(request: Request):
        s = config.load()
        return {"authenticated": auth.valid_session(request.cookies.get(auth.COOKIE)), "pin_set": bool(s["pin_hash"]),
                "router_configured": bool(s["router_password_enc"])}

    @app.post("/api/setup")
    def setup(body: SetupBody, response: Response):
        if config.load()["pin_hash"]:
            raise HTTPException(409, "Already set up")
        if len(body.pin) < auth.MIN_PIN:
            raise HTTPException(400, f"Use at least {auth.MIN_PIN} digits or characters")
        if body.router_password:
            _save_router_password(body.router_password)
        config.save({"pin_hash": auth.hash_pin(body.pin)})
        set_cookie(response)
        return {"ok": True}

    @app.post("/api/login")
    def login(body: PinBody, request: Request, response: Response):
        ip = client_ip(request)
        wait = throttle.wait_seconds(ip)
        if wait:
            raise HTTPException(429, f"Too many wrong PINs. Try again in {fmt_duration(wait)}.")
        s = config.load()
        if not s["pin_hash"] or not auth.check_any_pin(body.pin, s):
            throttle.failure(ip)
            raise HTTPException(401, "Wrong PIN")
        throttle.success(ip)
        set_cookie(response)
        return {"ok": True}

    @app.post("/api/logout")
    def logout(response: Response):
        response.delete_cookie(auth.COOKIE)
        return {"ok": True}

    # ---------- status ----------
    def uptime(hours: float) -> float | None:
        start = time.time() - hours * 3600
        first = store.one("SELECT MIN(ts) AS t FROM checks")
        if not first or first["t"] is None:
            return None
        start = max(start, first["t"])
        window = time.time() - start
        if window <= 0:
            return None
        down = 0.0
        for e in store.q("SELECT ts, end_ts FROM events WHERE kind='outage' AND (end_ts IS NULL OR end_ts > ?)", (start,)):
            down += min(e["end_ts"] or time.time(), time.time()) - max(e["ts"], start)
        return round(max(0.0, 100 * (1 - down / window)), 3)

    @app.get("/api/status")
    def status():
        st = monitor.state
        s = config.load()
        outage = store.one("SELECT ts, detail FROM events WHERE id=?", (st["outage_id"],)) if st["outage_id"] else None
        last_speed = store.one("SELECT * FROM speedtests ORDER BY ts DESC LIMIT 1")
        traffic = store.one("SELECT ts, data FROM traffic ORDER BY ts DESC LIMIT 1")
        dns = st["wan"].get("dns", []) if st["wan"] else []
        filters = sorted({DNS_FILTERS[d] for d in dns if d in DNS_FILTERS})
        counts = {
            "outages_24h": store.one("SELECT COUNT(*) c FROM events WHERE kind='outage' AND ts > ?", (time.time() - 86400,))["c"],
            "outages_7d": store.one("SELECT COUNT(*) c FROM events WHERE kind='outage' AND ts > ?", (time.time() - 7 * 86400,))["c"],
            "devices_online": store.one("SELECT COUNT(*) c FROM devices WHERE online=1")["c"],
            "unseen_alerts": store.one("SELECT COUNT(*) c FROM events WHERE seen=0 AND severity IN ('warn','error')")["c"],
        }
        return {
            "router_configured": bool(s["router_password_enc"]),
            "internet": st["internet"], "router": st["router"], "latency_ms": st["latency_ms"], "last_check": st["last_check"],
            "outage": outage, "uptime": {"24h": uptime(24), "7d": uptime(24 * 7), "30d": uptime(24 * 30)},
            "info": st["info"], "wan": st["wan"], "system": st["system"], "satellites": st["satellites"],
            "router_devices": st.get("router_devices"), "last_scan": st["last_scan"], "scan_error": st["scan_error"],
            "speedtest": {**st["speedtest"], "last": last_speed}, "traffic": _traffic_json(traffic),
            "access_control": st["access_control"], "enforce_error": st["enforce_error"],
            "dns_filter": filters[0] if filters else None, "router_error": monitor.router.last_error if monitor.router else None,
            **counts,
        }

    # ---------- devices ----------
    def ap_names():
        names = {}
        for sat in monitor.state["satellites"]:
            names[sat["mac"]] = sat["name"]
            if sat.get("parent_mac"):
                names.setdefault(sat["parent_mac"], "Router")
        return names

    @app.get("/api/devices")
    def devices():
        import json
        want = monitor.desired()
        applied = {r["mac"] for r in store.q("SELECT mac FROM applied_blocks")}
        profiles = {p["id"]: p for p in store.q("SELECT id, name, emoji FROM profiles")}
        protected = monitor.protected_macs()
        aps = ap_names()
        default = monitor.default_profile_id()
        now = datetime.now()
        out = []
        for d in store.q("SELECT * FROM devices ORDER BY online DESC, COALESCE(NULLIF(alias,''), NULLIF(router_name,''), mac) COLLATE NOCASE"):
            snap = json.loads(d["snapshot"] or "{}")
            prof = profiles.get(d["profile_id"])
            inherited = None
            if not prof and default is not None and parental.effective_profile(d, default, now) == default:
                inherited = profiles.get(default)
            out.append({
                "mac": d["mac"], "name": d["alias"] or d["router_name"] or d["model"] or d["mac"], "alias": d["alias"],
                "router_name": d["router_name"], "model": d["model"], "ip": d["last_ip"], "online": bool(d["online"]),
                "connection": snap.get("connection", ""), "signal": snap.get("signal"), "link_rate": snap.get("link_rate"),
                "ap": aps.get(snap.get("ap_mac"), "Router" if snap.get("connection") == "wired" else ""),
                "ssid": snap.get("ssid", ""), "profile": prof, "default_profile": inherited, "manual_block": bool(d["manual_block"]),
                "held": bool(d["held"]) and bool(d["manual_block"]), "randomized": parental.is_randomized_mac(d["mac"]),
                "blocked": d["mac"] in applied or bool(snap.get("blocked")), "block_reason": want.get(d["mac"]) or
                ("Blocked on the router" if snap.get("blocked") else ""), "protected": d["mac"] in protected,
                "first_seen": d["first_seen"], "last_seen": d["last_seen"],
            })
        return out

    @app.patch("/api/devices/{mac}")
    def patch_device(mac: str, body: DevicePatch):
        mac = norm_mac(mac)
        if not store.one("SELECT mac FROM devices WHERE mac=?", (mac,)):
            raise HTTPException(404, "Unknown device")
        if body.alias is not None:
            store.x("UPDATE devices SET alias=? WHERE mac=?", (body.alias.strip()[:60], mac))
        if body.clear_profile:
            store.x("UPDATE devices SET profile_id=NULL WHERE mac=?", (mac,))
        elif body.profile_id is not None:
            if not store.one("SELECT id FROM profiles WHERE id=?", (body.profile_id,)):
                raise HTTPException(404, "Unknown profile")
            store.x("UPDATE devices SET profile_id=? WHERE mac=?", (body.profile_id, mac))
        monitor.enforce()
        return {"ok": True}

    @app.post("/api/devices/{mac}/block")
    def block_device(mac: str, body: BlockBody):
        mac = norm_mac(mac)
        row = store.one("SELECT * FROM devices WHERE mac=?", (mac,))
        if not row:
            raise HTTPException(404, "Unknown device")
        if body.blocked and mac in monitor.protected_macs():
            raise HTTPException(400, "This device runs Orbi Control (or is protected), so it can't be blocked.")
        store.x("UPDATE devices SET manual_block=?, held=CASE WHEN ? THEN held ELSE 0 END WHERE mac=?", (int(body.blocked), int(body.blocked), mac))
        note = ""
        if not body.blocked:
            applied = store.one("SELECT mac FROM applied_blocks WHERE mac=?", (mac,))
            if not applied:  # blocked outside this app (e.g. in the Orbi app): undo it directly
                try:
                    router().set_blocked(mac, False)
                    monitor.mark_blocked(mac, False)
                except RouterError as e:
                    raise HTTPException(502, str(e))
        try:
            monitor.enforce()
        except RouterError as e:
            raise HTTPException(502, str(e))
        reason = monitor.desired().get(mac)
        if not body.blocked and reason:
            note = f"Still blocked by {reason}. Use Family → Extra time to allow it now."
        return {"ok": True, "note": note, "error": monitor.state["enforce_error"]}

    # ---------- family profiles ----------
    def profile_json(p, rules, devs, now):
        st = parental.profile_state(p, rules, now)
        return {**p, "rules": rules, "devices": devs, "state": {**st, "until": iso(st["until"])},
                "paused": p["paused_until"] is not None and (p["paused_until"] == parental.FOREVER or p["paused_until"] > time.time())}

    @app.get("/api/profiles")
    def profiles():
        now = datetime.now()
        out = []
        for p in store.q("SELECT * FROM profiles ORDER BY name COLLATE NOCASE"):
            rules = store.q("SELECT * FROM rules WHERE profile_id=? ORDER BY start", (p["id"],))
            devs = store.q("SELECT mac, COALESCE(NULLIF(alias,''), NULLIF(router_name,''), mac) AS name, online FROM devices WHERE profile_id=?", (p["id"],))
            out.append(profile_json(p, rules, devs, now))
        return out

    @app.post("/api/profiles")
    def create_profile(body: ProfileBody):
        name = body.name.strip()[:40]
        if not name:
            raise HTTPException(400, "Name required")
        pid = store.x("INSERT INTO profiles(name, emoji, created) VALUES(?,?,?)", (name, body.emoji[:8], time.time()))
        return {"id": pid}

    @app.patch("/api/profiles/{pid}")
    def update_profile(pid: int, body: ProfileBody):
        _profile_or_404(pid)
        store.x("UPDATE profiles SET name=?, emoji=? WHERE id=?", (body.name.strip()[:40], body.emoji[:8], pid))
        return {"ok": True}

    @app.delete("/api/profiles/{pid}")
    def delete_profile(pid: int):
        _profile_or_404(pid)
        store.x("UPDATE devices SET profile_id=NULL WHERE profile_id=?", (pid,))
        store.x("DELETE FROM profiles WHERE id=?", (pid,))
        if config.load().get("default_profile_id") == pid:
            config.save({"default_profile_id": None})
        monitor.enforce()
        return {"ok": True}

    @app.get("/api/family/settings")
    def family_settings():
        s = config.load()
        unassigned = store.one("SELECT COUNT(*) AS c FROM devices WHERE profile_id IS NULL")["c"]
        return {"default_profile_id": monitor.default_profile_id(), "hold_new_devices": bool(s.get("hold_new_devices")),
                "unassigned": unassigned}

    @app.put("/api/family/settings")
    def set_family_settings(body: FamilySettings):
        if body.default_profile_id is not None:
            _profile_or_404(body.default_profile_id)
        config.save({"default_profile_id": body.default_profile_id, "hold_new_devices": body.hold_new_devices})
        name = store.one("SELECT name FROM profiles WHERE id=?", (body.default_profile_id,))["name"] if body.default_profile_id else None
        store.event("parental", "Default profile changed", detail=f"Devices without a profile follow {name}" if name else "Devices without a profile are unrestricted")
        return {**_apply(), **family_settings()}

    @app.post("/api/family/assign-unassigned")
    def assign_unassigned(body: AssignBody):
        p = _profile_or_404(body.profile_id)
        n = store.one("SELECT COUNT(*) AS c FROM devices WHERE profile_id IS NULL")["c"]
        store.x("UPDATE devices SET profile_id=? WHERE profile_id IS NULL", (body.profile_id,))
        store.event("parental", f"Moved {n} devices into {p['name']}")
        return {**_apply(), "moved": n}

    @app.post("/api/profiles/{pid}/pause")
    def pause(pid: int, body: MinutesBody):
        p = _profile_or_404(pid)
        until = parental.FOREVER if body.minutes is None else time.time() + max(1, body.minutes) * 60
        store.x("UPDATE profiles SET paused_until=?, allow_until=NULL WHERE id=?", (until, pid))
        store.event("parental", f"Paused {p['name']}", detail="until resumed" if body.minutes is None else f"for {fmt_duration(body.minutes * 60)}")
        return _apply()

    @app.post("/api/profiles/{pid}/resume")
    def resume(pid: int):
        p = _profile_or_404(pid)
        store.x("UPDATE profiles SET paused_until=NULL WHERE id=?", (pid,))
        store.event("parental", f"Resumed {p['name']}")
        return _apply()

    @app.post("/api/profiles/{pid}/bonus")
    def bonus(pid: int, body: MinutesBody):
        p = _profile_or_404(pid)
        minutes = body.minutes or 30
        store.x("UPDATE profiles SET allow_until=?, paused_until=NULL WHERE id=?", (time.time() + minutes * 60, pid))
        store.event("parental", f"Gave {p['name']} {fmt_duration(minutes * 60)} extra time")
        return _apply()

    @app.post("/api/profiles/{pid}/bonus/cancel")
    def cancel_bonus(pid: int):
        _profile_or_404(pid)
        store.x("UPDATE profiles SET allow_until=NULL WHERE id=?", (pid,))
        return _apply()

    @app.post("/api/profiles/{pid}/rules")
    def add_rule(pid: int, body: RuleBody):
        _profile_or_404(pid)
        _validate_rule(body)
        rid = store.x("INSERT INTO rules(profile_id,label,days,start,end,enabled) VALUES(?,?,?,?,?,?)",
                      (pid, body.label.strip()[:30] or "Schedule", body.days, body.start, body.end, int(body.enabled)))
        _apply()
        return {"id": rid}

    @app.put("/api/rules/{rid}")
    def update_rule(rid: int, body: RuleBody):
        if not store.one("SELECT id FROM rules WHERE id=?", (rid,)):
            raise HTTPException(404, "Unknown schedule")
        _validate_rule(body)
        store.x("UPDATE rules SET label=?, days=?, start=?, end=?, enabled=? WHERE id=?",
                (body.label.strip()[:30] or "Schedule", body.days, body.start, body.end, int(body.enabled), rid))
        return _apply()

    @app.delete("/api/rules/{rid}")
    def delete_rule(rid: int):
        store.x("DELETE FROM rules WHERE id=?", (rid,))
        return _apply()

    def _profile_or_404(pid):
        p = store.one("SELECT * FROM profiles WHERE id=?", (pid,))
        if not p:
            raise HTTPException(404, "Unknown profile")
        return p

    def _validate_rule(body: RuleBody):
        if not HHMM.match(body.start) or not HHMM.match(body.end):
            raise HTTPException(400, "Times must be HH:MM")
        if not body.days or any(c not in "0123456" for c in body.days):
            raise HTTPException(400, "Pick at least one day")
        body.days = "".join(sorted(set(body.days)))

    def _apply():
        try:
            monitor.enforce()
        except RouterError as e:
            raise HTTPException(502, f"Saved, but the router didn't respond: {e}")
        return {"ok": True, "error": monitor.state["enforce_error"]}

    # ---------- history ----------
    @app.get("/api/history")
    def history(hours: int = 24):
        hours = max(1, min(hours, 24 * 30))
        bucket = 900 if hours <= 24 else 3600 if hours <= 24 * 7 else 4 * 3600
        start = time.time() - hours * 3600
        rows = store.q("""SELECT CAST(ts / ? AS INTEGER) * ? AS b, AVG(internet) AS up, AVG(latency_ms) AS lat, COUNT(*) AS n
                          FROM checks WHERE ts > ? GROUP BY b ORDER BY b""", (bucket, bucket, start))
        return {"bucket": bucket, "start": start, "points": rows}

    @app.get("/api/events")
    def events(limit: int = 100, kind: str | None = None):
        if kind:
            rows = store.q("SELECT * FROM events WHERE kind=? ORDER BY ts DESC LIMIT ?", (kind, min(limit, 500)))
        else:
            rows = store.q("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (min(limit, 500),))
        return rows

    @app.post("/api/events/seen")
    def events_seen():
        store.x("UPDATE events SET seen=1 WHERE seen=0")
        return {"ok": True}

    @app.get("/api/speedtests")
    def speedtests(days: int = 30):
        return store.q("SELECT * FROM speedtests WHERE ts > ? ORDER BY ts", (time.time() - days * 86400,))

    @app.post("/api/speedtest")
    def run_speedtest():
        router()
        if not monitor.start_speedtest("manual"):
            raise HTTPException(409, "A speed test is already running")
        return {"ok": True}

    @app.get("/api/traffic")
    def traffic(days: int = 30):
        import json
        out = {}
        for r in store.q("SELECT ts, data FROM traffic WHERE ts > ? ORDER BY ts", (time.time() - days * 86400,)):
            day = datetime.fromtimestamp(r["ts"]).strftime("%Y-%m-%d")
            d = json.loads(r["data"])
            out[day] = {"day": day, "down": d.get("today_down"), "up": d.get("today_up")}  # last sample of the day wins
        return list(out.values())

    # ---------- router controls ----------
    @app.get("/api/guest")
    def guest():
        try:
            return router().guest_wifi()
        except RouterError as e:
            raise HTTPException(502, str(e))

    @app.post("/api/guest")
    def set_guest(body: EnabledBody):
        try:
            router().set_guest_wifi(body.enabled)
            store.event("action", f"Guest Wi-Fi turned {'on' if body.enabled else 'off'}")
            return router().guest_wifi()
        except RouterError as e:
            raise HTTPException(502, str(e))

    @app.post("/api/router/reboot")
    def reboot(body: ConfirmBody):
        if not body.confirm:
            raise HTTPException(400, "Confirmation required")
        try:
            router().reboot()
        except RouterError as e:
            raise HTTPException(502, str(e))
        store.event("action", "Router reboot requested", detail="Internet will be down for a few minutes.", severity="warn")
        return {"ok": True}

    @app.get("/api/firmware")
    def firmware():
        try:
            return router().firmware_update()
        except RouterError as e:
            raise HTTPException(502, str(e))

    # ---------- settings ----------
    @app.get("/api/settings")
    def get_settings():
        s = config.load()
        return {k: s[k] for k in ("router_host", "health_interval", "scan_interval", "speedtest_daily_at", "alert_new_devices",
                                   "alert_admin_login_failures", "mute_new_device_macs", "port")} | {
            "router_configured": bool(s["router_password_enc"])}

    @app.patch("/api/settings")
    def patch_settings(body: SettingsPatch):
        patch = {k: v for k, v in body.model_dump().items() if v is not None}
        if "health_interval" in patch:
            patch["health_interval"] = max(10, min(patch["health_interval"], 600))
        if "scan_interval" in patch:
            patch["scan_interval"] = max(60, min(patch["scan_interval"], 3600))
        if patch.get("speedtest_daily_at") and not HHMM.match(patch["speedtest_daily_at"]):
            raise HTTPException(400, "Speed test time must be HH:MM (or empty to turn it off)")
        if "mute_new_device_macs" in patch:
            patch["mute_new_device_macs"] = sorted({norm_mac(m) for m in patch["mute_new_device_macs"] if m.strip()})
        config.save(patch)
        if "router_host" in patch:
            monitor.reload_router()
        return get_settings()

    @app.post("/api/settings/router-password")
    def router_password(body: PasswordBody):
        _save_router_password(body.password)
        return {"ok": True}

    def _save_router_password(password: str):
        s = config.load()
        try:
            RouterClient(s["router_host"], password, s["router_user"]).info()
        except RouterError:
            raise HTTPException(400, "The router rejected that password")
        config.set_router_password(password)
        monitor.reload_router()

    @app.post("/api/settings/pin")
    def change_pin(body: PinChange, request: Request, response: Response):
        if not auth.check_any_pin(body.current, config.load()):
            throttle.failure(client_ip(request))
            raise HTTPException(401, "Current PIN is wrong")
        if len(body.new) < auth.MIN_PIN:
            raise HTTPException(400, f"Use at least {auth.MIN_PIN} digits or characters")
        config.save({"pin_hash": auth.hash_pin(body.new)})
        auth.rotate_secret()  # sign out every other device
        set_cookie(response)
        return {"ok": True}

    @app.get("/api/settings/pins")
    def list_pins():
        return {"extra": [{"label": e.get("label", "")} for e in config.load().get("extra_pins", [])]}

    @app.post("/api/settings/pins")
    def add_pin(body: ExtraPinBody, request: Request):
        s = config.load()
        if not auth.check_any_pin(body.current, s):
            throttle.failure(client_ip(request))
            raise HTTPException(401, "Current PIN is wrong")
        if len(body.new) < auth.MIN_PIN:
            raise HTTPException(400, f"Use at least {auth.MIN_PIN} digits or characters")
        extra = list(s.get("extra_pins", []))
        if any(auth.check_pin(body.new, e["hash"]) for e in extra) or auth.check_pin(body.new, s["pin_hash"] or ""):
            raise HTTPException(409, "That PIN is already accepted")
        extra.append({"label": body.label.strip()[:40] or f"PIN {len(extra) + 2}", "hash": auth.hash_pin(body.new)})
        config.save({"extra_pins": extra})
        store.event("action", "Extra app PIN added", detail=f"{extra[-1]['label']} from {client_ip(request)}", severity="warn")
        return {"ok": True, "extra": [{"label": e["label"]} for e in extra]}

    @app.delete("/api/settings/pins/{label}")
    def remove_pin(label: str, request: Request):
        s = config.load()
        extra = [e for e in s.get("extra_pins", []) if e.get("label") != label]
        if len(extra) == len(s.get("extra_pins", [])):
            raise HTTPException(404, "No such PIN")
        config.save({"extra_pins": extra})
        store.event("action", f"Extra app PIN removed ({label})", detail=f"from {client_ip(request)}")
        return {"ok": True}

    @app.get("/api/access")
    def access():
        port = config.load()["port"]
        urls = [f"http://{ip}:{port}" for ip in _lan_ips()]
        return {"urls": urls, "qr_svg": _qr_svg(urls[0]) if urls else ""}

    # ---------- advanced ----------
    @app.get("/api/advanced")
    def advanced():
        adv = monitor.advanced
        if adv["data"] is None and not monitor.jobs.get("advanced", {}).get("running"):
            monitor.run_job("advanced", monitor.refresh_advanced)
        st = monitor.state
        return {"data": adv["data"], "ts": adv["ts"], "job": monitor.jobs.get("advanced"),
                "info": st["info"], "system": st["system"], "satellites": st["satellites"], "access_control": st["access_control"]}

    @app.post("/api/advanced/refresh")
    def advanced_refresh():
        router()
        monitor.run_job("advanced", monitor.refresh_advanced)
        return {"ok": True}

    @app.get("/api/routerlog")
    def routerlog(kind: str = "all", q: str = "", limit: int = 300):
        where, args = [], []
        groups = {"dhcp": "kind LIKE 'DHCP IP%'", "blocked": "(kind LIKE 'service blocked%' OR kind LIKE 'site blocked%')",
                  "logins": "kind LIKE 'Admin login%'", "upnp": "kind LIKE 'UPnP%'"}
        if kind in groups:
            where.append(groups[kind])
        if q:
            where.append("text LIKE ?")
            args.append(f"%{q}%")
        sql = "SELECT * FROM router_log" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY ts DESC LIMIT ?"
        rows = store.q(sql, (*args, min(limit, 1000)))
        names = {}
        for r in rows:
            ip = r["source"] or (re.search(r"\(([\d.]+)\)", r["kind"]) or [None, ""])[1]
            mac = (re.search(r"MAC address ([0-9A-Fa-f:]{17})", r["text"]) or [None, ""])[1].upper()
            if mac:
                d = store.one("SELECT COALESCE(NULLIF(alias,''), NULLIF(router_name,''), model) AS n FROM devices WHERE mac=?", (mac,))
                r["device"] = d["n"] if d else ""
            elif ip:
                r["device"] = names.setdefault(ip, monitor.device_by_ip(ip))
        return {"rows": rows, "total": store.one("SELECT COUNT(*) AS c FROM router_log")["c"]}

    @app.get("/api/jobs/{name}")
    def job(name: str):
        return monitor.jobs.get(name) or {"running": False}

    # ---------- content filtering (router DNS) ----------
    @app.get("/api/filtering")
    def filtering_status(check: bool = False):
        from . import filtering
        dns = (monitor.state["wan"] or {}).get("dns", [])
        out = {"providers": filtering.PROVIDERS, "current": filtering.provider_for(dns), "dns": dns, "job": monitor.jobs.get("filtering")}
        if check:
            out["check"] = filtering.check(config.load()["router_host"])
        return out

    @app.post("/api/filtering")
    def set_filtering(body: ProviderBody):
        from . import filtering
        if body.provider not in filtering.PROVIDERS:
            raise HTTPException(400, "Unknown provider")
        router()
        s = config.load()

        def apply():
            res = filtering.apply_provider(s["router_host"], config.router_password(s), body.provider)
            monitor.state["wan"] = monitor.router.wan()
            store.event("action", f"Content filter changed to {filtering.PROVIDERS[body.provider]['name']}",
                        detail="verified" if res.get("confirmed") else "applied; waiting for devices' DNS caches")
            return res
        if not monitor.run_job("filtering", apply):
            raise HTTPException(409, "A filter change is already running")
        return {"ok": True}

    # ---------- whole-house app & site blocking (router Block Sites) ----------
    @app.get("/api/siteblock")
    def siteblock():
        data = monitor.advanced["data"] or {}
        return {"block_sites": data.get("block_sites"), "schedule": data.get("schedule"), "ts": monitor.advanced["ts"],
                "job": monitor.jobs.get("siteblock")}

    @app.put("/api/siteblock")
    def set_siteblock(body: SiteBlockBody):
        if body.mode not in ("never", "always", "perschedule"):
            raise HTTPException(400, "Mode must be never, always or perschedule")
        keywords = sorted({k.strip().lower() for k in body.keywords if k.strip()})
        bad = [k for k in keywords if not re.fullmatch(r"[a-z0-9.\-]{3,60}", k)]
        if bad:
            raise HTTPException(400, f"Use letters, numbers, dots or dashes (3+ characters): {', '.join(bad)}")
        if body.mode != "never" and not keywords:
            raise HTTPException(400, "Add at least one app or keyword to block")
        if body.mode == "perschedule":
            if not HHMM.match(body.start) or not HHMM.match(body.end) or not body.days or any(c not in "0123456" for c in body.days):
                raise HTTPException(400, "Pick days and HH:MM times for the schedule")
        router()

        def apply():
            with monitor.ui_factory() as ui:
                if body.mode == "perschedule":
                    ui.set_schedule("".join(sorted(set(body.days))), body.start, body.end)
                ui.set_block_sites(body.mode, keywords)
            store.event("action", "Whole-house blocking updated",
                        detail={"never": "off", "always": "always on", "perschedule": "on a schedule"}[body.mode] + (f": {', '.join(keywords)}" if keywords else ""))
            monitor.refresh_advanced()
            return {"ok": True}
        if not monitor.run_job("siteblock", apply):
            raise HTTPException(409, "A blocking change is already running")
        return {"ok": True}

    # ---------- files (whole PC) ----------
    @app.exception_handler(files.FileError)
    def file_error(request: Request, e: files.FileError):
        return JSONResponse({"detail": str(e)}, status_code=e.status, headers={"Cache-Control": "no-store"})

    def files_on():
        if not config.load()["file_access"]:
            raise HTTPException(403, "File access is off (More → Files)")

    @app.get("/api/files/settings")
    def file_settings():
        return {"enabled": bool(config.load()["file_access"])}

    @app.put("/api/files/settings")
    def set_file_settings(body: FileAccessBody, request: Request):
        if body.enabled:
            ip = client_ip(request)
            wait = throttle.wait_seconds(ip)
            if wait:
                raise HTTPException(429, f"Too many wrong PINs. Try again in {fmt_duration(wait)}.")
            if not auth.check_any_pin(body.pin, config.load()):
                throttle.failure(ip)
                raise HTTPException(401, "Wrong PIN")
        config.save({"file_access": body.enabled})
        store.event("files", f"File access turned {'on' if body.enabled else 'off'}", detail=f"from {client_ip(request)}",
                    severity="warn" if body.enabled else "info")
        return {"enabled": body.enabled}

    @app.get("/api/files/list")
    def file_list(path: str = ""):
        files_on()
        if not path:
            return {"path": "", "parent": None, "entries": files.drives()}
        return files.listdir(path)

    @app.get("/api/files/download")
    def file_download(path: str, request: Request):
        files_on()
        path = files.resolve(path)
        files.file_size(path)
        store.event("files", "File downloaded", detail=f"{path} → {client_ip(request)}")
        return FileResponse(path, filename=os.path.basename(path), headers={"Cache-Control": "no-store"})

    @app.put("/api/files/upload")
    async def file_upload(request: Request, dir: str, name: str, overwrite: bool = False):
        import anyio
        files_on()
        folder = files.resolve(dir)
        target = os.path.join(folder, files.check_name(name))
        if not await anyio.to_thread.run_sync(files.run, os.path.isdir, folder):
            raise HTTPException(404, "Folder not found")
        if not overwrite and await anyio.to_thread.run_sync(files.run, os.path.lexists, target):
            raise HTTPException(409, f"{name} already exists")
        fd, tmp = await anyio.to_thread.run_sync(lambda: tempfile.mkstemp(prefix=".upload-", dir=folder))
        size = 0
        try:
            with os.fdopen(fd, "wb") as f:
                async for chunk in request.stream():
                    size += len(chunk)
                    await anyio.to_thread.run_sync(f.write, chunk)
            await anyio.to_thread.run_sync(os.replace, tmp, target)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
        store.event("files", "File uploaded", detail=f"{target} ({size:,} bytes) from {client_ip(request)}")
        return {"ok": True, "path": target, "size": size}

    @app.post("/api/files/mkdir")
    def file_mkdir(body: FileOpBody, request: Request):
        files_on()
        target = files.mkdir(body.path, body.name)
        store.event("files", "Folder created", detail=f"{target} from {client_ip(request)}")
        return {"ok": True, "path": target}

    @app.post("/api/files/rename")
    def file_rename(body: FileOpBody, request: Request):
        files_on()
        target = files.rename(body.path, body.name)
        store.event("files", "Renamed", detail=f"{body.path} → {target} from {client_ip(request)}")
        return {"ok": True, "path": target}

    @app.post("/api/files/delete")
    def file_delete(body: FileOpBody, request: Request):
        files_on()
        files.delete(body.path, body.recursive)
        store.event("files", "Deleted", detail=f"{files.resolve(body.path)} from {client_ip(request)}", severity="warn")
        return {"ok": True}

    # ---------- web app ----------
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/manifest.webmanifest")
    def manifest():
        return FileResponse(WEB_DIR / "manifest.webmanifest", media_type="application/manifest+json")

    @app.get("/")
    def index():
        return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    return app


def _traffic_json(row):
    import json
    return {"ts": row["ts"], **json.loads(row["data"])} if row else None


def _lan_ips():
    ips = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((config.load()["router_host"], 80))  # no packet is sent; just picks the LAN interface
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return ips


def _qr_svg(text):
    import qrcode
    import qrcode.image.svg
    img = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()
