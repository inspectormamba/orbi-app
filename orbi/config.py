"""Settings stored in %LOCALAPPDATA%\\OrbiControl\\settings.json (secrets DPAPI-encrypted)."""
import json
import os
import threading
from pathlib import Path

from . import dpapi

DATA_DIR = Path(os.environ.get("ORBI_DATA_DIR") or Path(os.environ.get("LOCALAPPDATA", Path.home())) / "OrbiControl")
SETTINGS_FILE = DATA_DIR / "settings.json"

DEFAULTS = {
    "router_host": "192.168.1.1",
    "router_user": "admin",
    "router_password_enc": "",
    "pin_hash": "",  # pbkdf2 hash of the primary app PIN; empty until setup
    "extra_pins": [],  # additional PINs the user added: [{"label": str, "hash": str}]
    "session_secret": "",
    "port": 8470,
    "health_interval": 30,  # seconds between internet/router checks
    "scan_interval": 120,  # seconds between device/satellite scans
    "traffic_interval": 900,
    "speedtest_daily_at": "04:00",  # "" disables the scheduled speed test
    "alert_new_devices": True,
    "alert_admin_login_failures": True,  # when off, failed router admin logins are neither recorded nor notified
    "mute_new_device_macs": [],  # MACs whose new-device joins are still recorded but raise no notification
    "log_interval": 600,  # seconds between router-log reads (each is a short admin login)
    "default_profile_id": None,  # profile followed by devices that aren't in one (incl. brand-new devices)
    "hold_new_devices": False,  # block never-seen devices until a parent approves them
    "protected_macs": [],  # never blocked (this PC is added automatically)
    "file_access": False,  # whole-PC file browser in the web app; turning it on needs the PIN
}

_lock = threading.Lock()


def load() -> dict:
    with _lock:
        try:
            data = json.loads(SETTINGS_FILE.read_text("utf-8"))
        except (FileNotFoundError, ValueError):
            data = {}
    return {**DEFAULTS, **data}


def save(patch: dict) -> dict:
    with _lock:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        try:
            current = json.loads(SETTINGS_FILE.read_text("utf-8"))
        except (FileNotFoundError, ValueError):
            current = {}
        current.update(patch)
        tmp = SETTINGS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(current, indent=2), "utf-8")
        os.replace(tmp, SETTINGS_FILE)  # atomic: never leaves a half-written file
    return {**DEFAULTS, **current}


def router_password(settings: dict) -> str:
    enc = settings.get("router_password_enc")
    return dpapi.unprotect(enc) if enc else ""


def set_router_password(password: str) -> dict:
    return save({"router_password_enc": dpapi.protect(password)})
