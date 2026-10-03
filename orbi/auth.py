"""App PIN and signed session cookies.

Anyone on the home Wi-Fi can reach the app, including whoever the parental controls
apply to, so everything sits behind a PIN with escalating lockouts after wrong guesses.
"""
import base64
import hashlib
import hmac
import secrets
import threading
import time

from . import config

COOKIE = "orbi_session"
SESSION_DAYS = 90
MIN_PIN = 6


def hash_pin(pin: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 300_000)
    return f"pbkdf2${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def check_pin(pin: str, stored: str) -> bool:
    try:
        _, salt, _ = stored.split("$")
    except ValueError:
        return False
    return hmac.compare_digest(hash_pin(pin, base64.b64decode(salt)), stored)


def accepted_hashes(settings: dict) -> list[str]:
    """Every PIN hash that may unlock the app: the primary plus any the user added."""
    hashes = [settings.get("pin_hash") or ""]
    hashes += [e.get("hash", "") for e in settings.get("extra_pins", [])]
    return [h for h in hashes if h]


def check_any_pin(pin: str, settings: dict) -> bool:
    return any(check_pin(pin, h) for h in accepted_hashes(settings))


def _secret() -> bytes:
    s = config.load()
    if not s["session_secret"]:
        s = config.save({"session_secret": secrets.token_hex(32)})
    return bytes.fromhex(s["session_secret"])


def make_session() -> str:
    payload = f"{int(time.time()) + SESSION_DAYS * 86400}.{secrets.token_hex(8)}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def valid_session(token: str | None) -> bool:
    if not token or token.count(".") != 2:
        return False
    expires, nonce, sig = token.split(".")
    good = hmac.new(_secret(), f"{expires}.{nonce}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, good) and expires.isdigit() and int(expires) > time.time()


def rotate_secret():
    """Signs everyone out (used when the PIN changes)."""
    config.save({"session_secret": secrets.token_hex(32)})


class Throttle:
    """5 wrong PINs → 1 min lockout, doubling each further miss (max 1 hour), per client IP."""

    def __init__(self):
        self._lock = threading.Lock()
        self._state: dict[str, tuple[int, float]] = {}

    def wait_seconds(self, ip: str) -> int:
        with self._lock:
            fails, until = self._state.get(ip, (0, 0))
            return max(0, int(until - time.time()))

    def failure(self, ip: str):
        with self._lock:
            fails, _ = self._state.get(ip, (0, 0))
            fails += 1
            lock = 0 if fails < 5 else min(3600, 60 * 2 ** (fails - 5))
            self._state[ip] = (fails, time.time() + lock)

    def success(self, ip: str):
        with self._lock:
            self._state.pop(ip, None)
