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
IDLE_MINUTES = 30  # a session unused this long is signed out (web/app.js also signs out after this long without input)
MIN_PIN = 6

# nonce -> time of its last request. Kept in memory only, so restarting the app signs everyone out too.
_last_seen: dict[str, float] = {}
_seen_lock = threading.Lock()


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
    nonce = secrets.token_hex(8)
    payload = f"{int(time.time()) + SESSION_DAYS * 86400}.{nonce}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    with _seen_lock:
        _last_seen[nonce] = time.time()
    return f"{payload}.{sig}"


def _parse(token: str | None):
    """(expires, nonce) of a correctly signed, unexpired token; None otherwise."""
    if not token or token.count(".") != 2:
        return None
    expires, nonce, sig = token.split(".")
    good = hmac.new(_secret(), f"{expires}.{nonce}".encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, good) and expires.isdigit() and int(expires) > time.time():
        return int(expires), nonce
    return None


def valid_session(token: str | None, touch: bool = False) -> bool:
    """touch=True counts this request as use of the session, restarting its idle timer."""
    parsed = _parse(token)
    if not parsed or parsed[1] in config.load().get("revoked_sessions", {}):
        return False
    now = time.time()
    with _seen_lock:
        last = _last_seen.get(parsed[1])
        if last is None or now - last > IDLE_MINUTES * 60:
            _last_seen.pop(parsed[1], None)
            return False
        if touch:
            _last_seen[parsed[1]] = now
    return True


def revoke_session(token: str | None):
    """Signing out invalidates the token itself, so a copied cookie stops working too."""
    parsed = _parse(token)
    if not parsed:
        return
    now = time.time()
    revoked = {n: exp for n, exp in config.load().get("revoked_sessions", {}).items() if exp > now}
    revoked[parsed[1]] = parsed[0]
    config.save({"revoked_sessions": revoked})
    with _seen_lock:
        _last_seen.pop(parsed[1], None)


def rotate_secret():
    """Signs everyone out (used when the PIN changes)."""
    config.save({"session_secret": secrets.token_hex(32), "revoked_sessions": {}})
    with _seen_lock:
        _last_seen.clear()


class Throttle:
    """Wrong-PIN lockouts: 5 misses from one client, or 20 across the whole house, lock PIN entry
    for 1 minute, doubling with each further miss (max 1 hour).

    Each attempt is counted *before* the PIN is checked, under one lock, so a burst of simultaneous
    guesses can't slip past the limit while the (deliberately slow) hash check runs. The house-wide
    count stops someone from spreading guesses over many addresses."""

    PER_CLIENT = 5
    HOUSE = 20
    _HOUSE_KEY = "*"

    def __init__(self):
        self._lock = threading.Lock()
        self._state: dict[str, tuple[int, float]] = {}

    @staticmethod
    def _lockout(fails: int, limit: int) -> float:
        return 0 if fails < limit else min(3600, 60 * 2 ** (fails - limit))

    def wait_seconds(self, ip: str) -> int:
        with self._lock:
            now = time.time()
            return max(0, int(max(self._state.get(k, (0, 0))[1] for k in (ip, self._HOUSE_KEY)) - now))

    def attempt(self, ip: str) -> int:
        """Seconds to wait if PIN entry is locked; otherwise 0, and the attempt is counted as a miss
        until success() is called."""
        with self._lock:
            now = time.time()
            wait = max(self._state.get(k, (0, 0))[1] for k in (ip, self._HOUSE_KEY)) - now
            if wait > 0:
                return int(wait) + 1
            for key, limit in ((ip, self.PER_CLIENT), (self._HOUSE_KEY, self.HOUSE)):
                fails = self._state.get(key, (0, 0))[0] + 1
                self._state[key] = (fails, now + self._lockout(fails, limit))
            return 0

    def success(self, ip: str):
        with self._lock:
            self._state.pop(ip, None)
            fails, _ = self._state.get(self._HOUSE_KEY, (0, 0))
            if fails > 0:  # undo this attempt's provisional miss
                fails -= 1
                self._state[self._HOUSE_KEY] = (fails, time.time() + self._lockout(fails, self.HOUSE) if fails >= self.HOUSE else 0)
