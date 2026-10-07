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

# nonce -> [time of its last request, label of the PIN that signed it in ("" = the main PIN)].
# Kept in memory only, so restarting the app signs everyone out too.
_last_seen: dict[str, list] = {}
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


def pin_label(pin: str, settings: dict) -> str | None:
    """Which PIN this is: "" for the main PIN, an extra PIN's label, or None if it's wrong."""
    if settings.get("pin_hash") and check_pin(pin, settings["pin_hash"]):
        return ""
    return next((e.get("label", "") for e in settings.get("extra_pins", []) if check_pin(pin, e.get("hash", ""))), None)


def _secret() -> bytes:
    s = config.load()
    if not s["session_secret"]:
        s = config.save({"session_secret": secrets.token_hex(32)})
    return bytes.fromhex(s["session_secret"])


def make_session(pin_label: str = "") -> str:
    nonce = secrets.token_hex(8)
    payload = f"{int(time.time()) + SESSION_DAYS * 86400}.{nonce}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    with _seen_lock:
        _last_seen[nonce] = [time.time(), pin_label]
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
        seen = _last_seen.get(parsed[1])
        if seen is None or now - seen[0] > IDLE_MINUTES * 60:
            _last_seen.pop(parsed[1], None)
            return False
        if touch:
            seen[0] = now
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


def revoke_pin_sessions(label: str):
    """Signs out every device that signed in with the extra PIN called `label` (used when it's removed)."""
    with _seen_lock:
        for nonce in [n for n, (_, l) in _last_seen.items() if l == label]:
            del _last_seen[nonce]


def rotate_secret():
    """Signs everyone out (used when the PIN changes)."""
    config.save({"session_secret": secrets.token_hex(32), "revoked_sessions": {}})
    with _seen_lock:
        _last_seen.clear()


LOCAL_IPS = {"127.0.0.1", "::1"}


class Throttle:
    """Wrong-PIN lockouts: 5 misses from one client, or 20 across the whole house, within an hour lock
    PIN entry for 1 minute, doubling with each further miss (max 1 hour).

    Misses expire after an hour, so occasional typos never add up. Each attempt is counted *before* the
    PIN is checked, under one lock, so a burst of simultaneous guesses can't slip past the limit while
    the (deliberately slow) hash check runs. The house-wide count stops someone from spreading guesses
    over many addresses; it never locks out this PC itself, so wrong PINs sent from a kid's device
    can't keep a parent from signing in at the PC."""

    PER_CLIENT = 5
    HOUSE = 20
    WINDOW = 3600
    _HOUSE_KEY = "*"

    def __init__(self):
        self._lock = threading.Lock()
        self._state: dict[str, dict] = {}  # key -> {"misses": [timestamps], "until": locked until}
        self._pending: dict[str, list] = {}  # ip -> attempts whose PIN check hasn't finished yet

    @staticmethod
    def _lockout(fails: int, limit: int) -> float:
        return 0 if fails < limit else min(3600, 60 * 2 ** (fails - limit))

    def _keys(self, ip):
        return (ip,) if ip in LOCAL_IPS else (ip, self._HOUSE_KEY)

    def _entry(self, key, now):
        e = self._state.setdefault(key, {"misses": [], "until": 0.0})
        e["misses"] = [t for t in e["misses"] if now - t < self.WINDOW]
        return e

    def _wait(self, ip, now):
        return max(self._state.get(k, {"until": 0.0})["until"] for k in self._keys(ip)) - now

    def wait_seconds(self, ip: str) -> int:
        with self._lock:
            return max(0, int(self._wait(ip, time.time())))

    def attempt(self, ip: str) -> int:
        """Seconds to wait if PIN entry is locked; otherwise 0, and the attempt is counted as a miss
        until success() is called."""
        with self._lock:
            now = time.time()
            wait = self._wait(ip, now)
            if wait > 0:
                return int(wait) + 1
            undo = []
            for key, limit in ((ip, self.PER_CLIENT), (self._HOUSE_KEY, self.HOUSE)):  # this PC's misses still count house-wide
                e = self._entry(key, now)
                before = e["until"]
                e["misses"].append(now)
                if len(e["misses"]) >= limit:
                    e["until"] = now + self._lockout(len(e["misses"]), limit)
                undo.append((key, now, before, e["until"]))
            self._pending.setdefault(ip, []).append(undo)
            return 0

    def success(self, ip: str):
        """The PIN was right: take back that attempt's provisional miss, and any lockout it alone started."""
        with self._lock:
            for key, ts, before, set_to in (self._pending.get(ip) or [[]]).pop():
                e = self._state.get(key)
                if not e:
                    continue
                if ts in e["misses"]:
                    e["misses"].remove(ts)
                if e["until"] == set_to:
                    e["until"] = before
            self._state.pop(ip, None)
            self._pending.pop(ip, None)

    def failure(self, ip: str):
        """The PIN was wrong: the provisional miss stays."""
        with self._lock:
            if self._pending.get(ip):
                self._pending[ip].pop()
