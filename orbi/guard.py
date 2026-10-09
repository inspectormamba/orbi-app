"""Watches the PIN page for someone trying to break in, and records what they tried.

The lockout in auth.Throttle already makes guessing hopeless; this is about *noticing* and *reacting*.
Every PIN attempt is recorded with the device (by its hardware address at that moment), the program that
sent it (User-Agent), and what was typed. What was typed is encrypted on disk with Windows DPAPI, never
written to the app log, and erased as soon as that device signs in successfully: a parent's typos are
near-misses of the real PIN and mustn't be left lying around as hints.

An attack by a program rather than a person (too fast to type, carrying on through the lockout, a
non-browser client, or probing the app's pages without signing in) gets an immediate alert, bans the
device from Orbi Control for a day, and (if "block_pin_attackers" is on) blocks it at the router.
This PC itself is never banned or blocked.
"""
import logging
import re
import threading
import time

from . import auth, config

log = logging.getLogger(__name__)

KEEP_DAYS = 30
TYPO_WINDOW = 15 * 60  # guesses from a device that signs in within this long were its owner's typos
BAN_SECONDS = 24 * 3600
FAST = (3, 2.0)  # this many attempts within this many seconds: nobody types a PIN that fast
THROUGH_LOCKOUT = (6, 10.0)  # attempts while locked out, within seconds: a program ignoring "try again later"
PROBE = (30, 60.0)  # requests refused for want of a sign-in, within seconds
BROWSER = re.compile(r"Mozilla/5\.0 .*(AppleWebKit|Gecko)/")


def scripted_agent(agent: str) -> bool:
    """curl, python-requests, PowerShell, Go, node…: anything that doesn't look like a browser."""
    return not BROWSER.search(agent or "")


class PinGuard:
    def __init__(self, monitor):
        self.monitor = monitor
        self.store = monitor.store
        self._lock = threading.Lock()
        self._recent: dict[str, list[tuple[float, str]]] = {}  # ip -> [(time, outcome)] in the last minute
        self._refused: dict[str, list[float]] = {}  # ip -> times of requests refused for no sign-in

    # ---- recording ----
    def attempt(self, ip: str, outcome: str, guess: str, agent: str, who: str) -> None:
        """outcome: "wrong", "locked" (refused by the lockout without checking) or "ok"."""
        now = time.time()
        name, mac = self.monitor.identify(ip)
        if outcome == "ok":
            # The device's owner got in: what it typed wrong just before was a typo of the real PIN.
            self.store.x("UPDATE pin_attempts SET guess=NULL WHERE ip=? AND ts > ?", (ip, now - TYPO_WINDOW))
            return
        with self._lock:
            hits = [h for h in self._recent.get(ip, []) if now - h[0] < 60] + [(now, outcome)]
            self._recent[ip] = hits
        why = self._automation(hits, agent, now)
        self.store.x("INSERT INTO pin_attempts(ts,ip,mac,device,agent,outcome,guess,automated) VALUES(?,?,?,?,?,?,?,?)",
                     (now, ip, mac, name, (agent or "")[:200], outcome, self._seal(guess), int(bool(why))))
        self.store.x("DELETE FROM pin_attempts WHERE ts < ?", (now - KEEP_DAYS * 86400,))
        self.monitor.wrong_pin(ip, who, mac)
        if why:
            self.attacked(ip, mac, who, why)

    @staticmethod
    def _automation(hits, agent, now) -> str:
        n, secs = FAST
        if sum(1 for t, _ in hits if now - t <= secs) >= n:
            return f"{n} PINs within {secs:g} seconds, too fast for a person"
        n, secs = THROUGH_LOCKOUT
        if sum(1 for t, o in hits if o == "locked" and now - t <= secs) >= n:
            return "it kept sending PINs straight through the lockout"
        if scripted_agent(agent):
            return f"the PINs came from a program, not a web browser ({(agent or 'no User-Agent')[:60]})"
        return ""

    def refused(self, ip: str, path: str, who: str) -> None:
        """A request for a page that needs signing in, without a valid sign-in. A browser left open makes a
        few of these; a program looking for a way in makes dozens."""
        if ip in auth.LOCAL_IPS:
            return
        now = time.time()
        n, secs = PROBE
        with self._lock:
            hits = [t for t in self._refused.get(ip, []) if now - t < secs] + [now]
            self._refused[ip] = hits
        if len(hits) >= n:
            self._refused[ip] = []
            self.attacked(ip, self.monitor.identify(ip)[1], who, f"{n} requests for the app's pages without signing in within a minute (last: {path[:60]})")

    # ---- reacting ----
    def attacked(self, ip: str, mac: str, who: str, why: str) -> None:
        """A program is attacking the app: alert at once, ban the device from the app, block it at the router."""
        if ip in auth.LOCAL_IPS:
            return
        now = time.time()
        bans = self.bans()
        if ip in bans:  # already dealt with
            return
        bans[ip] = {"mac": mac, "until": now + BAN_SECONDS, "who": who, "why": why, "since": now}
        self.store.put("pin_bans", bans)
        blocked = ""
        if config.load().get("block_pin_attackers", True) and mac and mac not in self.monitor.protected_macs():
            self.store.x("UPDATE devices SET manual_block=1 WHERE mac=?", (mac,))
            if self.store.one("SELECT mac FROM devices WHERE mac=?", (mac,)):
                self.monitor.wake_enforcer.set()
                blocked = " It's now blocked at the router too; unblock it in Devices if this was a mistake."
        log.warning("PIN attack from %s (%s): %s", who, mac or "no hardware address", why)
        self.store.event("pin_attack", f"Break-in attempt from {who}",
                         detail=f"A program tried to get into Orbi Control: {why}. The device can't use the app for 24 hours.{blocked}",
                         severity="error", mac=mac or "")
        self.monitor.notify("Break-in attempt on Orbi Control", f"{who}: {why}")

    def bans(self) -> dict:
        now = time.time()
        return {ip: b for ip, b in (self.store.get("pin_bans", {}) or {}).items() if b["until"] > now}

    def banned(self, ip: str) -> bool:
        """Whether requests from `ip` are refused. Goes by hardware address when the ban has one, so a device
        that later gets the banned address from the router isn't shut out."""
        if ip in auth.LOCAL_IPS:
            return False
        b = self.bans().get(ip)
        if not b:
            return False
        if b.get("mac"):
            now_mac = self.monitor.identify(ip)[1]
            return not now_mac or now_mac == b["mac"]
        return True

    def lift(self, ip: str | None = None, mac: str | None = None) -> None:
        self.store.put("pin_bans", {k: b for k, b in self.bans().items()
                                    if not ((ip and k == ip) or (mac and b.get("mac") == mac) or (ip is None and mac is None))})

    # ---- reading ----
    def recent(self, limit: int = 100) -> list[dict]:
        rows = self.store.q("SELECT * FROM pin_attempts ORDER BY ts DESC LIMIT ?", (limit,))
        return [{**{k: r[k] for k in ("ts", "ip", "mac", "device", "agent", "outcome", "automated")},
                 "guess": self._open(r["guess"])} for r in rows]

    @staticmethod
    def _seal(guess: str) -> str | None:
        if not guess:
            return None
        try:
            from . import dpapi
            return dpapi.protect(guess[:64])
        except Exception:
            return None  # can't protect it: don't keep it

    @staticmethod
    def _open(token: str | None) -> str | None:
        if not token:
            return None
        try:
            from . import dpapi
            return dpapi.unprotect(token)
        except Exception:
            return None
