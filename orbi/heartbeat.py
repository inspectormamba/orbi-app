"""Outside check-in: a "dead man's switch" for when this PC can't raise the alarm itself.

Everything Orbi Control does, its phone alerts included, runs on this PC. Unplug its network cable or turn it off and
schedules stop and nothing tells you. So every few minutes the app visits a check-in address at a free outside
service (healthchecks.io, or one you run); when the visits stop, that service alerts your phone.

Anyone with the address could keep checking in for a PC that's been switched off, so it's kept DPAPI-encrypted,
never shown again, and changing or removing it is recorded and sent to your phone.
"""
import re
import time
import urllib.error
import urllib.request

from . import config, dpapi

EVERY = 5 * 60  # set the check's period to 5 minutes and its grace time to 10 at the service


def configured(settings: dict | None = None) -> bool:
    return bool((settings or config.load()).get("heartbeat_url_enc"))


def url(settings: dict | None = None) -> str:
    enc = (settings or config.load()).get("heartbeat_url_enc")
    return dpapi.unprotect(enc) if enc else ""


def check_url(u: str) -> str:
    u = (u or "").strip()
    if not re.fullmatch(r"https://[A-Za-z0-9.\-]+(:\d+)?/[A-Za-z0-9/_\-.]{8,200}", u):
        raise ValueError("Paste the check's ping address, e.g. https://hc-ping.com/1f2e3d…")
    return u


def ping(address: str | None = None, suffix: str = "") -> dict:
    """One check-in. {"ok": bool, "detail": str}; never raises."""
    address = address or url()
    if not address:
        return {"ok": False, "detail": "Outside check-in isn't set up"}
    req = urllib.request.Request(address.rstrip("/") + suffix, headers={"User-Agent": "OrbiControl"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return {"ok": 200 <= r.status < 300, "detail": f"checked in ({r.status})"}
    except urllib.error.HTTPError as e:
        return {"ok": False, "detail": f"the service refused it (HTTP {e.code}); check the address"}
    except OSError as e:
        return {"ok": False, "detail": f"couldn't reach the service: {e}"}


def beat():
    """The regular check-in, remembered for the More screen."""
    if configured():
        config.save({"heartbeat_last": {**ping(), "ts": time.time()}})
