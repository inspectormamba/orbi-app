"""Family profiles: decide which devices should be blocked right now.

Precedence for a profile, highest first:
  1. paused (paused_until = -1 for "until resumed", or a future timestamp)
  2. bonus time (allow_until in the future) overrides schedules
  3. any active schedule rule (e.g. Bedtime 21:00-07:00) blocks
Days are Mon=0 .. Sun=6, as in datetime.weekday().

"Later bedtime tonight" (profile["late"] = {"date": "YYYY-MM-DD", "minutes": N}) delays only the *start* of
evening schedule windows (starting 5 PM or later) that begin on that date; when they end is unchanged.
"""
from datetime import datetime, timedelta

FOREVER = -1
LATE_FROM = 17 * 60  # "later bedtime tonight" only moves evening schedules (starting 5 PM or later), not e.g. Homework


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def rule_active(rule: dict, now: datetime, late: dict | None = None) -> bool:
    if not _rule_on(rule, now):
        return False
    if late and late.get("minutes") and rule["start"] != rule["end"] and _minutes(rule["start"]) >= LATE_FROM:
        start, t = _minutes(rule["start"]), now.hour * 60 + now.minute
        began = now.date() if t >= start else (now - timedelta(days=1)).date()
        if began.isoformat() == late.get("date") and (t - start) % 1440 < late["minutes"]:
            return False
    return True


def _rule_on(rule: dict, now: datetime) -> bool:
    if not rule.get("enabled", 1):
        return False
    days = str(rule.get("days", ""))
    start, end = _minutes(rule["start"]), _minutes(rule["end"])
    t = now.hour * 60 + now.minute
    today, yesterday = str(now.weekday()), str((now.weekday() - 1) % 7)
    if start == end:  # all day
        return today in days
    if start < end:
        return today in days and start <= t < end
    # overnight: the part after midnight belongs to the day the rule started
    return (today in days and t >= start) or (yesterday in days and t < end)


def profile_state(profile: dict, rules: list[dict], now: datetime) -> dict:
    """Returns {"blocked": bool, "reason": str, "until": datetime|None}."""
    ts = now.timestamp()
    paused = profile.get("paused_until")
    if paused is not None and (paused == FOREVER or paused > ts):
        until = None if paused == FOREVER else datetime.fromtimestamp(paused)
        return {"blocked": True, "reason": "Paused", "until": until}
    bonus = profile.get("allow_until")
    if bonus and bonus > ts:
        return {"blocked": False, "reason": "Extra time", "until": datetime.fromtimestamp(bonus)}
    late = profile.get("late")
    active = [r for r in rules if rule_active(r, now, late)]
    if active:
        return {"blocked": True, "reason": active[0].get("label") or "Schedule", "until": next_change(rules, now, True, late=late)}
    return {"blocked": False, "reason": "", "until": next_change(rules, now, False, late=late)}


def next_change(rules: list[dict], now: datetime, currently_blocked: bool, horizon_minutes: int = 8 * 24 * 60, late=None):
    """First minute (within 8 days) at which the schedule-blocked state flips."""
    if not any(r.get("enabled", 1) for r in rules):
        return None
    t = now.replace(second=0, microsecond=0)
    for _ in range(horizon_minutes):
        t += timedelta(minutes=1)
        if any(rule_active(r, t, late) for r in rules) != currently_blocked:
            return t
    return None


DEFAULT_RECENT_DAYS = 14  # devices unseen for longer don't inherit the default profile


def effective_profile(device: dict, default_profile_id, now: datetime):
    """The profile a device follows: its own, else the default (if it was seen recently)."""
    if device.get("profile_id") is not None:
        return device["profile_id"]
    if default_profile_id is None:
        return None
    seen = device.get("last_seen")
    if device.get("online") or seen is None or now.timestamp() - seen <= DEFAULT_RECENT_DAYS * 86400:
        return default_profile_id
    return None


def desired_blocks(profiles: list[dict], rules: list[dict], devices: list[dict], now: datetime,
                   protected: set[str] = frozenset(), default_profile_id=None) -> dict[str, str]:
    """mac -> reason for every device that should be blocked (manual blocks included).
    Devices without a profile follow the default profile when one is set."""
    by_profile: dict[int, list[dict]] = {}
    for r in rules:
        by_profile.setdefault(r["profile_id"], []).append(r)
    states = {p["id"]: profile_state(p, by_profile.get(p["id"], []), now) for p in profiles}
    names = {p["id"]: p["name"] for p in profiles}
    out = {}
    for d in devices:
        mac = d["mac"]
        if mac in protected:
            continue
        if d.get("manual_block"):
            out[mac] = "Blocked manually"
            continue
        pid = effective_profile(d, default_profile_id, now)
        st = states.get(pid)
        if st and st["blocked"]:
            out[mac] = f"{names[pid]}: {st['reason']}" + (" (default profile)" if d.get("profile_id") is None else "")
    return out


def late_night_date(now: datetime) -> str:
    """The evening a "later bedtime tonight" applies to (before 5 AM it's still last night)."""
    return (now - timedelta(hours=5)).date().isoformat()


def with_late(profiles: list[dict], late_map: dict, now: datetime) -> list[dict]:
    """Profiles with their "late" entry attached when it's for tonight (late_map: {"<pid>": {"date", "minutes"}})."""
    tonight = late_night_date(now)
    out = []
    for p in profiles:
        late = (late_map or {}).get(str(p["id"]))
        out.append({**p, "late": late} if late and late.get("date") == tonight else dict(p))
    return out


def is_restricted(profile: dict, rules: list[dict], now: datetime) -> bool:
    """A profile that limits its devices at all (has schedules, or is paused): its devices count as kids' devices."""
    paused = profile.get("paused_until")
    return any(r.get("enabled", 1) for r in rules) or (paused is not None and (paused == FOREVER or paused > now.timestamp()))


GENERIC_NAMES = {"", "iphone", "ipad", "android", "apple", "macbookpro", "macbook-pro", "macbookair", "macbook", "unknown",
                 "galaxy", "pixel", "localhost", "espressif", "amazon", "google", "chromecast", "roku"}


def name_match_profile(name: str, named_devices: list[dict]):
    """Profile to give a new device whose (non-generic) name matches devices that all share one profile.
    Catches phones/laptops that come back with a new private (randomized) MAC address."""
    key = (name or "").strip().lower()
    if key in GENERIC_NAMES or len(key) < 4:
        return None
    pids = {d["profile_id"] for d in named_devices if (d.get("router_name") or "").strip().lower() == key}
    if len(pids) == 1 and None not in pids:
        return pids.pop()
    return None


def is_randomized_mac(mac: str) -> bool:
    """Locally administered MACs (2nd hex digit 2, 6, A or E) are phones' 'private Wi-Fi addresses'."""
    try:
        return bool(int(mac.replace(":", "")[1], 16) & 2)
    except (ValueError, IndexError):
        return False
