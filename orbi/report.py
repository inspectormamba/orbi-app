"""Per-profile "what did they try?" report, built from the router log the app already collects.

The router logs the address of every device it blocks ([site blocked: tiktok] from source 192.168.1.42,
[service blocked: Block-DoT-853] from source ...). Addresses change, so each line is matched to a device
through the router's own DHCP log ([DHCP IP: (192.168.1.42)] to MAC address ...) as of that moment,
falling back to the device's latest known address. A device that set another's address by hand isn't in the
DHCP log, so while the app saw it on that address (address_sightings, from Monitor._watch_addresses) the
line is credited to it, not to the device the router gave the address to.
"""
import re
from collections import Counter

DHCP = re.compile(r"DHCP IP: \(([\d.]+)\)\] to MAC address ([0-9A-Fa-f:]{17})")
SIGHTING_SLACK = 10 * 60  # devices are listed every couple of minutes; allow for the gaps either side


def build(store, macs: set[str], since: float) -> dict:
    """{"devices": {mac: {"sites": {...}, "bypass": {...}, "vpn": {...}, "networks": [...]}}, "totals": {...}}"""
    macs = {m.upper() for m in macs}
    fallback = {r["last_ip"]: r["mac"] for r in store.q("SELECT mac, last_ip FROM devices WHERE last_ip IS NOT NULL ORDER BY last_seen")}
    owner: dict[str, str] = {}
    sightings: dict[str, list] = {}
    for s in store.q("SELECT mac, ip, first, last FROM address_sightings WHERE last > ?", (since - SIGHTING_SLACK,)):
        sightings.setdefault(s["ip"], []).append(s)
    per: dict[str, dict] = {}
    rows = store.q("SELECT ts, kind, source, text FROM router_log WHERE ts > ? AND (kind LIKE 'site blocked%' OR "
                   "kind LIKE 'service blocked%' OR kind LIKE 'DHCP IP%') ORDER BY ts", (since - 14 * 86400,))
    for r in rows:
        if r["kind"].startswith("DHCP IP"):
            m = DHCP.search(r["text"])
            if m:
                owner[m.group(1)] = m.group(2).upper()
            continue
        if r["ts"] <= since:
            continue
        borrowed = [s["mac"] for s in sightings.get(r["source"], [])
                    if s["first"] - SIGHTING_SLACK <= r["ts"] <= s["last"] + SIGHTING_SLACK]
        mac = (borrowed[-1] if borrowed else None) or owner.get(r["source"]) or fallback.get(r["source"])
        if mac not in macs:
            continue
        d = per.setdefault(mac, {"sites": Counter(), "bypass": Counter(), "vpn": Counter(), "networks": []})
        what = r["kind"].split(":", 1)[1].strip() if ":" in r["kind"] else r["kind"]
        if r["kind"].startswith("site blocked"):
            d["sites"][what] += 1
        elif "vpn" in what.lower():
            d["vpn"][what] += 1
        else:  # outside DNS, DNS-over-TLS: getting around the content filter
            d["bypass"][what] += 1
    for e in store.q("SELECT ts, title, mac FROM events WHERE kind='network_join' AND ts > ?", (since,)):
        if e["mac"] in macs:
            per.setdefault(e["mac"], {"sites": Counter(), "bypass": Counter(), "vpn": Counter(), "networks": []})["networks"].append(
                {"ts": e["ts"], "title": e["title"]})
    totals = {k: sum(sum(d[k].values()) for d in per.values()) for k in ("sites", "bypass", "vpn")}
    totals["networks"] = sum(len(d["networks"]) for d in per.values())
    return {"devices": {mac: {k: dict(v) if isinstance(v, Counter) else v for k, v in d.items()} for mac, d in per.items()},
            "totals": totals}


def summary(rep: dict) -> str:
    """One line for the weekly event, e.g. 'Blocked sites 412× (chatgpt 400, tiktok 12) · Filter bypass 37×'."""
    sites = Counter()
    for d in rep["devices"].values():
        sites.update(d["sites"])
    parts = []
    if rep["totals"]["sites"]:
        top = ", ".join(f"{k} {v}" for k, v in sites.most_common(3))
        parts.append(f"Blocked sites {rep['totals']['sites']}× ({top})")
    if rep["totals"]["bypass"]:
        parts.append(f"Tried to get around the content filter {rep['totals']['bypass']}×")
    if rep["totals"]["vpn"]:
        parts.append(f"VPN attempts {rep['totals']['vpn']}×")
    if rep["totals"]["networks"]:
        parts.append(f"Joined the IoT/Guest Wi-Fi {rep['totals']['networks']}×")
    return " · ".join(parts)
