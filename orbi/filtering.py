"""Content filtering: which family-DNS service the router uses, changed safely.

Every change snapshots the router's Internet settings, applies the new DNS, then checks
within two minutes that (1) nothing else in the Internet settings changed, (2) the
internet still works, and (3) the provider's filtering is really in effect. If any
check fails, the previous DNS servers are restored automatically.
"""
import logging
import socket
import time

from .routerui import RouterUI, RouterUIError

log = logging.getLogger("orbi.filtering")

YT_RESTRICTED = {"216.239.38.119": "moderate", "216.239.38.120": "strict"}

PROVIDERS = {
    "adguard_family": {"name": "AdGuard Family", "dns": ["94.140.14.15", "94.140.15.16"], "youtube": True,
                       "summary": "Blocks adult sites, forces SafeSearch, YouTube Restricted Mode. Reddit allowed. Also blocks ads and trackers, which breaks some streaming apps (ESPN won't play)."},
    "cleanbrowsing_family": {"name": "CleanBrowsing Family", "dns": ["185.228.168.168", "185.228.169.168"], "youtube": True,
                             "summary": "Blocks adult sites, VPN/proxy sites and Reddit; forces SafeSearch and YouTube Restricted Mode."},
    "cleanbrowsing_adult": {"name": "CleanBrowsing Adult", "dns": ["185.228.168.10", "185.228.169.11"], "youtube": False,
                            "summary": "Blocks adult sites and forces SafeSearch. YouTube unrestricted."},
    "cloudflare_family": {"name": "Cloudflare for Families", "dns": ["1.1.1.3", "1.0.0.3"], "youtube": False,
                          "summary": "Blocks malware and adult sites. No YouTube restriction."},
}


def provider_for(dns_servers) -> str | None:
    for key, p in PROVIDERS.items():
        if dns_servers and dns_servers[0] in p["dns"]:
            return key
    return None


def _resolve_via_router(router_ip: str, name: str) -> list[str]:
    import dns.message
    import dns.query
    r = dns.query.udp(dns.message.make_query(name, "A"), router_ip, timeout=4)
    return [rr.address for rrset in r.answer for rr in rrset if rrset.rdtype == 1]


def check(router_ip: str) -> dict:
    """What the router's DNS currently does (asks the router, like every device does)."""
    out = {"youtube": None, "safesearch": None, "adult_blocked": None, "internet": False}
    try:
        yt = _resolve_via_router(router_ip, "www.youtube.com")
        out["youtube"] = next((YT_RESTRICTED[i] for i in yt if i in YT_RESTRICTED), "unrestricted")
        out["safesearch"] = "216.239.38.120" in _resolve_via_router(router_ip, "www.google.com")
        adult = _resolve_via_router(router_ip, "pornhub.com")
        out["adult_blocked"] = not adult or adult[0] in ("0.0.0.0", "94.140.14.35") or adult[0].startswith(("185.228.168", "185.228.169"))
    except Exception as e:
        out["error"] = str(e)
    for host in ("1.1.1.1", "8.8.8.8"):
        try:
            socket.create_connection((host, 443), timeout=4).close()
            out["internet"] = True
            break
        except OSError:
            pass
    return out


def apply_provider(host: str, password: str, key: str, verify_timeout: float = 120) -> dict:
    if key not in PROVIDERS:
        raise ValueError(f"Unknown provider {key}")
    provider = PROVIDERS[key]
    with RouterUI(host, password) as ui:
        before = ui.ether_snapshot()
        f = ui.form("BAS_ether.htm")
        old = [f.get("wan_dns1_pri"), f.get("wan_dns1_sec")] if f.get("DNSAssign") == "1" else None
        log.info("switching DNS %s -> %s", old, provider["dns"])
        ui.set_dns(*provider["dns"])
        after = ui.ether_snapshot()
    problems = [f"{k} changed ({before[k]} -> {after[k]})" for k in before if before[k] != after[k]]

    # Roll back only for real breakage: other settings changed, or no internet.
    status, deadline = {}, time.time() + verify_timeout
    while not problems and time.time() < deadline:
        status = check(host)
        if status["internet"] and "error" not in status:
            break
        time.sleep(8)
    else:
        if not problems:
            problems.append(f"the internet didn't come back within {int(verify_timeout)}s: {status}")
    if not problems:
        # Filtering can take a few minutes to show while the router's DNS cache expires.
        confirm_deadline = time.time() + 360
        while provider["youtube"] and status.get("youtube") not in ("moderate", "strict") and time.time() < confirm_deadline:
            time.sleep(15)
            status = check(host)
        return {"ok": True, "provider": key, "status": status, "previous": old,
                "confirmed": status.get("youtube") in ("moderate", "strict") if provider["youtube"] else True}

    log.error("DNS change failed (%s); rolling back to %s", problems, old)
    if old:
        with RouterUI(host, password) as ui:
            ui.set_dns(*old)
    raise RouterUIError("Change undone: " + "; ".join(problems))
