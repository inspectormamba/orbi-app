"""Device check: the "vulnerability assessment" that router security subscriptions sell, done from this PC.

What it does, for every device online in the house:
  1. Connects to a short list of ports (TCP connect only).
  2. Reads what answers: web servers' headers and page titles, and what devices announce about themselves over
     UPnP (maker, model, firmware version). No logins are tried: not even factory-default passwords.
  3. Reports logins that travel unencrypted (Telnet, FTP, a web admin page that works over plain HTTP) and ports
     that malware and known router backdoors use.
  4. Looks up the firmware version it found in NIST's vulnerability database (only the product name and version
     are sent) and keeps the serious ones (score 7+) that apply to that exact version. Any of those on CISA's list
     of vulnerabilities attackers are actually using is marked urgent.

Version strings from SSH greetings aren't looked up: vendors (Synology, Apple, Linux distributions) patch OpenSSH
without changing its version number, so the database would report flaws that were already fixed.
"""
import http.client
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request

from . import exposure

HTTP_PORTS = {80: False, 8080: False, 8000: False, 5000: False, 8008: False, 9000: False,
              443: True, 8443: True, 5001: True}
PLAIN_PORTS = {21: "FTP", 23: "Telnet"}
BACKDOOR_PORTS = {32764: "a hidden router backdoor (SerComm)", 4444: "a common hacking-tool port",
                  31337: "a classic backdoor port", 12345: "the NetBus backdoor port", 6667: "IRC, used by botnets"}
PORTS = sorted(set(HTTP_PORTS) | set(PLAIN_PORTS) | set(BACKDOOR_PORTS))

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_KEEP_DAYS = 7
NVD_PAUSE = 6.5  # NIST allows 5 requests per 30 s without an API key
SERIOUS = 7.0
UA = "OrbiControl-devicecheck"
LOGIN_TITLE = re.compile(r"\b(log ?in|sign ?in|admin|router|synology|diskstation|nas|web ?ui|management console)\b", re.I)


def _insecure_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # home devices use self-signed certificates
    return ctx


def http_probe(ip: str, port: int, tls: bool, timeout: float = 4.0) -> dict:
    """GET / (following redirects on the same device): status, server, title, and whether it's a login page or
    sends the browser on to HTTPS."""
    path, hops = "/", 0
    while True:
        conn = (http.client.HTTPSConnection(ip, port, timeout=timeout, context=_insecure_ctx()) if tls
                else http.client.HTTPConnection(ip, port, timeout=timeout))
        try:
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0 (Orbi Control device check)", "Connection": "close"})
            r = conn.getresponse()
            try:
                body = r.read(30000)
            except http.client.IncompleteRead as e:  # some printers close mid-page
                body = e.partial
            status, hdr = r.status, {k.lower(): v for k, v in r.getheaders()}
        except Exception as e:
            return {"error": type(e).__name__}
        finally:
            conn.close()
        loc = hdr.get("location", "")
        if status in (301, 302, 303, 307, 308) and loc:
            if loc.lower().startswith("https://"):
                return {"status": status, "server": hdr.get("server", ""), "to_https": True, "login": False, "title": ""}
            u = urllib.parse.urlsplit(loc)
            if hops < 3 and u.scheme in ("", "http") and u.hostname in (None, ip) and u.port in (None, port):
                path, hops = (u.path or "/") + (f"?{u.query}" if u.query else ""), hops + 1
                continue
        break
    text = body.decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.S | re.I)
    title = re.sub(r"\s+", " ", (m.group(1) if m else "").replace("&nbsp;", " ")).strip()[:100]
    auth = hdr.get("www-authenticate", "")
    login = (bool(re.match(r"\s*(basic|digest)\b", auth, re.I)) or bool(re.search(r"type\s*=\s*[\"']?password", text, re.I))
             or bool(LOGIN_TITLE.search(title)))
    to_https = bool(re.search(r"(location(\.href)?\s*=|url\s*=)\s*[\"']?https://", text, re.I))
    return {"status": status, "server": hdr.get("server", ""), "title": title, "auth": auth[:60], "login": login, "to_https": to_https}


# ---------- UPnP: what devices say they are ----------
def ssdp_discover(local_ip: str, wait: float = 5.0) -> dict[str, list[tuple[str, str]]]:
    """{ip: [(description URL, SERVER header)]} from an SSDP search sent out of the home-network adapter."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    found: dict[str, dict[str, str]] = {}
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.bind((local_ip, 0))
        s.settimeout(0.5)
        msg = b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.monotonic() + wait
        while time.monotonic() < end:
            try:
                data, (src, _p) = s.recvfrom(4096)
            except socket.timeout:
                continue
            txt = data.decode("latin-1")
            loc = re.search(r"^location:\s*(\S+)", txt, re.I | re.M)
            srv = re.search(r"^server:\s*(.+?)\s*$", txt, re.I | re.M)
            if loc and urllib.parse.urlsplit(loc.group(1)).hostname == src:  # only descriptions on the device itself
                found.setdefault(src, {}).setdefault(loc.group(1), srv.group(1) if srv else "")
    finally:
        s.close()
    return {ip: list(locs.items())[:3] for ip, locs in found.items()}


def parse_description(xml: str, server: str = "") -> dict:
    """Maker, model and firmware from a UPnP device description (and its SERVER header)."""
    def tag(name):
        m = re.search(rf"<{name}>\s*(.*?)\s*</{name}>", xml, re.S)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""
    out = {"maker": tag("manufacturer"), "model": tag("modelName"), "model_number": tag("modelNumber"),
           "firmware": tag("softwareVersion") or tag("firmwareVersion")}
    if not out["firmware"]:
        # Synology puts DSM's version after the model ("DS220j 7.4-90080"); Sonos and others put theirs in SERVER
        m = re.match(r"\S+\s+(\d+(\.\d+)+(-\d+)*)$", out["model_number"])
        sm = re.search(r"\b(?:Sonos|DSM)/(\d+(?:\.\d+)+(?:-\d+)*)", server)
        out["firmware"] = (m.group(1) if m else "") or (sm.group(1) if sm else "")
    return {k: v for k, v in out.items() if v}


def upnp_identities(local_ip: str) -> dict[str, dict]:
    out = {}
    for ip, locs in ssdp_discover(local_ip).items():
        merged = {}
        for loc, server in locs:
            try:
                with urllib.request.urlopen(urllib.request.Request(loc, headers={"User-Agent": UA}), timeout=3) as r:
                    info = parse_description(r.read(60000).decode("utf-8", "replace"), server)
            except Exception:
                continue
            merged = {**info, **merged}  # the first (root) description wins
        if merged:
            out[ip] = merged
    return out


# ---------- vulnerability databases ----------
def vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def cmp(a: str, b: str) -> int:
    ka, kb = vkey(a), vkey(b)
    return (ka > kb) - (ka < kb)


def cpe_for(identity: dict) -> str | None:
    """The NIST product name for a device's firmware, or None when there's no version to check."""
    maker = re.sub(r"[^a-z0-9]", "", (identity.get("maker") or "").lower().split(",")[0].replace(" inc", ""))
    if not identity.get("firmware") or not maker:
        return None
    if maker == "synology":
        return "cpe:2.3:o:synology:diskstation_manager"
    model = (identity.get("model_number") or identity.get("model") or "").lower()
    if maker == "netgear":
        model = identity.get("model_number") or identity.get("model") or ""
        model = model.split()[0].lower() if model else ""
    else:
        model = (identity.get("model") or "").lower().replace(maker, "").strip()
    model = re.sub(r"[^a-z0-9]+", "_", model).strip("_")
    return f"cpe:2.3:o:{maker}:{model}_firmware" if model else None


def _score(cve: dict) -> float | None:
    m = cve.get("metrics", {})
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if m.get(k):
            return m[k][0]["cvssData"].get("baseScore")
    return None


def trim(cve: dict, cpe: str) -> dict:
    """Just what's needed to judge a version: the matching rules for this product, the score and the summary."""
    rules = [{k: cm.get(k) for k in ("criteria", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                                     "versionEndExcluding") if cm.get(k)}
             for cfg in cve.get("configurations", []) for node in cfg.get("nodes", []) for cm in node.get("cpeMatch", [])
             if cm.get("vulnerable") and cm.get("criteria", "").startswith(cpe + ":")]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"id": cve["id"], "score": _score(cve), "rules": rules, "summary": desc[:300]}


def applies(entry: dict, version: str) -> tuple[bool, str | None]:
    """(affects this version?, first fixed version if the database names one)."""
    for r in entry["rules"]:
        exact = r["criteria"].split(":")[5]
        if exact not in ("*", "-"):
            if cmp(exact, version) == 0:
                return True, None
            continue
        if r.get("versionStartIncluding") and cmp(version, r["versionStartIncluding"]) < 0:
            continue
        if r.get("versionStartExcluding") and cmp(version, r["versionStartExcluding"]) <= 0:
            continue
        if r.get("versionEndExcluding"):
            if cmp(version, r["versionEndExcluding"]) < 0:
                return True, r["versionEndExcluding"]
            continue
        if r.get("versionEndIncluding"):
            if cmp(version, r["versionEndIncluding"]) <= 0:
                return True, None
            continue
        if any(r.get(k) for k in ("versionStartIncluding", "versionStartExcluding")):
            return True, None  # open-ended: from that version on, no fix listed
    return False, None


def _get_json(url: str, timeout: float = 30):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=timeout) as r:
        return json.load(r)


_last_nvd = 0.0


def _nvd_get(url: str, timeout: float):
    """One request to NIST, spaced out to stay inside its limit for callers without an API key."""
    global _last_nvd
    wait = NVD_PAUSE - (time.monotonic() - _last_nvd)
    if wait > 0:
        time.sleep(wait)
    try:
        return _get_json(url, timeout=timeout)
    finally:
        _last_nvd = time.monotonic()


def nvd_entries(cpe: str) -> list[dict]:
    out, start = [], 0
    while True:
        q = urllib.parse.urlencode({"virtualMatchString": cpe, "resultsPerPage": 2000, "startIndex": start})
        try:
            d = _nvd_get(f"{NVD_URL}?{q}", timeout=90)
        except Exception:  # NIST's service is often slow: one more try before giving up until tomorrow
            d = _nvd_get(f"{NVD_URL}?{q}", timeout=120)
        out += [trim(v["cve"], cpe) for v in d.get("vulnerabilities", [])]
        start += d.get("resultsPerPage", 0) or 2000
        if start >= d.get("totalResults", 0):
            return out


def kev_ids(cache_file, fetch=_get_json) -> set[str]:
    """CVE ids on CISA's list of vulnerabilities attackers are using, refreshed daily."""
    try:
        fresh = cache_file.exists() and time.time() - cache_file.stat().st_mtime < 86400
        if not fresh:
            data = fetch(KEV_URL)
            cache_file.write_text(json.dumps([v["cveID"] for v in data["vulnerabilities"]]), "utf-8")
        return set(json.loads(cache_file.read_text("utf-8")))
    except Exception:
        try:
            return set(json.loads(cache_file.read_text("utf-8")))  # a stale list beats none
        except Exception:
            return set()


def known_vulns(cpe: str, version: str, cache: dict, kev: set[str], fetch=nvd_entries, now: float | None = None) -> list[dict]:
    """Serious vulnerabilities that apply to this exact version, worst first. cache is updated in place."""
    now = now or time.time()
    hit = cache.get(cpe)
    if not hit or now - hit["ts"] > NVD_KEEP_DAYS * 86400:
        hit = cache[cpe] = {"ts": now, "entries": fetch(cpe)}
    out = []
    for e in hit["entries"]:
        ok, fixed = applies(e, version)
        exploited = e["id"] in kev
        if ok and (exploited or (e["score"] or 0) >= SERIOUS):
            out.append({"id": e["id"], "score": e["score"], "fixed": fixed, "exploited": exploited, "summary": e["summary"]})
    return sorted(out, key=lambda v: (not v["exploited"], -(v["score"] or 0)))


# ---------- findings ----------
def port_findings(open_ports: list[int], probes: dict[int, dict], orbi: bool = False) -> list[dict]:
    out = []
    for p in open_ports:
        if p in BACKDOOR_PORTS:
            out.append({"key": f"backdoor:{p}", "severity": "bad", "title": f"Port {p} is open: {BACKDOOR_PORTS[p]}",
                        "fix": "Nothing in a normal home uses this port. If you don't know why it's open, unplug the device and "
                               "reset it to factory settings."})
        elif p == 23:
            out.append({"key": "telnet", "severity": "bad", "title": "Telnet is on (unencrypted remote login)",
                        "fix": "Telnet sends its password in plain text, and it's how botnets like Mirai take over gadgets. "
                               "Turn it off in the device's settings or app; if there's no way to, keep it off the network."})
        elif p == 21:
            out.append({"key": "ftp", "severity": "warn", "title": "FTP is on (unencrypted file login)",
                        "fix": "FTP sends its password in plain text. Turn it off, or use SFTP/FTPS if the device offers it."})
    for p, pr in sorted(probes.items()):
        if not HTTP_PORTS.get(p) and pr.get("login") and not pr.get("to_https") and orbi:
            out.append({"key": f"http-login:{p}", "severity": "info",
                        "title": f"Its admin page also works without encryption (http, port {p})",
                        "fix": "Netgear has no setting to turn this off. Orbi Control always uses https; if you open the "
                               "router's pages yourself, type https:// in front of the address."})
        elif not HTTP_PORTS.get(p) and pr.get("login") and not pr.get("to_https"):
            out.append({"key": f"http-login:{p}", "severity": "warn",
                        "title": f"Its login page works without encryption (http, port {p})",
                        "fix": "Anything typed there, including the password, crosses the network readable. Use the https:// "
                               "address, and turn on the device's \"redirect HTTP to HTTPS\" setting if it has one."})
    return out


def vuln_findings(identity: dict, vulns: list[dict]) -> list[dict]:
    if not vulns:
        return []
    worst, fw = vulns[0], identity.get("firmware", "")
    fixed = max((v["fixed"] for v in vulns if v["fixed"]), key=vkey, default=None)
    ids = ", ".join(v["id"] for v in vulns[:4]) + (f" and {len(vulns) - 4} more" if len(vulns) > 4 else "")
    exploited = [v for v in vulns if v["exploited"]]
    title = (f"Firmware {fw} has a flaw attackers are actively using" if exploited
             else f"Firmware {fw} has {len(vulns)} known serious vulnerabilit{'y' if len(vulns) == 1 else 'ies'}")
    fix = (f"Update the firmware{f' to {fixed} or later' if fixed else ''} from the device's app or settings. "
           f"{ids}. Worst: {worst['summary'][:180]}")
    return [{"key": "firmware-vulns", "severity": "bad" if exploited else "warn", "title": title, "fix": fix,
             "cves": [v["id"] for v in vulns]}]


def check_devices(targets: dict[str, dict], local_ip: str | None, nvd_cache: dict, kev: set[str],
                  extra_identities: dict[str, dict] | None = None, nvd=None) -> dict[str, dict]:
    """targets: {ip: {"key", "name"}}. Returns {key: {"ip","name","identity","ports","findings"}}."""
    found = exposure.scan(list(targets), PORTS)
    idents = upnp_identities(local_ip) if local_ip else {}
    for ip, ident in (extra_identities or {}).items():
        idents[ip] = {**idents.get(ip, {}), **ident}
    out = {}
    for ip, t in targets.items():
        ports = sorted(found.get(ip, []))
        probes = {p: http_probe(ip, p, HTTP_PORTS[p]) for p in ports if p in HTTP_PORTS}
        ident = idents.get(ip, {})
        findings = port_findings(ports, probes, orbi=bool(t.get("orbi")))
        cpe = cpe_for(ident)
        if cpe:
            try:
                findings += vuln_findings(ident, known_vulns(cpe, ident["firmware"], nvd_cache, kev, fetch=nvd or nvd_entries))
            except Exception as e:
                ident = {**ident, "lookup_error": f"Couldn't reach NIST's database: {type(e).__name__}"}
        out[t["key"]] = {"ip": ip, "name": t["name"], "identity": ident, "ports": ports, "findings": findings,
                         "web": {p: {k: v for k, v in pr.items() if k in ("title", "server", "status", "error")} for p, pr in probes.items()}}
    return out
