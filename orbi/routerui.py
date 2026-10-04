"""Reads and changes settings that only the Orbi's web admin pages expose.

The pages fill their forms with JavaScript on load and rebuild hidden fields on submit,
so instead of re-creating those POSTs by hand (and risking half-filled settings), this
drives the router's own pages in a headless Firefox: its own code runs exactly as when
you click Apply. The router allows one web admin session at a time, so every session
logs out when done. Sessions are serialized with a lock.
"""
import logging
import re
import threading
import time
from contextlib import contextmanager

log = logging.getLogger("orbi.routerui")
FIREFOX = r"C:\Program Files\Mozilla Firefox\firefox.exe"
_lock = threading.Lock()

FORM_STATE_JS = """
const out = {};
for (const e of document.forms[0].elements) {
  if (!e.name) continue;
  if (e.type === 'radio' || e.type === 'checkbox') { if (e.checked) out[e.name] = e.value; }
  else if (e.tagName === 'SELECT' && e.multiple) out[e.name] = [...e.options].map(o => o.text);
  else if (e.type !== 'button' && e.type !== 'submit') out[e.name] = e.value;
}
return out;"""

TABLE_ROWS_JS = r"""return [...document.querySelectorAll('table tr')]
  .map(r => [...r.cells].map(c => c.innerText.replace(/\s+/g, ' ').trim()))
  .filter(cells => cells.length > 1);"""


class RouterUIError(Exception):
    pass


class RouterUI:
    def __init__(self, host: str, password: str, user: str = "admin"):
        self.host, self.user, self.password = host, user, password
        self.d = None

    # ---- session ----
    def __enter__(self):
        _lock.acquire()
        try:
            from selenium import webdriver
            from selenium.webdriver.firefox.options import Options
            from selenium.webdriver.firefox.service import Service
            opts = Options()
            opts.add_argument("-headless")
            opts.binary_location = FIREFOX
            opts.accept_insecure_certs = True  # the router's certificate is self-signed
            opts.enable_bidi = True
            service = Service()
            service.creation_flags = 0x08000000  # CREATE_NO_WINDOW: no console flash under pythonw
            self.d = webdriver.Firefox(options=opts, service=service)
            self.d.set_page_load_timeout(40)
            self.d.network.add_auth_handler(self.user, self.password)
            return self
        except Exception:
            self._close()
            raise

    def __exit__(self, *exc):
        self._close()
        return False

    def _close(self):
        try:
            if self.d:
                try:
                    self.d.get(f"https://{self.host}/LGO_logout.htm")  # free the single admin session
                except Exception:
                    pass
                self.d.quit()
        finally:
            self.d = None
            _lock.release()

    def open(self, page: str, settle: float = 1.5):
        self.d.get(f"https://{self.host}/{page}")
        time.sleep(settle)  # let the page's onload scripts populate the form
        if "401" in (self.d.title or ""):
            raise RouterUIError("The router rejected the admin password")

    def form(self, page: str | None = None) -> dict:
        if page:
            self.open(page)
        return self.d.execute_script(FORM_STATE_JS)

    def rows(self, page: str | None = None) -> list[list[str]]:
        if page:
            self.open(page)
        return self.d.execute_script(TABLE_ROWS_JS)

    def _accept_alerts(self, rounds=3):
        for _ in range(rounds):
            try:
                alert = self.d.switch_to.alert
                log.info("router dialog: %s", alert.text)
                alert.accept()
                time.sleep(0.5)
            except Exception:
                return

    def _set(self, name_or_id: str, value):
        self.d.execute_script("""
            const [key, value] = arguments;
            const el = document.getElementById(key) || document.forms[0].elements[key];
            if (!el) throw new Error('no field ' + key);
            el.value = value; el.dispatchEvent(new Event('change', {bubbles: true}));""", name_or_id, str(value))

    def _click(self, element_id: str, wait: float = 6):
        self.d.execute_script("document.getElementById(arguments[0]).click()", element_id)
        time.sleep(0.5)
        self._accept_alerts()
        time.sleep(wait)
        self._accept_alerts()

    # ---- reads ----
    def read_all(self) -> dict:
        out = {}
        f = self.form("BAS_ether.htm")
        out["wan"] = {"type": f.get("wan_proto"), "ip": f.get("wan_ipaddr"), "netmask": f.get("wan_netmask"), "gateway": f.get("wan_gateway"),
                      "dns_mode": "manual" if f.get("DNSAssign") == "1" else "from ISP", "dns": [f.get("wan_dns1_pri"), f.get("wan_dns1_sec")]
                      if f.get("DNSAssign") == "1" else [f.get("wan_dns_pri"), f.get("wan_dns_sec")], "isp_dns": [f.get("wan_dns_pri"), f.get("wan_dns_sec")],
                      "mac": f.get("wan_hwaddr2")}
        f = self.form("LAN_lan.htm")
        reservations = []
        for cells in self.rows():
            ips = [c for c in cells if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", c)]
            macs = [c for c in cells if re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", c)]
            if ips and macs and len(cells) <= 6:
                name = next((c for c in cells if c not in ips + macs and not c.isdigit() and c), "")
                reservations.append({"ip": ips[0], "mac": macs[0].upper(), "name": name})
        out["lan"] = {"ip": f.get("lan_ipaddr"), "netmask": ".".join(f.get(f"sysLANSubnetMask{i}", "") for i in range(1, 5)),
                      "dhcp_enabled": f.get("dhcp_server") == "dhcp_server", "dhcp_start": f.get("dhcp_start"), "dhcp_end": f.get("dhcp_end"),
                      "reservations": reservations}
        out["block_services"] = self.read_block_services()
        f = self.form("BKS_keyword.htm")
        out["block_sites"] = {"mode": f.get("skeyword"), "keywords": f.get("cfKeyWord_DomainList") or [],
                              "trusted_ip": f.get("bs_trustedip") if f.get("bs_trustedip_enable") == "1" else None}
        f = self.form("FW_schedule.htm")
        out["schedule"] = parse_schedule(f)
        f = self.form("OPENVPN.htm")
        out["vpn"] = {"enabled": f.get("openvpnActive") == "openvpnEnable", "protocol": f.get("openvpn_protocol_tun"),
                      "port": f.get("openvpn_service_port_tun"), "port_tap": f.get("openvpn_service_port")}
        upnp = []
        for cells in self.rows("UPNP_upnp.htm"):
            if len(cells) >= 5 and cells[1] in ("TCP", "UDP"):
                upnp.append({"active": cells[0], "protocol": cells[1], "internal_port": cells[2], "external_port": cells[3], "ip": cells[4]})
        out["upnp"] = upnp
        return out

    # ---- writes (each verified by reading the page back) ----
    def set_dns(self, primary: str, secondary: str):
        self.open("BAS_ether.htm", settle=2)
        self.d.execute_script("document.querySelector('input[name=DNSAssign][value=\"1\"]').click()")
        for prefix, ip in (("DAddr", primary), ("PDAddr", secondary)):
            for i, part in enumerate(ip.split("."), 1):
                self._set(f"{prefix}{i}", part)
        self._click("apply", wait=12)
        f = self.form("BAS_ether.htm")
        if f.get("DNSAssign") != "1" or [f.get("wan_dns1_pri"), f.get("wan_dns1_sec")] != [primary, secondary]:
            raise RouterUIError(f"DNS change didn't stick (router shows {f.get('wan_dns1_pri')}, {f.get('wan_dns1_sec')})")

    def ether_snapshot(self) -> dict:
        """The Internet settings that must not change when only DNS is edited."""
        f = self.form("BAS_ether.htm")
        keep = ("wan_proto", "WANAssign", "MACAssign", "wan_hwaddr2", "domain_name", "system_name", "ipv6_proto", "wan_aggr")
        return {k: f.get(k) for k in keep}

    def add_service_rule(self, name: str, protocol: str, port_start: int, port_end: int | None = None):
        """Adds a Block Services rule for all devices (no-op if a rule with this name exists)."""
        existing = [r["name"] for r in self.read_block_services()["rules"]]
        if name in existing:
            return False
        self.open("BKS_service_add.htm")
        self._set("service_type", "User_Defined")
        self._set("protocol", protocol)
        self._set("portstart", port_start)
        self._set("portend", port_end or port_start)
        self._set("userdefined", name)
        self.d.execute_script("document.getElementById('filter_ip_all').click()")
        self._click("add", wait=4)
        if name not in [r["name"] for r in self.read_block_services()["rules"]]:
            raise RouterUIError(f"Block rule {name} wasn't added")
        self._click("apply", wait=6)  # the list page's Apply is what activates new rules
        return True

    PROTECTION_RULES = [  # (name, protocol, port)
        ("Block-External-DNS", "TCP/UDP", 53),  # devices must use the router's (filtered) DNS
        ("Block-DoT-853", "TCP/UDP", 853),  # DNS-over-TLS
        ("Block-VPN-OpenVPN", "TCP/UDP", 1194),
        ("Block-VPN-WireGuard", "UDP", 51820),
    ]

    def ensure_protection_rules(self) -> list[str]:
        """Adds any missing PROTECTION_RULES for all devices. A rule counts as present if one with the
        same name exists, or any rule already blocks that port for every device. Returns names added."""
        existing = self.read_block_services()["rules"]
        added = []
        for name, protocol, port in self.PROTECTION_RULES:
            if any(r["name"] == name or (r["port"] == str(port) and r["ips"].lower() == "all") for r in existing):
                continue
            if self.add_service_rule(name, protocol, port):
                added.append(name)
        return added

    def read_block_services(self) -> dict:
        f = self.form("BKS_service.htm")
        return {"mode": f.get("skeyword"), "rules": parse_rule_rows(self.rows())}

    def set_block_sites(self, mode: str, keywords: list[str]):
        """mode: never | always | perschedule. Replaces the keyword list."""
        self.open("BKS_keyword.htm")
        current = self.form().get("cfKeyWord_DomainList") or []
        if current:
            self.d.execute_script("document.getElementById('keyword_clearlist').click()")
            time.sleep(0.5)
            self._accept_alerts()
        for kw in keywords:
            self._set("keyword_domain", kw)
            self.d.execute_script("document.getElementById('keyword_addkeyword').click()")
            time.sleep(0.4)
            self._accept_alerts()
        self.d.execute_script("document.getElementById(arguments[0]).click()", {"never": "skeyword_never", "always": "skeyword_always",
                                                                                   "perschedule": "skeyword_sched"}[mode])
        self._click("apply", wait=5)
        f = self.form("BKS_keyword.htm")
        if f.get("skeyword") != mode or sorted(f.get("cfKeyWord_DomainList") or []) != sorted(keywords):
            raise RouterUIError("Block Sites change didn't stick")

    def set_schedule(self, days: str, start: str, end: str):
        """days: Mon=0..Sun=6 digits; start/end HH:MM, or both "00:00" for all day."""
        self.open("FW_schedule.htm")
        names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        all_days = len(set(days)) == 7
        self.d.execute_script("""
            const [allDays, days, names, allDay, sh, sm, eh, em] = arguments;
            const f = document.forms[0];
            const box = (n) => f.elements['checkboxName' + n];
            if (box('All').checked !== allDays) box('All').click();
            if (!allDays) names.forEach((n, i) => { if (box(n).checked !== days.includes(String(i))) box(n).click(); });
            if (box('hours').checked !== allDay) box('hours').click();
            if (!allDay) { f.elements.starthour.value = sh; f.elements.startminute.value = sm; f.elements.endhour.value = eh; f.elements.endminute.value = em; }
        """, all_days, days, names, start == end == "00:00", *(int(x) for x in start.split(":")), *(int(x) for x in end.split(":")))
        self._click("apply", wait=4)
        got = parse_schedule(self.form("FW_schedule.htm"))
        want_all_day = start == end == "00:00"
        if got["days"] != "".join(sorted(set(days))) or got["all_day"] != want_all_day or                 (not want_all_day and (got["start"], got["end"]) != (start, end)):
            raise RouterUIError(f"Schedule change didn't stick (router shows {got})")


def parse_rule_rows(rows: list[list[str]]) -> list[dict]:
    """Rows look like ['', '1', 'Block External DNS', '53', '192.168.1.2 - 192.168.1.15'] (first cell is a radio)."""
    rules = []
    for cells in rows:
        cells = [c for c in cells if c != ""]
        if len(cells) >= 4 and cells[0].isdigit() and re.fullmatch(r"[\d\-\s]+", cells[2]):
            rules.append({"name": cells[1], "port": cells[2], "ips": cells[3]})
    return rules


def parse_schedule(f: dict) -> dict:
    mask = int(f.get("schedule_day") or 0)
    # Netgear's bitmask runs Sunday=1, Monday=2 ... Saturday=64
    days = "".join(str(i) for i, bit in enumerate([2, 4, 8, 16, 32, 64, 1]) if mask & bit)
    all_day = f.get("checkboxNamehours") == "checkboxValue" or f.get("schedule_alldayenable") == "1"
    start = f"{int(f.get('schedule_starthour') or 0):02d}:{int(f.get('schedule_startminute') or 0):02d}"
    end = f"{int(f.get('schedule_endhour') or 0):02d}:{int(f.get('schedule_endminute') or 0):02d}"
    return {"days": days, "all_day": all_day, "start": "00:00" if all_day else start, "end": "00:00" if all_day else end}


@contextmanager
def session(host, password, user="admin"):
    with RouterUI(host, password, user) as ui:
        yield ui


# ---- router log (plain HTTP: the log page needs no JavaScript) ----
LOG_LINE = re.compile(r"^\[(?P<kind>[^\]]+)\]\s*(?:from source (?P<src>[\d.]+)\s*,?)?(?P<rest>.*?),?\s*"
                      r"(?P<when>\w+day, \w{3} \d{1,2},\d{4} \d{2}:\d{2}:\d{2})\s*$")


def fetch_log(host: str, password: str, user: str = "admin") -> list[dict]:
    """Returns the router's log (newest first) as dicts: ts, kind, source, text."""
    import requests
    import urllib3
    urllib3.disable_warnings()
    s = requests.Session()
    s.verify = False
    with _lock:  # don't collide with a browser session
        try:
            # The first request to a protected page answers 401 and hands out an XSRF cookie;
            # the router only accepts the password together with that cookie.
            r = s.get(f"https://{host}/FW_log.htm", auth=(user, password), timeout=30)
            if r.status_code == 401:
                r = s.get(f"https://{host}/FW_log.htm", auth=(user, password), timeout=30)
            if r.status_code == 401:
                raise RouterUIError("The router rejected the admin password")
            html = r.text
        finally:
            try:
                s.get(f"https://{host}/LGO_logout.htm", auth=(user, password), timeout=10)
            except Exception:
                pass
    m = re.search(r"<textarea[^>]*>(.*?)</textarea>", html, re.S | re.I)
    import html as htmllib
    return parse_log(htmllib.unescape(m.group(1)) if m else "")


def parse_log(text: str) -> list[dict]:
    from datetime import datetime
    out = []
    for line in text.splitlines():
        line = line.strip()
        m = LOG_LINE.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m["when"], "%A, %b %d,%Y %H:%M:%S").timestamp()
        except ValueError:
            continue  # e.g. the bogus year the router logs right after a restart
        out.append({"ts": ts, "kind": m["kind"].strip(), "source": m["src"] or "", "text": line})
    return out
