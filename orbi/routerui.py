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
            import shutil
            import tempfile
            from pathlib import Path
            from selenium import webdriver
            from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
            from selenium.webdriver.firefox.options import Options
            from selenium.webdriver.firefox.service import Service
            from . import geckodriver, routercert
            try:
                routercert.check(self.host)  # before Firefox can send the password anywhere
            except routercert.CertificateChanged as e:
                raise RouterUIError(str(e)) from e
            opts = Options()
            opts.add_argument("-headless")
            opts.binary_location = FIREFOX
            # The router's certificate is self-signed. Rather than accept any certificate, the profile trusts
            # exactly the pinned one; Firefox refuses an impostor before the password is ever sent.
            opts.accept_insecure_certs = False
            profile_dir = Path(tempfile.mkdtemp(prefix="orbi-ff-"))
            (profile_dir / "cert_override.txt").write_text(routercert.firefox_override(self.host), "utf-8")
            opts.profile = FirefoxProfile(str(profile_dir))
            shutil.rmtree(profile_dir, ignore_errors=True)  # Selenium has copied it
            opts.enable_bidi = True
            service = Service(executable_path=str(geckodriver.path()))  # pinned and hash-checked
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
        out["vpn"] = self.read_vpn()
        out["ddns"] = self.read_ddns()
        upnp = []
        out["upnp_enabled"] = self.form("UPNP_upnp.htm").get("UPnP") == "UPnP"
        for cells in self.rows():
            if len(cells) >= 5 and cells[1] in ("TCP", "UDP"):
                upnp.append({"active": cells[0], "protocol": cells[1], "internal_port": cells[2], "external_port": cells[3], "ip": cells[4]})
        out["upnp"] = upnp
        out["port_forwards"] = self.read_port_forwards()
        out["iot"] = self.read_iot()
        try:
            out["wps"] = self.read_wps()
        except Exception as e:  # not on every model's pages
            log.info("couldn't read WPS: %s", e)
            out["wps"] = None
        return out

    def read_wps(self) -> dict:
        """WPS: pressing Sync on the router or a satellite lets a WPS device join the main Wi-Fi without the
        password for 2 minutes. Netgear took the WPS on/off setting out of this firmware (RBR750 V7.2.8.8: the
        old field is commented out of the Advanced Wireless page), but the Add WPS Client page still offers
        push-button pairing, so WPS is on and can't be turned off."""
        self.open("WPS.htm", settle=2)
        return self.d.execute_script("""
            const text = document.body ? document.body.innerText : '';
            const off = document.querySelector('[name=wps_enable]');  // only if a firmware brings the setting back
            const offered = /Push Button/i.test(text);
            return {enabled: off && off.type !== 'hidden' ? off.value !== 'disabled' : (offered ? true : null),
                    adjustable: !!(off && off.type !== 'hidden')};""")

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

    # ---- Block Services (the router's firewall rules) ----
    def _fill_rule_form(self, name: str, protocol: str, port_start: int, port_end: int, applies: dict):
        """Fills the add/edit rule form (both pages use the same field names)."""
        self._set("service_type", "User_Defined")  # first: changing it rewrites the other fields
        self._set("protocol", protocol)
        self._set("portstart", port_start)
        self._set("portend", port_end)
        self._set("userdefined", name)
        self.d.execute_script("document.getElementById(arguments[0]).click()",
                              {"all": "filter_ip_all", "single": "filter_ip_single", "range": "filter_ip_range"}[applies["type"]])
        if applies["type"] == "single":
            for i, octet in enumerate(applies["ip"].split("."), 1):
                self._set(f"f_pcip{i}", octet)
        elif applies["type"] == "range":
            for i, (a, b) in enumerate(zip(applies["start"].split("."), applies["end"].split(".")), 1):
                self._set(f"f_startip{i}", a)
                self._set(f"f_endip{i}", b)

    def _activate_rules(self):
        """The list page's Apply is what puts added/edited/deleted rules into effect."""
        self.open("BKS_service.htm", settle=2)
        self._click("apply", wait=6)

    def _select_rule(self, index: int, expected_name: str) -> list[dict]:
        """Opens the rule list and selects row `index`, refusing if that row isn't the rule the user meant."""
        rules = self.read_block_services()["rules"]
        if index >= len(rules) or rules[index]["name"] != expected_name:
            raise RouterUIError(f"The router's rule list changed (no rule {expected_name!r} at position {index + 1}); refresh and try again")
        self.d.execute_script("document.querySelectorAll('input[name=ruleSelect]')[arguments[0]].click()", index)
        return rules

    def _check_rule(self, rules: list[dict], index: int, name: str, port_start: int, applies: dict):
        r = rules[index] if index < len(rules) else None
        if not r or r["name"] != name or rule_ips_text(applies) != r["ips"] or not r["port"].startswith(str(port_start)):
            raise RouterUIError(f"The router didn't save rule {name!r} as asked (it shows {r})")

    def add_rule(self, name: str, protocol: str, port_start: int, port_end: int, applies: dict) -> dict:
        if any(r["name"] == name for r in self.read_block_services()["rules"]):
            raise RouterUIError(f"A rule called {name!r} already exists")
        self.open("BKS_service_add.htm", settle=2)
        self._fill_rule_form(name, protocol, port_start, port_end, applies)
        self._click("add", wait=4)
        self._activate_rules()
        rules = self.read_block_services()["rules"]
        index = next((i for i, r in enumerate(rules) if r["name"] == name), len(rules))
        self._check_rule(rules, index, name, port_start, applies)
        return rules[index]

    def edit_rule(self, index: int, expected_name: str, name: str, protocol: str, port_start: int, port_end: int, applies: dict) -> dict:
        self._select_rule(index, expected_name)
        self._click("edit", wait=3)  # opens the edit form; nothing changes until it's accepted
        if (self.form().get("userdefined") or "") != expected_name:
            raise RouterUIError(f"The router opened the wrong rule for editing (expected {expected_name!r})")
        self._fill_rule_form(name, protocol, port_start, port_end, applies)
        self._click("apply", wait=4)  # "Accept"
        self._activate_rules()
        rules = self.read_block_services()["rules"]
        self._check_rule(rules, index, name, port_start, applies)
        return rules[index]

    def delete_rule(self, index: int, expected_name: str):
        before = self._select_rule(index, expected_name)
        self._click("delete", wait=4)
        self._activate_rules()
        after = self.read_block_services()["rules"]
        if after != before[:index] + before[index + 1:]:
            raise RouterUIError(f"Rule {expected_name!r} wasn't deleted as expected")

    def set_rules_mode(self, mode: str):
        """never | perschedule | always: when the Block Services rules are in force."""
        self.open("BKS_service.htm", settle=2)
        self.d.execute_script("document.getElementById(arguments[0]).click()",
                              {"never": "skeyword_never", "perschedule": "skeyword_sched", "always": "skeyword_always"}[mode])
        self._click("apply", wait=6)
        if self.read_block_services()["mode"] != mode:
            raise RouterUIError("The router didn't change when its firewall rules apply")

    PROTECTION_RULES = [  # (name, protocol, port)
        ("Block-External-DNS", "TCP/UDP", 53),  # devices must use the router's (filtered) DNS
        ("Block-DoT-853", "TCP/UDP", 853),  # DNS-over-TLS
        ("Block-VPN-OpenVPN", "TCP/UDP", 1194),
        ("Block-VPN-WireGuard", "UDP", 51820),
    ]

    def ensure_protection_rules(self) -> list[str]:
        """Makes sure each PROTECTION_RULES port is blocked for every device: adds missing rules, and widens
        one of ours that only covers some devices (an early version could save them for this PC only).
        Rules the user made that cover the port partly (e.g. a range that leaves out one device) are left alone.
        Returns what changed."""
        changed = []
        for name, protocol, port in self.PROTECTION_RULES:
            rules = self.read_block_services()["rules"]
            if any(r["port"] == str(port) and r["ips"].lower() == "all" for r in rules):
                continue
            mine = next((i for i, r in enumerate(rules) if r["name"] == name), None)
            if mine is not None:
                self.edit_rule(mine, name, name, protocol, port, port, {"type": "all"})
                changed.append(f"{name} (now covers every device)")
            elif not any(r["port"] == str(port) for r in rules):
                self.add_rule(name, protocol, port, port, {"type": "all"})
                changed.append(name)
        return changed

    # ---- DHCP address reservations (LAN Setup) ----
    def read_reservations(self) -> list[dict]:
        f = self.form("LAN_reserv_add.htm")
        ips = (f.get("reserved_ips") or "").split()
        macs = (f.get("reserved_macs") or "").split()
        names = (f.get("reserved_devname") or "").split("|")
        return [{"ip": ip, "mac": mac.upper(), "name": names[i] if i < len(names) else ""} for i, (ip, mac) in enumerate(zip(ips, macs))]

    def _fill_reservation(self, ip: str, mac: str, name: str):
        for i, octet in enumerate(ip.split("."), 1):
            self._set(f"rsv_ip{i}", octet)
        self._set("rsv_mac", mac)
        self._set("dv_name", name)

    def _check_reservations(self, expect: list[dict], what: str):
        got = self.read_reservations()
        norm = lambda rs: [(r["ip"], r["mac"].upper()) for r in rs]
        if norm(got) != norm(expect):
            raise RouterUIError(f"The router didn't {what} as asked (it lists {norm(got)})")
        return got

    def add_reservation(self, ip: str, mac: str, name: str) -> list[dict]:
        before = self.read_reservations()
        if any(r["mac"] == mac.upper() or r["ip"] == ip for r in before):
            raise RouterUIError(f"{ip} or {mac} already has a reservation")
        self.open("LAN_reserv_add.htm", settle=2)
        self._fill_reservation(ip, mac, name)
        self._click("add", wait=6)
        return self._check_reservations(before + [{"ip": ip, "mac": mac}], "save the reservation")

    def _select_reservation(self, index: int, expected_mac: str) -> list[dict]:
        before = self.read_reservations()
        if index >= len(before) or before[index]["mac"] != expected_mac.upper():
            raise RouterUIError("The router's reservation list changed; refresh and try again")
        self.open("LAN_lan.htm", settle=2)
        self.d.execute_script("document.querySelectorAll('input[name=ruleSelect]')[arguments[0]].click()", index)
        return before

    def edit_reservation(self, index: int, expected_mac: str, ip: str, mac: str, name: str) -> list[dict]:
        before = self._select_reservation(index, expected_mac)
        self._click("edit", wait=4)  # opens LAN_reserv_edit; nothing changes until it's applied
        if (self.form().get("orig_rsv_mac") or "").upper() != expected_mac.upper():
            raise RouterUIError("The router opened the wrong reservation for editing")
        self._fill_reservation(ip, mac, name)
        self.d.execute_script("document.forms[0].elements['Apply'].click()")
        import time
        time.sleep(1)
        self._accept_alerts()
        time.sleep(5)
        expect = [dict(r) for r in before]
        expect[index] = {"ip": ip, "mac": mac}
        return self._check_reservations(expect, "change the reservation")

    def delete_reservation(self, index: int, expected_mac: str) -> list[dict]:
        before = self._select_reservation(index, expected_mac)
        self._click("delete", wait=6)
        return self._check_reservations(before[:index] + before[index + 1:], "delete the reservation")

    # ---- UPnP and manual port forwarding ----
    def read_port_forwards(self) -> list[dict]:
        """Manual port-forwarding rules (FW_forward3.htm), shown read-only."""
        out = []
        for cells in self.rows("FW_forward3.htm"):
            cells = [c for c in cells if c != ""]
            if len(cells) >= 5 and cells[0].isdigit() and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", cells[-1]):
                out.append({"name": cells[1], "external_port": cells[2], "internal_port": cells[3], "ip": cells[-1]})
        return out

    def set_upnp(self, enabled: bool) -> bool:
        self.open("UPNP_upnp.htm", settle=2)
        if self.d.execute_script("return document.getElementById('upnp').checked") != enabled:
            self.d.execute_script("document.getElementById('upnp').click()")
        self._click("apply", wait=6)
        got = self.form("UPNP_upnp.htm").get("UPnP") == "UPnP"
        if got != enabled:
            raise RouterUIError("The router didn't change UPnP as asked")
        return got

    # ---- remote access: the Orbi's VPN server and Dynamic DNS ----
    def read_vpn(self) -> dict:
        f = self.form("OPENVPN.htm")
        return {"enabled": f.get("openvpnActive") == "openvpnEnable", "protocol": f.get("openvpn_protocol_tun"),
                "port": f.get("openvpn_service_port_tun"), "port_tap": f.get("openvpn_service_port")}

    DDNS_PROVIDERS = ("NETGEAR", "No-IP", "Dyn")

    def read_ddns(self) -> dict:
        """The router's Dynamic DNS settings. The password is never read back out."""
        f = self.form("DNS_ddns.htm")
        provider = f.get("sysDNSProviderlist") or ""
        netgear = provider == "NETGEAR"
        return {"enabled": f.get("sysDNSActive") == "dnsEnable", "provider": provider,
                "host": (f.get("sysDNSHost_Netgear") if netgear else f.get("sysDNSHost")) or "",
                "user": "" if netgear else f.get("sysDNSUser") or "", "wildcard": f.get("sysDNSWildCard") == "wildEnable"}

    def set_ddns(self, enabled: bool, provider: str, host: str, user: str, password: str | None = None) -> dict:
        """No-IP / Dyn accounts (NETGEAR's own service has a separate sign-up flow on the router page)."""
        self.open("DNS_ddns.htm", settle=3)
        if self.d.execute_script("return document.getElementById('sys_dnsactive').checked") != enabled:
            self.d.execute_script("document.getElementById('sys_dnsactive').click()")
        if enabled:
            self._set("sys_dnsprovider_list", provider)
            self._set("sys_dnshost", host)
            self._set("sys_dnsuser", user)
            if password:
                self._set("sys_dnspassword", password)
        self._click("apply", wait=8)
        got = self.read_ddns()
        want = {"enabled": enabled} if not enabled else {"enabled": True, "provider": provider, "host": host, "user": user}
        if any(got[k] != v for k, v in want.items()):
            raise RouterUIError(f"The router didn't save the Dynamic DNS settings as asked (it shows {got})")
        return got

    # ---- IoT Wi-Fi network (on the main Wireless Setup page) ----
    IOT_BANDS = {"both": "enable_iot_2g5g", "2.4": "enable_iot_2g", "5": "enable_iot_5g"}
    IOT_SECURITY = {"WPA2-PSK": ("security_wpa2_iot", "passphrase_Iot"), "WPA-AUTO-PSK": ("security_auto_iot", "passphrase_auto_Iot")}

    def read_iot(self) -> dict:
        f = self.form("WLG_wireless2.htm")
        two, five = f.get("enable_iot_2g_value") == "1", f.get("enable_iot_5g_value") == "1"
        return {"enabled": f.get("enable_iot") == "1", "ssid": f.get("ssid_iot") or "",
                "band": "both" if two and five else "5" if five else "2.4", "security": f.get("security_type_iot") or ""}

    _WIFI_SNAPSHOT_JS = """
const out = {};
for (const e of document.forms[0].elements) {
  if (!e.name || /iot|buttonHit|buttonValue|password_changed/i.test(e.name) || e.type === 'button' || e.type === 'submit') continue;
  if (e.type === 'radio' || e.type === 'checkbox') { if (e.checked) out[e.name] = e.value; } else out[e.name] = e.value;
}
return out;"""

    def set_iot(self, enabled: bool, ssid: str, band: str, security: str, password: str | None = None) -> dict:
        """Changes the IoT network. Saving restarts the router's and satellites' Wi-Fi; everything else on
        the page (main network name, password, channels) must come back unchanged."""
        self.open("WLG_wireless2.htm", settle=2.5)
        before = self.d.execute_script(self._WIFI_SNAPSHOT_JS)
        if self.d.execute_script("return document.getElementById('enable_iot').checked") != enabled:
            self.d.execute_script("document.getElementById('enable_iot').click()")
        if enabled:
            radio, field = self.IOT_SECURITY[security]
            self.d.execute_script("document.getElementById(arguments[0]).click()", self.IOT_BANDS[band])
            self._set("ssid_iot", ssid)
            self.d.execute_script("document.getElementById(arguments[0]).click()", radio)
            if password:
                self.d.execute_script("""
                    const el = document.getElementById(arguments[0]);
                    el.value = arguments[1];
                    for (const t of ['input', 'keyup', 'change']) el.dispatchEvent(new Event(t, {bubbles: true}));
                    document.forms[0].elements['password_changed_iot'].value = '1';""", field, password)
        self._click("Apply", wait=25)  # the router restarts Wi-Fi on every radio
        self.open("WLG_wireless2.htm", settle=3)
        got = self.read_iot()
        after = self.d.execute_script(self._WIFI_SNAPSHOT_JS)
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        if changed:
            raise RouterUIError(f"Other Wi-Fi settings changed while saving the IoT network: {', '.join(changed)}. Check them on the router")
        want = {"enabled": enabled} if not enabled else {"enabled": True, "ssid": ssid, "band": band, "security": security}
        if any(got[k] != v for k, v in want.items()):
            raise RouterUIError(f"The router didn't save the IoT network as asked (it shows {got})")
        if enabled and password and not self.d.execute_script("return document.getElementById(arguments[0]).value === arguments[1]",
                                                              self.IOT_SECURITY[security][1], password):
            raise RouterUIError("The router didn't save the new IoT password")
        return got

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


def rule_ips_text(applies: dict) -> str:
    """How the router's rule list shows who a rule applies to."""
    return {"all": lambda a: "all", "single": lambda a: a["ip"], "range": lambda a: f"{a['start']} - {a['end']}"}[applies["type"]](applies)


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
    import urllib3
    from . import routercert
    urllib3.disable_warnings()
    try:
        routercert.check(host)
    except routercert.CertificateChanged as e:
        raise RouterUIError(str(e)) from e
    s = routercert.session(host)  # must present the pinned certificate
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


def fetch_backup(host: str, password: str, user: str = "admin", model: str = "RBR750") -> bytes:
    """The router's settings file, exactly what its Backup button downloads (NETGEAR_<model>.cfg)."""
    import urllib3
    from . import routercert
    urllib3.disable_warnings()
    try:
        routercert.check(host)
    except routercert.CertificateChanged as e:
        raise RouterUIError(str(e)) from e
    s = routercert.session(host)
    with _lock:
        try:
            url = f"https://{host}/NETGEAR_{re.sub(r'[^A-Za-z0-9_-]', '', model) or 'RBR750'}.cfg"
            r = s.get(url, auth=(user, password), timeout=60)
            if r.status_code == 401:
                r = s.get(url, auth=(user, password), timeout=60)
            if r.status_code != 200:
                raise RouterUIError(f"The router didn't hand over its settings (HTTP {r.status_code})")
            data = r.content
        finally:
            try:
                s.get(f"https://{host}/LGO_logout.htm", auth=(user, password), timeout=10)
            except Exception:
                pass
    if len(data) < 1024 or data.lstrip()[:1] == b"<":
        raise RouterUIError("The router sent a web page instead of its settings file")
    return data


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
