"""Watching the home network itself: fake routers and unusual uploads.

A device that pretends to be the router gets every other device's traffic sent through it. It can do that two
ways, and both are visible from this PC:
  - ARP spoofing: it answers "I'm 192.168.1.1" with its own hardware address, so this PC's ARP table shows the
    router's address belonging to a different device.
  - A rogue DHCP server: it hands out addresses that name itself as the gateway. This PC asks for an address
    (DHCPDISCOVER, never accepting one) and every server on the network that answers is listed.

Upload spikes: the Orbi only reports whole-house usage (its Traffic Meter), not usage per device, so the check is
"the house is uploading far more than it normally does at this time of day". This PC's own upload is subtracted
out of the guesswork by reporting it separately (backups are the usual innocent cause).
"""
import json
import os
import socket
import struct
import subprocess
import time
from datetime import datetime
from statistics import quantiles

MAGIC = b"\x63\x82\x53\x63"

# Upload spike tuning (rates are MB per hour of whole-house upload, from the router's Traffic Meter).
SPIKE_FACTOR = 4  # this many times the usual (90th percentile) upload for the hour of day
SPIKE_FLOOR = 1000  # never alert below this rate, ~2.2 Mbit/s sustained
SPIKE_INTERVALS = 3  # consecutive readings above the line before alerting (45 min at the default 15-min interval)
# Replaying 20 days of this house's history (Oct 2026): 2 readings in a row gave 5 alerts in two weeks, mostly short
# bursts just over the line; 3 in a row gave 2, both sustained uploads at 5-11x normal.
BASELINE_DAYS = 14
MIN_HISTORY_DAYS = 5  # learning period before the alert can fire
MIN_BASELINE_SAMPLES = 20


def build_discover(mac: bytes, xid: bytes) -> bytes:
    """A DHCPDISCOVER asking for replies by broadcast (this PC already has an address and won't accept one)."""
    header = struct.pack("!BBBB4sHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                         b"\0" * 4, mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    return header + MAGIC + bytes([53, 1, 1, 55, 3, 1, 3, 6, 255])


def parse_offer(data: bytes, xid: bytes) -> dict | None:
    """{"server": server id, "gateway": router option, "offered": address} for an OFFER answering xid, else None."""
    if len(data) < 240 or data[0] != 2 or data[4:8] != xid or data[236:240] != MAGIC:
        return None
    out = {"offered": socket.inet_ntoa(data[16:20]), "server": None, "gateway": None}
    opts, i, kind = data[240:], 0, None
    while i < len(opts) and opts[i] != 255:
        if opts[i] == 0:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        code, ln = opts[i], opts[i + 1]
        val = opts[i + 2:i + 2 + ln]
        if code == 53 and ln == 1:
            kind = val[0]
        elif code == 54 and ln == 4:
            out["server"] = socket.inet_ntoa(val)
        elif code == 3 and ln >= 4:
            out["gateway"] = socket.inet_ntoa(val[:4])
        i += 2 + ln
    return out if kind == 2 else None


def dhcp_servers(local_ip: str, mac: str, timeout: float = 4.0) -> dict[str, dict]:
    """Every DHCP server that answers a DISCOVER from this PC's LAN adapter: {source address: offer}."""
    xid = os.urandom(4)
    mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    found: dict[str, dict] = {}
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Windows' own DHCP client also uses port 68
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((local_ip, 68))
        sock.settimeout(0.5)
        sock.sendto(build_discover(mac_bytes, xid), ("255.255.255.255", 67))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, (src, _port) = sock.recvfrom(4096)
            except socket.timeout:
                continue
            offer = parse_offer(data, xid)
            if offer:
                found[src] = offer
    finally:
        sock.close()
    return found


def local_ip_for(router_host: str) -> str | None:
    """The address this PC uses to reach the router (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((router_host, 9))
            return s.getsockname()[0]
    except OSError:
        return None


ADAPTER_PS = r"""
$ip = '{ip}'
$c = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | Where-Object { $_.IPAddress -contains $ip } | Select-Object -First 1
if (-not $c) { '{}'; exit }
$sent = $null
try { $sent = (Get-NetAdapter -InterfaceIndex $c.InterfaceIndex -ErrorAction Stop | Get-NetAdapterStatistics -ErrorAction Stop).SentBytes } catch {}
@{ mac = $c.MACAddress; dhcp_enabled = [bool]$c.DHCPEnabled; dhcp_server = $c.DHCPServer; sent_bytes = $sent } | ConvertTo-Json -Compress
"""


def adapter(local_ip: str) -> dict:
    """This PC's adapter on the home network: {"mac", "dhcp_enabled", "dhcp_server", "sent_bytes"}; {} if unknown."""
    import ipaddress
    try:
        script = ADAPTER_PS.replace("{ip}", str(ipaddress.IPv4Address(local_ip)))  # validated: it's spliced into the script
        out = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                             capture_output=True, text=True, timeout=30, creationflags=0x08000000).stdout  # CREATE_NO_WINDOW
        return json.loads(out.strip() or "{}")
    except Exception:
        return {}


def upload_rates(rows: list[dict], interval: float) -> list[tuple[float, float]]:
    """(ts, MB per hour uploaded since the previous reading) from Traffic Meter snapshots, oldest first.
    today_up restarts when the *router's* day ends, which needn't match this PC's clock, so a drop in the counter is
    the reset: yesterday_up then holds the finished day's total. A gap much longer than the interval (PC asleep,
    router down) gives no rate."""
    out, prev, prev_ts = [], None, None
    for r in rows:
        up = r.get("today_up")
        if up is None:
            prev = None
            continue
        if prev is not None:
            elapsed = r["ts"] - prev_ts
            if 0 < elapsed <= interval * 2.5:
                if up >= prev:
                    sent = up - prev
                else:
                    before_reset = (r.get("yesterday_up") or prev) - prev
                    sent = max(before_reset, 0) + up
                out.append((r["ts"], sent * 3600 / elapsed))
        prev, prev_ts = up, r["ts"]
    return out


def _hour_gap(a: int, b: int) -> int:
    d = abs(a - b) % 24
    return min(d, 24 - d)


def spike_line(rates: list[tuple[float, float]], now: float) -> dict | None:
    """What counts as unusual right now: {"line", "usual", "days"}, or None while still learning."""
    if not rates or now - rates[0][0] < MIN_HISTORY_DAYS * 86400:
        return None
    hour = datetime.fromtimestamp(now).hour
    since = now - BASELINE_DAYS * 86400
    same_hour = [r for ts, r in rates if since <= ts < now - 2 * 3600 and _hour_gap(datetime.fromtimestamp(ts).hour, hour) <= 1]
    if len(same_hour) < MIN_BASELINE_SAMPLES:
        return None
    usual = quantiles(same_hour, n=10)[-1]  # 90th percentile
    return {"line": max(usual * SPIKE_FACTOR, SPIKE_FLOOR), "usual": usual, "days": round((now - rates[0][0]) / 86400)}


def fmt_mb(mb: float) -> str:
    return f"{mb / 1000:.1f} GB" if mb >= 1000 else f"{mb:.0f} MB"
