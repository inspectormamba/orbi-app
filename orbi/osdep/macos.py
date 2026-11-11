"""macOS back end: Keychain secrets, the unified log for tamper-evidence, flock, launchd helper.

Mirrors what windows.py does on Windows, using only tools present on every mac (the `security`,
`logger`, `log`, `sysctl` and `osascript` CLIs) so there are no extra dependencies to pin.

Anti-tamper note: the Windows build keeps its second copy of every alert in the Application event
log, which needs an administrator to clear and is itself audited. The closest macOS facility is the
unified log: messages written with `logger` can be read back with `log show`, and erasing it needs
`sudo log erase` (and leaves the machine's own trace). Two real differences from Windows, documented
for honesty and handled as well as possible here:
  * The unified log is size-bounded and rotates, so very old entries can age out (weeks on a quiet
    machine, less on a busy one) rather than being kept the full 90 days. `verify()` writes a canary
    and reads it back so a degraded log can be surfaced at startup.
  * A single log message can be truncated, so each record is split into base64 chunks that are
    reassembled on read (see _encode_chunks / _parse_messages, which are pure and unit-tested).
"""
import base64
import json
import os
import re
import secrets
import subprocess
import time
from pathlib import Path

# fcntl is imported inside single_instance() so this module stays importable on Windows
# (its pure helpers _encode_chunks/_parse_messages are unit-tested there).

SYSTEM_LOG_NAME = "the macOS system log"
SERVICE_CREATION_FLAGS = 0  # POSIX: subprocess creationflags must be 0

KEYCHAIN_SERVICE = "OrbiControl"
LOG_TAG = "OrbiControl"
LOG_PREFIX = "OC|"
LOG_CHUNK = 1800  # raw utf-8 bytes per logger line, before base64, to stay under any truncation
LOG_LOOKBACK_DAYS = 90  # tamper.WINDOW is 80 days; read a little more


# ---- secrets: the login Keychain, one generic-password item per secret ----
# protect() stashes the secret in the Keychain and returns a "keychain:<id>" reference that goes in
# settings.json; unprotect() reads it back. The secret value itself never touches settings.json.
def protect(text: str) -> str:
    acct = secrets.token_hex(16)
    r = subprocess.run(["security", "add-generic-password", "-s", KEYCHAIN_SERVICE, "-a", acct,
                        "-w", text, "-U", "-A"], capture_output=True, text=True)
    if r.returncode != 0:
        raise OSError(f"Keychain write failed: {r.stderr.strip()}")
    return f"keychain:{acct}"


def unprotect(token: str) -> str:
    if not token.startswith("keychain:"):
        raise ValueError("not a Keychain reference")
    acct = token[len("keychain:"):]
    r = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", acct, "-w"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise OSError(f"Keychain read failed: {r.stderr.strip()}")
    return r.stdout.rstrip("\n")


# ---- tamper-evidence log: the unified log, via `logger` (write) and `log show` (read) ----
def _encode_chunks(event_id: int, text: str, uid: str) -> list[str]:
    """One logger line per chunk: OC|<event_id>|<uid>|<idx>|<total>|<base64 of a utf-8 slice>."""
    data = text.encode("utf-8")
    parts = [data[i:i + LOG_CHUNK] for i in range(0, len(data), LOG_CHUNK)] or [b""]
    total = len(parts)
    return [f"{LOG_PREFIX}{event_id}|{uid}|{idx}|{total}|{base64.b64encode(p).decode('ascii')}"
            for idx, p in enumerate(parts)]


def _parse_messages(messages):
    """messages: iterable of (timestamp_str, eventMessage). Returns [(ts, event_id, text)] for every
    record whose chunks are all present, newest first."""
    groups = {}  # uid -> {"eid", "total", "ts", "chunks": {idx: bytes}}
    for ts, msg in messages:
        if not msg.startswith(LOG_PREFIX):
            continue
        body = msg[len(LOG_PREFIX):]
        bits = body.split("|", 4)
        if len(bits) != 5:
            continue
        eid_s, uid, idx_s, total_s, b64 = bits
        try:
            eid, idx, total = int(eid_s), int(idx_s), int(total_s)
            chunk = base64.b64decode(b64)
        except (ValueError, Exception):
            continue
        g = groups.setdefault(uid, {"eid": eid, "total": total, "ts": ts, "chunks": {}})
        g["chunks"][idx] = chunk
        if ts > g["ts"]:
            g["ts"] = ts
    out = []
    for g in groups.values():
        if len(g["chunks"]) != g["total"]:
            continue  # a truncated/partial record: skip rather than hand back a half alert
        text = b"".join(g["chunks"][i] for i in range(g["total"])).decode("utf-8", "replace")
        out.append((g["ts"], g["eid"], text))
    out.sort(key=lambda r: r[0], reverse=True)
    return out


class SysLog:
    """The unified log. write() emits chunked `logger` lines; read() reassembles them from `log show`."""

    def write(self, event_id: int, text: str, warn: bool = False) -> bool:
        uid = secrets.token_hex(8)
        level = "user.warning" if warn else "user.notice"
        ok = True
        for line in _encode_chunks(event_id, text, uid):
            r = subprocess.run(["logger", "-t", LOG_TAG, "-p", level, line], capture_output=True, text=True)
            ok = ok and r.returncode == 0
        return ok

    def read(self, event_ids, count: int = 1):
        """Newest first: [(event id, text)]."""
        predicate = f'process == "logger" AND eventMessage BEGINSWITH "{LOG_PREFIX}"'
        r = subprocess.run(["log", "show", "--style", "ndjson", "--last", f"{LOG_LOOKBACK_DAYS}d",
                            "--predicate", predicate], capture_output=True, text=True, timeout=300)
        rows = []
        for ln in r.stdout.splitlines():
            ln = ln.strip()
            if not ln or not ln.startswith("{"):
                continue
            try:
                obj = json.loads(ln)
            except ValueError:
                continue
            msg, ts = obj.get("eventMessage"), obj.get("timestamp")
            if msg and ts:
                rows.append((ts, msg))
        want = set(event_ids)
        found = [(eid, text) for _ts, eid, text in _parse_messages(rows) if eid in want]
        return found[:count]

    def verify(self) -> bool:
        """Write a canary and read it straight back, so a rotated-out or unreadable log can be caught."""
        nonce = secrets.token_hex(8)
        self.write(0, f"canary {nonce}")
        time.sleep(1.0)  # the unified log is eventually consistent
        return any(text.endswith(nonce) for _eid, text in self.read((0,), count=50))


def boot_time() -> float:
    """Epoch seconds the machine last booted (sysctl kern.boottime)."""
    try:
        out = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"sec\s*=\s*(\d+)", out)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return time.time() - time.monotonic()  # fallback: monotonic clock is ~boot-relative on macOS


# ---- single instance: one per data folder (flock on a lockfile) ----
_lock_fd = None  # kept alive for the life of the process so the lock is held


def single_instance(data_dir) -> bool:
    import fcntl
    global _lock_fd
    try:
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        fd = open(Path(data_dir) / "orbi.lock", "w")
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    _lock_fd = fd
    return True


def _applescript_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def notify(title: str, message: str) -> bool:
    script = f"display notification {_applescript_str(message)} with title {_applescript_str(title)}"
    try:
        return subprocess.run(["osascript", "-e", script], capture_output=True, text=True).returncode == 0
    except Exception:
        return False


def firefox_binary() -> str:
    for p in ("/Applications/Firefox.app/Contents/MacOS/firefox",
              str(Path.home() / "Applications/Firefox.app/Contents/MacOS/firefox")):
        if os.path.isfile(p):
            return p
    return "/Applications/Firefox.app/Contents/MacOS/firefox"


def default_data_dir() -> Path:
    return Path.home() / "Library" / "Application Support" / "OrbiControl"


# ---- the pinned geckodriver for this OS (Apple Silicon) ----
GECKODRIVER = {
    "version": "0.37.1",
    "url": "https://github.com/mozilla/geckodriver/releases/download/v0.37.1/geckodriver-v0.37.1-macos-aarch64.tar.gz",
    "archive": "tar.gz",
    "member": "geckodriver",
    "exe_name": "geckodriver",
    "archive_sha256": "d02b3f7003f999caf90974a2ef5da0286c05d01cee19112c86846d759fdba4f5",
    "binary_sha256": "5d82307edc8549124bd4e7b6f275e1228e0a530e5abbfb294be3f310486561a4",
}


# ---- update / rollback helper (bash; runs from the old code, outlives this process) ----
HELPER = r'''#!/bin/bash
# args: AppPid Root Backup Port DataDir Version ReqChanged
APPPID="$1"; ROOT="$2"; BACKUP="$3"; PORT="$4"; DATADIR="$5"; VERSION="$6"; REQCHANGED="$7"
LABEL="%TASK%"
RESULT="$DATADIR/update-result.json"
PY="$ROOT/.venv/bin/python"
rm -f "$RESULT"
start_app() {
  if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
    launchctl kickstart -k "gui/$(id -u)/$LABEL"
  else
    nohup "$PY" -m orbi --background >/dev/null 2>&1 &
  fi
}
stop_app() {
  if launchctl print "gui/$(id -u)/$LABEL" >/dev/null 2>&1; then
    launchctl kill TERM "gui/$(id -u)/$LABEL" 2>/dev/null
  fi
  pkill -f "orbi --background" 2>/dev/null
}
test_app() {
  curl -fsS --max-time 5 "http://127.0.0.1:$PORT/api/session" 2>/dev/null \
    | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin).get('version')=='$VERSION' else 1)" 2>/dev/null
}
# wait for the old app to exit (up to 30s), then make sure it's gone
for _ in $(seq 1 30); do kill -0 "$APPPID" 2>/dev/null || break; sleep 1; done
kill -9 "$APPPID" 2>/dev/null
sleep 2
start_app
deadline=$(( $(date +%s) + 120 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if test_app; then printf '{"ok": true, "version": "%s"}' "$VERSION" > "$RESULT"; exit 0; fi
  sleep 3
done
# the new version didn't come up: put the old one back
stop_app
sleep 2
for d in "$BACKUP"/*/; do
  [ -d "$d" ] || continue
  name="$(basename "$d")"
  rsync -a --delete "$d" "$ROOT/$name/" 2>/dev/null || cp -R "$d." "$ROOT/$name/"
done
find "$BACKUP" -maxdepth 1 -type f -exec cp -f {} "$ROOT/" \;
if [ "$REQCHANGED" = "1" ]; then
  "$PY" -m pip install --quiet --disable-pip-version-check -r "$ROOT/requirements.txt"
fi
printf '{"ok": false, "version": "%s", "rolled_back": true}' "$VERSION" > "$RESULT"
start_app
'''

LAUNCHD_LABEL = "com.orbicontrol.agent"


def launch_update_helper(root: Path, task: str, data_dir: Path, bak: Path, port: int, req_changed: bool, version: str):
    script = data_dir / "update-helper.sh"
    script.write_text(HELPER.replace("%TASK%", LAUNCHD_LABEL), "utf-8")
    script.chmod(0o755)
    subprocess.Popen(["/bin/bash", str(script), str(os.getpid()), str(root), str(bak), str(port),
                      str(data_dir), version, "1" if req_changed else "0"],
                     start_new_session=True, close_fds=True, cwd=str(root),
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ---- network: the ARP table and this Mac's own adapters ----
# The text parsers are pure so they're unit-tested on any OS; only the subprocess wrappers need a Mac.
_ARP_LINE = re.compile(r"^\S+ \((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9A-Fa-f]{1,2}(?::[0-9A-Fa-f]{1,2}){5})(?=\s|$)")


def _run(args: list[str], timeout: float) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _pad_mac(mac: str) -> str:
    """macOS drops leading zeros (0:90:4c:1a:9:0); the app always compares AA:BB:CC:DD:EE:FF."""
    return ":".join(p.zfill(2) for p in mac.split(":")).upper()


def parse_arp(out: str, dynamic_only: bool = True) -> dict[str, str]:
    """`arp -an` output -> {ip: "AA:BB:CC:DD:EE:FF"}.
    Lines look like '? (192.168.1.1) at c8:9e:43:c2:e3:33 on en0 ifscope [ethernet]'. '(incomplete)' entries have no
    address; 'permanent' marks this Mac's own/static entries (Windows' "static"); broadcast/multicast are skipped."""
    table = {}
    for line in out.splitlines():
        m = _ARP_LINE.match(line.strip())
        if not m:
            continue
        mac = _pad_mac(m.group(2))
        if int(mac[:2], 16) & 1:  # broadcast / multicast group address
            continue
        if dynamic_only and " permanent" in line:
            continue
        table[m.group(1)] = mac
    return table


def arp_table() -> dict[str, str]:
    """ip -> hardware address for every learned (dynamic) entry in this Mac's ARP table."""
    return parse_arp(_run(["arp", "-an"], 10))


def arp_lookup(host: str) -> str | None:
    """The hardware address the ARP table has for `host` right now, or None."""
    return parse_arp(_run(["arp", "-n", host], 10), dynamic_only=False).get(host)


def parse_ifconfig(out: str) -> dict[str, dict]:
    """`ifconfig` output -> {"en0": {"mac": "AA:..", "ips": ["192.168.1.20"]}, ...}."""
    ifaces, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^([A-Za-z0-9]+): flags=", line)
        if m:
            cur = ifaces.setdefault(m.group(1), {"mac": None, "ips": []})
            continue
        if cur is None:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "ether":
            cur["mac"] = _pad_mac(parts[1])
        elif len(parts) >= 2 and parts[0] == "inet":
            cur["ips"].append(parts[1])
    return ifaces


def _iface_for(ip: str, ifaces: dict | None = None) -> str | None:
    ifaces = parse_ifconfig(_run(["ifconfig"], 10)) if ifaces is None else ifaces
    return next((name for name, i in ifaces.items() if ip in i["ips"]), None)


def local_macs() -> list[str]:
    """Hardware addresses of this Mac's adapters (Wi-Fi shows the address it uses on the current network)."""
    return [i["mac"] for i in parse_ifconfig(_run(["ifconfig"], 10)).values() if i["mac"]]


def parse_hardware_ports(out: str) -> dict[str, str]:
    """`networksetup -listallhardwareports` -> {"en0": "Ethernet", "en1": "Wi-Fi", ...}."""
    ports, port = {}, None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            ports[line.split(":", 1)[1].strip()] = port
    return ports


def adapter_name(ip: str) -> str:
    """A friendly name for the interface that has this address ("Wi-Fi", or "utun4" for a VPN), or ""."""
    iface = _iface_for(ip)
    if not iface:
        return ""
    return parse_hardware_ports(_run(["networksetup", "-listallhardwareports"], 10)).get(iface, iface)


def parse_netstat_obytes(out: str, iface: str) -> int | None:
    """Bytes sent on `iface`, from `netstat -ibn`. Columns are found from the header; rows with an empty Address
    column are skipped, since their columns shift left."""
    lines = [line.split() for line in out.splitlines() if line.strip()]
    if not lines or "Obytes" not in lines[0]:
        return None
    header = lines[0]
    col = header.index("Obytes")
    for parts in lines[1:]:
        if parts[0] == iface and len(parts) == len(header):
            try:
                return int(parts[col])
            except ValueError:
                continue
    return None


def lan_adapter(local_ip: str) -> dict:
    """The interface that has `local_ip`: {"mac", "dhcp_enabled", "dhcp_server", "sent_bytes"}; {} if unknown."""
    ifaces = parse_ifconfig(_run(["ifconfig"], 10))
    iface = _iface_for(local_ip, ifaces)
    if not iface:
        return {}
    server = _run(["ipconfig", "getoption", iface, "server_identifier"], 10).strip()  # empty when the address was set by hand
    return {"mac": ifaces[iface]["mac"], "dhcp_enabled": bool(server), "dhcp_server": server or None,
            "sent_bytes": parse_netstat_obytes(_run(["netstat", "-ibn", "-I", iface], 10), iface)}


IP_BOUND_IF = 25  # <netinet/in.h>: send only through this interface index (Python's socket module doesn't name it)


def dhcp_bind(sock, local_ip: str) -> None:
    """Binds the rogue-DHCP probe socket. BSD doesn't deliver broadcast replies to a socket bound to a unicast address,
    so bind the wildcard address and pin the socket to the home-network interface instead. SO_REUSEPORT lets it share
    port 68 with macOS's own DHCP client; macOS allows non-root binds below port 1024 (since 10.14)."""
    import socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    iface = _iface_for(local_ip)
    if iface:
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(iface))
    sock.bind(("", 68))


def venv_python(root: Path) -> Path:
    return root / ".venv" / "bin" / "python"
