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
