"""Notices when Orbi Control's history or protections are changed behind its back, and undoes what it can.

Anyone at this PC's keyboard runs as the same Windows user as the app, so nothing here can make the files
untouchable. What it does instead is keep a second record somewhere harder to reach: the Windows Event Log
(Application log, source "Orbi Control"). Writing to it needs no special rights; clearing it needs an
administrator, and Windows notes that it happened.

- Every alert is copied there as it's recorded. Alerts later deleted from the app are put back from the copy.
- A checkpoint (how much history there is, and the protective settings) is written every few minutes. After
  any change, including one made while the app was stopped, the app compares against it and says what's gone.
- Alert and protection switches turned off by anything other than the app itself are switched back on.
- A shut-down that didn't go through Quit, an update or a Windows restart is reported.

The database locks themselves are in store.py (LOCKS).
"""
import ctypes
import hashlib
import html
import json
import logging
import os
import re
import subprocess
import threading
import time

from . import config, store as store_mod

log = logging.getLogger(__name__)

SOURCE = "Orbi Control"
MIRROR, CHECKPOINT, TAMPER, STOPPED = 1, 2, 3, 4  # Event Log event IDs
WINDOW = 80 * 86400  # history checked for deletions: newer than the prune cutoff, with room to spare
CHECKPOINT_EVERY = 10 * 60
RESTORE_LIMIT = 20000  # most recent alert copies read back when restoring
# Switches that only ever make the app quieter or more permissive when turned off: put back if changed outside.
GUARDED = ("alert_admin_login_failures", "alert_new_devices", "block_pin_attackers", "hold_new_devices", "check_updates")
# Changes outside the app are reported. Only fingerprints go in the Event Log (other Windows users can read it).
WATCHED = ("pin_hash", "extra_pins", "protected_macs", "mute_new_device_macs", "default_profile_id", "router_host",
           "router_user", "router_cert_pins")
LABELS = {"alert_admin_login_failures": "Alert on failed router sign-ins", "alert_new_devices": "Alert on new devices",
          "block_pin_attackers": "Block devices attacking the PIN", "hold_new_devices": "Hold new devices",
          "check_updates": "Check for updates", "pin_hash": "the PIN", "extra_pins": "the spare PINs",
          "protected_macs": "never-blocked devices", "mute_new_device_macs": "muted devices",
          "default_profile_id": "the default profile", "router_host": "the router address",
          "router_user": "the router user name", "router_cert_pins": "the trusted router certificate"}


def fingerprint(settings: dict) -> dict:
    fp = {k: settings.get(k) for k in GUARDED}
    for k in WATCHED:
        fp[k] = hashlib.sha256(json.dumps(settings.get(k), sort_keys=True).encode()).hexdigest()[:16]
    return fp


def boot_time() -> float:
    return time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000


class WinLog:
    """The Application event log, through advapi32 (write) and wevtutil (read)."""

    def __init__(self):
        self._handle = None

    def write(self, event_id: int, text: str, warn: bool = False) -> bool:
        adv = ctypes.windll.advapi32
        if not self._handle:
            adv.RegisterEventSourceW.restype = ctypes.c_void_p
            self._handle = adv.RegisterEventSourceW(None, SOURCE)
            if not self._handle:
                return False
        adv.ReportEventW.argtypes = [ctypes.c_void_p, ctypes.c_ushort, ctypes.c_ushort, ctypes.c_ulong, ctypes.c_void_p,
                                     ctypes.c_ushort, ctypes.c_ulong, ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_void_p]
        strings = (ctypes.c_wchar_p * 1)(text[:30000])
        return bool(adv.ReportEventW(self._handle, 0x2 if warn else 0x4, 0, event_id, None, 1, 0, strings, None))

    def read(self, event_ids: tuple[int, ...], count: int = 1) -> list[tuple[int, str]]:
        """Newest first: [(event id, text)]."""
        ids = " or ".join(f"EventID={i}" for i in event_ids)
        query = f"*[System[Provider[@Name='{SOURCE}'] and ({ids})]]"
        out = subprocess.run(["wevtutil", "qe", "Application", f"/q:{query}", f"/c:{count}", "/rd:true", "/f:xml"],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
                             creationflags=subprocess.CREATE_NO_WINDOW)
        found = []
        for block in re.findall(r"<Event .*?</Event>", out.stdout, re.S):
            eid = re.search(r"<EventID[^>]*>(\d+)</EventID>", block)
            data = re.search(r"<Data>(.*?)</Data>", block, re.S)
            if eid and data:
                found.append((int(eid.group(1)), html.unescape(data.group(1))))
        return found


class Tamper:
    def __init__(self, monitor, winlog=None):
        self.monitor = monitor
        self.store = monitor.store
        self.log = winlog or WinLog()
        self._lock = threading.Lock()
        self._expected = None  # the protective settings as the app itself last saved them
        self._last = None  # the last checkpoint written
        self._last_written = 0.0
        self._log_checked = time.time()
        self.store.on_event = self._mirror
        config.on_save = self._saved

    # ---- recording ----
    def _mirror(self, row: dict) -> None:
        text = f"{row['title']}\n{row['detail']}".strip() + "\n\n" + json.dumps(row)
        self.log.write(MIRROR, text, warn=row["severity"] in ("warn", "error"))

    def _saved(self, settings: dict) -> None:
        with self._lock:
            self._expected = fingerprint(settings)
        self.checkpoint(force=True)

    def counts(self, since: float, until: float) -> dict:
        ev = self.store.one("SELECT COUNT(*) n, MAX(id) top FROM events WHERE ts >= ?", (since,))
        rl = self.store.one("SELECT COUNT(*) n FROM router_log WHERE ts >= ? AND ts <= ?", (since, until))
        return {"events": ev["n"], "top": ev["top"] or 0, "router_log": rl["n"]}

    def checkpoint(self, force: bool = False) -> dict:
        now = time.time()
        cp = {"t": now, **self.counts(now - WINDOW, now), "settings": fingerprint(config.load()), "pid": os.getpid()}
        # Alerts and settings change rarely and matter most after a stop; router-log lines arrive all day.
        moved = not self._last or any(cp[k] != self._last[k] for k in ("events", "top", "settings"))
        if force or moved or now - self._last_written >= CHECKPOINT_EVERY:
            self.log.write(CHECKPOINT, "Orbi Control checkpoint\n\n" + json.dumps(cp))
            self._last_written = now
        self._last = cp
        return cp

    def stopped(self, why: str) -> None:
        """A deliberate shut-down (Quit, or restarting into an update)."""
        self.checkpoint(force=True)
        self.log.write(STOPPED, f"Orbi Control stopped: {why}\n\n" + json.dumps({"t": time.time(), "why": why}))

    # ---- checking ----
    def startup(self) -> None:
        """Compare against what the Event Log says the app left behind last time it ran."""
        recent = self.log.read((CHECKPOINT, STOPPED), count=1)
        latest = self.log.read((CHECKPOINT,), count=1)
        self._expected = fingerprint(config.load())
        if not latest:
            self.checkpoint(force=True)  # first run with this protection
            return
        cp = json.loads(latest[0][1].rsplit("\n", 1)[-1])
        off_since = cp["t"]
        if recent and recent[0][0] == CHECKPOINT and boot_time() < off_since:
            self.alert("Orbi Control was shut down without Quit",
                       f"It stopped at about {time.strftime('%I:%M %p on %a %b %d', time.localtime(off_since))} and was off "
                       f"for {fmt_gap(time.time() - off_since)}. Windows didn't restart, so something ended it from "
                       "Task Manager, PowerShell or the scheduler. If that wasn't you, look at what changed meanwhile.")
        self._compare(cp, stopped=True)
        self.checkpoint(force=True)

    def check(self) -> None:
        """Runs every minute while the app is up."""
        missing = store_mod.LOCK_NAMES - {r["name"] for r in self.store.q("SELECT name FROM sqlite_master WHERE type='trigger'")}
        if missing:
            with self.store._write_lock:
                self.store.db.executescript(store_mod.LOCKS)
            self.alert("History lock was removed", "Something outside Orbi Control removed the lock that stops its "
                       "history being deleted. It has been put back.")
        if self._last:
            if time.time() - self._log_checked >= CHECKPOINT_EVERY:
                self._log_checked = time.time()
                newest = self.log.read((CHECKPOINT,), count=1)
                if not newest or json.loads(newest[0][1].rsplit("\n", 1)[-1])["t"] < self._last_written - 1:
                    self.alert("Windows Event Log was cleared", "Orbi Control's copies of its alerts in the Windows "
                               "Application log are gone. Clearing that log needs an administrator.")
            self._compare(self._last, stopped=False)
        self.checkpoint()

    def _compare(self, cp: dict, stopped: bool) -> None:
        when = "while Orbi Control was stopped" if stopped else "from outside Orbi Control"
        if time.time() - cp["t"] < 9 * 86400:  # older checkpoints overlap what pruning removes
            now = self.counts(cp["t"] - WINDOW, cp["t"])
            # By time as well as id: SQLite hands a deleted newest row's id to the next alert.
            ev = self.store.one("SELECT COUNT(*) n FROM events WHERE ts >= ? AND ts <= ? AND id <= ?",
                                (cp["t"] - WINDOW, cp["t"], cp["top"]))["n"]
            if ev < cp["events"]:
                lost = cp["events"] - ev
                back = self.restore(cp)
                self.alert("Alert history was deleted", f"{lost} alerts were deleted {when}. "
                           + (f"{back} were put back from the Windows Event Log." if back else
                              "Copies weren't found in the Windows Event Log."))
            if now["router_log"] < cp["router_log"]:
                self.alert("Router log history was deleted",
                           f"{cp['router_log'] - now['router_log']} router log lines were deleted {when}. "
                           "Lines the router still has will come back at the next log read.")
        with self._lock:
            expected = self._expected if not stopped else None
        expected = expected or cp["settings"]
        current = config.load()
        have = fingerprint(current)
        changed = [k for k in expected if k in have and have[k] != expected[k]]
        if not changed:
            return
        undo = {k: expected[k] for k in changed if k in GUARDED and expected[k] is True}
        if undo:
            config.save(undo)  # through the app, so this becomes the expected state
        names = ", ".join(LABELS.get(k, k) for k in changed)
        self.alert("Settings changed " + ("while Orbi Control was stopped" if stopped else "outside Orbi Control"),
                   f"Changed: {names}." + (f" Switched back on: {', '.join(LABELS[k] for k in undo)}." if undo else ""))
        with self._lock:
            self._expected = fingerprint(config.load())

    def restore(self, cp: dict) -> int:
        """Put back alerts that are gone from the app but still in the Event Log copy."""
        since = cp["t"] - WINDOW
        have = {(r["id"], round(r["ts"], 3)) for r in self.store.q("SELECT id, ts FROM events WHERE ts >= ?", (since,))}
        taken = {i for i, _ in have}
        back = 0
        for _, text in self.log.read((MIRROR,), count=RESTORE_LIMIT):
            try:
                e = json.loads(text.rsplit("\n", 1)[-1])
            except ValueError:
                continue
            if e["ts"] < since or e["id"] > cp["top"] or (e["id"], round(e["ts"], 3)) in have:
                continue
            detail = f"{e['detail']} · restored from the Windows Event Log".lstrip(" ·")
            row = (e["ts"], e["end_ts"], e["kind"], e["severity"], e["title"], detail, e["mac"])
            if e["id"] in taken:
                self.store.x("INSERT INTO events(ts,end_ts,kind,severity,title,detail,mac,seen) VALUES(?,?,?,?,?,?,?,1)", row)
            else:
                self.store.x("INSERT INTO events(id,ts,end_ts,kind,severity,title,detail,mac,seen) VALUES(?,?,?,?,?,?,?,?,1)",
                             (e["id"], *row))
                taken.add(e["id"])
            have.add((e["id"], round(e["ts"], 3)))
            back += 1
        return back

    def alert(self, title: str, detail: str) -> None:
        log.warning("%s: %s", title, detail)
        self.store.event("tamper", title, detail=detail, severity="error")
        self.log.write(TAMPER, f"{title}\n{detail}", warn=True)
        self.monitor.notify(title, detail)

    def loop(self) -> None:
        self.startup()
        self.monitor._every(lambda: 60, self.check)


def fmt_gap(seconds: float) -> str:
    from .monitor import fmt_duration
    return fmt_duration(seconds)
