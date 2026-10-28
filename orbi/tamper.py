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
import hashlib
import json
import logging
import os
import threading
import time

from . import config, osdep, store as store_mod

log = logging.getLogger(__name__)

# The tamper-evidence log's user-facing name differs by OS; Windows wording is kept verbatim.
OS_NAME = "Windows" if osdep.IS_WINDOWS else "macOS"
LOG_NAME = osdep.SYSTEM_LOG_NAME  # "the Windows Event Log" / "the macOS system log"
LOG_TITLE = "Windows Event Log" if osdep.IS_WINDOWS else "System log"
KILL_TOOLS = ("Task Manager, PowerShell or the scheduler" if osdep.IS_WINDOWS
              else "Activity Monitor, the terminal or launchd")

SOURCE = "Orbi Control"
MIRROR, CHECKPOINT, TAMPER, STOPPED = 1, 2, 3, 4  # Event Log event IDs
WINDOW = 80 * 86400  # history checked for deletions: newer than the prune cutoff, with room to spare
CHECKPOINT_EVERY = 10 * 60
RESTORE_LIMIT = 20000  # most recent alert copies read back when restoring
# Switches that only ever make the app quieter or more permissive when turned off: put back if changed outside.
GUARDED = ("alert_admin_login_failures", "alert_new_devices", "block_pin_attackers", "hold_new_devices", "check_updates",
           "push_enabled", "exposure_watch", "vulnscan_watch")
# Changes outside the app are reported. Only fingerprints go in the Event Log (other Windows users can read it).
WATCHED = ("pin_hash", "extra_pins", "protected_macs", "mute_new_device_macs", "default_profile_id", "router_host",
           "router_user", "router_cert_pins", "push_topic_enc", "push_server", "heartbeat_url_enc")
LABELS = {"alert_admin_login_failures": "Alert on failed router sign-ins", "alert_new_devices": "Alert on new devices",
          "block_pin_attackers": "Block devices attacking the PIN", "hold_new_devices": "Hold new devices",
          "check_updates": "Check for updates", "push_enabled": "Phone alerts",
          "exposure_watch": "Remote-access check", "vulnscan_watch": "Device check", "push_topic_enc": "the phone-alert code",
          "push_server": "the phone-alert server", "pin_hash": "the PIN", "extra_pins": "the spare PINs",
          "protected_macs": "never-blocked devices", "mute_new_device_macs": "muted devices",
          "default_profile_id": "the default profile", "router_host": "the router address",
          "router_user": "the router user name", "router_cert_pins": "the trusted router certificate",
          "heartbeat_url_enc": "the outside check-in address"}


def fingerprint(settings: dict) -> dict:
    fp = {k: settings.get(k) for k in GUARDED}
    for k in WATCHED:
        fp[k] = hashlib.sha256(json.dumps(settings.get(k), sort_keys=True).encode()).hexdigest()[:16]
    return fp


def boot_time() -> float:
    return osdep.boot_time()


class Tamper:
    def __init__(self, monitor, winlog=None):
        self.monitor = monitor
        self.store = monitor.store
        self.log = winlog or osdep.SysLog()
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
                       f"for {fmt_gap(time.time() - off_since)}. {OS_NAME} didn't restart, so something ended it from "
                       f"{KILL_TOOLS}. If that wasn't you, look at what changed meanwhile.")
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
                    self.alert(f"{LOG_TITLE} was cleared", f"Orbi Control's copies of its alerts in {LOG_NAME} "
                               "are gone. Clearing it needs an administrator.")
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
                           + (f"{back} were put back from {LOG_NAME}." if back else
                              f"Copies weren't found in {LOG_NAME}."))
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
        """Put back alerts that are gone from the app but still in the system-log copy."""
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
            detail = f"{e['detail']} · restored from {LOG_NAME}".lstrip(" ·")
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
