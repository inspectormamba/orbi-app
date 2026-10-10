"""History locks (store.LOCKS) and tamper detection (orbi/tamper.py)."""
import sqlite3
import time

import pytest

from orbi import config, tamper
from orbi.store import Store


class FakeLog:
    def __init__(self):
        self.entries: list[tuple[int, str]] = []

    def write(self, event_id, text, warn=False):
        self.entries.append((event_id, text))
        return True

    def read(self, event_ids, count=1):
        return [e for e in reversed(self.entries) if e[0] in event_ids][:count]

    def clear(self):
        self.entries.clear()


@pytest.fixture
def winlog():
    return FakeLog()


@pytest.fixture
def watch(monitor, winlog, monkeypatch):
    monkeypatch.setattr(config, "on_save", None)
    monkeypatch.setattr(tamper, "boot_time", lambda: 0.0)  # Windows hasn't restarted
    t = tamper.Tamper(monitor, winlog)
    t.startup()
    return t


def outside(path):
    """A connection from some other program: none of the app's SQL functions."""
    return sqlite3.connect(path, isolation_level=None)


def restart(monitor, winlog):
    """The app starting again on the same data."""
    monitor.store = Store(monitor.store.path)
    t = tamper.Tamper(monitor, winlog)
    t.startup()
    return t


def alerts(monitor):
    return [r["title"] for r in monitor.store.q("SELECT title FROM events WHERE kind='tamper' ORDER BY id")]


def test_other_programs_cannot_delete_history(monitor):
    monitor.store.event("block", "Site blocked")
    monitor.store.x("INSERT INTO router_log(ts,kind,text) VALUES(?,?,?)", (time.time(), "site", "blocked chatgpt.com"))
    db = outside(monitor.store.path)
    for table in ("events", "router_log"):
        with pytest.raises(sqlite3.OperationalError, match="orbi_keep_after"):
            db.execute(f"DELETE FROM {table} WHERE ts >= 0")
    with pytest.raises(sqlite3.IntegrityError, match="keeps its history"):
        monitor.store.x("DELETE FROM events")  # not even the app, for anything newer than the prune cutoff
    assert monitor.store.one("SELECT COUNT(*) n FROM events")["n"] == 1


def test_pruning_still_removes_old_history(monitor):
    monitor.store.event("block", "ancient", ts=time.time() - 100 * 86400)
    monitor.store.event("block", "recent")
    monitor.store.prune(days=7)  # a shorter retention can't reach inside the locked window
    assert [r["title"] for r in monitor.store.q("SELECT title FROM events")] == ["recent"]


def test_alerts_are_copied_to_the_event_log(watch, winlog):
    watch.monitor.store.event("pin", "Someone is guessing the PIN", detail="5 wrong PINs", severity="warn")
    text = [t for i, t in winlog.entries if i == tamper.MIRROR][-1]
    assert text.startswith("Someone is guessing the PIN\n5 wrong PINs")


def test_history_deleted_while_stopped_is_reported_and_put_back(watch, monitor, winlog):
    for n in range(3):
        monitor.store.event("block", f"alert {n}")
    watch.stopped("Quit from the tray")
    db = outside(monitor.store.path)
    db.execute("DROP TRIGGER events_keep")
    db.execute("DELETE FROM events")
    restart(monitor, winlog).stopped("Quit from the tray")
    assert alerts(monitor) == ["Alert history was deleted"]
    assert "3 were put back" in monitor.store.one("SELECT detail FROM events WHERE kind='tamper'")["detail"]
    assert {r["title"] for r in monitor.store.q("SELECT title FROM events WHERE kind='block'")} == {"alert 0", "alert 1", "alert 2"}
    t = restart(monitor, winlog)
    t.check()
    assert alerts(monitor) == ["Alert history was deleted"]  # put back once; nothing new to report


def test_removed_lock_is_put_back_and_deletions_restored(watch, monitor, winlog):
    monitor.store.event("block", "kept")
    watch.check()
    db = outside(monitor.store.path)
    db.execute("DROP TRIGGER events_keep")
    db.execute("DELETE FROM events WHERE title='kept'")
    watch.check()
    assert alerts(monitor) == ["History lock was removed", "Alert history was deleted"]
    assert monitor.store.one("SELECT COUNT(*) n FROM events WHERE title='kept'")["n"] == 1
    with pytest.raises(sqlite3.OperationalError):
        outside(monitor.store.path).execute("DELETE FROM events")


def test_router_log_deletions_are_reported(watch, monitor):
    monitor.store.x("INSERT INTO router_log(ts,kind,text) VALUES(?,?,?)", (time.time() - 60, "site", "blocked"))
    watch.check()
    db = outside(monitor.store.path)
    db.execute("DROP TRIGGER router_log_keep")
    db.execute("DELETE FROM router_log")
    watch.check()
    assert "Router log history was deleted" in alerts(monitor)


def test_alert_switch_turned_off_outside_the_app_is_switched_back(watch, monitor):
    config.save({"alert_new_devices": False})  # the app itself: fine
    watch.check()
    assert alerts(monitor) == []
    hook, config.on_save = config.on_save, None  # another process: no hook
    config.save({"alert_admin_login_failures": False, "alert_new_devices": True})
    config.on_save = hook
    watch.check()
    assert config.load()["alert_admin_login_failures"] is True
    detail = monitor.store.one("SELECT detail FROM events WHERE kind='tamper'")["detail"]
    assert "Alert on failed router sign-ins" in detail and "Switched back on" in detail
    watch.check()
    assert len(alerts(monitor)) == 1


def test_settings_changed_while_stopped(watch, monitor, winlog):
    watch.stopped("Quit from the tray")
    config.on_save = None
    config.save({"alert_admin_login_failures": False, "pin_hash": "pbkdf2$other"})
    restart(monitor, winlog)
    assert alerts(monitor) == ["Settings changed while Orbi Control was stopped"]
    assert config.load()["alert_admin_login_failures"] is True
    assert config.load()["pin_hash"] == "pbkdf2$other"  # reported, not undone: a forgotten-PIN reset looks like this


def test_pin_hash_never_reaches_the_event_log(watch, winlog):
    config.save({"pin_hash": "pbkdf2$secret-salt$secret-hash"})
    assert not any("secret" in text for _, text in winlog.entries)


def test_shutdown_without_quit_is_reported(watch, monitor, winlog):
    restart(monitor, winlog)  # killed: the last thing in the log is a checkpoint
    assert alerts(monitor) == ["Orbi Control was shut down without Quit"]


def test_quit_update_and_windows_restart_are_not_reported(watch, monitor, winlog, monkeypatch):
    watch.stopped("Quit from the tray")
    t = restart(monitor, winlog)
    t.stopped("updating to 1.1.9")
    restart(monitor, winlog)
    monkeypatch.setattr(tamper, "boot_time", lambda: time.time())  # Windows restarted since the last checkpoint
    restart(monitor, winlog)
    assert alerts(monitor) == []


def test_cleared_event_log_is_reported(watch, monitor, winlog, monkeypatch):
    winlog.clear()
    monkeypatch.setattr(watch, "_log_checked", 0)
    watch.check()
    assert alerts(monitor) == ["Windows Event Log was cleared"]
