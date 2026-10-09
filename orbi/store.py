"""SQLite storage (WAL mode, one connection per thread)."""
import contextvars
import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (ts REAL NOT NULL, internet INTEGER, router INTEGER, latency_ms REAL);
CREATE INDEX IF NOT EXISTS checks_ts ON checks(ts);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, end_ts REAL, kind TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'info',
  title TEXT NOT NULL, detail TEXT DEFAULT '', mac TEXT DEFAULT '', seen INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS devices (
  mac TEXT PRIMARY KEY, router_name TEXT DEFAULT '', alias TEXT DEFAULT '', model TEXT DEFAULT '',
  profile_id INTEGER, manual_block INTEGER NOT NULL DEFAULT 0, first_seen REAL, last_seen REAL,
  last_ip TEXT DEFAULT '', online INTEGER NOT NULL DEFAULT 0, snapshot TEXT DEFAULT '{}');
CREATE TABLE IF NOT EXISTS speedtests (ts REAL NOT NULL, down REAL, up REAL, ping REAL, trigger TEXT);
CREATE TABLE IF NOT EXISTS traffic (ts REAL NOT NULL, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, emoji TEXT DEFAULT '', paused_until REAL, allow_until REAL, created REAL);
CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY, profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT 'Bedtime', days TEXT NOT NULL DEFAULT '0123456', start TEXT NOT NULL, end TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS applied_blocks (mac TEXT PRIMARY KEY, reason TEXT, since REAL);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS router_log (ts REAL NOT NULL, kind TEXT NOT NULL, source TEXT DEFAULT '', text TEXT NOT NULL, UNIQUE(ts, text));
CREATE INDEX IF NOT EXISTS router_log_ts ON router_log(ts);
CREATE TABLE IF NOT EXISTS pin_attempts (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, ip TEXT, mac TEXT, device TEXT, agent TEXT,
  outcome TEXT NOT NULL, guess TEXT, automated INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS pin_attempts_ts ON pin_attempts(ts);
"""


# Who is making the current change through the web app, e.g. "Kids-iPad (192.168.1.40)".
# Set per request by web.py; every event recorded while handling it says who did it.
ACTOR = contextvars.ContextVar("actor", default="")


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        with self._write_lock:
            self.db.executescript(SCHEMA)
            self._migrate()

    def _migrate(self):
        cols = {r[1] for r in self.db.execute("PRAGMA table_info(devices)")}
        if "held" not in cols:  # added with "hold new devices for approval"
            self.db.execute("ALTER TABLE devices ADD COLUMN held INTEGER NOT NULL DEFAULT 0")

    @property
    def db(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def q(self, sql, args=()):
        return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def one(self, sql, args=()):
        r = self.db.execute(sql, args).fetchone()
        return dict(r) if r else None

    def x(self, sql, args=()):
        with self._write_lock:
            cur = self.db.execute(sql, args)
            return cur.lastrowid

    # ---- key/value ----
    def get(self, key, default=None):
        r = self.one("SELECT value FROM kv WHERE key=?", (key,))
        return json.loads(r["value"]) if r else default

    def put(self, key, value):
        self.x("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))

    # ---- events ----
    def event(self, kind, title, detail="", severity="info", mac="", ts=None, end_ts=None):
        if actor := ACTOR.get():
            detail = f"{detail} · by {actor}" if detail else f"by {actor}"
        return self.x("INSERT INTO events(ts,end_ts,kind,severity,title,detail,mac) VALUES(?,?,?,?,?,?,?)",
                      (ts or time.time(), end_ts, kind, severity, title, detail, mac))

    def close_event(self, event_id, end_ts=None, detail=None):
        if detail is None:
            self.x("UPDATE events SET end_ts=? WHERE id=?", (end_ts or time.time(), event_id))
        else:
            self.x("UPDATE events SET end_ts=?, detail=? WHERE id=?", (end_ts or time.time(), detail, event_id))

    def prune(self, days=90):
        cutoff = time.time() - days * 86400
        self.x("DELETE FROM checks WHERE ts < ?", (time.time() - 31 * 86400,))
        self.x("DELETE FROM events WHERE ts < ?", (cutoff,))
        self.x("DELETE FROM traffic WHERE ts < ?", (cutoff,))
        self.x("DELETE FROM router_log WHERE ts < ?", (cutoff,))
