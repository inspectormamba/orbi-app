"""Moving to another computer: the move file round-trips settings, secrets, history and PIN-page guesses."""
import json
import sqlite3
import zipfile
from contextlib import closing

import pytest

from orbi import migrate


def _fake_crypto(monkeypatch):
    """Each OS seals secrets its own way; stand in with a reversible marker per 'machine'."""
    machine = {"tag": "pc"}
    monkeypatch.setattr(migrate.osdep, "protect", lambda t: f"{machine['tag']}:{t}")

    def unprotect(tok):
        tag, _, val = tok.partition(":")
        if tag != machine["tag"]:
            raise OSError("sealed on another machine")
        return val
    monkeypatch.setattr(migrate.osdep, "unprotect", unprotect)
    monkeypatch.setattr(migrate.osdep, "single_instance", lambda d: True)
    return machine


def _old_machine(d):
    d.mkdir()
    (d / "settings.json").write_text(json.dumps({
        "router_password_enc": "pc:hunter2", "push_topic_enc": "pc:orbi-abc", "heartbeat_url_enc": "",
        "pin_hash": "pbkdf2$x", "session_secret": "s3cret", "router_cert_pins": {"192.168.1.1": "ab"},
        "hold_new_devices": True}))
    with closing(sqlite3.connect(d / "orbi.db")) as c, c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE devices (mac TEXT, alias TEXT)")
        c.execute("INSERT INTO devices VALUES ('AA:BB:CC:DD:EE:FF', 'James laptop')")
        c.execute("CREATE TABLE pin_attempts (ts REAL, guess TEXT)")
        c.execute("INSERT INTO pin_attempts VALUES (1, 'pc:1234'), (2, NULL)")
    (d / "router-backups").mkdir()
    (d / "router-backups" / "a.cfg").write_bytes(b"cfg")
    (d / "kev_ids.json").write_text("[]")


def test_round_trip_to_a_new_machine(tmp_path, monkeypatch):
    machine = _fake_crypto(monkeypatch)
    _old_machine(tmp_path / "pc")
    out = tmp_path / "move.zip"
    m = migrate.export(out, "correct horse", tmp_path / "pc")
    assert m["secrets"] == ["push_topic_enc", "router_password_enc"] and not m["unreadable_secrets"]

    raw = out.read_bytes()
    assert b"hunter2" not in raw and b"s3cret" not in raw and b"orbi-abc" not in raw  # nothing secret in the clear
    with zipfile.ZipFile(out) as z, z.open("orbi.db") as f:
        assert b"1234" not in f.read()

    machine["tag"] = "mac"
    migrate.import_(out, "correct horse", tmp_path / "mac")
    s = json.loads((tmp_path / "mac" / "settings.json").read_text())
    assert s["router_password_enc"] == "mac:hunter2" and s["push_topic_enc"] == "mac:orbi-abc"
    assert s["session_secret"] == "s3cret" and s["pin_hash"] == "pbkdf2$x" and s["hold_new_devices"] is True
    assert s["router_cert_pins"] == {"192.168.1.1": "ab"} and s["heartbeat_url_enc"] == ""
    with closing(sqlite3.connect(tmp_path / "mac" / "orbi.db")) as c:
        assert c.execute("SELECT alias FROM devices").fetchone()[0] == "James laptop"
        assert [r[0] for r in c.execute("SELECT guess FROM pin_attempts ORDER BY ts")] == ["mac:1234", None]
    assert (tmp_path / "mac" / "router-backups" / "a.cfg").read_bytes() == b"cfg"


def test_wrong_passphrase_or_tampering_changes_nothing(tmp_path, monkeypatch):
    _fake_crypto(monkeypatch)
    _old_machine(tmp_path / "pc")
    out = tmp_path / "move.zip"
    migrate.export(out, "correct horse", tmp_path / "pc")
    with pytest.raises(migrate.MoveError, match="Wrong passphrase"):
        migrate.import_(out, "wrong", tmp_path / "mac")
    assert not (tmp_path / "mac").exists()

    blob = bytearray(migrate.seal(b"payload", "pw"))
    blob[-1] ^= 1
    with pytest.raises(migrate.MoveError):
        migrate.unseal(bytes(blob), "pw")
    assert migrate.unseal(migrate.seal(b"x" * 1000, "pw"), "pw") == b"x" * 1000


def test_import_wont_overwrite_existing_data_without_force(tmp_path, monkeypatch):
    _fake_crypto(monkeypatch)
    _old_machine(tmp_path / "pc")
    out = tmp_path / "move.zip"
    migrate.export(out, "pw123456", tmp_path / "pc")
    _old_machine(tmp_path / "mac")
    with pytest.raises(migrate.MoveError, match="--force"):
        migrate.import_(out, "pw123456", tmp_path / "mac")
    migrate.import_(out, "pw123456", tmp_path / "mac", force=True)
    assert list(tmp_path.glob("mac-before-import-*"))


def test_refuses_paths_outside_the_data_folder():
    assert migrate._safe_name("router-backups/a.cfg")
    for bad in ("../x", "/etc/passwd", "C:/x", "a/../../b"):
        assert not migrate._safe_name(bad)
