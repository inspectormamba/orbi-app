"""Move Orbi Control to another computer (e.g. Windows PC -> Mac mini), keeping its history and settings.

Secrets can't simply be copied: on Windows they're DPAPI-encrypted for this Windows user on this PC, and on a Mac
they live in the login Keychain. So `export` decrypts them here and writes one move file, encrypted with a
passphrase you choose; `import` on the new machine decrypts it and stores the secrets the new OS's way.

    python -m orbi.migrate export orbi-move.zip      (on the old machine; the app may keep running)
    python -m orbi.migrate import orbi-move.zip      (on the new machine, BEFORE the app first starts there)

What moves: the database (devices, profiles, schedules, history, alerts), every setting, the router password, the
phone-alert topic, the outside check-in address, DNS account logins, the trusted router certificate, the app PIN and
spare PINs, the router setting backups. What doesn't: the anti-tamper copy kept in the old OS's own log (the new
machine starts its own), geckodriver (each OS downloads its own) and the release-signing key (copy it yourself only
if you'll publish releases from the new machine).

The move file is encrypted with a key derived from the passphrase by scrypt; the cipher is HMAC-SHA256 in counter
mode with an HMAC-SHA256 tag over everything (encrypt-then-MAC), standard library only. Delete the file once the
move is done; it holds the router password.
"""
import argparse
import getpass
import hashlib
import hmac
import json
import os
import secrets as pysecrets
import shutil
import sqlite3
import sys
import tempfile
import time
import zipfile
from contextlib import closing
from pathlib import Path

from . import config, osdep

FORMAT = "orbi-move-v1"
SECRET_KEYS = ("router_password_enc", "push_topic_enc", "heartbeat_url_enc", "nextdns_link_enc", "opendns_password_enc")
PLAIN_SENSITIVE = ("session_secret",)  # not encrypted at rest, but whoever has it can forge sign-ins: kept in the sealed part
EXTRA_FILES = ("kev_ids.json",)
EXTRA_DIRS = ("router-backups",)
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}


class MoveError(Exception):
    pass


# ---- sealing (passphrase encryption) ----
def _keys(passphrase: str, salt: bytes, params: dict) -> tuple[bytes, bytes]:
    k = hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=params["n"], r=params["r"], p=params["p"],
                       maxmem=128 * 1024 * 1024, dklen=64)
    return k[:32], k[32:]


def _stream(key: bytes, data: bytes) -> bytes:
    out = bytearray(len(data))
    for i in range(0, len(data), 32):
        block = hmac.new(key, (i // 32).to_bytes(8, "big"), hashlib.sha256).digest()
        chunk = data[i:i + 32]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, block))
    return bytes(out)


def seal(plaintext: bytes, passphrase: str) -> bytes:
    salt = pysecrets.token_bytes(16)
    enc, mac = _keys(passphrase, salt, SCRYPT)
    ct = _stream(enc, plaintext)
    header = json.dumps({"format": FORMAT, "salt": salt.hex(), "scrypt": SCRYPT}).encode()
    tag = hmac.new(mac, header + b"\n" + ct, hashlib.sha256).digest()
    return header + b"\n" + tag + ct


def unseal(blob: bytes, passphrase: str) -> bytes:
    try:
        header, rest = blob.split(b"\n", 1)
        meta = json.loads(header)
        assert meta["format"] == FORMAT
        salt = bytes.fromhex(meta["salt"])
    except Exception:
        raise MoveError("This isn't an Orbi Control move file (or it's damaged).")
    tag, ct = rest[:32], rest[32:]
    enc, mac = _keys(passphrase, salt, meta["scrypt"])
    if not hmac.compare_digest(tag, hmac.new(mac, header + b"\n" + ct, hashlib.sha256).digest()):
        raise MoveError("Wrong passphrase, or the move file was changed.")
    return _stream(enc, ct)


# ---- export ----
def _snapshot_db(src: Path, dst: Path) -> None:
    """A consistent copy of the live database (the app can keep running; WAL contents are included)."""
    with closing(sqlite3.connect(f"file:{src}?mode=ro", uri=True)) as a, closing(sqlite3.connect(dst)) as b:
        a.backup(b)


def export(out: Path, passphrase: str, data_dir: Path | None = None) -> dict:
    data_dir = Path(data_dir or config.DATA_DIR)
    raw = json.loads((data_dir / "settings.json").read_text("utf-8"))
    secrets_plain, missing = {}, []
    for k in SECRET_KEYS:
        if raw.get(k):
            try:
                secrets_plain[k] = osdep.unprotect(raw[k])
            except Exception:
                missing.append(k)
            raw[k] = ""
    sensitive = {k: raw.pop(k) for k in PLAIN_SENSITIVE if k in raw}

    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "orbi.db"
        _snapshot_db(data_dir / "orbi.db", db)
        guesses = {}
        with closing(sqlite3.connect(db)) as c, c:  # what was typed at the PIN page is sealed per-OS too
            if c.execute("SELECT 1 FROM sqlite_master WHERE name='pin_attempts'").fetchone():
                for rowid, token in c.execute("SELECT rowid, guess FROM pin_attempts WHERE guess IS NOT NULL"):
                    try:
                        guesses[str(rowid)] = osdep.unprotect(token)
                    except Exception:
                        pass
                c.execute("UPDATE pin_attempts SET guess=NULL")
        sealed = seal(json.dumps({"settings": raw, "secrets": secrets_plain, "sensitive": sensitive,
                                  "pin_guesses": guesses}).encode(), passphrase)
        manifest = {"format": FORMAT, "made": time.time(), "from": sys.platform,
                    "version": (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip(),
                    "secrets": sorted(secrets_plain), "unreadable_secrets": missing}
        out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
            z.writestr("sealed.bin", sealed)
            z.write(db, "orbi.db")
            for f in EXTRA_FILES:
                if (data_dir / f).is_file():
                    z.write(data_dir / f, f)
            for d in EXTRA_DIRS:
                for p in sorted((data_dir / d).rglob("*")) if (data_dir / d).is_dir() else []:
                    if p.is_file():
                        z.write(p, p.relative_to(data_dir).as_posix())
    return manifest


# ---- import ----
def _safe_name(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return bool(name) and not name.startswith(("/", "\\")) and ".." not in parts and ":" not in name


def import_(src: Path, passphrase: str, data_dir: Path | None = None, force: bool = False) -> dict:
    data_dir = Path(data_dir or config.DATA_DIR)
    with zipfile.ZipFile(src) as z:
        manifest = json.loads(z.read("manifest.json"))
        if manifest.get("format") != FORMAT:
            raise MoveError("This isn't an Orbi Control move file.")
        payload = json.loads(unseal(z.read("sealed.bin"), passphrase))  # before touching anything on disk

        data_dir.mkdir(parents=True, exist_ok=True)
        if not osdep.single_instance(data_dir):
            raise MoveError("Orbi Control is running on this machine. Stop it first (uninstall/stop the service), then import.")
        if (data_dir / "orbi.db").exists():
            if not force:
                raise MoveError(f"{data_dir} already has Orbi Control data. Re-run with --force to replace it "
                                "(the current data is kept in a backup folder next to it).")
            bak = data_dir.with_name(f"{data_dir.name}-before-import-{time.strftime('%Y%m%d-%H%M%S')}")
            shutil.copytree(data_dir, bak, ignore=shutil.ignore_patterns("orbi.lock"))
            for f in ("orbi.db", "orbi.db-wal", "orbi.db-shm"):
                (data_dir / f).unlink(missing_ok=True)

        for name in z.namelist():
            if name in ("manifest.json", "sealed.bin") or name.endswith("/"):
                continue
            if not _safe_name(name):
                raise MoveError(f"Refusing an unsafe path in the move file: {name!r}")
            dest = data_dir / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            with z.open(name) as r, open(dest, "wb") as w:
                shutil.copyfileobj(r, w)

    settings = payload["settings"]
    settings.update(payload.get("sensitive") or {})
    for k, v in (payload.get("secrets") or {}).items():
        settings[k] = osdep.protect(v)
    guesses = payload.get("pin_guesses") or {}
    if guesses:
        with closing(sqlite3.connect(data_dir / "orbi.db")) as c, c:
            for rowid, guess in guesses.items():
                try:
                    c.execute("UPDATE pin_attempts SET guess=? WHERE rowid=?", (osdep.protect(guess), int(rowid)))
                except Exception:
                    pass
    tmp = data_dir / "settings.json.tmp"
    tmp.write_text(json.dumps(settings, indent=2), "utf-8")
    os.replace(tmp, data_dir / "settings.json")
    return manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m orbi.migrate", description="Move Orbi Control to another computer.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export", help="write a passphrase-encrypted move file (on the old machine)")
    e.add_argument("file", type=Path)
    i = sub.add_parser("import", help="load a move file (on the new machine, before the app first starts)")
    i.add_argument("file", type=Path)
    i.add_argument("--force", action="store_true", help="replace data already on this machine (it's backed up first)")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "export":
            pw = getpass.getpass("Choose a passphrase for the move file: ")
            if len(pw) < 8:
                raise MoveError("Use at least 8 characters.")
            if getpass.getpass("Type it again: ") != pw:
                raise MoveError("The passphrases didn't match.")
            m = export(a.file, pw)
            print(f"Wrote {a.file} ({a.file.stat().st_size / 1e6:.1f} MB) from Orbi Control {m['version']}.")
            print(f"Secrets included: {', '.join(m['secrets']) or 'none'}")
            if m["unreadable_secrets"]:
                print(f"Couldn't read (re-enter these on the new machine): {', '.join(m['unreadable_secrets'])}")
            print("Copy it to the new machine, import it there, then delete it: it holds the router password.")
        else:
            m = import_(a.file, getpass.getpass("Passphrase: "), force=a.force)
            print(f"Imported Orbi Control data from {m['from']} (version {m['version']}) into {config.DATA_DIR}.")
            print("Start Orbi Control now (install-macos.sh does it), sign in with your usual PIN, and delete the move file.")
    except (MoveError, OSError) as ex:
        print(f"Error: {ex}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
