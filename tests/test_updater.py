import io
from .test_api import client  # noqa: F401  (fixture)
import json
import zipfile

import pytest

from orbi import updater
from orbi.store import Store


def make_zip(version="1.2.0", files=None, top="orbi-app-1.2.0"):
    files = files or {}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{top}/VERSION", version + "\n")
        z.writestr(f"{top}/orbi/__main__.py", "# new app\n")
        z.writestr(f"{top}/web/app.js", "// new ui\n")
        z.writestr(f"{top}/requirements.txt", files.pop("requirements.txt", "pynetgear==0.10.10\n"))
        for name, body in files.items():
            z.writestr(f"{top}/{name}", body)
    return buf.getvalue()


@pytest.fixture
def install(tmp_path, monkeypatch):
    """A fake installed copy (not a git checkout) at version 1.1.0."""
    root = tmp_path / "app"
    (root / "orbi").mkdir(parents=True)
    (root / "orbi" / "__main__.py").write_text("# old app\n")
    (root / "orbi" / "files.py").write_text("# removed upstream\n")
    (root / "web").mkdir()
    (root / "web" / "app.js").write_text("// old ui\n")
    (root / ".venv").mkdir()
    (root / ".venv" / "keep.txt").write_text("venv")
    (root / "VERSION").write_text("1.1.0\n")
    (root / "requirements.txt").write_text("pynetgear==0.10.10\n")
    monkeypatch.setattr(updater, "ROOT", root)
    data = tmp_path / "data"
    data.mkdir()
    return root, data


def test_parse_and_latest_picks_highest_tag(monkeypatch):
    assert updater.parse("v1.10.0") == (1, 10, 0) and updater.parse("nightly") is None
    tags = [{"name": "v1.2.0", "commit": {"sha": "a"}}, {"name": "v1.10.0", "commit": {"sha": "b"}}, {"name": "test", "commit": {"sha": "c"}}]
    def fake(url):
        if url.endswith("/tags?per_page=100"):
            return tags
        if "/git/ref/tags/" in url:
            return {"object": {"type": "commit", "sha": "b"}}  # lightweight tag: falls back to the commit message
        return {"commit": {"message": "Notes for b\n\nCo-Authored-By: Someone <x@y>"}}
    monkeypatch.setattr(updater, "_get_json", fake)
    info = updater.latest()
    assert info["version"] == "1.10.0" and info["notes"] == "Notes for b"  # trailer stripped
    assert info["zip"] == "https://github.com/inspectormamba/orbi-app/archive/refs/tags/v1.10.0.zip"


def test_check_reports_available(install, monkeypatch):
    monkeypatch.setattr(updater, "latest", lambda: {"version": "1.2.0", "tag": "v1.2.0", "notes": "x", "zip": "z"})
    st = updater.check()
    assert st["available"] and st["current"] == "1.1.0" and not st["git_checkout"]
    monkeypatch.setattr(updater, "latest", lambda: {"version": "1.1.0", "tag": "v1.1.0", "notes": "", "zip": "z"})
    assert not updater.check()["available"]


def test_annotated_tag_message_is_the_release_notes(monkeypatch):
    def fake(url):
        if "/git/ref/tags/" in url:
            return {"object": {"type": "tag", "sha": "t1"}}
        if "/git/tags/t1" in url:
            return {"message": "Orbi Control 1.2.0\n\n- New thing\n"}
        raise AssertionError(url)
    monkeypatch.setattr(updater, "_get_json", fake)
    assert updater.release_notes({"name": "v1.2.0", "commit": {"sha": "c"}}) == "Orbi Control 1.2.0\n\n- New thing"


def test_apply_accepts_check_output_and_ignores_its_url(install, monkeypatch):
    root, data = install
    urls = []
    monkeypatch.setattr(updater, "_get", lambda url, limit=0: urls.append(url) or make_zip("1.2.0"))
    updater.apply({"current": "1.1.0", "latest": "1.2.0", "available": True, "zip": "https://evil.example/x.zip"}, data, 8470,
                  launch_helper=lambda *a: None)
    assert urls == ["https://github.com/inspectormamba/orbi-app/archive/refs/tags/v1.2.0.zip"]
    assert updater.current_version() == "1.2.0"


def test_extract_rejects_unsafe_or_mismatched(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top/../../evil.txt", "x")
    with pytest.raises(updater.UpdateError):
        updater.extract(buf.getvalue(), tmp_path / "x", "1.2.0")
    with pytest.raises(updater.UpdateError, match="expected 1.3.0"):
        updater.extract(make_zip("1.2.0"), tmp_path / "y", "1.3.0")


def test_apply_swaps_code_keeps_venv_and_backs_up(install, monkeypatch):
    root, data = install
    monkeypatch.setattr(updater, "_get", lambda url, limit=0: make_zip("1.2.0"))
    launched = []
    res = updater.apply({"version": "1.2.0", "zip": "z"}, data, 8470, launch_helper=lambda *a: launched.append(a))
    assert res["from"] == "1.1.0" and res["to"] == "1.2.0"
    assert (root / "orbi" / "__main__.py").read_text() == "# new app\n"
    assert not (root / "orbi" / "files.py").exists()  # files removed upstream are removed
    assert (root / ".venv" / "keep.txt").exists()
    assert updater.current_version() == "1.2.0"
    assert (data / "update" / "backup" / "orbi" / "files.py").exists()
    assert launched and launched[0][3] is False  # requirements unchanged: no pip run
    assert json.loads((data / "update-pending.json").read_text())["to"] == "1.2.0"


def test_apply_restores_if_dependencies_fail(install, monkeypatch):
    root, data = install
    monkeypatch.setattr(updater, "_get", lambda url, limit=0: make_zip("1.2.0", {"requirements.txt": "newdep==1.0\n"}))
    calls = []

    def pip(r):
        calls.append(r)
        if len(calls) == 1:
            raise updater.UpdateError("pip failed")
    monkeypatch.setattr(updater, "_pip_install", pip)
    with pytest.raises(updater.UpdateError):
        updater.apply({"version": "1.2.0", "zip": "z"}, data, 8470, launch_helper=lambda *a: None)
    assert (root / "orbi" / "files.py").exists() and updater.current_version() == "1.1.0"
    assert (root / "requirements.txt").read_text() == "pynetgear==0.10.10\n"
    assert not (data / "update-pending.json").exists()


def test_git_checkout_is_never_updated(install):
    root, data = install
    (root / ".git").mkdir()
    with pytest.raises(updater.UpdateError, match="git pull"):
        updater.apply({"version": "1.2.0", "zip": "z"}, data, 8470, launch_helper=lambda *a: None)


def test_record_result(install, tmp_path):
    root, data = install
    store = Store(tmp_path / "orbi.db")
    (data / "update-pending.json").write_text(json.dumps({"from": "1.0.0", "to": "1.1.0"}))
    assert updater.record_result(store, data)[0] == "Orbi Control updated"
    assert not (data / "update-pending.json").exists()
    (data / "update-pending.json").write_text(json.dumps({"from": "1.1.0", "to": "1.2.0"}))
    (data / "update-result.json").write_text(json.dumps({"ok": False, "rolled_back": True}))
    assert updater.record_result(store, data)[0] == "Update failed"
    titles = [e["title"] for e in store.q("SELECT title FROM events WHERE kind='update' ORDER BY id")]
    assert titles == ["Updated to 1.1.0", "Update to 1.2.0 failed"]


def test_update_api(client):
    client.post("/api/setup", json={"pin": "246810"})
    assert client.get("/api/session").json()["version"] == updater.RUNNING == updater.current_version()
    assert client.post("/api/update/apply", json={}).status_code == 409  # this repo is a git checkout
