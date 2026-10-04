"""In-app updates from the project's GitHub tags.

A release is a tag like v1.2.0 whose VERSION file says 1.2.0. Updating downloads that tag from
the fixed repository below over HTTPS, backs up the current code, swaps the new code in (keeping
.venv and all data), reinstalls dependencies only if requirements.txt changed, and restarts. A
helper started from the *old* code watches the restart and puts the backup back if the new
version doesn't come up. Git checkouts are never touched: update those with `git pull`.
"""
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

log = logging.getLogger("orbi.updater")

REPO = "inspectormamba/orbi-app"  # fixed on purpose: updates can only ever come from here
ROOT = Path(__file__).resolve().parent.parent
MANAGED_DIRS = ("orbi", "web", "scripts", "tests")  # replaced wholesale on update
SKIP = {".venv", ".git", ".pytest_cache", "__pycache__", ".gitignore"}
MAX_ZIP = 50_000_000
TASK = "Orbi Control"
TRAILER = re.compile(r"^[A-Za-z-]+: \S")  # Co-Authored-By: ..., Signed-off-by: ...


class UpdateError(Exception):
    pass


def current_version() -> str:
    try:
        return (ROOT / "VERSION").read_text("utf-8").strip()
    except OSError:
        return "0.0.0"


def parse(v: str):
    """'v1.2.3' or '1.2.3' -> (1, 2, 3); anything else -> None."""
    parts = (v or "").strip().lstrip("v").split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def is_git_checkout() -> bool:
    return (ROOT / ".git").exists()


def _get(url: str, limit: int = 2_000_000) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "OrbiControl-updater", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise UpdateError("Download is larger than expected")
    return data


def _get_json(url: str):
    return json.loads(_get(url))


def latest() -> dict | None:
    """The newest vX.Y.Z tag on GitHub, with its commit message as release notes."""
    tags = [t for t in _get_json(f"https://api.github.com/repos/{REPO}/tags?per_page=100") if parse(t.get("name", ""))]
    if not tags:
        return None
    best = max(tags, key=lambda t: parse(t["name"]))
    return {**_info(best["name"]), "notes": release_notes(best)}


def release_notes(tag: dict) -> str:
    """The annotated tag's message (written for users); else the commit message minus git trailers."""
    try:
        ref = _get_json(f"https://api.github.com/repos/{REPO}/git/ref/tags/{tag['name']}")["object"]
        if ref.get("type") == "tag":
            return _get_json(f"https://api.github.com/repos/{REPO}/git/tags/{ref['sha']}")["message"].strip()[:4000]
        msg = _get_json(f"https://api.github.com/repos/{REPO}/commits/{tag['commit']['sha']}")["commit"]["message"]
        return "\n".join(l for l in msg.splitlines() if not TRAILER.match(l)).strip()[:4000]
    except Exception:  # notes are nice to have
        return ""


def _info(tag_name: str) -> dict:
    v = parse(tag_name)
    return {"version": ".".join(map(str, v)), "tag": tag_name, "zip": f"https://github.com/{REPO}/archive/refs/tags/{tag_name}.zip"}


def check() -> dict:
    cur = current_version()
    out = {"current": cur, "latest": None, "available": False, "notes": "", "git_checkout": is_git_checkout(),
           "checked": time.time(), "error": None}
    try:
        info = latest()
    except Exception as e:
        out["error"] = f"Couldn't reach GitHub: {e}"
        return out
    if info:
        out.update(latest=info["version"], notes=info["notes"], tag=info["tag"], zip=info["zip"],
                   available=parse(info["version"]) > (parse(cur) or (0, 0, 0)))
    return out


def extract(data: bytes, dest: Path, expect_version: str) -> Path:
    """Unpacks a GitHub source zip safely and returns its top folder."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest.resolve()) + os.sep) and target != dest.resolve():
                raise UpdateError(f"Unsafe path in update: {name}")
        z.extractall(dest)
    tops = [p for p in dest.iterdir() if p.is_dir()]
    if len(tops) != 1:
        raise UpdateError("Unexpected update layout")
    top = tops[0]
    if not (top / "orbi" / "__main__.py").is_file():
        raise UpdateError("Update is missing the app")
    found = (top / "VERSION").read_text("utf-8").strip() if (top / "VERSION").is_file() else ""
    if found != expect_version:
        raise UpdateError(f"Update says it's version {found or '?'}, expected {expect_version}")
    return top


def _top_files(folder: Path):
    return [p for p in folder.iterdir() if p.is_file() and p.name not in SKIP]


def _copy_tree_into(src: Path, dst: Path):
    """Makes dst's managed folders and top-level files match src (other files in dst are left alone)."""
    for d in MANAGED_DIRS:
        if (dst / d).exists():
            shutil.rmtree(dst / d)
        if (src / d).is_dir():
            shutil.copytree(src / d, dst / d, ignore=shutil.ignore_patterns("__pycache__"))
    for f in _top_files(src):
        shutil.copy2(f, dst / f.name)


def backup(dest: Path):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    _copy_tree_into(ROOT, dest)


def _pip_install(root: Path):
    py = root / ".venv" / "Scripts" / "python.exe"
    r = subprocess.run([str(py), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "-r", str(root / "requirements.txt")],
                       capture_output=True, text=True, timeout=900, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode:
        raise UpdateError(f"Installing dependencies failed: {(r.stderr or r.stdout).strip()[-400:]}")


def apply(info: dict, data_dir: Path, port: int, launch_helper=None) -> dict:
    """Installs the given release (from check()). Returns once the files are swapped and the
    restart helper is running; the caller should then exit the app."""
    if is_git_checkout():
        raise UpdateError("This copy is a git checkout. Update it with git pull instead.")
    version = info.get("version") or info["latest"]  # accepts latest() or check() output
    if not parse(version):
        raise UpdateError(f"Bad version {version!r}")
    info = {**info, "version": version, "zip": _info(f"v{version}")["zip"]}  # the URL is always rebuilt from REPO
    work = data_dir / "update"
    log.info("updating %s -> %s", current_version(), version)
    new_root = extract(_get(info["zip"], MAX_ZIP), work / "new", version)
    bak = work / "backup"
    backup(bak)
    req = lambda root: (root / "requirements.txt").read_text("utf-8").split()  # ignores CRLF vs LF and blank lines
    req_changed = req(new_root) != req(ROOT)
    try:
        _copy_tree_into(new_root, ROOT)
        if req_changed:
            _pip_install(ROOT)
    except Exception:
        log.exception("update failed; restoring the previous version")
        _copy_tree_into(bak, ROOT)
        if req_changed:
            try:
                _pip_install(ROOT)
            except Exception:
                log.exception("restoring dependencies failed")
        raise
    pending = {"from": current_version_of(bak), "to": info["version"], "ts": time.time()}
    (data_dir / "update-pending.json").write_text(json.dumps(pending), "utf-8")
    (launch_helper or _launch_helper)(data_dir, bak, port, req_changed)
    return pending


def current_version_of(folder: Path) -> str:
    try:
        return (folder / "VERSION").read_text("utf-8").strip()
    except OSError:
        return "0.0.0"


HELPER = r'''
param([int]$AppPid, [string]$Root, [string]$Backup, [int]$Port, [string]$DataDir, [string]$Version, [int]$ReqChanged)
$ErrorActionPreference = "Continue"
$result = Join-Path $DataDir "update-result.json"
Remove-Item $result -ErrorAction SilentlyContinue
function Start-App {
    # Use the scheduled task only if it runs *this* copy; otherwise start it directly.
    $task = Get-ScheduledTask -TaskName "%TASK%" -ErrorAction SilentlyContinue
    if ($task -and ($task.Actions | Where-Object { $_.WorkingDirectory -eq $Root })) { Start-ScheduledTask -TaskName "%TASK%" }
    else { Start-Process -FilePath (Join-Path $Root ".venv\Scripts\pythonw.exe") -ArgumentList "-m orbi --background" -WorkingDirectory $Root }
}
function Stop-App {
    # Only this copy: the process listening on its port, plus the venv launcher that started it.
    foreach ($c in @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId = $($c.OwningProcess)"
        if ($p -and $p.CommandLine -like "*-m orbi*") {
            $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.ParentProcessId)"
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
            if ($parent -and $parent.CommandLine -like "*-m orbi*") { Stop-Process -Id $parent.ProcessId -Force -ErrorAction SilentlyContinue }
        }
    }
}
function Test-App {
    try {
        $r = Invoke-WebRequest "http://127.0.0.1:$Port/api/session" -UseBasicParsing -TimeoutSec 5
        return (($r.Content | ConvertFrom-Json).version -eq $Version)
    } catch { return $false }
}
Wait-Process -Id $AppPid -Timeout 30 -ErrorAction SilentlyContinue
Stop-Process -Id $AppPid -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-App
$deadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $deadline) {
    if (Test-App) { @{ ok = $true; version = $Version } | ConvertTo-Json | Set-Content $result -Encoding utf8; exit 0 }
    Start-Sleep -Seconds 3
}
# The new version didn't come up: put the old one back.
Stop-App
Start-Sleep -Seconds 2
Get-ChildItem $Backup -Directory | ForEach-Object { robocopy $_.FullName (Join-Path $Root $_.Name) /MIR /NFL /NDL /NJH /NJS /NP | Out-Null }
Get-ChildItem $Backup -File | Copy-Item -Destination $Root -Force
if ($ReqChanged -eq 1) {
    & (Join-Path $Root ".venv\Scripts\python.exe") -m pip install --quiet --disable-pip-version-check -r (Join-Path $Root "requirements.txt")
}
@{ ok = $false; version = $Version; rolled_back = $true } | ConvertTo-Json | Set-Content $result -Encoding utf8
Start-App
'''


def _launch_helper(data_dir: Path, bak: Path, port: int, req_changed: bool):
    script = data_dir / "update-helper.ps1"
    script.write_text(HELPER.replace("%TASK%", TASK), "utf-8")
    version = json.loads((data_dir / "update-pending.json").read_text("utf-8"))["to"]
    flags = 0x00000008 | 0x00000200 | getattr(subprocess, "CREATE_NO_WINDOW", 0)  # DETACHED_PROCESS | NEW_PROCESS_GROUP
    subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", str(script),
                      "-AppPid", str(os.getpid()), "-Root", str(ROOT), "-Backup", str(bak), "-Port", str(port),
                      "-DataDir", str(data_dir), "-Version", version, "-ReqChanged", "1" if req_changed else "0"],
                     creationflags=flags, close_fds=True, cwd=str(ROOT))


def record_result(store, data_dir: Path) -> tuple[str, str] | None:
    """Called at startup: logs how the last update went. Returns a (title, message) to notify, if any."""
    pending_f, result_f = data_dir / "update-pending.json", data_dir / "update-result.json"
    if not pending_f.exists():
        try:
            result_f.unlink()  # the helper's "ok" note, written after we'd already logged the update
        except OSError:
            pass
        return None
    try:
        pending = json.loads(pending_f.read_text("utf-8"))
        result = json.loads(result_f.read_text("utf-8-sig")) if result_f.exists() else {}
    except ValueError:
        pending, result = {}, {}
    out = None
    if result.get("rolled_back"):
        store.event("update", f"Update to {pending.get('to')} failed", severity="error",
                    detail=f"The new version didn't start, so {pending.get('from')} was restored.")
        out = ("Update failed", f"Orbi Control {pending.get('to')} didn't start, so the previous version was restored.")
    elif current_version() == pending.get("to"):
        store.event("update", f"Updated to {pending.get('to')}", detail=f"from {pending.get('from')}")
        out = ("Orbi Control updated", f"Now running version {pending.get('to')}.")
    else:
        return None  # still starting up (the helper writes its result after this)
    for f in (pending_f, result_f):
        try:
            f.unlink()
        except OSError:
            pass
    return out
