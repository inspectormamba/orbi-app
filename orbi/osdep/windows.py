"""Windows back end: DPAPI secrets, the Application event log, logon mutex, update helper.

This is the code that used to live inline in dpapi.py, tamper.py (WinLog), __main__.py and
updater.py; it is unchanged in behaviour, only moved here behind the osdep interface.
"""
import base64
import ctypes
import hashlib
import html
import os
import re
import subprocess
from ctypes import wintypes
from pathlib import Path

SYSTEM_LOG_NAME = "the Windows Event Log"
SERVICE_CREATION_FLAGS = 0x08000000  # CREATE_NO_WINDOW: no console flash under pythonw


# ---- secrets: DPAPI (only this Windows user on this PC can read them) ----
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32
_ENTROPY = b"OrbiControl/v1"


def _blob(data: bytes) -> _Blob:
    buf = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))


def _take(blob: _Blob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        _kernel32.LocalFree(blob.pbData)


def protect(text: str) -> str:
    src, ent, out = _blob(text.encode("utf-8")), _blob(_ENTROPY), _Blob()
    if not _crypt32.CryptProtectData(ctypes.byref(src), "OrbiControl", ctypes.byref(ent), None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return base64.b64encode(_take(out)).decode("ascii")


def unprotect(token: str) -> str:
    src, ent, out = _blob(base64.b64decode(token)), _blob(_ENTROPY), _Blob()
    if not _crypt32.CryptUnprotectData(ctypes.byref(src), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    return _take(out).decode("utf-8")


# ---- tamper-evidence log: the Application event log ----
SOURCE = "Orbi Control"


class SysLog:
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

    def read(self, event_ids, count: int = 1):
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


def boot_time() -> float:
    import time
    return time.time() - ctypes.windll.kernel32.GetTickCount64() / 1000


# ---- single instance: one per data folder (named mutex) ----
def single_instance(data_dir) -> bool:
    tag = hashlib.sha1(str(data_dir).lower().encode()).hexdigest()[:12]
    ctypes.windll.kernel32.CreateMutexW(None, False, f"Local\\OrbiControl-{tag}")
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def notify(title: str, message: str) -> bool:
    """The tray icon's toast is the real path on Windows; this is a no-op fallback."""
    return False


def firefox_binary() -> str:
    for p in (r"C:\Program Files\Mozilla Firefox\firefox.exe",
              r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"):
        if os.path.isfile(p):
            return p
    return r"C:\Program Files\Mozilla Firefox\firefox.exe"


def default_data_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "OrbiControl"


# ---- the pinned geckodriver for this OS ----
GECKODRIVER = {
    "version": "0.37.1",
    "url": "https://github.com/mozilla/geckodriver/releases/download/v0.37.1/geckodriver-v0.37.1-win64.zip",
    "archive": "zip",
    "member": "geckodriver.exe",
    "exe_name": "geckodriver.exe",
    "archive_sha256": "dfed9315abe8d2fbc1b6161a2ee8002452e79cf05ee92fdc653a4e26bc35edd8",
    "binary_sha256": "e95b4eac7960ffcd5acbfd92bb7d49d48f99c1d01a20ddd297fef8c80821020d",
}


# ---- update / rollback helper (runs from the old code, outlives this process) ----
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


def launch_update_helper(root: Path, task: str, data_dir: Path, bak: Path, port: int, req_changed: bool, version: str):
    script = data_dir / "update-helper.ps1"
    script.write_text(HELPER.replace("%TASK%", task), "utf-8")
    # No console window, own process group so it outlives this app. Not DETACHED_PROCESS: PowerShell won't run without a console.
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", str(script),
                      "-AppPid", str(os.getpid()), "-Root", str(root), "-Backup", str(bak), "-Port", str(port),
                      "-DataDir", str(data_dir), "-Version", version, "-ReqChanged", "1" if req_changed else "0"],
                     creationflags=flags, close_fds=True, cwd=str(root))
