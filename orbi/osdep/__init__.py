"""Platform-specific services behind one interface, so the rest of the app is OS-agnostic.

Each back end (windows.py, macos.py) exposes the same names; this module picks the one for
the host and re-exports them. Only the matching back end is imported, so Windows-only calls
(ctypes.windll, wintypes) and macOS-only calls (the `security`/`log` CLIs) never load on the
other OS.

Exposed:
  IS_WINDOWS, IS_MAC            booleans
  SYSTEM_LOG_NAME              user-facing name of the tamper-evidence log
  protect(text) -> token        encrypt a secret for storage in settings.json
  unprotect(token) -> text      decrypt it
  SysLog                        the tamper-evidence log back end (write/read, see tamper.py)
  boot_time() -> float          wall-clock time the machine last booted (epoch seconds)
  single_instance(data_dir)     True if we're the only instance for this data folder
  notify(title, message)        a best-effort OS notification (tray has the richer path)
  firefox_binary() -> str       path to the Firefox executable
  default_data_dir() -> Path    where settings/db/logs live when ORBI_DATA_DIR is unset
  GECKODRIVER                   dict: the pinned geckodriver for this OS (see geckodriver.py)
  SERVICE_CREATION_FLAGS        creationflags for the Selenium driver subprocess
  launch_update_helper(...)     start the detached updater/rollback helper
"""
import sys

if sys.platform == "win32":
    from . import windows as _impl
elif sys.platform == "darwin":
    from . import macos as _impl
else:  # pragma: no cover - the app targets Windows and macOS only
    raise ImportError(f"Orbi Control runs on Windows and macOS, not {sys.platform!r}")

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

SYSTEM_LOG_NAME = _impl.SYSTEM_LOG_NAME
protect = _impl.protect
unprotect = _impl.unprotect
SysLog = _impl.SysLog
boot_time = _impl.boot_time
single_instance = _impl.single_instance
notify = _impl.notify
firefox_binary = _impl.firefox_binary
default_data_dir = _impl.default_data_dir
GECKODRIVER = _impl.GECKODRIVER
SERVICE_CREATION_FLAGS = _impl.SERVICE_CREATION_FLAGS
launch_update_helper = _impl.launch_update_helper
