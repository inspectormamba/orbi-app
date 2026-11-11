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
  arp_table() -> {ip: mac}      learned entries in the ARP table (MACs as AA:BB:CC:DD:EE:FF)
  arp_lookup(host) -> mac|None  the ARP entry for one address
  local_macs() -> [mac]         this machine's own adapter addresses (never blocked)
  adapter_name(ip) -> str       friendly name of the adapter with that address ("" if unknown)
  lan_adapter(ip) -> dict       {"mac", "dhcp_enabled", "dhcp_server", "sent_bytes"} for that adapter
  dhcp_bind(sock, ip)           bind the rogue-DHCP probe socket the way this OS needs
  venv_python(root) -> Path     the virtualenv's python inside an install folder
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
arp_table = _impl.arp_table
arp_lookup = _impl.arp_lookup
local_macs = _impl.local_macs
adapter_name = _impl.adapter_name
lan_adapter = _impl.lan_adapter
dhcp_bind = _impl.dhcp_bind
venv_python = _impl.venv_python
