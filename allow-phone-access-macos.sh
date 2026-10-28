#!/bin/bash
# Lets phones on your home network reach Orbi Control.
#
# Unlike Windows, macOS doesn't auto-block inbound LAN connections unless the built-in
# Application Firewall is turned on (System Settings > Network > Firewall). If it's off,
# phones can already open http://<this-mac-ip>:8470 with no change and you don't need this.
#
# If the firewall IS on, this adds the venv's Python to its allow list and unblocks it, so the
# firewall stops prompting / blocking port 8470. Needs sudo. Set your app PIN first.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
PY="$ROOT/.venv/bin/python"
FW="/usr/libexec/ApplicationFirewall/socketfilterfw"

[ -x "$PY" ] || { echo "Run install-macos.sh first."; exit 1; }
# Resolve the real interpreter the LaunchAgent runs (follow the venv symlink to the base python).
REAL_PY="$(readlink -f "$PY" 2>/dev/null || "$PY" -c 'import sys;print(sys.executable)')"

STATE="$("$FW" --getglobalstate 2>/dev/null || true)"
echo "$STATE"
if echo "$STATE" | grep -qi "disabled"; then
  echo "The Application Firewall is off, so phones can already reach Orbi Control on your Wi-Fi."
  IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
  [ -n "$IP" ] && echo "Try http://$IP:8470 on your phone (same Wi-Fi)."
  exit 0
fi

echo "Adding Python to the firewall allow list (needs sudo)..."
sudo "$FW" --add "$REAL_PY"
sudo "$FW" --unblockapp "$REAL_PY"
echo "Done. Phones on your Wi-Fi (and through the Orbi VPN) can now open Orbi Control."
IP="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
[ -n "$IP" ] && echo "Address: http://$IP:8470"
