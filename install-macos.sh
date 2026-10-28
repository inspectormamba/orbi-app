#!/bin/bash
# Installs Orbi Control for the current macOS user: a Python environment and a launchd
# LaunchAgent that starts it at login and restarts it within seconds if it ever stops
# (KeepAlive). No sudo needed. Phone access additionally needs allow-phone-access-macos.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv"
LABEL="com.orbicontrol.agent"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DATADIR="$HOME/Library/Application Support/OrbiControl"

command -v python3 >/dev/null || { echo "python3 is required (install from python.org or 'brew install python')."; exit 1; }
if [ ! -x "/Applications/Firefox.app/Contents/MacOS/firefox" ] && [ ! -x "$HOME/Applications/Firefox.app/Contents/MacOS/firefox" ]; then
  echo "Note: Firefox isn't installed. Status/devices/family work without it, but the router's"
  echo "      admin-page settings (DNS, Block Sites, schedules, VPN, firewall) need it. Install Firefox."
fi

if [ ! -x "$VENV/bin/python" ]; then
  echo "Creating Python environment..."
  python3 -m venv "$VENV"
fi
# requirements.txt pins every package with its hash, so pip installs exactly those files or nothing.
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -r "$ROOT/requirements.txt"

mkdir -p "$DATADIR/logs" "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$VENV/bin/python</string>
    <string>-m</string><string>orbi</string><string>--background</string>
  </array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Interactive</string>
  <key>StandardOutPath</key><string>$DATADIR/logs/launchd.out.log</string>
  <key>StandardErrorPath</key><string>$DATADIR/logs/launchd.err.log</string>
</dict>
</plist>
PLISTEOF

# (Re)load and start it under the user's GUI session.
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
launchctl kickstart -k "gui/$(id -u)/$LABEL"

echo "Orbi Control is installed and running. Open http://localhost:8470"
echo "For phone access, run allow-phone-access-macos.sh."
