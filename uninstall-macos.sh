#!/bin/bash
# Stops Orbi Control and removes its LaunchAgent. Keeps your settings, history and database
# under ~/Library/Application Support/OrbiControl. Pass --purge to also remove those and the
# Keychain secrets (router password, phone-alert code, check-in address).
set -uo pipefail
LABEL="com.orbicontrol.agent"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
DATADIR="$HOME/Library/Application Support/OrbiControl"

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
rm -f "$PLIST"
echo "Stopped and removed auto-start."

if [ "${1:-}" = "--purge" ]; then
  # Remove every OrbiControl Keychain item (there is one per stored secret).
  while security delete-generic-password -s OrbiControl >/dev/null 2>&1; do :; done
  rm -rf "$DATADIR"
  echo "Removed settings, history, database and Keychain secrets."
else
  echo "Settings and history kept at: $DATADIR"
  echo "Run with --purge to remove those and the Keychain secrets too."
fi
