#!/bin/bash
set -euo pipefail

LABEL="com.bkedigitalsolutions.licensing-agent"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
INSTALL_DIR="/Library/Application Support/BKE Digital Solutions/Licensing Agent"
DATA_DIR="/Library/Application Support/BKE Digital Solutions/Licensing Agent Data"
UTILITY_DIR="/Applications/Utilities/BKE Digital Solutions"
UNINSTALLER="$UTILITY_DIR/Uninstall BKE Licensing Agent.command"
RECEIPT="$LABEL"

printf '\nBKE Licensing Agent Uninstaller\n'
printf '%s\n' '==============================='
printf '%s\n' 'This removes the Agent runtime and License Center.'
printf '%s\n' 'Licensing/device state is preserved for safe reinstall.'
printf '\n'
read -r -p 'Continue? [y/N] ' answer
case "$answer" in
    y|Y|yes|YES) ;;
    *) echo 'Uninstall cancelled.'; exit 0 ;;
esac

sudo launchctl bootout system/$LABEL >/dev/null 2>&1 || true
sudo rm -f "$PLIST"
sudo rm -rf "$INSTALL_DIR"

if pkgutil --pkg-info "$RECEIPT" >/dev/null 2>&1; then
    sudo pkgutil --forget "$RECEIPT" >/dev/null
fi

(
    sleep 2
    sudo rm -f "$UNINSTALLER"
    sudo rmdir "$UTILITY_DIR" 2>/dev/null || true
) >/dev/null 2>&1 &

printf '\nBKE Licensing Agent removed.\n'
printf 'Preserved state: %s\n' "$DATA_DIR"
