#!/bin/bash
set -euo pipefail

VERSION="${1:-0.1.0}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PKGROOT="$ROOT_DIR/build/pkgroot"
OUTDIR="$ROOT_DIR/dist/installer"
SCRIPTS="$ROOT_DIR/packaging/macos/pkg-scripts"
LABEL="com.bkedigitalsolutions.licensing-agent"

AGENT_DIST="$ROOT_DIR/dist/bke-licensing-agent"
CENTER_DIST="$ROOT_DIR/dist/bke-license-center"

if [[ ! -x "$AGENT_DIST/bke-licensing-agent" ]]; then
    echo "Missing frozen Agent: $AGENT_DIST/bke-licensing-agent" >&2
    exit 1
fi
if [[ ! -x "$CENTER_DIST/bke-license-center" ]]; then
    echo "Missing frozen License Center: $CENTER_DIST/bke-license-center" >&2
    exit 1
fi

rm -rf "$PKGROOT" "$OUTDIR"
mkdir -p \
    "$PKGROOT/Library/Application Support/BKE Digital Solutions/Licensing Agent" \
    "$PKGROOT/Library/LaunchDaemons" \
    "$PKGROOT/Applications/Utilities/BKE Digital Solutions" \
    "$OUTDIR"

cp -R "$AGENT_DIST" "$PKGROOT/Library/Application Support/BKE Digital Solutions/Licensing Agent/"
cp -R "$CENTER_DIST" "$PKGROOT/Library/Application Support/BKE Digital Solutions/Licensing Agent/"
cp "$ROOT_DIR/packaging/macos/${LABEL}.plist" "$PKGROOT/Library/LaunchDaemons/${LABEL}.plist"
cp "$ROOT_DIR/packaging/macos/uninstall.sh" "$PKGROOT/Applications/Utilities/BKE Digital Solutions/Uninstall BKE Licensing Agent.command"

chmod 644 "$PKGROOT/Library/LaunchDaemons/${LABEL}.plist"
chmod +x "$PKGROOT/Applications/Utilities/BKE Digital Solutions/Uninstall BKE Licensing Agent.command"
chmod +x "$SCRIPTS/preinstall" "$SCRIPTS/postinstall"

pkgbuild \
    --root "$PKGROOT" \
    --scripts "$SCRIPTS" \
    --identifier "$LABEL" \
    --version "$VERSION" \
    --install-location "/" \
    "$OUTDIR/BKE-Licensing-Agent-${VERSION}.pkg"

echo "Built: $OUTDIR/BKE-Licensing-Agent-${VERSION}.pkg"
pkgutil --payload-files "$OUTDIR/BKE-Licensing-Agent-${VERSION}.pkg"
