#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-1.0.0}"
ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
STAGE="$ROOT_DIR/build/deb"
OUTDIR="$ROOT_DIR/dist/installer"

rm -rf "$STAGE" "$OUTDIR"
mkdir -p \
  "$STAGE/DEBIAN" \
  "$STAGE/opt/bke-digital-solutions/licensing-agent/agent" \
  "$STAGE/opt/bke-digital-solutions/licensing-agent/license-center" \
  "$STAGE/var/lib/bke-digital-solutions/licensing-agent/trusted-keys" \
  "$STAGE/lib/systemd/system" \
  "$OUTDIR"

cp -R "$ROOT_DIR/dist/linux/bke-licensing-agent/." "$STAGE/opt/bke-digital-solutions/licensing-agent/agent/"
cp -R "$ROOT_DIR/dist/linux/bke-license-center/." "$STAGE/opt/bke-digital-solutions/licensing-agent/license-center/"
cp "$ROOT_DIR/packaging/linux/bke-licensing-agent.service" "$STAGE/lib/systemd/system/"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: bke-licensing-agent
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: BKE Digital Solutions
Description: Persistent BKE Licensing Agent and License Center
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
getent group bke-licensing-agent >/dev/null || groupadd --system bke-licensing-agent
id bke-licensing-agent >/dev/null 2>&1 || useradd --system --gid bke-licensing-agent --home-dir /var/lib/bke-digital-solutions/licensing-agent --shell /usr/sbin/nologin bke-licensing-agent
chown -R bke-licensing-agent:bke-licensing-agent /var/lib/bke-digital-solutions/licensing-agent
systemctl daemon-reload
systemctl enable --now bke-licensing-agent.service
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
systemctl disable --now bke-licensing-agent.service 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
EOF
chmod 755 "$STAGE/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$STAGE" "$OUTDIR/BKE-Licensing-Agent-${VERSION}-Linux-x64.deb"
