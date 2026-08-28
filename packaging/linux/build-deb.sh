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

cat > "$STAGE/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -eu

# Mirror the restart-safe macOS package lifecycle: stop the existing authority
# before dpkg replaces its frozen payload, then let postinst restart it only
# after the new payload and service definition are fully installed.
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files bke-licensing-agent.service >/dev/null 2>&1; then
  systemctl stop bke-licensing-agent.service 2>/dev/null || true
  i=0
  while systemctl is-active --quiet bke-licensing-agent.service 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 30 ]; then
      echo "BKE Licensing Agent did not stop before payload replacement." >&2
      exit 1
    fi
    sleep 1
  done
fi
EOF
chmod 755 "$STAGE/DEBIAN/preinst"

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
getent group bke-licensing-agent >/dev/null || groupadd --system bke-licensing-agent
id bke-licensing-agent >/dev/null 2>&1 || useradd --system --gid bke-licensing-agent --home-dir /var/lib/bke-digital-solutions/licensing-agent --shell /usr/sbin/nologin bke-licensing-agent
mkdir -p /var/lib/bke-digital-solutions/licensing-agent
chown -R bke-licensing-agent:bke-licensing-agent /var/lib/bke-digital-solutions/licensing-agent
systemctl daemon-reload
systemctl enable bke-licensing-agent.service
systemctl restart bke-licensing-agent.service

i=0
until systemctl is-active --quiet bke-licensing-agent.service; do
  i=$((i + 1))
  if [ "$i" -ge 30 ]; then
    echo "BKE Licensing Agent did not become active after package installation." >&2
    systemctl status bke-licensing-agent.service --no-pager 2>/dev/null || true
    exit 1
  fi
  sleep 1
done
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu

case "${1:-}" in
  upgrade)
    # Do not disable the unit during an upgrade. Stopping it is sufficient and
    # preserves the enabled boot policy for the replacement package.
    systemctl stop bke-licensing-agent.service 2>/dev/null || true
    ;;
  remove|deconfigure)
    systemctl disable --now bke-licensing-agent.service 2>/dev/null || true
    ;;
esac
EOF
chmod 755 "$STAGE/DEBIAN/prerm"

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
systemctl daemon-reload 2>/dev/null || true
# /var/lib/bke-digital-solutions/licensing-agent is intentionally retained.
# Machine licensing/trust state must survive package replacement/removal.
EOF
chmod 755 "$STAGE/DEBIAN/postrm"

dpkg-deb --build --root-owner-group "$STAGE" "$OUTDIR/BKE-Licensing-Agent-${VERSION}-Linux-x64.deb"
