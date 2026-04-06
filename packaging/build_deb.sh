#!/bin/bash
# Build procflow .deb package.
# Run from the packaging/ directory: sudo bash build_deb.sh
set -euo pipefail

PKG=procflow
VER=1.0.1
ARCH=amd64
STAGE="${PKG}_${VER}_${ARCH}"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/usr/sbin"
mkdir -p "$STAGE/usr/share/man/man8"
mkdir -p "$STAGE/etc/procflow"
mkdir -p "$STAGE/lib/systemd/system"
mkdir -p "$STAGE/var/log/procflow"

# Binary (installed without .py extension, root-owned and not group/world-writable)
install -o root -g root -m 755 ../procflow.py "$STAGE/usr/sbin/procflow"

# Man page (compressed)
gzip -9 -c procflow.8 > "$STAGE/usr/share/man/man8/procflow.8.gz"

# Config, service, and DEBIAN metadata
install -m 644 procflow.conf             "$STAGE/etc/procflow/procflow.conf"
install -m 644 procflow.service          "$STAGE/lib/systemd/system/procflow.service"
install -m 644 DEBIAN/control          "$STAGE/DEBIAN/control"
install -m 644 DEBIAN/conffiles        "$STAGE/DEBIAN/conffiles"
install -m 755 DEBIAN/postinst         "$STAGE/DEBIAN/postinst"
install -m 755 DEBIAN/prerm            "$STAGE/DEBIAN/prerm"

dpkg-deb --build --root-owner-group "$STAGE"
echo "Built: ${STAGE}.deb"
echo ""
echo "Install with:  sudo dpkg -i ${STAGE}.deb"
echo "Remove with:   sudo dpkg -r ${PKG}"
