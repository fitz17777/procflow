#!/bin/bash
# ProcFlow installer
# Usage: curl -sSL https://raw.githubusercontent.com/fitz17777/procflow/main/install.sh | sudo bash
set -euo pipefail

VERSION="1.1.0"
DEB_URL="https://github.com/fitz17777/procflow/releases/download/v${VERSION}/procflow_${VERSION}_amd64.deb"
DEB_FILE="/tmp/procflow_${VERSION}_amd64.deb"

# ── Checks ────────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)." >&2
    exit 1
fi

if ! command -v dpkg &>/dev/null; then
    echo "ERROR: This installer requires a Debian/Ubuntu system (dpkg not found)." >&2
    exit 1
fi

ARCH=$(dpkg --print-architecture)
if [ "$ARCH" != "amd64" ]; then
    echo "ERROR: procflow is currently only packaged for amd64 (detected: $ARCH)." >&2
    exit 1
fi

# ── Dependencies ──────────────────────────────────────────────────────────────
echo "==> Updating package index..."
apt-get update -qq

echo "==> Installing dependencies..."
# linux-headers must match the running kernel exactly — cannot be in the .deb
KERNEL=$(uname -r)
apt-get install -y -qq \
    "linux-headers-${KERNEL}" \
    python3-bpfcc \
    bpfcc-tools

# ── Install procflow ──────────────────────────────────────────────────────────
echo "==> Downloading procflow v${VERSION}..."
curl -sSL "$DEB_URL" -o "$DEB_FILE"

echo "==> Installing procflow..."
dpkg -i "$DEB_FILE"
rm -f "$DEB_FILE"

# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
echo "==> procflow v${VERSION} installed."
echo ""
procflow --version
echo ""
systemctl is-active --quiet procflow && \
    echo "    Service:  running (systemctl status procflow)" || \
    echo "    Service:  not running — check: journalctl -u procflow -n 20"
echo "    Log file: /var/log/procflow/enriched_flow.log"
echo "    Config:   /etc/procflow/procflow.conf"
echo ""
echo "    To watch live output:"
echo "      sudo journalctl -u procflow -f"
echo "      sudo procflow --stdout-only --no-pam"
