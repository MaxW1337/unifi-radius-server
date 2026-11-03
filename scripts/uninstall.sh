#!/bin/bash
set -e

# ==============================================================================
# UniFi RADIUS Server - Uninstaller
# ==============================================================================

SERVICE_NAME="unifi-radius"
INSTALL_DIR="/data/unifi-radius"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: Please run this script as root."
    exit 1
fi

echo "[+] Stopping ${SERVICE_NAME} service..."
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
systemctl disable "${SERVICE_NAME}" 2>/dev/null || true

echo "[+] Removing systemd unit..."
rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
rm -f "/data/on_boot.d/10-unifi-radius.sh"
systemctl daemon-reload

read -p "Do you want to delete all database files and settings in ${INSTALL_DIR}? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "${INSTALL_DIR}"
    echo "[+] Completely removed ${INSTALL_DIR}."
else
    echo "[+] Database preserved in ${INSTALL_DIR}."
fi

echo "[✓] UniFi RADIUS Server has been uninstalled."

