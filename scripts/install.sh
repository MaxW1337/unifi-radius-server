#!/bin/bash
set -e

# ==============================================================================
# UniFi RADIUS Server - UDM-Pro / UDM-SE Installer
# https://github.com/MaxW1337/unifi-radius-server
# ==============================================================================

REPO="MaxW1337/unifi-radius-server"
INSTALL_DIR="/data/unifi-radius"
SERVICE_NAME="unifi-radius"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "=========================================================="
echo " Installing UniFi RADIUS Server for UDM-Pro / UDM-SE"
echo "=========================================================="

# 1. Check Root Privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: Please run this installer as root (e.g. sudo bash install.sh)."
    exit 1
fi

# 2. Architecture Detection
ARCH=$(uname -m)
case "$ARCH" in
    aarch64|arm64)
        TARGET_ARCH="arm64"
        ;;
    x86_64|amd64)
        TARGET_ARCH="amd64"
        ;;
    *)
        echo "[-] Error: Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "[+] Detected architecture: ${TARGET_ARCH} (${ARCH})"

# 3. Create persistent directory under /data
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

# 4. Resolve Latest GitHub Release
echo "[+] Checking for latest release from GitHub (${REPO})..."
LATEST_RELEASE_JSON=$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" || true)

# Parse tag name or fallback
TAG_NAME=$(echo "${LATEST_RELEASE_JSON}" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)

if [ -z "${TAG_NAME}" ]; then
    echo "[!] Warning: Could not detect latest tag via GitHub API. Falling back to 'latest'."
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/unifi-radius-linux-${TARGET_ARCH}"
else
    echo "[+] Found release tag: ${TAG_NAME}"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG_NAME}/unifi-radius-linux-${TARGET_ARCH}"
fi

# 5. Stop running service if present
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "[+] Stopping existing ${SERVICE_NAME} service..."
    systemctl stop "${SERVICE_NAME}"
fi

# 6. Download Binary
echo "[+] Downloading binary from: ${DOWNLOAD_URL}"
curl -fSL "${DOWNLOAD_URL}" -o "${INSTALL_DIR}/unifi-radius.tmp"
mv "${INSTALL_DIR}/unifi-radius.tmp" "${INSTALL_DIR}/unifi-radius"
chmod +x "${INSTALL_DIR}/unifi-radius"

echo "[+] Binary installed to: ${INSTALL_DIR}/unifi-radius"

# 7. Install Systemd Service
echo "[+] Creating systemd service at: ${SERVICE_FILE}"
cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=UniFi RADIUS Server (MAB & 802.1X Dynamic VLAN)
After=network.target network-online.target unifi.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/unifi-radius -db ${INSTALL_DIR}/radius.db
Restart=always
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Copy backup to /data for post-firmware update recovery
cp -f "${SERVICE_FILE}" "${INSTALL_DIR}/${SERVICE_NAME}.service"

# On-boot script integration if udm-utilities / on-boot-script is installed
if [ -d "/data/on_boot.d" ]; then
    echo "[+] Detected /data/on_boot.d. Installing auto-restore hook..."
    cat <<'BOOTHOOK' > "/data/on_boot.d/10-unifi-radius.sh"
#!/bin/bash
if [ ! -f /etc/systemd/system/unifi-radius.service ]; then
    cp -f /data/unifi-radius/unifi-radius.service /etc/systemd/system/unifi-radius.service
    systemctl daemon-reload
    systemctl enable --now unifi-radius
fi
BOOTHOOK
    chmod +x "/data/on_boot.d/10-unifi-radius.sh"
fi

# 8. Reload & Start Service
echo "[+] Enabling and starting ${SERVICE_NAME} service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl restart "${SERVICE_NAME}"

# 9. Verify Status
sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    UDM_IP=$(ip -4 addr show eth8 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || ip -4 addr show br0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
    echo ""
    echo "=========================================================="
    echo " [✓] UniFi RADIUS Server successfully installed & running!"
    echo "=========================================================="
    echo ""
    echo "  Web Interface:  http://${UDM_IP}:9182"
    echo "  RADIUS Port:    UDP 1812"
    echo "  Data Directory: ${INSTALL_DIR}"
    echo ""
    echo "  Next steps:"
    echo "  1. Open http://${UDM_IP}:9182 in your browser to set your admin password."
    echo "  2. Go to 'Settings' and enter your UniFi API Key."
    echo "  3. In UniFi Network, add a RADIUS profile pointing to 127.0.0.1:1812."
    echo "=========================================================="
else
    echo "[-] Service failed to start. View logs with: journalctl -u ${SERVICE_NAME} -n 50"
    exit 1
fi

