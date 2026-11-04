# UniFi RADIUS Server

[![Build & Test](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/build.yml/badge.svg)](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/build.yml)
[![Security Scanning](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/security.yml/badge.svg)](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/security.yml)
[![Release](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/release.yml/badge.svg)](https://github.com/MaxW1337/unifi-radius-server/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A lightweight, robust, and self-contained **RADIUS server written in Go**, designed to run natively on the **UniFi Dream Machine Pro (UDM-Pro)**, **UDM-SE**, and **UDR** (UniFi OS 3.x / 4.x, ARM64).

---

## Highlights

* 🚀 **Native & Extremely Lightweight**: Single standalone ARM64 binary located under `/data/unifi-radius/` (survives UDM firmware updates, ~15MB RAM footprint, zero Docker/Podman overhead).
* 🔒 **MAC Authentication Bypass (MAB)**: Seamless discovery and authentication for wired switch ports and wireless devices.
* 🏷️ **Dynamic VLAN Assignment (RFC 2868 / 3580)**: Automatically assigns devices to their designated VLANs using standard RADIUS tunnel attributes.
* 🌐 **Seamless UniFi Network Integration**:
  * **Hybrid Authentication**: Connect via official **UniFi API Key** (UniFi OS 3.x+ / Network 8.x+) or **Local Service Account** (username & password).
  * **Dynamic VLAN Dropdowns**: Automatically fetches all defined networks/VLANs directly from your UDM.
  * **Auto-Discovery of Switches & APs**: Discovers UniFi network hardware and provisions them as RADIUS clients (NAS) using your configured Shared Secret.
  * **Device Metadata Enrichment**: Resolves client hostnames, vendor OUIs, IP addresses, and switch port mappings directly from UniFi Network.
* 🛡️ **Built-in Certificate Authority (EAP-TLS CA)**:
  * Integrated Root CA for secure 802.1X EAP-TLS certificate-based authentication.
  * 1-Click client certificate issuance.
  * Direct export as password-protected **PKCS#12 (.p12 / .pfx)** bundles, individual **PEM files**, or **Apple `.mobileconfig` profiles** for 1-click Wi-Fi setup on iPhone, iPad, and Mac.
* ⚡ **100% Self-Contained UniFi-Style Web Interface**:
  * Clean, responsive dark theme matching official UniFi OS UX design principles.
  * **Zero CDN Dependencies**: All assets (HTMX, CSS, icons) are embedded directly into the Go binary via `embed` – works 100% offline and in air-gapped networks.
  * **Real-Time WebSocket Monitor**: Live streaming of incoming RADIUS authentications, client state changes, and server logs.
* 🔍 **Live Log Console with Multi-Filters**:
  * Real-time stream filtering by log level (`INFO`, `WARN`, `ERROR`), source (`RADIUS`, `UniFi Sync`, `CLIENT-ACTION`, etc.), and free-text search.
  * Live stream pause toggle and 1-click log export.
* 🔄 **Integrated Self-Update Engine**:
  * **1-Click Self-Update** in the Web UI with live progress indicators and automatic restart.
  * **Configurable Automated Updates**: Scheduled maintenance windows (daily, weekly, or monthly at your specified time).
  * **Cryptographic Integrity**: SHA-256 checksum verification against official GitHub Releases (`checksums.txt`) before applying updates.
* 💾 **Pure-Go SQLite Storage**: Zero external runtime dependencies; uses modern pure-Go SQLite under `/data/unifi-radius/radius.db`.
* 🔔 **Multi-Channel Alerts & Automated Backups**:
  * Notifications via **Telegram**, **Discord**, **Pushover**, and **Home Assistant Webhooks**.
  * Automated scheduled backups to **WebDAV (Nextcloud)**, **S3/MinIO**, or local mounted shares.

---

## 1-Click Installation on UDM (Pro / SE / UDR)

Connect to your UDM via SSH and execute the following command:

```bash
curl -fsSL https://raw.githubusercontent.com/MaxW1337/unifi-radius-server/main/scripts/install.sh | bash
```

### What the installer does:
1. Detects your CPU architecture (`arm64`).
2. Fetches and validates the latest release binary from GitHub.
3. Provisions the persistent data directory `/data/unifi-radius`.
4. Configures and enables the systemd service `/etc/systemd/system/unifi-radius.service`.
5. Installs an automatic persistence hook for firmware updates if `on-boot-script` (`/data/on_boot.d/`) is detected.
6. Starts the server and displays the initial setup URL.

### Alternative: Install via Debian Package (.deb)

Download and install the appropriate `.deb` package from the [Releases page](https://github.com/MaxW1337/unifi-radius-server/releases):

```bash
dpkg -i unifi-radius_*_arm64.deb
```

---

## Initial Setup & Quick Start

1. **Access the Web Interface**:
   Open your browser and navigate to: `http://<YOUR-UDM-IP>:9182`
   On first launch, you will be prompted to set up your **Admin Password**.

2. **Configure UniFi Network Connection**:
   * Navigate to **Settings** in the side navigation bar.
   * Under **UniFi Integration**, choose **UniFi API Key** (generate one in UniFi OS under *Settings* -> *Integrations* -> *API Keys*) or enter the credentials of a local UDM administrator.
   * Click **Test Connection**, followed by **Save Settings**.
   * Click **UniFi Sync** in the top navigation bar to immediately import all VLANs and UniFi switches/APs.

3. **Configure UniFi RADIUS Profile**:
   * Open the UniFi Network Application.
   * Navigate to **Settings** -> **Profiles** -> **RADIUS**.
   * Create a new profile (or update the existing one):
     * **Profile Name**: `UDM-Internal-RADIUS`
     * **VLAN Support**: Enabled (Required for Dynamic VLAN assignment!)
     * **IP Address**: `127.0.0.1` (or your UDM's gateway IP)
     * **Port**: `1812`
     * **Password / Shared Secret**: The *Global Shared Secret* configured in your server settings.
   * Save changes.

4. **Wired Switch 802.1X Control (Global Switch Settings)**:
   * In UniFi Network, navigate to **Settings** -> **Networks** -> **Global Switch Settings**.
   * Under **802.1X Control**:
     * **Credential Source**: Change from *Local* to **RADIUS Profile**.
     * **RADIUS Profile**: Select `UDM-Internal-RADIUS`.
     * **Fallback Network**: Select `LAN` (or your default native network).
   * *(Note: The built-in Migration Assistant can automate this step via the UniFi API).*

5. **Enable MAB on Switch Ports**:
   * In UniFi Network, select a Switch and open Port Manager.
   * Select a port and set **802.1X Control** to **MAC-based (MAB)**.
   * Connect a client device – its authentication request will appear instantly in the **Live Monitor**!

---

## Migration from Built-in UniFi RADIUS

If your UDM is currently running the built-in UniFi RADIUS server, the Web UI provides an **Automated Migration Assistant** under **Settings -> UniFi RADIUS Migration & Takeover**:

1. **Automatic Status Detection**:
   * Detects whether the built-in FreeRADIUS service is active.
   * Analyzes existing local RADIUS users, MAB entries, and configured secrets.
2. **1-Click Takeover**:
   * **Full Account Import**: Migrates all MAB devices (auto-normalized to standard MAC formats) and 802.1X accounts with their designated VLANs to SQLite.
   * **Shared Secret Sync**: Automatically adopts the existing secret so switches and access points continue operating without manual changes.
   * **RADIUS Profile Automation**: Creates or updates the UniFi RADIUS profile `UDM-Internal-RADIUS` (`127.0.0.1:1812`, VLAN Support: Active).
   * **Automated WLAN Re-Assignment**: Seamlessly switches all Enterprise and MAB-enabled Wi-Fi networks (SSIDs) from the default profile (`Default`) to `UDM-Internal-RADIUS`. This prevents the common UniFi blocking error *"Default profile cannot be paused because it is used by WiFi..."*.
   * **Global Switch 802.1X Control**: Sets switch 802.1X authentication source to `UDM-Internal-RADIUS` with LAN fallback.
   * **Port 1812 Release**: Disables the built-in UniFi FreeRADIUS service via the UniFi API so that port 1812 can be bound exclusively.

---

## Unknown Device Policies (MAB Policies)

You can customize how the server handles unknown MAC addresses under Settings:

| Policy | Behavior on Unknown MAC | Recommended Use Case |
| :--- | :--- | :--- |
| **Auto-Accept** | Immediately grants `Access-Accept` with the configured **Default Allow VLAN** and records the device as `pending`. | Frictionless onboarding (e.g., routing new devices to an isolated quarantine/guest VLAN). |
| **Reject & Log** | Issues `Access-Reject`, but records the device in the **Pending Queue**. Admins can approve it with 1 click in the Web UI. | Strong security with convenient 1-click approvals without manual MAC typing. |
| **Strict Reject** | Immediately rejects without persisting to the database. | Zero-trust environments where only pre-whitelisted MACs are permitted. |

---

## Certificates & 802.1X EAP-TLS

The server includes a complete internal Certificate Authority (CA):
1. Navigate to **Certificates (CA)** and click **Initialize Root CA**.
2. Click **Issue New Certificate** and enter a username or device identifier (e.g., `ceo-laptop` or `alice.smith`).
3. Download the bundle in your preferred format:
   * **.P12**: Standard PKCS#12 bundle for Windows, macOS, Android, and Linux.
   * **PEM**: Separate certificate and private key files.
   * **Apple Profile (.mobileconfig)**: Send via AirDrop or email to iPhone, iPad, or Mac – automatically installs the root CA and configures the Wi-Fi network with 1 tap!

---

## Service Management & CLI Commands

```bash
# Check service status
systemctl status unifi-radius

# Follow live service logs on UDM
journalctl -u unifi-radius -f

# Restart service
systemctl restart unifi-radius

# Stop service
systemctl stop unifi-radius

# Reset admin password (re-enables initial setup wizard in Web UI)
unifi-radius -reset-admin-password

# Set admin password directly from command line
unifi-radius -set-admin-password "MySuperSecretPassword123!"

# Complete uninstallation
bash /data/unifi-radius/scripts/uninstall.sh
```

---

## Local Development & Building

Requirements: Go 1.22+ (tested with Go 1.24/1.27)

```bash
# Run unit and integration tests
go test -v ./...

# Build local binary
go build -o bin/unifi-radius ./cmd/server

# Cross-compile for UDM-Pro / SE / UDR (Linux ARM64)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/unifi-radius-arm64 ./cmd/server
```

---

## License

This project is licensed under the [MIT License](LICENSE).
