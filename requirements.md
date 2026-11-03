# Requirements Specification: UniFi Native RADIUS Server

> **System Overview**: Self-contained, zero-dependency Golang RADIUS server with embedded UniFi-styled web interface, internal CA, and automated UniFi Network Application integration for UDM-Pro and UDM-SE.

---

## 1. Quick Reference & System Matrix

| Property | Value / Specification |
|---|---|
| **Target OS / Arch** | Linux ARM64 (`aarch64`) for UniFi OS 3.x / 4.x (UDM-Pro, UDM-SE) |
| **Additional Targets** | Windows AMD64, Linux AMD64 |
| **Install Path (UDM)** | `/data/unifi-radius/` (persists across firmware updates) |
| **Init System** | Systemd unit: `/etc/systemd/system/unifi-radius.service` |
| **Runtime Dependencies** | **None** (Pure Go, CGO=0, no Docker/Node.js/Python required) |
| **Database** | SQLite via `modernc.org/sqlite` (WAL-Mode, `busy_timeout=5000`) |
| **Default Ports** | RADIUS: UDP `1812` (empty fallback = 1812) • Web UI: TCP `9182` (empty fallback = 9182) |
| **Web UI Assets** | 100% Zero-CDN (Embedded HTMX, HTMX-WS, CSS via `embed.FS`) |
| **Auth Types** | MAB (RFC 2868/3580), 802.1X EAP-TLS (RSA 2048/4096), PAP |
| **UI Languages** | Deutsch (`de`, default), English (`en`) via `Accept-Language` & Cookie |

---

## 2. Functional Requirements (REQ)

### 2.1 RADIUS Engine (`REQ-RAD`)

| ID | Title | Technical Specification & Acceptance Criteria |
|---|---|---|
| **REQ-RAD-01** | **MAB Dynamic VLAN** | Assign VLAN via RFC 2868/3580 attributes: `Tunnel-Type=13 (VLAN)`, `Tunnel-Medium-Type=6 (802)`, `Tunnel-Private-Group-Id=<VLAN_ID>`. |
| **REQ-RAD-02** | **MAC Normalization** | Accept MAC formats: `AA:BB:CC:DD:EE:FF`, `aabbccddeeff`, `AA-BB-CC-DD-EE-FF`, `aabb.ccdd.eeff`. Canonical format in DB: uppercase colon-delimited. |
| **REQ-RAD-03** | **802.1X EAP-TLS** | Authenticate via X.509 client certificates signed by internal CA; reject revoked certificates immediately. |
| **REQ-RAD-04** | **Standard User Auth** | Support Username & Password authentication (PAP / 802.1X) with secure bcrypt hashing, dynamic VLAN assignment, and fast in-memory cache lookup. |
| **REQ-RAD-05** | **Shared Secrets** | Global Shared Secret with crypto-generator and copy button; support per-NAS IP/CIDR overrides in `nas_clients`. |
| **REQ-RAD-06** | **Unknown MAB Policy** | Configurable: `reject_log` (reject & log for 1-click approval) or `allow_default_vlan` (accept into default allow VLAN). |
| **REQ-RAD-07** | **Default Allow VLAN** | Fallback VLAN ID used when client has no explicit VLAN assigned (`c.vlan_id IS NULL`). |
| **REQ-RAD-08** | **High-Concurrency** | 32 parallel worker goroutines; 4 MB UDP receive socket buffer (`SO_RCVBUF`). Sub-millisecond auth latency. |

### 2.2 Certificate Authority (`REQ-CA`)

| ID | Title | Technical Specification & Acceptance Criteria |
|---|---|---|
| **REQ-CA-01** | **Internal Root CA** | Generate & persist RSA 4096-bit SHA-256 Root CA certificate and server certificate (`radius.internal`). |
| **REQ-CA-02** | **Client Issuance** | Issue RSA 2048-bit client certs directly via UI with custom Common Name (username) and validity period (days). |
| **REQ-CA-03** | **Export Formats** | PKCS#12 (`.p12` password-protected), PEM (`.crt`/`.key` bundles), Apple Profile (`.mobileconfig` for iOS/macOS). |
| **REQ-CA-04** | **Revocation** | 1-click certificate revocation; instantly denies authentication via RADIUS EAP-TLS. |

### 2.3 UniFi Controller Integration (`REQ-UNI`)

| ID | Title | Technical Specification & Acceptance Criteria |
|---|---|---|
| **REQ-UNI-01** | **Dual Auth Mode** | Support Modern UniFi OS API-Key (`X-API-KEY`) and Legacy User/Password session (`/api/auth/login`). |
| **REQ-UNI-02** | **VLAN Auto-Sync** | Periodically sync networks & VLAN IDs from UniFi Network to table `unifi_vlans`; provide in UI selects. Stream sync progress & results directly to live log feed (`[UNIFI-SYNC]`). |
| **REQ-UNI-03** | **NAS Discovery** | Auto-discover UniFi switches, APs, and gateways; populate authorized NAS clients list. |
| **REQ-UNI-04** | **Device Enrichment** | Enrich client MAC entries with UniFi live data: alias name, hostname, vendor OUI, IP address, switch port, switch MAC, wired/wireless flag. |
| **REQ-UNI-05** | **FreeRADIUS Migration** | Detect active built-in UDM FreeRADIUS, import user/MAB accounts, disable built-in daemon, reconfigure RADIUS profile to `127.0.0.1:1812`. |
| **REQ-UNI-06** | **Port Restart & Reconnect** | Remote switch port power-cycle (`POST .../cmd/devmgr`, `power-cycle`) and client station kick/reconnect (`POST .../cmd/stamgr`, `kick-sta`) via UniFi Network Application. |

### 2.4 Web Interface & UX (`REQ-UI`)

| ID | Title | Technical Specification & Acceptance Criteria |
|---|---|---|
| **REQ-UI-01** | **Zero-CDN Architecture** | All assets (HTMX, CSS, WebSocket scripts) embedded in binary via `embed.FS`; 100% functional offline/air-gapped. |
| **REQ-UI-02** | **Tab Navigation** | Dedicated template instances (`pages[name]`) preventing template execution conflicts across tabs: Dashboard, Clients, Certificates, Logs, Settings. |
| **REQ-UI-03** | **Client List & Filters** | Render VLAN ID **and** UniFi VLAN Name (`[VLAN 10] Gast-WLAN` or `Default (VLAN 1 - LAN)`). Live filtering via HTMX (250ms debounce) for query, status, and VLAN dropdown with 1-click clear (`×`). |
| **REQ-UI-04** | **Real-Time Streaming** | WebSocket feed (`/ws/feed`) streaming live RADIUS auth events and terminal logs without page reloads. |
| **REQ-UI-05** | **Security & CLI** | Admin session cookie (bcrypt hashed in DB). CLI flags: `-reset-admin-password`, `-set-admin-password <pass>`. |
| **REQ-UI-06** | **Version & Updates** | Display version on login/footer; async non-blocking update check via GitHub Releases API on login and settings tab (1h cache). |
| **REQ-UI-07** | **Multi-Language (i18n)** | Bilingual DE/EN. Auto-detected via `Accept-Language`, switchable in header/login, persisted via `lang` cookie (1 year). |
| **REQ-UI-08** | **Browser Timezone** | Timestamps formatted in UTC `<time class="local-time" datetime="...">`; localized in browser via client-side JS (`Intl.DateTimeFormat`, MutationObserver & HTMX hooks). |
| **REQ-UI-09** | **UniFi Sync Button Animation** | Topbar sync button features continuous CSS spin animation (`@keyframes spin`), status label toggle ("Synchronisiere...") and click-lock during sync; displays 2.5s green confirmation upon completion. |
| **REQ-UI-10** | **Port Restart & Reconnect Controls** | Client table actions (`⚡ Port`, `🔄 Reconnect`) with toast confirmations; Edit Modal option "Nach Speichern sofort Reconnect / Port-Neustart ausführen" and instant trigger buttons. |
| **REQ-UI-11** | **Standard User Management** | UI switcher in Add Modal (`💻 Gerät (MAB)` vs `👤 Benutzer (802.1X / PAP)`), bcrypt password hashing, inline username display with `USER` badge, editing with optional password change, and list filtering by entry type. |
| **REQ-UI-12** | **1-Click SQLite Backup & Restore** | Live transactional snapshot download (`GET /api/backup/download` via SQLite `VACUUM INTO`) and integrity-checked restoration (`POST /api/backup/restore` via `PRAGMA integrity_check`) in Settings tab. |
| **REQ-UI-13** | **Remote & Cloud Backup** | Automated scheduled backup (WebDAV, S3-compatible, Local/SMB mount) with retention pruning, live connection test (`POST /api/backup/remote/test`), and instant manual trigger (`POST /api/backup/remote/run`). |

### 2.5 Security Hardening (`REQ-SEC`)

| ID | Title | Technical Specification & Acceptance Criteria |
|---|---|---|
| **REQ-SEC-01** | **HTTP Security Headers** | Enforce `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: strict-origin-when-cross-origin`, strict `Content-Security-Policy` (`default-src 'self'`), and `Permissions-Policy`. |
| **REQ-SEC-02** | **CSRF & Cookie Protection** | Enforce `SameSite=Lax`, `HttpOnly=true`, and conditional `Secure` flag on `session_id`. Verify `Origin` / `Referer` on all state-changing POST endpoints (`s.csrfProtect`). |
| **REQ-SEC-03** | **WebSocket Auth & CSWSH** | Require active authenticated admin session on `/ws/feed` (reject with 401 Unauthorized); validate `Origin` header against `Host` to prevent Cross-Site WebSocket Hijacking. |
| **REQ-SEC-04** | **XSS & Template Defense** | Strict context-aware HTML escaping (`template.HTMLEscapeString`) on all live WebSocket snippets (client MAC, usernames, vendor strings, switch ports, logs). |
| **REQ-SEC-05** | **Rate Limiting & DoS Defense** | In-memory IP rate limiter locking out login attempts for 2 minutes after 5 consecutive failures; 50 MB request body limit (`http.MaxBytesReader`) on database restore uploads. |
| **REQ-SEC-06** | **Timing Attack Mitigation** | Perform constant-time dummy bcrypt hash comparison on non-existent users in RADIUS PAP handler to eliminate username enumeration via response latency. |
| **REQ-SEC-07** | **XML Profile Sanitization** | XML entity escaping (`encoding/xml`) for SSID, profile name, and credentials in Apple `.mobileconfig` generator. |

### 2.6 Messenger, Bots & Notification Integrations (`REQ-NOTIFY`)

| ID | Title | Technical Specification & Acceptance Criteria |
|---|---|---|
| **REQ-NOTIFY-01** | **Telegram 2-Way Bot** | Interactive bot via long-polling (`getUpdates`, zero inbound ports); strict user/chat ID whitelist (`allowedChatIDs`); slash commands (`/status`, `/pending`, `/vlan <mac> <id>`, `/block <mac>`, `/kick <mac>`); inline keyboard buttons (`[Freigeben]`, `[VLAN wählen]`, `[Sperren]`, `[Reconnect]`); strict HTML entity escaping against injection. |
| **REQ-NOTIFY-02** | **Discord 2-Way Bot** | Interactive bot via Discord Gateway WebSocket (`wss://gateway.discord.gg`, zero inbound ports); rich embed cards with color coding; interactive action row buttons with component interaction handling (`INTERACTION_CREATE`). |
| **REQ-NOTIFY-03** | **Home Assistant Webhook** | Automated HTTP POST with JSON event payload (`event_type`, `mac`, `vlan`, `vendor`, etc.) to HA webhook; strict SSRF defense (scheme allowlist `http`/`https`, host check, 5s timeout, 16KB body limit). |
| **REQ-NOTIFY-04** | **Pushover 1-Way Push** | Priority push notifications with custom alert sound and direct Web-UI link (`/clients?q=<mac>`) for instant 1-click approvals. |
| **REQ-NOTIFY-05** | **Alert Deduplication & Cooldown** | In-memory sliding window deduplicator (5-minute cooldown per device/event) preventing alert storms during RADIUS retry bursts. |
| **REQ-NOTIFY-06** | **Daily Summary & CA Expiry** | Background scheduler dispatching daily operational health reports at configured time (`HH:MM`) and proactive warnings when CA or server certificates expire within 14 days. |

---

## 3. Non-Functional Requirements & Architecture (`REQ-NFR`)

| ID | Domain | Technical Specification & Constraints |
|---|---|---|
| **REQ-NFR-01** | **Performance** | In-memory `FastCache` (`sync.RWMutex`) for client & NAS lookups; asynchronous batch log writer (100 ms flush / 50 batch size). |
| **REQ-NFR-02** | **Data Integrity** | Pure-Go SQLite (`CGO_ENABLED=0`), WAL-mode, foreign keys enabled, configurable log retention pruning (days / max records). |
| **REQ-NFR-03** | **Deployment** | Single static executable (`bin/unifi-radius-arm64` & `bin/unifi-radius.exe`); automated installation/uninstallation shell scripts. |
| **REQ-NFR-04** | **Testing** | 100% unit & integration test coverage across all packages (`ca`, `database`, `radius`, `unifi`, `updater`, `web`). |
| **REQ-NFR-05** | **CI/CD & Security Scanning** | Automated GitHub Actions pipeline (`build.yml`, `release.yml`, `security.yml`) for Go 1.27.x matrix builds (ARM64, AMD64, Windows), Govulncheck vulnerability database scanner, CodeQL semantic analysis, and Gosec AST security linter. |

---

## 4. Key Endpoints & CLI Interface

```text
HTTP Endpoints:
  GET  /                        -> Dashboard & Live Feed
  GET  /clients                 -> Client Management (Query: q, status, vlan)
  POST /clients/create          -> Add MAB Client
  POST /clients/update          -> Update Client & VLAN (optional immediate port restart/reconnect)
  POST /clients/approve         -> 1-Click Approve Pending Device
  POST /clients/delete          -> Delete Client
  POST /clients/restart-port    -> Power-Cycle Switch Port & Kick Client (UniFi cmd/devmgr & stamgr)
  POST /clients/reconnect       -> Disconnect/Reconnect Client Station (UniFi cmd/stamgr)
  GET  /certificates            -> CA & Certificate Overview
  POST /certificates/ca/init    -> Generate RSA 4096 Root CA
  POST /certificates/issue      -> Issue Client Cert (PEM/P12/MobileConfig)
  POST /certificates/revoke     -> Revoke Certificate
  GET  /logs                    -> Audit History & Live Log Filter
  GET  /settings                -> System, UniFi & RADIUS Configuration
  POST /settings/save           -> Persist Settings
  POST /api/notify/test         -> Test Notification Provider (Telegram/Discord/Pushover/HA)
  GET  /api/backup/download     -> Download Live SQLite Backup Snapshot (.db)
  POST /api/backup/restore      -> Restore Database from Uploaded Backup
  POST /api/backup/remote/test  -> Test Remote Backup Target (WebDAV, S3, Local)
  POST /api/backup/remote/run   -> Trigger Immediate Remote Backup & Retention Pruning
  GET  /ws/feed                 -> WebSocket Event Stream (Auth Logs & Terminal)
  GET  /api/update/check        -> Non-blocking GitHub Release Checker
  GET  /api/set-language        -> Language Toggle (?lang=de|en)

CLI Flags:
  -db <path>                    -> Path to SQLite database (default: data/radius.db)
  -web-port <int>               -> Web interface HTTP port (default: 9182)
  -radius-port <int>            -> RADIUS auth UDP port (default: 1812)
  -reset-admin-password         -> Clear admin password and re-enable setup wizard
  -set-admin-password <pass>    -> Direct headless password assignment
  -version                      -> Print application version and exit
```
