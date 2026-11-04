# UniFi RADIUS Server

[![Build & Test](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/build.yml/badge.svg)](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/build.yml)
[![Security Scanning](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/security.yml/badge.svg)](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/security.yml)
[![Release](https://github.com/MaxW1337/unifi-radius-server/actions/workflows/release.yml/badge.svg)](https://github.com/MaxW1337/unifi-radius-server/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Ein leichtgewichtiger, robuster und autarker **RADIUS-Server in Go**, der direkt nativ auf der **UniFi Dream Machine Pro (UDM-Pro)** und **UDM-SE** (UniFi OS 3.x / 4.x, ARM64) läuft.

---

## Highlights

* 🚀 **Nativ & Extrem Schlank**: Single-Binary ARM64 unter `/data/unifi-radius/` (überlebt UDM-Firmware-Updates, nur ~15MB RAM, kein Docker/Podman-Overhead).
* 🔒 **MAC Authentication Bypass (MAB)**: Automatische Erkennung und Authentifizierung von kabelgebundenen Switch-Ports und WLAN-Geräten.
* 🏷️ **Dynamic VLAN Assignment (RFC 2868 / 3580)**: Automatische Zuweisung des Ziel-VLANs per RADIUS-Tunnel-Attribute.
* 🌐 **Nahtlose UniFi-Integration**:
  * **Hybride Authentifizierung**: Verbindung wahlweise über offiziellen **UniFi API-Key** (ab UniFi OS 3.x / Network 8.x) oder **lokalen Service-Account** (Benutzer/Passwort).
  * **VLAN Dropdowns**: Lädt alle definierten Netzwerke/VLANs direkt aus der UDM.
  * **Auto-Autorisierung von Switches & APs**: Erkennt UniFi-Geräte automatisch und hinterlegt sie als RADIUS-Clients (NAS) mit dem konfigurierten Shared Secret.
  * **Geräte-Datenanreicherung**: Liest Namen, Hostnames, Hersteller (OUI), IP-Adressen und verbundene Switch-Ports automatisch aus UniFi aus.
* 🛡️ **Integrierte Zertifizierungsstelle (Internal CA)**:
  * Integrierte Root-CA für 802.1X EAP-TLS.
  * 1-Klick-Ausstellung von Client-Zertifikaten.
  * Direkter Download als passwortgeschütztes **PKCS#12 (.p12 / .pfx)** Bundle, **PEM-Dateien** oder **Apple `.mobileconfig` Profil** für 1-Klick-WLAN-Einrichtung auf iPhone, iPad und Mac.
* ⚡ **100% Autarkes UniFi-Style Webinterface**:
  * Dunkles, modernes Design im UniFi OS Look.
  * **Zero-CDN**: Alle Assets (HTMX, CSS, Icons) sind komplett per Go `embed` in die Binärdatei einkompiliert – funktioniert 100% offline und in isolierten Netzen.
  * **WebSockets Live Monitor**: Eingehende RADIUS-Authentifizierungsanfragen und Server-Logs werden in Echtzeit ohne Neuladen der Seite gestreamt.
* 🔄 **Integrierte Self-Update Engine**:
  * **1-Klick-Aktualisierung** direkt im Webinterface mit Live-Fortschritt und automatischem Neuladen.
  * **Automatische Updates**: Konfigurierbare Wartungsfenster (täglich, wöchentlich oder monatlich zur gewünschten Uhrzeit).
  * **Kryptografische Sicherheit**: Streaming-Validierung der SHA-256 Prüfsummen gegen GitHub Releases (`checksums.txt`) verhindert manipulierte Binaries.
* 💾 **Pure-Go SQLite**: Lokale Speicherung in `/data/unifi-radius/radius.db` ohne CGO-Abhängigkeit.

---

## 1-Klick Installation auf der UDM (Pro / SE)

Verbinde dich per SSH mit deiner UDM-Pro oder UDM-SE und führe folgenden Befehl aus:

```bash
curl -fsSL https://raw.githubusercontent.com/MaxW1337/unifi-radius-server/main/scripts/install.sh | bash
```

### Was das Skript macht:
1. Erkennt automatisch die Prozessorarchitektur (`arm64`).
2. Lädt das neueste Release-Binary von GitHub herunter.
3. Erstellt das persistente Verzeichnis `/data/unifi-radius`.
4. Richtet den systemd-Dienst `/etc/systemd/system/unifi-radius.service` ein.
5. Installiert bei vorhandenem `on-boot-script` (`/data/on_boot.d/`) einen automatischen Wiederherstellungs-Hook für Firmware-Updates.
6. Startet den Server und gibt die Zugangsdaten aus.

### Alternative: Installation via Debian-Paket (.deb)

Von der [Releases-Seite](https://github.com/MaxW1337/unifi-radius-server/releases) das passende `.deb`-Paket herunterladen und installieren:

```bash
dpkg -i unifi-radius_*_arm64.deb
```

---

## Ersteinrichtung

1. **Webinterface aufrufen**:
   Öffne im Browser: `http://<DEINE-UDM-IP>:9182`
   Beim ersten Aufruf wirst du aufgefordert, dein **Admin-Passwort** festzulegen.

2. **UniFi-Verbindung konfigurieren**:
   * Gehe im Menü auf **Einstellungen**.
   * Wähle als Authentifizierung **UniFi API-Key** (erstellbar in UniFi OS unter *Settings* -> *Integrations* -> *API Keys*) oder gib Benutzername/Passwort eines lokalen UDM-Admins ein.
   * Klicke auf **Verbindung testen** und anschließend auf **Einstellungen speichern**.
   * Klicke oben rechts auf **UniFi Sync**, um sofort alle VLANs und Switches zu importieren.

3. **UniFi RADIUS Profil einrichten**:
   * Öffne deine UniFi Network Application.
   * Gehe zu **Settings** -> **Profiles** -> **RADIUS**.
   * Erstelle ein neues Profil:
     * **Profile Name**: `UDM-Internal-RADIUS`
     * **VLAN Support**: Aktivieren (Wichtig für Dynamic VLAN!)
     * **IP Address**: `127.0.0.1` (oder die LAN-IP der UDM)
     * **Port**: `1812`
     * **Password / Shared Secret**: Das in den Server-Einstellungen hinterlegte *Global Shared Secret*.
   * Speichern.

4. **Wired Switch 802.1X Control (Globale Switch-Einstellungen)**:
   * Gehe in UniFi Network zu **Settings** -> **Networks** -> **Global Switch Settings**.
   * Unter **802.1X Control**:
     * **Credential Source**: Von *Local* auf **RADIUS Profile** umstellen.
     * **RADIUS Profile**: `UDM-Internal-RADIUS` auswählen.
     * **Fallback Network**: `LAN` (oder dein Standard-Netzwerk).
   * *(Hinweis: Der integrierte Migrations-Assistent übernimmt diese Umstellung automatisch über die UniFi API).*

5. **Port auf Switch aktivieren (MAB)**:
   * Wähle in UniFi Network einen Switch und den gewünschten Port aus.
   * Setze **802.1X Control** auf **MAC-based (MAB)**.
   * Sobald ein Gerät angeschlossen wird, erscheint es im **Live Monitor** des UniFi RADIUS Servers!

---

## Migration vom integrierten UniFi RADIUS Server

Falls in deiner UniFi Network Application der integrierte RADIUS-Server aktiviert ist, bietet das Webinterface einen **automatischen Migrations-Assistenten** unter **Einstellungen -> UniFi RADIUS Migration & Übernahme**:

1. **Automatische Erkennung**:
   * Erkennt sofort, ob der integrierte UniFi RADIUS-Server aktiv ist.
   * Ermittelt die Anzahl der vorhandenen lokalen RADIUS-Benutzer und MAB-Einträge sowie das hinterlegte Secret.
2. **1-Klick Migration**:
   * **Import aller Accounts**: Übernimmt alle MAB-Clients (automatisch formatiert) und 802.1X Benutzer (Passwörter sicher gehasht) inklusive ihrer VLAN-Zuweisungen nach SQLite.
   * **Shared Secret Übernahme**: Synchronisiert das bestehende Shared Secret, sodass Switches und Access Points nicht manuell umkonfiguriert werden müssen.
   * **Port 1812 freigeben**: Deaktiviert den integrierten UniFi FreeRADIUS-Dienst automatisch über die UniFi API, damit der neue Server den UDP-Port 1812 exklusiv binden kann.
   * **UniFi RADIUS-Profil anpassen**: Erstellt bzw. aktualisiert das UniFi RADIUS-Profil `UDM-Internal-RADIUS` (`127.0.0.1:1812`, VLAN Support: Aktiv) vollautomatisch.

---

## Richtlinien für unbekannte Geräte (MAB Policy)

In den Einstellungen kann festgelegt werden, wie sich der Server bei bisher unbekannten MAC-Adressen verhalten soll:

| Richtlinie | Verhalten bei unbekannter MAC | Verwendung |
| :--- | :--- | :--- |
| **Auto-Accept** | Erteilt sofort `Access-Accept` mit dem konfigurierten **Default Allow VLAN** und legt das Gerät als `pending` in der Datenbank an. | Komfortabelstes Onboarding (z.B. Geräte landen sofort in einem Quarantäne/Gast-VLAN). |
| **Reject & Log** | Erteilt `Access-Reject`, speichert das Gerät jedoch in der **Pending-Warteschlange**. Der Admin kann es mit 1 Klick im WebUI freigeben. | Maximale Kontrolle bei bequemer Freischaltung ohne manuelles Abtippen von MACs. |
| **Strict Reject** | Erteilt sofort `Access-Reject` ohne Speicherung in der Datenbank. | Nur vorab manuell registrierte Whitelist-Geräte erhalten Netzwerkzugriff. |

---

## Zertifikate & 802.1X EAP-TLS

Der Server beinhaltet eine vollwertige Zertifizierungsstelle (CA):
1. Navigiere zu **Zertifikate (CA)** und klicke auf **Root-CA jetzt initialisieren**.
2. Klicke auf **Neues Zertifikat ausstellen** und gib einen Benutzernamen oder Gerätenamen (z.B. `chef-laptop` oder `max.mustermann`) ein.
3. Wähle das gewünschte Download-Format:
   * **.P12**: Standard PKCS#12 Bundle für Windows, macOS, Android und Linux.
   * **PEM**: Getrennte Zertifikats- und Schlüsseldateien.
   * **Apple Profil (.mobileconfig)**: Datei per AirDrop, Mail oder Download auf iPhone, iPad oder Mac öffnen – richtet das WLAN und alle Zertifikate vollautomatisch mit einem Klick ein!

---

## Manuelle Steuerung & Befehle

```bash
# Status des Dienstes anzeigen
systemctl status unifi-radius

# Live-Logs der UDM anzeigen
journalctl -u unifi-radius -f

# Dienst neu starten
systemctl restart unifi-radius

# Dienst stoppen
systemctl stop unifi-radius

# Admin-Passwort zurücksetzen (aktiviert Ersteinrichtungs-Maske im Web)
unifi-radius -reset-admin-password

# Admin-Passwort direkt über CLI vergeben
unifi-radius -set-admin-password "MeinNeuesPasswort123!"

# Deinstallation
bash /data/unifi-radius/scripts/uninstall.sh
```

---

## Lokale Entwicklung & Bauen

Voraussetzung: Go 1.27+

```bash
# Abhängigkeiten laden & Unit-Tests ausführen
go test -v ./...

# Lokales Binary bauen
go build -o bin/unifi-radius ./cmd/server

# Cross-Compile für UDM-Pro / SE (Linux ARM64)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o bin/unifi-radius-arm64 ./cmd/server
```

---

## Lizenz

Dieses Projekt ist unter der [MIT-Lizenz](LICENSE) lizenziert.
