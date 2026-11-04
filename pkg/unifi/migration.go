package unifi

import (
	"fmt"
	"strings"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

// MigrationReport provides details about the migrated accounts and UniFi configuration adjustments.
type MigrationReport struct {
	BuiltinRadiusDetected bool     `json:"builtin_radius_detected"`
	BuiltinRadiusDisabled bool     `json:"builtin_radius_disabled"`
	TotalAccountsFound    int      `json:"total_accounts_found"`
	MABDevicesMigrated    int      `json:"mab_devices_migrated"`
	UsersMigrated         int      `json:"users_migrated"`
	SecretMigrated        bool     `json:"secret_migrated"`
	ProfileUpdated        bool     `json:"profile_updated"`
	ProfileName           string   `json:"profile_name"`
	Messages              []string `json:"messages"`
}

// CheckBuiltinRadiusStatus inspects whether the built-in UniFi RADIUS server is enabled and counts local accounts.
func CheckBuiltinRadiusStatus(client *Client) (bool, string, int, error) {
	setting, err := client.GetRadiusSetting()
	if err != nil {
		return false, "", 0, err
	}

	secret := ""
	if setting != nil {
		secret = setting.Secret
	}

	accounts, err := client.FetchAccounts()
	count := 0
	if err == nil {
		count = len(accounts)
	}

	enabled := setting != nil && setting.Enabled
	return enabled, secret, count, nil
}

// MigrateBuiltinRadius performs the migration of local credentials and configures UniFi Network.
func MigrateBuiltinRadius(client *Client, db *database.DB, disableBuiltin, updateProfile bool) (*MigrationReport, error) {
	report := &MigrationReport{
		Messages: make([]string, 0),
	}

	settings, err := db.GetSettings()
	if err != nil {
		return nil, fmt.Errorf("failed to load settings: %w", err)
	}

	// 1. Check UniFi RADIUS Setting
	radiusSetting, err := client.GetRadiusSetting()
	if err == nil && radiusSetting != nil {
		report.BuiltinRadiusDetected = radiusSetting.Enabled

		// If UniFi had a configured secret, migrate it if user hasn't set a custom one
		if radiusSetting.Secret != "" {
			if settings.GlobalSharedSecret == "radius_secret_changeme" || settings.GlobalSharedSecret == "" {
				settings.GlobalSharedSecret = radiusSetting.Secret
				_ = db.UpdateSettings(settings)
				report.SecretMigrated = true
				report.Messages = append(report.Messages, "Globales Shared Secret aus UniFi übernommen.")
			}
		}
	}

	// 2. Fetch Accounts (Local Credentials)
	accounts, err := client.FetchAccounts()
	if err != nil {
		report.Messages = append(report.Messages, fmt.Sprintf("Warnung: Lokale Accounts konnten nicht geladen werden: %v", err))
	} else {
		report.TotalAccountsFound = len(accounts)

		for _, acc := range accounts {
			var vlanID *int
			if acc.VLAN > 0 {
				v := acc.VLAN
				vlanID = &v
			}

			// Check if name is MAC address (MAB client)
			if utils.IsValidMAC(acc.Name) {
				normMAC, _ := utils.NormalizeMAC(acc.Name)
				existing, _ := db.GetClientByMAC(normMAC)

				if existing != nil {
					existing.VLANID = vlanID
					existing.Description = "Migriert aus UniFi Built-in RADIUS"
					if err := db.UpdateClient(existing); err == nil {
						report.MABDevicesMigrated++
					}
				} else {
					c := &models.Client{
						MACAddress:  normMAC,
						AuthType:    models.AuthTypeMAB,
						VLANID:      vlanID,
						Status:      models.ClientStatusActive,
						Description: "Migriert aus UniFi Built-in RADIUS",
					}
					if err := db.CreateClient(c); err == nil {
						report.MABDevicesMigrated++
					}
				}
			} else {
				// Regular username / password account
				username := strings.TrimSpace(acc.Name)
				if username == "" {
					continue
				}

				passHash := ""
				if acc.Password != "" {
					h, err := bcrypt.GenerateFromPassword([]byte(acc.Password), bcrypt.DefaultCost)
					if err == nil {
						passHash = string(h)
					}
				}

				existing, _ := db.GetClientByUsername(username)
				if existing != nil {
					existing.PasswordHash = passHash
					existing.VLANID = vlanID
					existing.Description = "Migriert aus UniFi Built-in RADIUS"
					if err := db.UpdateClient(existing); err == nil {
						report.UsersMigrated++
					}
				} else {
					c := &models.Client{
						Username:     username,
						PasswordHash: passHash,
						AuthType:     models.AuthTypePAP,
						VLANID:       vlanID,
						Status:       models.ClientStatusActive,
						Description:  "Migriert aus UniFi Built-in RADIUS",
					}
					if err := db.CreateClient(c); err == nil {
						report.UsersMigrated++
					}
				}
			}
		}

		report.Messages = append(report.Messages, fmt.Sprintf("%d MAB-Geräte und %d Benutzerkonten erfolgreich nach SQLite migriert.",
			report.MABDevicesMigrated, report.UsersMigrated))
	}

	// 3. Update / Create UniFi RADIUS Profile pointing to this server & switch WLANs
	var targetProfileID string
	if updateProfile || disableBuiltin {
		profileName := "UDM-Internal-RADIUS"
		serverSecret := settings.GlobalSharedSecret
		serverPort := settings.RADIUSAuthPort

		profile, err := client.CreateOrUpdateRadiusProfile(profileName, "127.0.0.1", serverPort, serverSecret)
		if err != nil {
			report.Messages = append(report.Messages, fmt.Sprintf("Warnung: UniFi RADIUS-Profil '%s' konnte nicht automatisch aktualisiert werden: %v", profileName, err))
		} else {
			report.ProfileUpdated = true
			report.ProfileName = profile.Name
			targetProfileID = profile.ID
			report.Messages = append(report.Messages, fmt.Sprintf("UniFi RADIUS-Profil '%s' (127.0.0.1:%d, VLAN Support: Aktiv) erfolgreich erstellt/aktualisiert.", profile.Name, serverPort))

			// Automatically switch any and all WLANs using RADIUS / Default profile to the new profile
			migratedWLANs, mwErr := client.MigrateAllRadiusWLANs(profile.ID)
			if mwErr != nil {
				report.Messages = append(report.Messages, fmt.Sprintf("Warnung beim Migrieren der WLANs: %v", mwErr))
			} else if len(migratedWLANs) > 0 {
				for _, wName := range migratedWLANs {
					report.Messages = append(report.Messages, fmt.Sprintf("WLAN '%s' (Enterprise / MAB) erfolgreich von Built-in RADIUS ('Default') auf Profil '%s' umgestellt.", wName, profile.Name))
				}
			} else {
				report.Messages = append(report.Messages, "Alle RADIUS-WLANs sind bereits auf 'UDM-Internal-RADIUS' umgestellt.")
			}

			// Automatically update Global Switch 802.1X Control (Credential Source: RADIUS Profile, Profile: UDM-Internal-RADIUS, Fallback: LAN)
			fallbackID, _ := client.GetDefaultLANNetworkID()
			if sErr := client.UpdateGlobalSwitch8021X(profile.ID, fallbackID); sErr == nil {
				report.Messages = append(report.Messages, fmt.Sprintf("UniFi 802.1X Switch-Control erfolgreich auf RADIUS-Profil '%s' (Fallback: LAN) umgestellt.", profile.Name))
			}
		}
	}

	// 4. Disable built-in RADIUS server if requested (to release UDP port 1812)
	if disableBuiltin && report.BuiltinRadiusDetected {
		if err := client.DisableBuiltinRadius(targetProfileID); err != nil {
			report.Messages = append(report.Messages, fmt.Sprintf("Warnung: Built-in RADIUS konnte nicht automatisch deaktiviert werden: %v", err))
		} else {
			report.BuiltinRadiusDisabled = true
			report.Messages = append(report.Messages, "Integrierter UniFi RADIUS-Dienst wurde erfolgreich deaktiviert (UDP-Port 1812 freigegeben).")
		}
	}

	return report, nil
}

