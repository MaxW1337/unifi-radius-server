package database

import (
	"strconv"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// GetSettings retrieves all system settings as a strongly-typed struct.
func (db *DB) GetSettings() (*models.Settings, error) {
	rows, err := db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sMap := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		sMap[k] = v
	}

	defVLAN, _ := strconv.Atoi(sMap["default_allow_vlan"])
	if defVLAN == 0 {
		defVLAN = 1
	}

	radPort, _ := strconv.Atoi(sMap["radius_auth_port"])
	if radPort == 0 {
		radPort = 1812
	}

	webPort, _ := strconv.Atoi(sMap["web_port"])
	if webPort == 0 {
		webPort = 9182
	}

	syncInterval, _ := strconv.Atoi(sMap["unifi_sync_interval"])
	if syncInterval <= 0 {
		syncInterval = 5
	}

	retention, _ := strconv.Atoi(sMap["log_retention_days"])
	if retention <= 0 {
		retention = 30
	}

	maxLogs, _ := strconv.Atoi(sMap["max_log_entries"])
	if maxLogs <= 0 {
		maxLogs = 10000
	}

	policy := models.UnknownMABPolicy(sMap["unknown_mab_policy"])
	if policy == "" {
		policy = models.PolicyRejectAndLog
	}

	notifyEvents := sMap["notify_events"]
	if notifyEvents == "" {
		notifyEvents = "pending,reject,reconnect,ca_expiry,daily"
	}
	dailyTime := sMap["daily_summary_time"]
	if dailyTime == "" {
		dailyTime = "08:00"
	}

	remoteBackupType := sMap["remote_backup_type"]
	if remoteBackupType == "" {
		remoteBackupType = "webdav"
	}
	remoteBackupSchedule := sMap["remote_backup_schedule"]
	if remoteBackupSchedule == "" {
		remoteBackupSchedule = "03:00"
	}
	remoteBackupRetention, _ := strconv.Atoi(sMap["remote_backup_retention"])
	if remoteBackupRetention <= 0 {
		remoteBackupRetention = 7
	}

	autoUpdateSchedule := sMap["auto_update_schedule"]
	if autoUpdateSchedule == "" {
		autoUpdateSchedule = "weekly"
	}
	autoUpdateTime := sMap["auto_update_time"]
	if autoUpdateTime == "" {
		autoUpdateTime = "03:00"
	}
	autoUpdateWeekday, _ := strconv.Atoi(sMap["auto_update_weekday"])
	if autoUpdateWeekday < 1 || autoUpdateWeekday > 7 {
		autoUpdateWeekday = 1 // Monday
	}
	autoUpdateDay, _ := strconv.Atoi(sMap["auto_update_day"])
	if autoUpdateDay < 1 || autoUpdateDay > 31 {
		autoUpdateDay = 1
	}

	autoDisconnect := true
	if val, exists := sMap["auto_disconnect_on_change"]; exists && val == "false" {
		autoDisconnect = false
	}

	return &models.Settings{
		DefaultAllowVLAN:       defVLAN,
		UnknownMABPolicy:       policy,
		GlobalSharedSecret:     sMap["global_shared_secret"],
		RADIUSAuthPort:         radPort,
		RadiusDebugMode:        sMap["radius_debug_mode"] == "true",
		AutoDisconnectOnChange: autoDisconnect,
		WebPort:                webPort,
		WebAdminPassword:   sMap["web_admin_password"],
		UniFiURL:           sMap["unifi_url"],
		UniFiAuthMode:      sMap["unifi_auth_mode"],
		UniFiAPIKey:        sMap["unifi_api_key"],
		UniFiUsername:      sMap["unifi_username"],
		UniFiPassword:      sMap["unifi_password"],
		UniFiSyncInterval:  syncInterval,
		LogRetentionDays:   retention,
		MaxLogEntries:      maxLogs,
		SSLEnabled:         sMap["ssl_enabled"] == "true",

		NotifyEvents:            notifyEvents,
		DailySummaryTime:        dailyTime,
		TelegramEnabled:         sMap["telegram_enabled"] == "true",
		TelegramBotToken:        sMap["telegram_bot_token"],
		TelegramChatIDs:         sMap["telegram_chat_ids"],
		DiscordEnabled:          sMap["discord_enabled"] == "true",
		DiscordBotToken:         sMap["discord_bot_token"],
		DiscordChannelID:        sMap["discord_channel_id"],
		PushoverEnabled:         sMap["pushover_enabled"] == "true",
		PushoverAPIToken:        sMap["pushover_api_token"],
		PushoverUserKey:         sMap["pushover_user_key"],
		HomeAssistantEnabled:    sMap["homeassistant_enabled"] == "true",
		HomeAssistantWebhookURL: sMap["homeassistant_webhook_url"],

		RemoteBackupEnabled:   sMap["remote_backup_enabled"] == "true",
		RemoteBackupType:      remoteBackupType,
		RemoteBackupURL:       sMap["remote_backup_url"],
		RemoteBackupPath:      sMap["remote_backup_path"],
		RemoteBackupUsername:  sMap["remote_backup_username"],
		RemoteBackupPassword:  sMap["remote_backup_password"],
		RemoteBackupSchedule:  remoteBackupSchedule,
		RemoteBackupRetention: remoteBackupRetention,

		AutoUpdateEnabled:  sMap["auto_update_enabled"] == "true",
		AutoUpdateSchedule: autoUpdateSchedule,
		AutoUpdateTime:     autoUpdateTime,
		AutoUpdateWeekday:  autoUpdateWeekday,
		AutoUpdateDay:      autoUpdateDay,
	}, nil
}

// UpdateSettings persists settings key-value pairs.
func (db *DB) UpdateSettings(s *models.Settings) error {
	pairs := map[string]string{
		"default_allow_vlan":   strconv.Itoa(s.DefaultAllowVLAN),
		"unknown_mab_policy":   string(s.UnknownMABPolicy),
		"global_shared_secret": s.GlobalSharedSecret,
		"radius_auth_port":          strconv.Itoa(s.RADIUSAuthPort),
		"radius_debug_mode":         strconv.FormatBool(s.RadiusDebugMode),
		"auto_disconnect_on_change": strconv.FormatBool(s.AutoDisconnectOnChange),
		"web_port":                  strconv.Itoa(s.WebPort),
		"unifi_url":            s.UniFiURL,
		"unifi_auth_mode":      s.UniFiAuthMode,
		"unifi_api_key":        s.UniFiAPIKey,
		"unifi_username":       s.UniFiUsername,
		"unifi_sync_interval":  strconv.Itoa(s.UniFiSyncInterval),
		"log_retention_days":   strconv.Itoa(s.LogRetentionDays),
		"max_log_entries":      strconv.Itoa(s.MaxLogEntries),
		"ssl_enabled":          strconv.FormatBool(s.SSLEnabled),

		"notify_events":            s.NotifyEvents,
		"daily_summary_time":       s.DailySummaryTime,
		"telegram_enabled":         strconv.FormatBool(s.TelegramEnabled),
		"telegram_chat_ids":        s.TelegramChatIDs,
		"discord_enabled":          strconv.FormatBool(s.DiscordEnabled),
		"discord_channel_id":       s.DiscordChannelID,
		"pushover_enabled":         strconv.FormatBool(s.PushoverEnabled),
		"homeassistant_enabled":    strconv.FormatBool(s.HomeAssistantEnabled),
		"homeassistant_webhook_url": s.HomeAssistantWebhookURL,

		"remote_backup_enabled":   strconv.FormatBool(s.RemoteBackupEnabled),
		"remote_backup_type":      s.RemoteBackupType,
		"remote_backup_url":       s.RemoteBackupURL,
		"remote_backup_path":      s.RemoteBackupPath,
		"remote_backup_username":  s.RemoteBackupUsername,
		"remote_backup_schedule":  s.RemoteBackupSchedule,
		"remote_backup_retention": strconv.Itoa(s.RemoteBackupRetention),

		"auto_update_enabled":  strconv.FormatBool(s.AutoUpdateEnabled),
		"auto_update_schedule": s.AutoUpdateSchedule,
		"auto_update_time":     s.AutoUpdateTime,
		"auto_update_weekday":  strconv.Itoa(s.AutoUpdateWeekday),
		"auto_update_day":      strconv.Itoa(s.AutoUpdateDay),
	}

	if s.RemoteBackupPassword != "" {
		pairs["remote_backup_password"] = s.RemoteBackupPassword
	}

	if s.TelegramBotToken != "" {
		pairs["telegram_bot_token"] = s.TelegramBotToken
	}
	if s.DiscordBotToken != "" {
		pairs["discord_bot_token"] = s.DiscordBotToken
	}
	if s.PushoverAPIToken != "" {
		pairs["pushover_api_token"] = s.PushoverAPIToken
	}
	if s.PushoverUserKey != "" {
		pairs["pushover_user_key"] = s.PushoverUserKey
	}

	if s.WebAdminPassword != "" {
		pairs["web_admin_password"] = s.WebAdminPassword
	}
	if s.UniFiPassword != "" {
		pairs["unifi_password"] = s.UniFiPassword
	}

	now := time.Now().UTC()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range pairs {
		if _, err := stmt.Exec(k, v, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ResetAdminPassword removes or clears the admin password, re-enabling the initial setup screen.
func (db *DB) ResetAdminPassword() error {
	_, err := db.Exec("DELETE FROM settings WHERE key = 'web_admin_password'")
	return err
}

// SetAdminPassword sets or updates the hashed admin password in the database.
func (db *DB) SetAdminPassword(hashedPassword string) error {
	_, err := db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('web_admin_password', ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, hashedPassword, time.Now().UTC())
	return err
}

// SetRadiusDebugMode enables or disables raw RADIUS packet debugging in settings.
func (db *DB) SetRadiusDebugMode(enabled bool) error {
	val := strconv.FormatBool(enabled)
	_, err := db.Exec(`
		INSERT INTO settings (key, value, updated_at) 
		VALUES ('radius_debug_mode', ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`, val, time.Now().UTC())
	return err
}


