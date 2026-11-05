package models

import (
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

// AuthType represents the authentication method used.
type AuthType string

const (
	AuthTypeMAB    AuthType = "mab"
	AuthTypeEAPTLS AuthType = "eap-tls"
	AuthTypePAP    AuthType = "pap"
)

// ClientStatus represents the status of a registered or discovered client.
type ClientStatus string

const (
	ClientStatusActive   ClientStatus = "active"
	ClientStatusDisabled ClientStatus = "disabled"
	ClientStatusPending  ClientStatus = "pending"
)

// UnknownMABPolicy defines how unknown MAC addresses are handled during MAB.
type UnknownMABPolicy string

const (
	PolicyAutoAcceptUnknown UnknownMABPolicy = "auto_accept" // Accept with default VLAN & record in DB
	PolicyRejectAndLog      UnknownMABPolicy = "reject_log"   // Reject, record in DB as pending for 1-click approve
	PolicyStrictReject      UnknownMABPolicy = "strict"       // Reject immediately
)

// Client represents a network client device (MAB) or user (802.1X/PAP).
type Client struct {
	ID              int64        `json:"id"`
	MACAddress      string       `json:"mac_address,omitempty"` // Canonical format: AA:BB:CC:DD:EE:FF
	Username        string       `json:"username,omitempty"`
	PasswordHash    string       `json:"-"`
	AuthType        AuthType     `json:"auth_type"`
	VLANID          *int         `json:"vlan_id,omitempty"` // nil means use Default Allow VLAN
	VLANName        string       `json:"vlan_name,omitempty"` // Enriched network / VLAN name from UniFi
	Status          ClientStatus `json:"status"`
	Description     string       `json:"description,omitempty"`
	UniFiName       string       `json:"unifi_name,omitempty"`
	UniFiHostname   string       `json:"unifi_hostname,omitempty"`
	UniFiVendor     string       `json:"unifi_vendor,omitempty"`
	UniFiIP         string       `json:"unifi_ip,omitempty"`
	UniFiSwitchName string       `json:"unifi_switch_name,omitempty"`
	UniFiSwitchPort string       `json:"unifi_switch_port,omitempty"`
	UniFiSwitchMAC  string       `json:"unifi_switch_mac,omitempty"`
	UniFiIsWired    bool         `json:"unifi_is_wired"`
	CertSerial      string       `json:"cert_serial,omitempty"`
	LastSeenAt      *time.Time   `json:"last_seen_at,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

// EffectiveVLAN returns the assigned VLAN ID or the fallback default VLAN.
func (c *Client) EffectiveVLAN(defaultVLAN int) int {
	if c.VLANID != nil && *c.VLANID > 0 {
		return *c.VLANID
	}
	return defaultVLAN
}

// IsRandomizedMAC returns true if this client has a valid MAC address that is locally administered (randomized/private).
func (c *Client) IsRandomizedMAC() bool {
	if c.MACAddress == "" {
		return false
	}
	return utils.IsRandomizedMAC(c.MACAddress)
}

// VLAN represents a virtual network fetched from the UniFi Network controller.
type VLAN struct {
	VLANID    int       `json:"vlan_id"`
	Name      string    `json:"name"`
	Subnet    string    `json:"subnet,omitempty"`
	Purpose   string    `json:"purpose,omitempty"`
	IsDefault bool      `json:"is_default"`
	SyncedAt  time.Time `json:"synced_at"`
}

// NASClient represents an authorized Network Access Server (UniFi Switch, AP, Gateway).
type NASClient struct {
	ID            int64     `json:"id"`
	IPOrCIDR      string    `json:"ip_or_cidr"`
	Name          string    `json:"name"`
	SharedSecret  string    `json:"shared_secret"`
	IsUniFiSynced bool      `json:"is_unifi_synced"`
	SyncedAt      time.Time `json:"synced_at"`
}

// Certificate represents a managed or issued X.509 certificate.
type Certificate struct {
	ID             int64      `json:"id"`
	SerialNumber   string     `json:"serial_number"`
	CommonName     string     `json:"common_name"`
	CertType       string     `json:"cert_type"` // 'ca', 'server', 'client'
	CertificatePEM string     `json:"certificate_pem"`
	PrivateKeyPEM  string     `json:"-"`
	ClientID       *int64     `json:"client_id,omitempty"`
	IssuedAt       time.Time  `json:"issued_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	IsRevoked      bool       `json:"is_revoked"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

// AuthLog represents an audit log entry of a RADIUS authentication attempt.
type AuthLog struct {
	ID             int64     `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ClientMAC      string    `json:"client_mac,omitempty"`
	Username       string    `json:"username,omitempty"`
	NASIP          string    `json:"nas_ip,omitempty"`
	NASPort        string    `json:"nas_port,omitempty"`
	NASName        string    `json:"nas_name,omitempty"`
	AuthType       AuthType  `json:"auth_type"`
	Status         string    `json:"status"` // 'ACCEPT', 'REJECT'
	VLANID         *int      `json:"vlan_id,omitempty"`
	Reason         string    `json:"reason"`
	LatencyMS      float64   `json:"latency_ms"`
	EnrichedName   string    `json:"enriched_name,omitempty"`
	EnrichedVendor string    `json:"enriched_vendor,omitempty"`
	RawRequest     string    `json:"raw_request,omitempty"`
	RawResponse    string    `json:"raw_response,omitempty"`
}

// SystemLog represents a general system/service event persisted for auditing.
type SystemLog struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
}

// BanInfo represents an active auto-quarantine ban.
type BanInfo struct {
	Target       string    `json:"target"` // MAC or Username
	TargetType   string    `json:"target_type"` // "mac" or "user"
	Reason       string    `json:"reason"`
	FailureCount int       `json:"failure_count"`
	BannedAt     time.Time `json:"banned_at"`
	ExpiresAt    time.Time `json:"expires_at"` // Zero time if permanent
	Permanent    bool      `json:"permanent"`
	LastNASIP    string    `json:"last_nas_ip,omitempty"`
	LastNASPort  string    `json:"last_nas_port,omitempty"`
}

// Settings represents global system configuration.
type Settings struct {
	DefaultAllowVLAN   int              `json:"default_allow_vlan"`
	UnknownMABPolicy   UnknownMABPolicy `json:"unknown_mab_policy"`
	GlobalSharedSecret string           `json:"global_shared_secret"`
	RADIUSAuthPort         int              `json:"radius_auth_port"`
	RadiusDebugMode        bool             `json:"radius_debug_mode"`
	AutoDisconnectOnChange bool             `json:"auto_disconnect_on_change"`
	WebPort                int              `json:"web_port"`

	// Intrusion Defense & Auto-Quarantine (Fail2ban)
	DefenseEnabled            bool `json:"defense_enabled"`
	DefenseMaxFailures        int  `json:"defense_max_failures"`
	DefenseWindowSeconds      int  `json:"defense_window_seconds"`
	DefenseBanDurationMinutes int  `json:"defense_ban_duration_minutes"`
	DefenseMACSpoofDetection  bool `json:"defense_mac_spoof_detection"`
	WebAdminPassword   string           `json:"-"`
	UniFiURL           string           `json:"unifi_url"`
	UniFiAuthMode      string           `json:"unifi_auth_mode"` // 'apikey' or 'credentials'
	UniFiAPIKey        string           `json:"unifi_api_key,omitempty"`
	UniFiUsername      string           `json:"unifi_username,omitempty"`
	UniFiPassword      string           `json:"-"`
	UniFiSyncInterval  int              `json:"unifi_sync_interval"` // minutes
	LogRetentionDays   int              `json:"log_retention_days"`
	MaxLogEntries      int              `json:"max_log_entries"`
	SSLEnabled         bool             `json:"ssl_enabled"`

	// Messenger, Bots & Push Notifications
	NotifyEvents            string `json:"notify_events"` // comma-separated: "pending,reject,reconnect,ca_expiry,daily"
	DailySummaryTime        string `json:"daily_summary_time"` // "08:00"
	TelegramEnabled         bool   `json:"telegram_enabled"`
	TelegramBotToken        string `json:"-"`
	TelegramChatIDs         string `json:"telegram_chat_ids"` // comma-separated
	DiscordEnabled          bool   `json:"discord_enabled"`
	DiscordBotToken         string `json:"-"`
	DiscordChannelID        string `json:"discord_channel_id"`
	PushoverEnabled         bool   `json:"pushover_enabled"`
	PushoverAPIToken        string `json:"-"`
	PushoverUserKey         string `json:"-"`
	HomeAssistantEnabled    bool   `json:"homeassistant_enabled"`
	HomeAssistantWebhookURL string `json:"homeassistant_webhook_url"`

	// Remote Backup Configuration
	RemoteBackupEnabled   bool   `json:"remote_backup_enabled"`
	RemoteBackupType      string `json:"remote_backup_type"` // 'webdav', 's3', 'local'
	RemoteBackupURL       string `json:"remote_backup_url"`
	RemoteBackupPath      string `json:"remote_backup_path"`
	RemoteBackupUsername  string `json:"remote_backup_username"`
	RemoteBackupPassword  string `json:"-"`
	RemoteBackupSchedule  string `json:"remote_backup_schedule"` // '03:00' (daily), or 'disabled'
	RemoteBackupRetention int    `json:"remote_backup_retention"` // keep last N backups

	// Automated Self-Update Configuration
	AutoUpdateEnabled  bool   `json:"auto_update_enabled"`
	AutoUpdateSchedule string `json:"auto_update_schedule"` // 'daily', 'weekly', 'monthly'
	AutoUpdateTime     string `json:"auto_update_time"`     // "03:00"
	AutoUpdateWeekday  int    `json:"auto_update_weekday"`  // 1 = Monday .. 7 = Sunday
	AutoUpdateDay      int    `json:"auto_update_day"`      // 1 .. 31
}

