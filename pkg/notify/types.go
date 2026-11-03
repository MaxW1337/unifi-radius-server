package notify

import (
	"time"
)

// Supported event types
const (
	EventPendingDevice = "pending"
	EventAuthReject    = "reject"
	EventReconnect     = "reconnect"
	EventCAExpiry      = "ca_expiry"
	EventDailySummary  = "daily"
)

// ActionButton represents an interactive button for Telegram and Discord.
type ActionButton struct {
	Label    string
	CustomID string
	Style    string // e.g. "primary", "danger", "success"
}

// NotificationEvent represents an alert to be dispatched to notification channels.
type NotificationEvent struct {
	Type           string         `json:"type"`
	Title          string         `json:"title"`
	Message        string         `json:"message"`
	ClientMAC      string         `json:"client_mac,omitempty"`
	Username       string         `json:"username,omitempty"`
	VLANID         *int           `json:"vlan_id,omitempty"`
	VLANName       string         `json:"vlan_name,omitempty"`
	SwitchName     string         `json:"switch_name,omitempty"`
	SwitchPort     string         `json:"switch_port,omitempty"`
	EnrichedVendor string         `json:"vendor,omitempty"`
	EnrichedName   string         `json:"name,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
	Buttons        []ActionButton `json:"buttons,omitempty"`
}

