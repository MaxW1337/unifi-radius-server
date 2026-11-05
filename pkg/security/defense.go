package security

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/notify"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

// AlertDispatcher dispatches alerts to messengers/webhooks.
type AlertDispatcher interface {
	Dispatch(ctx context.Context, ev notify.NotificationEvent)
}

// ClientKicker sends kick/reconnect commands to clients.
type ClientKicker interface {
	ReconnectClient(clientMAC string) error
}

// DefenseManager implements Fail2ban-style intrusion defense and auto-quarantine.
type DefenseManager struct {
	mu           sync.RWMutex
	failures     map[string][]time.Time
	activeBans   map[string]*models.BanInfo
	db           *database.DB
	bus          *eventbus.Bus
	dispatcher   AlertDispatcher
	kicker       ClientKicker

	enabled        bool
	maxFailures    int
	windowDuration time.Duration
	banDuration    time.Duration
	spoofDetection bool
}

// NewDefenseManager creates a new Intrusion Defense instance.
func NewDefenseManager(db *database.DB, bus *eventbus.Bus, dispatcher AlertDispatcher, kicker ClientKicker) *DefenseManager {
	dm := &DefenseManager{
		failures:       make(map[string][]time.Time),
		activeBans:     make(map[string]*models.BanInfo),
		db:             db,
		bus:            bus,
		dispatcher:     dispatcher,
		kicker:         kicker,
		enabled:        true,
		maxFailures:    5,
		windowDuration: 60 * time.Second,
		banDuration:    15 * time.Minute,
		spoofDetection: true,
	}

	if db != nil {
		if s, err := db.GetSettings(); err == nil {
			dm.ApplySettings(s)
		}
	}

	return dm
}

// ApplySettings updates the runtime defense parameters from system settings.
func (dm *DefenseManager) ApplySettings(s *models.Settings) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.enabled = s.DefenseEnabled
	if s.DefenseMaxFailures > 0 {
		dm.maxFailures = s.DefenseMaxFailures
	}
	if s.DefenseWindowSeconds > 0 {
		dm.windowDuration = time.Duration(s.DefenseWindowSeconds) * time.Second
	}
	if s.DefenseBanDurationMinutes > 0 {
		dm.banDuration = time.Duration(s.DefenseBanDurationMinutes) * time.Minute
	}
	dm.spoofDetection = s.DefenseMACSpoofDetection
}

// SetKicker updates the client kicker (e.g. after server initialization).
func (dm *DefenseManager) SetKicker(kicker ClientKicker) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.kicker = kicker
}

// SetDispatcher updates the alert dispatcher.
func (dm *DefenseManager) SetDispatcher(dispatcher AlertDispatcher) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.dispatcher = dispatcher
}

// RecordFailure registers a failed authentication and triggers a quarantine ban if the threshold is reached.
func (dm *DefenseManager) RecordFailure(mac, username, nasIP, nasPort, reason string) *models.BanInfo {
	dm.mu.Lock()
	if !dm.enabled {
		dm.mu.Unlock()
		return nil
	}

	now := time.Now()
	target, targetType := dm.resolveTarget(mac, username)
	if target == "" {
		dm.mu.Unlock()
		return nil
	}

	// Check if already banned
	if ban, exists := dm.activeBans[target]; exists {
		if ban.Permanent || now.Before(ban.ExpiresAt) {
			dm.mu.Unlock()
			return ban
		}
		delete(dm.activeBans, target)
	}

	// Add timestamp and filter out timestamps older than the sliding window
	windowCutoff := now.Add(-dm.windowDuration)
	var fresh []time.Time
	for _, t := range dm.failures[target] {
		if t.After(windowCutoff) {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, now)
	dm.failures[target] = fresh

	failCount := len(fresh)
	if failCount < dm.maxFailures {
		dm.mu.Unlock()
		return nil
	}

	// Threshold exceeded: Issue Quarantine Ban!
	delete(dm.failures, target)
	expiresAt := now.Add(dm.banDuration)
	ban := &models.BanInfo{
		Target:       target,
		TargetType:   targetType,
		Reason:       fmt.Sprintf("%d Fehlversuche in %ds: %s", failCount, int(dm.windowDuration.Seconds()), reason),
		FailureCount: failCount,
		BannedAt:     now,
		ExpiresAt:    expiresAt,
		Permanent:    false,
		LastNASIP:    nasIP,
		LastNASPort:  nasPort,
	}
	dm.activeBans[target] = ban
	dispatcher := dm.dispatcher
	kicker := dm.kicker
	bus := dm.bus
	dm.mu.Unlock()

	// 1. Log to eventbus
	if bus != nil {
		bus.PublishLog(eventbus.LogEvent{
			Timestamp: time.Now().Format("15:04:05"),
			Level:     eventbus.LogLevelError,
			Source:    "SECURITY",
			Message:   fmt.Sprintf("[Auto-Quarantäne] %s (%s) für %v gesperrt (%s)", target, targetType, dm.banDuration, ban.Reason),
		})
	}

	// 2. Immediate Disconnect/Kick
	if kicker != nil && targetType == "mac" {
		go func(m string) {
			_ = kicker.ReconnectClient(m)
		}(target)
	}

	// 3. Dispatch Security Alert to Telegram / Notifiers
	if dispatcher != nil {
		go func() {
			ev := notify.NotificationEvent{
				Type:        notify.EventQuarantineBan,
				Title:       "Auto-Quarantäne aktiv!",
				Message:     fmt.Sprintf("%d wiederholte Fehlversuche erkannt. Gerät/Konto wurde für %d Minuten gesperrt.", failCount, int(dm.banDuration.Minutes())),
				ClientMAC:   mac,
				Username:    username,
				Timestamp:   now,
			}
			dispatcher.Dispatch(context.Background(), ev)
		}()
	}

	return ban
}

// RecordSuccess clears failure counts upon successful authentication.
func (dm *DefenseManager) RecordSuccess(mac, username string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if target, _ := dm.resolveTarget(mac, username); target != "" {
		delete(dm.failures, target)
	}
}

// IsBanned checks whether a MAC or username is currently under an active quarantine ban.
func (dm *DefenseManager) IsBanned(mac, username string) (bool, *models.BanInfo) {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if !dm.enabled {
		return false, nil
	}

	now := time.Now()
	targets := []string{}
	if norm, err := utils.NormalizeMAC(mac); err == nil && norm != "" {
		targets = append(targets, norm)
	}
	if user := strings.TrimSpace(username); user != "" {
		targets = append(targets, user)
	}

	for _, target := range targets {
		if ban, exists := dm.activeBans[target]; exists {
			// Check expiration
			if !ban.Permanent && now.After(ban.ExpiresAt) {
				delete(dm.activeBans, target)
				if dm.bus != nil {
					dm.bus.PublishLog(eventbus.LogEvent{
						Timestamp: time.Now().Format("15:04:05"),
						Level:     eventbus.LogLevelInfo,
						Source:    "SECURITY",
						Message:   fmt.Sprintf("[Auto-Unban] Sperre für %s ist abgelaufen. Client entsperrt.", target),
					})
				}
				continue
			}
			return true, ban
		}
	}

	return false, nil
}

// Unban immediately releases a target from quarantine ban.
func (dm *DefenseManager) Unban(target string) bool {
	cleanTarget := strings.TrimSpace(target)
	if norm, err := utils.NormalizeMAC(cleanTarget); err == nil {
		cleanTarget = norm
	}

	dm.mu.Lock()
	ban, exists := dm.activeBans[cleanTarget]
	if !exists {
		dm.mu.Unlock()
		return false
	}
	delete(dm.activeBans, cleanTarget)
	delete(dm.failures, cleanTarget)
	kicker := dm.kicker
	bus := dm.bus
	dm.mu.Unlock()

	if bus != nil {
		bus.PublishLog(eventbus.LogEvent{
			Timestamp: time.Now().Format("15:04:05"),
			Level:     eventbus.LogLevelInfo,
			Source:    "SECURITY",
			Message:   fmt.Sprintf("[Manuell Entsperrt] Quarantäne-Sperre für %s wurde aufgehoben.", cleanTarget),
		})
	}

	if kicker != nil && ban.TargetType == "mac" {
		go func(m string) {
			_ = kicker.ReconnectClient(m)
		}(cleanTarget)
	}

	return true
}

// PermanentBan locks a target permanently.
func (dm *DefenseManager) PermanentBan(target string) bool {
	cleanTarget := strings.TrimSpace(target)
	if norm, err := utils.NormalizeMAC(cleanTarget); err == nil {
		cleanTarget = norm
	}

	dm.mu.Lock()
	ban, exists := dm.activeBans[cleanTarget]
	if !exists {
		ban = &models.BanInfo{
			Target:     cleanTarget,
			TargetType: "mac",
			BannedAt:   time.Now(),
		}
		if !utils.IsValidMAC(cleanTarget) {
			ban.TargetType = "user"
		}
	}
	ban.Permanent = true
	ban.ExpiresAt = time.Time{}
	ban.Reason = "Dauerhaft durch Administrator gesperrt"
	dm.activeBans[cleanTarget] = ban
	kicker := dm.kicker
	bus := dm.bus
	db := dm.db
	dm.mu.Unlock()

	// Update DB client status if it's a MAC
	if db != nil && ban.TargetType == "mac" {
		if c, err := db.GetClientByMAC(cleanTarget); err == nil && c != nil {
			c.Status = models.ClientStatusDisabled
			_ = db.UpdateClient(c)
		}
	}

	if bus != nil {
		bus.PublishLog(eventbus.LogEvent{
			Timestamp: time.Now().Format("15:04:05"),
			Level:     eventbus.LogLevelWarn,
			Source:    "SECURITY",
			Message:   fmt.Sprintf("[Dauerhafte Sperre] %s wurde dauerhaft blockiert.", cleanTarget),
		})
	}

	if kicker != nil && ban.TargetType == "mac" {
		go func(m string) {
			_ = kicker.ReconnectClient(m)
		}(cleanTarget)
	}

	return true
}

// ListActiveBans returns all currently active bans, purging expired ones.
func (dm *DefenseManager) ListActiveBans() []*models.BanInfo {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	now := time.Now()
	var result []*models.BanInfo
	for target, ban := range dm.activeBans {
		if !ban.Permanent && now.After(ban.ExpiresAt) {
			delete(dm.activeBans, target)
			continue
		}
		result = append(result, ban)
	}
	return result
}

// IsSpoofDetectionEnabled returns whether MAC spoofing checks are active.
func (dm *DefenseManager) IsSpoofDetectionEnabled() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.enabled && dm.spoofDetection
}

func (dm *DefenseManager) resolveTarget(mac, username string) (string, string) {
	if mac != "" {
		if norm, err := utils.NormalizeMAC(mac); err == nil {
			return norm, "mac"
		}
	}
	if u := strings.TrimSpace(username); u != "" {
		return u, "user"
	}
	return "", ""
}

