package unifi

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
)

// SyncService orchestrates periodic and on-demand synchronization with UniFi Network.
type SyncService struct {
	db          *database.DB
	bus         *eventbus.Bus
	triggerChan chan struct{}
	syncMu      sync.Mutex // Ensures single-execution and allows SyncNow() callers to wait until complete
	mu          sync.Mutex // Protects status fields and bus
	isSyncing   bool
	lastSync    time.Time
	lastErr     error
}

// NewSyncService creates a new synchronizer instance.
func NewSyncService(db *database.DB, bus ...*eventbus.Bus) *SyncService {
	var b *eventbus.Bus
	if len(bus) > 0 {
		b = bus[0]
	}
	return &SyncService{
		db:          db,
		bus:         b,
		triggerChan: make(chan struct{}, 1),
	}
}

// SetBus assigns or updates the event bus.
func (s *SyncService) SetBus(b *eventbus.Bus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bus = b
}

func (s *SyncService) publishLog(level eventbus.LogLevel, msg string) {
	log.Printf("[UniFi Sync] %s", msg)
	s.mu.Lock()
	b := s.bus
	s.mu.Unlock()
	if b != nil {
		b.PublishLog(eventbus.LogEvent{
			Timestamp: time.Now().Format("15:04:05"),
			Level:     level,
			Source:    "UNIFI-SYNC",
			Message:   msg,
		})
	}
}

// TriggerSync non-blockingly signals the background worker to execute a sync immediately.
func (s *SyncService) TriggerSync() {
	select {
	case s.triggerChan <- struct{}{}:
	default:
		// Already queued
	}
}

// LastSyncStatus returns the timestamp and error of the most recent sync run.
func (s *SyncService) LastSyncStatus() (time.Time, error, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSync, s.lastErr, s.isSyncing
}

// Start runs the periodic background loop until the context is canceled.
func (s *SyncService) Start(ctx context.Context) {
	log.Println("[UniFi Sync] Starting background sync worker...")

	// Run initial sync after a short delay so the server can finish startup
	go func() {
		time.Sleep(3 * time.Second)
		s.TriggerSync()
	}()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[UniFi Sync] Background sync worker stopped.")
			return

		case <-ticker.C:
			// Read current sync interval from DB settings
			if settings, err := s.db.GetSettings(); err == nil && settings.UniFiSyncInterval > 0 {
				newInterval := time.Duration(settings.UniFiSyncInterval) * time.Minute
				ticker.Reset(newInterval)
			}
			go func() { _ = s.executeSync() }()

		case <-s.triggerChan:
			go func() { _ = s.executeSync() }()
		}
	}
}

// SyncNow executes an immediate synchronous sync run, blocking until completion.
func (s *SyncService) SyncNow() error {
	return s.executeSync()
}

func (s *SyncService) executeSync() error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	s.mu.Lock()
	s.isSyncing = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.isSyncing = false
		s.lastSync = time.Now().UTC()
		s.mu.Unlock()
	}()

	s.publishLog(eventbus.LogLevelInfo, "Synchronisation mit UniFi Network gestartet...")

	settings, err := s.db.GetSettings()
	if err != nil {
		s.setErr(fmt.Errorf("failed to load settings: %w", err))
		s.publishLog(eventbus.LogLevelError, fmt.Sprintf("Einstellungen konnten nicht geladen werden: %v", err))
		return err
	}

	// Skip if no authentication details configured yet
	if (settings.UniFiAuthMode == "apikey" && settings.UniFiAPIKey == "") ||
		(settings.UniFiAuthMode == "credentials" && (settings.UniFiUsername == "" || settings.UniFiPassword == "")) {
		s.publishLog(eventbus.LogLevelWarn, "Synchronisation übersprungen: Keine UniFi API-Zugangsdaten oder API-Key konfiguriert.")
		s.setErr(nil)
		return nil
	}

	targetURL := settings.UniFiURL
	if targetURL == "" {
		targetURL = "https://127.0.0.1"
	}
	s.publishLog(eventbus.LogLevelInfo, fmt.Sprintf("Verbindung zu UniFi Controller (%s) wird aufgebaut...", targetURL))

	client, err := NewClient(Config{
		BaseURL:  settings.UniFiURL,
		AuthMode: settings.UniFiAuthMode,
		APIKey:   settings.UniFiAPIKey,
		Username: settings.UniFiUsername,
		Password: settings.UniFiPassword,
		Site:     "default",
	})
	if err != nil {
		s.setErr(err)
		s.publishLog(eventbus.LogLevelError, fmt.Sprintf("Verbindung zum UniFi Controller fehlgeschlagen: %v", err))
		return err
	}

	// 1. Sync VLANs
	vlans, err := client.FetchNetworks()
	if err != nil {
		s.publishLog(eventbus.LogLevelError, fmt.Sprintf("Fehler beim Abrufen der VLAN-Netzwerke: %v", err))
	} else if len(vlans) > 0 {
		if err := s.db.ReplaceVLANs(vlans); err != nil {
			s.publishLog(eventbus.LogLevelError, fmt.Sprintf("Fehler beim Speichern der VLANs in SQLite: %v", err))
		} else {
			s.publishLog(eventbus.LogLevelInfo, fmt.Sprintf("%d VLAN-Netzwerke erfolgreich synchronisiert.", len(vlans)))
		}
	} else {
		s.publishLog(eventbus.LogLevelInfo, "Keine benutzerdefinierten VLANs in UniFi gefunden.")
	}

	// 2. Sync NAS Devices (Switches / APs)
	devices, err := client.FetchDevices()
	if err != nil {
		s.publishLog(eventbus.LogLevelWarn, fmt.Sprintf("Fehler beim Abrufen der UniFi Geräte (Switches/APs): %v", err))
	} else if len(devices) > 0 {
		for i := range devices {
			devices[i].SharedSecret = settings.GlobalSharedSecret
		}
		if err := s.db.ReplaceUniFiNAS(devices); err != nil {
			s.publishLog(eventbus.LogLevelError, fmt.Sprintf("Fehler beim Aktualisieren der NAS-Clients: %v", err))
		} else {
			s.publishLog(eventbus.LogLevelInfo, fmt.Sprintf("%d UniFi Switches/APs als RADIUS-Clients synchronisiert.", len(devices)))
		}
	} else {
		s.publishLog(eventbus.LogLevelInfo, "Keine UniFi Switches oder Access Points gefunden.")
	}

	// 3. Enrich MAB Clients with UniFi user/device statistics
	clientInfoMap, err := client.FetchClients()
	if err != nil {
		s.publishLog(eventbus.LogLevelWarn, fmt.Sprintf("Fehler beim Abrufen der UniFi Client-Statistiken: %v", err))
	} else if len(clientInfoMap) > 0 {
		enrichedCount := s.enrichRegisteredClients(clientInfoMap)
		s.publishLog(eventbus.LogLevelInfo, fmt.Sprintf("%d registrierte Clients mit UniFi-Geräteinfos angereichert.", enrichedCount))
	}

	s.publishLog(eventbus.LogLevelInfo, "UniFi Synchronisation erfolgreich abgeschlossen.")
	s.setErr(nil)
	return nil
}

func (s *SyncService) enrichRegisteredClients(infoMap map[string]UniFiClientInfo) int {
	clients, _, err := s.db.ListClients("", "", 1000, 0)
	if err != nil {
		return 0
	}

	enrichedCount := 0
	for _, c := range clients {
		if c.MACAddress == "" {
			continue
		}
		info, found := infoMap[c.MACAddress]
		if !found {
			continue
		}

		changed := false
		if info.Name != "" && c.UniFiName != info.Name {
			c.UniFiName = info.Name
			changed = true
		}
		if info.Hostname != "" && c.UniFiHostname != info.Hostname {
			c.UniFiHostname = info.Hostname
			changed = true
		}
		if info.Vendor != "" && c.UniFiVendor != info.Vendor {
			c.UniFiVendor = info.Vendor
			changed = true
		}
		if info.IP != "" && c.UniFiIP != info.IP {
			c.UniFiIP = info.IP
			changed = true
		}
		if info.SwitchName != "" && c.UniFiSwitchName != info.SwitchName {
			c.UniFiSwitchName = info.SwitchName
			changed = true
		}
		if info.SwitchPort != "" && c.UniFiSwitchPort != info.SwitchPort {
			c.UniFiSwitchPort = info.SwitchPort
			changed = true
		}
		if info.SwitchMAC != "" && c.UniFiSwitchMAC != info.SwitchMAC {
			c.UniFiSwitchMAC = info.SwitchMAC
			changed = true
		}
		if c.UniFiIsWired != info.IsWired {
			c.UniFiIsWired = info.IsWired
			changed = true
		}

		if changed {
			if err := s.db.UpdateClient(&c); err == nil {
				enrichedCount++
			}
		}
	}
	return enrichedCount
}

func (s *SyncService) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err
}
