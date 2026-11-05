package notify

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/unifi"
)

// Service is the unified notification and bot management service.
type Service struct {
	db          *database.DB
	bus         *eventbus.Bus
	syncSvc     *unifi.SyncService
	dedup       *Deduplicator
	tgClient    *TelegramClient
	dcClient    *DiscordClient
	poClient    *PushoverClient
	haClient    *HomeAssistantClient
	dailyWorker *DailyWorker
	queue       chan NotificationEvent
	secMgr      SecurityManager
	mu          sync.RWMutex
	ctx         context.Context
	tgCancel    context.CancelFunc
	dcCancel    context.CancelFunc
}

// NewService creates a new notification service.
func NewService(db *database.DB, bus *eventbus.Bus, syncSvc *unifi.SyncService) *Service {
	s := &Service{
		db:      db,
		bus:     bus,
		syncSvc: syncSvc,
		dedup:   NewDeduplicator(5 * time.Minute),
		queue:   make(chan NotificationEvent, 256),
	}
	s.dailyWorker = NewDailyWorker(db, s)
	return s
}

// Reload re-reads configuration from SQLite and reinitializes bot and webhook clients.
func (s *Service) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	settings, err := s.db.GetSettings()
	if err != nil {
		return err
	}

	// Telegram
	if s.tgCancel != nil {
		s.tgCancel()
		s.tgCancel = nil
	}
	if settings.TelegramEnabled && settings.TelegramBotToken != "" {
		tg, err := NewTelegramClient(settings.TelegramBotToken, settings.TelegramChatIDs, s.db, s.syncSvc)
		if err == nil {
			tg.SetSecurityManager(s.secMgr)
			s.tgClient = tg
			if s.ctx != nil {
				tgCtx, tgCancel := context.WithCancel(s.ctx)
				s.tgCancel = tgCancel
				go tg.StartPolling(tgCtx)
			}
		}
	} else {
		s.tgClient = nil
	}

	// Discord
	if s.dcCancel != nil {
		s.dcCancel()
		s.dcCancel = nil
	}
	if s.dcClient != nil {
		s.dcClient.Stop()
	}
	if settings.DiscordEnabled && settings.DiscordBotToken != "" && settings.DiscordChannelID != "" {
		dc, err := NewDiscordClient(settings.DiscordBotToken, settings.DiscordChannelID, s.db, s.syncSvc)
		if err == nil {
			s.dcClient = dc
			if s.ctx != nil {
				dcCtx, dcCancel := context.WithCancel(s.ctx)
				s.dcCancel = dcCancel
				go dc.StartGateway(dcCtx)
			}
		}
	} else {
		s.dcClient = nil
	}

	// Pushover
	if settings.PushoverEnabled && settings.PushoverAPIToken != "" && settings.PushoverUserKey != "" {
		po, err := NewPushoverClient(settings.PushoverAPIToken, settings.PushoverUserKey)
		if err == nil {
			s.poClient = po
		}
	} else {
		s.poClient = nil
	}

	// Home Assistant
	if settings.HomeAssistantEnabled && settings.HomeAssistantWebhookURL != "" {
		ha, err := NewHomeAssistantClient(settings.HomeAssistantWebhookURL)
		if err == nil {
			s.haClient = ha
		}
	} else {
		s.haClient = nil
	}

	return nil
}

// Start launches the background worker goroutines.
func (s *Service) Start(ctx context.Context) {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()

	_ = s.Reload()

	// Start daily summary and CA expiration check worker
	go s.dailyWorker.Start(ctx)

	// Start event listener for RADIUS auth logs
	go s.listenAuthEvents(ctx)

	// Start queue consumer
	go s.processQueue(ctx)
}

func (s *Service) listenAuthEvents(ctx context.Context) {
	if s.bus == nil {
		return
	}

	authChan, unsubAuth := s.bus.SubscribeAuth()
	defer unsubAuth()

	for {
		select {
		case <-ctx.Done():
			return
		case a, ok := <-authChan:
			if !ok {
				return
			}
			s.handleAuthEvent(ctx, a)
		}
	}
}

func (s *Service) handleAuthEvent(ctx context.Context, a models.AuthLog) {
	settings, err := s.db.GetSettings()
	if err != nil || settings == nil {
		return
	}

	allowedEvents := strings.ToLower(settings.NotifyEvents)

	// Check if this was a pending client rejection or auto-discovery
	if strings.Contains(strings.ToLower(a.Reason), "pending") || strings.Contains(strings.ToLower(a.Reason), "unknown mac") {
		if strings.Contains(allowedEvents, EventPendingDevice) {
			key := fmt.Sprintf("pending:%s", a.ClientMAC)
			if s.dedup.ShouldSend(key) {
				ev := NotificationEvent{
					Type:           EventPendingDevice,
					Title:          "Neues Gerät erkannt (Pending Approval)",
					Message:        fmt.Sprintf("Gerät %s an %s:%s fordert Zugriff an.", a.ClientMAC, a.NASIP, a.NASPort),
					ClientMAC:      a.ClientMAC,
					Username:       a.Username,
					VLANID:         a.VLANID,
					EnrichedVendor: a.EnrichedVendor,
					EnrichedName:   a.EnrichedName,
					Timestamp:      a.Timestamp,
				}
				s.Dispatch(ctx, ev)
			}
		}
		return
	}

	// Check if REJECT
	if a.Status == "REJECT" && strings.Contains(allowedEvents, EventAuthReject) {
		ident := a.ClientMAC
		if ident == "" {
			ident = a.Username
		}
		key := fmt.Sprintf("reject:%s", ident)
		if s.dedup.ShouldSend(key) {
			ev := NotificationEvent{
				Type:           EventAuthReject,
				Title:          "RADIUS Authentifizierung ABGELEHNT",
				Message:        fmt.Sprintf("Anfrage von '%s' wurde abgewiesen: %s", ident, a.Reason),
				ClientMAC:      a.ClientMAC,
				Username:       a.Username,
				EnrichedVendor: a.EnrichedVendor,
				Timestamp:      a.Timestamp,
			}
			s.Dispatch(ctx, ev)
		}
	}
}

// Dispatch enqueues a notification event for asynchronous non-blocking broadcast.
func (s *Service) Dispatch(ctx context.Context, ev NotificationEvent) {
	select {
	case s.queue <- ev:
	default:
		// Queue full: drop oldest or warn to avoid blocking RADIUS workers
		log.Printf("[Notify] Warning: Notification queue full, dropping alert '%s'", ev.Title)
	}
}

func (s *Service) processQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.queue:
			s.broadcastEvent(ctx, ev)
		}
	}
}

func (s *Service) broadcastEvent(ctx context.Context, ev NotificationEvent) {
	s.mu.RLock()
	tg := s.tgClient
	dc := s.dcClient
	po := s.poClient
	ha := s.haClient
	s.mu.RUnlock()

	// 1. Telegram
	if tg != nil {
		go func() {
			if err := tg.Broadcast(ctx, ev); err != nil {
				log.Printf("[Telegram] Broadcast error: %v", err)
			}
		}()
	}

	// 2. Discord
	if dc != nil {
		go func() {
			if err := dc.SendEmbedMessage(ctx, ev); err != nil {
				log.Printf("[Discord] Send message error: %v", err)
			}
		}()
	}

	// 3. Pushover
	if po != nil {
		go func() {
			priority := 0
			if ev.Type == EventPendingDevice || ev.Type == EventAuthReject {
				priority = 1
			}
			clickURL := ""
			if ev.ClientMAC != "" {
				clickURL = fmt.Sprintf("http://localhost:9182/clients?q=%s", ev.ClientMAC)
			}
			if err := po.SendMessage(ctx, ev.Title, ev.Message, priority, clickURL); err != nil {
				log.Printf("[Pushover] Send error: %v", err)
			}
		}()
	}

	// 4. Home Assistant
	if ha != nil {
		go func() {
			if err := ha.SendEvent(ctx, ev); err != nil {
				log.Printf("[Home Assistant] Webhook error: %v", err)
			}
		}()
	}
}

// SendTest sends an immediate test notification to a specific provider.
func (s *Service) SendTest(ctx context.Context, provider string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ev := NotificationEvent{
		Type:      "test",
		Title:     "UniFi RADIUS Test-Benachrichtigung",
		Message:   fmt.Sprintf("Verbindungstest für '%s' erfolgreich! System ist online und einsatzbereit.", provider),
		Timestamp: time.Now(),
	}

	switch strings.ToLower(provider) {
	case "telegram":
		if s.tgClient == nil {
			return fmt.Errorf("telegram bot ist nicht aktiviert oder nicht konfiguriert")
		}
		return s.tgClient.Broadcast(ctx, ev)

	case "discord":
		if s.dcClient == nil {
			return fmt.Errorf("discord bot ist nicht aktiviert oder nicht konfiguriert")
		}
		return s.dcClient.SendEmbedMessage(ctx, ev)

	case "pushover":
		if s.poClient == nil {
			return fmt.Errorf("pushover ist nicht aktiviert oder nicht konfiguriert")
		}
		return s.poClient.SendMessage(ctx, ev.Title, ev.Message, 0, "http://localhost:9182/settings")

	case "homeassistant":
		if s.haClient == nil {
			return fmt.Errorf("home assistant webhook ist nicht aktiviert oder nicht konfiguriert")
		}
		return s.haClient.SendEvent(ctx, ev)

	default:
		return fmt.Errorf("unbekannter provider: %s", provider)
	}
}

// SetSecurityManager attaches an intrusion defense manager to forward interactive bot callbacks.
func (s *Service) SetSecurityManager(sm SecurityManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secMgr = sm
	if s.tgClient != nil {
		s.tgClient.SetSecurityManager(sm)
	}
}

