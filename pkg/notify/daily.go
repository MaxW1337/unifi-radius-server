package notify

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// DailyWorker performs periodic CA expiration checks and daily summary broadcasts.
type DailyWorker struct {
	db         *database.DB
	dispatcher *Service
}

// NewDailyWorker initializes the periodic background worker.
func NewDailyWorker(db *database.DB, dispatcher *Service) *DailyWorker {
	return &DailyWorker{
		db:         db,
		dispatcher: dispatcher,
	}
}

// Start begins the daily monitoring loop.
func (w *DailyWorker) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	// Initial check on startup
	go w.checkCAExpiry(ctx)

	lastSummaryDate := ""

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// 1. Check CA Expiry once per day (around 03:00 or startup)
			if now.Hour() == 3 && now.Minute() == 0 {
				w.checkCAExpiry(ctx)
			}

			// 2. Check Daily Summary
			settings, err := w.db.GetSettings()
			if err == nil && settings != nil {
				targetTime := settings.DailySummaryTime
				if targetTime == "" {
					targetTime = "08:00"
				}

				currentHM := now.Format("15:04")
				currentDate := now.Format("2006-01-02")

				if currentHM == targetTime && lastSummaryDate != currentDate {
					lastSummaryDate = currentDate
					w.sendDailySummary(ctx)
				}
			}
		}
	}
}

func (w *DailyWorker) checkCAExpiry(ctx context.Context) {
	if w.db == nil || w.dispatcher == nil {
		return
	}

	certs, err := w.db.ListCertificates("")
	if err != nil {
		return
	}

	now := time.Now().UTC()
	for _, cert := range certs {
		if cert.IsRevoked {
			continue
		}

		daysLeft := int(cert.ExpiresAt.Sub(now).Hours() / 24)
		if daysLeft > 0 && daysLeft <= 14 {
			ev := NotificationEvent{
				Type:      EventCAExpiry,
				Title:     fmt.Sprintf("Zertifikat läuft in %d Tagen ab", daysLeft),
				Message:   fmt.Sprintf("Das Zertifikat für '%s' (Typ: %s, Seriennr: %s) läuft am %s ab.", cert.CommonName, cert.CertType, cert.SerialNumber, cert.ExpiresAt.Format("02.01.2006")),
				Timestamp: now,
			}
			w.dispatcher.Dispatch(ctx, ev)
		}
	}
}

func (w *DailyWorker) sendDailySummary(ctx context.Context) {
	if w.db == nil || w.dispatcher == nil {
		return
	}

	clients, total, _ := w.db.ListClients("", "", 5000, 0)
	activeCount := 0
	pendingCount := 0
	disabledCount := 0

	for _, c := range clients {
		switch c.Status {
		case models.ClientStatusActive:
			activeCount++
		case models.ClientStatusPending:
			pendingCount++
		case models.ClientStatusDisabled:
			disabledCount++
		}
	}

	vlans, _ := w.db.ListVLANs()
	logs, totalLogs, _ := w.db.ListAuthLogs(1, 0, "", "")
	_ = logs

	ev := NotificationEvent{
		Type:  EventDailySummary,
		Title: "Täglicher RADIUS Systembericht",
		Message: fmt.Sprintf("Guten Morgen! Hier ist die Zusammenfassung des UniFi RADIUS Servers:\n• Registrierte Clients: %d (Aktiv: %d, Pending: %d, Gesperrt: %d)\n• Synchronisierte UniFi VLANs: %d\n• Aufgezeichnete Authentifizierungen: %d",
			total, activeCount, pendingCount, disabledCount, len(vlans), totalLogs),
		Timestamp: time.Now(),
	}

	log.Printf("[Notify] Dispatching daily summary...")
	w.dispatcher.Dispatch(ctx, ev)
}

