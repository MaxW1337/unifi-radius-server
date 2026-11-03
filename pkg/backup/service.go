package backup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// Service coordinates remote backups and background scheduled jobs.
type Service struct {
	db         *database.DB
	bus        *eventbus.Bus
	httpClient *http.Client
	mu         sync.Mutex
	lastRunDay string
}

// NewService creates a new backup service.
func NewService(db *database.DB, bus *eventbus.Bus) *Service {
	return &Service{
		db:  db,
		bus: bus,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// TestConnection validates the configured target credentials and reachability.
func (s *Service) TestConnection(ctx context.Context, cfg *models.Settings) error {
	if cfg == nil {
		var err error
		cfg, err = s.db.GetSettings()
		if err != nil {
			return err
		}
	}

	switch strings.ToLower(cfg.RemoteBackupType) {
	case "webdav":
		return TestWebDAV(ctx, s.httpClient, cfg.RemoteBackupURL, cfg.RemoteBackupUsername, cfg.RemoteBackupPassword)
	case "s3":
		return TestS3(ctx, s.httpClient, cfg.RemoteBackupURL, cfg.RemoteBackupPath, cfg.RemoteBackupUsername, cfg.RemoteBackupPassword)
	case "local":
		return TestLocal(cfg.RemoteBackupPath)
	default:
		return fmt.Errorf("unbekannter Backup-Zieltyp %q", cfg.RemoteBackupType)
	}
}

// RunBackup creates a point-in-time SQLite snapshot and uploads it to the configured remote target.
func (s *Service) RunBackup(ctx context.Context) (*BackupResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.db.GetSettings()
	if err != nil {
		return nil, fmt.Errorf("Einstellungen konnten nicht geladen werden: %w", err)
	}

	target := strings.ToLower(cfg.RemoteBackupType)
	if target == "" {
		target = "webdav"
	}

	filename := fmt.Sprintf("radius-backup-%s.db", time.Now().Format("2006-01-02-150405"))

	// Create temporary local snapshot
	tmpFile, err := os.CreateTemp("", "radius-backup-*.db")
	if err != nil {
		return nil, fmt.Errorf("Temporäre Backup-Datei konnte nicht erstellt werden: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := s.db.Backup(tmpFile); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("SQLite Snapshot fehlgeschlagen: %w", err)
	}
	tmpFile.Close()

	var uploadedSize int64

	switch target {
	case "webdav":
		if cfg.RemoteBackupURL == "" {
			return nil, errors.New("WebDAV URL ist nicht konfiguriert")
		}
		uploadedSize, err = UploadWebDAV(ctx, s.httpClient, cfg.RemoteBackupURL, cfg.RemoteBackupUsername, cfg.RemoteBackupPassword, filename, tmpPath)
		if err != nil {
			return nil, err
		}
		_ = PruneWebDAV(ctx, s.httpClient, cfg.RemoteBackupURL, cfg.RemoteBackupUsername, cfg.RemoteBackupPassword, cfg.RemoteBackupRetention)

	case "s3":
		if cfg.RemoteBackupURL == "" || cfg.RemoteBackupPath == "" {
			return nil, errors.New("S3 Endpoint und Bucket müssen konfiguriert sein")
		}
		parts := strings.SplitN(cfg.RemoteBackupPath, "/", 2)
		bucket := parts[0]
		prefix := ""
		if len(parts) > 1 {
			prefix = parts[1]
		}
		uploadedSize, err = UploadS3(ctx, s.httpClient, cfg.RemoteBackupURL, bucket, prefix, cfg.RemoteBackupUsername, cfg.RemoteBackupPassword, filename, tmpPath)
		if err != nil {
			return nil, err
		}

	case "local":
		if cfg.RemoteBackupPath == "" {
			return nil, errors.New("Lokaler Zielpfad ist nicht konfiguriert")
		}
		uploadedSize, err = SaveLocal(cfg.RemoteBackupPath, filename, tmpPath)
		if err != nil {
			return nil, err
		}
		_ = PruneLocal(cfg.RemoteBackupPath, cfg.RemoteBackupRetention)

	default:
		return nil, fmt.Errorf("nicht unterstützter Backup-Typ: %s", target)
	}

	result := &BackupResult{
		Success:   true,
		Target:    target,
		Filename:  filename,
		SizeBytes: uploadedSize,
		Message:   fmt.Sprintf("Backup erfolgreich übertragen (%d KB)", uploadedSize/1024),
		Timestamp: time.Now(),
	}

	if s.bus != nil {
		s.bus.PublishLog(eventbus.LogEvent{
			Timestamp: time.Now().Format("15:04:05"),
			Level:     eventbus.LogLevelInfo,
			Source:    "BACKUP",
			Message:   fmt.Sprintf("Remote-Backup [%s] erfolgreich erstellt: %s (%d KB)", strings.ToUpper(target), filename, uploadedSize/1024),
		})
	}

	return result, nil
}

// Start runs the periodic background scheduler for automated remote backups.
func (s *Service) Start(ctx context.Context) {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkScheduledBackup(ctx)
		}
	}
}

func (s *Service) checkScheduledBackup(ctx context.Context) {
	cfg, err := s.db.GetSettings()
	if err != nil || cfg == nil || !cfg.RemoteBackupEnabled {
		return
	}

	schedTime := strings.TrimSpace(cfg.RemoteBackupSchedule)
	if schedTime == "" || strings.ToLower(schedTime) == "disabled" || strings.ToLower(schedTime) == "manual" {
		return
	}

	now := time.Now()
	currentTime := now.Format("15:04")
	currentDay := now.Format("2006-01-02")

	if currentTime == schedTime && s.lastRunDay != currentDay {
		s.lastRunDay = currentDay
		log.Printf("[Backup Worker] Starte geplantes Remote-Backup (%s)...", cfg.RemoteBackupType)

		go func() {
			backupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			res, err := s.RunBackup(backupCtx)
			if err != nil {
				log.Printf("[Backup Worker] Fehler bei geplantem Remote-Backup: %v", err)
				if s.bus != nil {
					s.bus.PublishLog(eventbus.LogEvent{
						Timestamp: time.Now().Format("15:04:05"),
						Level:     eventbus.LogLevelError,
						Source:    "BACKUP",
						Message:   fmt.Sprintf("Fehler bei automatischem Remote-Backup: %v", err),
					})
				}
			} else {
				log.Printf("[Backup Worker] Geplantes Remote-Backup erfolgreich abgeschlossen: %s (%d KB)", res.Filename, res.SizeBytes/1024)
			}
		}()
	}
}

