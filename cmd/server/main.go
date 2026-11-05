package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/notify"
	"github.com/mwittenburg/unifi-radius-server/pkg/radius"
	"github.com/mwittenburg/unifi-radius-server/pkg/unifi"
	"github.com/mwittenburg/unifi-radius-server/pkg/version"
	"github.com/mwittenburg/unifi-radius-server/pkg/web"
	"golang.org/x/crypto/bcrypt"
)

var (
	Version   = version.Version
	GitCommit = version.GitCommit
	BuildDate = version.BuildDate
)

func main() {
	defaultDBPath := "/data/unifi-radius/radius.db"
	if runtime.GOOS == "windows" {
		defaultDBPath = "data/radius.db"
	}

	dbPathFlag := flag.String("db", defaultDBPath, "Path to SQLite database file")
	webPortFlag := flag.Int("web-port", 0, "Web UI port (overrides database setting)")
	radiusPortFlag := flag.Int("radius-port", 0, "RADIUS UDP auth port (overrides database setting)")
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	resetPassFlag := flag.Bool("reset-admin-password", false, "Reset admin password, re-enabling initial setup wizard in Web UI")
	setPassFlag := flag.String("set-admin-password", "", "Set a new admin password directly from command line")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("unifi-radius-server %s (commit: %s, built: %s, os/arch: %s/%s)\n",
			Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// 1. Initialize SQLite Database
	db, err := database.Open(*dbPathFlag)
	if err != nil {
		log.Fatalf("Fatal: failed to initialize database at %s: %v", *dbPathFlag, err)
	}
	defer db.Close()

	if *resetPassFlag {
		if err := db.ResetAdminPassword(); err != nil {
			log.Fatalf("Fatal: failed to reset admin password: %v", err)
		}
		fmt.Println("=========================================================")
		fmt.Println(" [OK] Admin-Passwort wurde erfolgreich zurückgesetzt!")
		fmt.Println("      Rufen Sie die Weboberfläche (/login) im Browser auf,")
		fmt.Println("      um direkt ein neues Passwort zu vergeben.")
		fmt.Println("=========================================================")
		os.Exit(0)
	}

	if *setPassFlag != "" {
		if len(*setPassFlag) < 4 {
			log.Fatalf("Fatal: das Passwort muss mindestens 4 Zeichen lang sein.")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(*setPassFlag), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Fatal: Fehler beim Hashen des Passworts: %v", err)
		}
		if err := db.SetAdminPassword(string(hash)); err != nil {
			log.Fatalf("Fatal: failed to set admin password: %v", err)
		}
		fmt.Println("=========================================================")
		fmt.Println(" [OK] Admin-Passwort wurde erfolgreich aktualisiert!")
		fmt.Println("=========================================================")
		os.Exit(0)
	}

	displayVersion := strings.TrimPrefix(Version, "v")

	log.Println("=========================================================")
	log.Printf(" Starting UniFi RADIUS Server v%s (%s/%s)", displayVersion, runtime.GOOS, runtime.GOARCH)
	log.Println(" Optimized for UniFi Dream Machine Pro & SE (UDM)")
	log.Println("=========================================================")
	log.Printf("[DB] SQLite database initialized at %s", *dbPathFlag)

	// 2. Read Settings
	settings, err := db.GetSettings()
	if err != nil {
		log.Fatalf("Fatal: failed to load settings: %v", err)
	}

	webPort := settings.WebPort
	if webPort <= 0 {
		webPort = 9182
	}
	if *webPortFlag > 0 {
		webPort = *webPortFlag
	}

	radiusPort := settings.RADIUSAuthPort
	if radiusPort <= 0 {
		radiusPort = 1812
	}
	if *radiusPortFlag > 0 {
		radiusPort = *radiusPortFlag
	}

	// 3. Initialize Shared Event Bus
	bus := eventbus.DefaultBus

	// 4. Initialize UniFi Sync Service
	syncSvc := unifi.NewSyncService(db, bus)

	// 5. Initialize RADIUS Engine
	radiusSrv := radius.NewServer(db, bus, radiusPort)
	if settings.RadiusDebugMode {
		radiusSrv.SetDebugMode(true)
	}

	// 6. Initialize Web Interface & Notification Service
	webSrv, err := web.NewServer(db, bus, syncSvc, webPort, Version)
	if err != nil {
		log.Fatalf("Fatal: failed to initialize web server: %v", err)
	}
	webSrv.SetRadiusServer(radiusSrv)
	notifySvc := webSrv.NotifyService()
	backupSvc := webSrv.BackupService()

	// 7. Context & Graceful Shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start Background Workers
	go syncSvc.Start(ctx)
	if notifySvc != nil {
		go notifySvc.Start(ctx)
	}
	if backupSvc != nil {
		go backupSvc.Start(ctx)
	}
	if updaterSvc := webSrv.UpdaterService(); updaterSvc != nil {
		go updaterSvc.StartAutoScheduler(ctx, func() (*models.Settings, error) {
			return db.GetSettings()
		}, func(newVersion string) {
			bus.PublishLog(eventbus.LogEvent{
				Timestamp: time.Now().Format("15:04:05"),
				Level:     eventbus.LogLevelInfo,
				Source:    "AUTO-UPDATE",
				Message:   fmt.Sprintf("UniFi RADIUS Server wurde planmäßig auf Version v%s aktualisiert.", newVersion),
			})
			if notifySvc != nil {
				notifySvc.Dispatch(context.Background(), notify.NotificationEvent{
					Type:      "system_update",
					Title:     "⚡ Automatisches Software-Update installiert",
					Message:   fmt.Sprintf("UniFi RADIUS Server wurde planmäßig im Wartungsfenster auf Version v%s aktualisiert und neu gestartet.", newVersion),
					Timestamp: time.Now(),
				})
			}
		})
	}

	go func() {
		if err := radiusSrv.Start(ctx); err != nil {
			log.Printf("[RADIUS] Error starting RADIUS server: %v", err)
		}
	}()

	go func() {
		if err := webSrv.Start(ctx); err != nil {
			log.Fatalf("Fatal: Web server error: %v", err)
		}
	}()

	// Periodic Log Retention Cleaner (every 12 hours)
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if s, err := db.GetSettings(); err == nil {
					prunedAuth, _ := db.PruneAuthLogs(s.LogRetentionDays, s.MaxLogEntries)
					prunedSys, _ := db.PruneSystemLogs(s.LogRetentionDays, 50000)
					if prunedAuth > 0 || prunedSys > 0 {
						log.Printf("[Retention] Cleaned up %d expired auth logs and %d system logs.", prunedAuth, prunedSys)
					}
				}
			}
		}
	}()

	log.Printf("[Ready] Web UI available at: http://localhost:%d", webPort)
	if radiusSrv.IsListening() {
		log.Printf("[Ready] RADIUS listening on UDP port: %d", radiusPort)
	} else {
		log.Printf("[Notice] RADIUS waiting to bind UDP port %d (waiting for FreeRADIUS migration/stop)", radiusPort)
	}

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %s. Shutting down gracefully...", sig)
	cancel()

	// Give services time to close cleanly
	time.Sleep(1 * time.Second)
	log.Println("UniFi RADIUS Server stopped.")
}

