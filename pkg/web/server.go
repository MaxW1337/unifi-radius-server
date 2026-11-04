package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mwittenburg/unifi-radius-server/pkg/backup"
	"github.com/mwittenburg/unifi-radius-server/pkg/ca"
	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/i18n"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/notify"
	"github.com/mwittenburg/unifi-radius-server/pkg/radius"
	"github.com/mwittenburg/unifi-radius-server/pkg/unifi"
	"github.com/mwittenburg/unifi-radius-server/pkg/updater"
	"golang.org/x/crypto/bcrypt"
)

//go:embed assets/*
var assetsFS embed.FS

//go:embed templates/*
var templatesFS embed.FS

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // Non-browser clients (e.g. testing)
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Host, r.Host)
	},
}

type attemptRecord struct {
	failedCount  int
	lockoutUntil time.Time
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*attemptRecord
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		attempts: make(map[string]*attemptRecord),
	}
}

func (l *loginLimiter) isBlocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, exists := l.attempts[ip]
	if !exists {
		return false
	}
	if time.Now().Before(rec.lockoutUntil) {
		return true
	}
	if time.Now().After(rec.lockoutUntil) && rec.failedCount >= 5 {
		delete(l.attempts, ip)
	}
	return false
}

func (l *loginLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, exists := l.attempts[ip]
	if !exists {
		rec = &attemptRecord{}
		l.attempts[ip] = rec
	}
	rec.failedCount++
	if rec.failedCount >= 5 {
		rec.lockoutUntil = time.Now().Add(2 * time.Minute)
	}
}

func (l *loginLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'self';")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// Server provides the web user interface and WebSocket feed.
type Server struct {
	db          *database.DB
	bus         *eventbus.Bus
	syncSvc     *unifi.SyncService
	radiusSrv   *radius.Server
	notifySvc   *notify.Service
	backupSvc   *backup.Service
	updater     *updater.Service
	pages       map[string]*template.Template
	httpServer  *http.Server
	sessions    map[string]time.Time
	sessionsMu  sync.RWMutex
	limiter     *loginLimiter
	port        int
	version     string
}

// NewServer initializes the HTTP web server.
func NewServer(db *database.DB, bus *eventbus.Bus, syncSvc *unifi.SyncService, port int, version ...string) (*Server, error) {
	if port <= 0 {
		port = 9182
	}
	if bus == nil {
		bus = eventbus.DefaultBus
	}

	ver := "1.0.0"
	if len(version) > 0 && version[0] != "" {
		ver = strings.TrimPrefix(version[0], "v")
	}

	funcMap := template.FuncMap{
		"tr": func(lang, key string, args ...any) string {
			return i18n.T(lang, key, args...)
		},
	}

	pages := make(map[string]*template.Template)
	pageNames := []string{
		"dashboard.html",
		"clients.html",
		"certificates.html",
		"logs.html",
		"settings.html",
	}

	for _, name := range pageNames {
		t, err := template.New(name).Funcs(funcMap).ParseFS(templatesFS, "templates/layout.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", name, err)
		}
		pages[name] = t
	}

	loginTmpl, err := template.New("login.html").Funcs(funcMap).ParseFS(templatesFS, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse login template: %w", err)
	}
	pages["login.html"] = loginTmpl

	updaterSvc := updater.NewService(ver, "MaxW1337", "unifi-radius-server")

	s := &Server{
		db:         db,
		bus:        bus,
		syncSvc:    syncSvc,
		notifySvc:  notify.NewService(db, bus, syncSvc),
		backupSvc:  backup.NewService(db, bus),
		updater:    updaterSvc,
		pages:      pages,
		sessions:   make(map[string]time.Time),
		limiter:    newLoginLimiter(),
		port:       port,
		version:    ver,
	}

	if syncSvc != nil {
		syncSvc.SetBus(bus)
	}

	mux := http.NewServeMux()

	// Embedded static assets (CSS, JS, SVGs)
	staticSub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		return nil, err
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Auth routes
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// WebSocket endpoint (protected by session check)
	mux.HandleFunc("/ws/feed", s.handleWebSocket)

	// Protected pages
	mux.HandleFunc("/", s.requireAuth(s.handleDashboard))
	mux.HandleFunc("/clients", s.requireAuth(s.handleClients))
	mux.HandleFunc("/clients/create", s.requireAuth(s.csrfProtect(s.handleCreateClient)))
	mux.HandleFunc("/clients/update", s.requireAuth(s.csrfProtect(s.handleUpdateClient)))
	mux.HandleFunc("/clients/approve", s.requireAuth(s.csrfProtect(s.handleApproveClient)))
	mux.HandleFunc("/clients/delete", s.requireAuth(s.csrfProtect(s.handleDeleteClient)))
	mux.HandleFunc("/clients/restart-port", s.requireAuth(s.csrfProtect(s.handleRestartPort)))
	mux.HandleFunc("/clients/reconnect", s.requireAuth(s.csrfProtect(s.handleReconnectClient)))

	mux.HandleFunc("/certificates", s.requireAuth(s.handleCertificates))
	mux.HandleFunc("/certificates/init-ca", s.requireAuth(s.csrfProtect(s.handleInitCA)))
	mux.HandleFunc("/certificates/issue", s.requireAuth(s.csrfProtect(s.handleIssueCert)))
	mux.HandleFunc("/certificates/revoke", s.requireAuth(s.csrfProtect(s.handleRevokeCert)))
	mux.HandleFunc("/certificates/download-p12", s.requireAuth(s.handleDownloadP12))
	mux.HandleFunc("/certificates/download-pem", s.requireAuth(s.handleDownloadPEM))
	mux.HandleFunc("/certificates/download-ca", s.requireAuth(s.handleDownloadCA))
	mux.HandleFunc("/certificates/download-mobileconfig", s.requireAuth(s.handleDownloadMobileConfig))

	mux.HandleFunc("/logs", s.requireAuth(s.handleLogs))

	mux.HandleFunc("/settings", s.requireAuth(s.handleSettings))
	mux.HandleFunc("/settings/save", s.requireAuth(s.csrfProtect(s.handleSaveSettings)))
	mux.HandleFunc("/api/unifi/test", s.requireAuth(s.handleTestUniFi))
	mux.HandleFunc("/api/unifi/sync", s.requireAuth(s.csrfProtect(s.handleTriggerSync)))
	mux.HandleFunc("/api/unifi/migration-status", s.requireAuth(s.handleMigrationStatus))
	mux.HandleFunc("/api/unifi/migrate", s.requireAuth(s.csrfProtect(s.handlePerformMigration)))

	// Update check & self-update
	mux.HandleFunc("/api/update/check", s.requireAuth(s.handleUpdateCheck))
	mux.HandleFunc("/api/update/apply", s.requireAuth(s.csrfProtect(s.handleApplyUpdate)))

	// Backup & Restore
	mux.HandleFunc("/api/backup/download", s.requireAuth(s.handleDownloadBackup))
	mux.HandleFunc("/api/backup/restore", s.requireAuth(s.csrfProtect(s.handleRestoreBackup)))
	mux.HandleFunc("/api/backup/remote/test", s.requireAuth(s.csrfProtect(s.handleTestRemoteBackup)))
	mux.HandleFunc("/api/backup/remote/run", s.requireAuth(s.csrfProtect(s.handleRunRemoteBackup)))

	// Notifications
	mux.HandleFunc("/api/notify/test", s.requireAuth(s.csrfProtect(s.handleTestNotification)))

	// Language switcher route
	mux.HandleFunc("/api/set-language", s.handleSetLanguage)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      securityHeadersMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return s, nil
}

// SetRadiusServer sets or overrides the RADIUS engine reference.
func (s *Server) SetRadiusServer(r *radius.Server) {
	s.radiusSrv = r
}

// RadiusServer returns the RADIUS engine reference.
func (s *Server) RadiusServer() *radius.Server {
	return s.radiusSrv
}

// SetNotifyService sets or overrides the notification service.
func (s *Server) SetNotifyService(n *notify.Service) {
	s.notifySvc = n
}

// NotifyService returns the notification service.
func (s *Server) NotifyService() *notify.Service {
	return s.notifySvc
}

// SetBackupService sets or overrides the backup service.
func (s *Server) SetBackupService(b *backup.Service) {
	s.backupSvc = b
}

// BackupService returns the backup service.
func (s *Server) BackupService() *backup.Service {
	return s.backupSvc
}

// UpdaterService returns the software updater service.
func (s *Server) UpdaterService() *updater.Service {
	return s.updater
}

// Start begins listening on the configured HTTP port.
func (s *Server) Start(ctx context.Context) error {
	log.Printf("[Web] UniFi-Style Web Interface listening on http://0.0.0.0:%d", s.port)
	s.bus.PublishLog(eventbus.LogEvent{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     eventbus.LogLevelInfo,
		Source:    "WEB",
		Message:   fmt.Sprintf("Web UI initialized and accessible on port %d", s.port),
	})

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
	}()

	err := s.httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// csrfProtect enforces same-origin on state-changing requests.
func (s *Server) csrfProtect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
			origin := r.Header.Get("Origin")
			if origin != "" {
				u, err := url.Parse(origin)
				if err != nil || !strings.EqualFold(u.Host, r.Host) {
					http.Error(w, "Forbidden: Cross-site request rejected", http.StatusForbidden)
					return
				}
			} else {
				referer := r.Header.Get("Referer")
				if referer != "" {
					u, err := url.Parse(referer)
					if err != nil || !strings.EqualFold(u.Host, r.Host) {
						http.Error(w, "Forbidden: Cross-site request rejected", http.StatusForbidden)
						return
					}
				}
			}
		}
		next(w, r)
	}
}

func getClientIP(r *http.Request) string {
	xfwd := r.Header.Get("X-Forwarded-For")
	if xfwd != "" {
		parts := strings.Split(xfwd, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// requireAuth ensures the user has an active session cookie or password is not configured yet.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := s.db.GetSettings()
		if err != nil || settings.WebAdminPassword == "" {
			// Password not set yet -> redirect to setup/login
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		cookie, err := r.Cookie("session_id")
		if err != nil || !s.isValidSession(cookie.Value) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}

func (s *Server) isValidSession(token string) bool {
	if token == "" {
		return false
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	expiry, exists := s.sessions[token]
	if !exists {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *Server) createSession() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	// Clean up expired sessions
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}

	s.sessions[token] = now.Add(24 * time.Hour)
	return token
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	settings, err := s.db.GetSettings()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	lang := i18n.DetectLanguage(r)
	isInitialSetup := settings.WebAdminPassword == ""
	clientIP := getClientIP(r)

	if r.Method == http.MethodPost {
		if s.limiter != nil && s.limiter.isBlocked(clientIP) {
			s.renderLogin(w, r, i18n.T(lang, "login.error_rate_limit"), isInitialSetup, settings.WebPort)
			return
		}

		enteredPass := r.FormValue("password")

		if isInitialSetup {
			if len(enteredPass) < 4 {
				s.renderLogin(w, r, i18n.T(lang, "login.error_minlen"), true, settings.WebPort)
				return
			}
			hash, err := bcrypt.GenerateFromPassword([]byte(enteredPass), bcrypt.DefaultCost)
			if err != nil {
				s.renderLogin(w, r, "Password hashing error", true, settings.WebPort)
				return
			}
			settings.WebAdminPassword = string(hash)
			_ = s.db.UpdateSettings(settings)

			if s.limiter != nil {
				s.limiter.recordSuccess(clientIP)
			}
			token := s.createSession()
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Existing password check
		err := bcrypt.CompareHashAndPassword([]byte(settings.WebAdminPassword), []byte(enteredPass))
		if err == nil {
			if s.limiter != nil {
				s.limiter.recordSuccess(clientIP)
			}
			token := s.createSession()
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if s.limiter != nil {
			s.limiter.recordFailure(clientIP)
			if s.limiter.isBlocked(clientIP) {
				s.renderLogin(w, r, i18n.T(lang, "login.error_rate_limit"), false, settings.WebPort)
				return
			}
		}
		s.renderLogin(w, r, i18n.T(lang, "login.error_invalid"), false, settings.WebPort)
		return
	}

	s.renderLogin(w, r, "", isInitialSetup, settings.WebPort)
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, errMsg string, isSetup bool, port int) {
	tmpl, exists := s.pages["login.html"]
	if !exists {
		http.Error(w, "Login template not found", http.StatusInternalServerError)
		return
	}
	lang := i18n.DetectLanguage(r)
	data := map[string]interface{}{
		"Error":          errMsg,
		"IsInitialSetup": isSetup,
		"Port":           port,
		"Version":        s.version,
		"Lang":           lang,
		"CurrentPath":    "/login",
	}
	_ = tmpl.ExecuteTemplate(w, "login.html", data)
}

func (s *Server) handleSetLanguage(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang != i18n.LangDE && lang != i18n.LangEN {
		lang = i18n.LangEN
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "lang",
		Value:    lang,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		SameSite: http.SameSiteLaxMode,
	})

	redirect := r.URL.Query().Get("redirect")
	if redirect == "" || !strings.HasPrefix(redirect, "/") {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		s.sessionsMu.Lock()
		delete(s.sessions, cookie.Value)
		s.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	clients, total, _ := s.db.ListClients("", "", 1000, 0)
	vlans, _ := s.db.ListVLANs()
	recentLogs, _, _ := s.db.ListAuthLogs(20, 0, "", "")

	activeCount := 0
	pendingCount := 0
	for _, c := range clients {
		if c.Status == models.ClientStatusActive {
			activeCount++
		} else if c.Status == models.ClientStatusPending {
			pendingCount++
		}
	}

	data := map[string]interface{}{
		"Title":          "Live Monitor",
		"PageTitle":      "RADIUS Live Monitor",
		"ActiveNav":      "dashboard",
		"TotalClients":   total,
		"ActiveClients":  activeCount,
		"PendingClients": pendingCount,
		"TotalVLANs":     len(vlans),
		"RecentLogs":     recentLogs,
	}
	s.renderPage(w, r, "dashboard.html", data)
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	statusFilter := models.ClientStatus(r.URL.Query().Get("status"))
	vlanFilter := r.URL.Query().Get("vlan")
	typeFilter := r.URL.Query().Get("type")

	clients, _, _ := s.db.ListClients(query, statusFilter, 500, 0, vlanFilter, typeFilter)
	vlans, _ := s.db.ListVLANs()
	settings, _ := s.db.GetSettings()

	defaultVLANName := ""
	for _, v := range vlans {
		if v.VLANID == settings.DefaultAllowVLAN {
			defaultVLANName = v.Name
			break
		}
	}

	for i := range clients {
		if clients[i].VLANID == nil || *clients[i].VLANID == 0 {
			if clients[i].VLANName == "" {
				clients[i].VLANName = defaultVLANName
			}
		}
	}

	data := map[string]interface{}{
		"Title":           "MAB Geräte & Benutzer",
		"PageTitle":       "MAB Geräte & Benutzer",
		"ActiveNav":       "clients",
		"Clients":         clients,
		"VLANs":           vlans,
		"DefaultVLAN":     settings.DefaultAllowVLAN,
		"DefaultVLANName": defaultVLANName,
		"SearchQuery":     query,
		"SelectedStatus":  statusFilter,
		"SelectedVLAN":    vlanFilter,
		"SelectedType":    typeFilter,
	}
	s.renderPage(w, r, "clients.html", data)
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	entryType := r.FormValue("entry_type")
	mac := strings.TrimSpace(r.FormValue("mac_address"))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	vlanStr := r.FormValue("vlan_id")
	status := models.ClientStatus(r.FormValue("status"))
	desc := r.FormValue("description")

	var vlanID *int
	if vlanStr != "" {
		if v, err := strconv.Atoi(vlanStr); err == nil && v > 0 {
			vlanID = &v
		}
	}

	c := &models.Client{
		VLANID:      vlanID,
		Status:      status,
		Description: desc,
	}

	if entryType == "user" || (mac == "" && username != "") {
		c.Username = username
		c.AuthType = models.AuthTypePAP
		if password != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err == nil {
				c.PasswordHash = string(hash)
			}
		}
	} else {
		c.MACAddress = mac
		c.AuthType = models.AuthTypeMAB
	}

	_ = s.db.CreateClient(c)
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	c, err := s.db.GetClientByID(id)
	if err != nil {
		http.Redirect(w, r, "/clients", http.StatusSeeOther)
		return
	}

	entryType := r.FormValue("entry_type")
	if entryType == "user" || (c.Username != "" && c.MACAddress == "") {
		newUsername := strings.TrimSpace(r.FormValue("username"))
		if newUsername != "" {
			c.Username = newUsername
		}
		newPass := r.FormValue("password")
		if newPass != "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
			if err == nil {
				c.PasswordHash = string(hash)
			}
		}
	} else {
		c.MACAddress = strings.TrimSpace(r.FormValue("mac_address"))
	}

	c.Description = r.FormValue("description")
	c.Status = models.ClientStatus(r.FormValue("status"))

	vlanStr := r.FormValue("vlan_id")
	if vlanStr != "" {
		if v, err := strconv.Atoi(vlanStr); err == nil && v > 0 {
			c.VLANID = &v
		} else {
			c.VLANID = nil
		}
	} else {
		c.VLANID = nil
	}

	_ = s.db.UpdateClient(c)

	reconnect := r.FormValue("reconnect")
	if reconnect == "1" || reconnect == "true" {
		go s.executePortRestartOrReconnect(c)
	}

	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (s *Server) handleRestartPort(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.FormValue("id")
	if idStr == "" {
		idStr = r.URL.Query().Get("id")
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)
	c, err := s.db.GetClientByID(id)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	go s.executePortRestartOrReconnect(c)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Trigger", `{"showToast": "Port-Neustart getriggert"}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (s *Server) handleReconnectClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	idStr := r.FormValue("id")
	if idStr == "" {
		idStr = r.URL.Query().Get("id")
	}
	id, _ := strconv.ParseInt(idStr, 10, 64)
	c, err := s.db.GetClientByID(id)
	if err != nil {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	if c.MACAddress == "" {
		http.Error(w, "Client MAC not available", http.StatusBadRequest)
		return
	}

	go func(client *models.Client) {
		unifiClient, err := s.getUniFiClient()
		if err != nil {
			s.publishLog(eventbus.LogLevelWarn, "CLIENT-ACTION", fmt.Sprintf("UniFi Verbindung fehlgeschlagen: %v", err))
			return
		}
		err = unifiClient.ReconnectClient(client.MACAddress)
		if err != nil {
			s.publishLog(eventbus.LogLevelWarn, "CLIENT-ACTION", fmt.Sprintf("Reconnect für Client %s fehlgeschlagen: %v", client.MACAddress, err))
		} else {
			s.publishLog(eventbus.LogLevelInfo, "CLIENT-ACTION", fmt.Sprintf("Client %s erfolgreich getrennt (Reconnect getriggert).", client.MACAddress))
		}
	}(c)

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Trigger", `{"showToast": "Client getrennt (Reconnect)"}`)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (s *Server) getUniFiClient() (*unifi.Client, error) {
	settings, err := s.db.GetSettings()
	if err != nil {
		return nil, err
	}
	return unifi.NewClient(unifi.Config{
		BaseURL:  settings.UniFiURL,
		AuthMode: settings.UniFiAuthMode,
		APIKey:   settings.UniFiAPIKey,
		Username: settings.UniFiUsername,
		Password: settings.UniFiPassword,
		Site:     "default",
	})
}

func (s *Server) publishLog(level eventbus.LogLevel, source, msg string) {
	log.Printf("[%s] [%s] %s", source, level, msg)
	if s.bus != nil {
		s.bus.PublishLog(eventbus.LogEvent{
			Timestamp: time.Now().Format("15:04:05"),
			Level:     level,
			Source:    source,
			Message:   msg,
		})
	}
}

func (s *Server) executePortRestartOrReconnect(c *models.Client) {
	if c == nil {
		return
	}
	unifiClient, err := s.getUniFiClient()
	if err != nil {
		s.publishLog(eventbus.LogLevelWarn, "CLIENT-ACTION", fmt.Sprintf("UniFi Verbindung fehlgeschlagen: %v", err))
		return
	}

	// Auto-discover switch info if missing and client is online in UniFi
	if c.UniFiSwitchMAC == "" && c.MACAddress != "" {
		if clientsMap, err := unifiClient.FetchClients(); err == nil {
			if info, found := clientsMap[c.MACAddress]; found {
				if info.SwitchMAC != "" {
					c.UniFiSwitchMAC = info.SwitchMAC
				}
				if info.SwitchPort != "" {
					c.UniFiSwitchPort = info.SwitchPort
				}
				if info.SwitchName != "" {
					c.UniFiSwitchName = info.SwitchName
				}
				c.UniFiIsWired = info.IsWired
				_ = s.db.UpdateClient(c)
			}
		}
	}

	portIdx, _ := strconv.Atoi(c.UniFiSwitchPort)
	if c.UniFiSwitchMAC != "" && portIdx > 0 {
		err := unifiClient.PowerCyclePort(c.UniFiSwitchMAC, portIdx)
		if err != nil {
			s.publishLog(eventbus.LogLevelWarn, "CLIENT-ACTION", fmt.Sprintf("Power-Cycle für Port %d auf Switch %s (%s) fehlgeschlagen: %v. Führe Fallback-Reconnect durch...", portIdx, c.UniFiSwitchName, c.UniFiSwitchMAC, err))
		} else {
			s.publishLog(eventbus.LogLevelInfo, "CLIENT-ACTION", fmt.Sprintf("Port %d auf Switch %s (%s) für Client %s erfolgreich neu gestartet (Power-Cycle).", portIdx, c.UniFiSwitchName, c.UniFiSwitchMAC, c.MACAddress))
		}
	} else if c.UniFiSwitchPort != "" && portIdx > 0 {
		s.publishLog(eventbus.LogLevelInfo, "CLIENT-ACTION", fmt.Sprintf("Switch-MAC unbekannt für Port %s. Führe Reconnect (Kick) für Client %s durch...", c.UniFiSwitchPort, c.MACAddress))
	}

	if c.MACAddress != "" {
		err := unifiClient.ReconnectClient(c.MACAddress)
		if err != nil {
			s.publishLog(eventbus.LogLevelWarn, "CLIENT-ACTION", fmt.Sprintf("Reconnect für Client %s fehlgeschlagen: %v", c.MACAddress, err))
		} else {
			s.publishLog(eventbus.LogLevelInfo, "CLIENT-ACTION", fmt.Sprintf("Client %s erfolgreich getrennt (Reconnect getriggert).", c.MACAddress))
		}
	}
}

func (s *Server) handleApproveClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	c, err := s.db.GetClientByID(id)
	if err == nil {
		c.Status = models.ClientStatusActive
		_ = s.db.UpdateClient(c)
	}
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	_ = s.db.DeleteClient(id)
	http.Redirect(w, r, "/clients", http.StatusSeeOther)
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	certs, _ := s.db.ListCertificates("")
	activeCA, _ := s.db.GetActiveCACertificate()

	data := map[string]interface{}{
		"Title":        "Zertifikate (CA)",
		"PageTitle":    "Zertifizierungsstelle & EAP-TLS",
		"ActiveNav":    "certificates",
		"Certificates": certs,
		"ActiveCA":     activeCA,
	}
	s.renderPage(w, r, "certificates.html", data)
}

func (s *Server) handleInitCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	newCA, err := ca.GenerateCA("UniFi RADIUS Root CA", 10)
	if err == nil {
		// Save Root CA
		caCert := &models.Certificate{
			SerialNumber:   fmt.Sprintf("%X", newCA.RootCert.SerialNumber),
			CommonName:     newCA.RootCert.Subject.CommonName,
			CertType:       "ca",
			CertificatePEM: newCA.RootCertPEM,
			PrivateKeyPEM:  newCA.RootKeyPEM,
			IssuedAt:       newCA.RootCert.NotBefore,
			ExpiresAt:      newCA.RootCert.NotAfter,
		}
		_ = s.db.SaveCertificate(caCert)

		// Generate Server Certificate for RADIUS
		serverCertPEM, serverKeyPEM, err := newCA.IssueServerCert("radius.internal", nil, []string{"radius.internal", "udm.local"}, 730)
		if err == nil {
			srvBlock, _ := ca.LoadCA(newCA.RootCertPEM, newCA.RootKeyPEM)
			if srvBlock != nil {
				serverCert := &models.Certificate{
					SerialNumber:   "SERVER-1",
					CommonName:     "radius.internal",
					CertType:       "server",
					CertificatePEM: serverCertPEM,
					PrivateKeyPEM:  serverKeyPEM,
					IssuedAt:       time.Now().UTC(),
					ExpiresAt:      time.Now().UTC().AddDate(2, 0, 0),
				}
				_ = s.db.SaveCertificate(serverCert)
			}
		}
	}

	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

func (s *Server) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	commonName := strings.TrimSpace(r.FormValue("common_name"))
	password := r.FormValue("password")
	_ = password
	ssid := strings.TrimSpace(r.FormValue("ssid"))
	valDays, _ := strconv.Atoi(r.FormValue("validity_days"))
	if valDays <= 0 {
		valDays = 365
	}

	activeCA, err := s.db.GetActiveCACertificate()
	if err != nil {
		http.Redirect(w, r, "/certificates", http.StatusSeeOther)
		return
	}

	loadedCA, err := ca.LoadCA(activeCA.CertificatePEM, activeCA.PrivateKeyPEM)
	if err != nil {
		http.Redirect(w, r, "/certificates", http.StatusSeeOther)
		return
	}

	certPEM, keyPEM, serial, err := loadedCA.IssueClientCert(commonName, valDays)
	if err != nil {
		http.Redirect(w, r, "/certificates", http.StatusSeeOther)
		return
	}

	// Persist
	cRecord := &models.Certificate{
		SerialNumber:   serial,
		CommonName:     commonName,
		CertType:       "client",
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().AddDate(0, 0, valDays),
	}
	_ = s.db.SaveCertificate(cRecord)

	// Pre-create or associate client
	existing, _ := s.db.GetClientByUsername(commonName)
	if existing == nil {
		_ = s.db.CreateClient(&models.Client{
			Username:    commonName,
			AuthType:    models.AuthTypeEAPTLS,
			Status:      models.ClientStatusActive,
			CertSerial:  serial,
			Description: fmt.Sprintf("802.1X Cert Client (SSID: %s)", ssid),
		})
	}

	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

func (s *Server) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	serial := r.FormValue("serial")
	_ = s.db.RevokeCertificate(serial)
	http.Redirect(w, r, "/certificates", http.StatusSeeOther)
}

func (s *Server) handleDownloadCA(w http.ResponseWriter, r *http.Request) {
	caCert, err := s.db.GetActiveCACertificate()
	if err != nil {
		http.Error(w, "No active CA found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=\"UniFi-Root-CA.crt\"")
	_, _ = w.Write([]byte(caCert.CertificatePEM))
}

func (s *Server) handleDownloadPEM(w http.ResponseWriter, r *http.Request) {
	serial := r.URL.Query().Get("serial")
	cert, err := s.db.GetCertificateBySerial(serial)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	caCert, _ := s.db.GetActiveCACertificate()
	caPEM := ""
	if caCert != nil {
		caPEM = caCert.CertificatePEM
	}

	bundle := ca.CombineBundle(cert.CertificatePEM, cert.PrivateKeyPEM, caPEM)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s-bundle.pem\"", cert.CommonName))
	_, _ = w.Write([]byte(bundle))
}

func (s *Server) handleDownloadP12(w http.ResponseWriter, r *http.Request) {
	serial := r.URL.Query().Get("serial")
	cert, err := s.db.GetCertificateBySerial(serial)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	caCert, err := s.db.GetActiveCACertificate()
	if err != nil {
		http.Error(w, "CA not found", http.StatusNotFound)
		return
	}

	p12Bytes, err := ca.ExportPKCS12(cert.CertificatePEM, cert.PrivateKeyPEM, caCert.CertificatePEM, "password")
	if err != nil {
		http.Error(w, fmt.Sprintf("Export error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-pkcs12")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.p12\"", cert.CommonName))
	_, _ = w.Write(p12Bytes)
}

func (s *Server) handleDownloadMobileConfig(w http.ResponseWriter, r *http.Request) {
	serial := r.URL.Query().Get("serial")
	cert, err := s.db.GetCertificateBySerial(serial)
	if err != nil {
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	caCert, err := s.db.GetActiveCACertificate()
	if err != nil {
		http.Error(w, "CA not found", http.StatusNotFound)
		return
	}

	p12Bytes, err := ca.ExportPKCS12(cert.CertificatePEM, cert.PrivateKeyPEM, caCert.CertificatePEM, "")
	if err != nil {
		http.Error(w, fmt.Sprintf("P12 error: %v", err), http.StatusInternalServerError)
		return
	}

	mobileConfig, err := ca.GenerateAppleMobileConfig(cert.CommonName, "UniFi-Enterprise", p12Bytes, caCert.CertificatePEM, "")
	if err != nil {
		http.Error(w, fmt.Sprintf("Config error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.mobileconfig\"", cert.CommonName))
	_, _ = w.Write(mobileConfig)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	macFilter := r.URL.Query().Get("mac")
	statusFilter := r.URL.Query().Get("status")
	logs, _, _ := s.db.ListAuthLogs(100, 0, statusFilter, macFilter)
	settings, _ := s.db.GetSettings()

	data := map[string]interface{}{
		"Title":         "Live Logs & Audit",
		"PageTitle":     "Live Logs & Audit Historie",
		"ActiveNav":     "logs",
		"Logs":          logs,
		"RetentionDays": settings.LogRetentionDays,
		"MACFilter":     macFilter,
		"StatusFilter":  statusFilter,
	}
	s.renderPage(w, r, "logs.html", data)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.db.GetSettings()
	vlans, _ := s.db.ListVLANs()

	data := map[string]interface{}{
		"Title":     "Einstellungen",
		"PageTitle": "Systemeinstellungen",
		"ActiveNav": "settings",
		"Settings":  settings,
		"VLANs":     vlans,
	}
	s.renderPage(w, r, "settings.html", data)
}

func (s *Server) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	settings, _ := s.db.GetSettings()
	settings.UniFiURL = r.FormValue("unifi_url")
	settings.UniFiAuthMode = r.FormValue("unifi_auth_mode")
	settings.UniFiAPIKey = r.FormValue("unifi_api_key")
	settings.UniFiUsername = r.FormValue("unifi_username")
	if p := r.FormValue("unifi_password"); p != "" {
		settings.UniFiPassword = p
	}

	if interval, err := strconv.Atoi(r.FormValue("unifi_sync_interval")); err == nil {
		settings.UniFiSyncInterval = interval
	}
	settings.GlobalSharedSecret = r.FormValue("global_shared_secret")
	if rPort, err := strconv.Atoi(r.FormValue("radius_auth_port")); err == nil && rPort > 0 {
		settings.RADIUSAuthPort = rPort
	} else {
		settings.RADIUSAuthPort = 1812
	}

	if defVLAN, err := strconv.Atoi(r.FormValue("default_allow_vlan")); err == nil {
		settings.DefaultAllowVLAN = defVLAN
	}
	settings.UnknownMABPolicy = models.UnknownMABPolicy(r.FormValue("unknown_mab_policy"))

	if wPort, err := strconv.Atoi(r.FormValue("web_port")); err == nil && wPort > 0 {
		settings.WebPort = wPort
	} else {
		settings.WebPort = 9182
	}
	if retDays, err := strconv.Atoi(r.FormValue("log_retention_days")); err == nil {
		settings.LogRetentionDays = retDays
	}

	if newAdminPass := r.FormValue("web_admin_password"); newAdminPass != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newAdminPass), bcrypt.DefaultCost)
		if err == nil {
			settings.WebAdminPassword = string(hash)
		}
	}

	// Notifications
	_ = r.ParseForm()
	notifyEventsList := r.Form["notify_events"]
	if len(notifyEventsList) > 0 {
		settings.NotifyEvents = strings.Join(notifyEventsList, ",")
	}
	if t := strings.TrimSpace(r.FormValue("daily_summary_time")); t != "" {
		settings.DailySummaryTime = t
	}

	settings.TelegramEnabled = r.FormValue("telegram_enabled") == "1" || r.FormValue("telegram_enabled") == "on"
	if tgTok := strings.TrimSpace(r.FormValue("telegram_bot_token")); tgTok != "" {
		settings.TelegramBotToken = tgTok
	}
	settings.TelegramChatIDs = strings.TrimSpace(r.FormValue("telegram_chat_ids"))

	settings.DiscordEnabled = r.FormValue("discord_enabled") == "1" || r.FormValue("discord_enabled") == "on"
	if dcTok := strings.TrimSpace(r.FormValue("discord_bot_token")); dcTok != "" {
		settings.DiscordBotToken = dcTok
	}
	settings.DiscordChannelID = strings.TrimSpace(r.FormValue("discord_channel_id"))

	settings.PushoverEnabled = r.FormValue("pushover_enabled") == "1" || r.FormValue("pushover_enabled") == "on"
	if poTok := strings.TrimSpace(r.FormValue("pushover_api_token")); poTok != "" {
		settings.PushoverAPIToken = poTok
	}
	if poUser := strings.TrimSpace(r.FormValue("pushover_user_key")); poUser != "" {
		settings.PushoverUserKey = poUser
	}

	settings.HomeAssistantEnabled = r.FormValue("homeassistant_enabled") == "1" || r.FormValue("homeassistant_enabled") == "on"
	settings.HomeAssistantWebhookURL = strings.TrimSpace(r.FormValue("homeassistant_webhook_url"))

	// Remote Backup
	settings.RemoteBackupEnabled = r.FormValue("remote_backup_enabled") == "1" || r.FormValue("remote_backup_enabled") == "on"
	if bType := strings.TrimSpace(r.FormValue("remote_backup_type")); bType != "" {
		settings.RemoteBackupType = bType
	}
	settings.RemoteBackupURL = strings.TrimSpace(r.FormValue("remote_backup_url"))
	settings.RemoteBackupPath = strings.TrimSpace(r.FormValue("remote_backup_path"))
	settings.RemoteBackupUsername = strings.TrimSpace(r.FormValue("remote_backup_username"))
	if bPass := strings.TrimSpace(r.FormValue("remote_backup_password")); bPass != "" {
		settings.RemoteBackupPassword = bPass
	}
	if bSched := strings.TrimSpace(r.FormValue("remote_backup_schedule")); bSched != "" {
		settings.RemoteBackupSchedule = bSched
	}
	if bRet, err := strconv.Atoi(r.FormValue("remote_backup_retention")); err == nil && bRet >= 0 {
		settings.RemoteBackupRetention = bRet
	}

	// Automated Self-Update
	settings.AutoUpdateEnabled = r.FormValue("auto_update_enabled") == "1" || r.FormValue("auto_update_enabled") == "on"
	if uSched := strings.TrimSpace(r.FormValue("auto_update_schedule")); uSched != "" {
		settings.AutoUpdateSchedule = uSched
	}
	if uTime := strings.TrimSpace(r.FormValue("auto_update_time")); uTime != "" {
		settings.AutoUpdateTime = uTime
	}
	if uWday, err := strconv.Atoi(r.FormValue("auto_update_weekday")); err == nil && uWday >= 1 && uWday <= 7 {
		settings.AutoUpdateWeekday = uWday
	}
	if uDay, err := strconv.Atoi(r.FormValue("auto_update_day")); err == nil && uDay >= 1 && uDay <= 31 {
		settings.AutoUpdateDay = uDay
	}

	_ = s.db.UpdateSettings(settings)

	if s.notifySvc != nil {
		_ = s.notifySvc.Reload()
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleTestRemoteBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if s.backupSvc == nil {
		_, _ = w.Write([]byte("<div class='badge reject' style='padding: 6px 10px;'>Backup-Dienst nicht initialisiert</div>"))
		return
	}

	settings, err := s.db.GetSettings()
	if err != nil {
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 6px 10px;'>Fehler: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	if t := strings.TrimSpace(r.FormValue("remote_backup_type")); t != "" {
		settings.RemoteBackupType = t
	}
	if u := strings.TrimSpace(r.FormValue("remote_backup_url")); u != "" {
		settings.RemoteBackupURL = u
	}
	if p := strings.TrimSpace(r.FormValue("remote_backup_path")); p != "" {
		settings.RemoteBackupPath = p
	}
	if user := strings.TrimSpace(r.FormValue("remote_backup_username")); user != "" {
		settings.RemoteBackupUsername = user
	}
	if pass := strings.TrimSpace(r.FormValue("remote_backup_password")); pass != "" {
		settings.RemoteBackupPassword = pass
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if err := s.backupSvc.TestConnection(ctx, settings); err != nil {
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 6px 10px;'>Verbindung fehlgeschlagen: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	_, _ = w.Write([]byte("<div class='badge active' style='padding: 6px 10px;'>✓ Verbindung zum Backup-Ziel erfolgreich hergestellt!</div>"))
}

func (s *Server) handleRunRemoteBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if s.backupSvc == nil {
		_, _ = w.Write([]byte("<div class='badge reject' style='padding: 6px 10px;'>Backup-Dienst nicht initialisiert</div>"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	res, err := s.backupSvc.RunBackup(ctx)
	if err != nil {
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 6px 10px;'>Backup fehlgeschlagen: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge active' style='padding: 6px 10px;'>✓ %s (%s, %d KB)</div>",
		template.HTMLEscapeString(res.Message),
		template.HTMLEscapeString(res.Filename),
		res.SizeBytes/1024,
	)))
}

func (s *Server) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	provider := r.FormValue("provider")
	if s.notifySvc == nil {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div class='badge reject' style='padding: 6px 10px;'>Benachrichtigungsdienst nicht initialisiert</div>"))
		return
	}

	_ = s.notifySvc.Reload()
	err := s.notifySvc.SendTest(r.Context(), provider)
	w.Header().Set("Content-Type", "text/html")
	if err != nil {
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 6px 10px;'>Fehler: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	_, _ = w.Write([]byte("<div class='badge active' style='padding: 6px 10px;'>✓ Test-Nachricht erfolgreich gesendet!</div>"))
}

func (s *Server) handleTestUniFi(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.db.GetSettings()
	client, err := unifi.NewClient(unifi.Config{
		BaseURL:  settings.UniFiURL,
		AuthMode: settings.UniFiAuthMode,
		APIKey:   settings.UniFiAPIKey,
		Username: settings.UniFiUsername,
		Password: settings.UniFiPassword,
	})
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 8px 12px;'>Fehler: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	if err := client.TestConnection(); err != nil {
		w.Header().Set("Content-Type", "text/html")
		errMsg := template.HTMLEscapeString(err.Error())
		if settings.UniFiAuthMode == "apikey" && (strings.Contains(settings.UniFiURL, "127.0.0.1") || strings.Contains(settings.UniFiURL, "localhost")) && (strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unauthorized")) {
			errMsg += "<br><small style='display:block; margin-top: 4px; font-weight: normal; opacity: 0.9;'>Hinweis: UniFi OS weist API-Keys über 127.0.0.1 ab. Bitte tragen Sie die Gateway-/LAN-IP der UDM ein (z. B. https://192.168.1.1 oder https://192.168.13.1).</small>"
		}
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 8px 12px; line-height: 1.4;'>Verbindung fehlgeschlagen: %s</div>", errMsg)))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<div class='badge active' style='padding: 8px 12px;'>Verbindung zu UniFi erfolgreich hergestellt!</div>"))
}

func (s *Server) handleTriggerSync(w http.ResponseWriter, r *http.Request) {
	if s.syncSvc != nil {
		_ = s.syncSvc.SyncNow()
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleMigrationStatus(w http.ResponseWriter, r *http.Request) {
	settings, _ := s.db.GetSettings()
	client, err := unifi.NewClient(unifi.Config{
		BaseURL:  settings.UniFiURL,
		AuthMode: settings.UniFiAuthMode,
		APIKey:   settings.UniFiAPIKey,
		Username: settings.UniFiUsername,
		Password: settings.UniFiPassword,
	})
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject'>Fehler: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	enabled, secret, count, err := unifi.CheckBuiltinRadiusStatus(client)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject'>Status nicht ermittelbar: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if enabled {
		secretMasked := "***"
		if len(secret) > 3 {
			secretMasked = secret[:2] + strings.Repeat("*", len(secret)-2)
		}
		html := fmt.Sprintf(`
		<div style="background-color: var(--yellow-bg); border: 1px solid var(--yellow); padding: 12px 16px; border-radius: 8px;">
			<div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
				<strong style="color: var(--yellow);">Integrierter UniFi RADIUS Server ist AKTIV</strong>
				<span class="badge pending">Aktiv auf UDM</span>
			</div>
			<div style="font-size: 12px; color: var(--text-muted); line-height: 1.5;">
				Gefundene lokale Benutzerkonten / MAB-Einträge: <strong>%d</strong> &bull; Shared Secret konfiguriert: <code>%s</code>
			</div>
			<div style="font-size: 11px; color: var(--text-dim); margin-top: 4px;">
				Tipp: Führe die Migration durch, um bestehende MAB-Geräte zu übernehmen und Port 1812 freizugeben.
			</div>
		</div>
		`, count, template.HTMLEscapeString(secretMasked))
		_, _ = w.Write([]byte(html))
	} else {
		html := fmt.Sprintf(`
		<div style="background-color: rgba(255, 255, 255, 0.02); border: 1px solid var(--border); padding: 10px 14px; border-radius: 8px; font-size: 12px; color: var(--text-muted);">
			Integrierter UniFi RADIUS-Server: <strong>Inaktiv / Deaktiviert</strong> &bull; Lokale Accounts in UniFi: <strong>%d</strong>
		</div>
		`, count)
		_, _ = w.Write([]byte(html))
	}
}

func (s *Server) handlePerformMigration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}

	disableBuiltin := r.FormValue("disable_builtin") == "1"
	updateProfile := r.FormValue("update_profile") == "1"

	settings, _ := s.db.GetSettings()
	client, err := unifi.NewClient(unifi.Config{
		BaseURL:  settings.UniFiURL,
		AuthMode: settings.UniFiAuthMode,
		APIKey:   settings.UniFiAPIKey,
		Username: settings.UniFiUsername,
		Password: settings.UniFiPassword,
	})
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 10px;'>Verbindungsfehler: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	report, err := unifi.MigrateBuiltinRadius(client, s.db, disableBuiltin, updateProfile)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(fmt.Sprintf("<div class='badge reject' style='padding: 10px;'>Migration fehlgeschlagen: %s</div>", template.HTMLEscapeString(err.Error()))))
		return
	}

	if s.syncSvc != nil {
		s.syncSvc.TriggerSync()
	}

	s.bus.PublishLog(eventbus.LogEvent{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     eventbus.LogLevelInfo,
		Source:    "MIGRATION",
		Message:   fmt.Sprintf("UniFi RADIUS Migration abgeschlossen: %d MAB-Geräte, %d Benutzer", report.MABDevicesMigrated, report.UsersMigrated),
	})

	w.Header().Set("Content-Type", "text/html")
	var sb strings.Builder
	sb.WriteString("<div style='background-color: var(--green-bg); border: 1px solid var(--green); padding: 14px 18px; border-radius: 8px;'>")
	sb.WriteString("<div style='font-weight: 600; color: var(--green); margin-bottom: 8px;'>✓ Migration erfolgreich durchgeführt!</div>")
	sb.WriteString("<ul style='margin-left: 20px; font-size: 12px; color: var(--text-main); line-height: 1.6;'>")
	for _, msg := range report.Messages {
		sb.WriteString(fmt.Sprintf("<li>%s</li>", template.HTMLEscapeString(msg)))
	}
	sb.WriteString("</ul></div>")

	_, _ = w.Write([]byte(sb.String()))
}

// handleWebSocket handles the HTMX WebSocket connection and streams live HTML snippets.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Authenticate WebSocket connection
	cookie, err := r.Cookie("session_id")
	if err != nil || !s.isValidSession(cookie.Value) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	authSub, unsubAuth := s.bus.SubscribeAuth()
	defer unsubAuth()

	logSub, replayLogs, unsubLog := s.bus.SubscribeLogs()
	defer unsubLog()

	// Replay recent logs to terminal
	for _, l := range replayLogs {
		html := formatLogLineHTML(l)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(html))
	}

	done := make(chan struct{})
	go func() {
		// Drain client incoming messages or detect disconnect
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				close(done)
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return

		case authEvent := <-authSub:
			html := formatAuthRowHTML(authEvent)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(html)); err != nil {
				return
			}

		case logEvent := <-logSub:
			html := formatLogLineHTML(logEvent)
			if err := conn.WriteMessage(websocket.TextMessage, []byte(html)); err != nil {
				return
			}
		}
	}
}

func formatAuthRowHTML(a models.AuthLog) string {
	statusBadge := `<span class="badge accept">ACCEPT</span>`
	if a.Status != "ACCEPT" {
		statusBadge = `<span class="badge reject">REJECT</span>`
	}

	vlanBadge := `<span class="badge dim">-</span>`
	if a.VLANID != nil {
		vlanBadge = fmt.Sprintf(`<span class="badge vlan">VLAN %d</span>`, *a.VLANID)
	}

	ident := a.ClientMAC
	if ident == "" {
		ident = a.Username
	}

	enrichedName := "Unbekannt"
	if a.EnrichedName != "" {
		enrichedName = a.EnrichedName
	}

	tsRFC := a.Timestamp.Format(time.RFC3339)
	tsFallback := a.Timestamp.Format("15:04:05")

	// Uses hx-swap-oob="afterbegin" on #live-feed-rows
	return fmt.Sprintf(`
	<tr id="live-feed-rows" hx-swap-oob="afterbegin">
		<td style="color: var(--text-dim); font-size: 12px;"><time class="local-time" datetime="%s" data-format="time">%s</time></td>
		<td>%s</td>
		<td><span class="code-pill">%s</span></td>
		<td>%s</td>
		<td>
			<div><strong>%s</strong></div>
			<div style="font-size: 11px; color: var(--text-dim);">%s</div>
		</td>
		<td>
			<div>%s</div>
			<div style="font-size: 11px; color: var(--text-dim);">Port %s</div>
		</td>
		<td style="color: var(--text-muted); font-size: 12px;">%.1f ms</td>
	</tr>
	`,
		template.HTMLEscapeString(tsRFC),
		template.HTMLEscapeString(tsFallback),
		statusBadge,
		template.HTMLEscapeString(ident),
		vlanBadge,
		template.HTMLEscapeString(enrichedName),
		template.HTMLEscapeString(a.EnrichedVendor),
		template.HTMLEscapeString(a.NASIP),
		template.HTMLEscapeString(a.NASPort),
		a.LatencyMS,
	)
}

func formatLogLineHTML(l eventbus.LogEvent) string {
	lvlClass := "terminal-lvl-info"
	if l.Level == eventbus.LogLevelWarn {
		lvlClass = "terminal-lvl-warn"
	} else if l.Level == eventbus.LogLevelError {
		lvlClass = "terminal-lvl-error"
	}

	nowRFC := time.Now().UTC().Format(time.RFC3339)

	// Uses hx-swap-oob="beforeend" on #terminalConsole
	return fmt.Sprintf(`
	<div id="terminalConsole" hx-swap-oob="beforeend">
		<div class="terminal-line">
			<span class="terminal-ts">[<time class="local-time" datetime="%s" data-format="time">%s</time>]</span>
			<span class="terminal-src">[%s]</span>
			<span class="%s">[%s]</span>
			<span>%s</span>
		</div>
	</div>
	`,
		template.HTMLEscapeString(nowRFC),
		template.HTMLEscapeString(l.Timestamp),
		template.HTMLEscapeString(l.Source),
		template.HTMLEscapeString(lvlClass),
		template.HTMLEscapeString(string(l.Level)),
		template.HTMLEscapeString(l.Message),
	)
}

func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, tmplName string, data map[string]interface{}) {
	tmpl, exists := s.pages[tmplName]
	if !exists {
		http.Error(w, fmt.Sprintf("Template '%s' not found", tmplName), http.StatusInternalServerError)
		return
	}

	if data != nil {
		if _, ok := data["Lang"]; !ok {
			data["Lang"] = i18n.DetectLanguage(r)
		}
		if _, ok := data["CurrentPath"]; !ok {
			data["CurrentPath"] = r.URL.Path
		}
		if _, ok := data["Version"]; !ok {
			data["Version"] = s.version
		}
		if _, ok := data["RadiusListening"]; !ok {
			if s.radiusSrv != nil {
				data["RadiusListening"] = s.radiusSrv.IsListening()
			} else {
				data["RadiusListening"] = true
			}
		}
		if _, ok := data["RadiusPort"]; !ok {
			if s.radiusSrv != nil {
				data["RadiusPort"] = s.radiusSrv.Port()
			} else {
				data["RadiusPort"] = 1812
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	err := tmpl.ExecuteTemplate(&buf, "layout", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Template rendering error: %v", err), http.StatusInternalServerError)
		return
	}
	_, _ = io.Copy(w, &buf)
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	view := r.URL.Query().Get("view")
	force := r.URL.Query().Get("force") == "true"

	info := s.updater.Check(force)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	switch view {
	case "badge":
		if info.UpdateAvailable {
			fmt.Fprintf(w, `<a href="%s" target="_blank" style="color: var(--yellow); text-decoration: none; font-size: 11px; display: inline-flex; align-items: center; gap: 4px;" title="Update v%s verfügbar!">
				<span class="pulse-dot" style="background-color: var(--yellow); width: 6px; height: 6px;"></span>
				<span>v%s verfügbar</span>
			</a>`, info.ReleaseURL, info.LatestVersion, info.LatestVersion)
		} else {
			fmt.Fprint(w, `<span style="color: var(--text-dim); font-size: 11px;">(Aktuell)</span>`)
		}
	case "settings":
		if info.UpdateAvailable {
			fmt.Fprintf(w, `
			<div style="background-color: rgba(234, 179, 8, 0.1); border: 1px solid rgba(234, 179, 8, 0.3); border-radius: 8px; padding: 16px; margin-top: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
				<div>
					<div style="font-weight: 600; color: var(--yellow); font-size: 15px;">⚡ Neue Version v%s verfügbar!</div>
					<div style="font-size: 12px; color: var(--text-muted); margin-top: 3px;">Aktuell installiert: v%s &bull; Veröffentlicht auf GitHub</div>
				</div>
				<div style="display: flex; gap: 10px; align-items: center;">
					<a href="%s" target="_blank" class="btn btn-secondary btn-sm" style="text-decoration: none;">Release-Notes</a>
					<button type="button" class="btn btn-primary btn-sm" onclick="triggerOneClickUpdate('%s')" style="display: inline-flex; align-items: center; gap: 6px;">
						<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
						<span>⚡ Jetzt auf v%s aktualisieren (One-Click)</span>
					</button>
				</div>
			</div>`, info.LatestVersion, info.CurrentVersion, info.ReleaseURL, info.LatestVersion, info.LatestVersion)
		} else if info.Error != "" {
			fmt.Fprintf(w, `
			<div style="font-size: 12px; color: var(--text-dim); margin-top: 10px;">
				Status: %s (v%s)
			</div>`, info.Error, info.CurrentVersion)
		} else {
			fmt.Fprintf(w, `
			<div style="display: flex; align-items: center; gap: 8px; color: var(--green); font-size: 13px; margin-top: 10px;">
				<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
				<span>UniFi RADIUS Server v%s ist auf dem neuesten Stand.</span>
			</div>`, info.CurrentVersion)
		}
	default:
		// Topbar banner
		if info.UpdateAvailable {
			fmt.Fprintf(w, `
			<div id="update-notification" style="background: linear-gradient(90deg, rgba(234, 179, 8, 0.15) 0%%, rgba(234, 179, 8, 0.05) 100%%); border: 1px solid rgba(234, 179, 8, 0.3); border-radius: 8px; padding: 10px 16px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; animation: fadeIn 0.3s ease-in-out;">
				<div style="display: flex; align-items: center; gap: 10px; font-size: 13px;">
					<span class="pulse-dot" style="background-color: var(--yellow);"></span>
					<span><strong>Update verfügbar:</strong> Version <strong>v%s</strong> ist verfügbar (Installiert: v%s).</span>
				</div>
				<div style="display: flex; align-items: center; gap: 8px;">
					<button type="button" class="btn btn-sm btn-primary" onclick="triggerOneClickUpdate('%s')" style="font-size: 12px; display: inline-flex; align-items: center; gap: 5px;">
						<span>⚡ Jetzt aktualisieren</span>
					</button>
					<a href="%s" target="_blank" class="btn btn-sm btn-secondary" style="text-decoration: none; font-size: 12px;">Release</a>
					<button type="button" class="btn btn-sm btn-secondary" onclick="document.getElementById('update-notification').remove();" style="font-size: 12px;">✕</button>
				</div>
			</div>`, info.LatestVersion, info.CurrentVersion, info.LatestVersion, info.ReleaseURL)
		} else {
			fmt.Fprint(w, `<div id="update-notification" style="display: none;"></div>`)
		}
	}
}

func (s *Server) handleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if s.updater == nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Update-Dienst ist nicht initialisiert",
		})
		return
	}

	version := strings.TrimSpace(r.FormValue("version"))
	s.publishLog(eventbus.LogLevelInfo, "UPDATE", fmt.Sprintf("Starte One-Click Self-Update (Zielversion: %s)...", version))

	if err := s.updater.ApplyUpdate(version); err != nil {
		s.publishLog(eventbus.LogLevelError, "UPDATE", fmt.Sprintf("Self-Update fehlgeschlagen: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Update fehlgeschlagen: %v", err),
		})
		return
	}

	s.publishLog(eventbus.LogLevelInfo, "UPDATE", fmt.Sprintf("Update auf v%s erfolgreich installiert. Server startet in 2 Sekunden neu...", version))

	if s.notifySvc != nil {
		targetDesc := version
		if targetDesc == "" {
			targetDesc = "neueste Version"
		}
		s.notifySvc.Dispatch(r.Context(), notify.NotificationEvent{
			Type:      "system_update",
			Title:     "⚡ Software-Update erfolgreich installiert",
			Message:   fmt.Sprintf("UniFi RADIUS Server wurde per One-Click auf %s aktualisiert. Der Server startet jetzt neu.", targetDesc),
			Timestamp: time.Now(),
		})
	}

	s.updater.TriggerRestart()

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      "Update erfolgreich installiert! Der Server startet neu. Die Seite lädt automatisch neu...",
		"reload_delay": 5,
	})
}

func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	filename := fmt.Sprintf("radius-backup-%s.db", time.Now().Format("2006-01-02-150405"))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	if err := s.db.Backup(w); err != nil {
		http.Error(w, fmt.Sprintf("Backup failed: %v", err), http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit backup file size to 50 MB to prevent memory / disk exhaustion DoS
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)

	file, _, err := r.FormFile("backup_file")
	if err != nil {
		http.Error(w, "No file uploaded or file exceeds maximum allowed size (50MB)", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if err := s.db.Restore(file); err != nil {
		http.Error(w, fmt.Sprintf("Restore failed: %v", err), http.StatusBadRequest)
		return
	}

	s.publishLog(eventbus.LogLevelInfo, "SYSTEM", "Datenbank-Backup erfolgreich wiederhergestellt.")
	http.Redirect(w, r, "/settings?restored=1", http.StatusSeeOther)
}
