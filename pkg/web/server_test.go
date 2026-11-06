package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/ca"
	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/unifi"
	"software.sslmate.com/src/go-pkcs12"
)

func setupTestWebServer(t *testing.T) (*Server, *database.DB) {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("Open test DB failed: %v", err)
	}

	bus := eventbus.NewBus(100)
	syncSvc := unifi.NewSyncService(db, bus)
	srv, err := NewServer(db, bus, syncSvc, 9999)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	return srv, db
}

func TestInitialLoginSetup(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Initial GET /login should display initial setup
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	srv.handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Ersteinrichtung") {
		t.Error("Expected initial setup text on first login")
	}

	// 2. POST /login with new password sets master password and session
	formData := url.Values{}
	formData.Set("password", "supersecret123")
	reqPost := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrPost := httptest.NewRecorder()
	srv.handleLogin(rrPost, reqPost)

	if rrPost.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", rrPost.Code)
	}

	cookies := rrPost.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session_id" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("Expected session_id cookie set after login")
	}

	// 3. Verify settings updated with hashed password
	settings, _ := db.GetSettings()
	if settings.WebAdminPassword == "" || settings.WebAdminPassword == "supersecret123" {
		t.Errorf("Password was not properly hashed in DB: %s", settings.WebAdminPassword)
	}
}

func TestProtectedRoutesRedirect(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// Set password
	settings, _ := db.GetSettings()
	settings.WebAdminPassword = "hash"
	_ = db.UpdateSettings(settings)

	// Access without session cookie should redirect to /login
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	srv.requireAuth(srv.handleDashboard)(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("Expected redirect 303, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Errorf("Expected redirect to /login, got %s", loc)
	}
}

func TestStaticAssetsEmbedded(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// Verify static assets can be read
	reqCSS := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	rrCSS := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rrCSS, reqCSS)

	if rrCSS.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /static/style.css, got %d", rrCSS.Code)
	}
	if !strings.Contains(rrCSS.Body.String(), "--unifi-blue") {
		t.Error("style.css does not contain UniFi blue palette")
	}

	reqHTMX := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	rrHTMX := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rrHTMX, reqHTMX)

	if rrHTMX.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /static/htmx.min.js, got %d", rrHTMX.Code)
	}

	// Verify favicon routes
	reqFavicon := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rrFavicon := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rrFavicon, reqFavicon)
	if rrFavicon.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /favicon.ico, got %d", rrFavicon.Code)
	}
	if ct := rrFavicon.Header().Get("Content-Type"); ct != "image/x-icon" {
		t.Errorf("Expected Content-Type image/x-icon for /favicon.ico, got %s", ct)
	}

	reqSVG := httptest.NewRequest(http.MethodGet, "/static/favicon.svg", nil)
	rrSVG := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rrSVG, reqSVG)
	if rrSVG.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /static/favicon.svg, got %d", rrSVG.Code)
	}
	if !strings.Contains(rrSVG.Body.String(), "<svg") {
		t.Error("favicon.svg does not contain SVG root element")
	}

	reqTouch := httptest.NewRequest(http.MethodGet, "/apple-touch-icon.png", nil)
	rrTouch := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rrTouch, reqTouch)
	if rrTouch.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for /apple-touch-icon.png, got %d", rrTouch.Code)
	}
	if ct := rrTouch.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Expected Content-Type image/png for /apple-touch-icon.png, got %s", ct)
	}
}

func TestTabRenderingDistinctContent(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Dashboard
	rrDashboard := httptest.NewRecorder()
	reqDashboard := httptest.NewRequest(http.MethodGet, "/", nil)
	srv.handleDashboard(rrDashboard, reqDashboard)
	if !strings.Contains(rrDashboard.Body.String(), "Echtzeit RADIUS-Aktivitätsmonitor") {
		t.Errorf("Dashboard page does not contain live monitor content")
	}
	if strings.Contains(rrDashboard.Body.String(), "UniFi RADIUS Migration & Übernahme") {
		t.Errorf("Dashboard page incorrectly contains settings content!")
	}

	// 2. Clients
	rrClients := httptest.NewRecorder()
	reqClients := httptest.NewRequest(http.MethodGet, "/clients", nil)
	srv.handleClients(rrClients, reqClients)
	if !strings.Contains(rrClients.Body.String(), "MAB Geräte") {
		t.Errorf("Clients page does not contain MAB clients content")
	}
	if strings.Contains(rrClients.Body.String(), "UniFi RADIUS Migration") {
		t.Errorf("Clients page incorrectly contains settings content!")
	}

	// 3. Certificates
	rrCerts := httptest.NewRecorder()
	reqCerts := httptest.NewRequest(http.MethodGet, "/certificates", nil)
	srv.handleCertificates(rrCerts, reqCerts)
	if !strings.Contains(rrCerts.Body.String(), "Integrierte CA") {
		t.Errorf("Certificates page does not contain CA content")
	}
	if strings.Contains(rrCerts.Body.String(), "UniFi RADIUS Migration") {
		t.Errorf("Certificates page incorrectly contains settings content!")
	}

	// 4. Logs
	rrLogs := httptest.NewRecorder()
	reqLogs := httptest.NewRequest(http.MethodGet, "/logs", nil)
	srv.handleLogs(rrLogs, reqLogs)
	if !strings.Contains(rrLogs.Body.String(), "Echtzeit System-") {
		t.Errorf("Logs page does not contain live log content")
	}
	if strings.Contains(rrLogs.Body.String(), "UniFi RADIUS Migration") {
		t.Errorf("Logs page incorrectly contains settings content!")
	}

	// 5. Settings
	rrSettings := httptest.NewRecorder()
	reqSettings := httptest.NewRequest(http.MethodGet, "/settings", nil)
	srv.handleSettings(rrSettings, reqSettings)
	if !strings.Contains(rrSettings.Body.String(), "UniFi RADIUS Migration") {
		t.Errorf("Settings page does not contain migration content")
	}
}

func TestMigrationEndpoints(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/proxy/network/api/s/default/get/setting/radius":
			w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"1","key":"radius","enabled":true,"x_secret":"migrated123","auth_port":1812}]}`))
		case "/proxy/network/api/s/default/set/setting/radius":
			w.Write([]byte(`{"meta":{"rc":"ok"}}`))
		case "/proxy/network/api/s/default/rest/account":
			w.Write([]byte(`{"meta":{"rc":"ok"},"data":[{"_id":"1","name":"00:11:22:33:44:55","vlan":25}]}`))
		case "/proxy/network/api/s/default/rest/radiusprofile":
			w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	srv, db := setupTestWebServer(t)
	defer db.Close()

	settings, _ := db.GetSettings()
	settings.UniFiURL = ts.URL
	settings.UniFiAuthMode = "apikey"
	settings.UniFiAPIKey = "dummy-key"
	_ = db.UpdateSettings(settings)

	// 1. Status endpoint
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/unifi/migration-status", nil)
	rrStatus := httptest.NewRecorder()
	srv.handleMigrationStatus(rrStatus, reqStatus)

	if rrStatus.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rrStatus.Code)
	}
	if !strings.Contains(rrStatus.Body.String(), "Integrierter UniFi RADIUS Server ist AKTIV") {
		t.Errorf("Unexpected status output: %s", rrStatus.Body.String())
	}

	// 2. Perform Migration endpoint
	form := url.Values{}
	form.Set("disable_builtin", "1")
	form.Set("update_profile", "1")
	reqMigrate := httptest.NewRequest(http.MethodPost, "/api/unifi/migrate", strings.NewReader(form.Encode()))
	reqMigrate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrMigrate := httptest.NewRecorder()
	srv.handlePerformMigration(rrMigrate, reqMigrate)

	if rrMigrate.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rrMigrate.Code)
	}
	if !strings.Contains(rrMigrate.Body.String(), "Migration erfolgreich durchgeführt") {
		t.Errorf("Unexpected migration output: %s", rrMigrate.Body.String())
	}

	// Verify MAB device imported in DB
	c, err := db.GetClientByMAC("00:11:22:33:44:55")
	if err != nil || c == nil || *c.VLANID != 25 {
		t.Fatalf("Client was not migrated into SQLite: %v, %+v", err, c)
	}
}

func TestLanguageSwitchAndEnglishRendering(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Language switcher route sets cookie
	reqSet := httptest.NewRequest(http.MethodGet, "/api/set-language?lang=en&redirect=/clients", nil)
	rrSet := httptest.NewRecorder()
	srv.handleSetLanguage(rrSet, reqSet)

	if rrSet.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", rrSet.Code)
	}
	cookies := rrSet.Result().Cookies()
	var foundLangCookie bool
	for _, c := range cookies {
		if c.Name == "lang" && c.Value == "en" {
			foundLangCookie = true
			break
		}
	}
	if !foundLangCookie {
		t.Errorf("Expected 'lang=en' cookie to be set")
	}

	// 2. Request with English Accept-Language header renders in English
	reqEN := httptest.NewRequest(http.MethodGet, "/clients", nil)
	reqEN.Header.Set("Accept-Language", "en-US,en;q=0.9")
	rrEN := httptest.NewRecorder()
	srv.handleClients(rrEN, reqEN)

	if !strings.Contains(rrEN.Body.String(), "MAB Devices") {
		t.Errorf("Expected English content 'MAB Devices', got:\n%s", rrEN.Body.String())
	}
	if !strings.Contains(rrEN.Body.String(), "Add New Device") {
		t.Errorf("Expected English button 'Add New Device'")
	}
}

func TestClientsVLANNameAndFiltering(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Add VLANs
	vlans := []models.VLAN{
		{VLANID: 1, Name: "Default LAN", IsDefault: true},
		{VLANID: 10, Name: "Office Network"},
		{VLANID: 20, Name: "IoT Devices"},
	}
	if err := db.ReplaceVLANs(vlans); err != nil {
		t.Fatalf("ReplaceVLANs failed: %v", err)
	}

	vlan10 := 10
	clientA := &models.Client{
		MACAddress:  "AA:BB:CC:DD:EE:01",
		VLANID:      &vlan10,
		Status:      models.ClientStatusActive,
		Description: "Office Workstation",
	}
	clientB := &models.Client{
		MACAddress:  "AA:BB:CC:DD:EE:02",
		VLANID:      nil,
		Status:      models.ClientStatusActive,
		Description: "Guest Tablet",
	}
	_ = db.CreateClient(clientA)
	_ = db.CreateClient(clientB)

	// 2. GET /clients - check both clients rendered and VLAN names appear
	req := httptest.NewRequest(http.MethodGet, "/clients", nil)
	rr := httptest.NewRecorder()
	srv.handleClients(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}
	body := rr.Body.String()

	if !strings.Contains(body, "Office Network") {
		t.Errorf("Expected VLAN name 'Office Network' in table rendering")
	}
	if !strings.Contains(body, "Default LAN") {
		t.Errorf("Expected Default VLAN name 'Default LAN' in table rendering")
	}
	if !strings.Contains(body, "name=\"vlan\"") {
		t.Errorf("Expected VLAN filter dropdown in template")
	}

	// 3. Filter by VLAN 10 (?vlan=10)
	reqVLAN10 := httptest.NewRequest(http.MethodGet, "/clients?vlan=10", nil)
	rrVLAN10 := httptest.NewRecorder()
	srv.handleClients(rrVLAN10, reqVLAN10)

	bodyVLAN10 := rrVLAN10.Body.String()
	if !strings.Contains(bodyVLAN10, "AA:BB:CC:DD:EE:01") {
		t.Errorf("Expected client A in filtered VLAN 10 results")
	}
	if strings.Contains(bodyVLAN10, "AA:BB:CC:DD:EE:02") {
		t.Errorf("Expected client B to be filtered out for VLAN 10")
	}

	// 4. Filter by default VLAN (?vlan=default)
	reqDef := httptest.NewRequest(http.MethodGet, "/clients?vlan=default", nil)
	rrDef := httptest.NewRecorder()
	srv.handleClients(rrDef, reqDef)

	bodyDef := rrDef.Body.String()
	if !strings.Contains(bodyDef, "AA:BB:CC:DD:EE:02") {
		t.Errorf("Expected client B in default VLAN results")
	}
	if strings.Contains(bodyDef, "AA:BB:CC:DD:EE:01") {
		t.Errorf("Expected client A to be filtered out for default VLAN")
	}
}

func TestUniFiSyncTriggerEndpoint(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	logCh, _, unsub := srv.bus.SubscribeLogs()
	defer unsub()

	req := httptest.NewRequest(http.MethodPost, "/api/unifi/sync", nil)
	rr := httptest.NewRecorder()
	srv.handleTriggerSync(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}

	found := false
	for len(logCh) > 0 {
		l := <-logCh
		if l.Source == "UNIFI-SYNC" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected UNIFI-SYNC log event on eventbus, got none")
	}
}

func TestRestartPortAndReconnectEndpoints(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// Create test client
	c := &models.Client{
		MACAddress:      "aa:bb:cc:dd:ee:11",
		AuthType:        models.AuthTypeMAB,
		Status:          models.ClientStatusActive,
		UniFiSwitchMAC:  "00:11:22:33:44:55",
		UniFiSwitchPort: "7",
		UniFiIsWired:    true,
	}
	if err := db.CreateClient(c); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// 1. Test POST /clients/restart-port via HTMX
	reqPort := httptest.NewRequest(http.MethodPost, "/clients/restart-port?id=1", nil)
	reqPort.Header.Set("HX-Request", "true")
	rrPort := httptest.NewRecorder()
	srv.handleRestartPort(rrPort, reqPort)

	if rrPort.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for HTMX restart-port, got %d", rrPort.Code)
	}
	if !strings.Contains(rrPort.Header().Get("HX-Trigger"), "showToast") {
		t.Errorf("Expected HX-Trigger showToast header, got %s", rrPort.Header().Get("HX-Trigger"))
	}

	// 2. Test POST /clients/reconnect via HTMX
	reqRec := httptest.NewRequest(http.MethodPost, "/clients/reconnect?id=1", nil)
	reqRec.Header.Set("HX-Request", "true")
	rrRec := httptest.NewRecorder()
	srv.handleReconnectClient(rrRec, reqRec)

	if rrRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for HTMX reconnect, got %d", rrRec.Code)
	}
	if !strings.Contains(rrRec.Header().Get("HX-Trigger"), "showToast") {
		t.Errorf("Expected HX-Trigger showToast header, got %s", rrRec.Header().Get("HX-Trigger"))
	}
}

func TestStandardUserCreateUpdateAndAuth(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Create a standard User with username & password
	formCreate := url.Values{}
	formCreate.Set("entry_type", "user")
	formCreate.Set("username", "johndoe")
	formCreate.Set("password", "Secret123!")
	formCreate.Set("vlan_id", "20")
	formCreate.Set("status", "active")
	formCreate.Set("description", "Test employee account")

	reqCreate := httptest.NewRequest(http.MethodPost, "/clients/create", strings.NewReader(formCreate.Encode()))
	reqCreate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrCreate := httptest.NewRecorder()
	srv.handleCreateClient(rrCreate, reqCreate)

	if rrCreate.Code != http.StatusSeeOther {
		t.Fatalf("Expected redirect 303, got %d", rrCreate.Code)
	}

	// Verify user persisted in database
	user, err := db.GetClientByUsername("johndoe")
	if err != nil {
		t.Fatalf("User johndoe not found in DB: %v", err)
	}
	if user.AuthType != models.AuthTypePAP {
		t.Errorf("Expected AuthType PAP, got %s", user.AuthType)
	}
	if user.VLANID == nil || *user.VLANID != 20 {
		t.Errorf("Expected VLAN 20, got %v", user.VLANID)
	}
	if user.PasswordHash == "" || user.PasswordHash == "Secret123!" {
		t.Errorf("Expected bcrypt hashed password, got: %s", user.PasswordHash)
	}

	// 2. Update user (change VLAN & update password)
	formUpdate := url.Values{}
	formUpdate.Set("id", "1")
	formUpdate.Set("entry_type", "user")
	formUpdate.Set("username", "johndoe")
	formUpdate.Set("password", "NewSecret456!")
	formUpdate.Set("vlan_id", "30")
	formUpdate.Set("status", "active")
	formUpdate.Set("description", "Updated employee account")

	reqUpdate := httptest.NewRequest(http.MethodPost, "/clients/update", strings.NewReader(formUpdate.Encode()))
	reqUpdate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrUpdate := httptest.NewRecorder()
	srv.handleUpdateClient(rrUpdate, reqUpdate)

	userUpdated, err := db.GetClientByUsername("johndoe")
	if err != nil {
		t.Fatalf("User johndoe not found after update: %v", err)
	}
	if userUpdated.VLANID == nil || *userUpdated.VLANID != 30 {
		t.Errorf("Expected updated VLAN 30, got %v", userUpdated.VLANID)
	}

	// 3. Test filtering by type (?type=user)
	reqFilter := httptest.NewRequest(http.MethodGet, "/clients?type=user", nil)
	rrFilter := httptest.NewRecorder()
	srv.handleClients(rrFilter, reqFilter)

	body := rrFilter.Body.String()
	if !strings.Contains(body, "johndoe") {
		t.Errorf("Expected user johndoe in filtered results")
	}
}

func TestBackupDownloadEndpoint(t *testing.T) {
	// Create temporary disk DB since VACUUM INTO requires a real file (not :memory:)
	tmpDB := filepath.Join(t.TempDir(), "radius_test_backup.db")
	db, err := database.Open(tmpDB)
	if err != nil {
		t.Fatalf("Open test DB failed: %v", err)
	}
	defer db.Close()

	bus := eventbus.NewBus(10)
	srv, err := NewServer(db, bus, nil, 9998)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/backup/download", nil)
	rr := httptest.NewRecorder()
	srv.handleDownloadBackup(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Disposition"), "radius-backup-") {
		t.Errorf("Expected Content-Disposition attachment header, got %s", rr.Header().Get("Content-Disposition"))
	}
	if rr.Body.Len() == 0 {
		t.Errorf("Expected non-empty backup database download")
	}
}

func TestAutoUpdateSettingsPersistence(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	form := url.Values{}
	form.Set("unifi_url", "https://192.168.1.1")
	form.Set("unifi_auth_mode", "apikey")
	form.Set("global_shared_secret", "test_secret_123")
	form.Set("web_port", "9182")
	form.Set("radius_auth_port", "1812")
	form.Set("default_allow_vlan", "1")
	form.Set("unknown_mab_policy", "reject_log")
	form.Set("log_retention_days", "30")

	// Auto Update fields
	form.Set("auto_update_enabled", "1")
	form.Set("auto_update_schedule", "weekly")
	form.Set("auto_update_time", "04:30")
	form.Set("auto_update_weekday", "3")
	form.Set("auto_update_day", "15")

	req := httptest.NewRequest(http.MethodPost, "/settings/save", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	srv.handleSaveSettings(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", rr.Code)
	}

	saved, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}

	if !saved.AutoUpdateEnabled {
		t.Errorf("Expected AutoUpdateEnabled to be true")
	}
	if saved.AutoUpdateSchedule != "weekly" {
		t.Errorf("Expected AutoUpdateSchedule 'weekly', got %s", saved.AutoUpdateSchedule)
	}
	if saved.AutoUpdateTime != "04:30" {
		t.Errorf("Expected AutoUpdateTime '04:30', got %s", saved.AutoUpdateTime)
	}
	if saved.AutoUpdateWeekday != 3 {
		t.Errorf("Expected AutoUpdateWeekday 3, got %d", saved.AutoUpdateWeekday)
	}
	if saved.AutoUpdateDay != 15 {
		t.Errorf("Expected AutoUpdateDay 15, got %d", saved.AutoUpdateDay)
	}
}

func TestApplyUpdateEndpointSecurityAndExecution(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Unauthenticated / Cross-site check
	reqCSRF := httptest.NewRequest(http.MethodPost, "/api/update/apply", nil)
	reqCSRF.Header.Set("Origin", "http://evil-attacker.com")
	rrCSRF := httptest.NewRecorder()

	handler := srv.csrfProtect(srv.handleApplyUpdate)
	handler(rrCSRF, reqCSRF)

	if rrCSRF.Code != http.StatusForbidden {
		t.Errorf("Expected CSRF rejection (403 Forbidden), got %d", rrCSRF.Code)
	}

	// 2. Authorized call with missing/invalid target
	reqValid := httptest.NewRequest(http.MethodPost, "/api/update/apply", strings.NewReader("version=99.99.99"))
	reqValid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqValid.Header.Set("Origin", "http://example.com")
	reqValid.Host = "example.com"
	rrValid := httptest.NewRecorder()

	handler(rrValid, reqValid)

	// Since 99.99.99 does not exist on GitHub, it should return 500 with a clean JSON error response
	if rrValid.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500 error for non-existent release, got %d", rrValid.Code)
	}

	var jsonResp map[string]interface{}
	if err := json.Unmarshal(rrValid.Body.Bytes(), &jsonResp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}
	if jsonResp["success"] != false || jsonResp["error"] == nil {
		t.Errorf("Expected {success: false, error: ...}, got: %v", jsonResp)
	}
}

func TestLogsPageAndEndpoints(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// Seed an auth log
	vlan := 20
	logEntry := &models.AuthLog{
		ClientMAC:      "11:22:33:44:55:66",
		Username:       "test-client-1",
		AuthType:       models.AuthTypeMAB,
		Status:         "ACCEPT",
		VLANID:         &vlan,
		Reason:         "Valid client entry",
		NASIP:          "192.168.1.1",
		NASPort:        "0/1",
		LatencyMS:      3.2,
		EnrichedName:   "Smart Camera",
		EnrichedVendor: "UniFi Protect",
		RawRequest:     "RAW-ACCESS-REQUEST-DUMP",
		RawResponse:    "RAW-ACCESS-ACCEPT-DUMP",
	}
	if err := db.InsertAuthLog(logEntry); err != nil {
		t.Fatalf("InsertAuthLog failed: %v", err)
	}

	// Seed a bus log event
	srv.bus.PublishLog(eventbus.LogEvent{
		Timestamp: "12:00:00",
		Level:     eventbus.LogLevelInfo,
		Source:    "RADIUS",
		Message:   "Test log line for prefilling console",
	})

	// 1. GET /logs
	req := httptest.NewRequest(http.MethodGet, "/logs", nil)
	rr := httptest.NewRecorder()
	srv.handleLogs(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /logs expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Test log line for prefilling console") {
		t.Error("Expected initial log event to be prefilled in #terminalConsole")
	}
	if !strings.Contains(body, "11:22:33:44:55:66") {
		t.Error("Expected historical log MAC to be in historical table")
	}
	if !strings.Contains(body, "Smart Camera") {
		t.Error("Expected enriched device name in historical table")
	}
	if !strings.Contains(body, "DEBUG: Aus") {
		t.Error("Expected debug mode button with initial 'DEBUG: Aus' state")
	}

	// 2. POST /api/radius/debug/toggle (HTMX)
	reqToggle := httptest.NewRequest(http.MethodPost, "/api/radius/debug/toggle", nil)
	reqToggle.Header.Set("HX-Request", "true")
	rrToggle := httptest.NewRecorder()
	srv.handleToggleDebugMode(rrToggle, reqToggle)

	if rrToggle.Code != http.StatusOK {
		t.Fatalf("Toggle debug mode expected 200, got %d", rrToggle.Code)
	}
	if !strings.Contains(rrToggle.Body.String(), "DEBUG: AKTIV") {
		t.Errorf("Expected 'DEBUG: AKTIV' in toggle response, got %s", rrToggle.Body.String())
	}

	settings, _ := db.GetSettings()
	if !settings.RadiusDebugMode {
		t.Error("Expected settings.RadiusDebugMode to be true")
	}

	// Toggle back to off
	rrToggle2 := httptest.NewRecorder()
	srv.handleToggleDebugMode(rrToggle2, reqToggle)
	if !strings.Contains(rrToggle2.Body.String(), "DEBUG: Aus") {
		t.Errorf("Expected 'DEBUG: Aus' in toggle response, got %s", rrToggle2.Body.String())
	}
	settings, _ = db.GetSettings()
	if settings.RadiusDebugMode {
		t.Error("Expected settings.RadiusDebugMode to be false")
	}

	// 3. GET /api/logs/export/csv
	reqCSV := httptest.NewRequest(http.MethodGet, "/api/logs/export/csv", nil)
	rrCSV := httptest.NewRecorder()
	srv.handleExportLogsCSV(rrCSV, reqCSV)

	if rrCSV.Code != http.StatusOK {
		t.Fatalf("CSV export expected 200, got %d", rrCSV.Code)
	}
	csvBody := rrCSV.Body.String()
	if !strings.Contains(csvBody, "11:22:33:44:55:66") || !strings.Contains(csvBody, "Smart Camera") {
		t.Errorf("Expected CSV export to contain log entry data, got: %s", csvBody)
	}

	// 4. GET /api/logs/auth/details?id=1
	logs, _, _ := db.ListAuthLogs(1, 0, "", "")
	if len(logs) == 0 {
		t.Fatal("No logs found for details test")
	}
	reqDetails := httptest.NewRequest(http.MethodGet, "/api/logs/auth/details?id=1", nil)
	rrDetails := httptest.NewRecorder()
	srv.handleAuthLogDetails(rrDetails, reqDetails)

	if rrDetails.Code != http.StatusOK {
		t.Fatalf("Details endpoint expected 200, got %d", rrDetails.Code)
	}

	var detailLog models.AuthLog
	if err := json.Unmarshal(rrDetails.Body.Bytes(), &detailLog); err != nil {
		t.Fatalf("Failed to parse details JSON: %v", err)
	}
	if detailLog.RawRequest != "RAW-ACCESS-REQUEST-DUMP" || detailLog.RawResponse != "RAW-ACCESS-ACCEPT-DUMP" {
		t.Errorf("Details endpoint raw packet mismatch: %+v", detailLog)
	}
}

func TestHistoricalSystemLogsAndExport(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	now := time.Now().UTC()

	// Seed system logs in SQLite
	_ = db.InsertSystemLog(&models.SystemLog{
		Timestamp: now.Add(-30 * time.Minute),
		Level:     "INFO",
		Source:    "RADIUS",
		Message:   "RADIUS worker listening on port 1812",
	})
	_ = db.InsertSystemLog(&models.SystemLog{
		Timestamp: now.Add(-10 * time.Minute),
		Level:     "WARN",
		Source:    "UNIFI-SYNC",
		Message:   "Sync connection timed out on 192.168.1.1",
	})
	_ = db.InsertSystemLog(&models.SystemLog{
		Timestamp: now.Add(-2 * time.Minute),
		Level:     "ERROR",
		Source:    "BACKUP",
		Message:   "WebDAV backup failed: disk full",
	})

	// 1. GET /logs with relative time filter (15m)
	req15m := httptest.NewRequest(http.MethodGet, "/logs?sys_range=15m", nil)
	rr15m := httptest.NewRecorder()
	srv.handleLogs(rr15m, req15m)

	if rr15m.Code != http.StatusOK {
		t.Fatalf("GET /logs?sys_range=15m expected 200, got %d", rr15m.Code)
	}
	body15m := rr15m.Body.String()
	if !strings.Contains(body15m, "Sync connection timed out") || !strings.Contains(body15m, "WebDAV backup failed") {
		t.Errorf("Expected 15m logs in HTML body, got: %s", body15m)
	}
	if strings.Contains(body15m, "RADIUS worker listening") {
		t.Errorf("Did not expect 30m old log in 15m filter, got: %s", body15m)
	}

	// 2. GET /logs with Level filter (ERROR)
	reqErr := httptest.NewRequest(http.MethodGet, "/logs?sys_level=ERROR", nil)
	rrErr := httptest.NewRecorder()
	srv.handleLogs(rrErr, reqErr)

	bodyErr := rrErr.Body.String()
	if !strings.Contains(bodyErr, "WebDAV backup failed") {
		t.Errorf("Expected ERROR log in body, got: %s", bodyErr)
	}
	if strings.Contains(bodyErr, "Sync connection timed out") {
		t.Errorf("Did not expect WARN log in ERROR filter, got: %s", bodyErr)
	}

	// 3. GET /logs with Source filter (UNIFI-SYNC)
	reqSync := httptest.NewRequest(http.MethodGet, "/logs?sys_source=UNIFI-SYNC", nil)
	rrSync := httptest.NewRecorder()
	srv.handleLogs(rrSync, reqSync)

	bodySync := rrSync.Body.String()
	if !strings.Contains(bodySync, "Sync connection timed out") {
		t.Errorf("Expected UNIFI-SYNC log in body, got: %s", bodySync)
	}
	if strings.Contains(bodySync, "WebDAV backup failed") {
		t.Errorf("Did not expect BACKUP log in UNIFI-SYNC filter, got: %s", bodySync)
	}

	// 4. GET /api/logs/system/export/csv
	reqCSV := httptest.NewRequest(http.MethodGet, "/api/logs/system/export/csv?range=1h", nil)
	rrCSV := httptest.NewRecorder()
	srv.handleExportSystemLogsCSV(rrCSV, reqCSV)

	if rrCSV.Code != http.StatusOK {
		t.Fatalf("Export system logs CSV expected 200, got %d", rrCSV.Code)
	}
	csvContent := rrCSV.Body.String()
	if !strings.Contains(csvContent, "ID,Timestamp,Level,Source,Message") {
		t.Errorf("CSV header mismatch, got: %s", csvContent)
	}
	if !strings.Contains(csvContent, "UNIFI-SYNC") || !strings.Contains(csvContent, "BACKUP") {
		t.Errorf("CSV content missing expected records, got: %s", csvContent)
	}

	// 5. Unit test parseSystemLogTimeRange
	f1, t1 := parseSystemLogTimeRange("1h", "", "")
	if f1 == nil || t1 == nil || !t1.After(*f1) {
		t.Errorf("parseSystemLogTimeRange(1h) failed: f=%v, t=%v", f1, t1)
	}

	fCustom, tCustom := parseSystemLogTimeRange("custom", "2026-11-05T08:00", "2026-11-05T12:00")
	if fCustom == nil || tCustom == nil {
		t.Fatalf("parseSystemLogTimeRange(custom) returned nil: f=%v, t=%v", fCustom, tCustom)
	}
	if fCustom.Local().Hour() != 8 || tCustom.Local().Hour() != 12 {
		t.Errorf("Custom range hours mismatch: f=%v (local: %v), t=%v (local: %v)", fCustom, fCustom.Local(), tCustom, tCustom.Local())
	}
}

func TestPrometheusMetricsAndAutoDisconnect(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. GET /metrics without any auth cookies or headers
	reqMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rrMetrics := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rrMetrics, reqMetrics)

	if rrMetrics.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from unauthenticated /metrics, got %d", rrMetrics.Code)
	}

	body := rrMetrics.Body.String()
	if !strings.Contains(body, "unifi_radius_uptime_seconds") || !strings.Contains(body, "radius_requests_total") {
		t.Errorf("Expected Prometheus metrics in response, got:\n%s", body)
	}

	// 2. Test saving auto_disconnect_on_change
	form := url.Values{
		"unifi_url":                 {"https://127.0.0.1"},
		"unifi_auth_mode":           {"apikey"},
		"unifi_sync_interval":       {"5"},
		"global_shared_secret":      {"testsecret"},
		"radius_auth_port":          {"1812"},
		"default_allow_vlan":        {"10"},
		"auto_disconnect_on_change": {"1"},
		"web_port":                  {"9182"},
		"log_retention_days":        {"30"},
	}
	reqSave := httptest.NewRequest(http.MethodPost, "/settings/save", strings.NewReader(form.Encode()))
	reqSave.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrSave := httptest.NewRecorder()
	srv.handleSaveSettings(rrSave, reqSave)

	settings, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}
	if !settings.AutoDisconnectOnChange {
		t.Errorf("Expected AutoDisconnectOnChange to be true after save, got false")
	}

	// 3. Test Client IsRandomizedMAC
	cRandom := &models.Client{MACAddress: "02:00:00:00:00:01"}
	if !cRandom.IsRandomizedMAC() {
		t.Errorf("Expected 02:00:00:00:00:01 to be recognized as randomized MAC")
	}

	cHardware := &models.Client{MACAddress: "FC:EC:DA:11:22:33"}
	if cHardware.IsRandomizedMAC() {
		t.Errorf("Expected FC:EC:DA:11:22:33 to be recognized as universal hardware MAC")
	}
}

func TestIntrusionDefenseSettingsAndUnban(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Test saving defense settings
	form := url.Values{
		"unifi_url":                    {"https://127.0.0.1"},
		"unifi_auth_mode":              {"apikey"},
		"unifi_sync_interval":          {"5"},
		"global_shared_secret":         {"testsecret"},
		"radius_auth_port":             {"1812"},
		"default_allow_vlan":           {"10"},
		"web_port":                     {"9182"},
		"log_retention_days":           {"30"},
		"defense_enabled":              {"1"},
		"defense_max_failures":         {"3"},
		"defense_window_seconds":       {"60"},
		"defense_ban_duration_minutes": {"15"},
		"defense_mac_spoof_detection":  {"1"},
	}
	reqSave := httptest.NewRequest(http.MethodPost, "/settings/save", strings.NewReader(form.Encode()))
	reqSave.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrSave := httptest.NewRecorder()
	srv.handleSaveSettings(rrSave, reqSave)

	settings, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}
	if !settings.DefenseEnabled {
		t.Errorf("Expected DefenseEnabled to be true")
	}
	if settings.DefenseMaxFailures != 3 {
		t.Errorf("Expected DefenseMaxFailures=3, got %d", settings.DefenseMaxFailures)
	}
	if settings.DefenseWindowSeconds != 60 {
		t.Errorf("Expected DefenseWindowSeconds=60, got %d", settings.DefenseWindowSeconds)
	}
	if settings.DefenseBanDurationMinutes != 15 {
		t.Errorf("Expected DefenseBanDurationMinutes=15, got %d", settings.DefenseBanDurationMinutes)
	}
	if !settings.DefenseMACSpoofDetection {
		t.Errorf("Expected DefenseMACSpoofDetection to be true")
	}

	// 2. Ban a client
	mac := "00:11:22:33:44:55"
	_ = db.CreateClient(&models.Client{
		MACAddress: mac,
		Status:     models.ClientStatusActive,
	})

	srv.DefenseManager().PermanentBan(mac)
	if banned, _ := srv.DefenseManager().IsBanned(mac, ""); !banned {
		t.Fatalf("Expected client %s to be banned", mac)
	}

	// 3. Render clients page to verify template executes and displays quarantine
	reqClients := httptest.NewRequest(http.MethodGet, "/clients", nil)
	rrClients := httptest.NewRecorder()
	srv.handleClients(rrClients, reqClients)
	if rrClients.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /clients, got %d", rrClients.Code)
	}
	body := rrClients.Body.String()
	if !strings.Contains(body, "Quarantäne") && !strings.Contains(body, "Quarantine") {
		t.Errorf("Expected Quarantäne badge in rendered clients page, got:\n%s", body)
	}
	if !strings.Contains(body, "Entsperren") && !strings.Contains(body, "Unban") {
		t.Errorf("Expected Entsperren button in rendered clients page")
	}

	// 4. Test handleSecurityUnban
	unbanForm := url.Values{"target": {mac}}
	reqUnban := httptest.NewRequest(http.MethodPost, "/api/security/unban", strings.NewReader(unbanForm.Encode()))
	reqUnban.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrUnban := httptest.NewRecorder()
	srv.handleSecurityUnban(rrUnban, reqUnban)

	if banned, _ := srv.DefenseManager().IsBanned(mac, ""); banned {
		t.Errorf("Expected client %s to be unbanned after calling handleSecurityUnban", mac)
	}

	// 5. Test handleSecurityBan
	reqBan := httptest.NewRequest(http.MethodPost, "/api/security/ban", strings.NewReader(unbanForm.Encode()))
	reqBan.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrBan := httptest.NewRecorder()
	srv.handleSecurityBan(rrBan, reqBan)

	if banned, _ := srv.DefenseManager().IsBanned(mac, ""); !banned {
		t.Errorf("Expected client %s to be banned after calling handleSecurityBan", mac)
	}
}

func TestSwitchAndPortRenderingInTablesAndLiveFeed(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Verify Clients table shows Switch name and Port
	testMAC := "00:AA:BB:CC:DD:EE"
	_ = db.CreateClient(&models.Client{
		MACAddress:      testMAC,
		Status:          models.ClientStatusActive,
		UniFiName:       "Test-Switch-Client",
		UniFiSwitchName: "USW-48-G2",
		UniFiSwitchPort: "18",
		UniFiIsWired:    true,
	})

	reqClients := httptest.NewRequest(http.MethodGet, "/clients", nil)
	rrClients := httptest.NewRecorder()
	srv.handleClients(rrClients, reqClients)
	if rrClients.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /clients, got %d", rrClients.Code)
	}
	bodyClients := rrClients.Body.String()
	if !strings.Contains(bodyClients, "USW-48-G2") {
		t.Errorf("Expected Clients table to contain SwitchName 'USW-48-G2', got:\n%s", bodyClients)
	}
	if !strings.Contains(bodyClients, "[Port 18]") {
		t.Errorf("Expected Clients table to contain '[Port 18]'")
	}

	// 2. Verify Dashboard table renders NASName and Port
	_ = db.InsertAuthLog(&models.AuthLog{
		Timestamp:      time.Now().UTC(),
		ClientMAC:      testMAC,
		Status:         "ACCEPT",
		NASIP:          "192.168.13.2",
		NASPort:        "18",
		NASName:        "USW-48-G2",
		Reason:         "Test MAB auth",
		LatencyMS:      1.5,
	})

	reqDash := httptest.NewRequest(http.MethodGet, "/", nil)
	rrDash := httptest.NewRecorder()
	srv.handleDashboard(rrDash, reqDash)
	if rrDash.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK from /, got %d", rrDash.Code)
	}
	bodyDash := rrDash.Body.String()
	if !strings.Contains(bodyDash, "USW-48-G2") {
		t.Errorf("Expected Dashboard table to display 'USW-48-G2', got:\n%s", bodyDash)
	}
	if !strings.Contains(bodyDash, "Port 18") {
		t.Errorf("Expected Dashboard table to display 'Port 18'")
	}
	if !strings.Contains(bodyDash, "192.168.13.2") {
		t.Errorf("Expected Dashboard table to display NAS IP '192.168.13.2'")
	}

	// 3. Verify WebSocket Live Feed formatting
	htmlLive := formatAuthRowHTML(models.AuthLog{
		ID:             999,
		Timestamp:      time.Now().UTC(),
		ClientMAC:      testMAC,
		Status:         "ACCEPT",
		NASIP:          "192.168.13.2",
		NASPort:        "18",
		NASName:        "USW-48-G2",
		Reason:         "Live test",
		LatencyMS:      2.0,
	})
	if !strings.Contains(htmlLive, "USW-48-G2") {
		t.Errorf("Expected live feed HTML to contain 'USW-48-G2', got:\n%s", htmlLive)
	}
	if !strings.Contains(htmlLive, "Port 18 • 192.168.13.2") {
		t.Errorf("Expected live feed HTML to contain 'Port 18 • 192.168.13.2'")
	}
}

func TestSessionLongevityAndCookiePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "sessions_test.db")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}
	defer db.Close()

	bus := eventbus.NewBus(100)
	srv, err := NewServer(db, bus, nil, 9991)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// 1. Initial Login Setup
	formData := url.Values{"password": {"adminpass123"}}
	reqPost := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
	reqPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrPost := httptest.NewRecorder()
	srv.handleLogin(rrPost, reqPost)

	if rrPost.Code != http.StatusSeeOther {
		t.Fatalf("Expected 303 redirect, got %d", rrPost.Code)
	}

	cookies := rrPost.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session_id" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("Expected session_id cookie set")
	}

	// Verify Cookie MaxAge and Expires are set for longevity (30 days default)
	expectedMaxAge := 30 * 24 * 3600
	if sessionCookie.MaxAge != expectedMaxAge {
		t.Errorf("Expected cookie MaxAge=%d, got %d", expectedMaxAge, sessionCookie.MaxAge)
	}
	if sessionCookie.Expires.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("Expected cookie Expires in ~30 days, got %v", sessionCookie.Expires)
	}

	token := sessionCookie.Value

	// Give the async DB save goroutine a moment
	time.Sleep(50 * time.Millisecond)

	// 2. Verify Session persisted in SQLite
	exp, found, err := db.GetSessionExpiry(token)
	if err != nil || !found {
		t.Fatalf("Expected session %s to be persisted in DB: found=%v, err=%v", token, found, err)
	}
	if exp.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("Expected DB expiration in ~30 days, got %v", exp)
	}

	// 3. Simulate Server Restart: New server instance with same DB loads session
	srv2, err := NewServer(db, bus, nil, 9992)
	if err != nil {
		t.Fatalf("NewServer 2 failed: %v", err)
	}
	if !srv2.isValidSession(token) {
		t.Errorf("Expected session %s to remain valid after server restart", token)
	}

	// 4. Test Sliding Expiration
	// Artificially age the session to 5 days left (< 15 days, which is half of 30 days)
	nearExpiry := time.Now().Add(5 * 24 * time.Hour)
	_ = db.SaveSession(token, nearExpiry)
	srv2.sessionsMu.Lock()
	srv2.sessions[token] = nearExpiry
	srv2.sessionsMu.Unlock()

	// Calling isValidSession should detect < 50% left and extend back to 30 days
	if !srv2.isValidSession(token) {
		t.Fatal("Expected session to be valid before extension")
	}
	time.Sleep(50 * time.Millisecond)

	srv2.sessionsMu.RLock()
	refreshedExp := srv2.sessions[token]
	srv2.sessionsMu.RUnlock()
	if refreshedExp.Before(time.Now().Add(29 * 24 * time.Hour)) {
		t.Errorf("Expected sliding expiration to extend session to ~30 days, got %v", refreshedExp)
	}

	// 5. Test Logout deletes from DB
	reqLogout := httptest.NewRequest(http.MethodGet, "/logout", nil)
	reqLogout.AddCookie(sessionCookie)
	rrLogout := httptest.NewRecorder()
	srv2.handleLogout(rrLogout, reqLogout)

	time.Sleep(20 * time.Millisecond)
	_, foundAfterLogout, _ := db.GetSessionExpiry(token)
	if foundAfterLogout {
		t.Errorf("Expected session to be deleted from DB on logout")
	}
	if srv2.isValidSession(token) {
		t.Errorf("Expected session to be invalid after logout")
	}

	// 6. Test Settings Save for web_session_duration_days
	form := url.Values{
		"unifi_url":                  {"https://127.0.0.1"},
		"unifi_auth_mode":            {"apikey"},
		"unifi_sync_interval":        {"5"},
		"global_shared_secret":       {"testsecret"},
		"radius_auth_port":           {"1812"},
		"default_allow_vlan":         {"10"},
		"web_port":                   {"9182"},
		"web_session_duration_days":  {"60"},
		"log_retention_days":         {"30"},
	}
	reqSave := httptest.NewRequest(http.MethodPost, "/settings/save", strings.NewReader(form.Encode()))
	reqSave.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrSave := httptest.NewRecorder()
	srv2.handleSaveSettings(rrSave, reqSave)

	settings, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}
	if settings.WebSessionDurationDays != 60 {
		t.Errorf("Expected WebSessionDurationDays=60, got %d", settings.WebSessionDurationDays)
	}
}

func TestCertificateIssuanceAndP12DownloadOptionalPassword(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// 1. Initialize Root CA
	rootCA, err := ca.GenerateCA("Test UniFi Root CA", 10)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}
	caRecord := &models.Certificate{
		SerialNumber:   "1",
		CommonName:     "Test UniFi Root CA",
		CertType:       "ca",
		CertificatePEM: rootCA.RootCertPEM,
		PrivateKeyPEM:  rootCA.RootKeyPEM,
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().AddDate(10, 0, 0),
	}
	if err := db.SaveCertificate(caRecord); err != nil {
		t.Fatalf("SaveCertificate for CA failed: %v", err)
	}

	// 2. Issue client certificate with EMPTY/OPTIONAL password
	formNoPass := url.Values{
		"common_name":   {"user.no.pass"},
		"password":      {""}, // Empty password!
		"ssid":          {"UniFi-Enterprise"},
		"validity_days": {"365"},
	}
	reqNoPass := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(formNoPass.Encode()))
	reqNoPass.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrNoPass := httptest.NewRecorder()
	srv.handleIssueCert(rrNoPass, reqNoPass)
	if rrNoPass.Code != http.StatusSeeOther {
		t.Fatalf("Expected redirect 303, got %d", rrNoPass.Code)
	}

	certs, err := db.ListCertificates("client")
	if err != nil || len(certs) != 1 {
		t.Fatalf("Expected 1 client cert, got %d (err: %v)", len(certs), err)
	}
	certNoPass := certs[0]
	if certNoPass.CommonName != "user.no.pass" {
		t.Errorf("Expected CommonName 'user.no.pass', got %q", certNoPass.CommonName)
	}
	if certNoPass.P12Password != "" {
		t.Errorf("Expected empty P12Password, got %q", certNoPass.P12Password)
	}

	// 3. Download .p12 for user.no.pass -> must decode with empty password
	reqDownNoPass := httptest.NewRequest(http.MethodGet, "/certificates/download-p12?serial="+certNoPass.SerialNumber, nil)
	rrDownNoPass := httptest.NewRecorder()
	srv.handleDownloadP12(rrDownNoPass, reqDownNoPass)
	if rrDownNoPass.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK downloading .p12, got %d: %s", rrDownNoPass.Code, rrDownNoPass.Body.String())
	}
	if rrDownNoPass.Header().Get("Content-Type") != "application/x-pkcs12" {
		t.Errorf("Expected Content-Type 'application/x-pkcs12', got %q", rrDownNoPass.Header().Get("Content-Type"))
	}
	p12BytesNoPass := rrDownNoPass.Body.Bytes()
	_, _, _, err = pkcs12.DecodeChain(p12BytesNoPass, "")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12 bundle created with empty password: %v", err)
	}

	// 4. Issue client certificate with custom password
	formWithPass := url.Values{
		"common_name":   {"user.with.pass"},
		"password":      {"MySecretPassword123"},
		"ssid":          {"Corp-Wi-Fi"},
		"validity_days": {"180"},
	}
	reqWithPass := httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(formWithPass.Encode()))
	reqWithPass.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrWithPass := httptest.NewRecorder()
	srv.handleIssueCert(rrWithPass, reqWithPass)
	if rrWithPass.Code != http.StatusSeeOther {
		t.Fatalf("Expected redirect 303, got %d", rrWithPass.Code)
	}

	certsAll, err := db.ListCertificates("client")
	if err != nil || len(certsAll) != 2 {
		t.Fatalf("Expected 2 client certs, got %d (err: %v)", len(certsAll), err)
	}
	var certWithPass *models.Certificate
	for i := range certsAll {
		if certsAll[i].CommonName == "user.with.pass" {
			certWithPass = &certsAll[i]
			break
		}
	}
	if certWithPass == nil {
		t.Fatal("user.with.pass certificate not found in DB")
	}
	if certWithPass.P12Password != "MySecretPassword123" {
		t.Errorf("Expected P12Password 'MySecretPassword123', got %q", certWithPass.P12Password)
	}

	// 5. Download .p12 for user.with.pass -> must decode with "MySecretPassword123"
	reqDownWithPass := httptest.NewRequest(http.MethodGet, "/certificates/download-p12?serial="+certWithPass.SerialNumber, nil)
	rrDownWithPass := httptest.NewRecorder()
	srv.handleDownloadP12(rrDownWithPass, reqDownWithPass)
	if rrDownWithPass.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK downloading .p12 with pass, got %d: %s", rrDownWithPass.Code, rrDownWithPass.Body.String())
	}
	p12BytesWithPass := rrDownWithPass.Body.Bytes()
	_, _, _, err = pkcs12.DecodeChain(p12BytesWithPass, "MySecretPassword123")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12 bundle created with password 'MySecretPassword123': %v", err)
	}

	// 6. Download .p12 with URL override parameter: ?password=AdHocPassword
	reqDownOverride := httptest.NewRequest(http.MethodGet, "/certificates/download-p12?serial="+certWithPass.SerialNumber+"&password=AdHocPassword", nil)
	rrDownOverride := httptest.NewRecorder()
	srv.handleDownloadP12(rrDownOverride, reqDownOverride)
	if rrDownOverride.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rrDownOverride.Code)
	}
	_, _, _, err = pkcs12.DecodeChain(rrDownOverride.Body.Bytes(), "AdHocPassword")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12 bundle created with override password: %v", err)
	}

	// 7. Download .mobileconfig -> should produce valid payload
	reqMobile := httptest.NewRequest(http.MethodGet, "/certificates/download-mobileconfig?serial="+certWithPass.SerialNumber, nil)
	rrMobile := httptest.NewRecorder()
	srv.handleDownloadMobileConfig(rrMobile, reqMobile)
	if rrMobile.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK downloading .mobileconfig, got %d", rrMobile.Code)
	}
	mobileContent := rrMobile.Body.String()
	if !strings.Contains(mobileContent, "MySecretPassword123") {
		t.Errorf("Expected mobileconfig to contain embedded P12 password 'MySecretPassword123'")
	}
}






