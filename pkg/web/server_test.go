package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/unifi"
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


