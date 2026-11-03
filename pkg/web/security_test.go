package web

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

func TestSecurityHeadersPresent(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	headers := rr.Header()
	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options: nosniff, got %q", headers.Get("X-Content-Type-Options"))
	}
	if headers.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Errorf("Expected X-Frame-Options: SAMEORIGIN, got %q", headers.Get("X-Frame-Options"))
	}
	if headers.Get("Referrer-Policy") != "strict-origin-when-cross-origin" {
		t.Errorf("Expected Referrer-Policy: strict-origin-when-cross-origin, got %q", headers.Get("Referrer-Policy"))
	}
	if !strings.Contains(headers.Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("Expected CSP to contain 'default-src self', got %q", headers.Get("Content-Security-Policy"))
	}
}

func TestCookieSecurityAttributes(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	formData := url.Values{}
	formData.Set("password", "validmasterpassword")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.handleLogin(rr, req)

	cookies := rr.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session_id" {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil {
		t.Fatal("session_id cookie not found")
	}
	if !sessionCookie.HttpOnly {
		t.Error("Expected session cookie to be HttpOnly")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("Expected SameSite=Lax, got %v", sessionCookie.SameSite)
	}
}

func TestXSSMitigationInLiveFeed(t *testing.T) {
	xssPayload := `<script>alert('XSS')</script><img src=x onerror=alert(1)>" onmouseover="evil()`

	// Test auth row escaping
	vlan := 10
	logEvent := models.AuthLog{
		Timestamp:      time.Now().UTC(),
		ClientMAC:      xssPayload,
		Username:       xssPayload,
		Status:         "ACCEPT",
		VLANID:         &vlan,
		EnrichedName:   xssPayload,
		EnrichedVendor: xssPayload,
		NASIP:          "192.168.1.1",
		NASPort:        xssPayload,
		LatencyMS:      1.5,
	}

	htmlRow := formatAuthRowHTML(logEvent)
	if strings.Contains(htmlRow, "<script>") || strings.Contains(htmlRow, "<img src=x") {
		t.Errorf("formatAuthRowHTML contains unescaped XSS payload: %s", htmlRow)
	}
	if !strings.Contains(htmlRow, "&lt;script&gt;") {
		t.Error("Expected HTML escaped script tag in formatAuthRowHTML")
	}

	// Test log line escaping
	sysLog := eventbus.LogEvent{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     eventbus.LogLevelInfo,
		Source:    xssPayload,
		Message:   xssPayload,
	}

	htmlLog := formatLogLineHTML(sysLog)
	if strings.Contains(htmlLog, "<script>") || strings.Contains(htmlLog, "<img src=x") {
		t.Errorf("formatLogLineHTML contains unescaped XSS payload: %s", htmlLog)
	}
	if !strings.Contains(htmlLog, "&lt;script&gt;") {
		t.Error("Expected HTML escaped script tag in formatLogLineHTML")
	}
}

func TestUnauthenticatedWebSocketRejected(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// Initial setup: set admin password
	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))

	// Attempt to connect to /ws/feed without session cookie
	req := httptest.NewRequest(http.MethodGet, "/ws/feed", nil)
	rr := httptest.NewRecorder()
	srv.handleWebSocket(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for unauthenticated websocket, got %d", rr.Code)
	}
}

func TestCSRFProtectionRejectsCrossSiteOrigin(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))
	token := srv.createSession()

	// Malicious cross-origin POST request
	formData := url.Values{}
	formData.Set("mac_address", "AA:BB:CC:DD:EE:FF")
	formData.Set("status", "active")

	req := httptest.NewRequest(http.MethodPost, "/clients/create", strings.NewReader(formData.Encode()))
	req.Host = "radius.internal:9182"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://attacker-evil-site.com")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})

	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for cross-origin POST, got %d", rr.Code)
	}
}

func TestLoginRateLimiting(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))

	// 5 failed attempts
	for i := 0; i < 5; i++ {
		formData := url.Values{}
		formData.Set("password", "wrongpass")
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "192.168.1.100:54321"
		rr := httptest.NewRecorder()
		srv.handleLogin(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Attempt %d: expected 200 OK with error, got %d", i+1, rr.Code)
		}
	}

	// 6th attempt should be blocked by rate limiter
	formData := url.Values{}
	formData.Set("password", "correctpassword")
	reqBlocked := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(formData.Encode()))
	reqBlocked.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBlocked.RemoteAddr = "192.168.1.100:54321"
	rrBlocked := httptest.NewRecorder()
	srv.handleLogin(rrBlocked, reqBlocked)

	body := rrBlocked.Body.String()
	if !strings.Contains(body, "Zu viele Fehlversuche") && !strings.Contains(body, "Too many failed attempts") {
		t.Errorf("Expected rate limit error message on 6th attempt, got body: %s", body)
	}
}

func TestSessionEviction(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	// Manually inject expired session
	srv.sessionsMu.Lock()
	srv.sessions["expired_token"] = time.Now().Add(-10 * time.Minute)
	srv.sessionsMu.Unlock()

	// Should be invalid
	if srv.isValidSession("expired_token") {
		t.Error("Expected expired session to be invalid")
	}

	// Expired session should have been purged from map
	srv.sessionsMu.RLock()
	_, exists := srv.sessions["expired_token"]
	srv.sessionsMu.RUnlock()
	if exists {
		t.Error("Expected expired session to be evicted from sessions map")
	}
}

func TestRestoreMaxPayloadLimit(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))
	token := srv.createSession()

	// Create an oversized body exceeding 50 MB (simulated via 51MB stream)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("backup_file", "huge.db")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}

	// Write 51 MB of zeros
	hugeData := make([]byte, 1024*1024)
	for i := 0; i < 51; i++ {
		_, _ = part.Write(hugeData)
	}
	writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/backup/restore", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})

	rr := httptest.NewRecorder()
	srv.handleRestoreBackup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for oversized backup file, got %d", rr.Code)
	}
}

func TestNotifyEndpointRequiresAuth(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))

	formData := url.Values{}
	formData.Set("provider", "telegram")
	req := httptest.NewRequest(http.MethodPost, "/api/notify/test", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	// requireAuth should redirect unauthenticated request to /login
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected redirect to login (303) or 401 for unauthenticated notify test, got %d", rr.Code)
	}
	if rr.Code == http.StatusSeeOther && rr.Header().Get("Location") != "/login" {
		t.Errorf("Expected redirect location /login, got %q", rr.Header().Get("Location"))
	}
}

func TestNotifyEndpointCSRFRejection(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))
	token := srv.createSession()

	formData := url.Values{}
	formData.Set("provider", "telegram")
	req := httptest.NewRequest(http.MethodPost, "/api/notify/test", strings.NewReader(formData.Encode()))
	req.Host = "radius.internal:9182"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil-attacker.com")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})

	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for cross-origin notify test, got %d", rr.Code)
	}
}

func TestNotifyEndpointHTMLEscaping(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))
	token := srv.createSession()

	xssPayload := "<script>alert('pwned')</script>"
	formData := url.Values{}
	formData.Set("provider", xssPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/notify/test", strings.NewReader(formData.Encode()))
	req.Host = "radius.internal:9182"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://radius.internal:9182")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})

	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "<script>") {
		t.Errorf("Response contains unescaped XSS: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("Expected escaped XSS tag in response, got: %s", body)
	}
}

func TestSettingsSaveCSRFProtection(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))
	token := srv.createSession()

	formData := url.Values{}
	formData.Set("telegram_enabled", "true")
	formData.Set("telegram_bot_token", "12345:token")

	req := httptest.NewRequest(http.MethodPost, "/settings/save", strings.NewReader(formData.Encode()))
	req.Host = "radius.internal:9182"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://malicious-site.org")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})

	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for cross-origin /settings/save, got %d", rr.Code)
	}
}

func TestRemoteBackupEndpointsSecurity(t *testing.T) {
	srv, db := setupTestWebServer(t)
	defer db.Close()

	hash, _ := bcrypt.GenerateFromPassword([]byte("adminpass123"), bcrypt.DefaultCost)
	_ = db.SetAdminPassword(string(hash))

	// 1. Unauthenticated requests to test and run should be redirected
	for _, ep := range []string{"/api/backup/remote/test", "/api/backup/remote/run"} {
		req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader("remote_backup_type=webdav"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusSeeOther && rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected redirect or 401 for unauthenticated %s, got %d", ep, rr.Code)
		}
	}

	// 2. CSRF rejection for cross-origin requests
	token := srv.createSession()
	for _, ep := range []string{"/api/backup/remote/test", "/api/backup/remote/run"} {
		req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader("remote_backup_type=webdav"))
		req.Host = "radius.internal:9182"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://evil-site.com")
		req.AddCookie(&http.Cookie{Name: "session_id", Value: token})

		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden for cross-origin %s, got %d", ep, rr.Code)
		}
	}

	// 3. Test reflected error message escaping (XSS mitigation)
	formData := url.Values{}
	formData.Set("remote_backup_type", "<script>alert('xss')</script>")

	req := httptest.NewRequest(http.MethodPost, "/api/backup/remote/test", strings.NewReader(formData.Encode()))
	req.Host = "radius.internal:9182"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://radius.internal:9182")
	req.AddCookie(&http.Cookie{Name: "session_id", Value: token})

	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "<script>") {
		t.Errorf("Reflected XSS script tag unescaped in response: %s", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("Expected escaped XSS tag in response, got: %s", body)
	}
}
