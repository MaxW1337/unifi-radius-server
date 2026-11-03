package unifi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"golang.org/x/crypto/bcrypt"
)

func TestMigrateBuiltinRadius(t *testing.T) {
	builtinDisabledCalled := false
	profileCreatedCalled := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/proxy/network/api/s/default/get/setting/radius":
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"_id":       "radius_setting_id",
						"key":       "radius",
						"enabled":   true,
						"x_secret":  "unifi_legacy_secret",
						"auth_port": 1812,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case "/proxy/network/api/s/default/set/setting/radius":
			builtinDisabledCalled = true
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if body["enabled"] != false {
				t.Errorf("Expected enabled=false, got %v", body["enabled"])
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}})

		case "/proxy/network/api/s/default/rest/account":
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"_id":        "acc_1",
						"name":       "00:11:22:33:44:55",
						"x_password": "001122334455",
						"vlan":       20,
					},
					{
						"_id":        "acc_2",
						"name":       "alice.employee",
						"x_password": "SuperSecretPassword!",
						"vlan":       10,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case "/proxy/network/api/s/default/rest/radiusprofile":
			if r.Method == http.MethodGet {
				// No existing profile
				json.NewEncoder(w).Encode(map[string]interface{}{
					"meta": map[string]string{"rc": "ok"},
					"data": []interface{}{},
				})
			} else if r.Method == http.MethodPost {
				profileCreatedCalled = true
				var p UniFiRadiusProfile
				json.NewDecoder(r.Body).Decode(&p)
				p.ID = "new_profile_id"
				json.NewEncoder(w).Encode(map[string]interface{}{
					"meta": map[string]string{"rc": "ok"},
					"data": []interface{}{p},
				})
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("database.Open failed: %v", err)
	}
	defer db.Close()

	client, err := NewClient(Config{
		BaseURL:  ts.URL,
		AuthMode: "apikey",
		APIKey:   "dummy-key",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	// 1. Check status
	enabled, secret, count, err := CheckBuiltinRadiusStatus(client)
	if err != nil {
		t.Fatalf("CheckBuiltinRadiusStatus failed: %v", err)
	}
	if !enabled || secret != "unifi_legacy_secret" || count != 2 {
		t.Errorf("Unexpected status: enabled=%v, secret=%s, count=%d", enabled, secret, count)
	}

	// 2. Perform Migration
	report, err := MigrateBuiltinRadius(client, db, true, true)
	if err != nil {
		t.Fatalf("MigrateBuiltinRadius failed: %v", err)
	}

	if report.MABDevicesMigrated != 1 {
		t.Errorf("Expected 1 MAB device migrated, got %d", report.MABDevicesMigrated)
	}
	if report.UsersMigrated != 1 {
		t.Errorf("Expected 1 user migrated, got %d", report.UsersMigrated)
	}
	if !builtinDisabledCalled {
		t.Error("Builtin RADIUS server was not disabled")
	}
	if !profileCreatedCalled {
		t.Error("UniFi RADIUS profile was not created")
	}

	// 3. Verify SQLite DB contents
	// Verify MAB client
	mabClient, err := db.GetClientByMAC("00:11:22:33:44:55")
	if err != nil || mabClient == nil {
		t.Fatalf("MAB client not found in DB: %v", err)
	}
	if mabClient.AuthType != models.AuthTypeMAB || *mabClient.VLANID != 20 {
		t.Errorf("MAB client mismatch: %+v", mabClient)
	}

	// Verify User account
	userClient, err := db.GetClientByUsername("alice.employee")
	if err != nil || userClient == nil {
		t.Fatalf("User client not found in DB: %v", err)
	}
	if userClient.AuthType != models.AuthTypePAP || *userClient.VLANID != 10 {
		t.Errorf("User client mismatch: %+v", userClient)
	}
	// Verify password hashed
	if bcrypt.CompareHashAndPassword([]byte(userClient.PasswordHash), []byte("SuperSecretPassword!")) != nil {
		t.Error("User password was not properly hashed with bcrypt")
	}

	// Verify shared secret was adopted
	settings, _ := db.GetSettings()
	if settings.GlobalSharedSecret != "unifi_legacy_secret" {
		t.Errorf("Expected GlobalSharedSecret to be updated to unifi_legacy_secret, got %s", settings.GlobalSharedSecret)
	}
}

