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

func TestMigrateAllRadiusWLANs(t *testing.T) {
	updatedWLANs := make(map[string]string)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/proxy/network/api/s/default/rest/radiusprofile":
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"_id":            "default_prof_id",
						"name":           "Default",
						"attr_hidden_id": "Default",
					},
					{
						"_id":  "custom_prof_id",
						"name": "UDM-Internal-RADIUS",
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case "/proxy/network/api/s/default/rest/wlanconf":
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"_id":                     "wlan_enterprise",
						"name":                    "Corp-Enterprise",
						"security":                "wpaeap",
						"radiusprofile_id":        "default_prof_id",
						"radius_mac_auth_enabled": false,
					},
					{
						"_id":                     "wlan_mab",
						"name":                    "IoT-MAB",
						"security":                "open",
						"radiusprofile_id":        "",
						"radius_mac_auth_enabled": true,
					},
					{
						"_id":                     "wlan_normal_psk",
						"name":                    "Home-PSK",
						"security":                "wpapsk",
						"radiusprofile_id":        "",
						"radius_mac_auth_enabled": false,
					},
				},
			}
			json.NewEncoder(w).Encode(resp)

		case "/proxy/network/api/s/default/rest/wlanconf/wlan_enterprise",
			"/proxy/network/api/s/default/rest/wlanconf/wlan_mab":
			var payload map[string]interface{}
			json.NewDecoder(r.Body).Decode(&payload)
			wlanID := "wlan_enterprise"
			if r.URL.Path == "/proxy/network/api/s/default/rest/wlanconf/wlan_mab" {
				wlanID = "wlan_mab"
			}
			updatedWLANs[wlanID] = payload["radiusprofile_id"].(string)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{"meta": map[string]string{"rc": "ok"}})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client, err := NewClient(Config{
		BaseURL:  ts.URL,
		Site:     "default",
		AuthMode: "apikey",
		APIKey:   "testkey",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	migrated, err := client.MigrateAllRadiusWLANs("custom_prof_id")
	if err != nil {
		t.Fatalf("MigrateAllRadiusWLANs failed: %v", err)
	}

	if len(migrated) != 2 {
		t.Fatalf("Expected 2 migrated WLANs, got %d (%v)", len(migrated), migrated)
	}

	if updatedWLANs["wlan_enterprise"] != "custom_prof_id" {
		t.Errorf("wlan_enterprise was not updated to custom_prof_id: %v", updatedWLANs["wlan_enterprise"])
	}
	if updatedWLANs["wlan_mab"] != "custom_prof_id" {
		t.Errorf("wlan_mab was not updated to custom_prof_id: %v", updatedWLANs["wlan_mab"])
	}
	if _, ok := updatedWLANs["wlan_normal_psk"]; ok {
		t.Error("wlan_normal_psk should NOT have been touched!")
	}
}

