package unifi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

func TestUniFiClientAPIKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-KEY")
		if apiKey != "test-secret-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/proxy/network/api/s/default/rest/networkconf" {
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{"name": "Default LAN", "purpose": "corporate", "vlan": "1", "ip_subnet": "192.168.1.0/24", "is_default": true},
					{"name": "IoT VLAN", "purpose": "corporate", "vlan": "20", "ip_subnet": "192.168.20.0/24"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		if r.URL.Path == "/proxy/network/api/s/default/stat/device" {
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{"name": "USW-Pro-24-PoE", "type": "usw", "model": "USW-24-PRO", "ip": "192.168.1.10", "mac": "00:11:22:33:44:55"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(Config{
		BaseURL:  ts.URL,
		AuthMode: "apikey",
		APIKey:   "test-secret-key",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	vlans, err := client.FetchNetworks()
	if err != nil {
		t.Fatalf("FetchNetworks failed: %v", err)
	}
	if len(vlans) != 2 {
		t.Fatalf("Expected 2 VLANs, got %d", len(vlans))
	}
	if vlans[1].VLANID != 20 || vlans[1].Name != "IoT VLAN" {
		t.Errorf("Unexpected VLAN: %+v", vlans[1])
	}

	devices, err := client.FetchDevices()
	if err != nil {
		t.Fatalf("FetchDevices failed: %v", err)
	}
	if len(devices) != 1 || devices[0].IPOrCIDR != "192.168.1.10" {
		t.Errorf("Unexpected devices: %+v", devices)
	}
}

func TestUniFiClientCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth/login" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if body["username"] == "admin" && body["password"] == "password123" {
				http.SetCookie(w, &http.Cookie{Name: "TOKEN", Value: "valid-session-token", Path: "/"})
				w.Header().Set("X-CSRF-Token", "csrf-token-123")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		cookie, err := r.Cookie("TOKEN")
		if err != nil || cookie.Value != "valid-session-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if r.URL.Path == "/proxy/network/api/s/default/rest/networkconf" {
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{"name": "Default", "vlan": "1"},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(Config{
		BaseURL:  ts.URL,
		AuthMode: "credentials",
		Username: "admin",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if err := client.Login(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	vlans, err := client.FetchNetworks()
	if err != nil {
		t.Fatalf("FetchNetworks failed: %v", err)
	}
	if len(vlans) != 1 {
		t.Errorf("Expected 1 VLAN, got %d", len(vlans))
	}
}

func TestSyncServiceIntegration(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("database.Open failed: %v", err)
	}
	defer db.Close()

	// Pre-create a client with MAC
	vlan1 := 1
	c := &models.Client{
		MACAddress: "AA:BB:CC:DD:EE:FF",
		AuthType:   models.AuthTypeMAB,
		VLANID:     &vlan1,
		Status:     models.ClientStatusActive,
	}
	if err := db.CreateClient(c); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/proxy/network/api/s/default/rest/networkconf":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{"name": "Corporate", "vlan": "10"},
				},
			})
		case "/proxy/network/api/s/default/stat/device":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{"name": "Core-Switch", "ip": "192.168.1.2"},
				},
			})
		case "/proxy/network/api/s/default/stat/sta", "/proxy/network/api/s/default/stat/alluser":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"mac":              "aabbccddeeff",
						"name":             "Workstation-01",
						"hostname":         "workstation.lan",
						"oui":              "Dell Inc.",
						"ip":               "192.168.1.50",
						"last_uplink_name": "Core-Switch",
						"sw_port":          4,
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// Configure settings pointing to mock server
	settings, _ := db.GetSettings()
	settings.UniFiURL = ts.URL
	settings.UniFiAuthMode = "apikey"
	settings.UniFiAPIKey = "dummy-key"
	settings.GlobalSharedSecret = "synced_radius_secret"
	if err := db.UpdateSettings(settings); err != nil {
		t.Fatalf("UpdateSettings failed: %v", err)
	}

	bus := eventbus.NewBus(20)
	logCh, _, unsub := bus.SubscribeLogs()
	defer unsub()

	syncSvc := NewSyncService(db, bus)
	if err := syncSvc.SyncNow(); err != nil {
		t.Fatalf("SyncNow failed: %v", err)
	}

	// Verify log events received on bus
	receivedSyncLogs := false
	for len(logCh) > 0 {
		l := <-logCh
		if l.Source == "UNIFI-SYNC" {
			receivedSyncLogs = true
			break
		}
	}
	if !receivedSyncLogs {
		t.Errorf("Expected UNIFI-SYNC log events on bus, but none found")
	}

	// Verify VLAN synced
	vlans, err := db.ListVLANs()
	if err != nil || len(vlans) != 1 || vlans[0].VLANID != 10 {
		t.Fatalf("VLAN sync check failed: %+v, err: %v", vlans, err)
	}

	// Verify NAS synced
	nasClients, err := db.ListNASClients()
	if err != nil {
		t.Fatalf("ListNASClients failed: %v", err)
	}
	foundNAS := false
	for _, n := range nasClients {
		if n.IPOrCIDR == "192.168.1.2" && n.SharedSecret == "synced_radius_secret" {
			foundNAS = true
			break
		}
	}
	if !foundNAS {
		t.Errorf("NAS 192.168.1.2 with secret not found in list: %+v", nasClients)
	}

	// Verify Client Enriched
	enrichedClient, err := db.GetClientByMAC("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("GetClientByMAC failed: %v", err)
	}
	if enrichedClient.UniFiName != "Workstation-01" || enrichedClient.UniFiVendor != "Dell Inc." || enrichedClient.UniFiSwitchPort != "4" {
		t.Errorf("Client enrichment not applied: %+v", enrichedClient)
	}
}

func TestReconnectAndPowerCycle(t *testing.T) {
	reconnectCalled := false
	powerCycleCalled := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proxy/network/api/s/default/cmd/stamgr" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if body["cmd"] == "kick-sta" && body["mac"] == "aa:bb:cc:dd:ee:ff" {
				reconnectCalled = true
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if r.URL.Path == "/proxy/network/api/s/default/cmd/devmgr" {
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			portIdx, _ := body["port_idx"].(float64)
			if body["cmd"] == "power-cycle" && body["mac"] == "00:11:22:33:44:55" && int(portIdx) == 12 {
				powerCycleCalled = true
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(Config{
		BaseURL:  ts.URL,
		AuthMode: "apikey",
		APIKey:   "key",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	if err := client.ReconnectClient("AA:BB:CC:DD:EE:FF"); err != nil {
		t.Errorf("ReconnectClient failed: %v", err)
	}
	if !reconnectCalled {
		t.Errorf("Expected ReconnectClient to hit stamgr endpoint")
	}

	if err := client.PowerCyclePort("00:11:22:33:44:55", 12); err != nil {
		t.Errorf("PowerCyclePort failed: %v", err)
	}
	if !powerCycleCalled {
		t.Errorf("Expected PowerCyclePort to hit devmgr endpoint")
	}
}

func TestRestartPortNonPoE(t *testing.T) {
	origPause := PortBouncePause
	PortBouncePause = 10 * time.Millisecond
	defer func() { PortBouncePause = origPause }()

	putStep := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/proxy/network/api/s/default/stat/device" {
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"_id":   "sw-test-123",
						"name":  "USW-48-G2",
						"mac":   "6c:63:f8:3f:08:fb",
						"model": "USL48B",
						"type":  "usw",
						"port_overrides": []map[string]interface{}{
							{
								"name":        "Port 18",
								"port_idx":    18,
								"portconf_id": "profile-radius-mab",
							},
						},
						"port_table": []map[string]interface{}{
							{
								"name":        "Port 18",
								"port_idx":    18,
								"port_poe":    false,
								"poe_caps":    0,
								"portconf_id": "profile-radius-mab",
							},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Method == http.MethodPut && r.URL.Path == "/proxy/network/api/s/default/rest/device/sw-test-123" {
			var body map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			overrides, _ := body["port_overrides"].([]interface{})
			if len(overrides) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			om, _ := overrides[0].(map[string]interface{})
			putStep++

			if putStep == 1 {
				// Step 1: disabled=true, portconf_id must be removed
				if om["disabled"] != true {
					t.Errorf("Step 1 expected disabled=true, got %v", om["disabled"])
				}
				if _, hasConf := om["portconf_id"]; hasConf {
					t.Errorf("Step 1 expected portconf_id to be removed, got %v", om["portconf_id"])
				}
				w.WriteHeader(http.StatusOK)
				return
			} else if putStep == 2 {
				// Step 2: disabled=false, portconf_id must be restored
				if om["disabled"] != false {
					t.Errorf("Step 2 expected disabled=false, got %v", om["disabled"])
				}
				if om["portconf_id"] != "profile-radius-mab" {
					t.Errorf("Step 2 expected portconf_id='profile-radius-mab', got %v", om["portconf_id"])
				}
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(Config{
		BaseURL:  ts.URL,
		AuthMode: "apikey",
		APIKey:   "test-key",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	err = client.RestartPortNonPoE("6c:63:f8:3f:08:fb", 18)
	if err != nil {
		t.Fatalf("RestartPortNonPoE failed: %v", err)
	}
	if putStep != 2 {
		t.Fatalf("Expected exactly 2 PUT calls (disable, then enable/restore), got %d", putStep)
	}
}

func TestRestartPortAutoDetect(t *testing.T) {
	origPause := PortBouncePause
	PortBouncePause = 10 * time.Millisecond
	defer func() { PortBouncePause = origPause }()

	nonPoEBounced := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/proxy/network/api/s/default/stat/device" {
			resp := map[string]interface{}{
				"meta": map[string]string{"rc": "ok"},
				"data": []map[string]interface{}{
					{
						"_id":   "sw-nonpoe-1",
						"name":  "USW-48-G2",
						"mac":   "6c:63:f8:3f:08:fb",
						"model": "USL48B",
						"type":  "usw",
						"port_overrides": []map[string]interface{}{
							{
								"port_idx":    5,
								"portconf_id": "conf-123",
							},
						},
						"port_table": []map[string]interface{}{
							{
								"port_idx":    5,
								"port_poe":    false,
								"poe_caps":    0,
								"portconf_id": "conf-123",
							},
						},
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		if r.Method == http.MethodPut && r.URL.Path == "/proxy/network/api/s/default/rest/device/sw-nonpoe-1" {
			nonPoEBounced = true
			w.WriteHeader(http.StatusOK)
			return
		}

		// Should NOT hit devmgr power-cycle for non-PoE port
		if r.URL.Path == "/proxy/network/api/s/default/cmd/devmgr" {
			t.Errorf("Should not call cmd/devmgr power-cycle for non-PoE port")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client, err := NewClient(Config{
		BaseURL:  ts.URL,
		AuthMode: "apikey",
		APIKey:   "test-key",
	})
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}

	err = client.RestartPort("6c:63:f8:3f:08:fb", 5)
	if err != nil {
		t.Fatalf("RestartPort failed: %v", err)
	}
	if !nonPoEBounced {
		t.Fatalf("Expected non-PoE bounce to be executed")
	}
}

