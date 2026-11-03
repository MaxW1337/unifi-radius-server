package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

func TestDeduplicator(t *testing.T) {
	d := NewDeduplicator(100 * time.Millisecond)

	key := "pending:AA:BB:CC:DD:EE:FF"

	// First alert should be permitted
	if !d.ShouldSend(key) {
		t.Error("Expected first alert to be permitted")
	}

	// Immediate repeat should be suppressed
	if d.ShouldSend(key) {
		t.Error("Expected immediate repeat alert to be suppressed by deduplicator")
	}

	// Wait for cooldown
	time.Sleep(120 * time.Millisecond)

	// After cooldown, should be permitted again
	if !d.ShouldSend(key) {
		t.Error("Expected alert to be permitted after cooldown")
	}
}

func TestHomeAssistantClient(t *testing.T) {
	var receivedPayload map[string]interface{}

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json, got %s", r.Header.Get("Content-Type"))
		}
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockServer.Close()

	ha, err := NewHomeAssistantClient(mockServer.URL)
	if err != nil {
		t.Fatalf("NewHomeAssistantClient failed: %v", err)
	}

	vlan := 20
	ev := NotificationEvent{
		Type:           EventPendingDevice,
		Title:          "Neues Gerät",
		Message:        "Bitte freigeben",
		ClientMAC:      "11:22:33:44:55:66",
		VLANID:         &vlan,
		EnrichedVendor: "Raspberry Pi Foundation",
		Timestamp:      time.Now(),
	}

	err = ha.SendEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("SendEvent failed: %v", err)
	}

	if receivedPayload["event"] != "unifi_radius_pending" {
		t.Errorf("Expected event unifi_radius_pending, got %v", receivedPayload["event"])
	}
	if receivedPayload["client_mac"] != "11:22:33:44:55:66" {
		t.Errorf("Expected client_mac 11:22:33:44:55:66, got %v", receivedPayload["client_mac"])
	}
}

func TestTelegramAuthorizationAndCommands(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer db.Close()

	// Pre-populate client
	vlan := 1
	c := &models.Client{
		MACAddress: "AA:BB:CC:DD:EE:01",
		Status:     models.ClientStatusPending,
		VLANID:     &vlan,
	}
	_ = db.CreateClient(c)

	tg, err := NewTelegramClient("dummy_token", "12345,67890", db, nil)
	if err != nil {
		t.Fatalf("NewTelegramClient failed: %v", err)
	}

	// 1. Authorization check
	if !tg.IsAuthorized(12345) {
		t.Error("Expected 12345 to be authorized")
	}
	if !tg.IsAuthorized(67890) {
		t.Error("Expected 67890 to be authorized")
	}
	if tg.IsAuthorized(99999) {
		t.Error("Expected 99999 to be UNauthorized")
	}

	// 2. Test callback button approval
	tg.handleCallback(context.Background(), "cb_1", 0, 0, "app|AA:BB:CC:DD:EE:01|10")

	updated, err := db.GetClientByMAC("AA:BB:CC:DD:EE:01")
	if err != nil || updated == nil {
		t.Fatalf("Failed to fetch updated client: %v", err)
	}
	if updated.Status != models.ClientStatusActive {
		t.Errorf("Expected status active, got %s", updated.Status)
	}
	if updated.VLANID == nil || *updated.VLANID != 10 {
		t.Errorf("Expected VLAN 10, got %v", updated.VLANID)
	}

	// 3. Test callback button block
	tg.handleCallback(context.Background(), "cb_2", 0, 0, "blk|AA:BB:CC:DD:EE:01")
	blocked, _ := db.GetClientByMAC("AA:BB:CC:DD:EE:01")
	if blocked.Status != models.ClientStatusDisabled {
		t.Errorf("Expected status disabled, got %s", blocked.Status)
	}
}
