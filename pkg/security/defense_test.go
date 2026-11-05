package security

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/notify"
)

type mockDispatcher struct {
	mu     sync.Mutex
	events []notify.NotificationEvent
}

func (m *mockDispatcher) Dispatch(ctx context.Context, ev notify.NotificationEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

type mockKicker struct {
	mu     sync.Mutex
	kicked []string
}

func (m *mockKicker) ReconnectClient(clientMAC string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kicked = append(m.kicked, clientMAC)
	return nil
}

func TestDefenseManagerQuarantineAndAutoUnban(t *testing.T) {
	bus := eventbus.NewBus(100)
	disp := &mockDispatcher{}
	kick := &mockKicker{}

	dm := NewDefenseManager(nil, bus, disp, kick)
	dm.ApplySettings(&models.Settings{
		DefenseEnabled:            true,
		DefenseMaxFailures:        3,
		DefenseWindowSeconds:      5,
		DefenseBanDurationMinutes: 1, // 1 minute
	})
	// For testing, override banDuration to 400ms
	dm.banDuration = 400 * time.Millisecond

	mac := "aa:bb:cc:11:22:33"

	// 1. Initial status: Not banned
	if banned, _ := dm.IsBanned(mac, ""); banned {
		t.Fatal("Expected client not to be banned initially")
	}

	// 2. First 2 failures: threshold not reached
	dm.RecordFailure(mac, "", "192.168.1.1", "1", "Bad password")
	dm.RecordFailure(mac, "", "192.168.1.1", "1", "Bad password")

	if banned, _ := dm.IsBanned(mac, ""); banned {
		t.Fatal("Expected client not to be banned after 2 failures")
	}

	// 3. 3rd failure: threshold reached -> triggers Quarantine Ban
	ban := dm.RecordFailure(mac, "", "192.168.1.1", "1", "Bad password")
	if ban == nil {
		t.Fatal("Expected BanInfo on 3rd failure")
	}

	banned, info := dm.IsBanned(mac, "")
	if !banned || info == nil {
		t.Fatal("Expected client to be banned after 3rd failure")
	}

	// Wait a moment for async kick & dispatch
	time.Sleep(20 * time.Millisecond)
	kick.mu.Lock()
	if len(kick.kicked) == 0 || kick.kicked[0] != "AA:BB:CC:11:22:33" {
		t.Errorf("Expected client to be kicked upon ban, got: %v", kick.kicked)
	}
	kick.mu.Unlock()

	disp.mu.Lock()
	if len(disp.events) == 0 || disp.events[0].Type != notify.EventQuarantineBan {
		t.Errorf("Expected EventQuarantineBan dispatched, got: %v", disp.events)
	}
	disp.mu.Unlock()

	// 4. Test Auto-Unban after expiration
	time.Sleep(500 * time.Millisecond) // exceeds 400ms banDuration
	if bannedAfter, _ := dm.IsBanned(mac, ""); bannedAfter {
		t.Errorf("Expected client to be auto-unbanned after banDuration expired")
	}
}

func TestDefenseManagerManualUnban(t *testing.T) {
	bus := eventbus.NewBus(100)
	kick := &mockKicker{}
	dm := NewDefenseManager(nil, bus, nil, kick)
	dm.maxFailures = 2
	dm.banDuration = 10 * time.Minute

	mac := "00:11:22:33:44:55"
	dm.RecordFailure(mac, "", "10.0.0.1", "2", "Fail 1")
	dm.RecordFailure(mac, "", "10.0.0.1", "2", "Fail 2")

	if banned, _ := dm.IsBanned(mac, ""); !banned {
		t.Fatal("Expected client to be banned")
	}

	// Manual unban
	unbanned := dm.Unban(mac)
	if !unbanned {
		t.Fatal("Expected Unban to return true")
	}

	if banned, _ := dm.IsBanned(mac, ""); banned {
		t.Fatal("Expected client to be unbanned")
	}
}

func TestDefenseManagerSuccessReset(t *testing.T) {
	dm := NewDefenseManager(nil, nil, nil, nil)
	dm.maxFailures = 3

	mac := "11:22:33:44:55:66"
	dm.RecordFailure(mac, "", "10.0.0.1", "1", "Fail 1")
	dm.RecordFailure(mac, "", "10.0.0.1", "1", "Fail 2")

	// Authentication succeeds
	dm.RecordSuccess(mac, "")

	// 3rd failure occurs, but previous 2 were reset!
	dm.RecordFailure(mac, "", "10.0.0.1", "1", "Fail 3")

	if banned, _ := dm.IsBanned(mac, ""); banned {
		t.Fatal("Client should not be banned because success reset the counter")
	}
}
