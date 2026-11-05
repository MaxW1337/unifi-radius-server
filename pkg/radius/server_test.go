package radius

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

func TestPacketEncodingAndDynamicVLAN(t *testing.T) {
	req := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 42,
	}
	_, _ = rand.Read(req.Authenticator[:])
	req.AddString(AttrUserName, "AA:BB:CC:DD:EE:FF")
	req.AddString(AttrCallingStationID, "AA:BB:CC:DD:EE:FF")

	secret := []byte("secret_xyz")
	reqBytes, err := req.Encode(secret)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	parsedReq, err := ParsePacket(reqBytes)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if parsedReq.Code != CodeAccessRequest || parsedReq.Identifier != 42 {
		t.Errorf("Mismatch in parsed packet: code=%d, id=%d", parsedReq.Code, parsedReq.Identifier)
	}

	// Create Accept with VLAN 40
	resp := parsedReq.CreateResponse(CodeAccessAccept)
	resp.AddDynamicVLAN(40)

	respBytes, err := resp.Encode(secret)
	if err != nil {
		t.Fatalf("Response Encode failed: %v", err)
	}

	parsedResp, err := ParsePacket(respBytes)
	if err != nil {
		t.Fatalf("Parsed Response failed: %v", err)
	}

	if parsedResp.Code != CodeAccessAccept {
		t.Fatalf("Expected CodeAccessAccept, got %d", parsedResp.Code)
	}

	vlanAttr := parsedResp.GetString(AttrTunnelPrivateGroupID)
	if vlanAttr != "40" {
		t.Errorf("Expected VLAN 40, got %s", vlanAttr)
	}
}

func TestServerMABFlow(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("database.Open failed: %v", err)
	}
	defer db.Close()

	settings, _ := db.GetSettings()
	settings.DefaultAllowVLAN = 15
	settings.UnknownMABPolicy = models.PolicyAutoAcceptUnknown
	settings.GlobalSharedSecret = "test_shared_secret"
	if err := db.UpdateSettings(settings); err != nil {
		t.Fatalf("UpdateSettings failed: %v", err)
	}

	// Register known active client
	vlan60 := 60
	_ = db.CreateClient(&models.Client{
		MACAddress: "00:11:22:33:44:55",
		AuthType:   models.AuthTypeMAB,
		VLANID:     &vlan60,
		Status:     models.ClientStatusActive,
	})

	// Register disabled client
	_ = db.CreateClient(&models.Client{
		MACAddress: "AA:AA:AA:AA:AA:AA",
		AuthType:   models.AuthTypeMAB,
		Status:     models.ClientStatusDisabled,
	})

	bus := eventbus.NewBus(50)
	authChan, unsub := bus.SubscribeAuth()
	defer unsub()

	testPort := 18123
	srv := NewServer(db, bus, testPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Server.Start failed: %v", err)
	}
	defer srv.Stop()

	// Wait for server to bind
	time.Sleep(50 * time.Millisecond)

	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:18123")
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(2 * time.Second))

	// 1. Send Request for Known Active Client
	req1 := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 1,
	}
	_, _ = rand.Read(req1.Authenticator[:])
	req1.AddString(AttrUserName, "001122334455")
	reqBytes1, _ := req1.Encode([]byte("test_shared_secret"))

	_, err = clientConn.Write(reqBytes1)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	replyBuf := make([]byte, 1024)
	n, err := clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("Read reply failed: %v", err)
	}

	resp1, err := ParsePacket(replyBuf[:n])
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	if resp1.Code != CodeAccessAccept {
		t.Errorf("Expected CodeAccessAccept for known client, got %d", resp1.Code)
	}
	if resp1.GetString(AttrTunnelPrivateGroupID) != "60" {
		t.Errorf("Expected VLAN 60, got %s", resp1.GetString(AttrTunnelPrivateGroupID))
	}

	// Verify Auth Event received on eventbus
	select {
	case event := <-authChan:
		if event.Status != "ACCEPT" || *event.VLANID != 60 {
			t.Errorf("Unexpected event on bus: %+v", event)
		}
	case <-time.After(1 * time.Second):
		t.Error("Timed out waiting for auth event on bus")
	}

	// 2. Send Request for Disabled Client
	req2 := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 2,
	}
	_, _ = rand.Read(req2.Authenticator[:])
	req2.AddString(AttrUserName, "AA-AA-AA-AA-AA-AA")
	reqBytes2, _ := req2.Encode([]byte("test_shared_secret"))

	_, _ = clientConn.Write(reqBytes2)
	n, err = clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("Read reply failed: %v", err)
	}

	resp2, _ := ParsePacket(replyBuf[:n])
	if resp2.Code != CodeAccessReject {
		t.Errorf("Expected CodeAccessReject for disabled client, got %d", resp2.Code)
	}

	// 3. Send Request for Unknown Client (Auto-Accept Policy)
	req3 := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 3,
	}
	_, _ = rand.Read(req3.Authenticator[:])
	req3.AddString(AttrCallingStationID, "99:88:77:66:55:44")
	reqBytes3, _ := req3.Encode([]byte("test_shared_secret"))

	_, _ = clientConn.Write(reqBytes3)
	n, err = clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("Read reply failed: %v", err)
	}

	resp3, _ := ParsePacket(replyBuf[:n])
	if resp3.Code != CodeAccessAccept {
		t.Errorf("Expected CodeAccessAccept for auto-accepted unknown client, got %d", resp3.Code)
	}
	if resp3.GetString(AttrTunnelPrivateGroupID) != "15" {
		t.Errorf("Expected Default VLAN 15, got %s", resp3.GetString(AttrTunnelPrivateGroupID))
	}

	// Wait for async batch writer to flush to SQLite
	time.Sleep(150 * time.Millisecond)

	// Verify client auto-created in database
	autoClient, err := db.GetClientByMAC("99:88:77:66:55:44")
	if err != nil || autoClient == nil {
		t.Fatalf("Expected auto-discovered client in DB: %v", err)
	}
	if autoClient.Status != models.ClientStatusPending {
		t.Errorf("Expected status 'pending', got %s", autoClient.Status)
	}
}

func TestConcurrentHighLoadRequests(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("database.Open failed: %v", err)
	}
	defer db.Close()

	settings, _ := db.GetSettings()
	settings.DefaultAllowVLAN = 10
	settings.GlobalSharedSecret = "high_load_secret"
	_ = db.UpdateSettings(settings)

	// Pre-seed 5 known clients
	for i := 1; i <= 5; i++ {
		vlan := 10 + i
		_ = db.CreateClient(&models.Client{
			MACAddress: "00:11:22:33:44:0" + string(rune('0'+i)),
			AuthType:   models.AuthTypeMAB,
			VLANID:     &vlan,
			Status:     models.ClientStatusActive,
		})
	}

	bus := eventbus.NewBus(100)
	testPort := 18125
	srv := NewServer(db, bus, testPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Server.Start failed: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	serverAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:18125")

	concurrency := 15
	requestsPerWorker := 20
	totalRequests := concurrency * requestsPerWorker

	var wg sync.WaitGroup
	errorsChan := make(chan error, totalRequests)

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			clientConn, err := net.DialUDP("udp", nil, serverAddr)
			if err != nil {
				errorsChan <- err
				return
			}
			defer clientConn.Close()
			clientConn.SetDeadline(time.Now().Add(3 * time.Second))

			buf := make([]byte, 1024)

			for reqIdx := 0; reqIdx < requestsPerWorker; reqIdx++ {
				req := &Packet{
					Code:       CodeAccessRequest,
					Identifier: byte((workerID*requestsPerWorker + reqIdx) % 255),
				}
				_, _ = rand.Read(req.Authenticator[:])
				req.AddString(AttrUserName, "00:11:22:33:44:01")
				reqBytes, _ := req.Encode([]byte("high_load_secret"))

				if _, err := clientConn.Write(reqBytes); err != nil {
					errorsChan <- err
					return
				}

				n, err := clientConn.Read(buf)
				if err != nil {
					errorsChan <- err
					return
				}

				resp, err := ParsePacket(buf[:n])
				if err != nil || resp.Code != CodeAccessAccept {
					errorsChan <- err
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errorsChan)

	var errs []error
	for err := range errorsChan {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		t.Fatalf("High load test encountered %d errors out of %d requests: %v", len(errs), totalRequests, errs[0])
	}
}

func TestServerPortConflictAndRetryBinding(t *testing.T) {
	testPort := 18129
	addr := net.UDPAddr{
		Port: testPort,
		IP:   net.ParseIP("0.0.0.0"),
	}

	// 1. Simulate existing process (e.g. FreeRADIUS) binding the port
	occupyingConn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		t.Fatalf("Failed to occupy test port %d: %v", testPort, err)
	}

	dbPath := filepath.Join(t.TempDir(), "radius_conflict.db")
	db, err := database.Open(dbPath)
	if err != nil {
		occupyingConn.Close()
		t.Fatalf("database.Open failed: %v", err)
	}
	defer db.Close()

	settings, _ := db.GetSettings()
	settings.GlobalSharedSecret = "retry_test_secret"
	_ = db.UpdateSettings(settings)

	// Create test client in DB
	vlan := 10
	_ = db.CreateClient(&models.Client{
		MACAddress: "00:AA:BB:CC:DD:EE",
		VLANID:     &vlan,
		Status:     models.ClientStatusActive,
		AuthType:   models.AuthTypeMAB,
	})

	bus := eventbus.NewBus(50)
	srv := NewServer(db, bus, testPort)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Start server while port is occupied. Should NOT return fatal error.
	if err := srv.Start(ctx); err != nil {
		occupyingConn.Close()
		t.Fatalf("Expected non-fatal Start, got error: %v", err)
	}
	defer srv.Stop()

	// Server should report not listening initially
	if srv.IsListening() {
		occupyingConn.Close()
		t.Fatal("Expected IsListening() to be false when port is occupied")
	}

	// 3. Free the port (simulating migration / stopping FreeRADIUS)
	occupyingConn.Close()

	// 4. Wait for background retry loop to bind the port
	deadline := time.Now().Add(5 * time.Second)
	bound := false
	for time.Now().Before(deadline) {
		if srv.IsListening() {
			bound = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !bound {
		t.Fatal("Server failed to automatically bind port after it was freed")
	}

	// 5. Send Access-Request to verify active packet processing
	serverAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", testPort))
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(2 * time.Second))

	req := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 42,
	}
	_, _ = rand.Read(req.Authenticator[:])
	req.AddString(AttrUserName, "00aabbccddee")
	reqBytes, _ := req.Encode([]byte("retry_test_secret"))

	if _, err := clientConn.Write(reqBytes); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	replyBuf := make([]byte, 1024)
	n, err := clientConn.Read(replyBuf)
	if err != nil {
		t.Fatalf("Read reply failed after port takeover: %v", err)
	}

	resp, err := ParsePacket(replyBuf[:n])
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}
	if resp.Code != CodeAccessAccept {
		t.Errorf("Expected CodeAccessAccept, got %d", resp.Code)
	}
}

func TestPacketFormatDebug(t *testing.T) {
	req := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 77,
	}
	_, _ = rand.Read(req.Authenticator[:])
	req.AddString(AttrUserName, "test-user-debug")
	req.AddString(AttrCallingStationID, "AA-BB-CC-DD-EE-FF")
	portBytes := make([]byte, 4)
	portBytes[3] = 42
	req.AddAttribute(AttrNASPort, portBytes)

	secret := []byte("testing123")
	rawBytes, err := req.Encode(secret)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	debugOutput := req.FormatDebug(rawBytes)
	if debugOutput == "" {
		t.Fatal("FormatDebug returned empty string")
	}

	// Verify it contains Code Name, ID, Attribute Names, Values, and Hex Dump
	expectedSubstrings := []string{
		"Access-Request",
		"ID: 77",
		"User-Name",
		"test-user-debug",
		"Calling-Station-Id",
		"AA-BB-CC-DD-EE-FF",
		"NAS-Port",
		"Hex Dump:",
	}

	for _, sub := range expectedSubstrings {
		if !contains(debugOutput, sub) {
			t.Errorf("FormatDebug output missing expected substring: %q\nOutput:\n%s", sub, debugOutput)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && findSubstr(s, substr)))
}

func findSubstr(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestServerDebugModeToggle(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := database.Open(filepath.Join(tmpDir, "radius_debug.db"))
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}
	defer db.Close()

	bus := eventbus.NewBus(10)
	srv := NewServer(db, bus, 18129)

	if srv.IsDebugMode() {
		t.Errorf("Expected debugMode default false, got true")
	}

	srv.SetDebugMode(true)
	if !srv.IsDebugMode() {
		t.Errorf("Expected debugMode true, got false")
	}

	srv.SetDebugMode(false)
	if srv.IsDebugMode() {
		t.Errorf("Expected debugMode false, got true")
	}
}

func TestNASPortAndNASNameExtraction(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := database.Open(filepath.Join(tmpDir, "radius_port.db"))
	if err != nil {
		t.Fatalf("Failed to open test db: %v", err)
	}
	defer db.Close()

	bus := eventbus.NewBus(10)
	srv := NewServer(db, bus, 18199)
	_ = srv

	// Create a test client with switch info
	mac := "00:22:33:44:55:66"
	_ = db.CreateClient(&models.Client{
		MACAddress:      mac,
		Status:          models.ClientStatusActive,
		UniFiSwitchName: "USW-48-G2",
		UniFiSwitchPort: "18",
	})

	// 1. Build RADIUS packet with binary NAS-Port (18 as uint32) and NAS-Identifier
	req := &Packet{
		Code:       CodeAccessRequest,
		Identifier: 12,
	}
	_, _ = rand.Read(req.Authenticator[:])
	req.AddString(AttrUserName, mac)
	req.AddString(AttrCallingStationID, mac)
	req.AddString(AttrNASIdentifier, "USW-48-G2")

	portBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(portBytes, 18)
	req.AddAttribute(AttrNASPort, portBytes)

	// Verify packet attributes
	rawPort := req.GetAttribute(AttrNASPort)
	if binaryToUint(rawPort) != 18 {
		t.Errorf("Expected port 18, got %d", binaryToUint(rawPort))
	}

	// Verify format value
	valStr := FormatValue(AttrNASPort, rawPort)
	if valStr != "18" {
		t.Errorf("Expected FormatValue to format port as '18', got %q", valStr)
	}
}


