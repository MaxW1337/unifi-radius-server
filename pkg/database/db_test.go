package database

import (
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

func setupTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return db
}

func TestDBInitialization(t *testing.T) {
	db := setupTestDB(t)

	settings, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}

	if settings.DefaultAllowVLAN != 1 {
		t.Errorf("Expected DefaultAllowVLAN=1, got %d", settings.DefaultAllowVLAN)
	}
	if settings.WebPort != 9182 {
		t.Errorf("Expected WebPort=9182, got %d", settings.WebPort)
	}
	if settings.RADIUSAuthPort != 1812 {
		t.Errorf("Expected RADIUSAuthPort=1812, got %d", settings.RADIUSAuthPort)
	}
}

func TestClientOperations(t *testing.T) {
	db := setupTestDB(t)

	// 1. Create MAB Client with un-normalized MAC
	vlan10 := 10
	c := &models.Client{
		MACAddress:  "00-11-22-33-44-55",
		AuthType:    models.AuthTypeMAB,
		VLANID:      &vlan10,
		Status:      models.ClientStatusActive,
		Description: "Office Printer",
		UniFiName:   "HP LaserJet",
	}

	err := db.CreateClient(c)
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	if c.ID == 0 {
		t.Fatalf("Expected valid client ID, got 0")
	}
	if c.MACAddress != "00:11:22:33:44:55" {
		t.Errorf("Expected normalized MAC 00:11:22:33:44:55, got %s", c.MACAddress)
	}

	// 2. Fetch by MAC with different casing/format
	found, err := db.GetClientByMAC("001122334455")
	if err != nil {
		t.Fatalf("GetClientByMAC failed: %v", err)
	}
	if found.ID != c.ID || found.Description != "Office Printer" {
		t.Errorf("Found client mismatch: %+v", found)
	}

	// 3. Update Client
	found.Description = "Updated Printer Name"
	vlan20 := 20
	found.VLANID = &vlan20
	if err := db.UpdateClient(found); err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}

	updated, _ := db.GetClientByID(c.ID)
	if *updated.VLANID != 20 || updated.Description != "Updated Printer Name" {
		t.Errorf("Client update not reflected: %+v", updated)
	}

	// 4. List and search
	list, total, err := db.ListClients("LaserJet", "", 10, 0)
	if err != nil || total != 1 || len(list) != 1 {
		t.Errorf("Search failed: total=%d, len=%d, err=%v", total, len(list), err)
	}

	// 5. Delete Client
	if err := db.DeleteClient(c.ID); err != nil {
		t.Fatalf("DeleteClient failed: %v", err)
	}
	_, err = db.GetClientByID(c.ID)
	if err != ErrClientNotFound {
		t.Errorf("Expected ErrClientNotFound, got %v", err)
	}
}

func TestClientVLANNameAndFiltering(t *testing.T) {
	db := setupTestDB(t)

	// Setup VLANs
	vlans := []models.VLAN{
		{VLANID: 10, Name: "Guest WiFi", Subnet: "192.168.10.0/24"},
		{VLANID: 20, Name: "Security Cameras", Subnet: "192.168.20.0/24"},
	}
	if err := db.ReplaceVLANs(vlans); err != nil {
		t.Fatalf("ReplaceVLANs failed: %v", err)
	}

	vlan10 := 10
	vlan20 := 20

	c1 := &models.Client{MACAddress: "11:22:33:44:55:01", VLANID: &vlan10, Status: models.ClientStatusActive, Description: "Guest Laptop"}
	c2 := &models.Client{MACAddress: "11:22:33:44:55:02", VLANID: &vlan20, Status: models.ClientStatusActive, Description: "Front Door Cam"}
	c3 := &models.Client{MACAddress: "11:22:33:44:55:03", VLANID: nil, Status: models.ClientStatusPending, Description: "Unknown Phone"}

	_ = db.CreateClient(c1)
	_ = db.CreateClient(c2)
	_ = db.CreateClient(c3)

	// 1. Verify GetClientByID resolves VLANName
	got1, err := db.GetClientByID(c1.ID)
	if err != nil {
		t.Fatalf("GetClientByID failed: %v", err)
	}
	if got1.VLANName != "Guest WiFi" {
		t.Errorf("Expected VLANName='Guest WiFi', got '%s'", got1.VLANName)
	}

	// 2. Verify ListClients returns all with VLANNames
	all, total, err := db.ListClients("", "", 10, 0)
	if err != nil || total != 3 {
		t.Fatalf("ListClients failed: total=%d, err=%v", total, err)
	}
	for _, c := range all {
		if c.ID == c1.ID && c.VLANName != "Guest WiFi" {
			t.Errorf("Client 1 VLANName mismatch: '%s'", c.VLANName)
		}
		if c.ID == c2.ID && c.VLANName != "Security Cameras" {
			t.Errorf("Client 2 VLANName mismatch: '%s'", c.VLANName)
		}
	}

	// 3. Test filter by VLAN 20
	camList, totalCam, err := db.ListClients("", "", 10, 0, "20")
	if err != nil || totalCam != 1 || len(camList) != 1 || camList[0].ID != c2.ID {
		t.Errorf("Filter by VLAN 20 failed: total=%d, len=%d", totalCam, len(camList))
	}

	// 4. Test filter by default VLAN
	defList, totalDef, err := db.ListClients("", "", 10, 0, "default")
	if err != nil || totalDef != 1 || len(defList) != 1 || defList[0].ID != c3.ID {
		t.Errorf("Filter by default VLAN failed: total=%d, len=%d", totalDef, len(defList))
	}

	// 5. Test search query by VLAN name
	searchList, totalSearch, err := db.ListClients("Cameras", "", 10, 0)
	if err != nil || totalSearch != 1 || len(searchList) != 1 || searchList[0].ID != c2.ID {
		t.Errorf("Search by VLAN name failed: total=%d, len=%d", totalSearch, len(searchList))
	}
}

func TestVLANOperations(t *testing.T) {
	db := setupTestDB(t)

	vlans := []models.VLAN{
		{VLANID: 1, Name: "Default LAN", Subnet: "192.168.1.0/24", IsDefault: true},
		{VLANID: 20, Name: "IoT Network", Subnet: "192.168.20.0/24", IsDefault: false},
		{VLANID: 30, Name: "Guest Network", Subnet: "192.168.30.0/24", IsDefault: false},
	}

	if err := db.ReplaceVLANs(vlans); err != nil {
		t.Fatalf("ReplaceVLANs failed: %v", err)
	}

	cached, err := db.ListVLANs()
	if err != nil {
		t.Fatalf("ListVLANs failed: %v", err)
	}
	if len(cached) != 3 {
		t.Fatalf("Expected 3 VLANs, got %d", len(cached))
	}

	v20, err := db.GetVLAN(20)
	if err != nil || v20.Name != "IoT Network" {
		t.Errorf("GetVLAN(20) mismatch: %+v, err=%v", v20, err)
	}
}

func TestNASOperations(t *testing.T) {
	db := setupTestDB(t)

	// Add manual NAS with CIDR
	nasSubnet := &models.NASClient{
		IPOrCIDR:     "192.168.10.0/24",
		Name:         "Lab Switches Subnet",
		SharedSecret: "lab_secret_xyz",
	}
	if err := db.CreateNASClient(nasSubnet); err != nil {
		t.Fatalf("CreateNASClient failed: %v", err)
	}

	// Match IP inside subnet
	found, err := db.FindNASByIP("192.168.10.45")
	if err != nil {
		t.Fatalf("FindNASByIP failed: %v", err)
	}
	if found.SharedSecret != "lab_secret_xyz" {
		t.Errorf("Shared secret mismatch: %s", found.SharedSecret)
	}

	// Match non-existing IP
	_, err = db.FindNASByIP("10.0.0.1")
	if err != ErrNASNotFound {
		t.Errorf("Expected ErrNASNotFound, got %v", err)
	}
}

func TestAuthLogsAndPruning(t *testing.T) {
	db := setupTestDB(t)

	vlan := 10
	logEntry := &models.AuthLog{
		Timestamp:      time.Now().UTC(),
		ClientMAC:      "00:11:22:33:44:55",
		AuthType:       models.AuthTypeMAB,
		Status:         "ACCEPT",
		VLANID:         &vlan,
		Reason:         "Valid known client",
		LatencyMS:      1.5,
		EnrichedName:   "Living Room TV",
		EnrichedVendor: "Sony",
	}

	if err := db.InsertAuthLog(logEntry); err != nil {
		t.Fatalf("InsertAuthLog failed: %v", err)
	}

	logs, total, err := db.ListAuthLogs(10, 0, "ACCEPT", "")
	if err != nil || total != 1 || len(logs) != 1 {
		t.Fatalf("ListAuthLogs failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	if logs[0].ClientMAC != "00:11:22:33:44:55" {
		t.Errorf("MAC mismatch in log: %s", logs[0].ClientMAC)
	}

	// Test Pruning
	pruned, err := db.PruneAuthLogs(30, 1000)
	if err != nil {
		t.Fatalf("PruneAuthLogs failed: %v", err)
	}
	if pruned < 0 {
		t.Errorf("Unexpected prune result: %d", pruned)
	}
}

func TestCertificates(t *testing.T) {
	db := setupTestDB(t)

	cert := &models.Certificate{
		SerialNumber:   "1001",
		CommonName:     "UniFi RADIUS Root CA",
		CertType:       "ca",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		PrivateKeyPEM:  "-----BEGIN EC PRIVATE KEY-----\nMIIE...\n-----END EC PRIVATE KEY-----",
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().AddDate(10, 0, 0),
		IsRevoked:      false,
	}

	if err := db.SaveCertificate(cert); err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	activeCA, err := db.GetActiveCACertificate()
	if err != nil {
		t.Fatalf("GetActiveCACertificate failed: %v", err)
	}
	if activeCA.SerialNumber != "1001" {
		t.Errorf("CA SerialNumber mismatch: %s", activeCA.SerialNumber)
	}

	if err := db.RevokeCertificate("1001"); err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}

	_, err = db.GetActiveCACertificate()
	if err != ErrCertNotFound {
		t.Errorf("Expected revoked CA not to be returned as active CA, got %v", err)
	}

	// Test client cert with optional P12Password
	clientCertWithPass := &models.Certificate{
		SerialNumber:   "2001",
		CommonName:     "client.with.pass",
		CertType:       "client",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nCLIENT1...\n-----END CERTIFICATE-----",
		PrivateKeyPEM:  "-----BEGIN RSA PRIVATE KEY-----\nKEY1...\n-----END RSA PRIVATE KEY-----",
		P12Password:    "MySecret123",
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().AddDate(1, 0, 0),
	}
	if err := db.SaveCertificate(clientCertWithPass); err != nil {
		t.Fatalf("SaveCertificate client with pass failed: %v", err)
	}
	loaded1, err := db.GetCertificateBySerial("2001")
	if err != nil {
		t.Fatalf("GetCertificateBySerial 2001 failed: %v", err)
	}
	if loaded1.P12Password != "MySecret123" {
		t.Errorf("Expected P12Password 'MySecret123', got %q", loaded1.P12Password)
	}

	// Test client cert without P12Password (empty/optional)
	clientCertNoPass := &models.Certificate{
		SerialNumber:   "2002",
		CommonName:     "client.no.pass",
		CertType:       "client",
		CertificatePEM: "-----BEGIN CERTIFICATE-----\nCLIENT2...\n-----END CERTIFICATE-----",
		PrivateKeyPEM:  "-----BEGIN RSA PRIVATE KEY-----\nKEY2...\n-----END RSA PRIVATE KEY-----",
		P12Password:    "",
		IssuedAt:       time.Now().UTC(),
		ExpiresAt:      time.Now().UTC().AddDate(1, 0, 0),
	}
	if err := db.SaveCertificate(clientCertNoPass); err != nil {
		t.Fatalf("SaveCertificate client no pass failed: %v", err)
	}
	loaded2, err := db.GetCertificateBySerial("2002")
	if err != nil {
		t.Fatalf("GetCertificateBySerial 2002 failed: %v", err)
	}
	if loaded2.P12Password != "" {
		t.Errorf("Expected empty P12Password, got %q", loaded2.P12Password)
	}
}

func TestAuthLogsMultiFieldSearchAndRaw(t *testing.T) {
	db := setupTestDB(t)

	vlan10 := 10
	logEntry := &models.AuthLog{
		Timestamp:      time.Now().UTC(),
		ClientMAC:      "AA:BB:CC:DD:EE:FF",
		Username:       "user-device-1",
		AuthType:       models.AuthTypeMAB,
		Status:         "ACCEPT",
		VLANID:         &vlan10,
		Reason:         "MAB Dynamic VLAN assigned",
		NASIP:          "192.168.1.50",
		NASPort:        "1/0/5",
		LatencyMS:      2.4,
		EnrichedName:   "Office Printer Pro",
		EnrichedVendor: "Canon Inc.",
		RawRequest:     "RAW-REQUEST-PACKET-DATA",
		RawResponse:    "RAW-RESPONSE-PACKET-DATA",
	}

	if err := db.InsertAuthLog(logEntry); err != nil {
		t.Fatalf("InsertAuthLog failed: %v", err)
	}

	// 1. Search by unformatted MAC (lowercase hex without colons)
	logs, total, err := db.ListAuthLogs(10, 0, "", "aabbccddeeff")
	if err != nil || total != 1 || len(logs) != 1 {
		t.Fatalf("ListAuthLogs by unformatted MAC failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	// 2. Search by partial colon MAC
	logs, total, err = db.ListAuthLogs(10, 0, "", "cc:dd")
	if err != nil || total != 1 || len(logs) != 1 {
		t.Fatalf("ListAuthLogs by partial MAC failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	// 3. Search by EnrichedName
	logs, total, err = db.ListAuthLogs(10, 0, "", "Printer")
	if err != nil || total != 1 || len(logs) != 1 {
		t.Fatalf("ListAuthLogs by EnrichedName failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	// 4. Search by Vendor
	logs, total, err = db.ListAuthLogs(10, 0, "", "Canon")
	if err != nil || total != 1 || len(logs) != 1 {
		t.Fatalf("ListAuthLogs by Vendor failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	// 5. Search by NAS IP
	logs, total, err = db.ListAuthLogs(10, 0, "", "192.168.1.50")
	if err != nil || total != 1 || len(logs) != 1 {
		t.Fatalf("ListAuthLogs by NAS IP failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	// 6. Search by Reason
	logs, total, err = db.ListAuthLogs(10, 0, "", "Dynamic VLAN")
	if err != nil || total != 1 || len(logs) != 1 {
		t.Fatalf("ListAuthLogs by Reason failed: total=%d, len=%d, err=%v", total, len(logs), err)
	}

	// 7. Get by ID and verify RAW data persistence
	id := logs[0].ID
	fetched, err := db.GetAuthLogByID(id)
	if err != nil {
		t.Fatalf("GetAuthLogByID failed: %v", err)
	}
	if fetched.RawRequest != "RAW-REQUEST-PACKET-DATA" {
		t.Errorf("RawRequest mismatch: got %q", fetched.RawRequest)
	}
	if fetched.RawResponse != "RAW-RESPONSE-PACKET-DATA" {
		t.Errorf("RawResponse mismatch: got %q", fetched.RawResponse)
	}
}

func TestRadiusDebugModeSettings(t *testing.T) {
	db := setupTestDB(t)

	s, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}
	if s.RadiusDebugMode {
		t.Errorf("Expected RadiusDebugMode default false, got true")
	}

	if err := db.SetRadiusDebugMode(true); err != nil {
		t.Fatalf("SetRadiusDebugMode failed: %v", err)
	}

	s, err = db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings failed: %v", err)
	}
	if !s.RadiusDebugMode {
		t.Errorf("Expected RadiusDebugMode true after update, got false")
	}
}

func TestWebSessionsPersistence(t *testing.T) {
	db := setupTestDB(t)

	tokenActive := "session-token-active-123"
	tokenExpired := "session-token-expired-456"

	now := time.Now().UTC()
	expActive := now.Add(30 * 24 * time.Hour)
	expExpired := now.Add(-1 * time.Hour)

	// 1. Save sessions
	if err := db.SaveSession(tokenActive, expActive); err != nil {
		t.Fatalf("SaveSession active failed: %v", err)
	}
	if err := db.SaveSession(tokenExpired, expExpired); err != nil {
		t.Fatalf("SaveSession expired failed: %v", err)
	}

	// 2. Load active sessions - should only contain active
	loaded, err := db.LoadActiveSessions()
	if err != nil {
		t.Fatalf("LoadActiveSessions failed: %v", err)
	}
	if _, ok := loaded[tokenActive]; !ok {
		t.Errorf("Expected tokenActive to be loaded")
	}
	if _, ok := loaded[tokenExpired]; ok {
		t.Errorf("Expected tokenExpired to be pruned/omitted")
	}

	// 3. Update active session expiration
	expExtended := now.Add(60 * 24 * time.Hour)
	if err := db.SaveSession(tokenActive, expExtended); err != nil {
		t.Fatalf("SaveSession update failed: %v", err)
	}
	gotExp, found, err := db.GetSessionExpiry(tokenActive)
	if err != nil || !found {
		t.Fatalf("GetSessionExpiry failed: found=%v, err=%v", found, err)
	}
	if gotExp.Sub(expExtended).Abs() > time.Second {
		t.Errorf("Expected expiration ~%v, got %v", expExtended, gotExp)
	}

	// 4. Delete session
	if err := db.DeleteSession(tokenActive); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}
	_, foundAfterDelete, _ := db.GetSessionExpiry(tokenActive)
	if foundAfterDelete {
		t.Errorf("Expected session to be deleted")
	}
}


