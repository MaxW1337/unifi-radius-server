package ca

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
)

func TestCAGenerationAndIssuing(t *testing.T) {
	// 1. Generate Root CA
	ca, err := GenerateCA("Test UniFi Root CA", 5)
	if err != nil {
		t.Fatalf("GenerateCA failed: %v", err)
	}

	if ca.RootCert == nil || ca.RootKey == nil {
		t.Fatal("Expected non-nil RootCert and RootKey")
	}

	if !ca.RootCert.IsCA {
		t.Error("Expected RootCert.IsCA to be true")
	}

	// 2. Issue Server Cert
	serverCertPEM, _, err := ca.IssueServerCert("radius.lan", []net.IP{net.ParseIP("192.168.1.1")}, []string{"radius.local"}, 365)
	if err != nil {
		t.Fatalf("IssueServerCert failed: %v", err)
	}

	serverBlock, _ := pem.Decode([]byte(serverCertPEM))
	serverCert, err := x509.ParseCertificate(serverBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse issued server cert: %v", err)
	}

	// Verify server cert signed by CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.RootCert)
	_, err = serverCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("Server cert verification against Root CA failed: %v", err)
	}

	// 3. Issue Client Cert
	clientCertPEM, clientKeyPEM, serial, err := ca.IssueClientCert("john.doe@company.lan", 180)
	if err != nil {
		t.Fatalf("IssueClientCert failed: %v", err)
	}
	if serial == "" {
		t.Error("Expected non-empty serial number")
	}

	clientBlock, _ := pem.Decode([]byte(clientCertPEM))
	clientCert, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse issued client cert: %v", err)
	}

	_, err = clientCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("Client cert verification against Root CA failed: %v", err)
	}

	// 4. Test CombineBundle
	bundle := CombineBundle(clientCertPEM, clientKeyPEM, ca.RootCertPEM)
	if !strings.Contains(bundle, "-----BEGIN CERTIFICATE-----") || !strings.Contains(bundle, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("Bundle missing expected PEM headers")
	}

	// 5. Test MobileConfig Generation
	mockP12 := []byte("dummy-p12-data")
	mobileConfigBytes, err := GenerateAppleMobileConfig("Test Wi-Fi", "Office-Enterprise", mockP12, ca.RootCertPEM, "Secret123")
	if err != nil {
		t.Fatalf("GenerateAppleMobileConfig failed: %v", err)
	}

	content := string(mobileConfigBytes)
	if !strings.Contains(content, "Office-Enterprise") || !strings.Contains(content, "com.apple.wifi.managed") {
		t.Error("Generated mobileconfig missing Wi-Fi payload")
	}

	// 6. Test LoadCA
	reloadedCA, err := LoadCA(ca.RootCertPEM, ca.RootKeyPEM)
	if err != nil {
		t.Fatalf("LoadCA failed: %v", err)
	}
	if reloadedCA.RootCert.SerialNumber.Cmp(ca.RootCert.SerialNumber) != 0 {
		t.Error("Reloaded CA serial number mismatch")
	}

	// 7. Test ExportPKCS12 with and without password (optional password support)
	p12WithPass, err := ExportPKCS12(clientCertPEM, clientKeyPEM, ca.RootCertPEM, "Secret123")
	if err != nil {
		t.Fatalf("ExportPKCS12 with password failed: %v", err)
	}
	if len(p12WithPass) == 0 {
		t.Fatal("Expected non-empty p12 data")
	}

	p12WithoutPass, err := ExportPKCS12(clientCertPEM, clientKeyPEM, ca.RootCertPEM, "")
	if err != nil {
		t.Fatalf("ExportPKCS12 without password failed: %v", err)
	}
	if len(p12WithoutPass) == 0 {
		t.Fatal("Expected non-empty p12 data with empty password")
	}
}
