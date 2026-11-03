package ca

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

var (
	ErrInvalidPEM     = errors.New("failed to parse PEM block")
	ErrUnsupportedKey = errors.New("unsupported private key type")
)

// CA represents a loaded Certificate Authority capable of issuing server and client certificates.
type CA struct {
	RootCert    *x509.Certificate
	RootKey     *rsa.PrivateKey
	RootCertPEM string
	RootKeyPEM  string
}

// GenerateCA creates a new self-signed Root CA certificate with RSA 4096-bit key.
func GenerateCA(commonName string, validityYears int) (*CA, error) {
	if commonName == "" {
		commonName = "UniFi RADIUS Root CA"
	}
	if validityYears <= 0 {
		validityYears = 10
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().UTC().Add(-1 * time.Hour)
	notAfter := notBefore.AddDate(validityYears, 0, 0)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"UniFi RADIUS"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	rootCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA cert: %w", err)
	}

	return &CA{
		RootCert:    rootCert,
		RootKey:     privKey,
		RootCertPEM: string(certPEM),
		RootKeyPEM:  string(keyPEM),
	}, nil
}

// LoadCA loads an existing Root CA from PEM certificate and private key strings.
func LoadCA(certPEM, keyPEM string) (*CA, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, fmt.Errorf("%w: root certificate", ErrInvalidPEM)
	}
	rootCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root cert: %w", err)
	}

	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, fmt.Errorf("%w: root private key", ErrInvalidPEM)
	}

	privKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8
		pk8Key, errPK8 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if errPK8 != nil {
			return nil, fmt.Errorf("failed to parse root private key: %w (pkcs8: %v)", err, errPK8)
		}
		var ok bool
		privKey, ok = pk8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
	}

	return &CA{
		RootCert:    rootCert,
		RootKey:     privKey,
		RootCertPEM: certPEM,
		RootKeyPEM:  keyPEM,
	}, nil
}

// IssueServerCert generates a server certificate signed by the Root CA for RADIUS EAP-TLS.
func (ca *CA) IssueServerCert(commonName string, sanIPs []net.IP, sanDNS []string, validityDays int) (string, string, error) {
	if validityDays <= 0 {
		validityDays = 730 // 2 years default
	}

	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate server key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().UTC().Add(-1 * time.Hour)
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"UniFi RADIUS"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: sanIPs,
		DNSNames:    sanDNS,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.RootCert, &serverKey.PublicKey, ca.RootKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	return string(certPEM), string(keyPEM), nil
}

// IssueClientCert generates a client certificate signed by the Root CA for 802.1X EAP-TLS authentication.
func (ca *CA) IssueClientCert(commonName string, validityDays int) (certPEM, keyPEM, serialNumberHex string, err error) {
	if validityDays <= 0 {
		validityDays = 365 // 1 year default
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate client key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().UTC().Add(-1 * time.Hour)
	notAfter := notBefore.AddDate(0, 0, validityDays)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"UniFi RADIUS Clients"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.RootCert, &clientKey.PublicKey, ca.RootKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign client cert: %w", err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)})

	return string(certPEMBytes), string(keyPEMBytes), fmt.Sprintf("%X", serialNumber), nil
}

// CombineBundle creates a single combined PEM with client cert, private key, and root CA.
func CombineBundle(clientCertPEM, clientKeyPEM, caCertPEM string) string {
	var buf bytes.Buffer
	buf.WriteString(clientCertPEM)
	if !bytes.HasSuffix([]byte(clientCertPEM), []byte("\n")) {
		buf.WriteString("\n")
	}
	buf.WriteString(clientKeyPEM)
	if !bytes.HasSuffix([]byte(clientKeyPEM), []byte("\n")) {
		buf.WriteString("\n")
	}
	buf.WriteString(caCertPEM)
	return buf.String()
}

