package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// ExportPKCS12 creates a password-protected PKCS#12 (.p12/.pfx) bundle containing
// the client certificate, client private key, and the root CA certificate.
func ExportPKCS12(clientCertPEM, clientKeyPEM, caCertPEM, password string) ([]byte, error) {
	// Parse client certificate
	clientCertBlock, _ := pem.Decode([]byte(clientCertPEM))
	if clientCertBlock == nil {
		return nil, fmt.Errorf("%w: client certificate", ErrInvalidPEM)
	}
	clientCert, err := x509.ParseCertificate(clientCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client certificate: %w", err)
	}

	// Parse client private key
	clientKeyBlock, _ := pem.Decode([]byte(clientKeyPEM))
	if clientKeyBlock == nil {
		return nil, fmt.Errorf("%w: client private key", ErrInvalidPEM)
	}
	clientKey, err := x509.ParsePKCS1PrivateKey(clientKeyBlock.Bytes)
	if err != nil {
		pk8Key, errPK8 := x509.ParsePKCS8PrivateKey(clientKeyBlock.Bytes)
		if errPK8 != nil {
			return nil, fmt.Errorf("failed to parse client private key: %w (pkcs8: %v)", err, errPK8)
		}
		var ok bool
		clientKey, ok = pk8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedKey
		}
	}

	// Parse CA certificate
	caCertBlock, _ := pem.Decode([]byte(caCertPEM))
	if caCertBlock == nil {
		return nil, fmt.Errorf("%w: CA certificate", ErrInvalidPEM)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Modern PKCS#12 bundle compatible with modern Windows, Apple, and Linux systems
	p12Data, err := pkcs12.Modern.Encode(clientKey, clientCert, []*x509.Certificate{caCert}, password)
	if err != nil {
		// Fallback to standard encoder if modern fails
		p12Data, err = pkcs12.Encode(rand.Reader, clientKey, clientCert, []*x509.Certificate{caCert}, password)
		if err != nil {
			return nil, fmt.Errorf("failed to encode PKCS#12: %w", err)
		}
	}

	return p12Data, nil
}

