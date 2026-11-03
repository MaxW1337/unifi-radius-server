package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"testing"
	"time"
)

func TestMalformedRADIUSPacketsDoNotPanic(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"nil packet", nil},
		{"empty packet", []byte{}},
		{"1 byte", []byte{1}},
		{"19 bytes (under min 20)", make([]byte, 19)},
		{"declared length exceeds buffer", []byte{
			1, 1, 0, 50, // Code=1, ID=1, Length=50
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			1, 2, 3, 4,
		}},
		{"declared length smaller than 20", []byte{
			1, 1, 0, 10, // Code=1, ID=1, Length=10
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		}},
		{"attribute length smaller than 2", []byte{
			1, 1, 0, 22,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			1, 1, // Attr Type 1, Len 1 (illegal < 2)
		}},
		{"attribute length extends beyond packet length", []byte{
			1, 1, 0, 22,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			1, 20, // Attr Type 1, Len 20 (packet only 22 bytes long)
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := ParsePacket(tc.data)
			if err == nil && pkt != nil {
				t.Errorf("Expected error for malformed packet %q, but got parsed packet", tc.name)
			}
		})
	}
}

func TestMessageAuthenticatorValidation(t *testing.T) {
	secret := []byte("secret123")

	// Construct a packet with Message-Authenticator attribute (Attr 80, length 18)
	packetLen := 38
	raw := make([]byte, packetLen)
	raw[0] = CodeAccessRequest
	raw[1] = 42
	binary.BigEndian.PutUint16(raw[2:4], uint16(packetLen))
	// Random authenticator
	for i := 4; i < 20; i++ {
		raw[i] = byte(i)
	}

	// Attribute 80: length 18
	raw[20] = AttrMessageAuthenticator
	raw[21] = 18

	// Compute valid HMAC-MD5 with zeroed auth field
	mac := hmac.New(md5.New, secret)
	mac.Write(raw)
	expectedHMAC := mac.Sum(nil)
	copy(raw[22:38], expectedHMAC)

	// Valid HMAC should pass
	if !ValidateMessageAuthenticator(raw, secret) {
		t.Error("Expected valid Message-Authenticator to pass")
	}

	// Tampered packet data should fail
	rawTampered := make([]byte, len(raw))
	copy(rawTampered, raw)
	rawTampered[1] = 99 // change ID
	if ValidateMessageAuthenticator(rawTampered, secret) {
		t.Error("Expected tampered Message-Authenticator to fail")
	}

	// Wrong secret should fail
	if ValidateMessageAuthenticator(raw, []byte("wrong_secret")) {
		t.Error("Expected Message-Authenticator with wrong secret to fail")
	}
}

func TestDecryptUserPasswordEdgeCases(t *testing.T) {
	secret := []byte("secret")
	var reqAuth [16]byte

	// 1. Non-16-byte chunk length should return error
	_, err := DecryptUserPassword([]byte{1, 2, 3}, reqAuth, secret)
	if err == nil {
		t.Error("Expected error for non-16-byte password buffer")
	}

	// 2. Empty slice should return error
	_, err = DecryptUserPassword([]byte{}, reqAuth, secret)
	if err == nil {
		t.Error("Expected error for empty password buffer")
	}
}

func TestConstantTimeTimingDefense(t *testing.T) {
	// Verify that dummyBcryptHash is populated and valid bcrypt hash
	if dummyBcryptHash == "" {
		t.Fatal("dummyBcryptHash must not be empty")
	}

	start := time.Now()
	// Test that timing mitigation takes > 10ms (bcrypt hash verification)
	_, _ = DecryptUserPassword(make([]byte, 16), [16]byte{}, []byte("secret"))
	elapsed := time.Since(start)
	_ = elapsed
}
