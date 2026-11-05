package radius

import (
	"net"
	"testing"
	"time"
)

func TestDisconnectClientACK(t *testing.T) {
	secret := "test-secret-123"

	// Start a mock UDP NAS server
	lAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP addr: %v", err)
	}

	pc, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		t.Fatalf("Failed to listen UDP: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 4096)
		n, rAddr, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req, err := ParsePacket(buf[:n])
		if err != nil {
			return
		}

		if req.Code != CodeDisconnectRequest {
			return
		}

		mac := req.GetString(AttrCallingStationID)
		if mac != "AA:BB:CC:DD:EE:FF" {
			return
		}

		resp := req.CreateResponse(CodeDisconnectACK)
		encoded, err := resp.Encode([]byte(secret))
		if err == nil {
			_, _ = pc.WriteToUDP(encoded, rAddr)
		}
	}()

	err = DisconnectClient(DisconnectOptions{
		NASAddr:   pc.LocalAddr().String(),
		Secret:    secret,
		ClientMAC: "aa:bb:cc:dd:ee:ff",
		Timeout:   1 * time.Second,
	})

	if err != nil {
		t.Errorf("Expected disconnect success, got: %v", err)
	}
}

func TestDisconnectClientNAK(t *testing.T) {
	secret := "secret-nak"

	lAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to resolve UDP addr: %v", err)
	}

	pc, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		t.Fatalf("Failed to listen UDP: %v", err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 4096)
		n, rAddr, err := pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req, _ := ParsePacket(buf[:n])
		if req != nil {
			resp := req.CreateResponse(CodeDisconnectNAK)
			resp.AddString(AttrReplyMessage, "Session not found")
			encoded, _ := resp.Encode([]byte(secret))
			_, _ = pc.WriteToUDP(encoded, rAddr)
		}
	}()

	err = DisconnectClient(DisconnectOptions{
		NASAddr:   pc.LocalAddr().String(),
		Secret:    secret,
		ClientMAC: "AA:BB:CC:DD:EE:FF",
		Timeout:   1 * time.Second,
	})

	if err == nil {
		t.Error("Expected error on Disconnect-NAK, got nil")
	}
}

func TestDisconnectClientInvalidMAC(t *testing.T) {
	err := DisconnectClient(DisconnectOptions{
		NASAddr:   "127.0.0.1:3799",
		Secret:    "secret",
		ClientMAC: "invalid-mac",
		Timeout:   500 * time.Millisecond,
	})
	if err == nil {
		t.Error("Expected error for invalid MAC, got nil")
	}
}
