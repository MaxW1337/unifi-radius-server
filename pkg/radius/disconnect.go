package radius

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

// DisconnectOptions specifies parameters for an RFC 5176 Disconnect-Request.
type DisconnectOptions struct {
	NASAddr   string // IP or host, with optional port (default 3799)
	Secret    string
	ClientMAC string
	Timeout   time.Duration
}

// DisconnectClient sends an RFC 5176 Disconnect-Request (Code 40) via UDP 3799.
func DisconnectClient(opts DisconnectOptions) error {
	cleanMAC, err := utils.NormalizeMAC(opts.ClientMAC)
	if err != nil {
		return fmt.Errorf("invalid client MAC: %w", err)
	}

	nasHost := strings.TrimSpace(opts.NASAddr)
	if nasHost == "" {
		return errors.New("NAS address is required")
	}
	if !strings.Contains(nasHost, ":") {
		nasHost = net.JoinHostPort(nasHost, "3799")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// Generate random identifier
	var idByte [1]byte
	_, _ = rand.Read(idByte[:])

	packet := &Packet{
		Code:       CodeDisconnectRequest,
		Identifier: idByte[0],
	}

	// RFC 5176 requires identification of the session. Calling-Station-Id is the client's MAC.
	packet.AddString(AttrCallingStationID, cleanMAC)

	encoded, err := packet.Encode([]byte(opts.Secret))
	if err != nil {
		return fmt.Errorf("failed to encode disconnect request: %w", err)
	}

	rAddr, err := net.ResolveUDPAddr("udp", nasHost)
	if err != nil {
		return fmt.Errorf("resolve NAS address failed: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return fmt.Errorf("dial UDP to NAS failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(encoded); err != nil {
		return fmt.Errorf("send disconnect request failed: %w", err)
	}

	respBuf := make([]byte, 4096)
	n, err := conn.Read(respBuf)
	if err != nil {
		return fmt.Errorf("read disconnect response timeout/failed: %w", err)
	}

	respPacket, err := ParsePacket(respBuf[:n])
	if err != nil {
		return fmt.Errorf("malformed disconnect response from NAS: %w", err)
	}

	switch respPacket.Code {
	case CodeDisconnectACK:
		return nil
	case CodeDisconnectNAK:
		replyMsg := respPacket.GetString(AttrReplyMessage)
		if replyMsg != "" {
			return fmt.Errorf("NAS returned Disconnect-NAK: %s", replyMsg)
		}
		return errors.New("NAS returned Disconnect-NAK (session not found or unsupported)")
	default:
		return fmt.Errorf("unexpected RADIUS code %d in response", respPacket.Code)
	}
}
