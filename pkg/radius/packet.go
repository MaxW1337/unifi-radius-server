package radius

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// RADIUS Packet Codes
const (
	CodeAccessRequest   = 1
	CodeAccessAccept    = 2
	CodeAccessReject    = 3
	CodeAccountingReq   = 4
	CodeAccountingResp  = 5
	CodeAccessChallenge = 11

	// RFC 5176 Dynamic Authorization Codes
	CodeDisconnectRequest = 40
	CodeDisconnectACK     = 41
	CodeDisconnectNAK     = 42
	CodeCoARequest        = 43
	CodeCoAACK            = 44
	CodeCoANAK            = 45
)

// Standard RADIUS Attribute Types
const (
	AttrUserName             = 1
	AttrUserPassword         = 2
	AttrNASIPAddress         = 4
	AttrNASPort              = 5
	AttrServiceType          = 6
	AttrFramedIPAddress      = 8
	AttrReplyMessage         = 18
	AttrCalledStationID      = 30
	AttrCallingStationID     = 31
	AttrNASIdentifier        = 32
	AttrTunnelType           = 64
	AttrTunnelMediumType     = 65
	AttrTunnelPreference     = 66
	AttrTunnelPrivateGroupID = 81
	AttrEAPMessage           = 79
	AttrMessageAuthenticator = 80
)

var (
	ErrPacketTooShort     = errors.New("radius packet too short")
	ErrInvalidPacketLen   = errors.New("radius packet length mismatch")
	ErrInvalidSecret      = errors.New("invalid shared secret / signature mismatch")
	ErrAttributeMalformed = errors.New("attribute malformed")
)

// Attribute represents a single TLV attribute.
type Attribute struct {
	Type  byte
	Value []byte
}

// Packet represents a parsed RADIUS message.
type Packet struct {
	Code          byte
	Identifier    byte
	Authenticator [16]byte
	Attributes    []Attribute
	Raw           []byte
}

// ParsePacket decodes a raw UDP payload into a Packet struct.
func ParsePacket(b []byte) (*Packet, error) {
	if len(b) < 20 {
		return nil, ErrPacketTooShort
	}

	length := binary.BigEndian.Uint16(b[2:4])
	if int(length) > len(b) || length < 20 {
		return nil, ErrInvalidPacketLen
	}

	p := &Packet{
		Code:       b[0],
		Identifier: b[1],
		Raw:        b[:length],
	}
	copy(p.Authenticator[:], b[4:20])

	// Parse attributes
	offset := 20
	for offset < int(length) {
		if offset+2 > int(length) {
			break
		}
		aType := b[offset]
		aLen := int(b[offset+1])
		if aLen < 2 || offset+aLen > int(length) {
			return nil, ErrAttributeMalformed
		}
		val := make([]byte, aLen-2)
		copy(val, b[offset+2:offset+aLen])
		p.Attributes = append(p.Attributes, Attribute{Type: aType, Value: val})
		offset += aLen
	}

	return p, nil
}

// GetAttribute returns the first attribute matching the given type, or nil.
func (p *Packet) GetAttribute(attrType byte) []byte {
	for _, attr := range p.Attributes {
		if attr.Type == attrType {
			return attr.Value
		}
	}
	return nil
}

// GetString returns the string value of an attribute.
func (p *Packet) GetString(attrType byte) string {
	val := p.GetAttribute(attrType)
	if val == nil {
		return ""
	}
	return string(val)
}

// AddAttribute appends a new attribute to the packet.
func (p *Packet) AddAttribute(attrType byte, val []byte) {
	p.Attributes = append(p.Attributes, Attribute{Type: attrType, Value: val})
}

// AddString appends a string attribute.
func (p *Packet) AddString(attrType byte, s string) {
	p.AddAttribute(attrType, []byte(s))
}

// AddDynamicVLAN adds RFC 2868 and RFC 3580 Dynamic VLAN tunnel attributes to the response.
func (p *Packet) AddDynamicVLAN(vlanID int) {
	if vlanID <= 0 {
		return
	}

	// Tunnel-Type: Tag 0, Value 13 (VLAN) -> 4 bytes: [Tag(1), Val1(1), Val2(1), Val3(1)] or 0x00 0x00 0x00 0x0D
	tunnelTypeVal := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelTypeVal, 13)
	p.AddAttribute(AttrTunnelType, tunnelTypeVal)

	// Tunnel-Medium-Type: Tag 0, Value 6 (802) -> 4 bytes: [0x00, 0x00, 0x00, 0x06]
	tunnelMediumVal := make([]byte, 4)
	binary.BigEndian.PutUint32(tunnelMediumVal, 6)
	p.AddAttribute(AttrTunnelMediumType, tunnelMediumVal)

	// Tunnel-Private-Group-ID: String of VLAN ID (RFC 3580)
	p.AddString(AttrTunnelPrivateGroupID, strconv.Itoa(vlanID))
}

// CreateResponse creates a reply packet matching code, identifier, and request authenticator.
func (p *Packet) CreateResponse(code byte) *Packet {
	resp := &Packet{
		Code:          code,
		Identifier:    p.Identifier,
		Authenticator: p.Authenticator,
	}
	return resp
}

// Encode builds the binary RADIUS wire-format packet and computes the response authenticator.
func (p *Packet) Encode(secret []byte) ([]byte, error) {
	// First calculate total length
	totalLen := 20
	for _, attr := range p.Attributes {
		totalLen += 2 + len(attr.Value)
	}

	if totalLen > 4096 {
		return nil, errors.New("packet exceeds maximum RADIUS size 4096")
	}

	buf := make([]byte, totalLen)
	buf[0] = p.Code
	buf[1] = p.Identifier
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	copy(buf[4:20], p.Authenticator[:])

	offset := 20
	for _, attr := range p.Attributes {
		buf[offset] = attr.Type
		buf[offset+1] = byte(2 + len(attr.Value))
		copy(buf[offset+2:], attr.Value)
		offset += 2 + len(attr.Value)
	}

	// Calculate Response / Request Authenticator:
	// For RFC 5176 Disconnect-Request / CoA-Request: MD5(Code + ID + Length + 16 zeroes + Attributes + Secret)
	// For Standard Responses: MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
	h := md5.New()
	h.Write(buf[0:4])
	if p.Code == CodeDisconnectRequest || p.Code == CodeCoARequest {
		var zeroes [16]byte
		h.Write(zeroes[:])
	} else {
		h.Write(p.Authenticator[:])
	}
	h.Write(buf[20:totalLen])
	h.Write(secret)
	respAuth := h.Sum(nil)
	copy(buf[4:20], respAuth)

	return buf, nil
}

// DecryptUserPassword decrypts an obfuscated PAP User-Password attribute using the shared secret.
func DecryptUserPassword(encPass []byte, reqAuth [16]byte, secret []byte) (string, error) {
	if len(encPass) == 0 || len(encPass)%16 != 0 {
		return "", errors.New("invalid encrypted password length")
	}

	var decrypted []byte
	lastCipher := reqAuth[:]

	for i := 0; i < len(encPass); i += 16 {
		h := md5.New()
		h.Write(secret)
		h.Write(lastCipher)
		mask := h.Sum(nil)

		chunk := make([]byte, 16)
		for j := 0; j < 16; j++ {
			chunk[j] = encPass[i+j] ^ mask[j]
		}
		decrypted = append(decrypted, chunk...)
		lastCipher = encPass[i : i+16]
	}

	// Remove trailing null bytes
	decrypted = bytes.TrimRight(decrypted, "\x00")
	return string(decrypted), nil
}

// ValidateMessageAuthenticator validates HMAC-MD5 attribute 80 if present.
func ValidateMessageAuthenticator(raw []byte, secret []byte) bool {
	if len(raw) < 20 {
		return false
	}

	// Find AttrMessageAuthenticator
	var authOffset int
	offset := 20
	packetLen := int(binary.BigEndian.Uint16(raw[2:4]))
	if packetLen > len(raw) {
		return false
	}

	for offset < packetLen {
		if offset+2 > packetLen {
			break
		}
		aType := raw[offset]
		aLen := int(raw[offset+1])
		if aLen < 2 || offset+aLen > packetLen {
			return false
		}
		if aType == AttrMessageAuthenticator && aLen == 18 {
			authOffset = offset + 2
			break
		}
		offset += aLen
	}

	if authOffset == 0 {
		return true // Not present, no HMAC validation required
	}

	originalAuth := make([]byte, 16)
	copy(originalAuth, raw[authOffset:authOffset+16])

	// Zero out authenticator field for calculation
	copyPacket := make([]byte, packetLen)
	copy(copyPacket, raw[:packetLen])
	for i := 0; i < 16; i++ {
		copyPacket[authOffset+i] = 0
	}

	mac := hmac.New(md5.New, secret)
	mac.Write(copyPacket)
	expected := mac.Sum(nil)

	return hmac.Equal(originalAuth, expected)
}

// CodeName returns the human-readable standard name for a RADIUS packet code.
func (p *Packet) CodeName() string {
	switch p.Code {
	case CodeAccessRequest:
		return "Access-Request (1)"
	case CodeAccessAccept:
		return "Access-Accept (2)"
	case CodeAccessReject:
		return "Access-Reject (3)"
	case CodeAccountingReq:
		return "Accounting-Request (4)"
	case CodeAccountingResp:
		return "Accounting-Response (5)"
	case CodeAccessChallenge:
		return "Access-Challenge (11)"
	default:
		return fmt.Sprintf("Code-%d", p.Code)
	}
}

// AttributeName returns the human-readable name of standard RADIUS attribute types.
func AttributeName(attrType byte) string {
	switch attrType {
	case AttrUserName:
		return "User-Name"
	case AttrUserPassword:
		return "User-Password"
	case AttrNASIPAddress:
		return "NAS-IP-Address"
	case AttrNASPort:
		return "NAS-Port"
	case AttrServiceType:
		return "Service-Type"
	case AttrFramedIPAddress:
		return "Framed-IP-Address"
	case AttrReplyMessage:
		return "Reply-Message"
	case AttrCalledStationID:
		return "Called-Station-Id"
	case AttrCallingStationID:
		return "Calling-Station-Id"
	case AttrNASIdentifier:
		return "NAS-Identifier"
	case 61: // AttrNASPortType
		return "NAS-Port-Type"
	case AttrTunnelType:
		return "Tunnel-Type"
	case AttrTunnelMediumType:
		return "Tunnel-Medium-Type"
	case AttrTunnelPreference:
		return "Tunnel-Preference"
	case AttrTunnelPrivateGroupID:
		return "Tunnel-Private-Group-Id"
	case AttrEAPMessage:
		return "EAP-Message"
	case AttrMessageAuthenticator:
		return "Message-Authenticator"
	case 87:
		return "NAS-Port-Id"
	default:
		return fmt.Sprintf("Attr-%d", attrType)
	}
}

// FormatValue returns a human-friendly representation of an attribute value.
func FormatValue(attrType byte, val []byte) string {
	switch attrType {
	case AttrUserName, AttrCallingStationID, AttrCalledStationID, AttrNASIdentifier, AttrTunnelPrivateGroupID, AttrReplyMessage, 87:
		return string(val)
	case AttrNASIPAddress, AttrFramedIPAddress:
		if len(val) == 4 {
			return net.IP(val).String()
		}
	case AttrNASPort, AttrServiceType, 61: // 32-bit uints
		if len(val) == 4 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint32(val))
		}
	case AttrTunnelType, AttrTunnelMediumType:
		if len(val) == 4 {
			return fmt.Sprintf("%d (Tag:%d)", binary.BigEndian.Uint32(val)&0x00FFFFFF, val[0])
		}
	case AttrUserPassword:
		return "[Obfuscated/Encrypted]"
	case AttrMessageAuthenticator:
		return fmt.Sprintf("0x%x (16 bytes)", val)
	}
	// Fallback: check printable ASCII
	isPrintable := true
	for _, b := range val {
		if b < 32 || b > 126 {
			isPrintable = false
			break
		}
	}
	if isPrintable && len(val) > 0 {
		return string(val)
	}
	return fmt.Sprintf("0x%x (%d bytes)", val, len(val))
}

// FormatDebug returns a structured breakdown of the packet including decoded attributes and hex dump.
func (p *Packet) FormatDebug(rawBytes []byte) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s | ID: %d | Attrs: %d | Len: %d bytes\n", p.CodeName(), p.Identifier, len(p.Attributes), len(rawBytes)))
	sb.WriteString(fmt.Sprintf("Authenticator: %x\n", p.Authenticator))
	sb.WriteString("Attributes:\n")
	for i, a := range p.Attributes {
		name := AttributeName(a.Type)
		val := FormatValue(a.Type, a.Value)
		sb.WriteString(fmt.Sprintf("  [%02d] %-24s (Type %2d, Len %2d): %s\n", i+1, name, a.Type, len(a.Value)+2, val))
	}
	if len(rawBytes) > 0 {
		sb.WriteString("Hex Dump:\n")
		sb.WriteString(hex.Dump(rawBytes))
	}
	return sb.String()
}
