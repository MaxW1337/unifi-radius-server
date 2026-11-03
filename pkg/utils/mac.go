package utils

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	ErrInvalidMAC = errors.New("invalid MAC address format")
	hexCleanRegex = regexp.MustCompile(`[^a-fA-F0-9]`)
)

// NormalizeMAC takes any common MAC address string representation and converts it
// to the standardized canonical format: AA:BB:CC:DD:EE:FF.
// Supported formats include:
// - AA:BB:CC:DD:EE:FF / aa:bb:cc:dd:ee:ff
// - AA-BB-CC-DD-EE-FF / aa-bb-cc-dd-ee-ff
// - AABB.CCDD.EEFF / aabb.ccdd.eeff (Cisco style)
// - AABBCCDDEEFF / aabbccddeeff (raw hex)
func NormalizeMAC(input string) (string, error) {
	clean := strings.TrimSpace(input)
	if clean == "" {
		return "", ErrInvalidMAC
	}

	// First try standard net.ParseMAC (handles :, -, and .)
	if hw, err := net.ParseMAC(clean); err == nil && len(hw) == 6 {
		return strings.ToUpper(fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
			hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])), nil
	}

	// Remove any non-hex characters
	rawHex := hexCleanRegex.ReplaceAllString(clean, "")
	if len(rawHex) != 12 {
		return "", fmt.Errorf("%w: %s", ErrInvalidMAC, input)
	}

	// Parse 6 bytes
	formatted := fmt.Sprintf("%s:%s:%s:%s:%s:%s",
		strings.ToUpper(rawHex[0:2]),
		strings.ToUpper(rawHex[2:4]),
		strings.ToUpper(rawHex[4:6]),
		strings.ToUpper(rawHex[6:8]),
		strings.ToUpper(rawHex[8:10]),
		strings.ToUpper(rawHex[10:12]),
	)

	return formatted, nil
}

// IsValidMAC checks whether a string is a valid MAC address in any recognized format.
func IsValidMAC(input string) bool {
	_, err := NormalizeMAC(input)
	return err == nil
}

