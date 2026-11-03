package notify

import (
	"strings"
	"testing"
	"time"
)

func TestSSRFProtectionHomeAssistant(t *testing.T) {
	badURLs := []string{
		"file:///etc/passwd",
		"ftp://malicious.host/upload",
		"gopher://malicious.host",
		"javascript:alert(1)",
		"",
		"http://",
		"https://",
	}

	for _, bad := range badURLs {
		t.Run("Reject_"+bad, func(t *testing.T) {
			_, err := NewHomeAssistantClient(bad)
			if err == nil {
				t.Errorf("Expected SSRF protection error for URL %q, got nil", bad)
			}
		})
	}

	validURLs := []string{
		"http://homeassistant.local:8123/api/webhook/secret_token",
		"https://ha.mydomain.com/api/webhook/abc123xyz",
	}
	for _, good := range validURLs {
		t.Run("Accept_"+good, func(t *testing.T) {
			client, err := NewHomeAssistantClient(good)
			if err != nil || client == nil {
				t.Errorf("Expected valid URL %q to be accepted, got err: %v", good, err)
			}
		})
	}
}

func TestTelegramHTMLEscapingAgainstInjection(t *testing.T) {
	payload := NotificationEvent{
		Type:           EventPendingDevice,
		Title:          "<script>alert('XSS')</script><b>Injected</b>",
		Message:        "<img src=x onerror=alert(1)>",
		ClientMAC:      "<script>evil()</script>",
		Username:       "admin<evil>",
		EnrichedVendor: "<a href=\"evil.com\">Click</a>",
		EnrichedName:   "Office <Printer>",
		SwitchName:     "Switch <1>",
		SwitchPort:     "<Port 5>",
		Timestamp:      time.Now(),
	}

	formatted := formatTelegramEventHTML(payload)

	// Verifies no raw dangerous HTML tags survived escaping
	dangerous := []string{"<script>", "<img", "<a href"}
	for _, d := range dangerous {
		if strings.Contains(formatted, d) {
			t.Errorf("formatTelegramEventHTML contains unescaped tag %q: %s", d, formatted)
		}
	}

	// Verifies proper HTML entities
	if !strings.Contains(formatted, "&lt;script&gt;") {
		t.Error("Expected escaped script tag")
	}
	if !strings.Contains(formatted, "&lt;img") {
		t.Error("Expected escaped img tag")
	}
}

