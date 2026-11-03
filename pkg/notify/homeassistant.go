package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HomeAssistantClient dispatches JSON webhook events to Home Assistant.
type HomeAssistantClient struct {
	webhookURL string
	httpClient *http.Client
}

// NewHomeAssistantClient initializes the Home Assistant webhook client.
func NewHomeAssistantClient(webhookURL string) (*HomeAssistantClient, error) {
	trimmed := strings.TrimSpace(webhookURL)
	if trimmed == "" {
		return nil, errors.New("empty webhook url")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook url: %w", err)
	}

	// SSRF Protection: only allow http and https schemes
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("forbidden url scheme %q: only http and https are allowed", scheme)
	}
	if u.Host == "" {
		return nil, errors.New("webhook url missing host")
	}

	return &HomeAssistantClient{
		webhookURL: trimmed,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

// SendEvent dispatches an event to the configured Home Assistant webhook endpoint.
func (ha *HomeAssistantClient) SendEvent(ctx context.Context, ev NotificationEvent) error {
	payload := map[string]interface{}{
		"event":       "unifi_radius_" + ev.Type,
		"title":       ev.Title,
		"message":     ev.Message,
		"client_mac":  ev.ClientMAC,
		"username":    ev.Username,
		"vlan_id":     ev.VLANID,
		"vlan_name":   ev.VLANName,
		"switch_name": ev.SwitchName,
		"switch_port": ev.SwitchPort,
		"vendor":      ev.EnrichedVendor,
		"timestamp":   ev.Timestamp.Format(time.RFC3339),
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ha.webhookURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "UniFi-RADIUS-Server")

	resp, err := ha.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send event to Home Assistant: %w", err)
	}
	defer resp.Body.Close()

	// Drain response with 16KB limit to prevent resource exhaustion
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16384))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("home assistant returned non-2xx status: %d", resp.StatusCode)
	}

	return nil
}

