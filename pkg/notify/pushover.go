package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const pushoverAPIURL = "https://api.pushover.net/1/messages.json"

// PushoverClient sends priority push notifications via Pushover.
type PushoverClient struct {
	apiToken   string
	userKey    string
	httpClient *http.Client
}

// NewPushoverClient initializes a new Pushover notification client.
func NewPushoverClient(apiToken, userKey string) (*PushoverClient, error) {
	tok := strings.TrimSpace(apiToken)
	usr := strings.TrimSpace(userKey)
	if tok == "" || usr == "" {
		return nil, errors.New("pushover api token and user key are required")
	}

	return &PushoverClient{
		apiToken: tok,
		userKey:  usr,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

// SendMessage delivers a notification message through Pushover.
func (p *PushoverClient) SendMessage(ctx context.Context, title, message string, priority int, clickURL string) error {
	data := url.Values{}
	data.Set("token", p.apiToken)
	data.Set("user", p.userKey)
	data.Set("title", title)
	data.Set("message", message)
	data.Set("priority", strconv.Itoa(priority))

	if clickURL != "" {
		data.Set("url", clickURL)
		data.Set("url_title", "Im Web-UI anzeigen")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pushoverAPIURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "UniFi-RADIUS-Server")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pushover request failed: %w", err)
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16384))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pushover returned status code %d", resp.StatusCode)
	}

	return nil
}

