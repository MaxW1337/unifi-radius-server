package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/unifi"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

const (
	discordAPIURL = "https://discord.com/api/v10"
	discordGWURL  = "wss://gateway.discord.gg/?v=10&encoding=json"
)

// DiscordClient implements a 2-way Discord Bot with Rich Embeds, Action Buttons, and Gateway interaction handling.
type DiscordClient struct {
	token      string
	channelID  string
	db         *database.DB
	syncSvc    *unifi.SyncService
	httpClient *http.Client
	wsConn     *websocket.Conn
	wsMu       sync.Mutex
	stopChan   chan struct{}
}

// NewDiscordClient initializes the Discord Bot client.
func NewDiscordClient(token, channelID string, db *database.DB, syncSvc *unifi.SyncService) (*DiscordClient, error) {
	tok := strings.TrimSpace(token)
	ch := strings.TrimSpace(channelID)
	if tok == "" || ch == "" {
		return nil, errors.New("discord token and channel id are required")
	}

	return &DiscordClient{
		token:      tok,
		channelID:  ch,
		db:         db,
		syncSvc:    syncSvc,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		stopChan:   make(chan struct{}),
	}, nil
}

// SendEmbedMessage delivers an embed message with interactive buttons to the configured Discord channel.
func (dc *DiscordClient) SendEmbedMessage(ctx context.Context, ev NotificationEvent) error {
	apiURL := fmt.Sprintf("%s/channels/%s/messages", discordAPIURL, dc.channelID)

	color := 0x3b82f6 // Blue default
	switch ev.Type {
	case EventPendingDevice:
		color = 0xf59e0b // Amber/Yellow
	case EventAuthReject:
		color = 0xef4444 // Red
	case EventReconnect:
		color = 0x10b981 // Green
	case EventDailySummary:
		color = 0x8b5cf6 // Purple
	}

	fields := []map[string]interface{}{}
	if ev.ClientMAC != "" {
		fields = append(fields, map[string]interface{}{
			"name":   "MAC-Adresse",
			"value":  fmt.Sprintf("`%s`", ev.ClientMAC),
			"inline": true,
		})
	}
	if ev.Username != "" {
		fields = append(fields, map[string]interface{}{
			"name":   "Benutzer",
			"value":  fmt.Sprintf("`%s`", ev.Username),
			"inline": true,
		})
	}
	if ev.EnrichedVendor != "" {
		fields = append(fields, map[string]interface{}{
			"name":   "Hersteller",
			"value":  ev.EnrichedVendor,
			"inline": true,
		})
	}
	if ev.SwitchName != "" && ev.SwitchPort != "" {
		fields = append(fields, map[string]interface{}{
			"name":   "Switch & Port",
			"value":  fmt.Sprintf("%s (Port %s)", ev.SwitchName, ev.SwitchPort),
			"inline": true,
		})
	}
	if ev.VLANID != nil {
		fields = append(fields, map[string]interface{}{
			"name":   "VLAN",
			"value":  fmt.Sprintf("%d (%s)", *ev.VLANID, ev.VLANName),
			"inline": true,
		})
	}

	embed := map[string]interface{}{
		"title":       ev.Title,
		"description": ev.Message,
		"color":       color,
		"fields":      fields,
		"timestamp":   ev.Timestamp.Format(time.RFC3339),
		"footer": map[string]interface{}{
			"text": "UniFi RADIUS Server",
		},
	}

	payload := map[string]interface{}{
		"embeds": []interface{}{embed},
	}

	// Add interactive buttons if this is an unapproved pending device
	if ev.Type == EventPendingDevice && ev.ClientMAC != "" {
		vlan := 1
		if ev.VLANID != nil {
			vlan = *ev.VLANID
		}
		components := []map[string]interface{}{
			{
				"type": 1, // Action Row
				"components": []map[string]interface{}{
					{
						"type":      2, // Button
						"style":     3, // Success / Green
						"label":     fmt.Sprintf("Freigeben (VLAN %d)", vlan),
						"custom_id": fmt.Sprintf("app|%s|%d", ev.ClientMAC, vlan),
					},
					{
						"type":      2, // Button
						"style":     4, // Danger / Red
						"label":     "Sperren",
						"custom_id": fmt.Sprintf("blk|%s", ev.ClientMAC),
					},
					{
						"type":      2, // Button
						"style":     2, // Secondary / Grey
						"label":     "Reconnect",
						"custom_id": fmt.Sprintf("kck|%s", ev.ClientMAC),
					},
				},
			},
		}
		payload["components"] = components
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bot "+dc.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := dc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord send message failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16384))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord returned status code %d", resp.StatusCode)
	}
	return nil
}

// StartGateway begins the Discord Gateway WebSocket connection to listen for button interaction events.
func (dc *DiscordClient) StartGateway(ctx context.Context) {
	log.Println("[Discord Bot] Connecting to Discord Gateway WebSocket...")

	for {
		select {
		case <-ctx.Done():
			return
		case <-dc.stopChan:
			return
		default:
			conn, _, err := websocket.DefaultDialer.DialContext(ctx, discordGWURL, nil)
			if err != nil {
				time.Sleep(5 * time.Second)
				continue
			}
			dc.wsConn = conn

			dc.runGatewaySession(ctx, conn)
			time.Sleep(3 * time.Second)
		}
	}
}

func (dc *DiscordClient) runGatewaySession(ctx context.Context, conn *websocket.Conn) {
	defer conn.Close()

	heartbeatDone := make(chan struct{})
	defer close(heartbeatDone)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}

			var payload struct {
				Op int             `json:"op"`
				D  json.RawMessage `json:"d"`
				T  string          `json:"t"`
			}
			if err := json.Unmarshal(msg, &payload); err != nil {
				continue
			}

			switch payload.Op {
			case 10: // Hello
				var helloData struct {
					HeartbeatInterval int `json:"heartbeat_interval"`
				}
				_ = json.Unmarshal(payload.D, &helloData)
				go dc.heartbeatWorker(conn, helloData.HeartbeatInterval, heartbeatDone)
				dc.sendIdentify(conn)

			case 0: // Dispatch
				if payload.T == "INTERACTION_CREATE" {
					dc.handleInteraction(payload.D)
				}
			}
		}
	}
}

func (dc *DiscordClient) heartbeatWorker(conn *websocket.Conn, intervalMs int, done chan struct{}) {
	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			dc.wsMu.Lock()
			_ = conn.WriteJSON(map[string]interface{}{"op": 1, "d": nil})
			dc.wsMu.Unlock()
		}
	}
}

func (dc *DiscordClient) sendIdentify(conn *websocket.Conn) {
	identify := map[string]interface{}{
		"op": 2,
		"d": map[string]interface{}{
			"token":   dc.token,
			"intents": 513, // Guilds + GuildMessages
			"properties": map[string]interface{}{
				"os":      "linux",
				"browser": "unifi-radius",
				"device":  "unifi-radius",
			},
		},
	}
	dc.wsMu.Lock()
	_ = conn.WriteJSON(identify)
	dc.wsMu.Unlock()
}

func (dc *DiscordClient) handleInteraction(data json.RawMessage) {
	var interaction struct {
		ID        string `json:"id"`
		Token     string `json:"token"`
		Type      int    `json:"type"` // 3 = Message Component
		ChannelID string `json:"channel_id"`
		Data      struct {
			CustomID string `json:"custom_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &interaction); err != nil {
		return
	}

	// Verify channel matches configured channel
	if dc.channelID != "" && interaction.ChannelID != dc.channelID {
		return
	}

	parts := strings.Split(interaction.Data.CustomID, "|")
	action := parts[0]
	respText := "Aktion ausgeführt."

	switch action {
	case "app":
		// app:<mac>:<vlan>
		if len(parts) >= 3 && dc.db != nil {
			mac := parts[1]
			vlanID, _ := strconv.Atoi(parts[2])
			normMAC, err := utils.NormalizeMAC(mac)
			if err == nil {
				c, err := dc.db.GetClientByMAC(normMAC)
				if err == nil && c != nil {
					c.Status = models.ClientStatusActive
					c.VLANID = &vlanID
					_ = dc.db.UpdateClient(c)
					respText = fmt.Sprintf("✅ Client `%s` erfolgreich freigegeben für VLAN %d!", normMAC, vlanID)
				}
			}
		}

	case "blk":
		// blk:<mac>
		if len(parts) >= 2 && dc.db != nil {
			mac := parts[1]
			normMAC, err := utils.NormalizeMAC(mac)
			if err == nil {
				c, err := dc.db.GetClientByMAC(normMAC)
				if err == nil && c != nil {
					c.Status = models.ClientStatusDisabled
					_ = dc.db.UpdateClient(c)
					respText = fmt.Sprintf("🚫 Client `%s` gesperrt (Disabled).", normMAC)
				}
			}
		}

	case "kck":
		if len(parts) >= 2 {
			respText = fmt.Sprintf("⚡ Reconnect getriggert für `%s`.", parts[1])
		}
	}

	// Acknowledge interaction via Discord REST
	dc.respondInteraction(interaction.ID, interaction.Token, respText)
}

func (dc *DiscordClient) respondInteraction(id, token, content string) {
	url := fmt.Sprintf("%s/interactions/%s/%s/callback", discordAPIURL, id, token)
	payload := map[string]interface{}{
		"type": 4, // ChannelMessageWithSource
		"d": map[string]interface{}{
			"content": content,
		},
	}
	bodyBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
	if req != nil {
		req.Header.Set("Content-Type", "application/json")
		if resp, err := dc.httpClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}
}

// Stop cleanly closes the Gateway connection.
func (dc *DiscordClient) Stop() {
	select {
	case <-dc.stopChan:
		return
	default:
		close(dc.stopChan)
	}
	if dc.wsConn != nil {
		_ = dc.wsConn.Close()
	}
}
