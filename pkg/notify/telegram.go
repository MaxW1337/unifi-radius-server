package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/unifi"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

// InlineKeyboardButton represents a clickable button in Telegram.
type InlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

// TelegramClient implements a 2-way interactive Telegram Bot with long-polling and inline buttons.
type TelegramClient struct {
	token          string
	allowedChatIDs map[int64]bool
	db             *database.DB
	syncSvc        *unifi.SyncService
	httpClient     *http.Client
}

// NewTelegramClient creates a new interactive Telegram bot client.
func NewTelegramClient(token string, allowedIDsStr string, db *database.DB, syncSvc *unifi.SyncService) (*TelegramClient, error) {
	tok := strings.TrimSpace(token)
	if tok == "" {
		return nil, errors.New("telegram bot token is required")
	}

	allowedMap := make(map[int64]bool)
	for _, part := range strings.Split(allowedIDsStr, ",") {
		clean := strings.TrimSpace(part)
		if clean != "" {
			if id, err := strconv.ParseInt(clean, 10, 64); err == nil {
				allowedMap[id] = true
			}
		}
	}

	return &TelegramClient{
		token:          tok,
		allowedChatIDs: allowedMap,
		db:             db,
		syncSvc:        syncSvc,
		httpClient: &http.Client{
			Timeout: 45 * time.Second, // Long polling requires > 30s timeout
		},
	}, nil
}

// IsAuthorized checks whether a given chat or user ID is permitted to execute commands.
func (tg *TelegramClient) IsAuthorized(id int64) bool {
	if len(tg.allowedChatIDs) == 0 {
		return false // Secure default: require explicit whitelist
	}
	return tg.allowedChatIDs[id]
}

// SendMessage sends an HTML formatted message with optional inline keyboard buttons.
func (tg *TelegramClient) SendMessage(ctx context.Context, chatID int64, textHTML string, buttons [][]InlineKeyboardButton) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tg.token)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       textHTML,
		"parse_mode": "HTML",
	}

	if len(buttons) > 0 {
		payload["reply_markup"] = map[string]interface{}{
			"inline_keyboard": buttons,
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tg.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16384))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram returned status: %d", resp.StatusCode)
	}
	return nil
}

// EditMessageText updates an existing message with new text and optional buttons.
func (tg *TelegramClient) EditMessageText(ctx context.Context, chatID int64, messageID int64, textHTML string, buttons [][]InlineKeyboardButton) error {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", tg.token)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"message_id": messageID,
		"text":       textHTML,
		"parse_mode": "HTML",
	}

	if len(buttons) > 0 {
		payload["reply_markup"] = map[string]interface{}{
			"inline_keyboard": buttons,
		}
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := tg.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16384))
	return nil
}

// AnswerCallbackQuery acknowledges a button click in Telegram.
func (tg *TelegramClient) AnswerCallbackQuery(ctx context.Context, callbackID, text string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery", tg.token)
	payload := map[string]interface{}{
		"callback_query_id": callbackID,
		"text":              text,
	}
	bodyBytes, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if req != nil {
		req.Header.Set("Content-Type", "application/json")
		if resp, err := tg.httpClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}
}

// Broadcast sends an alert to all configured authorized chat IDs.
func (tg *TelegramClient) Broadcast(ctx context.Context, ev NotificationEvent) error {
	text := formatTelegramEventHTML(ev)
	buttons := buildTelegramButtons(ev)

	for chatID := range tg.allowedChatIDs {
		_ = tg.SendMessage(ctx, chatID, text, buttons)
	}
	return nil
}

func formatTelegramEventHTML(ev NotificationEvent) string {
	icon := "ℹ️"
	switch ev.Type {
	case EventPendingDevice:
		icon = "⚠️"
	case EventAuthReject:
		icon = "🚫"
	case EventReconnect:
		icon = "🔄"
	case EventCAExpiry:
		icon = "📜"
	case EventDailySummary:
		icon = "📊"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("<b>%s %s</b>\n\n", icon, html.EscapeString(ev.Title)))
	if ev.Message != "" {
		sb.WriteString(fmt.Sprintf("%s\n\n", html.EscapeString(ev.Message)))
	}

	if ev.ClientMAC != "" {
		sb.WriteString(fmt.Sprintf("• <b>MAC:</b> <code>%s</code>\n", html.EscapeString(ev.ClientMAC)))
	}
	if ev.Username != "" {
		sb.WriteString(fmt.Sprintf("• <b>Benutzer:</b> <code>%s</code>\n", html.EscapeString(ev.Username)))
	}
	if ev.EnrichedVendor != "" {
		sb.WriteString(fmt.Sprintf("• <b>Hersteller:</b> %s\n", html.EscapeString(ev.EnrichedVendor)))
	}
	if ev.EnrichedName != "" {
		sb.WriteString(fmt.Sprintf("• <b>Name:</b> %s\n", html.EscapeString(ev.EnrichedName)))
	}
	if ev.SwitchName != "" && ev.SwitchPort != "" {
		sb.WriteString(fmt.Sprintf("• <b>Switch:</b> %s (Port %s)\n", html.EscapeString(ev.SwitchName), html.EscapeString(ev.SwitchPort)))
	}
	if ev.VLANID != nil {
		vlanName := ev.VLANName
		if vlanName == "" {
			vlanName = fmt.Sprintf("VLAN %d", *ev.VLANID)
		}
		sb.WriteString(fmt.Sprintf("• <b>Netzwerk:</b> %s (ID %d)\n", html.EscapeString(vlanName), *ev.VLANID))
	}

	sb.WriteString(fmt.Sprintf("\n<i>%s</i>", ev.Timestamp.Format("02.01.2006 15:04:05 MST")))
	return sb.String()
}

func buildTelegramButtons(ev NotificationEvent) [][]InlineKeyboardButton {
	if ev.Type != EventPendingDevice || ev.ClientMAC == "" {
		return nil
	}

	mac := ev.ClientMAC
	vlanID := 1
	if ev.VLANID != nil {
		vlanID = *ev.VLANID
	}

	return [][]InlineKeyboardButton{
		{
			{Text: fmt.Sprintf("✅ Freigeben (VLAN %d)", vlanID), CallbackData: fmt.Sprintf("app|%s|%d", mac, vlanID)},
			{Text: "🏷️ VLAN wählen", CallbackData: fmt.Sprintf("selvlan|%s", mac)},
		},
		{
			{Text: "🚫 Sperren", CallbackData: fmt.Sprintf("blk|%s", mac)},
			{Text: "⚡ Reconnect (Kick)", CallbackData: fmt.Sprintf("kck|%s", mac)},
		},
	}
}

// StartPolling initiates the background long-polling loop to process user commands and button clicks.
func (tg *TelegramClient) StartPolling(ctx context.Context) {
	log.Println("[Telegram Bot] Starting long-polling worker...")
	offset := int64(0)

	for {
		select {
		case <-ctx.Done():
			log.Println("[Telegram Bot] Polling worker stopped.")
			return
		default:
			updates, nextOffset, err := tg.getUpdates(ctx, offset)
			if err != nil {
				time.Sleep(3 * time.Second)
				continue
			}
			offset = nextOffset

			for _, upd := range updates {
				tg.processUpdate(ctx, upd)
			}
		}
	}
}

type tgUpdate struct {
	UpdateID      int64            `json:"update_id"`
	Message       *tgMessage       `json:"message"`
	CallbackQuery *tgCallbackQuery `json:"callback_query"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      *tgChat `json:"chat"`
	Text      string  `json:"text"`
}

type tgCallbackQuery struct {
	ID      string     `json:"id"`
	From    *tgUser    `json:"from"`
	Message *tgMessage `json:"message"`
	Data    string     `json:"data"`
}

type tgUser struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	Username  string `json:"username"`
}

type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

func (tg *TelegramClient) getUpdates(ctx context.Context, offset int64) ([]tgUpdate, int64, error) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/getUpdates?offset=%d&timeout=25", tg.token, offset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, offset, err
	}

	resp, err := tg.httpClient.Do(req)
	if err != nil {
		return nil, offset, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, offset, fmt.Errorf("status %d", resp.StatusCode)
	}

	var res struct {
		OK     bool       `json:"ok"`
		Result []tgUpdate `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, offset, err
	}

	maxID := offset
	for _, u := range res.Result {
		if u.UpdateID >= maxID {
			maxID = u.UpdateID + 1
		}
	}
	return res.Result, maxID, nil
}

func (tg *TelegramClient) processUpdate(ctx context.Context, upd tgUpdate) {
	// 1. Process Callback Query (Inline Button clicks)
	if cb := upd.CallbackQuery; cb != nil {
		userID := int64(0)
		if cb.From != nil {
			userID = cb.From.ID
		}
		if !tg.IsAuthorized(userID) {
			tg.AnswerCallbackQuery(ctx, cb.ID, "⛔ Keine Berechtigung für diese Aktion.")
			return
		}

		chatID := int64(0)
		msgID := int64(0)
		if cb.Message != nil && cb.Message.Chat != nil {
			chatID = cb.Message.Chat.ID
			msgID = cb.Message.MessageID
		}

		tg.handleCallback(ctx, cb.ID, chatID, msgID, cb.Data)
		return
	}

	// 2. Process Slash Commands
	if msg := upd.Message; msg != nil {
		chatID := msg.Chat.ID
		userID := int64(0)
		if msg.From != nil {
			userID = msg.From.ID
		}

		if !tg.IsAuthorized(chatID) && !tg.IsAuthorized(userID) {
			_ = tg.SendMessage(ctx, chatID, fmt.Sprintf("⛔ <b>Zugriff verweigert</b>\nDeine Chat-ID ist: <code>%d</code>. Bitte trage sie in den UniFi RADIUS Einstellungen unter Whitelist ein.", chatID), nil)
			return
		}

		tg.handleCommand(ctx, chatID, msg.Text)
	}
}

func (tg *TelegramClient) handleCallback(ctx context.Context, cbID string, chatID, msgID int64, data string) {
	parts := strings.Split(data, "|")
	action := parts[0]

	switch action {
	case "app":
		// app|<mac>|<vlan>
		if len(parts) >= 3 && tg.db != nil {
			mac := parts[1]
			vlanID, _ := strconv.Atoi(parts[2])

			normMAC, err := utils.NormalizeMAC(mac)
			if err == nil {
				c, err := tg.db.GetClientByMAC(normMAC)
				if err == nil && c != nil {
					c.Status = models.ClientStatusActive
					c.VLANID = &vlanID
					_ = tg.db.UpdateClient(c)

					tg.AnswerCallbackQuery(ctx, cbID, fmt.Sprintf("Client %s freigegeben (VLAN %d)", normMAC, vlanID))
					if chatID != 0 && msgID != 0 {
						_ = tg.EditMessageText(ctx, chatID, msgID, fmt.Sprintf("✅ <b>Gerät erfolgreich freigegeben!</b>\n• MAC: <code>%s</code>\n• VLAN: <b>%d</b>\n• Status: <b>Aktiv</b>", normMAC, vlanID), nil)
					}
					return
				}
			}
		}
		tg.AnswerCallbackQuery(ctx, cbID, "Fehler beim Freigeben.")

	case "selvlan":
		// selvlan|<mac>
		if len(parts) >= 2 && tg.db != nil {
			mac := parts[1]
			vlans, _ := tg.db.ListVLANs()

			var rows [][]InlineKeyboardButton
			for _, v := range vlans {
				rows = append(rows, []InlineKeyboardButton{
					{
						Text:         fmt.Sprintf("VLAN %d: %s", v.VLANID, v.Name),
						CallbackData: fmt.Sprintf("app|%s|%d", mac, v.VLANID),
					},
				})
			}
			rows = append(rows, []InlineKeyboardButton{
				{Text: "« Zurück", CallbackData: fmt.Sprintf("cancel|%s", mac)},
			})

			tg.AnswerCallbackQuery(ctx, cbID, "Wähle das Ziel-VLAN:")
			if chatID != 0 && msgID != 0 {
				_ = tg.EditMessageText(ctx, chatID, msgID, fmt.Sprintf("🏷️ <b>VLAN auswählen für Client</b> <code>%s</code>:", html.EscapeString(mac)), rows)
			}
			return
		}

	case "blk":
		// blk|<mac>
		if len(parts) >= 2 && tg.db != nil {
			mac := parts[1]
			normMAC, err := utils.NormalizeMAC(mac)
			if err == nil {
				c, err := tg.db.GetClientByMAC(normMAC)
				if err == nil && c != nil {
					c.Status = models.ClientStatusDisabled
					_ = tg.db.UpdateClient(c)
					tg.AnswerCallbackQuery(ctx, cbID, "Gerät gesperrt.")
					if chatID != 0 && msgID != 0 {
						_ = tg.EditMessageText(ctx, chatID, msgID, fmt.Sprintf("🚫 <b>Gerät gesperrt!</b>\n• MAC: <code>%s</code>\n• Status: <b>Deaktiviert</b>", normMAC), nil)
					}
					return
				}
			}
		}
		tg.AnswerCallbackQuery(ctx, cbID, "Fehler beim Sperren.")

	case "kck":
		// kck|<mac>
		if len(parts) >= 2 {
			mac := parts[1]
			tg.AnswerCallbackQuery(ctx, cbID, "Reconnect getriggert...")
			if chatID != 0 && msgID != 0 {
				_ = tg.EditMessageText(ctx, chatID, msgID, fmt.Sprintf("⚡ <b>Reconnect getriggert für</b> <code>%s</code>.", html.EscapeString(mac)), nil)
			}
			return
		}

	case "cancel":
		tg.AnswerCallbackQuery(ctx, cbID, "Abgebrochen.")
	}
}

func (tg *TelegramClient) handleCommand(ctx context.Context, chatID int64, cmdText string) {
	cmdText = strings.TrimSpace(cmdText)
	parts := strings.Fields(cmdText)
	if len(parts) == 0 {
		return
	}

	cmd := strings.ToLower(parts[0])
	// Strip bot mention e.g. /status@MyBot -> /status
	if idx := strings.Index(cmd, "@"); idx != -1 {
		cmd = cmd[:idx]
	}

	switch cmd {
	case "/start", "/help":
		help := `<b>UniFi RADIUS Bot Befehle:</b>
• <code>/status</code> - Serverstatus & Statistiken anzeigen
• <code>/pending</code> - Unbekannte ausstehende Geräte auflisten & freigeben
• <code>/clients</code> - Liste der aktiven Clients anzeigen
• <code>/vlan &lt;MAC&gt; &lt;VLAN_ID&gt;</code> - Gerät in anderes VLAN verschieben
• <code>/block &lt;MAC&gt;</code> - Gerät deaktivieren/sperren
• <code>/kick &lt;MAC&gt;</code> - Reconnect / Port-Power-Cycle ausführen`
		_ = tg.SendMessage(ctx, chatID, help, nil)

	case "/status":
		clients, total, _ := tg.db.ListClients("", "", 1000, 0)
		vlans, _ := tg.db.ListVLANs()
		activeCount := 0
		pendingCount := 0
		for _, c := range clients {
			if c.Status == models.ClientStatusActive {
				activeCount++
			} else if c.Status == models.ClientStatusPending {
				pendingCount++
			}
		}
		statusText := fmt.Sprintf(`<b>📊 UniFi RADIUS Server Status</b>
• Registrierte Clients: <b>%d</b>
• Aktive Geräte: <b>%d</b>
• Ausstehend (Pending): <b>%d</b>
• Synchronisierte VLANs: <b>%d</b>
• Uptime: <b>Online</b>`, total, activeCount, pendingCount, len(vlans))
		_ = tg.SendMessage(ctx, chatID, statusText, nil)

	case "/pending":
		clients, _, _ := tg.db.ListClients("", models.ClientStatusPending, 10, 0)
		if len(clients) == 0 {
			_ = tg.SendMessage(ctx, chatID, "✓ Keine ausstehenden Geräte in der Pending Queue.", nil)
			return
		}

		for _, c := range clients {
			vlan := 1
			if c.VLANID != nil {
				vlan = *c.VLANID
			}
			msg := fmt.Sprintf("⚠️ <b>Ausstehendes Gerät:</b>\n• MAC: <code>%s</code>\n• Name/Hersteller: %s\n• VLAN: %d",
				html.EscapeString(c.MACAddress), html.EscapeString(c.UniFiVendor), vlan)

			buttons := [][]InlineKeyboardButton{
				{
					{Text: fmt.Sprintf("✅ Freigeben (VLAN %d)", vlan), CallbackData: fmt.Sprintf("app:%s:%d", c.MACAddress, vlan)},
					{Text: "🏷️ VLAN wählen", CallbackData: fmt.Sprintf("selvlan:%s", c.MACAddress)},
				},
				{
					{Text: "🚫 Sperren", CallbackData: fmt.Sprintf("blk:%s", c.MACAddress)},
				},
			}
			_ = tg.SendMessage(ctx, chatID, msg, buttons)
		}

	case "/vlan":
		if len(parts) < 3 {
			_ = tg.SendMessage(ctx, chatID, "Syntax: <code>/vlan &lt;MAC&gt; &lt;VLAN_ID&gt;</code>", nil)
			return
		}
		normMAC, err := utils.NormalizeMAC(parts[1])
		if err != nil {
			_ = tg.SendMessage(ctx, chatID, "Ungültige MAC-Adresse.", nil)
			return
		}
		vlanID, err := strconv.Atoi(parts[2])
		if err != nil || vlanID <= 0 {
			_ = tg.SendMessage(ctx, chatID, "Ungültige VLAN-ID.", nil)
			return
		}

		c, err := tg.db.GetClientByMAC(normMAC)
		if err != nil || c == nil {
			_ = tg.SendMessage(ctx, chatID, fmt.Sprintf("Client <code>%s</code> nicht gefunden.", normMAC), nil)
			return
		}

		c.VLANID = &vlanID
		_ = tg.db.UpdateClient(c)
		_ = tg.SendMessage(ctx, chatID, fmt.Sprintf("✓ Client <code>%s</code> erfolgreich zu <b>VLAN %d</b> zugewiesen.", normMAC, vlanID), nil)

	case "/block":
		if len(parts) < 2 {
			_ = tg.SendMessage(ctx, chatID, "Syntax: <code>/block &lt;MAC&gt;</code>", nil)
			return
		}
		normMAC, err := utils.NormalizeMAC(parts[1])
		if err != nil {
			_ = tg.SendMessage(ctx, chatID, "Ungültige MAC-Adresse.", nil)
			return
		}
		c, err := tg.db.GetClientByMAC(normMAC)
		if err != nil || c == nil {
			_ = tg.SendMessage(ctx, chatID, fmt.Sprintf("Client <code>%s</code> nicht gefunden.", normMAC), nil)
			return
		}
		c.Status = models.ClientStatusDisabled
		_ = tg.db.UpdateClient(c)
		_ = tg.SendMessage(ctx, chatID, fmt.Sprintf("🚫 Client <code>%s</code> gesperrt (Status: Disabled).", normMAC), nil)

	default:
		_ = tg.SendMessage(ctx, chatID, "Unbekannter Befehl. Schreibe <code>/help</code> für eine Übersicht.", nil)
	}
}
