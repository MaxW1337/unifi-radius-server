package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

var (
	ErrUnauthorized = errors.New("unauthorized: check UniFi API key or credentials")
	ErrUnreachable  = errors.New("unreachable: cannot connect to UniFi controller")
)

// Config defines connection details for the UniFi Network controller.
type Config struct {
	BaseURL  string // e.g. "https://127.0.0.1"
	AuthMode string // "apikey" or "credentials"
	APIKey   string
	Username string
	Password string
	Site     string // usually "default"
}

// Client communicates with the UniFi OS Network controller.
type Client struct {
	cfg        Config
	httpClient *http.Client
	mu         sync.Mutex
	csrfToken  string
}

// NewClient initializes a UniFi API client with self-signed TLS support and cookie jar.
func NewClient(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://127.0.0.1"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	if cfg.Site == "" {
		cfg.Site = "default"
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{
		Transport: tr,
		Jar:       jar,
		Timeout:   10 * time.Second,
	}

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
	}, nil
}

// Login performs authentication if using "credentials" mode.
func (c *Client) Login() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cfg.AuthMode != "credentials" {
		return nil // API Key mode requires no login handshake
	}

	loginURL := fmt.Sprintf("%s/api/auth/login", c.cfg.BaseURL)
	payload := map[string]interface{}{
		"username":   c.cfg.Username,
		"password":   c.cfg.Password,
		"rememberMe": true,
	}
	bodyBytes, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	// Capture CSRF token if returned in header
	csrf := resp.Header.Get("X-CSRF-Token")
	if csrf != "" {
		c.csrfToken = csrf
	}

	return nil
}

func (c *Client) doRequest(method, endpoint string, body io.Reader) (*http.Response, error) {
	fullURL := fmt.Sprintf("%s%s", c.cfg.BaseURL, endpoint)
	req, err := http.NewRequest(method, fullURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.cfg.AuthMode == "apikey" {
		req.Header.Set("X-API-KEY", c.cfg.APIKey)
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	} else if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}

	// If unauthorized and using credentials, try re-logging in once
	if resp.StatusCode == http.StatusUnauthorized && c.cfg.AuthMode == "credentials" {
		resp.Body.Close()
		if err := c.Login(); err != nil {
			return nil, err
		}
		// Retry original request
		req2, _ := http.NewRequest(method, fullURL, body)
		req2.Header.Set("Accept", "application/json")
		if c.csrfToken != "" {
			req2.Header.Set("X-CSRF-Token", c.csrfToken)
		}
		return c.httpClient.Do(req2)
	}

	return resp, nil
}

type unifiResponse struct {
	Meta struct {
		Rc  string `json:"rc"`
		Msg string `json:"msg"`
	} `json:"meta"`
	Data []json.RawMessage `json:"data"`
}

func parseVlanID(val interface{}) int {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return 0
}

// FetchNetworks retrieves all configured virtual networks and VLANs from UniFi.
func (c *Client) FetchNetworks() ([]models.VLAN, error) {
	// Try standard UniFi OS proxy endpoint first, fallback to direct controller path
	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/rest/networkconf", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/rest/networkconf", c.cfg.Site),
	}

	var lastErr error
	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodGet, ep, nil)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			continue // try next endpoint
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to fetch networks, status: %d", resp.StatusCode)
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return nil, fmt.Errorf("failed to parse networks json: %w", err)
		}

		var vlans []models.VLAN
		seen := make(map[int]bool)
		for _, raw := range apiResp.Data {
			var netItem struct {
				Name         string      `json:"name"`
				Purpose      string      `json:"purpose"`
				Vlan         interface{} `json:"vlan"`
				VlanID       interface{} `json:"vlan_id"`
				IPSubnet     string      `json:"ip_subnet"`
				IsDefault    bool        `json:"is_default"`
				AttrHiddenID string      `json:"attr_hidden_id"`
				Default      bool        `json:"default"`
				VlanEnabled  bool        `json:"vlan_enabled"`
			}
			if err := json.Unmarshal(raw, &netItem); err != nil {
				continue
			}

			// Filter out non-client networks (WAN, VPN tunnels)
			purpose := strings.ToLower(netItem.Purpose)
			if purpose == "wan" || purpose == "remote-user-vpn" || purpose == "vpn-client" || purpose == "site-vpn" {
				continue
			}

			vlanID := parseVlanID(netItem.VlanID)
			if vlanID == 0 {
				vlanID = parseVlanID(netItem.Vlan)
			}

			// Default untagged LAN (e.g. corporate network without explicit VLAN tag or attr_hidden_id == "LAN")
			if vlanID == 0 && (netItem.AttrHiddenID == "LAN" || netItem.IsDefault || netItem.Default || !netItem.VlanEnabled) {
				vlanID = 1
			}

			if vlanID <= 0 || seen[vlanID] {
				continue
			}
			seen[vlanID] = true

			vlans = append(vlans, models.VLAN{
				VLANID:    vlanID,
				Name:      netItem.Name,
				Subnet:    netItem.IPSubnet,
				Purpose:   netItem.Purpose,
				IsDefault: netItem.IsDefault || netItem.Default || vlanID == 1,
				SyncedAt:  time.Now().UTC(),
			})
		}
		return vlans, nil
	}

	return nil, fmt.Errorf("could not retrieve networks from UniFi: %w", lastErr)
}

// FetchDevices retrieves all adopted switches, APs, and gateways.
func (c *Client) FetchDevices() ([]models.NASClient, error) {
	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/stat/device", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/stat/device", c.cfg.Site),
	}

	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return nil, err
		}

		var nasList []models.NASClient
		for _, raw := range apiResp.Data {
			var dev struct {
				IP    string `json:"ip"`
				Name  string `json:"name"`
				Model string `json:"model"`
				Type  string `json:"type"` // "usw", "uap", "ugw", "udm"
				Mac   string `json:"mac"`
			}
			if err := json.Unmarshal(raw, &dev); err != nil {
				continue
			}

			if dev.IP == "" {
				continue
			}

			displayName := dev.Name
			if displayName == "" {
				displayName = fmt.Sprintf("%s (%s)", strings.ToUpper(dev.Type), dev.Model)
			}

			nasList = append(nasList, models.NASClient{
				IPOrCIDR:      dev.IP,
				Name:          displayName,
				IsUniFiSynced: true,
				SyncedAt:      time.Now().UTC(),
			})
		}
		return nasList, nil
	}

	return nil, fmt.Errorf("failed to fetch devices from UniFi")
}

// UniFiClientInfo holds metadata about a known client on the UniFi network.
type UniFiClientInfo struct {
	MAC        string
	Hostname   string
	Name       string
	Vendor     string
	IP         string
	SwitchName string
	SwitchPort string
	SwitchMAC  string
	IsWired    bool
}

// FetchClients queries both active and historical clients to build an enrichment map by MAC.
func (c *Client) FetchClients() (map[string]UniFiClientInfo, error) {
	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/stat/alluser", c.cfg.Site),
		fmt.Sprintf("/proxy/network/api/s/%s/stat/sta", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/stat/alluser", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/stat/sta", c.cfg.Site),
	}

	clientsMap := make(map[string]UniFiClientInfo)

	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			continue
		}

		for _, raw := range apiResp.Data {
			var item struct {
				Mac           string `json:"mac"`
				Hostname      string `json:"hostname"`
				Name          string `json:"name"`
				Oui           string `json:"oui"`
				IP            string `json:"ip"`
				IsWired       bool   `json:"is_wired"`
				SwMac         string `json:"sw_mac"`
				SwPort        int    `json:"sw_port"`
				LastUplink    string `json:"last_uplink_name"`
				LastPortNum   int    `json:"last_port_num"`
				LastUplinkMac string `json:"last_uplink_mac"`
			}
			if err := json.Unmarshal(raw, &item); err != nil {
				continue
			}

			normalized, err := utils.NormalizeMAC(item.Mac)
			if err != nil {
				continue
			}

			swPortStr := ""
			if item.SwPort > 0 {
				swPortStr = strconv.Itoa(item.SwPort)
			} else if item.LastPortNum > 0 {
				swPortStr = strconv.Itoa(item.LastPortNum)
			}

			existing, exists := clientsMap[normalized]
			if !exists {
				existing = UniFiClientInfo{
					MAC: normalized,
				}
			}

			if item.Name != "" {
				existing.Name = item.Name
			}
			if item.Hostname != "" {
				existing.Hostname = item.Hostname
			}
			if item.Oui != "" {
				existing.Vendor = item.Oui
			}
			if item.IP != "" {
				existing.IP = item.IP
			}
			if swPortStr != "" {
				existing.SwitchPort = swPortStr
			}
			if item.LastUplink != "" {
				existing.SwitchName = item.LastUplink
			}
			if item.SwMac != "" {
				existing.SwitchMAC = strings.ToLower(item.SwMac)
			} else if item.LastUplinkMac != "" && existing.SwitchMAC == "" {
				existing.SwitchMAC = strings.ToLower(item.LastUplinkMac)
			}
			if item.IsWired {
				existing.IsWired = true
			}

			clientsMap[normalized] = existing
		}
	}

	return clientsMap, nil
}

// ReconnectClient sends a kick-sta command to disconnect a client station so it immediately reconnects.
func (c *Client) ReconnectClient(clientMAC string) error {
	clientMAC = strings.ToLower(strings.TrimSpace(clientMAC))
	if clientMAC == "" {
		return errors.New("client MAC is required")
	}

	payload := map[string]interface{}{
		"cmd": "kick-sta",
		"mac": clientMAC,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/cmd/stamgr", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/cmd/stamgr", c.cfg.Site),
	}

	var lastErr error
	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodPost, ep, bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err == nil && apiResp.Meta.Msg != "" {
			lastErr = fmt.Errorf("UniFi error: %s", apiResp.Meta.Msg)
		} else {
			lastErr = fmt.Errorf("request failed with status %d", resp.StatusCode)
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("failed to send reconnect command to UniFi")
}

// PowerCyclePort instructs UniFi to power cycle / restart a switch port.
func (c *Client) PowerCyclePort(switchMAC string, portIdx int) error {
	switchMAC = strings.ToLower(strings.TrimSpace(switchMAC))
	if switchMAC == "" {
		return errors.New("switch MAC is required")
	}
	if portIdx <= 0 {
		return errors.New("invalid port index")
	}

	payload := map[string]interface{}{
		"cmd":      "power-cycle",
		"mac":      switchMAC,
		"port_idx": portIdx,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/cmd/devmgr", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/cmd/devmgr", c.cfg.Site),
	}

	var lastErr error
	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodPost, ep, bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return nil
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err == nil && apiResp.Meta.Msg != "" {
			lastErr = fmt.Errorf("UniFi error: %s", apiResp.Meta.Msg)
		} else {
			lastErr = fmt.Errorf("request failed with status %d", resp.StatusCode)
		}
	}

	if lastErr != nil {
		return lastErr
	}
	return errors.New("failed to send power-cycle command to UniFi")
}

// TestConnection verifies whether the configured UniFi credentials / API key work.
func (c *Client) TestConnection() error {
	if c.cfg.AuthMode == "credentials" {
		return c.Login()
	}

	// For API key, verify by fetching networks
	_, err := c.FetchNetworks()
	return err
}

// UniFiRadiusSetting holds the state of the built-in UniFi RADIUS server.
type UniFiRadiusSetting struct {
	ID        string `json:"_id,omitempty"`
	Key       string `json:"key,omitempty"`
	Enabled   bool   `json:"enabled"`
	Secret    string `json:"x_secret,omitempty"`
	AuthPort  int    `json:"auth_port,omitempty"`
	AcctPort  int    `json:"acct_port,omitempty"`
}

// GetRadiusSetting retrieves the status and configuration of the built-in UniFi RADIUS server.
func (c *Client) GetRadiusSetting() (*UniFiRadiusSetting, error) {
	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/get/setting/radius", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/get/setting/radius", c.cfg.Site),
	}

	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			continue
		}

		if len(apiResp.Data) > 0 {
			var s UniFiRadiusSetting
			if err := json.Unmarshal(apiResp.Data[0], &s); err == nil {
				return &s, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to retrieve radius setting from UniFi")
}

// stopLocalFreeRadius stops and disables the freeradius system service when running directly on Linux/UDM.
func stopLocalFreeRadius() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	// Try systemctl first
	if err := exec.Command("systemctl", "stop", "freeradius").Run(); err == nil {
		_ = exec.Command("systemctl", "disable", "freeradius").Run()
		return nil
	}
	// Fallback to service command
	if err := exec.Command("service", "freeradius", "stop").Run(); err == nil {
		return nil
	}
	return errors.New("could not stop freeradius system service locally")
}

// SetBuiltinRadiusEnabled enables or disables UniFi's internal RADIUS server.
func (c *Client) SetBuiltinRadiusEnabled(enabled bool) error {
	var apiSuccess bool
	var lastErr error

	current, err := c.GetRadiusSetting()
	if err == nil && current != nil {
		current.Enabled = enabled
		bodyBytes, mErr := json.Marshal(current)
		if mErr == nil {
			// 1. Try POST to /set/setting/radius (UniFi standard action endpoint)
			endpointsPost := []string{
				fmt.Sprintf("/proxy/network/api/s/%s/set/setting/radius", c.cfg.Site),
				fmt.Sprintf("/api/s/%s/set/setting/radius", c.cfg.Site),
			}
			for _, ep := range endpointsPost {
				resp, rErr := c.doRequest(http.MethodPost, ep, bytes.NewReader(bodyBytes))
				if rErr != nil {
					lastErr = rErr
					continue
				}
				defer resp.Body.Close()
				if resp.StatusCode >= 200 && resp.StatusCode < 300 {
					apiSuccess = true
					break
				}
				var errResp struct {
					Meta struct {
						Msg  string `json:"msg"`
						Type string `json:"type"`
						Name string `json:"name"`
					} `json:"meta"`
				}
				if json.NewDecoder(resp.Body).Decode(&errResp) == nil && errResp.Meta.Msg != "" {
					if errResp.Meta.Msg == "api.err.ObjectReferredBy" {
						lastErr = fmt.Errorf("UniFi blockiert Änderung: %s '%s' referenziert noch das Built-in RADIUS Profil", errResp.Meta.Type, errResp.Meta.Name)
					} else {
						lastErr = fmt.Errorf("UniFi Fehler: %s", errResp.Meta.Msg)
					}
				} else {
					lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, ep)
				}
			}

			// 2. Try PUT to /rest/setting/radius/{id} (UniFi REST endpoint)
			if !apiSuccess && current.ID != "" {
				endpointsPut := []string{
					fmt.Sprintf("/proxy/network/api/s/%s/rest/setting/radius/%s", c.cfg.Site, current.ID),
					fmt.Sprintf("/api/s/%s/rest/setting/radius/%s", c.cfg.Site, current.ID),
				}
				for _, ep := range endpointsPut {
					resp, rErr := c.doRequest(http.MethodPut, ep, bytes.NewReader(bodyBytes))
					if rErr != nil {
						lastErr = rErr
						continue
					}
					defer resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						apiSuccess = true
						break
					}
					var errResp struct {
						Meta struct {
							Msg  string `json:"msg"`
							Type string `json:"type"`
							Name string `json:"name"`
						} `json:"meta"`
					}
					if json.NewDecoder(resp.Body).Decode(&errResp) == nil && errResp.Meta.Msg != "" {
						if errResp.Meta.Msg == "api.err.ObjectReferredBy" {
							lastErr = fmt.Errorf("UniFi blockiert Änderung: %s '%s' referenziert noch das Built-in RADIUS Profil", errResp.Meta.Type, errResp.Meta.Name)
						} else {
							lastErr = fmt.Errorf("UniFi Fehler: %s", errResp.Meta.Msg)
						}
					} else {
						lastErr = fmt.Errorf("HTTP %d from %s", resp.StatusCode, ep)
					}
				}
			}

			// 3. Fallback: PUT to /set/setting/radius (for mock/legacy compatibility)
			if !apiSuccess {
				for _, ep := range endpointsPost {
					resp, rErr := c.doRequest(http.MethodPut, ep, bytes.NewReader(bodyBytes))
					if rErr != nil {
						continue
					}
					defer resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						apiSuccess = true
						break
					}
				}
			}
		}
	} else if err != nil {
		lastErr = err
	}

	if !enabled {
		localStopErr := stopLocalFreeRadius()
		if apiSuccess || localStopErr == nil {
			return nil
		}
	} else {
		if apiSuccess {
			return nil
		}
	}

	if lastErr != nil {
		return fmt.Errorf("failed to change builtin RADIUS server state in UniFi: %w", lastErr)
	}
	return fmt.Errorf("failed to change builtin RADIUS server state in UniFi")
}

// DisableBuiltinRadius disables UniFi's internal RADIUS server to release UDP port 1812.
func (c *Client) DisableBuiltinRadius() error {
	return c.SetBuiltinRadiusEnabled(false)
}

// EnableBuiltinRadius enables UniFi's internal RADIUS server.
func (c *Client) EnableBuiltinRadius() error {
	return c.SetBuiltinRadiusEnabled(true)
}

// UniFiAccount represents a local RADIUS user or MAB MAC entry configured in UniFi Network.
type UniFiAccount struct {
	ID       string `json:"_id,omitempty"`
	Name     string `json:"name"`
	Password string `json:"x_password,omitempty"`
	VLAN     int    `json:"vlan,omitempty"`
}

// FetchAccounts retrieves all local RADIUS user accounts configured in UniFi Network.
func (c *Client) FetchAccounts() ([]UniFiAccount, error) {
	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/rest/account", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/rest/account", c.cfg.Site),
	}

	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return nil, err
		}

		var accounts []UniFiAccount
		for _, raw := range apiResp.Data {
			var rawAcc struct {
				ID       string      `json:"_id"`
				Name     string      `json:"name"`
				Password string      `json:"x_password"`
				VLAN     interface{} `json:"vlan"`
			}
			if err := json.Unmarshal(raw, &rawAcc); err != nil {
				continue
			}

			vlanInt := 0
			if rawAcc.VLAN != nil {
				switch v := rawAcc.VLAN.(type) {
				case float64:
					vlanInt = int(v)
				case string:
					vlanInt, _ = strconv.Atoi(v)
				}
			}

			accounts = append(accounts, UniFiAccount{
				ID:       rawAcc.ID,
				Name:     rawAcc.Name,
				Password: rawAcc.Password,
				VLAN:     vlanInt,
			})
		}
		return accounts, nil
	}

	return nil, fmt.Errorf("failed to fetch accounts from UniFi")
}

// UniFiRadiusServerConfig holds the host, port, and secret of an auth server in a profile.
type UniFiRadiusServerConfig struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Secret string `json:"x_secret"`
}

// UniFiRadiusProfile represents a RADIUS profile in UniFi Network.
type UniFiRadiusProfile struct {
	ID          string                    `json:"_id,omitempty"`
	Name        string                    `json:"name"`
	VlanEnabled bool                      `json:"vlan_enabled"`
	AuthServers []UniFiRadiusServerConfig `json:"auth_servers"`
}

// ListRadiusProfiles returns all RADIUS profiles configured in UniFi Network.
func (c *Client) ListRadiusProfiles() ([]UniFiRadiusProfile, error) {
	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/rest/radiusprofile", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/rest/radiusprofile", c.cfg.Site),
	}

	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return nil, err
		}

		var profiles []UniFiRadiusProfile
		for _, raw := range apiResp.Data {
			var p UniFiRadiusProfile
			if err := json.Unmarshal(raw, &p); err == nil {
				profiles = append(profiles, p)
			}
		}
		return profiles, nil
	}

	return nil, fmt.Errorf("failed to list radius profiles from UniFi")
}

// CreateOrUpdateRadiusProfile creates or updates a RADIUS profile pointing to this server.
func (c *Client) CreateOrUpdateRadiusProfile(profileName, serverIP string, port int, secret string) (*UniFiRadiusProfile, error) {
	if serverIP == "" {
		serverIP = "127.0.0.1"
	}
	if port <= 0 {
		port = 1812
	}

	profiles, err := c.ListRadiusProfiles()
	var existing *UniFiRadiusProfile
	if err == nil {
		for _, p := range profiles {
			if strings.EqualFold(p.Name, profileName) {
				pCopy := p
				existing = &pCopy
				break
			}
		}
	}

	authServers := []UniFiRadiusServerConfig{
		{
			IP:     serverIP,
			Port:   port,
			Secret: secret,
		},
	}

	payload := UniFiRadiusProfile{
		Name:        profileName,
		VlanEnabled: true,
		AuthServers: authServers,
	}

	if existing != nil && existing.ID != "" {
		// Update existing
		payload.ID = existing.ID
		bodyBytes, _ := json.Marshal(payload)

		endpoints := []string{
			fmt.Sprintf("/proxy/network/api/s/%s/rest/radiusprofile/%s", c.cfg.Site, existing.ID),
			fmt.Sprintf("/api/s/%s/rest/radiusprofile/%s", c.cfg.Site, existing.ID),
		}

		for _, ep := range endpoints {
			resp, err := c.doRequest(http.MethodPut, ep, bytes.NewReader(bodyBytes))
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return &payload, nil
			}
		}
	} else {
		// Create new profile
		bodyBytes, _ := json.Marshal(payload)
		endpoints := []string{
			fmt.Sprintf("/proxy/network/api/s/%s/rest/radiusprofile", c.cfg.Site),
			fmt.Sprintf("/api/s/%s/rest/radiusprofile", c.cfg.Site),
		}

		for _, ep := range endpoints {
			resp, err := c.doRequest(http.MethodPost, ep, bytes.NewReader(bodyBytes))
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return &payload, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to save radius profile in UniFi")
}

// UniFiWLAN represents a wireless network configured in UniFi Network.
type UniFiWLAN struct {
	ID              string `json:"_id,omitempty"`
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	Security        string `json:"security"`
	RadiusProfileID string `json:"radiusprofile_id,omitempty"`
	RadiusMacAuth   bool   `json:"radius_mac_auth_enabled"`
}

// ListWLANs returns all wireless networks configured in UniFi Network.
func (c *Client) ListWLANs() ([]UniFiWLAN, error) {
	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/rest/wlanconf", c.cfg.Site),
		fmt.Sprintf("/api/s/%s/rest/wlanconf", c.cfg.Site),
	}

	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodGet, ep, nil)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var apiResp unifiResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
			return nil, err
		}

		var wlans []UniFiWLAN
		for _, raw := range apiResp.Data {
			var w UniFiWLAN
			if err := json.Unmarshal(raw, &w); err == nil {
				wlans = append(wlans, w)
			}
		}
		return wlans, nil
	}

	return nil, fmt.Errorf("failed to list WLANs from UniFi")
}

// UpdateWLANRadiusProfile updates the RADIUS profile associated with a specific WLAN.
func (c *Client) UpdateWLANRadiusProfile(wlanID, profileID string) error {
	payload := map[string]string{
		"radiusprofile_id": profileID,
	}
	bodyBytes, _ := json.Marshal(payload)

	endpoints := []string{
		fmt.Sprintf("/proxy/network/api/s/%s/rest/wlanconf/%s", c.cfg.Site, wlanID),
		fmt.Sprintf("/api/s/%s/rest/wlanconf/%s", c.cfg.Site, wlanID),
	}

	for _, ep := range endpoints {
		resp, err := c.doRequest(http.MethodPut, ep, bytes.NewReader(bodyBytes))
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
	}

	return fmt.Errorf("failed to update WLAN radius profile in UniFi")
}

