package radius

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

// FastCache maintains an in-memory lock-protected cache of clients, NAS devices,
// and settings to allow sub-millisecond RADIUS responses without SQLite read locks.
type FastCache struct {
	db             *database.DB
	mu             sync.RWMutex
	clientsByMAC   map[string]*models.Client
	clientsByUser  map[string]*models.Client
	nasList        []models.NASClient
	settings       *models.Settings
	lastRefresh    time.Time
	refreshTimeout time.Duration
}

// NewFastCache loads initial database state into RAM.
func NewFastCache(db *database.DB) *FastCache {
	fc := &FastCache{
		db:             db,
		clientsByMAC:   make(map[string]*models.Client),
		clientsByUser:  make(map[string]*models.Client),
		refreshTimeout: 5 * time.Second,
	}
	_ = fc.Reload()
	return fc
}

// Reload reads all clients, NAS clients, and settings from SQLite into memory.
func (c *FastCache) Reload() error {
	settings, err := c.db.GetSettings()
	if err != nil {
		return err
	}

	clients, _, err := c.db.ListClients("", "", 50000, 0)
	if err != nil {
		return err
	}

	nasList, err := c.db.ListNASClients()
	if err != nil {
		return err
	}

	macMap := make(map[string]*models.Client, len(clients))
	userMap := make(map[string]*models.Client, len(clients))

	for i := range clients {
		clientCopy := clients[i]
		if clientCopy.MACAddress != "" {
			macMap[clientCopy.MACAddress] = &clientCopy
		}
		if clientCopy.Username != "" {
			userMap[clientCopy.Username] = &clientCopy
		}
	}

	c.mu.Lock()
	c.settings = settings
	c.clientsByMAC = macMap
	c.clientsByUser = userMap
	c.nasList = nasList
	c.lastRefresh = time.Now()
	c.mu.Unlock()

	return nil
}

// LookupClientByMAC performs a microsecond memory lookup for a MAC address.
func (c *FastCache) LookupClientByMAC(rawMAC string) (*models.Client, bool) {
	normMAC, err := utils.NormalizeMAC(rawMAC)
	if err != nil {
		return nil, false
	}

	c.mu.RLock()
	client, found := c.clientsByMAC[normMAC]
	c.mu.RUnlock()

	if found {
		return client, true
	}

	// If not found and cache is older than refreshTimeout, attempt single refresh
	if time.Since(c.lastRefresh) > c.refreshTimeout {
		_ = c.Reload()
		c.mu.RLock()
		client, found = c.clientsByMAC[normMAC]
		c.mu.RUnlock()
		return client, found
	}

	return nil, false
}

// LookupClientByUser performs a memory lookup for an 802.1X username.
func (c *FastCache) LookupClientByUser(username string) (*models.Client, bool) {
	trimmed := strings.TrimSpace(username)
	c.mu.RLock()
	client, found := c.clientsByUser[trimmed]
	c.mu.RUnlock()

	if found {
		return client, true
	}

	if time.Since(c.lastRefresh) > c.refreshTimeout {
		_ = c.Reload()
		c.mu.RLock()
		client, found = c.clientsByUser[trimmed]
		c.mu.RUnlock()
		return client, found
	}

	return nil, false
}

// LookupNAS resolves an incoming IP against exact and CIDR NAS entries in RAM.
func (c *FastCache) LookupNAS(remoteIP string) (*models.NASClient, bool) {
	parsedIP := net.ParseIP(strings.TrimSpace(remoteIP))
	if parsedIP == nil {
		return nil, false
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	// 1. Direct match
	for _, n := range c.nasList {
		if n.IPOrCIDR == remoteIP {
			nCopy := n
			return &nCopy, true
		}
	}

	// 2. CIDR match
	for _, n := range c.nasList {
		if strings.Contains(n.IPOrCIDR, "/") {
			_, ipNet, err := net.ParseCIDR(n.IPOrCIDR)
			if err == nil && ipNet.Contains(parsedIP) {
				nCopy := n
				return &nCopy, true
			}
		}
	}

	return nil, false
}

// GetSettings returns a cached copy of the system settings.
func (c *FastCache) GetSettings() *models.Settings {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.settings == nil {
		return &models.Settings{
			DefaultAllowVLAN:   1,
			UnknownMABPolicy:   models.PolicyRejectAndLog,
			GlobalSharedSecret: "radius_secret_changeme",
		}
	}
	sCopy := *c.settings
	return &sCopy
}

// OptimisticInsertMAC temporarily caches an auto-discovered MAC in memory immediately.
func (c *FastCache) OptimisticInsertMAC(client *models.Client) {
	if client == nil || client.MACAddress == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clientsByMAC[client.MACAddress] = client
}

