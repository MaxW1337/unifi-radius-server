package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
)

var (
	ErrClientNotFound = errors.New("client not found")
)

// CreateClient inserts a new client into the database.
func (db *DB) CreateClient(c *models.Client) error {
	if c.MACAddress != "" {
		normalized, err := utils.NormalizeMAC(c.MACAddress)
		if err != nil {
			return err
		}
		c.MACAddress = normalized
	}

	if c.Status == "" {
		c.Status = models.ClientStatusActive
	}
	if c.AuthType == "" {
		if c.MACAddress != "" {
			c.AuthType = models.AuthTypeMAB
		} else if c.Username != "" {
			c.AuthType = models.AuthTypePAP
		} else {
			c.AuthType = models.AuthTypeEAPTLS
		}
	}

	now := time.Now().UTC()
	c.CreatedAt = now
	c.UpdatedAt = now

	res, err := db.Exec(`
		INSERT INTO clients (
			mac_address, username, password_hash, auth_type, vlan_id, status,
			description, unifi_name, unifi_hostname, unifi_vendor, unifi_ip,
			unifi_switch_name, unifi_switch_port, unifi_switch_mac, unifi_is_wired,
			cert_serial, last_seen_at, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		nullString(c.MACAddress), nullString(c.Username), c.PasswordHash, string(c.AuthType),
		c.VLANID, string(c.Status), c.Description, c.UniFiName, c.UniFiHostname,
		c.UniFiVendor, c.UniFiIP, c.UniFiSwitchName, c.UniFiSwitchPort,
		c.UniFiSwitchMAC, c.UniFiIsWired, c.CertSerial,
		c.LastSeenAt, c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	c.ID = id
	return nil
}

// UpdateClient updates an existing client.
func (db *DB) UpdateClient(c *models.Client) error {
	if c.MACAddress != "" {
		normalized, err := utils.NormalizeMAC(c.MACAddress)
		if err != nil {
			return err
		}
		c.MACAddress = normalized
	}

	c.UpdatedAt = time.Now().UTC()

	_, err := db.Exec(`
		UPDATE clients SET
			mac_address = ?, username = ?, password_hash = ?, auth_type = ?, vlan_id = ?, status = ?,
			description = ?, unifi_name = ?, unifi_hostname = ?, unifi_vendor = ?,
			unifi_ip = ?, unifi_switch_name = ?, unifi_switch_port = ?,
			unifi_switch_mac = ?, unifi_is_wired = ?, cert_serial = ?,
			updated_at = ?
		WHERE id = ?
	`,
		nullString(c.MACAddress), nullString(c.Username), c.PasswordHash, string(c.AuthType), c.VLANID,
		string(c.Status), c.Description, c.UniFiName, c.UniFiHostname, c.UniFiVendor,
		c.UniFiIP, c.UniFiSwitchName, c.UniFiSwitchPort,
		c.UniFiSwitchMAC, c.UniFiIsWired, c.CertSerial, c.UpdatedAt, c.ID,
	)
	return err
}

// DeleteClient deletes a client by ID.
func (db *DB) DeleteClient(id int64) error {
	_, err := db.Exec("DELETE FROM clients WHERE id = ?", id)
	return err
}

// GetClientByID retrieves a client by primary key.
func (db *DB) GetClientByID(id int64) (*models.Client, error) {
	row := db.QueryRow(`
		SELECT c.id, c.mac_address, c.username, c.password_hash, c.auth_type, c.vlan_id, c.status,
		       c.description, c.unifi_name, c.unifi_hostname, c.unifi_vendor, c.unifi_ip,
		       c.unifi_switch_name, c.unifi_switch_port, c.unifi_switch_mac, c.unifi_is_wired,
		       c.cert_serial, c.last_seen_at, c.created_at, c.updated_at,
		       COALESCE(v.name, '') AS vlan_name
		FROM clients c
		LEFT JOIN unifi_vlans v ON c.vlan_id = v.vlan_id
		WHERE c.id = ?
	`, id)
	return scanClient(row)
}

// GetClientByMAC retrieves a client by MAC address, normalising input first.
func (db *DB) GetClientByMAC(mac string) (*models.Client, error) {
	normalized, err := utils.NormalizeMAC(mac)
	if err != nil {
		return nil, err
	}

	row := db.QueryRow(`
		SELECT c.id, c.mac_address, c.username, c.password_hash, c.auth_type, c.vlan_id, c.status,
		       c.description, c.unifi_name, c.unifi_hostname, c.unifi_vendor, c.unifi_ip,
		       c.unifi_switch_name, c.unifi_switch_port, c.unifi_switch_mac, c.unifi_is_wired,
		       c.cert_serial, c.last_seen_at, c.created_at, c.updated_at,
		       COALESCE(v.name, '') AS vlan_name
		FROM clients c
		LEFT JOIN unifi_vlans v ON c.vlan_id = v.vlan_id
		WHERE c.mac_address = ?
	`, normalized)
	return scanClient(row)
}

// GetClientByUsername retrieves a client/user by username.
func (db *DB) GetClientByUsername(username string) (*models.Client, error) {
	row := db.QueryRow(`
		SELECT c.id, c.mac_address, c.username, c.password_hash, c.auth_type, c.vlan_id, c.status,
		       c.description, c.unifi_name, c.unifi_hostname, c.unifi_vendor, c.unifi_ip,
		       c.unifi_switch_name, c.unifi_switch_port, c.unifi_switch_mac, c.unifi_is_wired,
		       c.cert_serial, c.last_seen_at, c.created_at, c.updated_at,
		       COALESCE(v.name, '') AS vlan_name
		FROM clients c
		LEFT JOIN unifi_vlans v ON c.vlan_id = v.vlan_id
		WHERE c.username = ?
	`, strings.TrimSpace(username))
	return scanClient(row)
}

// ListClients searches and paginates clients with optional VLAN and type filtering.
func (db *DB) ListClients(query string, status models.ClientStatus, limit, offset int, filters ...string) ([]models.Client, int, error) {
	var whereClauses []string
	var args []interface{}

	if status != "" {
		whereClauses = append(whereClauses, "c.status = ?")
		args = append(args, string(status))
	}

	if len(filters) > 0 {
		v := strings.TrimSpace(filters[0])
		if v == "default" {
			whereClauses = append(whereClauses, "(c.vlan_id IS NULL OR c.vlan_id = 0)")
		} else if v != "" && v != "all" {
			if vID, err := strconv.Atoi(v); err == nil {
				whereClauses = append(whereClauses, "c.vlan_id = ?")
				args = append(args, vID)
			}
		}
	}

	if len(filters) > 1 {
		t := strings.ToLower(strings.TrimSpace(filters[1]))
		if t == "mab" {
			whereClauses = append(whereClauses, "(c.auth_type = 'mab' OR (c.mac_address IS NOT NULL AND c.mac_address != ''))")
		} else if t == "user" || t == "pap" {
			whereClauses = append(whereClauses, "(c.auth_type = 'pap' OR (c.username IS NOT NULL AND c.username != ''))")
		}
	}

	if q := strings.TrimSpace(query); q != "" {
		pattern := "%" + q + "%"
		whereClauses = append(whereClauses, "(c.mac_address LIKE ? OR c.username LIKE ? OR c.description LIKE ? OR c.unifi_name LIKE ? OR c.unifi_hostname LIKE ? OR c.unifi_vendor LIKE ? OR COALESCE(v.name, '') LIKE ? OR CAST(c.vlan_id AS TEXT) LIKE ?)")
		args = append(args, pattern, pattern, pattern, pattern, pattern, pattern, pattern, pattern)
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	var total int
	countQuery := fmt.Sprintf(`
		SELECT COUNT(1) 
		FROM clients c 
		LEFT JOIN unifi_vlans v ON c.vlan_id = v.vlan_id 
		%s
	`, whereSQL)
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if limit <= 0 {
		limit = 50
	}
	querySQL := fmt.Sprintf(`
		SELECT c.id, c.mac_address, c.username, c.password_hash, c.auth_type, c.vlan_id, c.status,
		       c.description, c.unifi_name, c.unifi_hostname, c.unifi_vendor, c.unifi_ip,
		       c.unifi_switch_name, c.unifi_switch_port, c.unifi_switch_mac, c.unifi_is_wired,
		       c.cert_serial, c.last_seen_at,
		       c.created_at, c.updated_at,
		       COALESCE(v.name, '') AS vlan_name
		FROM clients c
		LEFT JOIN unifi_vlans v ON c.vlan_id = v.vlan_id
		%s
		ORDER BY c.status = 'pending' DESC, c.updated_at DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := db.Query(querySQL, fetchArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var clients []models.Client
	for rows.Next() {
		c, err := scanClientRow(rows)
		if err != nil {
			return nil, 0, err
		}
		clients = append(clients, *c)
	}

	return clients, total, nil
}

// UpsertPendingMABClient creates a new client with pending status or returns existing.
func (db *DB) UpsertPendingMABClient(mac string, defaultVLAN int, unifiName, unifiVendor string) (*models.Client, error) {
	normalized, err := utils.NormalizeMAC(mac)
	if err != nil {
		return nil, err
	}

	existing, err := db.GetClientByMAC(normalized)
	if err == nil {
		return existing, nil
	}

	now := time.Now().UTC()
	c := &models.Client{
		MACAddress:  normalized,
		AuthType:    models.AuthTypeMAB,
		VLANID:      &defaultVLAN,
		Status:      models.ClientStatusPending,
		Description: "Auto-discovered MAB device",
		UniFiName:   unifiName,
		UniFiVendor: unifiVendor,
		LastSeenAt:  &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := db.CreateClient(c); err != nil {
		return nil, err
	}
	return c, nil
}

// UpdateClientLastSeen updates the last_seen_at timestamp.
func (db *DB) UpdateClientLastSeen(id int64, t time.Time) error {
	_, err := db.Exec("UPDATE clients SET last_seen_at = ?, updated_at = ? WHERE id = ?", t.UTC(), t.UTC(), id)
	return err
}

func scanClient(row *sql.Row) (*models.Client, error) {
	var c models.Client
	var mac, uname, vlanName sql.NullString
	var authType, status string
	var lastSeen sql.NullTime

	err := row.Scan(
		&c.ID, &mac, &uname, &c.PasswordHash, &authType, &c.VLANID, &status,
		&c.Description, &c.UniFiName, &c.UniFiHostname, &c.UniFiVendor, &c.UniFiIP,
		&c.UniFiSwitchName, &c.UniFiSwitchPort, &c.UniFiSwitchMAC, &c.UniFiIsWired,
		&c.CertSerial, &lastSeen,
		&c.CreatedAt, &c.UpdatedAt, &vlanName,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	c.MACAddress = mac.String
	c.Username = uname.String
	c.AuthType = models.AuthType(authType)
	c.Status = models.ClientStatus(status)
	c.VLANName = vlanName.String
	if lastSeen.Valid {
		c.LastSeenAt = &lastSeen.Time
	}
	return &c, nil
}

func scanClientRow(rows *sql.Rows) (*models.Client, error) {
	var c models.Client
	var mac, uname, vlanName sql.NullString
	var authType, status string
	var lastSeen sql.NullTime

	err := rows.Scan(
		&c.ID, &mac, &uname, &c.PasswordHash, &authType, &c.VLANID, &status,
		&c.Description, &c.UniFiName, &c.UniFiHostname, &c.UniFiVendor, &c.UniFiIP,
		&c.UniFiSwitchName, &c.UniFiSwitchPort, &c.UniFiSwitchMAC, &c.UniFiIsWired,
		&c.CertSerial, &lastSeen,
		&c.CreatedAt, &c.UpdatedAt, &vlanName,
	)
	if err != nil {
		return nil, err
	}

	c.MACAddress = mac.String
	c.Username = uname.String
	c.AuthType = models.AuthType(authType)
	c.Status = models.ClientStatus(status)
	c.VLANName = vlanName.String
	if lastSeen.Valid {
		c.LastSeenAt = &lastSeen.Time
	}
	return &c, nil
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

// CountClients returns the total number of clients and the number of clients migrated from UniFi.
func (db *DB) CountClients() (total int, migrated int, err error) {
	err = db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&total)
	if err != nil {
		return 0, 0, err
	}
	_ = db.QueryRow("SELECT COUNT(*) FROM clients WHERE description LIKE '%Migriert%' OR description LIKE '%UniFi%'").Scan(&migrated)
	return total, migrated, nil
}

// EntityCounts represents database record totals for Prometheus metrics.
type EntityCounts struct {
	ClientsActive   int
	ClientsPending  int
	ClientsDisabled int
	TotalAuthLogs   int
	TotalSystemLogs int
}

// GetEntityCounts queries counts of clients and log tables.
func (db *DB) GetEntityCounts() (EntityCounts, error) {
	var counts EntityCounts
	rows, err := db.Query("SELECT status, COUNT(*) FROM clients GROUP BY status")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var st string
			var c int
			if err := rows.Scan(&st, &c); err == nil {
				switch st {
				case "active":
					counts.ClientsActive = c
				case "pending":
					counts.ClientsPending = c
				case "disabled", "blocked":
					counts.ClientsDisabled += c
				}
			}
		}
	}
	_ = db.QueryRow("SELECT COUNT(*) FROM auth_logs").Scan(&counts.TotalAuthLogs)
	_ = db.QueryRow("SELECT COUNT(*) FROM system_logs").Scan(&counts.TotalSystemLogs)
	return counts, nil
}



