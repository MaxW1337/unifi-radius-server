package database

import (
	"database/sql"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

var (
	ErrNASNotFound = errors.New("nas client not found")
)

// ListNASClients returns all configured and synced NAS devices.
func (db *DB) ListNASClients() ([]models.NASClient, error) {
	rows, err := db.Query("SELECT id, ip_or_cidr, name, shared_secret, is_unifi_synced, synced_at FROM nas_clients ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []models.NASClient
	for rows.Next() {
		var n models.NASClient
		if err := rows.Scan(&n.ID, &n.IPOrCIDR, &n.Name, &n.SharedSecret, &n.IsUniFiSynced, &n.SyncedAt); err != nil {
			return nil, err
		}
		list = append(list, n)
	}
	return list, nil
}

// FindNASByIP matches an incoming UDP source IP against exact IP addresses or CIDR ranges.
func (db *DB) FindNASByIP(incomingIP string) (*models.NASClient, error) {
	parsedIP := net.ParseIP(strings.TrimSpace(incomingIP))
	if parsedIP == nil {
		return nil, ErrNASNotFound
	}

	clients, err := db.ListNASClients()
	if err != nil {
		return nil, err
	}

	// 1. Direct exact match
	for _, n := range clients {
		if n.IPOrCIDR == incomingIP {
			return &n, nil
		}
	}

	// 2. CIDR subnet match
	for _, n := range clients {
		if strings.Contains(n.IPOrCIDR, "/") {
			_, ipNet, err := net.ParseCIDR(n.IPOrCIDR)
			if err == nil && ipNet.Contains(parsedIP) {
				return &n, nil
			}
		}
	}

	return nil, ErrNASNotFound
}

// CreateNASClient inserts a manual NAS client.
func (db *DB) CreateNASClient(n *models.NASClient) error {
	now := time.Now().UTC()
	n.SyncedAt = now
	res, err := db.Exec(
		"INSERT INTO nas_clients (ip_or_cidr, name, shared_secret, is_unifi_synced, synced_at) VALUES (?, ?, ?, ?, ?)",
		n.IPOrCIDR, n.Name, n.SharedSecret, n.IsUniFiSynced, n.SyncedAt,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	n.ID = id
	return nil
}

// DeleteNASClient removes a NAS client.
func (db *DB) DeleteNASClient(id int64) error {
	_, err := db.Exec("DELETE FROM nas_clients WHERE id = ?", id)
	return err
}

// ReplaceUniFiNAS updates all UniFi-synced NAS devices while leaving manual entries untouched.
func (db *DB) ReplaceUniFiNAS(devices []models.NASClient) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM nas_clients WHERE is_unifi_synced = 1"); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO nas_clients (ip_or_cidr, name, shared_secret, is_unifi_synced, synced_at)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(ip_or_cidr) DO UPDATE SET
			name = excluded.name,
			shared_secret = excluded.shared_secret,
			is_unifi_synced = 1,
			synced_at = excluded.synced_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, d := range devices {
		if _, err := stmt.Exec(d.IPOrCIDR, d.Name, d.SharedSecret, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetNASByID fetches a single NAS client by ID.
func (db *DB) GetNASByID(id int64) (*models.NASClient, error) {
	row := db.QueryRow("SELECT id, ip_or_cidr, name, shared_secret, is_unifi_synced, synced_at FROM nas_clients WHERE id = ?", id)
	var n models.NASClient
	if err := row.Scan(&n.ID, &n.IPOrCIDR, &n.Name, &n.SharedSecret, &n.IsUniFiSynced, &n.SyncedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNASNotFound
		}
		return nil, err
	}
	return &n, nil
}

