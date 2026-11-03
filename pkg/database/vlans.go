package database

import (
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// ListVLANs returns all currently cached UniFi VLANs ordered by VLAN ID.
func (db *DB) ListVLANs() ([]models.VLAN, error) {
	rows, err := db.Query("SELECT vlan_id, name, subnet, purpose, is_default, synced_at FROM unifi_vlans ORDER BY vlan_id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vlans []models.VLAN
	for rows.Next() {
		var v models.VLAN
		if err := rows.Scan(&v.VLANID, &v.Name, &v.Subnet, &v.Purpose, &v.IsDefault, &v.SyncedAt); err != nil {
			return nil, err
		}
		vlans = append(vlans, v)
	}
	return vlans, nil
}

// ReplaceVLANs atomic replaces the synced VLAN list with fresh entries from UniFi.
func (db *DB) ReplaceVLANs(vlans []models.VLAN) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM unifi_vlans"); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO unifi_vlans (vlan_id, name, subnet, purpose, is_default, synced_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(vlan_id) DO UPDATE SET
			name = excluded.name,
			subnet = excluded.subnet,
			purpose = excluded.purpose,
			is_default = excluded.is_default,
			synced_at = excluded.synced_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for _, v := range vlans {
		if _, err := stmt.Exec(v.VLANID, v.Name, v.Subnet, v.Purpose, v.IsDefault, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetVLAN retrieves a single VLAN by ID.
func (db *DB) GetVLAN(vlanID int) (*models.VLAN, error) {
	row := db.QueryRow("SELECT vlan_id, name, subnet, purpose, is_default, synced_at FROM unifi_vlans WHERE vlan_id = ?", vlanID)
	var v models.VLAN
	err := row.Scan(&v.VLANID, &v.Name, &v.Subnet, &v.Purpose, &v.IsDefault, &v.SyncedAt)
	if err != nil {
		return nil, err
	}
	return &v, nil
}

