package database

import (
	"fmt"
	"strings"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// InsertAuthLog persists an authentication attempt.
func (db *DB) InsertAuthLog(l *models.AuthLog) error {
	if l.Timestamp.IsZero() {
		l.Timestamp = time.Now().UTC()
	}

	res, err := db.Exec(`
		INSERT INTO auth_logs (
			timestamp, client_mac, username, nas_ip, nas_port, auth_type,
			status, vlan_id, reason, latency_ms, enriched_name, enriched_vendor
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		l.Timestamp.UTC(), l.ClientMAC, l.Username, l.NASIP, l.NASPort, string(l.AuthType),
		l.Status, l.VLANID, l.Reason, l.LatencyMS, l.EnrichedName, l.EnrichedVendor,
	)
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err == nil {
		l.ID = id
	}
	return nil
}

// ListAuthLogs retrieves paginated authentication logs with optional filters.
func (db *DB) ListAuthLogs(limit, offset int, statusFilter, macFilter string) ([]models.AuthLog, int, error) {
	var whereClauses []string
	var args []interface{}

	if s := strings.TrimSpace(statusFilter); s != "" {
		whereClauses = append(whereClauses, "status = ?")
		args = append(args, strings.ToUpper(s))
	}

	if m := strings.TrimSpace(macFilter); m != "" {
		pattern := "%" + m + "%"
		whereClauses = append(whereClauses, "(client_mac LIKE ? OR username LIKE ?)")
		args = append(args, pattern, pattern)
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(1) FROM auth_logs %s", whereSQL)
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	if limit <= 0 {
		limit = 50
	}
	querySQL := fmt.Sprintf(`
		SELECT id, timestamp, client_mac, username, nas_ip, nas_port, auth_type,
		       status, vlan_id, reason, latency_ms, enriched_name, enriched_vendor
		FROM auth_logs %s
		ORDER BY id DESC
		LIMIT ? OFFSET ?
	`, whereSQL)

	fetchArgs := append(args, limit, offset)
	rows, err := db.Query(querySQL, fetchArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []models.AuthLog
	for rows.Next() {
		var l models.AuthLog
		var authType string
		err := rows.Scan(
			&l.ID, &l.Timestamp, &l.ClientMAC, &l.Username, &l.NASIP, &l.NASPort,
			&authType, &l.Status, &l.VLANID, &l.Reason, &l.LatencyMS,
			&l.EnrichedName, &l.EnrichedVendor,
		)
		if err != nil {
			return nil, 0, err
		}
		l.AuthType = models.AuthType(authType)
		logs = append(logs, l)
	}

	return logs, total, nil
}

// PruneAuthLogs removes entries older than retentionDays or trims the table to maxEntries.
func (db *DB) PruneAuthLogs(retentionDays, maxEntries int) (int64, error) {
	var totalDeleted int64

	// 1. Delete older than retentionDays
	if retentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
		res, err := db.Exec("DELETE FROM auth_logs WHERE timestamp < ?", cutoff)
		if err == nil {
			d, _ := res.RowsAffected()
			totalDeleted += d
		}
	}

	// 2. Trim exceeding maxEntries
	if maxEntries > 0 {
		query := `
			DELETE FROM auth_logs WHERE id NOT IN (
				SELECT id FROM auth_logs ORDER BY id DESC LIMIT ?
			)
		`
		res, err := db.Exec(query, maxEntries)
		if err == nil {
			d, _ := res.RowsAffected()
			totalDeleted += d
		}
	}

	return totalDeleted, nil
}

