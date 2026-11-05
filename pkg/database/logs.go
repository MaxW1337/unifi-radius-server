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
			timestamp, client_mac, username, nas_ip, nas_port, nas_name, auth_type,
			status, vlan_id, reason, latency_ms, enriched_name, enriched_vendor,
			raw_request, raw_response
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		l.Timestamp.UTC(), l.ClientMAC, l.Username, l.NASIP, l.NASPort, l.NASName, string(l.AuthType),
		l.Status, l.VLANID, l.Reason, l.LatencyMS, l.EnrichedName, l.EnrichedVendor,
		l.RawRequest, l.RawResponse,
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

// ListAuthLogs retrieves paginated authentication logs with optional multi-field filters.
func (db *DB) ListAuthLogs(limit, offset int, statusFilter, queryFilter string) ([]models.AuthLog, int, error) {
	var whereClauses []string
	var args []interface{}

	if s := strings.TrimSpace(statusFilter); s != "" && s != "ALL" {
		whereClauses = append(whereClauses, "status = ?")
		args = append(args, strings.ToUpper(s))
	}

	if q := strings.TrimSpace(queryFilter); q != "" {
		pattern := "%" + q + "%"
		cleanMAC := strings.ReplaceAll(strings.ReplaceAll(q, ":", ""), "-", "")
		var macPatterns []string
		if len(cleanMAC) == 12 {
			var parts []string
			for i := 0; i < 12; i += 2 {
				parts = append(parts, strings.ToUpper(cleanMAC[i:i+2]))
			}
			macPatterns = append(macPatterns, "%"+strings.Join(parts, ":")+"%")
		}

		clause := "(client_mac LIKE ? OR username LIKE ? OR enriched_name LIKE ? OR enriched_vendor LIKE ? OR nas_ip LIKE ? OR nas_name LIKE ? OR reason LIKE ?)"
		clauseArgs := []interface{}{pattern, pattern, pattern, pattern, pattern, pattern, pattern}
		for _, mp := range macPatterns {
			clause = "(" + clause + " OR client_mac LIKE ?)"
			clauseArgs = append(clauseArgs, mp)
		}
		whereClauses = append(whereClauses, clause)
		args = append(args, clauseArgs...)
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
		SELECT id, timestamp, client_mac, username, nas_ip, nas_port, COALESCE(nas_name, ''), auth_type,
		       status, vlan_id, reason, latency_ms, enriched_name, enriched_vendor,
		       COALESCE(raw_request, ''), COALESCE(raw_response, '')
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
			&l.ID, &l.Timestamp, &l.ClientMAC, &l.Username, &l.NASIP, &l.NASPort, &l.NASName,
			&authType, &l.Status, &l.VLANID, &l.Reason, &l.LatencyMS,
			&l.EnrichedName, &l.EnrichedVendor,
			&l.RawRequest, &l.RawResponse,
		)
		if err != nil {
			return nil, 0, err
		}
		l.AuthType = models.AuthType(authType)
		logs = append(logs, l)
	}

	return logs, total, nil
}

// GetAuthLogByID retrieves a single authentication log with raw request/response details.
func (db *DB) GetAuthLogByID(id int64) (*models.AuthLog, error) {
	row := db.QueryRow(`
		SELECT id, timestamp, client_mac, username, nas_ip, nas_port, COALESCE(nas_name, ''), auth_type,
		       status, vlan_id, reason, latency_ms, enriched_name, enriched_vendor,
		       COALESCE(raw_request, ''), COALESCE(raw_response, '')
		FROM auth_logs
		WHERE id = ?
	`, id)

	var l models.AuthLog
	var authType string
	err := row.Scan(
		&l.ID, &l.Timestamp, &l.ClientMAC, &l.Username, &l.NASIP, &l.NASPort, &l.NASName,
		&authType, &l.Status, &l.VLANID, &l.Reason, &l.LatencyMS,
		&l.EnrichedName, &l.EnrichedVendor,
		&l.RawRequest, &l.RawResponse,
	)
	if err != nil {
		return nil, err
	}
	l.AuthType = models.AuthType(authType)
	return &l, nil
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

