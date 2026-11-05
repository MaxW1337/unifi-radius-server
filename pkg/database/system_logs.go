package database

import (
	"database/sql"
	"strings"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// InsertSystemLog saves a single system log event to the database.
func (db *DB) InsertSystemLog(entry *models.SystemLog) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	query := `
	INSERT INTO system_logs (timestamp, level, source, message)
	VALUES (?, ?, ?, ?);
	`
	res, err := db.Exec(query,
		entry.Timestamp.UTC(),
		strings.ToUpper(strings.TrimSpace(entry.Level)),
		strings.ToUpper(strings.TrimSpace(entry.Source)),
		entry.Message,
	)
	if err != nil {
		return err
	}

	id, err := res.LastInsertId()
	if err == nil {
		entry.ID = id
	}
	return nil
}

// InsertSystemLogsBatch writes multiple system log events in a single transaction for efficiency.
func (db *DB) InsertSystemLogsBatch(entries []models.SystemLog) error {
	if len(entries) == 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`INSERT INTO system_logs (timestamp, level, source, message) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range entries {
		ts := entries[i].Timestamp
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		_, err := stmt.Exec(
			ts.UTC(),
			strings.ToUpper(strings.TrimSpace(entries[i].Level)),
			strings.ToUpper(strings.TrimSpace(entries[i].Source)),
			entries[i].Message,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// ListSystemLogs retrieves paginated system logs matching the specified filters.
func (db *DB) ListSystemLogs(limit, offset int, level, source, query string, fromTime, toTime *time.Time) ([]models.SystemLog, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	var conditions []string
	var args []interface{}

	if trimmedLvl := strings.TrimSpace(level); trimmedLvl != "" {
		conditions = append(conditions, "UPPER(level) = ?")
		args = append(args, strings.ToUpper(trimmedLvl))
	}

	if trimmedSrc := strings.TrimSpace(source); trimmedSrc != "" {
		conditions = append(conditions, "(UPPER(source) = ? OR UPPER(source) LIKE ?)")
		args = append(args, strings.ToUpper(trimmedSrc), strings.ToUpper(trimmedSrc)+"-%")
	}

	if trimmedQ := strings.TrimSpace(query); trimmedQ != "" {
		conditions = append(conditions, "(message LIKE ? OR source LIKE ?)")
		pattern := "%" + trimmedQ + "%"
		args = append(args, pattern, pattern)
	}

	if fromTime != nil && !fromTime.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, fromTime.UTC())
	}

	if toTime != nil && !toTime.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, toTime.UTC())
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// 1. Get total count
	countQuery := "SELECT COUNT(*) FROM system_logs " + whereClause
	var total int
	err := db.QueryRow(countQuery, args...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// 2. Query page of rows
	querySQL := `
	SELECT id, timestamp, level, source, message
	FROM system_logs
	` + whereClause + `
	ORDER BY timestamp DESC, id DESC
	LIMIT ? OFFSET ?;
	`
	queryArgs := append(args, limit, offset)

	rows, err := db.Query(querySQL, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []models.SystemLog
	for rows.Next() {
		var l models.SystemLog
		var tsRaw sql.NullTime
		if err := rows.Scan(&l.ID, &tsRaw, &l.Level, &l.Source, &l.Message); err != nil {
			return nil, 0, err
		}
		if tsRaw.Valid {
			l.Timestamp = tsRaw.Time.UTC()
		}
		logs = append(logs, l)
	}

	if logs == nil {
		logs = []models.SystemLog{}
	}
	return logs, total, nil
}

// GetDistinctSystemLogSources returns all distinct source names recorded in system_logs.
func (db *DB) GetDistinctSystemLogSources() ([]string, error) {
	rows, err := db.Query("SELECT DISTINCT source FROM system_logs WHERE source != '' ORDER BY source ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sources []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err == nil && s != "" {
			sources = append(sources, s)
		}
	}
	return sources, nil
}

// PruneSystemLogs deletes system log entries older than retentionDays or trims table to maxEntries.
func (db *DB) PruneSystemLogs(retentionDays, maxEntries int) (int64, error) {
	var totalDeleted int64

	// 1. Delete older than retentionDays
	if retentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
		res, err := db.Exec("DELETE FROM system_logs WHERE timestamp < ?", cutoff)
		if err == nil {
			d, _ := res.RowsAffected()
			totalDeleted += d
		}
	}

	// 2. Trim exceeding maxEntries
	if maxEntries > 0 {
		trimQuery := `
		DELETE FROM system_logs
		WHERE id NOT IN (
			SELECT id FROM system_logs
			ORDER BY timestamp DESC, id DESC
			LIMIT ?
		);
		`
		res, err := db.Exec(trimQuery, maxEntries)
		if err == nil {
			d, _ := res.RowsAffected()
			totalDeleted += d
		}
	}

	return totalDeleted, nil
}
