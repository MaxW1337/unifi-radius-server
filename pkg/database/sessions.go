package database

import (
	"database/sql"
	"time"
)

// SaveSession inserts or updates a web session token and expiration time.
func (db *DB) SaveSession(token string, expiresAt time.Time) error {
	_, err := db.Exec(`
		INSERT INTO web_sessions (token, expires_at) VALUES (?, ?)
		ON CONFLICT(token) DO UPDATE SET expires_at = excluded.expires_at
	`, token, expiresAt.UTC())
	return err
}

// GetSessionExpiry looks up an active session in the database.
func (db *DB) GetSessionExpiry(token string) (time.Time, bool, error) {
	var exp time.Time
	err := db.QueryRow("SELECT expires_at FROM web_sessions WHERE token = ?", token).Scan(&exp)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return exp, true, nil
}

// DeleteSession removes a session token from the database.
func (db *DB) DeleteSession(token string) error {
	_, err := db.Exec("DELETE FROM web_sessions WHERE token = ?", token)
	return err
}

// PruneSessions removes all expired sessions.
func (db *DB) PruneSessions() error {
	_, err := db.Exec("DELETE FROM web_sessions WHERE expires_at <= ?", time.Now().UTC())
	return err
}

// LoadActiveSessions loads all non-expired sessions from the database into a map.
func (db *DB) LoadActiveSessions() (map[string]time.Time, error) {
	_ = db.PruneSessions()
	rows, err := db.Query("SELECT token, expires_at FROM web_sessions WHERE expires_at > ?", time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	sessions := make(map[string]time.Time)
	for rows.Next() {
		var token string
		var exp time.Time
		if err := rows.Scan(&token, &exp); err == nil {
			sessions[token] = exp
		}
	}
	return sessions, nil
}

