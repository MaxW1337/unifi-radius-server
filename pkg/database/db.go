package database

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the standard *sql.DB with application-specific helpers.
type DB struct {
	*sql.DB
	path string
}

// Path returns the SQLite file path.
func (db *DB) Path() string {
	return db.path
}

// Open creates or opens a SQLite database at the specified path, configures WAL mode,
// and runs migrations to ensure all tables exist.
func Open(dbPath string) (*DB, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dbPath)
	rawDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Single writer connection pool is ideal for SQLite
	rawDB.SetMaxOpenConns(1)
	rawDB.SetMaxIdleConns(1)
	rawDB.SetConnMaxLifetime(time.Hour)

	db := &DB{DB: rawDB, path: dbPath}
	if err := db.migrate(); err != nil {
		rawDB.Close()
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	if err := db.seedDefaults(); err != nil {
		rawDB.Close()
		return nil, fmt.Errorf("failed to seed defaults: %w", err)
	}

	return db, nil
}

func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac_address TEXT UNIQUE,
		username TEXT UNIQUE,
		password_hash TEXT,
		auth_type TEXT NOT NULL,
		vlan_id INTEGER,
		status TEXT NOT NULL,
		description TEXT DEFAULT '',
		unifi_name TEXT DEFAULT '',
		unifi_hostname TEXT DEFAULT '',
		unifi_vendor TEXT DEFAULT '',
		unifi_ip TEXT DEFAULT '',
		unifi_switch_name TEXT DEFAULT '',
		unifi_switch_port TEXT DEFAULT '',
		unifi_switch_mac TEXT DEFAULT '',
		unifi_is_wired BOOLEAN DEFAULT 0,
		cert_serial TEXT DEFAULT '',
		last_seen_at DATETIME,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS unifi_vlans (
		vlan_id INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		subnet TEXT DEFAULT '',
		purpose TEXT DEFAULT '',
		is_default BOOLEAN DEFAULT 0,
		synced_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS nas_clients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_or_cidr TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		shared_secret TEXT NOT NULL,
		is_unifi_synced BOOLEAN DEFAULT 0,
		synced_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		serial_number TEXT UNIQUE NOT NULL,
		common_name TEXT NOT NULL,
		cert_type TEXT NOT NULL,
		certificate_pem TEXT NOT NULL,
		private_key_pem TEXT,
		client_id INTEGER REFERENCES clients(id) ON DELETE SET NULL,
		issued_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		is_revoked BOOLEAN DEFAULT 0,
		revoked_at DATETIME
	);

	CREATE TABLE IF NOT EXISTS auth_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		client_mac TEXT DEFAULT '',
		username TEXT DEFAULT '',
		nas_ip TEXT DEFAULT '',
		nas_port TEXT DEFAULT '',
		nas_name TEXT DEFAULT '',
		auth_type TEXT NOT NULL,
		status TEXT NOT NULL,
		vlan_id INTEGER,
		reason TEXT NOT NULL,
		latency_ms REAL DEFAULT 0,
		enriched_name TEXT DEFAULT '',
		enriched_vendor TEXT DEFAULT '',
		raw_request TEXT DEFAULT '',
		raw_response TEXT DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS system_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		level TEXT NOT NULL,
		source TEXT NOT NULL,
		message TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS web_sessions (
		token TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_auth_logs_timestamp ON auth_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_auth_logs_mac ON auth_logs(client_mac);
	CREATE INDEX IF NOT EXISTS idx_clients_mac ON clients(mac_address);
	CREATE INDEX IF NOT EXISTS idx_clients_status ON clients(status);
	CREATE INDEX IF NOT EXISTS idx_system_logs_timestamp ON system_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level);
	CREATE INDEX IF NOT EXISTS idx_system_logs_source ON system_logs(source);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return err
	}

	// Dynamic column migrations for existing databases
	_, _ = db.Exec("ALTER TABLE clients ADD COLUMN unifi_switch_mac TEXT DEFAULT '';")
	_, _ = db.Exec("ALTER TABLE clients ADD COLUMN unifi_is_wired BOOLEAN DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE auth_logs ADD COLUMN raw_request TEXT DEFAULT '';")
	_, _ = db.Exec("ALTER TABLE auth_logs ADD COLUMN raw_response TEXT DEFAULT '';")
	_, _ = db.Exec("ALTER TABLE auth_logs ADD COLUMN nas_name TEXT DEFAULT '';")

	return nil
}

func (db *DB) seedDefaults() error {
	defaults := map[string]string{
		"default_allow_vlan":   "1",
		"unknown_mab_policy":   "reject_log",
		"global_shared_secret": "radius_secret_changeme",
		"radius_auth_port":          "1812",
		"radius_debug_mode":         "false",
		"auto_disconnect_on_change": "true",
		"defense_enabled":            "true",
		"defense_max_failures":       "5",
		"defense_window_seconds":     "60",
		"defense_ban_duration_minutes": "15",
		"defense_mac_spoof_detection": "true",
		"web_port":                  "9182",
		"web_session_duration_days": "30",
		"unifi_url":            "https://127.0.0.1",
		"unifi_auth_mode":      "apikey",
		"unifi_api_key":        "",
		"unifi_username":       "",
		"unifi_password":       "",
		"unifi_sync_interval":  "5",
		"log_retention_days":   "30",
		"max_log_entries":      "10000",
		"ssl_enabled":          "false",
		"auto_update_enabled":  "false",
		"auto_update_schedule": "weekly",
		"auto_update_time":     "03:00",
		"auto_update_weekday":  "1",
		"auto_update_day":      "1",
	}

	for k, v := range defaults {
		var exists int
		err := db.QueryRow("SELECT COUNT(1) FROM settings WHERE key = ?", k).Scan(&exists)
		if err != nil {
			return err
		}
		if exists == 0 {
			_, err = db.Exec("INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)", k, v, time.Now().UTC())
			if err != nil {
				return err
			}
		}
	}

	// Always ensure localhost / UDM local NAS client exists
	var nasCount int
	err := db.QueryRow("SELECT COUNT(1) FROM nas_clients WHERE ip_or_cidr IN ('127.0.0.1', '127.0.0.1/32')").Scan(&nasCount)
	if err == nil && nasCount == 0 {
		_, _ = db.Exec(`INSERT INTO nas_clients (ip_or_cidr, name, shared_secret, is_unifi_synced, synced_at)
			VALUES ('127.0.0.1', 'UDM Localhost', 'radius_secret_changeme', 0, ?)`, time.Now().UTC())
	}

	return nil
}

// Backup creates a clean, vacuumed SQLite backup to w.
func (db *DB) Backup(w io.Writer) error {
	tmpFile, err := os.CreateTemp("", "radius-backup-*.db")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	_ = os.Remove(tmpPath)

	_, err = db.Exec(fmt.Sprintf("VACUUM INTO '%s'", filepath.ToSlash(tmpPath)))
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("VACUUM INTO failed: %w", err)
	}
	defer os.Remove(tmpPath)

	f, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(w, f)
	return err
}

// Restore validates the uploaded SQLite backup and replaces current DB.
func (db *DB) Restore(r io.Reader) error {
	if db.path == "" || db.path == ":memory:" {
		return errors.New("cannot restore in-memory database")
	}

	tmpFile, err := os.CreateTemp("", "radius-restore-*.db")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmpFile, r); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to save uploaded backup: %w", err)
	}
	tmpFile.Close()

	// Verify integrity
	checkDB, err := sql.Open("sqlite", fmt.Sprintf("%s?_pragma=busy_timeout(2000)", tmpPath))
	if err != nil {
		return fmt.Errorf("uploaded file is not a valid sqlite database: %w", err)
	}
	var checkResult string
	err = checkDB.QueryRow("PRAGMA integrity_check;").Scan(&checkResult)
	checkDB.Close()
	if err != nil || checkResult != "ok" {
		return fmt.Errorf("database integrity check failed: %s", checkResult)
	}

	// Truncate current WAL
	_, _ = db.Exec("PRAGMA wal_checkpoint(TRUNCATE);")

	src, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dest, err := os.OpenFile(db.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open destination database: %w", err)
	}
	defer dest.Close()

	if _, err := io.Copy(dest, src); err != nil {
		return fmt.Errorf("failed to overwrite database file: %w", err)
	}

	_ = os.Remove(db.path + "-wal")
	_ = os.Remove(db.path + "-shm")

	return db.migrate()
}

