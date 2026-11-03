package backup

import "time"

// BackupResult describes the outcome of a remote backup execution.
type BackupResult struct {
	Success   bool      `json:"success"`
	Target    string    `json:"target"` // 'webdav', 's3', 'local'
	Filename  string    `json:"filename"`
	SizeBytes int64     `json:"size_bytes"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

