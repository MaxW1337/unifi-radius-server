package backup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TestLocal verifies that targetDir exists or can be created, and is writable.
func TestLocal(targetDir string) error {
	cleanDir := filepath.Clean(strings.TrimSpace(targetDir))
	if cleanDir == "" || cleanDir == "." {
		return errors.New("Zielverzeichnis darf nicht leer sein")
	}

	if err := os.MkdirAll(cleanDir, 0750); err != nil {
		return fmt.Errorf("Verzeichnis konnte nicht erstellt werden: %w", err)
	}

	// Write test file
	testFile := filepath.Join(cleanDir, ".backup_write_test")
	if err := os.WriteFile(testFile, []byte("ok"), 0600); err != nil {
		return fmt.Errorf("Schreibzugriff auf Zielverzeichnis verweigert: %w", err)
	}
	_ = os.Remove(testFile)

	return nil
}

// SaveLocal copies a backup file to the local or mounted target directory.
func SaveLocal(targetDir, filename, localFilePath string) (int64, error) {
	cleanDir := filepath.Clean(strings.TrimSpace(targetDir))
	if cleanDir == "" || cleanDir == "." {
		return 0, errors.New("Zielverzeichnis darf nicht leer sein")
	}

	if err := os.MkdirAll(cleanDir, 0750); err != nil {
		return 0, fmt.Errorf("Zielverzeichnis erstellen fehlgeschlagen: %w", err)
	}

	destPath := filepath.Join(cleanDir, filename)

	src, err := os.Open(localFilePath)
	if err != nil {
		return 0, err
	}
	defer src.Close()

	dest, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return 0, fmt.Errorf("Zieldatei konnte nicht angelegt werden: %w", err)
	}
	defer dest.Close()

	n, err := io.Copy(dest, src)
	if err != nil {
		return 0, fmt.Errorf("Fehler beim Kopieren: %w", err)
	}

	return n, nil
}

// PruneLocal removes older radius-backup-*.db files in targetDir exceeding retention.
func PruneLocal(targetDir string, retention int) error {
	if retention <= 0 {
		return nil
	}

	cleanDir := filepath.Clean(strings.TrimSpace(targetDir))
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return err
	}

	var backupFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, "radius-backup-") && strings.HasSuffix(name, ".db") {
			backupFiles = append(backupFiles, name)
		}
	}

	sort.Strings(backupFiles)

	if len(backupFiles) > retention {
		toDelete := backupFiles[:len(backupFiles)-retention]
		for _, f := range toDelete {
			_ = os.Remove(filepath.Join(cleanDir, f))
		}
	}

	return nil
}

