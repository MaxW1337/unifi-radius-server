package backup

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

func TestValidateURL(t *testing.T) {
	invalidCases := []string{
		"file:///etc/passwd",
		"ftp://user:pass@host/file",
		"gopher://malicious.host",
		"javascript:alert(1)",
		"http://",
		"https://",
		"",
	}

	for _, c := range invalidCases {
		_, err := ValidateURL(c)
		if err == nil {
			t.Errorf("Expected error for URL %q, got nil", c)
		}
	}

	validCases := []string{
		"http://192.168.1.10:8080/webdav",
		"https://nextcloud.example.com/remote.php/dav/files/admin/backups",
		"https://s3.eu-central-1.amazonaws.com",
		"http://minio.local:9000",
	}

	for _, c := range validCases {
		u, err := ValidateURL(c)
		if err != nil {
			t.Errorf("Unexpected error for valid URL %q: %v", c, err)
		}
		if u == nil || u.Host == "" {
			t.Errorf("Expected parsed URL with host for %q", c)
		}
	}
}

func TestLocalBackupAndPruning(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "radius-local-backup-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	if err := TestLocal(tempDir); err != nil {
		t.Fatalf("TestLocal failed on valid temp dir: %v", err)
	}

	// Create dummy local source file
	srcFile, err := os.CreateTemp("", "radius-src-*.db")
	if err != nil {
		t.Fatalf("Failed to create src file: %v", err)
	}
	_, _ = srcFile.WriteString("SQLITE-DATA-DUMMY")
	srcPath := srcFile.Name()
	srcFile.Close()
	defer os.Remove(srcPath)

	// Save 5 backups
	for i := 1; i <= 5; i++ {
		filename := fmt.Sprintf("radius-backup-2026-11-0%d-120000.db", i)
		n, err := SaveLocal(tempDir, filename, srcPath)
		if err != nil {
			t.Fatalf("SaveLocal failed on iteration %d: %v", i, err)
		}
		if n <= 0 {
			t.Errorf("Expected bytes written > 0, got %d", n)
		}
	}

	// Prune with retention = 3
	if err := PruneLocal(tempDir, 3); err != nil {
		t.Fatalf("PruneLocal failed: %v", err)
	}

	entries, _ := os.ReadDir(tempDir)
	var remaining []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "radius-backup-") {
			remaining = append(remaining, e.Name())
		}
	}

	if len(remaining) != 3 {
		t.Fatalf("Expected 3 remaining files after prune, got %d: %v", len(remaining), remaining)
	}

	// Should have kept the newest: 03, 04, 05
	if remaining[0] != "radius-backup-2026-11-03-120000.db" {
		t.Errorf("Expected oldest remaining to be day 03, got %s", remaining[0])
	}
}

func TestWebDAVUploadAndPrune(t *testing.T) {
	uploadedFiles := make(map[string][]byte)
	deletedFiles := make(map[string]bool)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "davuser" || pass != "davpass" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case "PROPFIND":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			xmlResp := `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response><D:href>/remote.php/dav/backups/radius-backup-2026-11-01-100000.db</D:href></D:response>
  <D:response><D:href>/remote.php/dav/backups/radius-backup-2026-11-02-100000.db</D:href></D:response>
  <D:response><D:href>/remote.php/dav/backups/radius-backup-2026-11-03-100000.db</D:href></D:response>
</D:multistatus>`
			_, _ = w.Write([]byte(xmlResp))

		case "PUT":
			data, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read error", http.StatusBadRequest)
				return
			}
			uploadedFiles[r.URL.Path] = data
			w.WriteHeader(http.StatusCreated)

		case "DELETE":
			deletedFiles[r.URL.Path] = true
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	client := srv.Client()

	// 1. Test WebDAV connection
	if err := TestWebDAV(ctx, client, srv.URL+"/remote.php/dav/backups", "davuser", "davpass"); err != nil {
		t.Fatalf("TestWebDAV failed: %v", err)
	}

	// 2. Upload dummy file
	dummyFile, err := os.CreateTemp("", "radius-dav-*.db")
	if err != nil {
		t.Fatalf("Failed to create dummy file: %v", err)
	}
	_, _ = dummyFile.WriteString("SQLITE-DATA-DAV")
	dummyPath := dummyFile.Name()
	dummyFile.Close()
	defer os.Remove(dummyPath)

	size, err := UploadWebDAV(ctx, client, srv.URL+"/remote.php/dav/backups", "davuser", "davpass", "radius-backup-test.db", dummyPath)
	if err != nil {
		t.Fatalf("UploadWebDAV failed: %v", err)
	}
	if size <= 0 {
		t.Errorf("Expected uploaded size > 0, got %d", size)
	}

	// 3. Test Prune (retention = 2) -> Should delete the oldest (01)
	if err := PruneWebDAV(ctx, client, srv.URL+"/remote.php/dav/backups", "davuser", "davpass", 2); err != nil {
		t.Fatalf("PruneWebDAV failed: %v", err)
	}

	if !deletedFiles["/remote.php/dav/backups/radius-backup-2026-11-01-100000.db"] {
		t.Error("Expected oldest backup to be deleted via WebDAV DELETE")
	}
}

func TestS3UploadAndSignature(t *testing.T) {
	receivedAuth := ""
	receivedAmzDate := ""

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedAmzDate = r.Header.Get("x-amz-date")

		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	ctx := context.Background()
	client := srv.Client()

	// 1. Test S3 connection
	if err := TestS3(ctx, client, srv.URL, "mybucket", "ACCESSKEY123", "SECRETKEY456"); err != nil {
		t.Fatalf("TestS3 failed: %v", err)
	}

	if !strings.HasPrefix(receivedAuth, "AWS4-HMAC-SHA256 Credential=ACCESSKEY123/") {
		t.Errorf("Invalid Authorization header: %s", receivedAuth)
	}
	if receivedAmzDate == "" {
		t.Error("Expected x-amz-date header")
	}

	// 2. Upload file
	dummyFile, err := os.CreateTemp("", "radius-s3-*.db")
	if err != nil {
		t.Fatalf("Failed to create dummy file: %v", err)
	}
	_, _ = dummyFile.WriteString("SQLITE-DATA-S3")
	dummyPath := dummyFile.Name()
	dummyFile.Close()
	defer os.Remove(dummyPath)

	size, err := UploadS3(ctx, client, srv.URL, "mybucket", "backups/radius", "ACCESSKEY123", "SECRETKEY456", "test.db", dummyPath)
	if err != nil {
		t.Fatalf("UploadS3 failed: %v", err)
	}
	if size <= 0 {
		t.Errorf("Expected uploaded size > 0, got %d", size)
	}
}

func TestServiceRunBackup(t *testing.T) {
	dbFile := filepath.Join(t.TempDir(), "test.db")
	db, err := database.Open(dbFile)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer db.Close()

	bus := eventbus.DefaultBus
	svc := NewService(db, bus)

	backupDir := t.TempDir()
	settings := &models.Settings{
		RemoteBackupEnabled:   true,
		RemoteBackupType:      "local",
		RemoteBackupPath:      backupDir,
		RemoteBackupRetention: 5,
		RemoteBackupSchedule:  "03:00",
	}
	if err := db.UpdateSettings(settings); err != nil {
		t.Fatalf("UpdateSettings failed: %v", err)
	}

	// Test connection
	if err := svc.TestConnection(context.Background(), settings); err != nil {
		t.Fatalf("TestConnection failed: %v", err)
	}

	// Run backup
	res, err := svc.RunBackup(context.Background())
	if err != nil {
		t.Fatalf("RunBackup failed: %v", err)
	}

	if !res.Success {
		t.Errorf("Expected success, got false")
	}
	if res.SizeBytes <= 0 {
		t.Errorf("Expected backup file size > 0, got %d", res.SizeBytes)
	}

	destFile := filepath.Join(backupDir, res.Filename)
	if _, err := os.Stat(destFile); err != nil {
		t.Errorf("Expected backup file to exist at %s: %v", destFile, err)
	}
}
