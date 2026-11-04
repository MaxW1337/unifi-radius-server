package updater

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.1", -1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"1.0", "1.0.0", 0},
		{"1.2.3", "1.2", 1},
		{"1.2", "1.2.3", -1},
		{"v1.1.0", "1.0.0", 1},
		{"1.0.0-beta", "1.0.0", 0},
	}

	for _, tt := range tests {
		res := CompareVersions(tt.v1, tt.v2)
		if res != tt.expected {
			t.Errorf("CompareVersions(%q, %q) = %d; expected %d", tt.v1, tt.v2, res, tt.expected)
		}
	}
}

type roundTripFunc func(req *http.Request) *http.Response

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func TestUpdaterCheckWithMock(t *testing.T) {
	mockRelease := GitHubRelease{
		TagName:     "v1.2.0",
		Name:        "Release 1.2.0",
		HTMLURL:     "https://github.com/MaxW1337/unifi-radius-server/releases/tag/v1.2.0",
		Body:        "Bugfixes and performance improvements",
		PublishedAt: "2026-11-03T12:00:00Z",
	}

	mockBytes, _ := json.Marshal(mockRelease)

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewReader(mockBytes)),
			}
		}),
	}

	svc := &Service{
		repoOwner:      "test",
		repoName:       "repo",
		currentVersion: "1.0.0",
		httpClient:     client,
		cacheDuration:  1 * time.Minute,
	}

	info := svc.Check(true)
	if info.Error != "" {
		t.Fatalf("Unexpected error: %s", info.Error)
	}

	if !info.UpdateAvailable {
		t.Errorf("Expected update to be available (1.2.0 > 1.0.0)")
	}

	if info.LatestVersion != "1.2.0" {
		t.Errorf("Expected latest version 1.2.0, got %s", info.LatestVersion)
	}

	if info.ReleaseURL != mockRelease.HTMLURL {
		t.Errorf("Expected release URL %s, got %s", mockRelease.HTMLURL, info.ReleaseURL)
	}

	// Test caching: if we call Check(false), should return cached
	cached := svc.Check(false)
	if cached != info {
		t.Errorf("Expected cached result to match")
	}
}

func TestParseExpectedChecksum(t *testing.T) {
	checksums := `
# SHA-256 Checksums
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  unifi-radius-linux-arm64
a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e *unifi-radius-linux-amd64
4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865  unifi-radius-windows-amd64.exe
`
	hash, err := ParseExpectedChecksum(checksums, "unifi-radius-linux-arm64")
	if err != nil || hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("Failed to parse arm64 checksum: %v, got %s", err, hash)
	}

	hash, err = ParseExpectedChecksum(checksums, "unifi-radius-linux-amd64")
	if err != nil || hash != "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e" {
		t.Errorf("Failed to parse amd64 checksum: %v, got %s", err, hash)
	}

	_, err = ParseExpectedChecksum(checksums, "non-existent-file")
	if err == nil {
		t.Errorf("Expected error for non-existent file, got nil")
	}
}

func TestShouldTriggerAutoUpdate(t *testing.T) {
	// 2026-11-04 is a Wednesday (ISO weekday = 3, day of month = 4)
	fixedTime := time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC)

	// 1. Disabled
	disabledSettings := &models.Settings{
		AutoUpdateEnabled:  false,
		AutoUpdateSchedule: "daily",
		AutoUpdateTime:     "03:00",
	}
	if ShouldTriggerAutoUpdate(disabledSettings, fixedTime) {
		t.Error("Expected false when AutoUpdateEnabled is false")
	}

	// 2. Daily - correct time
	dailySettings := &models.Settings{
		AutoUpdateEnabled:  true,
		AutoUpdateSchedule: "daily",
		AutoUpdateTime:     "03:00",
	}
	if !ShouldTriggerAutoUpdate(dailySettings, fixedTime) {
		t.Error("Expected true for daily update at 03:00")
	}

	// 2b. Daily - wrong time
	wrongTime := time.Date(2026, 11, 4, 4, 0, 0, 0, time.UTC)
	if ShouldTriggerAutoUpdate(dailySettings, wrongTime) {
		t.Error("Expected false for daily update at wrong time")
	}

	// 3. Weekly - Wednesday is 3
	weeklyMatch := &models.Settings{
		AutoUpdateEnabled:  true,
		AutoUpdateSchedule: "weekly",
		AutoUpdateTime:     "03:00",
		AutoUpdateWeekday:  3, // Wednesday
	}
	if !ShouldTriggerAutoUpdate(weeklyMatch, fixedTime) {
		t.Error("Expected true for weekly update on Wednesday")
	}

	weeklyMismatch := &models.Settings{
		AutoUpdateEnabled:  true,
		AutoUpdateSchedule: "weekly",
		AutoUpdateTime:     "03:00",
		AutoUpdateWeekday:  1, // Monday
	}
	if ShouldTriggerAutoUpdate(weeklyMismatch, fixedTime) {
		t.Error("Expected false for weekly update on wrong weekday")
	}

	// 4. Monthly - day 4
	monthlyMatch := &models.Settings{
		AutoUpdateEnabled:  true,
		AutoUpdateSchedule: "monthly",
		AutoUpdateTime:     "03:00",
		AutoUpdateDay:      4,
	}
	if !ShouldTriggerAutoUpdate(monthlyMatch, fixedTime) {
		t.Error("Expected true for monthly update on day 4")
	}

	monthlyMismatch := &models.Settings{
		AutoUpdateEnabled:  true,
		AutoUpdateSchedule: "monthly",
		AutoUpdateTime:     "03:00",
		AutoUpdateDay:      1,
	}
	if ShouldTriggerAutoUpdate(monthlyMismatch, fixedTime) {
		t.Error("Expected false for monthly update on wrong day")
	}
}

func TestApplyUpdateWithMockServer(t *testing.T) {
	assetName, err := GetPlatformAssetName()
	if err != nil {
		t.Skipf("Skipping ApplyUpdate test on unsupported platform: %v", err)
	}

	// Create dummy binary content (must be >= 1024 bytes)
	dummyBinary := make([]byte, 2048)
	for i := range dummyBinary {
		dummyBinary[i] = byte(i % 256)
	}
	hasher := sha256.New()
	hasher.Write(dummyBinary)
	validHash := hex.EncodeToString(hasher.Sum(nil))

	checksumsContent := fmt.Sprintf("%s  %s\n", validHash, assetName)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/checksums.txt"):
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(checksumsContent))
		case strings.HasSuffix(r.URL.Path, "/"+assetName):
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(dummyBinary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Prepare dummy current executable in TempDir
	tempDir := t.TempDir()
	targetBinaryPath := filepath.Join(tempDir, "unifi-radius-current")
	if strings.HasSuffix(assetName, ".exe") {
		targetBinaryPath += ".exe"
	}
	if err := os.WriteFile(targetBinaryPath, []byte("original binary content"), 0755); err != nil {
		t.Fatalf("Failed to write initial target binary: %v", err)
	}

	svc := NewService("1.0.0", "testowner", "testrepo")
	svc.SetDownloadBaseURL(ts.URL)
	svc.SetTargetExecutablePath(targetBinaryPath)

	// Apply update to v1.0.5
	if err := svc.ApplyUpdate("1.0.5"); err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}

	// Verify target executable content was replaced with dummyBinary
	newContent, err := os.ReadFile(targetBinaryPath)
	if err != nil {
		t.Fatalf("Failed to read updated executable: %v", err)
	}
	if !bytes.Equal(newContent, dummyBinary) {
		t.Errorf("Updated binary content does not match expected payload")
	}
}

func TestApplyUpdateSecurityChecksumMismatch(t *testing.T) {
	assetName, err := GetPlatformAssetName()
	if err != nil {
		t.Skipf("Skipping ApplyUpdate test on unsupported platform: %v", err)
	}

	dummyBinary := make([]byte, 2048)
	checksumsContent := fmt.Sprintf("0000000000000000000000000000000000000000000000000000000000000000  %s\n", assetName)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/checksums.txt"):
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte(checksumsContent))
		case strings.HasSuffix(r.URL.Path, "/"+assetName):
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(dummyBinary)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	targetBinaryPath := filepath.Join(tempDir, "unifi-radius-current")
	if strings.HasSuffix(assetName, ".exe") {
		targetBinaryPath += ".exe"
	}
	_ = os.WriteFile(targetBinaryPath, []byte("original binary content"), 0755)

	svc := NewService("1.0.0", "testowner", "testrepo")
	svc.SetDownloadBaseURL(ts.URL)
	svc.SetTargetExecutablePath(targetBinaryPath)

	// Apply update should fail due to checksum mismatch
	err = svc.ApplyUpdate("1.0.5")
	if err == nil {
		t.Fatalf("Expected ApplyUpdate to fail on checksum mismatch, but it succeeded")
	}
	if !strings.Contains(err.Error(), "checksum verification failed") {
		t.Errorf("Expected checksum verification error, got: %v", err)
	}

	// Verify original file was preserved
	content, _ := os.ReadFile(targetBinaryPath)
	if string(content) != "original binary content" {
		t.Errorf("Original executable was tampered with despite failed checksum!")
	}
}
