package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// UpdateInfo holds the result of a version check against GitHub Releases.
type UpdateInfo struct {
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseURL      string    `json:"release_url"`
	ReleaseNotes    string    `json:"release_notes"`
	PublishedAt     string    `json:"published_at"`
	CheckedAt       time.Time `json:"checked_at"`
	Error           string    `json:"error,omitempty"`
}

// GitHubRelease represents the subset of GitHub Releases API response needed.
type GitHubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	HTMLURL     string `json:"html_url"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
}

// Service handles checking for new versions, self-updating, and background scheduling.
type Service struct {
	repoOwner            string
	repoName             string
	currentVersion       string
	apiBaseURL           string
	downloadBaseURL      string
	targetExecutablePath string // override for testing; if empty, uses os.Executable()
	httpClient           *http.Client
	downloadClient       *http.Client
	mu                   sync.RWMutex
	cached               *UpdateInfo
	cacheDuration        time.Duration
}

// NewService creates a new update checker and updater service.
func NewService(currentVersion string, repoOwner, repoName string) *Service {
	if repoOwner == "" {
		repoOwner = "MaxW1337"
	}
	if repoName == "" {
		repoName = "unifi-radius-server"
	}
	if currentVersion == "" {
		currentVersion = "1.0.4"
	}

	return &Service{
		repoOwner:       repoOwner,
		repoName:        repoName,
		currentVersion:  currentVersion,
		apiBaseURL:      "https://api.github.com",
		downloadBaseURL: "https://github.com",
		httpClient: &http.Client{
			Timeout: 6 * time.Second,
		},
		downloadClient: &http.Client{
			Timeout: 120 * time.Second,
		},
		cacheDuration: 1 * time.Hour,
	}
}

// SetAPIBaseURL overrides the GitHub API URL (useful for testing with httptest).
func (s *Service) SetAPIBaseURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiBaseURL = url
}

// SetDownloadBaseURL overrides the GitHub download URL (useful for testing with httptest).
func (s *Service) SetDownloadBaseURL(url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.downloadBaseURL = url
}

// SetTargetExecutablePath overrides the executable destination path (useful for testing).
func (s *Service) SetTargetExecutablePath(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.targetExecutablePath = p
}

// Check queries GitHub Releases or returns cached information.
func (s *Service) Check(force bool) *UpdateInfo {
	s.mu.RLock()
	if !force && s.cached != nil && time.Since(s.cached.CheckedAt) < s.cacheDuration {
		res := s.cached
		s.mu.RUnlock()
		return res
	}
	s.mu.RUnlock()

	baseURL := s.apiBaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", baseURL, s.repoOwner, s.repoName)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return &UpdateInfo{
			CurrentVersion: s.currentVersion,
			Error:          err.Error(),
			CheckedAt:      time.Now(),
		}
	}

	req.Header.Set("User-Agent", "UniFi-RADIUS-Server/"+s.currentVersion)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		info := &UpdateInfo{
			CurrentVersion: s.currentVersion,
			Error:          "Update-Server nicht erreichbar (Offline)",
			CheckedAt:      time.Now(),
		}
		s.setCache(info)
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info := &UpdateInfo{
			CurrentVersion: s.currentVersion,
			Error:          fmt.Sprintf("GitHub API Status: %d", resp.StatusCode),
			CheckedAt:      time.Now(),
		}
		s.setCache(info)
		return info
	}

	var ghRel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&ghRel); err != nil {
		info := &UpdateInfo{
			CurrentVersion: s.currentVersion,
			Error:          "Ungültige Server-Antwort",
			CheckedAt:      time.Now(),
		}
		s.setCache(info)
		return info
	}

	latestClean := strings.TrimPrefix(strings.TrimSpace(ghRel.TagName), "v")
	currentClean := strings.TrimPrefix(strings.TrimSpace(s.currentVersion), "v")

	isNewer := CompareVersions(latestClean, currentClean) > 0

	info := &UpdateInfo{
		CurrentVersion:  s.currentVersion,
		LatestVersion:   latestClean,
		UpdateAvailable: isNewer,
		ReleaseURL:      ghRel.HTMLURL,
		ReleaseNotes:    ghRel.Body,
		PublishedAt:     ghRel.PublishedAt,
		CheckedAt:       time.Now(),
	}

	s.setCache(info)
	return info
}

func (s *Service) setCache(info *UpdateInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = info
}

// GetPlatformAssetName returns the release binary filename for the current OS and CPU architecture.
func GetPlatformAssetName() (string, error) {
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "arm64":
			return "unifi-radius-linux-arm64", nil
		case "amd64":
			return "unifi-radius-linux-amd64", nil
		}
	case "windows":
		switch runtime.GOARCH {
		case "amd64":
			return "unifi-radius-windows-amd64.exe", nil
		}
	}
	return "", fmt.Errorf("unsupported platform for binary self-update: %s/%s", runtime.GOOS, runtime.GOARCH)
}

// ParseExpectedChecksum extracts the SHA256 checksum for the specified asset from checksums.txt.
func ParseExpectedChecksum(checksumsContent, assetName string) (string, error) {
	lines := strings.Split(checksumsContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			hash := fields[0]
			name := strings.TrimPrefix(fields[1], "*")
			if strings.EqualFold(name, assetName) {
				return strings.ToLower(hash), nil
			}
		}
	}
	return "", fmt.Errorf("checksum for %s not found in checksums.txt", assetName)
}

// ApplyUpdate downloads the release binary, verifies its SHA256 checksum, sets execute permissions,
// and atomically replaces the running executable.
func (s *Service) ApplyUpdate(targetVersion string) error {
	assetName, err := GetPlatformAssetName()
	if err != nil {
		return err
	}

	targetVersion = strings.TrimSpace(targetVersion)
	if targetVersion == "" {
		info := s.Check(true)
		if info.Error != "" {
			return fmt.Errorf("failed to check latest version: %s", info.Error)
		}
		if !info.UpdateAvailable || info.LatestVersion == "" {
			return errors.New("no newer version available to update to")
		}
		targetVersion = info.LatestVersion
	}

	tag := "v" + strings.TrimPrefix(targetVersion, "v")

	s.mu.RLock()
	downloadBase := s.downloadBaseURL
	execPath := s.targetExecutablePath
	s.mu.RUnlock()

	if downloadBase == "" {
		downloadBase = "https://github.com"
	}

	// 1. Fetch checksums.txt
	checksumsURL := fmt.Sprintf("%s/%s/%s/releases/download/%s/checksums.txt", downloadBase, s.repoOwner, s.repoName, tag)
	reqCheck, err := http.NewRequest(http.MethodGet, checksumsURL, nil)
	if err != nil {
		return err
	}
	reqCheck.Header.Set("User-Agent", "UniFi-RADIUS-Server/"+s.currentVersion)

	respCheck, err := s.downloadClient.Do(reqCheck)
	if err != nil {
		return fmt.Errorf("failed to download checksums: %w", err)
	}
	defer respCheck.Body.Close()

	if respCheck.StatusCode != http.StatusOK {
		return fmt.Errorf("checksums download returned HTTP %d", respCheck.StatusCode)
	}

	checksumBytes, err := io.ReadAll(io.LimitReader(respCheck.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("failed to read checksums: %w", err)
	}

	expectedHash, err := ParseExpectedChecksum(string(checksumBytes), assetName)
	if err != nil {
		return err
	}

	// 2. Locate destination executable path
	if execPath == "" {
		p, err := os.Executable()
		if err != nil {
			return fmt.Errorf("cannot determine executable path: %w", err)
		}
		p, err = filepath.EvalSymlinks(p)
		if err != nil {
			return fmt.Errorf("cannot resolve symlinks for executable: %w", err)
		}
		execPath = p
	}

	execDir := filepath.Dir(execPath)

	// 3. Download asset into temporary file on the same filesystem/directory
	assetURL := fmt.Sprintf("%s/%s/%s/releases/download/%s/%s", downloadBase, s.repoOwner, s.repoName, tag, assetName)
	reqAsset, err := http.NewRequest(http.MethodGet, assetURL, nil)
	if err != nil {
		return err
	}
	reqAsset.Header.Set("User-Agent", "UniFi-RADIUS-Server/"+s.currentVersion)

	respAsset, err := s.downloadClient.Do(reqAsset)
	if err != nil {
		return fmt.Errorf("failed to download release binary: %w", err)
	}
	defer respAsset.Body.Close()

	if respAsset.StatusCode != http.StatusOK {
		return fmt.Errorf("binary download returned HTTP %d", respAsset.StatusCode)
	}

	tmpFile, err := os.CreateTemp(execDir, "unifi-radius-update-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file in %s: %w", execDir, err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	// Max 100 MB stream cap
	n, err := io.Copy(writer, io.LimitReader(respAsset.Body, 100*1024*1024))
	if err != nil {
		return fmt.Errorf("failed to stream binary: %w", err)
	}
	if n < 1024 {
		return fmt.Errorf("downloaded binary is too small (%d bytes)", n)
	}

	_ = tmpFile.Sync()
	_ = tmpFile.Close()

	actualHash := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualHash, expectedHash) {
		return fmt.Errorf("checksum verification failed: expected %s, got %s", expectedHash, actualHash)
	}

	// 4. Set executable permissions on Unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, 0755); err != nil {
			return fmt.Errorf("failed to set chmod 0755: %w", err)
		}
	}

	// 5. Replace binary
	if runtime.GOOS == "windows" {
		oldPath := execPath + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(execPath, oldPath); err != nil {
			return fmt.Errorf("failed to move old executable on Windows: %w", err)
		}
		if err := os.Rename(tmpPath, execPath); err != nil {
			// Rollback if replacement failed
			_ = os.Rename(oldPath, execPath)
			return fmt.Errorf("failed to install new executable on Windows: %w", err)
		}
	} else {
		if err := os.Rename(tmpPath, execPath); err != nil {
			return fmt.Errorf("failed to replace executable: %w", err)
		}
	}

	return nil
}

// TriggerRestart restarts the server process after a short delay so the HTTP response is completed.
func (s *Service) TriggerRestart() {
	go func() {
		time.Sleep(1500 * time.Millisecond)
		if runtime.GOOS == "linux" {
			_ = exec.Command("systemctl", "restart", "unifi-radius").Run()
		}
		os.Exit(0)
	}()
}

// ShouldTriggerAutoUpdate evaluates if the current time matches the scheduled auto-update window.
func ShouldTriggerAutoUpdate(s *models.Settings, now time.Time) bool {
	if s == nil || !s.AutoUpdateEnabled {
		return false
	}

	schedTime := strings.TrimSpace(s.AutoUpdateTime)
	if schedTime == "" {
		schedTime = "03:00"
	}

	currentTimeStr := now.Format("15:04")
	if currentTimeStr != schedTime {
		return false
	}

	switch s.AutoUpdateSchedule {
	case "daily":
		return true
	case "weekly":
		weekday := s.AutoUpdateWeekday
		if weekday < 1 || weekday > 7 {
			weekday = 1
		}
		return currentISOWeekday(now) == weekday
	case "monthly":
		day := s.AutoUpdateDay
		if day < 1 || day > 31 {
			day = 1
		}
		return now.Day() == day
	default:
		return false
	}
}

func currentISOWeekday(t time.Time) int {
	w := int(t.Weekday())
	if w == 0 {
		return 7 // Sunday
	}
	return w
}

// StartAutoScheduler starts the background ticker that checks and executes scheduled auto-updates.
func (s *Service) StartAutoScheduler(ctx context.Context, getSettings func() (*models.Settings, error), onUpdateApplied func(newVersion string)) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	var lastTriggeredMinute string

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			currentMinute := now.Format("2006-01-02 15:04")
			if currentMinute == lastTriggeredMinute {
				continue
			}

			settings, err := getSettings()
			if err != nil || settings == nil {
				continue
			}

			if ShouldTriggerAutoUpdate(settings, now) {
				lastTriggeredMinute = currentMinute

				// Check if update is available
				info := s.Check(true)
				if info != nil && info.UpdateAvailable && info.LatestVersion != "" {
					if err := s.ApplyUpdate(info.LatestVersion); err == nil {
						if onUpdateApplied != nil {
							onUpdateApplied(info.LatestVersion)
						}
						s.TriggerRestart()
						return
					}
				}
			}
		}
	}
}

// CompareVersions compares two semver strings (e.g. "1.1.0" vs "1.0.0").
// Returns:
//
//	 1 if v1 > v2
//	-1 if v1 < v2
//	 0 if v1 == v2
func CompareVersions(v1, v2 string) int {
	parts1 := parseVersionParts(v1)
	parts2 := parseVersionParts(v2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		p1 := 0
		p2 := 0
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		if p1 > p2 {
			return 1
		}
		if p1 < p2 {
			return -1
		}
	}

	return 0
}

func parseVersionParts(v string) []int {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "V")

	// Strip anything after '-' or '+' (e.g. -beta, +build)
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
		v = v[:idx]
	}

	segments := strings.Split(v, ".")
	var parts []int
	for _, seg := range segments {
		num, err := strconv.Atoi(strings.TrimSpace(seg))
		if err == nil {
			parts = append(parts, num)
		} else {
			parts = append(parts, 0)
		}
	}
	return parts
}
