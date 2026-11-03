package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
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

// Service handles checking for new versions and caching the response.
type Service struct {
	repoOwner      string
	repoName       string
	currentVersion string
	apiBaseURL     string
	httpClient     *http.Client
	mu             sync.RWMutex
	cached         *UpdateInfo
	cacheDuration  time.Duration
}

// NewService creates a new update checker service.
func NewService(currentVersion string, repoOwner, repoName string) *Service {
	if repoOwner == "" {
		repoOwner = "mwittenburg"
	}
	if repoName == "" {
		repoName = "unifi-radius-server"
	}
	if currentVersion == "" {
		currentVersion = "1.0.0"
	}

	return &Service{
		repoOwner:      repoOwner,
		repoName:       repoName,
		currentVersion: currentVersion,
		apiBaseURL:     "https://api.github.com",
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
		cacheDuration: 1 * time.Hour,
	}
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

// CompareVersions compares two semver strings (e.g. "1.1.0" vs "1.0.0").
// Returns:
//   1 if v1 > v2
//  -1 if v1 < v2
//   0 if v1 == v2
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
