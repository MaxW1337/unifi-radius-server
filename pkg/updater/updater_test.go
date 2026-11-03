package updater

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
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
		HTMLURL:     "https://github.com/mwittenburg/unifi-radius-server/releases/tag/v1.2.0",
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
