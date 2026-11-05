package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsRegistry(t *testing.T) {
	reg := NewRegistry()

	// Record sample requests
	reg.RecordRadiusRequest("mab", "Accept", 0.002)
	reg.RecordRadiusRequest("eap-tls", "Accept", 0.015)
	reg.RecordRadiusRequest("pap", "Reject", 0.005)
	reg.RecordCacheHit()
	reg.RecordCacheHit()
	reg.RecordCacheMiss()
	reg.RecordUniFiSync(true, 0.42)
	reg.RecordUniFiSync(false, 1.25)

	var buf bytes.Buffer
	err := reg.WritePrometheus(&buf, nil)
	if err != nil {
		t.Fatalf("WritePrometheus failed: %v", err)
	}

	out := buf.String()

	// Assertions on prometheus output
	expectedSubstrings := []string{
		"unifi_radius_build_info{",
		"unifi_radius_uptime_seconds",
		"radius_requests_total{type=\"Access-Request\",code=\"Accept\"} 2",
		"radius_requests_total{type=\"Access-Request\",code=\"Reject\"} 1",
		"radius_auth_methods_total{method=\"mab\"} 1",
		"radius_auth_methods_total{method=\"eap-tls\"} 1",
		"radius_auth_methods_total{method=\"pap\"} 1",
		"radius_cache_hits_total 2",
		"radius_cache_misses_total 1",
		"unifi_sync_duration_seconds",
		"unifi_sync_errors_total 1",
		"radius_request_duration_seconds_bucket",
		"radius_request_duration_seconds_count 3",
	}

	for _, sub := range expectedSubstrings {
		if !strings.Contains(out, sub) {
			t.Errorf("Expected prometheus output to contain %q, but was missing.\nOutput:\n%s", sub, out)
		}
	}
}

func TestMetricsHTTPHandler(t *testing.T) {
	reg := NewRegistry()
	reg.RecordRadiusRequest("mab", "Accept", 0.001)

	handler := reg.Handler(nil)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	contentType := rr.Header().Get("Content-Type")
	if !strings.Contains(contentType, "text/plain") {
		t.Errorf("Expected Content-Type text/plain, got %q", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "radius_requests_total") {
		t.Errorf("Expected body to contain radius_requests_total, got %s", body)
	}
}
