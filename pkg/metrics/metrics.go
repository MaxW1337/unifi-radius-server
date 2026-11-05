package metrics

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/version"
)

var (
	// DefaultDurationBuckets covers typical RADIUS processing times from < 1ms to 1s.
	DefaultDurationBuckets = []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0}
)

// Registry collects internal server and RADIUS runtime metrics.
type Registry struct {
	startTime time.Time

	// RADIUS Request counters
	requestsAccept uint64
	requestsReject uint64

	// Auth method counters
	authMAB    uint64
	authEAPTLS uint64
	authPAP    uint64
	authOther  uint64

	// Latency Histogram
	mu           sync.RWMutex
	bucketCounts []uint64
	durationSum  float64
	durationCnt  uint64

	// Cache counters
	cacheHits   uint64
	cacheMisses uint64

	// UniFi Sync stats
	syncSuccessTimestamp int64 // unix seconds
	syncDurationSeconds  float64
	syncErrors           uint64
}

// Global default registry instance
var DefaultRegistry = NewRegistry()

// NewRegistry initializes an empty metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		startTime:    time.Now(),
		bucketCounts: make([]uint64, len(DefaultDurationBuckets)),
	}
}

// RecordRadiusRequest records a processed RADIUS request with method, status and duration.
func (r *Registry) RecordRadiusRequest(authType string, code string, durationSec float64) {
	if code == "Accept" {
		atomic.AddUint64(&r.requestsAccept, 1)
	} else {
		atomic.AddUint64(&r.requestsReject, 1)
	}

	switch authType {
	case "mab":
		atomic.AddUint64(&r.authMAB, 1)
	case "eap-tls":
		atomic.AddUint64(&r.authEAPTLS, 1)
	case "pap":
		atomic.AddUint64(&r.authPAP, 1)
	default:
		atomic.AddUint64(&r.authOther, 1)
	}

	r.mu.Lock()
	r.durationSum += durationSec
	r.durationCnt++
	for i, le := range DefaultDurationBuckets {
		if durationSec <= le {
			r.bucketCounts[i]++
		}
	}
	r.mu.Unlock()
}

// RecordCacheHit increments the RAM cache hit counter.
func (r *Registry) RecordCacheHit() {
	atomic.AddUint64(&r.cacheHits, 1)
}

// RecordCacheMiss increments the RAM cache miss counter.
func (r *Registry) RecordCacheMiss() {
	atomic.AddUint64(&r.cacheMisses, 1)
}

// RecordUniFiSync records the result and duration of a UniFi controller sync cycle.
func (r *Registry) RecordUniFiSync(success bool, durationSec float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncDurationSeconds = durationSec
	if success {
		r.syncSuccessTimestamp = time.Now().Unix()
	} else {
		r.syncErrors++
	}
}

// WritePrometheus writes all collected metrics in standard Prometheus exposition format.
func (r *Registry) WritePrometheus(w io.Writer, db *database.DB) error {
	uptime := time.Since(r.startTime).Seconds()

	// 1. Server Build Info & Uptime
	fmt.Fprintf(w, "# HELP unifi_radius_build_info Build and version metadata.\n")
	fmt.Fprintf(w, "# TYPE unifi_radius_build_info gauge\n")
	fmt.Fprintf(w, "unifi_radius_build_info{version=%q,commit=%q,build_date=%q,go_version=%q,os=%q,arch=%q} 1\n",
		version.Version, version.GitCommit, version.BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)

	fmt.Fprintf(w, "# HELP unifi_radius_uptime_seconds Total runtime of the server in seconds.\n")
	fmt.Fprintf(w, "# TYPE unifi_radius_uptime_seconds gauge\n")
	fmt.Fprintf(w, "unifi_radius_uptime_seconds %.1f\n", uptime)

	// 2. RADIUS Requests
	accepts := atomic.LoadUint64(&r.requestsAccept)
	rejects := atomic.LoadUint64(&r.requestsReject)
	fmt.Fprintf(w, "# HELP radius_requests_total Total number of RADIUS requests processed.\n")
	fmt.Fprintf(w, "# TYPE radius_requests_total counter\n")
	fmt.Fprintf(w, "radius_requests_total{type=\"Access-Request\",code=\"Accept\"} %d\n", accepts)
	fmt.Fprintf(w, "radius_requests_total{type=\"Access-Request\",code=\"Reject\"} %d\n", rejects)

	// 3. Auth Methods
	fmt.Fprintf(w, "# HELP radius_auth_methods_total Total authentication attempts grouped by method.\n")
	fmt.Fprintf(w, "# TYPE radius_auth_methods_total counter\n")
	fmt.Fprintf(w, "radius_auth_methods_total{method=\"mab\"} %d\n", atomic.LoadUint64(&r.authMAB))
	fmt.Fprintf(w, "radius_auth_methods_total{method=\"eap-tls\"} %d\n", atomic.LoadUint64(&r.authEAPTLS))
	fmt.Fprintf(w, "radius_auth_methods_total{method=\"pap\"} %d\n", atomic.LoadUint64(&r.authPAP))
	fmt.Fprintf(w, "radius_auth_methods_total{method=\"other\"} %d\n", atomic.LoadUint64(&r.authOther))

	// 4. Request Duration Histogram
	r.mu.RLock()
	dSum := r.durationSum
	dCnt := r.durationCnt
	bCounts := make([]uint64, len(r.bucketCounts))
	copy(bCounts, r.bucketCounts)
	r.mu.RUnlock()

	fmt.Fprintf(w, "# HELP radius_request_duration_seconds Processing duration for RADIUS requests in seconds.\n")
	fmt.Fprintf(w, "# TYPE radius_request_duration_seconds histogram\n")
	for i, le := range DefaultDurationBuckets {
		fmt.Fprintf(w, "radius_request_duration_seconds_bucket{le=\"%g\"} %d\n", le, bCounts[i])
	}
	fmt.Fprintf(w, "radius_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", dCnt)
	fmt.Fprintf(w, "radius_request_duration_seconds_sum %f\n", dSum)
	fmt.Fprintf(w, "radius_request_duration_seconds_count %d\n", dCnt)

	// 5. Cache Stats
	fmt.Fprintf(w, "# HELP radius_cache_hits_total Total RAM cache hits.\n")
	fmt.Fprintf(w, "# TYPE radius_cache_hits_total counter\n")
	fmt.Fprintf(w, "radius_cache_hits_total %d\n", atomic.LoadUint64(&r.cacheHits))
	fmt.Fprintf(w, "# HELP radius_cache_misses_total Total RAM cache misses.\n")
	fmt.Fprintf(w, "# TYPE radius_cache_misses_total counter\n")
	fmt.Fprintf(w, "radius_cache_misses_total %d\n", atomic.LoadUint64(&r.cacheMisses))

	// 6. UniFi Sync Metrics
	r.mu.RLock()
	syncLast := r.syncSuccessTimestamp
	syncDur := r.syncDurationSeconds
	syncErrs := r.syncErrors
	r.mu.RUnlock()

	fmt.Fprintf(w, "# HELP unifi_sync_success_timestamp_seconds Unix timestamp of last successful UniFi sync.\n")
	fmt.Fprintf(w, "# TYPE unifi_sync_success_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "unifi_sync_success_timestamp_seconds %d\n", syncLast)

	fmt.Fprintf(w, "# HELP unifi_sync_duration_seconds Duration of last UniFi sync in seconds.\n")
	fmt.Fprintf(w, "# TYPE unifi_sync_duration_seconds gauge\n")
	fmt.Fprintf(w, "unifi_sync_duration_seconds %.3f\n", syncDur)

	fmt.Fprintf(w, "# HELP unifi_sync_errors_total Total errors encountered during UniFi sync.\n")
	fmt.Fprintf(w, "# TYPE unifi_sync_errors_total counter\n")
	fmt.Fprintf(w, "unifi_sync_errors_total %d\n", syncErrs)

	// 7. Database Entity Counts (Clients & Logs)
	if db != nil {
		counts, err := db.GetEntityCounts()
		if err == nil {
			fmt.Fprintf(w, "# HELP radius_clients_total Total configured network clients by status.\n")
			fmt.Fprintf(w, "# TYPE radius_clients_total gauge\n")
			fmt.Fprintf(w, "radius_clients_total{status=\"active\"} %d\n", counts.ClientsActive)
			fmt.Fprintf(w, "radius_clients_total{status=\"pending\"} %d\n", counts.ClientsPending)
			fmt.Fprintf(w, "radius_clients_total{status=\"disabled\"} %d\n", counts.ClientsDisabled)

			fmt.Fprintf(w, "# HELP radius_auth_logs_total Total persisted RADIUS authentication logs.\n")
			fmt.Fprintf(w, "# TYPE radius_auth_logs_total gauge\n")
			fmt.Fprintf(w, "radius_auth_logs_total %d\n", counts.TotalAuthLogs)

			fmt.Fprintf(w, "# HELP radius_system_logs_total Total persisted system and event logs.\n")
			fmt.Fprintf(w, "# TYPE radius_system_logs_total gauge\n")
			fmt.Fprintf(w, "radius_system_logs_total %d\n", counts.TotalSystemLogs)
		}
	}

	return nil
}

// Handler returns an unauthenticated standard Prometheus HTTP handler function.
func (r *Registry) Handler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WritePrometheus(w, db)
	}
}

// Helper funcs delegating to DefaultRegistry

// RecordRadiusRequest records a RADIUS request on the default registry.
func RecordRadiusRequest(authType string, code string, durationSec float64) {
	DefaultRegistry.RecordRadiusRequest(authType, code, durationSec)
}

// RecordCacheHit increments the default registry's cache hit counter.
func RecordCacheHit() {
	DefaultRegistry.RecordCacheHit()
}

// RecordCacheMiss increments the default registry's cache miss counter.
func RecordCacheMiss() {
	DefaultRegistry.RecordCacheMiss()
}

// RecordUniFiSync records UniFi sync stats on the default registry.
func RecordUniFiSync(success bool, durationSec float64) {
	DefaultRegistry.RecordUniFiSync(success, durationSec)
}

// Handler returns an HTTP handler for the default registry.
func Handler(db *database.DB) http.HandlerFunc {
	return DefaultRegistry.Handler(db)
}
