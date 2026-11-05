package database

import (
	"testing"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

func TestSystemLogsOperations(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()

	// 1. Insert single system log
	log1 := &models.SystemLog{
		Timestamp: now.Add(-30 * time.Minute),
		Level:     "INFO",
		Source:    "RADIUS",
		Message:   "RADIUS UDP service started on port 1812",
	}
	if err := db.InsertSystemLog(log1); err != nil {
		t.Fatalf("InsertSystemLog failed: %v", err)
	}
	if log1.ID == 0 {
		t.Errorf("Expected assigned ID > 0, got %d", log1.ID)
	}

	// 2. Insert batch of logs
	batch := []models.SystemLog{
		{
			Timestamp: now.Add(-20 * time.Minute),
			Level:     "WARN",
			Source:    "UNIFI-SYNC",
			Message:   "Controller connection timeout on 192.168.1.1",
		},
		{
			Timestamp: now.Add(-10 * time.Minute),
			Level:     "ERROR",
			Source:    "BACKUP",
			Message:   "S3 upload failed: bucket unreachable",
		},
		{
			Timestamp: now.Add(-5 * time.Minute),
			Level:     "DEBUG",
			Source:    "RADIUS-RAW",
			Message:   "<<< RECV Access-Request ID: 12",
		},
		{
			Timestamp: now,
			Level:     "INFO",
			Source:    "WEB",
			Message:   "Admin logged in from 192.168.1.50",
		},
	}
	if err := db.InsertSystemLogsBatch(batch); err != nil {
		t.Fatalf("InsertSystemLogsBatch failed: %v", err)
	}

	// 3. List all system logs
	allLogs, total, err := db.ListSystemLogs(10, 0, "", "", "", nil, nil)
	if err != nil || total != 5 || len(allLogs) != 5 {
		t.Fatalf("ListSystemLogs (all) failed: total=%d, len=%d, err=%v", total, len(allLogs), err)
	}

	// 4. Filter by Level
	warnLogs, totalWarn, err := db.ListSystemLogs(10, 0, "WARN", "", "", nil, nil)
	if err != nil || totalWarn != 1 || len(warnLogs) != 1 {
		t.Errorf("Filter by level WARN failed: total=%d, len=%d", totalWarn, len(warnLogs))
	}

	// 5. Filter by Source
	syncLogs, totalSync, err := db.ListSystemLogs(10, 0, "", "UNIFI-SYNC", "", nil, nil)
	if err != nil || totalSync != 1 || len(syncLogs) != 1 {
		t.Errorf("Filter by source UNIFI-SYNC failed: total=%d, len=%d", totalSync, len(syncLogs))
	}

	// 6. Filter by Query
	s3Logs, totalS3, err := db.ListSystemLogs(10, 0, "", "", "bucket", nil, nil)
	if err != nil || totalS3 != 1 || len(s3Logs) != 1 {
		t.Errorf("Filter by query 'bucket' failed: total=%d, len=%d", totalS3, len(s3Logs))
	}

	// 7. Filter by Time Range (Relative/Absolute)
	// Last 8 minutes should match only: RADIUS-RAW (-5 min), WEB (now)
	from8m := now.Add(-8 * time.Minute)
	recentLogs, totalRecent, err := db.ListSystemLogs(10, 0, "", "", "", &from8m, nil)
	if err != nil || totalRecent != 2 || len(recentLogs) != 2 {
		t.Errorf("Filter by time range (last 8m) failed: total=%d, len=%d", totalRecent, len(recentLogs))
	}

	// Between -25m and -5m should match: UNIFI-SYNC (-20m), BACKUP (-10m), RADIUS-RAW (-5m)
	from25m := now.Add(-25 * time.Minute)
	to5m := now.Add(-5 * time.Minute)
	rangeLogs, totalRange, err := db.ListSystemLogs(10, 0, "", "", "", &from25m, &to5m)
	if err != nil || totalRange != 3 || len(rangeLogs) != 3 {
		t.Errorf("Filter by bounded time range failed: total=%d, len=%d", totalRange, len(rangeLogs))
	}

	// 8. Test distinct sources
	sources, err := db.GetDistinctSystemLogSources()
	if err != nil || len(sources) != 5 {
		t.Errorf("GetDistinctSystemLogSources failed: sources=%v, len=%d, err=%v", sources, len(sources), err)
	}

	// 9. Pruning
	pruned, err := db.PruneSystemLogs(1, 3) // trim to max 3 entries
	if err != nil {
		t.Fatalf("PruneSystemLogs failed: %v", err)
	}
	if pruned != 2 {
		t.Errorf("Expected 2 entries pruned to reach max 3, got %d", pruned)
	}

	remaining, totalRemaining, err := db.ListSystemLogs(10, 0, "", "", "", nil, nil)
	if err != nil || totalRemaining != 3 || len(remaining) != 3 {
		t.Errorf("Expected 3 remaining logs after pruning, got %d", totalRemaining)
	}
}
