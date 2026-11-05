package radius

import (
	"context"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

type lastSeenItem struct {
	clientID  int64
	timestamp time.Time
}

// BatchWriter buffers database writes (auth logs, last seen timestamps, pending clients)
// and flushes them in bulk transactions to eliminate SQLite write contention.
type BatchWriter struct {
	db            *database.DB
	logQueue      chan *models.AuthLog
	lastSeenQueue chan lastSeenItem
	pendingQueue  chan *models.Client
	stopChan      chan struct{}
	wg            sync.WaitGroup
}

// NewBatchWriter initializes the asynchronous batch writer.
func NewBatchWriter(db *database.DB) *BatchWriter {
	return &BatchWriter{
		db:            db,
		logQueue:      make(chan *models.AuthLog, 10000),
		lastSeenQueue: make(chan lastSeenItem, 10000),
		pendingQueue:  make(chan *models.Client, 2000),
		stopChan:      make(chan struct{}),
	}
}

// EnqueueLog non-blockingly queues an audit log for batch insertion.
func (bw *BatchWriter) EnqueueLog(l *models.AuthLog) {
	select {
	case bw.logQueue <- l:
	default:
		// Queue full under extreme load, drop oldest or discard to keep RADIUS responder fast
	}
}

// EnqueueLastSeen non-blockingly queues a client last-seen timestamp update.
func (bw *BatchWriter) EnqueueLastSeen(clientID int64, t time.Time) {
	select {
	case bw.lastSeenQueue <- lastSeenItem{clientID: clientID, timestamp: t}:
	default:
	}
}

// EnqueuePendingClient queues an auto-discovered MAB client for database creation.
func (bw *BatchWriter) EnqueuePendingClient(c *models.Client) {
	select {
	case bw.pendingQueue <- c:
	default:
	}
}

// Start spawns the background batch flushing loop.
func (bw *BatchWriter) Start(ctx context.Context) {
	bw.wg.Add(1)
	go func() {
		defer bw.wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var logBatch []*models.AuthLog
		lastSeenBatch := make(map[int64]time.Time)
		var pendingBatch []*models.Client

		flush := func() {
			if len(logBatch) > 0 {
				bw.flushLogs(logBatch)
				logBatch = logBatch[:0]
			}
			if len(lastSeenBatch) > 0 {
				bw.flushLastSeen(lastSeenBatch)
				lastSeenBatch = make(map[int64]time.Time)
			}
			if len(pendingBatch) > 0 {
				bw.flushPending(pendingBatch)
				pendingBatch = pendingBatch[:0]
			}
		}

		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case <-bw.stopChan:
				flush()
				return

			case l := <-bw.logQueue:
				logBatch = append(logBatch, l)
				if len(logBatch) >= 100 {
					flush()
				}

			case ls := <-bw.lastSeenQueue:
				// Deduplicate updates by client ID
				lastSeenBatch[ls.clientID] = ls.timestamp
				if len(lastSeenBatch) >= 100 {
					flush()
				}

			case p := <-bw.pendingQueue:
				pendingBatch = append(pendingBatch, p)
				if len(pendingBatch) >= 50 {
					flush()
				}

			case <-ticker.C:
				if len(logBatch) > 0 || len(lastSeenBatch) > 0 || len(pendingBatch) > 0 {
					flush()
				}
			}
		}
	}()
}

// Stop cleanly terminates and flushes all queued items.
func (bw *BatchWriter) Stop() {
	select {
	case <-bw.stopChan:
		return
	default:
		close(bw.stopChan)
	}
	bw.wg.Wait()
}

func (bw *BatchWriter) flushLogs(batch []*models.AuthLog) {
	tx, err := bw.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO auth_logs (
			timestamp, client_mac, username, nas_ip, nas_port, nas_name, auth_type,
			status, vlan_id, reason, latency_ms, enriched_name, enriched_vendor,
			raw_request, raw_response
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return
	}
	defer stmt.Close()

	for _, l := range batch {
		_, _ = stmt.Exec(
			l.Timestamp.UTC(), l.ClientMAC, l.Username, l.NASIP, l.NASPort, l.NASName, string(l.AuthType),
			l.Status, l.VLANID, l.Reason, l.LatencyMS, l.EnrichedName, l.EnrichedVendor,
			l.RawRequest, l.RawResponse,
		)
	}

	_ = tx.Commit()
}

func (bw *BatchWriter) flushLastSeen(batch map[int64]time.Time) {
	tx, err := bw.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("UPDATE clients SET last_seen_at = ?, updated_at = ? WHERE id = ?")
	if err != nil {
		return
	}
	defer stmt.Close()

	now := time.Now().UTC()
	for clientID, ts := range batch {
		_, _ = stmt.Exec(ts.UTC(), now, clientID)
	}

	_ = tx.Commit()
}

func (bw *BatchWriter) flushPending(batch []*models.Client) {
	for _, c := range batch {
		if c.MACAddress != "" {
			_, _ = bw.db.UpsertPendingMABClient(c.MACAddress, *c.VLANID, c.UniFiName, c.UniFiVendor)
		}
	}
}
