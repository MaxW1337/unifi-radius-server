package notify

import (
	"sync"
	"time"
)

// Deduplicator prevents notification flooding and alert storms.
type Deduplicator struct {
	mu       sync.Mutex
	history  map[string]time.Time
	cooldown time.Duration
}

// NewDeduplicator creates a rate limiter with a specified cooldown window.
func NewDeduplicator(cooldown time.Duration) *Deduplicator {
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	return &Deduplicator{
		history:  make(map[string]time.Time),
		cooldown: cooldown,
	}
}

// ShouldSend checks whether an alert for the given key should be dispatched.
// If it should, it updates the timestamp and returns true. If within cooldown, it returns false.
func (d *Deduplicator) ShouldSend(key string) bool {
	if key == "" {
		return true
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	// Periodic cleanup of entries older than cooldown
	for k, lastTime := range d.history {
		if now.Sub(lastTime) > d.cooldown {
			delete(d.history, k)
		}
	}

	lastTime, exists := d.history[key]
	if exists && now.Sub(lastTime) < d.cooldown {
		return false
	}

	d.history[key] = now
	return true
}

