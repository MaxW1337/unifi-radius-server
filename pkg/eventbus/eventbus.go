package eventbus

import (
	"sync"

	"github.com/mwittenburg/unifi-radius-server/pkg/models"
)

// LogLevel defines the severity of a system log message.
type LogLevel string

const (
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
	LogLevelDebug LogLevel = "DEBUG"
)

// LogEvent represents an entry streamed to the live log console.
type LogEvent struct {
	Timestamp string   `json:"timestamp"`
	Level     LogLevel `json:"level"`
	Source    string   `json:"source"`
	Message   string   `json:"message"`
}

// Bus provides publish-subscribe capabilities for real-time WebSocket clients.
type Bus struct {
	mu           sync.RWMutex
	authSubChan  map[chan models.AuthLog]struct{}
	logSubChan   map[chan LogEvent]struct{}
	recentLogs   []LogEvent
	maxLogBuffer int
}

var DefaultBus = NewBus(200)

// NewBus creates an initialized EventBus.
func NewBus(maxLogBuffer int) *Bus {
	if maxLogBuffer <= 0 {
		maxLogBuffer = 200
	}
	return &Bus{
		authSubChan:  make(map[chan models.AuthLog]struct{}),
		logSubChan:   make(map[chan LogEvent]struct{}),
		recentLogs:   make([]LogEvent, 0, maxLogBuffer),
		maxLogBuffer: maxLogBuffer,
	}
}

// SubscribeAuth registers a subscriber channel for RADIUS authentication events.
func (b *Bus) SubscribeAuth() (chan models.AuthLog, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan models.AuthLog, 64)
	b.authSubChan[ch] = struct{}{}

	unsubscribe := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.authSubChan, ch)
		close(ch)
	}

	return ch, unsubscribe
}

// SubscribeLogs registers a subscriber channel for live system logs.
func (b *Bus) SubscribeLogs() (chan LogEvent, []LogEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan LogEvent, 64)
	b.logSubChan[ch] = struct{}{}

	// Make copy of recent logs for replay on connect
	replay := make([]LogEvent, len(b.recentLogs))
	copy(replay, b.recentLogs)

	unsubscribe := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.logSubChan, ch)
		close(ch)
	}

	return ch, replay, unsubscribe
}

// PublishAuth broadcasts an authentication attempt to all active listeners.
func (b *Bus) PublishAuth(event models.AuthLog) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.authSubChan {
		select {
		case ch <- event:
		default:
			// Non-blocking drop if subscriber is too slow
		}
	}
}

// PublishLog broadcasts a log line and keeps it in the ring buffer.
func (b *Bus) PublishLog(event LogEvent) {
	b.mu.Lock()
	if len(b.recentLogs) >= b.maxLogBuffer {
		b.recentLogs = b.recentLogs[1:]
	}
	b.recentLogs = append(b.recentLogs, event)
	b.mu.Unlock()

	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.logSubChan {
		select {
		case ch <- event:
		default:
		}
	}
}

