package lk

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Event is emitted by Monitor on each Check tick.
type Event interface{ event() }

type ExpiringSoon struct{ Until time.Duration }
type Expired struct{ Err error }
type ClockAnomaly struct{ DetectedAt time.Time }

// SeatLost is emitted when a heartbeat is rejected because the machine is
// no longer activated or the seat limit was exceeded — the app should
// re-Activate.
type SeatLost struct{ Err error }

func (ExpiringSoon) event() {}
func (Expired) event()      {}
func (ClockAnomaly) event() {}
func (SeatLost) event()     {}

// Monitor wraps a License and periodically re-checks it from a
// background goroutine. Long-running servers SHOULD use Monitor
// (or call Check manually) — without periodic re-check, license
// expiry goes undetected until next process restart.
type Monitor struct {
	lic      License
	interval time.Duration
	logger   *slog.Logger
}

// MonitorOption configures a Monitor.
type MonitorOption func(*Monitor)

// WithInterval sets the Check cadence (default 1h). Shorter
// intervals catch expiry faster at the cost of more disk I/O on
// the watermark sidecar (throttled to at most 1 write/hour
// regardless of Check frequency).
func WithInterval(d time.Duration) MonitorOption {
	return func(m *Monitor) { m.interval = d }
}

// WithEventLogger overrides the slog handler used for internal
// Monitor warnings (not the events themselves — those flow through
// the event channel).
func WithEventLogger(l *slog.Logger) MonitorOption {
	return func(m *Monitor) { m.logger = l }
}

// NewMonitor constructs a Monitor with default interval 1h. Apply
// MonitorOptions to override.
func NewMonitor(lic License, opts ...MonitorOption) *Monitor {
	m := &Monitor{
		lic:      lic,
		interval: 1 * time.Hour,
		logger:   slog.Default(),
	}
	for _, fn := range opts {
		fn(m)
	}
	return m
}

// Start spawns a goroutine that wakes every interval, calls
// lic.Check(), emits events. The returned channel is closed when
// ctx is cancelled.
//
// Events:
//
//	Expired      — Check returned ErrExpired (license TTL passed)
//	ClockAnomaly — Check returned ErrClockAnomaly (sidecar last_seen > now)
//	ExpiringSoon — Check OK, but Until() <= 30 days
//	SeatLost     — a heartbeat was rejected (ErrMachineNotActivated or
//	               ErrSeatLimitExceeded); the app should re-Activate
//
// Other Check errors (e.g., ErrWatermarkTampered) are logged but
// not emitted as events — they indicate environmental issues, not
// license state.
//
// If HeartbeatInterval() > 0 a second ticker fires at that cadence and
// calls lic.Heartbeat(ctx). On seat-related errors it emits SeatLost;
// other heartbeat errors are logged. When HeartbeatInterval() == 0 no
// heartbeat ticker is started.
func (m *Monitor) Start(ctx context.Context) <-chan Event {
	out := make(chan Event, 4)
	go func() {
		defer close(out)
		t := time.NewTicker(m.interval)
		defer t.Stop()

		// Optional heartbeat ticker (server-driven cadence). A nil channel
		// in the select blocks forever, so a zero interval = no pinging.
		var hbC <-chan time.Time
		if hb := m.lic.HeartbeatInterval(); hb > 0 {
			ht := time.NewTicker(hb)
			defer ht.Stop()
			hbC = ht.C
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := m.lic.Check(); err != nil {
					switch {
					case errors.Is(err, ErrExpired):
						select {
						case out <- Expired{Err: err}:
						case <-ctx.Done():
							return
						}
					case errors.Is(err, ErrClockAnomaly):
						select {
						case out <- ClockAnomaly{DetectedAt: time.Now()}:
						case <-ctx.Done():
							return
						}
					default:
						m.logger.Warn("lk: Check error", "err", err.Error())
					}
				} else if d := m.lic.Until(); d <= 30*24*time.Hour {
					select {
					case out <- ExpiringSoon{Until: d}:
					case <-ctx.Done():
						return
					}
				}
			case <-hbC:
				if err := m.lic.Heartbeat(ctx); err != nil {
					if errors.Is(err, ErrMachineNotActivated) || errors.Is(err, ErrSeatLimitExceeded) {
						select {
						case out <- SeatLost{Err: err}:
						case <-ctx.Done():
							return
						}
					} else {
						m.logger.Warn("lk: heartbeat error", "err", err.Error())
					}
				}
			}
		}
	}()
	return out
}
