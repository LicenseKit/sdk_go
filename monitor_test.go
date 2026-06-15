package lk

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// mockLicense lets us drive Check() outcomes for monitor tests.
type mockLicense struct {
	checkErr   error
	until      time.Duration
	hbInterval time.Duration
	heartbeat  func() error
}

func (m *mockLicense) Claims() Claims                   { return Claims{} }
func (m *mockLicense) Check() error                     { return m.checkErr }
func (m *mockLicense) ValidUntil() time.Time            { return time.Now().Add(m.until) }
func (m *mockLicense) Until() time.Duration             { return m.until }
func (m *mockLicense) Seats() (int, int)                { return 1, 1 }
func (m *mockLicense) Release() error                   { return nil }
func (m *mockLicense) HeartbeatInterval() time.Duration { return m.hbInterval }
func (m *mockLicense) Heartbeat(ctx context.Context) error {
	if m.heartbeat != nil {
		return m.heartbeat()
	}
	return nil
}

func TestMonitor_EmitsExpired(t *testing.T) {
	lic := &mockLicense{checkErr: ErrExpired}
	mon := NewMonitor(lic, WithInterval(10*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	events := mon.Start(ctx)
	select {
	case e := <-events:
		if _, ok := e.(Expired); !ok {
			t.Errorf("expected Expired, got %T", e)
		}
	case <-ctx.Done():
		t.Fatal("no event fired before ctx timeout")
	}
}

func TestMonitor_EmitsClockAnomaly(t *testing.T) {
	lic := &mockLicense{checkErr: ErrClockAnomaly}
	mon := NewMonitor(lic, WithInterval(10*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	events := mon.Start(ctx)
	select {
	case e := <-events:
		if _, ok := e.(ClockAnomaly); !ok {
			t.Errorf("expected ClockAnomaly, got %T", e)
		}
	case <-ctx.Done():
		t.Fatal("no event fired")
	}
}

func TestMonitor_EmitsExpiringSoon(t *testing.T) {
	lic := &mockLicense{checkErr: nil, until: 10 * 24 * time.Hour}
	mon := NewMonitor(lic, WithInterval(10*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	events := mon.Start(ctx)
	select {
	case e := <-events:
		if _, ok := e.(ExpiringSoon); !ok {
			t.Errorf("expected ExpiringSoon, got %T", e)
		}
	case <-ctx.Done():
		t.Fatal("no event fired")
	}
}

func TestMonitor_NoEventWhenHealthy(t *testing.T) {
	lic := &mockLicense{checkErr: nil, until: 365 * 24 * time.Hour}
	mon := NewMonitor(lic, WithInterval(10*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	events := mon.Start(ctx)
	select {
	case e := <-events:
		// Channel might close on ctx cancel — that's fine, no events emitted.
		if e != nil {
			t.Errorf("unexpected event: %T", e)
		}
	case <-ctx.Done():
		// Expected — no events fired, ctx timed out cleanly.
	}
}

func TestMonitor_CtxCancelClosesChannel(t *testing.T) {
	lic := &mockLicense{checkErr: nil, until: 365 * 24 * time.Hour}
	mon := NewMonitor(lic, WithInterval(10*time.Millisecond))
	ctx, cancel := context.WithCancel(context.Background())

	events := mon.Start(ctx)
	cancel()

	// Give the goroutine a tick to notice cancellation.
	deadline := time.After(100 * time.Millisecond)
	for {
		select {
		case _, ok := <-events:
			if !ok {
				return // channel closed — good
			}
			// Drain any in-flight events.
		case <-deadline:
			t.Fatal("event channel did not close within 100ms of ctx cancel")
		}
	}
}

func TestMonitor_HeartbeatPingsAndSeatLost(t *testing.T) {
	var pings int32
	lic := &mockLicense{
		hbInterval: 10 * time.Millisecond,
		until:      365 * 24 * time.Hour, // not expiring; keep Check quiet
		heartbeat: func() error {
			n := atomic.AddInt32(&pings, 1)
			if n >= 2 {
				return ErrMachineNotActivated // second ping: seat lost
			}
			return nil
		},
	}
	m := NewMonitor(lic, WithInterval(time.Hour)) // Check rarely; heartbeat is the driver
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var gotSeatLost bool
	for evt := range m.Start(ctx) {
		if _, ok := evt.(SeatLost); ok {
			gotSeatLost = true
			cancel()
			break
		}
	}
	if atomic.LoadInt32(&pings) < 2 {
		t.Fatalf("expected at least 2 heartbeat pings, got %d", pings)
	}
	if !gotSeatLost {
		t.Fatal("expected a SeatLost event")
	}
}

func TestMonitor_NoHeartbeatWhenIntervalZero(t *testing.T) {
	var pings int32
	lic := &mockLicense{
		hbInterval: 0, // not required
		until:      365 * 24 * time.Hour,
		heartbeat:  func() error { atomic.AddInt32(&pings, 1); return nil },
	}
	m := NewMonitor(lic, WithInterval(10*time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	for range m.Start(ctx) {
	}
	if atomic.LoadInt32(&pings) != 0 {
		t.Fatalf("heartbeat must not fire when interval is 0, got %d pings", pings)
	}
}
