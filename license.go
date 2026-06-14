package lk

import (
	"crypto/ed25519"
	"log/slog"
	"sync"
	"time"
)

// License is the handle returned by Verify.
type License interface {
	Claims() Claims
	Check() error
	ValidUntil() time.Time
	Until() time.Duration
}

type licenseImpl struct {
	mu                 sync.Mutex
	claims             Claims
	productKeys        map[string]ed25519.PublicKey
	fingerprint        []byte
	licenseID          [16]byte
	bundlePath         string // empty = no sidecar
	logger             *slog.Logger
	lastWatermarkWrite time.Time
	warnings           []time.Duration
	firedThresholds    map[time.Duration]bool
}

func (l *licenseImpl) Claims() Claims        { return l.claims }
func (l *licenseImpl) ValidUntil() time.Time { return time.Unix(l.claims.Exp, 0) }
func (l *licenseImpl) Until() time.Duration  { return time.Until(l.ValidUntil()) }

// Check — cheap re-verification. Reads watermark, computes
// effective_now = max(system, watermark.last_seen), compares to
// claims.Exp. Throttled sidecar write (at most 1/hour).
func (l *licenseImpl) Check() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if l.bundlePath != "" {
		wm, err := readWatermark(l.bundlePath, l.fingerprint, l.licenseID)
		if err != nil {
			return err
		}
		if !wm.IsZero() && wm.After(now) {
			return ErrClockAnomaly
		}
	}

	if now.Unix() >= l.claims.Exp {
		return ErrExpired
	}

	// Emit expiring-soon warnings (each threshold fires once).
	remaining := l.ValidUntil().Sub(now)
	for _, th := range l.warnings {
		if remaining <= th && !l.firedThresholds[th] {
			l.logger.Warn("lk: license expires soon",
				"in", remaining.Truncate(time.Hour).String(),
				"threshold", th.String())
			l.firedThresholds[th] = true
		}
	}

	// Throttled watermark advance.
	if l.bundlePath != "" && now.Sub(l.lastWatermarkWrite) > time.Hour {
		if err := writeWatermark(l.bundlePath, l.fingerprint, l.licenseID, now); err != nil {
			l.logger.Warn("lk: watermark write failed", "err", err.Error())
		} else {
			l.lastWatermarkWrite = now
		}
	}
	return nil
}
