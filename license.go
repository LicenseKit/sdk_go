package lk

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
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
	Seats() (limit, used int)
	Release() error
	Heartbeat(ctx context.Context) error
	HeartbeatInterval() time.Duration
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

	// online mode (zero/false when constructed via Verify)
	online            bool
	lkey              string
	client            *client
	clientMeta        *clientMeta
	refreshBefore     time.Duration
	revocationPoll    time.Duration
	lastRevocCheck    time.Time
	seatsLimit        int
	seatsUsed         int
	heartbeatInterval time.Duration // 0 = not required (offline always 0)
}

// Claims/ValidUntil/Until lock because online Check() mutates l.claims
// concurrently (e.g. from a Monitor goroutine). They take the lock
// directly rather than calling each other to avoid re-entrant locking.
func (l *licenseImpl) Claims() Claims {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.claims
}

func (l *licenseImpl) ValidUntil() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Unix(l.claims.Exp, 0)
}

func (l *licenseImpl) Until() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Until(time.Unix(l.claims.Exp, 0))
}

// Seats reports the machine (seat) usage. For licenses created by Verify
// (offline) it always returns (1, 1) — seat management is online-only.
func (l *licenseImpl) Seats() (int, int) {
	// l.online is set once at construction and never mutated.
	if !l.online {
		return 1, 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seatsLimit, l.seatsUsed
}

// Release frees this machine's seat (online only; offline is a no-op).
func (l *licenseImpl) Release() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.online || l.client == nil {
		return nil
	}
	return l.client.release(l.lkey, hexFingerprint(l.fingerprint))
}

// HeartbeatInterval is the server-driven keep-alive cadence; 0 means the
// license does not require heartbeats (and for offline licenses).
func (l *licenseImpl) HeartbeatInterval() time.Duration {
	if !l.online {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.heartbeatInterval
}

// Heartbeat pings the server to keep this machine's seat alive without
// minting a new token. Offline licenses are a no-op. Network I/O runs
// without l.mu held; on success the seat counters are refreshed.
func (l *licenseImpl) Heartbeat(ctx context.Context) error {
	if !l.online || l.client == nil {
		return nil
	}
	l.mu.Lock()
	lkey := l.lkey
	fp := hexFingerprint(l.fingerprint)
	l.mu.Unlock()

	resp, err := l.client.heartbeat(ctx, lkey, fp)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.seatsLimit, l.seatsUsed = resp.Seats.Limit, resp.Seats.Used
	l.mu.Unlock()
	return nil
}

func hexFingerprint(fp []byte) string { return hex.EncodeToString(fp) }

// Check — cheap re-verification. Online: refresh the token near expiry,
// optionally poll revocation, enforce expiry. Offline: read watermark,
// compare to claims.Exp, throttled sidecar write (at most 1/hour).
func (l *licenseImpl) Check() error {
	// l.online is set once at construction and never mutated.
	if l.online {
		return l.checkOnline()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if iatFloorViolated(now, l.claims.IAT) {
		return ErrClockAnomaly
	}

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
	remaining := time.Unix(l.claims.Exp, 0).Sub(now)
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

// checkOnline performs the online re-verification. Network I/O (token
// refresh + revocation poll) runs WITHOUT l.mu held — the lock is taken
// only to snapshot inputs and to write back results — so concurrent
// Check/Seats/Claims calls never block on a network round-trip.
func (l *licenseImpl) checkOnline() error {
	l.mu.Lock()
	now := time.Now()
	if iatFloorViolated(now, l.claims.IAT) {
		l.mu.Unlock()
		return ErrClockAnomaly
	}
	needRefresh := time.Until(time.Unix(l.claims.Exp, 0)) <= l.refreshBefore
	needRevoc := l.revocationPoll > 0 && now.Sub(l.lastRevocCheck) >= l.revocationPoll
	lkey := l.lkey
	fp := hexFingerprint(l.fingerprint)
	cm := l.clientMeta
	pid := l.claims.PID
	l.mu.Unlock()

	// Refresh the token near expiry (no lock held during I/O).
	if needRefresh {
		resp, rerr := l.client.exchange(lkey, fp, cm)
		switch {
		case rerr == nil:
			if keys, kerr := l.client.publicKeys(resp.Claims.PID); kerr == nil {
				if claims, verr := verifyLK1(resp.Token, keys); verr == nil {
					kb := make(map[string]string, len(keys))
					for kid, pk := range keys {
						kb[kid] = encodeKey(pk)
					}
					hb := heartbeatIntervalFrom(resp.Heartbeat)
					_ = writeCache(lkey, cacheEntry{
						Token: resp.Token, Claims: claims, Keys: kb, Seats: resp.Seats,
						HeartbeatSeconds: int(hb / time.Second),
					})
					l.mu.Lock()
					l.claims = claims
					l.productKeys = keys
					l.seatsLimit, l.seatsUsed = resp.Seats.Limit, resp.Seats.Used
					l.heartbeatInterval = hb
					l.mu.Unlock()
				}
			}
		case rerr == ErrSeatLimitExceeded, rerr == ErrLicenseKeyInvalid:
			return rerr
			// other refresh errors: fall through on the cached token (grace).
		}
	}

	// Optional revocation polling. Advance lastRevocCheck on the ATTEMPT
	// (not only on success) so a down revocation endpoint isn't hammered on
	// every Check — the next poll waits a full interval regardless.
	if needRevoc {
		l.mu.Lock()
		l.lastRevocCheck = time.Now()
		l.mu.Unlock()
		if sr, err := l.client.revocations(pid); err == nil {
			l.mu.Lock()
			keys := l.productKeys
			lid := l.claims.LID
			l.mu.Unlock()
			if list, verr := sr.verify(keys); verr == nil && list.contains(lid) {
				return ErrRevoked
			}
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Now().Unix() >= l.claims.Exp {
		return ErrExpired
	}
	remaining := time.Unix(l.claims.Exp, 0).Sub(now)
	for _, th := range l.warnings {
		if remaining <= th && !l.firedThresholds[th] {
			l.logger.Warn("lk: license expires soon",
				"in", remaining.Truncate(time.Hour).String(),
				"threshold", th.String())
			l.firedThresholds[th] = true
		}
	}
	return nil
}
