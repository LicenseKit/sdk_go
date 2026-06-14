package lk

import (
	"log/slog"
	"testing"
	"time"
)

func TestCheck_FutureIAT_ClockAnomaly(t *testing.T) {
	// White-box: a license whose claims.IAT is ahead of now simulates a
	// clock rolled back below issue time after a successful Verify. No
	// sidecar (bundlePath empty), so this exercises the stateless anchor.
	l := &licenseImpl{
		claims: Claims{
			IAT: time.Now().Add(1 * time.Hour).Unix(),
			Exp: time.Now().Add(365 * 24 * time.Hour).Unix(),
		},
		logger:          slog.Default(),
		firedThresholds: map[time.Duration]bool{},
	}

	if err := l.Check(); err != ErrClockAnomaly {
		t.Fatalf("expected ErrClockAnomaly, got %v", err)
	}
}

func TestCheck_IATWithinSkew_OK(t *testing.T) {
	l := &licenseImpl{
		claims: Claims{
			IAT: time.Now().Add(1 * time.Minute).Unix(),
			Exp: time.Now().Add(365 * 24 * time.Hour).Unix(),
		},
		logger:          slog.Default(),
		firedThresholds: map[time.Duration]bool{},
	}

	if err := l.Check(); err != nil {
		t.Fatalf("Check within skew should pass, got %v", err)
	}
}

func TestIATFloorViolated_ZeroIAT(t *testing.T) {
	// iat == 0 (unset) maps to 1970; now is never before that, so a
	// missing issue time must never look like a rollback.
	if iatFloorViolated(time.Now(), 0) {
		t.Fatal("zero iat must not be treated as a clock anomaly")
	}
}
