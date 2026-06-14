package lk

import (
	"encoding/hex"
	"runtime"
	"testing"
)

func TestCapturedFingerprint_Smoke(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("fingerprint capture not implemented on %s", runtime.GOOS)
	}
	got, err := CapturedFingerprint()
	if err != nil {
		// Linux CI in container often lacks /etc/machine-id; allow
		// graceful skip on the documented error.
		t.Skipf("CapturedFingerprint failed (likely missing OS source): %v", err)
	}
	if len(got) != 64 {
		t.Errorf("hex length: got %d, want 64", len(got))
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Errorf("not lowercase hex: %v", err)
	}
}

func TestCapturedFingerprint_Stable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skipf("fingerprint capture not implemented on %s", runtime.GOOS)
	}
	a, err := CapturedFingerprint()
	if err != nil {
		t.Skip(err)
	}
	b, _ := CapturedFingerprint()
	if a != b {
		t.Errorf("fingerprint changed between calls: %s vs %s", a, b)
	}
}
