package lk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeBundle — test helper that constructs an LKB1 bundle end-to-end:
// generate a fresh Ed25519 key, sign LK1 with provided claims, wrap
// into the JSON plaintext payload, encrypt under deriveBundleKey
// output.
func makeBundle(t *testing.T, fingerprintHex string, lid [16]byte, lic Claims) []byte {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	lic.KID = "key_test"
	if lic.IAT == 0 {
		lic.IAT = time.Now().Unix()
	}
	if lic.Exp == 0 {
		lic.Exp = time.Now().Add(365 * 24 * time.Hour).Unix()
	}

	tok := signLK1(t, priv, lic) // helper from token_test.go
	payload := map[string]any{
		"v":   1,
		"lk1": tok,
		"product": map[string]any{
			"id": "prod_test", "name": "Test Product", "slug": "test",
		},
		"product_keys": []map[string]any{
			{"kid": "key_test", "alg": "Ed25519", "pub_b64": base64.StdEncoding.EncodeToString(pub)},
		},
		"issued_at": time.Now().Unix(),
		"issuer":    "licensekit",
	}
	plaintext, _ := json.Marshal(payload)

	fp, _ := hex.DecodeString(fingerprintHex)
	key, _ := deriveBundleKey(fp, lid)
	return sealBundle(t, key, plaintext) // helper from bundle_test.go
}

func TestVerify_HappyPath(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "license.lkbundle")
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1, 2, 3}

	bundle := makeBundle(t, fp, lid, Claims{
		LID: "lic_test", PID: "prod_test", Sub: "alice",
		Typ: "subscription",
	})
	os.WriteFile(bundlePath, bundle, 0o644)

	lic, err := Verify(bundle,
		WithFingerprint(fp),
		WithBundlePath(bundlePath),
		WithLicenseID(lid),
	)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	c := lic.Claims()
	if c.Sub != "alice" {
		t.Errorf("claims roundtrip: %+v", c)
	}
	if err := lic.Check(); err != nil {
		t.Errorf("Check after Verify: %v", err)
	}
	if lic.Until() < 350*24*time.Hour {
		t.Errorf("Until too small: %v", lic.Until())
	}

	// Sidecar should have been created.
	if _, err := os.Stat(bundlePath + ".lk-watermark"); err != nil {
		t.Errorf("sidecar not created: %v", err)
	}
}

func TestVerify_WrongFingerprint(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	wrongFP := "ff112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	bundle := makeBundle(t, fp, lid, Claims{LID: "lic_x"})

	_, err := Verify(bundle, WithFingerprint(wrongFP), WithLicenseID(lid))
	if err != ErrWrongFingerprint {
		t.Fatalf("expected ErrWrongFingerprint, got %v", err)
	}
}

func TestVerify_ExpiredBundle(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	// Set Exp in the past.
	bundle := makeBundle(t, fp, lid, Claims{
		LID: "lic_x", Exp: time.Now().Add(-1 * time.Hour).Unix(),
	})

	_, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid))
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerify_ClockRollback(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "license.lkbundle")
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	bundle := makeBundle(t, fp, lid, Claims{LID: "lic_x"})
	os.WriteFile(bundlePath, bundle, 0o644)

	// Plant a watermark in the FUTURE (simulates: previous Verify
	// happened when clock was correct; now clock rolled back).
	fpRaw, _ := hex.DecodeString(fp)
	future := time.Now().Add(24 * time.Hour)
	if err := writeWatermark(bundlePath, fpRaw, lid, future); err != nil {
		t.Fatal(err)
	}

	_, err := Verify(bundle, WithFingerprint(fp), WithBundlePath(bundlePath), WithLicenseID(lid))
	if err != ErrClockAnomaly {
		t.Fatalf("expected ErrClockAnomaly, got %v", err)
	}
}

func TestVerify_MissingLicenseID(t *testing.T) {
	bundle := []byte("LKB1\x01" + "______________" + "ciphertext_stub_at_least_16_bytes_for_aead_tag")
	_, err := Verify(bundle, WithFingerprint("00"+`"`))
	if err == nil {
		t.Fatal("expected error for missing WithLicenseID, got nil")
	}
}

func TestVerify_FutureIAT_ClockAnomaly(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	// iat 1h in the future simulates the system clock rolled back below
	// the token's issue time. No sidecar involved — this is stateless.
	bundle := makeBundle(t, fp, lid, Claims{
		LID: "lic_x",
		IAT: time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid))
	if err != ErrClockAnomaly {
		t.Fatalf("expected ErrClockAnomaly, got %v", err)
	}
}

func TestVerify_IATWithinSkew_OK(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	// iat 1 minute ahead is within the 5-minute skew tolerance — fine.
	bundle := makeBundle(t, fp, lid, Claims{
		LID: "lic_x",
		IAT: time.Now().Add(1 * time.Minute).Unix(),
	})

	if _, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid)); err != nil {
		t.Fatalf("Verify within skew should pass, got %v", err)
	}
}

func TestVerify_IATBoundary(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}

	// 6 minutes ahead is just past the 5-minute skew → anomaly.
	justOver := makeBundle(t, fp, lid, Claims{LID: "lic_x", IAT: time.Now().Add(6 * time.Minute).Unix()})
	if _, err := Verify(justOver, WithFingerprint(fp), WithLicenseID(lid)); err != ErrClockAnomaly {
		t.Fatalf("6m ahead should be ErrClockAnomaly, got %v", err)
	}

	// 4 minutes ahead is within the 5-minute skew → OK.
	justUnder := makeBundle(t, fp, lid, Claims{LID: "lic_x", IAT: time.Now().Add(4 * time.Minute).Unix()})
	if _, err := Verify(justUnder, WithFingerprint(fp), WithLicenseID(lid)); err != nil {
		t.Fatalf("4m ahead should pass, got %v", err)
	}
}

func TestVerify_AutoWatermark_CreatesSidecar(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1, 2, 3}
	bundle := makeBundle(t, fp, lid, Claims{LID: "lic_x"})

	lic, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid), WithAutoWatermark())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	want := filepath.Join(tmp, "licensekit", lidString(lid)+".lk-watermark")
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("auto sidecar not created at %s: %v", want, err)
	}
	if err := lic.Check(); err != nil {
		t.Errorf("Check after auto Verify: %v", err)
	}
}

func TestVerify_AutoWatermark_ConfigDirError(t *testing.T) {
	orig := userConfigDir
	userConfigDir = func() (string, error) { return "", errors.New("no HOME") }
	t.Cleanup(func() { userConfigDir = orig })

	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	bundle := makeBundle(t, fp, lid, Claims{LID: "lic_x"})

	if _, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid), WithAutoWatermark()); err == nil {
		t.Fatal("expected error when userConfigDir fails, got nil")
	}
}

func TestVerify_AutoWatermark_ClockRollback(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	bundle := makeBundle(t, fp, lid, Claims{LID: "lic_x"})

	base := filepath.Join(tmp, "licensekit", lidString(lid))
	if err := os.MkdirAll(filepath.Dir(base), 0o700); err != nil {
		t.Fatal(err)
	}
	fpRaw, _ := hex.DecodeString(fp)
	if err := writeWatermark(base, fpRaw, lid, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	_, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid), WithAutoWatermark())
	if err != ErrClockAnomaly {
		t.Fatalf("expected ErrClockAnomaly, got %v", err)
	}
}

func TestVerify_BundlePathWinsOverAuto(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	explicitDir := t.TempDir()
	explicitPath := filepath.Join(explicitDir, "license.lkbundle")
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	lid := [16]byte{1}
	bundle := makeBundle(t, fp, lid, Claims{LID: "lic_x"})

	if _, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid),
		WithBundlePath(explicitPath), WithAutoWatermark()); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, err := os.Stat(explicitPath + ".lk-watermark"); err != nil {
		t.Errorf("explicit sidecar missing: %v", err)
	}
	auto := filepath.Join(tmp, "licensekit", lidString(lid)+".lk-watermark")
	if _, err := os.Stat(auto); err == nil {
		t.Errorf("auto sidecar should not exist when WithBundlePath is set")
	}
}
