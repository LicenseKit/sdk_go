package lk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// sealBundle — test-only helper. Mirrors backend's encodeLKBundle.
func sealBundle(t *testing.T, key, plaintext []byte) []byte {
	t.Helper()
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	out := append([]byte("LKB1"), 0x01)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, nil)
	return out
}

func TestDeriveBundleKey_KnownAnswer(t *testing.T) {
	fpHex := "deadbeefcafebabe1234567890abcdef" +
		"deadbeefcafebabe1234567890abcdef"
	fp, _ := hex.DecodeString(fpHex)
	lid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	key, err := deriveBundleKey(fp, lid)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key len: got %d, want 32", len(key))
	}

	// Determinism: same inputs → same output.
	key2, _ := deriveBundleKey(fp, lid)
	if !bytesEqualLK(key, key2) {
		t.Fatal("non-deterministic")
	}

	// Distinct license id → distinct key.
	lid[0] = 0xff
	key3, _ := deriveBundleKey(fp, lid)
	if bytesEqualLK(key, key3) {
		t.Fatal("license_id change did not change key")
	}
}

func TestDeriveBundleKey_WrongFPLen(t *testing.T) {
	lid := [16]byte{}
	if _, err := deriveBundleKey([]byte{1, 2, 3}, lid); err == nil {
		t.Fatal("expected error for short fingerprint")
	}
}

func TestDecodeBundle_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte(`{"hello":"world"}`)
	sealed := sealBundle(t, key, plaintext)

	got, err := decodeBundle(key, sealed)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext: got %q, want %q", got, plaintext)
	}
}

func TestDecodeBundle_WrongKey(t *testing.T) {
	right := make([]byte, 32)
	wrong := make([]byte, 32)
	wrong[0] = 0xff
	sealed := sealBundle(t, right, []byte("x"))
	if _, err := decodeBundle(wrong, sealed); err != ErrWrongFingerprint {
		t.Fatalf("expected ErrWrongFingerprint, got %v", err)
	}
}

func TestDecodeBundle_BadMagic(t *testing.T) {
	key := make([]byte, 32)
	bad := []byte("XXXX_garbage________________________________")
	if _, err := decodeBundle(key, bad); err != ErrMalformedBundle {
		t.Fatalf("expected ErrMalformedBundle for bad magic, got %v", err)
	}
}

func TestDecodeBundle_BadVersion(t *testing.T) {
	key := make([]byte, 32)
	bad := append([]byte("LKB1\x02"), make([]byte, 12+20)...)
	if _, err := decodeBundle(key, bad); err != ErrMalformedBundle {
		t.Fatalf("expected ErrMalformedBundle for bad version, got %v", err)
	}
}

func TestDecodeBundle_TooShort(t *testing.T) {
	key := make([]byte, 32)
	if _, err := decodeBundle(key, []byte("LKB1\x01short")); err != ErrMalformedBundle {
		t.Fatalf("expected ErrMalformedBundle for short bundle, got %v", err)
	}
}

func bytesEqualLK(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
