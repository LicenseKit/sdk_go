package lk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	bundleMagic     = "LKB1"
	bundleVersion   = 0x01
	bundleNonceLen  = 12
	bundleHeaderLen = 4 + 1 + bundleNonceLen
	bundleAeadTag   = 16
	fingerprintLen  = 32 // sha256 output (hex-decoded from 64-char string)
)

// deriveBundleKey — see backend spec § 3. Mirror of backend's
// internal/app/offline.go deriveBundleKey. Cross-language parity
// verified via testdata/vectors.json.
func deriveBundleKey(fingerprint []byte, licenseIDRaw [16]byte) ([]byte, error) {
	if len(fingerprint) != fingerprintLen {
		return nil, fmt.Errorf("lk: fingerprint must be %d bytes, got %d",
			fingerprintLen, len(fingerprint))
	}
	h := sha256.New()
	h.Write([]byte("lkbundle-v1"))
	h.Write(licenseIDRaw[:])
	salt := h.Sum(nil)

	r := hkdf.New(sha256.New, fingerprint, salt, []byte("lkbundle-v1-aes-256-key"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("lk: hkdf: %w", err)
	}
	return out, nil
}

// decodeBundle parses LKB1 wire format and AEAD-decrypts. AEAD
// failures collapse to ErrWrongFingerprint (intentional — can't
// distinguish 'wrong key' from 'tampered ciphertext' securely).
func decodeBundle(key, bundle []byte) ([]byte, error) {
	if len(bundle) < bundleHeaderLen+bundleAeadTag {
		return nil, ErrMalformedBundle
	}
	if string(bundle[0:4]) != bundleMagic {
		return nil, ErrMalformedBundle
	}
	if bundle[4] != bundleVersion {
		return nil, ErrMalformedBundle
	}
	nonce := bundle[5 : 5+bundleNonceLen]
	ciphertext := bundle[bundleHeaderLen:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("lk: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("lk: gcm: %w", err)
	}
	pt, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrWrongFingerprint
	}
	return pt, nil
}

// hexToFingerprint decodes a 64-char lowercase hex string into 32
// raw bytes. Used by Verify when WithFingerprint(...) supplies an
// explicit value AND by the auto-capture path's hex string.
func hexToFingerprint(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, errors.New("lk: fingerprint hex must be 64 chars")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("lk: fingerprint hex: %w", err)
	}
	return b, nil
}
