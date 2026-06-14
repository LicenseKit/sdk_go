package lk

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// CapturedFingerprint captures the machine fingerprint using the
// same algorithm lk-cli uses. Returns 64-char lowercase hex.
//
// Per-OS implementations live in fingerprint_<os>.go. If the OS
// is unsupported, returns an error rather than a guess.
//
// Composition: the per-OS impl returns one or more raw "identity"
// strings (e.g. /etc/machine-id contents on Linux). This dispatcher
// joins them with "\x00" separators, SHA-256 hashes the composite,
// hex-encodes the digest, and returns. The hash gives:
//   - constant 64-char output regardless of input length
//   - irreversibility — the raw machine-id never leaves the host
//   - collision-resistance across all known identifier formats
func CapturedFingerprint() (string, error) {
	sources, err := captureRawSources()
	if err != nil {
		return "", err
	}
	if len(sources) == 0 {
		return "", errMissingFingerprint
	}
	joined := strings.Join(sources, "\x00")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:]), nil
}
