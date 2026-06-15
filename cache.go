package lk

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// cacheEntry is the JSON persisted per license key. Integrity of Token +
// Claims is guaranteed by the LK1 signature (re-verified on read); Keys
// are public. No secret material is stored.
type cacheEntry struct {
	Token  string            `json:"token"`
	Claims Claims            `json:"claims"`
	Keys   map[string]string `json:"keys"` // kid -> base64(std) 32-byte pubkey
	Seats  seatsDTO          `json:"seats"`
}

func encodeKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// keyMap decodes the stored kid->b64 map into verifiable public keys.
func (e cacheEntry) keyMap() (map[string]ed25519.PublicKey, error) {
	out := make(map[string]ed25519.PublicKey, len(e.Keys))
	for kid, b := range e.Keys {
		raw, err := base64.StdEncoding.DecodeString(b)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: bad cached key %s", ErrActivationFailed, kid)
		}
		out[kid] = ed25519.PublicKey(raw)
	}
	return out, nil
}

// cacheName is the on-disk filename for a license key: SHA256(lkey)[:16]
// hex + suffix. Derivable from the LKEY alone for offline cold-start.
func cacheName(lkey string) string {
	h := sha256.Sum256([]byte(lkey))
	return hex.EncodeToString(h[:16]) + ".lktoken"
}

func cachePath(lkey string) (string, error) {
	base, err := userConfigDir()
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrActivationFailed, err)
	}
	dir := filepath.Join(base, "licensekit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("%w: %v", ErrActivationFailed, err)
	}
	return filepath.Join(dir, cacheName(lkey)), nil
}

func writeCache(lkey string, e cacheEntry) error {
	p, err := cachePath(lkey)
	if err != nil {
		return err
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o600)
}

func readCache(lkey string) (cacheEntry, error) {
	p, err := cachePath(lkey)
	if err != nil {
		return cacheEntry{}, err
	}
	return readCacheAt(p)
}

func readCacheAt(path string) (cacheEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return cacheEntry{}, err
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return cacheEntry{}, err
	}
	return e, nil
}
