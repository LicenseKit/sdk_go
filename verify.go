package lk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// userConfigDir is indirected for tests (os.UserConfigDir is not
// env-overridable on macOS).
var userConfigDir = os.UserConfigDir

// resolveAutoWatermarkPath derives a stable sidecar base path from the
// license ID under the OS user-config dir and ensures the parent dir
// exists. The returned path has no suffix; read/writeWatermark append
// ".lk-watermark" themselves.
func resolveAutoWatermarkPath(lid [16]byte) (string, error) {
	base, err := userConfigDir()
	if err != nil {
		return "", fmt.Errorf("lk: WithAutoWatermark: %w", err)
	}
	dir := filepath.Join(base, "licensekit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("lk: WithAutoWatermark: %w", err)
	}
	return filepath.Join(dir, lidString(lid)), nil
}

// bundlePayload is what's inside the AEAD-encrypted bytes (the JSON
// the backend writes; the SDK only consumes).
type bundlePayload struct {
	V           int                `json:"v"`
	LK1         string             `json:"lk1"`
	Product     bundleProduct      `json:"product"`
	ProductKeys []bundleProductKey `json:"product_keys"`
	IssuedAt    int64              `json:"issued_at"`
	Issuer      string             `json:"issuer"`
}

type bundleProduct struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type bundleProductKey struct {
	KID    string `json:"kid"`
	Alg    string `json:"alg"`
	PubB64 string `json:"pub_b64"`
}

// Verify parses + decrypts + validates an LKB1 bundle. Returns a
// License handle on success.
//
// WithLicenseID is REQUIRED. The LKB1 wire format doesn't carry the
// license ID in its unencrypted header; the HKDF salt uses it, so
// the SDK must know it to derive the AEAD key. The customer app
// knows which license file it's loading (it was minted for THAT
// license), so passes it explicitly.
func Verify(bundleBytes []byte, opts ...Option) (License, error) {
	o := newVerifyOpts(opts...)
	if !o.licenseIDSet {
		return nil, errors.New("lk: WithLicenseID is required — pass the raw 16-byte ULID the bundle was minted for")
	}

	// 1. Resolve fingerprint.
	var fpHex string
	if o.fingerprint != "" {
		fpHex = strings.ToLower(o.fingerprint)
	} else {
		captured, err := CapturedFingerprint()
		if err != nil {
			return nil, fmt.Errorf("lk: fingerprint capture: %w", err)
		}
		fpHex = captured
	}
	fp, err := hexToFingerprint(fpHex)
	if err != nil {
		return nil, err
	}

	// 2. Derive AEAD key.
	key, err := deriveBundleKey(fp, o.licenseID)
	if err != nil {
		return nil, err
	}

	// 3. Decrypt.
	plaintext, err := decodeBundle(key, bundleBytes)
	if err != nil {
		return nil, err
	}

	// 4. Parse plaintext JSON.
	var pl bundlePayload
	if err := json.Unmarshal(plaintext, &pl); err != nil {
		return nil, fmt.Errorf("lk: payload not JSON: %w", err)
	}
	if pl.V != 1 {
		return nil, fmt.Errorf("lk: unsupported payload version %d", pl.V)
	}

	// 5. Build pubkey map for LK1 verify.
	keys := make(map[string]ed25519.PublicKey, len(pl.ProductKeys))
	for _, k := range pl.ProductKeys {
		if k.Alg != "Ed25519" {
			return nil, fmt.Errorf("lk: unsupported alg %q for kid %s", k.Alg, k.KID)
		}
		pub, err := base64.StdEncoding.DecodeString(k.PubB64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("lk: invalid pub_b64 for kid %s", k.KID)
		}
		keys[k.KID] = ed25519.PublicKey(pub)
	}

	// 6. Verify LK1 signature.
	claims, err := verifyLK1(pl.LK1, keys)
	if err != nil {
		return nil, err
	}

	// Resolve an auto watermark path when requested and no explicit
	// path was given. Explicit WithBundlePath wins.
	if o.bundlePath == "" && o.autoWatermark {
		p, err := resolveAutoWatermarkPath(o.licenseID)
		if err != nil {
			return nil, err
		}
		o.bundlePath = p
	}

	// 7. Watermark + clock-anomaly.
	now := time.Now()
	// Stateless clock-rollback floor: now can't precede the token's
	// issue time (minus skew), regardless of any sidecar.
	if iatFloorViolated(now, claims.IAT) {
		return nil, ErrClockAnomaly
	}
	if o.bundlePath != "" {
		wm, err := readWatermark(o.bundlePath, fp, o.licenseID)
		if err != nil {
			return nil, err
		}
		if !wm.IsZero() && wm.After(now) {
			return nil, ErrClockAnomaly
		}
		// Write fresh watermark (TOFU on first call; advances on each Verify).
		if err := writeWatermark(o.bundlePath, fp, o.licenseID, now); err != nil {
			o.logger.Warn("lk: watermark write failed", "err", err.Error())
		}
	}

	// 8. Expiry check.
	if now.Unix() >= claims.Exp {
		return nil, ErrExpired
	}

	// 9. Build License handle.
	return &licenseImpl{
		claims:             claims,
		productKeys:        keys,
		fingerprint:        fp,
		licenseID:          o.licenseID,
		bundlePath:         o.bundlePath,
		logger:             o.logger,
		warnings:           o.expiringWarnings,
		firedThresholds:    map[time.Duration]bool{},
		lastWatermarkWrite: now,
	}, nil
}
