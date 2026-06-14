package lk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/hkdf"
)

const watermarkSuffix = ".lk-watermark"

// watermarkFile is the on-disk JSON layout.
type watermarkFile struct {
	LID      string `json:"lid"`       // prefixed (str form), human-readable
	LastSeen int64  `json:"last_seen"` // unix seconds
	MAC      string `json:"mac"`       // hex SHA-256 HMAC
}

// watermarkKey derives the HMAC key from fingerprint + license_id.
// Uses DISTINCT info string from the bundle-encryption key so the
// bundle-AEAD key can't be reused to forge watermarks.
func watermarkKey(fingerprint []byte, lid [16]byte) ([]byte, error) {
	if len(fingerprint) != fingerprintLen {
		return nil, fmt.Errorf("lk: watermarkKey: fingerprint length %d", len(fingerprint))
	}
	h := sha256.New()
	h.Write([]byte("lkbundle-v1-watermark"))
	h.Write(lid[:])
	salt := h.Sum(nil)
	r := hkdf.New(sha256.New, fingerprint, salt, []byte("lkbundle-v1-watermark"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// watermarkMAC computes the HMAC over a fixed byte concatenation
// (lid_raw_16 || ":" || last_seen_int64_decimal_ascii). Avoids any
// JSON-encoding determinism concerns.
func watermarkMAC(key []byte, lid [16]byte, lastSeen int64) string {
	h := hmac.New(sha256.New, key)
	h.Write(lid[:])
	h.Write([]byte(":"))
	h.Write([]byte(fmt.Sprintf("%d", lastSeen)))
	return hex.EncodeToString(h.Sum(nil))
}

// writeWatermark serialises a fresh sidecar next to the bundle file.
// Atomicity: write to .lk-watermark.tmp then rename. Permissions:
// 0o644 (no secrets in the sidecar).
func writeWatermark(bundlePath string, fingerprint []byte, lid [16]byte, ts time.Time) error {
	key, err := watermarkKey(fingerprint, lid)
	if err != nil {
		return err
	}
	wf := watermarkFile{
		LID:      "lic_" + lidString(lid),
		LastSeen: ts.Unix(),
		MAC:      watermarkMAC(key, lid, ts.Unix()),
	}
	data, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		return err
	}
	out := bundlePath + watermarkSuffix
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, out)
}

// readWatermark reads + HMAC-validates the sidecar. Returns:
//   - (zero, nil)   if the file is absent — TOFU, caller writes fresh
//   - (time, nil)   on success
//   - (zero, ErrWatermarkTampered) on HMAC mismatch / wrong fingerprint
//   - (zero, error) on I/O / JSON parse error
func readWatermark(bundlePath string, fingerprint []byte, lid [16]byte) (time.Time, error) {
	sidecar := bundlePath + watermarkSuffix
	data, err := os.ReadFile(sidecar)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	var wf watermarkFile
	if err := json.Unmarshal(data, &wf); err != nil {
		return time.Time{}, ErrWatermarkTampered
	}
	key, err := watermarkKey(fingerprint, lid)
	if err != nil {
		return time.Time{}, err
	}
	wantMAC := watermarkMAC(key, lid, wf.LastSeen)
	if !hmac.Equal([]byte(wantMAC), []byte(wf.MAC)) {
		return time.Time{}, ErrWatermarkTampered
	}
	return time.Unix(wf.LastSeen, 0), nil
}

// lidString — render raw ULID bytes to the standard Crockford-Base32
// representation (no prefix). Used only for the sidecar's human-
// readable `lid` field; not load-bearing for HMAC.
func lidString(lid [16]byte) string {
	const enc = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var out [26]byte
	out[0] = enc[(lid[0]&224)>>5]
	out[1] = enc[lid[0]&31]
	out[2] = enc[(lid[1]&248)>>3]
	out[3] = enc[((lid[1]&7)<<2)|((lid[2]&192)>>6)]
	out[4] = enc[(lid[2]&62)>>1]
	out[5] = enc[((lid[2]&1)<<4)|((lid[3]&240)>>4)]
	out[6] = enc[((lid[3]&15)<<1)|((lid[4]&128)>>7)]
	out[7] = enc[(lid[4]&124)>>2]
	out[8] = enc[((lid[4]&3)<<3)|((lid[5]&224)>>5)]
	out[9] = enc[lid[5]&31]
	out[10] = enc[(lid[6]&248)>>3]
	out[11] = enc[((lid[6]&7)<<2)|((lid[7]&192)>>6)]
	out[12] = enc[(lid[7]&62)>>1]
	out[13] = enc[((lid[7]&1)<<4)|((lid[8]&240)>>4)]
	out[14] = enc[((lid[8]&15)<<1)|((lid[9]&128)>>7)]
	out[15] = enc[(lid[9]&124)>>2]
	out[16] = enc[((lid[9]&3)<<3)|((lid[10]&224)>>5)]
	out[17] = enc[lid[10]&31]
	out[18] = enc[(lid[11]&248)>>3]
	out[19] = enc[((lid[11]&7)<<2)|((lid[12]&192)>>6)]
	out[20] = enc[(lid[12]&62)>>1]
	out[21] = enc[((lid[12]&1)<<4)|((lid[13]&240)>>4)]
	out[22] = enc[((lid[13]&15)<<1)|((lid[14]&128)>>7)]
	out[23] = enc[(lid[14]&124)>>2]
	out[24] = enc[((lid[14]&3)<<3)|((lid[15]&224)>>5)]
	out[25] = enc[lid[15]&31]
	return string(out[:])
}
