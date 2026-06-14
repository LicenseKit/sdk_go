package lk

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Version       int                  `json:"version"`
	Notes         string               `json:"notes"`
	Keys          json.RawMessage      `json:"keys"`  // ignore — for LK1 vectors
	Cases         json.RawMessage      `json:"cases"` // ignore — for LK1 vectors
	LKBundleCases []lkbundleVectorCase `json:"lkbundle_cases"`
}

type lkbundleVectorCase struct {
	Name     string                 `json:"name"`
	Kind     string                 `json:"kind"`
	Inputs   lkbundleVectorInputs   `json:"inputs"`
	Expected lkbundleVectorExpected `json:"expected"`
}

type lkbundleVectorInputs struct {
	FingerprintHex  string `json:"fingerprint_hex"`
	LicenseIDRawB64 string `json:"license_id_raw_b64"`
	NonceHex        string `json:"nonce_hex"`
	PlaintextB64    string `json:"plaintext_b64"`
}

type lkbundleVectorExpected struct {
	BundleB64     string `json:"bundle_b64"`
	DerivedKeyHex string `json:"derived_key_hex"`
}

func TestVectorsParity(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatal(err)
	}

	ran := 0
	for _, c := range vf.LKBundleCases {
		if c.Kind != "lkbundle_v1_decrypt_ok" {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			fp, _ := hex.DecodeString(c.Inputs.FingerprintHex)
			lidSlice, _ := base64.StdEncoding.DecodeString(c.Inputs.LicenseIDRawB64)
			if len(lidSlice) != 16 {
				t.Fatalf("license_id_raw_b64 not 16 bytes: %d", len(lidSlice))
			}
			var lid [16]byte
			copy(lid[:], lidSlice)
			bundle, _ := base64.StdEncoding.DecodeString(c.Expected.BundleB64)
			wantPT, _ := base64.StdEncoding.DecodeString(c.Inputs.PlaintextB64)
			wantKeyHex := c.Expected.DerivedKeyHex

			// 1. Key derivation parity (byte-for-byte).
			gotKey, err := deriveBundleKey(fp, lid)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(gotKey) != wantKeyHex {
				t.Errorf("derived key mismatch:\n got  %s\n want %s",
					hex.EncodeToString(gotKey), wantKeyHex)
			}

			// 2. Decrypt the issuer-produced bundle bytes.
			gotPT, err := decodeBundle(gotKey, bundle)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(gotPT) != string(wantPT) {
				t.Errorf("plaintext mismatch:\n got  %s\n want %s",
					string(gotPT), string(wantPT))
			}
		})
	}
	if ran == 0 {
		t.Fatal("no lkbundle_v1_decrypt_ok vectors found — backend may need to regenerate")
	}
}
