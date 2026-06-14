package lk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// signLK1 — test-only helper that mints a valid LK1 token. Mirrors
// backend's pkg/token.Sign byte-for-byte.
func signLK1(t *testing.T, priv ed25519.PrivateKey, c Claims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return "LK1." + payloadB64 + "." + sigB64
}

func TestVerifyLK1_HappyPath(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	in := Claims{
		LID: "lic_X", PID: "prod_Y", KID: "key_Z", Sub: "alice",
		Typ: "subscription", IAT: 1750000000, Exp: 1782000000,
	}
	tok := signLK1(t, priv, in)

	got, err := verifyLK1(tok, map[string]ed25519.PublicKey{"key_Z": pub})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.LID != "lic_X" || got.KID != "key_Z" {
		t.Errorf("claims roundtrip: got %+v", got)
	}
}

func TestVerifyLK1_TamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	in := Claims{LID: "lic_X", PID: "prod_Y", KID: "key_Z"}
	tok := signLK1(t, priv, in)

	// Flip a bit in the signature.
	parts := strings.Split(tok, ".")
	tampered := []byte(parts[2])
	tampered[0] ^= 0xff
	tampered2 := parts[0] + "." + parts[1] + "." + string(tampered)

	_, err := verifyLK1(tampered2, map[string]ed25519.PublicKey{"key_Z": pub})
	if err == nil {
		t.Fatal("expected ErrInvalidSignature, got nil")
	}
}

func TestVerifyLK1_UnknownKID(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tok := signLK1(t, priv, Claims{LID: "lic_X", KID: "key_unknown"})

	_, err := verifyLK1(tok, map[string]ed25519.PublicKey{"key_other": pub})
	if err != ErrUnknownKID {
		t.Fatalf("expected ErrUnknownKID, got %v", err)
	}
}

func TestVerifyLK1_BadFormat(t *testing.T) {
	pub := make(ed25519.PublicKey, 32)
	keys := map[string]ed25519.PublicKey{"k": pub}
	for _, bad := range []string{"", "not.a.token", "LK1.only.two", "LK1..."} {
		t.Run(bad, func(t *testing.T) {
			if _, err := verifyLK1(bad, keys); err == nil {
				t.Errorf("expected error for %q, got nil", bad)
			}
		})
	}
}
