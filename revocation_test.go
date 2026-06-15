package lk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
)

func TestRevocation_VerifyAndContains(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keys := map[string]ed25519.PublicKey{"key_1": pub}

	inner, _ := json.Marshal(struct {
		Revoked []string `json:"revoked"`
		IAT     int64    `json:"iat"`
	}{Revoked: []string{"lic_bad"}, IAT: 100})
	payload := base64.RawURLEncoding.EncodeToString(inner)
	sig := ed25519.Sign(priv, []byte("LKR1."+payload))

	s := signedRevocation{
		V: "LKR1", Payload: payload, KID: "key_1",
		Sig: base64.RawURLEncoding.EncodeToString(sig),
	}

	list, err := s.verify(keys)
	if err != nil {
		t.Fatal(err)
	}
	if !list.contains("lic_bad") || list.contains("lic_ok") {
		t.Fatalf("membership wrong: %+v", list)
	}

	// Unknown kid → ErrUnknownKID.
	badKid := s
	badKid.KID = "key_x"
	if _, err := badKid.verify(keys); err != ErrUnknownKID {
		t.Fatalf("want ErrUnknownKID, got %v", err)
	}

	// Tampered payload → signature mismatch.
	bad := s
	bad.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"revoked":["x"],"iat":1}`))
	if _, err := bad.verify(keys); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}

	// Unknown version → ErrActivationFailed (wrapped).
	badVer := s
	badVer.V = "LKR9"
	if _, err := badVer.verify(keys); !errors.Is(err, ErrActivationFailed) {
		t.Fatalf("want ErrActivationFailed for bad version, got %v", err)
	}
}
