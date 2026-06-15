package lk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const revocationVersion = "LKR1"

// signedRevocation mirrors the backend pkg/revocation.Signed envelope.
type signedRevocation struct {
	V       string `json:"v"`
	Payload string `json:"payload"`
	KID     string `json:"kid"`
	Sig     string `json:"sig"`
}

type revocationList struct {
	Revoked []string `json:"revoked"`
	IAT     int64    `json:"iat"`
}

func (l revocationList) contains(lid string) bool {
	for _, r := range l.Revoked {
		if r == lid {
			return true
		}
	}
	return false
}

// verify checks the LKR1 signature with the product keys and returns the
// inner list. Signing input is "LKR1." + payload (the base64url string).
func (s signedRevocation) verify(keys map[string]ed25519.PublicKey) (revocationList, error) {
	if s.V != revocationVersion {
		return revocationList{}, fmt.Errorf("%w: unknown revocation version %q", ErrActivationFailed, s.V)
	}
	pub, ok := keys[s.KID]
	if !ok {
		return revocationList{}, ErrUnknownKID
	}
	sig, err := base64.RawURLEncoding.DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return revocationList{}, ErrInvalidSignature
	}
	if !ed25519.Verify(pub, []byte(revocationVersion+"."+s.Payload), sig) {
		return revocationList{}, ErrInvalidSignature
	}
	raw, err := base64.RawURLEncoding.DecodeString(s.Payload)
	if err != nil {
		return revocationList{}, fmt.Errorf("%w: bad revocation payload", ErrActivationFailed)
	}
	var list revocationList
	if err := json.Unmarshal(raw, &list); err != nil {
		return revocationList{}, fmt.Errorf("%w: revocation payload not JSON", ErrActivationFailed)
	}
	return list, nil
}
