package lk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// verifyLK1 parses an LK1.<payload-b64>.<sig-b64> token, finds the
// public key by claims.kid in the keys map, verifies the Ed25519
// signature OVER the base64 payload bytes (NOT the decoded JSON —
// this is the load-bearing invariant of the wire format), and
// returns the parsed claims.
//
// Errors map to: ErrInvalidSignature (bad sig), ErrUnknownKID (kid
// not in map), or a generic wrap for malformed input.
func verifyLK1(tok string, keys map[string]ed25519.PublicKey) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] != "LK1" || parts[1] == "" || parts[2] == "" {
		return Claims{}, errors.New("lk: token must have LK1.<payload>.<sig> shape")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("lk: payload not base64-url")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("lk: signature not base64-url")
	}

	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, errors.New("lk: payload not JSON")
	}

	pub, ok := keys[c.KID]
	if !ok {
		return Claims{}, ErrUnknownKID
	}

	// Signature is over the BASE64 payload string bytes, NOT the
	// re-canonicalised JSON. This is the whole point of the LK1
	// wire format — any verifier that re-marshals JSON before
	// hashing will get the WRONG sig-input and reject valid tokens.
	if !ed25519.Verify(pub, []byte(parts[1]), sig) {
		return Claims{}, ErrInvalidSignature
	}
	return c, nil
}
