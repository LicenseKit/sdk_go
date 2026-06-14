package lk

// Claims is the payload of an LK1 token. Field order MUST match
// backend's pkg/token.Claims byte-for-byte (encoding/json emits in
// declaration order; signatures are computed over the byte stream).
// Cross-language SDKs in other repos verify parity against
// testdata/vectors.json.
//
// Exp vs LicExp semantics:
//
//   - Exp is when the TOKEN expires (bounded by the offline bundle
//     TTL chosen by the vendor at issue time; long-lived but finite).
//     Apps MUST refuse to act on the license after Exp.
//
//   - LicExp is when the underlying LICENSE expires (subscription
//     end, trial cutoff). Optional — absent for perpetual licenses.
//     Use for UX ("subscription ends in N days"); NOT for refusal
//     (Exp is the refusal cutoff).
type Claims struct {
	LID    string         `json:"lid"`
	PID    string         `json:"pid"`
	KID    string         `json:"kid"`
	Sub    string         `json:"sub"`
	Typ    string         `json:"typ"`
	IAT    int64          `json:"iat"`
	Exp    int64          `json:"exp"`
	Ent    map[string]any `json:"ent"`
	Meta   map[string]any `json:"meta,omitempty"`
	LicExp int64          `json:"lic_exp,omitempty"`
}
