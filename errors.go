package lk

import "errors"

// Public sentinel errors. Callers MAY type-check with errors.Is.
// Most app code only needs to react to ErrExpired vs everything-else.
var (
	// ErrMalformedBundle — bundle bytes don't match LKB1 wire format
	// (bad magic / version / too short). Likely a transport corruption
	// or wrong file.
	ErrMalformedBundle = errors.New("lk: malformed bundle")

	// ErrWrongFingerprint — AEAD decrypt failed. Either the bundle was
	// minted for a different machine (customer copied it across
	// machines) or the machine fingerprint sources changed (OS
	// reinstall, hardware swap). Cannot be distinguished from a
	// tampered ciphertext by design.
	ErrWrongFingerprint = errors.New("lk: wrong fingerprint or tampered bundle")

	// ErrInvalidSignature — LK1 token inside the bundle failed Ed25519
	// signature verification. Indicates the bundle was tampered after
	// issue OR signed by a key not in the bundle's product_keys list.
	// Also returned when a signed revocation list fails signature
	// verification in online mode.
	ErrInvalidSignature = errors.New("lk: invalid LK1 signature")

	// ErrExpired — bundle TTL has passed. The app must obtain a fresh
	// bundle from the vendor.
	ErrExpired = errors.New("lk: license expired")

	// ErrClockAnomaly — the system clock appears to have been rolled
	// back. Triggered either when system time is BEFORE the high-watermark
	// recorded in the sidecar, OR when system time is BEFORE the token's
	// signed issue time (iat) minus the allowed skew — the latter needs no
	// sidecar. Treat as expired (refuse to serve).
	ErrClockAnomaly = errors.New("lk: clock anomaly detected")

	// ErrWatermarkTampered — sidecar HMAC validation failed. Refuse
	// to verify until the sidecar is either valid or absent (a
	// missing sidecar is recreated on next Verify under
	// trust-on-first-use).
	ErrWatermarkTampered = errors.New("lk: watermark sidecar tampered")

	// ErrUnknownKID — the LK1 token's `kid` claim does not match any
	// key in the bundle's product_keys list. Indicates a bundle/key
	// version mismatch; the vendor needs to re-issue. Also returned when
	// a signed revocation list references a kid not in the known keys.
	ErrUnknownKID = errors.New("lk: unknown kid in token")

	// errMissingFingerprint — internal: no OS source available for
	// fingerprint capture. Wrapped by CapturedFingerprint into a
	// more informative error including the OS name.
	errMissingFingerprint = errors.New("lk: no fingerprint sources available on this OS")

	// ErrLicenseKeyInvalid — the license key string is malformed or not
	// recognised by the server (bad format / unknown key).
	ErrLicenseKeyInvalid = errors.New("lk: invalid license key")

	// ErrSeatLimitExceeded — activating this machine would exceed the
	// license's machine (seat) limit. Free a seat (Release on another
	// machine) or raise the limit.
	ErrSeatLimitExceeded = errors.New("lk: seat limit exceeded")

	// ErrActivationFailed — the online activation could not complete
	// (network error, non-2xx the SDK can't classify, no cached token to
	// fall back to). Wraps the underlying cause.
	ErrActivationFailed = errors.New("lk: activation failed")

	// ErrRevoked — the license appears in the product's signed
	// revocation list. Refuse to serve.
	ErrRevoked = errors.New("lk: license revoked")
)
