# LicenseKit Go SDK

Verify-side library for offline `.lkbundle` license files issued by
the LicenseKit backend. Zero network dependencies; all verification
happens locally against bytes the vendor delivered out-of-band.

> ⚠️ Pre-v1.0. API may change in minor releases until v1.0.0 ships.

## Install

```bash
go get github.com/LicenseKit/sdk_go
```

Requires Go 1.22+. No external dependencies beyond `golang.org/x/crypto` (HKDF) and `golang.org/x/sys` (Windows registry).

## Quick start

```go
package main

import (
    "log/slog"
    "os"
    "strings"

    "github.com/oklog/ulid/v2"
    lk "github.com/LicenseKit/sdk_go"
)

func main() {
    bundle, err := os.ReadFile("/etc/myapp/license.lkbundle")
    if err != nil {
        slog.Error("read bundle", "err", err)
        os.Exit(1)
    }

    // Decode the license-id string your vendor provided.
    u, _ := ulid.Parse(strings.TrimPrefix("lic_01H...", "lic_"))
    var lidRaw [16]byte = u

    lic, err := lk.Verify(bundle,
        lk.WithLicenseID(lidRaw),
        lk.WithBundlePath("/etc/myapp/license.lkbundle"),
    )
    if err != nil {
        slog.Error("license invalid", "err", err)
        os.Exit(1)
    }
    slog.Info("license OK", "subject", lic.Claims().Sub, "expires", lic.ValidUntil())

    // Before each license-gated operation:
    if err := lic.Check(); err != nil {
        slog.Error("license check failed", "err", err)
        return
    }
    // ... do work ...
}
```

See `examples/basic/` for a runnable demo.

## ⚠️ Long-running servers

If your app only calls `Verify` once at startup and runs for days or
weeks without restart, **license expiry will go undetected** until next
launch. You have two options:

**Option 1 — Call `lic.Check()` periodically yourself:**

```go
for range time.NewTicker(1 * time.Hour).C {
    if err := lic.Check(); err != nil {
        slog.Error("license expired or invalid", "err", err)
        gracefulShutdown()
        return
    }
}
```

**Option 2 — Use the built-in `Monitor`:**

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

mon := lk.NewMonitor(lic, lk.WithInterval(1*time.Hour))
go func() {
    for evt := range mon.Start(ctx) {
        switch e := evt.(type) {
        case lk.Expired:
            slog.Error("license expired, shutting down")
            gracefulShutdown()
        case lk.ClockAnomaly:
            slog.Error("clock rollback detected", "at", e.DetectedAt)
            gracefulShutdown()
        case lk.ExpiringSoon:
            slog.Warn("license expires soon", "in", e.Until)
        }
    }
}()
```

## API reference

### `func Verify(bundle []byte, opts ...Option) (License, error)`

Parses, decrypts, validates an LKB1 bundle. Returns a `License` handle
on success.

**Required:** `WithLicenseID(rawULID [16]byte)` — the license ID the
bundle was minted for. The LKB1 wire format does NOT carry this in its
unencrypted header (HKDF salt uses it), so the customer app must supply
it explicitly.

### `License` interface

```go
type License interface {
    Claims() Claims
    Check() error
    ValidUntil() time.Time
    Until() time.Duration
}
```

- `Claims()` — cached parsed claims (cheap, no I/O).
- `Check()` — re-validates expiry against `max(system_time, watermark.last_seen)`.
  Returns `ErrExpired`, `ErrClockAnomaly`, or nil. Cheap; throttled
  watermark write at most 1/hour.
- `ValidUntil()` — `time.Unix(claims.Exp, 0)`.
- `Until()` — `time.Until(ValidUntil())`.

### `Monitor`

`lk.NewMonitor(lic).Start(ctx) <-chan Event` — background goroutine that
periodically calls `Check` and emits events (`ExpiringSoon{Until}`,
`Expired{Err}`, `ClockAnomaly{DetectedAt}`). Channel closes when ctx
is cancelled.

### Options

| Option | Default | Purpose |
|---|---|---|
| `WithLicenseID(lid [16]byte)` | **required** | Raw 16-byte ULID of the license the bundle was minted for. |
| `WithFingerprint(hex string)` | auto-capture via OS | Override the machine-fingerprint capture path. Use when running in Docker / exotic OS where the default can't get a stable identifier. |
| `WithBundlePath(string)` | none | Where to read/write the `.lk-watermark` sidecar. If empty, watermark feature is disabled. |
| `WithLogger(*slog.Logger)` | `slog.Default()` | Where to emit WARN/ERROR records. |
| `WithExpiringWarnings([]time.Duration)` | `[30d, 7d, 1d]` | Thresholds at which the SDK emits a WARN log on Verify/Check that the license is approaching expiry. |

### Errors

| Sentinel | Meaning |
|---|---|
| `ErrMalformedBundle` | Bundle bytes don't match LKB1 wire format (bad magic / version / too short). |
| `ErrWrongFingerprint` | AEAD decrypt failed — wrong machine or tampered ciphertext. |
| `ErrInvalidSignature` | LK1 token's Ed25519 signature failed verification. |
| `ErrExpired` | Bundle TTL has passed. |
| `ErrClockAnomaly` | System time is BEFORE the high-watermark recorded in the sidecar. |
| `ErrWatermarkTampered` | Sidecar HMAC validation failed. |
| `ErrUnknownKID` | LK1 token's `kid` claim does not match any key in the bundle's `product_keys`. |

## Threat model

The SDK assumes a hostile customer environment:

- Customer may have root access to the host.
- Customer may copy the bundle to other machines (`ErrWrongFingerprint`).
- Customer may roll back the system clock (`ErrClockAnomaly` via watermark).
- Customer may delete the watermark sidecar (SDK creates fresh, treats as TOFU — defeats this layer alone, but watermark + clock-rollback combined still catches typical fraud).

The SDK does NOT defend against:
- Process memory dumps to extract claims after Verify succeeds.
- Customer running their own modified verifier instead of this SDK.
- Customer's IT colluding with the customer to defraud the vendor.

These are out of scope by design — they require app-level obfuscation,
attestation, or external enforcement (legal, EULA, audit).

## Cross-language SDKs

Wire-format parity is enforced via `testdata/vectors.json` (synced from
backend). All cross-language SDKs (Python, Rust, JS, …) consume the
same vectors as test fixtures. Currently only the Go SDK exists; other
languages will land by request.

## License

Apache-2.0 — see [LICENSE](LICENSE).
