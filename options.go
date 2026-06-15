package lk

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Option is a functional option for Verify.
type Option func(*verifyOpts)

type verifyOpts struct {
	logger           *slog.Logger
	fingerprint      string // explicit override; empty = capture via SDK
	bundlePath       string // path for watermark sidecar
	autoWatermark    bool   // derive sidecar path from license ID + user-config dir
	expiringWarnings []time.Duration
	licenseID        [16]byte
	licenseIDSet     bool
	licenseIDErr     error // deferred parse error from WithLicenseIDString; returned by Verify
	baseURL          string
	httpClient       *http.Client
	refreshBefore    time.Duration
	revocationPoll   time.Duration // 0 = disabled
	appVersion       string
}

// defaultExpiringWarnings — thresholds the SDK logs WARN on.
var defaultExpiringWarnings = []time.Duration{
	30 * 24 * time.Hour,
	7 * 24 * time.Hour,
	24 * time.Hour,
}

// WithLogger sets the slog handler that receives WARN/ERROR records
// from Verify and Check. Default: slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(o *verifyOpts) { o.logger = l }
}

// WithFingerprint overrides the machine-fingerprint capture path.
// Pass when running in an environment where the default capture
// can't get a stable identifier (Docker, exotic OS). The value MUST
// be the 64-char lowercase hex string the vendor used at issue time.
// If empty (default), the SDK captures via the same algorithm as
// lk-cli fingerprint.
func WithFingerprint(hex string) Option {
	return func(o *verifyOpts) { o.fingerprint = hex }
}

// WithBundlePath tells the SDK where to read/write the .lk-watermark
// sidecar. Verify always takes raw bundle bytes (never a path), so
// there is no path to default to: if this option is unset, the
// watermark / clock-anomaly feature is disabled entirely. Pass the
// path to the on-disk bundle to enable it.
// Takes precedence over WithAutoWatermark when both are set.
func WithBundlePath(path string) Option {
	return func(o *verifyOpts) { o.bundlePath = path }
}

// WithAutoWatermark enables the watermark / clock-anomaly sidecar with
// an SDK-chosen location, derived from the license ID under the OS
// user-config directory (e.g. ~/.config/licensekit/<LID>.lk-watermark
// on Linux). Use this when you don't want to manage a sidecar path
// yourself. If WithBundlePath is also set, that explicit path wins and
// this option is ignored. If the user-config directory can't be resolved
// (e.g. no HOME on a service account), Verify returns an error.
func WithAutoWatermark() Option {
	return func(o *verifyOpts) { o.autoWatermark = true }
}

// WithExpiringWarnings overrides the default thresholds (30d / 7d /
// 1d) at which the SDK emits a WARN log on Verify/Check that the
// license is approaching expiry.
func WithExpiringWarnings(thresholds []time.Duration) Option {
	return func(o *verifyOpts) { o.expiringWarnings = thresholds }
}

// WithLicenseID sets the license ID from raw 16-byte ULID bytes. A
// license ID is REQUIRED by Verify: the LKB1 wire format does not carry
// it in the unencrypted header, but the HKDF salt uses it to derive the
// AEAD key, so the SDK must know it.
//
// Prefer WithLicenseIDString if you have the vendor-provided "lic_..."
// string — it does the decoding for you. Use this only when you already
// hold the raw bytes.
func WithLicenseID(lidRaw [16]byte) Option {
	return func(o *verifyOpts) {
		o.licenseID = lidRaw
		o.licenseIDSet = true
	}
}

// WithLicenseIDString sets the license ID from the vendor-provided string
// form (e.g. "lic_01H...") — the SDK strips the "lic_" prefix and decodes
// the ULID to the raw 16 bytes Verify needs. Use WithLicenseID instead if
// you already hold the raw [16]byte. A malformed value is reported as an
// error from Verify (functional options cannot return one directly).
//
// Not to be confused with the online license key passed to Activate.
func WithLicenseIDString(id string) Option {
	return func(o *verifyOpts) {
		rest, ok := strings.CutPrefix(id, "lic_")
		if !ok {
			o.licenseIDErr = fmt.Errorf("lk: license id %q must be a \"lic_\"-prefixed ULID", id)
			return
		}
		u, err := ulid.Parse(rest)
		if err != nil {
			o.licenseIDErr = fmt.Errorf("lk: invalid license id %q: %w", id, err)
			return
		}
		o.licenseID = u // ulid.ULID is [16]byte
		o.licenseIDSet = true
	}
}

// WithBaseURL overrides the LicenseKit API host used by Activate.
// Default: https://api.licensekit.io.
func WithBaseURL(url string) Option {
	return func(o *verifyOpts) { o.baseURL = url }
}

// WithHTTPClient overrides the http.Client used by Activate (timeouts,
// proxy, custom transport, tests). Default: 10s timeout.
func WithHTTPClient(c *http.Client) Option {
	return func(o *verifyOpts) { o.httpClient = c }
}

// WithRefreshBefore sets how long before token expiry Check() re-exchanges
// for a fresh token. Default: 10% of the token's lifetime.
func WithRefreshBefore(d time.Duration) Option {
	return func(o *verifyOpts) { o.refreshBefore = d }
}

// WithRevocationPolling enables periodic checks of the product's signed
// revocation list during Check(). Default: disabled (the short token TTL
// already bounds revocation latency).
func WithRevocationPolling(interval time.Duration) Option {
	return func(o *verifyOpts) { o.revocationPoll = interval }
}

// WithAppVersion sets the app version reported in the audit `client`
// block sent to the server (hostname/os/arch/sdk version are filled
// automatically).
func WithAppVersion(v string) Option {
	return func(o *verifyOpts) { o.appVersion = v }
}

func newVerifyOpts(opts ...Option) *verifyOpts {
	o := &verifyOpts{
		logger:           slog.Default(),
		expiringWarnings: defaultExpiringWarnings,
		baseURL:          "https://api.licensekit.io",
		httpClient:       &http.Client{Timeout: 10 * time.Second},
	}
	for _, fn := range opts {
		fn(o)
	}
	return o
}
