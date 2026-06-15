package lk

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// sdkVersion is reported in the audit client block.
const sdkVersion = "go/0.5.0"

// Activate is the online entry point. It exchanges a license key for a
// fresh signed token, verifies it locally with the product's public
// keys, caches it for offline grace, and returns a License.
//
// If the network is unavailable, Activate falls back to a previously
// cached token for the same key (valid until that token's Exp).
func Activate(lkey string, opts ...Option) (License, error) {
	o := newVerifyOpts(opts...)

	fpHex := o.fingerprint
	if fpHex == "" {
		captured, err := CapturedFingerprint()
		if err != nil {
			return nil, err
		}
		fpHex = captured
	}
	fpHex = strings.ToLower(fpHex)
	fpRaw, err := hexToFingerprint(fpHex)
	if err != nil {
		return nil, err
	}

	c := newClient(o.baseURL, o.httpClient)
	cm := buildClientMeta(o.appVersion)

	resp, err := c.exchange(lkey, fpHex, cm)
	if err != nil {
		// Authoritative failures — do not fall back to cache.
		if err == ErrSeatLimitExceeded || err == ErrLicenseKeyInvalid {
			return nil, err
		}
		return activateFromCache(lkey, fpRaw, o, c)
	}

	keys, err := c.publicKeys(resp.Claims.PID)
	if err != nil {
		return activateFromCache(lkey, fpRaw, o, c)
	}

	claims, err := verifyLK1(resp.Token, keys)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if iatFloorViolated(now, claims.IAT) {
		return nil, ErrClockAnomaly
	}
	if now.Unix() >= claims.Exp {
		return nil, ErrExpired
	}

	kb := make(map[string]string, len(keys))
	for kid, pk := range keys {
		kb[kid] = encodeKey(pk)
	}
	_ = writeCache(lkey, cacheEntry{Token: resp.Token, Claims: claims, Keys: kb, Seats: resp.Seats})

	return newOnlineLicense(lkey, fpRaw, claims, keys, resp.Seats, cm, o, c), nil
}

func activateFromCache(lkey string, fpRaw []byte, o *verifyOpts, c *client) (License, error) {
	ent, err := readCache(lkey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrActivationFailed, err)
	}
	keys, err := ent.keyMap()
	if err != nil {
		return nil, err
	}
	claims, err := verifyLK1(ent.Token, keys)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if iatFloorViolated(now, claims.IAT) {
		return nil, ErrClockAnomaly
	}
	if now.Unix() >= claims.Exp {
		return nil, ErrExpired
	}
	return newOnlineLicense(lkey, fpRaw, claims, keys, ent.Seats, buildClientMeta(o.appVersion), o, c), nil
}

func newOnlineLicense(lkey string, fpRaw []byte, claims Claims, keys map[string]ed25519.PublicKey, seats seatsDTO, cm *clientMeta, o *verifyOpts, c *client) *licenseImpl {
	refresh := o.refreshBefore
	if refresh <= 0 {
		// Default: 10% of the token's full lifetime (Exp - IAT), so an
		// already-aged cached token doesn't refresh on the first Check.
		life := time.Duration(claims.Exp-claims.IAT) * time.Second
		refresh = life / 10
	}
	return &licenseImpl{
		claims:          claims,
		productKeys:     keys,
		fingerprint:     fpRaw,
		logger:          o.logger,
		warnings:        o.expiringWarnings,
		firedThresholds: map[time.Duration]bool{},
		online:          true,
		lkey:            lkey,
		client:          c,
		clientMeta:      cm,
		refreshBefore:   refresh,
		revocationPoll:  o.revocationPoll,
		seatsLimit:      seats.Limit,
		seatsUsed:       seats.Used,
	}
}

func buildClientMeta(appVersion string) *clientMeta {
	host, _ := os.Hostname()
	return &clientMeta{
		Hostname:   host,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		AppVersion: appVersion,
		SDKVersion: sdkVersion,
	}
}
