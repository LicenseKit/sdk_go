// Package lk verifies offline LicenseKit license bundles (.lkbundle
// files) on customer machines. Zero network dependencies; all
// verification happens locally against bytes the vendor delivers
// out-of-band (email, USB, signed mail, etc.).
//
// # Quickstart
//
//	bundle, _ := os.ReadFile("/etc/myapp/license.lkbundle")
//	lic, err := lk.Verify(bundle, lk.WithLicenseIDString("lic_01H..."), lk.WithLogger(myLogger))
//	if err != nil {
//	    log.Fatalf("license: %v", err)
//	}
//
//	// Before each license-gated operation:
//	if err := lic.Check(); err != nil {
//	    return fmt.Errorf("license check: %w", err)
//	}
//
// # Long-running servers
//
// If your app only calls Verify at startup and runs for days or
// weeks without restart, license expiry will go undetected until
// next launch. Either call lic.Check() periodically yourself OR
// use lk.NewMonitor(lic) to spawn a background watcher that emits
// events as expiry approaches.
//
// # Wire format
//
// The bundle is an LKB1-versioned binary: magic 'LKB1', version
// byte 0x01, 12-byte AES-GCM nonce, ciphertext+tag. AEAD key is
// derived via HKDF-SHA256 from the machine fingerprint (which the
// vendor knows because the customer ran lk-cli fingerprint and
// shipped the hex string with their license request).
//
// See https://github.com/LicenseKit/backend (private) for the full
// design.
package lk
