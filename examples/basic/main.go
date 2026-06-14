// Package main is a minimal runnable demonstration of the LicenseKit
// Go SDK. Reads a bundle from disk, verifies it against a passed
// license-ID hex, prints the claims, then runs a 2-second Monitor
// loop showing how expiry/clock-anomaly events fire.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	lk "github.com/LicenseKit/sdk_go"
)

func main() {
	var (
		bundlePath = flag.String("bundle", "license.lkbundle", "path to bundle file")
		licenseID  = flag.String("lid", "", "raw license id (32 hex chars)")
	)
	flag.Parse()

	if *licenseID == "" {
		fmt.Fprintln(os.Stderr, "usage: basic -bundle <path> -lid <32-hex-chars>")
		fmt.Fprintln(os.Stderr, "  (lid is the raw 16-byte ULID hex; ask your vendor for it)")
		os.Exit(2)
	}

	bundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		fatal("read bundle", err)
	}

	lidBytes, err := hex.DecodeString(*licenseID)
	if err != nil || len(lidBytes) != 16 {
		fatal("license_id must be 32 hex chars", err)
	}
	var lid [16]byte
	copy(lid[:], lidBytes)

	lic, err := lk.Verify(bundle,
		lk.WithLicenseID(lid),
		lk.WithBundlePath(*bundlePath),
		lk.WithLogger(slog.Default()),
	)
	if err != nil {
		fatal("verify", err)
	}

	c := lic.Claims()
	fmt.Printf("Valid license for subject %q, expires %s (in %s)\n",
		c.Sub, lic.ValidUntil().Format(time.RFC3339), lic.Until().Truncate(time.Minute))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mon := lk.NewMonitor(lic, lk.WithInterval(500*time.Millisecond))
	for evt := range mon.Start(ctx) {
		switch e := evt.(type) {
		case lk.Expired:
			fmt.Println("LICENSE EXPIRED — shutting down")
			_ = e
			return
		case lk.ClockAnomaly:
			fmt.Printf("CLOCK ROLLBACK detected at %v\n", e.DetectedAt)
			return
		case lk.ExpiringSoon:
			fmt.Printf("Warning: expires in %s\n", e.Until.Truncate(time.Hour))
		}
	}
}

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	if errors.Is(err, lk.ErrExpired) {
		os.Exit(3)
	}
	os.Exit(1)
}
