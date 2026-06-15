package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	lk "github.com/LicenseKit/sdk_go"
)

func main() {
	key := flag.String("key", "", "license key (lic_...)")
	flag.Parse()
	if *key == "" {
		fmt.Fprintln(os.Stderr, "usage: online -key lic_...")
		os.Exit(2)
	}

	lic, err := lk.Activate(*key, lk.WithAppVersion("example/1.0.0"))
	if err != nil {
		slog.Error("activate", "err", err)
		os.Exit(1)
	}
	defer func() { _ = lic.Release() }()

	limit, used := lic.Seats()
	c := lic.Claims()
	fmt.Printf("Activated %q — seats %d/%d, expires %s\n",
		c.Sub, used, limit, lic.ValidUntil().Format(time.RFC3339))

	if err := lic.Check(); err != nil {
		slog.Error("check", "err", err)
		os.Exit(1)
	}
	fmt.Println("license OK")
}
