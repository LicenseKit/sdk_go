//go:build linux

package lk

import (
	"errors"
	"os"
	"strings"
)

// captureRawSources reads Linux machine identity files.
//   - /etc/machine-id is the canonical systemd-managed identifier;
//     stable across reboots, changes only on systemd-firstboot.
//   - /sys/class/dmi/id/product_uuid is BIOS-level UUID; stable
//     across OS reinstall on bare metal but often unreadable in
//     containers / non-root contexts.
//
// Returns whichever sources are readable; fails only if none.
func captureRawSources() ([]string, error) {
	var out []string
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" {
			out = append(out, "machine-id:"+s)
		}
	}
	if b, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" {
			out = append(out, "dmi-product-uuid:"+s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("lk: no Linux fingerprint sources readable (need /etc/machine-id)")
	}
	return out, nil
}
