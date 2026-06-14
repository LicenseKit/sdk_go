//go:build darwin

package lk

import (
	"errors"
	"os/exec"
	"regexp"
	"strings"
)

// captureRawSources runs `ioreg -rd1 -c IOPlatformExpertDevice` and
// extracts the IOPlatformUUID line. This is the canonical macOS
// hardware UUID — stable across OS reinstall but changes on
// logic-board replacement.
func captureRawSources() ([]string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return nil, errors.New("lk: ioreg invocation failed: " + err.Error())
	}
	re := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
	m := re.FindStringSubmatch(string(out))
	if len(m) < 2 || m[1] == "" {
		return nil, errors.New("lk: IOPlatformUUID not found in ioreg output")
	}
	return []string{"ioplatform-uuid:" + strings.TrimSpace(m[1])}, nil
}
