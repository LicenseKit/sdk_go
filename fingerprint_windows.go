//go:build windows

package lk

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// captureRawSources reads MachineGuid from the registry — the
// Windows-side stable identifier. Created during OS install,
// changes only on reinstall or `sysprep /generalize`.
func captureRawSources() ([]string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return nil, errors.New("lk: open registry key Cryptography: " + err.Error())
	}
	defer k.Close()
	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return nil, errors.New("lk: read MachineGuid: " + err.Error())
	}
	if guid == "" {
		return nil, errors.New("lk: MachineGuid is empty")
	}
	return []string{"machine-guid:" + guid}, nil
}
