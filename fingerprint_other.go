//go:build !linux && !darwin && !windows

package lk

import "errors"

func captureRawSources() ([]string, error) {
	return nil, errors.New("lk: machine fingerprint capture is only implemented for linux / darwin / windows")
}
