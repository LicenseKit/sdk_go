package lk

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatermark_WriteReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "license.lkbundle")
	fp := make([]byte, 32)
	fp[0] = 0xab
	lid := [16]byte{1}
	now := time.Unix(1750000000, 0)

	if err := writeWatermark(bundle, fp, lid, now); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readWatermark(bundle, fp, lid)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Unix() != now.Unix() {
		t.Errorf("ts: got %v, want %v", got, now)
	}
}

func TestWatermark_TamperedHMAC(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "license.lkbundle")
	fp := make([]byte, 32)
	fp[0] = 0xab
	lid := [16]byte{1}
	now := time.Unix(1750000000, 0)

	if err := writeWatermark(bundle, fp, lid, now); err != nil {
		t.Fatal(err)
	}

	// Corrupt the sidecar — overwrite the last byte of the file.
	sidecarPath := bundle + ".lk-watermark"
	data, _ := os.ReadFile(sidecarPath)
	data[len(data)-2] ^= 0xff
	os.WriteFile(sidecarPath, data, 0o644)

	_, err := readWatermark(bundle, fp, lid)
	if err != ErrWatermarkTampered {
		t.Errorf("expected ErrWatermarkTampered, got %v", err)
	}
}

func TestWatermark_AbsentReturnsZero(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "license.lkbundle")
	fp := make([]byte, 32)
	lid := [16]byte{1}

	got, err := readWatermark(bundle, fp, lid)
	if err != nil {
		t.Errorf("absent watermark should return zero+nil, got err=%v", err)
	}
	if !got.IsZero() {
		t.Errorf("absent watermark should return zero time, got %v", got)
	}
}

func TestWatermark_DifferentFingerprintTreatedAsTamper(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "license.lkbundle")
	fp1 := make([]byte, 32)
	fp1[0] = 0xab
	fp2 := make([]byte, 32)
	fp2[0] = 0xcd
	lid := [16]byte{1}
	now := time.Unix(1750000000, 0)

	if err := writeWatermark(bundle, fp1, lid, now); err != nil {
		t.Fatal(err)
	}

	_, err := readWatermark(bundle, fp2, lid)
	if err != ErrWatermarkTampered {
		t.Errorf("wrong fingerprint should fail HMAC, got %v", err)
	}
}
