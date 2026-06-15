package lk

import (
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"
)

func TestWithLicenseIDString_ParsesPrefixedULID(t *testing.T) {
	var lid [16]byte
	lid[0], lid[15] = 0x01, 0xff
	idStr := "lic_" + ulid.ULID(lid).String()

	o := newVerifyOpts(WithLicenseIDString(idStr))
	if o.licenseIDErr != nil {
		t.Fatalf("unexpected parse error: %v", o.licenseIDErr)
	}
	if !o.licenseIDSet {
		t.Fatal("licenseIDSet should be true")
	}
	if o.licenseID != lid {
		t.Fatalf("decoded lid mismatch: got %x want %x", o.licenseID, lid)
	}
}

func TestWithLicenseIDString_RejectsMissingPrefix(t *testing.T) {
	o := newVerifyOpts(WithLicenseIDString(ulid.Make().String())) // no "lic_"
	if o.licenseIDErr == nil {
		t.Fatal("expected error for missing lic_ prefix")
	}
	if o.licenseIDSet {
		t.Fatal("licenseIDSet must stay false on error")
	}
}

func TestWithLicenseIDString_RejectsBadULID(t *testing.T) {
	o := newVerifyOpts(WithLicenseIDString("lic_not-a-valid-ulid"))
	if o.licenseIDErr == nil {
		t.Fatal("expected error for bad ULID")
	}
}

func TestVerify_LicenseIDErr_Surfaces(t *testing.T) {
	fp := strings.Repeat("ab", 32) // 64 hex chars
	_, err := Verify([]byte("ignored"), WithFingerprint(fp), WithLicenseIDString("nope"))
	if err == nil {
		t.Fatal("expected Verify to surface the license-id parse error")
	}
}

func TestVerify_StringAndRawAgree(t *testing.T) {
	fp := "00112233445566778899aabbccddeeff" + "00112233445566778899aabbccddeeff"
	var lid [16]byte
	lid[0], lid[3], lid[15] = 0x07, 0x42, 0x99
	bundle := makeBundle(t, fp, lid, Claims{LID: "lic_x"})

	// Raw path.
	if _, err := Verify(bundle, WithFingerprint(fp), WithLicenseID(lid)); err != nil {
		t.Fatalf("raw Verify: %v", err)
	}
	// String path — same lid expressed as lic_<ulid>.
	idStr := "lic_" + ulid.ULID(lid).String()
	if _, err := Verify(bundle, WithFingerprint(fp), WithLicenseIDString(idStr)); err != nil {
		t.Fatalf("string Verify: %v", err)
	}
}
