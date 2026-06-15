package lk

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestCache_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	pub, _, _ := ed25519.GenerateKey(nil)
	ent := cacheEntry{
		Token:  "tok",
		Claims: Claims{LID: "lic_x", PID: "prod_1", Exp: 123},
		Keys:   map[string]string{"key_1": encodeKey(pub)},
		Seats:  seatsDTO{Limit: 5, Used: 1},
	}
	if err := writeCache("lic_k", ent); err != nil {
		t.Fatal(err)
	}

	got, err := readCache("lic_k")
	if err != nil {
		t.Fatal(err)
	}
	if got.Token != "tok" || got.Claims.PID != "prod_1" || got.Seats.Limit != 5 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// keyMap decodes back to a usable verify key.
	km, err := got.keyMap()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := km["key_1"]; !ok {
		t.Fatal("key_1 missing from keyMap")
	}

	// File lands at the SHA256(lkey)[:16] path.
	want := filepath.Join(tmp, "licensekit", cacheName("lic_k"))
	if _, err := readCacheAt(want); err != nil {
		t.Fatalf("cache not at expected path %s: %v", want, err)
	}

	// Unknown key → miss (error).
	if _, err := readCache("other"); err == nil {
		t.Fatal("expected miss for unknown key")
	}
}
