package lk

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func onlineServer(t *testing.T, pub ed25519.PublicKey, token string, claims Claims) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(exchangeResp{Token: token, Claims: claims, Seats: seatsDTO{Limit: 3, Used: 1}})
	})
	mux.HandleFunc("/v1/products/prod_1/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kid": "key_1", "alg": "Ed25519", "status": "active", "public_key": []byte(pub)},
		}})
	})
	return httptest.NewServer(mux)
}

func TestActivate_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	pub, priv, _ := ed25519.GenerateKey(nil)
	claims := Claims{LID: "lic_x", PID: "prod_1", KID: "key_1", IAT: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()}
	tok := signLK1(t, priv, claims)
	srv := onlineServer(t, pub, tok, claims)
	defer srv.Close()

	lic, err := Activate("lic_key", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithFingerprint(strings.Repeat("ab", 32)))
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if lic.Claims().PID != "prod_1" {
		t.Fatalf("claims: %+v", lic.Claims())
	}
	if limit, used := lic.Seats(); limit != 3 || used != 1 {
		t.Fatalf("seats: %d/%d", limit, used)
	}
	if err := lic.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if _, err := readCache("lic_key"); err != nil {
		t.Fatalf("cache missing: %v", err)
	}
}

func TestActivate_OfflineColdStart(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	pub, priv, _ := ed25519.GenerateKey(nil)
	claims := Claims{LID: "lic_x", PID: "prod_1", KID: "key_1", IAT: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()}
	tok := signLK1(t, priv, claims)
	if err := writeCache("lic_key", cacheEntry{Token: tok, Claims: claims, Keys: map[string]string{"key_1": encodeKey(pub)}, Seats: seatsDTO{Limit: 3, Used: 1}}); err != nil {
		t.Fatal(err)
	}

	lic, err := Activate("lic_key", WithBaseURL("http://127.0.0.1:1"), WithHTTPClient(&http.Client{Timeout: 100 * time.Millisecond}), WithFingerprint(strings.Repeat("ab", 32)))
	if err != nil {
		t.Fatalf("cold-start: %v", err)
	}
	if lic.Claims().PID != "prod_1" {
		t.Fatalf("claims: %+v", lic.Claims())
	}
}

func TestActivate_SeatLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(apiError{Code: "seat_limit_exceeded", Message: "full"})
	}))
	defer srv.Close()
	_, err := Activate("lic_key", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()), WithFingerprint(strings.Repeat("ab", 32)))
	if err != ErrSeatLimitExceeded {
		t.Fatalf("want ErrSeatLimitExceeded, got %v", err)
	}
}

func TestRelease(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/certificates/release" {
			hit = true
			_ = json.NewEncoder(w).Encode(map[string]bool{"released": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	l := &licenseImpl{online: true, lkey: "lic_key", fingerprint: []byte{0xab}, client: newClient(srv.URL, srv.Client())}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("release endpoint not called")
	}
}

func TestCheck_RevocationPolling(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	pub, priv, _ := ed25519.GenerateKey(nil)
	claims := Claims{LID: "lic_x", PID: "prod_1", KID: "key_1", IAT: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()}
	tok := signLK1(t, priv, claims)

	inner, _ := json.Marshal(revocationList{Revoked: []string{"lic_x"}, IAT: 1})
	payload := base64.RawURLEncoding.EncodeToString(inner)
	sig := ed25519.Sign(priv, []byte("LKR1."+payload))

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(exchangeResp{Token: tok, Claims: claims, Seats: seatsDTO{Limit: 3, Used: 1}})
	})
	mux.HandleFunc("/v1/products/prod_1/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kid": "key_1", "alg": "Ed25519", "status": "active", "public_key": []byte(pub)},
		}})
	})
	mux.HandleFunc("/v1/products/prod_1/revocations", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(signedRevocation{V: "LKR1", Payload: payload, KID: "key_1", Sig: base64.RawURLEncoding.EncodeToString(sig)})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	lic, err := Activate("lic_key", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()),
		WithFingerprint(strings.Repeat("ab", 32)), WithRevocationPolling(time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if err := lic.Check(); err != ErrRevoked {
		t.Fatalf("want ErrRevoked, got %v", err)
	}
}

func TestCheck_RefreshNearExpiry(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	pub, priv, _ := ed25519.GenerateKey(nil)
	// Token already near expiry (30s left) so Check() triggers a refresh.
	near := Claims{LID: "lic_x", PID: "prod_1", KID: "key_1", IAT: time.Now().Add(-time.Hour).Unix(), Exp: time.Now().Add(30 * time.Second).Unix()}
	// The refreshed token the server will return (fresh 1h).
	fresh := Claims{LID: "lic_x", PID: "prod_1", KID: "key_1", IAT: time.Now().Unix(), Exp: time.Now().Add(time.Hour).Unix()}
	freshTok := signLK1(t, priv, fresh)
	nearTok := signLK1(t, priv, near)

	var exchanges int
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		exchanges++
		// First call (Activate) returns the near-expiry token; later calls return fresh.
		if exchanges == 1 {
			_ = json.NewEncoder(w).Encode(exchangeResp{Token: nearTok, Claims: near, Seats: seatsDTO{Limit: 3, Used: 1}})
			return
		}
		_ = json.NewEncoder(w).Encode(exchangeResp{Token: freshTok, Claims: fresh, Seats: seatsDTO{Limit: 3, Used: 2}})
	})
	mux.HandleFunc("/v1/products/prod_1/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kid": "key_1", "alg": "Ed25519", "status": "active", "public_key": []byte(pub)},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// WithRefreshBefore large enough that the 30s-left token is "near expiry".
	lic, err := Activate("lic_key", WithBaseURL(srv.URL), WithHTTPClient(srv.Client()),
		WithFingerprint(strings.Repeat("ab", 32)), WithRefreshBefore(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := lic.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if exchanges < 2 {
		t.Fatalf("expected a refresh exchange on Check, exchanges=%d", exchanges)
	}
	// Seats updated from the refresh response (Used 2).
	if _, used := lic.Seats(); used != 2 {
		t.Fatalf("seats not refreshed: used=%d want 2", used)
	}
}

func TestCheck_GraceWhenServerDown(t *testing.T) {
	tmp := t.TempDir()
	orig := userConfigDir
	userConfigDir = func() (string, error) { return tmp, nil }
	t.Cleanup(func() { userConfigDir = orig })

	pub, priv, _ := ed25519.GenerateKey(nil)
	// Near expiry so Check tries to refresh — but the server will be down.
	claims := Claims{LID: "lic_x", PID: "prod_1", KID: "key_1", IAT: time.Now().Add(-time.Hour).Unix(), Exp: time.Now().Add(30 * time.Second).Unix()}
	tok := signLK1(t, priv, claims)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(exchangeResp{Token: tok, Claims: claims, Seats: seatsDTO{Limit: 3, Used: 1}})
	})
	mux.HandleFunc("/v1/products/prod_1/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kid": "key_1", "alg": "Ed25519", "status": "active", "public_key": []byte(pub)},
		}})
	})
	srv := httptest.NewServer(mux)

	lic, err := Activate("lic_key", WithBaseURL(srv.URL), WithHTTPClient(&http.Client{Timeout: 200 * time.Millisecond}),
		WithFingerprint(strings.Repeat("ab", 32)), WithRefreshBefore(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// Now the server goes away; Check() should refresh-fail but grace on the
	// cached (still-valid, 30s-left) token → no error.
	srv.Close()
	if err := lic.Check(); err != nil {
		t.Fatalf("grace Check should pass on still-valid cached token, got %v", err)
	}
}
