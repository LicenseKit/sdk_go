package lk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_Exchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/certificates" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var req exchangeReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Key != "lic_k" || req.Fingerprint != "fp" {
			t.Errorf("bad body: %+v", req)
		}
		_ = json.NewEncoder(w).Encode(exchangeResp{
			Token:  "tok",
			Claims: Claims{LID: "lic_x", PID: "prod_1", Exp: 9999999999},
			Seats:  seatsDTO{Limit: 5, Used: 2},
		})
	}))
	defer srv.Close()

	c := newClient(srv.URL, srv.Client())
	resp, err := c.exchange("lic_k", "fp", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Token != "tok" || resp.Seats.Limit != 5 || resp.Claims.PID != "prod_1" {
		t.Fatalf("bad resp: %+v", resp)
	}
}

func TestClient_Exchange_SeatLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(apiError{Code: "seat_limit_exceeded", Message: "full"})
	}))
	defer srv.Close()
	_, err := newClient(srv.URL, srv.Client()).exchange("k", "fp", nil)
	if err != ErrSeatLimitExceeded {
		t.Fatalf("want ErrSeatLimitExceeded, got %v", err)
	}
}

func TestClient_Exchange_BadKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(apiError{Code: "license_key_invalid", Message: "nope"})
	}))
	defer srv.Close()
	_, err := newClient(srv.URL, srv.Client()).exchange("k", "fp", nil)
	if err != ErrLicenseKeyInvalid {
		t.Fatalf("want ErrLicenseKeyInvalid, got %v", err)
	}
}

func TestClient_PublicKeys(t *testing.T) {
	pub := make([]byte, 32) // 32 zero bytes — valid length
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/products/prod_1/keys" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{
			{"kid": "key_1", "alg": "Ed25519", "status": "active", "public_key": pub},
			{"kid": "key_old", "alg": "Ed25519", "status": "revoked", "public_key": pub},
		}})
	}))
	defer srv.Close()
	keys, err := newClient(srv.URL, srv.Client()).publicKeys("prod_1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keys["key_1"]; !ok {
		t.Fatal("active key missing")
	}
	if _, ok := keys["key_old"]; ok {
		t.Fatal("revoked key must be skipped")
	}
}

func TestClient_Release(t *testing.T) {
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
	if err := newClient(srv.URL, srv.Client()).release("k", "fp"); err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("release not called")
	}
}
