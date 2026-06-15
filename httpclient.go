package lk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type client struct {
	baseURL string
	hc      *http.Client
}

func newClient(baseURL string, hc *http.Client) *client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &client{baseURL: baseURL, hc: hc}
}

type clientMeta struct {
	Hostname   string `json:"hostname,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	AppVersion string `json:"app_version,omitempty"`
	SDKVersion string `json:"sdk_version,omitempty"`
}

type exchangeReq struct {
	Key         string      `json:"key"`
	Fingerprint string      `json:"fingerprint"`
	Client      *clientMeta `json:"client,omitempty"`
}

type seatsDTO struct {
	Limit int `json:"limit"`
	Used  int `json:"used"`
}

type exchangeResp struct {
	Token     string            `json:"token"`
	Claims    Claims            `json:"claims"`
	Seats     seatsDTO          `json:"seats"`
	Heartbeat *heartbeatInfoDTO `json:"heartbeat,omitempty"`
}

type heartbeatResp struct {
	Alive bool     `json:"alive"`
	Seats seatsDTO `json:"seats"`
}

type heartbeatInfoDTO struct {
	Require         bool `json:"require"`
	DurationSeconds int  `json:"duration_seconds"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (c *client) exchange(key, fingerprint string, cm *clientMeta) (exchangeResp, error) {
	var out exchangeResp
	err := c.postJSON("/v1/certificates", exchangeReq{Key: key, Fingerprint: fingerprint, Client: cm}, &out)
	return out, err
}

type releaseReq struct {
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

func (c *client) release(key, fingerprint string) error {
	return c.postJSON("/v1/certificates/release", releaseReq{Key: key, Fingerprint: fingerprint}, nil)
}

func (c *client) heartbeat(ctx context.Context, key, fingerprint string) (heartbeatResp, error) {
	var out heartbeatResp
	err := c.postJSONCtx(ctx, "/v1/certificates/heartbeat", releaseReq{Key: key, Fingerprint: fingerprint}, &out)
	return out, err
}

// publicKeys fetches the product signing keys, skipping revoked ones.
func (c *client) publicKeys(pid string) (map[string]ed25519.PublicKey, error) {
	var out struct {
		Keys []struct {
			KID       string `json:"kid"`
			Alg       string `json:"alg"`
			Status    string `json:"status"`
			PublicKey []byte `json:"public_key"`
		} `json:"keys"`
	}
	if err := c.getJSON("/v1/products/"+pid+"/keys", &out); err != nil {
		return nil, err
	}
	keys := make(map[string]ed25519.PublicKey, len(out.Keys))
	for _, k := range out.Keys {
		if k.Status == "revoked" || k.Alg != "Ed25519" {
			continue
		}
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: bad public_key for kid %s", ErrActivationFailed, k.KID)
		}
		keys[k.KID] = ed25519.PublicKey(k.PublicKey)
	}
	return keys, nil
}

// revocations fetches the signed revocation list for a product.
func (c *client) revocations(pid string) (signedRevocation, error) {
	var out signedRevocation
	err := c.getJSON("/v1/products/"+pid+"/revocations", &out)
	return out, err
}

func (c *client) postJSON(path string, body, out any) error {
	return c.postJSONCtx(context.Background(), path, body, out)
}

func (c *client) postJSONCtx(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: marshal: %v", ErrActivationFailed, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrActivationFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

func (c *client) getJSON(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrActivationFailed, err)
	}
	return c.do(req, out)
}

func (c *client) do(req *http.Request, out any) error {
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrActivationFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: read body: %v", ErrActivationFailed, err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%w: decode: %v", ErrActivationFailed, err)
		}
		return nil
	}

	var ae apiError
	_ = json.Unmarshal(data, &ae)
	switch ae.Code {
	case "seat_limit_exceeded":
		return ErrSeatLimitExceeded
	case "machine_not_activated":
		return ErrMachineNotActivated
	case "license_key_invalid", "license_key_wrong_env", "license_key_unknown_kid", "license_not_found":
		return ErrLicenseKeyInvalid
	}
	return fmt.Errorf("%w: http %d: %s", ErrActivationFailed, resp.StatusCode, ae.Message)
}
