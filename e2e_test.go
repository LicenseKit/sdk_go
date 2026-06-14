//go:build e2e

package lk_test

import (
	"testing"
)

// TestE2E_AgainstBackend is intended to verify a bundle minted by the
// sibling backend repo's POST /v1/licenses/:id/offline-bundle endpoint.
//
// Full automation is fragile (requires docker-compose, seed CLI, env
// variable juggling). Currently t.Skip'd — the README documents the
// manual procedure:
//
//	cd ../backend
//	make up && sleep 5 && ./bin/licensekitctl seed
//	# capture LIC_ID and API_KEY from output
//	curl -X POST "http://localhost:3000/v1/licenses/${LIC_ID}/offline-bundle" \
//	  -H "X-API-Key: $API_KEY" \
//	  -H "Content-Type: application/json" \
//	  -d "{\"fingerprint\":\"$(printf '%64s' '' | tr ' ' 'a')\",\"ttl\":\"90d\"}" \
//	  -o /tmp/demo.lkbundle
//	cd ../sdk_go
//	# decode LIC_ID's ULID hex via your tool of choice
//	LID_HEX="..."
//	go run examples/basic -bundle /tmp/demo.lkbundle -lid "$LID_HEX"
//
// Run with: go test -tags=e2e -run TestE2E_AgainstBackend -v
func TestE2E_AgainstBackend(t *testing.T) {
	t.Skip("manual e2e — see source comment for procedure")
}
