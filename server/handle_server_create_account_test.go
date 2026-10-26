package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
)

func TestCreateAccountStaging(t *testing.T) {
	for _, existingDID := range []bool{true, false} {
		t.Run(map[bool]string{true: "migration", false: "new-account"}[existingDID], func(t *testing.T) {
			s := newTestServer(t)
			s.attachPlcClient(t, newPlcTestServer(t))

			k, err := atcrypto.GeneratePrivateKeyK256()
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			pub, err := k.PublicKey()
			if err != nil {
				t.Fatalf("derive public key: %v", err)
			}

			did := "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
			const handle = "alice.pds.test"

			cache := identity.NewMemCache(10)
			resolvedDID := ""
			if existingDID {
				resolvedDID = did
			}
			if err := cache.PutDid(handle, resolvedDID); err != nil {
				t.Fatal(err)
			}
			if err := cache.PutDoc(did, &identity.DidDoc{
				Id: did,
				VerificationMethods: []identity.DidDocVerificationMethod{
					{
						Id:                 did + "#atproto",
						Type:               "Multikey",
						Controller:         did,
						PublicKeyMultibase: pub.Multibase(),
					},
				},
			}); err != nil {
				t.Fatalf("seed passport cache: %v", err)
			}
			s.passport = identity.NewPassport(nil, cache)

			tok := mintServiceAuthToken(t, k.Bytes(), did, s.config.Did, "com.atproto.server.createAccount", time.Now().Add(time.Minute))

			request := map[string]string{
				"handle":   handle,
				"email":    "alice@test.invalid",
				"password": "correct-horse-battery-staple",
			}
			if existingDID {
				request["did"] = did
				reserved := models.ReservedKey{KeyDid: pub.DIDKey(), Did: &did, PrivateKey: k.Bytes(), CreatedAt: time.Now().Add(-time.Hour)}
				sibling := models.ReservedKey{KeyDid: "legacy-sibling", Did: &did, PrivateKey: []byte("preserve"), CreatedAt: time.Now()}
				if err := s.db.Client().Create(&[]models.ReservedKey{reserved, sibling}).Error; err != nil {
					t.Fatal(err)
				}
				request["password"] = strings.Repeat("x", 73)
				badBody, _ := json.Marshal(request)
				c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createAccount", string(badBody), map[string]string{"authorization": "Bearer " + tok})
				if err := s.handleCreateAccount(c); err != nil || rec.Code != 500 {
					t.Fatalf("expected password-hashing failure: %d %v", rec.Code, err)
				}
				var kept models.ReservedKey
				if err := s.db.Client().Where("key_did = ?", reserved.KeyDid).First(&kept).Error; err != nil || !bytes.Equal(kept.PrivateKey, k.Bytes()) {
					t.Fatalf("failed migration discarded reserved private key: %v", err)
				}
				request["password"] = "correct-horse-battery-staple"
			}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}

			c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.createAccount", string(body), map[string]string{
				"authorization": "Bearer " + tok,
			})

			if err := s.handleCreateAccount(c); err != nil {
				t.Fatalf("handleCreateAccount: %v", err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
			}
			var response ComAtprotoServerCreateAccountResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if existingDID && response.Did != did {
				t.Fatalf("DID changed: %s", response.Did)
			}
			did = response.Did
			if response.AccessJwt == "" || response.RefreshJwt == "" {
				t.Fatal("missing migration credentials")
			}

			urepo, err := s.getRepoActorByDid(context.Background(), did)
			if err != nil {
				t.Fatalf("getRepoActorByDid: %v", err)
			}
			if existingDID {
				if !bytes.Equal(urepo.SigningKey, k.Bytes()) {
					t.Fatal("migration did not preserve the reserved signing key")
				}
				var remaining []models.ReservedKey
				if err := s.db.Client().Find(&remaining).Error; err != nil || len(remaining) != 1 || remaining[0].KeyDid != "legacy-sibling" {
					t.Fatalf("cleanup must remove only the consumed reservation: %v, %v", remaining, err)
				}
			}
			if urepo.Repo.Rev == "" {
				t.Fatal("repo has no rev after account creation via the existing-DID flow")
			}
			if len(urepo.Repo.Root) == 0 {
				t.Fatal("repo has no root after account creation via the existing-DID flow")
			}
			if urepo.Repo.Active() == existingDID {
				t.Errorf("active = %t for existing DID = %t", urepo.Repo.Active(), existingDID)
			}

			types := eventTypesFor(t, s, did)
			if existingDID {
				if len(types) != 0 {
					t.Errorf("migration creation emitted events: %v", types)
				}
				attachStatusDID(t, s, &testAccount{Did: did, SigningKey: urepo.SigningKey}, did, "valid")
				c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.activateAccount", "{}", map[string]string{"authorization": "Bearer " + response.AccessJwt})
				handler := s.handleLegacySessionMiddleware(s.handleOauthSessionMiddleware(s.handleServerActivateAccount))
				if err := handler(c); err != nil || rec.Code != 200 {
					t.Fatalf("activation: %d %s %v", rec.Code, rec.Body.String(), err)
				}
				urepo = mustRepoActor(t, s, did)
				if !urepo.Repo.Active() {
					t.Fatal("account still inactive after activation")
				}
				types = eventTypesFor(t, s, did)
				if !contains(types, "account") {
					t.Fatalf("missing activation event: %v", types)
				}
			}
			for _, want := range []string{"identity", "sync"} {
				if !contains(types, want) {
					t.Fatalf("missing %q event after account creation; got %v", want, types)
				}
			}
		})
	}
}
