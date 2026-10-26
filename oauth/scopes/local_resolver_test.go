package scopes

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

func localLexiconCBOR(t *testing.T, kind, id string) []byte {
	t.Helper()
	doc, err := atdata.UnmarshalJSON([]byte(fmt.Sprintf(`{"$type":"com.atproto.lexicon.schema","lexicon":1,"id":%q,"defs":{"main":{"type":%q,"name":"Local","key":"tid","collections":["com.example.record"],"permissions":[{"type":"permission","resource":"space","spaceType":"com.example.group","collection":["com.example.record"]}]}}}`, id, kind)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := atdata.MarshalCBOR(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLocalLexiconResolution(t *testing.T) {
	const did = "did:plc:abcdefghijklmnopqrstuvwx"
	for _, kind := range []string{"permission-set", "space", "space permissions"} {
		for _, mode := range []string{"valid", "wrong ID", "invalid CBOR", "deep CBOR", "oversized", "missing", "database error", "not hosted"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				dns := lexiconTestDNS(t, did)
				// The real guarded transport forbids this PDS endpoint. The
				// local reader must work without granting a self-fetch exception.
				dir := identity.NewMockDirectory()
				dir.Insert(identity.Identity{DID: did, Services: map[string]identity.ServiceEndpoint{
					"atproto_pds": {Type: "AtprotoPersonalDataServer", URL: "http://127.0.0.1:9443"},
				}})
				r := NewIndigoResolverWithDirectory(dir)
				r.dns.Resolver = net.Resolver{PreferGo: true, Dial: dns.Dial}
				calls := 0
				r.SetLocalLexiconReader(func(ctx context.Context, authority syntax.DID, nsid syntax.NSID) ([]byte, bool, error) {
					calls++
					if authority != did || nsid != "com.example.lexicon" || ctx.Err() != nil {
						t.Fatalf("wrong authority or NSID: %s/%s", authority, nsid)
					}
					schemaKind := kind
					if kind == "space permissions" {
						schemaKind = "permission-set"
					}
					switch mode {
					case "wrong ID":
						return localLexiconCBOR(t, schemaKind, "com.example.other"), true, nil
					case "invalid CBOR":
						return []byte{0xff}, true, nil
					case "deep CBOR":
						return append(bytes.Repeat([]byte{0x81}, 100), 0xf6), true, nil
					case "oversized":
						return make([]byte, atdata.MAX_CBOR_RECORD_SIZE+1), true, nil
					case "missing":
						return nil, true, fmt.Errorf("local record missing")
					case "database error":
						return nil, false, fmt.Errorf("local database error")
					case "not hosted":
						return nil, false, nil
					default:
						return localLexiconCBOR(t, schemaKind, nsid.String()), true, nil
					}
				})
				resolve := func() error {
					switch kind {
					case "space":
						cols, err := r.ResolveSpaceCollections(t.Context(), "com.example.lexicon")
						if err == nil && (len(cols) != 1 || cols[0] != "com.example.record") {
							t.Fatalf("collections=%v", cols)
						}
						return err
					case "space permissions":
						perms, err := r.ResolveSpacePermissions(t.Context(), "com.example.lexicon")
						if err == nil && (len(perms) != 1 || perms[0].Type != "com.example.group") {
							t.Fatalf("permissions=%v", perms)
						}
						return err
					default:
						_, err := r.ResolvePermissionSet(t.Context(), "com.example.lexicon")
						return err
					}
				}
				err := resolve()
				if mode == "valid" && err != nil {
					t.Fatalf("local resolution: %v", err)
				}
				if mode != "valid" && err == nil {
					t.Fatal("invalid local result accepted")
				}
				wantError := map[string]string{
					"wrong ID": "document type, version, or ID", "invalid CBOR": "CBOR preflight",
					"deep CBOR": "nesting exceeds 32", "oversized": "size limit",
					"missing": "local record missing", "database error": "local database error",
					"not hosted": "lexicon fetch requires HTTPS",
				}[mode]
				if wantError != "" && !strings.Contains(err.Error(), wantError) {
					t.Fatalf("expected %q without unintended fallback, got %v", wantError, err)
				}
				if calls != 1 {
					t.Fatalf("local reader calls=%d", calls)
				}
				_ = resolve()
				if calls != 1 {
					t.Fatalf("positive/negative cache missed: calls=%d", calls)
				}
				// Expiration must return to the actor store, not freeze local
				// declarations or failures indefinitely.
				r.mu.Lock()
				for key, entry := range r.cache {
					entry.expires = time.Time{}
					r.cache[key] = entry
				}
				for key, entry := range r.spaceCache {
					entry.expires = time.Time{}
					r.spaceCache[key] = entry
				}
				r.mu.Unlock()
				_ = resolve()
				if calls != 2 {
					t.Fatalf("expired cache did not retry local reader: %d", calls)
				}
			})
		}
	}
}

func TestLocalLexiconRequiresDNSAuthority(t *testing.T) {
	for _, nsid := range []string{"invalid", "com.example.lexicon"} {
		t.Run(nsid, func(t *testing.T) {
			dns := lexiconTestDNS(t, "not-a-did")
			r := NewIndigoResolverWithDirectory(identity.NewMockDirectory())
			r.dns.Resolver = net.Resolver{PreferGo: true, Dial: dns.Dial}
			r.SetLocalLexiconReader(func(context.Context, syntax.DID, syntax.NSID) ([]byte, bool, error) {
				t.Fatal("local hook called without a valid DNS authority")
				return nil, true, nil
			})
			if _, err := r.ResolvePermissionSet(t.Context(), nsid); err == nil {
				t.Fatal("local resolution bypassed NSID/DNS validation")
			}
		})
	}
}
