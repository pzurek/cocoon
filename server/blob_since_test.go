package server

import (
	"bytes"
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
)

func TestListBlobsSinceCommittedRevision(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			s := newBlobDeletionTestServer(t, backend)
			account := s.createTestAccount(t, "incremental.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			firstCID, first := blobRecord(t, "older blob, updated record")
			secondCID, second := blobRecord(t, "unchanged older record")
			thirdCID, third := blobRecord(t, "newer blob")
			mustApply(t, s, account.Did,
				Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("first"), Record: &first},
				Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("second"), Record: &second})
			before := mustRepoActor(t, s, account.Did).Rev
			assertListedBlobsSince(t, s, account.Did, before, "", 10, nil)
			first["text"] = "new text, same blob"
			mustApply(t, s, account.Did,
				Op{Type: OpTypeUpdate, Collection: "app.bsky.feed.post", Rkey: strPtr("first"), Record: &first},
				Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("third"), Record: &third},
				Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("duplicate"), Record: &third})
			after := mustRepoActor(t, s, account.Did).Rev
			want := []string{firstCID.String(), thirdCID.String()}
			sort.Strings(want)
			assertListedBlobsSince(t, s, account.Did, before, "", 10, want)
			// Every record in a batch has the commit's revision, not the
			// separate creation TIDs assigned while preparing its writes.
			justBeforeCommit := syntax.NewTIDFromInteger(syntax.TID(after).Integer() - 1).String()
			assertListedBlobsSince(t, s, account.Did, justBeforeCommit, "", 10, want)
			assertListedBlobsSince(t, s, account.Did, before, "", 1, want[:1])
			assertListedBlobsSince(t, s, account.Did, before, want[0], 1, want[1:])
			assertListedBlobsSince(t, s, account.Did, before, want[1], 1, nil)
			assertListedBlobsSince(t, s, account.Did, after, "", 10, nil)
			all := append(append([]string{}, want...), secondCID.String())
			sort.Strings(all)
			assertListedBlobsSince(t, s, account.Did, "", "", 10, all)
			// A new reference in another account must not make this DID's old
			// reference look newer, even for the same CID and record path.
			other := s.createTestAccount(t, "other-incremental.pds.test")
			s.seedGenesisRepo(t, other.Did, other.SigningKey)
			mustApply(t, s, other.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("second"), Record: &second})
			assertListedBlobsSince(t, s, account.Did, after, "", 10, nil)
			mustApply(t, s, account.Did, Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("first")})
			assertListedBlobsSince(t, s, account.Did, before, "", 10, []string{thirdCID.String()})
		})
	}
}

func TestListBlobsSinceImportAndLegacy(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			s := newBlobDeletionTestServer(t, backend)
			account := s.createTestAccount(t, "import-incremental.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			before := mustRepoActor(t, s, account.Did).Rev
			c, record := blobRecord(t, "imported without payload")
			root, blocks, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/imported"}, record)
			if code, body := callImportRepo(t, s, account, bytes.NewReader(importCAR(t, []cid.Cid{root}, blocks))); code != 200 {
				t.Fatalf("import: %d %s", code, body)
			}
			after := mustRepoActor(t, s, account.Did).Rev
			assertListedBlobsSince(t, s, account.Did, before, "", 10, []string{c.String()})
			justBeforeImport := syntax.NewTIDFromInteger(syntax.TID(after).Integer() - 1).String()
			assertListedBlobsSince(t, s, account.Did, justBeforeImport, "", 10, []string{c.String()})
			assertListedBlobsSince(t, s, account.Did, after, "", 10, nil)
			// Historical commit revisions cannot be reconstructed from record
			// creation times. Include unknown legacy references conservatively.
			legacyCID, legacy := blobRecord(t, "legacy unknown revision")
			raw, err := atdata.MarshalCBOR(legacy)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Create(&models.Record{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: "legacy", CreatedAt: before, Cid: legacyCID.String(), Value: raw}).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Where("did = ?", account.Did).Delete(&models.PublicBlobIndex{}).Error; err != nil {
				t.Fatal(err)
			}
			assertListedBlobsSince(t, s, account.Did, after, "", 10, []string{legacyCID.String()})
			// Reproduce a populated pre-revision schema, then run the actual
			// migration. Both historical revisions must become unknown, not NULL.
			if err := s.db.Client().Migrator().DropColumn(&models.Record{}, "RepoRev"); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(); err != nil {
				t.Fatal(err)
			}
			unknown := []string{c.String(), legacyCID.String()}
			sort.Strings(unknown)
			assertListedBlobsSince(t, s, account.Did, after, "", 10, unknown)
		})
	}
}

func assertListedBlobsSince(t *testing.T, s *Server, did, since, cursor string, limit int, want []string) {
	t.Helper()
	query := url.Values{"did": {did}, "since": {since}, "cursor": {cursor}, "limit": {strconv.Itoa(limit)}}
	e, w := newRequestContext("GET", "/xrpc/com.atproto.sync.listBlobs?"+query.Encode(), "", nil)
	if err := s.handleSyncListBlobs(e); err != nil || w.Code != 200 {
		t.Fatalf("list: %d %s %v", w.Code, w.Body.String(), err)
	}
	var got ComAtprotoSyncListBlobsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Cids) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got.Cids, want)) {
		t.Fatalf("since %s cursor %s: got %v, want %v", since, cursor, got.Cids, want)
	}
	if len(want) == 0 {
		if got.Cursor != nil {
			t.Fatalf("empty page cursor: %v", *got.Cursor)
		}
	} else if got.Cursor == nil || *got.Cursor != want[len(want)-1] {
		t.Fatalf("unexpected page cursor: %v", got.Cursor)
	}
}
