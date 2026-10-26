package server

import (
	"bytes"
	"context"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/haileyok/cocoon/models"
)

func localLexiconTestServer(t *testing.T) (*Server, *testAccount) {
	t.Helper()
	s := newTestServer(t)
	s.evtman = s.newTestEvtman(t)
	s.repoman = NewRepoMan(s)
	acct := s.createTestAccount(t, "lexicon.pds.test")
	s.seedGenesisRepo(t, acct.Did, acct.SigningKey)
	return s, acct
}

func putLocalLexicon(t *testing.T, s *Server, acct *testAccount, nsid, title string) []byte {
	t.Helper()
	record := MarshalableMap{
		"$type": "com.atproto.lexicon.schema", "lexicon": int64(1), "id": nsid,
		"defs": map[string]any{"main": map[string]any{"type": "permission-set", "title": title, "permissions": []any{}}},
	}
	mustApply(t, s, acct.Did, Op{Type: OpTypeCreate, Collection: "com.atproto.lexicon.schema", Rkey: strPtr(nsid), Record: &record})
	raw, err := atdata.MarshalCBOR(record)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestReadLocalLexiconCommittedAccounts(t *testing.T) {
	s, alice := localLexiconTestServer(t)
	bob := s.createTestAccount(t, "otherlexicon.pds.test")
	s.seedGenesisRepo(t, bob.Did, bob.SigningKey)
	for _, acct := range []*testAccount{alice, bob} {
		want := putLocalLexicon(t, s, acct, "com.example.lexicon", acct.Handle)
		got, hosted, err := s.readLocalLexicon(t.Context(), syntax.DID(acct.Did), "com.example.lexicon")
		if err != nil || !hosted || !bytes.Equal(want, got) {
			t.Fatalf("%s: hosted=%v err=%v record=%s", acct.Handle, hosted, err, got)
		}
	}
	// Bob must not get Alice's declaration at a different rkey.
	putLocalLexicon(t, s, alice, "com.example.alice", "Alice only")
	if raw, hosted, err := s.readLocalLexicon(t.Context(), syntax.DID(bob.Did), "com.example.alice"); err == nil || !hosted || raw != nil {
		t.Fatalf("cross-account lookup: hosted=%v err=%v record=%s", hosted, err, raw)
	}
	if raw, hosted, err := s.readLocalLexicon(t.Context(), "did:plc:abcdefghijklmnopqrstuvwx", "com.example.lexicon"); err != nil || hosted || raw != nil {
		t.Fatalf("remote account: hosted=%v err=%v record=%s", hosted, err, raw)
	}
}

func TestReadLocalLexiconFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing", "deactivated", "taken down", "bad root", "uncommitted index", "missing index", "missing block", "tampered block", "database error", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			s, acct := localLexiconTestServer(t)
			putLocalLexicon(t, s, acct, "com.example.lexicon", "Original")
			ctx := t.Context()
			nsid := syntax.NSID("com.example.lexicon")
			var record models.Record
			if err := s.db.Client().Where("did = ? AND nsid = ? AND rkey = ?", acct.Did, "com.atproto.lexicon.schema", nsid).First(&record).Error; err != nil {
				t.Fatal(err)
			}
			var err error
			switch mode {
			case "missing":
				nsid = "com.example.missing"
			case "deactivated":
				err = s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Update("deactivated", true).Error
			case "taken down":
				err = s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Update("takedown_ref", "test").Error
			case "bad root":
				err = s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Update("root", []byte("invalid")).Error
			case "uncommitted index":
				nsid = "com.example.uncommitted"
				record.Rkey = nsid.String()
				err = s.db.Client().Create(&record).Error
			case "missing index":
				err = s.db.Client().Delete(&record).Error
			case "missing block":
				err = s.db.Client().Where("did = ?", acct.Did).Delete(&models.Block{}).Error
			case "tampered block":
				err = s.db.Client().Model(&models.Block{}).Where("did = ? AND value = ?", acct.Did, record.Value).Update("value", []byte{0xa0}).Error
			case "database error":
				err = s.db.Client().Migrator().DropTable(&models.Record{})
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, hosted, err := s.readLocalLexicon(ctx, syntax.DID(acct.Did), nsid)
			if err == nil || raw != nil {
				t.Fatalf("%s: hosted=%v err=%v record=%x", mode, hosted, err, raw)
			}
			if mode != "canceled" && !hosted {
				t.Fatalf("local failure reported as remote: %v", err)
			}
		})
	}
}
