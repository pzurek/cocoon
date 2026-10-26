package server

import (
	"errors"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

func TestBlobQuotaRepeatedUploadIsIdempotent(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	a := s.createTestAccount(t, "quota.test")
	for range 2 {
		c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "same payload", nil)
		c.Set("repo", mustRepoActor(t, s, a.Did))
		if err := s.handleRepoUploadBlob(c); err != nil || w.Code != 200 {
			t.Fatalf("upload: %d %s %v", w.Code, w.Body.String(), err)
		}
	}
	var n int64
	if err := s.db.Client().Model(&models.Blob{}).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("same CID produced %d metadata/payload copies: %v", n, err)
	}
}

func TestBlobQuotaAdmission(t *testing.T) {
	s := newTestServer(t)
	s.config.BlobAccountQuotaBytes = 5
	s.config.BlobServerQuotaBytes = 8
	a := s.createTestAccount(t, "quota-a.test")
	b := s.createTestAccount(t, "quota-b.test")
	admit := func(did, cid string, size int64) error {
		return s.db.Client().Transaction(func(tx *gorm.DB) error {
			if err := lockBlobQuota(tx); err != nil {
				return err
			}
			return s.admitBlobCharge(tx, models.BlobCharge{Did: did, Cid: []byte(cid), Backend: "sqlite", Bytes: &size})
		})
	}
	if err := admit(a.Did, "a", 5); err != nil {
		t.Fatal(err)
	}
	if err := admit(a.Did, "a", 5); err != nil {
		t.Fatal("same CID charged twice", err)
	}
	if err := admit(a.Did, "b", 1); !errors.Is(err, errBlobAccountQuota) {
		t.Fatalf("account limit: %v", err)
	}
	if err := admit(b.Did, "a", 3); err != nil {
		t.Fatal(err)
	}
	if err := admit(b.Did, "b", 1); !errors.Is(err, errBlobServerQuota) {
		t.Fatalf("server limit: %v", err)
	}
	if err := s.db.Client().Create(&models.BlobCharge{Did: b.Did, Cid: []byte("unknown"), Backend: "s3:legacy"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := admit(b.Did, "c", 1); !errors.Is(err, errBlobQuotaNotReady) {
		t.Fatalf("unknown must fail closed: %v", err)
	}
	if err := admit(a.Did, "a", 5); err != nil {
		t.Fatal("unknown blocked known reuse", err)
	}
}

func TestBlobQuotaPublicGCReleasesSQLite(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = s.newTestEvtman(t)
	a := s.createTestAccount(t, "quota-gc.test")
	s.seedGenesisRepo(t, a.Did, a.SigningKey)
	cid, record := blobRecord(t, "quota payload")
	c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "quota payload", nil)
	c.Set("repo", mustRepoActor(t, s, a.Did))
	if err := s.handleRepoUploadBlob(c); err != nil || w.Code != 200 {
		t.Fatalf("upload: %d %v", w.Code, err)
	}
	mustApply(t, s, a.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("one"), Record: &record})
	mustApply(t, s, a.Did, Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("one")})
	var n int64
	if err := s.db.Client().Model(&models.BlobCharge{}).Where("did = ? AND cid = ?", a.Did, cid.Bytes()).Count(&n).Error; err != nil || n != 0 {
		t.Fatalf("GC retained %d SQLite charges: %v", n, err)
	}
}

func TestBlobQuotaHTTPAndConfiguration(t *testing.T) {
	for _, args := range []*Args{{BlobAccountQuotaBytes: -1}, {BlobServerQuotaBytes: -1}} {
		if _, err := New(args); err == nil || !strings.Contains(err.Error(), "quotas must not be negative") {
			t.Fatalf("negative config: %v", err)
		}
	}
	args := &Args{}
	_, _ = New(args) // stops at missing addr before opening resources
	if args.BlobAccountQuotaBytes != 5<<30 || args.BlobServerQuotaBytes != 100<<30 {
		t.Fatal("incorrect quota defaults")
	}
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.config.BlobAccountQuotaBytes = 3
	s.config.BlobServerQuotaBytes = 4
	a := s.createTestAccount(t, "quota-http-a.test")
	b := s.createTestAccount(t, "quota-http-b.test")
	for _, tc := range []struct {
		account *testAccount
		body    string
		status  int
		code    string
	}{
		{a, "abc", 200, ""}, {a, "abc", 200, ""}, {a, "d", 400, "BlobQuotaExceeded"},
		{b, "x", 200, ""}, {b, "y", 503, "BlobStorageFull"},
	} {
		c, w := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", tc.body, nil)
		c.Set("repo", mustRepoActor(t, s, tc.account.Did))
		if err := s.handleRepoUploadBlob(c); err != nil || w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
			t.Fatalf("upload %q: %d %s %v", tc.body, w.Code, w.Body.String(), err)
		}
	}
	s.config.BlobAccountQuotaBytes = 1
	uploadTestBlob(t, s, a, "abc") // lowering limits does not evict or block reuse
}

func TestBlobQuotaOverflowAndRollback(t *testing.T) {
	s := newTestServer(t)
	s.config.BlobAccountQuotaBytes = math.MaxInt64
	s.config.BlobServerQuotaBytes = math.MaxInt64
	n := int64(math.MaxInt64 - 1)
	if err := s.db.Client().Create(&models.BlobCharge{Did: "did:test:a", Cid: []byte("large"), Backend: "sqlite", Bytes: &n}).Error; err != nil {
		t.Fatal(err)
	}
	n = 2
	err := s.db.Client().Transaction(func(tx *gorm.DB) error {
		if err := lockBlobQuota(tx); err != nil {
			return err
		}
		return s.admitBlobCharge(tx, models.BlobCharge{Did: "did:test:b", Cid: []byte("overflow"), Backend: "sqlite", Bytes: &n})
	})
	if !errors.Is(err, errBlobServerQuota) {
		t.Fatalf("overflow admission: %v", err)
	}
	if err := s.db.Client().Exec("DELETE FROM blob_charges").Error; err != nil {
		t.Fatal(err)
	}
	rollback := errors.New("rollback")
	err = s.db.Client().Transaction(func(tx *gorm.DB) error {
		if err := lockBlobQuota(tx); err != nil {
			return err
		}
		if err := s.admitBlobCharge(tx, models.BlobCharge{Did: "did:test:a", Cid: []byte("rolledback"), Backend: "sqlite", Bytes: &n}); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	var count int64
	if err := s.db.Client().Model(&models.BlobCharge{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("rollback charge count %d: %v", count, err)
	}
}
