package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

func TestBlobQuotaLegacyS3Namespace(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		t.Run(engine, func(t *testing.T) {
			s := newBlobDeletionTestServer(t, engine)
			a := s.createTestAccount(t, "legacy-namespace.test")
			const payload = "legacy bucket payload"
			c, _ := blobRecord(t, payload)
			legacy := models.Blob{Did: a.Did, Cid: c.Bytes(), Storage: "s3"}
			if err := s.db.Client().Create(&legacy).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Exec("DELETE FROM blob_quota_states").Error; err != nil {
				t.Fatal(err)
			}
			if err := initBlobQuota(s.db.Client()); err != nil {
				t.Fatal(err)
			}
			var puts atomic.Int64
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodHead && r.URL.Path == "/original/"+s3BlobKey(a.Did, c):
					w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				case r.Method == http.MethodPut && r.URL.Path == "/replacement/"+s3BlobKey(a.Did, c):
					puts.Add(1)
					body, err := io.ReadAll(r.Body)
					if err != nil || string(body) != payload {
						t.Errorf("replacement payload: %q %v", body, err)
					}
				default:
					t.Errorf("unexpected S3 request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
				}
			}))
			defer endpoint.Close()
			s.s3Config = &S3Config{BlobstoreEnabled: true, Endpoint: endpoint.URL, Bucket: "replacement", Region: "test", AccessKey: "test", SecretKey: "test"}
			e, w := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", payload, nil)
			e.Set("repo", mustRepoActor(t, s, a.Did))
			if err := s.handleRepoUploadBlob(e); err != nil || w.Code != 503 || !strings.Contains(w.Body.String(), "BlobQuotaNotReady") {
				t.Fatalf("unbound legacy metadata must not imply publication in another bucket: %d %s %v", w.Code, w.Body.String(), err)
			}
			if puts.Load() != 0 {
				t.Fatal("ambiguous legacy upload performed PUT")
			}
			original := *s.s3Config
			original.Bucket = "original"
			p, err := BackfillBlobQuota(t.Context(), s.db.Client(), &original, 100)
			if err != nil || !p.Complete {
				t.Fatalf("bind original namespace: %+v %v", p, err)
			}
			uploadTestBlob(t, s, a, payload)
			if puts.Load() != 1 {
				t.Fatal("different bound namespace skipped PUT")
			}
			var charges int64
			if err := s.db.Client().Model(&models.BlobCharge{}).Count(&charges).Error; err != nil || charges != 2 {
				t.Fatalf("separate namespaces need separate charges: %d %v", charges, err)
			}
			// An older ambiguous row must not hide proven same-namespace reuse.
			if err := s.db.Client().Model(&legacy).Update("quota_backend", "").Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Model(&models.BlobQuotaState{}).Where("id = 1").Update("complete", false).Error; err != nil {
				t.Fatal(err)
			}
			uploadTestBlob(t, s, a, payload)
			if puts.Load() != 1 {
				t.Fatal("proven reuse performed another PUT")
			}
		})
	}
}

func TestBlobQuotaBackfillRestartable(t *testing.T) {
	s := newTestServer(t)
	for _, payload := range []string{"first", "second"} {
		c, _ := blobRecord(t, payload)
		b := models.Blob{Did: "did:test:legacy", Cid: c.Bytes(), Storage: "sqlite"}
		if err := s.db.Client().Create(&b).Error; err != nil {
			t.Fatal(err)
		}
		if err := s.db.Client().Create(&models.BlobPart{BlobID: b.ID, Data: []byte(payload)}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := s.db.Client().Exec("DELETE FROM blob_quota_states").Error; err != nil {
		t.Fatal(err)
	}
	p, err := BackfillBlobQuota(t.Context(), s.db.Client(), nil, 1)
	if err != nil || p.Complete || p.Scanned != 1 {
		t.Fatalf("first batch: %+v %v", p, err)
	}
	p, err = BackfillBlobQuota(t.Context(), s.db.Client(), nil, 1)
	if err != nil || !p.Complete || p.Scanned != 1 {
		t.Fatalf("resumed batch: %+v %v", p, err)
	}
	var total int64
	if err := s.db.Client().Raw("SELECT SUM(bytes) FROM blob_charges").Scan(&total).Error; err != nil || total != 11 {
		t.Fatalf("bytes=%d %v", total, err)
	}
}

func TestBlobQuotaBackfillUnknownS3(t *testing.T) {
	s := newTestServer(t)
	c, _ := blobRecord(t, "legacy")
	b := models.Blob{Did: "did:test:legacy", Cid: c.Bytes(), Storage: "s3"}
	if err := s.db.Client().Create(&b).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Exec("DELETE FROM blob_quota_states").Error; err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	var available atomic.Bool
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != "HEAD" {
			t.Errorf("unexpected %s", r.Method)
		}
		if !available.Load() {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Length", "6")
	}))
	defer endpoint.Close()
	cfg := &S3Config{BlobstoreEnabled: true, Endpoint: endpoint.URL, Bucket: "test", Region: "test", AccessKey: "test", SecretKey: "test"}
	p, err := BackfillBlobQuota(t.Context(), s.db.Client(), cfg, 1)
	if err != nil || p.Complete || p.Unknown != 1 || requests.Load() != 1 {
		t.Fatalf("unknown: %+v requests=%d %v", p, requests.Load(), err)
	}
	s.repoman, s.s3Config = NewRepoMan(s), cfg
	a := s.createTestAccount(t, "unknown-quota.test")
	e, w := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", "new data", nil)
	e.Set("repo", mustRepoActor(t, s, a.Did))
	if err := s.handleRepoUploadBlob(e); err != nil || w.Code != 503 || requests.Load() != 1 {
		t.Fatalf("unknown accounting must reject without HEAD/PUT: %d requests=%d %v", w.Code, requests.Load(), err)
	}
	available.Store(true)
	p, err = BackfillBlobQuota(t.Context(), s.db.Client(), cfg, 1)
	if err != nil || !p.Complete || p.Unknown != 0 || requests.Load() != 2 {
		t.Fatalf("resolved: %+v requests=%d %v", p, requests.Load(), err)
	}
}

func TestBlobQuotaLegacyS3ReuseAfterGC(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.config.BlobAccountQuotaBytes, s.config.BlobServerQuotaBytes = 6, 6
	a := s.createTestAccount(t, "legacy-reuse.test")
	c, _ := blobRecord(t, "legacy")
	if err := s.db.Client().Create(&models.Blob{Did: a.Did, Cid: c.Bytes(), Storage: "s3"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Exec("DELETE FROM blob_quota_states").Error; err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "HEAD":
			w.Header().Set("Content-Length", "6")
		case "PUT":
			_, _ = io.Copy(io.Discard, r.Body)
		default:
			t.Errorf("unexpected %s", r.Method)
			w.WriteHeader(400)
		}
	}))
	defer endpoint.Close()
	s.s3Config = &S3Config{BlobstoreEnabled: true, Endpoint: endpoint.URL, Bucket: "test", Region: "test", AccessKey: "test", SecretKey: "test"}
	p, err := BackfillBlobQuota(t.Context(), s.db.Client(), s.s3Config, 1)
	if err != nil || !p.Complete {
		t.Fatalf("backfill: %+v %v", p, err)
	}
	if err := s.db.Client().Transaction(func(tx *gorm.DB) error {
		if err := lockBlobQuota(tx); err != nil {
			return err
		}
		return deleteBlobPayloads(tx, a.Did, c.Bytes())
	}); err != nil {
		t.Fatal(err)
	}
	uploadTestBlob(t, s, a, "legacy")
	var n int64
	if err := s.db.Client().Model(&models.BlobCharge{}).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("repeated charge: %d %v", n, err)
	}
}

func TestBlobQuotaPopulatedOldSchema(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		t.Run(engine, func(t *testing.T) {
			database, _ := quotaDatabases(t, engine)
			c, _ := blobRecord(t, "old database")
			b := models.Blob{Did: "did:test:old", Cid: c.Bytes(), Storage: "sqlite"}
			if err := database.Create(&b).Error; err != nil {
				t.Fatal(err)
			}
			if err := database.Create(&models.BlobPart{BlobID: b.ID, Data: []byte("old database")}).Error; err != nil {
				t.Fatal(err)
			}
			for _, sql := range []string{"DROP TABLE blob_charges", "DROP TABLE blob_quota_states", "ALTER TABLE blobs DROP COLUMN quota_backend"} {
				if err := database.Exec(sql).Error; err != nil {
					t.Fatal(err)
				}
			}
			for range 2 {
				p, err := BackfillBlobQuota(t.Context(), database, nil, 1)
				if err != nil || !p.Complete {
					t.Fatalf("old schema: %+v %v", p, err)
				}
			}
			var charges []models.BlobCharge
			if err := database.Find(&charges).Error; err != nil || len(charges) != 1 || charges[0].Bytes == nil || *charges[0].Bytes != 12 {
				t.Fatalf("migrated bytes: %+v %v", charges, err)
			}
			var part models.BlobPart
			if err := database.First(&part).Error; err != nil || string(part.Data) != "old database" {
				t.Fatalf("migration lost payload: %q %v", part.Data, err)
			}
		})
	}
}

func TestBlobQuotaBackfillNestedAndBounded(t *testing.T) {
	s := newTestServer(t)
	for _, payload := range []string{"one", "two", "three"} {
		c, _ := blobRecord(t, payload)
		if err := s.db.Client().Create(&models.Blob{Did: "did:test:nested", Cid: c.Bytes(), Storage: "s3"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := s.db.Client().Exec("DELETE FROM blob_quota_states").Error; err != nil {
		t.Fatal(err)
	}
	var heads, lists atomic.Int64
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			heads.Add(1)
			w.WriteHeader(404)
			return
		}
		if r.Method != "GET" || r.URL.Query().Get("max-keys") != "1" {
			t.Errorf("unbounded probe: %s", r.URL)
			w.WriteHeader(400)
			return
		}
		lists.Add(1)
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<ListBucketResult><Contents><Key>legacy</Key><Size>3</Size></Contents></ListBucketResult>`)
	}))
	defer endpoint.Close()
	cfg := &S3Config{BlobstoreEnabled: true, Endpoint: endpoint.URL, Bucket: "test", Region: "test", AccessKey: "test", SecretKey: "test"}
	p, err := BackfillBlobQuota(t.Context(), s.db.Client(), cfg, 1)
	if err != nil || p.Complete || p.Scanned != 1 || heads.Load() != 1 || lists.Load() != 1 {
		t.Fatalf("bounded batch: %+v heads=%d lists=%d %v", p, heads.Load(), lists.Load(), err)
	}
}
