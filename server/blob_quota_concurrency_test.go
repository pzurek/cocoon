package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Two independent pools, never SetMaxOpenConns(1): this exercises the database
// gate rather than a Go mutex or SQLite's accidental single-connection queue.
func quotaDatabases(t *testing.T, engine string) (*gorm.DB, *gorm.DB) {
	t.Helper()
	var dialector gorm.Dialector
	if engine == "postgres" {
		dsn := os.Getenv("COCOON_TEST_POSTGRES_URL")
		if dsn == "" {
			t.Skip("COCOON_TEST_POSTGRES_URL not set")
		}
		admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal("open disposable PostgreSQL:", err)
		}
		schema := "quota_" + strings.ToLower(helpers.RandomVarchar(12))
		if err := admin.Exec(`CREATE SCHEMA "` + schema + `"`).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := admin.Exec(`DROP SCHEMA "` + schema + `" CASCADE`).Error; err != nil {
				t.Error(err)
			}
			pool, _ := admin.DB()
			_ = pool.Close()
		})
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dialector = postgres.Open(u.String())
	} else {
		dialector = sqlite.Open(filepath.Join(t.TempDir(), "quota.db") + "?_busy_timeout=10000&_journal_mode=WAL")
	}
	open := func() *gorm.DB {
		database, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal(err)
		}
		pool, err := database.DB()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = pool.Close() })
		return database
	}
	a, b := open(), open()
	if err := a.AutoMigrate(&models.Blob{}, &models.BlobPart{}, &models.BlobCharge{}, &models.BlobQuotaState{}); err != nil {
		t.Fatal(err)
	}
	if err := initBlobQuota(a); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestBlobQuotaIndependentAdmission(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		t.Run(engine, func(t *testing.T) {
			a, b := quotaDatabases(t, engine)
			servers := []*Server{
				{db: db.NewDB(a), config: &config{BlobAccountQuotaBytes: 10, BlobServerQuotaBytes: 10}},
				{db: db.NewDB(b), config: &config{BlobAccountQuotaBytes: 10, BlobServerQuotaBytes: 10}},
			}
			run := func(same bool) {
				var wg sync.WaitGroup
				start := make(chan struct{})
				errs := make(chan error, 16)
				for i := range 16 {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						<-start
						did, cid := fmt.Sprintf("did:test:%d", i), []byte(fmt.Sprintf("cid%d", i))
						if same {
							did, cid = "did:test:repeat", []byte("repeat")
						}
						s := servers[i%2]
						err := s.db.Client().Transaction(func(tx *gorm.DB) error {
							if err := lockBlobQuota(tx); err != nil {
								return err
							}
							size := int64(6)
							return s.admitBlobCharge(tx, models.BlobCharge{Did: did, Cid: cid, Backend: "sqlite", Bytes: &size})
						})
						errs <- err
					}(i)
				}
				close(start)
				wg.Wait()
				close(errs)
				success := 0
				for err := range errs {
					if err == nil {
						success++
					} else if same || !errors.Is(err, errBlobServerQuota) {
						t.Errorf("admission: %v", err)
					}
				}
				want := 1
				if same {
					want = 16
				}
				if success != want {
					t.Fatalf("successful admissions=%d want=%d", success, want)
				}
				var n int64
				if err := a.Model(&models.BlobCharge{}).Count(&n).Error; err != nil || n != 1 {
					t.Fatalf("charge count %d: %v", n, err)
				}
			}
			run(false)
			if err := a.Exec("DELETE FROM blob_charges").Error; err != nil {
				t.Fatal(err)
			}
			run(true)
		})
	}
}

func TestBlobQuotaIndependentS3Publication(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		t.Run(engine, func(t *testing.T) {
			a, b := quotaDatabases(t, engine)
			s1, s2 := newTestServer(t), newTestServer(t)
			s1.db, s2.db = db.NewDB(a), db.NewDB(b)
			if err := s1.Migrate(); err != nil {
				t.Fatal(err)
			}
			account := s1.createTestAccount(t, "quota-parallel.test")
			// Complete reference indexing before the concurrency barrier; the
			// test specifically measures publication/quota, not legacy indexing.
			if complete, err := s1.preparePublicBlobIndex(t.Context(), account.Did); err != nil || !complete {
				t.Fatalf("index: %v %v", complete, err)
			}
			bothPuts := make(chan struct{})
			var puts atomic.Int64
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PUT" {
					t.Errorf("unexpected %s", r.Method)
					w.WriteHeader(400)
					return
				}
				payload, err := io.ReadAll(r.Body)
				if err != nil || string(payload) != "repeat" {
					t.Errorf("PUT body: %q %v", payload, err)
				}
				if puts.Add(1) == 2 {
					close(bothPuts)
				}
				select {
				case <-bothPuts:
				case <-r.Context().Done():
				}
			}))
			defer endpoint.Close()
			for _, s := range []*Server{s1, s2} {
				s.repoman = NewRepoMan(s)
				s.config.BlobAccountQuotaBytes, s.config.BlobServerQuotaBytes = 6, 6
				s.s3Config = &S3Config{BlobstoreEnabled: true, Endpoint: endpoint.URL, Bucket: "test", Region: "test", AccessKey: "test", SecretKey: "test"}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			errs := make(chan error, 2)
			for _, s := range []*Server{s1, s2} {
				repo := mustRepoActor(t, s, account.Did)
				go func(s *Server) {
					c, w := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", "repeat", nil)
					c.SetRequest(c.Request().WithContext(ctx))
					c.Set("repo", repo)
					err := s.handleRepoUploadBlob(c)
					if err == nil && w.Code != 200 {
						err = fmt.Errorf("upload status %d: %s", w.Code, w.Body.String())
					}
					errs <- err
				}(s)
			}
			for range 2 {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
			for _, model := range []any{&models.Blob{}, &models.BlobCharge{}} {
				var n int64
				if err := a.Model(model).Count(&n).Error; err != nil || n != 1 {
					t.Fatalf("concurrent %T: %d %v", model, n, err)
				}
			}
			// A different CID is rejected before PUT, but metadata GC cannot
			// make the existing retained payload consume capacity a second time.
			c, w := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", "other!", nil)
			c.Set("repo", mustRepoActor(t, s1, account.Did))
			if err := s1.handleRepoUploadBlob(c); err != nil || w.Code != 400 || puts.Load() != 2 {
				t.Fatalf("quota before PUT: %d puts=%d %v", w.Code, puts.Load(), err)
			}
			if err := a.Transaction(func(tx *gorm.DB) error {
				if err := lockBlobQuota(tx); err != nil {
					return err
				}
				return deleteBlobPayloads(tx, account.Did, nil)
			}); err != nil {
				t.Fatal(err)
			}
			uploadTestBlob(t, s2, account, "repeat")
		})
	}
}
