package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Like the reservation concurrency tests, PostgreSQL uses a fresh disposable
// schema, never the supplied database's existing tables.
func newBlobDeletionTestServer(t *testing.T, backend string) *Server {
	t.Helper()
	if backend == "postgres" && os.Getenv("COCOON_TEST_POSTGRES_URL") == "" {
		t.Skip("set COCOON_TEST_POSTGRES_URL to a disposable PostgreSQL database")
	}
	s := newTestServer(t)
	if backend == "postgres" {
		address, err := url.Parse(os.Getenv("COCOON_TEST_POSTGRES_URL"))
		if err != nil {
			t.Fatal(err)
		}
		admin, err := gorm.Open(postgres.Open(address.String()), &gorm.Config{Logger: s.db.Client().Logger})
		if err != nil {
			t.Fatal(err)
		}
		schema := fmt.Sprintf("blob_deletion_test_%d", time.Now().UnixNano())
		if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := admin.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
				t.Error(err)
			}
			pool, _ := admin.DB()
			_ = pool.Close()
		})
		query := address.Query()
		query.Set("search_path", schema)
		address.RawQuery = query.Encode()
		gdb, err := gorm.Open(postgres.Open(address.String()), &gorm.Config{Logger: s.db.Client().Logger})
		if err != nil {
			t.Fatal(err)
		}
		s.db = db.NewDB(gdb)
		pool, _ := gdb.DB()
		t.Cleanup(func() { _ = pool.Close() })
		if err := s.Migrate(); err != nil {
			t.Fatal(err)
		}
		var isolation string
		if err := gdb.Raw("SHOW transaction_isolation").Scan(&isolation).Error; err != nil || isolation != "read committed" {
			t.Fatalf("expected READ COMMITTED: %q %v", isolation, err)
		}
	}
	s.repoman = NewRepoMan(s)
	s.evtman = s.newTestEvtman(t)
	return s
}

type blobDeletionContextKey struct{}

// Trace runs after Scan has populated the account snapshot and closed Rows,
// unlike a Row callback which fires before the result has been consumed.
type blobDeletionBarrierLogger struct {
	logger.Interface
	after func(context.Context, string)
}

func (l blobDeletionBarrierLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, rows := fc()
	l.Interface.Trace(ctx, begin, func() (string, int64) { return sql, rows }, err)
	l.after(ctx, sql)
}

func TestDeleteNonexistentAccountDoesNotRetainLocks(t *testing.T) {
	s := newTestServer(t)
	for i := 0; i < 8; i++ {
		did := fmt.Sprintf("did:plc:nonexistent%d", i)
		body, err := json.Marshal(ComAtprotoServerDeleteAccountRequest{Did: did, Password: "invalid", Token: "invalid"})
		if err != nil {
			t.Fatal(err)
		}
		e, _ := newRequestContext("POST", "/xrpc/com.atproto.server.deleteAccount", string(body), nil)
		if err := s.handleServerDeleteAccount(e); err == nil {
			t.Fatal("nonexistent account deletion succeeded")
		}
	}
	s.repoWriteLocks.Range(func(key, value any) bool {
		t.Errorf("rejected nonexistent account retained repository lock for %v", key)
		return true
	})
}

func TestPublicBlobIndexDeletionConcurrency(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			for _, order := range []string{"list-snapshot-first", "delete-transaction-first", "stale-upload"} {
				t.Run(order, func(t *testing.T) {
					s := newBlobDeletionTestServer(t, backend)
					account := s.createTestAccount(t, "blob-deletion-race.pds.test")
					if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Updates(map[string]any{
						"account_delete_code": "delete-token", "account_delete_code_expires_at": time.Now().Add(time.Hour),
					}).Error; err != nil {
						t.Fatal(err)
					}
					c, rec := blobRecord(t, "legacy reference before deletion")
					raw, err := atdata.MarshalCBOR(rec)
					if err != nil {
						t.Fatal(err)
					}
					if err := s.db.Client().Create(&models.Record{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: "one", Cid: c.String(), Value: raw}).Error; err != nil {
						t.Fatal(err)
					}
					stale := mustRepoActor(t, s, account.Did)
					body, err := json.Marshal(ComAtprotoServerDeleteAccountRequest{Did: account.Did, Password: account.Password, Token: "delete-token"})
					if err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()
					deletion, deleted := newRequestContext("POST", "/xrpc/com.atproto.server.deleteAccount", string(body), nil)
					deletion.SetRequest(deletion.Request().WithContext(ctx))
					list, listed := newRequestContext("GET", "/xrpc/com.atproto.sync.listBlobs?did="+account.Did, "", nil)
					list.SetRequest(list.Request().WithContext(context.WithValue(ctx, blobDeletionContextKey{}, true)))
					read, resumeRead := make(chan struct{}), make(chan struct{})
					releaseRead := sync.OnceFunc(func() { close(resumeRead) })
					defer releaseRead()
					var firstRead sync.Once
					s.db.Client().Logger = blobDeletionBarrierLogger{Interface: s.db.Client().Logger, after: func(ctx context.Context, sql string) {
						if ctx.Value(blobDeletionContextKey{}) == true && strings.Contains(sql, "SELECT r.*, a.* FROM repos") {
							firstRead.Do(func() {
								close(read)
								if order == "list-snapshot-first" {
									select {
									case <-resumeRead:
									case <-ctx.Done():
									}
								}
							})
						}
					}}
					wait := func(ch <-chan struct{}) {
						t.Helper()
						select {
						case <-ch:
						case <-ctx.Done():
							t.Fatal(ctx.Err())
						}
					}
					listDone := make(chan error, 1)
					deleteDone := make(chan error, 1)
					switch order {
					case "list-snapshot-first":
						go func() { listDone <- s.handleSyncListBlobs(list) }()
						wait(read)
						deleteDone <- s.handleServerDeleteAccount(deletion)
						releaseRead()
					case "delete-transaction-first":
						deleting, resumeDelete := make(chan struct{}), make(chan struct{})
						releaseDelete := sync.OnceFunc(func() { close(resumeDelete) })
						defer releaseDelete()
						if err := s.db.Client().Callback().Delete().After("gorm:delete").Register("pause-deletion-after-index", func(tx *gorm.DB) {
							if _, ok := tx.Statement.Model.(*models.PublicBlobIndex); ok {
								close(deleting)
								select {
								case <-resumeDelete:
								case <-ctx.Done():
								}
							}
						}); err != nil {
							t.Fatal(err)
						}
						go func() { deleteDone <- s.handleServerDeleteAccount(deletion) }()
						wait(deleting)
						// Directly prove deletion owns the mutex while its transaction
						// is open, before another request could acquire it.
						value, _ := s.repoWriteLocks.LoadOrStore(account.Did, &sync.Mutex{})
						if mu := value.(*sync.Mutex); mu.TryLock() {
							mu.Unlock()
							t.Error("account deletion does not hold repository lock")
						}
						go func() { listDone <- s.handleSyncListBlobs(list) }()
						wait(read)
						releaseDelete()
					case "stale-upload":
						upload, uploaded := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", "", nil)
						upload.Set("repo", stale)
						upload.SetRequest(upload.Request().WithContext(ctx))
						reader, writer := io.Pipe()
						defer reader.Close()
						defer writer.Close()
						upload.Request().Body = reader
						uploadDone := make(chan error, 1)
						go func() { uploadDone <- s.handleRepoUploadBlob(upload) }()
						// Write returning proves upload consumed data. Holding EOF
						// prevents publication until deletion has committed.
						if _, err := writer.Write([]byte("stale upload payload")); err != nil {
							t.Fatal(err)
						}
						deleteDone <- s.handleServerDeleteAccount(deletion)
						_ = writer.Close()
						if err := <-uploadDone; err != nil || uploaded.Code != 400 {
							t.Errorf("stale upload: status=%d err=%v body=%s", uploaded.Code, err, uploaded.Body.String())
						}
					}
					if err := <-deleteDone; err != nil || deleted.Code != 200 {
						t.Fatalf("delete account: %d %s %v", deleted.Code, deleted.Body.String(), err)
					}
					if order != "stale-upload" {
						if err := <-listDone; err != nil || listed.Code != 400 {
							t.Errorf("cold list after deletion: status=%d err=%v body=%s", listed.Code, err, listed.Body.String())
						}
					}
					for _, model := range []any{&models.PublicBlobRef{}, &models.PublicBlobIndex{}, &models.Record{}, &models.Blob{}, &models.Repo{}} {
						var count int64
						if err := s.db.Client().Model(model).Where("did = ?", account.Did).Count(&count).Error; err != nil || count != 0 {
							t.Errorf("deleted account left %T rows: %d %v", model, count, err)
						}
					}
				})
			}
		})
	}
}
