package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/models"
	"golang.org/x/time/rate"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestReserveSigningKeyInputAndRate(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `{"did":""}`, `{"did":"not-a-did"}`, `{"did":3}`, `{} {}`, `{} garbage`, `{"did":"did:web:` + strings.Repeat("a", 2041) + `"}`} {
		t.Run(body, func(t *testing.T) {
			s := newTestServer(t)
			c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", body, nil)
			if err := s.handleServerReserveSigningKey(c); err != nil || w.Code != 400 {
				t.Fatalf("invalid input: %d %v %s", w.Code, err, w.Body.String())
			}
			var count int64
			if err := s.db.Client().Model(&models.ReservedKey{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatal("invalid input created a reservation")
			}
		})
	}
	for _, body := range []string{`{}`, `{"did":null}`, `{}` + strings.Repeat(" ", 16*1024-2), `{"did":"did:web:` + strings.Repeat("a", 2040) + `"}`} {
		t.Run(fmt.Sprintf("valid bytes=%d", len(body)), func(t *testing.T) {
			s := newTestServer(t)
			c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", body, nil)
			if err := s.handleServerReserveSigningKey(c); err != nil || w.Code != 200 {
				t.Fatalf("valid input: %d %v %s", w.Code, err, w.Body.String())
			}
		})
	}
	t.Run("chunked oversized suffix", func(t *testing.T) {
		s := newTestServer(t)
		c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", `{}`+strings.Repeat(" ", 16*1024), nil)
		c.Request().ContentLength = -1
		if err := s.handleServerReserveSigningKey(c); err != nil || w.Code != 413 {
			t.Fatalf("oversize: %d %v", w.Code, err)
		}
	})
	t.Run("generation burst and stable reuse", func(t *testing.T) {
		s := newTestServer(t)
		// Freeze replenishment so slow CI cannot refill a token mid-test.
		s.reservationLimiter = rate.NewLimiter(0, 5)
		var first string
		for i := 0; i < 6; i++ {
			body := fmt.Sprintf(`{"did":"did:web:reservation%d.test"}`, i)
			c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", body, nil)
			if err := s.handleServerReserveSigningKey(c); err != nil {
				t.Fatal(err)
			}
			want := 200
			if i == 5 {
				want = 429
			}
			if w.Code != want {
				t.Fatalf("request %d: %d, want %d", i, w.Code, want)
			}
			if i == 0 {
				first = w.Body.String()
			}
		}
		c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", `{"did":"did:web:reservation0.test"}`, nil)
		if err := s.handleServerReserveSigningKey(c); err != nil || w.Code != 200 || w.Body.String() != first {
			t.Fatalf("reuse must not generate or rate limit: %d %v %s", w.Code, err, w.Body.String())
		}
	})
}

func TestReserveSigningKeyConcurrentAdmission(t *testing.T) {
	for _, backend := range []string{"sqlite", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			if backend == "postgres" && os.Getenv("COCOON_TEST_POSTGRES_URL") == "" {
				t.Skip("set COCOON_TEST_POSTGRES_URL to a disposable PostgreSQL database")
			}
			for _, sameDID := range []bool{false, true} {
				t.Run(fmt.Sprintf("sameDid=%v", sameDID), func(t *testing.T) {
					s := newTestServer(t)
					// A separate pool and Server ensure the database lock, not the
					// in-process repository mutex, serializes admission.
					var dialector gorm.Dialector
					if backend == "postgres" {
						address, err := url.Parse(os.Getenv("COCOON_TEST_POSTGRES_URL"))
						if err != nil {
							t.Fatal(err)
						}
						admin, err := gorm.Open(postgres.Open(address.String()), &gorm.Config{Logger: s.db.Client().Logger})
						if err != nil {
							t.Fatal(err)
						}
						schema := fmt.Sprintf("reservation_test_%d", time.Now().UnixNano())
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
						dialector = postgres.Open(address.String())
						first, err := gorm.Open(dialector, &gorm.Config{Logger: s.db.Client().Logger})
						if err != nil {
							t.Fatal(err)
						}
						s.db = db.NewDB(first)
						if err := s.db.AutoMigrate(&models.ReservedKey{}); err != nil {
							t.Fatal(err)
						}
						pool, _ := first.DB()
						t.Cleanup(func() { _ = pool.Close() })
					} else {
						var files []struct{ Name, File string }
						if err := s.db.Client().Raw("PRAGMA database_list").Scan(&files).Error; err != nil {
							t.Fatal(err)
						}
						dialector = sqlite.Open(files[0].File)
					}
					otherDB, err := gorm.Open(dialector, &gorm.Config{Logger: s.db.Client().Logger})
					if err != nil {
						t.Fatal(err)
					}
					pool, _ := otherDB.DB()
					t.Cleanup(func() { _ = pool.Close() })
					other := &Server{db: db.NewDB(otherDB), logger: s.logger}
					if !sameDID {
						rows := make([]models.ReservedKey, 9999)
						for i := range rows {
							rows[i] = models.ReservedKey{KeyDid: fmt.Sprintf("existing-%05d", i), CreatedAt: time.Now().Add(-time.Hour)}
						}
						if err := s.db.Client().CreateInBatches(rows, 200).Error; err != nil {
							t.Fatal(err)
						}
					}
					start := make(chan struct{})
					type result struct {
						status int
						key    string
						err    error
					}
					results := make(chan result, 4)
					var wg sync.WaitGroup
					for i := 0; i < 4; i++ {
						wg.Add(1)
						go func(i int) {
							defer wg.Done()
							target := s
							if i%2 != 0 {
								target = other
							}
							index := i
							if sameDID {
								index = 0
							}
							c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", fmt.Sprintf(`{"did":"did:web:new%d.test"}`, index), nil)
							<-start
							err := target.handleServerReserveSigningKey(c)
							var body ServerReserveSigningKeyResponse
							_ = json.Unmarshal(w.Body.Bytes(), &body)
							results <- result{w.Code, body.SigningKey, err}
						}(i)
					}
					close(start)
					wg.Wait()
					close(results)
					success := 0
					keys := map[string]bool{}
					for result := range results {
						if result.err != nil {
							t.Fatal(result.err)
						}
						if result.status == 200 {
							success++
							keys[result.key] = true
						} else if result.status != 503 {
							t.Fatalf("unexpected status: %d", result.status)
						}
					}
					var count int64
					if err := s.db.Client().Model(&models.ReservedKey{}).Count(&count).Error; err != nil {
						t.Fatal(err)
					}
					if sameDID {
						if success != 4 || count != 1 || len(keys) != 1 {
							t.Fatalf("reuse: successes=%d rows=%d keys=%d", success, count, len(keys))
						}
					} else if success != 1 || count != 10000 {
						t.Fatalf("capacity: successes=%d rows=%d", success, count)
					}
					if !sameDID {
						anonymous, denied := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", `{}`, nil)
						if err := s.handleServerReserveSigningKey(anonymous); err != nil || denied.Code != 503 {
							t.Fatalf("anonymous capacity bypass: %d %v", denied.Code, err)
						}
						var stored models.ReservedKey
						if err := s.db.Client().Where("did IS NOT NULL").Take(&stored).Error; err != nil {
							t.Fatal(err)
						}
						// Saturation does not evict an old key or prevent its reuse.
						s.reservationLimiter = rate.NewLimiter(0, 0)
						body, _ := json.Marshal(ServerReserveSigningKeyRequest{Did: stored.Did})
						c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", string(body), nil)
						if err := s.handleServerReserveSigningKey(c); err != nil || w.Code != 200 {
							t.Fatalf("reuse at capacity: %d %v", w.Code, err)
						}
						var response ServerReserveSigningKeyResponse
						if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.SigningKey != stored.KeyDid {
							t.Fatal("capacity changed existing key")
						}
					}
				})
			}
		})
	}
}

func TestReserveSigningKeyDatabaseFailure(t *testing.T) {
	s := newTestServer(t)
	if err := s.db.Client().Exec("CREATE TRIGGER fail_reserved_key BEFORE INSERT ON reserved_keys BEGIN SELECT RAISE(ABORT, 'test insert failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.reserveSigningKey", `{}`, nil)
	if err := s.handleServerReserveSigningKey(c); err != nil || w.Code != 500 {
		t.Fatalf("insert failure: %d %v", w.Code, err)
	}
	var count int64
	if err := s.db.Client().Model(&models.ReservedKey{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("failed insert left state: %d %v", count, err)
	}
}
