package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/haileyok/cocoon/space"
	"github.com/labstack/echo/v4"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func lifecycleServer(t *testing.T) *Server {
	t.Helper()
	s := newTestServer(t)
	s.config.DisableSpaces = true
	s.echo = echo.New()
	s.httpd = &http.Server{Addr: "127.0.0.1:0", Handler: s.echo}
	s.evtman = s.newTestEvtman(t)
	t.Cleanup(func() { _ = s.evtpersister.Shutdown(context.Background()) })
	return s
}

// Isolate the old ListenAndServe panic so the regression test reports a
// failure rather than killing the rest of the suite.
func TestServeStartupFailures(t *testing.T) {
	if mode := os.Getenv("COCOON_LIFECYCLE_CHILD"); mode != "" {
		s := lifecycleServer(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		s.httpd.Addr = ln.Addr().String()
		if mode == "migration" {
			// A real incompatible schema, not a stubbed migration.
			if err := s.db.Client().Exec("DROP TABLE actors").Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Exec("CREATE VIEW actors AS SELECT 1 AS did").Error; err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err = s.Serve(ctx)
		if err == nil {
			t.Fatal("Serve returned nil on startup failure")
		}
		if mode == "migration" && !strings.Contains(err.Error(), "migration") {
			t.Fatalf("Serve bound listener despite failed migration: %v", err)
		}
		sqlDB, _ := s.db.Client().DB()
		if err := sqlDB.Ping(); err == nil {
			t.Fatal("Serve leaked database on startup failure")
		}
		select {
		case <-s.evtpersister.cleanupDone:
		default:
			t.Fatal("Serve leaked event cleanup on startup failure")
		}
		return
	}
	for _, mode := range []string{"migration", "bind"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestServeStartupFailures$", "-test.v")
			cmd.Env = append(os.Environ(), "COCOON_LIFECYCLE_CHILD="+mode)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("startup failure child: %v\n%s", err, out)
			}
		})
	}
}

func TestServeDrainsWriteBeforeClosingDatabase(t *testing.T) {
	s := lifecycleServer(t)
	// Reserve a disposable loopback address; Serve must own the listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.httpd.Addr = ln.Addr().String()
	_ = ln.Close()
	if err := s.db.Client().Exec("CREATE TABLE lifecycle_writes (value TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	var dbPath string
	if err := s.db.Client().Raw("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&dbPath).Error; err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	s.echo.POST("/lifecycle-write", func(e echo.Context) error {
		close(entered)
		<-release
		if err := s.db.Client().WithContext(e.Request().Context()).Exec("INSERT INTO lifecycle_writes VALUES ('committed')").Error; err != nil {
			return e.String(http.StatusInternalServerError, err.Error())
		}
		return e.String(http.StatusOK, "committed")
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	client := &http.Client{Timeout: 3 * time.Second}
	url := "http://" + s.httpd.Addr
	waitLifecycleHTTP(t, client, url)
	response := make(chan error, 1)
	go func() {
		r, err := client.Post(url+"/lifecycle-write", "text/plain", nil)
		if err == nil {
			defer r.Body.Close()
			body, _ := io.ReadAll(r.Body)
			if r.StatusCode != http.StatusOK || string(body) != "committed" {
				err = fmt.Errorf("response %d: %s", r.StatusCode, body)
			}
		}
		response <- err
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		close(release)
		t.Fatalf("Serve returned before request drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-response; err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not finish after request drained")
	}
	sqlDB, _ := s.db.Client().DB()
	if err := sqlDB.Ping(); err == nil {
		t.Fatal("database still open after Serve")
	}
	if conn, err := net.DialTimeout("tcp", s.httpd.Addr, time.Second); err == nil {
		conn.Close()
		t.Fatal("listener still open after Serve")
	}
	reopened, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	reopenedSQL, _ := reopened.DB()
	defer reopenedSQL.Close()
	var value string
	if err := reopened.Raw("SELECT value FROM lifecycle_writes").Scan(&value).Error; err != nil || value != "committed" {
		t.Fatalf("persisted write = %q, error = %v", value, err)
	}
}

func TestServeClosesHijackedSubscription(t *testing.T) {
	for _, cursor := range []string{"", "?cursor=0"} {
		t.Run(cursor, func(t *testing.T) {
			s := lifecycleServer(t)
			s.shutdownTimeout = 200 * time.Millisecond
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			s.httpd.Addr = ln.Addr().String()
			ln.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- s.Serve(ctx) }()
			waitLifecycleHTTP(t, &http.Client{Timeout: time.Second}, "http://"+s.httpd.Addr)
			conn, _, err := websocket.DefaultDialer.Dial("ws://"+s.httpd.Addr+"/xrpc/com.atproto.sync.subscribeRepos"+cursor, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("websocket prevented graceful shutdown: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("hijacked handler never exited")
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := conn.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseGoingAway) {
				t.Fatalf("expected going-away frame, got %v", err)
			}
			sqlDB, _ := s.db.Client().DB()
			if sqlDB.Ping() == nil {
				t.Fatal("database not closed")
			}
		})
	}
}

func waitLifecycleHTTP(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r, err := client.Get(url + "/xrpc/_health"); err == nil {
			r.Body.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not listen")
}

func TestServeForcedShutdownReportsErrorAndJoinsHandler(t *testing.T) {
	s := lifecycleServer(t)
	s.shutdownTimeout = 30 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.httpd.Addr = ln.Addr().String()
	ln.Close()
	entered := make(chan struct{})
	handlerDone := make(chan error, 1)
	s.echo.GET("/blocked", func(e echo.Context) error {
		close(entered)
		<-e.Request().Context().Done()
		sqlDB, _ := s.db.Client().DB()
		handlerDone <- sqlDB.Ping()
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	client := &http.Client{Timeout: 2 * time.Second}
	waitLifecycleHTTP(t, client, "http://"+s.httpd.Addr)
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		if r, err := client.Get("http://" + s.httpd.Addr + "/blocked"); err == nil {
			r.Body.Close()
		}
	}()
	<-entered
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("forced shutdown returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forced shutdown did not return")
	}
	if err := <-handlerDone; err != nil {
		t.Fatalf("database closed before forced handler finished: %v", err)
	}
	<-clientDone
	sqlDB, _ := s.db.Client().DB()
	if sqlDB.Ping() == nil {
		t.Fatal("database not closed after forced handler finished")
	}
}

func TestDbPersisterShutdownJoinsCleanup(t *testing.T) {
	s := newTestServer(t)
	p, err := NewDbPersister(s.db.Client(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for range 2 {
		if err := p.Shutdown(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case <-p.cleanupDone:
		default:
			t.Fatal("Shutdown returned before event cleanup exited")
		}
	}
}

func TestSpaceWorkerStopCancelsActiveOperation(t *testing.T) {
	s := newTestServer(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	if err := s.db.Client().Callback().Query().Before("gorm:query").Register("lifecycle:block-query", func(tx *gorm.DB) {
		once.Do(func() {
			close(entered)
			select {
			case <-tx.Statement.Context.Done():
			case <-release:
			}
		})
	}); err != nil {
		t.Fatal(err)
	}
	s.startSpaceWorkers()
	<-entered
	done := make(chan struct{})
	go func() { s.stopSpaceWorkers(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("stop did not cancel the active retry operation")
	}
	s.stopSpaceWorkers() // idempotent
}

func TestBackupCancellationInterruptsVacuumWait(t *testing.T) {
	s := newTestServer(t)
	sqlDB, _ := s.db.Client().DB()
	sqlDB.SetMaxOpenConns(1)
	conn, err := sqlDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.doBackup(ctx); close(done) }()
	deadline := time.Now().Add(time.Second)
	for sqlDB.Stats().WaitCount == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if sqlDB.Stats().WaitCount == 0 {
		t.Fatal("backup never tried to acquire a SQL connection")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("VACUUM did not honor cancellation while waiting for connection")
	}
}

func TestBackupRoutineCancellationJoinsS3Upload(t *testing.T) {
	t.Chdir(t.TempDir()) // isolate last-backup.txt
	s := newTestServer(t)
	entered, cancelled := make(chan struct{}), make(chan struct{})
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer endpoint.Close()
	s.s3Config = &S3Config{BackupsEnabled: true, Endpoint: endpoint.URL, Region: "test", Bucket: "test", AccessKey: "test", SecretKey: "test"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.backupRoutine(ctx); close(done) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("backup did not reach local S3 endpoint")
	}
	select {
	case <-done:
		t.Fatal("backup routine detached its upload")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backup routine did not join cancelled upload")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("S3 request was not cancelled")
	}
	if _, err := os.Stat("last-backup.txt"); !os.IsNotExist(err) {
		t.Fatalf("cancelled backup wrote success marker: %v", err)
	}
}

func TestNewClosesDatabaseOnKeyReadFailure(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("requires Linux file descriptor inspection")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "failed-constructor.db")
	s, err := New(&Args{
		Addr: "127.0.0.1:0", DbName: dbPath, Did: testDid, Hostname: testHostname,
		ContactEmail: "test@example.invalid", AdminPassword: "test", SessionSecret: "test",
		RotationKeyPath: filepath.Join(dir, "missing.key"), DisableSpaces: true,
	})
	if err == nil || s != nil {
		t.Fatalf("New = %v, %v; want key read failure", s, err)
	}
	fds, err := filepath.Glob("/proc/self/fd/*")
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if target, err := os.Readlink(fd); err == nil && strings.HasPrefix(target, dbPath) {
			t.Errorf("constructor leaked open database descriptor: %s", target)
		}
	}
}

func TestServeCancelsAndJoinsStartupWorker(t *testing.T) {
	s := lifecycleServer(t)
	entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	if err := s.db.Client().Callback().Raw().Before("gorm:raw").Register("lifecycle:block-cleanup", func(tx *gorm.DB) {
		if !strings.HasPrefix(tx.Statement.SQL.String(), "DELETE FROM oauth_tokens") {
			return
		}
		once.Do(func() {
			close(entered)
			<-tx.Statement.Context.Done()
			close(cancelled)
			<-release
		})
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("startup worker did not run")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("worker operation did not receive cancellation")
	}
	select {
	case err := <-done:
		close(release)
		t.Fatalf("Serve did not join worker: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	sqlDB, _ := s.db.Client().DB()
	if err := sqlDB.Ping(); err != nil {
		close(release)
		t.Fatalf("database closed while worker still active: %v", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not finish after worker exited")
	}
	if sqlDB.Ping() == nil {
		t.Fatal("database still open after worker exited")
	}
}

func TestSpaceFanoutCancelsActiveDelivery(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(fmt.Sprintf("deleted=%t", deleted), func(t *testing.T) {
			s := newTestServer(t)
			acct := s.createTestAccount(t, "fanout.pds.test")
			ref, err := space.ParseRef("at://" + acct.Did + "/space/com.example.group/lifecycle")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.spaceStore(nil, acct.Did).createSpace(ref, models.SimplespaceConfig{WritePolicy: policyPublic}); err != nil {
				t.Fatal(err)
			}
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				select {
				case <-r.Context().Done():
					close(cancelled)
				case <-release:
				}
			}))
			defer endpoint.Close()
			defer close(release)
			const service = "did:web:fanout.test"
			cache := identity.NewMemCache(10)
			if err := cache.PutDoc(service, &identity.DidDoc{Id: service, Service: []identity.DidDocService{{Id: "#atproto_pds", ServiceEndpoint: endpoint.URL}}}); err != nil {
				t.Fatal(err)
			}
			s.passport = identity.NewPassport(endpoint.Client(), cache)
			s.spaceHTTP = endpoint.Client()
			recipient := models.SpaceCredentialRecipient{Did: acct.Did, Space: ref.String(), ServiceDid: service, ServiceEndpoint: endpoint.URL, ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339Nano)}
			if err := s.db.Client().Create(&recipient).Error; err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.workerCtx = ctx
			if deleted {
				err = s.deleteSpace(context.Background(), ref)
			} else {
				err = s.processNotifyWrite(context.Background(), notifyWriteBody{Space: ref.String(), Repo: acct.Did, RepoRev: nextTID(""), Data: []byte{1}})
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { s.spaceJobs.Wait(); close(done) }()
			// Release the test endpoint before joining on any failure path.
			t.Cleanup(func() { <-done })
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("fan-out did not reach local recipient")
			}
			cancel()
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("worker cancellation did not cancel active fan-out request")
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("fan-out did not exit after cancellation")
			}
		})
	}
}

func TestSpaceWorkerCancelsDeepQueries(t *testing.T) {
	for _, tc := range []struct {
		name, table string
		deleted     bool
	}{
		{"write-space", "spaces", false},
		{"write-config", "simplespace_configs", false},
		{"write-recipients", "space_credential_recipients", false},
		{"write-member", "simplespace_members", false},
		{"deleted-space", "spaces", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			authority := s.createTestAccount(t, "authority.pds.test")
			writer := s.createTestAccount(t, "writer.pds.test")
			ref, err := space.ParseRef("at://" + authority.Did + "/space/com.example.group/lifecycle")
			if err != nil {
				t.Fatal(err)
			}
			st := s.spaceStore(nil, authority.Did)
			if err := st.createSpace(ref, models.SimplespaceConfig{WritePolicy: policyMemberList}); err != nil {
				t.Fatal(err)
			}
			if err := st.putMember(ref.String(), writer.Did, true, true); err != nil {
				t.Fatal(err)
			}
			var row any = &models.SpaceNotificationRetry{Repo: writer.Did, Space: ref.String(), RepoRev: nextTID(""), Data: []byte{1}, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}
			if tc.deleted {
				if err := st.deleteSpace(ref.String()); err != nil {
					t.Fatal(err)
				}
				row = &models.SpaceDeletedNotificationRetry{Space: ref.String(), Service: "did:web:unused.test", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}
			}
			if err := s.db.Client().Create(row).Error; err != nil {
				t.Fatal(err)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			if err := s.db.Client().Callback().Query().Before("gorm:query").Register("lifecycle:block-deep-query", func(tx *gorm.DB) {
				if tx.Statement.Table == tc.table {
					once.Do(func() {
						close(entered)
						select {
						case <-tx.Statement.Context.Done():
						case <-release:
							// Abort the blocked query on a failed-test cleanup;
							// do not continue to network collaborators.
							tx.AddError(errors.New("released blocked test query"))
						}
					})
				}
			}); err != nil {
				t.Fatal(err)
			}
			s.startSpaceWorkers()
			t.Cleanup(s.stopSpaceWorkers)
			defer close(release)
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatalf("retry did not reach %s query", tc.table)
			}
			done := make(chan struct{})
			go func() { s.stopSpaceWorkers(); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatalf("worker stop did not cancel deeper %s query", tc.table)
			}
		})
	}
}

func TestGoSpaceWithoutWorkerContext(t *testing.T) {
	s := newTestServer(t)
	result := make(chan error, 1)
	s.goSpace(func(ctx context.Context) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
			result <- errors.New("missing bounded fan-out context")
			return
		}
		result <- ctx.Err()
	})
	s.spaceJobs.Wait()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
