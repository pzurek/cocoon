package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func TestSpacesDisabledRoutes(t *testing.T) {
	s := newTestServer(t)
	s.echo = echo.New()
	s.addRoutes()
	routes := s.echo.Routes()
	s.config.DisableSpaces = true
	s.echo = echo.New()
	s.addRoutes()
	for _, route := range routes {
		if !strings.HasPrefix(route.Path, "/xrpc/com.atproto.space.") && !strings.HasPrefix(route.Path, "/xrpc/com.atproto.simplespace.") {
			continue
		}
		t.Run(route.Path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(route.Method, route.Path, strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("atproto-proxy", "did:web:example.com#atproto_pds")
			s.echo.ServeHTTP(w, r)
			if w.Code != http.StatusNotFound {
				t.Fatalf("disabled endpoint: %d %s", w.Code, w.Body.String())
			}
		})
	}
	// Unknown methods in these namespaces must not fall through to the proxy.
	for _, path := range []string{"/xrpc/com.atproto.space.futureMethod", "/xrpc/com.atproto.simplespace.futureMethod"} {
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("disabled namespace %s: %d", path, w.Code)
		}
	}
	// Echo routes RawPath, while the proxy interprets decoded Path. Both must
	// enforce the opt-out, including authenticated requests with a proxy target.
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	s.proxyHTTPClient = proxyTestHTTPClient(t, upstream)
	cache := identity.NewMemCache(10)
	if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
		Id: "did:web:appview.test", Service: []identity.DidDocService{{Id: "#view", ServiceEndpoint: "https://203.0.113.10"}},
	}); err != nil {
		t.Fatal(err)
	}
	s.passport = identity.NewPassport(upstream.Client(), cache)
	acct := s.createTestAccount(t, "disabled-spaces.pds.test")
	repo := mustRepoActor(t, s, acct.Did)
	session, err := s.createSession(t.Context(), &repo.Repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/xrpc/com.atproto.%73pace.listSpaces", "/xrpc/com.atproto.%73pace.futureMethod",
		"/xrpc/com.atproto.%73implespace.getSpace", "/xrpc/com.atproto.%73implespace.futureMethod",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			for _, token := range []string{"", session.AccessToken} {
				w := httptest.NewRecorder()
				r := httptest.NewRequest(method, path, strings.NewReader(`{}`))
				r.Header.Set("atproto-proxy", "did:web:appview.test#view")
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				s.echo.ServeHTTP(w, r)
				if w.Code != http.StatusNotFound {
					t.Errorf("encoded disabled namespace %s %s: %d", method, path, w.Code)
				}
			}
		}
	}
	if calls.Load() != 0 {
		t.Errorf("disabled namespace made %d proxy requests", calls.Load())
	}
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/xrpc/com.atproto.server.describeServer", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ordinary endpoint disabled: %d %s", w.Code, w.Body.String())
	}
}

func TestSpacesDisabledPreservesQueuedNotifications(t *testing.T) {
	s := newTestServer(t)
	// These expired entries would be deleted by the worker's first pass.
	write := models.SpaceNotificationRetry{Repo: "did:web:test.invalid", Space: "test", RepoRev: "test", Data: []byte{1}}
	deleted := models.SpaceDeletedNotificationRetry{Space: "test", Service: "did:web:test.invalid"}
	for _, row := range []any{&write, &deleted} {
		if err := s.db.Create(t.Context(), row, nil).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, disabled := range []bool{true, false} {
		s.config.DisableSpaces = disabled
		s.startSpaceWorkers()
		s.stopSpaceWorkers()
		for _, row := range []any{&write, &deleted} {
			var count int64
			if err := s.db.Client().Model(row).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			want := int64(0)
			if disabled {
				want = 1
			}
			if count != want {
				t.Fatalf("disabled=%t: queued rows=%d, want %d", disabled, count, want)
			}
		}
	}
}

// Smoke tests for the Spaces test network itself.
func TestSpaceHarnessCredentialAndOAuth(t *testing.T) {
	n := newSpaceNet(t)
	pds1, pds2 := n.newPDS(), n.newPDS()
	alice := pds1.createActor("alice")
	bob := pds2.createActor("bob")

	sp := createSpace(t, alice, spaceOpts{members: []*actor{bob}})
	mustOK(t, doWrite(alice, sp, writeOpts{rkey: "a"}))

	cred := credentialFor(t, bob, pds1, sp)
	got := cred.get(t, pds1, "com.atproto.space.getRecord", map[string]string{"space": sp, "repo": alice.did, "collection": testCollection, "rkey": "a"})
	mustOK(t, got)

	app := pds2.createOAuthActor("carol", "atproto space:"+testSpaceType+"?authority=*&collection=*")
	mustOK(t, doWrite(app, sp, writeOpts{rkey: "c"}))
	narrow := pds2.createOAuthActor("dave", "atproto space:"+testSpaceType+"?authority=*&action=read")
	expectErr(t, doWrite(narrow, sp, writeOpts{rkey: "d"}), 403, "InsufficientScope")
}
