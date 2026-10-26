package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bluesky-social/gttp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/identity"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestProxyRPCPermissions(t *testing.T) {
	const aud = "did:web:appview.test#view"
	const timeline = "app.bsky.feed.getTimeline"
	const feed = "app.bsky.feed.getFeed"
	const skeleton = "app.bsky.feed.getFeedSkeleton"
	rpc := func(method, audience string) string { return "rpc:" + method + "?aud=" + url.QueryEscape(audience) }
	for _, tc := range []struct {
		name, method, nsid, scope, header string
		legacy                            bool
		want                              int
	}{
		{"no RPC grant", "GET", timeline, "atproto", aud, false, 403},
		{"matching GET", "GET", timeline, rpc(timeline, aud), aud, false, 200},
		{"fallback audience", "GET", timeline, rpc(timeline, aud), "", false, 200},
		{"different service", "GET", timeline, rpc(timeline, aud), "did:web:appview.test#other", false, 403},
		{"different DID", "GET", timeline, rpc(timeline, "did:web:other.test#view"), aud, false, 403},
		{"bare DID is not service audience", "GET", timeline, rpc(timeline, "did:web:appview.test"), aud, false, 403},
		{"different method", "GET", timeline, rpc(skeleton, aud), aud, false, 403},
		{"POST denied", "POST", "chat.bsky.convo.sendMessage", "atproto", aud, false, 403},
		{"POST permitted", "POST", "chat.bsky.convo.sendMessage", "transition:chat.bsky", aud, false, 200},
		{"legacy", "GET", timeline, "", aud, true, 200},
		{"feed needs both methods", "GET", feed, rpc(feed, aud), aud, false, 403},
		{"skeleton alone is insufficient", "GET", feed, rpc(skeleton, aud), aud, false, 403},
		{"feed permitted", "GET", feed, rpc(feed, aud) + " " + rpc(skeleton, aud), aud, false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			type forwarded struct {
				method, path, query, body, auth string
				headers                         http.Header
			}
			seen := make(chan forwarded, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/xrpc/com.atproto.repo.getRecord" {
					io.WriteString(w, `{"uri":"at://did:web:owner.test/app.bsky.feed.generator/test","cid":"bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku","value":{"$type":"app.bsky.feed.generator","did":"did:web:generator.test","displayName":"Test","createdAt":"2026-09-09T00:00:00Z"}}`)
					return
				}
				body, _ := io.ReadAll(r.Body)
				seen <- forwarded{r.Method, r.URL.Path, r.URL.RawQuery, string(body), r.Header.Get("Authorization"), r.Header.Clone()}
				w.Header().Add("Set-Cookie", "session=upstream; Path=/")
				w.Header().Add("Set-Cookie", "other=upstream; Path=/")
				w.Header().Set("Access-Control-Allow-Origin", "https://upstream.test")
				w.Header().Set("Connection", "Content-Language")
				w.Header().Set("Content-Language", "en")
				w.Header().Set("Atproto-Repo-Rev", "test-rev")
				w.Header().Add("Atproto-Content-Labelers", "did:web:labeler-one.test")
				w.Header().Add("Atproto-Content-Labelers", "did:web:labeler-two.test")
				w.Header().Set("Retry-After", "30")
				io.WriteString(w, `{"ok":true}`)
			}))
			t.Cleanup(upstream.Close)
			s := newTestServer(t)
			s.proxyHTTPClient = proxyTestHTTPClient(t, upstream)
			attachOauthProvider(t, s)
			account := s.createTestAccount(t, "proxy.pds.test")
			cache := identity.NewMemCache(10)
			if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
				Id: "did:web:appview.test", Service: []identity.DidDocService{
					{Id: "#view", ServiceEndpoint: "https://203.0.113.10"}, {Id: "#other", ServiceEndpoint: "https://203.0.113.10"},
				},
			}); err != nil {
				t.Fatal(err)
			}
			s.passport = identity.NewPassport(upstream.Client(), cache)
			s.config.FallbackProxy = aud
			s.echo = echo.New()
			s.echo.Validator = newTestValidator()
			s.addRoutes()
			query := "limit=3"
			if tc.nsid == feed {
				query = url.Values{"feed": {"at://did:web:owner.test/app.bsky.feed.generator/test"}}.Encode()
			}
			target := "/xrpc/" + tc.nsid + "?" + query
			body := ""
			if tc.method == "POST" {
				body = `{"text":"test"}`
			}
			r := httptest.NewRequest(tc.method, target, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("atproto-proxy", tc.header)
			r.Header.Set("Cookie", "session=synthetic-pds-cookie")
			r.Header.Set("Proxy-Authorization", "Basic private")
			r.Header.Set("Forwarded", "for=192.0.2.1")
			r.Header.Set("X-Forwarded-For", "192.0.2.1")
			r.Header.Set("Origin", "https://pds.test")
			r.Header.Set("Referer", "https://pds.test/account")
			r.Header.Add("Connection", "X-Atproto-Hop")
			r.Header.Add("Connection", "X-Atproto-Other-Hop")
			r.Header.Set("X-Atproto-Hop", "private")
			r.Header.Set("X-Atproto-Other-Hop", "private")
			r.Header.Set("Accept-Language", "en-NZ")
			r.Header.Set("X-Bsky-Topics", "test-topic")
			r.Header.Set("X-Atproto-Example", "protocol-extension")
			r.Header.Add("Atproto-Accept-Labelers", "did:web:labeler-one.test")
			r.Header.Add("Atproto-Accept-Labelers", "did:web:labeler-two.test")
			if tc.legacy {
				r.Header.Set("Accept-Encoding", "gzip")
				repo, err := s.getRepoActorByDid(context.Background(), account.Did)
				if err != nil {
					t.Fatal(err)
				}
				session, err := s.createSession(context.Background(), &repo.Repo)
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Authorization", "Bearer "+session.AccessToken)
			} else {
				setProxyTestOAuth(t, s, r, account.Did, tc.scope)
			}
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == 403 {
				assertInsufficientScope(t, w.Code, w.Body.Bytes())
				if calls.Load() != 0 {
					t.Fatalf("denied request made %d upstream calls", calls.Load())
				}
				return
			}
			wantCalls := int32(1)
			if tc.nsid == feed {
				wantCalls = 2
			}
			if calls.Load() != wantCalls || len(seen) != 1 {
				t.Fatalf("unexpected upstream calls: %d", calls.Load())
			}
			got := <-seen
			if got.method != tc.method || got.path != "/xrpc/"+tc.nsid || got.query != query || got.body != body || w.Body.String() != `{"ok":true}` {
				t.Fatal("proxy changed the request or response payload")
			}
			for _, name := range []string{"Cookie", "Proxy-Authorization", "DPoP", "Atproto-Proxy", "Forwarded", "X-Forwarded-For", "Origin", "Referer", "Connection", "X-Atproto-Hop", "X-Atproto-Other-Hop"} {
				if got.headers.Get(name) != "" {
					t.Errorf("forwarded private request header %s", name)
				}
			}
			for _, name := range []string{"Set-Cookie", "Access-Control-Allow-Origin", "Connection", "Content-Language"} {
				if w.Header().Get(name) != "" {
					t.Errorf("forwarded unsafe response header %s", name)
				}
			}
			for _, name := range []string{"Content-Type", "Accept-Language", "X-Bsky-Topics", "X-Atproto-Example", "Atproto-Accept-Labelers"} {
				if !reflect.DeepEqual(got.headers.Values(name), r.Header.Values(name)) {
					t.Errorf("changed allowed request header %s: %v", name, got.headers.Values(name))
				}
			}
			encoding := "identity"
			if tc.legacy {
				encoding = "gzip"
			}
			if got.headers.Get("Accept-Encoding") != encoding {
				t.Errorf("upstream Accept-Encoding = %q, want %q", got.headers.Get("Accept-Encoding"), encoding)
			}
			if tc.method == "POST" && got.headers.Get("Content-Length") != fmt.Sprint(len(body)) {
				t.Error("did not preserve POST content length")
			}
			if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Atproto-Repo-Rev") != "test-rev" || w.Header().Get("Retry-After") != "30" ||
				!reflect.DeepEqual(w.Header().Values("Atproto-Content-Labelers"), []string{"did:web:labeler-one.test", "did:web:labeler-two.test"}) {
				t.Error("changed allowed response headers or combined repeated values")
			}
			token, _, err := new(jwt.Parser).ParseUnverified(strings.TrimPrefix(got.auth, "Bearer "), jwt.MapClaims{})
			if err != nil {
				t.Fatal(err)
			}
			claims := token.Claims.(jwt.MapClaims)
			wantAud, wantLxm := "did:web:appview.test", tc.nsid
			if tc.nsid == feed {
				wantAud, wantLxm = "did:web:generator.test", skeleton
			}
			if claims["iss"] != account.Did || claims["aud"] != wantAud || claims["lxm"] != wantLxm {
				t.Fatal("incorrect service-auth claims")
			}
		})
	}
}

func setProxyTestOAuth(t *testing.T, s *Server, r *http.Request, did, scope string) {
	t.Helper()
	access := "proxy-test-access"
	proof := newTestDpopProof(t, s, r.Method, "https://"+testHostname+r.URL.String(), &access)
	parsed, _, err := new(jwt.Parser).ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	keyJSON, err := json.Marshal(parsed.Header["jwk"])
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.ParseKey(keyJSON)
	if err != nil {
		t.Fatal(err)
	}
	thumb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jkt := base64.RawURLEncoding.EncodeToString(thumb)
	grant := provider.OauthToken{
		Token: access, Sub: did, ClientId: "http://localhost", RefreshToken: "proxy-test-refresh",
		ExpiresAt: time.Now().Add(time.Hour), Parameters: provider.ParRequest{Scope: scope, DpopJkt: &jkt},
	}
	if err := s.db.Create(context.Background(), &grant, nil).Error; err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "DPoP "+access)
	r.Header.Set("DPoP", proof)
}

func TestProxyTransport(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			const payload = `{"text":"streamed request"}`
			var compressed bytes.Buffer
			zip, err := gzip.NewWriterLevel(&compressed, gzip.NoCompression)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := zip.Write(bytes.Repeat([]byte("x"), 3<<20)); err != nil {
				t.Fatal(err)
			}
			if err := zip.Close(); err != nil {
				t.Fatal(err)
			}
			type received struct {
				body     string
				length   int64
				encoding string
				err      error
			}
			seen := make(chan received, 1)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				seen <- received{string(body), r.ContentLength, r.Header.Get("Accept-Encoding"), err}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "gzip")
				w.Header().Set("Content-Length", fmt.Sprint(compressed.Len()))
				_, _ = w.Write(compressed.Bytes())
			}))
			t.Cleanup(upstream.Close)
			s := newTestServer(t)
			s.proxyHTTPClient = proxyTestHTTPClient(t, upstream)
			account := s.createTestAccount(t, "transport.pds.test")
			cache := identity.NewMemCache(10)
			if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
				Id: "did:web:appview.test", Service: []identity.DidDocService{{Id: "#view", ServiceEndpoint: "https://203.0.113.10"}},
			}); err != nil {
				t.Fatal(err)
			}
			s.passport = identity.NewPassport(upstream.Client(), cache)
			s.config.FallbackProxy = "did:web:appview.test#view"
			s.echo = echo.New()
			s.echo.Validator = newTestValidator()
			s.addRoutes()
			frontend := httptest.NewServer(s.echo)
			t.Cleanup(frontend.Close)
			repo, err := s.getRepoActorByDid(context.Background(), account.Did)
			if err != nil {
				t.Fatal(err)
			}
			session, err := s.createSession(context.Background(), &repo.Repo)
			if err != nil {
				t.Fatal(err)
			}
			var body io.Reader
			if method == http.MethodPost {
				body = io.NopCloser(strings.NewReader(payload))
			}
			req, err := http.NewRequest(method, frontend.URL+"/xrpc/app.bsky.feed.getTimeline", body)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+session.AccessToken)
			req.Header.Set("Accept-Encoding", "gzip")
			req.Header.Set("Content-Type", "application/json")
			client := frontend.Client()
			client.Timeout = 5 * time.Second
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 || resp.Uncompressed || resp.Header.Get("Content-Encoding") != "gzip" || resp.ContentLength != int64(compressed.Len()) || !bytes.Equal(raw, compressed.Bytes()) {
				t.Fatalf("gzip response changed: status=%d headers=%v length=%d bytes=%d", resp.StatusCode, resp.Header, resp.ContentLength, len(raw))
			}
			got := <-seen
			wantBody, wantLength := "", int64(0)
			if method == http.MethodPost {
				wantBody, wantLength = payload, -1
			}
			if got.err != nil || got.body != wantBody || got.length != wantLength || got.encoding != "gzip" {
				t.Fatalf("upstream request changed: %+v", got)
			}
		})
	}
}

func proxyTestHTTPClient(t *testing.T, upstream *httptest.Server) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	client := newProxyHTTPClient(
		gttp.WithTLSConfig(&tls.Config{RootCAs: roots, ServerName: "example.com"}),
		gttp.WithDialContext(func(ctx context.Context, network, address string) (net.Conn, error) {
			// Map only approved logical public IPs to the disposable TLS server.
			if address != "203.0.113.10:443" && address != "203.0.113.10:8443" && address != "203.0.113.11:443" {
				return nil, fmt.Errorf("unexpected dial: %s", address)
			}
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		}),
	)
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func proxyTransportContext(t *testing.T, endpoint, method string) (*Server, echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	s := newTestServer(t)
	cache := identity.NewMemCache(10)
	if err := cache.PutDoc("did:web:appview.test", &identity.DidDoc{
		Id: "did:web:appview.test", Service: []identity.DidDocService{{Id: "#view", ServiceEndpoint: endpoint}},
	}); err != nil {
		t.Fatal(err)
	}
	s.passport = identity.NewPassport(nil, cache)
	s.config.FallbackProxy = "did:web:appview.test#view"
	e, w := newRequestContext("GET", "/xrpc/"+method+"?feed=at://did:web:owner.test/app.bsky.feed.generator/test", "", nil)
	e.Set("credentialKind", credentialLegacyAccess)
	return s, e, w
}

func TestProxyDefaultTransportBlocksPrivateTargets(t *testing.T) {
	for _, method := range []string{"app.bsky.feed.getTimeline", "app.bsky.feed.getFeed"} {
		t.Run(method, func(t *testing.T) {
			var connections atomic.Int32
			upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, `{"value":{"$type":"app.bsky.feed.generator","did":"did:web:generator.test"}}`)
			}))
			upstream.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			upstream.StartTLS()
			t.Cleanup(upstream.Close)
			for _, endpoint := range []string{upstream.URL, strings.Replace(upstream.URL, "127.0.0.1", "localhost", 1)} {
				s, e, w := proxyTransportContext(t, endpoint, method)
				if method == "app.bsky.feed.getFeed" {
					_ = s.handleProxyBskyFeedGetFeed(e)
					if w.Code != 500 {
						t.Errorf("private feed lookup: status %d", w.Code)
					}
				} else if err := s.handleProxy(e); !errors.Is(err, gttp.ErrBlockedByIPPolicy) {
					t.Errorf("expected IP-policy rejection, got %v", err)
				}
			}
			if connections.Load() != 0 {
				t.Fatalf("private service received %d connections", connections.Load())
			}
		})
	}
}

func TestProxyCancellation(t *testing.T) {
	for _, method := range []string{"app.bsky.feed.getTimeline", "app.bsky.feed.getFeed"} {
		for _, stage := range []string{"headers", "body"} {
			t.Run(method+"/"+stage, func(t *testing.T) {
				entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if stage == "body" {
						w.Header().Set("Content-Type", "application/json")
						io.WriteString(w, "{")
						w.(http.Flusher).Flush()
					}
					close(entered)
					select {
					case <-r.Context().Done():
						close(cancelled)
					case <-release:
					}
				}))
				t.Cleanup(upstream.Close)
				s, e, _ := proxyTransportContext(t, "https://203.0.113.10", method)
				s.proxyHTTPClient = proxyTestHTTPClient(t, upstream)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				e.SetRequest(e.Request().WithContext(ctx))
				done := make(chan struct{})
				t.Cleanup(func() {
					cancel()
					close(release)
					<-done
				})
				go func() {
					defer close(done)
					if method == "app.bsky.feed.getFeed" {
						_ = s.handleProxyBskyFeedGetFeed(e)
					} else {
						_ = s.handleProxy(e)
					}
				}()
				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("upstream was not reached")
				}
				cancel()
				select {
				case <-cancelled:
				case <-time.After(2 * time.Second):
					t.Error("incoming cancellation did not reach upstream")
				}
				select {
				case <-done:
				case <-time.After(4 * time.Second):
					t.Fatal("proxy did not return after cancellation")
				}
			})
		}
	}
}

func TestProxyRedirectPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		wantErr      error
		wantAuth     string
	}{
		{"same origin", "/done", nil, "Bearer test"},
		{"other origin", "https://203.0.113.11/done", nil, ""},
		{"private", "https://127.0.0.1/done", gttp.ErrBlockedByIPPolicy, ""},
		{"downgrade", "http://203.0.113.10/done", gttp.ErrSchemeDowngrade, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/done" {
					http.Redirect(w, r, tc.target, http.StatusFound)
					return
				}
				io.WriteString(w, r.Header.Get("Authorization"))
			}))
			t.Cleanup(upstream.Close)
			client := proxyTestHTTPClient(t, upstream)
			req, err := http.NewRequest("GET", "https://203.0.113.10/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer test")
			resp, err := client.Do(req)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || calls.Load() != 1 {
					t.Fatalf("redirect: calls=%d error=%v, want %v", calls.Load(), err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != tc.wantAuth || calls.Load() != 2 {
				t.Fatalf("redirect: calls=%d body=%q error=%v", calls.Load(), body, err)
			}
		})
	}
}

func TestProxyRedirectDoesNotRestoreAuthorization(t *testing.T) {
	for _, last := range []string{"/last", "https://203.0.113.10/last"} {
		t.Run(last, func(t *testing.T) {
			seen := make(chan string, 3)
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("Authorization")
				switch r.URL.Path {
				case "/start":
					http.Redirect(w, r, "https://203.0.113.10:8443/first", http.StatusFound)
				case "/first":
					http.Redirect(w, r, last, http.StatusFound)
				case "/last":
					io.WriteString(w, "ok")
				}
			}))
			t.Cleanup(upstream.Close)
			client := proxyTestHTTPClient(t, upstream)
			req, err := http.NewRequest("GET", "https://203.0.113.10/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer test")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != "ok" || len(seen) != 3 {
				t.Fatalf("redirect chain failed: calls=%d body=%q error=%v", len(seen), body, err)
			}
			for i, want := range []string{"Bearer test", "", ""} {
				if got := <-seen; got != want {
					t.Errorf("hop %d authorization = %q, want %q", i, got, want)
				}
			}
		})
	}
}

func TestProxyDeadline(t *testing.T) {
	for _, stage := range []string{"headers", "body"} {
		t.Run(stage, func(t *testing.T) {
			release := make(chan struct{})
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stage == "body" {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			t.Cleanup(upstream.Close)
			t.Cleanup(func() { close(release) })
			client := proxyTestHTTPClient(t, upstream)
			if client.Timeout != 30*time.Second {
				t.Fatalf("proxy deadline = %v, want 30s", client.Timeout)
			}
			client.Timeout = 100 * time.Millisecond
			resp, err := client.Get("https://203.0.113.10/stall")
			if stage == "body" {
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				_, err = io.ReadAll(resp.Body)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline while reading %s, got %v", stage, err)
			}
		})
	}
}

func TestCopyProxyHeaders(t *testing.T) {
	for _, request := range []bool{true, false} {
		t.Run(fmt.Sprintf("request=%t", request), func(t *testing.T) {
			src := http.Header{
				"content-type": {"application/json"}, "Content-Encoding": {"gzip"}, "Content-Length": {"123"},
				"Content-Language": {"mi"}, "Atproto-Repo-Rev": {"rev"}, "Retry-After": {"15"},
				"Atproto-Content-Labelers": {"one", "two"}, "Atproto-Accept-Labelers": {"three", "four"},
				"Accept-Encoding": {"gzip"}, "Accept-Language": {"en-NZ"}, "X-Bsky-Topics": {"topic"},
				"x-ATPROTO-Extension": {"extension"},
				"cOnNeCtIoN":          {" x-AtProto-Hop, Retry-After ", "ATPROTO-ACCEPT-LABELERS"},
				"X-Atproto-Hop":       {"private"}, "Cookie": {"secret"}, "Set-Cookie": {"upstream"},
				"Authorization": {"private"}, "DPoP": {"proof"}, "Atproto-Proxy": {"routing"},
				"Keep-Alive": {"timeout=5"}, "Proxy-Connection": {"keep-alive"}, "Proxy-Authenticate": {"Basic"},
				"Proxy-Authorization": {"private"}, "Te": {"trailers"}, "Trailer": {"Set-Cookie"},
				"Transfer-Encoding": {"chunked"}, "Upgrade": {"websocket"}, "X-Unknown": {"private"},
				"Access-Control-Allow-Origin": {"https://upstream.test"},
			}
			dst := http.Header{"Set-Cookie": {"pds-owned"}, "Access-Control-Allow-Origin": {"https://client.test"}}
			copyProxyHeaders(dst, src, request)
			want := http.Header{
				"Set-Cookie": {"pds-owned"}, "Access-Control-Allow-Origin": {"https://client.test"},
				"Content-Type": {"application/json"}, "Content-Encoding": {"gzip"}, "Content-Length": {"123"},
			}
			if request {
				want["Accept-Encoding"] = []string{"gzip"}
				want["Accept-Language"] = []string{"en-NZ"}
				want["X-Bsky-Topics"] = []string{"topic"}
				want["X-Atproto-Extension"] = []string{"extension"}
			} else {
				want["Content-Language"] = []string{"mi"}
				want["Atproto-Repo-Rev"] = []string{"rev"}
				want["Atproto-Content-Labelers"] = []string{"one", "two"}
			}
			if !reflect.DeepEqual(dst, want) {
				t.Fatalf("headers = %v, want %v", dst, want)
			}
			src["content-type"][0] = "changed"
			if dst.Get("Content-Type") != "application/json" {
				t.Fatal("copied headers alias the source")
			}
		})
	}
}
