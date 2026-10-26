package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/haileyok/cocoon/oauth"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/labstack/echo/v4/middleware"
)

func TestSameOriginRequest(t *testing.T) {
	for _, tc := range []struct {
		name, target, origin, referer string
		want                          bool
	}{
		{"same origin", "https://pds.example/account", "https://pds.example", "", true},
		{"foreign scheme", "https://pds.example/account", "http://pds.example", "", false},
		{"same site subdomain", "https://pds.example/account", "https://evil.pds.example", "", false},
		{"foreign port", "https://pds.example/account", "https://pds.example:444", "", false},
		{"default port", "https://pds.example/account", "https://pds.example:443", "", true},
		{"host case", "https://pds.example/account", "https://PDS.EXAMPLE", "", true},
		{"http dev", "http://localhost:8080/account", "http://localhost:8080", "", true},
		{"ipv6", "http://[::1]:8080/account", "http://[::1]:8080", "", true},
		{"null", "https://pds.example/account", "null", "https://pds.example/account", false},
		{"missing", "https://pds.example/account", "", "", false},
		{"referer fallback", "https://pds.example/account", "", "https://pds.example/account?request_uri=abc", true},
		{"foreign referer scheme", "https://pds.example/account", "", "http://pds.example/account", false},
		{"foreign referer site", "https://pds.example/account", "", "https://evil.pds.example/account", false},
		{"origin takes precedence", "https://pds.example/account", "https://evil.example", "https://pds.example/account", false},
		{"userinfo", "https://pds.example/account", "https://evil@pds.example", "", false},
		{"origin path", "https://pds.example/account", "https://pds.example/path", "", false},
		{"origin query", "https://pds.example/account", "https://pds.example?x=y", "", false},
		{"origin fragment", "https://pds.example/account", "https://pds.example#x", "", false},
		{"scheme relative", "https://pds.example/account", "//pds.example", "", false},
		{"multiple origins", "https://pds.example/account", "https://pds.example https://evil.example", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newRequestContext("POST", tc.target, "", map[string]string{"Origin": tc.origin, "Referer": tc.referer})
			if tc.origin == "" {
				e.Request().Header.Del("Origin")
			}
			if got := isSameOriginRequest(e); got != tc.want {
				t.Fatalf("same origin = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAuthorizeRequiresSameOriginBeforeChangingRequest(t *testing.T) {
	s, _, cookie := manageServer(t) // Real routes, cookie store and production renderer.
	for _, decision := range []string{"accept", "reject"} {
		for _, tc := range []struct{ name, origin, referer string }{
			{"cross site", "https://attacker.test", ""},
			{"same site sibling", "https://evil.pds.test", ""},
			{"foreign scheme", "http://pds.test", ""},
			{"null origin", "null", "https://pds.test/oauth/authorize"},
			{"missing provenance", "", ""},
			{"foreign referer", "", "https://evil.pds.test/"},
		} {
			t.Run(decision+"/"+tc.name, func(t *testing.T) {
				id := oauth.GenerateRequestId()
				insertAuthRequest(t, s, id)
				form := url.Values{"request_uri": {oauth.EncodeRequestUri(id)}, "accept_or_reject": {decision}}
				r := httptest.NewRequest(http.MethodPost, "https://pds.test/oauth/authorize", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if tc.origin != "" {
					r.Header.Set("Origin", tc.origin)
				}
				r.Header.Set("Referer", tc.referer)
				r.AddCookie(cookie) // SameSite is a browser policy, not a server-side check.
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, r)
				if w.Code != http.StatusForbidden {
					t.Errorf("status = %d, want 403", w.Code)
				}
				var stored provider.OauthAuthorizationRequest
				if err := s.db.First(context.Background(), &stored, "request_id = ?", id).Error; err != nil {
					t.Fatalf("unauthorized request was deleted: %v", err)
				}
				if stored.Code != nil || stored.Sub != nil || stored.Accepted != nil {
					t.Fatal("unauthorized request issued a code or changed consent")
				}
			})
		}
	}
}

func TestSameOriginRejectsAmbiguousHeaders(t *testing.T) {
	for _, headers := range []http.Header{
		{"Origin": {"https://pds.test", "https://evil.test"}},
		{"Origin": {""}, "Referer": {"https://pds.test/account"}},
		{"Referer": {"https://pds.test/account", "https://evil.test/"}},
	} {
		e, _ := newRequestContext("POST", "https://pds.test/account", "", nil)
		e.Request().Header = headers
		if isSameOriginRequest(e) {
			t.Fatalf("accepted ambiguous headers: %v", headers)
		}
	}
}

func TestSameOriginBehindTLSProxy(t *testing.T) {
	e, _ := newRequestContext("POST", "http://pds.test/account", "", map[string]string{
		"Origin": "https://pds.test", "X-Forwarded-Proto": "https",
	})
	// Echo trusts forwarding headers only from a trusted proxy peer.
	e.Request().RemoteAddr = "127.0.0.1:1234"
	if !isSameOriginRequest(e) {
		t.Fatal("legitimate TLS-terminated request was rejected")
	}
	e.Request().Header.Set("Origin", "http://pds.test")
	if isSameOriginRequest(e) {
		t.Fatal("foreign scheme accepted behind TLS proxy")
	}
}

func TestAuthorizeAllowsSameOriginRefererFallback(t *testing.T) {
	s, acct, cookie := manageServer(t)
	insertAuthRequest(t, s, "referer-fallback")
	form := url.Values{"request_uri": {oauth.EncodeRequestUri("referer-fallback")}, "accept_or_reject": {"accept"}}
	r := httptest.NewRequest("POST", "https://pds.test/oauth/authorize", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Referer", "https://pds.test/oauth/authorize?client_id=http%3A%2F%2Flocalhost")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatalf("fallback: %d %s", w.Code, w.Body.String())
	}
	var stored provider.OauthAuthorizationRequest
	if err := s.db.First(context.Background(), &stored, "request_id = ?", "referer-fallback").Error; err != nil {
		t.Fatal(err)
	}
	if stored.Code == nil || stored.Sub == nil || *stored.Sub != acct.Did {
		t.Fatal("legitimate fallback did not issue a code for the signed-in account")
	}
}

func TestAccountActionsRejectForeignScheme(t *testing.T) {
	s, acct, cookie := manageServer(t)
	token := insertOauthToken(t, s, provider.OauthToken{Sub: acct.Did, ClientId: "http://localhost"})
	for _, path := range []string{"/account/switch", "/account/revoke"} {
		form := url.Values{"did": {acct.Did}, "id": {itoa(token.ID)}}
		r := httptest.NewRequest("POST", "https://pds.test"+path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "http://pds.test")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code != 403 || len(w.Result().Cookies()) != 0 {
			t.Fatalf("%s: status=%d; must not save a switched session", path, w.Code)
		}
	}
	if err := s.db.First(context.Background(), &provider.OauthToken{}, "id = ?", token.ID).Error; err != nil {
		t.Fatalf("foreign scheme revoked token: %v", err)
	}
}

func TestBrowserSecurityHeadersOnProductionRoutes(t *testing.T) {
	s, _ := recoveryServer(t)
	s.loadTemplates()
	s.echo.Use(browserSecurityHeaders)
	for _, directive := range []string{
		"default-src 'none'", "script-src 'none'", "style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:", "base-uri 'none'", "frame-ancestors 'none'",
	} {
		if !strings.Contains(browserContentSecurityPolicy, directive) {
			t.Errorf("missing browser policy: %s", directive)
		}
	}
	if strings.Contains(browserContentSecurityPolicy, "form-action") {
		t.Fatal("a form-action restriction needs browser tests for cross-origin OAuth callbacks")
	}
	for _, path := range []string{
		"/account", "/account/signin", "/account/signin/verify", "/account/signout",
		"/account/2fa", "/account/2fa/totp", "/account/2fa/yubikey", "/account/not-found", "/oauth/authorize",
	} {
		w := browserDo(s, nil, "GET", path, nil)
		for name, want := range map[string]string{
			"Content-Security-Policy": browserContentSecurityPolicy,
			"X-Frame-Options":         "DENY", "X-Content-Type-Options": "nosniff",
			"Referrer-Policy": "same-origin", "Cache-Control": "no-store",
		} {
			if got := w.Header().Get(name); got != want {
				t.Errorf("%s %s = %q, want %q", path, name, got, want)
			}
		}
	}
	// The real rendered pages, not an alternate renderer, retain their styles.
	w := browserDo(s, nil, "GET", "/account/signin", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `/static/style.css`) {
		t.Fatal("production signin template did not render")
	}
	w = browserDo(s, nil, "POST", "/oauth/authorize", url.Values{})
	if w.Code != 403 || w.Header().Get("Content-Security-Policy") != browserContentSecurityPolicy {
		t.Fatal("CSRF denial lost browser security headers")
	}
}

func TestBrowserSecurityDoesNotChangeProtocolCORS(t *testing.T) {
	s, _ := recoveryServer(t)
	s.echo.Use(browserSecurityHeaders)
	s.echo.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"}, AllowHeaders: []string{"*"}, AllowMethods: []string{"*"}, AllowCredentials: true,
	}))
	for _, path := range []string{"/oauth/token", "/oauth/par", "/oauth/revoke", "/oauth/jwks", "/xrpc/com.atproto.server.describeServer", "/accounts"} {
		r := httptest.NewRequest("OPTIONS", path, nil)
		r.Header.Set("Origin", "https://app.example")
		r.Header.Set("Access-Control-Request-Method", "POST")
		w := httptest.NewRecorder()
		s.echo.ServeHTTP(w, r)
		if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s CORS changed: %d %v", path, w.Code, w.Header())
		}
		for _, name := range []string{"Content-Security-Policy", "X-Frame-Options", "Referrer-Policy", "Cache-Control"} {
			if w.Header().Get(name) != "" {
				t.Errorf("browser header %s leaked onto %s", name, path)
			}
		}
	}
}
