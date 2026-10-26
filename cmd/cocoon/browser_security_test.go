package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"golang.org/x/crypto/bcrypt"
)

// Exercise the actual CLI -> server.New -> session middleware -> handlers and
// production renderer. In particular, decoding a cookie on the next request
// must not reset its flags to Gorilla's defaults when flashes are saved.
func checkCLIBrowserCookies(t *testing.T, addr, dbPath string, secure bool) {
	t.Helper()
	const handle = "cookie-policy.pds.test"
	const password = "synthetic-cookie-policy-password"
	const did = "did:plc:abcdefghijklmnopqrstuvwx"
	db, err := sql.Open("sqlite3", dbPath+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := atcrypto.GeneratePrivateKeyK256()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO repos (did, created_at, email, password, signing_key, two_factor_type) VALUES (?, ?, ?, ?, ?, ?)", did, time.Now(), "cookie-policy@example.invalid", string(hash), key.Bytes(), "none"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO actors (did, handle) VALUES (?, ?)", did, handle); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	var cookie *http.Cookie
	request := func(method, path string, form url.Values, status int) string {
		t.Helper()
		req, err := http.NewRequest(method, "http://"+addr+path, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		scheme := "http"
		if secure {
			scheme = "https"
			req.Header.Set("X-Forwarded-Proto", scheme)
		}
		req.Header.Set("Origin", scheme+"://"+addr)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		// The production CLI listens on HTTP behind TLS termination. Carry the
		// cookie explicitly so the secure-mode test checks server policy, not
		// net/http's refusal to send Secure cookies over this backend connection.
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != status {
			t.Fatalf("%s %s: status=%d, want %d", method, path, resp.StatusCode, status)
		}
		if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s %s: production browser header middleware not wired", method, path)
		}
		found := false
		for _, c := range resp.Cookies() {
			if c.Name != "session" {
				continue
			}
			found = true
			cookie = c
			if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Secure != secure || c.Path != "/" || c.Domain != "" {
				t.Errorf("%s %s: cookie HttpOnly=%t SameSite=%v Secure=%t Path=%q Domain=%q; want true, Lax, %t, /, host-only", method, path, c.HttpOnly, c.SameSite, c.Secure, c.Path, c.Domain, secure)
			}
			t.Logf("%s %s: HttpOnly=%t SameSite=%v Secure=%t Path=%q hostOnly=%t", method, path, c.HttpOnly, c.SameSite, c.Secure, c.Path, c.Domain == "")
		}
		if !found {
			t.Fatalf("%s %s did not exercise a session save", method, path)
		}
		return string(body)
	}

	request("GET", "/account/signin", nil, 200)
	if cookie.MaxAge != 86400*30 {
		t.Errorf("store default MaxAge changed: %d", cookie.MaxAge)
	}
	request("POST", "/account/signin", url.Values{"username": {handle}, "password": {"wrong-password"}}, 303)
	if body := request("GET", "/account/signin", nil, 200); !strings.Contains(body, "Handle or password is incorrect.") {
		t.Fatal("sign-in error flash was not rendered")
	}
	request("POST", "/account/signin", url.Values{"username": {handle}, "password": {password}}, 303)
	if body := request("GET", "/account", nil, 200); !strings.Contains(body, handle) {
		t.Fatal("account page did not authenticate the real sign-in cookie")
	}
	request("POST", "/account/revoke", url.Values{"id": {"999999"}}, 303)
	if body := request("GET", "/account", nil, 200); !strings.Contains(body, "That session was already signed out.") {
		t.Fatal("authenticated account flash was not rendered")
	}
	request("GET", "/account/signin?add=1", nil, 200)
}
