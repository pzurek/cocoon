package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/golang-jwt/jwt/v4"
	"github.com/haileyok/cocoon/oauth/constants"
	"github.com/haileyok/cocoon/oauth/provider"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// postOauthToken drives /oauth/token through the full router with a fresh
// DPoP proof, the way a real client would.
func postOauthToken(t *testing.T, s *Server, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	proof := newTestDpopProof(t, s, "POST", "https://"+testHostname+"/oauth/token", nil)
	r := httptest.NewRequest("POST", "https://"+testHostname+"/oauth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	s.echo.ServeHTTP(w, r)
	return w
}

// assertInvalidGrant checks the RFC 6749 §5.2 error shape. OAuth clients key
// "this grant is dead, re-authenticate" off error=invalid_grant; any other
// code (e.g. the XRPC-style "InvalidToken") leaves them retrying forever.
func assertInvalidGrant(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	if body["error"] != "invalid_grant" {
		t.Fatalf("error = %q, want %q (body %s)", body["error"], "invalid_grant", w.Body.String())
	}
	if body["error_description"] == "" {
		t.Fatalf("missing error_description (body %s)", w.Body.String())
	}
}

func TestOauthTokenRefreshInvalidGrant(t *testing.T) {
	for _, tc := range []struct {
		name string
		// seed prepares the DB and returns the refresh token to present.
		seed func(t *testing.T, s *Server, account *testAccount) string
	}{
		{
			name: "unknown refresh token",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				return "never-issued"
			},
		},
		{
			name: "revoked by session version bump",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, account.Did, "revoked-refresh")
				if err := s.db.Exec(context.Background(), "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, account.Did).Error; err != nil {
					t.Fatal(err)
				}
				return "revoked-refresh"
			},
		},
		{
			name: "account no longer exists",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, "did:plc:doesnotexistxxxxxxxxxxxx", "orphan-refresh")
				return "orphan-refresh"
			},
		},
		{
			name: "session expired",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, account.Did, "old-session-refresh")
				old := time.Now().Add(-15 * 24 * time.Hour)
				if err := s.db.Exec(context.Background(), "UPDATE oauth_tokens SET created_at = ? WHERE refresh_token = ?", nil, old, "old-session-refresh").Error; err != nil {
					t.Fatal(err)
				}
				return "old-session-refresh"
			},
		},
		{
			name: "refresh token expired",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				seedRefreshToken(t, s, account.Did, "stale-refresh")
				old := time.Now().Add(-15 * 24 * time.Hour)
				if err := s.db.Exec(context.Background(), "UPDATE oauth_tokens SET updated_at = ? WHERE refresh_token = ?", nil, old, "stale-refresh").Error; err != nil {
					t.Fatal(err)
				}
				return "stale-refresh"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			refresh := tc.seed(t, s, account)
			w := postOauthToken(t, s, url.Values{
				"client_id":     {"http://localhost"},
				"grant_type":    {"refresh_token"},
				"refresh_token": {refresh},
			})
			assertInvalidGrant(t, w)
		})
	}
}

func TestOauthTokenRefreshRotation(t *testing.T) {
	for _, name := range []string{"sequential", "concurrent", "update failure", "history failure"} {
		t.Run(name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			sqlDB, err := s.db.Client().DB()
			if err != nil {
				t.Fatal(err)
			}
			sqlDB.SetMaxOpenConns(1)
			auth, _ := authorizationCodeFixture(t, s, account)
			auth.Parameters.Scope = "atproto include:com.example.permissions"
			token := provider.OauthToken{
				ClientId: auth.ClientId, ClientAuth: auth.ClientAuth, Sub: account.Did,
				Parameters: auth.Parameters, Token: "old-access", RefreshToken: "old-refresh",
				ExpiresAt: time.Now().Add(time.Hour),
			}
			if err := s.db.Create(ctx, &token, nil).Error; err != nil {
				t.Fatal(err)
			}
			if name == "sequential" {
				// Upgrade a database with an existing session but no replay history.
				if err := s.db.Exec(ctx, "DROP TABLE oauth_used_refresh_tokens", nil).Error; err != nil {
					t.Fatal(err)
				}
				for range 2 {
					if err := s.Migrate(); err != nil {
						t.Fatal(err)
					}
				}
			}
			form := url.Values{
				"client_id": {auth.ClientId}, "grant_type": {"refresh_token"},
				"refresh_token": {token.RefreshToken},
			}
			n := 1
			if name == "concurrent" {
				n = 8
			}
			var arrived atomic.Int32
			release := make(chan struct{})
			s.scopeResolver = codeExchangeResolver(func(ctx context.Context) {
				if arrived.Add(1) == int32(n) {
					close(release)
				}
				select {
				case <-release:
				case <-ctx.Done():
				}
			})
			if name == "update failure" || name == "history failure" {
				target := "UPDATE ON oauth_tokens"
				if name == "history failure" {
					target = "INSERT ON oauth_used_refresh_tokens"
				}
				if err := s.db.Exec(ctx, "CREATE TRIGGER fail_rotation BEFORE "+target+" BEGIN SELECT RAISE(ABORT, 'test failure'); END", nil).Error; err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form).WithContext(ctx))
				if w.Code != 500 {
					t.Fatalf("failed update: %d %s", w.Code, w.Body.String())
				}
				if err := s.db.Exec(ctx, "DROP TRIGGER fail_rotation", nil).Error; err != nil {
					t.Fatal(err)
				}
			}
			results := make(chan *httptest.ResponseRecorder, n)
			for range n {
				r := authorizationCodeRequest(t, s, form).WithContext(ctx)
				go func() {
					w := httptest.NewRecorder()
					s.echo.ServeHTTP(w, r)
					results <- w
				}()
			}
			var response OauthTokenResponse
			successes := 0
			for range n {
				w := <-results
				if w.Code == 200 {
					successes++
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
				} else {
					assertInvalidGrant(t, w)
				}
			}
			wantCount := int64(1)
			if name == "concurrent" {
				wantCount = 0 // A concurrent loser detects replay and revokes the winner.
			}
			if successes != 1 || countOauthTokens(t, s) != wantCount {
				t.Fatalf("wanted one response and %d stored sessions, got %d responses and %d sessions", wantCount, successes, countOauthTokens(t, s))
			}
			wantScope := auth.Parameters.Scope + " repo:com.example.record?action=create"
			if response.TokenType != "DPoP" || response.Sub != account.Did || response.Scope != wantScope || response.RefreshToken == token.RefreshToken {
				t.Fatalf("incorrect rotated credentials: %+v", response)
			}
			parsed, err := jwt.Parse(response.AccessToken, func(*jwt.Token) (any, error) { return s.privateKey.Public(), nil }, jwt.WithValidMethods([]string{"ES256"}))
			if err != nil {
				t.Fatal(err)
			}
			claims := parsed.Claims.(jwt.MapClaims)
			cnf, ok := claims["cnf"].(map[string]any)
			if !ok || cnf["jkt"] != *auth.Parameters.DpopJkt || claims["scope"] != wantScope {
				t.Fatal("JWT scope or DPoP confirmation differs from the refreshed grant")
			}
			if name != "concurrent" {
				// Keep rotating: replay of any superseded token must find the session,
				// not only replay of the immediate predecessor.
				for range 2 {
					next := url.Values{"client_id": {auth.ClientId}, "grant_type": {"refresh_token"}, "refresh_token": {response.RefreshToken}}
					w := httptest.NewRecorder()
					s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, next))
					if w.Code != 200 {
						t.Fatalf("valid rotation: %d %s", w.Code, w.Body.String())
					}
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := s.pruneOauthTokens(ctx, time.Now()); err != nil {
				t.Fatal(err)
			}
			seedRefreshToken(t, s, account.Did, "unrelated-session")
			w := httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
			assertInvalidGrant(t, w)
			if countOauthTokens(t, s) != 1 {
				t.Fatal("refresh replay must revoke only the matching session")
			}
			if err := s.db.First(ctx, &provider.OauthToken{}, "refresh_token = ?", "unrelated-session").Error; err != nil {
				t.Fatalf("replay revoked unrelated session: %v", err)
			}

			r := httptest.NewRequest("GET", "/xrpc/com.atproto.server.getSession", nil)
			r.Header.Set("Authorization", "DPoP "+response.AccessToken)
			r.Header.Set("DPoP", newTestDpopProofWithKey(t, s, r.Method, "https://"+testHostname+r.URL.String(), &response.AccessToken, s.privateKey))
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("winner's access token usable after replay: %d %s", w.Code, w.Body.String())
			}
			form.Set("refresh_token", response.RefreshToken)
			w = httptest.NewRecorder()
			s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
			assertInvalidGrant(t, w)
			if _, err := s.pruneOauthTokens(ctx, time.Now()); err != nil {
				t.Fatal(err)
			}
			var history int64
			if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM oauth_used_refresh_tokens", nil).Scan(&history).Error; err != nil {
				t.Fatal(err)
			}
			if history != 0 {
				t.Fatal("revoked session left orphaned replay history after pruning")
			}
		})
	}
}

func TestOauthRefreshRechecksAfterScopeResolution(t *testing.T) {
	for _, method := range []string{"none", "private_key_jwt"} {
		for _, change := range []string{"valid", "session expiry", "refresh expiry", "revocation", "token deletion", "account deletion"} {
			t.Run(method+"/"+change, func(t *testing.T) {
				s, account := endpointTestServer(t)
				ctx := t.Context()
				auth, _ := authorizationCodeFixture(t, s, account)
				auth.Parameters.Scope = "atproto include:com.example.permissions"
				form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"old-refresh"}}
				sessionLifetime, refreshLifetime := 14*24*time.Hour, 14*24*time.Hour
				if method == "private_key_jwt" {
					sessionLifetime, refreshLifetime = 730*24*time.Hour, 90*24*time.Hour
					key, err := jwk.FromRaw(s.privateKey.Public())
					if err != nil {
						t.Fatal(err)
					}
					if err := key.Set(jwk.KeyIDKey, "refresh-client"); err != nil {
						t.Fatal(err)
					}
					metadata := map[string]any{
						"redirect_uris": []string{"https://example.com/callback"}, "response_types": []string{"code"},
						"grant_types": []string{"authorization_code", "refresh_token"}, "scope": "atproto",
						"application_type": "web", "token_endpoint_auth_method": method,
						"token_endpoint_auth_signing_alg": "ES256", "dpop_bound_access_tokens": true,
						"jwks": map[string]any{"keys": []any{key}},
					}
					clientServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						_ = json.NewEncoder(w).Encode(metadata)
					}))
					t.Cleanup(clientServer.Close)
					auth.ClientId = clientServer.URL + "/client-metadata.json"
					metadata["client_id"] = auth.ClientId
					assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
						"iss": auth.ClientId, "sub": auth.ClientId, "aud": "https://" + testHostname,
						"iat": time.Now().Unix(), "jti": "refresh-assertion",
					})
					assertion.Header["kid"] = "refresh-client"
					signed, err := assertion.SignedString(s.privateKey)
					if err != nil {
						t.Fatal(err)
					}
					form.Set("client_assertion_type", constants.ClientAssertionTypeJwtBearer)
					form.Set("client_assertion", signed)
				}
				form.Set("client_id", auth.ClientId)
				token := provider.OauthToken{
					ClientId: auth.ClientId, ClientAuth: provider.ClientAuth{Method: method}, Sub: account.Did,
					Parameters: auth.Parameters, Token: "old-access", RefreshToken: "old-refresh",
					ExpiresAt: time.Now().Add(-time.Hour), SessionVersion: 7,
				}
				// Valid refreshes may outlive access tokens and, for confidential clients, two weeks.
				token.CreatedAt = time.Now().Add(-sessionLifetime + 24*time.Hour)
				token.UpdatedAt = time.Now().Add(-refreshLifetime + 24*time.Hour)
				if err := s.db.Exec(ctx, "UPDATE repos SET session_version = ? WHERE did = ?", nil, token.SessionVersion, account.Did).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Create(ctx, &token, nil).Error; err != nil {
					t.Fatal(err)
				}
				resolved := false
				s.scopeResolver = codeExchangeResolver(func(ctx context.Context) {
					resolved = true
					var err error
					switch change {
					case "session expiry", "refresh expiry":
						expires := time.Now().Add(20 * time.Millisecond)
						column, lifetime := "created_at", sessionLifetime
						if change == "refresh expiry" {
							column, lifetime = "updated_at", refreshLifetime
						}
						err = s.db.Exec(ctx, "UPDATE oauth_tokens SET "+column+" = ? WHERE id = ?", nil, expires.Add(-lifetime), token.ID).Error
						time.Sleep(time.Until(expires) + time.Millisecond)
					case "revocation":
						err = s.db.Exec(ctx, "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, account.Did).Error
					case "token deletion":
						err = s.db.Exec(ctx, "DELETE FROM oauth_tokens WHERE id = ?", nil, token.ID).Error
					case "account deletion":
						err = s.db.Exec(ctx, "DELETE FROM repos WHERE did = ?", nil, account.Did).Error
					}
					if err != nil {
						t.Fatal(err)
					}
				})
				w := httptest.NewRecorder()
				s.echo.ServeHTTP(w, authorizationCodeRequest(t, s, form))
				if !resolved {
					t.Fatalf("request did not reach scope resolution: %d %s", w.Code, w.Body.String())
				}
				if change == "valid" {
					if w.Code != 200 {
						t.Fatalf("valid refresh rejected: %d %s", w.Code, w.Body.String())
					}
					var response OauthTokenResponse
					if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					var stored provider.OauthToken
					if err := s.db.First(ctx, &stored, "token = ?", response.AccessToken).Error; err != nil {
						t.Fatal(err)
					}
					if stored.RefreshToken != response.RefreshToken || !stored.CreatedAt.Equal(token.CreatedAt) || !stored.UpdatedAt.After(token.UpdatedAt) {
						t.Fatal("rotation must preserve session creation time and renew refresh time")
					}
				} else {
					assertInvalidGrant(t, w)
					var rotated int64
					if err := s.db.Raw(ctx, "SELECT COUNT(*) FROM oauth_tokens WHERE token != ? OR refresh_token != ?", nil, token.Token, token.RefreshToken).Scan(&rotated).Error; err != nil {
						t.Fatal(err)
					}
					wantCount := int64(1)
					if change == "token deletion" {
						wantCount = 0
					}
					if rotated != 0 || countOauthTokens(t, s) != wantCount {
						t.Fatal("rejected refresh changed stored credentials")
					}
				}
			})
		}
	}
}

func TestOauthTokenAuthorizationCodeInvalidGrant(t *testing.T) {
	const redirectURI = "http://127.0.0.1/"
	verifier := strings.Repeat("verifier", 8)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	for _, tc := range []struct {
		name string
		// seed prepares the DB and returns the authorization code to present.
		seed func(t *testing.T, s *Server, account *testAccount) string
	}{
		{
			name: "unknown or already-used code",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				return "never-issued-code"
			},
		},
		{
			name: "revoked by session version bump",
			seed: func(t *testing.T, s *Server, account *testAccount) string {
				ctx := context.Background()
				auth := provider.OauthAuthorizationRequest{
					RequestId:  "stale-auth",
					ClientId:   "http://localhost",
					ClientAuth: provider.ClientAuth{Method: "none"},
					Parameters: provider.ParRequest{
						Scope: "atproto", RedirectURI: redirectURI,
						CodeChallenge: &challenge, CodeChallengeMethod: "S256",
					},
					ExpiresAt: time.Now().Add(time.Hour),
					Sub:       to.StringPtr(account.Did),
					Code:      to.StringPtr("stale-code"),
				}
				if err := s.db.Create(ctx, &auth, nil).Error; err != nil {
					t.Fatal(err)
				}
				if err := s.db.Exec(ctx, "UPDATE repos SET session_version = session_version + 1 WHERE did = ?", nil, account.Did).Error; err != nil {
					t.Fatal(err)
				}
				return "stale-code"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, account := endpointTestServer(t)
			code := tc.seed(t, s, account)
			w := postOauthToken(t, s, url.Values{
				"client_id":     {"http://localhost"},
				"grant_type":    {"authorization_code"},
				"code":          {code},
				"redirect_uri":  {redirectURI},
				"code_verifier": {verifier},
			})
			assertInvalidGrant(t, w)
		})
	}
}

// seedRefreshToken inserts an OAuth token for a public (auth method "none")
// client with no DPoP key binding, so the request reaches the grant checks.
func seedRefreshToken(t *testing.T, s *Server, sub, refresh string) {
	t.Helper()
	token := provider.OauthToken{
		ClientId:     "http://localhost",
		ClientAuth:   provider.ClientAuth{Method: "none"},
		Sub:          sub,
		Parameters:   provider.ParRequest{Scope: "atproto", RedirectURI: "http://127.0.0.1/"},
		Token:        "access-" + refresh,
		RefreshToken: refresh,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := s.db.Create(context.Background(), &token, nil).Error; err != nil {
		t.Fatal(err)
	}
}
