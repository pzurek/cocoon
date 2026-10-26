package server

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
)

// updateEmail security rules under test:
//
//  1. Changing a *confirmed* email address requires the emailed token
//     (requestEmailUpdate delivers it to the current address). Without this,
//     any holder of an access token could swap the account email and then
//     chain the unauthenticated password-reset flow to take over the
//     account, defeating email 2FA.
//  2. Disabling the email auth factor on a 2FA-enabled account requires the
//     token (existing behavior, kept).
//  3. Changing an *unconfirmed* email stays token-free (registration-style
//     correction of a typo'd address) — the address was never proven, so
//     there is nothing to defend.
//  4. Enabling is restricted to the same confirmed mailbox. Explicit toggles
//     preserve confirmation, whereas an omitted toggle resets it and clears
//     all emailed challenges. Snapshot checks and proof consumption are atomic.

const updateEmailTestToken = "ABCDE-FGHIJ"

// setEmailConfirmed flips the account's email confirmation state.
func (s *Server) setEmailConfirmed(t *testing.T, did string, confirmed bool) {
	t.Helper()
	ts := time.Now().Add(-time.Hour)
	var val *time.Time
	if confirmed {
		val = &ts
	}
	if err := s.db.Exec(context.Background(), "UPDATE repos SET email_confirmed_at = ? WHERE did = ?", nil, val, did).Error; err != nil {
		t.Fatalf("set email_confirmed_at: %v", err)
	}
}

// setEmailUpdateCode seeds a valid emailed update token on the account.
func (s *Server) setEmailUpdateCode(t *testing.T, did, code string) {
	t.Helper()
	eat := time.Now().Add(10 * time.Minute).UTC()
	if err := s.db.Exec(context.Background(), "UPDATE repos SET email_update_code = ?, email_update_code_expires_at = ? WHERE did = ?", nil, code, eat, did).Error; err != nil {
		t.Fatalf("set email_update_code: %v", err)
	}
}

func callUpdateEmail(t *testing.T, s *Server, acct *testAccount, body string) (int, string) {
	t.Helper()
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.updateEmail", body, nil)
	repo, err := s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	c.Set("repo", repo)
	if err := s.handleServerUpdateEmail(c); err != nil {
		t.Fatalf("handler returned error: %v", err)
	}
	return rec.Code, rec.Body.String()
}

func (s *Server) currentEmail(t *testing.T, did string) string {
	t.Helper()
	repo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatalf("getRepoActorByDid: %v", err)
	}
	return repo.Repo.Email
}

// TestUpdateEmailConfirmedChangeRequiresToken: with a confirmed email, an
// address change without the emailed token must be rejected.
func TestUpdateEmailConfirmedChangeRequiresToken(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)

	code, _ := callUpdateEmail(t, s, acct, `{"email":"attacker@evil.example"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for confirmed-email change without token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != acct.Email {
		t.Fatalf("email was changed without a token: %q", got)
	}
}

// TestUpdateEmailConfirmedChangeWithTokenSucceeds: the same change with a
// valid emailed token succeeds.
func TestUpdateEmailConfirmedChangeWithTokenSucceeds(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	s.setEmailUpdateCode(t, acct.Did, updateEmailTestToken)

	code, _ := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":"newaddr@example.com","token":%q}`, updateEmailTestToken))
	if code != http.StatusOK {
		t.Fatalf("expected 200 for confirmed-email change with valid token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != "newaddr@example.com" {
		t.Fatalf("email not updated: %q", got)
	}
}

// TestUpdateEmailDisableAuthFactorStillRequiresToken: 2FA-disable keeps
// requiring the token (existing behavior).
func TestUpdateEmailDisableAuthFactorStillRequiresToken(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	if err := s.db.Exec(context.Background(), "UPDATE repos SET two_factor_type = ? WHERE did = ?", nil, models.TwoFactorTypeEmail, acct.Did).Error; err != nil {
		t.Fatalf("set 2fa: %v", err)
	}

	// Same address, disabling the factor, no token -> rejected.
	code, _ := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":%q,"emailAuthFactor":false}`, acct.Email))
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 2FA-disable without token, got %d", code)
	}

	// With the token it succeeds.
	s.setEmailUpdateCode(t, acct.Did, updateEmailTestToken)
	code, _ = callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":%q,"emailAuthFactor":false,"token":%q}`, acct.Email, updateEmailTestToken))
	if code != http.StatusOK {
		t.Fatalf("expected 200 for 2FA-disable with token, got %d", code)
	}
}

// TestUpdateEmailUnconfirmedChangeWithoutToken: changing an unconfirmed
// address stays token-free.
func TestUpdateEmailUnconfirmedChangeWithoutToken(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, false)

	code, _ := callUpdateEmail(t, s, acct, `{"email":"fixed-typo@example.com"}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200 for unconfirmed-email change without token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != "fixed-typo@example.com" {
		t.Fatalf("email not updated: %q", got)
	}
}

// TestUpdateEmailWrongTokenRejected: a bad token must not authorize the change.
func TestUpdateEmailWrongTokenRejected(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	s.setEmailUpdateCode(t, acct.Did, updateEmailTestToken)

	code, _ := callUpdateEmail(t, s, acct, `{"email":"attacker@evil.example","token":"WRONG-CODE"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong token, got %d", code)
	}
	if got := s.currentEmail(t, acct.Did); got != acct.Email {
		t.Fatalf("email was changed with a wrong token: %q", got)
	}
}

func emailUpdateState(t *testing.T, s *Server, did string) models.Repo {
	t.Helper()
	var repo models.Repo
	if err := s.db.First(context.Background(), &repo, "did = ?", did).Error; err != nil {
		t.Fatal(err)
	}
	return repo
}

func seedEmailUpdateChallenges(t *testing.T, s *Server, did string) {
	t.Helper()
	updates := map[string]any{}
	for _, field := range []string{"email_update", "email_verification", "password_reset", "plc_operation", "account_delete", "two_factor"} {
		updates[field+"_code"] = updateEmailTestToken
		updates[field+"_code_expires_at"] = time.Now().UTC().Add(time.Hour)
	}
	if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", did).Updates(updates).Error; err != nil {
		t.Fatal(err)
	}
}

func TestUpdateEmailFactorPolicy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		confirmed  bool
		enabled    bool
		change     bool
		factor     string
		token      string
		wantStatus int
		normal     bool
	}{
		{"unconfirmed enable", false, false, false, "true", "", 400, false},
		{"unconfirmed change and enable", false, false, true, "true", "", 400, false},
		{"confirmed change and enable with proof", true, true, true, "true", updateEmailTestToken, 400, false},
		{"confirmed enable", true, false, false, "true", "", 200, false},
		{"confirmed enable idempotent", true, true, false, "true", "", 200, false},
		{"enable ignores irrelevant token", true, false, false, "true", "WRONG", 200, false},
		{"explicit disabled preserves confirmation", true, false, false, "false", "", 200, false},
		{"disable needs proof", true, true, false, "false", "", 400, false},
		{"disable with proof", true, true, false, "false", updateEmailTestToken, 200, false},
		{"disable wrong proof", true, true, false, "false", "WRONG", 400, false},
		{"omitted same confirmed needs proof", true, false, false, "", "", 400, false},
		{"omitted same confirmed resets", true, true, false, "", updateEmailTestToken, 200, true},
		{"null same confirmed resets", true, true, false, "null", updateEmailTestToken, 200, true},
		{"omitted same unconfirmed resets", false, false, false, "", "", 200, true},
		{"unconfirmed enabled change clears factor without proof", false, true, true, "", "", 200, true},
		{"change clears email factor", true, true, true, "", updateEmailTestToken, 200, true},
		{"explicit false change clears email factor", true, true, true, "false", updateEmailTestToken, 200, true},
		{"wrong proof unchanged", true, true, true, "", "WRONG", 400, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			acct := s.createTestAccount(t, "alice.pds.test")
			s.setEmailConfirmed(t, acct.Did, tc.confirmed)
			seedEmailUpdateChallenges(t, s, acct.Did)
			if tc.enabled {
				if err := s.db.Exec(context.Background(), "UPDATE repos SET two_factor_type = ? WHERE did = ?", nil, models.TwoFactorTypeEmail, acct.Did).Error; err != nil {
					t.Fatal(err)
				}
			}
			before := emailUpdateState(t, s, acct.Did)
			email := acct.Email
			if tc.change {
				email = "new@example.com"
			}
			body := fmt.Sprintf(`{"email":%q,"token":%q`, email, tc.token)
			if tc.factor != "" {
				body += `,"emailAuthFactor":` + tc.factor
			}
			status, response := callUpdateEmail(t, s, acct, body+"}")
			if status != tc.wantStatus {
				t.Fatalf("status = %d, want %d: %s", status, tc.wantStatus, response)
			}
			after := emailUpdateState(t, s, acct.Did)
			want := before
			if tc.wantStatus == 200 {
				if tc.normal {
					want.Email = email
					want.EmailConfirmedAt = nil
					want.TwoFactorType = models.TwoFactorTypeNone
					want.EmailUpdateCode, want.EmailUpdateCodeExpiresAt = nil, nil
					want.EmailVerificationCode, want.EmailVerificationCodeExpiresAt = nil, nil
					want.PasswordResetCode, want.PasswordResetCodeExpiresAt = nil, nil
					want.PlcOperationCode, want.PlcOperationCodeExpiresAt = nil, nil
					want.AccountDeleteCode, want.AccountDeleteCodeExpiresAt = nil, nil
					want.TwoFactorCode, want.TwoFactorCodeExpiresAt = nil, nil
				} else if tc.factor == "true" {
					want.TwoFactorType = models.TwoFactorTypeEmail
				} else if tc.enabled {
					want.TwoFactorType = models.TwoFactorTypeNone
					want.EmailUpdateCode, want.EmailUpdateCodeExpiresAt = nil, nil
				}
			}
			if !reflect.DeepEqual(after, want) {
				// Report field names, not account secrets, on regression.
				gotValue, wantValue := reflect.ValueOf(after), reflect.ValueOf(want)
				for i := 0; i < gotValue.NumField(); i++ {
					if !reflect.DeepEqual(gotValue.Field(i).Interface(), wantValue.Field(i).Interface()) {
						t.Errorf("unexpected mutation of %s", gotValue.Type().Field(i).Name)
					}
				}
			}
		})
	}
}

func TestUpdateEmailExpiredProofUnchanged(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	seedEmailUpdateChallenges(t, s, acct.Did)
	if err := s.db.Exec(context.Background(), "UPDATE repos SET email_update_code_expires_at = ? WHERE did = ?", nil, time.Now().UTC().Add(-time.Hour), acct.Did).Error; err != nil {
		t.Fatal(err)
	}
	before := emailUpdateState(t, s, acct.Did)
	status, body := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":"new@example.com","token":%q}`, updateEmailTestToken))
	if status != 400 || !strings.Contains(body, "ExpiredToken") {
		t.Fatalf("expected expired token: %d %s", status, body)
	}
	if !reflect.DeepEqual(before, emailUpdateState(t, s, acct.Did)) {
		t.Fatal("expired proof changed account")
	}
}

func TestUpdateEmailStaleSnapshot(t *testing.T) {
	for _, change := range []string{"email", "confirmation", "confirmation added", "factor", "proof", "expiry", "reuse"} {
		t.Run(change, func(t *testing.T) {
			s := newTestServer(t)
			acct := s.createTestAccount(t, "alice.pds.test")
			s.setEmailConfirmed(t, acct.Did, change != "confirmation added")
			seedEmailUpdateChallenges(t, s, acct.Did)
			repo, err := s.getRepoActorByDid(context.Background(), acct.Did)
			if err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"email":"new@example.com","token":%q}`, updateEmailTestToken)
			updates := map[string]any{}
			switch change {
			case "email":
				updates["email"] = "changed@example.com"
				body = fmt.Sprintf(`{"email":%q,"emailAuthFactor":true}`, acct.Email)
			case "confirmation":
				updates["email_confirmed_at"] = nil
				body = fmt.Sprintf(`{"email":%q,"emailAuthFactor":true}`, acct.Email)
			case "confirmation added":
				updates["email_confirmed_at"] = time.Now().UTC()
				body = `{"email":"new@example.com"}`
			case "factor":
				updates["two_factor_type"] = models.TwoFactorTypeEmail
				body = fmt.Sprintf(`{"email":%q,"emailAuthFactor":false}`, acct.Email)
			case "proof":
				updates["email_update_code"] = "REPLACED"
			case "expiry":
				updates["email_update_code_expires_at"] = time.Now().UTC().Add(-time.Hour)
			case "reuse":
				status, response := callUpdateEmail(t, s, acct, body)
				if status != 200 {
					t.Fatalf("first use: %d %s", status, response)
				}
			}
			if len(updates) > 0 {
				if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Updates(updates).Error; err != nil {
					t.Fatal(err)
				}
			}
			before := emailUpdateState(t, s, acct.Did)
			c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.updateEmail", body, nil)
			c.Set("repo", repo)
			if err := s.handleServerUpdateEmail(c); err != nil {
				t.Fatal(err)
			}
			if rec.Code != 400 {
				t.Fatalf("stale snapshot accepted: %d %s", rec.Code, rec.Body.String())
			}
			if !reflect.DeepEqual(before, emailUpdateState(t, s, acct.Did)) {
				t.Fatal("stale snapshot changed account")
			}
		})
	}
}

func TestUpdateEmailPreservesOtherFactors(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	creds := []models.TwoFactorCredential{
		{Did: acct.Did, Type: models.TwoFactorCredentialTOTP, Secret: []byte("totp secret")},
		{Did: acct.Did, Type: models.TwoFactorCredentialYubicoOTP, PublicID: "yubikey"},
	}
	backup := models.TwoFactorBackupCode{Did: acct.Did, CodeHash: []byte("backup hash")}
	if err := s.db.Create(context.Background(), &creds, nil).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(context.Background(), &backup, nil).Error; err != nil {
		t.Fatal(err)
	}
	// Compare persisted values: database round-trips strip monotonic clock data.
	if err := s.db.Client().Where("did = ?", acct.Did).Order("id").Find(&creds).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.First(context.Background(), &backup, "did = ?", acct.Did).Error; err != nil {
		t.Fatal(err)
	}
	// Unknown/future non-email values must not be treated as email OTP either.
	if err := s.db.Exec(context.Background(), "UPDATE repos SET two_factor_type = ?, two_factor_failed_attempts = 3 WHERE did = ?", nil, "other", acct.Did).Error; err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		fmt.Sprintf(`{"email":%q,"emailAuthFactor":false}`, acct.Email),
		`{"email":"new@example.com"}`,
	} {
		status, response := callUpdateEmail(t, s, acct, body)
		if status != 200 {
			t.Fatalf("update: %d %s", status, response)
		}
	}
	got := emailUpdateState(t, s, acct.Did)
	if got.TwoFactorType != "other" || got.TwoFactorFailedAttempts != 3 {
		t.Fatal("unrelated factor state changed")
	}
	s.setEmailConfirmed(t, acct.Did, true)
	beforeEnable := emailUpdateState(t, s, acct.Did)
	status, _ := callUpdateEmail(t, s, acct, `{"email":"new@example.com","emailAuthFactor":true}`)
	if status != 400 || !reflect.DeepEqual(beforeEnable, emailUpdateState(t, s, acct.Did)) {
		t.Fatal("email enable must not replace an unrelated factor type")
	}
	var gotCreds []models.TwoFactorCredential
	if err := s.db.Client().Where("did = ?", acct.Did).Order("id").Find(&gotCreds).Error; err != nil {
		t.Fatal(err)
	}
	var gotBackup models.TwoFactorBackupCode
	if err := s.db.First(context.Background(), &gotBackup, "did = ?", acct.Did).Error; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(creds, gotCreds) || !reflect.DeepEqual(backup, gotBackup) {
		t.Fatal("authenticator credentials or backup codes changed")
	}
}

func TestUpdateEmailConcurrentProofSingleUse(t *testing.T) {
	s := newTestServer(t)
	sqlDB, err := s.db.Client().DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	acct := s.createTestAccount(t, "alice.pds.test")
	// Keep email, confirmation and factor state unchanged so only the proof
	// predicate can distinguish the winning request from a replay.
	s.setEmailConfirmed(t, acct.Did, false)
	seedEmailUpdateChallenges(t, s, acct.Did)
	repo, err := s.getRepoActorByDid(context.Background(), acct.Did)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	statuses := make(chan int, 2)
	errors := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.updateEmail",
			fmt.Sprintf(`{"email":%q,"token":%q}`, acct.Email, updateEmailTestToken), nil)
		c.Set("repo", repo)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errors <- s.handleServerUpdateEmail(c)
			statuses <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	a, b := <-statuses, <-statuses
	if !((a == 200 && b == 400) || (a == 400 && b == 200)) {
		t.Fatalf("proof must authorize exactly one update, got %d and %d", a, b)
	}
	got := emailUpdateState(t, s, acct.Did)
	if got.EmailUpdateCode != nil || got.EmailUpdateCodeExpiresAt != nil {
		t.Fatal("successful update did not consume proof")
	}
	if got.Email != repo.Email || got.EmailConfirmedAt != nil || got.TwoFactorType != repo.TwoFactorType {
		t.Fatal("proof-only concurrency control unexpectedly changed address, confirmation or factor")
	}
}

func TestUpdateEmailFailedWritePreservesProof(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	other := s.createTestAccount(t, "bob.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	seedEmailUpdateChallenges(t, s, acct.Did)
	before := emailUpdateState(t, s, acct.Did)
	status, _ := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":%q,"token":%q}`, other.Email, updateEmailTestToken))
	if status != 500 {
		t.Fatalf("expected existing unique-email constraint error, got %d", status)
	}
	if !reflect.DeepEqual(before, emailUpdateState(t, s, acct.Did)) {
		t.Fatal("failed email write consumed proof or changed account")
	}
}

func TestUpdateEmailNormalizesAddressBeforeToggle(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "alice.pds.test")
	s.setEmailConfirmed(t, acct.Did, true)
	status, response := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":%q,"emailAuthFactor":true}`, strings.ToUpper(acct.Email)))
	if status != 200 {
		t.Fatalf("enable with normalized address: %d %s", status, response)
	}
	got := emailUpdateState(t, s, acct.Did)
	if got.Email != acct.Email || got.EmailConfirmedAt == nil || got.TwoFactorType != models.TwoFactorTypeEmail {
		t.Fatal("normalization should enable without changing or unconfirming the address")
	}
}

func TestUpdateEmailMixedCaseStoredAddressToggle(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		enable  bool
		token   string
	}{
		{"enable", false, true, ""},
		{"disable with proof", true, false, updateEmailTestToken},
		{"already disabled no-op", false, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			acct := s.createTestAccount(t, "alice.pds.test")
			factor := models.TwoFactorTypeNone
			if tc.enabled {
				factor = models.TwoFactorTypeEmail
			}
			if err := s.db.Exec(context.Background(), "UPDATE repos SET email = ?, two_factor_type = ? WHERE did = ?",
				nil, "Alice@example.com", factor, acct.Did).Error; err != nil {
				t.Fatal(err)
			}
			s.setEmailConfirmed(t, acct.Did, true)
			seedEmailUpdateChallenges(t, s, acct.Did)
			want := emailUpdateState(t, s, acct.Did)
			status, response := callUpdateEmail(t, s, acct, fmt.Sprintf(
				`{"email":"Alice@example.com","emailAuthFactor":%t,"token":%q}`, tc.enable, tc.token))
			if status != 200 {
				t.Fatalf("same-address toggle: %d %s", status, response)
			}
			if tc.enable {
				want.TwoFactorType = models.TwoFactorTypeEmail
			} else if tc.enabled {
				want.TwoFactorType = models.TwoFactorTypeNone
				want.EmailUpdateCode, want.EmailUpdateCodeExpiresAt = nil, nil
			}
			if !reflect.DeepEqual(emailUpdateState(t, s, acct.Did), want) {
				t.Fatal("toggle must preserve stored email spelling, confirmation and unrelated state")
			}
		})
	}
}
