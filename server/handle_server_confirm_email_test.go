package server

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
)

func emailChallengeSnapshot(t *testing.T, s *Server, did string) *models.RepoActor {
	t.Helper()
	repo, err := s.getRepoActorByDid(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func callEmailChallenge(t *testing.T, s *Server, repo *models.RepoActor, action, email, token string) int {
	t.Helper()
	c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server."+action,
		fmt.Sprintf(`{"email":%q,"token":%q}`, email, token), nil)
	c.Set("repo", repo)
	var err error
	switch action {
	case "confirmEmail":
		err = s.handleServerConfirmEmail(c)
	case "requestEmailConfirmation":
		err = s.handleServerRequestEmailConfirmation(c)
	case "requestEmailUpdate":
		err = s.handleServerRequestEmailUpdate(c)
	default:
		t.Fatalf("unknown action %q", action)
	}
	if err != nil {
		t.Fatal(err)
	}
	return rec.Code
}

func TestEmailChallengeStaleAfterUpdate(t *testing.T) {
	for _, action := range []string{"confirmEmail", "requestEmailConfirmation", "requestEmailUpdate"} {
		for _, sameAddress := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/same=%t", action, sameAddress), func(t *testing.T) {
				s := newTestServer(t)
				acct := s.createTestAccount(t, "alice.pds.test")
				other := s.createTestAccount(t, "bob.pds.test")
				seedEmailUpdateChallenges(t, s, acct.Did)
				s.setEmailConfirmed(t, acct.Did, action == "requestEmailUpdate")
				stale := emailChallengeSnapshot(t, s, acct.Did)
				address := "new@test.invalid"
				if sameAddress {
					address = acct.Email
				}
				status, body := callUpdateEmail(t, s, acct, fmt.Sprintf(`{"email":%q,"token":%q}`, address, updateEmailTestToken))
				if status != 200 {
					t.Fatalf("real updateEmail: %d %s", status, body)
				}
				before := emailUpdateState(t, s, acct.Did)
				otherBefore := emailUpdateState(t, s, other.Did)
				if status := callEmailChallenge(t, s, stale, action, acct.Email, updateEmailTestToken); status != 400 {
					t.Errorf("stale snapshot accepted: status %d", status)
				}
				if !reflect.DeepEqual(before, emailUpdateState(t, s, acct.Did)) {
					t.Error("stale request changed account or recreated cleared challenge")
				}
				if !reflect.DeepEqual(otherBefore, emailUpdateState(t, s, other.Did)) {
					t.Error("unrelated account changed")
				}
			})
		}
	}
}

func TestEmailConfirmationProof(t *testing.T) {
	for _, scenario := range []string{"wrong address", "stored address changed", "stored case changed", "wrong token", "replaced", "expiry replaced", "expired snapshot", "expired database", "missing", "replayed"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestServer(t)
			acct := s.createTestAccount(t, "alice.pds.test")
			seedEmailUpdateChallenges(t, s, acct.Did)
			stale := emailChallengeSnapshot(t, s, acct.Did)
			address, token := acct.Email, updateEmailTestToken
			updates := map[string]any{}
			switch scenario {
			case "wrong address":
				address = "wrong@test.invalid"
			case "stored address changed":
				updates["email"] = "different@test.invalid"
			case "stored case changed":
				updates["email"] = strings.ToUpper(acct.Email)
			case "wrong token":
				token = "WRONG"
			case "replaced":
				updates["email_verification_code"] = "REPLACEMENT"
			case "expiry replaced":
				updates["email_verification_code_expires_at"] = time.Now().UTC().Add(2 * time.Hour)
			case "expired snapshot", "expired database":
				updates["email_verification_code_expires_at"] = time.Now().UTC().Add(-time.Minute)
			case "missing":
				updates["email_verification_code"] = nil
				updates["email_verification_code_expires_at"] = nil
			case "replayed":
				if status := callEmailChallenge(t, s, stale, "confirmEmail", address, token); status != 200 {
					t.Fatalf("first use: %d", status)
				}
			}
			if len(updates) > 0 {
				if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Updates(updates).Error; err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "expired snapshot" {
				stale = emailChallengeSnapshot(t, s, acct.Did)
			}
			before := emailUpdateState(t, s, acct.Did)
			if status := callEmailChallenge(t, s, stale, "confirmEmail", address, token); status != 400 {
				t.Errorf("invalid proof accepted: %d", status)
			}
			if !reflect.DeepEqual(before, emailUpdateState(t, s, acct.Did)) {
				t.Error("failed confirmation mutated account/challenges")
			}
		})
	}
}

func TestEmailChallengeControls(t *testing.T) {
	for _, action := range []string{"confirmEmail", "requestEmailConfirmation", "requestEmailUpdate"} {
		for _, confirmed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/confirmed=%t", action, confirmed), func(t *testing.T) {
				s := newTestServer(t)
				acct := s.createTestAccount(t, "Alice.pds.test")
				other := s.createTestAccount(t, "bob.pds.test")
				seedEmailUpdateChallenges(t, s, acct.Did)
				s.setEmailConfirmed(t, acct.Did, confirmed)
				repo := emailChallengeSnapshot(t, s, acct.Did)
				want := emailUpdateState(t, s, acct.Did)
				otherBefore := emailUpdateState(t, s, other.Did)
				start := time.Now().UTC()
				status := callEmailChallenge(t, s, repo, action, strings.ToLower(acct.Email), updateEmailTestToken)
				wantStatus := 200
				if action == "requestEmailConfirmation" && confirmed {
					wantStatus = 400
				}
				if status != wantStatus {
					t.Fatalf("status = %d, want %d", status, wantStatus)
				}
				got := emailUpdateState(t, s, acct.Did)
				switch {
				case action == "confirmEmail":
					if got.EmailConfirmedAt == nil || got.EmailConfirmedAt.Before(start) {
						t.Fatal("missing fresh confirmation")
					}
					want.EmailConfirmedAt = got.EmailConfirmedAt
					want.EmailVerificationCode, want.EmailVerificationCodeExpiresAt = nil, nil
				case action == "requestEmailConfirmation" && !confirmed:
					if got.EmailVerificationCode == nil || *got.EmailVerificationCode == updateEmailTestToken || got.EmailVerificationCodeExpiresAt == nil || !got.EmailVerificationCodeExpiresAt.After(start) {
						t.Fatal("missing fresh confirmation challenge")
					}
					want.EmailVerificationCode, want.EmailVerificationCodeExpiresAt = got.EmailVerificationCode, got.EmailVerificationCodeExpiresAt
				case action == "requestEmailUpdate" && confirmed:
					if got.EmailUpdateCode == nil || *got.EmailUpdateCode == updateEmailTestToken || got.EmailUpdateCodeExpiresAt == nil || !got.EmailUpdateCodeExpiresAt.After(start) {
						t.Fatal("missing fresh update challenge")
					}
					want.EmailUpdateCode, want.EmailUpdateCodeExpiresAt = got.EmailUpdateCode, got.EmailUpdateCodeExpiresAt
				}
				if !reflect.DeepEqual(want, got) || !reflect.DeepEqual(otherBefore, emailUpdateState(t, s, other.Did)) {
					t.Fatal("unexpected account/challenge changes")
				}
			})
		}
	}
}

func TestEmailChallengeInitialIssuance(t *testing.T) {
	for _, action := range []string{"requestEmailConfirmation", "requestEmailUpdate"} {
		t.Run(action, func(t *testing.T) {
			s := newTestServer(t)
			acct := s.createTestAccount(t, "alice.pds.test")
			s.setEmailConfirmed(t, acct.Did, action == "requestEmailUpdate")
			repo := emailChallengeSnapshot(t, s, acct.Did)
			if status := callEmailChallenge(t, s, repo, action, "", ""); status != 200 {
				t.Fatalf("initial issuance: %d", status)
			}
			got := emailUpdateState(t, s, acct.Did)
			code, expiry := got.EmailVerificationCode, got.EmailVerificationCodeExpiresAt
			if action == "requestEmailUpdate" {
				code, expiry = got.EmailUpdateCode, got.EmailUpdateCodeExpiresAt
			}
			if code == nil || len(*code) != 11 || expiry == nil || !expiry.After(time.Now()) {
				t.Fatal("initial challenge not persisted")
			}
		})
	}
}

func TestEmailChallengeIssuerSnapshot(t *testing.T) {
	for _, action := range []string{"requestEmailConfirmation", "requestEmailUpdate"} {
		for _, scenario := range []string{"address", "confirmation", "challenge"} {
			t.Run(action+"/"+scenario, func(t *testing.T) {
				s := newTestServer(t)
				acct := s.createTestAccount(t, "alice.pds.test")
				seedEmailUpdateChallenges(t, s, acct.Did)
				s.setEmailConfirmed(t, acct.Did, action == "requestEmailUpdate")
				stale := emailChallengeSnapshot(t, s, acct.Did)
				updates := map[string]any{}
				switch scenario {
				case "address":
					updates["email"] = strings.ToUpper(acct.Email)
				case "confirmation":
					updates["email_confirmed_at"] = time.Now().UTC()
				case "challenge":
					field := "email_verification_code"
					if action == "requestEmailUpdate" {
						field = "email_update_code"
					}
					updates[field] = "REPLACEMENT"
				}
				if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", acct.Did).Updates(updates).Error; err != nil {
					t.Fatal(err)
				}
				before := emailUpdateState(t, s, acct.Did)
				if status := callEmailChallenge(t, s, stale, action, "", ""); status != 400 {
					t.Errorf("stale issuer: %d", status)
				}
				if !reflect.DeepEqual(before, emailUpdateState(t, s, acct.Did)) {
					t.Error("stale issuer overwrote current state")
				}
			})
		}
	}
}

func TestEmailChallengeWriteFailure(t *testing.T) {
	for _, action := range []string{"confirmEmail", "requestEmailConfirmation", "requestEmailUpdate"} {
		t.Run(action, func(t *testing.T) {
			s := newTestServer(t)
			acct := s.createTestAccount(t, "alice.pds.test")
			seedEmailUpdateChallenges(t, s, acct.Did)
			s.setEmailConfirmed(t, acct.Did, action == "requestEmailUpdate")
			repo := emailChallengeSnapshot(t, s, acct.Did)
			before := emailUpdateState(t, s, acct.Did)
			if err := s.db.Client().Exec(`CREATE TRIGGER reject_email_write BEFORE UPDATE ON repos BEGIN SELECT RAISE(ABORT, 'test write failure'); END`).Error; err != nil {
				t.Fatal(err)
			}
			if status := callEmailChallenge(t, s, repo, action, acct.Email, updateEmailTestToken); status != 500 {
				t.Errorf("failed write status: %d", status)
			}
			if !reflect.DeepEqual(before, emailUpdateState(t, s, acct.Did)) {
				t.Error("failed write changed account/challenges")
			}
		})
	}
}

func TestEmailConfirmationConcurrentSingleUse(t *testing.T) {
	s := newTestServer(t)
	sqlDB, err := s.db.Client().DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	acct := s.createTestAccount(t, "alice.pds.test")
	seedEmailUpdateChallenges(t, s, acct.Did)
	repo := emailChallengeSnapshot(t, s, acct.Did)
	start := make(chan struct{})
	statuses := make(chan int, 2)
	errors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		c, rec := newRequestContext(http.MethodPost, "/xrpc/com.atproto.server.confirmEmail",
			fmt.Sprintf(`{"email":%q,"token":%q}`, acct.Email, updateEmailTestToken), nil)
		c.Set("repo", repo)
		go func() {
			<-start
			errors <- s.handleServerConfirmEmail(c)
			statuses <- rec.Code
		}()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	a, b := <-statuses, <-statuses
	if !((a == 200 && b == 400) || (a == 400 && b == 200)) {
		t.Fatalf("want one success and one rejection, got %d and %d", a, b)
	}
	got := emailUpdateState(t, s, acct.Did)
	if got.EmailConfirmedAt == nil || got.EmailVerificationCode != nil || got.EmailVerificationCodeExpiresAt != nil {
		t.Fatal("proof not consumed atomically with confirmation")
	}
}
