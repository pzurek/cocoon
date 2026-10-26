package server

import (
	"strings"
	"time"

	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerUpdateEmailRequest struct {
	Email           string `json:"email" validate:"required"`
	EmailAuthFactor *bool  `json:"emailAuthFactor"`
	Token           string `json:"token"`
}

func (s *Server) handleServerUpdateEmail(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerUpdateEmail")

	urepo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoServerUpdateEmailRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	req.Email = strings.ToLower(req.Email)
	emailFactor := urepo.TwoFactorType == models.TwoFactorTypeEmail
	// Account creation can preserve mixed case. Compare normalized addresses
	// for toggles, but retain the stored spelling for the SQL snapshot guard.
	explicitToggle := req.EmailAuthFactor != nil && req.Email == strings.ToLower(urepo.Email)
	updates := map[string]any{"two_factor_type": urepo.TwoFactorType}
	checkToken := false

	if req.EmailAuthFactor != nil && *req.EmailAuthFactor {
		// Enabling is only safe for the existing, confirmed mailbox. Never
		// carry an email factor onto an unconfirmed replacement address, or
		// replace an unrelated factor stored in this field.
		if !explicitToggle || urepo.EmailConfirmedAt == nil ||
			(urepo.TwoFactorType != models.TwoFactorTypeNone && !emailFactor) {
			return helpers.InputError(e, nil)
		}
		updates["two_factor_type"] = models.TwoFactorTypeEmail
	} else if explicitToggle {
		// Explicit false is not an email update: preserve confirmation and
		// unrelated challenges. An already-disabled email factor is a no-op.
		if emailFactor {
			checkToken = true
			updates["two_factor_type"] = models.TwoFactorTypeNone
			updates["email_update_code"] = nil
			updates["email_update_code_expires_at"] = nil
		}
	} else {
		// An omitted toggle takes the normal update path, even for the same
		// address. Reset confirmation, the email factor, and every challenge
		// delivered to the old mailbox in the same write. Authenticator
		// credentials, backup codes and shared lockout state are untouched.
		checkToken = urepo.EmailConfirmedAt != nil || req.Token != ""
		updates["email"] = req.Email
		updates["email_confirmed_at"] = nil
		if emailFactor {
			updates["two_factor_type"] = models.TwoFactorTypeNone
		}
		for _, field := range []string{"email_update", "email_verification", "password_reset", "plc_operation", "account_delete", "two_factor"} {
			updates[field+"_code"] = nil
			updates[field+"_code_expires_at"] = nil
		}
	}

	// The middleware's account snapshot may already be stale. Condition the
	// mutation on every state value used to authorize it; when proof is used,
	// its check and consumption are part of this same atomic SQL statement.
	query := s.db.Client().WithContext(ctx).Model(&models.Repo{}).Where(map[string]any{
		"did":                urepo.Repo.Did,
		"email":              urepo.Email,
		"email_confirmed_at": urepo.EmailConfirmedAt,
		"two_factor_type":    urepo.TwoFactorType,
	})
	if checkToken {
		if req.Token == "" || urepo.EmailUpdateCode == nil || urepo.EmailUpdateCodeExpiresAt == nil {
			return helpers.InvalidTokenError(e)
		}

		if *urepo.EmailUpdateCode != req.Token {
			return helpers.InvalidTokenError(e)
		}

		now := time.Now().UTC()
		if !now.Before(*urepo.EmailUpdateCodeExpiresAt) {
			return helpers.ExpiredTokenError(e)
		}
		query = query.Where("email_update_code = ? AND email_update_code_expires_at = ? AND email_update_code_expires_at > ?",
			req.Token, urepo.EmailUpdateCodeExpiresAt, now)
	}

	result := query.Updates(updates)
	if result.Error != nil {
		logger.Error("error updating repo", "error", result.Error)
		return helpers.ServerError(e, nil)
	}
	if result.RowsAffected != 1 {
		return helpers.InvalidTokenError(e)
	}

	return e.NoContent(200)
}
