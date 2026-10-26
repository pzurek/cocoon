package server

import (
	"strings"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoServerConfirmEmailRequest struct {
	Email string `json:"email" validate:"required"`
	Token string `json:"token" validate:"required"`
}

func (s *Server) handleServerConfirmEmail(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerConfirmEmail")

	urepo := e.Get("repo").(*models.RepoActor)

	var req ComAtprotoServerConfirmEmailRequest
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding", "error", err)
		return helpers.ServerError(e, nil)
	}

	if err := e.Validate(req); err != nil {
		return helpers.InputError(e, nil)
	}

	if strings.ToLower(req.Email) != strings.ToLower(urepo.Email) {
		return helpers.InputError(e, to.StringPtr("InvalidEmail"))
	}

	if urepo.EmailVerificationCode == nil || urepo.EmailVerificationCodeExpiresAt == nil {
		return helpers.ExpiredTokenError(e)
	}

	if *urepo.EmailVerificationCode != req.Token {
		return helpers.InputError(e, to.StringPtr("InvalidToken"))
	}

	now := time.Now().UTC()
	if !now.Before(*urepo.EmailVerificationCodeExpiresAt) {
		return helpers.ExpiredTokenError(e)
	}

	// Bind proof consumption to the exact stored mailbox and challenge, not
	// merely the middleware snapshot. Concurrent uses can have only one winner.
	result := s.db.Client().WithContext(ctx).Model(&models.Repo{}).
		Where("did = ? AND email = ? AND email_verification_code = ? AND email_verification_code_expires_at = ? AND email_verification_code_expires_at > ?",
			urepo.Repo.Did, urepo.Email, req.Token, urepo.EmailVerificationCodeExpiresAt, now).
		Updates(map[string]any{
			"email_verification_code":            nil,
			"email_verification_code_expires_at": nil,
			"email_confirmed_at":                 now,
		})
	if result.Error != nil {
		logger.Error("error updating user", "error", result.Error)
		return helpers.ServerError(e, nil)
	}
	if result.RowsAffected != 1 {
		return helpers.InvalidTokenError(e)
	}

	return e.NoContent(200)
}
