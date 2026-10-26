package server

import (
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleServerRequestEmailConfirmation(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerRequestEmailConfirm")

	urepo := e.Get("repo").(*models.RepoActor)

	if urepo.EmailConfirmedAt != nil {
		return helpers.InputError(e, to.StringPtr("InvalidRequest"))
	}

	code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
	eat := time.Now().Add(10 * time.Minute).UTC()

	// A stale request must not recreate a challenge cleared by updateEmail,
	// including a same-address reset. Do not hold a transaction while mailing.
	result := s.db.Client().WithContext(ctx).Model(&models.Repo{}).Where(map[string]any{
		"did":                                urepo.Repo.Did,
		"email":                              urepo.Email,
		"email_confirmed_at":                 nil,
		"email_verification_code":            urepo.EmailVerificationCode,
		"email_verification_code_expires_at": urepo.EmailVerificationCodeExpiresAt,
	}).Updates(map[string]any{
		"email_verification_code":            code,
		"email_verification_code_expires_at": eat,
	})
	if result.Error != nil {
		logger.Error("error updating user", "error", result.Error)
		return helpers.ServerError(e, nil)
	}
	if result.RowsAffected != 1 {
		return helpers.InputError(e, to.StringPtr("InvalidRequest"))
	}

	if err := s.sendEmailVerification(urepo.Email, urepo.Handle, code); err != nil {
		logger.Error("error sending mail", "error", err)
		return helpers.ServerError(e, nil)
	}

	return e.NoContent(200)
}
