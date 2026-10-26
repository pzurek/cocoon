package server

import (
	"fmt"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoRequestEmailUpdateResponse struct {
	TokenRequired bool `json:"tokenRequired"`
}

func (s *Server) handleServerRequestEmailUpdate(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleServerRequestEmailUpdate")

	urepo := e.Get("repo").(*models.RepoActor)

	if urepo.EmailConfirmedAt != nil {
		code := fmt.Sprintf("%s-%s", helpers.RandomVarchar(5), helpers.RandomVarchar(5))
		eat := time.Now().Add(10 * time.Minute).UTC()

		// Only issue for the mailbox/state that will receive the email. A
		// concurrent change or proof consumption invalidates this snapshot.
		result := s.db.Client().WithContext(ctx).Model(&models.Repo{}).Where(map[string]any{
			"did":                          urepo.Repo.Did,
			"email":                        urepo.Email,
			"email_confirmed_at":           urepo.EmailConfirmedAt,
			"email_update_code":            urepo.EmailUpdateCode,
			"email_update_code_expires_at": urepo.EmailUpdateCodeExpiresAt,
		}).Updates(map[string]any{
			"email_update_code":            code,
			"email_update_code_expires_at": eat,
		})
		if result.Error != nil {
			logger.Error("error updating repo", "error", result.Error)
			return helpers.ServerError(e, nil)
		}
		if result.RowsAffected != 1 {
			return helpers.InputError(e, to.StringPtr("InvalidRequest"))
		}

		if err := s.sendEmailUpdate(urepo.Email, urepo.Handle, code); err != nil {
			logger.Error("error sending email", "error", err)
			return helpers.ServerError(e, nil)
		}
	}

	return e.JSON(200, ComAtprotoRequestEmailUpdateResponse{
		TokenRequired: urepo.EmailConfirmedAt != nil,
	})
}
