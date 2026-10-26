package server

import (
	"sort"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
)

type ComAtprotoSyncListBlobsResponse struct {
	Cursor *string  `json:"cursor,omitempty"`
	Cids   []string `json:"cids"`
}

func (s *Server) handleSyncListBlobs(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleSyncListBlobs")

	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	// TODO: add tid param
	cursor := e.QueryParam("cursor")
	limit, err := getLimitFromContext(e, 500)
	if err != nil || limit < 1 || limit > 1000 {
		return helpers.InputError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find user for requested blobs", "error", err)
		return helpers.InputError(e, nil)
	}

	if !urepo.Active() && e.Get("inactiveRepoRead") != urepo.Repo.Did {
		return helpers.InputError(e, to.StringPtr("RepoDeactivated"))
	}

	// Like the reference, list distinct public-record references, not uploads.
	// This excludes temporary/space-only blobs and includes referenced blobs
	// even when their payload has not yet arrived during a repository migration.
	var records []models.Record
	if err := s.db.Raw(ctx, "SELECT value FROM records WHERE did = ?", nil, did).Scan(&records).Error; err != nil {
		logger.Error("error getting records", "error", err)
		return helpers.ServerError(e, nil)
	}
	refs, err := countBlobRefs(records)
	if err != nil {
		logger.Error("error decoding blob references", "error", err)
		return helpers.ServerError(e, nil)
	}
	cstrs := make([]string, 0, len(refs))
	for c := range refs {
		if value := c.String(); value > cursor {
			cstrs = append(cstrs, value)
		}
	}
	sort.Strings(cstrs)
	if len(cstrs) > limit {
		cstrs = cstrs[:limit]
	}

	var newcursor *string
	if len(cstrs) > 0 {
		newcursor = &cstrs[len(cstrs)-1]
	}

	return e.JSON(200, ComAtprotoSyncListBlobsResponse{
		Cursor: newcursor,
		Cids:   cstrs,
	})
}
