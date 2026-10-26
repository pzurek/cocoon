package server

import (
	"net/http"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/haileyok/cocoon/internal/helpers"
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
	unlock := s.lockRepoWrite(did)
	defer unlock()
	// The pre-lock account snapshot may predate a completed deletion. A cold
	// list mutates the index, so revalidate before allowing any backfill.
	urepo, err = s.getRepoActorByDid(ctx, did)
	if err != nil {
		logger.Error("could not find user for requested blobs", "error", err)
		return helpers.InputError(e, nil)
	}
	if !urepo.Active() && e.Get("inactiveRepoRead") != urepo.Repo.Did {
		return helpers.InputError(e, to.StringPtr("RepoDeactivated"))
	}
	complete, err := s.preparePublicBlobIndex(ctx, did)
	if err != nil {
		logger.Error("error preparing blob references", "error", err)
		return helpers.ServerError(e, nil)
	}
	if !complete {
		e.Response().Header().Set("Retry-After", "1")
		return e.JSON(http.StatusServiceUnavailable, map[string]string{"error": "BlobIndexNotReady", "message": "legacy blob references are being indexed; retry this request"})
	}
	// The DID/CID covering index seeks past even an exhausted cursor; no
	// records, payloads, or earlier pages are read or decoded.
	cstrs := make([]string, 0, limit)
	if err := s.db.Raw(ctx, "SELECT DISTINCT blob_cid FROM public_blob_refs WHERE did = ? AND blob_cid > ? ORDER BY blob_cid LIMIT ?", nil, did, cursor, limit).Scan(&cstrs).Error; err != nil {
		logger.Error("error getting blob references", "error", err)
		return helpers.ServerError(e, nil)
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
