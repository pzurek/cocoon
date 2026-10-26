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

	since := e.QueryParam("since")
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
	// Seek by DID/CID; incremental reads also consult last-write revisions,
	// never record payloads. Unknown legacy history is included conservatively.
	cstrs := make([]string, 0, limit)
	query := s.db.Client().WithContext(ctx).Table("public_blob_refs AS b").
		Select("DISTINCT b.blob_cid").Where("b.did = ? AND b.blob_cid > ?", did, cursor)
	if since != "" {
		query = query.Joins("JOIN records AS r ON r.did = b.did AND r.nsid = b.nsid AND r.rkey = b.rkey").
			Where("r.repo_rev = '' OR r.repo_rev > ?", since)
	}
	if err := query.Order("b.blob_cid").Limit(limit).Scan(&cstrs).Error; err != nil {
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
