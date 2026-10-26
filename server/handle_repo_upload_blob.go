package server

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"github.com/multiformats/go-multihash"
	"gorm.io/gorm"
)

const (
	blockSize                    = 0x10000
	DefaultBlobUploadLimit int64 = 5 * 1024 * 1024
)

type ComAtprotoRepoUploadBlobResponse struct {
	Blob struct {
		Type string `json:"$type"`
		Ref  struct {
			Link string `json:"$link"`
		} `json:"ref"`
		MimeType string `json:"mimeType"`
		Size     int    `json:"size"`
	} `json:"blob"`
}

func (s *Server) handleRepoUploadBlob(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleRepoUploadBlob")

	urepo := e.Get("repo").(*models.RepoActor)
	if urepo.Repo.TakenDown() {
		return helpers.InputError(e, to.StringPtr("AccountTakedown"))
	}

	mime := e.Request().Header.Get("content-type")
	if mime == "" {
		mime = "application/octet-stream"
	}

	limit := s.config.BlobUploadLimit
	if limit == 0 {
		limit = DefaultBlobUploadLimit
	}
	if e.Request().ContentLength > limit {
		return helpers.InputError(e, to.StringPtr("BlobTooLarge"))
	}
	// Spool and hash with bounded memory before creating any persistent rows.
	// The same seekable file supports S3 signing/retries without a RAM copy.
	file, err := os.CreateTemp("", "cocoon-upload-*")
	if err != nil {
		logger.Error("error creating upload file", "error", err)
		return helpers.ServerError(e, nil)
	}
	defer os.Remove(file.Name())
	defer file.Close()
	hash := sha256.New()
	body := http.MaxBytesReader(e.Response(), e.Request().Body, limit)
	defer body.Close()
	read, err := io.Copy(io.MultiWriter(file, hash), body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return helpers.InputError(e, to.StringPtr("BlobTooLarge"))
		}
		logger.Error("error reading blob", "error", err)
		return helpers.ServerError(e, nil)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		logger.Error("error rewinding upload", "error", err)
		return helpers.ServerError(e, nil)
	}
	digest, err := multihash.Encode(hash.Sum(nil), multihash.SHA2_256)
	if err != nil {
		logger.Error("error encoding blob digest", "error", err)
		return helpers.ServerError(e, nil)
	}
	c := cid.NewCidV1(cid.Raw, digest)

	unlock := s.lockRepoWrite(urepo.Repo.Did)
	defer unlock()
	// Authentication and spooling precede this lock. Deletion may have
	// committed meanwhile; never recreate index or payload rows for it.
	urepo, err = s.getRepoActorByDid(ctx, urepo.Repo.Did)
	if err != nil {
		logger.Error("could not find upload account", "error", err)
		return helpers.InputError(e, nil)
	}
	if urepo.Repo.TakenDown() {
		return helpers.InputError(e, to.StringPtr("AccountTakedown"))
	}
	complete, err := s.preparePublicBlobIndex(ctx, urepo.Repo.Did)
	if err != nil {
		logger.Error("error preparing blob references", "error", err)
		return helpers.ServerError(e, nil)
	}
	if !complete {
		e.Response().Header().Set("Retry-After", "1")
		return e.JSON(http.StatusServiceUnavailable, map[string]string{"error": "BlobIndexNotReady", "message": "legacy blob references are being indexed; retry this request"})
	}
	blob := models.Blob{Did: urepo.Repo.Did, Cid: c.Bytes(), CreatedAt: s.repoman.clock.Next().String(), Storage: "sqlite", QuotaBackend: s.uploadBlobBackend()}
	s3Upload := s.s3Config != nil && s.s3Config.BlobstoreEnabled
	if s3Upload {
		blob.Storage = "s3"
		var reused bool
		// Persist the charge before any network write. A failed COMMIT may
		// have committed: return without PUT, and let a retry reuse the charge.
		if err := s.db.Client().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := lockBlobQuota(tx); err != nil {
				return err
			}
			var err error
			reused, err = s.admitBlobUpload(tx, blob, read)
			return err
		}); err != nil {
			logger.Error("error reserving blob quota", "error", err)
			return blobQuotaError(e, err)
		}
		if !reused {
			svc, err := s.s3Client()
			if err != nil {
				return helpers.ServerError(e, nil)
			}
			// No failure cleanup/refund: an ambiguous PUT or metadata COMMIT
			// can coexist with a successful publication by another process.
			// Retaining both object and charge is conservative and retryable.
			if _, err := svc.PutObjectWithContext(ctx, &s3.PutObjectInput{Bucket: aws.String(s.s3Config.Bucket), Key: aws.String(s3BlobKey(blob.Did, c)), Body: file}); err != nil {
				logger.Error("error uploading blob to s3", "error", err)
				return helpers.ServerError(e, nil)
			}
		}
	}
	if err := s.db.Transaction(ctx, func(tx *db.DB) error {
		if err := lockBlobQuota(tx.Client()); err != nil {
			return err
		}
		reused, err := s.admitBlobUpload(tx.Client(), blob, read)
		if err != nil {
			return err
		}
		if reused {
			return nil
		}
		var refs int64
		if err := tx.Raw(ctx, "SELECT COUNT(*) FROM public_blob_refs WHERE did = ? AND blob_cid = ?", nil, blob.Did, c.String()).Scan(&refs).Error; err != nil {
			return err
		}
		blob.RefCount = int(refs)
		if err := tx.Create(ctx, &blob, nil).Error; err != nil {
			return err
		}
		if s3Upload {
			return nil
		}
		buf := make([]byte, blockSize)
		for part := 0; ; part++ {
			n, err := io.ReadFull(file, buf)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return err
			}
			if n > 0 {
				if err := tx.Create(ctx, &models.BlobPart{BlobID: blob.ID, Idx: part, Data: buf[:n]}, nil).Error; err != nil {
					return err
				}
			}
			if err != nil {
				return nil
			}
		}
	}); err != nil {
		logger.Error("error persisting blob", "error", err)
		return blobQuotaError(e, err)
	}

	resp := ComAtprotoRepoUploadBlobResponse{}
	resp.Blob.Type = "blob"
	resp.Blob.Ref.Link = c.String()
	resp.Blob.MimeType = mime
	resp.Blob.Size = int(read)

	return e.JSON(200, resp)
}
