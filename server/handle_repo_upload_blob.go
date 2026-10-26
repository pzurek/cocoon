package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/internal/db"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/labstack/echo/v4"
	"github.com/multiformats/go-multihash"
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
	var records []models.Record
	if err := s.db.Client().WithContext(ctx).Select("value").Where("did = ?", urepo.Repo.Did).Find(&records).Error; err != nil {
		logger.Error("error reading blob references", "error", err)
		return helpers.ServerError(e, nil)
	}
	refs, err := countBlobRefs(records)
	if err != nil {
		logger.Error("error decoding blob references", "error", err)
		return helpers.ServerError(e, nil)
	}
	blob := models.Blob{Did: urepo.Repo.Did, Cid: c.Bytes(), RefCount: refs[c], CreatedAt: s.repoman.clock.Next().String(), Storage: "sqlite"}
	s3Upload := s.s3Config != nil && s.s3Config.BlobstoreEnabled
	commitPossible := false
	if s3Upload {
		blob.Storage = "s3"
		svc, err := s.s3Client()
		if err != nil {
			return helpers.ServerError(e, nil)
		}
		var existing int64
		if err := s.db.Client().WithContext(ctx).Model(&models.Blob{}).Where("did = ? AND cid = ? AND storage = ?", blob.Did, blob.Cid, "s3").Count(&existing).Error; err != nil {
			return helpers.ServerError(e, nil)
		}
		key := s3BlobKey(blob.Did, c)
		// The repository lock serializes same-CID publication and cleanup.
		// Never remove an object backing an earlier successful upload.
		if existing == 0 {
			defer func() {
				if commitPossible {
					return
				}
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				if _, err := svc.DeleteObjectWithContext(cleanup, &s3.DeleteObjectInput{Bucket: aws.String(s.s3Config.Bucket), Key: aws.String(key)}); err != nil {
					logger.Error("error removing failed S3 upload", "key", key, "error", err)
				}
			}()
		}
		if _, err := svc.PutObjectWithContext(ctx, &s3.PutObjectInput{Bucket: aws.String(s.s3Config.Bucket), Key: aws.String(key), Body: file}); err != nil {
			logger.Error("error uploading blob to s3", "error", err)
			return helpers.ServerError(e, nil)
		}
	}
	if err := s.db.Transaction(ctx, func(tx *db.DB) error {
		if err := tx.Create(ctx, &blob, nil).Error; err != nil {
			return err
		}
		if s3Upload {
			// A COMMIT error may mean only its acknowledgment was lost.
			// Retain the object once commit is possible, even on error.
			commitPossible = true
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
		return helpers.ServerError(e, nil)
	}

	resp := ComAtprotoRepoUploadBlobResponse{}
	resp.Blob.Type = "blob"
	resp.Blob.Ref.Link = c.String()
	resp.Blob.MimeType = mime
	resp.Blob.Size = int(read)

	return e.JSON(200, resp)
}
