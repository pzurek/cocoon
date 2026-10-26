package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type BlobQuotaProgress struct {
	Scanned  int
	Unknown  int64
	Complete bool
}

// BackfillBlobQuota is an explicit operator action, never an upload-side HEAD
// scan. Each invocation inventories <= batch rows and probes <= batch unknown
// payloads, sequentially, with no SDK retries and a five-second request deadline.
// Run with the original S3 configuration for legacy metadata. It does not list
// the bucket or discover already-orphaned objects, versions, or extra copies.
func BackfillBlobQuota(ctx context.Context, database *gorm.DB, storage *S3Config, batch int) (BlobQuotaProgress, error) {
	var progress BlobQuotaProgress
	if batch < 1 || batch > 100 {
		return progress, errors.New("blob quota batch must be between 1 and 100")
	}
	database = database.WithContext(ctx)
	if err := database.AutoMigrate(&models.Blob{}, &models.BlobPart{}, &models.BlobCharge{}, &models.BlobQuotaState{}); err != nil {
		return progress, err
	}
	if err := initBlobQuota(database); err != nil {
		return progress, err
	}
	err := database.Transaction(func(tx *gorm.DB) error {
		if err := lockBlobQuota(tx); err != nil {
			return err
		}
		var state models.BlobQuotaState
		if err := tx.First(&state, 1).Error; err != nil {
			return err
		}
		if state.Complete {
			return nil
		}
		var blobs []models.Blob
		if err := tx.Where("id > ?", state.LastID).Order("id").Limit(batch + 1).Find(&blobs).Error; err != nil {
			return err
		}
		state.Complete = len(blobs) <= batch
		if len(blobs) > batch {
			blobs = blobs[:batch]
		}
		for _, blob := range blobs {
			charge := models.BlobCharge{Did: blob.Did, Cid: blob.Cid, Backend: blobChargeBackend(blob)}
			if blob.Storage != "s3" {
				// Logical unique payload bytes, not duplicate legacy physical copies.
				// Reads choose the first row; use that row consistently for duplicates.
				var first models.Blob
				if err := tx.Where("did = ? AND cid = ? AND storage <> 's3'", blob.Did, blob.Cid).Order("id").First(&first).Error; err != nil {
					return err
				}
				var size int64
				if err := tx.Raw("SELECT COALESCE(SUM(length(data)), 0) FROM blob_parts WHERE blob_id = ?", first.ID).Scan(&size).Error; err != nil {
					return err
				}
				charge.Bytes = &size
			}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&charge).Error; err != nil {
				return err
			}
			state.LastID = blob.ID
			progress.Scanned++
		}
		return tx.Save(&state).Error
	})
	if err != nil {
		return progress, err
	}
	var unknown []models.BlobCharge
	if err := database.Where("bytes IS NULL OR backend = 's3:legacy'").Order("checked_at, did, cid, backend").Limit(batch).Find(&unknown).Error; err != nil {
		return progress, err
	}
	s := &Server{s3Config: storage}
	for _, charge := range unknown {
		if err := ctx.Err(); err != nil {
			return progress, err
		}
		size, probeErr := s.probeBlobCharge(ctx, charge)
		if err := database.Transaction(func(tx *gorm.DB) error {
			if err := lockBlobQuota(tx); err != nil {
				return err
			}
			if probeErr == nil && charge.Backend == "s3:legacy" {
				// Bind legacy accounting to the operator-supplied original bucket.
				// Otherwise GC followed by reupload would charge the same retained
				// payload again under the new, explicit namespace identifier.
				var current models.BlobCharge
				r := chargeQuery(tx, charge).Find(&current)
				if r.Error != nil {
					return r.Error
				}
				if r.RowsAffected == 0 {
					return nil
				}
				if current.Bytes != nil {
					size = *current.Bytes
				}
				target := current
				target.Backend, target.Bytes = s.uploadBlobBackend(), &size
				if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&target).Error; err != nil {
					return err
				}
				if err := s.admitBlobCharge(tx, target); err != nil {
					return err
				}
				if err := chargeQuery(tx, charge).Delete(&models.BlobCharge{}).Error; err != nil {
					return err
				}
				return tx.Model(&models.Blob{}).Where("did = ? AND cid = ? AND storage = 's3' AND (quota_backend = '' OR quota_backend IS NULL OR quota_backend = 's3:legacy')", charge.Did, charge.Cid).Update("quota_backend", target.Backend).Error
			}
			updates := map[string]any{"checked_at": time.Now().UnixNano()}
			if probeErr == nil {
				updates["bytes"] = size
			}
			// Never overwrite a measured upload or recreate a deleted charge.
			return chargeQuery(tx.Model(&models.BlobCharge{}), charge).Where("bytes IS NULL OR backend = 's3:legacy'").Updates(updates).Error
		}); err != nil {
			return progress, err
		}
	}
	var state models.BlobQuotaState
	if err := database.First(&state, 1).Error; err != nil {
		return progress, err
	}
	if err := database.Model(&models.BlobCharge{}).Where("bytes IS NULL OR backend = 's3:legacy'").Count(&progress.Unknown).Error; err != nil {
		return progress, err
	}
	progress.Complete = state.Complete && progress.Unknown == 0
	return progress, nil
}

func (s *Server) probeBlobCharge(ctx context.Context, charge models.BlobCharge) (int64, error) {
	if s.s3Config == nil || !s.s3Config.BlobstoreEnabled || (charge.Backend != "s3:legacy" && charge.Backend != s.uploadBlobBackend()) {
		return 0, errors.New("unknown blob storage configuration")
	}
	if charge.Bytes != nil {
		return *charge.Bytes, nil
	}
	c, err := cid.Cast(charge.Cid)
	if err != nil {
		return 0, err
	}
	svc, err := s.s3Client()
	if err != nil {
		return 0, err
	}
	svc.Config.MaxRetries = aws.Int(0)
	key := s3BlobKey(charge.Did, c)
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	out, err := svc.HeadObjectWithContext(probe, &s3.HeadObjectInput{Bucket: aws.String(s.s3Config.Bucket), Key: aws.String(key)})
	cancel()
	if err == nil {
		if out.ContentLength == nil || *out.ContentLength < 0 {
			return 0, errors.New("unknown object length")
		}
		return *out.ContentLength, nil
	}
	var failure awserr.RequestFailure
	if !isS3NoSuchKey(err) && !(errors.As(err, &failure) && failure.StatusCode() == 404) {
		return 0, err
	}
	probe, cancel = context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, err := svc.ListObjectsV2WithContext(probe, &s3.ListObjectsV2Input{Bucket: aws.String(s.s3Config.Bucket), Prefix: aws.String(key + "/"), MaxKeys: aws.Int64(1)})
	if err != nil {
		return 0, err
	}
	if len(list.Contents) != 1 || list.Contents[0].Size == nil || *list.Contents[0].Size < 0 {
		return 0, fmt.Errorf("legacy object size unavailable")
	}
	return *list.Contents[0].Size, nil
}
