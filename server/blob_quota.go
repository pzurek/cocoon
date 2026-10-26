package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	DefaultBlobAccountQuotaBytes int64 = 5 << 30
	DefaultBlobServerQuotaBytes  int64 = 100 << 30
)

var (
	errBlobAccountQuota  = errors.New("BlobQuotaExceeded")
	errBlobServerQuota   = errors.New("BlobStorageFull")
	errBlobQuotaNotReady = errors.New("BlobQuotaNotReady")
)

// Lock order: process repository lock (when used), then this database gate,
// then payload/record rows. Call at the START of the outer transaction, before
// reads or writes, not just inside a nested GC savepoint. No S3 I/O under it.
// The database gate, unlike lockRepoWrite, serializes independent processes.
func lockBlobQuota(tx *gorm.DB) error {
	query := "UPDATE blob_charges SET backend = backend WHERE 1 = 0"
	if tx.Dialector.Name() == "postgres" {
		query = "LOCK TABLE blob_charges IN EXCLUSIVE MODE"
	}
	return tx.Exec(query).Error
}

func initBlobQuota(database *gorm.DB) error {
	return database.Transaction(func(tx *gorm.DB) error {
		if err := lockBlobQuota(tx); err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&models.Blob{}).Count(&count).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.BlobQuotaState{ID: 1, Complete: count == 0}).Error
	})
}

func blobChargeBackend(blob models.Blob) string {
	if blob.QuotaBackend != "" {
		return blob.QuotaBackend
	}
	if blob.Storage == "s3" {
		return "s3:legacy"
	}
	return "sqlite"
}

func (s *Server) uploadBlobBackend() string {
	if s.s3Config == nil || !s.s3Config.BlobstoreEnabled {
		return "sqlite"
	}
	// Credentials and CDN URLs are not storage identity. A different bucket or
	// endpoint is a separately retained copy, not a free reuse of an old charge.
	id := fmt.Sprintf("%s\n%s\n%s", s.s3Config.Endpoint, s.s3Config.Region, s.s3Config.Bucket)
	return fmt.Sprintf("s3:%x", sha256.Sum256([]byte(id)))
}

func chargeQuery(tx *gorm.DB, c models.BlobCharge) *gorm.DB {
	return tx.Where("did = ? AND cid = ? AND backend = ?", c.Did, c.Cid, c.Backend)
}

// admitBlobUpload rechecks the account under the database gate, so a request
// authenticated before account deletion cannot recreate its payload metadata.
func (s *Server) admitBlobUpload(tx *gorm.DB, blob models.Blob, size int64) (bool, error) {
	var repo models.Repo
	if err := tx.Where("did = ?", blob.Did).First(&repo).Error; err != nil {
		return false, err
	}
	if repo.TakenDown() {
		return false, errors.New("account taken down")
	}
	var existing models.Blob
	r := tx.Where("did = ? AND cid = ? AND storage = ? AND (quota_backend = ? OR quota_backend = '' OR quota_backend IS NULL)", blob.Did, blob.Cid, blob.Storage, blob.QuotaBackend).
		Order("CASE WHEN quota_backend = '' OR quota_backend IS NULL THEN 1 ELSE 0 END, id").Limit(1).Find(&existing)
	if r.Error != nil {
		return false, r.Error
	}
	c := models.BlobCharge{Did: blob.Did, Cid: blob.Cid, Backend: blob.QuotaBackend, Bytes: &size}
	if r.RowsAffected != 0 {
		// Unbound legacy S3 metadata cannot prove that this namespace has the
		// object. Require backfill with the original configuration before reuse.
		if blob.Storage == "s3" && existing.QuotaBackend != blob.QuotaBackend {
			return false, errBlobQuotaNotReady
		}
		c.Backend = blobChargeBackend(existing)
		// Grandfather an existing payload, not a new write: measured bytes can
		// establish its missing charge even during legacy accounting.
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&c).Error; err != nil {
			return false, err
		}
		return true, s.admitBlobCharge(tx, c)
	}
	return false, s.admitBlobCharge(tx, c)
}

// admitBlobCharge requires the gate. A charge is a logical payload, not a
// bound on physical database pages, object versions, temp files or backups.
func (s *Server) admitBlobCharge(tx *gorm.DB, c models.BlobCharge) error {
	if c.Bytes == nil || *c.Bytes < 0 {
		return errors.New("invalid blob charge size")
	}
	var prior models.BlobCharge
	r := chargeQuery(tx, c).Find(&prior)
	if r.Error != nil {
		return r.Error
	}
	if r.RowsAffected != 0 {
		if prior.Bytes != nil && *prior.Bytes != *c.Bytes {
			return errors.New("blob charge size mismatch")
		}
		// A measured retry can resolve one unknown legacy payload, even when
		// positive growth is blocked. It does not admit a new storage identity.
		return chargeQuery(tx.Model(&models.BlobCharge{}), c).Update("bytes", *c.Bytes).Error
	}
	var state models.BlobQuotaState
	if err := tx.First(&state, 1).Error; err != nil {
		return err
	}
	if !state.Complete {
		return errBlobQuotaNotReady
	}
	var totals struct{ Total, Account, Unknown int64 }
	if err := tx.Raw(`SELECT COALESCE(SUM(bytes), 0) AS total,
		COALESCE(SUM(CASE WHEN did = ? THEN bytes ELSE 0 END), 0) AS account,
		COALESCE(SUM(CASE WHEN bytes IS NULL OR bytes < 0 THEN 1 ELSE 0 END), 0) AS unknown
		FROM blob_charges`, c.Did).Scan(&totals).Error; err != nil {
		return err
	}
	if totals.Unknown != 0 {
		return errBlobQuotaNotReady
	}
	account, server := s.config.BlobAccountQuotaBytes, s.config.BlobServerQuotaBytes
	if account == 0 {
		account = DefaultBlobAccountQuotaBytes
	}
	if server == 0 {
		server = DefaultBlobServerQuotaBytes
	}
	if account < 0 || server < 0 || totals.Total < 0 || totals.Account < 0 {
		return errors.New("invalid blob quota")
	}
	// Subtraction after the used > limit check avoids signed addition overflow.
	if totals.Account > account || *c.Bytes > account-totals.Account {
		return errBlobAccountQuota
	}
	if totals.Total > server || *c.Bytes > server-totals.Total {
		return errBlobServerQuota
	}
	return tx.Create(&c).Error
}

func blobQuotaError(e echo.Context, err error) error {
	status := http.StatusInternalServerError
	code := "InternalServerError"
	switch {
	case errors.Is(err, errBlobAccountQuota):
		status, code = http.StatusBadRequest, errBlobAccountQuota.Error()
	case errors.Is(err, errBlobServerQuota):
		status, code = http.StatusServiceUnavailable, errBlobServerQuota.Error()
	case errors.Is(err, errBlobQuotaNotReady):
		status, code = http.StatusServiceUnavailable, errBlobQuotaNotReady.Error()
	}
	return e.JSON(status, map[string]string{"error": code})
}

// deleteBlobPayloads runs within the caller's gated transaction. nil CID means
// account deletion; otherwise only unused rows of that CID are eligible.
func deleteBlobPayloads(tx *gorm.DB, did string, cid []byte) error {
	where := "did = ?"
	args := []any{did}
	if cid != nil {
		where += " AND cid = ? AND ref_count <= 0"
		args = append(args, cid)
	}
	// Seed unknown S3 charges before deleting legacy metadata, even if the
	// backfill has not reached these rows. Never credit retained S3 objects.
	query := `INSERT INTO blob_charges (did, cid, backend, bytes)
		SELECT did, cid, CASE WHEN quota_backend = '' OR quota_backend IS NULL THEN 's3:legacy' ELSE quota_backend END, NULL
		FROM blobs WHERE ` + where + ` AND storage = 's3' GROUP BY did, cid, quota_backend
		ON CONFLICT (did, cid, backend) DO NOTHING`
	if err := tx.Exec(query, args...).Error; err != nil {
		return err
	}
	if err := tx.Exec("DELETE FROM blob_parts WHERE blob_id IN (SELECT id FROM blobs WHERE "+where+")", args...).Error; err != nil {
		return err
	}
	if err := tx.Exec("DELETE FROM blobs WHERE "+where, args...).Error; err != nil {
		return err
	}
	return tx.Exec(`DELETE FROM blob_charges WHERE did = ? AND backend = 'sqlite'
		AND NOT EXISTS (SELECT 1 FROM blobs WHERE blobs.did = blob_charges.did AND blobs.cid = blob_charges.cid AND storage <> 's3')`, did).Error
}
