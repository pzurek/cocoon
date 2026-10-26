package server

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"gorm.io/gorm"
)

func TestBlobQuotaPayloadDeletion(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres"} {
		for _, mode := range []string{"public", "space", "account"} {
			for _, storage := range []string{"sqlite", "s3", "legacy-s3"} {
				t.Run(engine+"/"+mode+"/"+storage, func(t *testing.T) {
					s := newBlobDeletionTestServer(t, engine)
					a := s.createTestAccount(t, "quota-delete.test")
					c, record := blobRecord(t, "retained")
					b := models.Blob{Did: a.Did, Cid: c.Bytes(), Storage: storage, QuotaBackend: storage}
					if storage == "legacy-s3" {
						b.Storage, b.QuotaBackend = "s3", ""
					}
					if err := s.db.Client().Create(&b).Error; err != nil {
						t.Fatal(err)
					}
					if storage == "sqlite" {
						if err := s.db.Client().Create(&models.BlobPart{BlobID: b.ID, Data: []byte("retained")}).Error; err != nil {
							t.Fatal(err)
						}
					}
					if storage != "legacy-s3" {
						size := int64(8)
						if err := s.db.Client().Create(&models.BlobCharge{Did: a.Did, Cid: c.Bytes(), Backend: storage, Bytes: &size}).Error; err != nil {
							t.Fatal(err)
						}
					}
					switch mode {
					case "public":
						s.seedGenesisRepo(t, a.Did, a.SigningKey)
						mustApply(t, s, a.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("one"), Record: &record})
						mustApply(t, s, a.Did, Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("one")})
					case "space":
						if err := s.db.Client().Create(&models.PublicBlobIndex{Did: a.Did, Complete: true}).Error; err != nil {
							t.Fatal(err)
						}
						if err := s.db.Client().Transaction(func(tx *gorm.DB) error {
							if err := lockBlobQuota(tx); err != nil {
								return err
							}
							return s.spaceStore(tx, a.Did).gcBlobs([]string{c.String()})
						}); err != nil {
							t.Fatal(err)
						}
					case "account":
						if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", a.Did).Updates(map[string]any{"account_delete_code": "delete", "account_delete_code_expires_at": time.Now().Add(time.Hour)}).Error; err != nil {
							t.Fatal(err)
						}
						body, err := json.Marshal(ComAtprotoServerDeleteAccountRequest{Did: a.Did, Password: a.Password, Token: "delete"})
						if err != nil {
							t.Fatal(err)
						}
						e, w := newRequestContext("POST", "/xrpc/com.atproto.server.deleteAccount", string(body), nil)
						if err := s.handleServerDeleteAccount(e); err != nil || w.Code != 200 {
							t.Fatalf("delete account: %d %s %v", w.Code, w.Body.String(), err)
						}
					}
					for _, model := range []any{&models.Blob{}, &models.BlobPart{}} {
						var n int64
						if err := s.db.Client().Model(model).Count(&n).Error; err != nil || n != 0 {
							t.Fatalf("retained %T: %d %v", model, n, err)
						}
					}
					var charges []models.BlobCharge
					if err := s.db.Client().Find(&charges).Error; err != nil {
						t.Fatal(err)
					}
					if storage == "sqlite" {
						if len(charges) != 0 {
							t.Fatal("deleted SQLite payload still charged")
						}
					} else if len(charges) != 1 || (charges[0].Bytes == nil) != (storage == "legacy-s3") {
						t.Fatalf("S3 charge lost: %+v", charges)
					}
				})
			}
		}
	}
}

func TestBlobQuotaDeleteRollback(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	a := s.createTestAccount(t, "quota-rollback.test")
	uploadTestBlob(t, s, a, "rollback")
	failure := errors.New("after payload deletion")
	err := s.db.Client().Transaction(func(tx *gorm.DB) error {
		if err := lockBlobQuota(tx); err != nil {
			return err
		}
		if err := deleteBlobPayloads(tx, a.Did, nil); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	for _, model := range []any{&models.Blob{}, &models.BlobPart{}, &models.BlobCharge{}} {
		var n int64
		if err := s.db.Client().Model(model).Count(&n).Error; err != nil || n != 1 {
			t.Fatalf("rollback lost %T: %d %v", model, n, err)
		}
	}
}
