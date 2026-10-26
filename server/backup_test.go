package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/haileyok/cocoon/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestBackupRestore(t *testing.T) {
	for _, mode := range []string{"local", "local-and-s3", "s3-failure"} {
		t.Run(mode, func(t *testing.T) {
			t.Chdir(t.TempDir())
			s := newTestServer(t)
			account := s.createTestAccount(t, "restore.pds.test")
			root, rev := s.seedGenesisRepo(t, account.Did, account.SigningKey)
			payload := []byte("durable asymmetric blob bytes 01234")
			blob := models.Blob{Did: account.Did, Cid: []byte("backup-test"), Storage: "sqlite", RefCount: 1}
			if err := s.db.Client().Create(&blob).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Create(&models.BlobPart{BlobID: blob.ID, Data: payload}).Error; err != nil {
				t.Fatal(err)
			}
			s.config.BackupDir = t.TempDir()
			uploaded := filepath.Join(t.TempDir(), "uploaded.db")
			attempted := make(chan struct{}, 1)
			marker := filepath.Join(s.config.BackupDir, "last-backup.txt")
			const previous = "2020-01-01T00:00:00Z"
			if mode == "s3-failure" {
				if err := os.WriteFile(marker, []byte(previous), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "local" {
				endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					select {
					case attempted <- struct{}{}:
					default:
					}
					if mode == "s3-failure" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					file, err := os.Create(uploaded)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					_, err = io.Copy(file, r.Body)
					closeErr := file.Close()
					if err != nil || closeErr != nil {
						t.Errorf("capture backup: %v %v", err, closeErr)
						w.WriteHeader(500)
					}
				}))
				defer endpoint.Close()
				s.s3Config = &S3Config{BackupsEnabled: true, Endpoint: endpoint.URL, Region: "test", Bucket: "test", AccessKey: "test", SecretKey: "test"}
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			if mode == "local" {
				go func() { s.backupRoutine(ctx); close(done) }()
			} else {
				// Observe a completed upload/failure, not cancellation racing it.
				s.doBackup(ctx)
				close(done)
			}
			defer func() { cancel(); <-done }()
			var paths []string
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				paths, _ = filepath.Glob(filepath.Join(s.config.BackupDir, "*.db"))
				if len(paths) == 1 {
					if mode == "s3-failure" && len(attempted) > 0 {
						break
					}
					if _, err := os.Stat(marker); err == nil {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if len(paths) != 1 {
				t.Fatalf("local-only scheduling must publish one snapshot: %v", paths)
			}
			cancel()
			<-done
			// A closed channel can be received again by the deferred cleanup.
			if info, err := os.Stat(paths[0]); err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("snapshot permissions: %v %v", info, err)
			}
			if mode == "local-and-s3" {
				paths = append(paths, uploaded)
			}
			if mode != "local" && len(attempted) == 0 {
				t.Fatal("backup did not attempt S3 upload")
			}
			if temporary, err := filepath.Glob(filepath.Join(s.config.BackupDir, ".cocoon-backup-*.tmp")); err != nil || len(temporary) != 0 {
				t.Fatalf("backup left temporary files: %v %v", temporary, err)
			}
			for _, path := range paths {
				restored, err := gorm.Open(sqlite.Open(path+"?mode=ro"), &gorm.Config{})
				if err != nil {
					t.Fatal(err)
				}
				pool, err := restored.DB()
				if err != nil {
					t.Fatal(err)
				}
				defer pool.Close()
				var integrity string
				if err := restored.Raw("PRAGMA integrity_check").Scan(&integrity).Error; err != nil || integrity != "ok" {
					t.Fatalf("restore integrity: %s %v", integrity, err)
				}
				var repo models.Repo
				if err := restored.Where("did = ?", account.Did).Take(&repo).Error; err != nil || !bytes.Equal(repo.SigningKey, account.SigningKey) {
					t.Fatalf("restore lost account key: %v", err)
				}
				if !bytes.Equal(repo.Root, root.Bytes()) || repo.Rev != rev {
					t.Fatal("restore changed repository head")
				}
				var block models.Block
				if err := restored.Where("did = ? AND cid = ?", account.Did, root.Bytes()).Take(&block).Error; err != nil {
					t.Fatalf("restore lost root block: %v", err)
				}
				got, err := root.Prefix().Sum(block.Value)
				if err != nil || got != root {
					t.Fatalf("restored root content mismatch: %v", err)
				}
				var part models.BlobPart
				if err := restored.Where("blob_id = ?", blob.ID).Take(&part).Error; err != nil || !bytes.Equal(part.Data, payload) {
					t.Fatalf("restore lost payload: %v", err)
				}
			}
			completion, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "s3-failure" {
				if string(completion) != previous {
					t.Fatalf("failed upload changed prior success marker: %s", completion)
				}
			} else if stamp, err := time.Parse(time.RFC3339Nano, string(completion)); err != nil || time.Since(stamp) > time.Minute {
				t.Fatalf("backup did not record successful completion: %s %v", completion, err)
			}
		})
	}
}
