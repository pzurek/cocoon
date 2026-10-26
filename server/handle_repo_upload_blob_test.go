package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"testing/iotest"

	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
	"gorm.io/gorm"
)

func TestUploadBlobBoundsAndAtomicity(t *testing.T) {
	const limit = 2*blockSize + 17
	for _, tc := range []struct {
		name                               string
		size                               int
		knownLength, interrupted, failPart bool
		want                               int
	}{
		{name: "empty", want: 200},
		{name: "at limit", size: limit, want: 200},
		{name: "below limit", size: limit - 1, want: 200},
		{name: "above limit unknown length", size: limit + 1, want: 400},
		{name: "above limit known length", size: limit + 1, knownLength: true, want: 400},
		{name: "interrupted after chunk", size: blockSize, interrupted: true, want: 500},
		{name: "second chunk persistence failure", size: limit, failPart: true, want: 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			s.repoman = NewRepoMan(s)
			s.config.BlobUploadLimit = limit
			acct := s.createTestAccount(t, "upload.pds.test")
			temp := t.TempDir()
			t.Setenv("TMPDIR", temp)
			payload := make([]byte, tc.size)
			for i := range payload {
				payload[i] = byte(i*31 + i/blockSize)
			}
			var body io.Reader = bytes.NewReader(payload)
			if tc.interrupted {
				body = io.MultiReader(body, iotest.ErrReader(errors.New("interrupted upload")))
			}
			if tc.failPart {
				if err := s.db.Exec(t.Context(), "CREATE TRIGGER fail_blob_part BEFORE INSERT ON blob_parts WHEN NEW.idx = 1 BEGIN SELECT RAISE(ABORT, 'test insertion failure'); END", nil).Error; err != nil {
					t.Fatal(err)
				}
			}
			c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "", nil)
			c.Set("repo", mustRepoActor(t, s, acct.Did))
			c.Request().Body = io.NopCloser(body)
			c.Request().ContentLength = -1
			if tc.knownLength {
				c.Request().ContentLength = int64(tc.size)
			}
			if err := s.handleRepoUploadBlob(c); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.want {
				t.Errorf("status=%d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			var blobs []models.Blob
			var parts []models.BlobPart
			if err := s.db.Client().Find(&blobs).Error; err != nil {
				t.Fatal(err)
			}
			if err := s.db.Client().Order("idx").Find(&parts).Error; err != nil {
				t.Fatal(err)
			}
			if tc.want != 200 {
				if len(blobs) != 0 || len(parts) != 0 {
					t.Errorf("failed upload retained %d blobs and %d parts", len(blobs), len(parts))
				}
			} else {
				wantCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
				if err != nil {
					t.Fatal(err)
				}
				var response ComAtprotoRepoUploadBlobResponse
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response.Blob.Size != tc.size || response.Blob.Ref.Link != wantCID.String() || len(blobs) != 1 || !bytes.Equal(blobs[0].Cid, wantCID.Bytes()) {
					t.Fatal("incorrect persisted or returned blob metadata")
				}
				var stored []byte
				for _, part := range parts {
					stored = append(stored, part.Data...)
				}
				if !bytes.Equal(stored, payload) {
					t.Fatal("stored payload differs")
				}
			}
			files, err := os.ReadDir(temp)
			if err != nil || len(files) != 0 {
				t.Fatalf("upload left temporary files: %v, %v", files, err)
			}
		})
	}
}

func TestUploadBlobS3FailureCleanup(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		oversize, failPut, failDB, prior, cancel bool
		uncertainCommit                          bool
		want                                     int
	}{
		{name: "success", want: 200},
		{name: "oversized", oversize: true, want: 400},
		{name: "failed put after storing object", failPut: true, want: 500},
		{name: "failed database insert", failDB: true, want: 500},
		{name: "failed repeat preserves prior object", failDB: true, prior: true, want: 500},
		{name: "canceled after storing object", cancel: true, want: 500},
		{name: "commit acknowledgment lost", uncertainCommit: true, want: 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			s.repoman = NewRepoMan(s)
			acct := s.createTestAccount(t, "s3upload.pds.test")
			payload := bytes.Repeat([]byte("s3 payload"), 8193)
			wantCID, err := cid.NewPrefixV1(cid.Raw, multihash.SHA2_256).Sum(payload)
			if err != nil {
				t.Fatal(err)
			}
			s.config.BlobUploadLimit = int64(len(payload))
			if tc.oversize {
				s.config.BlobUploadLimit--
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var mu sync.Mutex
			var stored []byte
			requests := 0
			if tc.prior {
				stored = bytes.Clone(payload)
				blob := models.Blob{Did: acct.Did, Cid: wantCID.Bytes(), Storage: "s3"}
				if err := s.db.Client().Create(&blob).Error; err != nil {
					t.Fatal(err)
				}
			}
			if tc.failDB {
				if err := s.db.Exec(t.Context(), "CREATE TRIGGER fail_blob BEFORE INSERT ON blobs BEGIN SELECT RAISE(ABORT, 'test insertion failure'); END", nil).Error; err != nil {
					t.Fatal(err)
				}
			}
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				requests++
				if r.URL.Path != "/uploads/"+s3BlobKey(acct.Did, wantCID) {
					t.Errorf("unexpected S3 path: %s", r.URL.Path)
					w.WriteHeader(400)
					return
				}
				switch r.Method {
				case http.MethodPut:
					data, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					stored = data
					if tc.cancel {
						cancel()
					}
					if tc.failPut {
						w.WriteHeader(http.StatusForbidden)
						_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code></Error>`)
					}
				case http.MethodDelete:
					stored = nil
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected S3 method: %s", r.Method)
					w.WriteHeader(400)
				}
			}))
			defer endpoint.Close()
			s.s3Config = &S3Config{BlobstoreEnabled: true, Bucket: "uploads", Region: "us-east-1", Endpoint: endpoint.URL, AccessKey: "test", SecretKey: "test"}
			c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "", nil)
			c.Set("repo", mustRepoActor(t, s, acct.Did))
			c.SetRequest(c.Request().WithContext(ctx))
			c.Request().Body = io.NopCloser(bytes.NewReader(payload))
			c.Request().ContentLength = -1
			if tc.uncertainCommit {
				// Target blob publication's COMMIT, not the separate one-time
				// legacy-index transaction that precedes any S3 publication.
				if complete, err := s.preparePublicBlobIndex(ctx, acct.Did); err != nil || !complete {
					t.Fatalf("prepare public blob index: complete=%v err=%v", complete, err)
				}
				sqlDB, err := s.db.Client().DB()
				if err != nil {
					t.Fatal(err)
				}
				s.db.Client().Statement.ConnPool = commitErrorPool{sqlDB}
			}
			if err := s.handleRepoUploadBlob(c); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.want {
				t.Fatalf("status=%d, want %d: %s", w.Code, tc.want, w.Body.String())
			}
			var blobs []models.Blob
			if err := s.db.Client().Find(&blobs).Error; err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if tc.want == 200 || tc.prior || tc.uncertainCommit {
				if !bytes.Equal(stored, payload) || len(blobs) != 1 || blobs[0].Storage != "s3" || !bytes.Equal(blobs[0].Cid, wantCID.Bytes()) {
					t.Fatal("expected intact S3 object and matching metadata")
				}
			} else if len(stored) != 0 || len(blobs) != 0 {
				t.Fatalf("failed upload retained %d object bytes and %d rows", len(stored), len(blobs))
			}
			if tc.oversize && requests != 0 {
				t.Fatalf("oversized upload reached S3: %d requests", requests)
			}
		})
	}
}

// Model a database that commits successfully but loses the acknowledgment.
// The handler must not infer a rollback from the returned error.
type commitErrorPool struct{ *sql.DB }

func (p commitErrorPool) BeginTx(ctx context.Context, opts *sql.TxOptions) (gorm.ConnPool, error) {
	tx, err := p.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &commitErrorTx{tx}, nil
}

type commitErrorTx struct{ *sql.Tx }

func (tx commitErrorTx) Commit() error {
	if err := tx.Tx.Commit(); err != nil {
		return err
	}
	return errors.New("commit acknowledgment lost")
}

func TestUploadBlobDefaultLimit(t *testing.T) {
	s := newTestServer(t)
	acct := s.createTestAccount(t, "default-upload.pds.test")
	c, w := newRequestContext(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "", nil)
	c.Set("repo", mustRepoActor(t, s, acct.Did))
	c.Request().Body = io.NopCloser(bytes.NewReader(make([]byte, 5*1024*1024+1)))
	c.Request().ContentLength = -1
	if err := s.handleRepoUploadBlob(c); err != nil {
		t.Fatal(err)
	}
	if w.Code != 400 {
		t.Fatalf("status=%d, want 400: %s", w.Code, w.Body.String())
	}
	var response struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Error != "BlobTooLarge" {
		t.Fatalf("expected BlobTooLarge: %s, %v", w.Body.String(), err)
	}
}
