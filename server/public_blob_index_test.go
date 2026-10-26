package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atdata"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	"gorm.io/gorm"
)

func TestPublicBlobIndexWarmReads(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "indexed-public.pds.test")
	c, rec := blobRecord(t, "indexed public payload")
	raw, err := atdata.MarshalCBOR(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := indexRecords(context.Background(), s.db, account.Did, []models.Record{{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: "one", Cid: c.String(), Value: raw}}); err != nil {
		t.Fatal(err)
	}
	// Poison stored CBOR after indexing: warm listing/upload must never decode
	// it again. This is a scan detector, not a supported out-of-band mutation.
	if err := s.db.Client().Model(&models.Record{}).Where("did = ?", account.Did).Update("value", []byte{0xff}).Error; err != nil {
		t.Fatal(err)
	}
	for _, cursor := range []string{"", "zzzz"} {
		e, w := newRequestContext("GET", fmt.Sprintf("/xrpc/com.atproto.sync.listBlobs?did=%s&cursor=%s", account.Did, cursor), "", nil)
		if err := s.handleSyncListBlobs(e); err != nil || w.Code != 200 {
			t.Fatalf("indexed list scanned CBOR: %d %s %v", w.Code, w.Body.String(), err)
		}
		var got ComAtprotoSyncListBlobsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if cursor == "" && (len(got.Cids) != 1 || got.Cids[0] != c.String()) {
			t.Fatalf("missing public reference without payload: %+v", got)
		}
		if cursor != "" && (len(got.Cids) != 0 || got.Cursor != nil) {
			t.Fatalf("exhausted cursor: %+v", got)
		}
	}
	uploadTestBlob(t, s, account, "indexed public payload")
	assertBlobRefs(t, s, account.Did, c, 1)
	// GC repairs an inaccurate count from the index, never by decoding the
	// untouched (poisoned) record, even when the old count reaches zero.
	second := models.Record{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: "two", Cid: c.String(), Value: raw}
	if _, err := indexRecords(t.Context(), s.db, account.Did, []models.Record{second}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ?", account.Did).Update("ref_count", 1).Error; err != nil {
		t.Fatal(err)
	}
	second.Cid = ""
	if _, err := indexRecords(t.Context(), s.db, account.Did, []models.Record{second}); err != nil {
		t.Fatal(err)
	}
	assertBlobRefs(t, s, account.Did, c, 1)
}

func TestPublicBlobIndexLegacyBackfillBoundedAndSafe(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "legacy-public.pds.test")
	c, rec := blobRecord(t, "legacy public payload")
	raw, err := atdata.MarshalCBOR(rec)
	if err != nil {
		t.Fatal(err)
	}
	const total = 2*publicBlobBackfillBatch + 3
	records := make([]models.Record, total)
	for i := range records {
		records[i] = models.Record{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: fmt.Sprintf("%06d", i), Cid: c.String(), Value: raw}
	}
	if err := s.db.Client().CreateInBatches(&records, 100).Error; err != nil {
		t.Fatal(err)
	}
	// An incorrect legacy count and an absent marker must never authorize GC.
	blob := models.Blob{Did: account.Did, Cid: c.Bytes(), RefCount: 0}
	if err := s.db.Client().Create(&blob).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Create(&models.BlobPart{BlobID: blob.ID, Data: []byte("legacy public payload")}).Error; err != nil {
		t.Fatal(err)
	}
	// Simulate stale index rows with no completeness marker.
	if err := s.db.Client().Create(&models.PublicBlobRef{Did: account.Did, Nsid: "stale", Rkey: "stale", BlobCid: c.String()}).Error; err != nil {
		t.Fatal(err)
	}
	deleted := records[total-1]
	deleted.Cid = ""
	inserted := records[0]
	inserted.Rkey = "000000-before-cursor"
	if _, err := indexRecords(t.Context(), s.db, account.Did, []models.Record{deleted, inserted}); err != nil {
		t.Fatal(err)
	}
	assertBlobRefs(t, s, account.Did, c, 0)
	var state models.PublicBlobIndex
	if err := s.db.Client().Where("did = ?", account.Did).First(&state).Error; err != nil {
		t.Fatal(err)
	}
	if state.Complete || state.Rkey != records[publicBlobBackfillBatch-1].Rkey {
		t.Fatalf("unbounded or prematurely complete backfill: %+v", state)
	}
	var count int64
	if err := s.db.Client().Model(&models.PublicBlobRef{}).Where("did = ?", account.Did).Count(&count).Error; err != nil || count != publicBlobBackfillBatch+1 {
		t.Fatalf("backfill rows = %d, err %v", count, err)
	}
	e, w := newRequestContext("GET", "/xrpc/com.atproto.sync.listBlobs?did="+account.Did, "", nil)
	if err := s.handleSyncListBlobs(e); err != nil || w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("partial index exposed: %d %s %v", w.Code, w.Body.String(), err)
	}
	// Final bounded step is driven by upload, which must seed the full count.
	uploadTestBlob(t, s, account, "legacy public payload")
	// Existing legacy rows are repaired when a touched CID is next written.
	if _, err := indexRecords(t.Context(), s.db, account.Did, []models.Record{inserted}); err != nil {
		t.Fatal(err)
	}
	assertBlobRefs(t, s, account.Did, c, total)
	if err := s.db.Client().Model(&models.PublicBlobRef{}).Where("did = ?", account.Did).Count(&count).Error; err != nil || count != total {
		t.Fatalf("final index rows = %d, err %v", count, err)
	}
	var parts int64
	if err := s.db.Client().Model(&models.BlobPart{}).Where("blob_id = ?", blob.ID).Count(&parts).Error; err != nil || parts != 1 {
		t.Fatalf("legacy payload deleted: %d %v", parts, err)
	}
}

func TestPublicBlobIndexRollback(t *testing.T) {
	for _, failure := range []string{"decode", "record-write", "index-write"} {
		t.Run(failure, func(t *testing.T) {
			s := newTestServer(t)
			const did = "did:web:rollback-index.test"
			c, rec := blobRecord(t, "rollback public payload")
			raw, err := atdata.MarshalCBOR(rec)
			if err != nil {
				t.Fatal(err)
			}
			record := models.Record{Did: did, Nsid: "app.bsky.feed.post", Rkey: "one", Cid: c.String(), Value: raw}
			if err := s.db.Client().Create(&record).Error; err != nil {
				t.Fatal(err)
			}
			if failure == "decode" {
				if err := s.db.Client().Model(&record).Update("value", []byte{0xff}).Error; err != nil {
					t.Fatal(err)
				}
			} else {
				table := "records"
				if failure == "index-write" {
					table = "public_blob_refs"
				}
				if err := s.db.Client().Exec("CREATE TRIGGER fail_index BEFORE INSERT ON " + table + " BEGIN SELECT RAISE(ABORT, 'test failure'); END").Error; err != nil {
					t.Fatal(err)
				}
			}
			if _, err := indexRecords(t.Context(), s.db, did, []models.Record{record}); err == nil {
				t.Fatal("expected index transaction failure")
			}
			for _, model := range []any{&models.PublicBlobRef{}, &models.PublicBlobIndex{}} {
				var count int64
				if err := s.db.Client().Model(model).Where("did = ?", did).Count(&count).Error; err != nil || count != 0 {
					t.Fatalf("failed transaction left %T rows: %d %v", model, count, err)
				}
			}
		})
	}
}

func TestPublicBlobIndexUploadBackfillRetry(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	account := s.createTestAccount(t, "upload-backfill.pds.test")
	c, rec := blobRecord(t, "backfilled upload")
	raw, err := atdata.MarshalCBOR(rec)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]models.Record, publicBlobBackfillBatch+1)
	for i := range records {
		records[i] = models.Record{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: fmt.Sprintf("%06d", i), Cid: c.String(), Value: raw}
	}
	if err := s.db.Client().CreateInBatches(&records, 100).Error; err != nil {
		t.Fatal(err)
	}
	e, w := newRequestContext("POST", "/xrpc/com.atproto.repo.uploadBlob", "backfilled upload", nil)
	e.Set("repo", mustRepoActor(t, s, account.Did))
	if err := s.handleRepoUploadBlob(e); err != nil || w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("upload with partial index: %d %s %v", w.Code, w.Body.String(), err)
	}
	var count int64
	if err := s.db.Client().Model(&models.Blob{}).Where("did = ?", account.Did).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("partial backfill published upload: %d %v", count, err)
	}
	uploadTestBlob(t, s, account, "backfilled upload")
	assertBlobRefs(t, s, account.Did, c, len(records))
}

func TestPublicBlobIndexImportSerializesWithWrites(t *testing.T) {
	s := newTestServer(t)
	s.repoman = NewRepoMan(s)
	s.evtman = s.newTestEvtman(t)
	account := s.createTestAccount(t, "import-write-index.pds.test")
	s.seedGenesisRepo(t, account.Did, account.SigningKey)
	repo := mustRepoActor(t, s, account.Did)
	importCID, imported := blobRecord(t, "imported reference")
	writeCID, written := blobRecord(t, "written reference")
	root, blocks, _ := importFixture(t, account.Did, []string{"app.bsky.feed.post/imported"}, imported)
	e, w := newRequestContext("POST", "/xrpc/com.atproto.repo.importRepo", "", nil)
	e.Set("repo", repo)
	e.Request().Body = io.NopCloser(bytes.NewReader(importCAR(t, []cid.Cid{root}, blocks)))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	e.SetRequest(e.Request().WithContext(ctx))
	paused, resume := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(resume) })
	defer release()
	var once sync.Once
	if err := s.db.Client().Callback().Create().Before("gorm:create").Register("pause-import-index", func(tx *gorm.DB) {
		if tx.Statement.Table == "public_blob_refs" {
			once.Do(func() {
				close(paused)
				select {
				case <-resume:
				case <-ctx.Done():
				}
			})
		}
	}); err != nil {
		t.Fatal(err)
	}
	importDone := make(chan error, 1)
	go func() { importDone <- s.handleRepoImportRepo(e) }()
	select {
	case <-paused:
	case err := <-importDone:
		t.Fatalf("import did not reach index publication: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := s.repoman.applyWrites(ctx, repo.Repo, []Op{{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("written"), Record: &written}}, nil, nil)
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("write escaped repository lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if err := <-importDone; err != nil || w.Code != 200 {
		t.Fatalf("import failed: %d %s %v", w.Code, w.Body.String(), err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	for _, c := range []cid.Cid{importCID, writeCID} {
		var count int64
		if err := s.db.Client().Model(&models.PublicBlobRef{}).Where("did = ? AND blob_cid = ?", account.Did, c.String()).Count(&count).Error; err != nil || count != 1 {
			t.Fatalf("serialized import/write lost public reference: %s %d %v", c, count, err)
		}
	}
}

func TestPublicBlobIndexQueryPlan(t *testing.T) {
	s := newTestServer(t)
	for _, cursor := range []string{"", "zzzz"} {
		var plan []struct{ Detail string }
		if err := s.db.Client().Raw("EXPLAIN QUERY PLAN SELECT DISTINCT blob_cid FROM public_blob_refs WHERE did = ? AND blob_cid > ? ORDER BY blob_cid LIMIT ?", "did:web:plan.test", cursor, 500).Scan(&plan).Error; err != nil {
			t.Fatal(err)
		}
		if len(plan) != 1 || !strings.Contains(plan[0].Detail, "SEARCH public_blob_refs USING COVERING INDEX idx_public_blob_did_cid (did=? AND blob_cid>?)") {
			t.Fatalf("cursor %q does not use bounded index seek: %+v", cursor, plan)
		}
		t.Logf("cursor %q: %s", cursor, plan[0].Detail)
	}
}

func TestPublicBlobIndexSpaceGCSafety(t *testing.T) {
	for _, state := range []string{"absent", "incomplete", "referenced", "unreferenced"} {
		t.Run(state, func(t *testing.T) {
			s := newTestServer(t)
			const did = "did:web:space-gc-index.test"
			c, _ := blobRecord(t, "space gc public reference")
			blob := models.Blob{Did: did, Cid: c.Bytes(), RefCount: 0}
			if err := s.db.Client().Create(&blob).Error; err != nil {
				t.Fatal(err)
			}
			if state != "absent" {
				if err := s.db.Client().Create(&models.PublicBlobIndex{Did: did, Complete: state != "incomplete"}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if state == "referenced" {
				if err := s.db.Client().Create(&models.PublicBlobRef{Did: did, Nsid: "app.bsky.feed.post", Rkey: "one", BlobCid: c.String()}).Error; err != nil {
					t.Fatal(err)
				}
			}
			if err := s.spaceStore(nil, did).gcBlobs([]string{c.String()}); err != nil {
				t.Fatal(err)
			}
			var count int64
			if err := s.db.Client().Model(&models.Blob{}).Where("did = ?", did).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if (count == 0) != (state == "unreferenced") {
				t.Fatalf("space GC with %s public index: remaining payloads=%d", state, count)
			}
		})
	}
}

func TestPublicBlobIndexAccountDeletion(t *testing.T) {
	s := newTestServer(t)
	s.evtman = s.newTestEvtman(t)
	account := s.createTestAccount(t, "delete-public-index.pds.test")
	expires := time.Now().Add(time.Hour)
	if err := s.db.Client().Model(&models.Repo{}).Where("did = ?", account.Did).Updates(map[string]any{"account_delete_code": "delete-token", "account_delete_code_expires_at": expires}).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Create(&models.PublicBlobIndex{Did: account.Did, Complete: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Client().Create(&models.PublicBlobRef{Did: account.Did, Nsid: "app.bsky.feed.post", Rkey: "one", BlobCid: "reference"}).Error; err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ComAtprotoServerDeleteAccountRequest{Did: account.Did, Password: account.Password, Token: "delete-token"})
	if err != nil {
		t.Fatal(err)
	}
	e, w := newRequestContext("POST", "/xrpc/com.atproto.server.deleteAccount", string(body), nil)
	if err := s.handleServerDeleteAccount(e); err != nil || w.Code != 200 {
		t.Fatalf("delete account: %d %s %v", w.Code, w.Body.String(), err)
	}
	for _, model := range []any{&models.PublicBlobRef{}, &models.PublicBlobIndex{}} {
		var count int64
		if err := s.db.Client().Model(model).Where("did = ?", account.Did).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("deleted account left %T rows: %d %v", model, count, err)
		}
	}
}

// Measures reference discovery only: no real identity, network, or blob IO.
// The baseline is the old query/decode/dedup/sort algorithm, on the same DB.
func TestPublicBlobIndexSyntheticCost(t *testing.T) {
	s := newTestServer(t)
	const did = "did:web:synthetic-index.test"
	const total = 4096
	records := make([]models.Record, total)
	var target string
	for i := range records {
		c, rec := blobRecord(t, fmt.Sprintf("synthetic-%d", i))
		raw, err := atdata.MarshalCBOR(rec)
		if err != nil {
			t.Fatal(err)
		}
		records[i] = models.Record{Did: did, Nsid: "app.bsky.feed.post", Rkey: fmt.Sprintf("%06d", i), Cid: c.String(), Value: raw}
		target = c.String()
	}
	if err := s.db.Client().CreateInBatches(&records, 100).Error; err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for {
		complete, err := s.preparePublicBlobIndex(t.Context(), did)
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			break
		}
	}
	t.Logf("one-time backfill: %d records, %s", total, time.Since(start))
	measure := func(name string, fn func()) {
		t.Helper()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		fn()
		runtime.ReadMemStats(&after)
		t.Logf("%s: elapsed=%s allocated=%d bytes", name, time.Since(start), after.TotalAlloc-before.TotalAlloc)
	}
	var baseline []string
	measure("before traversal (10 pages incl exhausted, 40960 CBOR decodes)", func() {
		cursor := ""
		for {
			var records []models.Record
			if err := s.db.Client().Select("value").Where("did = ?", did).Find(&records).Error; err != nil {
				t.Fatal(err)
			}
			refs, err := countBlobRefs(records)
			if err != nil {
				t.Fatal(err)
			}
			page := make([]string, 0, len(refs))
			for c := range refs {
				if value := c.String(); value > cursor {
					page = append(page, value)
				}
			}
			sort.Strings(page)
			page = page[:min(500, len(page))]
			if len(page) == 0 {
				break
			}
			baseline = append(baseline, page...)
			cursor = page[len(page)-1]
		}
	})
	var indexed []string
	measure("after traversal (10 pages incl exhausted, 0 CBOR decodes)", func() {
		cursor := ""
		for {
			if complete, err := s.preparePublicBlobIndex(t.Context(), did); err != nil || !complete {
				t.Fatalf("warm index: %v %v", complete, err)
			}
			page := make([]string, 0, 500)
			if err := s.db.Raw(t.Context(), "SELECT DISTINCT blob_cid FROM public_blob_refs WHERE did = ? AND blob_cid > ? ORDER BY blob_cid LIMIT ?", nil, did, cursor, 500).Scan(&page).Error; err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			indexed = append(indexed, page...)
			cursor = page[len(page)-1]
		}
	})
	if !reflect.DeepEqual(baseline, indexed) || len(indexed) != total {
		t.Fatal("indexed traversal differs from baseline")
	}
	measure("before upload reference lookup (20 uploads, 81920 CBOR decodes)", func() {
		for range 20 {
			var records []models.Record
			if err := s.db.Client().Select("value").Where("did = ?", did).Find(&records).Error; err != nil {
				t.Fatal(err)
			}
			if _, err := countBlobRefs(records); err != nil {
				t.Fatal(err)
			}
		}
	})
	measure("after upload reference lookup (20 uploads, 0 CBOR decodes)", func() {
		for range 20 {
			if complete, err := s.preparePublicBlobIndex(t.Context(), did); err != nil || !complete {
				t.Fatalf("warm index: %v %v", complete, err)
			}
			var count int64
			if err := s.db.Raw(t.Context(), "SELECT COUNT(*) FROM public_blob_refs WHERE did = ? AND blob_cid = ?", nil, did, target).Scan(&count).Error; err != nil || count != 1 {
				t.Fatalf("upload reference lookup = %d, %v", count, err)
			}
		}
	})
}
