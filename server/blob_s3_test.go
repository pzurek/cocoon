package server

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/haileyok/cocoon/models"
)

func TestS3RetentionAfterLastPublicReference(t *testing.T) {
	for _, cdn := range []bool{false, true} {
		t.Run(map[bool]string{false: "proxy", true: "cdn"}[cdn], func(t *testing.T) {
			s := newTestServer(t)
			s.repoman = NewRepoMan(s)
			s.evtman = s.newTestEvtman(t)
			account := s.createTestAccount(t, "retention.pds.test")
			s.seedGenesisRepo(t, account.Did, account.SigningKey)
			const payload = "retained object after metadata removal"
			c, record := blobRecord(t, payload)
			var deletes atomic.Int64
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deletes.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.Method != http.MethodGet || r.URL.Path != "/bucket/"+s3BlobKey(account.Did, c) {
					t.Errorf("unexpected object request: %s %s", r.Method, r.URL.Path)
					w.WriteHeader(400)
					return
				}
				_, _ = io.WriteString(w, payload)
			}))
			defer endpoint.Close()
			s.s3Config = &S3Config{BlobstoreEnabled: true, Endpoint: endpoint.URL, Bucket: "bucket", Region: "test", AccessKey: "test", SecretKey: "test"}
			if cdn {
				s.s3Config.CDNUrl = endpoint.URL + "/bucket"
			}
			if err := s.db.Client().Create(&models.Blob{Did: account.Did, Cid: c.Bytes(), Storage: "s3"}).Error; err != nil {
				t.Fatal(err)
			}
			mustApply(t, s, account.Did, Op{Type: OpTypeCreate, Collection: "app.bsky.feed.post", Rkey: strPtr("one"), Record: &record})
			target := "/xrpc/com.atproto.sync.getBlob?did=" + account.Did + "&cid=" + c.String()
			e, w := newRequestContext(http.MethodGet, target, "", nil)
			if err := s.handleSyncGetBlob(e); err != nil {
				t.Fatal(err)
			}
			if cdn {
				if w.Code != 302 || w.Header().Get("Location") != endpoint.URL+"/bucket/"+s3BlobKey(account.Did, c) {
					t.Fatalf("public CDN redirect: %d %s", w.Code, w.Header().Get("Location"))
				}
			} else if w.Code != 200 || w.Body.String() != payload {
				t.Fatalf("public proxy bytes: %d %s", w.Code, w.Body.String())
			}
			mustApply(t, s, account.Did, Op{Type: OpTypeDelete, Collection: "app.bsky.feed.post", Rkey: strPtr("one")})
			e, w = newRequestContext(http.MethodGet, target, "", nil)
			if err := s.handleSyncGetBlob(e); err != nil || w.Code != 400 || !strings.Contains(w.Body.String(), "BlobNotFound") || w.Header().Get("Location") != "" {
				t.Fatalf("removed metadata must not serve or redirect: %d %s %v", w.Code, w.Body.String(), err)
			}
			if deletes.Load() != 0 {
				t.Fatal("record deletion unexpectedly erased retained S3 object")
			}
			// A direct object/CDN URL bypasses the PDS metadata check. This is
			// why public buckets cannot promise revocation or private blobs.
			response, err := http.Get(endpoint.URL + "/bucket/" + s3BlobKey(account.Did, c))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			data, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != 200 || string(data) != payload {
				t.Fatalf("retained object: %d %s %v", response.StatusCode, data, err)
			}
		})
	}
}

// fakeS3 is a minimal path-style S3 endpoint serving GetObject and
// ListObjectsV2 over an in-memory bucket.
func fakeS3(t *testing.T, bucket string, objects map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == bucket {
			prefix := r.URL.Query().Get("prefix")
			var keys []string
			for k := range objects {
				if strings.HasPrefix(k, prefix) {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			type content struct {
				Key  string
				Size int
			}
			type result struct {
				XMLName  xml.Name `xml:"ListBucketResult"`
				Name     string
				Prefix   string
				KeyCount int
				MaxKeys  int
				Contents []content
			}
			res := result{Name: bucket, Prefix: prefix, KeyCount: len(keys), MaxKeys: 1000}
			for _, k := range keys {
				res.Contents = append(res.Contents, content{Key: k, Size: len(objects[k])})
			}
			w.Header().Set("Content-Type", "application/xml")
			_ = xml.NewEncoder(w).Encode(res)
			return
		}
		key, ok := strings.CutPrefix(path, bucket+"/")
		body, found := objects[key]
		if !ok || !found {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetS3BlobKeyLayouts(t *testing.T) {
	t.Parallel()

	const (
		did  = "did:plc:oisofpd7lj26yvgiivf3lxsi"
		cstr = "bafkreifq2pczayel2ljghsigxe4bbf7vkwucrtcqtjpmr532o7t65ev2wa"
	)
	c := mustCid(t, cstr)

	tests := []struct {
		name    string
		objects map[string]string
		want    string
		wantErr bool
	}{
		{
			name:    "flat key",
			objects: map[string]string{"blobs/" + did + "/" + cstr: "flat"},
			want:    "flat",
		},
		{
			name:    "key nested under a cid directory",
			objects: map[string]string{"blobs/" + did + "/" + cstr + "/8c8119e0dcc22e219c27ca3082fa3e59": "nested"},
			want:    "nested",
		},
		{
			name: "flat key preferred over nested",
			objects: map[string]string{
				"blobs/" + did + "/" + cstr:                                       "flat",
				"blobs/" + did + "/" + cstr + "/8c8119e0dcc22e219c27ca3082fa3e59": "nested",
			},
			want: "flat",
		},
		{
			name:    "other blobs do not match",
			objects: map[string]string{"blobs/" + did + "/" + cstr + "x/abc": "other", "blobs/did:plc:other/" + cstr + "/abc": "other"},
			wantErr: true,
		},
		{
			name:    "missing",
			objects: map[string]string{},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := fakeS3(t, "bucket", tc.objects)
			s := newTestServer(t)
			s.s3Config = &S3Config{
				BlobstoreEnabled: true,
				Endpoint:         srv.URL,
				Region:           "us-east-1",
				Bucket:           "bucket",
				AccessKey:        "k",
				SecretKey:        "s",
			}

			body, err := s.getS3Blob(context.Background(), did, c)
			if tc.wantErr {
				if err == nil {
					body.Close()
					t.Fatal("expected error")
				}
				if !isS3NoSuchKey(err) {
					t.Fatalf("expected NoSuchKey error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("getS3Blob: %v", err)
			}
			defer body.Close()
			got, _ := io.ReadAll(body)
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
