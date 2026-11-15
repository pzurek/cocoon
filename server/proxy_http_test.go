package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Exercise the guarded transport rather than assuming it is *http.Transport.
// Cancellation of both proxy paths is covered by TestProxyCancellation.
func TestProxyResponseHeaderTimeout(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() { close(release) })
	client := proxyTestHTTPClient(t, upstream)
	// Prove the response-header deadline works independently of the whole-request
	// deadline. The context bounds a broken implementation without hanging tests.
	client.Timeout = 0
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://203.0.113.10", nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || ctx.Err() != nil {
		t.Fatalf("expected transport timeout before context deadline, got %v (context: %v)", err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed < 9*time.Second {
		t.Fatalf("response-header deadline fired too early: %v", elapsed)
	}
}
