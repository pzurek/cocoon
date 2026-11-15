package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/gttp"
)

// Keep the fork's stricter deadlines while adopting upstream's larger idle pool.
const (
	proxyDialTimeout           = 5 * time.Second
	proxyResponseHeaderTimeout = 10 * time.Second
	proxyRequestTimeout        = 30 * time.Second
	proxyTLSHandshakeTimeout   = 5 * time.Second
	proxyIdleConnTimeout       = 90 * time.Second
	proxyMaxIdleConnsPerHost   = 32
)

// newProxyHTTPClient bounds upstream calls without weakening SSRF or redirect
// checks. Both proxy paths also propagate the inbound request context.
func newProxyHTTPClient(opts ...gttp.Option) *http.Client {
	client := gttp.New(append(opts,
		gttp.WithStrictSSRFProtection(),
		gttp.WithNoProxy(),
		gttp.WithTimeout(proxyRequestTimeout),
		gttp.WithDialTimeout(proxyDialTimeout),
		gttp.WithResponseHeaderTimeout(proxyResponseHeaderTimeout),
		gttp.WithTLSHandshakeTimeout(proxyTLSHandshakeTimeout),
		gttp.WithIdleConnTimeout(proxyIdleConnTimeout),
		gttp.WithMaxIdleConns(100),
		gttp.WithMaxIdleConnsPerHost(proxyMaxIdleConnsPerHost),
		gttp.WithNoRetries(),
		gttp.WithDisableCompression(),
	)...)
	checkRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := checkRedirect(req, via); err != nil {
			return err
		}
		// Go rebuilds headers from the original request on every redirect.
		for _, previous := range via {
			if !strings.EqualFold(previous.URL.Scheme, req.URL.Scheme) || !strings.EqualFold(previous.URL.Host, req.URL.Host) {
				req.Header.Del("Authorization")
				break
			}
		}
		return nil
	}
	return client
}
