// Package proxy forwards every AWS API call eksuvia does not implement to the
// upstream local emulator.
//
// This is what makes eksuvia composable rather than competitive. Emulating EKS
// convincingly requires IAM, STS, EC2, ELBv2, ECR, CloudFormation and more, and
// Floci already implements those well. eksuvia owns only the EKS-shaped
// surface -- the part AWS hides -- and hands everything else straight through,
// so callers point a single AWS_ENDPOINT_URL at eksuvia and every service works.
package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// New builds a reverse proxy to the upstream emulator.
func New(endpoint string, logger *slog.Logger) (http.Handler, error) {
	target, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("proxy: parsing endpoint %q: %w", endpoint, err)
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// Preserve the client's Host header. SigV4 signs the Host, and while
			// local emulators are lenient about signature verification, tools
			// that construct URLs from the response rely on it being stable.
			r.Out.Host = r.In.Host
			r.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("upstream emulator unreachable",
				"endpoint", endpoint, "method", r.Method, "path", r.URL.Path, "error", err)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("x-amzn-ErrorType", "ServiceUnavailableException")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintf(w, `{"message":%q}`,
				"eksuvia could not reach the upstream AWS emulator at "+endpoint+
					": is Floci running? Start it, or point --floci-endpoint elsewhere.")
		},
		Transport: &http.Transport{
			ResponseHeaderTimeout: 60 * time.Second,
		},
	}
	return rp, nil
}
