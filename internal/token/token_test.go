package token

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// stsResponse is the JSON envelope a real GetCallerIdentity returns.
const stsResponse = `{
  "GetCallerIdentityResponse": {
    "GetCallerIdentityResult": {
      "Account": "000000000000",
      "Arn": "arn:aws:sts::000000000000:assumed-role/Admin/session-name",
      "UserId": "AROAEXAMPLE:session-name"
    },
    "ResponseMetadata": {"RequestId": "01234567-89ab-cdef-0123-456789abcdef"}
  }
}`

// fakeSTS stands in for the local emulator's STS. It records the cluster ID
// header so tests can assert the binding is actually transmitted.
type fakeSTS struct {
	server       *httptest.Server
	gotClusterID string
	status       int
	body         string
	requestCount int
}

func newFakeSTS(t *testing.T) *fakeSTS {
	t.Helper()
	f := &fakeSTS{status: http.StatusOK, body: stsResponse}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requestCount++
		f.gotClusterID = r.Header.Get(clusterIDHeader)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		fmt.Fprint(w, f.body)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeSTS) verifier(t *testing.T, clusterID string) *Verifier {
	t.Helper()
	u, err := url.Parse(f.server.URL)
	if err != nil {
		t.Fatalf("parsing fake STS URL: %v", err)
	}
	return &Verifier{ClusterID: clusterID, STSEndpoint: u}
}

// tokenOpts describes a synthetic presigned URL.
type tokenOpts struct {
	host          string
	scheme        string
	path          string
	action        string
	signedHeaders string
	expires       string
	date          time.Time
	extraParam    string
	prefix        string
}

// makeToken builds a token the way `aws eks get-token` does. The signature is
// arbitrary because verification is delegated to STS; what is under test is the
// structural validation that happens before that call.
func makeToken(base string, o tokenOpts) string {
	u, _ := url.Parse(base)
	if o.host != "" {
		u.Host = o.host
	}
	if o.scheme != "" {
		u.Scheme = o.scheme
	}
	u.Path = "/"
	if o.path != "" {
		u.Path = o.path
	}

	action := "GetCallerIdentity"
	if o.action != "" {
		action = o.action
	}
	signedHeaders := "host;x-k8s-aws-id"
	if o.signedHeaders != "" {
		signedHeaders = o.signedHeaders
	}
	expires := "60"
	if o.expires != "" {
		expires = o.expires
	}
	date := o.date
	if date.IsZero() {
		date = time.Now().UTC()
	}

	q := url.Values{}
	q.Set("Action", action)
	q.Set("Version", "2011-06-15")
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", "AKIAEXAMPLE/20260816/us-east-1/sts/aws4_request")
	q.Set("X-Amz-Date", date.Format(dateHeaderFormat))
	q.Set("X-Amz-Expires", expires)
	q.Set("X-Amz-SignedHeaders", signedHeaders)
	q.Set("X-Amz-Signature", strings.Repeat("a", 64))
	if o.extraParam != "" {
		q.Set(o.extraParam, "value")
	}
	u.RawQuery = q.Encode()

	prefix := v1Prefix
	if o.prefix != "" {
		prefix = o.prefix
	}
	return prefix + base64.RawURLEncoding.EncodeToString([]byte(u.String()))
}

func TestVerifyAcceptsWellFormedToken(t *testing.T) {
	sts := newFakeSTS(t)
	v := sts.verifier(t, "my-cluster")

	id, err := v.Verify(context.Background(), makeToken(sts.server.URL, tokenOpts{}))
	if err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}

	if id.ARN != "arn:aws:sts::000000000000:assumed-role/Admin/session-name" {
		t.Errorf("ARN = %q", id.ARN)
	}
	// The assumed-role session must collapse to the role for mapping to work.
	if id.CanonicalARN != "arn:aws:iam::000000000000:role/Admin" {
		t.Errorf("CanonicalARN = %q, want the underlying IAM role", id.CanonicalARN)
	}
	if id.SessionName != "session-name" {
		t.Errorf("SessionName = %q, want session-name", id.SessionName)
	}
	if id.AccountID != "000000000000" {
		t.Errorf("AccountID = %q", id.AccountID)
	}
}

func TestVerifySendsClusterIDHeader(t *testing.T) {
	sts := newFakeSTS(t)
	v := sts.verifier(t, "my-cluster")

	if _, err := v.Verify(context.Background(), makeToken(sts.server.URL, tokenOpts{})); err != nil {
		t.Fatalf("Verify returned unexpected error: %v", err)
	}
	// This header is the entire anti-replay mechanism. If it stops being sent,
	// tokens silently become valid across clusters.
	if sts.gotClusterID != "my-cluster" {
		t.Errorf("STS received %s=%q, want my-cluster", clusterIDHeader, sts.gotClusterID)
	}
}

func TestVerifyRejectsMalformedTokens(t *testing.T) {
	sts := newFakeSTS(t)
	v := sts.verifier(t, "my-cluster")

	tests := []struct {
		name  string
		token string
	}{
		{"missing prefix", strings.TrimPrefix(makeToken(sts.server.URL, tokenOpts{}), v1Prefix)},
		{"wrong prefix", makeToken(sts.server.URL, tokenOpts{prefix: "k8s-aws-v2."})},
		{"not base64", v1Prefix + "!!!not-base64!!!"},
		{"oversized", v1Prefix + strings.Repeat("A", maxTokenLenBytes+1)},
		{"foreign host", makeToken(sts.server.URL, tokenOpts{host: "evil.example.com"})},
		{"unexpected path", makeToken(sts.server.URL, tokenOpts{path: "/some/path"})},
		{"wrong action", makeToken(sts.server.URL, tokenOpts{action: "GetSessionToken"})},
		{"cluster header not signed", makeToken(sts.server.URL, tokenOpts{signedHeaders: "host"})},
		{"non-whitelisted parameter", makeToken(sts.server.URL, tokenOpts{extraParam: "X-Amz-Injected"})},
		{"expires out of range", makeToken(sts.server.URL, tokenOpts{expires: "99999"})},
		{"negative expires", makeToken(sts.server.URL, tokenOpts{expires: "-1"})},
		{"non-numeric expires", makeToken(sts.server.URL, tokenOpts{expires: "soon"})},
		{"expired", makeToken(sts.server.URL, tokenOpts{date: time.Now().UTC().Add(-16 * time.Minute)})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := sts.requestCount
			if _, err := v.Verify(context.Background(), tt.token); err == nil {
				t.Fatalf("Verify accepted a %s token", tt.name)
			}
			// Structural rejection must not cost an upstream call, otherwise an
			// unauthenticated caller can drive load against STS.
			if sts.requestCount != before {
				t.Errorf("Verify called STS for a %s token", tt.name)
			}
		})
	}
}

func TestVerifyAcceptsTokenInsideExpiryWindow(t *testing.T) {
	sts := newFakeSTS(t)
	v := sts.verifier(t, "my-cluster")

	// 14 minutes old is still inside the 15-minute window measured from
	// x-amz-date -- deliberately not the 60-second x-amz-expires value.
	token := makeToken(sts.server.URL, tokenOpts{date: time.Now().UTC().Add(-14 * time.Minute)})
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify rejected a token still inside its window: %v", err)
	}
}

func TestVerifyPropagatesSTSRejection(t *testing.T) {
	sts := newFakeSTS(t)
	sts.status = http.StatusForbidden
	sts.body = `{"Error":{"Code":"InvalidClientTokenId"}}`
	v := sts.verifier(t, "my-cluster")

	_, err := v.Verify(context.Background(), makeToken(sts.server.URL, tokenOpts{}))
	if err == nil {
		t.Fatal("Verify accepted a token STS rejected")
	}
	if !strings.Contains(err.Error(), "STS rejected") {
		t.Errorf("error = %q, want it to mention the STS rejection", err)
	}
}

func TestVerifyRejectsUnmappablePrincipal(t *testing.T) {
	sts := newFakeSTS(t)
	// An ARN that authenticates but is not a principal we can canonicalize.
	sts.body = strings.Replace(stsResponse,
		"arn:aws:sts::000000000000:assumed-role/Admin/session-name",
		"arn:aws:s3:::some-bucket", 1)
	v := sts.verifier(t, "my-cluster")

	if _, err := v.Verify(context.Background(), makeToken(sts.server.URL, tokenOpts{})); err == nil {
		t.Fatal("Verify accepted a non-principal ARN")
	}
}

func TestVerifyUsesInjectedClock(t *testing.T) {
	sts := newFakeSTS(t)
	v := sts.verifier(t, "my-cluster")
	signedAt := time.Now().UTC()
	token := makeToken(sts.server.URL, tokenOpts{date: signedAt})

	// Advance the clock past the window; the same token must now be refused.
	v.Now = func() time.Time { return signedAt.Add(16 * time.Minute) }
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("Verify accepted a token past its expiry under the injected clock")
	}
}
