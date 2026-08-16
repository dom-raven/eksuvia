// Package token verifies the bearer tokens that `aws eks get-token` produces.
//
// The token is not a JWT. It is a presigned AWS STS GetCallerIdentity URL,
// base64url-encoded and prefixed with "k8s-aws-v1.". The signature covers an
// x-k8s-aws-id header carrying the cluster name, which is what stops a token
// minted for cluster A from being replayed against cluster B.
//
// Verification therefore means: structurally validate the URL without trusting
// it, then dereference it against STS with the cluster ID header attached. STS
// itself performs the SigV4 check and tells us who the caller is. We never
// verify a signature ourselves.
//
// The constants and the parameter whitelist below are taken from
// kubernetes-sigs/aws-iam-authenticator so that a token accepted here is
// accepted by real EKS and vice versa.
package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dom-raven/eksuvia/internal/awsarn"
)

const (
	// v1Prefix is the only token version EKS has ever issued.
	v1Prefix = "k8s-aws-v1."

	// clusterIDHeader binds a token to a single cluster. It must appear in the
	// presigned URL's SignedHeaders, otherwise the token is replayable.
	clusterIDHeader = "x-k8s-aws-id"

	// presignedURLExpiration is the real lifetime of a token, measured from the
	// x-amz-date in the URL. Note this is deliberately not x-amz-expires: the
	// CLI pins that to 60 for legacy reasons and EKS ignores it.
	presignedURLExpiration = 15 * time.Minute

	// maxTokenLenBytes bounds work done on untrusted input before parsing.
	maxTokenLenBytes = 1024 * 4

	dateHeaderFormat = "20060102T150405Z"
)

// parameterWhitelist is the exact set of query parameters permitted in the
// presigned URL. Anything else is rejected outright rather than forwarded,
// which prevents a caller from smuggling extra parameters into the STS call we
// make on their behalf.
var parameterWhitelist = map[string]bool{
	"action":               true,
	"version":              true,
	"x-amz-algorithm":      true,
	"x-amz-credential":     true,
	"x-amz-date":           true,
	"x-amz-expires":        true,
	"x-amz-security-token": true,
	"x-amz-signature":      true,
	"x-amz-signedheaders":  true,
}

// Identity is the caller behind a verified token.
type Identity struct {
	// ARN is exactly what STS returned, e.g. an assumed-role ARN.
	ARN string
	// CanonicalARN collapses assumed roles to their IAM role, and is the value
	// that access entries and aws-auth are matched against.
	CanonicalARN string
	AccountID    string
	UserID       string
	// SessionName is the STS session, exposed to aws-auth as {{SessionName}}.
	SessionName string
}

// FormatError means the token was malformed. It is reported separately from a
// verification failure because it never warrants an upstream STS call.
type FormatError struct{ msg string }

func (e FormatError) Error() string { return "eksuvia: invalid token: " + e.msg }

// Verifier checks tokens for one cluster against one STS endpoint.
type Verifier struct {
	// ClusterID is the cluster name the token must have been signed for.
	ClusterID string
	// STSEndpoint is where GetCallerIdentity is actually dereferenced. Against
	// real AWS this is sts.<region>.amazonaws.com; here it is the local Floci
	// endpoint. Only URLs pointing at this host are accepted.
	STSEndpoint *url.URL
	// Client performs the STS call. Nil uses a 10s default.
	Client *http.Client
	// Now allows tests to control expiry evaluation.
	Now func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Verify validates a `k8s-aws-v1.` token and resolves it to an identity.
//
// The structural checks run before any network call, so a malformed or expired
// token costs nothing. Only a well-formed, in-date, correctly-scoped URL is
// ever dereferenced.
func (v *Verifier) Verify(ctx context.Context, token string) (*Identity, error) {
	if len(token) > maxTokenLenBytes {
		return nil, FormatError{"token is too large"}
	}
	if !strings.HasPrefix(token, v1Prefix) {
		return nil, FormatError{fmt.Sprintf("token is missing expected %q prefix", v1Prefix)}
	}

	tokenBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, v1Prefix))
	if err != nil {
		return nil, FormatError{err.Error()}
	}

	parsedURL, err := url.Parse(string(tokenBytes))
	if err != nil {
		return nil, FormatError{err.Error()}
	}

	// Real EKS pins this to https against a known STS hostname. Locally the STS
	// endpoint is usually plain http on localhost, so the scheme is taken from
	// the configured endpoint rather than hardcoded -- but the host still has to
	// match exactly, which is the check that actually matters.
	if !strings.EqualFold(parsedURL.Host, v.STSEndpoint.Host) {
		return nil, FormatError{fmt.Sprintf("unexpected hostname %q in pre-signed URL", parsedURL.Host)}
	}
	if parsedURL.Scheme != v.STSEndpoint.Scheme {
		return nil, FormatError{fmt.Sprintf("unexpected scheme %q in pre-signed URL", parsedURL.Scheme)}
	}
	if parsedURL.Path != "/" && parsedURL.Path != "" {
		return nil, FormatError{"unexpected path in pre-signed URL"}
	}

	queryParamsLower := make(url.Values)
	for key, values := range parsedURL.Query() {
		lower := strings.ToLower(key)
		if !parameterWhitelist[lower] {
			return nil, FormatError{fmt.Sprintf("non-whitelisted query parameter %q", key)}
		}
		if len(values) != 1 {
			return nil, FormatError{"query parameter with multiple values not supported"}
		}
		queryParamsLower.Set(lower, values[0])
	}

	if queryParamsLower.Get("action") != "GetCallerIdentity" {
		return nil, FormatError{"unexpected action parameter in pre-signed URL"}
	}
	if !hasSignedClusterIDHeader(queryParamsLower) {
		return nil, FormatError{"client did not sign the " + clusterIDHeader + " header in the pre-signed URL"}
	}

	// x-amz-expires is validated for shape but deliberately not used as the
	// expiry, mirroring upstream. The real clock starts at x-amz-date.
	expiration, err := strconv.Atoi(queryParamsLower.Get("x-amz-expires"))
	if err != nil || expiration < 0 || expiration > 900 {
		return nil, FormatError{fmt.Sprintf("invalid x-amz-expires parameter in pre-signed URL: %s", queryParamsLower.Get("x-amz-expires"))}
	}

	dateParsed, err := time.Parse(dateHeaderFormat, queryParamsLower.Get("x-amz-date"))
	if err != nil {
		return nil, FormatError{fmt.Sprintf("error parsing x-amz-date parameter: %v", err)}
	}
	if dateParsed.Add(presignedURLExpiration).Before(v.now()) {
		return nil, FormatError{fmt.Sprintf("pre-signed URL is expired (signed at %s)", dateParsed)}
	}

	return v.callSTS(ctx, parsedURL.String())
}

// hasSignedClusterIDHeader reports whether the cluster ID header is covered by
// the signature. Without it the token is valid for any cluster.
func hasSignedClusterIDHeader(q url.Values) bool {
	for _, h := range strings.Split(q.Get("x-amz-signedheaders"), ";") {
		if strings.EqualFold(strings.TrimSpace(h), clusterIDHeader) {
			return true
		}
	}
	return false
}

// getCallerIdentityWrapper is the JSON envelope STS returns when asked for
// application/json. The nesting is genuinely this deep in the real API.
type getCallerIdentityWrapper struct {
	GetCallerIdentityResponse struct {
		GetCallerIdentityResult struct {
			Account string `json:"Account"`
			Arn     string `json:"Arn"`
			UserID  string `json:"UserId"`
		} `json:"GetCallerIdentityResult"`
		ResponseMetadata struct {
			RequestID string `json:"RequestId"`
		} `json:"ResponseMetadata"`
	} `json:"GetCallerIdentityResponse"`
}

func (v *Verifier) callSTS(ctx context.Context, presigned string) (*Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, presigned, nil)
	if err != nil {
		return nil, err
	}
	// Supplying the cluster ID here is the crux of the scheme. If the token was
	// signed for a different cluster the signature will not cover this value and
	// STS rejects the request, so a token cannot cross cluster boundaries.
	req.Header.Set(clusterIDHeader, v.ClusterID)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("eksuvia: error calling STS: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("eksuvia: error reading STS response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("eksuvia: STS rejected the token (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var wrapper getCallerIdentityWrapper
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("eksuvia: malformed STS response: %w", err)
	}
	result := wrapper.GetCallerIdentityResponse.GetCallerIdentityResult
	if result.Arn == "" {
		return nil, fmt.Errorf("eksuvia: STS response contained no ARN")
	}

	canonical, err := awsarn.Canonicalize(result.Arn)
	if err != nil {
		return nil, err
	}

	return &Identity{
		ARN:          result.Arn,
		CanonicalARN: canonical,
		AccountID:    result.Account,
		UserID:       result.UserID,
		SessionName:  awsarn.SessionName(result.Arn),
	}, nil
}
