package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/dom-raven/eksuvia/internal/identity"
	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/token"
)

// TokenReview request/response types, matching authentication.k8s.io/v1.
//
// These are declared locally rather than imported from k8s.io/api so that
// eksuvia is not pinned to a single Kubernetes minor version -- awkward for a
// tool whose job is emulating several at once. The shape is stable and
// versioned by the API group.
type tokenReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Spec       tokenReviewSpec    `json:"spec"`
	Status     *tokenReviewStatus `json:"status,omitempty"`
}

// tokenReviewResponse is what eksuvia sends back. It deliberately omits spec:
// the API server ignores it, and echoing the request would put a stray empty
// token field in every reply.
type tokenReviewResponse struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Status     tokenReviewStatus `json:"status"`
}

func newTokenReviewResponse(status tokenReviewStatus) tokenReviewResponse {
	return tokenReviewResponse{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Status:     status,
	}
}

type tokenReviewSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type tokenReviewStatus struct {
	Authenticated bool      `json:"authenticated"`
	User          *userInfo `json:"user,omitempty"`
	Audiences     []string  `json:"audiences,omitempty"`
	Error         string    `json:"error,omitempty"`
}

type userInfo struct {
	Username string              `json:"username"`
	UID      string              `json:"uid,omitempty"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}

// awsAuthCacheTTL bounds how stale a cached aws-auth ConfigMap may be.
//
// Short, because editing aws-auth and immediately testing the result is a
// normal workflow and a long cache makes the emulator feel broken. The API
// server caches successful reviews for far longer anyway.
const awsAuthCacheTTL = 5 * time.Second

type awsAuthCacheEntry struct {
	parsed  *identity.AWSAuth
	fetched time.Time
}

var awsAuthCache sync.Map // cluster name -> awsAuthCacheEntry

// handleTokenReview authenticates a bearer token on behalf of an emulated
// cluster's API server.
//
// This is the hidden EKS component with the largest blast radius. Real EKS runs
// an aws-iam-authenticator webhook here; a token arrives, its presigned STS URL
// is dereferenced to learn the caller's IAM ARN, and that ARN is mapped through
// access entries or aws-auth to a Kubernetes username and groups.
//
// The mapping step is the part emulators usually skip, returning system:masters
// for anyone holding valid AWS credentials. That makes RBAC untestable locally
// and hides exactly the class of bug -- a principal mapped to the wrong groups,
// or not mapped at all -- that this webhook exists to produce faithfully.
func (s *Server) handleTokenReview(w http.ResponseWriter, r *http.Request, p Params) {
	clusterName := p["cluster"]

	var review tokenReview
	if !decodeJSON(w, r, &review) {
		return
	}

	state, err := s.store.Get(clusterName)
	if err != nil {
		s.denyToken(w, review, "eksuvia does not know a cluster named "+clusterName)
		return
	}

	verifier := &token.Verifier{
		ClusterID:   clusterName,
		STSEndpoint: s.stsEndpoint,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	awsIdentity, err := verifier.Verify(ctx, review.Spec.Token)
	if err != nil {
		// A malformed token is routine, not exceptional: the API server sends
		// every unrecognised bearer token here, including service-account tokens
		// that earlier authenticators already declined. Logging these at error
		// level would bury real problems.
		var formatErr token.FormatError
		if errors.As(err, &formatErr) {
			s.log.Debug("rejecting token", "cluster", clusterName, "reason", err)
		} else {
			s.log.Warn("token verification failed", "cluster", clusterName, "error", err)
		}
		s.denyToken(w, review, err.Error())
		return
	}

	awsAuth := s.loadAWSAuth(ctx, clusterName)
	kubeIdentity, err := state.Resolver(awsAuth).Resolve(awsIdentity)
	if err != nil {
		// The caller proved who they are but has no route into the cluster.
		// Surfacing the ARN here is what turns an opaque 403 into a fixable one.
		s.log.Info("authenticated principal is not mapped into the cluster",
			"cluster", clusterName, "arn", awsIdentity.CanonicalARN)
		s.denyToken(w, review, err.Error())
		return
	}

	s.log.Debug("authenticated principal",
		"cluster", clusterName,
		"arn", awsIdentity.CanonicalARN,
		"username", kubeIdentity.Username,
		"groups", kubeIdentity.Groups,
		"via", kubeIdentity.Source)

	writeJSON(w, http.StatusOK, newTokenReviewResponse(tokenReviewStatus{
		Authenticated: true,
		Audiences:     review.Spec.Audiences,
		User: &userInfo{
			Username: kubeIdentity.Username,
			UID:      kubeIdentity.UID,
			Groups:   kubeIdentity.Groups,
			Extra: map[string][]string{
				// Mirrors the attributes real EKS attaches, which show up in
				// audit logs and can be matched by admission policy.
				"arn":          {awsIdentity.ARN},
				"canonicalArn": {awsIdentity.CanonicalARN},
				"accountId":    {awsIdentity.AccountID},
				"sessionName":  {awsIdentity.SessionName},
				// eksuvia-only: which mechanism granted the mapping.
				"eksuvia.dev/source": {kubeIdentity.Source},
			},
		},
	}))
}

// denyToken returns an unauthenticated TokenReview.
//
// The HTTP status stays 200: a webhook that returns non-2xx is treated by the
// API server as broken rather than as a denial, and it will fail the request
// with a server error instead of a clean 401.
func (s *Server) denyToken(w http.ResponseWriter, review tokenReview, reason string) {
	writeJSON(w, http.StatusOK, newTokenReviewResponse(tokenReviewStatus{
		Authenticated: false,
		Audiences:     review.Spec.Audiences,
		Error:         reason,
	}))
}

// loadAWSAuth reads and caches the aws-auth ConfigMap for a cluster.
//
// Reading from the API server during a TokenReview looks like a deadlock risk,
// but is not: eksuvia's client authenticates with an admin client certificate,
// which the x509 authenticator handles without ever consulting this webhook.
func (s *Server) loadAWSAuth(ctx context.Context, cluster string) *identity.AWSAuth {
	if cached, ok := awsAuthCache.Load(cluster); ok {
		entry := cached.(awsAuthCacheEntry)
		if time.Since(entry.fetched) < awsAuthCacheTTL {
			return entry.parsed
		}
	}

	client, err := s.clientFor(cluster)
	if err != nil {
		return nil
	}
	data, err := client.GetConfigMap(ctx, model.AWSAuthConfigMapNS, model.AWSAuthConfigMapName)
	if err != nil {
		s.log.Debug("could not read aws-auth", "cluster", cluster, "error", err)
		return nil
	}
	if data == nil {
		awsAuthCache.Store(cluster, awsAuthCacheEntry{parsed: nil, fetched: time.Now()})
		return nil
	}

	parsed, err := identity.ParseAWSAuth(data)
	if err != nil {
		// A malformed ConfigMap locks people out of real clusters too, so the
		// failure is preserved -- but it is worth shouting about locally.
		s.log.Warn("aws-auth ConfigMap is malformed and will be ignored", "cluster", cluster, "error", err)
		return nil
	}

	awsAuthCache.Store(cluster, awsAuthCacheEntry{parsed: parsed, fetched: time.Now()})
	return parsed
}
