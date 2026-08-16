package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/dom-raven/eksuvia/internal/awsarn"
	"github.com/dom-raven/eksuvia/internal/config"
	"github.com/dom-raven/eksuvia/internal/kindprov"
	"github.com/dom-raven/eksuvia/internal/oidc"
	"github.com/dom-raven/eksuvia/internal/proxy"
	"github.com/dom-raven/eksuvia/internal/store"
)

// Server is the eksuvia HTTP surface: the EKS control plane API, the
// TokenReview webhook the emulated API servers call back into, the per-cluster
// OIDC discovery endpoints, and a proxy for everything else.
type Server struct {
	cfg    config.Config
	store  *store.Store
	kind   *kindprov.Provisioner
	log    *slog.Logger
	router *Router

	// stsEndpoint is where presigned GetCallerIdentity URLs are dereferenced.
	stsEndpoint *url.URL

	// issuerIndex maps an OIDC issuer ID back to its cluster, so the discovery
	// endpoints can be served from a flat path.
	issuerIndex sync.Map // string -> string (issuerID -> cluster name)

	// createMu serialises cluster creation. kind writes to a shared kubeconfig
	// and pulls node images; concurrent creates are a reliable way to produce
	// half-built clusters.
	createMu sync.Mutex
}

// NewServer wires up the routes.
func NewServer(cfg config.Config, st *store.Store, kp *kindprov.Provisioner, logger *slog.Logger) (*Server, error) {
	stsEndpoint, err := url.Parse(cfg.FlociEndpoint)
	if err != nil {
		return nil, fmt.Errorf("api: parsing floci endpoint: %w", err)
	}

	s := &Server{
		cfg:         cfg,
		store:       st,
		kind:        kp,
		log:         logger,
		router:      NewRouter(),
		stsEndpoint: stsEndpoint,
	}

	fallback, err := proxy.New(cfg.FlociEndpoint, logger)
	if err != nil {
		return nil, err
	}
	s.router.Fallback(fallback)
	s.registerRoutes()
	return s, nil
}

func (s *Server) registerRoutes() {
	r := s.router

	// --- EKS control plane (restJson1) ---
	r.Handle(http.MethodPost, "/clusters", s.handleCreateCluster)
	r.Handle(http.MethodGet, "/clusters", s.handleListClusters)
	r.Handle(http.MethodGet, "/clusters/:name", s.handleDescribeCluster)
	r.Handle(http.MethodDelete, "/clusters/:name", s.handleDeleteCluster)

	r.Handle(http.MethodPost, "/clusters/:name/node-groups", s.handleCreateNodegroup)
	r.Handle(http.MethodGet, "/clusters/:name/node-groups", s.handleListNodegroups)
	r.Handle(http.MethodGet, "/clusters/:name/node-groups/:nodegroup", s.handleDescribeNodegroup)
	r.Handle(http.MethodDelete, "/clusters/:name/node-groups/:nodegroup", s.handleDeleteNodegroup)

	r.Handle(http.MethodPost, "/clusters/:name/addons", s.handleCreateAddon)
	r.Handle(http.MethodGet, "/clusters/:name/addons", s.handleListAddons)
	r.Handle(http.MethodGet, "/clusters/:name/addons/:addon", s.handleDescribeAddon)
	r.Handle(http.MethodDelete, "/clusters/:name/addons/:addon", s.handleDeleteAddon)
	r.Handle(http.MethodGet, "/addons/supported-versions", s.handleDescribeAddonVersions)

	// Access entries. The principal ARN arrives URL-encoded as one segment.
	r.Handle(http.MethodPost, "/clusters/:name/access-entries", s.handleCreateAccessEntry)
	r.Handle(http.MethodGet, "/clusters/:name/access-entries", s.handleListAccessEntries)
	r.Handle(http.MethodGet, "/clusters/:name/access-entries/:principal", s.handleDescribeAccessEntry)
	r.Handle(http.MethodDelete, "/clusters/:name/access-entries/:principal", s.handleDeleteAccessEntry)
	r.Handle(http.MethodPost, "/clusters/:name/access-entries/:principal/access-policies", s.handleAssociateAccessPolicy)
	r.Handle(http.MethodGet, "/clusters/:name/access-entries/:principal/access-policies", s.handleListAssociatedAccessPolicies)
	r.Handle(http.MethodDelete, "/clusters/:name/access-entries/:principal/access-policies/:policy", s.handleDisassociateAccessPolicy)
	r.Handle(http.MethodGet, "/access-policies", s.handleListAccessPolicies)

	// --- eksuvia internals ---
	// The TokenReview webhook each emulated API server calls to authenticate
	// bearer tokens. Namespaced by cluster so a token cannot cross clusters.
	r.Handle(http.MethodPost, "/_eksuvia/webhook/:cluster", s.handleTokenReview)
	// Per-cluster OIDC provider backing IRSA.
	r.Handle(http.MethodGet, "/id/:issuer/.well-known/openid-configuration", s.handleOIDCDiscovery)
	r.Handle(http.MethodGet, "/id/:issuer/keys", s.handleOIDCKeys)
	// Operational endpoints.
	r.Handle(http.MethodGet, "/_eksuvia/health", s.handleHealth)
	r.Handle(http.MethodPost, "/_eksuvia/clusters/:name/irsa-token", s.handleMintIRSAToken)
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.logRequests(s.router)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.log.Debug("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, _ Params) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"clusters": s.store.Names(),
		"upstream": s.cfg.FlociEndpoint,
	})
}

// clusterARN builds the ARN for a cluster.
func (s *Server) clusterARN(name string) string {
	return fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", s.cfg.Region, s.cfg.AccountID, name)
}

func (s *Server) nodegroupARN(cluster, nodegroup, id string) string {
	return fmt.Sprintf("arn:aws:eks:%s:%s:nodegroup/%s/%s/%s", s.cfg.Region, s.cfg.AccountID, cluster, nodegroup, id)
}

// accessEntryARN builds the ARN for an access entry.
//
// The principal ARN cannot be embedded verbatim: it contains colons, and
// nesting one ARN inside another produces a string no ARN parser can read. Real
// EKS decomposes it instead, as
// access-entry/<cluster>/<resource-type>/<account>/<name>/<id>, and so does
// this.
func (s *Server) accessEntryARN(cluster, principal string) string {
	resourceType, name, account := "role", principal, s.cfg.AccountID
	if parsed, err := awsarn.Parse(principal); err == nil {
		account = parsed.AccountID
		parts := strings.SplitN(parsed.Resource, "/", 2)
		resourceType = parts[0]
		if len(parts) == 2 {
			// Only the final segment is the principal's name; IAM paths are
			// dropped, matching how the console renders these.
			segments := strings.Split(parts[1], "/")
			name = segments[len(segments)-1]
		} else {
			name = parts[0] // e.g. "root", which has no name component
		}
	}
	id := strings.ToLower(oidc.IssuerID(cluster+principal, s.cfg.AccountID)[:16])
	return fmt.Sprintf("arn:aws:eks:%s:%s:access-entry/%s/%s/%s/%s/%s",
		s.cfg.Region, s.cfg.AccountID, cluster, resourceType, account, name, id)
}
