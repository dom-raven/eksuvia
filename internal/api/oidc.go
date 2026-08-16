package api

import (
	"net/http"
	"time"

	"github.com/dom-raven/eksuvia/internal/oidc"
)

// handleOIDCDiscovery serves a cluster's OpenID Connect discovery document.
//
// Unlike an emulator that treats the issuer URL as a decorative string, this
// endpoint is genuinely dereferenced: STS fetches it, follows jwks_uri, and
// verifies the signature on a projected service-account token before issuing
// credentials. That is what allows an unmodified AWS SDK inside a pod to
// complete AssumeRoleWithWebIdentity against a local cluster.
func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request, p Params) {
	signer := s.signerForIssuer(p["issuer"])
	if signer == nil {
		writeError(w, http.StatusNotFound, ErrResourceNotFound, "no such OIDC issuer")
		return
	}
	// Discovery documents are cacheable; STS will re-fetch on key rotation.
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, signer.Discovery())
}

// handleOIDCKeys serves the JWKS containing a cluster's public signing key.
func (s *Server) handleOIDCKeys(w http.ResponseWriter, r *http.Request, p Params) {
	signer := s.signerForIssuer(p["issuer"])
	if signer == nil {
		writeError(w, http.StatusNotFound, ErrResourceNotFound, "no such OIDC issuer")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, signer.JWKS())
}

// signerForIssuer resolves an issuer ID to the owning cluster's signer.
func (s *Server) signerForIssuer(issuerID string) *oidc.Signer {
	name, ok := s.issuerIndex.Load(issuerID)
	if !ok {
		return nil
	}
	state, err := s.store.Get(name.(string))
	if err != nil {
		return nil
	}
	return state.Signer
}

type mintIRSATokenRequest struct {
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
	Audience       string `json:"audience"`
	ExpirySeconds  int    `json:"expirySeconds"`
}

// handleMintIRSAToken issues a service-account token out of band.
//
// This is not an AWS API and is namespaced under /_eksuvia to make that
// obvious. It exists because the useful local workflow -- test an IAM trust
// policy without first deploying a pod -- has no equivalent on real EKS. The
// normal in-pod path does not touch this endpoint: there, the kubelet projects
// a token signed by the same key.
func (s *Server) handleMintIRSAToken(w http.ResponseWriter, r *http.Request, p Params) {
	state, err := s.store.Get(p["name"])
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req mintIRSATokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Namespace == "" || req.ServiceAccount == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			"namespace and serviceAccount are required")
		return
	}

	ttl := time.Duration(req.ExpirySeconds) * time.Second
	if req.ExpirySeconds == 0 {
		ttl = 24 * time.Hour
	}
	if ttl > 7*24*time.Hour {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			"expirySeconds cannot exceed 7 days")
		return
	}

	audience := req.Audience
	if audience == "" {
		audience = oidc.DefaultAudience
	}

	tok, err := state.Signer.MintServiceAccountToken(req.Namespace, req.ServiceAccount, audience, ttl)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrServerException, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":    tok,
		"issuer":   state.Signer.Issuer,
		"subject":  "system:serviceaccount:" + req.Namespace + ":" + req.ServiceAccount,
		"audience": audience,
	})
}
