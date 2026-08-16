package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/dom-raven/eksuvia/internal/awsarn"
	"github.com/dom-raven/eksuvia/internal/identity"
	"github.com/dom-raven/eksuvia/internal/kube"
	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/store"
)

// ownerLabel marks RBAC objects eksuvia generates, so reconciliation can
// safely delete what it owns and nothing else.
const ownerLabel = "eksuvia.dev/managed-by"

type createAccessEntryRequest struct {
	PrincipalARN     string            `json:"principalArn"`
	KubernetesGroups []string          `json:"kubernetesGroups"`
	Tags             map[string]string `json:"tags"`
	Username         string            `json:"username"`
	Type             string            `json:"type"`
}

func (s *Server) handleCreateAccessEntry(w http.ResponseWriter, r *http.Request, p Params) {
	state, err := s.store.Get(p["name"])
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req createAccessEntryRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.PrincipalARN == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter, "principalArn is required.")
		return
	}

	// Access entries are stored under the canonical ARN so that a caller
	// arriving as an assumed-role session resolves to the entry created for the
	// underlying role -- which is how people actually write them.
	canonical, err := awsarn.Canonicalize(req.PrincipalARN)
	if err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			fmt.Sprintf("The principal ARN %q is not valid: %v", req.PrincipalARN, err))
		return
	}

	if _, exists := state.AccessEntries[canonical]; exists {
		writeError(w, http.StatusConflict, ErrResourceInUse,
			fmt.Sprintf("An access entry for principal %q already exists.", req.PrincipalARN))
		return
	}

	entryType := req.Type
	if entryType == "" {
		entryType = model.AccessEntryTypeStandard
	}
	username := req.Username
	if username == "" {
		username = req.PrincipalARN
	}

	now := model.UnixMillisFloat(time.Now())
	entry := &model.AccessEntry{
		ClusterName:      state.Cluster.Name,
		PrincipalARN:     req.PrincipalARN,
		KubernetesGroups: req.KubernetesGroups,
		AccessEntryARN:   s.accessEntryARN(state.Cluster.Name, req.PrincipalARN),
		CreatedAt:        now,
		ModifiedAt:       now,
		Tags:             req.Tags,
		Username:         username,
		Type:             entryType,
	}

	if err := s.store.Update(state.Cluster.Name, func(c *store.ClusterState) {
		c.AccessEntries[canonical] = entry
	}); err != nil {
		writeStoreError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"accessEntry": entry})
}

func (s *Server) handleListAccessEntries(w http.ResponseWriter, r *http.Request, p Params) {
	state, err := s.store.Get(p["name"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	arns := make([]string, 0, len(state.AccessEntries))
	for _, entry := range state.AccessEntries {
		arns = append(arns, entry.PrincipalARN)
	}
	sort.Strings(arns)
	writeJSON(w, http.StatusOK, map[string]any{"accessEntries": arns})
}

func (s *Server) handleDescribeAccessEntry(w http.ResponseWriter, r *http.Request, p Params) {
	entry, _, err := s.lookupAccessEntry(p["name"], p["principal"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if entry == nil {
		writeError(w, http.StatusNotFound, ErrResourceNotFound,
			fmt.Sprintf("No access entry found for principal %q.", p["principal"]))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accessEntry": entry})
}

func (s *Server) handleDeleteAccessEntry(w http.ResponseWriter, r *http.Request, p Params) {
	entry, canonical, err := s.lookupAccessEntry(p["name"], p["principal"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if entry == nil {
		writeError(w, http.StatusNotFound, ErrResourceNotFound,
			fmt.Sprintf("No access entry found for principal %q.", p["principal"]))
		return
	}

	if err := s.store.Update(p["name"], func(c *store.ClusterState) {
		delete(c.AccessEntries, canonical)
	}); err != nil {
		writeStoreError(w, err)
		return
	}

	// Revoking access must also remove the RBAC bindings, or the principal
	// keeps working until the cluster is recreated.
	if client, err := s.clientFor(p["name"]); err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := s.deleteBindingsFor(ctx, client, entry); err != nil {
			s.log.Warn("could not remove RBAC bindings for deleted access entry",
				"cluster", p["name"], "principal", entry.PrincipalARN, "error", err)
		}
	}

	w.WriteHeader(http.StatusOK)
}

type associateAccessPolicyRequest struct {
	PolicyARN   string             `json:"policyArn"`
	AccessScope *model.AccessScope `json:"accessScope"`
}

func (s *Server) handleAssociateAccessPolicy(w http.ResponseWriter, r *http.Request, p Params) {
	entry, canonical, err := s.lookupAccessEntry(p["name"], p["principal"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if entry == nil {
		writeError(w, http.StatusNotFound, ErrResourceNotFound,
			fmt.Sprintf("No access entry found for principal %q.", p["principal"]))
		return
	}

	var req associateAccessPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !identity.IsKnownAccessPolicy(req.PolicyARN) {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			fmt.Sprintf("The access policy %q is not a recognised Amazon EKS access policy.", req.PolicyARN))
		return
	}
	scope := model.AccessScope{Type: model.AccessScopeCluster}
	if req.AccessScope != nil {
		scope = *req.AccessScope
	}
	if scope.Type == model.AccessScopeNamespace && len(scope.Namespaces) == 0 {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			"A namespace-scoped access policy requires at least one namespace.")
		return
	}

	now := model.UnixMillisFloat(time.Now())
	policy := model.AssociatedAccessPolicy{
		PolicyARN:    req.PolicyARN,
		AccessScope:  scope,
		AssociatedAt: now,
		ModifiedAt:   now,
	}

	if err := s.store.Update(p["name"], func(c *store.ClusterState) {
		target := c.AccessEntries[canonical]
		if target == nil {
			return
		}
		// Re-associating the same policy updates its scope rather than
		// duplicating it, matching the real API's upsert behaviour.
		for i := range target.Policies {
			if target.Policies[i].PolicyARN == req.PolicyARN {
				target.Policies[i].AccessScope = scope
				target.Policies[i].ModifiedAt = now
				return
			}
		}
		target.Policies = append(target.Policies, policy)
		target.ModifiedAt = now
	}); err != nil {
		writeStoreError(w, err)
		return
	}

	// Reconcile immediately so the grant is live by the time the call returns.
	if client, err := s.clientFor(p["name"]); err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := s.reconcileAccessEntry(ctx, client, entry); err != nil {
			s.log.Warn("could not reconcile RBAC for access policy",
				"cluster", p["name"], "principal", entry.PrincipalARN, "error", err)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"clusterName":            p["name"],
		"principalArn":           entry.PrincipalARN,
		"associatedAccessPolicy": policy,
	})
}

func (s *Server) handleListAssociatedAccessPolicies(w http.ResponseWriter, r *http.Request, p Params) {
	entry, _, err := s.lookupAccessEntry(p["name"], p["principal"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if entry == nil {
		writeError(w, http.StatusNotFound, ErrResourceNotFound,
			fmt.Sprintf("No access entry found for principal %q.", p["principal"]))
		return
	}
	policies := entry.Policies
	if policies == nil {
		policies = []model.AssociatedAccessPolicy{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"clusterName":              p["name"],
		"principalArn":             entry.PrincipalARN,
		"associatedAccessPolicies": policies,
	})
}

func (s *Server) handleDisassociateAccessPolicy(w http.ResponseWriter, r *http.Request, p Params) {
	entry, canonical, err := s.lookupAccessEntry(p["name"], p["principal"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if entry == nil {
		writeError(w, http.StatusNotFound, ErrResourceNotFound,
			fmt.Sprintf("No access entry found for principal %q.", p["principal"]))
		return
	}

	// Bindings are computed from the entry's policy list, so the old bindings
	// must be removed before the list changes -- otherwise the removed policy's
	// binding is no longer derivable and would be orphaned in the cluster.
	if client, err := s.clientFor(p["name"]); err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := s.deleteBindingsFor(ctx, client, entry); err != nil {
			s.log.Warn("could not remove RBAC bindings", "cluster", p["name"], "error", err)
		}
	}

	if err := s.store.Update(p["name"], func(c *store.ClusterState) {
		target := c.AccessEntries[canonical]
		if target == nil {
			return
		}
		kept := target.Policies[:0]
		for _, policy := range target.Policies {
			if policy.PolicyARN != p["policy"] {
				kept = append(kept, policy)
			}
		}
		target.Policies = kept
		target.ModifiedAt = model.UnixMillisFloat(time.Now())
	}); err != nil {
		writeStoreError(w, err)
		return
	}

	// Re-apply whatever survived.
	if client, err := s.clientFor(p["name"]); err == nil {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if updated, _, err := s.lookupAccessEntry(p["name"], p["principal"]); err == nil && updated != nil {
			if err := s.reconcileAccessEntry(ctx, client, updated); err != nil {
				s.log.Warn("could not reconcile RBAC after disassociate", "cluster", p["name"], "error", err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleListAccessPolicies(w http.ResponseWriter, r *http.Request, _ Params) {
	writeJSON(w, http.StatusOK, map[string]any{"accessPolicies": identity.KnownAccessPolicies()})
}

// lookupAccessEntry resolves an access entry by principal ARN, tolerating both
// the raw and canonical forms.
func (s *Server) lookupAccessEntry(cluster, principal string) (*model.AccessEntry, string, error) {
	state, err := s.store.Get(cluster)
	if err != nil {
		return nil, "", err
	}
	canonical, cErr := awsarn.Canonicalize(principal)
	if cErr != nil {
		canonical = principal
	}
	if entry, ok := state.AccessEntries[canonical]; ok {
		return entry, canonical, nil
	}
	if entry, ok := state.AccessEntries[principal]; ok {
		return entry, principal, nil
	}
	return nil, canonical, nil
}

// clientFor returns a Kubernetes client for a provisioned cluster.
func (s *Server) clientFor(cluster string) (*kube.Client, error) {
	state, err := s.store.Get(cluster)
	if err != nil {
		return nil, err
	}
	if len(state.Kubeconfig) == 0 {
		return nil, fmt.Errorf("cluster %q is not ready yet", cluster)
	}
	return kube.NewFromKubeconfig(state.Kubeconfig)
}

// reconcileAccessEntry materialises the RBAC objects implied by one access
// entry's associated policies.
//
// This is the step that makes access policies real. EKS does the same thing
// inside its hidden control plane: an access policy is not a bespoke
// authorization engine, it is a binding to a built-in ClusterRole.
func (s *Server) reconcileAccessEntry(ctx context.Context, client *kube.Client, entry *model.AccessEntry) error {
	username := entry.Username
	if username == "" {
		username = entry.PrincipalARN
	}

	var namespaces []string
	if needsNamespaces(entry) {
		var err error
		namespaces, err = client.ListNamespaceNames(ctx)
		if err != nil {
			return fmt.Errorf("listing namespaces: %w", err)
		}
	}

	labels := map[string]string{ownerLabel: "eksuvia"}
	for _, binding := range identity.BindingsFor(entry, username, namespaces) {
		var err error
		if binding.ClusterScoped() {
			err = client.ApplyClusterRoleBinding(ctx, binding.Name, binding.RoleRef, binding.Subject, labels)
		} else {
			err = client.ApplyRoleBinding(ctx, binding.Namespace, binding.Name, binding.RoleRef, binding.Subject, labels)
		}
		if err != nil {
			return fmt.Errorf("applying binding %s: %w", binding.Name, err)
		}
	}
	return nil
}

// deleteBindingsFor removes the RBAC objects generated for an access entry.
func (s *Server) deleteBindingsFor(ctx context.Context, client *kube.Client, entry *model.AccessEntry) error {
	username := entry.Username
	if username == "" {
		username = entry.PrincipalARN
	}
	var namespaces []string
	if needsNamespaces(entry) {
		namespaces, _ = client.ListNamespaceNames(ctx)
	}
	for _, binding := range identity.BindingsFor(entry, username, namespaces) {
		path := "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/" + binding.Name
		if !binding.ClusterScoped() {
			path = fmt.Sprintf("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings/%s", binding.Namespace, binding.Name)
		}
		if err := client.Do(ctx, http.MethodDelete, path, nil, "", nil); err != nil && !kube.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func needsNamespaces(entry *model.AccessEntry) bool {
	for _, policy := range entry.Policies {
		if policy.AccessScope.Type == model.AccessScopeNamespace {
			return true
		}
	}
	return false
}
