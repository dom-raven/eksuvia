package identity

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/dom-raven/eksuvia/internal/model"
)

// accessPolicyRole maps an AWS-managed cluster access policy to the built-in
// Kubernetes ClusterRole it is defined to be equivalent to.
//
// AWS documents these equivalences explicitly, which is what makes access
// entries emulable at all: EKS is not running bespoke authorization logic, it
// is creating ordinary RBAC bindings against roles that ship with Kubernetes.
var accessPolicyRole = map[string]string{
	model.ClusterAdminPolicyARN: model.ClusterAdminPolicyRole,
	model.AdminPolicyARN:        model.NamespacedAdminRole,
	model.EditPolicyARN:         model.NamespacedEditRole,
	model.ViewPolicyARN:         model.NamespacedViewRole,
	// AmazonEKSAdminViewPolicy extends view with read access to resources that
	// hold secrets material. There is no single built-in equivalent, so it is
	// approximated by view; see docs/fidelity.md.
	model.AdminViewPolicyARN: model.NamespacedViewRole,
}

// KnownAccessPolicies returns the AWS-managed policies ListAccessPolicies
// advertises, in a stable order.
func KnownAccessPolicies() []model.AccessPolicy {
	arns := make([]string, 0, len(accessPolicyRole))
	for arn := range accessPolicyRole {
		arns = append(arns, arn)
	}
	sort.Strings(arns)

	out := make([]model.AccessPolicy, 0, len(arns))
	for _, arn := range arns {
		name := arn
		if i := strings.LastIndex(arn, "/"); i >= 0 {
			name = arn[i+1:]
		}
		out = append(out, model.AccessPolicy{Name: name, ARN: arn})
	}
	return out
}

// IsKnownAccessPolicy reports whether an access policy ARN is one AWS defines.
func IsKnownAccessPolicy(arn string) bool {
	_, ok := accessPolicyRole[arn]
	return ok
}

// RBACBinding is a ClusterRoleBinding or RoleBinding that must exist in the
// cluster to enforce one associated access policy.
type RBACBinding struct {
	// Name is deterministic, so reconciling twice is idempotent.
	Name string
	// Namespace is empty for a ClusterRoleBinding.
	Namespace string
	// RoleRef is the built-in ClusterRole being bound.
	RoleRef string
	// Subject is the Kubernetes username the access entry resolves to.
	Subject string
}

// ClusterScoped reports whether this binding is cluster-wide.
func (b RBACBinding) ClusterScoped() bool { return b.Namespace == "" }

// BindingsFor computes every RBAC object implied by one access entry.
//
// A cluster-scoped policy yields a single ClusterRoleBinding. A namespace-scoped
// policy yields one RoleBinding per named namespace. This mirrors what EKS
// materialises in the cluster, which is why `kubectl auth can-i` gives honest
// answers against eksuvia rather than optimistic ones.
//
// Note the deliberate gap: EKS resolves namespace wildcards (test*) at
// authorization time inside its own admission path, whereas RBAC RoleBindings
// require concrete namespaces. Wildcards are expanded against the namespaces
// that exist at reconcile time and re-expanded when namespaces change; a
// namespace created later is picked up on the next reconcile, not instantly.
func BindingsFor(entry *model.AccessEntry, username string, existingNamespaces []string) []RBACBinding {
	var out []RBACBinding

	for _, policy := range entry.Policies {
		role, ok := accessPolicyRole[policy.PolicyARN]
		if !ok {
			continue
		}

		if policy.AccessScope.Type == model.AccessScopeCluster {
			out = append(out, RBACBinding{
				Name:    bindingName(entry.PrincipalARN, policy.PolicyARN, ""),
				RoleRef: role,
				Subject: username,
			})
			continue
		}

		for _, ns := range expandNamespaces(policy.AccessScope.Namespaces, existingNamespaces) {
			out = append(out, RBACBinding{
				Name:      bindingName(entry.PrincipalARN, policy.PolicyARN, ns),
				Namespace: ns,
				RoleRef:   role,
				Subject:   username,
			})
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// expandNamespaces resolves the namespace patterns on an access scope against
// the namespaces that currently exist. Patterns support a trailing *, which is
// the only wildcard form EKS accepts.
func expandNamespaces(patterns, existing []string) []string {
	seen := map[string]bool{}
	var out []string

	for _, pattern := range patterns {
		if !strings.Contains(pattern, "*") {
			if !seen[pattern] {
				seen[pattern] = true
				out = append(out, pattern)
			}
			continue
		}
		prefix := strings.TrimSuffix(pattern, "*")
		for _, ns := range existing {
			if strings.HasPrefix(ns, prefix) && !seen[ns] {
				seen[ns] = true
				out = append(out, ns)
			}
		}
	}
	sort.Strings(out)
	return out
}

// bindingName derives a stable, DNS-safe name for a generated binding.
//
// Principal ARNs contain characters RBAC object names forbid, and can exceed
// the 253-character limit, so the identifying parts are hashed. The eksuvia-
// prefix makes generated objects obvious in `kubectl get clusterrolebindings`
// and lets the reconciler safely delete what it owns.
func bindingName(principalARN, policyARN, namespace string) string {
	sum := sha1.Sum([]byte(principalARN + "|" + policyARN + "|" + namespace))
	policyName := policyARN
	if i := strings.LastIndex(policyARN, "/"); i >= 0 {
		policyName = policyARN[i+1:]
	}
	return fmt.Sprintf("eksuvia-%s-%s", strings.ToLower(policyName), hex.EncodeToString(sum[:])[:10])
}
