package identity

import (
	"strings"
	"testing"

	"github.com/dom-raven/eksuvia/internal/model"
)

func TestBindingsForClusterScopedPolicy(t *testing.T) {
	entry := &model.AccessEntry{
		PrincipalARN: "arn:aws:iam::000000000000:role/Admin",
		Policies: []model.AssociatedAccessPolicy{{
			PolicyARN:   model.ClusterAdminPolicyARN,
			AccessScope: model.AccessScope{Type: model.AccessScopeCluster},
		}},
	}

	bindings := BindingsFor(entry, "alice", nil)
	if len(bindings) != 1 {
		t.Fatalf("got %d bindings, want 1", len(bindings))
	}
	b := bindings[0]
	if !b.ClusterScoped() {
		t.Error("expected a cluster-scoped binding")
	}
	if b.RoleRef != model.ClusterAdminPolicyRole {
		t.Errorf("RoleRef = %q, want %q", b.RoleRef, model.ClusterAdminPolicyRole)
	}
	if b.Subject != "alice" {
		t.Errorf("Subject = %q, want alice", b.Subject)
	}
}

func TestBindingsForNamespaceScopedPolicy(t *testing.T) {
	entry := &model.AccessEntry{
		PrincipalARN: "arn:aws:iam::000000000000:role/Dev",
		Policies: []model.AssociatedAccessPolicy{{
			PolicyARN: model.EditPolicyARN,
			AccessScope: model.AccessScope{
				Type:       model.AccessScopeNamespace,
				Namespaces: []string{"team-a", "team-b"},
			},
		}},
	}

	bindings := BindingsFor(entry, "dev", nil)
	if len(bindings) != 2 {
		t.Fatalf("got %d bindings, want one per namespace", len(bindings))
	}
	for _, b := range bindings {
		if b.ClusterScoped() {
			t.Errorf("binding %q should be namespaced", b.Name)
		}
		if b.RoleRef != model.NamespacedEditRole {
			t.Errorf("RoleRef = %q, want edit", b.RoleRef)
		}
	}
}

func TestBindingsExpandNamespaceWildcards(t *testing.T) {
	entry := &model.AccessEntry{
		PrincipalARN: "arn:aws:iam::000000000000:role/Dev",
		Policies: []model.AssociatedAccessPolicy{{
			PolicyARN: model.ViewPolicyARN,
			AccessScope: model.AccessScope{
				Type:       model.AccessScopeNamespace,
				Namespaces: []string{"team-*"},
			},
		}},
	}

	existing := []string{"default", "kube-system", "team-a", "team-b", "other"}
	bindings := BindingsFor(entry, "dev", existing)
	if len(bindings) != 2 {
		t.Fatalf("got %d bindings, want 2 matching namespaces", len(bindings))
	}
	for _, b := range bindings {
		if !strings.HasPrefix(b.Namespace, "team-") {
			t.Errorf("wildcard matched unexpected namespace %q", b.Namespace)
		}
	}
}

func TestBindingNamesAreStableAndDNSSafe(t *testing.T) {
	entry := &model.AccessEntry{
		PrincipalARN: "arn:aws:iam::000000000000:role/some/deep/path/Admin",
		Policies: []model.AssociatedAccessPolicy{{
			PolicyARN:   model.ClusterAdminPolicyARN,
			AccessScope: model.AccessScope{Type: model.AccessScopeCluster},
		}},
	}

	first := BindingsFor(entry, "alice", nil)
	second := BindingsFor(entry, "alice", nil)
	if first[0].Name != second[0].Name {
		t.Error("binding names must be stable so reconciliation is idempotent")
	}

	name := first[0].Name
	if !strings.HasPrefix(name, "eksuvia-") {
		t.Errorf("name %q should be identifiable as eksuvia-generated", name)
	}
	// ARNs contain colons and slashes, which RBAC object names forbid.
	if strings.ContainsAny(name, ":/_") || strings.ToLower(name) != name {
		t.Errorf("name %q is not a valid Kubernetes object name", name)
	}
	if len(name) > 253 {
		t.Errorf("name %q exceeds the Kubernetes name length limit", name)
	}
}

func TestBindingNamesDifferPerPolicyAndNamespace(t *testing.T) {
	entry := &model.AccessEntry{
		PrincipalARN: "arn:aws:iam::000000000000:role/Dev",
		Policies: []model.AssociatedAccessPolicy{
			{PolicyARN: model.ViewPolicyARN, AccessScope: model.AccessScope{
				Type: model.AccessScopeNamespace, Namespaces: []string{"a", "b"}}},
			{PolicyARN: model.EditPolicyARN, AccessScope: model.AccessScope{
				Type: model.AccessScopeNamespace, Namespaces: []string{"a"}}},
		},
	}

	seen := map[string]bool{}
	for _, b := range BindingsFor(entry, "dev", nil) {
		if seen[b.Name] {
			t.Fatalf("duplicate binding name %q would silently overwrite a grant", b.Name)
		}
		seen[b.Name] = true
	}
	if len(seen) != 3 {
		t.Errorf("got %d distinct bindings, want 3", len(seen))
	}
}

func TestUnknownPolicyProducesNoBindings(t *testing.T) {
	entry := &model.AccessEntry{
		PrincipalARN: "arn:aws:iam::000000000000:role/Admin",
		Policies: []model.AssociatedAccessPolicy{{
			PolicyARN:   "arn:aws:eks::aws:cluster-access-policy/NotARealPolicy",
			AccessScope: model.AccessScope{Type: model.AccessScopeCluster},
		}},
	}
	if got := BindingsFor(entry, "alice", nil); len(got) != 0 {
		t.Errorf("got %d bindings for an unknown policy, want 0", len(got))
	}
}

func TestKnownAccessPolicies(t *testing.T) {
	policies := KnownAccessPolicies()
	if len(policies) == 0 {
		t.Fatal("expected the AWS-managed access policies to be advertised")
	}

	var foundClusterAdmin bool
	for _, p := range policies {
		if p.ARN == model.ClusterAdminPolicyARN {
			foundClusterAdmin = true
			if p.Name != "AmazonEKSClusterAdminPolicy" {
				t.Errorf("Name = %q, want AmazonEKSClusterAdminPolicy", p.Name)
			}
		}
		if !IsKnownAccessPolicy(p.ARN) {
			t.Errorf("IsKnownAccessPolicy(%q) = false", p.ARN)
		}
	}
	if !foundClusterAdmin {
		t.Error("AmazonEKSClusterAdminPolicy missing from the advertised set")
	}
	if IsKnownAccessPolicy("arn:aws:eks::aws:cluster-access-policy/Nope") {
		t.Error("IsKnownAccessPolicy accepted an unknown policy")
	}
}
