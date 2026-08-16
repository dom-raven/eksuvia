package identity

import (
	"testing"

	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/token"
)

func adminSession() *token.Identity {
	return &token.Identity{
		ARN:          "arn:aws:sts::000000000000:assumed-role/Admin/alice",
		CanonicalARN: "arn:aws:iam::000000000000:role/Admin",
		AccountID:    "000000000000",
		UserID:       "AROAEXAMPLE:alice",
		SessionName:  "alice",
	}
}

func entryFor(arn, username string, groups ...string) map[string]*model.AccessEntry {
	return map[string]*model.AccessEntry{
		arn: {
			PrincipalARN:     arn,
			Username:         username,
			KubernetesGroups: groups,
			Type:             model.AccessEntryTypeStandard,
		},
	}
}

func TestResolveFromAccessEntry(t *testing.T) {
	r := &Resolver{
		AuthenticationMode: model.AuthModeAPI,
		AccessEntries:      entryFor("arn:aws:iam::000000000000:role/Admin", "alice", "platform-team"),
	}

	got, err := r.Resolve(adminSession())
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}
	if got.Username != "alice" {
		t.Errorf("Username = %q, want alice", got.Username)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "platform-team" {
		t.Errorf("Groups = %v, want [platform-team]", got.Groups)
	}
	if got.Source != SourceAccessEntry {
		t.Errorf("Source = %q, want %q", got.Source, SourceAccessEntry)
	}
}

func TestResolveAccessEntryDefaultsUsernameToPrincipal(t *testing.T) {
	r := &Resolver{
		AuthenticationMode: model.AuthModeAPI,
		AccessEntries:      entryFor("arn:aws:iam::000000000000:role/Admin", ""),
	}
	got, err := r.Resolve(adminSession())
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}
	if got.Username != "arn:aws:iam::000000000000:role/Admin" {
		t.Errorf("Username = %q, want the principal ARN", got.Username)
	}
}

func TestResolveUnmappedPrincipalIsRejected(t *testing.T) {
	r := &Resolver{
		AuthenticationMode: model.AuthModeAPI,
		AccessEntries:      entryFor("arn:aws:iam::000000000000:role/SomebodyElse", "bob"),
	}

	_, err := r.Resolve(adminSession())
	if err == nil {
		t.Fatal("Resolve accepted a principal with no mapping")
	}
	// The error must name the ARN: an unexplained 403 is the single most
	// common EKS access complaint, and the whole point of emulating this
	// faithfully is to make it diagnosable.
	unmapped, ok := err.(*UnmappedPrincipalError)
	if !ok {
		t.Fatalf("error type = %T, want *UnmappedPrincipalError", err)
	}
	if unmapped.CanonicalARN != "arn:aws:iam::000000000000:role/Admin" {
		t.Errorf("CanonicalARN = %q", unmapped.CanonicalARN)
	}
}

func TestResolveFromAWSAuth(t *testing.T) {
	awsAuth, err := ParseAWSAuth(map[string]string{
		"mapRoles": `
- rolearn: arn:aws:iam::000000000000:role/Admin
  username: admin-from-configmap
  groups:
    - system:masters
`,
	})
	if err != nil {
		t.Fatalf("ParseAWSAuth returned unexpected error: %v", err)
	}

	r := &Resolver{AuthenticationMode: model.AuthModeConfigMap, AWSAuth: awsAuth}
	got, err := r.Resolve(adminSession())
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}
	if got.Username != "admin-from-configmap" {
		t.Errorf("Username = %q", got.Username)
	}
	if got.Source != SourceAWSAuth {
		t.Errorf("Source = %q, want %q", got.Source, SourceAWSAuth)
	}
}

func TestAccessEntryWinsOverAWSAuth(t *testing.T) {
	// This precedence rule is the one teams migrating off aws-auth trip over:
	// when a principal appears in both, the ConfigMap entry is ignored outright
	// rather than merged.
	awsAuth, err := ParseAWSAuth(map[string]string{
		"mapRoles": `
- rolearn: arn:aws:iam::000000000000:role/Admin
  username: from-configmap
  groups: [system:masters]
`,
	})
	if err != nil {
		t.Fatalf("ParseAWSAuth returned unexpected error: %v", err)
	}

	r := &Resolver{
		AuthenticationMode: model.AuthModeAPIAndConfigMap,
		AccessEntries:      entryFor("arn:aws:iam::000000000000:role/Admin", "from-access-entry"),
		AWSAuth:            awsAuth,
	}

	got, err := r.Resolve(adminSession())
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}
	if got.Username != "from-access-entry" {
		t.Errorf("Username = %q, want from-access-entry", got.Username)
	}
	if len(got.Groups) != 0 {
		t.Errorf("Groups = %v, want the ConfigMap groups to be ignored entirely", got.Groups)
	}
}

func TestAuthenticationModeGatesEachMechanism(t *testing.T) {
	awsAuth, _ := ParseAWSAuth(map[string]string{
		"mapRoles": `
- rolearn: arn:aws:iam::000000000000:role/Admin
  username: from-configmap
  groups: [system:masters]
`,
	})
	entries := entryFor("arn:aws:iam::000000000000:role/Admin", "from-access-entry")

	t.Run("API mode ignores the ConfigMap", func(t *testing.T) {
		r := &Resolver{AuthenticationMode: model.AuthModeAPI, AWSAuth: awsAuth}
		if _, err := r.Resolve(adminSession()); err == nil {
			t.Fatal("API mode honoured an aws-auth mapping")
		}
	})

	t.Run("CONFIG_MAP mode ignores access entries", func(t *testing.T) {
		r := &Resolver{AuthenticationMode: model.AuthModeConfigMap, AccessEntries: entries}
		if _, err := r.Resolve(adminSession()); err == nil {
			t.Fatal("CONFIG_MAP mode honoured an access entry")
		}
	})
}

func TestAWSAuthTemplateExpansion(t *testing.T) {
	awsAuth, err := ParseAWSAuth(map[string]string{
		"mapRoles": `
- rolearn: arn:aws:iam::000000000000:role/NodeInstanceRole
  username: "system:node:{{EC2PrivateDNSName}}"
  groups:
    - system:bootstrappers
    - system:nodes
`,
	})
	if err != nil {
		t.Fatalf("ParseAWSAuth returned unexpected error: %v", err)
	}

	node := &token.Identity{
		ARN:          "arn:aws:sts::000000000000:assumed-role/NodeInstanceRole/ip-10-0-1-5",
		CanonicalARN: "arn:aws:iam::000000000000:role/NodeInstanceRole",
		AccountID:    "000000000000",
		SessionName:  "ip-10-0-1-5",
	}

	r := &Resolver{AuthenticationMode: model.AuthModeConfigMap, AWSAuth: awsAuth}
	got, err := r.Resolve(node)
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}
	// Node authorization keys off the system:node:<name> username shape.
	if got.Username != "system:node:ip-10-0-1-5" {
		t.Errorf("Username = %q, want system:node:ip-10-0-1-5", got.Username)
	}
}

func TestAWSAuthMatchesIgnoringCaseAndPath(t *testing.T) {
	awsAuth, _ := ParseAWSAuth(map[string]string{
		"mapRoles": `
- rolearn: arn:aws:iam::000000000000:role/some/path/admin
  username: matched
  groups: [system:masters]
`,
	})
	r := &Resolver{AuthenticationMode: model.AuthModeConfigMap, AWSAuth: awsAuth}

	got, err := r.Resolve(&token.Identity{
		ARN:          "arn:aws:sts::000000000000:assumed-role/Admin/session",
		CanonicalARN: "arn:aws:iam::000000000000:role/Admin",
		AccountID:    "000000000000",
	})
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}
	if got.Username != "matched" {
		t.Errorf("Username = %q, want matched", got.Username)
	}
}

func TestParseAWSAuthRejectsMalformedYAML(t *testing.T) {
	if _, err := ParseAWSAuth(map[string]string{"mapRoles": "this: is: not: valid"}); err == nil {
		t.Fatal("ParseAWSAuth accepted malformed YAML")
	}
}

func TestParseAWSAuthHandlesEmptyAndMissingKeys(t *testing.T) {
	got, err := ParseAWSAuth(map[string]string{"mapRoles": "   "})
	if err != nil {
		t.Fatalf("ParseAWSAuth returned unexpected error: %v", err)
	}
	if len(got.MapRoles) != 0 || len(got.MapUsers) != 0 {
		t.Errorf("expected an empty result, got %+v", got)
	}
}
