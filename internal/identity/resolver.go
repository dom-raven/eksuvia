// Package identity maps a verified AWS principal onto a Kubernetes identity.
//
// This is the step real EKS performs inside its hidden control plane and never
// exposes. It is also where most production EKS access bugs actually live, so
// emulating it faithfully -- rather than granting every caller cluster-admin --
// is the main reason eksuvia exists.
//
// Two mechanisms coexist, and their interaction is subtle:
//
//   - Access entries (the CreateAccessEntry API), used when the cluster's
//     authentication mode is API or API_AND_CONFIG_MAP.
//   - The aws-auth ConfigMap in kube-system, used when the mode is CONFIG_MAP
//     or API_AND_CONFIG_MAP.
//
// When a principal appears in both, the access entry wins outright and the
// ConfigMap entry is ignored -- not merged. Teams migrating from aws-auth trip
// over this constantly, so eksuvia reproduces it exactly.
package identity

import (
	"fmt"
	"strings"

	"github.com/dom-raven/eksuvia/internal/awsarn"
	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/token"
	"gopkg.in/yaml.v3"
)

// KubernetesIdentity is the result of mapping an AWS principal into a cluster.
type KubernetesIdentity struct {
	Username string
	UID      string
	Groups   []string
	// Source records which mechanism produced the mapping, for diagnostics.
	// Real EKS gives you no visibility here at all; eksuvia surfaces it because
	// "why am I forbidden" is the whole reason people reach for a local cluster.
	Source string
}

// Mapping sources.
const (
	SourceAccessEntry = "access-entry"
	SourceAWSAuth     = "aws-auth"
)

// AWSAuthRoleMapping is one entry under the ConfigMap's mapRoles key.
type AWSAuthRoleMapping struct {
	RoleARN  string   `yaml:"rolearn"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups"`
}

// AWSAuthUserMapping is one entry under the ConfigMap's mapUsers key.
type AWSAuthUserMapping struct {
	UserARN  string   `yaml:"userarn"`
	Username string   `yaml:"username"`
	Groups   []string `yaml:"groups"`
}

// AWSAuth is the parsed aws-auth ConfigMap.
type AWSAuth struct {
	MapRoles    []AWSAuthRoleMapping
	MapUsers    []AWSAuthUserMapping
	MapAccounts []string
}

// ParseAWSAuth reads the three well-known keys out of an aws-auth ConfigMap's
// data. Each value is itself a YAML document embedded in a string, which is why
// this cannot be a single unmarshal.
func ParseAWSAuth(data map[string]string) (*AWSAuth, error) {
	out := &AWSAuth{}
	if raw, ok := data["mapRoles"]; ok && strings.TrimSpace(raw) != "" {
		if err := yaml.Unmarshal([]byte(raw), &out.MapRoles); err != nil {
			return nil, fmt.Errorf("aws-auth: parsing mapRoles: %w", err)
		}
	}
	if raw, ok := data["mapUsers"]; ok && strings.TrimSpace(raw) != "" {
		if err := yaml.Unmarshal([]byte(raw), &out.MapUsers); err != nil {
			return nil, fmt.Errorf("aws-auth: parsing mapUsers: %w", err)
		}
	}
	if raw, ok := data["mapAccounts"]; ok && strings.TrimSpace(raw) != "" {
		if err := yaml.Unmarshal([]byte(raw), &out.MapAccounts); err != nil {
			return nil, fmt.Errorf("aws-auth: parsing mapAccounts: %w", err)
		}
	}
	return out, nil
}

// Resolver maps principals for a single cluster.
type Resolver struct {
	// AuthenticationMode is the cluster's accessConfig.authenticationMode.
	AuthenticationMode string
	// AccessEntries is keyed by canonical principal ARN.
	AccessEntries map[string]*model.AccessEntry
	// AWSAuth is the parsed ConfigMap, or nil if absent.
	AWSAuth *AWSAuth
}

func (r *Resolver) accessEntriesEnabled() bool {
	return r.AuthenticationMode == model.AuthModeAPI || r.AuthenticationMode == model.AuthModeAPIAndConfigMap
}

func (r *Resolver) configMapEnabled() bool {
	return r.AuthenticationMode == model.AuthModeConfigMap || r.AuthenticationMode == model.AuthModeAPIAndConfigMap
}

// Resolve turns a verified AWS identity into a Kubernetes identity, or returns
// an error if the principal is not mapped into this cluster at all.
//
// A principal that authenticates successfully to AWS but has no mapping is
// *not* an authentication failure in Kubernetes terms -- it is an unknown user.
// Real EKS reports this to kubectl as a 403 mentioning the ARN, which is the
// behaviour callers write their error handling against.
func (r *Resolver) Resolve(aws *token.Identity) (*KubernetesIdentity, error) {
	if r.accessEntriesEnabled() {
		if entry := r.lookupAccessEntry(aws.CanonicalARN); entry != nil {
			return r.fromAccessEntry(entry, aws), nil
		}
	}

	if r.configMapEnabled() && r.AWSAuth != nil {
		if id := r.fromAWSAuth(aws); id != nil {
			return id, nil
		}
	}

	return nil, &UnmappedPrincipalError{ARN: aws.ARN, CanonicalARN: aws.CanonicalARN}
}

// UnmappedPrincipalError means the caller proved who they are to AWS but that
// identity has no route into this cluster.
type UnmappedPrincipalError struct {
	ARN          string
	CanonicalARN string
}

func (e *UnmappedPrincipalError) Error() string {
	return fmt.Sprintf("the principal %q is not mapped into this cluster: create an access entry for it, or add it to the aws-auth ConfigMap", e.CanonicalARN)
}

func (r *Resolver) lookupAccessEntry(canonicalARN string) *model.AccessEntry {
	if r.AccessEntries == nil {
		return nil
	}
	if entry, ok := r.AccessEntries[canonicalARN]; ok {
		return entry
	}
	// EKS compares principal ARNs case-insensitively on the resource portion,
	// so a role recorded as .../MyRole still matches a caller arriving as
	// .../myrole. Falling back to a scan keeps that behaviour without forcing
	// every writer to normalise case first.
	for arn, entry := range r.AccessEntries {
		if strings.EqualFold(arn, canonicalARN) {
			return entry
		}
	}
	return nil
}

func (r *Resolver) fromAccessEntry(entry *model.AccessEntry, aws *token.Identity) *KubernetesIdentity {
	username := entry.Username
	if username == "" {
		// EKS defaults an unset username to the principal ARN itself.
		username = entry.PrincipalARN
	}
	username = expandTemplates(username, aws)

	groups := append([]string(nil), entry.KubernetesGroups...)

	// Associated access policies do not add groups. They are enforced by RBAC
	// objects that eksuvia reconciles into the cluster binding this username to
	// the matching built-in ClusterRole -- exactly as EKS does. See
	// internal/identity/rbac.go.
	return &KubernetesIdentity{
		Username: username,
		UID:      "aws-iam-authenticator:" + aws.AccountID + ":" + aws.UserID,
		Groups:   groups,
		Source:   SourceAccessEntry,
	}
}

func (r *Resolver) fromAWSAuth(aws *token.Identity) *KubernetesIdentity {
	for i := range r.AWSAuth.MapRoles {
		m := &r.AWSAuth.MapRoles[i]
		if arnMatches(m.RoleARN, aws.CanonicalARN) {
			return &KubernetesIdentity{
				Username: expandTemplates(m.Username, aws),
				UID:      "aws-iam-authenticator:" + aws.AccountID + ":" + aws.UserID,
				Groups:   expandGroupTemplates(m.Groups, aws),
				Source:   SourceAWSAuth,
			}
		}
	}
	for i := range r.AWSAuth.MapUsers {
		m := &r.AWSAuth.MapUsers[i]
		if arnMatches(m.UserARN, aws.CanonicalARN) {
			return &KubernetesIdentity{
				Username: expandTemplates(m.Username, aws),
				UID:      "aws-iam-authenticator:" + aws.AccountID + ":" + aws.UserID,
				Groups:   expandGroupTemplates(m.Groups, aws),
				Source:   SourceAWSAuth,
			}
		}
	}
	return nil
}

// arnMatches compares a configured ARN against a caller's canonical ARN,
// tolerating both case differences and an omitted IAM path -- both of which
// upstream accepts and both of which people rely on by accident.
func arnMatches(configured, canonical string) bool {
	if configured == "" {
		return false
	}
	if strings.EqualFold(configured, canonical) {
		return true
	}
	return strings.EqualFold(awsarn.StripPath(configured), awsarn.StripPath(canonical))
}

// expandTemplates substitutes the aws-auth template variables.
//
// {{EC2PrivateDNSName}} is the interesting one: on real EKS the authenticator
// resolves it by calling ec2:DescribeInstances for the caller's instance ID.
// eksuvia has no EC2 instances, so it substitutes the kind node name that the
// node group provisioner recorded in the session name, which preserves the
// system:node:<name> username shape that node authorization depends on.
func expandTemplates(s string, aws *token.Identity) string {
	if s == "" {
		return s
	}
	r := strings.NewReplacer(
		"{{SessionName}}", aws.SessionName,
		"{{AccountID}}", aws.AccountID,
		"{{EC2PrivateDNSName}}", aws.SessionName,
		"{{AccessKeyID}}", "",
	)
	return r.Replace(s)
}

func expandGroupTemplates(groups []string, aws *token.Identity) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, expandTemplates(g, aws))
	}
	return out
}
