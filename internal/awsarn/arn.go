// Package awsarn parses and canonicalizes AWS principal ARNs.
//
// The canonicalization rules here mirror kubernetes-sigs/aws-iam-authenticator's
// pkg/arn. Getting these exactly right matters: an EKS cluster resolves an IAM
// principal to a Kubernetes identity by matching the *canonical* ARN against
// access entries and the aws-auth ConfigMap. In particular a caller arriving as
// an STS assumed-role session must collapse to the underlying IAM role, or the
// mapping silently misses and the user gets an opaque 403.
package awsarn

import (
	"fmt"
	"strings"
)

// ARN is a parsed AWS Amazon Resource Name.
type ARN struct {
	Partition string
	Service   string
	Region    string
	AccountID string
	Resource  string
}

// String renders the ARN back into its canonical string form.
func (a ARN) String() string {
	return strings.Join([]string{"arn", a.Partition, a.Service, a.Region, a.AccountID, a.Resource}, ":")
}

// Parse splits an ARN into its six colon-delimited components. The resource
// component may itself contain colons (as in "assumed-role/Role/session"), so
// only the first five separators are significant.
func Parse(arn string) (ARN, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return ARN{}, fmt.Errorf("arn: not enough sections in %q", arn)
	}
	if parts[0] != "arn" {
		return ARN{}, fmt.Errorf("arn: %q does not start with 'arn:'", arn)
	}
	if parts[1] == "" {
		return ARN{}, fmt.Errorf("arn: missing partition in %q", arn)
	}
	if parts[2] == "" {
		return ARN{}, fmt.Errorf("arn: missing service in %q", arn)
	}
	if parts[5] == "" {
		return ARN{}, fmt.Errorf("arn: missing resource in %q", arn)
	}
	return ARN{
		Partition: parts[1],
		Service:   parts[2],
		Region:    parts[3],
		AccountID: parts[4],
		Resource:  parts[5],
	}, nil
}

// Canonicalize validates that an ARN names a principal the authenticator can
// map, and rewrites STS assumed-role ARNs into the IAM role they came from.
//
// Accepted inputs:
//
//	arn:aws:iam::123456789012:root
//	arn:aws:iam::123456789012:user/Bob
//	arn:aws:iam::123456789012:role/S3Access
//	arn:aws:iam::123456789012:role/some/path/S3Access
//	arn:aws:sts::123456789012:assumed-role/Accounting-Role/Mary  -> iam role
//	arn:aws:sts::123456789012:federated-user/Bob
//
// Anything else is rejected rather than passed through, matching upstream: a
// principal we cannot reason about must not be silently trusted.
func Canonicalize(arn string) (string, error) {
	parsed, err := Parse(arn)
	if err != nil {
		return "", err
	}

	parts := strings.Split(parsed.Resource, "/")
	resource := parts[0]

	switch parsed.Service {
	case "sts":
		switch resource {
		case "federated-user":
			return arn, nil
		case "assumed-role":
			if len(parts) < 3 {
				return "", fmt.Errorf("arn: unrecognized assumed-role principal %q", arn)
			}
			// IAM role ARNs may carry a path, and the session name is always the
			// final segment. Everything between is part of the role name.
			role := strings.Join(parts[1:len(parts)-1], "/")
			return fmt.Sprintf("arn:%s:iam::%s:role/%s", parsed.Partition, parsed.AccountID, role), nil
		default:
			return "", fmt.Errorf("arn: unrecognized STS principal %q", arn)
		}
	case "iam":
		switch resource {
		case "role", "user", "root", "federated-user":
			return arn, nil
		default:
			return "", fmt.Errorf("arn: unrecognized IAM principal %q", arn)
		}
	default:
		return "", fmt.Errorf("arn: non-IAM principal %q", arn)
	}
}

// SessionName returns the session component of an STS assumed-role ARN, which
// aws-auth templates expose as {{SessionName}}. It returns "" for any other
// principal shape.
func SessionName(arn string) string {
	parsed, err := Parse(arn)
	if err != nil || parsed.Service != "sts" {
		return ""
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) < 3 || parts[0] != "assumed-role" {
		return ""
	}
	return parts[len(parts)-1]
}

// StripPath removes any embedded path from an IAM role or user ARN, so that
// arn:aws:iam::1:role/some/path/Admin becomes arn:aws:iam::1:role/Admin.
//
// EKS access entries match on the full ARN including path; this helper exists
// for the aws-auth compatibility layer, which historically tolerated both.
func StripPath(arn string) string {
	parsed, err := Parse(arn)
	if err != nil {
		return arn
	}
	parts := strings.Split(parsed.Resource, "/")
	if len(parts) < 2 {
		return arn
	}
	parsed.Resource = parts[0] + "/" + parts[len(parts)-1]
	return parsed.String()
}
