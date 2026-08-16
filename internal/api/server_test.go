package api

import (
	"strings"
	"testing"

	"github.com/dom-raven/eksuvia/internal/awsarn"
	"github.com/dom-raven/eksuvia/internal/config"
)

func testServer() *Server {
	cfg := config.Defaults()
	cfg.Region = "us-east-1"
	cfg.AccountID = "000000000000"
	return &Server{cfg: cfg}
}

func TestAccessEntryARNIsParseable(t *testing.T) {
	// Regression: the principal ARN used to be embedded verbatim, producing a
	// string with eleven colon-separated sections that no ARN parser can read.
	s := testServer()

	tests := []struct {
		name         string
		principal    string
		wantType     string
		wantResource string
	}{
		{"role", "arn:aws:iam::000000000000:role/Developer", "role", "Developer"},
		{"role with path", "arn:aws:iam::000000000000:role/some/path/Developer", "role", "Developer"},
		{"user", "arn:aws:iam::000000000000:user/alice", "user", "alice"},
		{"account root", "arn:aws:iam::000000000000:root", "root", "root"},
		{"cross-account role", "arn:aws:iam::111122223333:role/Peer", "role", "Peer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.accessEntryARN("demo", tt.principal)

			parsed, err := awsarn.Parse(got)
			if err != nil {
				t.Fatalf("accessEntryARN produced an unparseable ARN %q: %v", got, err)
			}
			if strings.Count(got, ":") != 5 {
				t.Errorf("ARN %q has %d colons, want 5 — a nested ARN has leaked in",
					got, strings.Count(got, ":"))
			}
			if parsed.Service != "eks" {
				t.Errorf("service = %q, want eks", parsed.Service)
			}
			if !strings.HasPrefix(parsed.Resource, "access-entry/demo/"+tt.wantType+"/") {
				t.Errorf("resource = %q, want it to start with access-entry/demo/%s/", parsed.Resource, tt.wantType)
			}
			if !strings.Contains(parsed.Resource, "/"+tt.wantResource+"/") {
				t.Errorf("resource = %q, want it to contain the principal name %q", parsed.Resource, tt.wantResource)
			}
		})
	}
}

func TestAccessEntryARNIsStableAndDistinct(t *testing.T) {
	s := testServer()
	a := s.accessEntryARN("demo", "arn:aws:iam::000000000000:role/Developer")

	if a != s.accessEntryARN("demo", "arn:aws:iam::000000000000:role/Developer") {
		t.Error("accessEntryARN must be deterministic")
	}
	if a == s.accessEntryARN("other", "arn:aws:iam::000000000000:role/Developer") {
		t.Error("the same principal on different clusters must get different ARNs")
	}
	if a == s.accessEntryARN("demo", "arn:aws:iam::000000000000:role/Other") {
		t.Error("different principals must get different ARNs")
	}
}

func TestClusterAndNodegroupARNs(t *testing.T) {
	s := testServer()

	cluster := s.clusterARN("demo")
	if cluster != "arn:aws:eks:us-east-1:000000000000:cluster/demo" {
		t.Errorf("clusterARN = %q", cluster)
	}
	if _, err := awsarn.Parse(cluster); err != nil {
		t.Errorf("clusterARN is unparseable: %v", err)
	}

	ng := s.nodegroupARN("demo", "workers", "abc123")
	if ng != "arn:aws:eks:us-east-1:000000000000:nodegroup/demo/workers/abc123" {
		t.Errorf("nodegroupARN = %q", ng)
	}
	if _, err := awsarn.Parse(ng); err != nil {
		t.Errorf("nodegroupARN is unparseable: %v", err)
	}
}
