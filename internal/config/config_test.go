package config

import (
	"strings"
	"testing"
)

func TestValidateAcceptsDefaults(t *testing.T) {
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default configuration is invalid: %v", err)
	}
}

func TestValidateRejectsSelfProxyLoop(t *testing.T) {
	// Pointing the upstream at eksuvia's own port turns every unimplemented
	// call into an infinite loop, which presents as a hang rather than an
	// error. It is an easy mistake to make when moving Floci off 4566.
	cases := []struct {
		name   string
		listen string
		floci  string
	}{
		{"wildcard listen, localhost upstream", ":4566", "http://localhost:4566"},
		{"wildcard listen, loopback upstream", ":4566", "http://127.0.0.1:4566"},
		{"explicit host match", "127.0.0.1:4566", "http://127.0.0.1:4566"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Listen = tc.listen
			cfg.FlociEndpoint = tc.floci
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate accepted a self-referential upstream")
			}
			if !strings.Contains(err.Error(), "points back at eksuvia") {
				t.Errorf("error = %q, want it to explain the loop", err)
			}
		})
	}
}

func TestValidateAllowsDistinctPorts(t *testing.T) {
	cfg := Defaults()
	cfg.Listen = ":4566"
	cfg.FlociEndpoint = "http://localhost:4567"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected a valid configuration: %v", err)
	}
}

func TestValidateRequiresAbsoluteUpstreamURL(t *testing.T) {
	cfg := Defaults()
	cfg.FlociEndpoint = "floci:4566"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted an upstream without a scheme")
	}
}

func TestValidateTrimsTrailingSlash(t *testing.T) {
	cfg := Defaults()
	cfg.FlociEndpoint = "http://floci:4566/"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned unexpected error: %v", err)
	}
	if cfg.FlociEndpoint != "http://floci:4566" {
		t.Errorf("FlociEndpoint = %q, want the trailing slash removed", cfg.FlociEndpoint)
	}
}

func TestValidateRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no listen address", func(c *Config) { c.Listen = "" }},
		{"no upstream", func(c *Config) { c.FlociEndpoint = "" }},
		{"no account id", func(c *Config) { c.AccountID = "" }},
		{"no region", func(c *Config) { c.Region = "" }},
		{"no state dir", func(c *Config) { c.StateDir = "" }},
		{"negative pool size", func(c *Config) { c.WorkerPoolSize = -1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate accepted a configuration with %s", tt.name)
			}
		})
	}
}

func TestAdvertisedBaseURL(t *testing.T) {
	cfg := Defaults()
	cfg.AdvertiseHost = "host.docker.internal"
	cfg.Listen = ":4566"
	if got, want := cfg.AdvertisedBaseURL(), "http://host.docker.internal:4566"; got != want {
		t.Errorf("AdvertisedBaseURL() = %q, want %q", got, want)
	}
}

func TestClusterAssetsDirIsPerCluster(t *testing.T) {
	cfg := Defaults()
	a := cfg.ClusterAssetsDir("alpha")
	b := cfg.ClusterAssetsDir("beta")
	if a == b {
		t.Error("two clusters must not share an assets directory; their signing keys would collide")
	}
	if !strings.HasSuffix(a, "alpha") {
		t.Errorf("assets dir %q should be named for the cluster", a)
	}
}
