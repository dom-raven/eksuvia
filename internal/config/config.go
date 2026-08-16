// Package config holds eksuvia's runtime settings.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is the fully resolved runtime configuration.
type Config struct {
	// Listen is the address eksuvia serves on. It defaults to the AWS-emulator
	// convention so AWS_ENDPOINT_URL keeps its familiar value and eksuvia acts
	// as the single front door, proxying non-EKS calls onward to Floci.
	Listen string

	// FlociEndpoint is the upstream local AWS emulator. Everything eksuvia does
	// not implement itself is proxied here, and STS token verification is
	// dereferenced against it.
	FlociEndpoint string

	// AdvertiseHost is the hostname by which other containers reach eksuvia.
	//
	// This matters more than it looks. The kind API server must reach the
	// TokenReview webhook, and Floci must reach the OIDC discovery document, and
	// neither of them can use "localhost" -- that resolves to their own
	// container. On Docker Desktop host.docker.internal works out of the box; on
	// plain Linux this usually needs to be the bridge gateway address.
	AdvertiseHost string

	// Region and AccountID shape generated ARNs. The defaults match Floci's, so
	// ARNs minted here resolve against roles created there.
	Region    string
	AccountID string

	// ClusterCreatorARN is the principal granted cluster-admin when a cluster is
	// created with bootstrapClusterCreatorAdminPermissions (the default).
	//
	// Real EKS reads the creator's identity off the signed CreateCluster
	// request. eksuvia cannot: verifying SigV4 would require the caller's secret
	// key, and local emulators accept unsigned or dummy credentials by design.
	// So the creator is configured rather than inferred, defaulting to the
	// identity Floci's STS reports for the conventional test credentials.
	ClusterCreatorARN string

	// StateDir holds per-cluster material mounted into the control plane.
	StateDir string

	// WorkerPoolSize is how many kind worker nodes each cluster starts with.
	//
	// kind cannot add nodes to a running cluster, so node groups draw from this
	// pool. Raising it costs memory per cluster; exceeding it surfaces as an
	// insufficient-capacity health issue on the node group, which is the same
	// shape of failure real EKS reports.
	WorkerPoolSize int

	// ClusterCreateTimeout bounds waiting for a control plane to be ready.
	ClusterCreateTimeout time.Duration

	// NodeImage overrides the kind node image for every cluster.
	NodeImage string
}

// Defaults returns the baseline configuration.
func Defaults() Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return Config{
		Listen:               ":4566",
		FlociEndpoint:        "http://floci:4566",
		AdvertiseHost:        "host.docker.internal",
		Region:               "us-east-1",
		AccountID:            "000000000000",
		ClusterCreatorARN:    "arn:aws:iam::000000000000:root",
		StateDir:             filepath.Join(home, ".eksuvia"),
		WorkerPoolSize:       2,
		ClusterCreateTimeout: 5 * time.Minute,
	}
}

// Validate checks the configuration and normalises it.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("config: listen address is required")
	}
	if c.FlociEndpoint == "" {
		return fmt.Errorf("config: floci endpoint is required")
	}
	u, err := url.Parse(c.FlociEndpoint)
	if err != nil {
		return fmt.Errorf("config: parsing floci endpoint: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("config: floci endpoint %q must be an absolute URL", c.FlociEndpoint)
	}
	c.FlociEndpoint = strings.TrimSuffix(c.FlociEndpoint, "/")

	// A self-referential proxy target turns every unimplemented call into an
	// infinite loop, which presents as a hang rather than an error. Catch the
	// obvious form of the mistake up front.
	if sameEndpoint(c.Listen, u.Host) {
		return fmt.Errorf("config: floci endpoint %q points back at eksuvia's own listen address %q; "+
			"run Floci on a different port and pass --floci-endpoint", c.FlociEndpoint, c.Listen)
	}

	if c.WorkerPoolSize < 0 {
		return fmt.Errorf("config: worker pool size cannot be negative")
	}
	if c.AccountID == "" {
		return fmt.Errorf("config: account id is required")
	}
	if c.Region == "" {
		return fmt.Errorf("config: region is required")
	}
	if c.StateDir == "" {
		return fmt.Errorf("config: state directory is required")
	}
	return nil
}

// sameEndpoint reports whether a listen address and a URL host refer to the
// same port on the local machine.
func sameEndpoint(listen, host string) bool {
	listenPort := portOf(listen)
	if listenPort == "" || listenPort != portOf(host) {
		return false
	}
	listenHost := hostOf(listen)
	targetHost := hostOf(host)
	// An empty or wildcard listen host binds every interface, so any local
	// target on the same port is a loop.
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "::" {
		return isLocalHostname(targetHost)
	}
	return listenHost == targetHost
}

func portOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i+1:]
	}
	return ""
}

func hostOf(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return strings.Trim(addr[:i], "[]")
	}
	return strings.Trim(addr, "[]")
}

func isLocalHostname(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "":
		return true
	}
	return false
}

// ClusterAssetsDir is where one cluster's keys and webhook config live.
func (c *Config) ClusterAssetsDir(clusterName string) string {
	return filepath.Join(c.StateDir, "clusters", clusterName)
}

// AdvertisedBaseURL is the URL other containers use to reach eksuvia.
func (c *Config) AdvertisedBaseURL() string {
	return fmt.Sprintf("http://%s%s", c.AdvertiseHost, portSuffix(c.Listen))
}

func portSuffix(listen string) string {
	if p := portOf(listen); p != "" {
		return ":" + p
	}
	return ""
}
