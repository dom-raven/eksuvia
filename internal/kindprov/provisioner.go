// Package kindprov provisions the Kubernetes data plane behind an emulated
// EKS cluster, using kind.
//
// kind is chosen over lighter distributions on purpose. It runs upstream
// Kubernetes bootstrapped by kubeadm, with a real kubelet and containerd on
// every node -- the same components EKS runs. Distributions that bundle their
// own ingress, service LB, storage class and CNI diverge from EKS in exactly
// the places workloads notice, and a node that is a process rather than a
// machine cannot model a node group at all.
//
// The interesting work here is not "start a cluster". It is configuring the
// API server the way EKS configures its hidden one: a webhook token
// authenticator pointed back at eksuvia, and a service-account signing key
// eksuvia holds so that projected tokens are verifiable through a real OIDC
// discovery document.
package kindprov

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/kind/pkg/cluster"
	"sigs.k8s.io/kind/pkg/log"
)

// NamePrefix namespaces kind clusters created by eksuvia, so `kind get
// clusters` stays readable and two tools cannot collide on a bare name.
const NamePrefix = "eksuvia-"

// AssetsMountPath is where per-cluster material is mounted inside the
// control-plane container.
const AssetsMountPath = "/etc/eksuvia"

// Spec describes the cluster to provision.
type Spec struct {
	// EKSName is the cluster name as the caller sees it.
	EKSName string
	// KubernetesVersion is the EKS-style "1.31".
	KubernetesVersion string
	// NodeImage overrides the kind node image. Empty derives one from the
	// Kubernetes version.
	NodeImage string
	// WorkerPoolSize is how many worker nodes to create up front.
	//
	// kind cannot add nodes to a running cluster, so node groups are backed by
	// a pool allocated at creation time. See AllocateNodes.
	WorkerPoolSize int
	// ServiceIPv4CIDR mirrors kubernetesNetworkConfig.serviceIpv4Cidr.
	ServiceIPv4CIDR string
	// OIDCIssuer is the service-account issuer URL the API server will stamp
	// into projected tokens.
	OIDCIssuer string
	// SigningKeyPEM and PublicKeyPEM are the service-account keypair.
	SigningKeyPEM []byte
	PublicKeyPEM  []byte
	// WebhookURL is where the API server sends TokenReview requests. It must be
	// reachable from inside the control-plane container, which is why it is
	// usually host.docker.internal rather than localhost.
	WebhookURL string
	// AssetsDir is the host directory holding this cluster's material.
	AssetsDir string
}

// Result reports what was provisioned.
type Result struct {
	KindName   string
	Kubeconfig []byte
	// Endpoint is the API server URL reachable from the host.
	Endpoint string
	// CACertPEM is the cluster CA, returned by DescribeCluster.
	CACertPEM []byte
	// WorkerNodes are the kind node names available to node groups.
	WorkerNodes []string
}

// Provisioner creates and destroys kind clusters.
type Provisioner struct {
	provider *cluster.Provider
	// detectErr records a missing container runtime, reported when a cluster
	// operation is actually attempted rather than at startup.
	detectErr error
	// CreateTimeout bounds how long to wait for the control plane to be ready.
	CreateTimeout time.Duration
}

// ErrNoRuntime means no container runtime was found.
var ErrNoRuntime = errors.New("no container runtime detected: eksuvia needs Docker or Podman running to create clusters")

// New builds a Provisioner using whichever container runtime is available.
//
// A missing runtime is deliberately not fatal here. eksuvia still serves the
// EKS API surface, health checks and the proxy to Floci without one, and
// failing at startup would make every one of those untestable. The error is
// surfaced when a cluster operation is actually attempted, where it is
// actionable.
func New(logger log.Logger) *Provisioner {
	p := &Provisioner{CreateTimeout: 5 * time.Minute}

	detected, err := cluster.DetectNodeProvider()
	if err != nil {
		p.detectErr = fmt.Errorf("%w: %v", ErrNoRuntime, err)
		return p
	}

	opts := []cluster.ProviderOption{detected}
	if logger != nil {
		opts = append(opts, cluster.ProviderWithLogger(logger))
	}
	p.provider = cluster.NewProvider(opts...)
	return p
}

// Available reports whether a container runtime was found.
func (p *Provisioner) Available() error { return p.detectErr }

// KindName derives the kind cluster name for an EKS cluster name.
func KindName(eksName string) string { return NamePrefix + eksName }

// Create provisions the kind cluster for an EKS cluster.
func (p *Provisioner) Create(ctx context.Context, spec Spec) (*Result, error) {
	if p.detectErr != nil {
		return nil, p.detectErr
	}
	if err := writeAssets(spec); err != nil {
		return nil, err
	}

	cfg, err := buildKindConfig(spec)
	if err != nil {
		return nil, err
	}

	kindName := KindName(spec.EKSName)
	timeout := p.CreateTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	opts := []cluster.CreateOption{
		cluster.CreateWithV1Alpha4Config(cfg),
		cluster.CreateWithWaitForReady(timeout),
		cluster.CreateWithDisplaySalutation(false),
		cluster.CreateWithDisplayUsage(false),
	}
	if image := nodeImage(spec); image != "" {
		opts = append(opts, cluster.CreateWithNodeImage(image))
	}

	if err := p.provider.Create(kindName, opts...); err != nil {
		return nil, fmt.Errorf("kindprov: creating cluster %q: %w", kindName, err)
	}

	// Deliberately the host-reachable kubeconfig: `aws eks update-kubeconfig`
	// writes an endpoint the developer's kubectl must reach directly.
	raw, err := p.provider.KubeConfig(kindName, false)
	if err != nil {
		return nil, fmt.Errorf("kindprov: reading kubeconfig for %q: %w", kindName, err)
	}

	return &Result{KindName: kindName, Kubeconfig: []byte(raw)}, nil
}

// Delete tears down the kind cluster and removes its assets.
func (p *Provisioner) Delete(ctx context.Context, eksName, assetsDir string) error {
	if p.detectErr != nil {
		return p.detectErr
	}
	kindName := KindName(eksName)
	if err := p.provider.Delete(kindName, ""); err != nil {
		return fmt.Errorf("kindprov: deleting cluster %q: %w", kindName, err)
	}
	if assetsDir != "" {
		if err := os.RemoveAll(assetsDir); err != nil {
			return fmt.Errorf("kindprov: removing assets for %q: %w", eksName, err)
		}
	}
	return nil
}

// List returns the EKS names of kind clusters eksuvia owns. Clusters created by
// other tools are ignored, so eksuvia never deletes something it did not make.
func (p *Provisioner) List() ([]string, error) {
	if p.detectErr != nil {
		return nil, p.detectErr
	}
	all, err := p.provider.List()
	if err != nil {
		return nil, fmt.Errorf("kindprov: listing clusters: %w", err)
	}
	var out []string
	for _, name := range all {
		if strings.HasPrefix(name, NamePrefix) {
			out = append(out, strings.TrimPrefix(name, NamePrefix))
		}
	}
	return out, nil
}

// writeAssets materialises the per-cluster files mounted into the control
// plane: the service-account keypair and the token webhook kubeconfig.
func writeAssets(spec Spec) error {
	if spec.AssetsDir == "" {
		return fmt.Errorf("kindprov: assets directory is required")
	}
	if err := os.MkdirAll(spec.AssetsDir, 0o755); err != nil {
		return fmt.Errorf("kindprov: creating assets directory: %w", err)
	}

	// 0644 rather than 0600: the API server and controller-manager run as a
	// non-root user inside the node container and must be able to read these.
	// The directory only ever holds material for a throwaway local cluster.
	files := map[string][]byte{
		"sa.key":             spec.SigningKeyPEM,
		"sa.pub":             spec.PublicKeyPEM,
		"webhook.kubeconfig": webhookKubeconfig(spec.WebhookURL),
	}
	for name, content := range files {
		if len(content) == 0 {
			return fmt.Errorf("kindprov: refusing to write empty %s", name)
		}
		if err := os.WriteFile(filepath.Join(spec.AssetsDir, name), content, 0o644); err != nil {
			return fmt.Errorf("kindprov: writing %s: %w", name, err)
		}
	}
	return nil
}

// webhookKubeconfig renders the kubeconfig the API server uses to reach
// eksuvia's TokenReview endpoint.
//
// insecure-skip-tls-verify is set because the webhook is plain HTTP on a local
// bridge network. That is acceptable here and nowhere else: the endpoint
// arbitrates cluster access, so in any non-local deployment it must be TLS with
// a pinned CA. This is called out in docs/fidelity.md.
func webhookKubeconfig(webhookURL string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
  - name: eksuvia
    cluster:
      server: %s
      insecure-skip-tls-verify: true
users:
  - name: eksuvia
contexts:
  - name: eksuvia
    context:
      cluster: eksuvia
      user: eksuvia
current-context: eksuvia
`, webhookURL))
}

// buildKindConfig assembles the kind cluster definition.
func buildKindConfig(spec Spec) (*v1alpha4.Cluster, error) {
	if spec.OIDCIssuer == "" {
		return nil, fmt.Errorf("kindprov: OIDC issuer is required")
	}
	if spec.WebhookURL == "" {
		return nil, fmt.Errorf("kindprov: webhook URL is required")
	}

	mount := v1alpha4.Mount{
		HostPath:      spec.AssetsDir,
		ContainerPath: AssetsMountPath,
		Readonly:      true,
	}

	nodes := []v1alpha4.Node{{
		Role:        v1alpha4.ControlPlaneRole,
		ExtraMounts: []v1alpha4.Mount{mount},
	}}
	for i := 0; i < spec.WorkerPoolSize; i++ {
		nodes = append(nodes, v1alpha4.Node{Role: v1alpha4.WorkerRole})
	}

	cfg := &v1alpha4.Cluster{
		TypeMeta: v1alpha4.TypeMeta{
			Kind:       "Cluster",
			APIVersion: "kind.x-k8s.io/v1alpha4",
		},
		Nodes:                nodes,
		KubeadmConfigPatches: kubeadmPatches(spec),
	}
	if spec.ServiceIPv4CIDR != "" {
		cfg.Networking.ServiceSubnet = spec.ServiceIPv4CIDR
	}
	return cfg, nil
}

// kubeadmPatches produces the API server and controller-manager configuration
// that turns a stock kind cluster into an EKS-shaped one.
//
// Two patches are emitted for each component, one pinned to kubeadm v1beta3 and
// one to v1beta4. kind applies a patch only when its apiVersion matches the
// generated object, so exactly one of each pair takes effect and the other is
// inert. This is what lets a single build target both older Kubernetes
// versions (map-shaped extraArgs) and 1.31+ (list-shaped extraArgs) without
// branching on the version string.
func kubeadmPatches(spec Spec) []string {
	apiServerArgs := [][2]string{
		// The issuer must match what eksuvia serves at its discovery endpoint,
		// or STS rejects every projected token.
		{"service-account-issuer", spec.OIDCIssuer},
		{"service-account-key-file", AssetsMountPath + "/sa.pub"},
		{"service-account-signing-key-file", AssetsMountPath + "/sa.key"},
		// Both audiences are required: sts.amazonaws.com for IRSA, and the
		// issuer itself so ordinary in-cluster tokens keep working.
		{"api-audiences", strings.Join([]string{"sts.amazonaws.com", spec.OIDCIssuer}, ",")},
		{"authentication-token-webhook-config-file", AssetsMountPath + "/webhook.kubeconfig"},
		// EKS caches authenticated tokens; matching the TTL means a revoked
		// access entry takes about as long to bite here as it does in AWS.
		{"authentication-token-webhook-cache-ttl", "7m"},
		{"authentication-token-webhook-version", "v1"},
	}
	controllerManagerArgs := [][2]string{
		// Without this the controller-manager signs legacy tokens with kubeadm's
		// key, which the API server no longer trusts.
		{"service-account-private-key-file", AssetsMountPath + "/sa.key"},
	}

	return []string{
		clusterConfigPatch("kubeadm.k8s.io/v1beta3", apiServerArgs, controllerManagerArgs, false),
		clusterConfigPatch("kubeadm.k8s.io/v1beta4", apiServerArgs, controllerManagerArgs, true),
	}
}

// clusterConfigPatch renders a ClusterConfiguration merge patch. listStyle
// selects the v1beta4 extraArgs encoding, which is a list of name/value pairs
// rather than a map.
func clusterConfigPatch(apiVersion string, apiServerArgs, cmArgs [][2]string, listStyle bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: %s\nkind: ClusterConfiguration\n", apiVersion)
	b.WriteString("apiServer:\n  extraArgs:\n")
	writeArgs(&b, apiServerArgs, listStyle, "    ")
	b.WriteString("controllerManager:\n  extraArgs:\n")
	writeArgs(&b, cmArgs, listStyle, "    ")
	return b.String()
}

func writeArgs(b *strings.Builder, args [][2]string, listStyle bool, indent string) {
	for _, arg := range args {
		if listStyle {
			fmt.Fprintf(b, "%s- name: %q\n%s  value: %q\n", indent, arg[0], indent, arg[1])
		} else {
			fmt.Fprintf(b, "%s%s: %q\n", indent, arg[0], arg[1])
		}
	}
}

// nodeImage resolves the kind node image for a Kubernetes version.
//
// An explicit image always wins. Otherwise the EKS-style "1.31" is turned into
// the conventional kind tag. kind pins its images by digest per release; using
// a bare tag means the image must already be pullable, which is called out in
// the docs rather than papered over with a stale digest table that would rot.
func nodeImage(spec Spec) string {
	if spec.NodeImage != "" {
		return spec.NodeImage
	}
	v := strings.TrimSpace(spec.KubernetesVersion)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	// EKS reports minor versions ("1.31"); kind images are patch-versioned.
	if strings.Count(v, ".") == 1 {
		v += ".0"
	}
	return "kindest/node:" + v
}
