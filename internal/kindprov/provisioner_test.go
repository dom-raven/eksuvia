package kindprov

import (
	"strings"
	"testing"

	"sigs.k8s.io/kind/pkg/apis/config/v1alpha4"
	"sigs.k8s.io/yaml"
)

func testSpec() Spec {
	return Spec{
		EKSName:           "demo",
		KubernetesVersion: "1.31",
		WorkerPoolSize:    2,
		ServiceIPv4CIDR:   "10.100.0.0/16",
		OIDCIssuer:        "http://172.17.0.1:4566/id/ABC123",
		SigningKeyPEM:     []byte("key"),
		PublicKeyPEM:      []byte("pub"),
		WebhookURL:        "http://172.17.0.1:4566/_eksuvia/webhook/demo",
		AssetsDir:         "/home/user/.eksuvia/clusters/demo",
	}
}

// kubeadm ClusterConfiguration, only the parts eksuvia patches.
type clusterConfig struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	APIServer  componentConfig `json:"apiServer"`
	Controller componentConfig `json:"controllerManager"`
}

type componentConfig struct {
	// ExtraArgs is deliberately left untyped: v1beta3 encodes it as a map and
	// v1beta4 as a list, and this test asserts on the raw shape.
	ExtraArgs    interface{}   `json:"extraArgs"`
	ExtraVolumes []hostPathVol `json:"extraVolumes"`
}

type hostPathVol struct {
	Name      string `json:"name"`
	HostPath  string `json:"hostPath"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
	PathType  string `json:"pathType"`
}

func parsePatches(t *testing.T, patches []string) map[string]clusterConfig {
	t.Helper()
	out := map[string]clusterConfig{}
	for i, patch := range patches {
		var cfg clusterConfig
		if err := yaml.Unmarshal([]byte(patch), &cfg); err != nil {
			t.Fatalf("patch %d is not valid YAML: %v\n%s", i, err, patch)
		}
		if cfg.Kind != "ClusterConfiguration" {
			t.Fatalf("patch %d has kind %q, want ClusterConfiguration", i, cfg.Kind)
		}
		out[cfg.APIVersion] = cfg
	}
	return out
}

// TestPatchesMountAssetsIntoStaticPods is a regression test for the bug that
// made every cluster creation time out.
//
// kube-apiserver and kube-controller-manager run as static pods, so a file
// bind-mounted onto the node is invisible to them unless kubeadm mounts it.
// Without extraVolumes the API server points --service-account-signing-key-file
// at a nonexistent path, crash-loops, and kubeadm waits five minutes for a
// control plane that never becomes healthy.
func TestPatchesMountAssetsIntoStaticPods(t *testing.T) {
	spec := testSpec()
	configs := parsePatches(t, kubeadmPatches(spec))

	for apiVersion, cfg := range configs {
		for name, component := range map[string]componentConfig{
			"apiServer":         cfg.APIServer,
			"controllerManager": cfg.Controller,
		} {
			if len(component.ExtraVolumes) == 0 {
				t.Fatalf("%s/%s has no extraVolumes: the signing key would not be visible inside the static pod",
					apiVersion, name)
			}
			vol := component.ExtraVolumes[0]
			if vol.HostPath != AssetsMountPath || vol.MountPath != AssetsMountPath {
				t.Errorf("%s/%s volume = hostPath %q -> mountPath %q, want both %q",
					apiVersion, name, vol.HostPath, vol.MountPath, AssetsMountPath)
			}
			if !vol.ReadOnly {
				t.Errorf("%s/%s volume should be read-only", apiVersion, name)
			}
		}
	}
}

func TestPatchesEmitBothKubeadmAPIVersions(t *testing.T) {
	// One patch per kubeadm API version, each pinned by apiVersion so kind
	// applies only the one matching the generated object. This is what lets a
	// single build target Kubernetes versions using map-shaped extraArgs
	// (v1beta3) and list-shaped extraArgs (v1beta4).
	configs := parsePatches(t, kubeadmPatches(testSpec()))

	v3, ok := configs["kubeadm.k8s.io/v1beta3"]
	if !ok {
		t.Fatal("no v1beta3 patch emitted")
	}
	v4, ok := configs["kubeadm.k8s.io/v1beta4"]
	if !ok {
		t.Fatal("no v1beta4 patch emitted")
	}

	if _, isMap := v3.APIServer.ExtraArgs.(map[string]interface{}); !isMap {
		t.Errorf("v1beta3 extraArgs = %T, want a map", v3.APIServer.ExtraArgs)
	}
	if _, isList := v4.APIServer.ExtraArgs.([]interface{}); !isList {
		t.Errorf("v1beta4 extraArgs = %T, want a list", v4.APIServer.ExtraArgs)
	}
}

func TestPatchesCarryTheEKSControlPlaneFlags(t *testing.T) {
	spec := testSpec()
	joined := strings.Join(kubeadmPatches(spec), "\n")

	required := []string{
		"authentication-token-webhook-config-file",
		AssetsMountPath + "/webhook.kubeconfig",
		"service-account-issuer",
		spec.OIDCIssuer,
		"service-account-signing-key-file",
		AssetsMountPath + "/sa.key",
		"service-account-key-file",
		AssetsMountPath + "/sa.pub",
		"api-audiences",
		"sts.amazonaws.com",
		// Without this the controller-manager signs legacy tokens with
		// kubeadm's key, which the API server no longer trusts.
		"service-account-private-key-file",
	}
	for _, want := range required {
		if !strings.Contains(joined, want) {
			t.Errorf("patches are missing %q", want)
		}
	}
}

func TestBuildKindConfig(t *testing.T) {
	spec := testSpec()
	cfg, err := buildKindConfig(spec)
	if err != nil {
		t.Fatalf("buildKindConfig returned unexpected error: %v", err)
	}

	if len(cfg.Nodes) != spec.WorkerPoolSize+1 {
		t.Fatalf("got %d nodes, want %d workers plus a control plane",
			len(cfg.Nodes), spec.WorkerPoolSize)
	}
	if cfg.Nodes[0].Role != v1alpha4.ControlPlaneRole {
		t.Errorf("first node role = %q, want control-plane", cfg.Nodes[0].Role)
	}
	for _, n := range cfg.Nodes[1:] {
		if n.Role != v1alpha4.WorkerRole {
			t.Errorf("pool node role = %q, want worker", n.Role)
		}
	}

	// The assets directory must be bind-mounted onto the control-plane node, in
	// addition to being mounted into the static pods by extraVolumes.
	mounts := cfg.Nodes[0].ExtraMounts
	if len(mounts) != 1 || mounts[0].HostPath != spec.AssetsDir || mounts[0].ContainerPath != AssetsMountPath {
		t.Errorf("control-plane extraMounts = %+v, want %s -> %s", mounts, spec.AssetsDir, AssetsMountPath)
	}
	if cfg.Networking.ServiceSubnet != spec.ServiceIPv4CIDR {
		t.Errorf("serviceSubnet = %q, want %q", cfg.Networking.ServiceSubnet, spec.ServiceIPv4CIDR)
	}
}

func TestBuildKindConfigRequiresIssuerAndWebhook(t *testing.T) {
	spec := testSpec()
	spec.OIDCIssuer = ""
	if _, err := buildKindConfig(spec); err == nil {
		t.Error("buildKindConfig accepted an empty OIDC issuer")
	}

	spec = testSpec()
	spec.WebhookURL = ""
	if _, err := buildKindConfig(spec); err == nil {
		t.Error("buildKindConfig accepted an empty webhook URL")
	}
}

func TestNodeImageDerivation(t *testing.T) {
	tests := []struct {
		version  string
		override string
		want     string
	}{
		{version: "1.31", want: "kindest/node:v1.31.0"},
		{version: "1.31.4", want: "kindest/node:v1.31.4"},
		{version: "v1.30", want: "kindest/node:v1.30.0"},
		{version: "1.31", override: "custom/node:latest", want: "custom/node:latest"},
		{version: "", want: ""},
	}
	for _, tt := range tests {
		got := nodeImage(Spec{KubernetesVersion: tt.version, NodeImage: tt.override})
		if got != tt.want {
			t.Errorf("nodeImage(%q, override=%q) = %q, want %q", tt.version, tt.override, got, tt.want)
		}
	}
}

func TestKindNameIsNamespaced(t *testing.T) {
	// Prevents colliding with clusters other tools created, and makes
	// `kind get clusters` legible.
	if got := KindName("demo"); got != "eksuvia-demo" {
		t.Errorf("KindName(demo) = %q, want eksuvia-demo", got)
	}
}

func TestWebhookKubeconfigIsValid(t *testing.T) {
	raw := webhookKubeconfig("http://172.17.0.1:4566/_eksuvia/webhook/demo")

	var parsed struct {
		APIVersion     string `json:"apiVersion"`
		CurrentContext string `json:"current-context"`
		Clusters       []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server string `json:"server"`
			} `json:"cluster"`
		} `json:"clusters"`
	}
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("webhook kubeconfig is not valid YAML: %v\n%s", err, raw)
	}
	if parsed.APIVersion != "v1" || parsed.CurrentContext == "" {
		t.Errorf("webhook kubeconfig is missing required fields: %+v", parsed)
	}
	if len(parsed.Clusters) != 1 || parsed.Clusters[0].Cluster.Server != "http://172.17.0.1:4566/_eksuvia/webhook/demo" {
		t.Errorf("webhook kubeconfig server = %+v", parsed.Clusters)
	}
}
