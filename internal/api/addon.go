package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/store"
)

// addonCatalog is the set of managed add-ons eksuvia advertises through
// DescribeAddonVersions.
//
// The entries mirror the add-ons EKS actually offers, because tools resolve a
// version from this call before creating one -- Terraform's
// aws_eks_addon.most_recent, eksctl's defaults -- and an empty catalog makes
// them fail before they ever get to CreateAddon.
//
// providedByKind records whether kind's own bootstrap already runs the
// component. Those add-ons are genuinely present and report ACTIVE; the rest
// are tracked as API objects but deploy nothing yet, and say so in their health
// rather than claiming a healthy state they have not earned.
var addonCatalog = []struct {
	Name           string
	Versions       []string
	providedByKind bool
}{
	{Name: "coredns", Versions: []string{"v1.11.3-eksbuild.1", "v1.11.1-eksbuild.9"}, providedByKind: true},
	{Name: "kube-proxy", Versions: []string{"v1.31.2-eksbuild.3", "v1.30.6-eksbuild.3"}, providedByKind: true},
	{Name: "vpc-cni", Versions: []string{"v1.19.0-eksbuild.1", "v1.18.6-eksbuild.1"}},
	{Name: "aws-ebs-csi-driver", Versions: []string{"v1.37.0-eksbuild.1"}},
	{Name: "aws-efs-csi-driver", Versions: []string{"v2.1.4-eksbuild.1"}},
	{Name: "eks-pod-identity-agent", Versions: []string{"v1.3.4-eksbuild.1"}},
	{Name: "metrics-server", Versions: []string{"v0.7.2-eksbuild.1"}},
	{Name: "snapshot-controller", Versions: []string{"v8.1.0-eksbuild.2"}},
}

func lookupAddon(name string) (versions []string, providedByKind, known bool) {
	for _, a := range addonCatalog {
		if a.Name == name {
			return a.Versions, a.providedByKind, true
		}
	}
	return nil, false, false
}

// notInstalledIssue explains an add-on that exists as an API object but has no
// workload behind it.
//
// The code is deliberately "Unknown" -- a real EKS health code -- rather than
// borrowing a specific one like ConfigurationConflict, which would send anyone
// debugging this down the wrong path.
func notInstalledIssue(name string) model.Issue {
	return model.Issue{
		Code: "Unknown",
		Message: fmt.Sprintf(
			"eksuvia tracks the %q add-on through the EKS API but does not deploy it yet, "+
				"so no workload was installed in the cluster. See docs/roadmap.md.", name),
		ResourceIDs: []string{name},
	}
}

type addonVersionInfo struct {
	AddonVersion  string               `json:"addonVersion"`
	Architecture  []string             `json:"architecture,omitempty"`
	Compatibility []addonCompatibility `json:"compatibilities,omitempty"`
}

type addonCompatibility struct {
	ClusterVersion   string   `json:"clusterVersion"`
	PlatformVersions []string `json:"platformVersions"`
	DefaultVersion   bool     `json:"defaultVersion"`
}

type addonInfo struct {
	AddonName     string             `json:"addonName"`
	Type          string             `json:"type"`
	AddonVersions []addonVersionInfo `json:"addonVersions"`
}

// handleDescribeAddonVersions advertises the add-on catalog.
func (s *Server) handleDescribeAddonVersions(w http.ResponseWriter, r *http.Request, _ Params) {
	query := r.URL.Query()
	wantName := query.Get("addonName")
	clusterVersion := query.Get("kubernetesVersion")
	if clusterVersion == "" {
		clusterVersion = model.DefaultKubernetesVersion
	}

	addons := make([]addonInfo, 0, len(addonCatalog))
	for _, entry := range addonCatalog {
		if wantName != "" && entry.Name != wantName {
			continue
		}
		versions := make([]addonVersionInfo, 0, len(entry.Versions))
		for i, v := range entry.Versions {
			versions = append(versions, addonVersionInfo{
				AddonVersion: v,
				Architecture: []string{"amd64", "arm64"},
				Compatibility: []addonCompatibility{{
					ClusterVersion:   clusterVersion,
					PlatformVersions: []string{"*"},
					// The first entry is the default, which is what
					// "most_recent" resolution keys off.
					DefaultVersion: i == 0,
				}},
			})
		}
		addons = append(addons, addonInfo{
			AddonName:     entry.Name,
			Type:          "infra",
			AddonVersions: versions,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"addons": addons})
}

type createAddonRequest struct {
	AddonName             string            `json:"addonName"`
	AddonVersion          string            `json:"addonVersion"`
	ServiceAccountRoleARN string            `json:"serviceAccountRoleArn"`
	ResolveConflicts      string            `json:"resolveConflicts"`
	ClientRequestToken    string            `json:"clientRequestToken"`
	Tags                  map[string]string `json:"tags"`
	ConfigurationValues   string            `json:"configurationValues"`
}

func (s *Server) handleCreateAddon(w http.ResponseWriter, r *http.Request, p Params) {
	clusterName := p["name"]
	state, err := s.store.Get(clusterName)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req createAddonRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.AddonName == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter, "addonName is required.")
		return
	}

	versions, providedByKind, known := lookupAddon(req.AddonName)
	if !known {
		writeErrorDetail(w, http.StatusBadRequest, ErrInvalidParameter, errorBody{
			Message:     fmt.Sprintf("Addon %q is not supported.", req.AddonName),
			ClusterName: clusterName,
			AddonName:   req.AddonName,
		})
		return
	}
	if _, exists := state.Addons[req.AddonName]; exists {
		writeErrorDetail(w, http.StatusConflict, ErrResourceInUse, errorBody{
			Message:     fmt.Sprintf("Addon %q is already installed on cluster %q.", req.AddonName, clusterName),
			ClusterName: clusterName,
			AddonName:   req.AddonName,
		})
		return
	}

	version := req.AddonVersion
	if version == "" {
		version = versions[0]
	}

	now := model.UnixMillisFloat(time.Now())
	addon := &model.Addon{
		AddonName:             req.AddonName,
		ClusterName:           clusterName,
		AddonVersion:          version,
		AddonARN:              fmt.Sprintf("arn:aws:eks:%s:%s:addon/%s/%s", s.cfg.Region, s.cfg.AccountID, clusterName, req.AddonName),
		CreatedAt:             now,
		ModifiedAt:            now,
		ServiceAccountRoleARN: req.ServiceAccountRoleARN,
		Tags:                  req.Tags,
		ConfigurationValues:   req.ConfigurationValues,
		Status:                model.AddonStatusCreating,
	}

	if err := s.store.Update(clusterName, func(c *store.ClusterState) {
		c.Addons[req.AddonName] = addon
	}); err != nil {
		writeStoreError(w, err)
		return
	}

	go s.reconcileAddon(clusterName, req.AddonName, providedByKind)

	writeJSON(w, http.StatusOK, map[string]any{"addon": addon})
}

// reconcileAddon settles an add-on into its real status.
func (s *Server) reconcileAddon(clusterName, addonName string, providedByKind bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status := model.AddonStatusDegraded
	var health *model.AddonHealth

	if providedByKind {
		// coredns and kube-proxy are bootstrapped by kubeadm, so the component
		// really is running. Confirm rather than assume: if the cluster is not
		// reachable, do not claim ACTIVE.
		if client, err := s.clientFor(clusterName); err == nil {
			if err := client.Ready(ctx); err == nil {
				status = model.AddonStatusActive
			}
		}
	}
	if status != model.AddonStatusActive {
		health = &model.AddonHealth{Issues: []model.Issue{notInstalledIssue(addonName)}}
	}

	_ = s.store.Update(clusterName, func(c *store.ClusterState) {
		addon := c.Addons[addonName]
		if addon == nil {
			return
		}
		addon.Status = status
		addon.Health = health
		addon.ModifiedAt = model.UnixMillisFloat(time.Now())
	})
}

func (s *Server) handleListAddons(w http.ResponseWriter, r *http.Request, p Params) {
	state, err := s.store.Get(p["name"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	names := make([]string, 0, len(state.Addons))
	for name := range state.Addons {
		names = append(names, name)
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string]any{"addons": names})
}

func (s *Server) handleDescribeAddon(w http.ResponseWriter, r *http.Request, p Params) {
	state, err := s.store.Get(p["name"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	addon := state.Addons[p["addon"]]
	if addon == nil {
		writeErrorDetail(w, http.StatusNotFound, ErrResourceNotFound, errorBody{
			Message:     fmt.Sprintf("No addon %q found for cluster %q.", p["addon"], p["name"]),
			ClusterName: p["name"],
			AddonName:   p["addon"],
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"addon": addon})
}

func (s *Server) handleDeleteAddon(w http.ResponseWriter, r *http.Request, p Params) {
	clusterName, addonName := p["name"], p["addon"]
	state, err := s.store.Get(clusterName)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	addon := state.Addons[addonName]
	if addon == nil {
		writeErrorDetail(w, http.StatusNotFound, ErrResourceNotFound, errorBody{
			Message:     fmt.Sprintf("No addon %q found for cluster %q.", addonName, clusterName),
			ClusterName: clusterName,
			AddonName:   addonName,
		})
		return
	}

	addon.Status = model.AddonStatusDeleting
	if err := s.store.Update(clusterName, func(c *store.ClusterState) {
		delete(c.Addons, addonName)
	}); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"addon": addon})
}
