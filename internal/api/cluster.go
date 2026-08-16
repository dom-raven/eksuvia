package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/dom-raven/eksuvia/internal/kindprov"
	"github.com/dom-raven/eksuvia/internal/kube"
	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/oidc"
	"github.com/dom-raven/eksuvia/internal/store"
)

// clusterNamePattern is the constraint EKS enforces on cluster names. It is
// applied here so a name that would be rejected by AWS is also rejected
// locally, rather than failing later at a confusing layer.
var clusterNamePattern = regexp.MustCompile(`^[0-9A-Za-z][A-Za-z0-9\-_]{0,99}$`)

type createClusterRequest struct {
	Name               string                         `json:"name"`
	Version            string                         `json:"version"`
	RoleARN            string                         `json:"roleArn"`
	ResourcesVpcConfig *model.VpcConfigResponse       `json:"resourcesVpcConfig"`
	KubernetesNetwork  *model.KubernetesNetworkConfig `json:"kubernetesNetworkConfig"`
	Logging            *model.Logging                 `json:"logging"`
	Tags               map[string]string              `json:"tags"`
	ClientRequestToken string                         `json:"clientRequestToken"`
	AccessConfig       *model.AccessConfig            `json:"accessConfig"`
	UpgradePolicy      *model.UpgradePolicy           `json:"upgradePolicy"`
}

func (s *Server) handleCreateCluster(w http.ResponseWriter, r *http.Request, _ Params) {
	var req createClusterRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if !clusterNamePattern.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			fmt.Sprintf("Cluster name %q is invalid: it must start with an alphanumeric character and contain only alphanumerics, hyphens and underscores.", req.Name))
		return
	}
	if req.RoleARN == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter, "roleArn is required.")
		return
	}

	version := req.Version
	if version == "" {
		version = model.DefaultKubernetesVersion
	}

	authMode := model.DefaultAuthenticationMode
	bootstrapAdmin := true
	if req.AccessConfig != nil {
		if req.AccessConfig.AuthenticationMode != "" {
			authMode = req.AccessConfig.AuthenticationMode
		}
		if req.AccessConfig.BootstrapClusterCreatorAdminPermissions != nil {
			bootstrapAdmin = *req.AccessConfig.BootstrapClusterCreatorAdminPermissions
		}
	}
	switch authMode {
	case model.AuthModeAPI, model.AuthModeConfigMap, model.AuthModeAPIAndConfigMap:
	default:
		writeError(w, http.StatusBadRequest, ErrInvalidParameter,
			fmt.Sprintf("Invalid authenticationMode %q: expected API, CONFIG_MAP or API_AND_CONFIG_MAP.", authMode))
		return
	}

	issuerID := oidc.IssuerID(req.Name, s.cfg.AccountID)
	issuer := fmt.Sprintf("%s/id/%s", s.cfg.AdvertisedBaseURL(), issuerID)
	signer, err := oidc.NewSigner(issuer)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrServerException, err.Error())
		return
	}

	serviceCIDR := model.DefaultServiceIPv4CIDR
	ipFamily := model.DefaultIPFamily
	if req.KubernetesNetwork != nil {
		if req.KubernetesNetwork.ServiceIPv4CIDR != "" {
			serviceCIDR = req.KubernetesNetwork.ServiceIPv4CIDR
		}
		if req.KubernetesNetwork.IPFamily != "" {
			ipFamily = req.KubernetesNetwork.IPFamily
		}
	}

	vpcConfig := model.VpcConfigResponse{EndpointPublicAccess: true}
	if req.ResourcesVpcConfig != nil {
		vpcConfig = *req.ResourcesVpcConfig
	}
	// EKS always creates a cluster security group and reports it back; tools
	// read this field to attach rules, so it must be populated even though
	// eksuvia has no real VPC behind it. The format is load-bearing: some
	// tooling validates it against ^sg-[0-9a-f]{17}$.
	if vpcConfig.ClusterSecurityGroupID == "" {
		vpcConfig.ClusterSecurityGroupID = "sg-" + strings.ToLower(issuerID[:17])
	}
	// AWS returns empty arrays here, never null. A caller that iterates without
	// a nil check breaks on null, and that is a tedious bug to trace back to
	// the emulator.
	if vpcConfig.SubnetIDs == nil {
		vpcConfig.SubnetIDs = []string{}
	}
	if vpcConfig.SecurityGroupIDs == nil {
		vpcConfig.SecurityGroupIDs = []string{}
	}

	now := time.Now()
	state := &store.ClusterState{
		Cluster: model.Cluster{
			Name:                 req.Name,
			ARN:                  s.clusterARN(req.Name),
			CreatedAt:            model.UnixMillisFloat(now),
			Version:              version,
			RoleARN:              req.RoleARN,
			ResourcesVpcConfig:   vpcConfig,
			Status:               model.ClusterStatusCreating,
			PlatformVersion:      model.DefaultPlatformVersion,
			Tags:                 req.Tags,
			ClientRequestToken:   req.ClientRequestToken,
			CertificateAuthority: model.Certificate{},
			Identity:             &model.Identity{OIDC: model.OIDC{Issuer: issuer}},
			KubernetesNetworkConfig: &model.KubernetesNetworkConfig{
				ServiceIPv4CIDR: serviceCIDR,
				IPFamily:        ipFamily,
			},
			Logging: req.Logging,
			AccessConfig: &model.AccessConfig{
				AuthenticationMode:                      authMode,
				BootstrapClusterCreatorAdminPermissions: &bootstrapAdmin,
			},
			UpgradePolicy: req.UpgradePolicy,
			ID:            issuerID,
		},
		KindName: kindprov.KindName(req.Name),
		Signer:   signer,
	}

	if err := s.store.Add(state); err != nil {
		writeStoreError(w, err)
		return
	}
	s.issuerIndex.Store(issuerID, req.Name)

	// EKS returns immediately with status CREATING and provisions in the
	// background. Reproducing that -- rather than blocking until ready -- is
	// what makes callers exercise their real waiter code.
	go s.provisionCluster(req.Name, bootstrapAdmin)

	writeJSON(w, http.StatusOK, map[string]any{"cluster": state.Cluster})
}

// provisionCluster does the slow work of standing up the data plane and moves
// the cluster to ACTIVE or FAILED.
func (s *Server) provisionCluster(name string, bootstrapAdmin bool) {
	s.createMu.Lock()
	defer s.createMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.ClusterCreateTimeout+2*time.Minute)
	defer cancel()

	state, err := s.store.Get(name)
	if err != nil {
		return // deleted while queued
	}

	fail := func(err error) {
		s.log.Error("cluster provisioning failed", "cluster", name, "error", err)
		_ = s.store.Update(name, func(c *store.ClusterState) {
			c.Cluster.Status = model.ClusterStatusFailed
		})
	}

	pubPEM, err := state.Signer.PublicKeyPEM()
	if err != nil {
		fail(err)
		return
	}

	spec := kindprov.Spec{
		EKSName:           name,
		KubernetesVersion: state.Cluster.Version,
		NodeImage:         s.cfg.NodeImage,
		WorkerPoolSize:    s.cfg.WorkerPoolSize,
		ServiceIPv4CIDR:   state.Cluster.KubernetesNetworkConfig.ServiceIPv4CIDR,
		OIDCIssuer:        state.Signer.Issuer,
		SigningKeyPEM:     state.Signer.PrivateKeyPEM(),
		PublicKeyPEM:      pubPEM,
		WebhookURL:        fmt.Sprintf("%s/_eksuvia/webhook/%s", s.cfg.AdvertisedBaseURL(), name),
		AssetsDir:         s.cfg.ClusterAssetsDir(name),
	}

	s.log.Info("provisioning cluster", "cluster", name, "kind", spec.EKSName, "version", state.Cluster.Version)
	result, err := s.kind.Create(ctx, spec)
	if err != nil {
		fail(err)
		return
	}

	caPEM, err := kube.CACertPEM(result.Kubeconfig)
	if err != nil {
		fail(err)
		return
	}
	endpoint, err := kube.ServerURL(result.Kubeconfig)
	if err != nil {
		fail(err)
		return
	}

	client, err := kube.NewFromKubeconfig(result.Kubeconfig)
	if err != nil {
		fail(err)
		return
	}

	_ = s.store.Update(name, func(c *store.ClusterState) {
		c.Kubeconfig = result.Kubeconfig
		c.Cluster.Endpoint = endpoint
		encoded := base64.StdEncoding.EncodeToString(caPEM)
		c.Cluster.CertificateAuthority = model.Certificate{Data: &encoded}
		c.Cluster.Status = model.ClusterStatusActive
	})

	// The cluster creator's access entry is what makes the very first
	// `kubectl get nodes` work. Without it the creator authenticates fine and is
	// then refused by RBAC, which is a genuinely confusing first experience.
	if bootstrapAdmin {
		if err := s.bootstrapCreatorAccess(ctx, name, client); err != nil {
			s.log.Warn("could not bootstrap cluster creator access", "cluster", name, "error", err)
		}
	}

	s.log.Info("cluster active", "cluster", name, "endpoint", endpoint)
}

// bootstrapCreatorAccess grants cluster-admin to the configured creator
// principal, mirroring bootstrapClusterCreatorAdminPermissions.
func (s *Server) bootstrapCreatorAccess(ctx context.Context, cluster string, client *kube.Client) error {
	entry := &model.AccessEntry{
		ClusterName:    cluster,
		PrincipalARN:   s.cfg.ClusterCreatorARN,
		AccessEntryARN: s.accessEntryARN(cluster, s.cfg.ClusterCreatorARN),
		CreatedAt:      model.UnixMillisFloat(time.Now()),
		ModifiedAt:     model.UnixMillisFloat(time.Now()),
		Type:           model.AccessEntryTypeStandard,
		Username:       s.cfg.ClusterCreatorARN,
		Policies: []model.AssociatedAccessPolicy{{
			PolicyARN:    model.ClusterAdminPolicyARN,
			AccessScope:  model.AccessScope{Type: model.AccessScopeCluster},
			AssociatedAt: model.UnixMillisFloat(time.Now()),
			ModifiedAt:   model.UnixMillisFloat(time.Now()),
		}},
	}

	if err := s.store.Update(cluster, func(c *store.ClusterState) {
		c.AccessEntries[entry.PrincipalARN] = entry
	}); err != nil {
		return err
	}
	return s.reconcileAccessEntry(ctx, client, entry)
}

func (s *Server) handleListClusters(w http.ResponseWriter, r *http.Request, _ Params) {
	writeJSON(w, http.StatusOK, map[string]any{"clusters": s.store.Names()})
}

func (s *Server) handleDescribeCluster(w http.ResponseWriter, r *http.Request, p Params) {
	state, err := s.store.Get(p["name"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cluster": state.Cluster})
}

func (s *Server) handleDeleteCluster(w http.ResponseWriter, r *http.Request, p Params) {
	name := p["name"]
	state, err := s.store.Get(name)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	// Real EKS refuses to delete a cluster that still has node groups, and
	// reports exactly this exception. Callers rely on it to sequence teardown.
	if len(state.Nodegroups) > 0 {
		writeErrorDetail(w, http.StatusConflict, ErrResourceInUse, errorBody{
			Message:     "Cluster has nodegroups attached",
			ClusterName: name,
		})
		return
	}

	deleted, err := s.store.Delete(name)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	deleted.Cluster.Status = model.ClusterStatusDeleting
	s.issuerIndex.Delete(deleted.Cluster.ID)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := s.kind.Delete(ctx, name, s.cfg.ClusterAssetsDir(name)); err != nil {
			s.log.Error("deleting cluster", "cluster", name, "error", err)
			return
		}
		s.log.Info("cluster deleted", "cluster", name)
	}()

	writeJSON(w, http.StatusOK, map[string]any{"cluster": deleted.Cluster})
}
