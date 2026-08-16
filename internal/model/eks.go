// Package model contains the wire types for the EKS control plane API.
//
// EKS uses the restJson1 protocol: resources are addressed by path
// (GET /clusters/{name}) with lowerCamelCase JSON bodies, unlike the
// X-Amz-Target style of most AWS services. Field names and casing here are
// load-bearing -- the AWS SDKs, eksctl and Terraform all unmarshal these
// verbatim, so a single renamed key surfaces as a confusing nil deref in
// somebody else's tool.
package model

import "time"

// Cluster status values. A real cluster dwells in CREATING for ~10 minutes;
// eksuvia moves through the same states in seconds but never skips them, so
// that callers which poll for ACTIVE exercise their real code path.
const (
	ClusterStatusCreating = "CREATING"
	ClusterStatusActive   = "ACTIVE"
	ClusterStatusDeleting = "DELETING"
	ClusterStatusFailed   = "FAILED"
	ClusterStatusUpdating = "UPDATING"
)

// Authentication modes for cluster access.
const (
	AuthModeConfigMap          = "CONFIG_MAP"
	AuthModeAPI                = "API"
	AuthModeAPIAndConfigMap    = "API_AND_CONFIG_MAP"
	DefaultAuthenticationMode  = AuthModeAPIAndConfigMap
	DefaultKubernetesVersion   = "1.31"
	DefaultPlatformVersion     = "eks.1"
	DefaultServiceIPv4CIDR     = "10.100.0.0/16"
	DefaultIPFamily            = "ipv4"
	DefaultClusterUpgradePlan  = "EXTENDED"
	DefaultNodegroupAMIType    = "AL2023_x86_64_STANDARD"
	DefaultNodegroupCapacity   = "ON_DEMAND"
	DefaultNodegroupDiskSizeGB = 20
)

// Certificate carries the base64 PEM of the cluster CA.
//
// Data is a pointer because EKS reports it as null -- not an empty string --
// until the cluster reaches ACTIVE, and callers branch on that.
type Certificate struct {
	Data *string `json:"data"`
}

// OIDC is the cluster's IRSA issuer.
type OIDC struct {
	Issuer string `json:"issuer"`
}

// Identity wraps the OIDC issuer under the shape DescribeCluster returns.
type Identity struct {
	OIDC OIDC `json:"oidc"`
}

// VpcConfigResponse is the resourcesVpcConfig block. eksuvia has no real VPC,
// but the fields are echoed back faithfully because Terraform and eksctl assert
// on them.
type VpcConfigResponse struct {
	SubnetIDs              []string `json:"subnetIds"`
	SecurityGroupIDs       []string `json:"securityGroupIds"`
	ClusterSecurityGroupID string   `json:"clusterSecurityGroupId,omitempty"`
	VpcID                  string   `json:"vpcId,omitempty"`
	EndpointPublicAccess   bool     `json:"endpointPublicAccess"`
	EndpointPrivateAccess  bool     `json:"endpointPrivateAccess"`
	PublicAccessCIDRs      []string `json:"publicAccessCidrs,omitempty"`
}

// KubernetesNetworkConfig describes service networking.
type KubernetesNetworkConfig struct {
	ServiceIPv4CIDR string `json:"serviceIpv4Cidr,omitempty"`
	ServiceIPv6CIDR string `json:"serviceIpv6Cidr,omitempty"`
	IPFamily        string `json:"ipFamily,omitempty"`
}

// AccessConfig controls how IAM principals map into the cluster.
type AccessConfig struct {
	AuthenticationMode                      string `json:"authenticationMode"`
	BootstrapClusterCreatorAdminPermissions *bool  `json:"bootstrapClusterCreatorAdminPermissions,omitempty"`
}

// LogSetup is one logging selection.
type LogSetup struct {
	Types   []string `json:"types"`
	Enabled bool     `json:"enabled"`
}

// Logging is the cluster logging block.
type Logging struct {
	ClusterLogging []LogSetup `json:"clusterLogging"`
}

// UpgradePolicy mirrors the standard/extended support setting.
type UpgradePolicy struct {
	SupportType string `json:"supportType,omitempty"`
}

// Cluster is the DescribeCluster payload.
type Cluster struct {
	Name                    string                   `json:"name"`
	ARN                     string                   `json:"arn"`
	CreatedAt               float64                  `json:"createdAt"`
	Version                 string                   `json:"version"`
	Endpoint                string                   `json:"endpoint,omitempty"`
	RoleARN                 string                   `json:"roleArn"`
	ResourcesVpcConfig      VpcConfigResponse        `json:"resourcesVpcConfig"`
	KubernetesNetworkConfig *KubernetesNetworkConfig `json:"kubernetesNetworkConfig,omitempty"`
	Logging                 *Logging                 `json:"logging,omitempty"`
	Identity                *Identity                `json:"identity,omitempty"`
	Status                  string                   `json:"status"`
	CertificateAuthority    Certificate              `json:"certificateAuthority"`
	ClientRequestToken      string                   `json:"clientRequestToken,omitempty"`
	PlatformVersion         string                   `json:"platformVersion"`
	Tags                    map[string]string        `json:"tags,omitempty"`
	AccessConfig            *AccessConfig            `json:"accessConfig,omitempty"`
	UpgradePolicy           *UpgradePolicy           `json:"upgradePolicy,omitempty"`
	ID                      string                   `json:"id,omitempty"`
}

// UnixMillisFloat renders a timestamp the way the EKS API does: seconds since
// the epoch carrying a fractional millisecond part.
func UnixMillisFloat(t time.Time) float64 {
	return float64(t.UnixNano()) / float64(time.Second)
}

// Nodegroup status values.
const (
	NodegroupStatusCreating     = "CREATING"
	NodegroupStatusActive       = "ACTIVE"
	NodegroupStatusUpdating     = "UPDATING"
	NodegroupStatusDeleting     = "DELETING"
	NodegroupStatusCreateFailed = "CREATE_FAILED"
	NodegroupStatusDegraded     = "DEGRADED"
)

// NodegroupScalingConfig is the desired/min/max triple.
type NodegroupScalingConfig struct {
	MinSize     *int32 `json:"minSize,omitempty"`
	MaxSize     *int32 `json:"maxSize,omitempty"`
	DesiredSize *int32 `json:"desiredSize,omitempty"`
}

// NodegroupResources reports what the node group actually created. eksuvia
// reports the kind node container names in place of ASG names.
type NodegroupResources struct {
	AutoScalingGroups []AutoScalingGroup `json:"autoScalingGroups,omitempty"`
}

// AutoScalingGroup names one backing ASG.
type AutoScalingGroup struct {
	Name string `json:"name"`
}

// Taint is a Kubernetes taint applied by the node group.
type Taint struct {
	Key    string `json:"key,omitempty"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect,omitempty"`
}

// Nodegroup is the DescribeNodegroup payload.
type Nodegroup struct {
	NodegroupName  string                  `json:"nodegroupName"`
	NodegroupARN   string                  `json:"nodegroupArn"`
	ClusterName    string                  `json:"clusterName"`
	Version        string                  `json:"version,omitempty"`
	ReleaseVersion string                  `json:"releaseVersion,omitempty"`
	CreatedAt      float64                 `json:"createdAt"`
	ModifiedAt     float64                 `json:"modifiedAt"`
	Status         string                  `json:"status"`
	CapacityType   string                  `json:"capacityType,omitempty"`
	ScalingConfig  *NodegroupScalingConfig `json:"scalingConfig,omitempty"`
	InstanceTypes  []string                `json:"instanceTypes,omitempty"`
	Subnets        []string                `json:"subnets,omitempty"`
	AMIType        string                  `json:"amiType,omitempty"`
	NodeRole       string                  `json:"nodeRole"`
	Labels         map[string]string       `json:"labels,omitempty"`
	Taints         []Taint                 `json:"taints,omitempty"`
	Resources      *NodegroupResources     `json:"resources,omitempty"`
	DiskSize       *int32                  `json:"diskSize,omitempty"`
	Health         *NodegroupHealth        `json:"health,omitempty"`
	Tags           map[string]string       `json:"tags,omitempty"`
}

// NodegroupHealth carries issues preventing the group from going ACTIVE.
type NodegroupHealth struct {
	Issues []Issue `json:"issues"`
}

// Issue is one health problem.
type Issue struct {
	Code        string   `json:"code,omitempty"`
	Message     string   `json:"message,omitempty"`
	ResourceIDs []string `json:"resourceIds,omitempty"`
}

// Access entry types.
const (
	AccessEntryTypeStandard  = "STANDARD"
	AccessEntryTypeEC2Linux  = "EC2_LINUX"
	AccessScopeCluster       = "cluster"
	AccessScopeNamespace     = "namespace"
	ClusterAdminPolicyARN    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
	AdminPolicyARN           = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy"
	EditPolicyARN            = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSEditPolicy"
	ViewPolicyARN            = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
	AdminViewPolicyARN       = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminViewPolicy"
	ClusterAdminPolicyRole   = "cluster-admin"
	NamespacedAdminRole      = "admin"
	NamespacedEditRole       = "edit"
	NamespacedViewRole       = "view"
	EKSNodeUsernameTemplate  = "system:node:{{EC2PrivateDNSName}}"
	AWSAuthConfigMapName     = "aws-auth"
	AWSAuthConfigMapNS       = "kube-system"
	SystemMastersGroup       = "system:masters"
	SystemNodesGroup         = "system:nodes"
	SystemBootstrappersGroup = "system:bootstrappers"
)

// AccessScope limits an access policy to the whole cluster or to namespaces.
type AccessScope struct {
	Type       string   `json:"type"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// AssociatedAccessPolicy is one policy bound to an access entry.
type AssociatedAccessPolicy struct {
	PolicyARN    string      `json:"policyArn"`
	AccessScope  AccessScope `json:"accessScope"`
	AssociatedAt float64     `json:"associatedAt"`
	ModifiedAt   float64     `json:"modifiedAt"`
}

// AccessEntry maps an IAM principal into the cluster.
type AccessEntry struct {
	ClusterName      string            `json:"clusterName"`
	PrincipalARN     string            `json:"principalArn"`
	KubernetesGroups []string          `json:"kubernetesGroups,omitempty"`
	AccessEntryARN   string            `json:"accessEntryArn"`
	CreatedAt        float64           `json:"createdAt"`
	ModifiedAt       float64           `json:"modifiedAt"`
	Tags             map[string]string `json:"tags,omitempty"`
	Username         string            `json:"username,omitempty"`
	Type             string            `json:"type"`

	// Policies is eksuvia-internal bookkeeping for associated access policies.
	// It is not serialized on the AccessEntry itself because the real API
	// returns policies only from ListAssociatedAccessPolicies.
	Policies []AssociatedAccessPolicy `json:"-"`
}

// AccessPolicy is an AWS-managed cluster access policy.
type AccessPolicy struct {
	Name string `json:"name"`
	ARN  string `json:"arn"`
}

// Addon status values.
const (
	AddonStatusCreating = "CREATING"
	AddonStatusActive   = "ACTIVE"
	AddonStatusDeleting = "DELETING"
	AddonStatusDegraded = "DEGRADED"
)

// Addon is an EKS managed add-on.
type Addon struct {
	AddonName             string            `json:"addonName"`
	ClusterName           string            `json:"clusterName"`
	Status                string            `json:"status"`
	AddonVersion          string            `json:"addonVersion"`
	AddonARN              string            `json:"addonArn"`
	CreatedAt             float64           `json:"createdAt"`
	ModifiedAt            float64           `json:"modifiedAt"`
	ServiceAccountRoleARN string            `json:"serviceAccountRoleArn,omitempty"`
	Tags                  map[string]string `json:"tags,omitempty"`
	ConfigurationValues   string            `json:"configurationValues,omitempty"`
	Health                *AddonHealth      `json:"health,omitempty"`
}

// AddonHealth carries the issues preventing an add-on from being healthy.
type AddonHealth struct {
	Issues []Issue `json:"issues"`
}

// PodIdentityAssociation binds a service account to an IAM role.
type PodIdentityAssociation struct {
	ClusterName    string            `json:"clusterName"`
	Namespace      string            `json:"namespace"`
	ServiceAccount string            `json:"serviceAccount"`
	RoleARN        string            `json:"roleArn"`
	AssociationARN string            `json:"associationArn"`
	AssociationID  string            `json:"associationId"`
	Tags           map[string]string `json:"tags,omitempty"`
	CreatedAt      float64           `json:"createdAt"`
	ModifiedAt     float64           `json:"modifiedAt"`
}
