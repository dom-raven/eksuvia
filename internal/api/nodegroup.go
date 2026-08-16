package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dom-raven/eksuvia/internal/kube"
	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/oidc"
	"github.com/dom-raven/eksuvia/internal/store"
)

// nodegroupLabel marks which node group owns a node. Its presence is also how
// eksuvia tells an allocated node from a free one in the pool.
const nodegroupLabel = "eks.amazonaws.com/nodegroup"

type createNodegroupRequest struct {
	NodegroupName string                        `json:"nodegroupName"`
	ScalingConfig *model.NodegroupScalingConfig `json:"scalingConfig"`
	DiskSize      *int32                        `json:"diskSize"`
	Subnets       []string                      `json:"subnets"`
	InstanceTypes []string                      `json:"instanceTypes"`
	AMIType       string                        `json:"amiType"`
	NodeRole      string                        `json:"nodeRole"`
	Labels        map[string]string             `json:"labels"`
	Taints        []model.Taint                 `json:"taints"`
	Tags          map[string]string             `json:"tags"`
	CapacityType  string                        `json:"capacityType"`
	Version       string                        `json:"version"`
}

func (s *Server) handleCreateNodegroup(w http.ResponseWriter, r *http.Request, p Params) {
	clusterName := p["name"]
	state, err := s.store.Get(clusterName)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	var req createNodegroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.NodegroupName == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter, "nodegroupName is required.")
		return
	}
	if req.NodeRole == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidParameter, "nodeRole is required.")
		return
	}
	if _, exists := state.Nodegroups[req.NodegroupName]; exists {
		writeErrorDetail(w, http.StatusConflict, ErrResourceInUse, errorBody{
			Message:       "NodeGroup already exists with name " + req.NodegroupName + " and cluster name " + clusterName,
			ClusterName:   clusterName,
			NodegroupName: req.NodegroupName,
		})
		return
	}
	if state.Cluster.Status != model.ClusterStatusActive {
		writeErrorDetail(w, http.StatusBadRequest, ErrInvalidRequest, errorBody{
			Message:     "Cluster " + clusterName + " is not ACTIVE.",
			ClusterName: clusterName,
		})
		return
	}

	desired := int32(2)
	if req.ScalingConfig != nil && req.ScalingConfig.DesiredSize != nil {
		desired = *req.ScalingConfig.DesiredSize
	}
	capacityType := req.CapacityType
	if capacityType == "" {
		capacityType = model.DefaultNodegroupCapacity
	}
	amiType := req.AMIType
	if amiType == "" {
		amiType = model.DefaultNodegroupAMIType
	}
	instanceTypes := req.InstanceTypes
	if len(instanceTypes) == 0 {
		instanceTypes = []string{"t3.medium"}
	}
	diskSize := req.DiskSize
	if diskSize == nil {
		d := int32(model.DefaultNodegroupDiskSizeGB)
		diskSize = &d
	}
	version := req.Version
	if version == "" {
		version = state.Cluster.Version
	}

	now := model.UnixMillisFloat(time.Now())
	ng := &model.Nodegroup{
		NodegroupName: req.NodegroupName,
		NodegroupARN:  s.nodegroupARN(clusterName, req.NodegroupName, oidc.IssuerID(clusterName+req.NodegroupName, s.cfg.AccountID)[:8]),
		ClusterName:   clusterName,
		Version:       version,
		CreatedAt:     now,
		ModifiedAt:    now,
		Status:        model.NodegroupStatusCreating,
		CapacityType:  capacityType,
		ScalingConfig: req.ScalingConfig,
		InstanceTypes: instanceTypes,
		Subnets:       req.Subnets,
		AMIType:       amiType,
		NodeRole:      req.NodeRole,
		Labels:        req.Labels,
		Taints:        req.Taints,
		DiskSize:      diskSize,
		Tags:          req.Tags,
	}

	if err := s.store.Update(clusterName, func(c *store.ClusterState) {
		c.Nodegroups[req.NodegroupName] = ng
	}); err != nil {
		writeStoreError(w, err)
		return
	}

	go s.allocateNodegroup(clusterName, req.NodegroupName, desired, instanceTypes[0])

	writeJSON(w, http.StatusOK, map[string]any{"nodegroup": ng})
}

// allocateNodegroup claims nodes from the cluster's worker pool and stamps the
// EKS-shaped labels and taints onto them.
//
// This is where kind's one hard constraint shows through: it cannot add nodes
// to a running cluster. So workers are created up front as a pool, and a node
// group claims from it. The consequence is deliberate and documented -- a node
// group asking for more capacity than the pool has left does not silently
// shrink, it goes DEGRADED with a NodeCreationFailure health issue, which is
// the same shape of failure real EKS reports when an AZ has no capacity.
func (s *Server) allocateNodegroup(clusterName, nodegroupName string, desired int32, instanceType string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	setStatus := func(status string, issues []model.Issue, nodes []string) {
		_ = s.store.Update(clusterName, func(c *store.ClusterState) {
			ng := c.Nodegroups[nodegroupName]
			if ng == nil {
				return
			}
			ng.Status = status
			ng.ModifiedAt = model.UnixMillisFloat(time.Now())
			if len(issues) > 0 {
				ng.Health = &model.NodegroupHealth{Issues: issues}
			}
			if len(nodes) > 0 {
				ng.Resources = &model.NodegroupResources{
					AutoScalingGroups: []model.AutoScalingGroup{{
						Name: "eksuvia-" + clusterName + "-" + nodegroupName,
					}},
				}
			}
		})
	}

	client, err := s.clientFor(clusterName)
	if err != nil {
		setStatus(model.NodegroupStatusCreateFailed, []model.Issue{{
			Code:    "InternalFailure",
			Message: err.Error(),
		}}, nil)
		return
	}

	free, err := s.freeWorkerNodes(ctx, client)
	if err != nil {
		setStatus(model.NodegroupStatusCreateFailed, []model.Issue{{
			Code:    "InternalFailure",
			Message: err.Error(),
		}}, nil)
		return
	}

	claim := free
	var issues []model.Issue
	if int32(len(free)) < desired {
		issues = append(issues, model.Issue{
			Code: "NodeCreationFailure",
			Message: fmt.Sprintf(
				"Requested %d nodes but only %d free nodes remain in this cluster's kind worker pool. "+
					"kind cannot add nodes to a running cluster, so raise --worker-pool-size and recreate the cluster.",
				desired, len(free)),
			ResourceIDs: []string{nodegroupName},
		})
	} else {
		claim = free[:desired]
	}

	zone := s.cfg.Region + "a"
	labels := map[string]string{
		nodegroupLabel: nodegroupName,
		// The full set real EKS applies. Workloads select on these, so a
		// nodeSelector that works in production must work here too.
		"eks.amazonaws.com/capacityType":         model.DefaultNodegroupCapacity,
		"eks.amazonaws.com/nodegroup-image":      "ami-eksuvia",
		"node.kubernetes.io/instance-type":       instanceType,
		"beta.kubernetes.io/instance-type":       instanceType,
		"topology.kubernetes.io/region":          s.cfg.Region,
		"topology.kubernetes.io/zone":            zone,
		"failure-domain.beta.kubernetes.io/zone": zone,
	}

	state, err := s.store.Get(clusterName)
	if err != nil {
		return
	}
	if ng := state.Nodegroups[nodegroupName]; ng != nil {
		for k, v := range ng.Labels {
			labels[k] = v
		}
	}

	claimed := make([]string, 0, len(claim))
	for _, node := range claim {
		patch := kube.Object{"metadata": kube.Object{"labels": labels}}
		if taints := taintPatch(state.Nodegroups[nodegroupName]); taints != nil {
			patch["spec"] = kube.Object{"taints": taints}
		}
		if err := client.PatchNode(ctx, node, patch); err != nil {
			s.log.Warn("could not label node for node group",
				"cluster", clusterName, "nodegroup", nodegroupName, "node", node, "error", err)
			continue
		}
		claimed = append(claimed, node)
	}

	status := model.NodegroupStatusActive
	if len(issues) > 0 {
		status = model.NodegroupStatusDegraded
	}
	if len(claimed) == 0 {
		status = model.NodegroupStatusCreateFailed
	}
	setStatus(status, issues, claimed)

	s.log.Info("node group allocated",
		"cluster", clusterName, "nodegroup", nodegroupName,
		"nodes", claimed, "status", status)
}

// freeWorkerNodes returns pool nodes not yet claimed by a node group.
func (s *Server) freeWorkerNodes(ctx context.Context, client *kube.Client) ([]string, error) {
	names, err := client.ListNodeNames(ctx)
	if err != nil {
		return nil, err
	}
	var free []string
	for _, name := range names {
		labels, err := client.GetNodeLabels(ctx, name)
		if err != nil {
			continue
		}
		// Never hand out the control plane: EKS node groups are worker-only, and
		// scheduling onto a control-plane node would be a fidelity break that
		// masks missing tolerations.
		if _, isControlPlane := labels["node-role.kubernetes.io/control-plane"]; isControlPlane {
			continue
		}
		if _, claimed := labels[nodegroupLabel]; claimed {
			continue
		}
		free = append(free, name)
	}
	sort.Strings(free)
	return free, nil
}

func taintPatch(ng *model.Nodegroup) []kube.Object {
	if ng == nil || len(ng.Taints) == 0 {
		return nil
	}
	out := make([]kube.Object, 0, len(ng.Taints))
	for _, t := range ng.Taints {
		out = append(out, kube.Object{
			"key":    t.Key,
			"value":  t.Value,
			"effect": normaliseTaintEffect(t.Effect),
		})
	}
	return out
}

// normaliseTaintEffect converts the EKS enum (NO_SCHEDULE) to the Kubernetes
// spelling (NoSchedule). Passing the AWS form straight through produces a node
// the scheduler silently ignores.
func normaliseTaintEffect(effect string) string {
	switch strings.ToUpper(effect) {
	case "NO_SCHEDULE":
		return "NoSchedule"
	case "PREFER_NO_SCHEDULE":
		return "PreferNoSchedule"
	case "NO_EXECUTE":
		return "NoExecute"
	default:
		return effect
	}
}

func (s *Server) handleListNodegroups(w http.ResponseWriter, r *http.Request, p Params) {
	state, err := s.store.Get(p["name"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	names := make([]string, 0, len(state.Nodegroups))
	for name := range state.Nodegroups {
		names = append(names, name)
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string]any{"nodegroups": names})
}

func (s *Server) handleDescribeNodegroup(w http.ResponseWriter, r *http.Request, p Params) {
	ng, err := s.getNodegroup(p["name"], p["nodegroup"])
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if ng == nil {
		writeErrorDetail(w, http.StatusNotFound, ErrResourceNotFound, errorBody{
			Message:       "No node group found for name: " + p["nodegroup"] + ".",
			ClusterName:   p["name"],
			NodegroupName: p["nodegroup"],
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodegroup": ng})
}

func (s *Server) handleDeleteNodegroup(w http.ResponseWriter, r *http.Request, p Params) {
	clusterName, nodegroupName := p["name"], p["nodegroup"]
	ng, err := s.getNodegroup(clusterName, nodegroupName)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if ng == nil {
		writeErrorDetail(w, http.StatusNotFound, ErrResourceNotFound, errorBody{
			Message:       "No node group found for name: " + nodegroupName + ".",
			ClusterName:   clusterName,
			NodegroupName: nodegroupName,
		})
		return
	}

	ng.Status = model.NodegroupStatusDeleting
	if err := s.store.Update(clusterName, func(c *store.ClusterState) {
		delete(c.Nodegroups, nodegroupName)
	}); err != nil {
		writeStoreError(w, err)
		return
	}

	// Returning the nodes to the free pool is what makes create/delete cycles
	// work without recreating the cluster.
	go s.releaseNodegroupNodes(clusterName, nodegroupName)

	writeJSON(w, http.StatusOK, map[string]any{"nodegroup": ng})
}

// releaseNodegroupNodes strips a node group's labels and taints from its nodes.
func (s *Server) releaseNodegroupNodes(clusterName, nodegroupName string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	client, err := s.clientFor(clusterName)
	if err != nil {
		return
	}
	names, err := client.ListNodeNames(ctx)
	if err != nil {
		return
	}

	for _, node := range names {
		labels, err := client.GetNodeLabels(ctx, node)
		if err != nil || labels[nodegroupLabel] != nodegroupName {
			continue
		}
		// A null value in a strategic merge patch deletes the key.
		removal := kube.Object{}
		for key := range labels {
			if strings.HasPrefix(key, "eks.amazonaws.com/") {
				removal[key] = nil
			}
		}
		patch := kube.Object{
			"metadata": kube.Object{"labels": removal},
			"spec":     kube.Object{"taints": []kube.Object{}},
		}
		if err := client.PatchNode(ctx, node, patch); err != nil {
			s.log.Warn("could not release node back to the pool",
				"cluster", clusterName, "node", node, "error", err)
		}
	}
}

func (s *Server) getNodegroup(cluster, nodegroup string) (*model.Nodegroup, error) {
	state, err := s.store.Get(cluster)
	if err != nil {
		return nil, err
	}
	return state.Nodegroups[nodegroup], nil
}
