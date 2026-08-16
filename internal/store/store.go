// Package store holds emulator state.
//
// State is deliberately in-memory and process-scoped. A local EKS emulator that
// silently resurrects yesterday's clusters is worse than one that starts clean,
// and the durable artefact -- the kind cluster itself -- already survives
// restarts and is reconciled on startup.
package store

import (
	"fmt"
	"sort"
	"sync"

	"github.com/dom-raven/eksuvia/internal/identity"
	"github.com/dom-raven/eksuvia/internal/model"
	"github.com/dom-raven/eksuvia/internal/oidc"
)

// ClusterState is everything eksuvia knows about one emulated cluster.
type ClusterState struct {
	Cluster model.Cluster

	// KindName is the kind cluster backing this EKS cluster. It is derived from
	// the EKS name but namespaced, so `kind get clusters` stays legible and two
	// tools cannot collide on a bare name like "test".
	KindName string

	// Kubeconfig is the admin kubeconfig kind produced. It is used internally to
	// reconcile RBAC and read namespaces, and is never returned over the API --
	// callers are expected to go through `aws eks update-kubeconfig` and the IAM
	// path, exactly as they would against AWS.
	Kubeconfig []byte

	// Signer issues the cluster's IRSA service-account tokens and backs its
	// OIDC discovery document.
	Signer *oidc.Signer

	Nodegroups    map[string]*model.Nodegroup
	Addons        map[string]*model.Addon
	AccessEntries map[string]*model.AccessEntry
	PodIdentities map[string]*model.PodIdentityAssociation
}

// Resolver builds an identity resolver reflecting this cluster's current
// access configuration. awsAuth may be nil when the ConfigMap is absent.
func (c *ClusterState) Resolver(awsAuth *identity.AWSAuth) *identity.Resolver {
	mode := model.DefaultAuthenticationMode
	if c.Cluster.AccessConfig != nil && c.Cluster.AccessConfig.AuthenticationMode != "" {
		mode = c.Cluster.AccessConfig.AuthenticationMode
	}
	return &identity.Resolver{
		AuthenticationMode: mode,
		AccessEntries:      c.AccessEntries,
		AWSAuth:            awsAuth,
	}
}

// Store is a concurrency-safe registry of clusters.
type Store struct {
	mu       sync.RWMutex
	clusters map[string]*ClusterState
}

// New returns an empty store.
func New() *Store {
	return &Store{clusters: make(map[string]*ClusterState)}
}

// ErrNotFound is returned when a named cluster does not exist. Callers map it
// onto the EKS ResourceNotFoundException.
type ErrNotFound struct{ Name string }

func (e *ErrNotFound) Error() string { return fmt.Sprintf("cluster %q not found", e.Name) }

// ErrAlreadyExists is returned when a cluster name is taken.
type ErrAlreadyExists struct{ Name string }

func (e *ErrAlreadyExists) Error() string { return fmt.Sprintf("cluster %q already exists", e.Name) }

// Add registers a new cluster, refusing to overwrite an existing one.
func (s *Store) Add(c *ClusterState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clusters[c.Cluster.Name]; exists {
		return &ErrAlreadyExists{Name: c.Cluster.Name}
	}
	if c.Nodegroups == nil {
		c.Nodegroups = make(map[string]*model.Nodegroup)
	}
	if c.Addons == nil {
		c.Addons = make(map[string]*model.Addon)
	}
	if c.AccessEntries == nil {
		c.AccessEntries = make(map[string]*model.AccessEntry)
	}
	if c.PodIdentities == nil {
		c.PodIdentities = make(map[string]*model.PodIdentityAssociation)
	}
	s.clusters[c.Cluster.Name] = c
	return nil
}

// Get returns a cluster by name.
func (s *Store) Get(name string) (*ClusterState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clusters[name]
	if !ok {
		return nil, &ErrNotFound{Name: name}
	}
	return c, nil
}

// Delete removes a cluster, returning the state it removed.
func (s *Store) Delete(name string) (*ClusterState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clusters[name]
	if !ok {
		return nil, &ErrNotFound{Name: name}
	}
	delete(s.clusters, name)
	return c, nil
}

// Names returns every cluster name, sorted for stable ListClusters output.
func (s *Store) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.clusters))
	for name := range s.clusters {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// All returns every cluster, for shutdown and reconciliation sweeps.
func (s *Store) All() []*ClusterState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ClusterState, 0, len(s.clusters))
	for _, c := range s.clusters {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cluster.Name < out[j].Cluster.Name })
	return out
}

// Update applies fn to a cluster under the store's write lock.
func (s *Store) Update(name string, fn func(*ClusterState)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clusters[name]
	if !ok {
		return &ErrNotFound{Name: name}
	}
	fn(c)
	return nil
}
