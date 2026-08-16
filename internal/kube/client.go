// Package kube is a small Kubernetes REST client.
//
// eksuvia touches a deliberately narrow slice of the Kubernetes API: read the
// aws-auth ConfigMap, label nodes, list namespaces, and reconcile a handful of
// RBAC bindings. client-go would bring roughly forty modules to do that, and
// would pin this project to a Kubernetes minor version -- awkward for a tool
// whose entire purpose is emulating several Kubernetes versions at once.
//
// So this is hand-rolled against the REST API, which is stable and versioned.
// It is not a general-purpose client and should not grow into one.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Client talks to one cluster's API server using admin credentials.
type Client struct {
	server string
	http   *http.Client
}

// kubeconfig is the subset of a kubeconfig file this package understands. kind
// always emits a single-context config with embedded certificate data, so the
// file-reference variants are intentionally unsupported.
type kubeconfig struct {
	Clusters []struct {
		Name    string `yaml:"name"`
		Cluster struct {
			Server                   string `yaml:"server"`
			CertificateAuthorityData string `yaml:"certificate-authority-data"`
		} `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string `yaml:"name"`
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
			ClientKeyData         string `yaml:"client-key-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// NewFromKubeconfig builds a client from raw kubeconfig bytes.
func NewFromKubeconfig(raw []byte) (*Client, error) {
	var cfg kubeconfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("kube: parsing kubeconfig: %w", err)
	}
	if len(cfg.Clusters) == 0 || len(cfg.Users) == 0 {
		return nil, fmt.Errorf("kube: kubeconfig has no cluster or user entry")
	}

	caPEM, err := base64.StdEncoding.DecodeString(cfg.Clusters[0].Cluster.CertificateAuthorityData)
	if err != nil {
		return nil, fmt.Errorf("kube: decoding cluster CA: %w", err)
	}
	certPEM, err := base64.StdEncoding.DecodeString(cfg.Users[0].User.ClientCertificateData)
	if err != nil {
		return nil, fmt.Errorf("kube: decoding client certificate: %w", err)
	}
	keyPEM, err := base64.StdEncoding.DecodeString(cfg.Users[0].User.ClientKeyData)
	if err != nil {
		return nil, fmt.Errorf("kube: decoding client key: %w", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("kube: building client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("kube: cluster CA contained no usable certificate")
	}

	return &Client{
		server: strings.TrimSuffix(cfg.Clusters[0].Cluster.Server, "/"),
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:      pool,
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				},
			},
		},
	}, nil
}

// CACertPEM extracts the cluster CA from a kubeconfig.
//
// DescribeCluster must return this as certificateAuthority.data, so that a
// kubeconfig written by `aws eks update-kubeconfig` can verify the API server.
func CACertPEM(raw []byte) ([]byte, error) {
	var cfg kubeconfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("kube: parsing kubeconfig: %w", err)
	}
	if len(cfg.Clusters) == 0 {
		return nil, fmt.Errorf("kube: kubeconfig has no cluster entry")
	}
	return base64.StdEncoding.DecodeString(cfg.Clusters[0].Cluster.CertificateAuthorityData)
}

// ServerURL extracts the API server endpoint from a kubeconfig.
func ServerURL(raw []byte) (string, error) {
	var cfg kubeconfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("kube: parsing kubeconfig: %w", err)
	}
	if len(cfg.Clusters) == 0 {
		return "", fmt.Errorf("kube: kubeconfig has no cluster entry")
	}
	return cfg.Clusters[0].Cluster.Server, nil
}

// StatusError carries a non-2xx response from the API server.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("kube: API server returned %d: %s", e.Code, e.Body)
}

// IsNotFound reports whether an error is a 404 from the API server.
func IsNotFound(err error) bool {
	var se *StatusError
	if ok := asStatusError(err, &se); ok {
		return se.Code == http.StatusNotFound
	}
	return false
}

// IsAlreadyExists reports whether an error is a 409 from the API server.
func IsAlreadyExists(err error) bool {
	var se *StatusError
	if ok := asStatusError(err, &se); ok {
		return se.Code == http.StatusConflict
	}
	return false
}

func asStatusError(err error, target **StatusError) bool {
	for err != nil {
		if se, ok := err.(*StatusError); ok {
			*target = se
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// Do issues a request against the API server and decodes a JSON response.
//
// contentType is only consulted when body is non-nil; patch verbs require the
// specific patch media type rather than application/json.
func (c *Client) Do(ctx context.Context, method, path string, body any, contentType string, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("kube: encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.server+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("kube: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("kube: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("kube: decoding response: %w", err)
	}
	return nil
}

// Object is an untyped Kubernetes object.
type Object map[string]any

// List is a generic list response.
type List struct {
	Items []Object `json:"items"`
}

// Ready reports whether the API server is serving. It is used to decide when an
// emulated cluster may transition to ACTIVE.
func (c *Client) Ready(ctx context.Context) error {
	return c.Do(ctx, http.MethodGet, "/readyz", nil, "", nil)
}

// GetConfigMap fetches a ConfigMap's data, returning nil if it does not exist.
func (c *Client) GetConfigMap(ctx context.Context, namespace, name string) (map[string]string, error) {
	var out struct {
		Data map[string]string `json:"data"`
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/configmaps/%s", namespace, url.PathEscape(name))
	if err := c.Do(ctx, http.MethodGet, path, nil, "", &out); err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return out.Data, nil
}

// ListNamespaceNames returns every namespace name in the cluster.
func (c *Client) ListNamespaceNames(ctx context.Context) ([]string, error) {
	var out List
	if err := c.Do(ctx, http.MethodGet, "/api/v1/namespaces", nil, "", &out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Items))
	for _, item := range out.Items {
		if name := objectName(item); name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// ListNodeNames returns every node name in the cluster.
func (c *Client) ListNodeNames(ctx context.Context) ([]string, error) {
	var out List
	if err := c.Do(ctx, http.MethodGet, "/api/v1/nodes", nil, "", &out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Items))
	for _, item := range out.Items {
		if name := objectName(item); name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

// GetNodeLabels returns the labels currently on a node.
func (c *Client) GetNodeLabels(ctx context.Context, node string) (map[string]string, error) {
	var out struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	path := "/api/v1/nodes/" + url.PathEscape(node)
	if err := c.Do(ctx, http.MethodGet, path, nil, "", &out); err != nil {
		return nil, err
	}
	return out.Metadata.Labels, nil
}

// PatchNode applies a strategic merge patch to a node, used to stamp the
// EKS-shaped labels and taints onto kind's worker nodes.
func (c *Client) PatchNode(ctx context.Context, node string, patch Object) error {
	path := "/api/v1/nodes/" + url.PathEscape(node)
	return c.Do(ctx, http.MethodPatch, path, patch, "application/strategic-merge-patch+json", nil)
}

// ApplyClusterRoleBinding creates or replaces a ClusterRoleBinding.
func (c *Client) ApplyClusterRoleBinding(ctx context.Context, name, clusterRole, username string, labels map[string]string) error {
	obj := Object{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "ClusterRoleBinding",
		"metadata":   Object{"name": name, "labels": labels},
		"roleRef": Object{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     clusterRole,
		},
		"subjects": []Object{{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "User",
			"name":     username,
		}},
	}
	return c.createOrReplace(ctx,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/"+url.PathEscape(name),
		obj)
}

// ApplyRoleBinding creates or replaces a namespaced RoleBinding.
func (c *Client) ApplyRoleBinding(ctx context.Context, namespace, name, clusterRole, username string, labels map[string]string) error {
	obj := Object{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   Object{"name": name, "namespace": namespace, "labels": labels},
		"roleRef": Object{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "ClusterRole",
			"name":     clusterRole,
		},
		"subjects": []Object{{
			"apiGroup": "rbac.authorization.k8s.io",
			"kind":     "User",
			"name":     username,
		}},
	}
	base := fmt.Sprintf("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings", namespace)
	return c.createOrReplace(ctx, base, base+"/"+url.PathEscape(name), obj)
}

// createOrReplace POSTs an object, falling back to PUT when it already exists.
// RoleRef is immutable, so a conflicting binding whose role differs must be
// deleted first; that case is handled by deleting and retrying once.
func (c *Client) createOrReplace(ctx context.Context, collectionPath, itemPath string, obj Object) error {
	err := c.Do(ctx, http.MethodPost, collectionPath, obj, "", nil)
	if err == nil {
		return nil
	}
	if !IsAlreadyExists(err) {
		return err
	}
	if putErr := c.Do(ctx, http.MethodPut, itemPath, obj, "", nil); putErr != nil {
		// roleRef changed: replace is rejected, so drop and recreate.
		if delErr := c.Do(ctx, http.MethodDelete, itemPath, nil, "", nil); delErr != nil {
			return putErr
		}
		return c.Do(ctx, http.MethodPost, collectionPath, obj, "", nil)
	}
	return nil
}

// DeleteClusterRoleBindingsWithLabel removes generated cluster-scoped bindings,
// used when an access entry or its policies go away.
func (c *Client) DeleteClusterRoleBindingsWithLabel(ctx context.Context, selector string) error {
	path := "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings?labelSelector=" + url.QueryEscape(selector)
	err := c.Do(ctx, http.MethodDelete, path, nil, "", nil)
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

func objectName(o Object) string {
	meta, ok := o["metadata"].(map[string]any)
	if !ok {
		return ""
	}
	name, _ := meta["name"].(string)
	return name
}
