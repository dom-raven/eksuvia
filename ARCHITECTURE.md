# Architecture

How eksuvia is put together, and why each piece is the way it is.

Read [docs/how-eks-works.md](docs/how-eks-works.md) first if you want the background on what is being emulated.

## The one-sentence version

eksuvia is a Go daemon that speaks the EKS control plane API, provisions kind clusters configured to call back into it for authentication, serves a real OIDC provider for those clusters, and proxies every other AWS call to Floci.

## Package layout

```
cmd/eksuvia/          entrypoint: flags, logging, signal handling
internal/
  api/                HTTP surface
    router.go         path router (ARNs appear as URL-encoded segments)
    server.go         route table and shared helpers
    cluster.go        CreateCluster → provisioning → ACTIVE
    nodegroup.go      node groups, backed by real kind nodes
    access.go         access entries, policies, RBAC reconciliation
    addon.go          managed add-on catalogue and lifecycle
    webhook.go        TokenReview: the IAM authenticator
    oidc.go           OIDC discovery, JWKS, out-of-band token minting
    errors.go         EKS exception shapes
  awsarn/             ARN parsing and canonicalization
  token/              k8s-aws-v1 token verification
  identity/           IAM principal → Kubernetes identity, and → RBAC
  oidc/               per-cluster signing keys, JWKS, SA tokens
  kindprov/           kind provisioning and kubeadm patching
  kube/               minimal Kubernetes REST client
  store/              in-memory cluster state
  proxy/              reverse proxy to Floci
  config/             configuration and validation
```

Dependencies point inward: `api` uses everything, the leaf packages (`awsarn`, `token`, `oidc`, `identity`) know nothing about HTTP and are unit-testable in isolation. That is deliberate — the fidelity-critical logic is exactly the logic that can be tested without Docker.

## Request flow

```
AWS SDK / CLI / eksctl / Terraform
        │
        ▼
   Router  ── /clusters*, /access-policies, /addons/* ──► eksuvia handlers
        │
        └── everything else ─────────────────────────────► Floci (reverse proxy)
```

A path eksuvia knows but with an unsupported method returns `405` rather than being proxied — otherwise Floci answers with a confusing unrelated error.

## Cluster creation

`CreateCluster` returns immediately with `status: CREATING`, then provisions in the background. This is not laziness: it is what real EKS does, and reproducing it forces callers to exercise their real waiter code rather than a fast path that only exists locally.

The background sequence:

1. Generate an RSA-2048 keypair and derive the OIDC issuer URL.
2. Write `sa.key`, `sa.pub` and `webhook.kubeconfig` into a per-cluster assets directory.
3. Build a kind config that bind-mounts that directory into the control-plane node at `/etc/eksuvia` and patches kubeadm.
4. Create the cluster; wait for readiness.
5. Extract the CA and endpoint from the kubeconfig; publish them on `DescribeCluster`.
6. Reconcile the cluster-creator access entry into RBAC.
7. Flip to `ACTIVE`.

### The kubeadm patches

This is the crux of the whole design. eksuvia configures kind's API server with:

| Flag | Why |
|---|---|
| `--authentication-token-webhook-config-file` | points the API server at eksuvia's TokenReview endpoint |
| `--authentication-token-webhook-cache-ttl=7m` | matches EKS, so revocation latency feels the same |
| `--service-account-issuer` | the OIDC issuer eksuvia serves |
| `--service-account-signing-key-file` | **eksuvia's private key** — so projected tokens are ones we can publish a JWKS for |
| `--service-account-key-file` | the matching public key |
| `--api-audiences=sts.amazonaws.com,<issuer>` | IRSA audience, plus the issuer so ordinary in-cluster tokens keep working |

and the controller-manager with `--service-account-private-key-file` pointing at the same key — without which it signs legacy tokens the API server no longer trusts.

Two patches are emitted per component, one pinned to `kubeadm.k8s.io/v1beta3` and one to `v1beta4`. kind applies a patch only when its `apiVersion` matches the generated object, so exactly one of each pair takes effect. This is what lets a single build target both older Kubernetes (map-shaped `extraArgs`) and 1.31+ (list-shaped) without branching on the version string.

## Authentication path

```
kubectl → API server → TokenReview → eksuvia
                                       │
                       structural validation (no network)
                                       │
                       GET presigned URL + x-k8s-aws-id → Floci STS
                                       │
                            canonicalize ARN
                                       │
              access entries ──┐               ┌── aws-auth ConfigMap
                               ▼               ▼
                        Resolver (mode-gated, access entry wins)
                                       │
                     {username, uid, groups} → API server → RBAC
```

Three properties worth preserving if you touch this code:

- **Malformed tokens never reach the network.** Every structural check runs first, so an unauthenticated caller cannot drive load against STS. There is a test asserting exactly this.
- **Denials return HTTP 200 with `authenticated: false`.** A non-2xx response is treated by the API server as a *broken webhook*, and it fails the request with a server error instead of a clean 401.
- **Reading `aws-auth` during a TokenReview is not a deadlock.** eksuvia's Kubernetes client authenticates with an admin client certificate, handled by the x509 authenticator without ever consulting this webhook.

## Access entries become real RBAC

An access policy is not a bespoke authorization engine — AWS documents each one as equivalent to a built-in ClusterRole. So eksuvia reconciles associations into actual `ClusterRoleBinding` and `RoleBinding` objects, named deterministically (`eksuvia-<policy>-<hash>`) and labelled `eksuvia.dev/managed-by`, so reconciliation is idempotent and deletion only ever removes what eksuvia owns.

Namespace wildcards (`team-*`) are expanded against namespaces that exist at reconcile time, because RBAC RoleBindings require concrete namespaces. A namespace created later is picked up on the next reconcile, not instantly — a documented deviation.

## Node groups and the pool

kind cannot add nodes to a running cluster. That is a hard upstream constraint, and it shapes the design.

So each cluster is created with a **pool** of worker nodes (`--worker-pool-size`, default 2). `CreateNodegroup` claims free nodes from the pool and stamps them with the EKS label set; `DeleteNodegroup` strips those labels and returns them.

When a node group asks for more capacity than the pool has left, it does **not** silently shrink. It goes `DEGRADED` with a `NodeCreationFailure` health issue — which happens to be the same shape of failure real EKS reports when an AZ has no capacity. The constraint and the fidelity happen to align.

## Why a hand-rolled Kubernetes client

eksuvia touches a narrow slice of the Kubernetes API: read a ConfigMap, label nodes, list namespaces, apply a few RBAC bindings. `client-go` would bring roughly forty modules for that, and would pin the project to a single Kubernetes minor version — awkward for a tool whose purpose is emulating several at once.

The whole module graph is currently 24 modules. `internal/kube` is intentionally not a general-purpose client and should not grow into one.

## Why proxy to Floci instead of reimplementing AWS

Emulating EKS convincingly needs IAM, STS, EC2, ELBv2, ECR and CloudFormation. Building those is a larger project than this one, and Floci already does it well across ~69 services. eksuvia owns only the part AWS hides.

The practical benefit: one `AWS_ENDPOINT_URL`. Callers do not need to know which service is emulated by which process.

## State

Cluster state is in-memory and process-scoped. An emulator that silently resurrects yesterday's clusters is worse than one that starts clean, and the expensive artefact — the kind cluster — survives restarts anyway.

The consequence is deliberate: kind clusters from a previous run are **detected and reported at startup but not adopted**, because their signing keys and access entries lived in a previous process's memory. Telling the user plainly beats a confusing "cluster not found" against something they can see in `kind get clusters`. Making state durable is on the [roadmap](docs/roadmap.md).

## Testing strategy

Unit tests cover the logic that does not need Docker, which is most of the logic that matters:

- `awsarn` — canonicalization, including the assumed-role collapse and rejection of non-principals
- `token` — every structural rejection path, the cluster-ID binding, the 15-minute window, injected clock
- `identity` — resolver precedence, mode gating, `aws-auth` templates, RBAC binding generation
- `oidc` — key ID derivation matching Kubernetes, JWKS round-trip, minted token verification
- `config` — the self-proxy loop guard
- `api` — routing, including URL-encoded ARN segments

What is **not** covered is anything requiring a live cluster: provisioning, the webhook round trip, node labelling. See [project status](README.md#project-status).
