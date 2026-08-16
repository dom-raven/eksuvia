<div align="center">

# eksuvia

**Run Amazon EKS locally.** A high-fidelity local EKS emulator: real upstream Kubernetes via [kind](https://kind.sigs.k8s.io/), real AWS APIs via [Floci](https://github.com/floci-io/floci), and the *hidden* EKS control plane emulated in between.

[![CI](https://github.com/dom-raven/eksuvia/actions/workflows/ci.yml/badge.svg)](https://github.com/dom-raven/eksuvia/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.24%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status: early](https://img.shields.io/badge/status-early-orange.svg)](#project-status)

</div>

---

> **exuvia** *(n.)* — the cast-off exoskeleton of an insect. Hollow, brittle, and structurally perfect: legs, antennae, even the breathing tubes. An exact replica of the animal, with none of the animal inside.
>
> That is the goal. **EKS-shaped. AWS-free.**

---

## The problem

You cannot test Amazon EKS locally, because **most of EKS is not Kubernetes.**

Spin up kind, k3s or minikube and you get a Kubernetes API server. What you do *not* get is everything AWS runs in the control plane it never shows you — and that hidden layer is where local development actually breaks:

- **IAM authentication.** `kubectl` does not send a password. It sends a presigned STS `GetCallerIdentity` URL, which EKS dereferences to learn your IAM ARN and then maps to a Kubernetes user through access entries or the `aws-auth` ConfigMap.
- **IRSA.** A pod assumes an IAM role by presenting a projected service-account token to STS, which validates it against an OIDC provider EKS hosts on your cluster's behalf.
- **Node groups.** `CreateNodegroup` is an AWS API call that eventually makes nodes appear in `kubectl get nodes`, carrying labels workloads select on.

None of that exists in a stock local cluster. So the code that touches it is the code you cannot test until it reaches a real cluster — and IAM-to-RBAC mapping bugs are precisely the class of failure that surfaces as an opaque `403 Forbidden` in staging at 6pm.

## The idea

Three layers, each doing the part it is genuinely good at:

```
┌─────────────────────────────────────────────────────────────┐
│  your tools: aws cli · eksctl · terraform · kubectl · sdks  │
└────────────────────────────┬────────────────────────────────┘
                             │  AWS_ENDPOINT_URL=http://localhost:4566
┌────────────────────────────▼────────────────────────────────┐
│                          eksuvia                            │
│                                                             │
│   the hidden EKS control plane, emulated:                   │
│     · EKS REST API      (clusters, node groups, add-ons)    │
│     · IAM authenticator (k8s-aws-v1 token → IAM ARN → RBAC) │
│     · access entries    (→ real RBAC bindings)              │
│     · OIDC provider     (real JWKS, backing real IRSA)      │
└──────────┬───────────────────────────────┬──────────────────┘
           │ provisions & configures        │ proxies everything else
┌──────────▼──────────────┐   ┌─────────────▼──────────────────┐
│          kind           │   │            Floci               │
│  upstream Kubernetes    │   │  IAM · STS · EC2 · ELBv2 · ECR │
│  kubeadm · containerd   │   │  S3 · SQS · CloudFormation · … │
│  a real kubelet/node    │   │        (~69 AWS services)      │
└─────────────────────────┘   └────────────────────────────────┘
```

eksuvia owns only the EKS-shaped surface — the part AWS hides. Everything else is proxied straight through to Floci, so you point **one** `AWS_ENDPOINT_URL` at eksuvia and every AWS service works.

## Why kind, and why not just use what exists

Floci already emulates EKS by starting a **k3s** container per cluster, and it does a genuinely good job of the API shape. eksuvia exists because of what sits underneath and around that:

| | Floci's EKS today | eksuvia |
|---|---|---|
| **Data plane** | k3s | kind — upstream kubeadm, containerd, real kubelet |
| **`aws eks get-token`** | ✅ accepted | ✅ accepted |
| **IAM ARN → Kubernetes user** | every valid token → `system:masters` | resolved via access entries / `aws-auth`, like real EKS |
| **RBAC is testable** | ❌ everyone is cluster-admin | ✅ least-privilege mappings behave as they will in production |
| **Access entries + access policies** | ❌ [documented as not implemented](https://github.com/floci-io/floci/blob/main/docs/services/eks.md) | ✅ API + reconciled into real RBAC bindings |
| **IRSA from inside a pod** | ❌ *"Floci has no kubelet"* — tokens minted via a bespoke endpoint | ✅ real projected tokens, real OIDC discovery, unmodified AWS SDKs |
| **Node groups** | metadata only — nothing in `kubectl get nodes` | real kind nodes with EKS labels and taints |
| **Add-ons** | ❌ not implemented | API + catalog (installation is partial — see [fidelity](docs/fidelity.md)) |

**k3s is a distribution; EKS is upstream Kubernetes.** k3s bundles Traefik, klipper-lb, local-path storage and flannel, runs its controllers in one binary, and defaults to sqlite. Those differences show up exactly where workloads notice. kind runs the same components EKS runs — and, critically, gives you **real nodes**, without which a node group cannot be modelled at all.

The headline difference is the third row. An emulator that maps every valid token to `system:masters` makes RBAC untestable and hides the single most common EKS access bug: a principal mapped to the wrong groups, or not mapped at all.

## How the interesting parts work

**IAM authentication is a real webhook.** eksuvia configures kind's API server with `--authentication-token-webhook-config-file` pointed back at itself. A token arrives, its presigned STS URL is structurally validated (host, signed headers, the 15-minute window measured from `x-amz-date`, the parameter whitelist), then dereferenced against Floci's STS with the `x-k8s-aws-id` header attached — the check that stops a token minted for one cluster being replayed against another. The resulting IAM ARN is canonicalized (assumed-role sessions collapse to their role) and mapped through access entries or `aws-auth`, with EKS's real precedence: **when a principal appears in both, the access entry wins outright and the ConfigMap entry is ignored, not merged.**

**IRSA is real, not simulated.** eksuvia generates an RSA keypair per cluster and hands the private half to kind's API server as its service-account signing key, with `--service-account-issuer` pointed at a discovery document eksuvia serves. The *real kubelet* then projects *real* tokens, signed by a key whose public half sits at a JWKS endpoint STS can actually fetch. A pod running an unmodified AWS SDK performs a genuine `AssumeRoleWithWebIdentity`. Nothing in that path is stubbed.

**Access policies become RBAC.** `AmazonEKSClusterAdminPolicy` and friends are documented by AWS as equivalent to built-in ClusterRoles, so eksuvia reconciles them into actual `ClusterRoleBinding`/`RoleBinding` objects. `kubectl auth can-i` gives honest answers.

## Quick start

> **Requires** Docker (or Podman) and Go 1.24+. See [project status](#project-status) before you rely on this.

```bash
go install github.com/dom-raven/eksuvia/cmd/eksuvia@latest
```

Bring up eksuvia and Floci together:

```bash
git clone https://github.com/dom-raven/eksuvia
cd eksuvia
docker compose up -d
```

Point the AWS CLI at eksuvia and use it exactly as you would use AWS:

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

aws eks create-cluster \
  --name demo \
  --role-arn arn:aws:iam::000000000000:role/eksClusterRole \
  --resources-vpc-config subnetIds=[],securityGroupIds=[] \
  --kubernetes-version 1.31

# CREATING → ACTIVE, like the real thing
aws eks describe-cluster --name demo --query 'cluster.status'

aws eks update-kubeconfig --name demo
kubectl get nodes
```

That last `kubectl` call authenticates by presigning an STS request, which eksuvia verifies and maps to a Kubernetes identity — the same path a real cluster uses.

Give a teammate's role read-only access to two namespaces:

```bash
aws eks create-access-entry \
  --cluster-name demo \
  --principal-arn arn:aws:iam::000000000000:role/Developer

aws eks associate-access-policy \
  --cluster-name demo \
  --principal-arn arn:aws:iam::000000000000:role/Developer \
  --policy-arn arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy \
  --access-scope type=namespace,namespaces=team-*
```

Attach a node group and watch real nodes get claimed and labelled:

```bash
aws eks create-nodegroup \
  --cluster-name demo --nodegroup-name workers \
  --node-role arn:aws:iam::000000000000:role/eksNodeRole \
  --subnets subnet-1 --scaling-config minSize=1,maxSize=3,desiredSize=2

kubectl get nodes -L eks.amazonaws.com/nodegroup,node.kubernetes.io/instance-type
```

## Configuration

Every flag has an `EKSUVIA_`-prefixed environment variable.

| Flag | Default | Purpose |
|---|---|---|
| `--listen` | `:4566` | Address to serve the AWS endpoint on |
| `--floci-endpoint` | `http://floci:4566` | Upstream emulator for every non-EKS service |
| `--advertise-host` | `host.docker.internal` | How **containers** reach eksuvia — must not be `localhost` |
| `--worker-pool-size` | `2` | kind worker nodes per cluster for node groups to claim |
| `--cluster-creator-arn` | `arn:aws:iam::000000000000:root` | Principal granted cluster-admin on creation |
| `--region` / `--account-id` | `us-east-1` / `000000000000` | Shape of generated ARNs |
| `--node-image` | *(derived)* | Override the kind node image |

> **On Linux**, `host.docker.internal` is not resolvable by default. Set `--advertise-host` to your Docker bridge gateway (usually `172.17.0.1`). This is the single most likely thing to need adjusting — the API server must reach the token webhook, and Floci must reach the OIDC endpoint.

## Project status

**Early, but the core is verified on real infrastructure.**

Every push runs a CI job that stands up an actual kind cluster and asserts the emulation holds. As of the latest run:

```
✔ cluster reached ACTIVE
✔ all EKS control-plane flags present in the generated kube-apiserver manifest
✔ service-account tokens verify against the injected signing key   (CoreDNS Ready)

NAME                       STATUS   VERSION   NODEGROUP   INSTANCE-TYPE   ZONE
eksuvia-ci-control-plane   Ready    v1.31.0
eksuvia-ci-worker          Ready    v1.31.0   workers     t3.medium       us-east-1a
eksuvia-ci-worker2         Ready    v1.31.0   workers     t3.medium       us-east-1a

✔ kubectl auth can-i list pods   --as arn:aws:iam::…:role/Developer  → yes
✔ kubectl auth can-i delete pods --as arn:aws:iam::…:role/Developer  → no
```

That last pair is the one that matters. `AmazonEKSViewPolicy` was associated through the EKS API, reconciled into a real `ClusterRoleBinding`, and is **enforced** — it grants read and refuses delete. That is the difference between recording a policy and honouring one.

CoreDNS reaching Ready is also load-bearing evidence: it authenticates with a service-account token, so it only starts if the API server accepts tokens signed by the key eksuvia injected at bootstrap.

**What is still unverified:** the IAM token webhook round trip and in-pod IRSA, both of which need Floci's STS in the loop. The CI job runs eksuvia standalone, so `aws eks get-token` authentication has been unit-tested but not exercised against a live cluster.

The Go core passes `go vet` and `go test -race`, and the fidelity-critical packages are covered at **85–89%**:

| Package | What it does | Coverage |
|---|---|---|
| `config` | configuration and guardrails | 89.4% |
| `awsarn` | ARN parsing and canonicalization | 88.9% |
| `identity` | IAM principal → Kubernetes identity → RBAC | 87.0% |
| `oidc` | signing keys, JWKS, IRSA tokens | 85.7% |
| `token` | `k8s-aws-v1` verification | 84.7% |

The HTTP surface was also exercised directly against the running binary, which caught two real bugs — a nested ARN in `accessEntryArn`, and a stray `spec` echoed in webhook replies. A third, worse one showed up only in CI: `kube-apiserver` runs as a static pod, so the injected signing key was invisible to it until the kubeadm patch grew an `extraVolumes` entry. Every cluster creation timed out until that was fixed, and there is now a regression test for it.

Expect rough edges away from the tested path — Podman, Docker Desktop on macOS/Windows, and Kubernetes versions other than 1.31 are all unexercised. If you hit one, an issue with the log output is genuinely useful.

| Area | State |
|---|---|
| Cluster CRUD, kind provisioning, kubeadm patching | implemented, **verified in CI** |
| Node groups backed by real labelled nodes | implemented, **verified in CI** |
| Access entries + policies → enforced RBAC | implemented, **verified in CI** |
| OIDC signing key accepted by the API server | implemented, **verified in CI** |
| IAM token webhook → RBAC mapping | implemented, unit-tested; needs Floci to verify live |
| In-pod IRSA (`AssumeRoleWithWebIdentity`) | wired; needs Floci to verify live |
| Add-on API and catalogue | implemented; installation is partial |
| Proxy to Floci for all other AWS services | implemented |
| EKS Pod Identity, Fargate, cloud controller (ELBv2/EBS), IRSA admission webhook | [roadmap](docs/roadmap.md) |

See **[docs/fidelity.md](docs/fidelity.md)** for a blunt account of what is faithful, what is approximated, and what is missing — including the deliberate deviations and why they were made.

## Documentation

- **[How EKS actually works](docs/how-eks-works.md)** — a teardown of the hidden control plane: the token format, the authenticator, IRSA, Pod Identity, node bootstrap, access entries.
- **[Architecture](ARCHITECTURE.md)** — how eksuvia is put together and why.
- **[Fidelity](docs/fidelity.md)** — faithful vs. approximated vs. missing, with reasons.
- **[Roadmap](docs/roadmap.md)** — what is next and how to help.

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable contribution right now is **running it against real Docker and reporting what breaks.**

## Related projects

- [kind](https://github.com/kubernetes-sigs/kind) — Kubernetes in Docker; the data plane
- [Floci](https://github.com/floci-io/floci) — the local AWS emulator eksuvia proxies to
- [aws-iam-authenticator](https://github.com/kubernetes-sigs/aws-iam-authenticator) — the reference for the token format implemented here
- [amazon-eks-pod-identity-webhook](https://github.com/aws/amazon-eks-pod-identity-webhook) — the IRSA admission webhook

## License

[MIT](LICENSE).

Not affiliated with, endorsed by, or sponsored by Amazon Web Services. "Amazon EKS" and "AWS" are trademarks of Amazon.com, Inc. or its affiliates; they are used here only to describe compatibility.
