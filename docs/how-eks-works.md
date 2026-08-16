# How Amazon EKS actually works

A teardown of the parts AWS runs and does not show you. This is the research eksuvia is built on; it is written to be useful even if you never run eksuvia.

Everything here describes real EKS. What eksuvia does or does not reproduce is in [fidelity.md](fidelity.md).

---

## 1. The shape of a cluster

An EKS cluster is two halves that meet at a network boundary.

**The control plane** runs in an AWS-owned VPC you have no access to. Every cluster gets its own — no sharing between clusters or accounts. AWS places **at least two API server instances and three etcd instances across three Availability Zones**, in auto-scaling groups, behind a Network Load Balancer that terminates at the endpoint `DescribeCluster` hands you. Unhealthy instances are replaced automatically, in a different AZ if needed.

**The data plane** runs in *your* VPC: managed node groups, self-managed nodes, Fargate, Karpenter-provisioned capacity, EKS Auto Mode, or Hybrid Nodes. The two halves talk over cross-account ENIs that EKS injects into your subnets.

The consequence that matters for emulation: **you never see the control plane's components**. There is no `kube-system` pod for the API server, no way to read its flags, no way to inspect the authenticator. Everything in the rest of this document is inferred from behaviour, from AWS documentation, and from the open-source components AWS publishes.

---

## 2. Authentication: the token is a presigned URL

This is the most misunderstood part of EKS, and the piece most local emulators skip.

When you run `kubectl` against EKS, your kubeconfig contains an **exec credential plugin**:

```yaml
users:
- name: arn:aws:eks:us-east-1:123456789012:cluster/demo
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: ["--region", "us-east-1", "eks", "get-token", "--cluster-name", "demo"]
```

`aws eks get-token` does **not** contact EKS. It builds a **presigned AWS STS `GetCallerIdentity` URL**, signs it with SigV4, base64url-encodes it, and prefixes it:

```
k8s-aws-v1.aHR0cHM6Ly9zdHMudXMtZWFzdC0xLmFtYXpvbmF3cy5jb20vP0FjdGlvbj1HZXRDYWxsZXJJZGVudGl0eSZ...
```

Decoded, it is an ordinary URL:

```
https://sts.us-east-1.amazonaws.com/
  ?Action=GetCallerIdentity
  &Version=2011-06-15
  &X-Amz-Algorithm=AWS4-HMAC-SHA256
  &X-Amz-Credential=AKIA…/20260816/us-east-1/sts/aws4_request
  &X-Amz-Date=20260816T155427Z
  &X-Amz-Expires=60
  &X-Amz-SignedHeaders=host;x-k8s-aws-id
  &X-Amz-Signature=…
```

### The `x-k8s-aws-id` header is the whole trick

Note `X-Amz-SignedHeaders=host;x-k8s-aws-id`. The signature covers a header named **`x-k8s-aws-id`, whose value is the cluster name** — but the header is not in the URL. It is supplied by whoever *dereferences* the URL.

That is what binds a token to one cluster. The API server's authenticator adds `x-k8s-aws-id: demo` when it calls STS. If the token had been signed for a different cluster, the signature would not match and STS rejects the request. Without this, any token would work against any cluster you could reach.

### Validation, in order

The authenticator (`kubernetes-sigs/aws-iam-authenticator`) checks the following *before* making any network call:

| Check | Value |
|---|---|
| Prefix | `k8s-aws-v1.` |
| Max size | 4096 bytes |
| Encoding | `base64.RawURLEncoding` — unpadded |
| Scheme / host | `https`, and a known STS hostname |
| Path | `/` |
| Query parameters | whitelist only: `action`, `version`, `x-amz-algorithm`, `x-amz-credential`, `x-amz-date`, `x-amz-expires`, `x-amz-security-token`, `x-amz-signature`, `x-amz-signedheaders` |
| Action | `GetCallerIdentity` |
| Signed headers | must include `x-k8s-aws-id` |
| `x-amz-expires` | integer in `[0, 900]` |
| Expiry | **`x-amz-date` + 15 minutes** |

Two details catch people out:

- **The parameter whitelist is a security control, not tidiness.** The authenticator is about to issue an HTTP request built from attacker-controlled input. Anything outside the whitelist is rejected rather than forwarded.
- **`x-amz-expires` is not the expiry.** The CLI pins it to `60` for legacy reasons and it is *ignored*. The real lifetime is 15 minutes from `x-amz-date`.

Only then is the URL fetched, with `x-k8s-aws-id` and `Accept: application/json`. STS does the SigV4 verification and answers:

```json
{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{
  "Account":"123456789012",
  "Arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice",
  "UserId":"AROAEXAMPLE:alice"}}}
```

The authenticator never verifies a signature itself. It asks STS who the caller is.

### Canonicalization

The returned ARN is usually an **assumed-role session**, but mappings are written against the **role**. So ARNs are canonicalized first:

| Input | Canonical |
|---|---|
| `arn:aws:sts::123:assumed-role/Admin/alice` | `arn:aws:iam::123:role/Admin` |
| `arn:aws:sts::123:assumed-role/some/path/Admin/alice` | `arn:aws:iam::123:role/some/path/Admin` |
| `arn:aws:iam::123:role/Admin` | unchanged |
| `arn:aws:iam::123:user/Bob` | unchanged |
| `arn:aws:iam::123:root` | unchanged |
| `arn:aws:sts::123:federated-user/Bob` | unchanged |
| anything else | **rejected** |

The last row matters: a non-principal ARN is refused outright rather than passed through.

---

## 3. Authorization: two mapping mechanisms, one precedence rule

A canonical ARN still is not a Kubernetes identity. EKS maps it through one or both of:

### `aws-auth` ConfigMap (the original)

A ConfigMap in `kube-system` whose values are YAML documents embedded in strings:

```yaml
apiVersion: v1
kind: ConfigMap
metadata: {name: aws-auth, namespace: kube-system}
data:
  mapRoles: |
    - rolearn: arn:aws:iam::123456789012:role/NodeInstanceRole
      username: system:node:{{EC2PrivateDNSName}}
      groups: [system:bootstrappers, system:nodes]
  mapUsers: |
    - userarn: arn:aws:iam::123456789012:user/alice
      username: alice
      groups: [system:masters]
```

Templates available in `username` and `groups`: `{{EC2PrivateDNSName}}`, `{{SessionName}}`, `{{AccountID}}`.

`{{EC2PrivateDNSName}}` is the interesting one — the authenticator resolves it by calling `ec2:DescribeInstances` for the caller's instance. It produces the `system:node:<name>` username that **node authorization** depends on: the Node authorizer only lets a kubelet read objects relevant to *its own* node, and it identifies that node from the username.

This mechanism is famous for being dangerous. It is a single ConfigMap with no validation, no audit trail, and no way to grant yourself back in if you break it. A malformed edit locks everyone out of the cluster permanently.

### Access entries (the replacement, 2023+)

A first-class API: `CreateAccessEntry`, `AssociateAccessPolicy`. An entry maps a principal ARN to a username and groups; associated **access policies** grant permissions, scoped either cluster-wide or to namespaces (with a trailing `*` wildcard).

AWS defines these policies as equivalent to built-in ClusterRoles:

| Access policy | Equivalent ClusterRole |
|---|---|
| `AmazonEKSClusterAdminPolicy` | `cluster-admin` |
| `AmazonEKSAdminPolicy` | `admin` |
| `AmazonEKSEditPolicy` | `edit` |
| `AmazonEKSViewPolicy` | `view` |
| `AmazonEKSAdminViewPolicy` | `view` + read access to resources holding secrets material |

That equivalence is what makes access entries emulable: EKS is not running a bespoke authorization engine, it is creating ordinary RBAC bindings.

### The precedence rule people get wrong

`authenticationMode` selects which mechanisms are live: `CONFIG_MAP`, `API`, or `API_AND_CONFIG_MAP` (the console default).

In `API_AND_CONFIG_MAP`, when a principal appears in **both**:

> **The access entry wins outright. The `aws-auth` entry is ignored — not merged.**

Teams migrating off `aws-auth` hit this constantly: they create an access entry expecting it to *add* permissions, and instead silently lose the groups the ConfigMap was granting.

Two more one-way doors: once `API` is enabled it cannot be disabled, and if `CONFIG_MAP` was not enabled at creation it cannot be enabled later.

---

## 4. IRSA: how a pod gets an IAM role

**IAM Roles for Service Accounts** predates Pod Identity and is still the most widely deployed mechanism.

Each cluster gets an OIDC issuer:

```
https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E
```

Serving `/.well-known/openid-configuration` and a JWKS. **AWS rotates the signing key every 7 days** and keeps old public keys until they expire.

The flow:

1. **Annotate** a ServiceAccount with `eks.amazonaws.com/role-arn`.
2. **Admission.** The `amazon-eks-pod-identity-webhook` — which AWS runs in its hidden control plane — mutates pods using that ServiceAccount, injecting `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_REGION`, `AWS_DEFAULT_REGION`, and a **projected service-account token volume** at `/var/run/secrets/eks.amazonaws.com/serviceaccount/` with audience `sts.amazonaws.com` and a 24-hour expiry.
3. **Projection.** The kubelet mints the token, signed by the API server's service-account signing key, and rotates it for the pod's lifetime.
4. **Assumption.** Any modern AWS SDK notices those environment variables and calls `sts:AssumeRoleWithWebIdentity` with the token.
5. **Verification.** STS fetches the cluster's OIDC discovery document and JWKS, verifies the RS256 signature, then evaluates the role's trust policy:

```json
{"Effect": "Allow",
 "Principal": {"Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE…"},
 "Action": "sts:AssumeRoleWithWebIdentity",
 "Condition": {"StringEquals": {
   "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE…:sub": "system:serviceaccount:my-ns:my-sa",
   "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE…:aud": "sts.amazonaws.com"}}}
```

Note the issuer appears **with the scheme stripped** in both the provider ARN and the condition keys.

**The emulation-critical point:** step 3 requires a kubelet. There is no way to fake it convincingly from outside — a token minted by anything other than the API server will not match what a pod receives. The only faithful approach is to control the API server's *signing key*, so that tokens the real kubelet projects are ones you can publish a JWKS for.

The `sub` claim is `system:serviceaccount:<namespace>:<name>`, which is why IRSA trust policies are namespace-scoped by construction.

---

## 5. EKS Pod Identity: the newer mechanism

Introduced in 2023 to fix IRSA's two real problems: trust policies do not scale past a few dozen roles, and a role's trust policy must name every cluster that may assume it.

- The **EKS Pod Identity Agent** runs as a DaemonSet using `hostNetwork`, binding **`169.254.170.23`** (and `[fd00:ec2::23]`) on ports 80 and 2703.
- Pods get `AWS_CONTAINER_CREDENTIALS_FULL_URI=http://169.254.170.23/v1/credentials` and `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token`.
- The SDK requests credentials from the agent; the agent calls **`eks-auth:AssumeRoleForPodIdentity`** against the regional EKS endpoint, which validates the JWT, looks up the association created by `CreatePodIdentityAssociation`, assumes the role, and returns credentials.
- The **node role** needs `eks-auth:AssumeRoleForPodIdentity` on `Resource: "*"`.

Trust policy is now a simple `pods.eks.amazonaws.com` principal — no per-cluster OIDC condition. The mutation still happens at pod admission time, so an association created after a pod starts does not apply until the pod restarts.

---

## 6. Node groups and how a node joins

`CreateNodegroup` creates a launch template and an Auto Scaling group. Instances boot an EKS-optimized AMI and bootstrap themselves.

**Amazon Linux 2** used `/etc/eks/bootstrap.sh`, which called `DescribeCluster` to discover the endpoint, CA and service CIDR.

**Amazon Linux 2023** replaced it with **`nodeadm`**, driven by YAML in user data:

```yaml
apiVersion: node.eks.aws/v1alpha1
kind: NodeConfig
spec:
  cluster:
    name: demo
    apiServerEndpoint: https://XXXX.gr7.us-east-1.eks.amazonaws.com
    certificateAuthority: <base64>
    cidr: 10.100.0.0/16
```

Unlike `bootstrap.sh`, `nodeadm` requires this to be **explicit** — it does not discover cluster metadata. For EKS-managed node groups AWS appends the default `NodeConfig` to user data automatically, which is why you rarely write it yourself.

The kubelet then joins via **TLS bootstrap**, authenticating with the same IAM token mechanism as `kubectl` — the node's IAM role maps to `system:bootstrappers` and `system:nodes`, which is what the classic `aws-auth` `mapRoles` entry is for. It submits a CSR, the control plane approves it, and the kubelet switches to its issued client certificate.

EKS then stamps nodes with labels workloads select on:

```
eks.amazonaws.com/nodegroup=workers
eks.amazonaws.com/nodegroup-image=ami-0123456789abcdef
eks.amazonaws.com/capacityType=ON_DEMAND
node.kubernetes.io/instance-type=t3.medium
topology.kubernetes.io/region=us-east-1
topology.kubernetes.io/zone=us-east-1a
```

plus `spec.providerID: aws:///us-east-1a/i-0123456789abcdef`.

One API/Kubernetes mismatch worth knowing: node group taints use the **EKS enum spelling** (`NO_SCHEDULE`), while Kubernetes expects `NoSchedule`. Passing the AWS form straight through produces a taint the scheduler silently ignores.

---

## 7. The rest of the hidden control plane

- **Managed add-ons.** `DescribeAddonVersions` → `CreateAddon` for `vpc-cni`, `coredns`, `kube-proxy`, `aws-ebs-csi-driver`, `eks-pod-identity-agent`, `metrics-server` and others. Versions are strings like `v1.11.3-eksbuild.1`, compatibility-gated per Kubernetes version. Tools resolve a version from this call *before* creating anything, so an empty catalog breaks them early.
- **VPC CNI.** Pods get **real VPC IP addresses** from ENIs attached to the node, not an overlay. This is a genuine architectural difference from every local Kubernetes distribution and the source of the classic "IP address exhaustion" failure mode.
- **Cloud controller.** `Service type=LoadBalancer` provisions an NLB/ALB; `PersistentVolumeClaim` provisions EBS. Both are AWS-side controllers reconciling Kubernetes objects into AWS resources.
- **Fargate profiles.** A scheduler component matches pods by namespace and labels, then places them on AWS-managed capacity with no node you control.
- **Platform versions.** `eks.N` — an AWS-internal patch level for the control plane, independent of the Kubernetes version.
- **Cluster lifecycle.** `CREATING` (~10 minutes) → `ACTIVE`, with `endpoint`, `certificateAuthority.data` and `identity.oidc.issuer` all `null` until `ACTIVE`.

---

## 8. What this means for emulation

Pulling the threads together, a convincing local EKS needs five things:

1. **Real upstream Kubernetes with real nodes.** Node groups, node labels, taints, node authorization and DaemonSets are meaningless without them.
2. **Control of the API server's flags.** The token webhook and the service-account issuer/signing key are configured at startup and cannot be retrofitted.
3. **A faithful token authenticator.** Structural validation, the `x-k8s-aws-id` binding, ARN canonicalization, and — the part usually skipped — the actual mapping to a Kubernetes identity, with `system:masters` granted only when the mapping says so.
4. **A dereferenceable OIDC provider** whose key the API server signs with, so real projected tokens verify.
5. **The surrounding AWS APIs.** IAM, STS, EC2, ELBv2, ECR. Emulating these too would be a second, larger project — which is why eksuvia proxies them to Floci instead.

---

## Sources

- [Amazon EKS architecture](https://docs.aws.amazon.com/eks/latest/userguide/eks-architecture.html) · [EKS control plane best practices](https://docs.aws.amazon.com/eks/latest/best-practices/control-plane.html)
- [EKS API Reference](https://docs.aws.amazon.com/eks/latest/APIReference/API_Operations.html) · [DescribeCluster](https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html)
- [aws-iam-authenticator `pkg/token/token.go`](https://github.com/kubernetes-sigs/aws-iam-authenticator/blob/master/pkg/token/token.go)
- [Grant IAM users access with a ConfigMap](https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html) · [Access policy permissions](https://docs.aws.amazon.com/eks/latest/userguide/access-policy-permissions.html)
- [A deep dive into simplified EKS access management](https://aws.amazon.com/blogs/containers/a-deep-dive-into-simplified-amazon-eks-access-management-controls/) · [Datadog: EKS cluster access management deep dive](https://securitylabs.datadoghq.com/articles/eks-cluster-access-management-deep-dive/)
- [IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) · [amazon-eks-pod-identity-webhook](https://github.com/aws/amazon-eks-pod-identity-webhook) · [EKS Pod Identity webhook deep-dive](https://blog.mikesir87.io/2020/09/eks-pod-identity-webhook-deep-dive/)
- [EKS Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html) · [Datadog: EKS Pod Identity deep dive](https://securitylabs.datadoghq.com/articles/eks-pod-identity-deep-dive/)
- [eksctl node bootstrapping](https://docs.aws.amazon.com/eks/latest/eksctl/node-bootstrapping.html) · [amazon-eks-ami](https://github.com/awslabs/amazon-eks-ami)
