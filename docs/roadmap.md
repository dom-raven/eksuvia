# Roadmap

Ordered roughly by value per unit of effort. Nothing here is scheduled; this is a list of what would make eksuvia meaningfully better, and it is where to look if you want to contribute.

## 0. Verify it end to end

**The single most valuable thing right now.** The core was written on a machine without Docker, so cluster provisioning has never been executed. Specifically unverified:

- Do the kubeadm patches apply cleanly across Kubernetes 1.29–1.32? (The v1beta3/v1beta4 dual-patch trick is reasoned-through but untested.)
- Can the API server inside the kind node actually reach the token webhook, on Docker Desktop *and* on plain Linux?
- Does the control-plane node accept a bind-mounted service-account signing key, given the API server runs as non-root?
- Does `aws eks update-kubeconfig` + `kubectl get nodes` complete the full loop?

Running this and reporting the failures — with logs — is worth more than any new feature.

## 1. The IRSA mutating webhook

The OIDC provider is real and the signing key is wired in. What is missing is the admission webhook that makes it ergonomic: watch for pods whose ServiceAccount carries `eks.amazonaws.com/role-arn`, and inject `AWS_ROLE_ARN`, `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_REGION`, and the projected token volume with audience `sts.amazonaws.com`.

With this, an unmodified AWS SDK in a pod does real IRSA with zero manual pod-spec changes — the flow that is genuinely impossible on emulators without a kubelet.

Requires: a `MutatingWebhookConfiguration`, a serving certificate, and Floci's STS trusting the cluster's issuer.

## 2. EKS Pod Identity

The newer mechanism, and increasingly the recommended one.

- `CreatePodIdentityAssociation` / `Describe` / `List` / `Delete`
- `eks-auth:AssumeRoleForPodIdentity`
- A Pod Identity Agent DaemonSet on `169.254.170.23:80`
- Pod mutation injecting `AWS_CONTAINER_CREDENTIALS_FULL_URI`

Self-contained, and the API surface is small.

## 3. Cloud controller

Reconcile Kubernetes objects into Floci resources:

- `Service type=LoadBalancer` → an ELBv2 in Floci, plus a proxy container routing to node ports. [`cloud-provider-kind`](https://github.com/kubernetes-sigs/cloud-provider-kind) solves the hard half with Envoy and is a good model.
- `PersistentVolumeClaim` → an EBS volume in Floci via a CSI driver.
- Node `providerID` set to `aws:///<zone>/<instance-id>`.

This is what makes AWS Load Balancer Controller and the EBS CSI driver testable locally.

## 4. Real add-on installation

Today only `coredns` and `kube-proxy` are genuinely present. Installing the rest from upstream manifests — `aws-ebs-csi-driver`, `metrics-server`, `eks-pod-identity-agent`, `snapshot-controller` — would make `CreateAddon` mean something. `vpc-cni` is the hard one and probably should stay a no-op, since kind's CNI cannot reproduce VPC IP semantics anyway.

## 5. Durable state

Persist cluster metadata (including the OIDC signing key) so eksuvia can adopt kind clusters across restarts instead of reporting and ignoring them. Needs care: the signing key is sensitive even locally, so file permissions and a clear "this is a dev tool" boundary matter.

## 6. Fargate profiles

`CreateFargateProfile` plus a scheduling shim: match pods by namespace and labels, and place them on a dedicated tainted node representing Fargate capacity. Not high fidelity, but enough to exercise profile selectors and the `eks.amazonaws.com/compute-type: fargate` label.

## 7. API completeness

- `UpdateClusterConfig`, `UpdateClusterVersion`, `UpdateNodegroupConfig`, `UpdateNodegroupVersion`, and the `DescribeUpdate` / `ListUpdates` machinery
- `TagResource` / `UntagResource` / `ListTagsForResource`
- Pagination (`nextToken`) across list operations
- `DescribeClusterVersions`, `DescribeAddonConfiguration`
- Identity provider configs

## 8. Ecosystem compatibility tests

The real proof. A test matrix running `eksctl`, `terraform-aws-eks`, Pulumi and the AWS SDKs against eksuvia, asserting the same outcomes as against AWS. Floci's `compatibility-tests` directory is a good model.

---

## Contributing

Pick anything above, or open an issue describing what you hit. Items 0 and 1 are the ones that unblock the most.
