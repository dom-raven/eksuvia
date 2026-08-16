# Fidelity

A blunt account of what eksuvia reproduces faithfully, what it approximates, and what it does not do at all.

The purpose of an emulator is for code that works against it to work against the real thing. Where that guarantee does not hold, it should be written down rather than discovered.

---

## Faithful

These are implemented to match real EKS behaviour, including the awkward details.

**`k8s-aws-v1` token verification.** Prefix, 4 KiB size cap, `base64.RawURLEncoding`, path and host validation, the exact query-parameter whitelist, `Action=GetCallerIdentity`, the `x-k8s-aws-id` signed-header requirement, `x-amz-expires` range validation, and expiry measured as **`x-amz-date` + 15 minutes** rather than from `x-amz-expires`. Structural rejection happens before any network call.

**ARN canonicalization.** Assumed-role sessions collapse to their IAM role, including roles with embedded paths. Non-principal ARNs are rejected rather than passed through. Partitions other than `aws` are preserved.

**Access entry / `aws-auth` precedence.** `authenticationMode` gates each mechanism. When a principal appears in both, the access entry wins outright and the ConfigMap entry is ignored — not merged.

**`aws-auth` templates.** `{{SessionName}}` and `{{AccountID}}` expand as upstream does.

**Access policies as RBAC.** The five AWS-managed policies map to their documented ClusterRole equivalents and are reconciled into real bindings, so `kubectl auth can-i` is honest.

**Cluster lifecycle.** `CreateCluster` returns `CREATING` and provisions asynchronously; `endpoint`, `certificateAuthority.data` and the OIDC issuer are only meaningful once `ACTIVE`. `DeleteCluster` refuses while node groups exist, with `ResourceInUseException`.

**Error shapes.** EKS exception names on both `x-amzn-ErrorType` header spellings, with `clusterName` / `nodegroupName` / `addonName` in the body, so typed SDK errors and retry logic behave correctly.

**OIDC key ID derivation.** Base64url of the SHA-256 of the DER PKIX public key — byte-identical to Kubernetes, so the `kid` in a projected token matches the published JWKS.

**Node labels and taints.** The full EKS label set, and the `NO_SCHEDULE` → `NoSchedule` enum conversion that is easy to miss.

---

## Approximated — with reasons

**The cluster creator's identity is configured, not inferred.**
Real EKS reads the creator from the signed `CreateCluster` request. eksuvia cannot: verifying SigV4 needs the caller's secret key, and local emulators accept dummy credentials by design. So `--cluster-creator-arn` names the principal that `bootstrapClusterCreatorAdminPermissions` grants cluster-admin to, defaulting to the identity Floci reports for conventional test credentials.
*Impact:* if you use a non-default identity, set the flag or create an access entry explicitly.

**Node groups draw from a fixed pool.**
kind cannot add nodes to a running cluster. Workers are created up front (`--worker-pool-size`) and node groups claim from that pool. Requesting more than remains yields `DEGRADED` with `NodeCreationFailure`.
*Impact:* scaling is bounded by the pool. The failure mode is real-EKS-shaped, but its trigger is not.

**Namespace wildcards resolve at reconcile time.**
EKS evaluates `team-*` in its own authorization path. RBAC RoleBindings need concrete namespaces, so eksuvia expands the pattern against existing namespaces. A namespace created afterwards is picked up on the next reconcile, not instantly.

**`{{EC2PrivateDNSName}}` substitutes the session name.**
Upstream resolves it via `ec2:DescribeInstances`. There are no EC2 instances here, so the session name is used, preserving the `system:node:<name>` username shape node authorization depends on.

**`AmazonEKSAdminViewPolicy` maps to `view`.**
It is really `view` plus read access to resources holding secrets material, with no single built-in equivalent. `view` is the closest honest approximation and is slightly *less* permissive than the real policy.

**The OIDC issuer is not an `oidc.eks.<region>.amazonaws.com` URL.**
It must be dereferenceable by STS from inside a container, so it is `http://<advertise-host>:<port>/id/<ID>`. The identifier keeps the real 32-character uppercase-hex shape, so generated trust policies look like production ones.
*Impact:* trust policies written locally need the issuer substituted before use against AWS.

**Add-ons: API is real, installation is partial.**
`DescribeAddonVersions` advertises a catalogue so Terraform and eksctl can resolve versions. `coredns` and `kube-proxy` genuinely run (kubeadm bootstraps them) and report `ACTIVE`. Every other add-on is tracked as an API object but deploys nothing, and says so in `health.issues` rather than claiming a healthy state it has not earned.

**The token webhook runs over plain HTTP.**
`insecure-skip-tls-verify` on a local bridge network. This endpoint arbitrates cluster access; in any non-local deployment it must be TLS with a pinned CA. eksuvia is a development tool and should never be exposed beyond localhost.

**No signing-key rotation.** AWS rotates the OIDC key every 7 days. eksuvia generates one keypair per cluster and keeps it.

---

## Not implemented

| Area | Notes |
|---|---|
| **EKS Pod Identity** | No agent DaemonSet on `169.254.170.23`, no `AssumeRoleForPodIdentity`, no associations API. IRSA is the supported path today. |
| **The IRSA mutating webhook** | The OIDC machinery is real, but nothing yet injects `AWS_ROLE_ARN` and the projected volume from a ServiceAccount annotation. You must set them on the pod spec yourself, or use the `/_eksuvia/clusters/<name>/irsa-token` endpoint. **This is the highest-value next piece.** |
| **Cloud controller** | `Service type=LoadBalancer` does not create an ELBv2 in Floci; PVCs do not create EBS volumes. |
| **Fargate profiles** | No API, no scheduling. |
| **VPC CNI semantics** | Pods get kind's CNI addresses, not VPC IPs from ENIs. IP-exhaustion behaviour cannot be reproduced. |
| **`UpdateClusterConfig` / `UpdateClusterVersion`** | No in-place upgrades; recreate instead. |
| **Identity provider configs** | `AssociateIdentityProviderConfig` and friends. |
| **Encryption config** | No envelope encryption via KMS. |
| **EKS Auto Mode, Hybrid Nodes, Outposts, EKS Anywhere** | Out of scope for now. |
| **Insights, capabilities, ACK, Argo CD, kro** | Out of scope. |
| **Pagination** | List operations return everything; `nextToken` is not implemented. Fine at local scale, but a caller that *requires* pagination will not exercise it. |
| **Durable state** | Cluster metadata is in-memory. Restarting eksuvia orphans running kind clusters — they are reported at startup but not adopted. |

---

## Deliberate non-goals

**Production use.** This is a development and CI tool. It runs an authentication webhook over plain HTTP and accepts dummy credentials.

**Replacing Floci.** eksuvia emulates the part of EKS that AWS hides and proxies everything else. Reimplementing IAM, STS, EC2 and ELBv2 would be a larger project that already exists.

**Being faster than the real thing at the cost of realism.** Cluster creation goes through `CREATING`, node groups take time to settle, and denials look like real denials. An emulator whose timing model is a fast path you cannot hit in production teaches the wrong lessons.
