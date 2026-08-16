# IRSA against a local cluster

Demonstrates the flow that is genuinely hard to emulate: a pod assuming an IAM
role by presenting a projected service-account token to STS.

Nothing here is eksuvia-specific except the endpoint. The same manifests work
against real EKS.

## 1. Create the cluster

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test

aws eks create-cluster --name demo \
  --role-arn arn:aws:iam::000000000000:role/eksClusterRole \
  --resources-vpc-config subnetIds=[],securityGroupIds=[] \
  --kubernetes-version 1.31

# wait for ACTIVE
until [ "$(aws eks describe-cluster --name demo --query 'cluster.status' --output text)" = ACTIVE ]; do sleep 5; done
aws eks update-kubeconfig --name demo
```

## 2. Create the IAM role with an OIDC trust policy

Take the issuer from the cluster and strip the scheme — that is how it appears
in both the provider ARN and the condition keys:

```bash
ISSUER=$(aws eks describe-cluster --name demo --query 'cluster.identity.oidc.issuer' --output text)
ISSUER_HOST=${ISSUER#http://}; ISSUER_HOST=${ISSUER_HOST#https://}

cat > trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::000000000000:oidc-provider/${ISSUER_HOST}"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "${ISSUER_HOST}:sub": "system:serviceaccount:default:s3-reader",
      "${ISSUER_HOST}:aud": "sts.amazonaws.com"
    }}
  }]
}
EOF

aws iam create-role --role-name S3Reader --assume-role-policy-document file://trust.json
```

## 3. Deploy

```bash
kubectl apply -f manifests.yaml
kubectl logs job/irsa-demo
```

The pod's AWS SDK finds `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`,
exchanges the projected token for credentials, and calls S3 as the assumed role.

## Note on the projected volume

Real EKS runs a mutating admission webhook that injects the environment
variables and the projected volume automatically, from the
`eks.amazonaws.com/role-arn` annotation alone. eksuvia does not do that yet
([roadmap item 1](../../docs/roadmap.md)), so `manifests.yaml` sets them
explicitly. The annotation is left in place so the same file works unchanged
against real EKS.

## Shortcut: mint a token without a pod

Useful for checking a trust policy before deploying anything. This endpoint is
eksuvia-only and has no AWS equivalent:

```bash
curl -sX POST http://localhost:4566/_eksuvia/clusters/demo/irsa-token \
  -H 'Content-Type: application/json' \
  -d '{"namespace":"default","serviceAccount":"s3-reader"}'
```
