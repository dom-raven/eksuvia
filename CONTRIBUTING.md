# Contributing

Thanks for looking. eksuvia is early, and the most useful contributions right now are unglamorous.

## The highest-value thing you can do

**Run it against real Docker and tell us what breaks.**

The core was written on a machine without a container runtime, so cluster provisioning has never actually executed. If you run the quick start and hit a wall, an issue containing:

- your OS and container runtime (Docker Desktop / Docker Engine / Podman)
- the `--advertise-host` you used
- `eksuvia --log-level debug` output
- `docker logs eksuvia-<cluster>-control-plane` if the cluster came up but the API server misbehaved

is worth more than a feature PR. See [item 0 on the roadmap](docs/roadmap.md) for the specific unknowns.

## Development

```bash
make check     # gofmt, vet, test — everything CI runs
make build     # binary into ./bin
make test      # unit tests
make cover     # coverage summary
```

Go 1.24+. No other tooling required for the unit tests; Docker or Podman is needed only to exercise provisioning.

## Design principles

A few things worth knowing before changing code:

**Fidelity beats convenience.** If real EKS returns a confusing error, eksuvia should return the same confusing error. An emulator whose behaviour is nicer than production teaches the wrong lessons. Where a deviation is unavoidable, document it in [docs/fidelity.md](docs/fidelity.md) — that file is part of the contract.

**Do not grant `system:masters` as a shortcut.** The entire point of the identity resolver is that RBAC is testable. Anything that short-circuits the mapping defeats the project.

**Keep the dependency graph small.** The module list is currently 24 entries. `internal/kube` is deliberately a narrow hand-rolled client rather than `client-go`, because eksuvia should not be pinned to one Kubernetes minor version. Please don't add `client-go`.

**Leaf packages stay HTTP-free.** `awsarn`, `token`, `oidc` and `identity` know nothing about `net/http` handlers, which is what makes the fidelity-critical logic unit-testable without Docker. Keep it that way.

**Explain the surprising parts.** Comments should say *why*, especially where the code encodes an EKS quirk. `x-amz-expires` is not the expiry; a denying webhook still returns HTTP 200; taint effects need enum conversion. Someone will otherwise "fix" these.

## Testing

New behaviour needs a test if it can be tested without Docker. The bar is not coverage percentage — it is whether a future refactor that breaks EKS compatibility would fail.

The existing tests are a decent guide to style: table-driven, named after the behaviour rather than the function, with a comment on any case that exists because of a real-world quirk.

## Commits and PRs

- Focused commits with a clear subject line.
- Say what you verified and what you did not. "Compiles and unit tests pass, not run against Docker" is a perfectly good PR note and much better than silence.
- Update [docs/fidelity.md](docs/fidelity.md) if you change what is faithful, approximated, or missing.

## Scope

eksuvia emulates the EKS-specific control plane and proxies everything else to [Floci](https://github.com/floci-io/floci). Requests to reimplement IAM, STS, EC2 or S3 here belong upstream in Floci instead.

## Code of conduct

Be decent to each other. Disagree about technical things freely; don't be unpleasant about people.
