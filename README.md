# Problem Frame Gate

Before dispatch, does a declared action have the required finite frame, capability,
resource and evidence records? Problem Frame Gate checks those bindings and prepares
an atomic gate bundle. Committing that bundle and invoking an actuator are separate
host-controlled steps. It implements the audit-calculus concepts in:

Takahashi, K. (2026). *Problemogenesis Theory: A Finite Proof-Carrying Audit
Calculus for Problem-Frame Activation*. Zenodo.
https://doi.org/10.5281/zenodo.20913669

The package is strict by default.  A log is not accepted under the strict audit rules unless a finite
manifest declares writer authority, protected action constructors, capacities,
certificate families, risk modes, and gate bundle policy.

## Install

Current source and [PyPI package](https://pypi.org/project/problem-frame-gate/1.1.0/):
**1.1.0**, Python 3.10+, Apache-2.0. In an isolated Python environment
(POSIX shell or PowerShell):

```sh
python -m pip install problem-frame-gate==1.1.0
pfg --help
```

Installation may use the network; local inspection does not call a model or dispatch
an operation. Installation does not require running tests. Contributor checks are
in [operations](docs/operations.md) and the [quickstart](docs/quickstart.md).

## Safe Quickstart

The wheel packages `problem_frame_gate`, not checkout-relative `docs/examples/`.
For the commands below, use a source checkout and run from its root with the installed
CLI, or prepare the same relative paths from the three complete fixtures:
[horizon](docs/examples/horizon.json), [log](docs/examples/log.json), and
[gate request](docs/examples/gate-request.json). These are synthetic assumption-bearing
records, not production certificates. Changing an `accepted` flag does not establish evidence.

This small path only reads those files and prints a fold/gate result (POSIX shell or
PowerShell); it neither appends the bundle nor invokes an actuator:

```sh
pfg fold --horizon docs/examples/horizon.json docs/examples/log.json
pfg check-gate --horizon docs/examples/horizon.json --bundle docs/examples/gate-request.json docs/examples/log.json
```

Inspect `ok`, issues and the bound gate transcript. Commands are source-checked,
not newly execution-verified. See [schema checks and full walkthrough](docs/quickstart.md).
For a new project, `pfg init-manifest` prints a starter manifest; redirecting it with
`> horizon.json` writes a file and must use a fresh destination. A starter manifest
alone is not a complete action/evidence log.

The generated bundle contains exactly five protected rows:

1. `GateCheck`
2. `OutboxClaim`
3. `UseCap`
4. `ConsumeResource`
5. `RiskClose`

Each row must be written by the executor writer and committed in one atomic
group.  A standalone `OutboxClaim` is rejected.

For deployment, declare real writers, issuers, frames, resources and risk policy,
then supply legitimate evidence or callable checkers. The synthetic family/risk
assumptions cannot be adopted as self-issued production approval.

## Python Example

From the source checkout root with the package installed, this smaller example
reads the same three synthetic fixtures and checks the gate in memory. It does
not commit records or dispatch an actuator:

```python
import json
from pathlib import Path

from problem_frame_gate import Envelope, ExecutorGate, GateRequest, Horizon

def load_fixture(name):
    return json.loads(Path("docs/examples", name).read_text(encoding="utf-8"))

horizon = Horizon.from_mapping(load_fixture("horizon.json"))
log = tuple(Envelope.from_mapping(item) for item in load_fixture("log.json"))
request = GateRequest.from_mapping(load_fixture("gate-request.json"))
gate = ExecutorGate()
print(gate.check(horizon, log, request).ok)
```

The [complete synthetic construction](docs/python-gate-example.md) shows the finite
family-check and risk-route assumptions explicitly. For a production profile, use
the [callable checker requirements](docs/quickstart.md), not caller-provided success flags.

## Durable Runtime Path

`GateCommitter` atomically appends the accepted five-row bundle to an
`AppendOnlyStore`; it does not call an actuator. `MemoryAppendOnlyStore` is in-memory;
`SQLiteAppendOnlyStore` provides the local durable option. `OutboxBroker` is a separate
dispatcher and can invoke an actuator only after durable `OutboxClaim` and
`DispatchStarted` records. See [operations](docs/operations.md) and the existing
[SQLite example](examples/sqlite_gate_commit.py). Durable records do not guarantee
exactly-once external effects.

## Security Boundary

The library proves finite audit consistency.  It does not prove external truth,
cryptographic collision resistance, statistical model validity, or physical
effect.  Those are explicit assumptions in checker results.

Strict certificates require a finite family-check record with a checker name,
transcript digest, dependency digest, revocation frontier, and check time.
Boolean certificate flags are treated as legacy assumptions and fail strict
v1.1.0 checks.  Certificate issue rows can also carry signature fields; Python
deployments may require and verify them with `SignatureRegistry`.

Verification routes and production requirements:

- JSON-only use relies on manifest-declared environment assumptions such as
  `CertificateFamilyChecker` and `StatisticalModel`.
- Python deployments can register callable `CertificateFamily` and `RiskMode`
  checkers.  The verifier reuses those registries when replaying embedded
  `GateCheck` transcripts.
- `production_profile()` supplies callable finite risk-route checkers and
  rejects assumption-only statistical routes unless the deployment explicitly
  declares that boundary.

This finite audit-consistency boundary is not universal action safety, OAuth
infrastructure or a sandbox. Hosts remain responsible for execution isolation and
unresolved external outcomes.

## Machine-readable interfaces

Use the [schema contract](docs/schema.md), [JSON format](docs/json-format.md),
[issue codes](docs/issue-codes.md), and [CLI source](src/problem_frame_gate/cli.py).
The [positive fixtures](docs/examples/) and [deliberate unsafe fixtures](examples/unsafe/)
show accepted and rejected finite inputs; fixture acceptance is not external truth.

## Release

The canonical repository is `https://github.com/kadubon/problem-frame-gate`.
Versioned releases are published by GitHub Actions through PyPI Trusted
Publishing from `.github/workflows/workflow.yml`; no long-lived PyPI token is
required.

## Research navigation

Use the [Collective Intelligence Research and OSS Index](https://kadubon.github.io/github.io/collective-intelligence-index.html)
for [authority boundaries](https://kadubon.github.io/github.io/collective-intelligence-index.html#problem-authority)
and [retry/recovery](https://kadubon.github.io/github.io/collective-intelligence-index.html#problem-retry-recovery).
These routes explain host obligations, not permission to dispatch.
