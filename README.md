# Problem Frame Gate

Problem Frame Gate is a Python library and CLI for finite, proof-carrying audit
checks around AI decision frames and external action gates.  It implements the
audit-calculus concepts in:

Takahashi, K. (2026). *Problemogenesis Theory: A Finite Proof-Carrying Audit
Calculus for Problem-Frame Activation*. Zenodo.
https://doi.org/10.5281/zenodo.20913669

The package is strict by default.  A log is not considered safe unless a finite
manifest declares writer authority, protected action constructors, capacities,
certificate families, risk modes, and gate bundle policy.

## Install

```bash
uv sync --all-extras
uv run pytest
```

From PyPI:

```bash
pip install problem-frame-gate
pfg init-manifest > horizon.json
```

## Safe Quickstart

Create a strict manifest:

```bash
pfg init-manifest > horizon.json
```

Validate and fold a log:

```bash
pfg validate-schema horizon horizon.json
pfg validate-schema log log.json
pfg verify-log --horizon horizon.json log.json
pfg fold --horizon horizon.json log.json
```

Check an action gate and emit the atomic bundle:

```bash
pfg validate-schema gate-request gate-request.json
pfg check-gate --horizon horizon.json --bundle gate-request.json log.json
```

The generated bundle contains exactly five protected rows:

1. `GateCheck`
2. `OutboxClaim`
3. `UseCap`
4. `ConsumeResource`
5. `RiskClose`

Each row must be written by the executor writer and committed in one atomic
group.  A standalone `OutboxClaim` is rejected.

## Python Example

```python
from problem_frame_gate import Envelope, EnvelopeClass, ExecutorGate, GateRequest, Horizon

horizon = Horizon.strict_default(agent_writers=("agent",))

def env(eid: str, commit: int, kind: str, **payload: object) -> Envelope:
    return Envelope(eid, eid, "0", commit, "agent", "agent", 1, EnvelopeClass.NORMAL, {"kind": kind, **payload})

log = [
    env("e0", 0, "Frame", frame_id="p1", scope="lab", goal="test anomaly",
        evidence_ids=["u1"], actions=["run-check"], acceptance=["review"], risk_ids=["r1"]),
    env("e1", 1, "Evidence", evidence_id="u1", digest="sha256:source"),
    env("e2", 2, "Issue", cert_id="c-risk", family="risk", issuer="agent", expires_at=99, family_check=True),
    env("e3", 3, "Activated", frame_id="p1"),
    env("e4", 4, "RiskReg", hypothesis_id="h1", family="fixed"),
    env("e5", 5, "RiskReserve", risk_id="r1", hypothesis_id="h1", frame_id="p1", eta="1/100"),
    env("e6", 6, "RiskSpend", risk_id="r1", hypothesis_id="h1", frame_id="p1",
        eta="1/100", mode="fixed", cert_id="c-risk"),
    env("e7", 7, "ReserveResource", lease_id="lease1", token_id="tool", frame_id="p1"),
    env("e8", 8, "MintCap", capability_id="cap1", frame_id="p1", action="run-check"),
    env("e9", 9, "AuthorizeOutbox", outbox_id="out1", frame_id="p1", action="run-check"),
]

request = GateRequest(
    gate_id="gate1", bundle_id="bundle1", frame_id="p1", action="run-check",
    outbox_id="out1", capability_id="cap1", lease_id="lease1",
    risk_id="r1", hypothesis_id="h1", risk_mode="fixed", risk_cert_id="c-risk",
    source_time=9, commit_time=10,
)

gate = ExecutorGate()
assert gate.check(horizon, log, request).ok
bundle = gate.create_bundle(horizon, log, request)
assert bundle.verify(horizon, log).ok
```

## Security Boundary

The library proves finite audit consistency.  It does not prove external truth,
cryptographic collision resistance, statistical model validity, or physical
effect.  Those are explicit assumptions in checker results.

See `docs/quickstart.md`, `docs/schema.md`, `docs/theory-mapping.md`, and
`docs/operations.md` for operational use.

## Release

The canonical repository is `https://github.com/kadubon/problem-frame-gate`.
Versioned releases are published by GitHub Actions through PyPI Trusted
Publishing from `.github/workflows/workflow.yml`; no long-lived PyPI token is
required.
