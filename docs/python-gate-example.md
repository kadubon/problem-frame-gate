# Problem Frame Gate: synthetic Python gate construction

This is the complete construction example relocated from README. With the installed
package, the Python snippets run in one process in the order shown. They construct
synthetic in-memory records. Digests such as `sha256:source` are illustrative; declared
family/risk witnesses rely on explicit environment assumptions. They are not production
evidence and must not be self-issued to bypass callable checks. The memory committer
does not make storage crash-durable and no snippet here calls an actuator.

## Construct the finite gate

```python
from problem_frame_gate import (
    Envelope,
    EnvelopeClass,
    ExecutorGate,
    GateRequest,
    Horizon,
    RiskClaimRecord,
    RiskRouteWitness,
    digest_json,
)

horizon = Horizon.strict_default(agent_writers=("agent",))

def env(eid: str, commit: int, kind: str, **payload: object) -> Envelope:
    return Envelope(eid, eid, "0", commit, "agent", "agent", 1, EnvelopeClass.NORMAL, {"kind": kind, **payload})

family_check = {
    "accepted": True,
    "checker": "example-certificate-family-v1",
    "transcript_digest": digest_json({"checker": "example-certificate-family-v1", "accepted": True}),
    "dependency_digest": digest_json({"dependencies": [], "source_ids": []}),
    "revocation_frontier": [],
    "checked_at": 2,
    "assumption": "CertificateFamilyChecker",
}

log = [
    env("e0", 0, "Frame", frame_id="p1", scope="lab", goal="test anomaly",
        evidence_ids=["u1"], actions=["run-check"], acceptance=["review"], risk_ids=["r1"]),
    env("e1", 1, "Evidence", evidence_id="u1", digest="sha256:source"),
    env("e2", 2, "Issue", cert_id="c-risk", family="risk", issuer="agent",
        expires_at=99, family_check=family_check),
    env("e3", 3, "Activated", frame_id="p1"),
    env("e4", 4, "RiskReg", hypothesis_id="h1", family="fixed"),
    env("e5", 5, "RiskReserve", risk_id="r1", hypothesis_id="h1", frame_id="p1", eta="1/100"),
    env("e6", 6, "RiskSpend", risk_id="r1", hypothesis_id="h1", frame_id="p1",
        eta="1/100", mode="fixed", cert_id="c-risk"),
    env("e7", 7, "ReserveResource", lease_id="lease1", token_id="tool", frame_id="p1"),
    env("e8", 8, "MintCap", capability_id="cap1", frame_id="p1", action="run-check"),
    env("e9", 9, "AuthorizeOutbox", outbox_id="out1", frame_id="p1", action="run-check"),
]

risk_claim = RiskClaimRecord(
    claim_id="q1",
    risk_id="r1",
    hypothesis_id="h1",
    mode="fixed",
    cert_id="c-risk",
    eta="1/100",
    event_id="F1",
    standardized_event_id="F1",
    route_witness=RiskRouteWitness(
        accepted=True,
        checker="example-risk-route-v1",
        transcript_digest=digest_json({"checker": "example-risk-route-v1", "mode": "fixed"}),
        route="fixed",
    ),
)

request = GateRequest(
    gate_id="gate1", bundle_id="bundle1", frame_id="p1", action="run-check",
    outbox_id="out1", capability_id="cap1", lease_id="lease1",
    risk_id="r1", hypothesis_id="h1", risk_mode="fixed", risk_cert_id="c-risk",
    source_time=9, commit_time=10, risk_claim=risk_claim.to_json(), risk_alpha="1/50",
)

gate = ExecutorGate()
assert gate.check(horizon, log, request).ok
bundle = gate.create_bundle(horizon, log, request)
assert bundle.verify(horizon, log).ok
```

## Durable Runtime Path

Use the runtime helpers when an agent needs to commit a gate decision before any
external tool call:

```python
from problem_frame_gate import GateCommitter, MemoryAppendOnlyStore, OutboxBroker

store = MemoryAppendOnlyStore(log)
commit = GateCommitter(store).commit_gate(horizon, request)
assert commit.ok
```

`GateCommitter` only appends the accepted five-row gate bundle.  It never calls
an actuator.  `OutboxBroker` is the separate component that dispatches only
after a durable `OutboxClaim` and `DispatchStarted` row exist.  Production
deployments can use `SQLiteAppendOnlyStore` or implement the `AppendOnlyStore`
protocol with their own replicated storage.


See [production assumptions and callable checkers](quickstart.md),
[durable commit and dispatch](operations.md), and the [README](../README.md).
