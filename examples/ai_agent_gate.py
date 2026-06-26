from problem_frame_gate import Envelope, EnvelopeClass, ExecutorGate, GateRequest, Horizon


def env(eid: str, commit: int, kind: str, **payload: object) -> Envelope:
    return Envelope(
        eid=eid,
        event=eid,
        slot="0",
        commit_time=commit,
        writer="agent",
        owner="agent",
        version=1,
        envelope_class=EnvelopeClass.NORMAL,
        payload={"kind": kind, **payload},
    )


horizon = Horizon.strict_default(agent_writers=("agent",), normal_capacity=100)

log = [
    env(
        "e0",
        0,
        "Frame",
        frame_id="p1",
        scope="agent-demo",
        goal="investigate a bounded anomaly",
        evidence_ids=["u1"],
        actions=["run-check"],
        acceptance=["human-review"],
        risk_ids=["r1"],
    ),
    env("e1", 1, "Evidence", evidence_id="u1", digest="sha256:source"),
    env("e2", 2, "Issue", cert_id="c-risk", family="risk", issuer="agent", expires_at=99, family_check=True),
    env("e3", 3, "Activated", frame_id="p1"),
    env("e4", 4, "RiskReg", hypothesis_id="h1", family="fixed"),
    env("e5", 5, "RiskReserve", risk_id="r1", hypothesis_id="h1", frame_id="p1", eta="1/100"),
    env(
        "e6",
        6,
        "RiskSpend",
        risk_id="r1",
        hypothesis_id="h1",
        frame_id="p1",
        eta="1/100",
        mode="fixed",
        cert_id="c-risk",
    ),
    env("e7", 7, "ReserveResource", lease_id="lease1", token_id="tool", frame_id="p1"),
    env("e8", 8, "MintCap", capability_id="cap1", frame_id="p1", action="run-check"),
    env("e9", 9, "AuthorizeOutbox", outbox_id="out1", frame_id="p1", action="run-check"),
]

request = GateRequest(
    gate_id="gate1",
    bundle_id="bundle1",
    frame_id="p1",
    action="run-check",
    outbox_id="out1",
    capability_id="cap1",
    lease_id="lease1",
    risk_id="r1",
    hypothesis_id="h1",
    risk_mode="fixed",
    risk_cert_id="c-risk",
    source_time=9,
    commit_time=10,
)

gate = ExecutorGate()
result = gate.check(horizon, log, request)
print(result.to_json())
if result.ok:
    for envelope in gate.create_bundle(horizon, log, request):
        print(envelope.to_json())
