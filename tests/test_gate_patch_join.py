from collections.abc import Sequence

from problem_frame_gate import (
    CheckResult,
    Envelope,
    EnvelopeClass,
    ExecutorGate,
    FoldKernel,
    FoldState,
    GateRequest,
    Horizon,
    JoinProposal,
    PatchChecker,
    PatchProposal,
    ReadFootprint,
    RiskClaimRecord,
    RiskRouteWitness,
    TouchMatrix,
    WriteClass,
    WriteCover,
    digest_json,
    digest_log,
)
from problem_frame_gate.join import JoinChecker


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


def cert_check() -> dict[str, object]:
    return {
        "accepted": True,
        "checker": "unit-certificate-family-v1",
        "transcript_digest": digest_json({"checker": "unit-certificate-family-v1", "accepted": True}),
        "dependency_digest": digest_json({"dependencies": [], "source_ids": []}),
        "revocation_frontier": [],
        "checked_at": 2,
        "assumption": "CertificateFamilyChecker",
    }


def horizon() -> Horizon:
    return Horizon.strict_default(agent_writers=("agent",), normal_capacity=100)


def base_log() -> list[Envelope]:
    return [
        env(
            "e0",
            0,
            "Frame",
            frame_id="p1",
            scope="agent-demo",
            goal="investigate anomaly",
            evidence_ids=["u1"],
            actions=["run-check"],
            acceptance=["review"],
            risk_ids=["r1"],
        ),
        env("e1", 1, "Evidence", evidence_id="u1", digest="sha256:source"),
        env(
            "e2",
            2,
            "Issue",
            cert_id="c-risk",
            family="risk",
            issuer="agent",
            expires_at=99,
            family_check=cert_check(),
        ),
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


def gate_request() -> GateRequest:
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
            checker="unit-risk-route-v1",
            transcript_digest=digest_json({"checker": "unit-risk-route-v1", "mode": "fixed"}),
            route="fixed",
        ),
    )
    return GateRequest(
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
        risk_claim=risk_claim.to_json(),
        risk_alpha="1/50",
    )


def test_executor_gate_accepts_and_bundle_consumes_linear_authority() -> None:
    log = base_log()
    gate = ExecutorGate()
    request = gate_request()

    result = gate.check(horizon(), log, request)
    assert result.ok, [issue.to_json() for issue in result.issues]

    bundle = gate.create_bundle(horizon(), log, request)
    state = FoldKernel().fold(horizon(), [*log, *bundle])
    assert state.component("capabilities")["cap1"]["status"] == "used"
    assert state.component("resources")["lease1"]["status"] == "consumed"
    assert state.component("risk")["spends"]["r1"]["closed_at"] == 10
    assert state.component("outboxes")["out1"]["status"] == "claimed"


def test_gate_rejects_after_frame_suspension() -> None:
    log = [*base_log(), env("e10", 10, "Suspended", frame_id="p1")]
    request = GateRequest(**{**gate_request().to_json(), "source_time": 10, "commit_time": 11})
    result = ExecutorGate().check(horizon(), log, request)
    assert not result.ok
    assert any(issue.code == "gate-frame-inactive" for issue in result.issues)


def test_patch_checker_rejects_non_append_patch() -> None:
    log = base_log()
    proposal = PatchProposal(
        expected_source_digest=digest_log(log),
        append=(env("e9", 11, "Evidence", evidence_id="u2"),),
    )
    result = PatchChecker().check(horizon(), log, proposal)
    assert not result.ok
    assert any(issue.code == "patch-not-append-only" for issue in result.issues)


def test_patch_checker_runs_affected_invariant() -> None:
    log = base_log()
    proposal = PatchProposal(
        expected_source_digest=digest_log(log),
        append=(env("e10", 10, "Evidence", evidence_id="u2"),),
        affected_invariants=("has-u2",),
        write_classes=(WriteClass("Evidence", "u2"),),
        write_cover=WriteCover((WriteClass("Evidence", "u2"),), ("e10",)),
        read_footprints=(ReadFootprint("has-u2", ("u2",)),),
        touch_matrix=TouchMatrix({"Evidence:u2|u2": "touch"}),
    )

    def invariant(state: FoldState, _target: Sequence[Envelope]) -> CheckResult:
        return CheckResult.success() if "u2" in state.component("evidence") else CheckResult.fail()

    result = PatchChecker().check(horizon(), log, proposal, invariants={"has-u2": invariant})
    assert result.ok


def test_join_rejects_double_resource_consumption() -> None:
    log = base_log()
    branch_a = [*log, env("a10", 10, "ConsumeResource", lease_id="lease1", consumer="a")]
    branch_b = [*log, env("b10", 10, "ConsumeResource", lease_id="lease1", consumer="b")]
    result = JoinChecker().check(
        horizon(),
        JoinProposal(branches=(tuple(branch_a), tuple(branch_b)), ancestor=tuple(log)),
    )
    assert not result.ok
    assert any(issue.code == "join-target-fold" for issue in result.issues)


def test_fake_outbox_claim_is_rejected_at_legal_log_level() -> None:
    log = [
        *base_log(),
        env("e10", 10, "OutboxClaim", outbox_id="out1", frame_id="p1", action="run-check", gate_id="fake"),
    ]
    result = FoldKernel().check_fold(horizon(), log)
    assert not result.ok
    assert any(issue.code in {"protected-writer-authority", "gate-bundle-missing-group"} for issue in result.issues)


def test_gate_bundle_missing_close_is_rejected() -> None:
    log = base_log()
    bundle = ExecutorGate().create_bundle(horizon(), log, gate_request())
    truncated = bundle.envelopes[:-1]
    result = FoldKernel().check_fold(horizon(), [*log, *truncated])
    assert not result.ok
    assert any(issue.code == "gate-bundle-size" for issue in result.issues)


def test_patch_suspension_requires_cap_and_outbox_invalidation() -> None:
    log = base_log()
    proposal = PatchProposal(
        expected_source_digest=digest_log(log),
        append=(env("e10", 10, "Suspended", frame_id="p1"),),
    )
    result = PatchChecker().check(horizon(), log, proposal)
    assert not result.ok
    assert any(issue.code == "patch-frame-invalidates-capability" for issue in result.issues)
