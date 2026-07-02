from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from problem_frame_gate import (
    CheckResult,
    ClockWatermark,
    DispatchResult,
    Envelope,
    EnvelopeClass,
    ExecutorGate,
    FormationProofBuilder,
    Frame,
    GateCommitter,
    GateRequest,
    Horizon,
    IntegerClockWatermarkProvider,
    JoinChecker,
    JoinProposal,
    MemoryAppendOnlyStore,
    OutboxBroker,
    ReachabilityChecker,
    ReachabilityTranscript,
    RiskClaimRecord,
    RiskRouteWitness,
    SignatureRegistry,
    SQLiteAppendOnlyStore,
    TransitionRecord,
    check_certificate_live,
    digest_json,
    digest_log,
    example_profile,
    is_sha256_digest,
    production_profile,
)
from problem_frame_gate.cli import main
from problem_frame_gate.fold import FoldKernel
from problem_frame_gate.metrics import MemoryMetricsSink
from problem_frame_gate.risk import standard_risk_registry
from problem_frame_gate.storage import AppendResult, StoreSnapshot, snapshot_from_json


def env(eid: str, commit: int, kind: str, writer: str = "agent", **payload: Any) -> Envelope:
    return Envelope(
        eid=eid,
        event=eid,
        slot="0",
        commit_time=commit,
        writer=writer,
        owner=writer,
        version=1,
        envelope_class=EnvelopeClass.NORMAL,
        payload={"kind": kind, **payload},
    )


def horizon() -> Horizon:
    return Horizon.strict_default(agent_writers=("agent",), normal_capacity=100)


def family_check() -> dict[str, object]:
    return {
        "accepted": True,
        "checker": "unit-certificate-family-v1",
        "transcript_digest": digest_json({"checker": "unit-certificate-family-v1", "accepted": True}),
        "dependency_digest": digest_json({"dependencies": [], "source_ids": ["source"]}),
        "revocation_frontier": [],
        "checked_at": 2,
        "assumption": "CertificateFamilyChecker",
    }


def source_log(**issue_overrides: object) -> tuple[Envelope, ...]:
    issue_payload = {
        "cert_id": "risk-cert",
        "issuer": "agent",
        "family": "risk",
        "subject": "h1",
        "dependencies": [],
        "source_ids": ["source"],
        "family_check": family_check(),
        "dependency_digest": digest_json({"dependencies": [], "source_ids": ["source"]}),
        "assumption": "CertificateFamilyChecker",
    }
    issue_payload.update(issue_overrides)
    return (
        env("source", 1, "Evidence", evidence_id="source", digest=digest_json({"source": 1})),
        env("issue", 2, "Issue", **issue_payload),
        env(
            "frame",
            3,
            "Frame",
            frame_id="p1",
            scope="email",
            goal="send approved mail",
            evidence_ids=["source"],
            actions=["send-email"],
            acceptance=["approved"],
            resources=["lease1"],
            risk_ids=["risk1"],
        ),
        env("active", 4, "Activated", frame_id="p1"),
        env("cap", 5, "MintCap", capability_id="cap1", frame_id="p1", action="send-email"),
        env("resource", 6, "ReserveResource", lease_id="lease1", frame_id="p1", amount=1),
        env("outbox", 7, "AuthorizeOutbox", outbox_id="out1", frame_id="p1", action="send-email"),
        env("risk-reg", 8, "RiskReg", hypothesis_id="h1", family="risk"),
        env("risk-reserve", 9, "RiskReserve", risk_id="risk1", hypothesis_id="h1", frame_id="p1", eta="1/100"),
        env(
            "risk-spend",
            10,
            "RiskSpend",
            risk_id="risk1",
            hypothesis_id="h1",
            frame_id="p1",
            eta="1/100",
            mode="fixed",
            cert_id="risk-cert",
        ),
    )


def risk_claim(*, assumption: str = "StatisticalModel") -> RiskClaimRecord:
    return RiskClaimRecord(
        claim_id="claim1",
        risk_id="risk1",
        hypothesis_id="h1",
        mode="fixed",
        cert_id="risk-cert",
        eta="1/100",
        event_id="failure",
        standardized_event_id="failure",
        route_witness=RiskRouteWitness(
            accepted=True,
            checker="unit-risk-route-v1",
            transcript_digest=digest_json({"checker": "unit-risk-route-v1", "mode": "fixed"}),
            route="fixed",
            spend_before_selection=True,
            assumption=assumption,
        ),
        assumption=assumption,
    )


def gate_request(log: tuple[Envelope, ...], *, claim_assumption: str = "StatisticalModel") -> GateRequest:
    return GateRequest(
        gate_id="gate1",
        bundle_id="bundle1",
        frame_id="p1",
        action="send-email",
        outbox_id="out1",
        capability_id="cap1",
        lease_id="lease1",
        risk_id="risk1",
        hypothesis_id="h1",
        risk_mode="fixed",
        risk_cert_id="risk-cert",
        source_time=10,
        commit_time=11,
        expected_source_digest=digest_log(log),
        required_certificate_ids=("risk-cert",),
        risk_claim=risk_claim(assumption=claim_assumption).to_json(),
        risk_alpha="1/10",
    )


def test_strict_digest_helper_rejects_prefix_only_values() -> None:
    assert is_sha256_digest(digest_json({"ok": True}))
    assert not is_sha256_digest("sha256:x")
    assert not is_sha256_digest("sha256:" + "A" * 64)
    assert not is_sha256_digest(None)


def test_memory_and_sqlite_append_only_store_cas(tmp_path: Path) -> None:
    log = source_log()
    store = MemoryAppendOnlyStore()
    first = store.append_atomic(horizon(), store.snapshot().digest, log)
    assert first.ok
    duplicate = store.append_atomic(horizon(), first.snapshot.digest, (log[0],))
    assert not duplicate.ok
    assert any(issue.code == "store-duplicate-eid" for issue in duplicate.result.issues)

    sqlite_store = SQLiteAppendOnlyStore(tmp_path / "audit.db")
    try:
        sqlite_result = sqlite_store.append_atomic(horizon(), sqlite_store.snapshot().digest, log[:2])
        assert sqlite_result.ok
        conflict = sqlite_store.append_atomic(horizon(), "sha256:" + "0" * 64, log[2:3])
        assert not conflict.ok
        assert any(issue.code == "store-cas-conflict" for issue in conflict.result.issues)
    finally:
        sqlite_store.close()


def test_gate_committer_clock_watermark_and_broker_dispatch() -> None:
    log = source_log()
    h = horizon()
    store = MemoryAppendOnlyStore(log)
    request = gate_request(log)
    commit = GateCommitter(store).commit_gate(h, request)
    assert commit.ok
    bundle = ExecutorGate().create_bundle(h, log, request, watermark_provider=IntegerClockWatermarkProvider())
    gate_payload = bundle.envelopes[0].payload
    assert isinstance(gate_payload["clock_watermark"], dict)
    assert any(str(row).startswith("clock_watermark:") for row in bundle.source_cut.watermark_rows)

    class AcceptingDispatcher:
        def __init__(self) -> None:
            self.calls = 0

        def dispatch(self, request: dict[str, Any]) -> DispatchResult:
            self.calls += 1
            return DispatchResult(True, {"outbox_id": request["outbox_id"]})

    dispatcher = AcceptingDispatcher()
    broker = OutboxBroker(store, dispatcher)
    dispatch = broker.poll_once(h)
    assert dispatch.ok
    assert dispatch.dispatched
    assert dispatcher.calls == 1
    folded = FoldKernel().fold(h, store.snapshot().envelopes)
    assert folded.component("outboxes")["out1"]["status"] == "actuatorAccepted"
    idle = OutboxBroker(MemoryAppendOnlyStore(log), dispatcher).poll_once(h)
    assert idle.ok
    assert not idle.dispatched


def test_signature_registry_verifies_certificate_rows() -> None:
    class AcceptingSignature:
        def verify(self, **_: object) -> bool:
            return True

    signed_log = source_log(
        key_id="k1",
        signature_algorithm="unit-ed25519",
        signed_payload_digest=digest_json({"cert_id": "risk-cert"}),
        signature="unit-signature",
    )
    state = FoldKernel().fold(horizon(), signed_log)
    registry = SignatureRegistry()
    registry.register("agent", "k1", "unit-ed25519", AcceptingSignature())
    assert check_certificate_live(
        state,
        "risk-cert",
        10,
        horizon=horizon(),
        signature_registry=registry,
        require_signature=True,
    ).ok
    rejected = check_certificate_live(state, "risk-cert", 10, horizon=horizon(), require_signature=True)
    assert any(issue.code == "certificate-signature-registry" for issue in rejected.issues)

    class RejectingSignature:
        def verify(self, **_: object) -> bool:
            return False

    bad_registry = SignatureRegistry()
    bad_registry.register("agent", "k1", "unit-ed25519", RejectingSignature())
    invalid = check_certificate_live(
        state,
        "risk-cert",
        10,
        horizon=horizon(),
        signature_registry=bad_registry,
        require_signature=True,
    )
    assert any(issue.code == "certificate-signature-invalid" for issue in invalid.issues)


def test_production_profile_rejects_assumption_only_risk_route() -> None:
    log = source_log()
    profile = production_profile("email-agent")
    request = gate_request(log, claim_assumption="StatisticalModel")
    result = ExecutorGate(risk_registry=profile.risk_registry).check(profile.horizon, log, request)
    assert any(issue.code == "risk-assumption-undeclared" for issue in result.issues)
    assert set(standard_risk_registry()) == {"fixed", "selectedEvent", "conditionalSelective", "anytime"}
    assert example_profile("browser-agent").to_json()["name"] == "browser-agent"
    with pytest.raises(ValueError, match="unknown profile"):
        production_profile("unknown")


def test_join_liveness_repairs_cover_resource_and_risk_cells() -> None:
    log = source_log()
    suspended = (*log, env("suspend", 11, "Suspended", frame_id="p1"))
    result = JoinChecker().check(
        horizon(),
        JoinProposal(branches=(suspended,), ancestor=log),
    )
    codes = {issue.code for issue in result.issues}
    assert {"join-frame-invalidates-resource", "join-frame-invalidates-risk", "join-liveness-repair-witness"} <= codes

    repaired = (
        *log,
        env("cap-revoke", 11, "RevokeCap", capability_id="cap1"),
        env("outbox-revoke", 12, "RevokeOutbox", outbox_id="out1"),
        env("resource-release", 13, "ReleaseResource", lease_id="lease1"),
        env("risk-close", 14, "RiskClose", writer="executor-gate", risk_id="risk1"),
        env("suspend", 15, "Suspended", frame_id="p1"),
    )
    repaired_result = JoinChecker().check(
        horizon(),
        JoinProposal(
            branches=(repaired,),
            ancestor=log,
            liveness_repairs=("capability:cap1", "outbox:out1", "resource:lease1", "risk:risk1"),
        ),
    )
    assert not {"join-frame-invalidates-resource", "join-frame-invalidates-risk"} & {
        issue.code for issue in repaired_result.issues
    }


def test_clock_watermark_is_stable_json() -> None:
    watermark = ClockWatermark(1, 2, digest_json({"source": 1}))
    assert watermark.to_json()["watermark_digest"] == digest_json(
        {
            "source_time": 1,
            "commit_time": 2,
            "source_digest": digest_json({"source": 1}),
            "clock_policy": "integer-commit-time",
        }
    )
    with pytest.raises(ValueError, match="source_time"):
        IntegerClockWatermarkProvider().watermark(source_time=2, commit_time=2, source_digest=digest_json({}))


def test_runtime_failure_paths_metrics_and_snapshot_json() -> None:
    log = source_log()
    metrics = MemoryMetricsSink()
    bad_request = GateRequest.from_mapping(
        {**gate_request(log).to_json(), "expected_source_digest": "sha256:" + "0" * 64}
    )
    mismatch = GateCommitter(MemoryAppendOnlyStore(log), metrics=metrics).commit_gate(horizon(), bad_request)
    assert not mismatch.ok
    assert any(issue.code == "gate-commit-source-digest" for issue in mismatch.check.issues)
    assert metrics.counters["pfg.gate_commit.rejected{reason=source_digest}"] == 1
    snapshot = snapshot_from_json({"envelopes": [row.to_json() for row in log]})
    assert snapshot.digest == digest_log(log)
    with pytest.raises(TypeError, match="snapshot envelopes"):
        snapshot_from_json({"envelopes": {}})


def test_broker_fail_closed_paths() -> None:
    class UnusedDispatcher:
        def dispatch(self, request: dict[str, Any]) -> DispatchResult:
            raise AssertionError("dispatcher must not run")

    invalid_store = MemoryAppendOnlyStore(
        (
            Envelope(
                "bad",
                "bad",
                "0",
                0,
                "agent",
                "agent",
                1,
                EnvelopeClass.NORMAL,
                {},
            ),
        )
    )
    folded = OutboxBroker(invalid_store, UnusedDispatcher()).poll_once(Horizon.unsafe_for_tests())
    assert not folded.ok
    assert any(issue.code == "broker-fold" for issue in folded.result.issues)

    class RejectingAppendStore:
        def __init__(self, snapshot: StoreSnapshot) -> None:
            self._snapshot = snapshot

        def snapshot(self) -> StoreSnapshot:
            return self._snapshot

        def append_atomic(
            self,
            horizon_value: Horizon,
            expected_digest: str,
            append: tuple[Envelope, ...],
            *,
            verifier: object | None = None,
        ) -> AppendResult:
            del horizon_value, expected_digest, append, verifier
            return AppendResult(False, self._snapshot, CheckResult.fail())

    committed = GateCommitter(MemoryAppendOnlyStore(source_log())).commit_gate(horizon(), gate_request(source_log()))
    assert committed.append is not None
    race = OutboxBroker(RejectingAppendStore(committed.append.snapshot), UnusedDispatcher()).poll_once(horizon())
    assert not race.ok


def test_formation_builder_and_reachability_facade() -> None:
    log = source_log()
    state = FoldKernel().fold(horizon(), log)
    frame = Frame.from_payload(log[2].payload)
    build = FormationProofBuilder().build(frame, state)
    assert build.ok
    assert build.proof is not None
    missing = FormationProofBuilder().build(Frame("missing", "", "", ("none",), (), ()), state)
    assert not missing.result.ok
    checker = ReachabilityChecker()
    assert checker.verify(ReachabilityTranscript(())).ok
    bad_transition = TransitionRecord("", "", "gate", "")
    assert not checker.verify(ReachabilityTranscript((bad_transition,)), horizon()).ok


def test_cli_report_reachability_and_probe(tmp_path: Path, capsys: object) -> None:
    h_path = tmp_path / "horizon.json"
    log_path = tmp_path / "log.json"
    h_path.write_text(json_dumps(horizon().to_json()), encoding="utf-8")
    log_path.write_text(json_dumps([row.to_json() for row in source_log()]), encoding="utf-8")
    assert main(["report", str(log_path), "--horizon", str(h_path)]) == 0
    assert '"gate_bundles": 0' in capsys.readouterr().out
    assert main(["reachability", "explain", "reach-witness"]) == 0
    assert "transition" in capsys.readouterr().out
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    (probe_dir / "horizon.json").write_text(h_path.read_text(encoding="utf-8"), encoding="utf-8")
    (probe_dir / "log.json").write_text(log_path.read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["probe", "run", str(probe_dir)]) == 0
    assert '"verify-log"' in capsys.readouterr().out
    assert main(["probe", "run", str(tmp_path / "missing")]) == 1


def json_dumps(value: object) -> str:
    import json

    return json.dumps(value, sort_keys=True)
