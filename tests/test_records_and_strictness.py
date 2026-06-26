import json
from pathlib import Path

from problem_frame_gate import (
    CheckResult,
    Envelope,
    EnvelopeClass,
    ExecutorGate,
    GateRequest,
    Horizon,
    JoinProposal,
    PatchChecker,
    PatchProposal,
    ReachabilityTranscript,
    ReadFootprint,
    ReplayCertificate,
    RiskClaimRecord,
    RiskRouteWitness,
    SourceCut,
    SwapCover,
    TouchMatrix,
    TransitionRecord,
    WriteClass,
    WriteCover,
    check_reachability,
    check_replay_certificate,
    check_source_cut,
    digest_json,
    digest_log,
)
from problem_frame_gate.certificates import check_certificate_live
from problem_frame_gate.cli import main
from problem_frame_gate.fold import FoldKernel
from problem_frame_gate.join import JoinChecker, union_join


def env(eid: str, commit: int, kind: str, writer: str = "agent", **payload: object) -> Envelope:
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


def cert_check(
    *, dependencies: tuple[str, ...] = (), source_ids: tuple[str, ...] = (), checked_at: int = 2
) -> dict[str, object]:
    return {
        "accepted": True,
        "checker": "unit-certificate-family-v1",
        "transcript_digest": digest_json({"checker": "unit-certificate-family-v1", "accepted": True}),
        "dependency_digest": digest_json({"dependencies": sorted(dependencies), "source_ids": sorted(source_ids)}),
        "revocation_frontier": [],
        "checked_at": checked_at,
        "assumption": "CertificateFamilyChecker",
    }


def base_log() -> list[Envelope]:
    return [
        env(
            "e0",
            0,
            "Frame",
            frame_id="p1",
            scope="demo",
            goal="g",
            evidence_ids=["u1"],
            actions=["act"],
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
            family_check=cert_check(dependencies=("e1",), source_ids=("u1",)),
            source_ids=["u1"],
            dependencies=["e1"],
            assumption="StatisticalModel",
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
        env("e8", 8, "MintCap", capability_id="cap1", frame_id="p1", action="act"),
        env("e9", 9, "AuthorizeOutbox", outbox_id="out1", frame_id="p1", action="act"),
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
        action="act",
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


def test_empty_horizon_is_rejected() -> None:
    result = FoldKernel().check_fold(Horizon(), base_log())
    assert not result.ok
    assert any(issue.code == "incomplete-manifest" for issue in result.issues)


def test_gate_bundle_coherence_rejects_tampering() -> None:
    bundle = ExecutorGate().create_bundle(horizon(), base_log(), gate_request())
    tampered = list(bundle.envelopes)
    claim = tampered[1]
    tampered[1] = Envelope(
        claim.eid,
        claim.event,
        claim.slot,
        claim.commit_time,
        claim.writer,
        claim.owner,
        claim.version,
        claim.envelope_class,
        {**claim.payload, "outbox_id": "other"},
        commit_group=claim.commit_group,
    )
    result = FoldKernel().check_fold(horizon(), [*base_log(), *tampered])
    assert not result.ok
    assert any(issue.code == "gate-bundle-coherence" for issue in result.issues)


def test_replay_certificate_accepts_and_rejects_swap_traces() -> None:
    log = (env("a", 0, "Evidence", evidence_id="a"), env("b", 1, "Evidence", evidence_id="b"))
    h = Horizon.strict_default(agent_writers=("agent",))
    cert = ReplayCertificate(
        word=("b", "a"),
        swaps=((0, "b", "a"),),
        cover=SwapCover(independent_pairs=(("a", "b"),), component_equalities=("evidence",)),
        target_digest=digest_log(log),
    )
    assert check_replay_certificate(h, log, cert).ok
    bad = ReplayCertificate(
        word=("b", "a"),
        swaps=((0, "b", "a"),),
        cover=SwapCover(),
        target_digest=digest_log(log),
    )
    assert not check_replay_certificate(h, log, bad).ok


def test_source_cut_checks_frontier_and_digest() -> None:
    log = tuple(base_log())
    included = tuple(env.eid for env in log if env.commit_time <= 5)
    frontier = tuple(env.eid for env in log if env.commit_time > 5)
    cut_digest = digest_log(tuple(env for env in log if env.commit_time <= 5))
    cut = SourceCut(
        "cut1",
        5,
        included,
        frontier,
        cut_digest,
        clock_rows=("source_time:5",),
        watermark_rows=(f"source_digest:{cut_digest}",),
    )
    assert check_source_cut(horizon(), log, cut).ok
    bad = SourceCut("cut1", 5, included[:-1], frontier, cut.digest)
    assert not check_source_cut(horizon(), log, bad).ok


def test_reachability_chain_checks_digest_links() -> None:
    abort_row = Envelope(
        "abort1",
        "abort1",
        "0",
        1,
        "agent",
        "agent",
        1,
        EnvelopeClass.ABORT,
        {"kind": "Abort", "frame_id": "p1"},
    )
    abort_witness = {"source": [], "rows": [abort_row.to_json()]}
    abort_target = digest_log((abort_row,))
    abort_result = CheckResult.success(footprint={"ReachTranscript"}, digest=abort_target)
    fail_row = Envelope(
        "fail1",
        "fail1",
        "0",
        2,
        "agent",
        "agent",
        1,
        EnvelopeClass.FAIL_CLOSED,
        {"kind": "FailClosed", "frame_id": "p1"},
    )
    fail_witness = {"source": [abort_row.to_json()], "rows": [fail_row.to_json()]}
    fail_target = digest_log((abort_row, fail_row))
    fail_result = CheckResult.success(footprint={"ReachTranscript"}, digest=fail_target)
    good = ReachabilityTranscript(
        (
            TransitionRecord(
                digest_log(()),
                abort_target,
                "abort",
                digest_json(abort_result.to_json()),
                witness_kind="abort",
                witness_digest=digest_json(abort_witness),
                capacity_class="abort",
                witness=abort_witness,
            ),
            TransitionRecord(
                abort_target,
                fail_target,
                "failClosed",
                digest_json(fail_result.to_json()),
                witness_kind="failClosed",
                witness_digest=digest_json(fail_witness),
                capacity_class="failClosed",
                witness=fail_witness,
            ),
        ),
        assumptions=("PhysicalActuator",),
    )
    result = check_reachability(good)
    assert result.ok
    assert result.assumptions == ("PhysicalActuator",)
    bad = ReachabilityTranscript(
        (
            TransitionRecord("g0", "g1", "patch", "t1"),
            TransitionRecord("wrong", "g2", "gate", "t2"),
        )
    )
    assert not check_reachability(bad).ok


def test_certificate_liveness_rejects_bad_family_issuer_expiry_and_dependency() -> None:
    h = horizon()
    state = FoldKernel().fold(h, base_log())
    live = check_certificate_live(state, "c-risk", 6, horizon=h)
    assert live.ok
    assert live.assumptions == ("CertificateFamilyChecker", "StatisticalModel")

    bad_log = [
        env("e1", 1, "Evidence", evidence_id="u1"),
        env(
            "e2",
            2,
            "Issue",
            cert_id="c-risk",
            family="risk",
            issuer="mallory",
            expires_at=3,
            family_check=False,
            dependencies=["missing"],
        ),
    ]
    bad_state = FoldKernel().fold(Horizon.unsafe_for_tests(), bad_log)
    result = check_certificate_live(bad_state, "c-risk", 6, horizon=h)
    codes = {issue.code for issue in result.issues}
    assert {"certificate-expired", "certificate-issuer", "certificate-family-check", "certificate-dependency"} <= codes


def test_patch_touch_matrix_and_frame_invalidation_repairs() -> None:
    log = base_log()
    proposal = PatchProposal(
        expected_source_digest=digest_log(log),
        append=(
            env("e10", 10, "RevokeCap", capability_id="cap1"),
            env("e11", 11, "RevokeOutbox", outbox_id="out1"),
            env("e12", 12, "ReleaseResource", lease_id="lease1"),
            env("e13", 13, "Suspended", frame_id="p1"),
        ),
        affected_invariants=("status",),
        write_classes=(
            WriteClass("Capability", "cap1"),
            WriteClass("Outbox", "out1"),
            WriteClass("Resource", "lease1"),
            WriteClass("FrameStatus", "p1"),
        ),
        write_cover=WriteCover(
            (
                WriteClass("Capability", "cap1"),
                WriteClass("Outbox", "out1"),
                WriteClass("Resource", "lease1"),
                WriteClass("FrameStatus", "p1"),
            ),
            ("e10", "e11", "e12", "e13"),
        ),
        read_footprints=(ReadFootprint("status", ("frame:p1",)),),
        touch_matrix=TouchMatrix(
            {
                "Capability:cap1|frame:p1": "non_touch",
                "Outbox:out1|frame:p1": "non_touch",
                "Resource:lease1|frame:p1": "non_touch",
                "FrameStatus:p1|frame:p1": "touch",
            }
        ),
        liveness_repairs=("capability:cap1", "outbox:out1", "resource:lease1", "risk:r1"),
    )
    assert PatchChecker().check(horizon(), log, proposal, invariants={"status": lambda *_: digest_ok()}).ok


def digest_ok() -> CheckResult:
    return CheckResult.success(digest=digest_json({"ok": True}))


def test_join_valid_requires_ancestor_and_rechecks() -> None:
    log = base_log()
    branch_a = [*log, env("a10", 10, "Evidence", evidence_id="ua")]
    branch_b = [*log, env("b10", 11, "Evidence", evidence_id="ub")]
    result = JoinChecker().check(
        horizon(),
        JoinProposal(
            branches=(tuple(branch_a), tuple(branch_b)),
            ancestor=tuple(log),
            affected_invariants=("evidence",),
            repair_rechecks=("evidence",),
        ),
    )
    assert result.ok
    assert not union_join(horizon(), (branch_a, branch_b)).ok


def test_cli_new_commands(tmp_path: Path, capsys: object) -> None:
    horizon_path = tmp_path / "horizon.json"
    log_path = tmp_path / "log.json"
    request_path = tmp_path / "request.json"
    horizon_path.write_text(json.dumps(horizon().to_json()), encoding="utf-8")
    log_path.write_text(json.dumps([env.to_json() for env in base_log()]), encoding="utf-8")
    request_path.write_text(json.dumps(gate_request().to_json()), encoding="utf-8")

    assert main(["init-manifest"]) == 0
    assert '"strict": true' in capsys.readouterr().out
    assert main(["validate-schema", "horizon", str(horizon_path)]) == 0
    assert main(["validate-schema", "log", str(log_path)]) == 0
    assert main(["validate-schema", "gate-request", str(request_path)]) == 0
    assert main(["check-gate", "--horizon", str(horizon_path), "--bundle", str(request_path), str(log_path)]) == 0
    assert '"GateCheck"' in capsys.readouterr().out
    assert main(["explain", "gate-bundle-coherence"]) == 0
    assert "GateCheck" in capsys.readouterr().out

    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{}", encoding="utf-8")
    assert main(["validate-schema", "gate-request", str(bad_path)]) == 1
    bad_request_path = tmp_path / "bad-request.json"
    bad_request_path.write_text(json.dumps({**gate_request().to_json(), "risk_claim": []}), encoding="utf-8")
    assert main(["check-gate", "--horizon", str(horizon_path), str(bad_request_path), str(log_path)]) == 1
    assert "gate request is malformed" in capsys.readouterr().out
