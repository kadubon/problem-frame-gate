import json
from fractions import Fraction
from pathlib import Path

from problem_frame_gate import (
    CheckResult,
    Envelope,
    EnvelopeClass,
    FoldKernel,
    FormationProof,
    Horizon,
    RiskClaimRecord,
    RiskRouteWitness,
    check_formation,
    check_risk_claims,
    check_risk_ledger,
    check_risk_spend_live,
    digest_json,
    digest_log,
    summarize_risk_ledger,
)
from problem_frame_gate.cli import main


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


def route_witness(mode: str = "fixed") -> RiskRouteWitness:
    return RiskRouteWitness(
        accepted=True,
        checker="unit-risk-route-v1",
        transcript_digest=digest_json({"checker": "unit-risk-route-v1", "mode": mode}),
        route=mode,
    )


def sample_log() -> list[Envelope]:
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
            obligations=["human-review"],
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
    ]


def test_formation_accepts_finite_witnesses() -> None:
    horizon = Horizon.strict_default(agent_writers=("agent",))
    state = FoldKernel().fold(horizon, sample_log())
    proof = FormationProof(
        frame_id="p1",
        source_evidence=("u1",),
        goal_witnesses=("goal-text",),
        action_witnesses=("action-set",),
        acceptance_witnesses=("acceptance-set",),
        risk_witnesses=("r1",),
        obligation_witnesses=("human-review",),
        certificate_ids=("c-risk",),
    )
    result = check_formation(state, proof, at_time=6, horizon=horizon)
    assert result.ok, [issue.to_json() for issue in result.issues]


def test_formation_rejects_unwitnessed_obligation() -> None:
    horizon = Horizon.strict_default(agent_writers=("agent",))
    state = FoldKernel().fold(horizon, sample_log())
    proof = FormationProof(
        frame_id="p1",
        source_evidence=("u1",),
        goal_witnesses=("goal-text",),
        action_witnesses=("action-set",),
        acceptance_witnesses=("acceptance-set",),
        risk_witnesses=("r1",),
    )
    result = check_formation(state, proof, at_time=6, horizon=horizon)
    assert not result.ok
    assert any(issue.code == "formation-obligation" for issue in result.issues)


def test_risk_ledger_summary_and_live_spend() -> None:
    horizon = Horizon.strict_default(agent_writers=("agent",))
    state = FoldKernel().fold(horizon, sample_log())
    summary = summarize_risk_ledger(state)
    assert summary.total_spend == Fraction(1, 100)
    assert check_risk_ledger(state, alpha="1/50").ok
    assert not check_risk_ledger(state, alpha="1/200").ok
    assert check_risk_spend_live(
        state,
        risk_id="r1",
        hypothesis_id="h1",
        mode="fixed",
        cert_id="c-risk",
        at_time=6,
        horizon=horizon,
    ).ok
    assert not check_risk_spend_live(
        state,
        risk_id="r1",
        hypothesis_id="h1",
        mode="anytime",
        cert_id="c-risk",
        at_time=6,
        horizon=horizon,
    ).ok

    claims = (
        RiskClaimRecord(
            claim_id="q1",
            risk_id="r1",
            hypothesis_id="h1",
            mode="fixed",
            cert_id="c-risk",
            eta="1/100",
            event_id="F1",
            standardized_event_id="F1",
            route_witness=route_witness("fixed"),
        ),
    )
    assert check_risk_claims(state, claims, alpha="1/50", at_time=6, horizon=horizon).ok
    assert not check_risk_claims(state, claims, alpha="1/200", at_time=6, horizon=horizon).ok


def test_cli_digest_scan_verify_and_fold(tmp_path: Path, capsys: object) -> None:
    horizon = Horizon.strict_default(agent_writers=("agent",))
    log = sample_log()
    horizon_path = tmp_path / "horizon.json"
    log_path = tmp_path / "log.json"
    horizon_path.write_text(json.dumps(horizon.to_json()), encoding="utf-8")
    log_path.write_text(json.dumps([env.to_json() for env in log]), encoding="utf-8")

    assert main(["digest", str(horizon_path)]) == 0
    assert "sha256:" in capsys.readouterr().out

    assert main(["scan", str(log_path)]) == 0
    assert capsys.readouterr().out.strip() == "[]"

    assert main(["verify-log", "--horizon", str(horizon_path), str(log_path)]) == 0
    assert '"ok": true' in capsys.readouterr().out

    assert main(["fold", "--horizon", str(horizon_path), str(log_path)]) == 0
    assert digest_log(log) in capsys.readouterr().out


def test_check_result_json_for_empty_failure() -> None:
    result = CheckResult.fail()
    assert not result.ok
    assert result.to_json()["ok"] is False
