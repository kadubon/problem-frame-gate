from problem_frame_gate import Envelope, EnvelopeClass, EnvelopeVerifier, Horizon, OrderEdge


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


def test_verifier_accepts_legal_log() -> None:
    horizon = Horizon.from_mapping(
        {
            "events": ["e0", "e1"],
            "audit_order": [OrderEdge("e0", "e1").to_json()],
            "capacities": {"normal": 2},
            "writer_authority": {"*": ["agent"]},
            "version_intervals": {"*": [1, 1]},
            "protected_constructors": {
                "GateCheck": ["executor-gate"],
                "OutboxClaim": ["executor-gate"],
                "UseCap": ["executor-gate"],
                "ConsumeResource": ["executor-gate"],
                "RiskClose": ["executor-gate"],
            },
            "certificate_families": {"risk": ["agent"]},
            "risk_modes": ["fixed", "selectedEvent", "conditionalSelective", "anytime"],
        }
    )
    result = EnvelopeVerifier().verify(
        horizon,
        [
            env("e0", 0, "Evidence", evidence_id="u1"),
            env("e1", 1, "Issue", cert_id="c1", dependencies=["u1"]),
        ],
    )
    assert result.ok


def test_verifier_rejects_writer_without_authority() -> None:
    horizon = Horizon(strict=False, writer_authority={"Issue": ("issuer",)})
    result = EnvelopeVerifier().verify(
        horizon,
        [env("e0", 0, "Issue", cert_id="c1")],
    )
    assert not result.ok
    assert any(issue.code == "writer-authority" for issue in result.issues)


def test_verifier_rejects_capacity_overflow() -> None:
    horizon = Horizon(strict=False, capacities={EnvelopeClass.NORMAL: 1})
    result = EnvelopeVerifier().verify(
        horizon,
        [env("e0", 0, "Evidence", evidence_id="u1"), env("e1", 1, "Evidence", evidence_id="u2")],
    )
    assert not result.ok
    assert any(issue.code == "capacity-exceeded" for issue in result.issues)
