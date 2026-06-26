import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from problem_frame_gate import (
    CertificateFamily,
    CheckResult,
    DependencyRef,
    Envelope,
    EnvelopeClass,
    EnvelopeVerifier,
    ExecutorGate,
    FoldKernel,
    FoldState,
    GateBundle,
    GateRequest,
    Horizon,
    Issue,
    JoinChecker,
    JoinKey,
    JoinProposal,
    OrderEdge,
    PatchChecker,
    PatchProposal,
    ReachabilityTranscript,
    RepairWitness,
    ReplayCertificate,
    RiskClaimRecord,
    RiskMode,
    RiskRouteWitness,
    SourceCut,
    TransitionRecord,
    VersionInterval,
    WriteClass,
    WriteCover,
    canonical_order,
    check_certificate_live,
    check_reachability,
    check_replay_certificate,
    check_risk_claims,
    check_risk_ledger,
    check_risk_spend_live,
    check_source_cut,
    digest_json,
    digest_log,
    legal_log,
)
from problem_frame_gate.schema import SCHEMAS, validate_json_artifact


def env(
    eid: str,
    commit: int,
    kind: str,
    *,
    writer: str = "agent",
    **payload: object,
) -> Envelope:
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
    return Horizon.strict_default(agent_writers=("agent",), normal_capacity=200)


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


def source_log() -> list[Envelope]:
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
        env("e2", 2, "Issue", cert_id="c-risk", family="risk", issuer="agent", family_check=cert_check()),
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


def risk_claim() -> RiskClaimRecord:
    return RiskClaimRecord(
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


def gate_request(**overrides: object) -> GateRequest:
    data: dict[str, object] = {
        "gate_id": "gate1",
        "bundle_id": "bundle1",
        "frame_id": "p1",
        "action": "act",
        "outbox_id": "out1",
        "capability_id": "cap1",
        "lease_id": "lease1",
        "risk_id": "r1",
        "hypothesis_id": "h1",
        "risk_mode": "fixed",
        "risk_cert_id": "c-risk",
        "source_time": 9,
        "commit_time": 10,
        "risk_claim": risk_claim().to_json(),
        "risk_alpha": "1/50",
    }
    data.update(overrides)
    return GateRequest.from_mapping(data)


def replace_payload(envelope: Envelope, payload: Mapping[str, object]) -> Envelope:
    return Envelope(
        envelope.eid,
        envelope.event,
        envelope.slot,
        envelope.commit_time,
        envelope.writer,
        envelope.owner,
        envelope.version,
        envelope.envelope_class,
        payload,
        envelope.dependencies,
        envelope.commit_group,
    )


def replace_envelope(
    envelope: Envelope,
    *,
    slot: str | None = None,
    commit_time: int | None = None,
    payload: Mapping[str, object] | None = None,
) -> Envelope:
    return Envelope(
        envelope.eid,
        envelope.event,
        slot if slot is not None else envelope.slot,
        commit_time if commit_time is not None else envelope.commit_time,
        envelope.writer,
        envelope.owner,
        envelope.version,
        envelope.envelope_class,
        dict(payload or envelope.payload),
        envelope.dependencies,
        envelope.commit_group,
    )


def transition_from_result(
    *,
    source_digest: str,
    kind: str,
    result: CheckResult,
    witness: Mapping[str, object],
    capacity_class: str = "normal",
) -> TransitionRecord:
    assert result.digest is not None
    return TransitionRecord(
        source_digest=source_digest,
        target_digest=result.digest,
        kind=kind,
        transcript_digest=digest_json(result.to_json()),
        witness_kind=kind,
        witness_digest=digest_json(witness),
        capacity_class=capacity_class,
        witness=witness,
    )


def test_public_witness_round_trips_and_schema_kinds() -> None:
    h = horizon()
    log = source_log()
    bundle = ExecutorGate().create_bundle(h, log, gate_request())
    assert GateBundle.from_mapping(bundle.to_json()).record == bundle.record
    assert len(GateBundle.from_mapping(bundle.to_json())) == 5
    assert validate_json_artifact("gate-bundle", bundle.to_json()) == []

    assert bundle.source_cut is not None
    cut = SourceCut.from_mapping(bundle.source_cut.to_json())
    assert check_source_cut(h, tuple(log), cut).ok
    assert validate_json_artifact("source-cut", cut.to_json()) == []

    replay = ReplayCertificate.from_mapping(
        {
            "word": ["e1", "e0"],
            "swaps": [[0, "e1", "e0"]],
            "cover": {"independent_pairs": [["e0", "e1"]], "component_equalities": ["evidence"]},
            "target_digest": digest_log((log[0], log[1])),
        }
    )
    assert check_replay_certificate(h, (log[0], log[1]), replay).ok
    assert validate_json_artifact("replay-certificate", replay.to_json()) == []

    assert RiskClaimRecord.from_mapping(risk_claim().to_json()) == risk_claim()
    assert validate_json_artifact("risk-claim", risk_claim().to_json()) == []

    patch = PatchProposal.from_mapping(
        {
            "expected_source_digest": digest_log(log),
            "append": [env("e10", 10, "Evidence", evidence_id="u2").to_json()],
            "affected_invariants": ["has-u2"],
            "write_classes": [{"name": "Evidence", "object_id": "u2"}],
            "write_cover": {
                "classes": [{"name": "Evidence", "object_id": "u2"}],
                "covered_eids": ["e10"],
            },
            "read_footprints": [{"invariant": "has-u2", "entries": ["u2"]}],
            "touch_matrix": {"Evidence:u2|u2": "touch"},
            "transported_cells": [],
            "liveness_repairs": [],
            "transcript_digest": None,
        }
    )
    assert validate_json_artifact("patch-proposal", patch.to_json()) == []

    join = JoinProposal.from_mapping(
        {
            "branches": [[log[0].to_json()], [log[0].to_json(), env("j1", 1, "Evidence", evidence_id="j").to_json()]],
            "ancestor": [log[0].to_json()],
            "repairs": [],
            "escrow_conflicts": [],
            "join_keys": [],
            "repair_witnesses": [],
            "affected_invariants": [],
            "repair_rechecks": [],
            "transcript_digest": None,
        }
    )
    assert validate_json_artifact("join-proposal", join.to_json()) == []

    gate_witness = {"source": [env.to_json() for env in log], "bundle": bundle.to_json()}
    gate_replay = bundle.verify(h, log)
    reach = ReachabilityTranscript.from_mapping(
        {
            "transitions": [
                {
                    "source_digest": digest_log(log),
                    "target_digest": gate_replay.digest,
                    "kind": "gate",
                    "transcript_digest": digest_json(gate_replay.to_json()),
                    "witness_kind": "gate",
                    "witness_digest": digest_json(gate_witness),
                    "capacity_class": "normal",
                    "witness": gate_witness,
                }
            ],
            "assumptions": ["PhysicalActuator"],
        }
    )
    assert check_reachability(reach, h).ok
    assert validate_json_artifact("reachability", reach.to_json()) == []


def test_typed_reachability_replays_patch_join_and_capacity_witnesses() -> None:
    h = horizon()
    patch_source = (env("p0", 0, "Evidence", evidence_id="p0"),)
    patch_proposal = PatchProposal(
        expected_source_digest=digest_log(patch_source),
        append=(env("p1", 1, "Evidence", evidence_id="p1"),),
        write_cover=WriteCover((WriteClass("Evidence", "p1"),), ("p1",)),
    )
    patch_result = PatchChecker().check(h, patch_source, patch_proposal)
    patch_witness = {
        "source": [row.to_json() for row in patch_source],
        "proposal": patch_proposal.to_json(),
    }
    patch_transition = transition_from_result(
        source_digest=digest_log(patch_source),
        kind="patch",
        result=patch_result,
        witness=patch_witness,
    )

    ancestor = (env("a0", 0, "Evidence", evidence_id="a0"),)
    join_proposal = JoinProposal(
        branches=(ancestor, (*ancestor, env("a1", 1, "Evidence", evidence_id="a1"))),
        ancestor=ancestor,
    )
    join_result = JoinChecker().check(h, join_proposal)
    join_witness = {"proposal": join_proposal.to_json()}
    join_transition = transition_from_result(
        source_digest=patch_transition.target_digest,
        kind="join",
        result=join_result,
        witness=join_witness,
    )

    assert check_reachability(ReachabilityTranscript((patch_transition, join_transition)), h).ok

    abort_row = Envelope(
        "abort-bad",
        "abort-bad",
        "0",
        1,
        "agent",
        "agent",
        1,
        EnvelopeClass.NORMAL,
        {"kind": "Abort", "frame_id": "p1"},
    )
    abort_witness = {"source": [], "rows": [abort_row.to_json()], "assumption": "PhysicalActuator"}
    abort_result = CheckResult.success(footprint={"ReachTranscript"}, digest=digest_log((abort_row,)))
    bad_abort = transition_from_result(
        source_digest=digest_log(()),
        kind="abort",
        result=abort_result,
        witness=abort_witness,
    )
    bad_abort_result = check_reachability(ReachabilityTranscript((bad_abort,)))
    assert {"reach-capacity-class", "reach-capacity-row"} <= {issue.code for issue in bad_abort_result.issues}
    assert "PhysicalActuator" in bad_abort_result.assumptions


def test_typed_reachability_rejects_malformed_witnesses() -> None:
    h = horizon()
    source = (env("p0", 0, "Evidence", evidence_id="p0"),)
    proposal = PatchProposal(
        expected_source_digest=digest_log(source),
        append=(env("p1", 1, "Evidence", evidence_id="p1"),),
        write_cover=WriteCover((WriteClass("Evidence", "p1"),), ("p1",)),
    )
    patch_result = PatchChecker().check(h, source, proposal)
    patch_witness = {"source": [row.to_json() for row in source], "proposal": proposal.to_json()}
    patch_transition = transition_from_result(
        source_digest=digest_log(source),
        kind="patch",
        result=patch_result,
        witness=patch_witness,
    )
    no_horizon = check_reachability(ReachabilityTranscript((patch_transition,)))
    assert any(issue.code == "reach-horizon" for issue in no_horizon.issues)

    wrong_digest = TransitionRecord(
        source_digest=patch_transition.source_digest,
        target_digest=digest_json({"wrong": "target"}),
        kind="patch",
        transcript_digest=digest_json({"wrong": "transcript"}),
        witness_kind="patch",
        witness_digest=digest_json({"wrong": "witness"}),
        witness=patch_witness,
    )
    wrong_result = check_reachability(ReachabilityTranscript((wrong_digest,)), h)
    assert {"reach-witness-digest", "reach-target-digest", "reach-transcript-digest"} <= {
        issue.code for issue in wrong_result.issues
    }

    malformed_cases = [
        TransitionRecord(
            patch_transition.source_digest,
            patch_transition.target_digest,
            "patch",
            patch_transition.transcript_digest,
            "patch",
            digest_json({"source": "bad", "proposal": proposal.to_json()}),
            witness={"source": "bad", "proposal": proposal.to_json()},
        ),
        TransitionRecord(
            patch_transition.source_digest,
            patch_transition.target_digest,
            "patch",
            patch_transition.transcript_digest,
            "patch",
            digest_json({"source": [], "proposal": []}),
            witness={"source": [], "proposal": []},
        ),
        TransitionRecord(
            digest_log(()),
            digest_log(()),
            "join",
            digest_json({"bad": "join"}),
            "join",
            digest_json({"proposal": []}),
            witness={"proposal": []},
        ),
        TransitionRecord(
            digest_log(()),
            digest_log(()),
            "gate",
            digest_json({"bad": "gate"}),
            "gate",
            digest_json({"source": [], "bundle": []}),
            witness={"source": [], "bundle": []},
        ),
        TransitionRecord(
            digest_log(()),
            digest_log(()),
            "abort",
            digest_json({"bad": "abort"}),
            "abort",
            digest_json({"source": [], "rows": [None]}),
            capacity_class="abort",
            witness={"source": [], "rows": [None]},
        ),
    ]
    codes = {
        issue.code
        for transition in malformed_cases
        for issue in check_reachability(ReachabilityTranscript((transition,)), h).issues
    }
    assert {"reach-witness-envelopes", "reach-patch-witness", "reach-join-witness", "reach-gate-witness"} <= codes


def test_semantic_gate_replay_rejects_forged_gatecheck() -> None:
    h = horizon()
    log = source_log()
    bundle = ExecutorGate().create_bundle(h, log, gate_request())

    bad_prefix = (Envelope("bad", "bad", "0", 0, "agent", "agent", 1, EnvelopeClass.NORMAL, {}),)
    folded_bad = ExecutorGate().check(h, bad_prefix, gate_request(source_time=0, commit_time=1))
    assert any(issue.code == "gate-source-fold" for issue in folded_bad.issues)

    frame_only = log[:4]
    missing_authority = ExecutorGate().check(h, frame_only, gate_request(source_time=3, commit_time=4, action="other"))
    assert {"gate-action-not-allowed", "gate-capability-missing", "gate-resource-missing", "gate-outbox-missing"} <= {
        issue.code for issue in missing_authority.issues
    }

    malformed_request = GateRequest(**{**gate_request().to_json(), "risk_claim": []})
    malformed_claim = ExecutorGate().check(h, log, malformed_request)
    assert any(issue.code == "gate-risk-claim" for issue in malformed_claim.issues)

    incoherent_claim = risk_claim().to_json()
    incoherent_claim["cert_id"] = "other"
    incoherent = ExecutorGate().check(h, log, gate_request(risk_claim=incoherent_claim))
    assert any(issue.code == "gate-risk-claim-coherence" for issue in incoherent.issues)

    tampered = list(bundle.envelopes)
    gate = tampered[0]
    payload = dict(gate.payload)
    request = dict(payload["request"])
    request["risk_claim"] = None
    payload["request"] = request
    tampered[0] = replace_payload(gate, payload)
    result = FoldKernel().check_fold(h, [*log, *tampered])
    codes = {issue.code for issue in result.issues}
    assert {"gate-semantic-gate-risk-claim-missing", "gate-semantic-transcript"} <= codes

    tampered_cut = list(bundle.envelopes)
    gate = tampered_cut[0]
    payload = dict(gate.payload)
    source_cut = dict(payload["source_cut"])
    source_cut["clock_rows"] = []
    source_cut["watermark_rows"] = []
    payload["source_cut"] = source_cut
    tampered_cut[0] = replace_payload(gate, payload)
    cut_result = FoldKernel().check_fold(h, [*log, *tampered_cut])
    assert {"gate-source-cut-clock", "gate-source-cut-watermark"} <= {issue.code for issue in cut_result.issues}


def test_registry_checkers_and_assumption_failures_are_enforced() -> None:
    h = horizon()
    state = FoldKernel().fold(h, source_log())

    def cert_checker(
        _certificate: Mapping[str, object],
        _state: object,
        _at_time: int,
        _horizon: object,
    ) -> CheckResult:
        return CheckResult.fail(Issue("cert-registry-fail", "certificate checker rejected"))

    cert_result = check_certificate_live(
        state,
        "c-risk",
        9,
        horizon=h,
        registry={"risk": CertificateFamily("risk", ("agent",), checker=cert_checker)},
    )
    assert not cert_result.ok
    assert CertificateFamily("risk", ("agent",), checker=cert_checker).to_json()["checker"] == "cert_checker"
    assumed_family = CertificateFamily("risk", ("agent",), assumption="CertificateFamilyChecker").check(
        state.component("certificates")["c-risk"], state, 9, h
    )
    assert assumed_family.ok

    undeclared_family = CertificateFamily("risk", ("agent",), assumption="Undeclared").check(
        state.component("certificates")["c-risk"], state, 9, h
    )
    assert any(issue.code == "certificate-family-registry-checker" for issue in undeclared_family.issues)

    def risk_checker(
        _record: RiskClaimRecord,
        _state: object,
        _at_time: int,
        _horizon: Horizon,
    ) -> CheckResult:
        return CheckResult.fail(Issue("risk-registry-fail", "risk checker rejected"))

    risk_result = check_risk_claims(
        state,
        (risk_claim(),),
        alpha="1/50",
        at_time=9,
        horizon=h,
        registry={"fixed": RiskMode("fixed", checker=risk_checker)},
    )
    assert not risk_result.ok
    assumed_mode = RiskMode("fixed", assumption="StatisticalModel")
    assert assumed_mode.to_json()["assumption"] == "StatisticalModel"
    assert assumed_mode.check(risk_claim(), state, 9, h).ok

    undeclared_mode = RiskMode("fixed", assumption="Undeclared").check(risk_claim(), state, 9, h)
    assert any(issue.code == "risk-mode-registry-checker" for issue in undeclared_mode.issues)

    orphan_risk = FoldState(
        {
            "risk": {
                "reserves": {"negative": {"reserved_at": 0}},
                "spends": {
                    "orphan": {"eta": "1/100", "spent_at": 1},
                    "negative": {"eta": "-1/100", "spent_at": 1},
                },
            }
        },
        (),
        "sha256:test",
    )
    ledger_result = check_risk_ledger(orphan_risk)
    assert {"risk-spend-without-reserve", "negative-risk-spend"} <= {issue.code for issue in ledger_result.issues}
    bad_fraction_state = FoldState(
        {
            "risk": {
                "reserves": {"bad": {"reserved_at": 0}},
                "spends": {"bad": {"eta": "bad", "spent_at": 1}},
            }
        },
        (),
        "sha256:test",
    )
    bad_fraction_ledger = check_risk_ledger(bad_fraction_state, alpha="bad")
    assert {"risk-spend-eta", "risk-alpha-format"} <= {issue.code for issue in bad_fraction_ledger.issues}
    bad_fraction_claim = RiskClaimRecord.from_mapping({**risk_claim().to_json(), "eta": "bad"})
    bad_claim_result = check_risk_claims(state, (bad_fraction_claim,), alpha="bad", at_time=9, horizon=h)
    assert {"risk-claim-eta", "risk-alpha-format"} <= {issue.code for issue in bad_claim_result.issues}
    with pytest.raises(TypeError, match="risk_claim"):
        GateRequest.from_mapping({**gate_request().to_json(), "risk_claim": []})
    assert any(
        issue.code == "risk-mode-undeclared"
        for issue in check_risk_spend_live(
            state,
            risk_id="r1",
            hypothesis_id="h1",
            mode="fixed",
            cert_id="c-risk",
            at_time=9,
            horizon=Horizon.from_mapping({**h.to_json(), "risk_modes": ["anytime"]}),
        ).issues
    )


def test_patch_join_schema_and_mapping_failure_edges() -> None:
    source = (env("cap", 0, "MintCap", capability_id="cap1"),)
    patch = PatchProposal(
        expected_source_digest=digest_log(source),
        append=(env("use", 1, "UseCap", capability_id="cap1"),),
        write_classes=(WriteClass("Capability", "cap1"),),
        write_cover=WriteCover((WriteClass("Capability", "cap1"),), ("other",)),
        transported_cells=(),
    )
    result = PatchChecker().check(Horizon.unsafe_for_tests(), source, patch)
    assert {"patch-write-cover", "patch-transported-cell"} <= {issue.code for issue in result.issues}

    with pytest.raises(TypeError, match="touch_matrix"):
        PatchProposal.from_mapping({"expected_source_digest": "d", "append": [], "touch_matrix": []})

    bad_source = (Envelope("bad", "bad", "0", 0, "agent", "agent", 1, EnvelopeClass.NORMAL, {}),)
    source_fold = PatchChecker().check(
        Horizon.unsafe_for_tests(),
        bad_source,
        PatchProposal(expected_source_digest=digest_log(bad_source), append=()),
    )
    assert any(issue.code == "patch-source-fold" for issue in source_fold.issues)

    ancestor = (env("a", 0, "Evidence", evidence_id="a"),)
    branch_a = (*ancestor, env("ra", 1, "RiskReserve", risk_id="r", hypothesis_id="h", eta="1/100"))
    branch_b = (*ancestor, env("rb", 1, "RiskReserve", risk_id="r", hypothesis_id="h", eta="1/100"))
    join = JoinProposal(
        branches=(branch_a, branch_b),
        ancestor=ancestor,
        escrow_conflicts=("risk:r",),
        join_keys=(JoinKey("risk:r", ("wrong",)),),
        repair_witnesses=(RepairWitness("repair", "risk:r", False, "not-a-digest"),),
    )
    join_result = JoinChecker().check(Horizon.unsafe_for_tests(), join)
    assert {"join-key-mismatch", "join-liveness-repair"} <= {issue.code for issue in join_result.issues}

    with pytest.raises(TypeError):
        JoinProposal.from_mapping({"branches": "bad"})


def test_verifier_manifest_commit_group_and_gate_bundle_edges() -> None:
    h = horizon()
    verifier = EnvelopeVerifier()
    assert verifier.canonical_order(h, ()) == ()
    assert canonical_order(h, ()) == ()
    assert legal_log(h, ()).ok

    h_bad_manifest = Horizon.from_mapping(
        {
            **h.to_json(),
            "events": ["dup", "dup"],
            "protected_constructors": {**h.to_json()["protected_constructors"], "GateCheck": ["agent"]},
        }
    )
    manifest_codes = {issue.code for issue in verifier.verify(h_bad_manifest, ()).issues}
    assert {"duplicate-events", "protected-constructor-policy"} <= manifest_codes

    downset_horizon = Horizon.from_mapping(
        {**h.to_json(), "events": ["before", "after"], "audit_order": [OrderEdge("before", "after").to_json()]}
    )
    after = Envelope("after", "after", "0", 0, "agent", "agent", 1, EnvelopeClass.NORMAL, {"kind": "Evidence"})
    assert any(issue.code == "downset-violation" for issue in verifier.verify(downset_horizon, (after,)).issues)

    duplicate_slot_log = (
        env("", 0, "Evidence", evidence_id="empty"),
        Envelope(
            "d1", "same", "0", 1, "agent", "agent", 1, EnvelopeClass.NORMAL, {"kind": "Evidence", "evidence_id": "x"}
        ),
        Envelope(
            "d2", "same", "0", 2, "agent", "agent", 1, EnvelopeClass.NORMAL, {"kind": "Evidence", "evidence_id": "x"}
        ),
    )
    slot_codes = {issue.code for issue in verifier.verify(h, duplicate_slot_log).issues}
    assert {"empty-eid", "duplicate-protected-slot"} <= slot_codes

    dependency_log = (
        Envelope(
            "dep",
            "dep",
            "0",
            0,
            "agent",
            "agent",
            1,
            EnvelopeClass.NORMAL,
            {"kind": "Evidence", "evidence_id": "dep"},
            dependencies=(DependencyRef(event="missing", slot="0"),),
        ),
    )
    assert any(issue.code == "missing-dependency" for issue in verifier.verify(h, dependency_log).issues)
    root = Envelope(
        "root",
        "root",
        "0",
        0,
        "agent",
        "agent",
        1,
        EnvelopeClass.NORMAL,
        {"kind": "Evidence", "evidence_id": "root"},
    )
    child = Envelope(
        "child",
        "child",
        "0",
        1,
        "agent",
        "agent",
        1,
        EnvelopeClass.NORMAL,
        {"kind": "Evidence", "evidence_id": "child"},
        dependencies=(DependencyRef(event="root", slot="0"),),
    )
    assert verifier.verify(h, (root, child)).ok

    group_horizon = Horizon.from_mapping({**h.to_json(), "commit_groups": {"g": ["a", "b"]}})
    grouped_a = Envelope(
        "a",
        "a",
        "0",
        0,
        "agent",
        "agent",
        1,
        EnvelopeClass.NORMAL,
        {"kind": "Evidence", "evidence_id": "a"},
        commit_group="g",
    )
    grouped_b = Envelope(
        "b",
        "b",
        "0",
        1,
        "agent",
        "agent",
        1,
        EnvelopeClass.NORMAL,
        {"kind": "Evidence", "evidence_id": "b"},
        commit_group="g",
    )
    assert [env.eid for env in verifier.canonical_order(group_horizon, (grouped_a, grouped_b))] == ["a", "b"]
    group_codes = {
        issue.code
        for issue in verifier.verify(
            group_horizon,
            (
                env("a", 0, "Evidence", evidence_id="a", writer="agent"),
                Envelope(
                    "x",
                    "x",
                    "0",
                    1,
                    "agent",
                    "agent",
                    1,
                    EnvelopeClass.NORMAL,
                    {"kind": "Evidence", "evidence_id": "x"},
                    commit_group="unknown",
                ),
            ),
        ).issues
    }
    assert {"unknown-commit-group"} <= group_codes
    partial = Envelope(
        "a",
        "a",
        "0",
        0,
        "agent",
        "agent",
        1,
        EnvelopeClass.NORMAL,
        {"kind": "Evidence", "evidence_id": "a"},
        commit_group="g",
    )
    assert any(issue.code == "partial-commit-group" for issue in verifier.verify(group_horizon, (partial,)).issues)

    writer_horizon = Horizon(strict=False, writer_authority={"Frame": ("agent",)})
    writer_result = verifier.verify(writer_horizon, (env("e", 0, "Evidence", evidence_id="e"),))
    writer_codes = {issue.code for issue in writer_result.issues}
    assert "unknown-writer-family" in writer_codes

    version_horizon = Horizon(strict=False, version_intervals={"Evidence": VersionInterval(2, 3)})
    version_result = verifier.verify(version_horizon, (env("e", 0, "Evidence", evidence_id="e"),))
    version_codes = {issue.code for issue in version_result.issues}
    assert "version-out-of-range" in version_codes

    bundle = list(ExecutorGate().create_bundle(h, source_log(), gate_request()).envelopes)
    duplicate_kind = list(bundle)
    duplicate_kind[2] = replace_payload(duplicate_kind[2], {"kind": "OutboxClaim", "outbox_id": "out1"})
    duplicate_codes = {issue.code for issue in verifier.verify(h, [*source_log(), *duplicate_kind]).issues}
    assert {"gate-bundle-duplicate-kind", "gate-bundle-missing-kind"} <= duplicate_codes

    bad_time = list(bundle)
    bad_time[4] = replace_envelope(bad_time[4], commit_time=11)
    bad_time_result = verifier.verify(h, [*source_log(), *bad_time])
    assert any(issue.code == "gate-bundle-commit-time" for issue in bad_time_result.issues)

    close_before = list(bundle)
    close_before[4] = replace_envelope(close_before[4], commit_time=9)
    close_before_result = verifier.verify(h, [*source_log(), *close_before])
    assert any(issue.code == "gate-bundle-risk-close-order" for issue in close_before_result.issues)

    interleaved_codes = {
        issue.code
        for issue in verifier.verify(
            h, [*source_log(), *bundle, env("inter", 10, "Evidence", evidence_id="inter")]
        ).issues
    }
    assert "gate-bundle-interleaving" in interleaved_codes

    bad_order = list(bundle)
    bad_order[0] = replace_envelope(bad_order[0], slot="x")
    assert any(issue.code == "gate-bundle-order" for issue in verifier.verify(h, [*source_log(), *bad_order]).issues)

    malformed_gate = list(bundle)
    gate_payload = dict(malformed_gate[0].payload)
    gate_payload["request"] = "bad"
    malformed_gate[0] = replace_payload(malformed_gate[0], gate_payload)
    malformed_gate_result = verifier.verify(h, [*source_log(), *malformed_gate])
    assert any(issue.code == "gate-bundle-request" for issue in malformed_gate_result.issues)

    missing_record = list(bundle)
    gate_payload = dict(missing_record[0].payload)
    del gate_payload["gate_record"]
    missing_record[0] = replace_payload(missing_record[0], gate_payload)
    missing_record_result = verifier.verify(h, [*source_log(), *missing_record])
    assert any(issue.code == "gate-record-missing" for issue in missing_record_result.issues)

    missing_cut = list(bundle)
    gate_payload = dict(missing_cut[0].payload)
    del gate_payload["source_cut"]
    missing_cut[0] = replace_payload(missing_cut[0], gate_payload)
    missing_cut_result = verifier.verify(h, [*source_log(), *missing_cut])
    assert any(issue.code == "gate-source-cut-missing" for issue in missing_cut_result.issues)

    incoherent_gate = list(bundle)
    gate_payload = dict(incoherent_gate[0].payload)
    gate_payload["bundle_id"] = "wrong"
    gate_payload["gate_id"] = "wrong"
    gate_payload["frame_id"] = "wrong"
    incoherent_gate[0] = replace_payload(incoherent_gate[0], gate_payload)
    incoherent_codes = {issue.code for issue in verifier.verify(h, [*source_log(), *incoherent_gate]).issues}
    assert {"gate-bundle-id", "gate-record-coherence"} <= incoherent_codes

    bad_cut = list(bundle)
    gate_payload = dict(bad_cut[0].payload)
    source_cut = dict(gate_payload["source_cut"])
    source_cut["included_eids"] = "bad"
    source_cut["digest"] = "sha256:wrong"
    gate_payload["source_cut"] = source_cut
    bad_cut[0] = replace_payload(bad_cut[0], gate_payload)
    bad_cut_codes = {issue.code for issue in verifier.verify(h, [*source_log(), *bad_cut]).issues}
    assert {"gate-source-cut-included", "gate-source-cut-digest"} <= bad_cut_codes

    bad_source_time = list(bundle)
    gate_payload = dict(bad_source_time[0].payload)
    request = dict(gate_payload["request"])
    request["source_time"] = "bad"
    gate_payload["request"] = request
    bad_source_time[0] = replace_payload(bad_source_time[0], gate_payload)
    source_time_codes = {issue.code for issue in verifier.verify(h, [*source_log(), *bad_source_time]).issues}
    assert {"gate-source-cut", "gate-semantic-request"} <= source_time_codes

    bad_record = list(bundle)
    gate_payload = dict(bad_record[0].payload)
    gate_record = dict(gate_payload["gate_record"])
    gate_record["source_digest"] = "sha256:wrong"
    gate_record["transcript_digest"] = "not-a-digest"
    gate_payload["gate_record"] = gate_record
    gate_payload["gate_record_digest"] = "sha256:wrong"
    bad_record[0] = replace_payload(bad_record[0], gate_payload)
    record_codes = {issue.code for issue in verifier.verify(h, [*source_log(), *bad_record]).issues}
    assert {"gate-record-source-digest", "gate-record-transcript", "gate-record-digest"} <= record_codes


def test_schema_validator_rejects_public_artifact_shapes() -> None:
    assert validate_json_artifact("missing-kind", {}) == ["unknown schema kind: missing-kind"]
    assert "$.risk_claim.route_witness.accepted: expected constant True" in validate_json_artifact(
        "gate-request",
        {**gate_request().to_json(), "risk_claim": {**risk_claim().to_json(), "route_witness": {"accepted": False}}},
    )
    assert validate_json_artifact("risk-claim", {**risk_claim().to_json(), "mode": "bad"}) == [
        "$.mode: expected one of ['fixed', 'selectedEvent', 'conditionalSelective', 'anytime']"
    ]
    horizon_json = horizon().to_json()
    horizon_json["capacities"]["normal"] = -1
    assert "$.capacities.normal: value is smaller than 0" in validate_json_artifact("horizon", horizon_json)
    assert "$[0].dependencies[0]: value does not match any allowed shape" in validate_json_artifact(
        "log",
        [{**source_log()[0].to_json(), "dependencies": [123]}],
    )
    gate_bundle_errors = validate_json_artifact("gate-bundle", {"record": {}, "envelopes": [], "source_cut": {}})
    assert "$.envelopes: array has fewer than 5 items" in gate_bundle_errors
    patch_errors = validate_json_artifact(
        "patch-proposal",
        {
            "expected_source_digest": "sha256:x",
            "append": [],
            "write_cover": {"classes": [], "covered_eids": []},
            "touch_matrix": {"cell": 1},
        },
    )
    assert "$.touch_matrix.cell: expected type string" in patch_errors
    assert any(
        "pattern" in error
        for error in validate_json_artifact("risk-claim", {**risk_claim().to_json(), "eta": "not-a-fraction"})
    )
    bad_reachability = {
        "transitions": [
            {
                "source_digest": digest_json({"s": 1}),
                "target_digest": digest_json({"s": 2}),
                "kind": "gate",
                "transcript_digest": digest_json({"t": 1}),
                "witness_kind": "gate",
                "witness_digest": digest_json({"w": 1}),
                "capacity_class": "normal",
            }
        ],
        "assumptions": [],
    }
    assert "$.transitions[0]: missing witness" in validate_json_artifact("reachability", bad_reachability)


def test_public_schema_files_track_internal_schema_contracts() -> None:
    schema_files = {
        "horizon": "horizon.schema.json",
        "log": "envelope-log.schema.json",
        "gate-request": "gate-request.schema.json",
        "gate-bundle": "gate-bundle.schema.json",
        "source-cut": "source-cut.schema.json",
        "replay-certificate": "replay-certificate.schema.json",
        "risk-claim": "risk-claim.schema.json",
        "patch-proposal": "patch-proposal.schema.json",
        "join-proposal": "join-proposal.schema.json",
        "reachability": "reachability.schema.json",
    }
    assert set(schema_files) == set(SCHEMAS)
    for kind, filename in schema_files.items():
        public_schema = json.loads(Path("schemas", filename).read_text(encoding="utf-8"))
        internal_schema = SCHEMAS[kind]
        assert _required_fields(public_schema, kind) >= _required_fields(internal_schema, kind)
        assert _pattern_count(public_schema) >= _pattern_count(internal_schema)


def _required_fields(schema: Mapping[str, object], kind: str) -> set[str]:
    if kind == "log":
        items = schema.get("items")
        assert isinstance(items, Mapping)
        required = items.get("required", ())
    else:
        required = schema.get("required", ())
    assert isinstance(required, list)
    return {str(item) for item in required}


def _pattern_count(value: object) -> int:
    if isinstance(value, Mapping):
        return int("pattern" in value) + sum(_pattern_count(item) for item in value.values())
    if isinstance(value, list):
        return sum(_pattern_count(item) for item in value)
    return 0


def test_from_mapping_type_guards() -> None:
    with pytest.raises(TypeError):
        GateBundle.from_mapping({"record": [], "envelopes": []})
    with pytest.raises(TypeError):
        ReplayCertificate.from_mapping({"word": [], "swaps": [[0, "a"]], "cover": {}, "target_digest": "d"})
    with pytest.raises(TypeError):
        ReachabilityTranscript.from_mapping({"transitions": [None]})
    assert json.loads(json.dumps(gate_request().to_json()))["risk_alpha"] == "1/50"
