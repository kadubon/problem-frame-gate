from __future__ import annotations

import json
import math
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

import pytest

from problem_frame_gate import (
    AffectedClauseSet,
    AuditTranscript,
    CertificateFamily,
    CheckResult,
    DependencyRef,
    Envelope,
    EnvelopeClass,
    EnvelopeVerifier,
    ExecutorGate,
    FormationProof,
    GateRequest,
    Horizon,
    Issue,
    JoinChecker,
    JoinProposal,
    OrderEdge,
    PatchChecker,
    PatchProposal,
    ReachabilityTranscript,
    ReadFootprint,
    ReplayCertificate,
    RiskClaimRecord,
    SourceCut,
    StrictManifest,
    SwapCover,
    TouchMatrix,
    TransitionRecord,
    VersionInterval,
    WriteClass,
    canonical_json_bytes,
    check_certificate_live,
    check_formation,
    check_reachability,
    check_replay_certificate,
    check_risk_claims,
    check_risk_ledger,
    check_risk_spend_live,
    check_source_cut,
    check_well_audited,
    digest_json,
    digest_log,
    digest_many,
    scan_for_sensitive_data,
    summarize_risk_ledger,
)
from problem_frame_gate.cli import _read_gate_request, _read_log, _validate_schema, main
from problem_frame_gate.digest import normalize_json
from problem_frame_gate.errors import FoldError
from problem_frame_gate.fold import (
    CapabilityComponent,
    CertificateComponent,
    EvidenceComponent,
    FoldKernel,
    FoldState,
    FrameComponent,
    OutboxComponent,
    ResourceComponent,
    RiskComponent,
)
from problem_frame_gate.result import CheckBuilder


def env(
    eid: str,
    commit: int,
    kind: str,
    *,
    writer: str = "agent",
    event: str | None = None,
    slot: str = "0",
    version: int = 1,
    cls: EnvelopeClass = EnvelopeClass.NORMAL,
    deps: tuple[DependencyRef, ...] = (),
    commit_group: str | None = None,
    **payload: object,
) -> Envelope:
    return Envelope(
        eid=eid,
        event=event or eid,
        slot=slot,
        commit_time=commit,
        writer=writer,
        owner=writer,
        version=version,
        envelope_class=cls,
        payload={"kind": kind, **payload},
        dependencies=deps,
        commit_group=commit_group,
    )


def strict_horizon() -> Horizon:
    return Horizon.strict_default(agent_writers=("agent",), normal_capacity=200)


def gate_source_log() -> list[Envelope]:
    return [
        env(
            "f",
            0,
            "Frame",
            frame_id="p1",
            scope="s",
            goal="g",
            evidence_ids=["src"],
            actions=["act"],
            acceptance=["done"],
            risk_ids=["r1"],
        ),
        env("src", 1, "Evidence", evidence_id="src", digest="sha256:source"),
        env(
            "cert",
            2,
            "Issue",
            cert_id="risk-cert",
            family="risk",
            issuer="agent",
            source_ids=["src"],
            dependencies=["src"],
            expires_at=50,
            family_check="ok",
            assumption="StatisticalModel",
        ),
        env("active", 3, "Activated", frame_id="p1"),
        env("risk-reg", 4, "RiskReg", hypothesis_id="h1", family="fixed"),
        env("risk-reserve", 5, "RiskReserve", risk_id="r1", hypothesis_id="h1", frame_id="p1", eta="1/100"),
        env(
            "risk-spend",
            6,
            "RiskSpend",
            risk_id="r1",
            hypothesis_id="h1",
            frame_id="p1",
            eta="1/100",
            mode="fixed",
            cert_id="risk-cert",
        ),
        env("lease", 7, "ReserveResource", lease_id="lease1", token_id="tool", frame_id="p1"),
        env("cap", 8, "MintCap", capability_id="cap1", frame_id="p1", action="act"),
        env("out", 9, "AuthorizeOutbox", outbox_id="out1", frame_id="p1", action="act"),
    ]


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
        "risk_cert_id": "risk-cert",
        "source_time": 9,
        "commit_time": 10,
    }
    data.update(overrides)
    return GateRequest(**data)


def ok_invariant(*_: object) -> CheckResult:
    return CheckResult.success(digest=digest_json({"ok": True}))


@dataclass(frozen=True)
class PlainRecord:
    value: int


def test_digest_and_result_public_shapes() -> None:
    assert normalize_json(PlainRecord(3)) == {"value": 3}
    assert normalize_json(EnvelopeClass.NORMAL) == "normal"
    assert normalize_json(Fraction(1, 3)) == "1/3"
    assert json.loads(canonical_json_bytes({"items": {"b", "a"}})) == {"items": ["a", "b"]}
    assert digest_many([{"b": 2}, {"a": 1}]).startswith("sha256:")

    with pytest.raises(TypeError):
        normalize_json(b"raw")
    with pytest.raises(ValueError):
        normalize_json(math.inf)
    with pytest.raises(TypeError):
        normalize_json(object())
    with pytest.raises(ValueError):
        digest_json({"ok": True}, algorithm="sha512")

    issue = Issue("code", "message", location="loc", severity="warning", details={"x": 1})
    assert issue.to_json()["details"] == {"x": 1}
    result = CheckResult.success(footprint={"A"}, assumptions=("Env",)).with_digest("d").with_transcript_digest("t")
    assert result
    assert result.to_json()["assumptions"] == ["Env"]
    merged = result.merge(CheckResult.fail(Issue("bad", "bad"), footprint={"B"}, assumptions=("Env2",)))
    assert not merged.ok
    assert merged.footprint == frozenset({"A", "B"})
    assert merged.assumptions == ("Env", "Env2")

    builder = CheckBuilder(footprint={"base"})
    builder.add_footprint("extra")
    builder.add_assumption("External")
    builder.warning("warn", "warning")
    assert builder.result().ok


def test_model_parsers_manifest_and_transcripts() -> None:
    assert OrderEdge.from_value({"before": "a", "after": "b"}).to_json() == ["a", "b"]
    with pytest.raises(ValueError):
        OrderEdge.from_value(["a"])
    assert VersionInterval.from_value({"min": 1, "max": 2}).contains(2)
    with pytest.raises(ValueError):
        VersionInterval.from_value([1])
    assert DependencyRef.from_value("eid").to_json() == {"eid": "eid"}
    assert DependencyRef.from_value({"event": "e", "slot": "s"}).to_json() == {"event": "e", "slot": "s"}

    mapped = Envelope.from_mapping(
        {
            "eid": "e",
            "event": "event",
            "slot": "slot",
            "writer": "agent",
            "payload": {"kind": "Source", "source_id": "src"},
            "dependencies": [{"event": "root", "slot": "0"}],
            "commit_group": "g",
        }
    )
    assert mapped.object_key == "src"
    assert mapped.to_json()["dependencies"] == [{"event": "root", "slot": "0"}]
    with pytest.raises(ValueError):
        Envelope.from_mapping({"eid": "bad", "event": "e", "writer": "w", "payload": []})
    bad_kind = Envelope("bad", "e", "s", 0, "w", "w", 1, EnvelopeClass.NORMAL, {})
    with pytest.raises(ValueError):
        _ = bad_kind.kind

    manifest = StrictManifest.minimal(agent_writers=("agent",))
    assert manifest.strict
    assert StrictManifest.from_mapping({**manifest.to_json(), "strict": False}).strict
    assert CertificateFamily("risk", ("agent",), "StatisticalModel").to_json()["issuers"] == ["agent"]
    transcript = AuditTranscript(
        "checker",
        objects=("o",),
        reads=("r",),
        frontiers=("f",),
        clocks=("c",),
        capacities=("n",),
        digests=("d",),
        swaps=("s",),
    )
    assert transcript.to_json()["checker"] == "checker"


def test_verifier_reports_malformed_logs_without_crashing() -> None:
    base_h = Horizon.strict_default(agent_writers=("agent",), normal_capacity=1)
    h = Horizon.from_mapping({**base_h.to_json(), "events": ["known"]})
    malformed = Envelope("bad", "unknown", "0", 0, "agent", "agent", 2, EnvelopeClass.NORMAL, {})
    duplicate = env("bad", 1, "Evidence", evidence_id="x")
    dependent = env("dep", 2, "Evidence", evidence_id="dep", deps=(DependencyRef(eid="missing"),))
    secret = env("secret", 3, "Evidence", evidence_id="secret", token="sk-abcdefghijklmnopqrstuvwxyz")
    result = EnvelopeVerifier().verify(h, [malformed, duplicate, dependent, secret])
    codes = {issue.code for issue in result.issues}
    assert {
        "payload-kind",
        "duplicate-eid",
        "unknown-event",
        "missing-dependency",
        "sensitive-payload",
        "capacity-exceeded",
    } <= codes

    weak = EnvelopeVerifier().verify(Horizon.unsafe_for_tests(), [env("ok", 0, "Evidence", evidence_id="ok")])
    assert weak.ok
    assert any(issue.code == "unsafe-manifest" for issue in weak.issues)

    cyclic = Horizon(
        strict=False,
        audit_order=(OrderEdge("a", "b"), OrderEdge("b", "a")),
        capacities={EnvelopeClass.NORMAL: -1},
    )
    cycle_result = EnvelopeVerifier().verify(
        cyclic,
        [
            env("a", 0, "Evidence", event="a", evidence_id="a"),
            env("b", 1, "Evidence", event="b", evidence_id="b"),
        ],
    )
    assert {"cyclic-order", "negative-capacity", "canonical-order"} <= {issue.code for issue in cycle_result.issues}

    table_horizon = Horizon(
        strict=False,
        writer_authority={"Evidence": ("alice",)},
        version_intervals={"Frame": VersionInterval(1, 1)},
    )
    table_result = EnvelopeVerifier().verify(
        table_horizon,
        [env("e", 0, "Evidence", writer="mallory", version=2, evidence_id="e")],
    )
    assert {"writer-authority", "unknown-version-family"} <= {issue.code for issue in table_result.issues}


def test_fold_components_cover_state_machine_edges() -> None:
    frame_component = FrameComponent()
    frame_state = frame_component.initial_state()
    for row in (
        env("f", 0, "Frame", frame_id="p", scope="s", goal="g", evidence_ids=[], actions=["a"], acceptance=["done"]),
        env("proposed", 1, "Proposed", frame_id="p"),
        env("active", 2, "Activated", frame_id="p"),
        env("diagnostic", 3, "DiagnosticActivated", frame_id="p"),
        env("suspend", 4, "Suspended", frame_id="p"),
        env("invalid", 5, "Invalidated", frame_id="p"),
        env("withdraw", 6, "Withdrawn", frame_id="p"),
    ):
        frame_state = frame_component.apply(frame_state, row)
    assert frame_state["p"]["status"] == "withdrawn"
    with pytest.raises(FoldError):
        frame_component.apply(frame_state, env("bad-frame", 7, "Frame"))

    cert_component = CertificateComponent()
    cert_state = cert_component.apply(cert_component.initial_state(), env("issue", 0, "Issue", cert_id="c"))
    cert_state = cert_component.apply(cert_state, env("revoke", 1, "Revoke", cert_id="c"))
    assert cert_state["c"]["revoked_at"] == 1
    with pytest.raises(FoldError):
        cert_component.apply(cert_state, env("revoke-again", 2, "Revoke", cert_id="c"))

    cap_component = CapabilityComponent()
    cap_state = cap_component.apply(
        cap_component.initial_state(),
        env("cap1", 0, "MintCap", capability_id="cap1", frame_id="p", action="a"),
    )
    cap_state = cap_component.apply(cap_state, env("use", 1, "UseCap", capability_id="cap1", outbox_id="out"))
    assert cap_state["cap1"]["status"] == "used"
    with pytest.raises(FoldError):
        cap_component.apply(cap_state, env("revoke-used", 2, "RevokeCap", capability_id="cap1"))
    cap_state = cap_component.apply(cap_state, env("cap2", 3, "MintCap", capability_id="cap2"))
    cap_state = cap_component.apply(cap_state, env("expire", 4, "ExpireCap", capability_id="cap2"))
    assert cap_state["cap2"]["status"] == "expired"

    resource_component = ResourceComponent()
    resource_state = resource_component.apply(
        resource_component.initial_state(),
        env("res1", 0, "ReserveResource", lease_id="l1"),
    )
    resource_state = resource_component.apply(resource_state, env("release", 1, "ReleaseResource", lease_id="l1"))
    assert resource_state["l1"]["status"] == "released"
    with pytest.raises(FoldError):
        resource_component.apply(resource_state, env("consume-released", 2, "ConsumeResource", lease_id="l1"))

    outbox_component = OutboxComponent()
    outbox_state = outbox_component.apply(
        outbox_component.initial_state(),
        env("out", 0, "AuthorizeOutbox", outbox_id="out"),
    )
    outbox_state = outbox_component.apply(outbox_state, env("claim", 1, "OutboxClaim", outbox_id="out", gate_id="g"))
    outbox_state = outbox_component.apply(outbox_state, env("dispatch", 2, "DispatchStarted", outbox_id="out"))
    outbox_state = outbox_component.apply(outbox_state, env("accepted", 3, "ActuatorAccepted", outbox_id="out"))
    outbox_state = outbox_component.apply(outbox_state, env("receipt", 4, "ReceiptCommitted", outbox_id="out"))
    assert outbox_state["out"]["status"] == "receiptCommitted"
    with pytest.raises(FoldError):
        outbox_component.apply(outbox_state, env("bad-transition", 5, "DispatchStarted", outbox_id="out"))

    risk_component = RiskComponent()
    risk_state = risk_component.apply(risk_component.initial_state(), env("reg", 0, "RiskReg", hypothesis_id="h"))
    risk_state = risk_component.apply(
        risk_state,
        env("reserve", 1, "RiskReserve", risk_id="r", hypothesis_id="h", eta="1/10"),
    )
    risk_state = risk_component.apply(risk_state, env("spend", 2, "RiskSpend", risk_id="r", eta="1/10"))
    risk_state = risk_component.apply(risk_state, env("close", 3, "RiskClose", risk_id="r"))
    assert risk_state["spends"]["r"]["closed_at"] == 3
    with pytest.raises(FoldError):
        risk_component.apply(risk_state, env("close-again", 4, "RiskClose", risk_id="r"))

    evidence_state = EvidenceComponent().apply({}, env("source", 0, "Source", source_id="src", digest="d"))
    assert evidence_state["src"]["kind"] == "Source"
    fold_result = FoldKernel().check_fold(Horizon.unsafe_for_tests(), [env("bad", 0, "Frame")])
    assert fold_result.issues[0].code == "fold-rejected"


def test_gate_rejects_clock_digest_scope_and_bad_bundle_writer() -> None:
    h = strict_horizon()
    bad_request = gate_request(source_time=10, commit_time=10, expected_source_digest="sha256:wrong", action="delete")
    result = ExecutorGate().check(h, [], bad_request)
    codes = {issue.code for issue in result.issues}
    assert {"gate-clock-order", "gate-source-digest", "gate-frame-missing"} <= codes

    scoped_log = [
        env("f", 0, "Frame", frame_id="p1", scope="s", goal="g", evidence_ids=[], actions=["act"], acceptance=["done"]),
        env("active", 1, "Activated", frame_id="p1"),
        env("cap", 2, "MintCap", capability_id="cap1", frame_id="other", action="other"),
        env("lease", 3, "ReserveResource", lease_id="lease1", frame_id="other"),
        env("release", 4, "ReleaseResource", lease_id="lease1"),
        env("out", 5, "AuthorizeOutbox", outbox_id="out1", frame_id="other", action="other"),
        env("revoke-out", 6, "RevokeOutbox", outbox_id="out1"),
    ]
    scoped = ExecutorGate().check(h, scoped_log, gate_request(source_time=6, commit_time=7))
    scoped_codes = {issue.code for issue in scoped.issues}
    assert {
        "gate-capability-scope",
        "gate-resource-not-live",
        "gate-resource-scope",
        "gate-outbox-not-authorized",
        "gate-outbox-scope",
    } <= scoped_codes

    with pytest.raises(ValueError, match="failed verification"):
        ExecutorGate().create_bundle(h, gate_source_log(), gate_request(), writer="agent")


def test_risk_claim_modes_and_ledger_failures() -> None:
    h = strict_horizon()
    state = FoldKernel().fold(h, gate_source_log())
    assert summarize_risk_ledger(state).to_json()["spend_ids"] == ["r1"]
    assert check_risk_ledger(state, alpha="1/100").ok
    assert not check_risk_ledger(state, alpha="1/200").ok

    missing = check_risk_spend_live(
        state,
        risk_id="missing",
        hypothesis_id="h",
        mode="fixed",
        cert_id="risk-cert",
        at_time=9,
        horizon=h,
    )
    assert any(issue.code == "risk-spend-missing" for issue in missing.issues)

    mismatch = check_risk_spend_live(
        state,
        risk_id="r1",
        hypothesis_id="other",
        mode="selectedEvent",
        cert_id="other-cert",
        at_time=5,
        ledger_digest="sha256:other",
        horizon=Horizon.strict_default(agent_writers=("agent",), normal_capacity=200, fail_closed_capacity=10),
    )
    assert {
        "risk-hypothesis-mismatch",
        "risk-mode-mismatch",
        "risk-cert-mismatch",
        "risk-ledger-mismatch",
        "risk-spend-after-use",
    } <= {issue.code for issue in mismatch.issues}

    closed_state = FoldKernel().fold(
        Horizon.unsafe_for_tests(),
        [*gate_source_log(), env("close", 10, "RiskClose", risk_id="r1")],
    )
    closed = check_risk_spend_live(
        closed_state,
        risk_id="r1",
        hypothesis_id="h1",
        mode="fixed",
        cert_id="risk-cert",
        at_time=11,
    )
    assert any(issue.code == "risk-spend-closed" for issue in closed.issues)

    claims = (
        RiskClaimRecord("c1", "r1", "h1", "fixed", "risk-cert", "1/100", "", "std"),
        RiskClaimRecord("c2", "r1", "h1", "selectedEvent", "risk-cert", "1/100", "event", "std", selection_time=5),
        RiskClaimRecord(
            "c3",
            "r1",
            "h1",
            "conditionalSelective",
            "risk-cert",
            "1/100",
            "event",
            "std",
            route_check=False,
        ),
        RiskClaimRecord("c4", "r1", "h1", "anytime", "risk-cert", "1/100", "event", "std"),
    )
    claim_result = check_risk_claims(state, claims, alpha="1/100", at_time=9, horizon=h)
    claim_codes = {issue.code for issue in claim_result.issues}
    assert {
        "risk-claim-duplicate",
        "risk-fixed-event",
        "risk-selection-event",
        "risk-post-selection-reserve",
        "risk-conditional-route",
        "risk-stopping-time",
        "risk-alpha-bound",
    } <= claim_codes
    assert "StatisticalModel" in claim_result.assumptions
    assert claims[0].to_json()["risk_id"] == "r1"


def test_certificate_and_formation_failure_surfaces() -> None:
    missing_state = FoldState({"certificates": {}, "evidence": {}}, (), "d")
    assert check_certificate_live(missing_state, "missing", 1).issues[0].code == "certificate-missing"

    state = FoldState(
        {
            "certificates": {
                "c": {
                    "issued": True,
                    "issued_at": 5,
                    "issuer": "agent",
                    "family": "unknown",
                    "expires_at": 4,
                    "revoked_at": 3,
                    "dependencies": ("missing",),
                    "source_ids": ("src",),
                    "family_check": False,
                }
            },
            "evidence": {"late": {"committed_at": 10}},
        },
        ("issue",),
        "d",
    )
    live = check_certificate_live(state, "c", 4, horizon=strict_horizon())
    assert {
        "certificate-issued-after-use",
        "certificate-expired",
        "certificate-family",
        "certificate-family-check",
        "certificate-dependency",
        "certificate-source",
    } <= {issue.code for issue in live.issues}

    proof = FormationProof("p", (), (), (), (), seed="residue")
    assert proof.to_json()["seed"] == "residue"
    assert check_formation(FoldState({"frames": {}}, (), "d"), proof, at_time=0).issues[0].code == "frame-missing"
    no_definition = FoldState({"frames": {"p": {}}, "evidence": {}}, (), "d")
    assert check_formation(no_definition, proof, at_time=0).issues[0].code == "frame-definition-missing"

    bad_formation = FoldState(
        {
            "frames": {
                "p": {
                    "frame": {
                        "frame_id": "p",
                        "scope": "s",
                        "goal": "",
                        "evidence_ids": ["src"],
                        "actions": [],
                        "acceptance": [],
                        "risk_ids": ["r"],
                        "obligations": ["o"],
                    }
                }
            },
            "evidence": {},
            "certificates": {},
        },
        (),
        "d",
    )
    formation = check_formation(bad_formation, proof, at_time=0)
    assert {
        "formation-source",
        "frame-evidence-unwitnessed",
        "formation-goal",
        "formation-action",
        "formation-acceptance",
        "formation-risk",
        "formation-obligation",
        "formation-residue-route",
    } <= {issue.code for issue in formation.issues}
    missing_evidence = check_formation(
        bad_formation,
        FormationProof("p", ("missing",), (), (), (), seed="standard"),
        at_time=0,
    )
    assert any(issue.code == "evidence-missing" for issue in missing_evidence.issues)

    audited = check_well_audited(
        FoldState(
            {
                "capabilities": {"cap": {"status": "used"}},
                "resources": {"lease": {"status": "consumed"}},
                "outboxes": {"out": {"status": "claimed"}},
            },
            (),
            "d",
        )
    )
    assert {"capability-use-without-outbox", "resource-consume-time-missing", "outbox-claim-without-gate"} <= {
        issue.code for issue in audited.issues
    }


def test_patch_and_join_edge_conditions() -> None:
    h = strict_horizon()
    source = [env("src", 0, "Evidence", evidence_id="src")]
    proposal = PatchProposal(
        expected_source_digest="sha256:wrong",
        append=(env("src", 1, "Evidence", evidence_id="duplicate"),),
        affected_invariants=(),
        write_classes=(WriteClass("Evidence", "src"),),
        read_footprints=(ReadFootprint("inv", ("evidence:src",)),),
        touch_matrix=TouchMatrix({TouchMatrix.key(WriteClass("Evidence", "src"), "evidence:src"): "touch"}),
    )
    assert proposal.to_json()["write_classes"] == [{"name": "Evidence", "object_id": "src"}]
    assert AffectedClauseSet(("inv",)).to_json() == ["inv"]
    patch = PatchChecker().check(h, source, proposal, invariants={"inv": ok_invariant})
    assert {
        "patch-source-digest",
        "patch-not-append-only",
        "patch-affected-completeness",
        "patch-target-fold",
    } <= {issue.code for issue in patch.issues}

    no_footprint = PatchChecker().check(
        h,
        source,
        PatchProposal(digest_log(source), append=(env("new", 1, "Evidence", evidence_id="new"),)),
        invariants={"inv": ok_invariant},
    )
    assert any(issue.code == "patch-footprint-missing" for issue in no_footprint.issues)

    no_touch = PatchChecker().check(
        h,
        source,
        PatchProposal(
            digest_log(source),
            append=(env("new2", 2, "Evidence", evidence_id="new2"),),
            write_classes=(WriteClass("Evidence", "new2"),),
            read_footprints=(ReadFootprint("inv", ("evidence:src",)),),
        ),
        invariants={"inv": ok_invariant},
    )
    assert {"patch-touch-cell", "patch-invariant-not-rechecked"} <= {issue.code for issue in no_touch.issues}

    ancestor = (env("a", 0, "Evidence", evidence_id="a"),)
    conflict_a = (*ancestor, env("same", 1, "Evidence", evidence_id="a1"))
    conflict_b = (*ancestor, env("same", 1, "Evidence", evidence_id="b1"))
    join = JoinChecker().check(
        h,
        JoinProposal(
            branches=(conflict_a, conflict_b),
            ancestor=ancestor,
            repairs=(env("same", 2, "Evidence", evidence_id="repair"),),
            affected_invariants=("inv",),
        ),
    )
    assert {"join-eid-conflict", "join-repair-conflict", "join-repair-recheck"} <= {issue.code for issue in join.issues}
    assert JoinProposal(branches=(ancestor,), ancestor=ancestor).to_json()["ancestor"]

    missing_ancestor = JoinChecker().check(h, JoinProposal(branches=(ancestor,), ancestor=()))
    assert any(issue.code == "join-ancestor-missing" for issue in missing_ancestor.issues)

    invalid_target = JoinChecker().check(
        h,
        JoinProposal(
            branches=(
                ancestor,
                (*ancestor, Envelope("bad", "bad", "0", 1, "agent", "agent", 1, EnvelopeClass.NORMAL, {})),
            ),
            ancestor=ancestor,
        ),
    )
    assert any(issue.code == "join-target-fold" for issue in invalid_target.issues)

    frame_base = (
        env("f", 0, "Frame", frame_id="p", scope="s", goal="g", evidence_ids=[], actions=["a"], acceptance=["done"]),
        env("active", 1, "Activated", frame_id="p"),
        env("cap", 2, "MintCap", capability_id="cap", frame_id="p", action="a"),
        env("out", 3, "AuthorizeOutbox", outbox_id="out", frame_id="p", action="a"),
    )
    invalidating = JoinChecker().check(
        h,
        JoinProposal(
            branches=(frame_base, (*frame_base, env("suspend", 4, "Suspended", frame_id="p"))),
            ancestor=frame_base,
        ),
    )
    assert {"join-frame-invalidates-capability", "join-frame-invalidates-outbox"} <= {
        issue.code for issue in invalidating.issues
    }


def test_replay_source_cut_reachability_and_security_edges() -> None:
    h = strict_horizon()
    log = (
        env("a", 0, "Evidence", evidence_id="a"),
        env("b", 1, "Evidence", evidence_id="b", deps=(DependencyRef(eid="c"),), commit_group="g"),
        env("c", 2, "Evidence", evidence_id="c", commit_group="g"),
    )
    bad_word = check_replay_certificate(h, log, ReplayCertificate(("a", "a"), (), SwapCover(), digest_log(log)))
    assert any(issue.code == "replay-word" for issue in bad_word.issues)
    bad_trace = check_replay_certificate(
        h,
        log,
        ReplayCertificate(
            ("b", "a", "c"),
            ((5, "b", "a"), (0, "x", "a")),
            SwapCover(independent_pairs=(("a", "b"),)),
            "wrong",
        ),
    )
    assert {"replay-target-digest", "replay-swap-index", "replay-swap-pair", "replay-not-canonical"} <= {
        issue.code for issue in bad_trace.issues
    }

    cut = SourceCut("cut", 1, ("a", "b"), (), "sha256:wrong")
    cut_result = check_source_cut(h, log, cut)
    assert {"source-cut-frontier", "source-cut-digest", "source-cut-dependency", "source-cut-commit-group"} <= {
        issue.code for issue in cut_result.issues
    }
    assert not check_source_cut(Horizon(), log, cut).ok

    reach = check_reachability(ReachabilityTranscript((TransitionRecord("", "target", "patch", ""),)))
    assert any(issue.code == "reach-record" for issue in reach.issues)

    issues = scan_for_sensitive_data(
        {"password": "x", "items": ["C:\\Users\\alice\\secret.txt"], "empty_password": "", "nested": {"token": 123}}
    )
    assert issues[0].to_json()["preview"] == "***"
    assert scan_for_sensitive_data({"path": "C:\\Users\\alice\\secret.txt"}, allow_local_paths=True) == ()


def test_cli_additional_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    data_path = tmp_path / "data.json"
    data_path.write_text(json.dumps({"b": 2, "a": 1}), encoding="utf-8")
    assert main(["digest", str(data_path)]) == 0
    assert "sha256:" in capsys.readouterr().out

    secret_path = tmp_path / "secret.json"
    secret_path.write_text(json.dumps({"api_key": "sk-abcdefghijklmnopqrstuvwxyz"}), encoding="utf-8")
    assert main(["scan", str(secret_path)]) == 1
    assert "secret-looking" in capsys.readouterr().out

    h_path = tmp_path / "horizon.json"
    log_path = tmp_path / "log.json"
    h_path.write_text(json.dumps(strict_horizon().to_json()), encoding="utf-8")
    log_path.write_text(json.dumps([env("e", 0, "Evidence", evidence_id="e").to_json()]), encoding="utf-8")
    assert main(["verify-log", "--horizon", str(h_path), str(log_path)]) == 0
    assert main(["fold", "--horizon", str(h_path), str(log_path)]) == 0
    assert "ordered_eids" in capsys.readouterr().out

    bad_log_path = tmp_path / "bad-log.json"
    bad_request_path = tmp_path / "bad-request.json"
    bad_log_path.write_text("{}", encoding="utf-8")
    bad_request_path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="log JSON"):
        _read_log(bad_log_path)
    with pytest.raises(ValueError, match="gate request"):
        _read_gate_request(bad_request_path)
    assert _validate_schema("horizon", []) == ["horizon must be a JSON object"]
    assert _validate_schema("log", ["bad", {"payload": {}}]) == [
        "log[0] must be an object",
        "log[1] must contain payload.kind",
    ]
    assert _validate_schema("gate-request", []) == ["gate request must be a JSON object"]

    assert main(["explain", "unknown-code"]) == 0
    assert "No detailed explanation" in capsys.readouterr().out
