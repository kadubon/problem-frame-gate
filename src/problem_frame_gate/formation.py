"""Finite problem-frame formation checks."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .certificates import all_certificates_live
from .fold import FoldState
from .model import Frame, Horizon
from .result import CheckBuilder, CheckResult


@dataclass(frozen=True, slots=True)
class FormationProof:
    """Finite proof object for activating a bounded decision frame."""

    frame_id: str
    source_evidence: tuple[str, ...]
    goal_witnesses: tuple[str, ...]
    action_witnesses: tuple[str, ...]
    acceptance_witnesses: tuple[str, ...]
    risk_witnesses: tuple[str, ...] = ()
    obligation_witnesses: tuple[str, ...] = ()
    seed: str = "standard"
    certificate_ids: tuple[str, ...] = ()
    transcript_digest: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "frame_id": self.frame_id,
            "source_evidence": list(self.source_evidence),
            "goal_witnesses": list(self.goal_witnesses),
            "action_witnesses": list(self.action_witnesses),
            "acceptance_witnesses": list(self.acceptance_witnesses),
            "risk_witnesses": list(self.risk_witnesses),
            "obligation_witnesses": list(self.obligation_witnesses),
            "seed": self.seed,
            "certificate_ids": list(self.certificate_ids),
            "transcript_digest": self.transcript_digest,
            "metadata": dict(self.metadata),
        }


def check_formation(
    state: FoldState, proof: FormationProof, *, at_time: int, horizon: Horizon | None = None
) -> CheckResult:
    """Check the semantic fields required before a frame carries authority."""

    builder = CheckBuilder(
        footprint={
            "FoldKernel",
            "ClauseKernel",
            "IssuerAuthentication",
            "RevocationOracle",
            "ClockWatermark",
        }
    )
    frames: dict[str, dict[str, Any]] = state.component("frames")
    record = frames.get(proof.frame_id)
    if record is None:
        builder.error("frame-missing", "frame is not present in folded state", location=proof.frame_id)
        return builder.result()

    frame_data = record.get("frame")
    if not isinstance(frame_data, Mapping):
        builder.error(
            "frame-definition-missing",
            "frame definition payload is missing",
            location=proof.frame_id,
        )
        return builder.result()
    frame = Frame.from_payload(frame_data)

    evidence = state.component("evidence")
    _require_nonempty(proof.source_evidence, "formation-source", "source evidence is required", builder)
    for evidence_id in proof.source_evidence:
        if evidence_id not in evidence:
            builder.error(
                "evidence-missing",
                "source evidence is absent from the folded state",
                location=evidence_id,
            )
    for evidence_id in frame.evidence_ids:
        if evidence_id not in proof.source_evidence:
            builder.error(
                "frame-evidence-unwitnessed",
                "frame evidence id is not cited by proof",
                location=evidence_id,
            )

    if not frame.goal.strip() or not proof.goal_witnesses:
        builder.error("formation-goal", "frame goal must be finite and witnessed", location=proof.frame_id)
    if not frame.actions or not proof.action_witnesses:
        builder.error(
            "formation-action",
            "frame action set must be finite and witnessed",
            location=proof.frame_id,
        )
    if not frame.acceptance or not proof.acceptance_witnesses:
        builder.error(
            "formation-acceptance",
            "acceptance criteria must be finite and witnessed",
            location=proof.frame_id,
        )
    for risk_id in frame.risk_ids:
        if risk_id not in proof.risk_witnesses:
            builder.error("formation-risk", "frame risk id is not witnessed", location=risk_id)
    for obligation in frame.obligations:
        if obligation not in proof.obligation_witnesses:
            builder.error("formation-obligation", "frame obligation is not witnessed", location=obligation)

    if proof.seed == "residue" and not (proof.risk_witnesses or proof.obligation_witnesses):
        builder.error(
            "formation-residue-route",
            "residue seed requires either risk evidence or diagnostic obligations",
            location=proof.frame_id,
        )

    return builder.result().merge(all_certificates_live(state, proof.certificate_ids, at_time, horizon=horizon))


def check_well_audited(state: FoldState) -> CheckResult:
    """Built-in safety checks for the default components."""

    builder = CheckBuilder(footprint={"ClauseKernel", "FoldKernel"})
    for cap_id, cap in state.component("capabilities").items():
        if cap.get("status") == "used" and not cap.get("outbox_id"):
            builder.error(
                "capability-use-without-outbox",
                "used capability must cite an outbox",
                location=cap_id,
            )
    for lease_id, lease in state.component("resources").items():
        if lease.get("status") == "consumed" and lease.get("consumed_at") is None:
            builder.error(
                "resource-consume-time-missing",
                "consumed resource must record a time",
                location=lease_id,
            )
    for outbox_id, outbox in state.component("outboxes").items():
        if outbox.get("status") in {
            "claimed",
            "dispatchStarted",
            "actuatorAccepted",
        } and not outbox.get("gate_id"):
            builder.error("outbox-claim-without-gate", "claimed outbox must cite a gate", location=outbox_id)
    return builder.result()


def _require_nonempty(values: tuple[str, ...], code: str, message: str, builder: CheckBuilder) -> None:
    if not values:
        builder.error(code, message)
