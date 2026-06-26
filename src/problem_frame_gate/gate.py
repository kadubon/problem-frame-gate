"""Execution gate for external actions."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .certificates import all_certificates_live
from .fold import FoldKernel, FoldState
from .formation import check_well_audited
from .model import Envelope, EnvelopeClass, Horizon, Status
from .result import CheckBuilder, CheckResult
from .risk import check_risk_spend_live
from .verifier import EnvelopeVerifier, digest_log


@dataclass(frozen=True, slots=True)
class GateRequest:
    """All fields the executor gate must bind into the audit log."""

    gate_id: str
    bundle_id: str
    frame_id: str
    action: str
    outbox_id: str
    capability_id: str
    lease_id: str
    risk_id: str
    hypothesis_id: str
    risk_mode: str
    risk_cert_id: str
    source_time: int
    commit_time: int
    executor_id: str = "executor"
    resource_amount: Any = 1
    ledger_digest: str | None = None
    expected_source_digest: str | None = None
    required_certificate_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "bundle_id": self.bundle_id,
            "frame_id": self.frame_id,
            "action": self.action,
            "outbox_id": self.outbox_id,
            "capability_id": self.capability_id,
            "lease_id": self.lease_id,
            "risk_id": self.risk_id,
            "hypothesis_id": self.hypothesis_id,
            "risk_mode": self.risk_mode,
            "risk_cert_id": self.risk_cert_id,
            "source_time": self.source_time,
            "commit_time": self.commit_time,
            "executor_id": self.executor_id,
            "resource_amount": self.resource_amount,
            "ledger_digest": self.ledger_digest,
            "expected_source_digest": self.expected_source_digest,
            "required_certificate_ids": list(self.required_certificate_ids),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class GateRecord:
    """Finite row that binds a gate decision to one source prefix."""

    gate_id: str
    bundle_id: str
    frame_id: str
    action: str
    outbox_id: str
    capability_id: str
    lease_id: str
    risk_id: str
    hypothesis_id: str
    risk_mode: str
    risk_cert_id: str
    source_digest: str
    ledger_digest: str | None
    transcript_digest: str
    source_time: int
    commit_time: int

    @classmethod
    def from_request(cls, request: GateRequest, *, source_digest: str, transcript_digest: str) -> GateRecord:
        return cls(
            gate_id=request.gate_id,
            bundle_id=request.bundle_id,
            frame_id=request.frame_id,
            action=request.action,
            outbox_id=request.outbox_id,
            capability_id=request.capability_id,
            lease_id=request.lease_id,
            risk_id=request.risk_id,
            hypothesis_id=request.hypothesis_id,
            risk_mode=request.risk_mode,
            risk_cert_id=request.risk_cert_id,
            source_digest=source_digest,
            ledger_digest=request.ledger_digest,
            transcript_digest=transcript_digest,
            source_time=request.source_time,
            commit_time=request.commit_time,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "bundle_id": self.bundle_id,
            "frame_id": self.frame_id,
            "action": self.action,
            "outbox_id": self.outbox_id,
            "capability_id": self.capability_id,
            "lease_id": self.lease_id,
            "risk_id": self.risk_id,
            "hypothesis_id": self.hypothesis_id,
            "risk_mode": self.risk_mode,
            "risk_cert_id": self.risk_cert_id,
            "source_digest": self.source_digest,
            "ledger_digest": self.ledger_digest,
            "transcript_digest": self.transcript_digest,
            "source_time": self.source_time,
            "commit_time": self.commit_time,
        }


@dataclass(frozen=True, slots=True)
class GateBundle:
    """Atomic five-row executor-gate bundle."""

    record: GateRecord
    envelopes: tuple[Envelope, ...]

    def __iter__(self) -> Iterator[Envelope]:
        return iter(self.envelopes)

    def __len__(self) -> int:
        return len(self.envelopes)

    def to_json(self) -> dict[str, Any]:
        return {
            "record": self.record.to_json(),
            "envelopes": [env.to_json() for env in self.envelopes],
        }

    def verify(self, horizon: Horizon, source: Sequence[Envelope]) -> CheckResult:
        return EnvelopeVerifier().verify(horizon, tuple(source) + self.envelopes)


class ExecutorGate:
    """Before-use checker and atomic bundle producer."""

    footprint = frozenset(
        {
            "ExecutorGate",
            "FoldKernel",
            "EnvelopeVerifier",
            "ClauseKernel",
            "ClockWatermark",
            "RiskLedger",
        }
    )

    def __init__(self, fold_kernel: FoldKernel | None = None) -> None:
        self.fold_kernel = fold_kernel or FoldKernel()

    def check(self, horizon: Horizon, envelopes: Sequence[Envelope], request: GateRequest) -> CheckResult:
        builder = CheckBuilder(footprint=set(self.footprint))
        if request.source_time >= request.commit_time:
            builder.error("gate-clock-order", "source time must be before commit time")

        prefix = tuple(env for env in envelopes if env.commit_time <= request.source_time)
        source_digest = digest_log(prefix)
        if request.expected_source_digest is not None and request.expected_source_digest != source_digest:
            builder.error(
                "gate-source-digest",
                "source-prefix digest does not match the gate request",
                details={"expected": request.expected_source_digest, "actual": source_digest},
            )

        try:
            state = self.fold_kernel.fold(horizon, prefix)
        except Exception as exc:
            builder.error("gate-source-fold", f"source prefix does not fold: {exc}")
            return builder.result(digest=source_digest)

        builder_result = builder.result(digest=source_digest)
        semantic = self._check_state(state, request)
        certificates = all_certificates_live(
            state, request.required_certificate_ids, request.source_time, horizon=horizon
        )
        risk = check_risk_spend_live(
            state,
            risk_id=request.risk_id,
            hypothesis_id=request.hypothesis_id,
            mode=request.risk_mode,
            cert_id=request.risk_cert_id,
            at_time=request.source_time,
            ledger_digest=request.ledger_digest,
            horizon=horizon,
        )
        return builder_result.merge(check_well_audited(state), semantic, certificates, risk)

    def create_bundle(
        self,
        horizon: Horizon,
        envelopes: Sequence[Envelope],
        request: GateRequest,
        *,
        writer: str = "executor-gate",
        owner: str = "executor-gate",
        version: int = 1,
    ) -> GateBundle:
        result = self.check(horizon, envelopes, request)
        if not result.ok:
            messages = "; ".join(issue.message for issue in result.issues if issue.severity == "error")
            raise ValueError(f"gate request rejected: {messages}")

        source_prefix = tuple(env for env in envelopes if env.commit_time <= request.source_time)
        source_digest = digest_log(source_prefix)
        transcript_digest = result.digest or source_digest
        record = GateRecord.from_request(request, source_digest=source_digest, transcript_digest=transcript_digest)
        payloads: tuple[Mapping[str, Any], ...] = (
            {
                "kind": "GateCheck",
                "gate_id": request.gate_id,
                "bundle_id": request.bundle_id,
                "frame_id": request.frame_id,
                "action": request.action,
                "source_digest": source_digest,
                "request": request.to_json(),
                "gate_record": record.to_json(),
            },
            {
                "kind": "OutboxClaim",
                "gate_id": request.gate_id,
                "outbox_id": request.outbox_id,
                "frame_id": request.frame_id,
                "action": request.action,
                "source_digest": source_digest,
            },
            {
                "kind": "UseCap",
                "capability_id": request.capability_id,
                "outbox_id": request.outbox_id,
                "frame_id": request.frame_id,
                "action": request.action,
            },
            {
                "kind": "ConsumeResource",
                "lease_id": request.lease_id,
                "frame_id": request.frame_id,
                "amount": request.resource_amount,
                "consumer": request.executor_id,
            },
            {
                "kind": "RiskClose",
                "risk_id": request.risk_id,
                "hypothesis_id": request.hypothesis_id,
                "frame_id": request.frame_id,
                "ledger_digest": request.ledger_digest,
            },
        )
        bundle = tuple(
            Envelope(
                eid=f"{request.bundle_id}:{index}",
                event=f"{request.bundle_id}:{index}",
                slot=str(index),
                commit_time=request.commit_time,
                writer=writer,
                owner=owner,
                version=version,
                envelope_class=EnvelopeClass.NORMAL,
                payload=payload,
                commit_group=request.bundle_id,
            )
            for index, payload in enumerate(payloads)
        )
        gate_bundle = GateBundle(record=record, envelopes=bundle)
        verify = gate_bundle.verify(horizon, envelopes)
        if not verify.ok:
            messages = "; ".join(issue.message for issue in verify.issues if issue.severity == "error")
            raise ValueError(f"created gate bundle failed verification: {messages}")
        return gate_bundle

    def _check_state(self, state: FoldState, request: GateRequest) -> CheckResult:
        builder = CheckBuilder(footprint=set(self.footprint))
        frames = state.component("frames")
        frame_record = frames.get(request.frame_id)
        if frame_record is None:
            builder.error(
                "gate-frame-missing",
                "frame is absent from source prefix",
                location=request.frame_id,
            )
            return builder.result()
        if frame_record.get("status") != Status.ACTIVE.value:
            builder.error(
                "gate-frame-inactive",
                "external action requires an active frame",
                location=request.frame_id,
                details={"status": frame_record.get("status")},
            )
        frame = frame_record.get("frame", {})
        if isinstance(frame, Mapping) and frame.get("actions") and request.action not in frame.get("actions", ()):
            builder.error(
                "gate-action-not-allowed",
                "action is not in the frame action set",
                location=request.action,
            )

        cap = state.component("capabilities").get(request.capability_id)
        if cap is None:
            builder.error("gate-capability-missing", "capability is absent", location=request.capability_id)
        else:
            if cap.get("status") != "unused":
                builder.error(
                    "gate-capability-not-live",
                    "capability is not unused",
                    location=request.capability_id,
                )
            if cap.get("frame_id") != request.frame_id or cap.get("action") != request.action:
                builder.error(
                    "gate-capability-scope",
                    "capability scope does not match request",
                    location=request.capability_id,
                )

        lease = state.component("resources").get(request.lease_id)
        if lease is None:
            builder.error("gate-resource-missing", "resource lease is absent", location=request.lease_id)
        else:
            if lease.get("status") != "leased":
                builder.error(
                    "gate-resource-not-live",
                    "resource lease is not live",
                    location=request.lease_id,
                )
            if lease.get("frame_id") != request.frame_id:
                builder.error(
                    "gate-resource-scope",
                    "resource lease frame does not match request",
                    location=request.lease_id,
                )

        outbox = state.component("outboxes").get(request.outbox_id)
        if outbox is None:
            builder.error("gate-outbox-missing", "outbox authorization is absent", location=request.outbox_id)
        else:
            if outbox.get("status") != "authorized":
                builder.error(
                    "gate-outbox-not-authorized",
                    "outbox is not in authorized state",
                    location=request.outbox_id,
                )
            if outbox.get("frame_id") != request.frame_id or outbox.get("action") != request.action:
                builder.error(
                    "gate-outbox-scope",
                    "outbox scope does not match request",
                    location=request.outbox_id,
                )

        return builder.result()
