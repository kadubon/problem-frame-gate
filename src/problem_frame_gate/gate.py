"""Execution gate for external actions."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .certificates import CertificateFamily, all_certificates_live
from .clock import ClockWatermarkProvider
from .digest import digest_json
from .fold import FoldKernel, FoldState
from .formation import check_well_audited
from .model import Envelope, EnvelopeClass, Horizon, Status
from .records import SourceCut
from .result import CheckBuilder, CheckResult
from .risk import RiskClaimRecord, RiskMode, check_risk_claims, check_risk_spend_live
from .signatures import SignatureRegistry
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
    risk_claim: Mapping[str, Any] | None = None
    risk_alpha: str = "1"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> GateRequest:
        if not isinstance(value, Mapping):
            raise TypeError("gate request must be an object")
        risk_claim_value = value.get("risk_claim")
        if risk_claim_value is not None and not isinstance(risk_claim_value, Mapping):
            raise TypeError("risk_claim must be an object")
        return cls(
            gate_id=str(value["gate_id"]),
            bundle_id=str(value["bundle_id"]),
            frame_id=str(value["frame_id"]),
            action=str(value["action"]),
            outbox_id=str(value["outbox_id"]),
            capability_id=str(value["capability_id"]),
            lease_id=str(value["lease_id"]),
            risk_id=str(value["risk_id"]),
            hypothesis_id=str(value["hypothesis_id"]),
            risk_mode=str(value["risk_mode"]),
            risk_cert_id=str(value["risk_cert_id"]),
            source_time=int(value["source_time"]),
            commit_time=int(value["commit_time"]),
            executor_id=str(value.get("executor_id", "executor")),
            resource_amount=value.get("resource_amount", 1),
            ledger_digest=str(value["ledger_digest"]) if value.get("ledger_digest") is not None else None,
            expected_source_digest=(
                str(value["expected_source_digest"]) if value.get("expected_source_digest") is not None else None
            ),
            required_certificate_ids=tuple(str(item) for item in value.get("required_certificate_ids", ())),
            risk_claim=dict(risk_claim_value) if risk_claim_value is not None else None,
            risk_alpha=str(value.get("risk_alpha", "1")),
            metadata=dict(value.get("metadata", {})),
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
            "source_time": self.source_time,
            "commit_time": self.commit_time,
            "executor_id": self.executor_id,
            "resource_amount": self.resource_amount,
            "ledger_digest": self.ledger_digest,
            "expected_source_digest": self.expected_source_digest,
            "required_certificate_ids": list(self.required_certificate_ids),
            "risk_claim": dict(self.risk_claim) if self.risk_claim is not None else None,
            "risk_alpha": self.risk_alpha,
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

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> GateRecord:
        return cls(
            gate_id=str(value["gate_id"]),
            bundle_id=str(value["bundle_id"]),
            frame_id=str(value["frame_id"]),
            action=str(value["action"]),
            outbox_id=str(value["outbox_id"]),
            capability_id=str(value["capability_id"]),
            lease_id=str(value["lease_id"]),
            risk_id=str(value["risk_id"]),
            hypothesis_id=str(value["hypothesis_id"]),
            risk_mode=str(value["risk_mode"]),
            risk_cert_id=str(value["risk_cert_id"]),
            source_digest=str(value["source_digest"]),
            ledger_digest=str(value["ledger_digest"]) if value.get("ledger_digest") is not None else None,
            transcript_digest=str(value["transcript_digest"]),
            source_time=int(value["source_time"]),
            commit_time=int(value["commit_time"]),
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
    source_cut: SourceCut | None = None

    def __iter__(self) -> Iterator[Envelope]:
        return iter(self.envelopes)

    def __len__(self) -> int:
        return len(self.envelopes)

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "record": self.record.to_json(),
            "envelopes": [env.to_json() for env in self.envelopes],
        }
        if self.source_cut is not None:
            data["source_cut"] = self.source_cut.to_json()
        return data

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> GateBundle:
        source_cut_value = value.get("source_cut")
        return cls(
            record=GateRecord.from_mapping(_mapping(value["record"])),
            envelopes=tuple(Envelope.from_mapping(item) for item in _sequence(value["envelopes"])),
            source_cut=SourceCut.from_mapping(source_cut_value) if isinstance(source_cut_value, Mapping) else None,
        )

    def verify(
        self,
        horizon: Horizon,
        source: Sequence[Envelope],
        *,
        certificate_registry: Mapping[str, CertificateFamily] | None = None,
        risk_registry: Mapping[str, RiskMode] | None = None,
        signature_registry: SignatureRegistry | None = None,
        require_certificate_signatures: bool = False,
    ) -> CheckResult:
        return EnvelopeVerifier(
            certificate_registry=certificate_registry,
            risk_registry=risk_registry,
            signature_registry=signature_registry,
            require_certificate_signatures=require_certificate_signatures,
        ).verify(horizon, tuple(source) + self.envelopes)


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

    def __init__(
        self,
        fold_kernel: FoldKernel | None = None,
        *,
        certificate_registry: Mapping[str, CertificateFamily] | None = None,
        risk_registry: Mapping[str, RiskMode] | None = None,
        signature_registry: SignatureRegistry | None = None,
        require_certificate_signatures: bool = False,
    ) -> None:
        self.fold_kernel = fold_kernel or FoldKernel()
        self.certificate_registry = certificate_registry
        self.risk_registry = risk_registry
        self.signature_registry = signature_registry
        self.require_certificate_signatures = require_certificate_signatures

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
            state,
            request.required_certificate_ids,
            request.source_time,
            horizon=horizon,
            registry=self.certificate_registry,
            signature_registry=self.signature_registry,
            require_signature=self.require_certificate_signatures,
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
            certificate_registry=self.certificate_registry,
            signature_registry=self.signature_registry,
            require_certificate_signature=self.require_certificate_signatures,
        )
        risk_claim = self._check_risk_claim(state, request, horizon)
        return builder_result.merge(check_well_audited(state), semantic, certificates, risk, risk_claim)

    def create_bundle(
        self,
        horizon: Horizon,
        envelopes: Sequence[Envelope],
        request: GateRequest,
        *,
        writer: str = "executor-gate",
        owner: str = "executor-gate",
        version: int = 1,
        watermark_provider: ClockWatermarkProvider | None = None,
    ) -> GateBundle:
        result = self.check(horizon, envelopes, request)
        if not result.ok:
            messages = "; ".join(issue.message for issue in result.issues if issue.severity == "error")
            raise ValueError(f"gate request rejected: {messages}")

        source_prefix = tuple(env for env in envelopes if env.commit_time <= request.source_time)
        source_digest = digest_log(source_prefix)
        transcript_digest = digest_json(result.to_json())
        record = GateRecord.from_request(request, source_digest=source_digest, transcript_digest=transcript_digest)
        watermark = None
        clock_rows: tuple[str, ...] = (f"source_time:{request.source_time}", f"commit_time:{request.commit_time}")
        watermark_rows: tuple[str, ...] = (f"source_digest:{source_digest}",)
        if watermark_provider is not None:
            watermark = watermark_provider.watermark(
                source_time=request.source_time,
                commit_time=request.commit_time,
                source_digest=source_digest,
            )
            clock_rows = watermark.clock_rows()
            watermark_rows = watermark.watermark_rows()
        source_cut = SourceCut(
            cut_id=f"{request.gate_id}:source-cut",
            source_time=request.source_time,
            included_eids=tuple(env.eid for env in source_prefix),
            excluded_frontier_eids=tuple(env.eid for env in envelopes if env.commit_time > request.source_time),
            digest=source_digest,
            clock_rows=clock_rows,
            watermark_rows=watermark_rows,
        )
        gate_record_digest = digest_json(record.to_json())
        payloads: tuple[Mapping[str, Any], ...] = (
            {
                "kind": "GateCheck",
                "gate_id": request.gate_id,
                "bundle_id": request.bundle_id,
                "frame_id": request.frame_id,
                "action": request.action,
                "source_digest": source_digest,
                "source_cut": source_cut.to_json(),
                "request": request.to_json(),
                "gate_record": record.to_json(),
                "gate_record_digest": gate_record_digest,
                "transcript_digest": transcript_digest,
                "clock_watermark": watermark.to_json() if watermark is not None else None,
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
        gate_bundle = GateBundle(record=record, envelopes=bundle, source_cut=source_cut)
        verify = gate_bundle.verify(
            horizon,
            envelopes,
            certificate_registry=self.certificate_registry,
            risk_registry=self.risk_registry,
            signature_registry=self.signature_registry,
            require_certificate_signatures=self.require_certificate_signatures,
        )
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

    def _check_risk_claim(self, state: FoldState, request: GateRequest, horizon: Horizon) -> CheckResult:
        builder = CheckBuilder(footprint={"RiskLedger", "RiskTranscript"})
        if request.risk_claim is None:
            if horizon.strict:
                builder.error(
                    "gate-risk-claim-missing",
                    "strict gate request must bind an accepted risk claim record",
                    location=request.risk_id,
                )
            return builder.result()
        try:
            claim = RiskClaimRecord.from_mapping(request.risk_claim)
        except (KeyError, TypeError, ValueError) as exc:
            builder.error(
                "gate-risk-claim",
                f"gate risk claim is malformed: {exc}",
                location=request.risk_id,
            )
            return builder.result()
        expected = {
            "risk_id": request.risk_id,
            "hypothesis_id": request.hypothesis_id,
            "mode": request.risk_mode,
            "cert_id": request.risk_cert_id,
            "ledger_digest": request.ledger_digest,
        }
        actual = {
            "risk_id": claim.risk_id,
            "hypothesis_id": claim.hypothesis_id,
            "mode": claim.mode,
            "cert_id": claim.cert_id,
            "ledger_digest": claim.ledger_digest,
        }
        for field_name, expected_value in expected.items():
            if actual[field_name] != expected_value:
                builder.error(
                    "gate-risk-claim-coherence",
                    "risk claim record does not match the gate request tuple",
                    location=claim.claim_id,
                    details={"field": field_name, "expected": expected_value, "actual": actual[field_name]},
                )
        claim_result = check_risk_claims(
            state,
            (claim,),
            alpha=request.risk_alpha,
            at_time=request.source_time,
            horizon=horizon,
            registry=self.risk_registry,
            certificate_registry=self.certificate_registry,
            signature_registry=self.signature_registry,
            require_certificate_signature=self.require_certificate_signatures,
        )
        return builder.result().merge(claim_result)


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("expected object mapping")
    return value


def _sequence(value: object) -> Sequence[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise TypeError("expected sequence")
    return tuple(_mapping(item) for item in value)
