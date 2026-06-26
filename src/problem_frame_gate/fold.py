"""Deterministic component replay over a legal envelope log."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Protocol

from .errors import FoldError, LogVerificationError
from .model import Envelope, Frame, Horizon, Status
from .result import CheckBuilder, CheckResult
from .verifier import EnvelopeVerifier, digest_log


class StateComponent(Protocol):
    name: str

    def initial_state(self) -> Any: ...

    def apply(self, state: Any, envelope: Envelope) -> Any: ...


@dataclass(frozen=True, slots=True)
class FoldState:
    components: Mapping[str, Any]
    ordered_eids: tuple[str, ...]
    log_digest: str

    def component(self, name: str) -> Any:
        return self.components.get(name, {})

    def to_json(self) -> dict[str, Any]:
        return {
            "components": self.components,
            "ordered_eids": list(self.ordered_eids),
            "log_digest": self.log_digest,
        }


class FoldKernel:
    """Replay kernel with manifest-supplied components."""

    footprint = frozenset({"FoldKernel", "EnvelopeVerifier"})

    def __init__(self, components: Sequence[StateComponent] | None = None) -> None:
        self.components = tuple(components or default_components())
        names = [component.name for component in self.components]
        if len(names) != len(set(names)):
            raise ValueError("component names must be unique")
        self.verifier = EnvelopeVerifier()

    def fold(self, horizon: Horizon, envelopes: Sequence[Envelope]) -> FoldState:
        legal = self.verifier.verify(horizon, envelopes)
        if not legal.ok:
            raise LogVerificationError("log is not legal")
        ordered = self.verifier.canonical_order(horizon, envelopes)
        states: dict[str, Any] = {component.name: component.initial_state() for component in self.components}
        for env in ordered:
            for component in self.components:
                try:
                    states[component.name] = component.apply(states[component.name], env)
                except FoldError:
                    raise
                except Exception as exc:  # pragma: no cover - defensive wrapper
                    raise FoldError(f"{component.name} rejected envelope {env.eid}: {exc}") from exc
        return FoldState(states, tuple(env.eid for env in ordered), digest_log(envelopes))

    def check_fold(self, horizon: Horizon, envelopes: Sequence[Envelope]) -> CheckResult:
        builder = CheckBuilder(footprint=set(self.footprint))
        legal = self.verifier.verify(horizon, envelopes)
        if not legal.ok:
            return legal.merge(builder.result())
        try:
            state = self.fold(horizon, envelopes)
        except FoldError as exc:
            builder.error("fold-rejected", str(exc))
            return builder.result(digest=legal.digest)
        return builder.result(digest=state.log_digest)


class FrameComponent:
    name = "frames"

    def initial_state(self) -> dict[str, dict[str, Any]]:
        return {}

    def apply(self, state: dict[str, dict[str, Any]], envelope: Envelope) -> dict[str, dict[str, Any]]:
        next_state = deepcopy(state)
        kind = envelope.kind
        payload = envelope.payload
        frame_id = str(payload.get("frame_id", payload.get("object", "")))

        if kind in {"Frame", "ProblemFrame"}:
            frame = Frame.from_payload(payload)
            if not frame.frame_id:
                raise FoldError(f"frame payload in {envelope.eid} has no frame_id")
            record = next_state.setdefault(frame.frame_id, {})
            record["frame"] = frame.to_json()
            record.setdefault("status", Status.INACTIVE.value)
        elif kind == "Proposed":
            _require(frame_id, "frame_id", envelope)
            record = next_state.setdefault(frame_id, {})
            record["status"] = Status.INACTIVE.value
        elif kind == "Activated":
            _require(frame_id, "frame_id", envelope)
            record = next_state.setdefault(frame_id, {})
            record["status"] = Status.ACTIVE.value
            record["activated_by"] = envelope.eid
        elif kind == "DiagnosticActivated":
            _require(frame_id, "frame_id", envelope)
            record = next_state.setdefault(frame_id, {})
            record["status"] = Status.DIAGNOSTIC_ACTIVE.value
        elif kind == "Suspended":
            _require(frame_id, "frame_id", envelope)
            record = next_state.setdefault(frame_id, {})
            record["status"] = Status.SUSPENDED.value
        elif kind == "Invalidated":
            _require(frame_id, "frame_id", envelope)
            record = next_state.setdefault(frame_id, {})
            record["status"] = Status.INVALID.value
        elif kind == "Withdrawn":
            _require(frame_id, "frame_id", envelope)
            record = next_state.setdefault(frame_id, {})
            record["status"] = Status.WITHDRAWN.value
        return next_state


class CertificateComponent:
    name = "certificates"

    def initial_state(self) -> dict[str, dict[str, Any]]:
        return {}

    def apply(self, state: dict[str, dict[str, Any]], envelope: Envelope) -> dict[str, dict[str, Any]]:
        next_state = deepcopy(state)
        payload = envelope.payload
        kind = envelope.kind
        if kind == "Issue":
            cert_id = str(payload.get("cert_id", payload.get("object", "")))
            _require(cert_id, "cert_id", envelope)
            if cert_id in next_state and next_state[cert_id].get("issued"):
                raise FoldError(f"certificate {cert_id} is issued twice")
            next_state[cert_id] = {
                "issued": True,
                "issued_at": envelope.commit_time,
                "issuer": payload.get("issuer", envelope.writer),
                "family": payload.get("family", ""),
                "subject": payload.get("subject", payload.get("object", "")),
                "expires_at": payload.get("expires_at"),
                "dependencies": list(payload.get("dependencies", ())),
                "source_ids": list(payload.get("source_ids", ())),
                "dependency_digest": payload.get("dependency_digest"),
                "family_check": payload.get("family_check"),
                "assumption": payload.get("assumption"),
                "revoked_at": None,
                "payload_eid": envelope.eid,
            }
        elif kind in {"Revoke", "CapRevoked"}:
            cert_id = str(payload.get("cert_id", ""))
            if cert_id:
                record = next_state.get(cert_id)
                if record is None:
                    raise FoldError(f"cannot revoke unknown certificate {cert_id}")
                if record.get("revoked_at") is not None:
                    raise FoldError(f"certificate {cert_id} is revoked twice")
                record["revoked_at"] = envelope.commit_time
        return next_state


class CapabilityComponent:
    name = "capabilities"

    def initial_state(self) -> dict[str, dict[str, Any]]:
        return {}

    def apply(self, state: dict[str, dict[str, Any]], envelope: Envelope) -> dict[str, dict[str, Any]]:
        next_state = deepcopy(state)
        payload = envelope.payload
        kind = envelope.kind
        if kind in {"MintCap", "CapMinted"}:
            cap_id = str(payload.get("capability_id", payload.get("cap_id", payload.get("object", ""))))
            _require(cap_id, "capability_id", envelope)
            if cap_id in next_state:
                raise FoldError(f"capability {cap_id} is minted twice")
            next_state[cap_id] = {
                "status": "unused",
                "frame_id": payload.get("frame_id"),
                "action": payload.get("action"),
                "source_digest": payload.get("source_digest"),
                "minted_at": envelope.commit_time,
                "expires_at": payload.get("expires_at"),
            }
        elif kind in {"UseCap", "CapUsed"}:
            cap_id = str(payload.get("capability_id", payload.get("cap_id", "")))
            record = _get(next_state, cap_id, "capability", envelope)
            if record.get("status") != "unused":
                raise FoldError(f"capability {cap_id} is not live")
            record["status"] = "used"
            record["outbox_id"] = payload.get("outbox_id")
            record["used_at"] = envelope.commit_time
        elif kind in {"RevokeCap", "CapRevoked"}:
            cap_id = str(payload.get("capability_id", payload.get("cap_id", "")))
            if cap_id:
                record = _get(next_state, cap_id, "capability", envelope)
                if record.get("status") == "used":
                    raise FoldError(f"capability {cap_id} is already used")
                record["status"] = "revoked"
        elif kind in {"ExpireCap", "CapExpired"}:
            cap_id = str(payload.get("capability_id", payload.get("cap_id", "")))
            record = _get(next_state, cap_id, "capability", envelope)
            if record.get("status") == "used":
                raise FoldError(f"capability {cap_id} is already used")
            record["status"] = "expired"
        return next_state


class ResourceComponent:
    name = "resources"

    def initial_state(self) -> dict[str, dict[str, Any]]:
        return {}

    def apply(self, state: dict[str, dict[str, Any]], envelope: Envelope) -> dict[str, dict[str, Any]]:
        next_state = deepcopy(state)
        payload = envelope.payload
        kind = envelope.kind
        if kind == "ReserveResource":
            lease_id = str(payload.get("lease_id", payload.get("object", "")))
            _require(lease_id, "lease_id", envelope)
            if lease_id in next_state:
                raise FoldError(f"resource lease {lease_id} is reserved twice")
            next_state[lease_id] = {
                "status": "leased",
                "token_id": payload.get("token_id"),
                "frame_id": payload.get("frame_id"),
                "amount": payload.get("amount", 1),
                "reserved_at": envelope.commit_time,
            }
        elif kind == "ConsumeResource":
            lease_id = str(payload.get("lease_id", payload.get("object", "")))
            record = _get(next_state, lease_id, "resource lease", envelope)
            if record.get("status") != "leased":
                raise FoldError(f"resource lease {lease_id} is not leased")
            record["status"] = "consumed"
            record["consumed_at"] = envelope.commit_time
            record["consumer"] = payload.get("consumer")
        elif kind == "ReleaseResource":
            lease_id = str(payload.get("lease_id", payload.get("object", "")))
            record = _get(next_state, lease_id, "resource lease", envelope)
            if record.get("status") != "leased":
                raise FoldError(f"resource lease {lease_id} is not leased")
            record["status"] = "released"
        return next_state


class OutboxComponent:
    name = "outboxes"

    def initial_state(self) -> dict[str, dict[str, Any]]:
        return {}

    def apply(self, state: dict[str, dict[str, Any]], envelope: Envelope) -> dict[str, dict[str, Any]]:
        next_state = deepcopy(state)
        payload = envelope.payload
        kind = envelope.kind
        outbox_id = str(payload.get("outbox_id", payload.get("object", "")))
        if kind == "AuthorizeOutbox":
            _require(outbox_id, "outbox_id", envelope)
            if outbox_id in next_state:
                raise FoldError(f"outbox {outbox_id} is authorized twice")
            next_state[outbox_id] = {
                "status": "authorized",
                "frame_id": payload.get("frame_id"),
                "action": payload.get("action"),
                "authorized_at": envelope.commit_time,
            }
        elif kind == "OutboxClaim":
            record = _get(next_state, outbox_id, "outbox", envelope)
            if record.get("status") != "authorized":
                raise FoldError(f"outbox {outbox_id} is not authorized")
            record["status"] = "claimed"
            record["gate_id"] = payload.get("gate_id")
            record["claimed_at"] = envelope.commit_time
        elif kind == "RevokeOutbox":
            record = _get(next_state, outbox_id, "outbox", envelope)
            if record.get("status") != "authorized":
                raise FoldError(f"outbox {outbox_id} is not authorized")
            record["status"] = "revoked"
        elif kind in {
            "DispatchStarted",
            "ActuatorAccepted",
            "ActuatorRejected",
            "ReceiptCommitted",
            "ReceiptMissing",
            "ReceiptConflict",
        }:
            record = _get(next_state, outbox_id, "outbox", envelope)
            transitions = {
                "DispatchStarted": {"claimed"},
                "ActuatorAccepted": {"dispatchStarted"},
                "ActuatorRejected": {"dispatchStarted"},
                "ReceiptCommitted": {"actuatorAccepted"},
                "ReceiptMissing": {"actuatorAccepted"},
                "ReceiptConflict": {"actuatorAccepted"},
            }
            if record.get("status") not in transitions[kind]:
                raise FoldError(f"outbox {outbox_id} cannot transition to {kind}")
            record["status"] = {
                "DispatchStarted": "dispatchStarted",
                "ActuatorAccepted": "actuatorAccepted",
                "ActuatorRejected": "actuatorRejected",
                "ReceiptCommitted": "receiptCommitted",
                "ReceiptMissing": "receiptMissing",
                "ReceiptConflict": "receiptConflict",
            }[kind]
        return next_state


class RiskComponent:
    name = "risk"

    def initial_state(self) -> dict[str, Any]:
        return {"hypotheses": {}, "reserves": {}, "spends": {}}

    def apply(self, state: dict[str, Any], envelope: Envelope) -> dict[str, Any]:
        next_state = deepcopy(state)
        payload = envelope.payload
        kind = envelope.kind
        if kind == "RiskReg":
            hyp = str(payload.get("hypothesis_id", payload.get("hypothesis", payload.get("object", ""))))
            _require(hyp, "hypothesis_id", envelope)
            if hyp in next_state["hypotheses"]:
                raise FoldError(f"hypothesis {hyp} is registered twice")
            next_state["hypotheses"][hyp] = {
                "family": payload.get("family"),
                "registered_at": envelope.commit_time,
            }
        elif kind == "RiskReserve":
            risk_id = str(payload.get("risk_id", payload.get("object", "")))
            _require(risk_id, "risk_id", envelope)
            if risk_id in next_state["reserves"]:
                raise FoldError(f"risk id {risk_id} is reserved twice")
            next_state["reserves"][risk_id] = {
                "hypothesis_id": payload.get("hypothesis_id"),
                "frame_id": payload.get("frame_id"),
                "eta": _fraction_text(payload.get("eta", "0")),
                "reserved_at": envelope.commit_time,
            }
        elif kind == "RiskSpend":
            risk_id = str(payload.get("risk_id", payload.get("object", "")))
            reserve = _get(next_state["reserves"], risk_id, "risk reserve", envelope)
            if risk_id in next_state["spends"]:
                raise FoldError(f"risk id {risk_id} is spent twice")
            next_state["spends"][risk_id] = {
                "hypothesis_id": payload.get("hypothesis_id", reserve.get("hypothesis_id")),
                "frame_id": payload.get("frame_id", reserve.get("frame_id")),
                "eta": _fraction_text(payload.get("eta", reserve.get("eta", "0"))),
                "mode": payload.get("mode"),
                "cert_id": payload.get("cert_id"),
                "ledger_digest": payload.get("ledger_digest"),
                "spent_at": envelope.commit_time,
                "closed_at": None,
            }
        elif kind == "RiskClose":
            risk_id = str(payload.get("risk_id", payload.get("object", "")))
            spend = _get(next_state["spends"], risk_id, "risk spend", envelope)
            if spend.get("closed_at") is not None:
                raise FoldError(f"risk id {risk_id} is closed twice")
            spend["closed_at"] = envelope.commit_time
        return next_state


class EvidenceComponent:
    name = "evidence"

    def initial_state(self) -> dict[str, dict[str, Any]]:
        return {}

    def apply(self, state: dict[str, dict[str, Any]], envelope: Envelope) -> dict[str, dict[str, Any]]:
        next_state = deepcopy(state)
        payload = envelope.payload
        kind = envelope.kind
        if kind in {"Record", "Evidence", "Source"}:
            evidence_id = str(payload.get("evidence_id", payload.get("source_id", payload.get("object", ""))))
            _require(evidence_id, "evidence_id", envelope)
            next_state[evidence_id] = {
                "kind": kind,
                "record_id": payload.get("record_id"),
                "digest": payload.get("digest"),
                "committed_at": envelope.commit_time,
                "eid": envelope.eid,
            }
        return next_state


def default_components() -> tuple[StateComponent, ...]:
    return (
        FrameComponent(),
        CertificateComponent(),
        EvidenceComponent(),
        CapabilityComponent(),
        ResourceComponent(),
        OutboxComponent(),
        RiskComponent(),
    )


def _require(value: str, field_name: str, envelope: Envelope) -> None:
    if not value:
        raise FoldError(f"{field_name} is required in envelope {envelope.eid}")


def _get(state: dict[str, Any], key: str, label: str, envelope: Envelope) -> dict[str, Any]:
    if not key or key not in state:
        raise FoldError(f"unknown {label} {key!r} in envelope {envelope.eid}")
    record = state[key]
    if not isinstance(record, dict):
        raise FoldError(f"{label} {key!r} has invalid state")
    return record


def _fraction_text(value: Any) -> str:
    return str(Fraction(str(value)))
