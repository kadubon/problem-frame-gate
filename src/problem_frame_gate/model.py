"""Portable data model for finite audit logs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

JsonMap = Mapping[str, Any]
DEFAULT_GATE_BUNDLE_KINDS = ("GateCheck", "OutboxClaim", "UseCap", "ConsumeResource", "RiskClose")
DEFAULT_RISK_MODES = ("fixed", "selectedEvent", "conditionalSelective", "anytime")
DEFAULT_PROTECTED_CONSTRUCTORS = {
    "GateCheck": ("executor-gate",),
    "OutboxClaim": ("executor-gate",),
    "UseCap": ("executor-gate",),
    "ConsumeResource": ("executor-gate",),
    "RiskClose": ("executor-gate",),
}


class EnvelopeClass(str, Enum):
    NORMAL = "normal"
    ABORT = "abort"
    FAIL_CLOSED = "failClosed"


class ClauseRole(str, Enum):
    INVARIANT = "invariant"
    LIVENESS = "liveness"


class Status(str, Enum):
    INACTIVE = "inactive"
    ACTIVE = "active"
    DIAGNOSTIC_ACTIVE = "diagnosticActive"
    SUSPENDED = "suspended"
    INVALID = "invalid"
    BLOCKED = "blocked"
    WITHDRAWN = "withdrawn"


@dataclass(frozen=True, slots=True)
class OrderEdge:
    before: str
    after: str

    @classmethod
    def from_value(cls, value: Sequence[str] | Mapping[str, str]) -> OrderEdge:
        if isinstance(value, Mapping):
            return cls(str(value["before"]), str(value["after"]))
        if len(value) != 2:
            raise ValueError("order edge must contain exactly two event ids")
        return cls(str(value[0]), str(value[1]))

    def to_json(self) -> list[str]:
        return [self.before, self.after]


@dataclass(frozen=True, slots=True)
class VersionInterval:
    minimum: int = 1
    maximum: int = 1

    @classmethod
    def from_value(cls, value: Sequence[int] | Mapping[str, int]) -> VersionInterval:
        if isinstance(value, Mapping):
            return cls(
                int(value.get("minimum", value.get("min", 1))),
                int(value.get("maximum", value.get("max", 1))),
            )
        if len(value) != 2:
            raise ValueError("version interval must contain two bounds")
        return cls(int(value[0]), int(value[1]))

    def contains(self, version: int) -> bool:
        return self.minimum <= version <= self.maximum

    def to_json(self) -> dict[str, int]:
        return {"minimum": self.minimum, "maximum": self.maximum}


@dataclass(frozen=True, slots=True)
class DependencyRef:
    """A dependency by envelope id, or by event plus slot."""

    eid: str | None = None
    event: str | None = None
    slot: str | None = None

    @classmethod
    def from_value(cls, value: str | Mapping[str, Any]) -> DependencyRef:
        if isinstance(value, str):
            return cls(eid=value)
        return cls(
            eid=str(value["eid"]) if value.get("eid") is not None else None,
            event=str(value["event"]) if value.get("event") is not None else None,
            slot=str(value["slot"]) if value.get("slot") is not None else None,
        )

    def to_json(self) -> dict[str, str]:
        data: dict[str, str] = {}
        if self.eid is not None:
            data["eid"] = self.eid
        if self.event is not None:
            data["event"] = self.event
        if self.slot is not None:
            data["slot"] = self.slot
        return data


@dataclass(frozen=True, slots=True)
class Envelope:
    """One append-only audit-log envelope."""

    eid: str
    event: str
    slot: str
    commit_time: int
    writer: str
    owner: str
    version: int
    envelope_class: EnvelopeClass
    payload: JsonMap
    dependencies: tuple[DependencyRef, ...] = ()
    commit_group: str | None = None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Envelope:
        payload = value.get("payload")
        if not isinstance(payload, Mapping):
            raise ValueError("envelope payload must be a JSON object")
        return cls(
            eid=str(value["eid"]),
            event=str(value["event"]),
            slot=str(value.get("slot", value.get("lambda", ""))),
            commit_time=int(value.get("commit_time", value.get("commit", 0))),
            writer=str(value["writer"]),
            owner=str(value.get("owner", "")),
            version=int(value.get("version", 1)),
            envelope_class=EnvelopeClass(value.get("class", value.get("envelope_class", "normal"))),
            payload=dict(payload),
            dependencies=tuple(DependencyRef.from_value(dep) for dep in value.get("dependencies", ())),
            commit_group=str(value["commit_group"]) if value.get("commit_group") is not None else None,
        )

    @property
    def kind(self) -> str:
        kind = self.payload.get("kind")
        if not isinstance(kind, str) or not kind:
            raise ValueError(f"envelope {self.eid} payload.kind must be a non-empty string")
        return kind

    @property
    def object_key(self) -> str:
        for key in (
            "object",
            "object_id",
            "frame_id",
            "cert_id",
            "capability_id",
            "risk_id",
            "outbox_id",
            "lease_id",
            "evidence_id",
            "source_id",
            "gate_id",
            "bundle_id",
        ):
            value = self.payload.get(key)
            if value is not None:
                return str(value)
        return ""

    @property
    def protected_slot(self) -> tuple[str, str, str, str]:
        return (self.event, self.slot, self.kind, self.object_key)

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "eid": self.eid,
            "event": self.event,
            "slot": self.slot,
            "commit": self.commit_time,
            "writer": self.writer,
            "owner": self.owner,
            "version": self.version,
            "class": self.envelope_class.value,
            "payload": dict(self.payload),
        }
        if self.dependencies:
            data["dependencies"] = [dep.to_json() for dep in self.dependencies]
        if self.commit_group:
            data["commit_group"] = self.commit_group
        return data


@dataclass(frozen=True, slots=True)
class Horizon:
    """Finite verifier configuration.

    This is strict by default.  Empty safety tables are rejected by the verifier.
    Use :meth:`unsafe_for_tests` only for deliberately weak unit fixtures.
    """

    strict: bool = True
    events: tuple[str, ...] = ()
    causal_order: tuple[OrderEdge, ...] = ()
    availability_order: tuple[OrderEdge, ...] = ()
    audit_order: tuple[OrderEdge, ...] = ()
    capacities: Mapping[EnvelopeClass, int] = field(default_factory=dict)
    writer_authority: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    version_intervals: Mapping[str, VersionInterval] = field(default_factory=dict)
    commit_groups: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    protected_constructors: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    gate_bundle_kinds: tuple[str, ...] = DEFAULT_GATE_BUNDLE_KINDS
    executor_writer: str = "executor-gate"
    clock_policy: str = "integer-commit-time"
    certificate_families: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    risk_modes: tuple[str, ...] = DEFAULT_RISK_MODES
    env_assumptions: tuple[str, ...] = ()
    codebook: tuple[str, ...] = ()
    allow_local_paths: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Horizon:
        return cls(
            strict=bool(value.get("strict", True)),
            events=tuple(str(v) for v in value.get("events", ())),
            causal_order=_edges(value.get("causal_order", ())),
            availability_order=_edges(value.get("availability_order", ())),
            audit_order=_edges(value.get("audit_order", ())),
            capacities={EnvelopeClass(k): int(v) for k, v in value.get("capacities", {}).items()},
            writer_authority={
                str(k): tuple(str(writer) for writer in writers)
                for k, writers in value.get("writer_authority", {}).items()
            },
            version_intervals={
                str(k): VersionInterval.from_value(v) for k, v in value.get("version_intervals", {}).items()
            },
            commit_groups={
                str(k): tuple(str(eid) for eid in eids) for k, eids in value.get("commit_groups", {}).items()
            },
            protected_constructors={
                str(k): tuple(str(writer) for writer in writers)
                for k, writers in value.get("protected_constructors", {}).items()
            },
            gate_bundle_kinds=tuple(str(v) for v in value.get("gate_bundle_kinds", DEFAULT_GATE_BUNDLE_KINDS)),
            executor_writer=str(value.get("executor_writer", "executor-gate")),
            clock_policy=str(value.get("clock_policy", "integer-commit-time")),
            certificate_families={
                str(k): tuple(str(issuer) for issuer in issuers)
                for k, issuers in value.get("certificate_families", {}).items()
            },
            risk_modes=tuple(str(v) for v in value.get("risk_modes", DEFAULT_RISK_MODES)),
            env_assumptions=tuple(str(v) for v in value.get("env_assumptions", ())),
            codebook=tuple(str(v) for v in value.get("codebook", ())),
            allow_local_paths=bool(value.get("allow_local_paths", False)),
        )

    @classmethod
    def strict_default(
        cls,
        *,
        agent_writers: tuple[str, ...] = ("agent",),
        executor_writer: str = "executor-gate",
        normal_capacity: int = 1000,
        abort_capacity: int = 100,
        fail_closed_capacity: int = 10,
    ) -> Horizon:
        """Return a strict manifest suitable for examples and production templates."""

        protected = dict.fromkeys(DEFAULT_GATE_BUNDLE_KINDS, (executor_writer,))
        writer_authority: dict[str, tuple[str, ...]] = {"*": (*agent_writers, executor_writer)}
        writer_authority.update(protected)
        return cls(
            strict=True,
            capacities={
                EnvelopeClass.NORMAL: normal_capacity,
                EnvelopeClass.ABORT: abort_capacity,
                EnvelopeClass.FAIL_CLOSED: fail_closed_capacity,
            },
            writer_authority=writer_authority,
            version_intervals={"*": VersionInterval(1, 1)},
            protected_constructors=protected,
            gate_bundle_kinds=DEFAULT_GATE_BUNDLE_KINDS,
            executor_writer=executor_writer,
            certificate_families={
                "source": agent_writers,
                "risk": agent_writers,
                "approval": agent_writers,
                "safety": agent_writers,
                "formation": agent_writers,
            },
            risk_modes=DEFAULT_RISK_MODES,
            codebook=DEFAULT_RISK_MODES,
        )

    @classmethod
    def unsafe_for_tests(cls) -> Horizon:
        """Return a deliberately weak manifest for tests that do not model authority."""

        return cls(
            strict=False,
            protected_constructors={},
            gate_bundle_kinds=(),
            allow_local_paths=False,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "strict": self.strict,
            "events": list(self.events),
            "causal_order": [edge.to_json() for edge in self.causal_order],
            "availability_order": [edge.to_json() for edge in self.availability_order],
            "audit_order": [edge.to_json() for edge in self.audit_order],
            "capacities": {key.value: value for key, value in self.capacities.items()},
            "writer_authority": {key: list(value) for key, value in self.writer_authority.items()},
            "version_intervals": {key: value.to_json() for key, value in self.version_intervals.items()},
            "commit_groups": {key: list(value) for key, value in self.commit_groups.items()},
            "protected_constructors": {key: list(value) for key, value in self.protected_constructors.items()},
            "gate_bundle_kinds": list(self.gate_bundle_kinds),
            "executor_writer": self.executor_writer,
            "clock_policy": self.clock_policy,
            "certificate_families": {key: list(value) for key, value in self.certificate_families.items()},
            "risk_modes": list(self.risk_modes),
            "env_assumptions": list(self.env_assumptions),
            "codebook": list(self.codebook),
            "allow_local_paths": self.allow_local_paths,
        }


@dataclass(frozen=True, slots=True)
class StrictManifest(Horizon):
    """Named strict manifest type for public APIs."""

    @classmethod
    def minimal(cls, **kwargs: Any) -> StrictManifest:
        horizon = Horizon.strict_default(**kwargs)
        return cls.from_mapping(horizon.to_json())

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> StrictManifest:
        horizon = Horizon.from_mapping(value)
        data = horizon.to_json()
        data["strict"] = True
        return cls(
            strict=True,
            events=tuple(data["events"]),
            causal_order=_edges(data["causal_order"]),
            availability_order=_edges(data["availability_order"]),
            audit_order=_edges(data["audit_order"]),
            capacities={EnvelopeClass(k): int(v) for k, v in data["capacities"].items()},
            writer_authority={k: tuple(v) for k, v in data["writer_authority"].items()},
            version_intervals={k: VersionInterval.from_value(v) for k, v in data["version_intervals"].items()},
            commit_groups={k: tuple(v) for k, v in data["commit_groups"].items()},
            protected_constructors={k: tuple(v) for k, v in data["protected_constructors"].items()},
            gate_bundle_kinds=tuple(data["gate_bundle_kinds"]),
            executor_writer=str(data["executor_writer"]),
            clock_policy=str(data["clock_policy"]),
            certificate_families={k: tuple(v) for k, v in data["certificate_families"].items()},
            risk_modes=tuple(data["risk_modes"]),
            env_assumptions=tuple(data["env_assumptions"]),
            codebook=tuple(data["codebook"]),
            allow_local_paths=bool(data["allow_local_paths"]),
        )


@dataclass(frozen=True, slots=True)
class Frame:
    """A bounded decision or problem frame controlled by the audit log."""

    frame_id: str
    scope: str
    goal: str
    evidence_ids: tuple[str, ...]
    actions: tuple[str, ...]
    acceptance: tuple[str, ...]
    resources: tuple[str, ...] = ()
    risk_ids: tuple[str, ...] = ()
    obligations: tuple[str, ...] = ()
    provenance: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Frame:
        return cls(
            frame_id=str(payload.get("frame_id", payload.get("object", ""))),
            scope=str(payload.get("scope", "")),
            goal=str(payload.get("goal", "")),
            evidence_ids=tuple(str(v) for v in payload.get("evidence_ids", ())),
            actions=tuple(str(v) for v in payload.get("actions", ())),
            acceptance=tuple(str(v) for v in payload.get("acceptance", ())),
            resources=tuple(str(v) for v in payload.get("resources", ())),
            risk_ids=tuple(str(v) for v in payload.get("risk_ids", ())),
            obligations=tuple(str(v) for v in payload.get("obligations", ())),
            provenance=dict(payload.get("provenance", {})),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "frame_id": self.frame_id,
            "scope": self.scope,
            "goal": self.goal,
            "evidence_ids": list(self.evidence_ids),
            "actions": list(self.actions),
            "acceptance": list(self.acceptance),
            "resources": list(self.resources),
            "risk_ids": list(self.risk_ids),
            "obligations": list(self.obligations),
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class AuditTranscript:
    """Finite record of objects read by a checker."""

    checker: str
    objects: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()
    frontiers: tuple[str, ...] = ()
    clocks: tuple[str, ...] = ()
    capacities: tuple[str, ...] = ()
    digests: tuple[str, ...] = ()
    swaps: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "checker": self.checker,
            "objects": list(self.objects),
            "reads": list(self.reads),
            "frontiers": list(self.frontiers),
            "clocks": list(self.clocks),
            "capacities": list(self.capacities),
            "digests": list(self.digests),
            "swaps": list(self.swaps),
        }


def _edges(values: Sequence[Any]) -> tuple[OrderEdge, ...]:
    return tuple(OrderEdge.from_value(value) for value in values)
