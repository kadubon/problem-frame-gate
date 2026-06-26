"""Append-only patch installation checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .fold import FoldKernel, FoldState
from .model import Envelope, Horizon
from .result import CheckBuilder, CheckResult
from .verifier import digest_log

Invariant = Callable[[FoldState, Sequence[Envelope]], CheckResult]


@dataclass(frozen=True, slots=True)
class ReadFootprint:
    invariant: str
    entries: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {"invariant": self.invariant, "entries": list(self.entries)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReadFootprint:
        return cls(str(value["invariant"]), tuple(str(item) for item in _sequence(value["entries"])))


@dataclass(frozen=True, slots=True)
class WriteClass:
    name: str
    object_id: str = ""

    def to_json(self) -> dict[str, str]:
        return {"name": self.name, "object_id": self.object_id}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> WriteClass:
        return cls(str(value["name"]), str(value.get("object_id", "")))


@dataclass(frozen=True, slots=True)
class WriteCover:
    classes: tuple[WriteClass, ...]
    covered_eids: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "classes": [write.to_json() for write in self.classes],
            "covered_eids": list(self.covered_eids),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> WriteCover:
        return cls(
            classes=tuple(WriteClass.from_mapping(_mapping(item)) for item in _sequence(value["classes"])),
            covered_eids=tuple(str(item) for item in _sequence(value["covered_eids"])),
        )


@dataclass(frozen=True, slots=True)
class TouchMatrix:
    cells: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def key(write_class: WriteClass, read_entry: str) -> str:
        return f"{write_class.name}:{write_class.object_id}|{read_entry}"

    def verdict(self, write_class: WriteClass, read_entry: str) -> str | None:
        return self.cells.get(self.key(write_class, read_entry))

    def to_json(self) -> dict[str, str]:
        return dict(self.cells)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> TouchMatrix:
        return cls({str(key): str(item) for key, item in value.items()})


@dataclass(frozen=True, slots=True)
class AffectedClauseSet:
    clauses: tuple[str, ...]

    def to_json(self) -> list[str]:
        return list(self.clauses)

    @classmethod
    def from_mapping(cls, value: Sequence[Any]) -> AffectedClauseSet:
        return cls(tuple(str(item) for item in value))


@dataclass(frozen=True, slots=True)
class PatchProposal:
    expected_source_digest: str
    append: tuple[Envelope, ...]
    affected_invariants: tuple[str, ...] = ()
    write_classes: tuple[WriteClass, ...] = ()
    write_cover: WriteCover | None = None
    read_footprints: tuple[ReadFootprint, ...] = ()
    touch_matrix: TouchMatrix = field(default_factory=TouchMatrix)
    transported_cells: tuple[str, ...] = ()
    liveness_repairs: tuple[str, ...] = ()
    transcript_digest: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "expected_source_digest": self.expected_source_digest,
            "append": [env.to_json() for env in self.append],
            "affected_invariants": list(self.affected_invariants),
            "write_classes": [write.to_json() for write in self.write_classes],
            "write_cover": self.write_cover.to_json() if self.write_cover else None,
            "read_footprints": [read.to_json() for read in self.read_footprints],
            "touch_matrix": self.touch_matrix.to_json(),
            "transported_cells": list(self.transported_cells),
            "liveness_repairs": list(self.liveness_repairs),
            "transcript_digest": self.transcript_digest,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> PatchProposal:
        write_cover_value = value.get("write_cover")
        touch_matrix_value = value.get("touch_matrix", {})
        if not isinstance(touch_matrix_value, Mapping):
            raise TypeError("touch_matrix must be an object")
        return cls(
            expected_source_digest=str(value["expected_source_digest"]),
            append=tuple(Envelope.from_mapping(_mapping(item)) for item in _sequence(value["append"])),
            affected_invariants=tuple(str(item) for item in _sequence(value.get("affected_invariants", ()))),
            write_classes=tuple(
                WriteClass.from_mapping(_mapping(item)) for item in _sequence(value.get("write_classes", ()))
            ),
            write_cover=WriteCover.from_mapping(write_cover_value) if isinstance(write_cover_value, Mapping) else None,
            read_footprints=tuple(
                ReadFootprint.from_mapping(_mapping(item)) for item in _sequence(value.get("read_footprints", ()))
            ),
            touch_matrix=TouchMatrix.from_mapping(touch_matrix_value),
            transported_cells=tuple(str(item) for item in _sequence(value.get("transported_cells", ()))),
            liveness_repairs=tuple(str(item) for item in _sequence(value.get("liveness_repairs", ()))),
            transcript_digest=str(value["transcript_digest"]) if value.get("transcript_digest") is not None else None,
        )


class PatchChecker:
    """Finite patch-preservation checker."""

    footprint = frozenset({"PatchKernel", "FoldKernel", "EnvelopeVerifier", "ClauseKernel"})

    def __init__(self, fold_kernel: FoldKernel | None = None) -> None:
        self.fold_kernel = fold_kernel or FoldKernel()

    def check(
        self,
        horizon: Horizon,
        source: Sequence[Envelope],
        proposal: PatchProposal,
        *,
        invariants: dict[str, Invariant] | None = None,
    ) -> CheckResult:
        builder = CheckBuilder(footprint=set(self.footprint))
        source_digest = digest_log(source)
        if proposal.expected_source_digest != source_digest:
            builder.error(
                "patch-source-digest",
                "source digest does not match patch proposal",
                details={"expected": proposal.expected_source_digest, "actual": source_digest},
            )

        source_ids = {env.eid for env in source}
        duplicate_appends = [env.eid for env in proposal.append if env.eid in source_ids]
        if duplicate_appends:
            builder.error(
                "patch-not-append-only",
                "patch contains existing envelope ids",
                details={"eids": duplicate_appends},
            )

        try:
            source_folded = self.fold_kernel.fold(horizon, source)
        except Exception as exc:
            builder.error("patch-source-fold", f"patch source is not a legal folded log: {exc}")
            return builder.result(digest=source_digest)

        self._check_write_universe(proposal, builder)
        self._check_footprints(proposal, invariants or {}, builder)
        self._check_transported_cells(proposal, builder)

        target = tuple(source) + tuple(proposal.append)
        try:
            folded = self.fold_kernel.fold(horizon, target)
        except Exception as exc:
            builder.error("patch-target-fold", f"patch target is not a legal folded log: {exc}")
            return builder.result(digest=source_digest)

        for name, invariant in (invariants or {}).items():
            if name not in proposal.affected_invariants:
                builder.warning(
                    "patch-invariant-not-rechecked",
                    "invariant was supplied but not listed as affected",
                    location=name,
                )
                continue
            result = invariant(folded, target)
            if not result.ok:
                for issue in result.issues:
                    builder.error(issue.code, issue.message, location=issue.location, details=issue.details)
        self._check_frame_invalidation(source_folded, folded, proposal, builder)

        return builder.result(digest=digest_log(target))

    def _check_write_universe(self, proposal: PatchProposal, builder: CheckBuilder) -> None:
        if proposal.append and proposal.write_cover is None:
            builder.error(
                "patch-write-universe",
                "strict patch must carry a write cover for the finite write universe touched by appended rows",
            )
            if not proposal.write_classes:
                return
        declared = tuple(proposal.write_cover.classes if proposal.write_cover else proposal.write_classes)
        declared_keys = {_write_key(write) for write in declared}
        for env in proposal.append:
            try:
                write = _write_class_for(env)
            except ValueError as exc:
                builder.error("patch-write-class", str(exc), location=env.eid)
                continue
            if _write_key(write) not in declared_keys and (write.name, "") not in declared_keys:
                builder.error(
                    "patch-write-universe",
                    "appended row is not covered by the declared write universe",
                    location=env.eid,
                    details={"write": write.to_json()},
                )
        if proposal.write_cover is not None:
            expected_eids = tuple(sorted(env.eid for env in proposal.append))
            actual_eids = tuple(sorted(proposal.write_cover.covered_eids))
            if actual_eids != expected_eids:
                builder.error(
                    "patch-write-cover",
                    "write cover must cite exactly the appended envelope ids",
                    details={"expected": list(expected_eids), "actual": list(actual_eids)},
                )

    def _check_footprints(
        self,
        proposal: PatchProposal,
        invariants: dict[str, Invariant],
        builder: CheckBuilder,
    ) -> None:
        footprint_by_invariant = {footprint.invariant: footprint for footprint in proposal.read_footprints}
        affected = set(proposal.affected_invariants)
        writes = proposal.write_cover.classes if proposal.write_cover else proposal.write_classes
        for name in invariants:
            footprint = footprint_by_invariant.get(name)
            if footprint is None:
                builder.error("patch-footprint-missing", "invariant has no read footprint witness", location=name)
                continue
            touched = False
            for write in writes:
                for read_entry in footprint.entries:
                    verdict = proposal.touch_matrix.verdict(write, read_entry)
                    if verdict not in {"touch", "non_touch"}:
                        builder.error(
                            "patch-touch-cell",
                            "touch matrix must classify every write/read pair",
                            location=name,
                            details={"write": write.to_json(), "read": read_entry},
                        )
                    touched = touched or verdict == "touch"
            if touched and name not in affected:
                builder.error(
                    "patch-affected-completeness",
                    "touched invariant is missing from affected set",
                    location=name,
                )

    def _check_transported_cells(self, proposal: PatchProposal, builder: CheckBuilder) -> None:
        transported = set(proposal.transported_cells)
        for env in proposal.append:
            key = _linear_cell_key(env)
            if key and key not in transported:
                builder.error(
                    "patch-transported-cell",
                    "linear resource/outbox/capability/risk write must cite a transported cell",
                    location=env.eid,
                    details={"cell": key},
                )

    def _check_frame_invalidation(
        self, source: FoldState, folded: FoldState, proposal: PatchProposal, builder: CheckBuilder
    ) -> None:
        non_active_frames = {
            str(env.payload.get("frame_id", env.payload.get("object", "")))
            for env in proposal.append
            if env.kind in {"Suspended", "Invalidated", "Withdrawn"}
        }
        liveness_repairs = set(proposal.liveness_repairs)
        for frame_id in non_active_frames:
            for cap_id, cap in source.component("capabilities").items():
                if cap.get("frame_id") == frame_id and cap.get("status") == "unused":
                    repair_key = f"capability:{cap_id}"
                    if repair_key not in liveness_repairs:
                        builder.error(
                            "patch-liveness-repair-witness",
                            "frame non-activation must cite the capability liveness repair",
                            location=cap_id,
                            details={"repair": repair_key},
                        )
            for outbox_id, outbox in source.component("outboxes").items():
                if outbox.get("frame_id") == frame_id and outbox.get("status") == "authorized":
                    repair_key = f"outbox:{outbox_id}"
                    if repair_key not in liveness_repairs:
                        builder.error(
                            "patch-liveness-repair-witness",
                            "frame non-activation must cite the outbox liveness repair",
                            location=outbox_id,
                            details={"repair": repair_key},
                        )
            for lease_id, resource in source.component("resources").items():
                if resource.get("frame_id") == frame_id and resource.get("status") == "leased":
                    repair_key = f"resource:{lease_id}"
                    if repair_key not in liveness_repairs:
                        builder.error(
                            "patch-liveness-repair-witness",
                            "frame non-activation must cite the resource liveness repair",
                            location=lease_id,
                            details={"repair": repair_key},
                        )
            for risk_id, spend in source.component("risk").get("spends", {}).items():
                if spend.get("frame_id") == frame_id and spend.get("closed_at") is None:
                    repair_key = f"risk:{risk_id}"
                    if repair_key not in liveness_repairs:
                        builder.error(
                            "patch-liveness-repair-witness",
                            "frame non-activation must cite the risk liveness repair",
                            location=risk_id,
                            details={"repair": repair_key},
                        )
            for cap_id, cap in folded.component("capabilities").items():
                if cap.get("frame_id") == frame_id and cap.get("status") == "unused":
                    builder.error(
                        "patch-frame-invalidates-capability",
                        "non-active frame patch must revoke, expire, or use outstanding capabilities",
                        location=cap_id,
                    )
            for outbox_id, outbox in folded.component("outboxes").items():
                if outbox.get("frame_id") == frame_id and outbox.get("status") == "authorized":
                    builder.error(
                        "patch-frame-invalidates-outbox",
                        "non-active frame patch must revoke or block unclaimed outboxes",
                        location=outbox_id,
                    )
            for lease_id, resource in folded.component("resources").items():
                if resource.get("frame_id") == frame_id and resource.get("status") == "leased":
                    builder.error(
                        "patch-frame-invalidates-resource",
                        "non-active frame patch must consume or release outstanding resources",
                        location=lease_id,
                    )


def _write_class_for(env: Envelope) -> WriteClass:
    kind = env.kind
    payload = env.payload
    if kind in {"Suspended", "Invalidated", "Withdrawn", "Activated", "DiagnosticActivated", "Proposed"}:
        return WriteClass("FrameStatus", str(payload.get("frame_id", payload.get("object", ""))))
    if kind in {"Frame", "ProblemFrame"}:
        return WriteClass("Frame", str(payload.get("frame_id", payload.get("object", ""))))
    if kind in {"MintCap", "CapMinted", "UseCap", "CapUsed", "RevokeCap", "CapRevoked", "ExpireCap", "CapExpired"}:
        cap_id = payload.get("capability_id", payload.get("cap_id", payload.get("object", "")))
        return WriteClass("Capability", str(cap_id))
    if kind in {"ReserveResource", "ConsumeResource", "ReleaseResource"}:
        return WriteClass("Resource", str(payload.get("lease_id", payload.get("object", ""))))
    if kind in {
        "AuthorizeOutbox",
        "OutboxClaim",
        "RevokeOutbox",
        "DispatchStarted",
        "ActuatorAccepted",
        "ActuatorRejected",
        "ReceiptCommitted",
        "ReceiptMissing",
        "ReceiptConflict",
    }:
        return WriteClass("Outbox", str(payload.get("outbox_id", payload.get("object", ""))))
    if kind in {"RiskReg", "RiskReserve", "RiskSpend", "RiskClose"}:
        risk_id = payload.get("risk_id", payload.get("hypothesis_id", payload.get("object", "")))
        return WriteClass("Risk", str(risk_id))
    if kind in {"Issue", "Revoke"}:
        return WriteClass("Certificate", str(payload.get("cert_id", payload.get("object", ""))))
    if kind in {"Record", "Evidence", "Source"}:
        evidence_id = payload.get("evidence_id", payload.get("source_id", payload.get("object", "")))
        return WriteClass("Evidence", str(evidence_id))
    return WriteClass(kind, env.object_key)


def _write_key(write: WriteClass) -> tuple[str, str]:
    return (write.name, write.object_id)


def _linear_cell_key(env: Envelope) -> str:
    kind = env.kind
    payload = env.payload
    if kind in {"UseCap", "CapUsed"}:
        return f"capability:{payload.get('capability_id', payload.get('cap_id', ''))}"
    if kind == "ConsumeResource":
        return f"resource:{payload.get('lease_id', payload.get('object', ''))}"
    if kind == "OutboxClaim":
        return f"outbox:{payload.get('outbox_id', payload.get('object', ''))}"
    if kind == "RiskClose":
        return f"risk:{payload.get('risk_id', payload.get('object', ''))}"
    return ""


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("expected object mapping")
    return value


def _sequence(value: object) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise TypeError("expected sequence")
    return value
