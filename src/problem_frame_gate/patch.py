"""Append-only patch installation checks."""

from __future__ import annotations

from collections.abc import Callable, Sequence
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


@dataclass(frozen=True, slots=True)
class WriteClass:
    name: str
    object_id: str = ""

    def to_json(self) -> dict[str, str]:
        return {"name": self.name, "object_id": self.object_id}


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


@dataclass(frozen=True, slots=True)
class AffectedClauseSet:
    clauses: tuple[str, ...]

    def to_json(self) -> list[str]:
        return list(self.clauses)


@dataclass(frozen=True, slots=True)
class PatchProposal:
    expected_source_digest: str
    append: tuple[Envelope, ...]
    affected_invariants: tuple[str, ...] = ()
    write_classes: tuple[WriteClass, ...] = ()
    read_footprints: tuple[ReadFootprint, ...] = ()
    touch_matrix: TouchMatrix = field(default_factory=TouchMatrix)
    transcript_digest: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "expected_source_digest": self.expected_source_digest,
            "append": [env.to_json() for env in self.append],
            "affected_invariants": list(self.affected_invariants),
            "write_classes": [write.to_json() for write in self.write_classes],
            "read_footprints": [read.to_json() for read in self.read_footprints],
            "touch_matrix": self.touch_matrix.to_json(),
            "transcript_digest": self.transcript_digest,
        }


class PatchChecker:
    """Practical append-only subset of the paper's patch checker."""

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

        self._check_footprints(proposal, invariants or {}, builder)

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
        self._check_frame_invalidation(folded, proposal, builder)

        return builder.result(digest=digest_log(target))

    def _check_footprints(
        self,
        proposal: PatchProposal,
        invariants: dict[str, Invariant],
        builder: CheckBuilder,
    ) -> None:
        footprint_by_invariant = {footprint.invariant: footprint for footprint in proposal.read_footprints}
        affected = set(proposal.affected_invariants)
        for name in invariants:
            footprint = footprint_by_invariant.get(name)
            if footprint is None:
                builder.error("patch-footprint-missing", "invariant has no read footprint witness", location=name)
                continue
            touched = False
            for write in proposal.write_classes:
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

    def _check_frame_invalidation(self, folded: FoldState, proposal: PatchProposal, builder: CheckBuilder) -> None:
        non_active_frames = {
            str(env.payload.get("frame_id", env.payload.get("object", "")))
            for env in proposal.append
            if env.kind in {"Suspended", "Invalidated", "Withdrawn"}
        }
        for frame_id in non_active_frames:
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
