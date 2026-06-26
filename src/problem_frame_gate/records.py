"""Finite proof-carrying records from the audit calculus."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .digest import digest_json
from .model import Envelope, Horizon
from .result import CheckBuilder, CheckResult
from .verifier import EnvelopeVerifier, canonical_order, digest_log


@dataclass(frozen=True, slots=True)
class SwapCover:
    """Finite set of adjacent pairs certified as component-preserving."""

    independent_pairs: tuple[tuple[str, str], ...] = ()
    component_equalities: tuple[str, ...] = ()

    def permits(self, left: str, right: str) -> bool:
        return (left, right) in self.independent_pairs or (right, left) in self.independent_pairs

    def to_json(self) -> dict[str, Any]:
        return {
            "independent_pairs": [list(pair) for pair in self.independent_pairs],
            "component_equalities": list(self.component_equalities),
        }


@dataclass(frozen=True, slots=True)
class ReplayCertificate:
    """Certificate that a non-canonical replay word reaches the canonical word."""

    word: tuple[str, ...]
    swaps: tuple[tuple[int, str, str], ...]
    cover: SwapCover
    target_digest: str

    def to_json(self) -> dict[str, Any]:
        return {
            "word": list(self.word),
            "swaps": [[index, left, right] for index, left, right in self.swaps],
            "cover": self.cover.to_json(),
            "target_digest": self.target_digest,
        }


def check_replay_certificate(
    horizon: Horizon, envelopes: tuple[Envelope, ...], certificate: ReplayCertificate
) -> CheckResult:
    builder = CheckBuilder(footprint={"TraceChecker", "FoldKernel", "EnvelopeVerifier"})
    legal = EnvelopeVerifier().verify(horizon, envelopes)
    if not legal.ok:
        return legal.merge(builder.result())

    id_set = {env.eid for env in envelopes}
    if set(certificate.word) != id_set or len(certificate.word) != len(id_set):
        builder.error("replay-word", "replay word must be a permutation of the log envelope ids")
        return builder.result(digest=digest_log(envelopes), transcript_digest=digest_json(certificate.to_json()))
    if certificate.target_digest != digest_log(envelopes):
        builder.error("replay-target-digest", "replay certificate target digest does not match the log")

    current = list(certificate.word)
    for step, (index, left, right) in enumerate(certificate.swaps):
        if index < 0 or index + 1 >= len(current):
            builder.error("replay-swap-index", "swap index is outside the replay word", details={"step": step})
            continue
        if current[index] != left or current[index + 1] != right:
            builder.error(
                "replay-swap-pair",
                "swap row does not match the current adjacent pair",
                details={"step": step, "expected": [current[index], current[index + 1]], "actual": [left, right]},
            )
            continue
        if not certificate.cover.permits(left, right):
            builder.error(
                "replay-swap-cover",
                "adjacent swap is not covered by an independence certificate",
                details={"step": step, "pair": [left, right]},
            )
        current[index], current[index + 1] = current[index + 1], current[index]

    canonical = [env.eid for env in canonical_order(horizon, envelopes)]
    if current != canonical:
        builder.error(
            "replay-not-canonical",
            "certified swap trace does not reach the canonical replay word",
            details={"actual": current, "canonical": canonical},
        )
    return builder.result(digest=digest_log(envelopes), transcript_digest=digest_json(certificate.to_json()))


@dataclass(frozen=True, slots=True)
class SourceCut:
    """Finite consistent-cut record for a source prefix."""

    cut_id: str
    source_time: int
    included_eids: tuple[str, ...]
    excluded_frontier_eids: tuple[str, ...]
    digest: str
    clock_rows: tuple[str, ...] = ()
    watermark_rows: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "cut_id": self.cut_id,
            "source_time": self.source_time,
            "included_eids": list(self.included_eids),
            "excluded_frontier_eids": list(self.excluded_frontier_eids),
            "digest": self.digest,
            "clock_rows": list(self.clock_rows),
            "watermark_rows": list(self.watermark_rows),
        }


def check_source_cut(horizon: Horizon, envelopes: tuple[Envelope, ...], cut: SourceCut) -> CheckResult:
    builder = CheckBuilder(footprint={"ClockWatermark", "EnvelopeVerifier"})
    legal = EnvelopeVerifier().verify(horizon, envelopes)
    if not legal.ok:
        return legal.merge(builder.result())

    by_id = {env.eid: env for env in envelopes}
    expected_included = tuple(sorted(env.eid for env in envelopes if env.commit_time <= cut.source_time))
    expected_frontier = tuple(sorted(env.eid for env in envelopes if env.commit_time > cut.source_time))
    if tuple(sorted(cut.included_eids)) != expected_included:
        builder.error(
            "source-cut-included",
            "source cut included set does not match commit-time prefix",
            details={"expected": list(expected_included), "actual": sorted(cut.included_eids)},
        )
    if tuple(sorted(cut.excluded_frontier_eids)) != expected_frontier:
        builder.error(
            "source-cut-frontier",
            "source cut frontier must list all later envelopes in the finite log",
            details={"expected": list(expected_frontier), "actual": sorted(cut.excluded_frontier_eids)},
        )

    included = tuple(by_id[eid] for eid in cut.included_eids if eid in by_id)
    if cut.digest != digest_log(included):
        builder.error("source-cut-digest", "source cut digest does not match included envelopes")

    included_ids = set(cut.included_eids)
    for env in included:
        for dep in env.dependencies:
            if dep.eid is not None and dep.eid not in included_ids:
                builder.error(
                    "source-cut-dependency",
                    "source cut is not closed under dependencies",
                    location=env.eid,
                    details=dep.to_json(),
                )
        if env.commit_group:
            group_ids = {row.eid for row in envelopes if row.commit_group == env.commit_group}
            if not group_ids.issubset(included_ids):
                builder.error(
                    "source-cut-commit-group",
                    "source cut is not closed under commit groups",
                    location=env.commit_group,
                )
    return builder.result(digest=cut.digest, transcript_digest=digest_json(cut.to_json()))


@dataclass(frozen=True, slots=True)
class TransitionRecord:
    source_digest: str
    target_digest: str
    kind: str
    transcript_digest: str
    capacity_class: str = "normal"

    def to_json(self) -> dict[str, str]:
        return {
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
            "kind": self.kind,
            "transcript_digest": self.transcript_digest,
            "capacity_class": self.capacity_class,
        }


@dataclass(frozen=True, slots=True)
class ReachabilityTranscript:
    transitions: tuple[TransitionRecord, ...]
    assumptions: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        return {
            "transitions": [transition.to_json() for transition in self.transitions],
            "assumptions": list(self.assumptions),
        }


def check_reachability(transcript: ReachabilityTranscript) -> CheckResult:
    builder = CheckBuilder(footprint={"ReachTranscript"})
    previous_target: str | None = None
    for index, transition in enumerate(transcript.transitions):
        if not transition.source_digest or not transition.target_digest or not transition.transcript_digest:
            builder.error("reach-record", "transition record must bind source, target, and premise transcript")
        if previous_target is not None and transition.source_digest != previous_target:
            builder.error(
                "reach-chain",
                "transition source digest must match previous target digest",
                details={"index": index, "expected": previous_target, "actual": transition.source_digest},
            )
        previous_target = transition.target_digest
    for assumption in transcript.assumptions:
        builder.add_assumption(assumption)
    return builder.result(transcript_digest=digest_json(transcript.to_json()))
