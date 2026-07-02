"""Finite proof-carrying records from the audit calculus."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .digest import digest_json, is_sha256_digest
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

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SwapCover:
        return cls(
            independent_pairs=tuple(_string_pair(item) for item in _sequence(value.get("independent_pairs", ()))),
            component_equalities=tuple(str(item) for item in _sequence(value.get("component_equalities", ()))),
        )


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

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReplayCertificate:
        swaps: list[tuple[int, str, str]] = []
        for item in _sequence(value["swaps"]):
            if not isinstance(item, Sequence) or isinstance(item, str | bytes) or len(item) != 3:
                raise TypeError("swap rows must be [index, left, right]")
            swaps.append((int(item[0]), str(item[1]), str(item[2])))
        cover = value.get("cover")
        if not isinstance(cover, Mapping):
            raise TypeError("replay certificate cover must be an object")
        return cls(
            word=tuple(str(item) for item in _sequence(value["word"])),
            swaps=tuple(swaps),
            cover=SwapCover.from_mapping(cover),
            target_digest=str(value["target_digest"]),
        )


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
        if step >= len(certificate.cover.component_equalities):
            builder.error(
                "replay-component-equality",
                "each replay swap must cite a component equality witness",
                details={"step": step},
            )
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

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SourceCut:
        return cls(
            cut_id=str(value["cut_id"]),
            source_time=int(value["source_time"]),
            included_eids=tuple(str(item) for item in _sequence(value["included_eids"])),
            excluded_frontier_eids=tuple(str(item) for item in _sequence(value["excluded_frontier_eids"])),
            digest=str(value["digest"]),
            clock_rows=tuple(str(item) for item in _sequence(value.get("clock_rows", ()))),
            watermark_rows=tuple(str(item) for item in _sequence(value.get("watermark_rows", ()))),
        )


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
    if f"source_time:{cut.source_time}" not in cut.clock_rows:
        builder.error("source-cut-clock", "source cut must bind the source_time clock row")
    if f"source_digest:{cut.digest}" not in cut.watermark_rows:
        builder.error("source-cut-watermark", "source cut must bind the source digest watermark row")

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
    witness_kind: str = ""
    witness_digest: str = ""
    capacity_class: str = "normal"
    witness: Mapping[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
            "kind": self.kind,
            "transcript_digest": self.transcript_digest,
            "witness_kind": self.witness_kind,
            "witness_digest": self.witness_digest,
            "capacity_class": self.capacity_class,
            "witness": dict(self.witness) if self.witness is not None else None,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> TransitionRecord:
        witness = value.get("witness")
        if witness is not None and not isinstance(witness, Mapping):
            raise TypeError("transition witness must be an object")
        return cls(
            source_digest=str(value["source_digest"]),
            target_digest=str(value["target_digest"]),
            kind=str(value["kind"]),
            transcript_digest=str(value["transcript_digest"]),
            witness_kind=str(value.get("witness_kind", "")),
            witness_digest=str(value.get("witness_digest", "")),
            capacity_class=str(value.get("capacity_class", "normal")),
            witness=dict(witness) if witness is not None else None,
        )


@dataclass(frozen=True, slots=True)
class ReachabilityTranscript:
    transitions: tuple[TransitionRecord, ...]
    assumptions: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        return {
            "transitions": [transition.to_json() for transition in self.transitions],
            "assumptions": list(self.assumptions),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReachabilityTranscript:
        return cls(
            transitions=tuple(
                TransitionRecord.from_mapping(_mapping(item)) for item in _sequence(value["transitions"])
            ),
            assumptions=tuple(str(item) for item in _sequence(value.get("assumptions", ()))),
        )


def check_reachability(
    transcript: ReachabilityTranscript,
    horizon: Horizon | None = None,
    *,
    certificate_registry: Mapping[str, Any] | None = None,
    risk_registry: Mapping[str, Any] | None = None,
) -> CheckResult:
    builder = CheckBuilder(footprint={"ReachTranscript"})
    previous_target: str | None = None
    allowed = {"patch", "join", "gate", "abort", "failClosed"}
    for index, transition in enumerate(transcript.transitions):
        if (
            not is_sha256_digest(transition.source_digest)
            or not is_sha256_digest(transition.target_digest)
            or not is_sha256_digest(transition.transcript_digest)
        ):
            builder.error(
                "reach-record",
                "transition record must bind source, target, and premise transcript SHA-256 digests",
                details={"index": index},
            )
        if transition.kind not in allowed:
            builder.error(
                "reach-kind",
                "transition kind must be patch, join, gate, abort, or failClosed",
                details={"index": index, "kind": transition.kind},
            )
        if transition.witness_kind != transition.kind or not is_sha256_digest(transition.witness_digest):
            builder.error(
                "reach-witness",
                "transition must bind a concrete checker witness for its kind",
                details={
                    "index": index,
                    "kind": transition.kind,
                    "witness_kind": transition.witness_kind,
                    "witness_digest": transition.witness_digest,
                },
            )
        if transition.witness is None:
            builder.error(
                "reach-witness-payload",
                "transition must carry the typed witness payload needed to re-run its checker",
                details={"index": index, "kind": transition.kind},
            )
        else:
            _check_transition_witness(
                transition,
                horizon,
                certificate_registry=certificate_registry,
                risk_registry=risk_registry,
                builder=builder,
                index=index,
            )
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


def _check_transition_witness(
    transition: TransitionRecord,
    horizon: Horizon | None,
    *,
    certificate_registry: Mapping[str, Any] | None,
    risk_registry: Mapping[str, Any] | None,
    builder: CheckBuilder,
    index: int,
) -> None:
    witness = transition.witness
    if witness is None:
        return
    actual_witness_digest = digest_json(dict(witness))
    if transition.witness_digest != actual_witness_digest:
        builder.error(
            "reach-witness-digest",
            "transition witness digest does not match the embedded typed witness",
            details={"index": index, "expected": actual_witness_digest, "actual": transition.witness_digest},
        )
    if transition.kind in {"patch", "join", "gate"} and horizon is None:
        builder.error(
            "reach-horizon",
            "patch, join, and gate reachability witnesses require a horizon for checker replay",
            details={"index": index, "kind": transition.kind},
        )
        return
    if transition.kind == "patch" and horizon is not None:
        _check_patch_transition(transition, horizon, witness, builder, index)
    elif transition.kind == "join" and horizon is not None:
        _check_join_transition(transition, horizon, witness, builder, index)
    elif transition.kind == "gate" and horizon is not None:
        _check_gate_transition(
            transition,
            horizon,
            witness,
            certificate_registry=certificate_registry,
            risk_registry=risk_registry,
            builder=builder,
            index=index,
        )
    elif transition.kind in {"abort", "failClosed"}:
        _check_capacity_transition(transition, witness, builder, index)


def _check_patch_transition(
    transition: TransitionRecord,
    horizon: Horizon,
    witness: Mapping[str, Any],
    builder: CheckBuilder,
    index: int,
) -> None:
    from .patch import PatchChecker, PatchProposal

    source = _witness_envelopes(witness.get("source"), builder, index, "source")
    proposal_value = witness.get("proposal")
    if source is None or not isinstance(proposal_value, Mapping):
        builder.error(
            "reach-patch-witness",
            "patch witness must carry source and proposal objects",
            details={"index": index},
        )
        return
    try:
        proposal = PatchProposal.from_mapping(proposal_value)
    except (KeyError, TypeError, ValueError) as exc:
        builder.error("reach-patch-witness", f"patch witness proposal is malformed: {exc}", details={"index": index})
        return
    _compare_transition_result(transition, PatchChecker().check(horizon, source, proposal), builder, index)


def _check_join_transition(
    transition: TransitionRecord,
    horizon: Horizon,
    witness: Mapping[str, Any],
    builder: CheckBuilder,
    index: int,
) -> None:
    from .join import JoinChecker, JoinProposal

    proposal_value = witness.get("proposal")
    if not isinstance(proposal_value, Mapping):
        builder.error("reach-join-witness", "join witness must carry a proposal object", details={"index": index})
        return
    try:
        proposal = JoinProposal.from_mapping(proposal_value)
    except (KeyError, TypeError, ValueError) as exc:
        builder.error("reach-join-witness", f"join witness proposal is malformed: {exc}", details={"index": index})
        return
    _compare_transition_result(transition, JoinChecker().check(horizon, proposal), builder, index)


def _check_gate_transition(
    transition: TransitionRecord,
    horizon: Horizon,
    witness: Mapping[str, Any],
    *,
    certificate_registry: Mapping[str, Any] | None,
    risk_registry: Mapping[str, Any] | None,
    builder: CheckBuilder,
    index: int,
) -> None:
    from .gate import GateBundle

    source = _witness_envelopes(witness.get("source"), builder, index, "source")
    bundle_value = witness.get("bundle")
    if source is None or not isinstance(bundle_value, Mapping):
        builder.error(
            "reach-gate-witness",
            "gate witness must carry source and bundle objects",
            details={"index": index},
        )
        return
    try:
        bundle = GateBundle.from_mapping(bundle_value)
    except (KeyError, TypeError, ValueError) as exc:
        builder.error("reach-gate-witness", f"gate witness bundle is malformed: {exc}", details={"index": index})
        return
    _compare_transition_result(
        transition,
        bundle.verify(
            horizon,
            source,
            certificate_registry=certificate_registry,
            risk_registry=risk_registry,
        ),
        builder,
        index,
    )


def _check_capacity_transition(
    transition: TransitionRecord,
    witness: Mapping[str, Any],
    builder: CheckBuilder,
    index: int,
) -> None:
    source = _witness_envelopes(witness.get("source"), builder, index, "source")
    rows = _witness_envelopes(witness.get("rows"), builder, index, "rows")
    if source is None or rows is None:
        return
    expected_class = "abort" if transition.kind == "abort" else "failClosed"
    if transition.capacity_class != expected_class:
        builder.error(
            "reach-capacity-class",
            "abort and fail-closed transitions must use the matching capacity class",
            details={"index": index, "expected": expected_class, "actual": transition.capacity_class},
        )
    for row in rows:
        if row.envelope_class.value != expected_class:
            builder.error(
                "reach-capacity-row",
                "abort and fail-closed witness rows must use the matching envelope class",
                location=row.eid,
                details={"index": index, "expected": expected_class, "actual": row.envelope_class.value},
            )
    result = CheckResult.success(footprint={"ReachTranscript"}, digest=digest_log((*source, *rows)))
    _compare_transition_result(transition, result, builder, index)
    assumption = witness.get("assumption")
    if isinstance(assumption, str) and assumption:
        builder.add_assumption(assumption)


def _compare_transition_result(
    transition: TransitionRecord,
    result: CheckResult,
    builder: CheckBuilder,
    index: int,
) -> None:
    for issue in result.issues:
        if issue.severity == "error":
            builder.error(
                f"reach-checker-{issue.code}",
                issue.message,
                location=issue.location,
                details=issue.details,
            )
        else:
            builder.warning(
                f"reach-checker-{issue.code}",
                issue.message,
                location=issue.location,
                details=issue.details,
            )
    if result.digest != transition.target_digest:
        builder.error(
            "reach-target-digest",
            "transition target digest does not match checker replay",
            details={"index": index, "expected": result.digest, "actual": transition.target_digest},
        )
    expected_transcript = digest_json(result.to_json())
    if transition.transcript_digest != expected_transcript:
        builder.error(
            "reach-transcript-digest",
            "transition transcript digest does not match checker replay",
            details={"index": index, "expected": expected_transcript, "actual": transition.transcript_digest},
        )
    for assumption in result.assumptions:
        builder.add_assumption(assumption)


def _witness_envelopes(
    value: Any,
    builder: CheckBuilder,
    index: int,
    field: str,
) -> tuple[Envelope, ...] | None:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        builder.error(
            "reach-witness-envelopes",
            "reachability witness envelope field must be an array",
            details={"index": index, "field": field},
        )
        return None
    try:
        return tuple(Envelope.from_mapping(_mapping(item)) for item in value)
    except (KeyError, TypeError, ValueError) as exc:
        builder.error(
            "reach-witness-envelopes",
            f"reachability witness envelope field is malformed: {exc}",
            details={"index": index, "field": field},
        )
        return None


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("expected object mapping")
    return value


def _sequence(value: object) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise TypeError("expected sequence")
    return value


def _string_pair(value: object) -> tuple[str, str]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes) or len(value) != 2:
        raise TypeError("expected pair")
    return (str(value[0]), str(value[1]))
