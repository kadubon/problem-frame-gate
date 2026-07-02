"""Finite branch join checks."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .digest import digest_json, is_sha256_digest
from .fold import FoldKernel, FoldState
from .model import Envelope, Horizon
from .result import CheckBuilder, CheckResult
from .verifier import digest_log


@dataclass(frozen=True, slots=True)
class JoinKey:
    key: str
    branch_eids: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {"key": self.key, "branch_eids": list(self.branch_eids)}

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> JoinKey:
        return cls(str(value["key"]), tuple(str(item) for item in _sequence(value["branch_eids"])))


@dataclass(frozen=True, slots=True)
class RepairWitness:
    repair_eid: str
    conflict_key: str
    rechecked: bool
    transcript_digest: str

    def to_json(self) -> dict[str, Any]:
        return {
            "repair_eid": self.repair_eid,
            "conflict_key": self.conflict_key,
            "rechecked": self.rechecked,
            "transcript_digest": self.transcript_digest,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RepairWitness:
        return cls(
            repair_eid=str(value["repair_eid"]),
            conflict_key=str(value["conflict_key"]),
            rechecked=bool(value["rechecked"]),
            transcript_digest=str(value["transcript_digest"]),
        )


@dataclass(frozen=True, slots=True)
class JoinProposal:
    branches: tuple[tuple[Envelope, ...], ...]
    ancestor: tuple[Envelope, ...] = ()
    repairs: tuple[Envelope, ...] = ()
    escrow_conflicts: tuple[str, ...] = ()
    join_keys: tuple[JoinKey, ...] = ()
    repair_witnesses: tuple[RepairWitness, ...] = ()
    affected_invariants: tuple[str, ...] = ()
    repair_rechecks: tuple[str, ...] = ()
    liveness_repairs: tuple[str, ...] = ()
    transcript_digest: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "branches": [[env.to_json() for env in branch] for branch in self.branches],
            "ancestor": [env.to_json() for env in self.ancestor],
            "repairs": [env.to_json() for env in self.repairs],
            "escrow_conflicts": list(self.escrow_conflicts),
            "join_keys": [key.to_json() for key in self.join_keys],
            "repair_witnesses": [witness.to_json() for witness in self.repair_witnesses],
            "affected_invariants": list(self.affected_invariants),
            "repair_rechecks": list(self.repair_rechecks),
            "liveness_repairs": list(self.liveness_repairs),
            "transcript_digest": self.transcript_digest,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> JoinProposal:
        return cls(
            branches=tuple(
                tuple(Envelope.from_mapping(_mapping(env)) for env in _sequence(branch))
                for branch in _sequence(value["branches"])
            ),
            ancestor=tuple(Envelope.from_mapping(_mapping(env)) for env in _sequence(value.get("ancestor", ()))),
            repairs=tuple(Envelope.from_mapping(_mapping(env)) for env in _sequence(value.get("repairs", ()))),
            escrow_conflicts=tuple(str(item) for item in _sequence(value.get("escrow_conflicts", ()))),
            join_keys=tuple(JoinKey.from_mapping(_mapping(item)) for item in _sequence(value.get("join_keys", ()))),
            repair_witnesses=tuple(
                RepairWitness.from_mapping(_mapping(item)) for item in _sequence(value.get("repair_witnesses", ()))
            ),
            affected_invariants=tuple(str(item) for item in _sequence(value.get("affected_invariants", ()))),
            repair_rechecks=tuple(str(item) for item in _sequence(value.get("repair_rechecks", ()))),
            liveness_repairs=tuple(str(item) for item in _sequence(value.get("liveness_repairs", ()))),
            transcript_digest=str(value["transcript_digest"]) if value.get("transcript_digest") is not None else None,
        )


class JoinChecker:
    """Finite branch-join checker."""

    footprint = frozenset({"JoinKernel", "FoldKernel", "EnvelopeVerifier", "ClauseKernel"})

    def __init__(self, fold_kernel: FoldKernel | None = None) -> None:
        self.fold_kernel = fold_kernel or FoldKernel()

    def check(self, horizon: Horizon, proposal: JoinProposal) -> CheckResult:
        builder = CheckBuilder(footprint=set(self.footprint))
        self._check_common_ancestor(proposal, builder)
        self._check_escrow_conflicts(proposal, builder)
        by_eid: dict[str, Envelope] = {}
        for branch_index, branch in enumerate(proposal.branches):
            for env in branch:
                previous = by_eid.get(env.eid)
                if previous is not None and digest_json(previous.to_json()) != digest_json(env.to_json()):
                    builder.error(
                        "join-eid-conflict",
                        "same envelope id has different contents across branches",
                        location=env.eid,
                        details={"branch": branch_index},
                    )
                by_eid.setdefault(env.eid, env)
        for repair in proposal.repairs:
            previous = by_eid.get(repair.eid)
            if previous is not None and digest_json(previous.to_json()) != digest_json(repair.to_json()):
                builder.error(
                    "join-repair-conflict",
                    "repair envelope conflicts with existing id",
                    location=repair.eid,
                )
            by_eid[repair.eid] = repair

        target = tuple(by_eid.values())
        try:
            folded = self.fold_kernel.fold(horizon, target)
        except Exception as exc:
            builder.error("join-target-fold", f"joined target is not safe under default components: {exc}")
            return builder.result(digest=digest_log(target))
        self._check_repairs_folded(proposal, target, builder)
        self._check_frame_invalidation(folded, proposal, builder)

        return builder.result(digest=digest_log(target))

    def _check_common_ancestor(self, proposal: JoinProposal, builder: CheckBuilder) -> None:
        ancestor = {env.eid: digest_json(env.to_json()) for env in proposal.ancestor}
        if not ancestor:
            builder.error("join-ancestor-missing", "join proposal must cite a common ancestor")
            return
        for branch_index, branch in enumerate(proposal.branches):
            branch_map = {env.eid: digest_json(env.to_json()) for env in branch}
            for eid, digest in ancestor.items():
                if branch_map.get(eid) != digest:
                    builder.error(
                        "join-ancestor",
                        "branch does not contain the exact common ancestor envelope",
                        location=eid,
                        details={"branch": branch_index},
                    )

    def _check_repairs_folded(
        self, proposal: JoinProposal, target: tuple[Envelope, ...], builder: CheckBuilder
    ) -> None:
        target_ids = {env.eid for env in target}
        repair_ids = {env.eid for env in proposal.repairs}
        witnesses = {witness.repair_eid: witness for witness in proposal.repair_witnesses}
        for repair_id in repair_ids:
            if repair_id not in target_ids:
                builder.error("join-repair-folded", "repair row is not folded into the join target", location=repair_id)
            witness = witnesses.get(repair_id)
            if witness is None:
                builder.error("join-repair-witness", "repair row must carry a typed repair witness", location=repair_id)
            elif not witness.rechecked or not is_sha256_digest(witness.transcript_digest):
                builder.error(
                    "join-repair-witness",
                    "repair witness must be folded and rechecked with a transcript digest",
                    location=repair_id,
                )
        for invariant in proposal.affected_invariants:
            if invariant not in proposal.repair_rechecks:
                builder.error(
                    "join-repair-recheck",
                    "affected invariant must be branch-stable or have an accepted repair recheck",
                    location=invariant,
                )

    def _check_escrow_conflicts(self, proposal: JoinProposal, builder: CheckBuilder) -> None:
        ancestor_ids = {env.eid for env in proposal.ancestor}
        occurrences: dict[str, list[str]] = {}
        for branch_index, branch in enumerate(proposal.branches):
            seen_on_branch: set[str] = set()
            for env in branch:
                if env.eid in ancestor_ids:
                    continue
                key = _linear_cell_key(env)
                if not key or key in seen_on_branch:
                    continue
                seen_on_branch.add(key)
                occurrences.setdefault(key, []).append(f"{branch_index}:{env.eid}")
        join_keys = {join_key.key: join_key for join_key in proposal.join_keys}
        witnesses = {witness.conflict_key: witness for witness in proposal.repair_witnesses}
        declared_conflicts = set(proposal.escrow_conflicts)
        for key, rows in sorted(occurrences.items()):
            if len(rows) < 2:
                continue
            if key not in declared_conflicts:
                builder.error(
                    "join-escrow-conflict",
                    "linear cell is written on multiple branches without an escrow conflict declaration",
                    location=key,
                    details={"rows": rows},
                )
            join_key = join_keys.get(key)
            if join_key is None:
                builder.error(
                    "join-key-missing",
                    "branch conflict must carry a semantic join key",
                    location=key,
                    details={"rows": rows},
                )
            elif tuple(sorted(join_key.branch_eids)) != tuple(sorted(row.split(":", 1)[1] for row in rows)):
                expected_eids = sorted(row.split(":", 1)[1] for row in rows)
                builder.error(
                    "join-key-mismatch",
                    "semantic join key does not cite the conflicting branch rows",
                    location=key,
                    details={"expected": expected_eids, "actual": list(join_key.branch_eids)},
                )
            witness = witnesses.get(key)
            if witness is None or not witness.rechecked or not is_sha256_digest(witness.transcript_digest):
                builder.error(
                    "join-liveness-repair",
                    "branch conflict must carry a folded and rechecked repair witness",
                    location=key,
                )

    def _check_frame_invalidation(self, folded: FoldState, proposal: JoinProposal, builder: CheckBuilder) -> None:
        components = folded.components
        frames = components.get("frames", {})
        non_active = {
            frame_id
            for frame_id, record in frames.items()
            if record.get("status") in {"suspended", "invalid", "withdrawn"}
        }
        liveness_repairs = set(proposal.liveness_repairs)
        for frame_id in non_active:
            for cap_id, cap in components.get("capabilities", {}).items():
                if cap.get("frame_id") == frame_id and cap.get("status") == "unused":
                    _require_liveness_repair("capability", cap_id, liveness_repairs, builder)
                    builder.error(
                        "join-frame-invalidates-capability",
                        "join leaves a live cap for non-active frame",
                        location=cap_id,
                    )
            for outbox_id, outbox in components.get("outboxes", {}).items():
                if outbox.get("frame_id") == frame_id and outbox.get("status") == "authorized":
                    _require_liveness_repair("outbox", outbox_id, liveness_repairs, builder)
                    builder.error(
                        "join-frame-invalidates-outbox",
                        "join leaves an authorized outbox for non-active frame",
                        location=outbox_id,
                    )
            for lease_id, resource in components.get("resources", {}).items():
                if resource.get("frame_id") == frame_id and resource.get("status") == "leased":
                    _require_liveness_repair("resource", lease_id, liveness_repairs, builder)
                    builder.error(
                        "join-frame-invalidates-resource",
                        "join leaves a live resource lease for non-active frame",
                        location=lease_id,
                    )
            for risk_id, spend in components.get("risk", {}).get("spends", {}).items():
                if spend.get("frame_id") == frame_id and spend.get("closed_at") is None:
                    _require_liveness_repair("risk", risk_id, liveness_repairs, builder)
                    builder.error(
                        "join-frame-invalidates-risk",
                        "join leaves an open risk spend for non-active frame",
                        location=risk_id,
                    )


def union_join(
    horizon: Horizon,
    branches: Sequence[Sequence[Envelope]],
    repairs: Sequence[Envelope] = (),
    ancestor: Sequence[Envelope] = (),
) -> CheckResult:
    return JoinChecker().check(
        horizon,
        JoinProposal(
            branches=tuple(tuple(branch) for branch in branches),
            ancestor=tuple(ancestor),
            repairs=tuple(repairs),
        ),
    )


def _linear_cell_key(env: Envelope) -> str:
    try:
        kind = env.kind
    except ValueError:
        return ""
    payload = env.payload
    if kind in {"MintCap", "UseCap", "CapUsed", "RevokeCap", "ExpireCap"}:
        return f"capability:{payload.get('capability_id', payload.get('cap_id', ''))}"
    if kind in {"ReserveResource", "ConsumeResource", "ReleaseResource"}:
        return f"resource:{payload.get('lease_id', payload.get('object', ''))}"
    if kind in {"AuthorizeOutbox", "OutboxClaim", "RevokeOutbox"}:
        return f"outbox:{payload.get('outbox_id', payload.get('object', ''))}"
    if kind in {"RiskReserve", "RiskSpend", "RiskClose"}:
        return f"risk:{payload.get('risk_id', payload.get('object', ''))}"
    if kind in {"Issue", "Revoke"}:
        return f"certificate:{payload.get('cert_id', payload.get('object', ''))}"
    return ""


def _require_liveness_repair(
    kind: str,
    object_id: str,
    repairs: set[str],
    builder: CheckBuilder,
) -> None:
    repair_key = f"{kind}:{object_id}"
    if repair_key not in repairs:
        builder.error(
            "join-liveness-repair-witness",
            "non-active frame join must cite the liveness repair key",
            location=object_id,
            details={"repair": repair_key},
        )


def _mapping(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("expected object mapping")
    return value


def _sequence(value: object) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise TypeError("expected sequence")
    return value
