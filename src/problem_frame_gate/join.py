"""Finite branch join checks."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .digest import digest_json
from .fold import FoldKernel, FoldState
from .model import Envelope, Horizon
from .result import CheckBuilder, CheckResult
from .verifier import digest_log


@dataclass(frozen=True, slots=True)
class JoinProposal:
    branches: tuple[tuple[Envelope, ...], ...]
    ancestor: tuple[Envelope, ...] = ()
    repairs: tuple[Envelope, ...] = ()
    affected_invariants: tuple[str, ...] = ()
    repair_rechecks: tuple[str, ...] = ()
    transcript_digest: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "branches": [[env.to_json() for env in branch] for branch in self.branches],
            "ancestor": [env.to_json() for env in self.ancestor],
            "repairs": [env.to_json() for env in self.repairs],
            "affected_invariants": list(self.affected_invariants),
            "repair_rechecks": list(self.repair_rechecks),
            "transcript_digest": self.transcript_digest,
        }


class JoinChecker:
    """Algebraic union plus default linear-resource checks via folding."""

    footprint = frozenset({"JoinKernel", "FoldKernel", "EnvelopeVerifier", "ClauseKernel"})

    def __init__(self, fold_kernel: FoldKernel | None = None) -> None:
        self.fold_kernel = fold_kernel or FoldKernel()

    def check(self, horizon: Horizon, proposal: JoinProposal) -> CheckResult:
        builder = CheckBuilder(footprint=set(self.footprint))
        self._check_common_ancestor(proposal, builder)
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
        for repair_id in repair_ids:
            if repair_id not in target_ids:
                builder.error("join-repair-folded", "repair row is not folded into the join target", location=repair_id)
        for invariant in proposal.affected_invariants:
            if invariant not in proposal.repair_rechecks:
                builder.error(
                    "join-repair-recheck",
                    "affected invariant must be branch-stable or have an accepted repair recheck",
                    location=invariant,
                )

    def _check_frame_invalidation(self, folded: FoldState, proposal: JoinProposal, builder: CheckBuilder) -> None:
        components = folded.components
        frames = components.get("frames", {})
        non_active = {
            frame_id
            for frame_id, record in frames.items()
            if record.get("status") in {"suspended", "invalid", "withdrawn"}
        }
        for frame_id in non_active:
            for cap_id, cap in components.get("capabilities", {}).items():
                if cap.get("frame_id") == frame_id and cap.get("status") == "unused":
                    builder.error(
                        "join-frame-invalidates-capability",
                        "join leaves a live cap for non-active frame",
                        location=cap_id,
                    )
            for outbox_id, outbox in components.get("outboxes", {}).items():
                if outbox.get("frame_id") == frame_id and outbox.get("status") == "authorized":
                    builder.error(
                        "join-frame-invalidates-outbox",
                        "join leaves an authorized outbox for non-active frame",
                        location=outbox_id,
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
