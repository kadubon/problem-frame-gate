"""First-class reachability checker facade."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .model import Horizon
from .records import ReachabilityTranscript, TransitionRecord, check_reachability
from .result import CheckResult


@dataclass(frozen=True, slots=True)
class TransitionWitness:
    """Typed transition witness payload with a digest supplied by TransitionRecord."""

    kind: str
    payload: Mapping[str, Any]

    def to_json(self) -> dict[str, object]:
        return {"kind": self.kind, "payload": dict(self.payload)}


class ReachabilityChecker:
    """Facade for typed reachability verification."""

    def verify(
        self,
        transcript: ReachabilityTranscript,
        horizon: Horizon | None = None,
        *,
        certificate_registry: Mapping[str, Any] | None = None,
        risk_registry: Mapping[str, Any] | None = None,
    ) -> CheckResult:
        return check_reachability(
            transcript,
            horizon,
            certificate_registry=certificate_registry,
            risk_registry=risk_registry,
        )


__all__ = ["ReachabilityChecker", "ReachabilityTranscript", "TransitionRecord", "TransitionWitness"]
