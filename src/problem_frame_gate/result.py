"""Small result objects shared by all checkers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal

Severity = Literal["error", "warning"]


@dataclass(frozen=True, slots=True)
class Issue:
    """One checker finding."""

    code: str
    message: str
    location: str = ""
    severity: Severity = "error"
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
        }
        if self.location:
            data["location"] = self.location
        if self.details:
            data["details"] = dict(self.details)
        return data


@dataclass(frozen=True, slots=True)
class CheckResult:
    """A finite checker result with an explicit trusted-footprint label set."""

    ok: bool
    issues: tuple[Issue, ...] = ()
    footprint: frozenset[str] = frozenset()
    digest: str | None = None
    transcript_digest: str | None = None
    assumptions: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.ok

    @classmethod
    def success(
        cls,
        *,
        footprint: set[str] | frozenset[str] | None = None,
        digest: str | None = None,
        transcript_digest: str | None = None,
        assumptions: tuple[str, ...] = (),
    ) -> CheckResult:
        return cls(True, (), frozenset(footprint or ()), digest, transcript_digest, assumptions)

    @classmethod
    def fail(
        cls,
        *issues: Issue,
        footprint: set[str] | frozenset[str] | None = None,
        digest: str | None = None,
        transcript_digest: str | None = None,
        assumptions: tuple[str, ...] = (),
    ) -> CheckResult:
        return cls(False, tuple(issues), frozenset(footprint or ()), digest, transcript_digest, assumptions)

    def with_digest(self, digest: str) -> CheckResult:
        return replace(self, digest=digest)

    def with_transcript_digest(self, transcript_digest: str) -> CheckResult:
        return replace(self, transcript_digest=transcript_digest)

    def merge(self, *others: CheckResult) -> CheckResult:
        ok = self.ok and all(other.ok for other in others)
        issues = self.issues + tuple(issue for other in others for issue in other.issues)
        footprint = set(self.footprint)
        assumptions = list(self.assumptions)
        for other in others:
            footprint.update(other.footprint)
            assumptions.extend(item for item in other.assumptions if item not in assumptions)
        transcript_digest = self.transcript_digest
        if transcript_digest is None:
            transcript_digest = next((other.transcript_digest for other in others if other.transcript_digest), None)
        return CheckResult(ok, issues, frozenset(footprint), self.digest, transcript_digest, tuple(assumptions))

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ok": self.ok,
            "issues": [issue.to_json() for issue in self.issues],
            "footprint": sorted(self.footprint),
        }
        if self.digest:
            data["digest"] = self.digest
        if self.transcript_digest:
            data["transcript_digest"] = self.transcript_digest
        if self.assumptions:
            data["assumptions"] = list(self.assumptions)
        return data


class CheckBuilder:
    """Mutable helper for deterministic finite checkers."""

    def __init__(self, *, footprint: set[str] | None = None) -> None:
        self._issues: list[Issue] = []
        self._footprint = set(footprint or ())
        self._assumptions: list[str] = []

    def error(
        self,
        code: str,
        message: str,
        *,
        location: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self._issues.append(Issue(code, message, location=location, severity="error", details=details or {}))

    def warning(
        self,
        code: str,
        message: str,
        *,
        location: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self._issues.append(Issue(code, message, location=location, severity="warning", details=details or {}))

    def add_footprint(self, *labels: str) -> None:
        self._footprint.update(labels)

    def add_assumption(self, *labels: str) -> None:
        self._assumptions.extend(label for label in labels if label not in self._assumptions)

    def result(self, *, digest: str | None = None, transcript_digest: str | None = None) -> CheckResult:
        ok = not any(issue.severity == "error" for issue in self._issues)
        return CheckResult(
            ok,
            tuple(self._issues),
            frozenset(self._footprint),
            digest,
            transcript_digest,
            tuple(self._assumptions),
        )
