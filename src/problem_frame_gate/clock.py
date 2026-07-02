"""Clock and watermark records for gate source cuts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .digest import digest_json


@dataclass(frozen=True, slots=True)
class ClockWatermark:
    """Portable clock/watermark witness bound into a gate source cut."""

    source_time: int
    commit_time: int
    source_digest: str
    clock_policy: str = "integer-commit-time"
    watermark_digest: str = ""

    def __post_init__(self) -> None:
        if not self.watermark_digest:
            object.__setattr__(
                self,
                "watermark_digest",
                digest_json(
                    {
                        "source_time": self.source_time,
                        "commit_time": self.commit_time,
                        "source_digest": self.source_digest,
                        "clock_policy": self.clock_policy,
                    }
                ),
            )

    def clock_rows(self) -> tuple[str, ...]:
        return (
            f"source_time:{self.source_time}",
            f"commit_time:{self.commit_time}",
            f"clock_policy:{self.clock_policy}",
        )

    def watermark_rows(self) -> tuple[str, ...]:
        return (f"source_digest:{self.source_digest}", f"clock_watermark:{self.watermark_digest}")

    def to_json(self) -> dict[str, object]:
        return {
            "source_time": self.source_time,
            "commit_time": self.commit_time,
            "source_digest": self.source_digest,
            "clock_policy": self.clock_policy,
            "watermark_digest": self.watermark_digest,
        }


class ClockWatermarkProvider(Protocol):
    """Provider interface used by gate bundle construction."""

    def watermark(self, *, source_time: int, commit_time: int, source_digest: str) -> ClockWatermark: ...


@dataclass(frozen=True, slots=True)
class IntegerClockWatermarkProvider:
    """Deterministic provider for integer commit-time logs."""

    clock_policy: str = "integer-commit-time"

    def watermark(self, *, source_time: int, commit_time: int, source_digest: str) -> ClockWatermark:
        if source_time >= commit_time:
            raise ValueError("source_time must be strictly before commit_time")
        return ClockWatermark(source_time, commit_time, source_digest, self.clock_policy)
