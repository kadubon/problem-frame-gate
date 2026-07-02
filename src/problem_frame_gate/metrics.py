"""Optional metrics sinks for runtime paths."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol


class MetricsSink(Protocol):
    def increment(self, name: str, value: int = 1, tags: Mapping[str, str] | None = None) -> None: ...


@dataclass(slots=True)
class MemoryMetricsSink:
    """In-memory metrics sink for tests and embedded deployments."""

    counters: dict[str, int] = field(default_factory=dict)

    def increment(self, name: str, value: int = 1, tags: Mapping[str, str] | None = None) -> None:
        suffix = ""
        if tags:
            suffix = "{" + ",".join(f"{key}={tags[key]}" for key in sorted(tags)) + "}"
        self.counters[f"{name}{suffix}"] = self.counters.get(f"{name}{suffix}", 0) + value
