"""Append-only storage backends for durable gate bundles."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .digest import canonical_json_bytes
from .model import Envelope, Horizon
from .result import CheckBuilder, CheckResult
from .verifier import EnvelopeVerifier, digest_log


@dataclass(frozen=True, slots=True)
class StoreSnapshot:
    """A deterministic finite view of an append-only store."""

    envelopes: tuple[Envelope, ...]
    digest: str

    @property
    def length(self) -> int:
        return len(self.envelopes)

    def to_json(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "length": self.length,
            "envelopes": [env.to_json() for env in self.envelopes],
        }


@dataclass(frozen=True, slots=True)
class AppendResult:
    """Result of an atomic compare-and-append operation."""

    ok: bool
    snapshot: StoreSnapshot
    result: CheckResult
    committed_eids: tuple[str, ...] = ()

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "snapshot": {"digest": self.snapshot.digest, "length": self.snapshot.length},
            "result": self.result.to_json(),
            "committed_eids": list(self.committed_eids),
        }


class AppendOnlyStore(Protocol):
    """Protocol implemented by append-only stores."""

    def snapshot(self) -> StoreSnapshot: ...

    def append_atomic(
        self,
        horizon: Horizon,
        expected_digest: str,
        append: Sequence[Envelope],
        *,
        verifier: EnvelopeVerifier | None = None,
    ) -> AppendResult: ...


class MemoryAppendOnlyStore:
    """Thread-safe in-memory append-only store for tests and embedded agents."""

    def __init__(self, envelopes: Sequence[Envelope] = ()) -> None:
        self._lock = threading.RLock()
        self._envelopes = tuple(envelopes)

    def snapshot(self) -> StoreSnapshot:
        with self._lock:
            return _snapshot(self._envelopes)

    def append_atomic(
        self,
        horizon: Horizon,
        expected_digest: str,
        append: Sequence[Envelope],
        *,
        verifier: EnvelopeVerifier | None = None,
    ) -> AppendResult:
        with self._lock:
            current = _snapshot(self._envelopes)
            validation = _validate_append(horizon, current.envelopes, expected_digest, tuple(append), verifier)
            if not validation.ok:
                return AppendResult(False, current, validation)
            self._envelopes = (*self._envelopes, *append)
            return AppendResult(True, _snapshot(self._envelopes), validation, tuple(env.eid for env in append))


class SQLiteAppendOnlyStore:
    """Stdlib SQLite append-only store with compare-and-swap appends."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS envelopes "
            "(ordinal INTEGER PRIMARY KEY AUTOINCREMENT, eid TEXT NOT NULL UNIQUE, payload TEXT NOT NULL)"
        )

    def close(self) -> None:
        self._connection.close()

    def snapshot(self) -> StoreSnapshot:
        with self._lock:
            return _snapshot(self._read_all())

    def append_atomic(
        self,
        horizon: Horizon,
        expected_digest: str,
        append: Sequence[Envelope],
        *,
        verifier: EnvelopeVerifier | None = None,
    ) -> AppendResult:
        append_tuple = tuple(append)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                current_envelopes = self._read_all()
                current = _snapshot(current_envelopes)
                validation = _validate_append(horizon, current.envelopes, expected_digest, append_tuple, verifier)
                if not validation.ok:
                    self._connection.execute("ROLLBACK")
                    return AppendResult(False, current, validation)
                for env in append_tuple:
                    payload = canonical_json_bytes(env.to_json()).decode("utf-8")
                    self._connection.execute(
                        "INSERT INTO envelopes(eid, payload) VALUES (?, ?)",
                        (env.eid, payload),
                    )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            return AppendResult(True, self.snapshot(), validation, tuple(env.eid for env in append_tuple))

    def _read_all(self) -> tuple[Envelope, ...]:
        rows = self._connection.execute("SELECT payload FROM envelopes ORDER BY ordinal ASC").fetchall()
        return tuple(Envelope.from_mapping(json.loads(str(row[0]))) for row in rows)


def _snapshot(envelopes: Sequence[Envelope]) -> StoreSnapshot:
    items = tuple(envelopes)
    return StoreSnapshot(items, digest_log(items))


def _validate_append(
    horizon: Horizon,
    source: tuple[Envelope, ...],
    expected_digest: str,
    append: tuple[Envelope, ...],
    verifier: EnvelopeVerifier | None,
) -> CheckResult:
    builder = CheckBuilder(footprint={"AppendOnlyStore", "EnvelopeVerifier"})
    source_digest = digest_log(source)
    if expected_digest != source_digest:
        builder.error(
            "store-cas-conflict",
            "append expected digest does not match the current store snapshot",
            details={"expected": expected_digest, "actual": source_digest},
        )
    source_ids = {env.eid for env in source}
    duplicates = sorted(env.eid for env in append if env.eid in source_ids)
    if duplicates:
        builder.error(
            "store-duplicate-eid",
            "append contains envelope ids already in the store",
            details={"eids": duplicates},
        )
    target = (*source, *append)
    legal = (verifier or EnvelopeVerifier()).verify(horizon, target)
    return builder.result(digest=digest_log(target)).merge(legal)


def snapshot_from_json(value: Mapping[str, object]) -> StoreSnapshot:
    """Build a snapshot from a portable JSON object."""

    envelopes_value = value.get("envelopes")
    if not isinstance(envelopes_value, list):
        raise TypeError("snapshot envelopes must be an array")
    envelopes = tuple(Envelope.from_mapping(item) for item in envelopes_value)
    return StoreSnapshot(envelopes, digest_log(envelopes))
