"""Deterministic JSON encoding and digest helpers.

The public wire format is deliberately plain JSON.  Other implementations only
need sorted-object canonicalization, UTF-8, and SHA-256 to interoperate.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
from collections.abc import Iterable, Mapping
from enum import Enum
from fractions import Fraction
from typing import Any

SHA256_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
SHA256_DIGEST_RE = re.compile(SHA256_DIGEST_PATTERN)


def normalize_json(value: Any) -> Any:
    """Convert common Python objects into canonical JSON-compatible values."""

    if hasattr(value, "to_json") and callable(value.to_json):
        return normalize_json(value.to_json())
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return normalize_json(dataclasses.asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Fraction):
        return f"{value.numerator}/{value.denominator}"
    if isinstance(value, Mapping):
        return {str(k): normalize_json(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, tuple | list):
        return [normalize_json(v) for v in value]
    if isinstance(value, set | frozenset):
        return sorted((normalize_json(v) for v in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, bytes):
        raise TypeError("bytes are not allowed in canonical JSON; pass an encoded string")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite floats are not allowed in canonical JSON")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return RFC-8259-compatible canonical bytes for a JSON value."""

    normalized = normalize_json(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_json(value: Any, *, algorithm: str = "sha256") -> str:
    """Digest a JSON-like value and prefix the algorithm name."""

    if algorithm != "sha256":
        raise ValueError("only sha256 is currently supported")
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def digest_many(values: Iterable[Any], *, algorithm: str = "sha256") -> str:
    """Digest a finite sequence as one canonical JSON array."""

    return digest_json(list(values), algorithm=algorithm)


def is_sha256_digest(value: object) -> bool:
    """Return whether *value* is a canonical project SHA-256 digest string."""

    return isinstance(value, str) and SHA256_DIGEST_RE.fullmatch(value) is not None
