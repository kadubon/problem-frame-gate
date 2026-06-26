"""Sensitive-data guardrails for audit-log payloads."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

SECRET_KEY_NAME = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret|private[_-]?key|password|credential|client[_-]?secret)"
)

SECRET_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    (
        "JWT-like token",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
)

LOCAL_PATH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Windows user path", re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+")),
    ("Unix home path", re.compile(r"(?i)(^|\s)/home/[^/\s]+")),
    ("SSH material path", re.compile(r"(?i)(^|[/\\])\.ssh([/\\]|$)")),
    ("cloud credentials path", re.compile(r"(?i)(^|[/\\])\.(aws|config/gcloud)([/\\]|$)")),
)


@dataclass(frozen=True, slots=True)
class SensitiveDataIssue:
    path: str
    reason: str
    preview: str

    def to_json(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason, "preview": self.preview}


def scan_for_sensitive_data(value: Any, *, allow_local_paths: bool = False) -> tuple[SensitiveDataIssue, ...]:
    """Find common secrets and machine-local paths in a JSON-like value."""

    issues: list[SensitiveDataIssue] = []
    _walk(value, "$", issues, allow_local_paths=allow_local_paths)
    return tuple(issues)


def _walk(value: Any, path: str, issues: list[SensitiveDataIssue], *, allow_local_paths: bool) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            if SECRET_KEY_NAME.search(key_text) and _non_empty_scalar(child):
                issues.append(SensitiveDataIssue(child_path, "secret-looking field name", _preview(child)))
            _walk(child, child_path, issues, allow_local_paths=allow_local_paths)
        return

    if isinstance(value, tuple | list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]", issues, allow_local_paths=allow_local_paths)
        return

    if not isinstance(value, str):
        return

    for reason, pattern in SECRET_VALUE_PATTERNS:
        if pattern.search(value):
            issues.append(SensitiveDataIssue(path, reason, _preview(value)))
    if not allow_local_paths:
        for reason, pattern in LOCAL_PATH_PATTERNS:
            if pattern.search(value):
                issues.append(SensitiveDataIssue(path, reason, _preview(value)))


def _non_empty_scalar(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    return value is not None and not isinstance(value, Mapping | list | tuple)


def _preview(value: Any) -> str:
    text = str(value).replace("\n", "\\n")
    if len(text) <= 16:
        return "***"
    return f"{text[:4]}...{text[-4:]}"
