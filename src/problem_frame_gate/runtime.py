"""Runtime helpers that commit accepted gate bundles without dispatching actions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace

from .certificates import CertificateFamily
from .gate import ExecutorGate, GateBundle, GateRequest
from .metrics import MetricsSink
from .model import Horizon
from .result import CheckBuilder, CheckResult
from .risk import RiskMode
from .storage import AppendOnlyStore, AppendResult, StoreSnapshot
from .verifier import EnvelopeVerifier


@dataclass(frozen=True, slots=True)
class GateCommitResult:
    """Outcome of a durable gate-bundle commit attempt."""

    check: CheckResult
    append: AppendResult | None
    snapshot: StoreSnapshot
    bundle: GateBundle | None = None

    @property
    def ok(self) -> bool:
        return self.check.ok and self.append is not None and self.append.ok

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "check": self.check.to_json(),
            "append": self.append.to_json() if self.append is not None else None,
            "snapshot": {"digest": self.snapshot.digest, "length": self.snapshot.length},
            "bundle": self.bundle.to_json() if self.bundle is not None else None,
        }


class GateCommitter:
    """Check a gate request, create its bundle, and append it atomically."""

    def __init__(
        self,
        store: AppendOnlyStore,
        *,
        gate: ExecutorGate | None = None,
        certificate_registry: Mapping[str, CertificateFamily] | None = None,
        risk_registry: Mapping[str, RiskMode] | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        self.store = store
        self.gate = gate or ExecutorGate(certificate_registry=certificate_registry, risk_registry=risk_registry)
        self.metrics = metrics

    def commit_gate(self, horizon: Horizon, request: GateRequest) -> GateCommitResult:
        snapshot = self.store.snapshot()
        if request.expected_source_digest is not None and request.expected_source_digest != snapshot.digest:
            builder = CheckBuilder(footprint={"GateCommitter", "AppendOnlyStore"})
            builder.error(
                "gate-commit-source-digest",
                "gate request expected digest does not match the current durable store snapshot",
                details={"expected": request.expected_source_digest, "actual": snapshot.digest},
            )
            self._metric("pfg.gate_commit.rejected", reason="source_digest")
            return GateCommitResult(builder.result(digest=snapshot.digest), None, snapshot)

        bound_request = request
        if request.expected_source_digest is None:
            bound_request = replace(request, expected_source_digest=snapshot.digest)

        check = self.gate.check(horizon, snapshot.envelopes, bound_request)
        if not check.ok:
            self._metric("pfg.gate_commit.rejected", reason="check")
            return GateCommitResult(check, None, snapshot)
        try:
            bundle = self.gate.create_bundle(horizon, snapshot.envelopes, bound_request)
        except ValueError as exc:
            builder = CheckBuilder(footprint={"GateCommitter", "ExecutorGate"})
            builder.error("gate-commit-bundle", str(exc))
            self._metric("pfg.gate_commit.rejected", reason="bundle")
            return GateCommitResult(builder.result(digest=snapshot.digest), None, snapshot)
        verifier = EnvelopeVerifier(
            certificate_registry=self.gate.certificate_registry,
            risk_registry=self.gate.risk_registry,
            signature_registry=self.gate.signature_registry,
            require_certificate_signatures=self.gate.require_certificate_signatures,
        )
        append = self.store.append_atomic(horizon, snapshot.digest, tuple(bundle), verifier=verifier)
        self._metric("pfg.gate_commit.committed" if append.ok else "pfg.gate_commit.rejected", reason="append")
        return GateCommitResult(check, append, snapshot, bundle if append.ok else None)

    def _metric(self, name: str, *, reason: str) -> None:
        if self.metrics is not None:
            self.metrics.increment(name, tags={"reason": reason})
