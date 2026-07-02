"""Outbox broker that dispatches only durable claimed actions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .fold import FoldKernel
from .metrics import MetricsSink
from .model import Envelope, EnvelopeClass, Horizon
from .result import CheckBuilder, CheckResult
from .storage import AppendOnlyStore


@dataclass(frozen=True, slots=True)
class DispatchResult:
    """Result returned by an action dispatcher."""

    accepted: bool
    receipt: Mapping[str, Any] | None = None
    error: str = ""

    def to_json(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "receipt": dict(self.receipt or {}),
            "error": self.error,
        }


class ActionDispatcher(Protocol):
    """External actuator interface used by :class:`OutboxBroker`."""

    def dispatch(self, request: Mapping[str, Any]) -> DispatchResult: ...


@dataclass(frozen=True, slots=True)
class BrokerPollResult:
    ok: bool
    outbox_id: str | None
    result: CheckResult
    dispatched: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "outbox_id": self.outbox_id,
            "result": self.result.to_json(),
            "dispatched": self.dispatched,
        }


class OutboxBroker:
    """Poll durable claimed outboxes and append dispatch lifecycle rows."""

    def __init__(
        self,
        store: AppendOnlyStore,
        dispatcher: ActionDispatcher,
        *,
        fold_kernel: FoldKernel | None = None,
        writer: str = "executor-gate",
        metrics: MetricsSink | None = None,
    ) -> None:
        self.store = store
        self.dispatcher = dispatcher
        self.fold_kernel = fold_kernel or FoldKernel()
        self.writer = writer
        self.metrics = metrics

    def poll_once(self, horizon: Horizon) -> BrokerPollResult:
        snapshot = self.store.snapshot()
        try:
            state = self.fold_kernel.fold(horizon, snapshot.envelopes)
        except Exception as exc:
            builder = CheckBuilder(footprint={"OutboxBroker", "FoldKernel"})
            builder.error("broker-fold", f"broker snapshot cannot be folded: {exc}")
            self._metric("pfg.broker.poll_failed", reason="fold")
            return BrokerPollResult(False, None, builder.result(digest=snapshot.digest))

        claimed = [
            (outbox_id, record)
            for outbox_id, record in sorted(state.component("outboxes").items())
            if record.get("status") == "claimed"
        ]
        if not claimed:
            self._metric("pfg.broker.idle", reason="no_claimed_outbox")
            return BrokerPollResult(True, None, CheckResult.success(footprint={"OutboxBroker"}, digest=snapshot.digest))

        outbox_id, record = claimed[0]
        started = _broker_envelope(
            outbox_id,
            "DispatchStarted",
            _next_time(snapshot.envelopes),
            self.writer,
            {
                "kind": "DispatchStarted",
                "outbox_id": outbox_id,
                "gate_id": record.get("gate_id"),
                "frame_id": record.get("frame_id"),
                "action": record.get("action"),
            },
        )
        started_append = self.store.append_atomic(horizon, snapshot.digest, (started,))
        if not started_append.ok:
            self._metric("pfg.broker.poll_failed", reason="dispatch_started_append")
            return BrokerPollResult(False, outbox_id, started_append.result)

        dispatch = self.dispatcher.dispatch(
            {
                "outbox_id": outbox_id,
                "gate_id": record.get("gate_id"),
                "frame_id": record.get("frame_id"),
                "action": record.get("action"),
            }
        )
        after_started = self.store.snapshot()
        kind = "ActuatorAccepted" if dispatch.accepted else "ActuatorRejected"
        outcome = _broker_envelope(
            outbox_id,
            kind,
            _next_time(after_started.envelopes),
            self.writer,
            {
                "kind": kind,
                "outbox_id": outbox_id,
                "gate_id": record.get("gate_id"),
                "receipt": dict(dispatch.receipt or {}),
                "error": dispatch.error,
            },
        )
        outcome_append = self.store.append_atomic(horizon, after_started.digest, (outcome,))
        self._metric("pfg.broker.dispatched" if outcome_append.ok else "pfg.broker.poll_failed", reason=kind)
        return BrokerPollResult(outcome_append.ok, outbox_id, outcome_append.result, dispatched=outcome_append.ok)

    def _metric(self, name: str, *, reason: str) -> None:
        if self.metrics is not None:
            self.metrics.increment(name, tags={"reason": reason})


def _next_time(envelopes: tuple[Envelope, ...]) -> int:
    if not envelopes:
        return 1
    return max(env.commit_time for env in envelopes) + 1


def _broker_envelope(
    outbox_id: str,
    kind: str,
    commit_time: int,
    writer: str,
    payload: Mapping[str, Any],
) -> Envelope:
    return Envelope(
        eid=f"broker:{outbox_id}:{kind}:{commit_time}",
        event=f"broker:{outbox_id}:{kind}",
        slot="0",
        commit_time=commit_time,
        writer=writer,
        owner=writer,
        version=1,
        envelope_class=EnvelopeClass.NORMAL,
        payload=dict(payload),
    )
