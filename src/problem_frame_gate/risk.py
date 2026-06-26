"""Finite risk-ledger helpers."""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .certificates import check_certificate_live
from .fold import FoldState
from .model import Horizon
from .result import CheckBuilder, CheckResult


@dataclass(frozen=True, slots=True)
class RiskLedgerSummary:
    total_spend: Fraction
    spend_ids: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "total_spend": f"{self.total_spend.numerator}/{self.total_spend.denominator}",
            "spend_ids": list(self.spend_ids),
        }


@dataclass(frozen=True, slots=True)
class RiskClaimRecord:
    """Finite risk-claim record used by the risk theorem."""

    claim_id: str
    risk_id: str
    hypothesis_id: str
    mode: str
    cert_id: str
    eta: str
    event_id: str
    standardized_event_id: str
    selection_event_id: str | None = None
    stopping_time_id: str | None = None
    selection_time: int | None = None
    ledger_digest: str | None = None
    route_check: bool = True
    assumption: str = "StatisticalModel"

    def to_json(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "risk_id": self.risk_id,
            "hypothesis_id": self.hypothesis_id,
            "mode": self.mode,
            "cert_id": self.cert_id,
            "eta": self.eta,
            "event_id": self.event_id,
            "standardized_event_id": self.standardized_event_id,
            "selection_event_id": self.selection_event_id,
            "stopping_time_id": self.stopping_time_id,
            "selection_time": self.selection_time,
            "ledger_digest": self.ledger_digest,
            "route_check": self.route_check,
            "assumption": self.assumption,
        }


def summarize_risk_ledger(state: FoldState) -> RiskLedgerSummary:
    spends: dict[str, dict[str, Any]] = state.component("risk").get("spends", {})
    total = sum((Fraction(str(spend.get("eta", "0"))) for spend in spends.values()), start=Fraction(0))
    return RiskLedgerSummary(total, tuple(sorted(spends)))


def check_risk_ledger(state: FoldState, *, alpha: Fraction | str | None = None) -> CheckResult:
    """Check finite spend accounting and an optional global risk bound."""

    builder = CheckBuilder(footprint={"RiskLedger", "RiskTranscript"})
    risk = state.component("risk")
    reserves: dict[str, dict[str, Any]] = risk.get("reserves", {})
    spends: dict[str, dict[str, Any]] = risk.get("spends", {})

    for risk_id, spend in spends.items():
        reserve = reserves.get(risk_id)
        if reserve is None:
            builder.error("risk-spend-without-reserve", "risk spend has no reserve", location=risk_id)
            continue
        if int(reserve.get("reserved_at", 0)) > int(spend.get("spent_at", 0)):
            builder.error("risk-order", "risk spend precedes its reserve", location=risk_id)
        if Fraction(str(spend.get("eta", "0"))) < 0:
            builder.error("negative-risk-spend", "risk spend must be non-negative", location=risk_id)

    summary = summarize_risk_ledger(state)
    if alpha is not None and summary.total_spend > Fraction(str(alpha)):
        builder.error(
            "risk-bound-exceeded",
            "finite risk spend exceeds the declared bound",
            details={"total": str(summary.total_spend), "alpha": str(alpha)},
        )
    return builder.result()


def check_risk_spend_live(
    state: FoldState,
    *,
    risk_id: str,
    hypothesis_id: str,
    mode: str,
    cert_id: str,
    at_time: int,
    ledger_digest: str | None = None,
    horizon: Horizon | None = None,
) -> CheckResult:
    """Before-use check for one risk spend."""

    builder = CheckBuilder(footprint={"RiskLedger", "RiskTranscript", "ClockWatermark"})
    risk = state.component("risk")
    spend = risk.get("spends", {}).get(risk_id)
    if spend is None:
        builder.error("risk-spend-missing", "risk spend is not installed", location=risk_id)
        return builder.result()
    if spend.get("hypothesis_id") != hypothesis_id:
        builder.error("risk-hypothesis-mismatch", "risk spend cites a different hypothesis", location=risk_id)
    if spend.get("mode") != mode:
        builder.error("risk-mode-mismatch", "risk spend cites a different statistical mode", location=risk_id)
    if horizon is not None and mode not in horizon.risk_modes:
        builder.error("risk-mode-undeclared", "risk mode is not declared by the manifest", location=risk_id)
    if spend.get("cert_id") != cert_id:
        builder.error("risk-cert-mismatch", "risk spend cites a different certificate", location=risk_id)
    if ledger_digest is not None and spend.get("ledger_digest") != ledger_digest:
        builder.error("risk-ledger-mismatch", "risk spend cites a different ledger digest", location=risk_id)
    if int(spend.get("spent_at", 0)) > at_time:
        builder.error("risk-spend-after-use", "risk spend is committed after use", location=risk_id)
    closed_at = spend.get("closed_at")
    if closed_at is not None and int(closed_at) <= at_time:
        builder.error("risk-spend-closed", "risk spend is already closed at use time", location=risk_id)
    return builder.result().merge(check_certificate_live(state, cert_id, at_time, horizon=horizon))


def check_risk_claims(
    state: FoldState,
    records: tuple[RiskClaimRecord, ...],
    *,
    alpha: Fraction | str,
    at_time: int,
    horizon: Horizon,
) -> CheckResult:
    """Check finite installed risk claims and their union-bound spend."""

    builder = CheckBuilder(footprint={"RiskLedger", "RiskTranscript"})
    seen_risks: set[str] = set()
    total = Fraction(0)
    for record in records:
        if record.risk_id in seen_risks:
            builder.error("risk-claim-duplicate", "risk id appears in more than one claim", location=record.risk_id)
        seen_risks.add(record.risk_id)
        total += Fraction(record.eta)
        spend = check_risk_spend_live(
            state,
            risk_id=record.risk_id,
            hypothesis_id=record.hypothesis_id,
            mode=record.mode,
            cert_id=record.cert_id,
            at_time=at_time,
            ledger_digest=record.ledger_digest,
            horizon=horizon,
        )
        if not spend.ok:
            for issue in spend.issues:
                builder.error(issue.code, issue.message, location=issue.location, details=issue.details)
        if record.mode == "fixed" and not record.event_id:
            builder.error("risk-fixed-event", "fixed mode requires a failure event", location=record.claim_id)
        if record.mode == "selectedEvent" and not record.selection_event_id:
            builder.error(
                "risk-selection-event",
                "selected-event mode requires a selection event",
                location=record.claim_id,
            )
        if record.mode == "conditionalSelective" and not record.route_check:
            builder.error(
                "risk-conditional-route",
                "conditional-selective mode requires an accepted route check",
                location=record.claim_id,
            )
        if record.mode == "anytime" and not record.stopping_time_id:
            builder.error(
                "risk-stopping-time",
                "anytime mode requires a certified stopping time",
                location=record.claim_id,
            )
        if record.selection_time is not None:
            reserve = state.component("risk").get("reserves", {}).get(record.risk_id, {})
            if int(reserve.get("reserved_at", at_time + 1)) >= record.selection_time:
                builder.error(
                    "risk-post-selection-reserve",
                    "risk reserve must precede the selection or stopping decision",
                    location=record.claim_id,
                )
        if record.assumption:
            builder.add_assumption(record.assumption)
    if total > Fraction(str(alpha)):
        builder.error(
            "risk-alpha-bound",
            "finite risk spend exceeds the declared alpha bound",
            details={"total": str(total), "alpha": str(alpha)},
        )
    return builder.result()
