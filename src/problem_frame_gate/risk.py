"""Finite risk-ledger helpers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from fractions import Fraction
from typing import Any

from .certificates import CertificateFamily, check_certificate_live
from .digest import is_sha256_digest
from .fold import FoldState
from .model import Horizon
from .result import CheckBuilder, CheckResult
from .signatures import SignatureRegistry

RiskModeChecker = Callable[["RiskClaimRecord", FoldState, int, Horizon], CheckResult]


@dataclass(frozen=True, slots=True)
class RiskRouteWitness:
    """Finite checker witness for a statistical route."""

    accepted: bool
    checker: str
    transcript_digest: str
    route: str
    spend_before_selection: bool = True
    assumption: str = "StatisticalModel"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RiskRouteWitness:
        return cls(
            accepted=bool(value.get("accepted", False)),
            checker=str(value.get("checker", "")),
            transcript_digest=str(value.get("transcript_digest", "")),
            route=str(value.get("route", "")),
            spend_before_selection=bool(value.get("spend_before_selection", True)),
            assumption=str(value.get("assumption", "StatisticalModel")),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "checker": self.checker,
            "transcript_digest": self.transcript_digest,
            "route": self.route,
            "spend_before_selection": self.spend_before_selection,
            "assumption": self.assumption,
        }


@dataclass(frozen=True, slots=True)
class RiskMode:
    """Registry entry for one risk-claim mode."""

    name: str
    checker: RiskModeChecker | None = None
    assumption: str = "StatisticalModel"

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "assumption": self.assumption}
        if self.checker is not None:
            data["checker"] = getattr(self.checker, "__name__", "callable")
        return data

    def check(self, record: RiskClaimRecord, state: FoldState, at_time: int, horizon: Horizon) -> CheckResult:
        if self.checker is None:
            if self.assumption and self.assumption in horizon.env_assumptions:
                return CheckResult.success(footprint={"RiskModeRegistry"}, assumptions=(self.assumption,))
            builder = CheckBuilder(footprint={"RiskModeRegistry"})
            builder.error(
                "risk-mode-registry-checker",
                "risk mode registry entry needs a callable checker or a manifest-declared assumption",
                location=record.claim_id,
                details={"mode": self.name, "assumption": self.assumption},
            )
            return builder.result()
        return self.checker(record, state, at_time, horizon)


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
    route_witness: RiskRouteWitness | None = None
    assumption: str = "StatisticalModel"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> RiskClaimRecord:
        if not isinstance(value, Mapping):
            raise TypeError("risk claim must be an object")
        route_witness_value = value.get("route_witness")
        route_witness = (
            RiskRouteWitness.from_mapping(route_witness_value) if isinstance(route_witness_value, Mapping) else None
        )
        return cls(
            claim_id=str(value["claim_id"]),
            risk_id=str(value["risk_id"]),
            hypothesis_id=str(value["hypothesis_id"]),
            mode=str(value["mode"]),
            cert_id=str(value["cert_id"]),
            eta=str(value["eta"]),
            event_id=str(value.get("event_id", "")),
            standardized_event_id=str(value.get("standardized_event_id", "")),
            selection_event_id=(
                str(value["selection_event_id"]) if value.get("selection_event_id") is not None else None
            ),
            stopping_time_id=str(value["stopping_time_id"]) if value.get("stopping_time_id") is not None else None,
            selection_time=int(value["selection_time"]) if value.get("selection_time") is not None else None,
            ledger_digest=str(value["ledger_digest"]) if value.get("ledger_digest") is not None else None,
            route_witness=route_witness,
            assumption=str(value.get("assumption", "StatisticalModel")),
        )

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
            "route_witness": self.route_witness.to_json() if self.route_witness else None,
            "assumption": self.assumption,
        }


def summarize_risk_ledger(state: FoldState) -> RiskLedgerSummary:
    spends: dict[str, dict[str, Any]] = state.component("risk").get("spends", {})
    total = Fraction(0)
    for spend in spends.values():
        eta = _fraction_or_none(spend.get("eta", "0"))
        if eta is not None:
            total += eta
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
        eta = _parse_fraction(
            spend.get("eta", "0"),
            builder,
            code="risk-spend-eta",
            message="risk spend eta must be a finite fraction string",
            location=risk_id,
        )
        if eta is not None and eta < 0:
            builder.error("negative-risk-spend", "risk spend must be non-negative", location=risk_id)

    summary = summarize_risk_ledger(state)
    alpha_value = None
    if alpha is not None:
        alpha_value = _parse_fraction(
            alpha,
            builder,
            code="risk-alpha-format",
            message="risk alpha bound must be a finite fraction string",
            location="alpha",
        )
    if alpha_value is not None and summary.total_spend > alpha_value:
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
    certificate_registry: Mapping[str, CertificateFamily] | None = None,
    signature_registry: SignatureRegistry | None = None,
    require_certificate_signature: bool = False,
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
    return builder.result().merge(
        check_certificate_live(
            state,
            cert_id,
            at_time,
            horizon=horizon,
            registry=certificate_registry,
            signature_registry=signature_registry,
            require_signature=require_certificate_signature,
        )
    )


def check_risk_claims(
    state: FoldState,
    records: tuple[RiskClaimRecord, ...],
    *,
    alpha: Fraction | str,
    at_time: int,
    horizon: Horizon,
    registry: Mapping[str, RiskMode] | None = None,
    certificate_registry: Mapping[str, CertificateFamily] | None = None,
    signature_registry: SignatureRegistry | None = None,
    require_certificate_signature: bool = False,
) -> CheckResult:
    """Check finite installed risk claims and their union-bound spend."""

    builder = CheckBuilder(footprint={"RiskLedger", "RiskTranscript"})
    seen_risks: set[str] = set()
    total = Fraction(0)
    for record in records:
        if record.risk_id in seen_risks:
            builder.error("risk-claim-duplicate", "risk id appears in more than one claim", location=record.risk_id)
        seen_risks.add(record.risk_id)
        eta = _parse_fraction(
            record.eta,
            builder,
            code="risk-claim-eta",
            message="risk claim eta must be a finite fraction string",
            location=record.claim_id,
        )
        if eta is not None:
            total += eta
        spend = check_risk_spend_live(
            state,
            risk_id=record.risk_id,
            hypothesis_id=record.hypothesis_id,
            mode=record.mode,
            cert_id=record.cert_id,
            at_time=at_time,
            ledger_digest=record.ledger_digest,
            horizon=horizon,
            certificate_registry=certificate_registry,
            signature_registry=signature_registry,
            require_certificate_signature=require_certificate_signature,
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
        _check_route_witness(record, horizon, builder)
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
        if registry is not None and record.mode in registry:
            mode_result = registry[record.mode].check(record, state, at_time, horizon)
            if not mode_result.ok:
                for issue in mode_result.issues:
                    builder.error(issue.code, issue.message, location=issue.location, details=issue.details)
            for assumption in mode_result.assumptions:
                builder.add_assumption(assumption)
        elif horizon.strict:
            witness_assumption = (
                record.route_witness.assumption if record.route_witness is not None else record.assumption
            )
            if not witness_assumption or witness_assumption not in horizon.env_assumptions:
                builder.error(
                    "risk-mode-unregistered",
                    "strict risk mode must have a registry checker or a declared environment assumption",
                    location=record.claim_id,
                    details={"mode": record.mode, "assumption": witness_assumption},
                )
        if record.assumption:
            builder.add_assumption(record.assumption)
    alpha_value = _parse_fraction(
        alpha,
        builder,
        code="risk-alpha-format",
        message="risk alpha bound must be a finite fraction string",
        location="alpha",
    )
    if alpha_value is not None and total > alpha_value:
        builder.error(
            "risk-alpha-bound",
            "finite risk spend exceeds the declared alpha bound",
            details={"total": str(total), "alpha": str(alpha)},
        )
    return builder.result()


def standard_risk_registry() -> dict[str, RiskMode]:
    """Return callable checkers for the four built-in finite risk routes."""

    return {
        "fixed": RiskMode("fixed", checker=_standard_risk_mode_checker, assumption=""),
        "selectedEvent": RiskMode("selectedEvent", checker=_standard_risk_mode_checker, assumption=""),
        "conditionalSelective": RiskMode("conditionalSelective", checker=_standard_risk_mode_checker, assumption=""),
        "anytime": RiskMode("anytime", checker=_standard_risk_mode_checker, assumption=""),
    }


def _standard_risk_mode_checker(
    record: RiskClaimRecord,
    state: FoldState,
    at_time: int,
    horizon: Horizon,
) -> CheckResult:
    builder = CheckBuilder(footprint={"RiskModeRegistry", "RiskTranscript"})
    if record.mode not in horizon.risk_modes:
        builder.error("risk-mode-undeclared", "risk mode is not declared by the manifest", location=record.claim_id)
    if record.route_witness is None or not record.route_witness.accepted:
        builder.error("risk-route-check", "risk route must carry an accepted finite witness", location=record.claim_id)
    if record.mode == "fixed" and not record.event_id:
        builder.error("risk-fixed-event", "fixed mode requires a failure event", location=record.claim_id)
    if record.mode in {"selectedEvent", "conditionalSelective"} and not record.selection_event_id:
        builder.error(
            "risk-selection-event",
            "selected risk routes require a finite selection event",
            location=record.claim_id,
        )
    if record.mode == "anytime" and not record.stopping_time_id:
        builder.error("risk-stopping-time", "anytime mode requires a stopping-time witness", location=record.claim_id)
    reserve = state.component("risk").get("reserves", {}).get(record.risk_id, {})
    if record.selection_time is not None and int(reserve.get("reserved_at", at_time + 1)) >= record.selection_time:
        builder.error(
            "risk-post-selection-reserve",
            "risk reserve must precede the selection or stopping decision",
            location=record.claim_id,
        )
    return builder.result()


def _check_route_witness(record: RiskClaimRecord, horizon: Horizon, builder: CheckBuilder) -> None:
    witness = record.route_witness
    if witness is None:
        builder.error(
            "risk-route-witness",
            "risk claim must carry a finite route witness instead of a boolean route flag",
            location=record.claim_id,
        )
        builder.add_assumption(record.assumption)
        return
    if not witness.accepted:
        builder.error("risk-route-check", "risk route witness was not accepted", location=record.claim_id)
    if not witness.checker:
        builder.error("risk-route-checker", "risk route witness must name its checker", location=record.claim_id)
    if not is_sha256_digest(witness.transcript_digest):
        builder.error(
            "risk-route-transcript",
            "risk route witness must bind a SHA-256 transcript digest",
            location=record.claim_id,
        )
    if witness.route != record.mode:
        builder.error(
            "risk-route-mode",
            "risk route witness route must match the claim mode",
            location=record.claim_id,
            details={"expected": record.mode, "actual": witness.route},
        )
    if not witness.spend_before_selection:
        builder.error(
            "risk-spend-before-selection",
            "risk spend must be reserved before route selection or stopping",
            location=record.claim_id,
        )
    if witness.assumption:
        if horizon.strict and witness.assumption not in horizon.env_assumptions:
            builder.error(
                "risk-assumption-undeclared",
                "risk route assumption must be declared by the strict manifest",
                location=record.claim_id,
                details={"assumption": witness.assumption},
            )
        builder.add_assumption(witness.assumption)


def _parse_fraction(
    value: Any,
    builder: CheckBuilder,
    *,
    code: str,
    message: str,
    location: str,
) -> Fraction | None:
    parsed = _fraction_or_none(value)
    if parsed is None:
        builder.error(code, message, location=location, details={"value": str(value)})
    return parsed


def _fraction_or_none(value: Any) -> Fraction | None:
    try:
        return Fraction(str(value))
    except (TypeError, ValueError, ZeroDivisionError):
        return None
