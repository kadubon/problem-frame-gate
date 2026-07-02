"""Manifest and registry profiles for common agent deployments."""

from __future__ import annotations

from dataclasses import dataclass

from .model import Horizon
from .risk import RiskMode, standard_risk_registry

PROFILE_NAMES = (
    "browser-agent",
    "code-agent",
    "ci-deploy",
    "lab-automation",
    "finance-action",
    "email-agent",
)


@dataclass(frozen=True, slots=True)
class RuntimeProfile:
    """A named operational profile with explicit assumption boundaries."""

    name: str
    horizon: Horizon
    risk_registry: dict[str, RiskMode]
    require_callable_risk_registry: bool = False

    def to_json(self) -> dict[str, object]:
        return {
            "name": self.name,
            "horizon": self.horizon.to_json(),
            "risk_registry": sorted(self.risk_registry),
            "require_callable_risk_registry": self.require_callable_risk_registry,
        }


def example_profile(name: str = "browser-agent") -> RuntimeProfile:
    """Return a copy-paste profile that permits documented assumptions."""

    _validate_profile_name(name)
    return RuntimeProfile(
        name=name,
        horizon=Horizon.strict_default(env_assumptions=("CertificateFamilyChecker", "StatisticalModel")),
        risk_registry={},
        require_callable_risk_registry=False,
    )


def production_profile(name: str = "browser-agent") -> RuntimeProfile:
    """Return a stricter profile where risk routes require callable checkers."""

    _validate_profile_name(name)
    return RuntimeProfile(
        name=name,
        horizon=Horizon.strict_default(env_assumptions=("CertificateFamilyChecker",)),
        risk_registry=standard_risk_registry(),
        require_callable_risk_registry=True,
    )


def _validate_profile_name(name: str) -> None:
    if name not in PROFILE_NAMES:
        raise ValueError(f"unknown profile {name!r}; expected one of {', '.join(PROFILE_NAMES)}")
