"""Time-indexed certificate checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .fold import FoldState
from .model import Horizon
from .result import CheckBuilder, CheckResult


@dataclass(frozen=True, slots=True)
class CertificateFamily:
    """Finite certificate-family policy."""

    name: str
    issuers: tuple[str, ...]
    assumption: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "issuers": list(self.issuers), "assumption": self.assumption}


def check_certificate_live(
    state: FoldState, cert_id: str, at_time: int, *, horizon: Horizon | None = None
) -> CheckResult:
    """Check that a certificate was issued and not revoked or expired at a time."""

    builder = CheckBuilder(footprint={"IssuerAuthentication", "RevocationOracle", "ClockWatermark"})
    certs: dict[str, dict[str, Any]] = state.component("certificates")
    cert = certs.get(cert_id)
    if cert is None or not cert.get("issued"):
        builder.error("certificate-missing", "certificate is not issued", location=cert_id)
        return builder.result()

    issued_at = int(cert.get("issued_at", 0))
    if issued_at > at_time:
        builder.error(
            "certificate-issued-after-use",
            "certificate issue time is after the checked time",
            location=cert_id,
            details={"issued_at": issued_at, "at_time": at_time},
        )

    revoked_at = cert.get("revoked_at")
    if revoked_at is not None and int(revoked_at) <= at_time:
        builder.error(
            "certificate-revoked",
            "certificate is revoked at the checked time",
            location=cert_id,
            details={"revoked_at": revoked_at, "at_time": at_time},
        )

    expires_at = cert.get("expires_at")
    if expires_at is not None and int(expires_at) <= at_time:
        builder.error(
            "certificate-expired",
            "certificate is expired at the checked time",
            location=cert_id,
            details={"expires_at": expires_at, "at_time": at_time},
        )

    family = str(cert.get("family", ""))
    issuer = str(cert.get("issuer", ""))
    if horizon is not None and horizon.strict:
        allowed_issuers = horizon.certificate_families.get(family)
        if allowed_issuers is None:
            builder.error("certificate-family", "certificate family is not declared by the manifest", location=cert_id)
        elif issuer not in allowed_issuers:
            builder.error(
                "certificate-issuer",
                "certificate issuer is not authorized for its family",
                location=cert_id,
                details={"family": family, "issuer": issuer, "allowed": list(allowed_issuers)},
            )
        if cert.get("family_check") not in {True, "ok", "OK"}:
            builder.error(
                "certificate-family-check",
                "strict certificate must carry an accepted finite family check",
                location=cert_id,
            )

    ordered = set(state.ordered_eids)
    evidence = state.component("evidence")
    for dep in cert.get("dependencies", ()):
        dep_id = str(dep)
        if dep_id not in ordered and dep_id not in evidence and dep_id not in certs:
            builder.error(
                "certificate-dependency",
                "certificate dependency is absent from the source prefix",
                location=cert_id,
                details={"dependency": dep_id},
            )
    for source_id in cert.get("source_ids", ()):
        source = evidence.get(str(source_id))
        if source is None:
            builder.error("certificate-source", "certificate source object is absent", location=str(source_id))
        elif int(source.get("committed_at", 0)) > at_time:
            builder.error(
                "certificate-source-time",
                "certificate source object is committed after the checked time",
                location=str(source_id),
            )
    if cert.get("assumption"):
        builder.add_assumption(str(cert["assumption"]))
    return builder.result()


def all_certificates_live(
    state: FoldState, cert_ids: tuple[str, ...], at_time: int, *, horizon: Horizon | None = None
) -> CheckResult:
    result = CheckResult.success(footprint={"IssuerAuthentication", "RevocationOracle", "ClockWatermark"})
    for cert_id in cert_ids:
        result = result.merge(check_certificate_live(state, cert_id, at_time, horizon=horizon))
    return result
