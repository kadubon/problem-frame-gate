"""Time-indexed certificate checks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .digest import digest_json
from .fold import FoldState
from .model import Horizon
from .result import CheckBuilder, CheckResult

CertificateChecker = Callable[[Mapping[str, Any], FoldState, int, Horizon | None], CheckResult]


@dataclass(frozen=True, slots=True)
class CertificateFamily:
    """Finite certificate-family policy."""

    name: str
    issuers: tuple[str, ...]
    checker: CertificateChecker | None = None
    assumption: str = ""

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name, "issuers": list(self.issuers), "assumption": self.assumption}
        if self.checker is not None:
            data["checker"] = getattr(self.checker, "__name__", "callable")
        return data

    def check(
        self, certificate: Mapping[str, Any], state: FoldState, at_time: int, horizon: Horizon | None = None
    ) -> CheckResult:
        if self.checker is None:
            declared_assumption = self.assumption and horizon is not None and self.assumption in horizon.env_assumptions
            if horizon is None or not horizon.strict or declared_assumption:
                return CheckResult.success(
                    footprint={"CertificateFamilyRegistry"},
                    assumptions=(self.assumption,) if self.assumption else (),
                )
            builder = CheckBuilder(footprint={"CertificateFamilyRegistry"})
            builder.error(
                "certificate-family-registry-checker",
                "certificate family registry entry needs a callable checker or a manifest-declared assumption",
                location=str(certificate.get("subject", certificate.get("payload_eid", ""))),
                details={"family": self.name, "assumption": self.assumption},
            )
            return builder.result()
        return self.checker(certificate, state, at_time, horizon)


def check_certificate_live(
    state: FoldState,
    cert_id: str,
    at_time: int,
    *,
    horizon: Horizon | None = None,
    registry: Mapping[str, CertificateFamily] | None = None,
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
        _check_family_record(cert_id, cert, state, at_time, builder)

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
    if registry is not None and family in registry:
        family_result = registry[family].check(cert, state, at_time, horizon)
        if not family_result.ok:
            for issue in family_result.issues:
                builder.error(issue.code, issue.message, location=issue.location, details=issue.details)
        for assumption in family_result.assumptions:
            builder.add_assumption(assumption)
    elif horizon is not None and horizon.strict:
        assumption = _family_assumption(cert)
        if not assumption or assumption not in horizon.env_assumptions:
            builder.error(
                "certificate-family-unregistered",
                "strict certificate family must have a registry checker or a declared environment assumption",
                location=cert_id,
                details={"family": family, "assumption": assumption},
            )
        else:
            builder.add_assumption(assumption)
    if cert.get("assumption"):
        builder.add_assumption(str(cert["assumption"]))
    return builder.result()


def all_certificates_live(
    state: FoldState,
    cert_ids: tuple[str, ...],
    at_time: int,
    *,
    horizon: Horizon | None = None,
    registry: Mapping[str, CertificateFamily] | None = None,
) -> CheckResult:
    result = CheckResult.success(footprint={"IssuerAuthentication", "RevocationOracle", "ClockWatermark"})
    for cert_id in cert_ids:
        result = result.merge(check_certificate_live(state, cert_id, at_time, horizon=horizon, registry=registry))
    return result


def certificate_dependency_digest(certificate: Mapping[str, Any]) -> str:
    """Digest the finite dependency/source witness carried by an issue row."""

    return digest_json(
        {
            "dependencies": sorted(str(dep) for dep in certificate.get("dependencies", ())),
            "source_ids": sorted(str(source_id) for source_id in certificate.get("source_ids", ())),
        }
    )


def _check_family_record(
    cert_id: str,
    certificate: Mapping[str, Any],
    state: FoldState,
    at_time: int,
    builder: CheckBuilder,
) -> None:
    family_check = certificate.get("family_check")
    if not isinstance(family_check, Mapping):
        builder.error(
            "certificate-family-check",
            "strict certificate must carry a finite family-check record, not a boolean flag",
            location=cert_id,
        )
        legacy_boolean = isinstance(family_check, bool) and family_check
        legacy_string = isinstance(family_check, str) and family_check in {"ok", "OK"}
        if legacy_boolean or legacy_string:
            builder.add_assumption("LegacyBooleanCertificateCheck")
        return
    if family_check.get("accepted") is not True:
        builder.error(
            "certificate-family-check",
            "certificate family checker did not accept the issue row",
            location=cert_id,
        )
    checker = family_check.get("checker")
    if not isinstance(checker, str) or not checker:
        builder.error("certificate-family-checker", "family-check record must name its checker", location=cert_id)
    transcript_digest = family_check.get("transcript_digest")
    if not _sha256_text(transcript_digest):
        builder.error(
            "certificate-family-transcript",
            "family-check record must bind a SHA-256 transcript digest",
            location=cert_id,
        )
    dependency_digest = family_check.get("dependency_digest", certificate.get("dependency_digest"))
    expected_dependency_digest = certificate_dependency_digest(certificate)
    if dependency_digest != expected_dependency_digest:
        builder.error(
            "certificate-dependency-digest",
            "certificate dependency digest does not match issue-row dependencies and sources",
            location=cert_id,
            details={"expected": expected_dependency_digest, "actual": dependency_digest},
        )
    frontier = family_check.get("revocation_frontier")
    if not isinstance(frontier, list):
        builder.error(
            "certificate-revocation-frontier",
            "family-check record must include a finite revocation frontier",
            location=cert_id,
        )
    elif any(not isinstance(item, str) for item in frontier):
        builder.error(
            "certificate-revocation-frontier",
            "revocation frontier entries must be strings",
            location=cert_id,
        )
    checked_at = family_check.get("checked_at")
    if not isinstance(checked_at, int) or checked_at > at_time:
        builder.error(
            "certificate-family-check-time",
            "family-check record must be checked no later than the use time",
            location=cert_id,
        )
    if certificate.get("payload_eid") and certificate["payload_eid"] not in state.ordered_eids:
        builder.error(
            "certificate-issue-row",
            "certificate issue row is not present in the folded source prefix",
            location=cert_id,
        )
    assumption = family_check.get("assumption")
    if isinstance(assumption, str) and assumption:
        builder.add_assumption(assumption)


def _sha256_text(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and len(value) > len("sha256:")


def _family_assumption(certificate: Mapping[str, Any]) -> str:
    family_check = certificate.get("family_check")
    if isinstance(family_check, Mapping) and isinstance(family_check.get("assumption"), str):
        return str(family_check["assumption"])
    if isinstance(certificate.get("assumption"), str):
        return str(certificate["assumption"])
    return ""
