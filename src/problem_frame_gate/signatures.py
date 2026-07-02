"""Signature-verifier registry for certificate issue rows."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from .result import CheckBuilder, CheckResult


class SignatureVerifier(Protocol):
    """Verifier for one issuer/key/algorithm tuple."""

    def verify(
        self,
        *,
        issuer: str,
        key_id: str,
        algorithm: str,
        payload_digest: str,
        signature: str,
    ) -> bool: ...


@dataclass(slots=True)
class SignatureRegistry:
    """Small deterministic registry. It does not implement cryptography itself."""

    verifiers: dict[tuple[str, str, str], SignatureVerifier] = field(default_factory=dict)

    def register(self, issuer: str, key_id: str, algorithm: str, verifier: SignatureVerifier) -> None:
        self.verifiers[(issuer, key_id, algorithm)] = verifier

    def verify(self, certificate: Mapping[str, object], *, required: bool = False) -> CheckResult:
        builder = CheckBuilder(footprint={"SignatureRegistry"})
        issuer = str(certificate.get("issuer", ""))
        key_id = certificate.get("key_id")
        algorithm = certificate.get("signature_algorithm")
        payload_digest = certificate.get("signed_payload_digest")
        signature = certificate.get("signature")
        fields_present = all(isinstance(item, str) and item for item in (key_id, algorithm, payload_digest, signature))
        if not fields_present:
            if required:
                builder.error(
                    "certificate-signature-missing",
                    "certificate requires key_id, signature_algorithm, signed_payload_digest, and signature fields",
                    location=str(certificate.get("payload_eid", certificate.get("subject", ""))),
                )
            return builder.result()
        verifier = self.verifiers.get((issuer, str(key_id), str(algorithm)))
        if verifier is None:
            builder.error(
                "certificate-signature-verifier",
                "no signature verifier is registered for the issuer/key/algorithm tuple",
                location=str(certificate.get("payload_eid", certificate.get("subject", ""))),
                details={"issuer": issuer, "key_id": key_id, "algorithm": algorithm},
            )
            return builder.result()
        if not verifier.verify(
            issuer=issuer,
            key_id=str(key_id),
            algorithm=str(algorithm),
            payload_digest=str(payload_digest),
            signature=str(signature),
        ):
            builder.error(
                "certificate-signature-invalid",
                "registered signature verifier rejected the certificate",
                location=str(certificate.get("payload_eid", certificate.get("subject", ""))),
            )
        return builder.result()
