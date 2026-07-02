# Security Notes

The audit log should contain stable identifiers, digests, and finite
certificates.  It should not contain raw local paths, API keys, private keys,
tokens, passwords, or user-specific filesystem details.

## Built-In Scanner

`EnvelopeVerifier` scans every payload by default.  It rejects common secret
formats and machine-local paths such as user home directories, `.ssh`, and cloud
credential locations.  This is a guardrail, not a replacement for secret
management.

Use the scanner directly:

```bash
pfg scan log.json
```

or:

```python
from problem_frame_gate import scan_for_sensitive_data

issues = scan_for_sensitive_data({"path": "/home/person/.ssh/id_ed25519"})
assert issues
```

## Recommended Repository Controls

- Keep `.env`, private keys, database files, and local caches ignored.
- Run `uv run bandit -c pyproject.toml -r src`.
- Run `uv run pip-audit`.
- Enable GitHub secret scanning and branch protection.
- Prefer PyPI trusted publishing over long-lived API tokens.

## Deployment Boundary

The library can prove that an action claim came from a checked gate bundle.  It
does not prove that the actuator or physical environment obeyed the command.
Deployments should log actuator acceptance and effect observation separately.

## Registry And Assumption Routes

JSON-only workflows rely on manifest-declared assumptions such as
`CertificateFamilyChecker` and `StatisticalModel`.  Python deployments can reduce
that assumption footprint by passing callable `CertificateFamily`, `RiskMode`,
and `SignatureRegistry` entries to the gate/verifier path.

`production_profile()` deliberately omits the statistical assumption and provides
callable finite risk-route checkers.  It verifies route structure and timing; it
still does not prove that the external statistical model is true.
