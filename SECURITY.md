# Security Policy

Report vulnerabilities through a private security advisory when the repository
is hosted on GitHub, or contact the maintainers through the published package
metadata.

## Scope

This project protects the audit layer.  It checks for secret-looking fields,
private key blocks, common API key formats, and machine-local paths before
payloads are accepted by the legal-log verifier.

The package does not provide cryptographic key management, hardware isolation,
or physical actuator safety by itself.  Those must be supplied by the deployment
and cited as explicit assumptions in the audit transcript.

## Baseline Checks

Run before publishing or deploying:

```bash
uv run ruff check .
uv run mypy
uv run pytest
uv run bandit -c pyproject.toml -r src
uv run pip-audit
uv build
uv run python scripts/generate_sbom.py --output sbom.json
```
