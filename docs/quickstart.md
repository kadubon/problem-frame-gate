# Quickstart

Problem Frame Gate is strict by default.  Start with a manifest:

```bash
pip install problem-frame-gate
pfg init-manifest > horizon.json
```

Prepare a JSON audit log using `schemas/envelope-log.schema.json`, then run:

```bash
pfg validate-schema horizon horizon.json
pfg validate-schema log log.json
pfg verify-log --horizon horizon.json log.json
```

Before an AI system writes to an external tool, create a gate request and run:

```bash
pfg validate-schema gate-request gate-request.json
pfg check-gate --horizon horizon.json --bundle gate-request.json log.json
```

Only append and dispatch the returned five-row bundle after `ok` is true.

For local development, use:

```bash
uv sync --all-extras
uv run pytest
```
