# Schema

The stable JSON schemas are in `schemas/`:

- `horizon.schema.json`: strict manifest.
- `envelope-log.schema.json`: append-only audit log.
- `gate-request.schema.json`: action gate request.

The CLI `pfg validate-schema` performs the same required-field checks without
adding a runtime JSON-schema dependency.
