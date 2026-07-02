"""Small JSON-schema subset used by the CLI and tests.

The project intentionally keeps runtime dependencies at zero.  This module
therefore implements only the JSON Schema keywords used by the bundled public
schemas, not a general-purpose JSON Schema engine.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

Schema = Mapping[str, Any]

SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
FRACTION_PATTERN = r"^-?(0|[1-9][0-9]*)(/[1-9][0-9]*)?$"


HORIZON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "strict",
        "capacities",
        "writer_authority",
        "version_intervals",
        "protected_constructors",
        "gate_bundle_kinds",
        "executor_writer",
        "clock_policy",
        "certificate_families",
        "risk_modes",
    ],
    "properties": {
        "strict": {"const": True},
        "events": {"type": "array", "items": {"type": "string"}},
        "causal_order": {"type": "array", "items": {"$ref": "order-edge"}},
        "availability_order": {"type": "array", "items": {"$ref": "order-edge"}},
        "audit_order": {"type": "array", "items": {"$ref": "order-edge"}},
        "capacities": {
            "type": "object",
            "required": ["normal", "abort", "failClosed"],
            "properties": {
                "normal": {"type": "integer", "minimum": 0},
                "abort": {"type": "integer", "minimum": 0},
                "failClosed": {"type": "integer", "minimum": 0},
            },
            "additionalProperties": False,
        },
        "writer_authority": {"type": "object", "additionalProperties": {"$ref": "string-array"}},
        "version_intervals": {"type": "object", "additionalProperties": {"$ref": "version-interval"}},
        "commit_groups": {"type": "object", "additionalProperties": {"$ref": "string-array"}},
        "protected_constructors": {"type": "object", "additionalProperties": {"$ref": "string-array"}},
        "gate_bundle_kinds": {
            "type": "array",
            "prefixItems": [
                {"const": "GateCheck"},
                {"const": "OutboxClaim"},
                {"const": "UseCap"},
                {"const": "ConsumeResource"},
                {"const": "RiskClose"},
            ],
            "minItems": 5,
            "maxItems": 5,
        },
        "executor_writer": {"type": "string", "minLength": 1},
        "clock_policy": {"type": "string", "minLength": 1},
        "certificate_families": {"type": "object", "additionalProperties": {"$ref": "string-array"}},
        "risk_modes": {
            "type": "array",
            "prefixItems": [
                {"const": "fixed"},
                {"const": "selectedEvent"},
                {"const": "conditionalSelective"},
                {"const": "anytime"},
            ],
            "minItems": 4,
            "maxItems": 4,
        },
        "env_assumptions": {"type": "array", "items": {"type": "string"}},
        "codebook": {"type": "array", "items": {"type": "string"}},
        "allow_local_paths": {"type": "boolean"},
    },
    "additionalProperties": False,
}


ENVELOPE_LOG_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {
        "type": "object",
        "required": ["eid", "event", "slot", "commit", "writer", "owner", "version", "class", "payload"],
        "properties": {
            "eid": {"type": "string", "minLength": 1},
            "event": {"type": "string", "minLength": 1},
            "slot": {"type": "string"},
            "commit": {"type": "integer"},
            "commit_time": {"type": "integer"},
            "writer": {"type": "string", "minLength": 1},
            "owner": {"type": "string"},
            "version": {"type": "integer", "minimum": 1},
            "class": {"enum": ["normal", "abort", "failClosed"]},
            "envelope_class": {"enum": ["normal", "abort", "failClosed"]},
            "payload": {
                "type": "object",
                "required": ["kind"],
                "properties": {"kind": {"type": "string", "minLength": 1}},
                "additionalProperties": True,
            },
            "dependencies": {
                "type": "array",
                "items": {"anyOf": [{"type": "string"}, {"$ref": "dependency-ref"}]},
            },
            "commit_group": {"type": ["string", "null"]},
        },
        "additionalProperties": False,
    },
}


GATE_REQUEST_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "gate_id",
        "bundle_id",
        "frame_id",
        "action",
        "outbox_id",
        "capability_id",
        "lease_id",
        "risk_id",
        "hypothesis_id",
        "risk_mode",
        "risk_cert_id",
        "source_time",
        "commit_time",
        "risk_claim",
        "risk_alpha",
    ],
    "properties": {
        "gate_id": {"type": "string", "minLength": 1},
        "bundle_id": {"type": "string", "minLength": 1},
        "frame_id": {"type": "string", "minLength": 1},
        "action": {"type": "string", "minLength": 1},
        "outbox_id": {"type": "string", "minLength": 1},
        "capability_id": {"type": "string", "minLength": 1},
        "lease_id": {"type": "string", "minLength": 1},
        "risk_id": {"type": "string", "minLength": 1},
        "hypothesis_id": {"type": "string", "minLength": 1},
        "risk_mode": {"enum": ["fixed", "selectedEvent", "conditionalSelective", "anytime"]},
        "risk_cert_id": {"type": "string", "minLength": 1},
        "source_time": {"type": "integer"},
        "commit_time": {"type": "integer"},
        "executor_id": {"type": "string"},
        "resource_amount": {},
        "ledger_digest": {"type": ["string", "null"], "pattern": SHA256_PATTERN},
        "expected_source_digest": {"type": ["string", "null"], "pattern": SHA256_PATTERN},
        "required_certificate_ids": {"$ref": "string-array"},
        "risk_claim": {"$ref": "risk-claim"},
        "risk_alpha": {"$ref": "fraction"},
        "metadata": {"type": "object", "additionalProperties": True},
    },
    "additionalProperties": False,
}


GATE_RECORD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "gate_id",
        "bundle_id",
        "frame_id",
        "action",
        "outbox_id",
        "capability_id",
        "lease_id",
        "risk_id",
        "hypothesis_id",
        "risk_mode",
        "risk_cert_id",
        "source_digest",
        "ledger_digest",
        "transcript_digest",
        "source_time",
        "commit_time",
    ],
    "properties": {
        "gate_id": {"type": "string", "minLength": 1},
        "bundle_id": {"type": "string", "minLength": 1},
        "frame_id": {"type": "string", "minLength": 1},
        "action": {"type": "string", "minLength": 1},
        "outbox_id": {"type": "string", "minLength": 1},
        "capability_id": {"type": "string", "minLength": 1},
        "lease_id": {"type": "string", "minLength": 1},
        "risk_id": {"type": "string", "minLength": 1},
        "hypothesis_id": {"type": "string", "minLength": 1},
        "risk_mode": {"type": "string", "minLength": 1},
        "risk_cert_id": {"type": "string", "minLength": 1},
        "source_digest": {"$ref": "sha256-digest"},
        "ledger_digest": {"type": ["string", "null"], "pattern": SHA256_PATTERN},
        "transcript_digest": {"$ref": "sha256-digest"},
        "source_time": {"type": "integer"},
        "commit_time": {"type": "integer"},
    },
    "additionalProperties": False,
}


SOURCE_CUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "cut_id",
        "source_time",
        "included_eids",
        "excluded_frontier_eids",
        "digest",
        "clock_rows",
        "watermark_rows",
    ],
    "properties": {
        "cut_id": {"type": "string", "minLength": 1},
        "source_time": {"type": "integer"},
        "included_eids": {"$ref": "string-array"},
        "excluded_frontier_eids": {"$ref": "string-array"},
        "digest": {"$ref": "sha256-digest"},
        "clock_rows": {"$ref": "string-array"},
        "watermark_rows": {"$ref": "string-array"},
    },
    "additionalProperties": False,
}


RISK_CLAIM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": [
        "claim_id",
        "risk_id",
        "hypothesis_id",
        "mode",
        "cert_id",
        "eta",
        "event_id",
        "standardized_event_id",
        "route_witness",
        "assumption",
    ],
    "properties": {
        "claim_id": {"type": "string", "minLength": 1},
        "risk_id": {"type": "string", "minLength": 1},
        "hypothesis_id": {"type": "string", "minLength": 1},
        "mode": {"enum": ["fixed", "selectedEvent", "conditionalSelective", "anytime"]},
        "cert_id": {"type": "string", "minLength": 1},
        "eta": {"$ref": "fraction"},
        "event_id": {"type": "string"},
        "standardized_event_id": {"type": "string"},
        "selection_event_id": {"type": ["string", "null"]},
        "stopping_time_id": {"type": ["string", "null"]},
        "selection_time": {"type": ["integer", "null"]},
        "ledger_digest": {"type": ["string", "null"], "pattern": SHA256_PATTERN},
        "route_witness": {"$ref": "risk-route-witness"},
        "assumption": {"type": "string", "minLength": 1},
    },
    "additionalProperties": False,
}


GATE_BUNDLE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["record", "envelopes", "source_cut"],
    "properties": {
        "record": {"$ref": "gate-record"},
        "envelopes": {"type": "array", "items": {"$ref": "envelope"}, "minItems": 5, "maxItems": 5},
        "source_cut": {"$ref": "source-cut"},
    },
    "additionalProperties": False,
}


REPLAY_CERTIFICATE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["word", "swaps", "cover", "target_digest"],
    "properties": {
        "word": {"$ref": "string-array"},
        "swaps": {
            "type": "array",
            "items": {
                "type": "array",
                "prefixItems": [{"type": "integer"}, {"type": "string"}, {"type": "string"}],
                "minItems": 3,
                "maxItems": 3,
            },
        },
        "cover": {"$ref": "swap-cover"},
        "target_digest": {"$ref": "sha256-digest"},
    },
    "additionalProperties": False,
}


PATCH_PROPOSAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["expected_source_digest", "append", "write_cover", "touch_matrix"],
    "properties": {
        "expected_source_digest": {"$ref": "sha256-digest"},
        "append": {"type": "array", "items": {"$ref": "envelope"}},
        "affected_invariants": {"$ref": "string-array"},
        "write_classes": {"type": "array", "items": {"$ref": "write-class"}},
        "write_cover": {"$ref": "write-cover"},
        "read_footprints": {"type": "array", "items": {"$ref": "read-footprint"}},
        "touch_matrix": {"type": "object", "additionalProperties": {"type": "string"}},
        "transported_cells": {"$ref": "string-array"},
        "liveness_repairs": {"$ref": "string-array"},
        "transcript_digest": {"type": ["string", "null"], "pattern": SHA256_PATTERN},
    },
    "additionalProperties": False,
}


JOIN_PROPOSAL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["branches", "ancestor"],
    "properties": {
        "branches": {"type": "array", "items": {"type": "array", "items": {"$ref": "envelope"}}},
        "ancestor": {"type": "array", "items": {"$ref": "envelope"}},
        "repairs": {"type": "array", "items": {"$ref": "envelope"}},
        "escrow_conflicts": {"$ref": "string-array"},
        "join_keys": {"type": "array", "items": {"$ref": "join-key"}},
        "repair_witnesses": {"type": "array", "items": {"$ref": "repair-witness"}},
        "affected_invariants": {"$ref": "string-array"},
        "repair_rechecks": {"$ref": "string-array"},
        "liveness_repairs": {"$ref": "string-array"},
        "transcript_digest": {"type": ["string", "null"], "pattern": SHA256_PATTERN},
    },
    "additionalProperties": False,
}


REACHABILITY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["transitions", "assumptions"],
    "properties": {
        "transitions": {"type": "array", "items": {"$ref": "transition-record"}},
        "assumptions": {"$ref": "string-array"},
    },
    "additionalProperties": False,
}


REFS: dict[str, dict[str, Any]] = {
    "envelope": ENVELOPE_LOG_SCHEMA["items"],
    "gate-record": GATE_RECORD_SCHEMA,
    "source-cut": SOURCE_CUT_SCHEMA,
    "risk-claim": RISK_CLAIM_SCHEMA,
    "risk-route-witness": {
        "type": "object",
        "required": ["accepted", "checker", "transcript_digest", "route", "spend_before_selection", "assumption"],
        "properties": {
            "accepted": {"const": True},
            "checker": {"type": "string", "minLength": 1},
            "transcript_digest": {"$ref": "sha256-digest"},
            "route": {"type": "string", "minLength": 1},
            "spend_before_selection": {"type": "boolean"},
            "assumption": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    },
    "swap-cover": {
        "type": "object",
        "required": ["independent_pairs", "component_equalities"],
        "properties": {
            "independent_pairs": {
                "type": "array",
                "items": {
                    "type": "array",
                    "prefixItems": [{"type": "string"}, {"type": "string"}],
                    "minItems": 2,
                    "maxItems": 2,
                },
            },
            "component_equalities": {"$ref": "string-array"},
        },
        "additionalProperties": False,
    },
    "write-class": {
        "type": "object",
        "required": ["name", "object_id"],
        "properties": {"name": {"type": "string", "minLength": 1}, "object_id": {"type": "string"}},
        "additionalProperties": False,
    },
    "write-cover": {
        "type": "object",
        "required": ["classes", "covered_eids"],
        "properties": {
            "classes": {"type": "array", "items": {"$ref": "write-class"}},
            "covered_eids": {"$ref": "string-array"},
        },
        "additionalProperties": False,
    },
    "read-footprint": {
        "type": "object",
        "required": ["invariant", "entries"],
        "properties": {"invariant": {"type": "string", "minLength": 1}, "entries": {"$ref": "string-array"}},
        "additionalProperties": False,
    },
    "join-key": {
        "type": "object",
        "required": ["key", "branch_eids"],
        "properties": {"key": {"type": "string", "minLength": 1}, "branch_eids": {"$ref": "string-array"}},
        "additionalProperties": False,
    },
    "repair-witness": {
        "type": "object",
        "required": ["repair_eid", "conflict_key", "rechecked", "transcript_digest"],
        "properties": {
            "repair_eid": {"type": "string", "minLength": 1},
            "conflict_key": {"type": "string", "minLength": 1},
            "rechecked": {"type": "boolean"},
            "transcript_digest": {"$ref": "sha256-digest"},
        },
        "additionalProperties": False,
    },
    "transition-record": {
        "type": "object",
        "required": [
            "source_digest",
            "target_digest",
            "kind",
            "transcript_digest",
            "witness_kind",
            "witness_digest",
            "capacity_class",
            "witness",
        ],
        "properties": {
            "source_digest": {"$ref": "sha256-digest"},
            "target_digest": {"$ref": "sha256-digest"},
            "kind": {"enum": ["patch", "join", "gate", "abort", "failClosed"]},
            "transcript_digest": {"$ref": "sha256-digest"},
            "witness_kind": {"type": "string", "minLength": 1},
            "witness_digest": {"$ref": "sha256-digest"},
            "capacity_class": {"enum": ["normal", "abort", "failClosed"]},
            "witness": {"type": "object", "additionalProperties": True},
        },
        "additionalProperties": False,
    },
    "sha256-digest": {"type": "string", "pattern": SHA256_PATTERN},
    "fraction": {"type": "string", "pattern": FRACTION_PATTERN},
    "dependency-ref": {
        "type": "object",
        "properties": {
            "eid": {"type": "string"},
            "event": {"type": "string"},
            "slot": {"type": "string"},
        },
        "additionalProperties": False,
    },
    "order-edge": {
        "anyOf": [
            {
                "type": "array",
                "prefixItems": [{"type": "string"}, {"type": "string"}],
                "minItems": 2,
                "maxItems": 2,
            },
            {
                "type": "object",
                "required": ["before", "after"],
                "properties": {"before": {"type": "string"}, "after": {"type": "string"}},
                "additionalProperties": False,
            },
        ]
    },
    "string-array": {"type": "array", "items": {"type": "string", "minLength": 1}},
    "version-interval": {
        "type": "object",
        "required": ["minimum", "maximum"],
        "properties": {
            "minimum": {"type": "integer", "minimum": 1},
            "maximum": {"type": "integer", "minimum": 1},
        },
        "additionalProperties": False,
    },
}


SCHEMAS: dict[str, dict[str, Any]] = {
    "horizon": HORIZON_SCHEMA,
    "log": ENVELOPE_LOG_SCHEMA,
    "gate-request": GATE_REQUEST_SCHEMA,
    "gate-bundle": GATE_BUNDLE_SCHEMA,
    "source-cut": SOURCE_CUT_SCHEMA,
    "replay-certificate": REPLAY_CERTIFICATE_SCHEMA,
    "risk-claim": RISK_CLAIM_SCHEMA,
    "patch-proposal": PATCH_PROPOSAL_SCHEMA,
    "join-proposal": JOIN_PROPOSAL_SCHEMA,
    "reachability": REACHABILITY_SCHEMA,
}


def validate_json_artifact(kind: str, data: Any) -> list[str]:
    """Validate one public JSON artifact and return deterministic errors."""

    schema = SCHEMAS.get(kind)
    if schema is None:
        return [f"unknown schema kind: {kind}"]
    errors: list[str] = []
    _validate(data, schema, "$", errors)
    return errors


def _validate(value: Any, schema: Schema, path: str, errors: list[str]) -> None:
    if "$ref" in schema:
        _validate(value, REFS[str(schema["$ref"])], path, errors)
        return
    if "anyOf" in schema:
        alternatives = schema["anyOf"]
        if not isinstance(alternatives, Sequence):
            errors.append(f"{path}: anyOf must be an array")
            return
        for alternative in alternatives:
            trial: list[str] = []
            _validate(value, alternative, path, trial)
            if not trial:
                return
        errors.append(f"{path}: value does not match any allowed shape")
        return
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
        return
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {list(schema['enum'])!r}")
        return

    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(value, expected_type):
        errors.append(f"{path}: expected type {_type_label(expected_type)}")
        return

    if isinstance(value, str):
        minimum = schema.get("minLength")
        if isinstance(minimum, int) and len(value) < minimum:
            errors.append(f"{path}: string is shorter than {minimum}")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            errors.append(f"{path}: string does not match pattern {pattern}")
    if isinstance(value, int) and not isinstance(value, bool):
        minimum_number = schema.get("minimum")
        if isinstance(minimum_number, int | float) and value < minimum_number:
            errors.append(f"{path}: value is smaller than {minimum_number}")
    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if isinstance(minimum_items, int) and len(value) < minimum_items:
            errors.append(f"{path}: array has fewer than {minimum_items} items")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            errors.append(f"{path}: array has more than {maximum_items} items")
        prefix_items = schema.get("prefixItems")
        if isinstance(prefix_items, Sequence):
            for index, item_schema in enumerate(prefix_items):
                if index < len(value):
                    _validate(value[index], item_schema, f"{path}[{index}]", errors)
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            start = len(prefix_items) if isinstance(prefix_items, Sequence) else 0
            for index, item in enumerate(value[start:], start=start):
                _validate(item, item_schema, f"{path}[{index}]", errors)
    if isinstance(value, Mapping):
        required = schema.get("required", ())
        if isinstance(required, Sequence):
            for field in required:
                if field not in value:
                    errors.append(f"{path}: missing {field}")
        properties = schema.get("properties", {})
        if isinstance(properties, Mapping):
            for field, field_schema in properties.items():
                if field in value:
                    _validate(value[field], field_schema, f"{path}.{field}", errors)
        additional = schema.get("additionalProperties", True)
        known = set(properties) if isinstance(properties, Mapping) else set()
        for field, item in value.items():
            if field in known:
                continue
            if additional is False:
                errors.append(f"{path}.{field}: additional property is not allowed")
            elif isinstance(additional, Mapping):
                _validate(item, additional, f"{path}.{field}", errors)


def _matches_type(value: Any, expected_type: Any) -> bool:
    if isinstance(expected_type, Sequence) and not isinstance(expected_type, str):
        return any(_matches_type(value, item) for item in expected_type)
    if expected_type == "object":
        return isinstance(value, Mapping)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "null":
        return value is None
    return True


def _type_label(expected_type: Any) -> str:
    if isinstance(expected_type, Sequence) and not isinstance(expected_type, str):
        return "|".join(str(item) for item in expected_type)
    return str(expected_type)
