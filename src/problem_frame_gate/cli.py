"""Command line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .digest import digest_json
from .fold import FoldKernel
from .gate import ExecutorGate, GateRequest
from .model import Envelope, Horizon
from .security import scan_for_sensitive_data
from .verifier import EnvelopeVerifier


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pfg", description="Finite audit-log checker for AI action gates")
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = sub.add_parser("init-manifest", help="print a strict starter manifest")
    init_cmd.add_argument("--agent-writer", default="agent")
    init_cmd.add_argument("--executor-writer", default="executor-gate")

    digest_cmd = sub.add_parser("digest", help="print the canonical SHA-256 digest of a JSON file")
    digest_cmd.add_argument("path")

    scan_cmd = sub.add_parser("scan", help="scan a JSON file for secrets and machine-local paths")
    scan_cmd.add_argument("path")
    scan_cmd.add_argument("--allow-local-paths", action="store_true")

    verify_cmd = sub.add_parser("verify-log", help="verify a JSON envelope log")
    verify_cmd.add_argument("log")
    verify_cmd.add_argument("--horizon", required=True)

    fold_cmd = sub.add_parser("fold", help="fold a JSON envelope log with default components")
    fold_cmd.add_argument("log")
    fold_cmd.add_argument("--horizon", required=True)

    gate_cmd = sub.add_parser("check-gate", help="check a gate request against a JSON envelope log")
    gate_cmd.add_argument("request")
    gate_cmd.add_argument("log")
    gate_cmd.add_argument("--horizon", required=True)
    gate_cmd.add_argument("--bundle", action="store_true", help="print the accepted gate bundle")

    schema_cmd = sub.add_parser("validate-schema", help="validate a known JSON artifact shape")
    schema_cmd.add_argument("kind", choices=["horizon", "log", "gate-request"])
    schema_cmd.add_argument("path")

    explain_cmd = sub.add_parser("explain", help="explain a checker issue code")
    explain_cmd.add_argument("code")

    args = parser.parse_args(argv)
    if args.command == "init-manifest":
        horizon = Horizon.strict_default(agent_writers=(args.agent_writer,), executor_writer=args.executor_writer)
        print(json.dumps(horizon.to_json(), indent=2, sort_keys=True))
        return 0
    if args.command == "digest":
        print(digest_json(_read_json(args.path)))
        return 0
    if args.command == "scan":
        issues = scan_for_sensitive_data(_read_json(args.path), allow_local_paths=args.allow_local_paths)
        print(json.dumps([issue.to_json() for issue in issues], indent=2, sort_keys=True))
        return 1 if issues else 0
    if args.command == "verify-log":
        horizon = Horizon.from_mapping(_read_json(args.horizon))
        envelopes = _read_log(args.log)
        result = EnvelopeVerifier().verify(horizon, envelopes)
        print(json.dumps(result.to_json(), indent=2, sort_keys=True))
        return 0 if result.ok else 1
    if args.command == "fold":
        horizon = Horizon.from_mapping(_read_json(args.horizon))
        envelopes = _read_log(args.log)
        state = FoldKernel().fold(horizon, envelopes)
        print(json.dumps(state.to_json(), indent=2, sort_keys=True, default=str))
        return 0
    if args.command == "check-gate":
        horizon = Horizon.from_mapping(_read_json(args.horizon))
        envelopes = _read_log(args.log)
        request = _read_gate_request(args.request)
        gate = ExecutorGate()
        result = gate.check(horizon, envelopes, request)
        if args.bundle and result.ok:
            bundle = gate.create_bundle(horizon, envelopes, request)
            print(json.dumps(bundle.to_json(), indent=2, sort_keys=True, default=str))
        else:
            print(json.dumps(result.to_json(), indent=2, sort_keys=True))
        return 0 if result.ok else 1
    if args.command == "validate-schema":
        errors = _validate_schema(args.kind, _read_json(args.path))
        print(json.dumps({"ok": not errors, "errors": errors}, indent=2, sort_keys=True))
        return 0 if not errors else 1
    if args.command == "explain":
        print(_explain(args.code))
        return 0
    return 2


def _read_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_log(path: str | Path) -> tuple[Envelope, ...]:
    data = _read_json(path)
    if not isinstance(data, list):
        raise ValueError("log JSON must be an array of envelopes")
    return tuple(Envelope.from_mapping(item) for item in data)


def _read_gate_request(path: str | Path) -> GateRequest:
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError("gate request JSON must be an object")
    return GateRequest(**data)


def _validate_schema(kind: str, data: Any) -> list[str]:
    errors: list[str] = []
    if kind == "horizon":
        if not isinstance(data, dict):
            return ["horizon must be a JSON object"]
        required_horizon: tuple[str, ...] = (
            "capacities",
            "writer_authority",
            "version_intervals",
            "protected_constructors",
            "certificate_families",
            "risk_modes",
        )
        errors.extend(f"missing {field}" for field in required_horizon if field not in data)
    elif kind == "log":
        if not isinstance(data, list):
            return ["log must be a JSON array"]
        for index, item in enumerate(data):
            if not isinstance(item, dict):
                errors.append(f"log[{index}] must be an object")
                continue
            if "payload" not in item or not isinstance(item["payload"], dict) or "kind" not in item["payload"]:
                errors.append(f"log[{index}] must contain payload.kind")
    elif kind == "gate-request":
        if not isinstance(data, dict):
            return ["gate request must be a JSON object"]
        required_gate: tuple[str, ...] = (
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
        )
        errors.extend(f"missing {field}" for field in required_gate if field not in data)
    return errors


def _explain(code: str) -> str:
    explanations = {
        "incomplete-manifest": (
            "Strict manifests must declare capacities, writer authority, versions, protected constructors, "
            "certificate families, and risk modes."
        ),
        "protected-writer-authority": "A protected action constructor was written by a non-reserved writer.",
        "gate-bundle-missing-group": "Gate rows must be committed as one atomic group.",
        "gate-bundle-coherence": "The five gate rows do not bind the same GateCheck tuple.",
        "certificate-family-check": "A strict certificate must carry an accepted finite family-specific check.",
        "risk-alpha-bound": "Installed finite risk claims exceed the declared risk budget.",
        "patch-affected-completeness": "A touched invariant was not listed for recheck.",
        "join-ancestor-missing": "Join proposals must cite a common ancestor.",
    }
    return explanations.get(code, "No detailed explanation is registered for this issue code.")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
