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
from .records import ReachabilityTranscript, check_reachability
from .schema import validate_json_artifact
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
    schema_cmd.add_argument(
        "kind",
        choices=[
            "horizon",
            "log",
            "gate-request",
            "gate-bundle",
            "source-cut",
            "replay-certificate",
            "risk-claim",
            "patch-proposal",
            "join-proposal",
            "reachability",
        ],
    )
    schema_cmd.add_argument("path")

    explain_cmd = sub.add_parser("explain", help="explain a checker issue code")
    explain_cmd.add_argument("code")

    report_cmd = sub.add_parser("report", help="summarize verification and folded audit-log state")
    report_cmd.add_argument("log")
    report_cmd.add_argument("--horizon", required=True)
    report_cmd.add_argument("--format", choices=["json"], default="json")

    reach_cmd = sub.add_parser("reachability", help="verify or explain a reachability transcript")
    reach_sub = reach_cmd.add_subparsers(dest="reachability_command", required=True)
    reach_verify = reach_sub.add_parser("verify", help="verify a reachability transcript")
    reach_verify.add_argument("transcript")
    reach_verify.add_argument("--horizon")
    reach_explain = reach_sub.add_parser("explain", help="explain a reachability issue code")
    reach_explain.add_argument("code")

    probe_cmd = sub.add_parser("probe", help="run built-in unsafe fixture probes")
    probe_sub = probe_cmd.add_subparsers(dest="probe_command", required=True)
    probe_run = probe_sub.add_parser("run", help="run JSON probes from a directory")
    probe_run.add_argument("directory")

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
        try:
            request = _read_gate_request(args.request)
        except (KeyError, TypeError, ValueError) as exc:
            print(json.dumps({"ok": False, "errors": [f"gate request is malformed: {exc}"]}, indent=2, sort_keys=True))
            return 1
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
    if args.command == "report":
        horizon = Horizon.from_mapping(_read_json(args.horizon))
        envelopes = _read_log(args.log)
        print(json.dumps(_report(horizon, envelopes), indent=2, sort_keys=True, default=str))
        return 0
    if args.command == "reachability":
        if args.reachability_command == "explain":
            print(_explain(args.code))
            return 0
        reach_horizon = Horizon.from_mapping(_read_json(args.horizon)) if args.horizon else None
        transcript_data = _read_json(args.transcript)
        transcript = ReachabilityTranscript.from_mapping(transcript_data)
        result = check_reachability(transcript, reach_horizon)
        print(json.dumps(result.to_json(), indent=2, sort_keys=True))
        return 0 if result.ok else 1
    if args.command == "probe":
        probe_result = _run_probes(Path(args.directory))
        print(json.dumps(probe_result, indent=2, sort_keys=True))
        return 0 if probe_result["ok"] else 1
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
    return GateRequest.from_mapping(data)


def _validate_schema(kind: str, data: Any) -> list[str]:
    return validate_json_artifact(kind, data)


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
        "join-liveness-repair-witness": (
            "A join that makes a frame non-active must cite cap/outbox/resource/risk repair keys."
        ),
        "reach-witness": "A reachability transition must bind a typed witness and matching witness digest.",
        "store-cas-conflict": "The append-only store snapshot changed before the append could commit.",
        "store-duplicate-eid": "An append tried to reuse an existing envelope id.",
        "gate-commit-source-digest": "The gate request does not bind the current durable store digest.",
        "certificate-signature-registry": (
            "A certificate signature exists or is required but no verifier registry was supplied."
        ),
        "certificate-signature-invalid": "A registered verifier rejected the certificate signature.",
        "broker-fold": "The broker cannot fold the current durable snapshot, so it will not dispatch actions.",
    }
    return explanations.get(code, "No detailed explanation is registered for this issue code.")


def _report(horizon: Horizon, envelopes: tuple[Envelope, ...]) -> dict[str, object]:
    verifier = EnvelopeVerifier()
    legal = verifier.verify(horizon, envelopes)
    report: dict[str, object] = {
        "verification": legal.to_json(),
        "log": {"rows": len(envelopes), "digest": legal.digest},
        "gate_bundles": sum(1 for env in envelopes if env.payload.get("kind") == "GateCheck"),
        "abort_rows": sum(1 for env in envelopes if env.envelope_class.value == "abort"),
        "fail_closed_rows": sum(1 for env in envelopes if env.envelope_class.value == "failClosed"),
    }
    if not legal.ok:
        return report
    state = FoldKernel().fold(horizon, envelopes)
    report["fold"] = {
        "digest": state.log_digest,
        "frames": len(state.component("frames")),
        "capabilities": len(state.component("capabilities")),
        "outboxes": len(state.component("outboxes")),
        "resources": len(state.component("resources")),
        "certificates": len(state.component("certificates")),
        "risk_reserves": len(state.component("risk").get("reserves", {})),
        "risk_spends": len(state.component("risk").get("spends", {})),
    }
    return report


def _run_probes(directory: Path) -> dict[str, object]:
    if not directory.exists() or not directory.is_dir():
        return {"ok": False, "errors": [f"probe directory does not exist: {directory}"], "probes": []}
    probes: list[dict[str, object]] = []
    for path in sorted(directory.glob("*.json")):
        data = _read_json(path)
        kind = _probe_kind(path.name)
        errors = validate_json_artifact(kind, data) if kind else []
        probes.append({"path": str(path), "kind": kind or "unknown", "schema_errors": errors})
    horizon_path = directory / "horizon.json"
    log_path = directory / "log.json"
    if horizon_path.exists() and log_path.exists():
        horizon = Horizon.from_mapping(_read_json(horizon_path))
        log = _read_log(log_path)
        verification = EnvelopeVerifier().verify(horizon, log)
        probes.append({"path": str(log_path), "kind": "verify-log", "result": verification.to_json()})
    return {"ok": True, "probes": probes}


def _probe_kind(name: str) -> str | None:
    mapping = {
        "horizon.json": "horizon",
        "log.json": "log",
        "gate-request.json": "gate-request",
        "gate-bundle.json": "gate-bundle",
        "risk-claim.json": "risk-claim",
        "reachability.json": "reachability",
    }
    return mapping.get(name)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
