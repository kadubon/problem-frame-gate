from __future__ import annotations

import json
from pathlib import Path

from problem_frame_gate import ExecutorGate, GateRequest, production_profile
from problem_frame_gate.model import Envelope

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    profile = production_profile("email-agent")
    log = tuple(
        Envelope.from_mapping(item)
        for item in json.loads((ROOT / "docs/examples/log.json").read_text(encoding="utf-8"))
    )
    request = GateRequest.from_mapping(
        json.loads((ROOT / "docs/examples/gate-request.json").read_text(encoding="utf-8"))
    )
    result = ExecutorGate(risk_registry=profile.risk_registry).check(profile.horizon, log, request)
    print(json.dumps(result.to_json(), indent=2, sort_keys=True))
    return 0 if not result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
