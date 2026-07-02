"""Small verification benchmark for local performance checks."""

from __future__ import annotations

import argparse
import time

from problem_frame_gate import Envelope, EnvelopeClass, FoldKernel, Horizon, MemoryAppendOnlyStore, legal_log


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark legal-log verify, fold, and memory append")
    parser.add_argument("--rows", type=int, default=1000)
    args = parser.parse_args()
    horizon = Horizon.strict_default(agent_writers=("agent",), normal_capacity=max(args.rows + 10, 1000))
    log = tuple(
        Envelope(
            eid=f"e{index}",
            event=f"event-{index}",
            slot="0",
            commit_time=index,
            writer="agent",
            owner="agent",
            version=1,
            envelope_class=EnvelopeClass.NORMAL,
            payload={"kind": "Evidence", "evidence_id": f"ev{index}", "digest": f"sha256:{index:064x}"[-71:]},
        )
        for index in range(args.rows)
    )
    start = time.perf_counter()
    verify = legal_log(horizon, log)
    verify_seconds = time.perf_counter() - start
    start = time.perf_counter()
    state = FoldKernel().fold(horizon, log)
    fold_seconds = time.perf_counter() - start
    store = MemoryAppendOnlyStore()
    start = time.perf_counter()
    append = store.append_atomic(horizon, store.snapshot().digest, log)
    append_seconds = time.perf_counter() - start
    print(
        {
            "rows": args.rows,
            "verify_ok": verify.ok,
            "fold_digest": state.log_digest,
            "append_ok": append.ok,
            "verify_seconds": round(verify_seconds, 6),
            "fold_seconds": round(fold_seconds, 6),
            "append_seconds": round(append_seconds, 6),
        }
    )
    return 0 if verify.ok and append.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
