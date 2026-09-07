#!/usr/bin/env python3
"""Idempotent hot-path envelope (stdlib + this package only).

Measures guarded-call throughput when every call carries a unique
``idempotency_key`` (pre-check scan + locked atomic scan per call) so
deployments can plan rotation for idempotent-heavy workloads.

Run: ``python benchmarks/bench_idempotent.py [--calls N]``. Uses an ephemeral
identity and a temp journal; writes nothing outside the temp dir. Manual on
purpose: wall-clock numbers are too noisy for a CI gate.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from interceptor import guard  # noqa: E402
from interceptor.approval import ApprovalDecision  # noqa: E402
from interceptor.identity import EphemeralSigningIdentity  # noqa: E402


class AllowNow:
    def decide(self, request) -> ApprovalDecision:
        return ApprovalDecision("allowed", "bench")


def bench_idempotent(calls: int) -> dict[str, float]:
    tmp = Path(tempfile.mkdtemp(prefix="bench-idem-"))
    os.environ["INTERCEPTOR_EVIDENCE_HOME"] = str(tmp / "home")
    journal = tmp / "journal.jsonl"
    identity = EphemeralSigningIdentity.generate()

    @guard(
        action="bench.refund",
        journal=journal,
        approval_provider=AllowNow(),
        identity=identity,
        idempotency_key="order_id",
    )
    def refund(order_id: str) -> str:
        return "ok"

    start = time.perf_counter()
    for i in range(calls):
        refund(f"order-{i}")
    secs = time.perf_counter() - start
    size_kb = journal.stat().st_size / 1024
    return {
        "calls": float(calls),
        "events": float(2 * calls),
        "per_sec": calls / secs if secs > 0 else 0.0,
        "ms_per_call": (secs / calls * 1000) if calls else 0.0,
        "journal_kb": size_kb,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=int, default=2000)
    args = parser.parse_args()
    for calls in (200, args.calls):
        row = bench_idempotent(calls)
        print(
            f"idempotent calls={int(row['calls'])} events={int(row['events'])} "
            f"throughput={row['per_sec']:.0f}/s "
            f"({row['ms_per_call']:.2f}ms/call) "
            f"journal={row['journal_kb']:.0f}KiB"
        )


if __name__ == "__main__":
    main()
