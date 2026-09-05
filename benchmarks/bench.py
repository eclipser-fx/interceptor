#!/usr/bin/env python3
"""Append/verify envelope for the evidence journal (stdlib + this package only).

Measures guarded-call throughput and offline verification time at several
journal sizes so deployments can plan rotation and witness intervals.
Run: ``python benchmarks/bench.py [--calls N]``. Uses an ephemeral identity
and a temp journal; writes nothing outside the temp dir.
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

from interceptor import guard, verify_journal  # noqa: E402
from interceptor.approval import ApprovalDecision  # noqa: E402
from interceptor.identity import EphemeralSigningIdentity  # noqa: E402


class AllowNow:
    def decide(self, request) -> ApprovalDecision:
        return ApprovalDecision("allowed", "bench")


def bench(calls: int) -> dict[str, float]:
    tmp = Path(tempfile.mkdtemp(prefix="bench-"))
    os.environ["INTERCEPTOR_EVIDENCE_HOME"] = str(tmp / "home")
    journal = tmp / "journal.jsonl"
    identity = EphemeralSigningIdentity.generate()
    home = tmp / "home"
    home.mkdir(parents=True, exist_ok=True)

    @guard(action="bench.act", journal=journal, approval_provider=AllowNow(), identity=identity)
    def act(x: int) -> int:
        return x

    start = time.perf_counter()
    for i in range(calls):
        act(i)
    append_secs = time.perf_counter() - start

    start = time.perf_counter()
    result = verify_journal(journal, identity.public_key())
    verify_secs = time.perf_counter() - start
    assert result.valid, result.issues
    size_kb = journal.stat().st_size / 1024
    return {
        "calls": float(calls),
        "events": float(2 * calls),
        "append_per_sec": calls / append_secs,
        "verify_per_sec": (2 * calls) / verify_secs,
        "journal_kb": size_kb,
        "kb_per_1k_events": size_kb / (2 * calls / 1000),
    }


def _pub_pem(identity: EphemeralSigningIdentity) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return identity.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calls", type=int, default=2000)
    args = parser.parse_args()
    for calls in (200, args.calls):
        row = bench(calls)
        print(
            f"calls={int(row['calls'])} events={int(row['events'])} "
            f"append={row['append_per_sec']:.0f}/s "
            f"verify={row['verify_per_sec']:.0f} events/s "
            f"journal={row['journal_kb']:.0f}KiB "
            f"({row['kb_per_1k_events']:.0f}KiB per 1k events)"
        )


if __name__ == "__main__":
    main()
