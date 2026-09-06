"""Reverse interop: TypeScript writes, Python verifies and audits.

The committed vectors prove Python→TypeScript. This proves the other
direction: the Effect guard's journals verify, audit, and inspect correctly
under the Python implementation — including receipts, redaction, retention,
and idempotent duplicates. Skipped when node or the TS toolchain is absent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from interceptor import audit_journal, inspect_journal
from interceptor.identity import load_public_key
from interceptor.verification import verify_journal

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
TSC = ROOT / "ts" / "node_modules" / ".bin" / "tsc"

needs_ts = pytest.mark.skipif(
    NODE is None or not TSC.exists(), reason="node or the TS toolchain is not installed"
)


@needs_ts
def test_typescript_journal_verifies_audits_and_inspects(tmp_path):
    journal = tmp_path / "ts-journal.jsonl"
    pubkey = tmp_path / "ts-verify.pem"
    build = subprocess.run(
        [str(TSC), "-p", str(ROOT / "ts" / "tsconfig.json")],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=ROOT / "ts",
    )
    assert build.returncode == 0, build.stderr
    emit = subprocess.run(
        [NODE, str(ROOT / "ts" / "dist" / "scripts" / "emit-sample.js"), str(journal), str(pubkey)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert emit.returncode == 0, emit.stderr

    key = load_public_key(pubkey)
    result = verify_journal(journal, key)
    assert result.valid, result.issues
    assert result.events_verified == 3

    report = audit_journal(journal, key)
    assert report.structurally_valid
    assert sorted(inv.status.value for inv in report.invocations) == ["denied", "succeeded"]

    events = [json.loads(line) for line in journal.read_text().splitlines()]
    decision, outcome, duplicate = events
    assert decision["action_name"] == "billing.refund"
    assert "sk-live-INTEROP" not in decision["redacted_input_summary"]
    assert "<REDACTED>" in decision["redacted_input_summary"]
    assert outcome["receipt"] == {"processor": "stripe", "refund_id": "re_9"}
    assert duplicate["decision"] == "denied"
    # Same-process duplicates short-circuit before the journal scan (as in the
    # Python engine), so no prior id is linked.
    assert "duplicate_of" not in duplicate

    privacy = inspect_journal(journal, public_key_path=pubkey)
    assert privacy.decision_count == 2
    assert privacy.actions[0].classification.value == "partially_redacted"
    assert list(privacy.actions[0].retained_parameter_names) == ["amountCents", "orderId"]
