"""Cross-language proof: the Node.js verifier checks Python-made journals.

EVIDENCE_FORMAT.md exists so evidence can be checked without the library that
produced it. These tests hold that claim: they build journals with the Python
guard (all event types, floats, receipts, redaction) and verify them with
``verifiers/node/verify.mjs`` in a subprocess. Skipped when node is absent.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from helpers import allow
from interceptor import (
    archive_journal,
    checkpoint_journal,
    countersign_journal,
    guard,
    resolve_journal,
)
from interceptor.identity import EphemeralSigningIdentity, generate_private_key

NODE = shutil.which("node")
VERIFIER = Path(__file__).resolve().parent.parent / "verifiers" / "node" / "verify.mjs"

needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


def run_verifier(
    journal: Path, *public_keys: Path, extra: list[str] | None = None
) -> tuple[int, str]:
    cmd = [NODE, str(VERIFIER), "--journal", str(journal)]
    for key in public_keys:
        cmd += ["--public-key", str(key)]
    cmd += extra or []
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout + proc.stderr


@needs_node
def test_node_verifies_full_journal(evidence_home, tmp_path):
    @guard(
        action="billing.refund",
        risk="high",
        approval_provider=allow(),
        idempotency_key="order_id",
        receipt_from=lambda r: {"processor": "acme", "refund_id": r["id"]},
    )
    def refund(order_id: str, amount: float, api_key: str = "secret") -> dict:
        return {"id": "re_1", "amount": amount}

    assert refund("o-1", 19.99)["id"] == "re_1"
    journal = evidence_home / "journal.jsonl"
    checkpoint_journal(journal)

    from interceptor.audit import audit_journal
    from interceptor.identity import load_trusted_public_keys

    report = audit_journal(journal, load_trusted_public_keys(evidence_home))
    resolve_journal(journal, report.invocations[0].decision_event_id, "confirmed_completed")

    counter_key = tmp_path / "counter.pem"
    generate_private_key(counter_key)
    countersign_journal(journal, counter_key)
    signer = EphemeralSigningIdentity.from_file(counter_key)
    counter_pub = tmp_path / "counter-pub.pem"
    from cryptography.hazmat.primitives import serialization

    counter_pub.write_bytes(
        signer.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    code, out = run_verifier(journal, evidence_home / "verify_key.pem", counter_pub)
    assert code == 0, out
    assert "3 events verified" not in out  # more than decision/outcome/checkpoint now
    assert "OK" in out


@needs_node
def test_node_rejects_tampering(evidence_home):
    @guard(action="test.node-tamper", approval_provider=allow())
    def act(amount: int) -> int:
        return amount

    act(5)
    journal = evidence_home / "journal.jsonl"
    lines = journal.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n")

    code, out = run_verifier(journal, evidence_home / "verify_key.pem")
    assert code == 1
    assert "hash_mismatch" in out


@needs_node
def test_node_rejects_truncation(evidence_home):
    @guard(action="test.node-trunc", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    witness = checkpoint_journal(journal).witness_path
    journal.write_text("")  # wipe everything after the checkpoint
    code, out = run_verifier(
        journal, evidence_home / "verify_key.pem", extra=["--checkpoint", str(witness)]
    )
    assert code == 1
    assert "truncation" in out


@needs_node
def test_node_rejects_dot_segment_archive_path(evidence_home, tmp_path):
    @guard(action="test.node-dotpath", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    lines = journal.read_text().splitlines()
    tip_hash = json.loads(lines[-1])["event_hash"]
    lines.append(
        json.dumps(
            {
                "schema_version": "1",
                "event_type": "archive",
                "event_id": "00000000-0000-4000-8000-000000000099",
                "timestamp_utc": "2026-01-01T00:00:00.000000Z",
                "key_id": "ed25519:0000000000000000",
                "previous_event_hash": tip_hash,
                "event_hash": "0" * 64,
                "signature": "e30=",
                "prior_count": 2,
                "prior_head": "0" * 64,
                "archived_path": "..",
            }
        )
    )
    journal.write_text("\n".join(lines) + "\n")

    code, out = run_verifier(journal, evidence_home / "verify_key.pem")
    assert code == 1
    assert "archive_bad_path" in out


@needs_node
def test_node_verifies_archive_link(evidence_home):
    @guard(action="test.node-archive", approval_provider=allow())
    def act() -> str:
        return "ok"

    act()
    journal = evidence_home / "journal.jsonl"
    report = archive_journal(journal)
    code, out = run_verifier(journal, evidence_home / "verify_key.pem")
    assert code == 0, out
    code, out = run_verifier(report.archived_path, evidence_home / "verify_key.pem")
    assert code == 0, out
