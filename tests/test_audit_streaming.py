"""Streaming audit: identical reports without retaining full event bodies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from helpers import allow, deny
from interceptor import (
    audit_journal,
    audit_journal_streaming,
    guard,
    resolve_journal,
    witness_journal,
)
from interceptor.audit import _AUDIT_EVENT_FIELDS, _project_audit_event
from interceptor.errors import ActionDenied, DuplicateActionError, EvidenceAuditError
from interceptor.identity import load_trusted_public_keys
from interceptor.verification import load_journal_snapshot

VECTORS_DIR = Path(__file__).resolve().parent.parent / "verifiers" / "vectors" / "v1"


def _rich_journal(evidence_home: Path, tmp_path: Path) -> Path:
    journal = tmp_path / "rich.jsonl"

    @guard(action="s.ok", journal=journal, approval_provider=allow())
    def ok(x: int) -> int:
        return x

    @guard(action="s.no", journal=journal, approval_provider=deny())
    def no(x: int) -> int:
        return x  # pragma: no cover - denied, never runs

    @guard(action="s.fail", journal=journal, approval_provider=allow())
    def fail(x: int) -> int:
        raise RuntimeError("boom")

    @guard(action="s.dry", journal=journal, approval_provider=allow(), dry_run=True)
    def dry(x: int) -> int:
        return x  # pragma: no cover - dry run, never runs

    @guard(
        action="s.idem",
        journal=journal,
        approval_provider=allow(),
        idempotency_key="order_id",
    )
    def idem(order_id: str) -> str:
        return "ok"

    ok(1)
    with pytest.raises(ActionDenied):
        no(1)
    with pytest.raises(RuntimeError):
        fail(1)
    assert dry(1) is None
    idem("o1")
    with pytest.raises(DuplicateActionError):
        idem("o1")

    from interceptor.verification import verify_journal

    identity_keys = load_trusted_public_keys(evidence_home)
    # Resolve the failed invocation as not-completed (retry is safe).
    snapshot = load_journal_snapshot(journal, identity_keys)
    failed_decision = next(
        event["event_id"]
        for event in snapshot.events
        if event["event_type"] == "decision" and event["action_name"] == "s.fail"
    )
    resolve_journal(journal, failed_decision, "confirmed_not_completed", note="checked: no charge")
    witness_journal(journal, tmp_path / "witness")
    assert verify_journal(journal, identity_keys).valid
    return journal


def test_streaming_matches_full_on_rich_journal(evidence_home: Path, tmp_path: Path):
    journal = _rich_journal(evidence_home, tmp_path)
    keys = load_trusted_public_keys(evidence_home)
    full = audit_journal(journal, keys)
    streamed = audit_journal_streaming(journal, keys)
    assert streamed == full
    statuses = sorted(inv.status.value for inv in streamed.invocations)
    assert "succeeded" in statuses
    assert "denied" in statuses
    assert "dry_run" in statuses
    # The failed call was resolved as not-completed, so it classifies there.
    assert "resolved_not_completed" in statuses
    assert "failed" not in statuses


def test_streaming_refuses_invalid_journal_identically(evidence_home: Path, tmp_path: Path):
    journal = _rich_journal(evidence_home, tmp_path)
    lines = journal.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n")
    keys = load_trusted_public_keys(evidence_home)
    with pytest.raises(EvidenceAuditError) as full_exc:
        audit_journal(journal, keys)
    with pytest.raises(EvidenceAuditError) as streamed_exc:
        audit_journal_streaming(journal, keys)
    assert str(streamed_exc.value) == str(full_exc.value)


def test_projection_drops_verification_only_fields(evidence_home: Path, tmp_path: Path):
    journal = _rich_journal(evidence_home, tmp_path)
    keys = load_trusted_public_keys(evidence_home)
    snapshot = load_journal_snapshot(journal, keys, project=_project_audit_event)
    assert snapshot.verification.valid
    assert snapshot.events
    for event in snapshot.events:
        assert set(event) <= _AUDIT_EVENT_FIELDS
    dropped = {
        "redacted_input_summary",
        "approval_reason",
        "signature",
        "event_hash",
        "previous_event_hash",
    }
    full = load_journal_snapshot(journal, keys)
    assert any(dropped & set(event) for event in full.events)


def _vector_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    assert isinstance(key, Ed25519PublicKey)
    return key


def test_streaming_matches_full_on_all_vectors(tmp_path: Path):
    for vector in sorted(VECTORS_DIR.glob("*.json")):
        payload = json.loads(vector.read_text())
        if "audit" not in payload.get("expect", {}):
            continue
        journal = tmp_path / f"{vector.stem}.jsonl"
        journal.write_text("\n".join(payload["journal"]) + "\n")
        keys = [_vector_key(pem) for pem in payload["public_keys"]]
        full = audit_journal(journal, keys)
        streamed = audit_journal_streaming(journal, keys)
        assert streamed == full, f"vector {vector.stem} diverges"
        expect = payload["expect"]["audit"]
        assert streamed.structurally_valid is expect["structurally_valid"]
        assert sorted(inv.status.value for inv in streamed.invocations) == sorted(
            expect["statuses"]
        )
