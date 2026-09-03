"""Operational audit statuses and causal-link validation."""

from __future__ import annotations

import json

import pytest

from helpers import allow, deny
from interceptor import ActionDenied, InvocationStatus, audit_journal, guard
from interceptor.errors import EvidenceAuditError
from interceptor.identity import LocalSigningIdentity
from interceptor.journal import FileJournal, finalize_event, new_event_id, utc_timestamp


def audit(home):
    identity = LocalSigningIdentity.load_or_create()
    return audit_journal(home / "journal.jsonl", identity.public_key())


def test_audit_classifies_completed_failed_and_denied_calls(evidence_home):
    @guard(action="audit.succeeds", approval_provider=allow())
    def succeeds() -> None:
        return None

    @guard(action="audit.fails", approval_provider=allow())
    def fails() -> None:
        raise ValueError("expected")

    @guard(action="audit.denied", approval_provider=deny())
    def denied() -> None:
        raise AssertionError("must not execute")

    succeeds()
    with pytest.raises(ValueError, match="expected"):
        fails()
    with pytest.raises(ActionDenied):
        denied()

    report = audit(evidence_home)
    assert report.structurally_valid
    assert report.needs_reconciliation
    assert [item.status for item in report.invocations] == [
        InvocationStatus.SUCCEEDED,
        InvocationStatus.FAILED,
        InvocationStatus.DENIED,
    ]


def test_allowed_decision_without_outcome_requires_reconciliation(evidence_home):
    @guard(action="audit.unknown", approval_provider=allow())
    def action() -> None:
        return None

    action()
    path = evidence_home / "journal.jsonl"
    decision_line = path.read_text().splitlines()[0]
    path.write_text(decision_line + "\n")

    report = audit(evidence_home)
    assert report.structurally_valid
    assert report.needs_reconciliation
    assert report.invocations[0].status is InvocationStatus.NEEDS_RECONCILIATION
    assert report.invocations[0].outcome_event_id is None


def test_duplicate_outcome_is_structurally_invalid(evidence_home):
    @guard(action="audit.duplicate", approval_provider=allow())
    def action() -> None:
        return None

    action()
    path = evidence_home / "journal.jsonl"
    outcome = json.loads(path.read_text().splitlines()[1])
    identity = LocalSigningIdentity.load_or_create()

    def duplicate(previous_hash):
        payload = {
            key: value for key, value in outcome.items() if key not in ("event_hash", "signature")
        }
        payload["event_id"] = new_event_id()
        payload["timestamp_utc"] = utc_timestamp()
        payload["previous_event_hash"] = previous_hash
        return finalize_event(payload, identity.sign)

    FileJournal(path).append_event(duplicate)

    report = audit(evidence_home)
    assert not report.structurally_valid
    assert report.needs_reconciliation
    assert {issue.code for issue in report.issues} == {"duplicate_outcome"}


def test_audit_refuses_tampered_journal(evidence_home):
    @guard(action="audit.tampered", approval_provider=allow())
    def action() -> None:
        return None

    action()
    path = evidence_home / "journal.jsonl"
    path.write_text(path.read_text().replace('"risk":"medium"', '"risk":"low"'))

    with pytest.raises(EvidenceAuditError, match="cryptographic verification"):
        audit(evidence_home)
