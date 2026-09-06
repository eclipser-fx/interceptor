"""Witness shipping and provider reconciliation."""

from __future__ import annotations

import json

import pytest

from helpers import allow
from interceptor import (
    guard,
    reconcile_journal,
    verify_journal,
    witness_journal,
)
from interceptor.checkpoint import checkpoint_journal
from interceptor.errors import EvidenceAuditError
from interceptor.identity import (
    EphemeralSigningIdentity,
    generate_private_key,
    load_trusted_public_keys,
)


def _act(journal, **kwargs):
    @guard(action="w.act", journal=journal, approval_provider=allow(), **kwargs)
    def act(x: int) -> int:
        return x

    return act


def test_witness_ships_and_verifies(evidence_home, tmp_path):
    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    shipped_dir = tmp_path / "witness"
    report = witness_journal(journal, shipped_dir)
    assert report.shipped_path.exists()
    assert (shipped_dir / "latest.checkpoint").exists()
    assert report.countersignature_event_id is None
    keys = load_trusted_public_keys(evidence_home)
    assert verify_journal(journal, keys, checkpoint=report.shipped_path).valid


def test_witness_with_counter_key(evidence_home, tmp_path):
    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    counter = tmp_path / "counter.pem"
    generate_private_key(counter)
    report = witness_journal(journal, tmp_path / "witness", counter_key=counter)
    assert report.countersignature_event_id is not None
    kinds = [json.loads(line)["event_type"] for line in journal.read_text().splitlines()]
    assert "countersignature" in kinds


def test_witness_cli(evidence_home, tmp_path, capsys):
    from interceptor.cli import EXIT_OK, main

    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    out_dir = tmp_path / "w"
    assert main(["witness", "--journal", str(journal), "--witness-dir", str(out_dir)]) == EXIT_OK
    assert "shipped witness" in capsys.readouterr().out
    assert (
        main(["witness", "--journal", str(journal), "--witness-dir", str(out_dir), "--json"])
        == EXIT_OK
    )
    payload = json.loads(capsys.readouterr().out)
    # The first witness run appended a checkpoint, so the second commits 3 events.
    assert payload["checkpoint_count"] == 3


def test_witness_audit_covered_uncovered_and_empty(evidence_home, tmp_path):
    from interceptor import audit_witnesses

    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    witness_dir = tmp_path / "w"
    first = witness_journal(journal, witness_dir)
    _act(journal)(2)
    second = witness_journal(journal, witness_dir)
    assert first.shipped_path != second.shipped_path
    keys = load_trusted_public_keys(evidence_home)
    report = audit_witnesses(witness_dir, journal, keys)
    assert report.valid
    assert len(report.files) == 2
    # Truncate the journal below the newest witness: it goes uncovered.
    lines = journal.read_text().splitlines()
    journal.write_text("\n".join(lines[:2]) + "\n")
    stale = audit_witnesses(witness_dir, journal, keys)
    assert not stale.valid
    assert any(not item.covered for item in stale.files)
    assert audit_witnesses(tmp_path / "empty", journal, keys).valid is False


def test_witness_audit_cli(evidence_home, tmp_path, capsys):
    from interceptor.cli import EXIT_FAILURE, EXIT_OK, main

    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    out_dir = tmp_path / "w"
    assert main(["witness", "--journal", str(journal), "--witness-dir", str(out_dir)]) == EXIT_OK
    capsys.readouterr()
    assert (
        main(["witness-audit", "--journal", str(journal), "--witness-dir", str(out_dir)]) == EXIT_OK
    )
    assert "covers 1 shipped witness" in capsys.readouterr().out
    journal.write_text("")
    assert (
        main(["witness-audit", "--journal", str(journal), "--witness-dir", str(out_dir)])
        == EXIT_FAILURE
    )


def test_reconcile_matched_mismatched_unknown(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(
        action="billing.refund",
        journal=journal,
        approval_provider=allow(),
        receipt_from=lambda r: {"processor": "acme", "refund_id": r["id"]},
    )
    def refund(which: str) -> dict:
        return {"id": which}

    refund("re_ok")
    refund("re_bad")
    refund("re_gone")
    keys = load_trusted_public_keys(evidence_home)

    def fetch(receipt):
        if receipt["refund_id"] == "re_gone":
            return None
        status = "settled" if receipt["refund_id"] == "re_ok" else "pending"
        return {"processor": "acme", "refund_id": receipt["refund_id"], "status": status}

    report = reconcile_journal(journal, keys, fetch)
    by_id = {r.receipt["refund_id"]: r.status for r in report.reconciliations}
    # Receipts only carry what the extractor returned (no status field), so all
    # provider records superset-match: use a stricter fetch to force mismatch.
    assert by_id == {"re_ok": "matched", "re_bad": "matched", "re_gone": "provider_unknown"}
    assert not report.complete  # unknown is not matched

    # A receipt field disagreeing with the provider is a mismatch finding.
    journal2 = evidence_home / "j2.jsonl"

    @guard(
        action="billing.refund",
        journal=journal2,
        approval_provider=allow(),
        receipt_from=lambda r: {"processor": "acme", "refund_id": r["id"], "status": "claimed"},
    )
    def refund2(which: str) -> dict:
        return {"id": which}

    refund2("re_bad")

    def provider_says_settled(receipt):
        return {"processor": "acme", "refund_id": receipt["refund_id"], "status": "settled"}

    rep2 = reconcile_journal(journal2, keys, provider_says_settled)
    assert rep2.reconciliations[0].status == "mismatched"
    assert "claimed" in rep2.reconciliations[0].detail
    assert rep2.mismatched


def test_stripe_fetcher_matches_and_mismatches(evidence_home):
    from interceptor import StripeRefundFetcher

    journal = evidence_home / "journal.jsonl"

    @guard(
        action="billing.refund",
        journal=journal,
        approval_provider=allow(),
        receipt_from=lambda r: {"processor": "stripe", "refund_id": r["id"]},
    )
    def refund(which: str) -> dict:
        return {"id": which}

    refund("re_ok")
    refund("re_disputed")
    keys = load_trusted_public_keys(evidence_home)

    class FakeRefund:
        def __init__(self, id, status):
            self.id = id
            self.status = status

    records = {"re_ok": "succeeded", "re_disputed": "failed"}

    class FakeStripe:
        class Refund:
            @staticmethod
            def retrieve(refund_id):
                return FakeRefund(refund_id, records[refund_id])

    report = reconcile_journal(journal, keys, StripeRefundFetcher(FakeStripe()))
    # The extractor only transcribed processor+refund_id, so both match...
    assert report.complete

    journal2 = evidence_home / "j2.jsonl"

    @guard(
        action="billing.refund",
        journal=journal2,
        approval_provider=allow(),
        receipt_from=lambda r: {
            "processor": "stripe",
            "refund_id": r["id"],
            "status": "succeeded",
        },
    )
    def refund2(which: str) -> dict:
        return {"id": which}

    refund2("re_ok")
    refund2("re_disputed")
    rep2 = reconcile_journal(journal2, keys, StripeRefundFetcher(FakeStripe()))
    assert [r.status for r in rep2.reconciliations] == ["matched", "mismatched"]
    assert rep2.mismatched

    # Another processor's receipts are not applicable, never mismatches.
    journal3 = evidence_home / "j3.jsonl"

    @guard(
        action="billing.refund",
        journal=journal3,
        approval_provider=allow(),
        receipt_from=lambda r: {"processor": "other", "refund_id": r["id"]},
    )
    def refund3(which: str) -> dict:
        return {"id": which}

    refund3("x-1")
    rep3 = reconcile_journal(journal3, keys, StripeRefundFetcher(FakeStripe()))
    assert rep3.reconciliations[0].status == "provider_unknown"


def test_reconcile_fetch_error_and_object_fetcher(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(
        action="billing.refund",
        journal=journal,
        approval_provider=allow(),
        receipt_from=lambda r: {"processor": "acme", "refund_id": r["id"]},
    )
    def refund(which: str) -> dict:
        return {"id": which}

    refund("re_1")
    keys = load_trusted_public_keys(evidence_home)

    def boom(receipt):
        raise ConnectionError("provider down")

    report = reconcile_journal(journal, keys, boom)
    assert report.reconciliations[0].status == "fetch_error"
    assert not report.complete

    class Fetcher:
        def fetch(self, receipt):
            return dict(receipt)

    good = reconcile_journal(journal, keys, Fetcher())
    assert good.complete


def test_reconcile_skips_receiptless_and_refuses_invalid(evidence_home):
    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    keys = load_trusted_public_keys(evidence_home)
    report = reconcile_journal(journal, keys, lambda receipt: dict(receipt))
    assert report.reconciliations == ()
    assert not report.complete
    # Tamper: reconciliation must fail closed, not compare against forgery.
    lines = journal.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    journal.write_text("\n".join(lines) + "\n")
    with pytest.raises(EvidenceAuditError):
        reconcile_journal(journal, keys, lambda receipt: dict(receipt))


def test_witness_countersign_failure_keeps_witness(evidence_home, tmp_path):
    from interceptor.errors import CountersignError

    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    # Counter-key failures keep their type (not JournalError) so callers can
    # distinguish them — see test_hardening.py.
    with pytest.raises(CountersignError):
        witness_journal(journal, tmp_path / "w", counter_key=tmp_path / "missing.pem")
    # The witness was still shipped before countersigning failed.
    assert (tmp_path / "w" / "latest.checkpoint").exists()


def test_checkpoint_witness_path_used_by_witness(evidence_home, tmp_path):
    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    first = checkpoint_journal(journal)
    assert first.witness_path.exists()
    _ = EphemeralSigningIdentity.generate()
