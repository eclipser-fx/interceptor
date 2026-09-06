"""Second review batch: fail-closed signals, archive safety, type precision."""

from __future__ import annotations

import pytest

from helpers import allow
from interceptor import guard
from interceptor.archive import _rollback_archive, archive_journal
from interceptor.errors import (
    ArchiveError,
    ContractError,
    CountersignError,
    IdentityError,
    ResolutionError,
)
from interceptor.identity import load_trusted_public_keys, rotate_key
from interceptor.journal import FileJournal
from interceptor.shipping import FanoutJournalStore


def _act(journal, **kwargs):
    @guard(action="h.act", journal=journal, approval_provider=allow(), **kwargs)
    def act(x: int) -> int:
        return x

    return act


def test_keep_validated_before_mutation(evidence_home):
    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    before = journal.read_bytes()
    with pytest.raises(ArchiveError):
        archive_journal(journal, keep=0)
    assert journal.read_bytes() == before
    assert list(evidence_home.glob("journal-*.jsonl")) == []


def test_rollback_restores_on_raced_writer(evidence_home, monkeypatch):
    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    real_stats = FileJournal.archive_stats

    def slip(self):
        if self.path == journal:
            return real_stats(self)
        count, head = real_stats(self)  # the renamed file
        return count + 1, head  # pretend a writer slipped in

    monkeypatch.setattr(FileJournal, "archive_stats", slip)
    with pytest.raises(ArchiveError, match="concurrent write"):
        archive_journal(journal)
    # Rolled back: live journal intact, no successor started.
    assert journal.exists()
    assert "h.act" in journal.read_text()


def test_rollback_refuses_over_existing_successor(tmp_path):
    archived = tmp_path / "old.jsonl"
    archived.write_text("evidence\n")
    successor = tmp_path / "live.jsonl"
    successor.write_text("foreign events\n")
    assert _rollback_archive(archived, successor) is False
    assert successor.read_text() == "foreign events\n"
    assert archived.exists()


def test_rollback_happens_when_path_clear(tmp_path):
    archived = tmp_path / "old.jsonl"
    archived.write_text("evidence\n")
    assert _rollback_archive(archived, tmp_path / "live.jsonl") is True
    assert (tmp_path / "live.jsonl").read_text() == "evidence\n"


def test_resolve_rejects_dry_run(evidence_home):
    from interceptor import resolve_journal

    journal = evidence_home / "journal.jsonl"

    @guard(action="h.dry", journal=journal, approval_provider=allow(), dry_run=True)
    def plan() -> None:
        return None

    plan()
    import json

    decision = next(
        json.loads(line)
        for line in journal.read_text().splitlines()
        if json.loads(line)["event_type"] == "decision"
    )
    with pytest.raises(ResolutionError, match="dry run"):
        resolve_journal(journal, decision["event_id"], "confirmed_not_completed")


def test_raw_engine_never_with_provider_fails_closed(evidence_home, tmp_path):
    import inspect

    from interceptor.contracts import build_contract
    from interceptor.engine import execute_sync
    from interceptor.policy import BudgetProvider

    def raw(x: int) -> int:
        return x

    contract = build_contract(raw, action="h.raw", risk="low", approval="never")
    with pytest.raises(ContractError, match="approval='never'"):
        execute_sync(
            target=raw,
            args=(1,),
            kwargs={},
            contract=contract,
            sensitive=frozenset(),
            patterns=(),
            canonical_metadata=None,
            signature=inspect.signature(raw),
            journal=tmp_path / "j.jsonl",
            approval_provider=BudgetProvider(10),
            identity=None,
            observer=None,
        )


def test_rotate_rejects_non_key_successor(evidence_home):
    with pytest.raises(IdentityError, match="Ed25519PrivateKey"):
        rotate_key(new_key="not-a-key")  # type: ignore[arg-type]


def test_witness_preserves_countersign_error(evidence_home, tmp_path):
    from interceptor import witness_journal

    journal = evidence_home / "journal.jsonl"
    _act(journal)(1)
    # Unreadable counter key: the countersign failure must keep its type.
    with pytest.raises(CountersignError):
        witness_journal(journal, tmp_path / "w", counter_key=tmp_path / "missing.pem")
    assert (tmp_path / "w" / "latest.checkpoint").exists()


def test_ship_error_signals(evidence_home, tmp_path):
    from interceptor.errors import EventShipError

    journal = tmp_path / "j.jsonl"

    def down(event):
        raise RuntimeError("witness down")

    @guard(
        action="h.ship",
        journal=FanoutJournalStore(FileJournal(journal), [down]),
        approval_provider=allow(),
    )
    def act(x: int) -> int:
        return x * 2

    # Decision path: nothing executed, decision id attached for resolution.
    with pytest.raises(EventShipError) as exc_info:
        act(1)
    assert exc_info.value.executed is False
    assert exc_info.value.decision_event_id is not None

    good = FanoutJournalStore(FileJournal(journal), [])

    @guard(action="h.ship", journal=good, approval_provider=allow())
    def act2(x: int) -> int:
        return x * 2

    def outcome_only(event):
        if event.get("event_type") == "outcome":
            raise RuntimeError("witness down")

    flaky = FanoutJournalStore(FileJournal(journal), [outcome_only])

    @guard(action="h.ship", journal=flaky, approval_provider=allow())
    def act3(x: int) -> int:
        return x * 2

    with pytest.raises(EventShipError) as exc_info:
        act3(3)
    assert exc_info.value.executed is True
    assert exc_info.value.retry_safe is False
    assert exc_info.value.function_outcome == "succeeded"
    assert exc_info.value.result == 6
    keys = load_trusted_public_keys(evidence_home)
    from interceptor import verify_journal

    assert verify_journal(journal, keys).valid


def test_ship_error_is_caught_as_persistence_error(evidence_home, tmp_path):
    from interceptor.errors import EventShipError, EvidencePersistenceError, JournalError

    err = EventShipError("witness down", executed=True, retry_safe=False)
    assert isinstance(err, JournalError)
    assert isinstance(err, EvidencePersistenceError)
    try:
        raise err
    except EvidencePersistenceError as caught:
        assert caught.retry_safe is False
    else:  # pragma: no cover - the raise above always fires
        raise AssertionError("unreachable")


def test_resolve_note_marks_truncation(evidence_home, tmp_path):
    from interceptor import resolve_journal

    journal = tmp_path / "j.jsonl"

    @guard(action="h.note", journal=journal, approval_provider=allow())
    def act() -> None:
        raise ValueError("nope")

    with pytest.raises(ValueError):
        act()
    import json

    decision = next(
        json.loads(line)
        for line in journal.read_text().splitlines()
        if json.loads(line)["event_type"] == "decision"
    )
    report = resolve_journal(journal, decision["event_id"], "confirmed_completed", note="x" * 2000)
    assert len(report.resolution_event["note"]) == 1000
    assert report.resolution_event["note"].endswith("…")
