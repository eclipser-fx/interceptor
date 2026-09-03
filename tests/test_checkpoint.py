"""Checkpoint: a durable, signed commit of the journal tail.

Tail truncation (deleting events from the end of the journal) is otherwise
undetectable offline. The checkpoint event commits to the event count at a
point in time, and its witness file lets ``verify_journal(..., checkpoint=)``
treat any journal shorter than that count as truncated.
"""

from __future__ import annotations

import json

from helpers import allow
from interceptor import checkpoint_journal, guard, verify_journal
from interceptor.cli import EXIT_FAILURE, EXIT_OK, main
from interceptor.identity import LocalSigningIdentity, load_public_key


def recorded_actions(evidence_home, count: int = 2) -> None:
    journal = evidence_home / "journal.jsonl"

    @guard(action="test.checkpoint.act", approval_provider=allow(), journal=journal)
    def act(amount: int) -> int:
        return amount

    for i in range(count):
        act(i)


def events(path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def truncate(path, keep: int) -> None:
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:keep]) + ("\n" if keep else ""))


def public_key():
    return load_public_key(LocalSigningIdentity.load_or_create().public_key_path)


# --- appending --------------------------------------------------------------


def test_checkpoint_appends_a_signed_event_and_writes_witness(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)

    report = checkpoint_journal(journal, witness_path=evidence_home / "witness.txt")

    chain = events(journal)
    assert [e["event_type"] for e in chain] == [
        "decision",
        "outcome",
        "decision",
        "outcome",
        "checkpoint",
    ]
    checkpoint = chain[-1]
    assert checkpoint["checkpoint_count"] == 4
    assert checkpoint["head_sha256"] == chain[-2]["event_hash"]

    witness = json.loads((evidence_home / "witness.txt").read_text())
    assert witness["event_id"] == checkpoint["event_id"]

    result = verify_journal(journal, public_key(), checkpoint=report.witness_path)
    assert result.valid, result.issues


def test_checkpoint_on_an_empty_journal(evidence_home):
    journal = evidence_home / "journal.jsonl"
    report = checkpoint_journal(journal)

    checkpoint = events(journal)[0]
    assert checkpoint["event_type"] == "checkpoint"
    assert checkpoint["checkpoint_count"] == 0
    assert checkpoint["head_sha256"] is None

    result = verify_journal(journal, public_key(), checkpoint=report.witness_path)
    assert result.valid, result.issues


def test_default_witness_path_is_next_to_the_journal(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    report = checkpoint_journal(journal)
    assert report.witness_path == journal.with_name(journal.name + ".checkpoint")
    assert report.witness_path.exists()


# --- truncation detection ---------------------------------------------------


def test_verify_detects_truncation_below_the_committed_count(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    report = checkpoint_journal(journal)

    truncate(journal, keep=2)

    result = verify_journal(journal, public_key(), checkpoint=report.witness_path)
    assert not result.valid
    codes = [issue.code for issue in result.issues]
    assert "checkpoint_truncation" in codes


def test_verify_detects_a_removed_checkpoint(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    report = checkpoint_journal(journal)

    truncate(journal, keep=4)

    result = verify_journal(journal, public_key(), checkpoint=report.witness_path)
    assert not result.valid
    codes = [issue.code for issue in result.issues]
    assert "checkpoint_not_found" in codes


def test_verify_against_a_different_journal_fails(evidence_home):
    first = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    report = checkpoint_journal(first)

    other = evidence_home / "other.jsonl"

    @guard(action="test.checkpoint.other", approval_provider=allow(), journal=other)
    def act(amount: int) -> int:
        return amount

    for i in range(6):
        act(i)

    result = verify_journal(other, public_key(), checkpoint=report.witness_path)
    assert not result.valid
    assert any(issue.code == "checkpoint_not_found" for issue in result.issues)


def test_growth_past_the_checkpoint_still_verifies(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    report = checkpoint_journal(journal)

    @guard(action="test.checkpoint.more", approval_provider=allow(), journal=journal)
    def act(amount: int) -> int:
        return amount

    act(99)

    result = verify_journal(journal, public_key(), checkpoint=report.witness_path)
    assert result.valid, result.issues


def test_journal_without_witness_still_verifies_a_checkpoint(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    checkpoint_journal(journal)

    result = verify_journal(journal, public_key())
    assert result.valid, result.issues
    assert result.events_verified == 5


def test_tampered_checkpoint_event_is_detected(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    checkpoint_journal(journal)

    chain = events(journal)
    chain[-1]["checkpoint_count"] = 999
    journal.write_text("\n".join(json.dumps(e, sort_keys=True) for e in chain) + "\n")

    result = verify_journal(journal, public_key())
    assert not result.valid
    assert any(issue.code == "hash_mismatch" for issue in result.issues)


# --- witness validation -----------------------------------------------------


def test_invalid_witness_file_fails_verification(evidence_home):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    bad = evidence_home / "bad-witness.txt"
    bad.write_text("not json at all")

    result = verify_journal(journal, public_key(), checkpoint=bad)
    assert not result.valid
    assert any(issue.code == "checkpoint_witness_invalid" for issue in result.issues)


def test_witness_signed_by_another_key_fails(evidence_home, monkeypatch, tmp_path):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    report = checkpoint_journal(journal)

    other_home = tmp_path / "other-home"
    monkeypatch.setenv("INTERCEPTOR_EVIDENCE_HOME", str(other_home))
    other_identity = LocalSigningIdentity.load_or_create()
    other_key = load_public_key(other_identity.public_key_path)

    result = verify_journal(journal, other_key, checkpoint=report.witness_path)
    assert not result.valid
    assert any(issue.code == "checkpoint_witness_invalid" for issue in result.issues)


# --- coexistence with the other read paths ----------------------------------


def test_audit_and_inspect_skip_checkpoint_events(evidence_home):
    from interceptor import audit_journal, inspect_journal

    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)
    checkpoint_journal(journal)

    audit = audit_journal(journal, public_key())
    assert audit.structurally_valid
    assert len(audit.invocations) == 2

    report = inspect_journal(journal)
    assert report.decision_count == 2
    assert report.outcome_count == 2


# --- the CLI ----------------------------------------------------------------


def test_checkpoint_cli_roundtrip(evidence_home, capsys):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)

    assert main(["checkpoint", "--journal", str(journal)]) == EXIT_OK
    witness = journal.with_name(journal.name + ".checkpoint")
    assert witness.exists()

    out = capsys.readouterr().out
    assert "events committed: 4" in out

    assert main(["verify", "--journal", str(journal), "--checkpoint", str(witness)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "checkpoint witness applied" in out

    truncate(journal, keep=2)
    assert main(["verify", "--journal", str(journal), "--checkpoint", str(witness)]) == EXIT_FAILURE
    out = capsys.readouterr().out
    assert "[checkpoint_truncation]" in out


def test_checkpoint_cli_json_output(evidence_home, capsys):
    journal = evidence_home / "journal.jsonl"
    recorded_actions(evidence_home)

    assert main(["checkpoint", "--journal", str(journal), "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["checkpoint_count"] == 4
    assert payload["head_sha256"] is not None
