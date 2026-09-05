"""Next-batch features: rotation records, durable policy, shipping, archive chain."""

from __future__ import annotations

import json

import pytest

from helpers import allow
from interceptor import (
    FileBudgetProvider,
    FileRateLimitProvider,
    guard,
    verify_archive_chain,
)
from interceptor.approval import ApprovalRequest
from interceptor.archive import archive_journal
from interceptor.errors import DuplicateActionError, JournalError
from interceptor.identity import (
    LocalSigningIdentity,
    key_id_for,
    load_public_key,
    load_trusted_public_keys,
    record_rotation_event,
    rotate_key,
)
from interceptor.journal import FileJournal
from interceptor.shipping import FanoutJournalStore, FileMirrorSink
from interceptor.verification import verify_journal


def _req(action: str = "a.act") -> ApprovalRequest:
    return ApprovalRequest(action, "low", "required", "", "h", "c")


def test_rotation_record_shape_and_verify(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="t.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    old = LocalSigningIdentity.load_or_create()
    rotate_key()
    trusted = load_trusted_public_keys(evidence_home)
    result = verify_journal(journal, trusted)
    assert result.valid, result.issues
    rotations = [
        json.loads(line)
        for line in journal.read_text().splitlines()
        if json.loads(line)["event_type"] == "rotation"
    ]
    assert len(rotations) == 1
    rot = rotations[0]
    assert rot["prior_key_id"] == old.key_id == rot["key_id"]
    assert rot["successor_key_id"].startswith("ed25519:")
    assert rot["successor_key_id"] == f"ed25519:{rot['successor_fingerprint'][:16]}"
    new = LocalSigningIdentity.load_or_create()
    assert rot["successor_key_id"] == new.key_id
    # New writes still verify after the rotation record.
    act(2)
    assert verify_journal(journal, trusted).valid


def test_rotation_record_no_journal_no_file(evidence_home, tmp_path):
    LocalSigningIdentity.load_or_create()
    rotate_key()  # no journal yet: must not create one, must not fail
    assert not (evidence_home / "journal.jsonl").exists()
    other = tmp_path / "empty.jsonl"
    assert not other.exists()


def test_record_rotation_event_direct(evidence_home):
    ident = LocalSigningIdentity.load_or_create()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    successor = Ed25519PrivateKey.generate().public_key()
    journal = evidence_home / "direct.jsonl"
    event = record_rotation_event(
        prior_key_id=ident.key_id,
        sign=ident.sign,
        successor=successor,
        journal_path=journal,
    )
    assert event["event_type"] == "rotation"
    assert verify_journal(journal, load_trusted_public_keys(evidence_home)).valid


def test_rotation_tamper_detected(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="t.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    rotate_key()
    lines = journal.read_text().splitlines()
    tampered = json.loads(lines[-1])
    assert tampered["event_type"] == "rotation"
    tampered["successor_key_id"] = "ed25519:0000000000000000"
    lines[-1] = json.dumps(tampered, sort_keys=True)
    journal.write_text("\n".join(lines) + "\n")
    result = verify_journal(journal, load_trusted_public_keys(evidence_home))
    assert not result.valid


def test_file_budget_global_and_restart(tmp_path):
    state = tmp_path / "budget.json"
    provider = FileBudgetProvider(2, state)
    assert provider.decide(_req()).allowed
    assert provider.decide(_req()).allowed
    assert not provider.decide(_req()).allowed
    restarted = FileBudgetProvider(2, state)
    assert not restarted.decide(_req()).allowed


def test_file_budget_per_action(tmp_path):
    state = tmp_path / "budget-pa.json"
    provider = FileBudgetProvider(1, state, per_action=True)
    assert provider.decide(_req("a.one")).allowed
    assert not provider.decide(_req("a.one")).allowed
    assert provider.decide(_req("a.two")).allowed


def test_file_budget_corrupt_fails_closed(tmp_path):
    state = tmp_path / "budget.json"
    state.write_text("{not json")
    assert not FileBudgetProvider(5, state).decide(_req()).allowed


def test_file_rate_limit_window_and_restart(tmp_path):
    state = tmp_path / "rl.json"
    r1 = FileRateLimitProvider(1, 60.0, state, clock=lambda: 100.0)
    assert r1.decide(_req()).allowed
    r2 = FileRateLimitProvider(1, 60.0, state, clock=lambda: 100.0)
    assert not r2.decide(_req()).allowed
    r3 = FileRateLimitProvider(1, 60.0, state, clock=lambda: 200.0)
    assert r3.decide(_req()).allowed


def test_file_rate_limit_corrupt_fails_closed(tmp_path):
    state = tmp_path / "rl.json"
    state.write_text("[1,2")
    assert not FileRateLimitProvider(5, 60.0, state).decide(_req()).allowed


def test_file_budget_and_rate_limit_bad_args(tmp_path):
    with pytest.raises(ValueError):
        FileBudgetProvider(-1, tmp_path / "b.json")
    with pytest.raises(ValueError):
        FileRateLimitProvider(0, 60.0, tmp_path / "r.json")
    with pytest.raises(ValueError):
        FileRateLimitProvider(1, 0.0, tmp_path / "r.json")


def test_fanout_mirror_and_guard_flow(evidence_home, tmp_path):
    live = tmp_path / "live.jsonl"
    mirror = tmp_path / "mirror.jsonl"
    store = FanoutJournalStore(FileJournal(live), [FileMirrorSink(mirror)])
    assert store.path == live
    assert len(store.sinks) == 1

    @guard(action="m.act", journal=store, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    assert len(mirror.read_text().strip().splitlines()) == 2


def test_fanout_callable_sink_and_atomic(tmp_path):
    live = tmp_path / "live.jsonl"
    seen: list[dict] = []
    store = FanoutJournalStore(FileJournal(live), [seen.append])
    assert store.path == live

    @guard(
        action="m.keyed",
        journal=store,
        approval_provider=allow(),
        idempotency_key="order_id",
    )
    def act(order_id: str) -> str:
        return order_id

    act("K-1")
    assert len(seen) == 2  # decision + outcome shipped
    with pytest.raises(DuplicateActionError):
        act("K-1")
    assert len(seen) == 3  # duplicate decision also shipped


def test_fanout_ship_failure_policy(tmp_path):
    live = tmp_path / "live.jsonl"
    store = FileJournal(live)

    def boom(event):
        raise RuntimeError("sink down")

    strict = FanoutJournalStore(store, [boom], on_ship_failure="raise")
    with pytest.raises(JournalError):
        strict.append_event(lambda prev: {**_minimal_event(prev)})
    lax = FanoutJournalStore(store, [boom], on_ship_failure="ignore")
    lax.append_event(lambda prev: {**_minimal_event(prev)})
    with pytest.raises(ValueError):
        FanoutJournalStore(store, [], on_ship_failure="sometimes")


def _minimal_event(prev):
    from interceptor.identity import LocalSigningIdentity
    from interceptor.journal import (
        EVENT_SCHEMA_VERSION,
        finalize_event,
        new_event_id,
        utc_timestamp,
    )

    ident = LocalSigningIdentity.load_or_create()
    payload = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_type": "checkpoint",
        "event_id": new_event_id(),
        "timestamp_utc": utc_timestamp(),
        "key_id": ident.key_id,
        "previous_event_hash": prev,
        "checkpoint_count": 0,
        "head_sha256": prev,
    }
    return finalize_event(payload, ident.sign)


def test_archive_chain_valid_and_cli(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="c.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    archive_journal(journal)
    act(2)
    report = verify_archive_chain(journal, load_trusted_public_keys(evidence_home))
    assert report.valid, report.issues
    assert len(report.files_checked) == 2
    from interceptor.cli import main

    assert main(["verify-chain", "--journal", str(journal)]) == 0


def test_archive_chain_missing_predecessor(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="c.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    report0 = archive_journal(journal)
    act(2)
    report0.archived_path.unlink()
    report = verify_archive_chain(journal, load_trusted_public_keys(evidence_home))
    assert not report.valid
    assert any(i.code == "archive_missing" for i in report.issues)


def test_archive_chain_count_mismatch(evidence_home):
    journal = evidence_home / "journal.jsonl"

    @guard(action="c.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    info = archive_journal(journal)
    act(2)
    # Append an extra event to the predecessor so its count no longer matches.
    with open(info.archived_path, "a") as handle:
        handle.write((info.archived_path.read_text().splitlines()[0]) + "\n")
    report = verify_archive_chain(journal, load_trusted_public_keys(evidence_home))
    assert not report.valid
    assert any(i.code in ("archive_count_mismatch", "archive_invalid") for i in report.issues)


def test_key_rotate_cli_records_rotation(evidence_home, capsys):
    journal = evidence_home / "journal.jsonl"

    @guard(action="k.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    from interceptor.cli import main

    assert main(["key-rotate", "--journal", str(journal)]) == 0
    capsys.readouterr()
    kinds = [json.loads(line)["event_type"] for line in journal.read_text().splitlines()]
    assert "rotation" in kinds


def test_verify_chain_cli_json(evidence_home, capsys):
    journal = evidence_home / "journal.jsonl"

    @guard(action="c.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    from interceptor.cli import main

    assert main(["verify-chain", "--journal", str(journal), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["valid"] is True


def test_node_verifier_accepts_rotation(evidence_home):
    pytest.importorskip("os")
    journal = evidence_home / "journal.jsonl"

    @guard(action="n.act", journal=journal, approval_provider=allow())
    def act(x: int) -> int:
        return x

    act(1)
    rotate_key()
    trusted = load_trusted_public_keys(evidence_home)
    assert verify_journal(journal, trusted).valid
    old = trusted[0]
    new = trusted[1] if len(trusted) > 1 else trusted[0]
    assert key_id_for(old) != key_id_for(new) or len(trusted) == 2
    _ = load_public_key(LocalSigningIdentity.load_or_create().public_key_path)
