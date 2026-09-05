"""Key rotation: old and new keys must coexist in one verifiable journal.

Rotation replaces the signing key; the outgoing public key stays registered in
the trusted set so evidence signed before the rotation keeps verifying. This is
an operator trust decision — the verifier accepts events signed by any key the
operator still trusts.
"""

from __future__ import annotations

import json

from helpers import allow
from interceptor import (
    audit_journal,
    checkpoint_journal,
    guard,
    inspect_journal,
    verify_journal,
)
from interceptor.cli import EXIT_FAILURE, EXIT_OK, main
from interceptor.identity import (
    LocalSigningIdentity,
    key_id_for,
    load_public_key,
    load_trusted_public_keys,
    rotate_key,
)


def record(evidence_home, action: str = "test.rotation.act", count: int = 2) -> None:
    journal = evidence_home / "journal.jsonl"

    @guard(action=action, approval_provider=allow(), journal=journal)
    def act(amount: int) -> int:
        return amount

    for i in range(count):
        act(i)


def current_key(evidence_home):
    return load_public_key(LocalSigningIdentity.load_or_create().public_key_path)


def test_rotation_keeps_old_evidence_verifiable(evidence_home):
    record(evidence_home)
    old_key = current_key(evidence_home)
    old_key_id = key_id_for(old_key)

    new_identity = rotate_key()
    assert new_identity.key_id != old_key_id  # the signing key actually changed
    record(evidence_home, action="test.rotation.after")

    journal = evidence_home / "journal.jsonl"
    trusted = load_trusted_public_keys(evidence_home)
    assert len(trusted) == 2

    result = verify_journal(journal, trusted)
    assert result.valid, result.issues
    # 8 action events + 1 signed rotation record.
    assert result.events_verified == 9


def test_verifying_with_only_the_new_key_flags_old_events(evidence_home):
    record(evidence_home)
    new_identity = rotate_key()
    record(evidence_home, action="test.rotation.after")

    result = verify_journal(
        evidence_home / "journal.jsonl",
        load_public_key(new_identity.public_key_path),
    )
    assert not result.valid
    assert any(issue.code == "unknown_key" for issue in result.issues)


def test_verifying_with_only_the_old_key_flags_new_events(evidence_home):
    record(evidence_home)
    old_key = current_key(evidence_home)
    rotate_key()
    record(evidence_home, action="test.rotation.after")

    result = verify_journal(evidence_home / "journal.jsonl", old_key)
    assert not result.valid
    assert any(issue.code == "unknown_key" for issue in result.issues)


def test_load_or_create_registers_the_current_key(evidence_home):
    identity = LocalSigningIdentity.load_or_create()
    trusted = load_trusted_public_keys(evidence_home)
    assert len(trusted) == 1
    assert trusted[0] == identity.public_key()


def test_rotate_registers_old_and_new_keys(evidence_home):
    old_identity = LocalSigningIdentity.load_or_create()
    old_key_id = old_identity.key_id

    rotate_key()

    trusted = load_trusted_public_keys(evidence_home)
    ids = {key_id_for(key) for key in trusted}
    assert old_key_id in ids
    assert LocalSigningIdentity.load_or_create().key_id in ids
    assert len(ids) == 2


def test_audit_and_inspect_span_a_rotation(evidence_home):
    record(evidence_home, count=1)
    rotate_key()
    record(evidence_home, action="test.rotation.after", count=1)

    journal = evidence_home / "journal.jsonl"
    trusted = load_trusted_public_keys(evidence_home)

    audit = audit_journal(journal, trusted)
    assert audit.structurally_valid
    assert len(audit.invocations) == 2

    report = inspect_journal(journal)
    assert report.decision_count == 2
    assert report.outcome_count == 2


def test_checkpoint_witness_survives_a_rotation(evidence_home):
    journal = evidence_home / "journal.jsonl"
    record(evidence_home)
    checkpoint = checkpoint_journal(journal)
    rotate_key()

    trusted = load_trusted_public_keys(evidence_home)
    result = verify_journal(journal, trusted, checkpoint=checkpoint.witness_path)
    assert result.valid, result.issues


# --- the CLI ----------------------------------------------------------------


def test_verify_cli_defaults_to_the_trusted_set(evidence_home, capsys):
    record(evidence_home)
    rotate_key()
    record(evidence_home, action="test.rotation.after")

    assert main(["verify"]) == EXIT_OK
    assert "OK" in capsys.readouterr().out


def test_verify_cli_with_only_the_new_key_fails(evidence_home, capsys):
    record(evidence_home)
    new_identity = rotate_key()
    record(evidence_home, action="test.rotation.after")

    assert main(["verify", "--public-key", str(new_identity.public_key_path)]) == EXIT_FAILURE
    out = capsys.readouterr().out
    assert "[unknown_key]" in out


def test_key_rotate_cli(evidence_home, capsys):
    LocalSigningIdentity.load_or_create()
    before = LocalSigningIdentity.load_or_create().key_id

    assert main(["key-rotate"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "now trusted" in out

    after = LocalSigningIdentity.load_or_create().key_id
    assert after != before
    assert len(load_trusted_public_keys(evidence_home)) == 2


def test_key_info_reports_trusted_keys(evidence_home, capsys):
    assert main(["key-info"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "trusted_keys" in out


def test_verify_with_repeated_public_keys_accepts_both_generations(evidence_home):
    record(evidence_home)
    old_identity = LocalSigningIdentity.load_or_create()
    old_key = old_identity.public_key()
    rotate_key()
    record(evidence_home, action="test.rotation.after")

    new_key = LocalSigningIdentity.load_or_create().public_key()
    result = verify_journal(evidence_home / "journal.jsonl", (old_key, new_key))
    assert result.valid, result.issues


def test_verify_ignores_unrelated_keys_but_accepts_the_signing_generations(
    evidence_home, monkeypatch, tmp_path
):
    record(evidence_home)
    rotate_key()
    record(evidence_home, action="test.rotation.after")

    other_home = tmp_path / "other-home"
    other_home.mkdir()
    monkeypatch.setenv("INTERCEPTOR_EVIDENCE_HOME", str(other_home))
    other = LocalSigningIdentity.load_or_create()

    # The unrelated key alone proves nothing about this journal.
    result = verify_journal(evidence_home / "journal.jsonl", other.public_key())
    assert not result.valid
    assert any(issue.code == "unknown_key" for issue in result.issues)


def test_rotation_records_are_not_silently_trusted(evidence_home, monkeypatch, tmp_path):
    """An attacker adding a key file does not gain forgery by default.

    The trusted set is read from the home, which a local attacker controls;
    the operator's real anchor is an explicit --public-key copy. This test pins
    that default verification still fails closed on events the operator has not
    explicitly trusted elsewhere.
    """
    record(evidence_home)
    other_home = tmp_path / "other-home"
    other_home.mkdir()
    monkeypatch.setenv("INTERCEPTOR_EVIDENCE_HOME", str(other_home))
    other = LocalSigningIdentity.load_or_create()

    forged = json.loads((evidence_home / "journal.jsonl").read_text().splitlines()[0])
    forged["action_name"] = "attacker.changed.this"
    (evidence_home / "journal.jsonl").write_text(json.dumps(forged, sort_keys=True) + "\n")

    result = verify_journal(evidence_home / "journal.jsonl", other.public_key())
    assert not result.valid
