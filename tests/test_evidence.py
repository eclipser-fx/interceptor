"""Journal chain, identity, verification, and tamper detection."""

from __future__ import annotations

import itertools
import json
import os
import stat
from pathlib import Path

import pytest

import interceptor as ge
from helpers import allow
from interceptor import guard
from interceptor.canonical import (
    REDACTED,
    canonical_json_bytes,
    canonicalize,
    sha256_hex,
)
from interceptor.identity import LocalSigningIdentity, load_public_key
from interceptor.journal import (
    _read_last_event_hash,
    _read_last_event_hash_scan,
)
from interceptor.redaction import build_sensitive_set
from interceptor.verification import verify_journal


def make_journal(home: Path, count: int) -> Path:
    @guard(action="test.chain", approval_provider=allow())
    def act(i: int) -> int:
        return i

    for i in range(count):
        act(i)
    return home / "journal.jsonl"


def verify(path: Path):
    identity = LocalSigningIdentity.load_or_create()
    return verify_journal(path, load_public_key(identity.public_key_path))


# --- chain integrity --------------------------------------------------------


def test_chain_links_each_event_to_the_previous(evidence_home):
    path = make_journal(evidence_home, 3)
    recorded = [json.loads(line) for line in path.read_text().splitlines()]

    assert recorded[0]["previous_event_hash"] is None
    for previous, current in itertools.pairwise(recorded):
        assert current["previous_event_hash"] == previous["event_hash"]


def test_modified_event_is_detected(evidence_home):
    path = make_journal(evidence_home, 2)
    lines = path.read_text().splitlines()

    tampered = json.loads(lines[0])
    tampered["risk"] = "low"
    lines[0] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    result = verify(path)
    assert not result.valid
    assert result.issues


def test_reordered_events_are_detected(evidence_home):
    path = make_journal(evidence_home, 2)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[1], lines[0], *lines[2:]]) + "\n")

    assert not verify(path).valid


def test_deleted_middle_event_is_detected(evidence_home):
    path = make_journal(evidence_home, 3)
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")

    assert not verify(path).valid


def test_truncated_tail_is_not_detectable(evidence_home):
    """A documented limit, pinned so the docs cannot drift away from reality.

    Detecting this needs an external witness — a checkpoint, a counter-signature,
    an append-only remote. The journal alone cannot do it.
    """
    path = make_journal(evidence_home, 3)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-2]) + "\n")

    assert verify(path).valid, "if this ever fails, the threat model improved"


def test_wrong_key_fails_verification(evidence_home, tmp_path):
    path = make_journal(evidence_home, 1)
    other = LocalSigningIdentity.load_or_create(home=tmp_path / "other")

    result = verify_journal(path, other.public_key())
    assert not result.valid


def test_verification_is_memory_bounded(evidence_home):
    """A journal far larger than any single event verifies without loading it whole.

    ``verify_journal`` streams one line at a time and retains no parsed events,
    so peak Python memory stays near the largest single event regardless of the
    total file size. A regression to ``read_bytes()`` makes peak memory scale
    with the whole journal and fails here.
    """
    import tracemalloc

    @guard(
        action="test.big",
        approval_provider=allow(),
        metadata={"blob": "x" * 8_000},
    )
    def act(i: int) -> int:
        return i

    for i in range(160):
        act(i)

    path = evidence_home / "journal.jsonl"
    total_size = path.stat().st_size
    assert total_size > 1_000_000, f"journal too small to prove the point ({total_size} bytes)"

    identity = LocalSigningIdentity.load_or_create()
    key = load_public_key(identity.public_key_path)

    tracemalloc.start()
    result = verify_journal(path, key)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    assert result.valid
    assert peak < total_size // 2, f"peak {peak} bytes vs journal {total_size} bytes"


# --- appending --------------------------------------------------------------


def test_corrupt_tail_refuses_to_extend(evidence_home):
    path = make_journal(evidence_home, 1)
    with path.open("a") as handle:
        handle.write("{not json}\n")

    @guard(action="test.chain", approval_provider=allow())
    def act(i: int) -> int:
        return i

    with pytest.raises(ge.JournalError, match="corrupt"):
        act(99)


def test_backward_tail_read_matches_forward_scan(evidence_home):
    """The fast tail read must agree with the obvious implementation."""
    path = make_journal(evidence_home, 12)

    with open(path, "a+b") as handle:
        fast = _read_last_event_hash(handle)
    with open(path, "a+b") as handle:
        slow = _read_last_event_hash_scan(handle)
    assert fast == slow

    # And on an empty file.
    empty = evidence_home / "empty.jsonl"
    empty.touch()
    with open(empty, "a+b") as handle:
        assert _read_last_event_hash(handle) is None


def test_tail_read_handles_a_line_longer_than_the_window(evidence_home, monkeypatch):
    monkeypatch.setattr("interceptor.journal._TAIL_READ_BYTES", 8)
    path = make_journal(evidence_home, 3)

    with open(path, "a+b") as handle:
        fast = _read_last_event_hash(handle)
    with open(path, "a+b") as handle:
        slow = _read_last_event_hash_scan(handle)
    assert fast == slow


def test_tail_read_tolerates_trailing_newlines(evidence_home):
    path = make_journal(evidence_home, 2)
    with path.open("a") as handle:
        handle.write("\n\n")

    with open(path, "a+b") as handle:
        fast = _read_last_event_hash(handle)
    with open(path, "a+b") as handle:
        slow = _read_last_event_hash_scan(handle)
    assert fast == slow


def test_journal_store_can_be_swapped(evidence_home):
    captured = []

    class Recording:
        path = Path("memory")

        def append_event(self, build):
            event = build(captured[-1]["event_hash"] if captured else None)
            captured.append(event)
            return event

    @guard(action="test.custom_store", approval_provider=allow(), journal=Recording())
    def act():
        return "ok"

    act()
    assert [e["event_type"] for e in captured] == ["decision", "outcome"]
    assert not (evidence_home / "journal.jsonl").exists()


# --- identity ---------------------------------------------------------------


def test_key_is_created_with_restrictive_permissions(evidence_home):
    identity = LocalSigningIdentity.load_or_create()
    private = identity.home / "signing_key.pem"

    assert private.exists()
    if os.name == "posix":
        mode = private.stat().st_mode
        assert not mode & (stat.S_IRWXG | stat.S_IRWXO), stat.filemode(mode)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_world_readable_key_is_refused(evidence_home):
    identity = LocalSigningIdentity.load_or_create()
    private = identity.home / "signing_key.pem"
    private.chmod(0o644)

    with pytest.raises(ge.IdentityError, match="accessible to other users"):
        LocalSigningIdentity.load_or_create()


def test_key_id_is_derived_from_the_public_key(evidence_home):
    identity = LocalSigningIdentity.load_or_create()
    assert identity.key_id.startswith("ed25519:")
    assert identity.key_id == f"ed25519:{identity.fingerprint[:16]}"


def test_missing_public_key_is_regenerated(evidence_home):
    identity = LocalSigningIdentity.load_or_create()
    identity.public_key_path.unlink()

    restored = LocalSigningIdentity.load_or_create()
    assert restored.public_key_path.exists()
    assert restored.key_id == identity.key_id


def test_private_key_never_appears_in_evidence(evidence_home):
    path = make_journal(evidence_home, 2)
    private_pem = (evidence_home / "signing_key.pem").read_text()

    journal_text = path.read_text()
    assert "PRIVATE KEY" not in journal_text
    for line in private_pem.splitlines():
        if len(line) > 20 and "-----" not in line:
            assert line not in journal_text


def test_custom_redact_name_is_redacted_in_output_hash(evidence_home):
    """The output hash must respect ``redact=[...]``, not just built-in names."""

    @guard(action="test.custom.out", approval_provider=allow(), redact=["ssn"])
    def act() -> dict:
        return {"ssn": "123-45-6789", "name": "alice"}

    act()
    journal_text = (evidence_home / "journal.jsonl").read_text()
    recorded = [json.loads(line) for line in journal_text.splitlines() if line.strip()]
    outcome = recorded[1]

    sensitive = build_sensitive_set(["ssn"])
    redacted_result = canonicalize({"ssn": "123-45-6789", "name": "alice"}, sensitive).value
    assert redacted_result == {"ssn": REDACTED, "name": "alice"}
    expected = sha256_hex(canonical_json_bytes(redacted_result))

    assert outcome["redacted_output_hash"] == expected
    assert "123-45-6789" not in journal_text
