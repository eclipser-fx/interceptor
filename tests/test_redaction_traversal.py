"""Redaction must reach every container type canonicalization expands.

This file exists because of a specific defect. Redaction and canonicalization
used to be two passes: the redactor understood mappings and sequences, the
canonicalizer additionally expanded dataclasses into mappings. A dataclass
holding an ``api_key`` therefore passed through redaction untouched — nothing
in it looked like a mapping — and was then expanded by the canonicalizer into
``{"api_key": "sk-live-..."}``, which went into the input hash, into the
journal, and into the text shown to whoever was asked to approve the call.

Named tuples were worse. A named tuple *is* a tuple, so the sequence branch
flattened it positionally and the field names were gone before any matching
could happen.

The structural fix is one fused traversal, so nothing can expand without
having been offered to the redactor. These tests pin the property directly
rather than pinning the fix, so a future refactor that reintroduces a second
pass fails here.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any, NamedTuple

import pytest

from helpers import allow
from interceptor import guard
from interceptor.canonical import REDACTED, canonicalize
from interceptor.redaction import SENSITIVE_NAMES

SECRET = "sk-live-DO-NOT-LEAK-0123456789"


@dataclasses.dataclass
class Credentials:
    user: str
    api_key: str


class CredentialsTuple(NamedTuple):
    user: str
    api_key: str


@dataclasses.dataclass
class Outer:
    label: str
    inner: Credentials


def _dumped(value: Any) -> str:
    return json.dumps(canonicalize(value, SENSITIVE_NAMES).value, sort_keys=True)


# --- the traversal itself ---------------------------------------------------


def test_dataclass_field_is_redacted():
    assert SECRET not in _dumped(Credentials(user="wira", api_key=SECRET))


def test_named_tuple_field_is_redacted():
    assert SECRET not in _dumped(CredentialsTuple(user="wira", api_key=SECRET))


def test_named_tuple_keeps_its_field_names():
    # The sequence branch would produce a list and lose the names entirely.
    result = canonicalize(CredentialsTuple(user="wira", api_key=SECRET), SENSITIVE_NAMES).value
    assert result == {"user": "wira", "api_key": REDACTED}


def test_nested_dataclass_field_is_redacted():
    assert SECRET not in _dumped(Outer(label="x", inner=Credentials("wira", SECRET)))


def test_dataclass_inside_dict_inside_list():
    payload = {"accounts": [{"creds": Credentials("wira", SECRET)}]}
    assert SECRET not in _dumped(payload)


def test_plain_dict_still_redacted():
    assert SECRET not in _dumped({"api_key": SECRET})


def test_non_sensitive_dataclass_fields_survive():
    result = canonicalize(Credentials(user="wira", api_key=SECRET), SENSITIVE_NAMES).value
    assert result == {"user": "wira", "api_key": REDACTED}


def test_redacted_values_are_collected_for_scrubbing():
    _, collected = canonicalize(Credentials("wira", SECRET), SENSITIVE_NAMES)
    assert SECRET in collected


def test_unsupported_objects_carry_no_data():
    class Opaque:
        def __init__(self) -> None:
            self.api_key = SECRET

        def __repr__(self) -> str:  # pragma: no cover - must never be called
            return f"Opaque({SECRET})"

    dumped = _dumped(Opaque())
    assert SECRET not in dumped
    assert "unsupported" in dumped


# --- the same property, end to end through the guard ------------------------


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("dataclass", Credentials("wira", SECRET)),
        ("named_tuple", CredentialsTuple("wira", SECRET)),
        ("nested_dataclass", Outer("x", Credentials("wira", SECRET))),
        ("dict", {"api_key": SECRET}),
        ("list_of_dataclass", [Credentials("wira", SECRET)]),
    ],
)
def test_secret_never_reaches_journal_or_prompt(evidence_home, label, value):
    provider = allow()

    @guard(action=f"test.{label}", approval_provider=provider)
    def act(config: Any) -> str:
        return "done"

    act(value)

    journal_text = (evidence_home / "journal.jsonl").read_text()
    assert SECRET not in journal_text, f"{label}: secret reached the journal"

    prompt_text = provider.seen[0].redacted_input_summary
    assert SECRET not in prompt_text, f"{label}: secret reached the approval prompt"


def test_secret_in_return_value_is_not_hashed_raw(evidence_home):
    """A returned dataclass holding a token must hash as redacted.

    The output hash is not reversible, but a hash of a low-entropy secret can
    be confirmed by guessing, so the hash must be taken over redacted content.
    """

    @guard(action="test.returns_secret", approval_provider=allow())
    def act() -> Credentials:
        return Credentials("wira", SECRET)

    act()

    events = [
        json.loads(line)
        for line in (evidence_home / "journal.jsonl").read_text().splitlines()
        if line.strip()
    ]
    outcome = next(e for e in events if e["event_type"] == "outcome")

    from interceptor.canonical import canonical_json_bytes, sha256_hex

    leaked = sha256_hex(canonical_json_bytes({"api_key": SECRET, "user": "wira"}))
    assert outcome["redacted_output_hash"] != leaked


def test_error_message_echoing_a_dataclass_secret_is_scrubbed(evidence_home):
    @guard(action="test.raises", approval_provider=allow())
    def act(config: Credentials) -> None:
        raise ValueError(f"upstream rejected token {config.api_key}")

    with pytest.raises(ValueError):
        act(Credentials("wira", SECRET))

    assert SECRET not in (evidence_home / "journal.jsonl").read_text()


def test_declared_extra_names_reach_dataclass_fields(evidence_home):
    @dataclasses.dataclass
    class Custom:
        pin: str

    @guard(action="test.custom_redact", redact=["pin"], approval_provider=allow())
    def act(config: Custom) -> str:
        return "ok"

    act(Custom(pin="9074"))
    assert "9074" not in (evidence_home / "journal.jsonl").read_text()
