"""Unicode lookalikes must not bypass name-based redaction.

Redaction matches parameter and field names against a sensitive-name set.
Matching with ``.lower()`` alone is trivially defeated by homoglyphs:
``api_kеy`` (Cyrillic е), ``тoken`` (Cyrillic т), ``ａpi_key`` (fullwidth a)
all render identically to the ASCII name but are different code points.

This file pins the normalization rule in
:func:`interceptor.canonical.fold_name` and the end-to-end behavior:
a secret planted under a lookalike name must be redacted exactly like the
ASCII spelling, and the original spelling is what appears in the output.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest

from helpers import allow
from interceptor import guard
from interceptor.canonical import REDACTED, canonicalize, fold_name
from interceptor.redaction import SENSITIVE_NAMES

SECRET = "sk-live-HOMOGLYPH-TEST-0123456789"

#: Each probe folds to a built-in sensitive name.
CONFUSED_NAMES = [
    "\u0430pi_key",  # Cyrillic а
    "api_k\u0435y",  # Cyrillic е
    "\u0442oken",  # Cyrillic т
    "passw\u043erd",  # Cyrillic о
    "se\u0441ret",  # Cyrillic с
    "client_s\u0435cret",  # Cyrillic е
    "auth\u043erization",  # Cyrillic о
    "pr\u0456vate_key",  # Cyrillic і
    "\u03b1pi_key",  # Greek α
    "to\u03baen",  # Greek κ
    "\uff41pi_key",  # fullwidth a
    "auth\u00f3rization",  # ó
]


def _dumped(value: Any) -> str:
    return json.dumps(canonicalize(value, SENSITIVE_NAMES).value, sort_keys=True)


# --- the folding rule --------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("api_key", "api_key"),
        ("API_KEY", "api_key"),
        ("Api_Key", "api_key"),
        ("\u0430pi_key", "api_key"),  # Cyrillic а
        ("api_k\u0435y", "api_key"),  # Cyrillic е
        ("\uff41pi_key", "api_key"),  # fullwidth a
        ("\u212aey", "key"),  # Kelvin sign
        ("passw\u043erd", "password"),
        ("se\u0441ret", "secret"),
        ("auth\u00f3rization", "authorization"),  # ó decomposes to o + accent
        ("crede\u0301ntials", "credentials"),  # combining accent, NFD input
        ("\u03b1pi_key", "api_key"),  # Greek α
        ("plain", "plain"),  # untouched
    ],
)
def test_fold_name(name: str, expected: str) -> None:
    assert fold_name(name) == expected


# --- canonicalization -------------------------------------------------------


@pytest.mark.parametrize("confused", CONFUSED_NAMES)
def test_confused_names_are_redacted(confused: str) -> None:
    assert SECRET not in _dumped({confused: SECRET})


@pytest.mark.parametrize("confused", CONFUSED_NAMES)
def test_original_spelling_is_preserved(confused: str) -> None:
    result = canonicalize({confused: SECRET}, SENSITIVE_NAMES).value
    assert result == {confused: REDACTED}


def test_confused_name_nested_under_a_list_is_redacted() -> None:
    assert SECRET not in _dumped({"payload": [{"api_k\u0435y": SECRET}]})


@dataclasses.dataclass
class ConfusedCredentials:
    # A homoglyph of ``api_key``; valid as a Python identifier.
    api_kеy: str  # deliberate lookalike field name (Cyrillic е)


def test_confused_dataclass_field_is_redacted() -> None:
    assert SECRET not in _dumped(ConfusedCredentials(SECRET))


def test_declared_extra_names_are_folded() -> None:
    from interceptor.redaction import build_sensitive_set

    extra = build_sensitive_set(["p\u0456n"])  # homoglyph of "pin"
    assert "pin" in extra
    assert SECRET not in json.dumps(canonicalize({"p\u0456n": SECRET}, extra).value)


# --- end to end through the guard -------------------------------------------


@pytest.mark.parametrize("confused", CONFUSED_NAMES)
def test_confused_secret_never_reaches_journal_or_prompt(evidence_home, confused: str) -> None:
    provider = allow()

    @guard(action="test.homoglyph", approval_provider=provider)
    def act(config: Any) -> str:
        return "done"

    act({confused: SECRET})

    journal_text = (evidence_home / "journal.jsonl").read_text()
    assert SECRET not in journal_text, f"{confused!r}: secret reached the journal"

    prompt_text = provider.seen[0].redacted_input_summary
    assert SECRET not in prompt_text, f"{confused!r}: secret reached the approval prompt"


def test_confused_error_message_is_scrubbed(evidence_home) -> None:
    @guard(action="test.homoglyph_raises", approval_provider=allow())
    def act(config: Any) -> None:
        raise ValueError(f"upstream rejected token {config['api_kеy']}")

    with pytest.raises(ValueError):
        act({"api_kеy": SECRET})

    assert SECRET not in (evidence_home / "journal.jsonl").read_text()
