"""Which names count as sensitive, and how redacted evidence is summarised.

The redaction *traversal* lives in :mod:`guardrail_evidence.canonical`, fused
with canonicalization so the two cannot disagree about which container types
expand into named fields. This module owns the policy — the name set — and the
presentation helpers that run on already-redacted structures.

Matching is by name, case-insensitively, against a built-in set plus any names
declared via ``@guard(redact=[...])``. Matched values are replaced with the
literal ``<REDACTED>``, so no length, prefix, or hash of the raw value reaches
evidence. That matters for low-entropy secrets: a hash of a six-digit PIN is
the PIN.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .canonical import REDACTED, fold_name
from .errors import ContractError

#: Built-in sensitive names, lowercase. Matching is case-insensitive and
#: confusable-insensitive (see :func:`guardrail_evidence.canonical.fold_name`).
SENSITIVE_NAMES: frozenset[str] = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth_header",
        "authorization",
        "client_secret",
        "credential",
        "credentials",
        "passwd",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "secret_key",
        "session_token",
        "token",
    }
)

_MAX_SUMMARY_VALUE_CHARS = 120
_MAX_SUMMARY_TOTAL_CHARS = 2000


def build_sensitive_set(extra_names: Iterable[str] | None = None) -> frozenset[str]:
    """The built-in sensitive set plus caller-declared names, folded to ASCII."""
    if not extra_names:
        return SENSITIVE_NAMES
    folded: set[str] = set()
    for raw in extra_names:
        if not isinstance(raw, str):
            raise ContractError(f"redact name {raw!r} must be a string")
        name = fold_name(raw)
        if not name.strip():
            raise ContractError(f"redact name {raw!r} folds to empty; provide a non-empty name")
        folded.add(name)
    return SENSITIVE_NAMES | frozenset(folded)


def bounded_summary(redacted_canonical: Any) -> str:
    """A short, single-line summary of an already-redacted canonical structure.

    Shown in approval prompts and stored on decision events. Because it is
    derived exclusively from the redacted canonical structure, it can never
    contain more than the journal already does. Values are truncated so the
    summary stays bounded regardless of input size.
    """
    if not isinstance(redacted_canonical, dict):
        text = json.dumps(redacted_canonical, ensure_ascii=False, sort_keys=True)
        return _truncate(text, _MAX_SUMMARY_TOTAL_CHARS)

    parts: list[str] = []
    for name in sorted(redacted_canonical):
        value_text = json.dumps(redacted_canonical[name], ensure_ascii=False, sort_keys=True)
        parts.append(f"{name}={_truncate(value_text, _MAX_SUMMARY_VALUE_CHARS)}")
    return _truncate(", ".join(parts), _MAX_SUMMARY_TOTAL_CHARS)


def scrub_text(text: str, redacted_values: Iterable[str], *, max_chars: int = 300) -> str:
    """Replace known raw sensitive values in *text* and bound its length.

    Exception messages routinely echo their inputs — an HTTP client quoting an
    ``Authorization`` header, a database driver quoting a connection string —
    so any value the traversal redacted is replaced before the message is
    persisted.

    Longer values are substituted first: replacing a short value that happens
    to be a substring of a longer one would otherwise fragment the longer one
    and leave parts of it in the text.
    """
    for raw in sorted({v for v in redacted_values if v}, key=len, reverse=True):
        text = text.replace(raw, REDACTED)
    return _truncate(text, max_chars)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...(truncated)"
