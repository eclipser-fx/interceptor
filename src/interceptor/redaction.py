"""Which names count as sensitive, and how redacted evidence is summarised.

The redaction *traversal* lives in :mod:`interceptor.canonical`, fused
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
import re
from collections.abc import Iterable, Sequence
from typing import Any

from .canonical import REDACTED, fold_name
from .errors import ContractError

#: Built-in sensitive names, lowercase. Matching is case-insensitive and
#: confusable-insensitive (see :func:`interceptor.canonical.fold_name`).
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

#: High-precision value patterns always applied on top of name-based redaction.
#: These catch secrets passed under non-sensitive names (``data``, ``payload``,
#: connection strings) or embedded inside larger strings. Kept intentionally
#: narrow: every pattern must have a negligible false-positive rate on ordinary
#: prose, because a match replaces the whole string value with ``<REDACTED>``.
DEFAULT_VALUE_PATTERNS: tuple[str, ...] = (
    r"sk-live-[A-Za-z0-9_-]{8,}",
    r"sk-test-[A-Za-z0-9_-]{8,}",
    r"ghp_[A-Za-z0-9]{8,}",
    r"gho_[A-Za-z0-9]{8,}",
    r"xox[bap]-[A-Za-z0-9-]{8,}",
    r"AKIA[0-9A-Z]{16}",
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
)

_COMPILED_DEFAULTS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in DEFAULT_VALUE_PATTERNS
)


def compile_value_patterns(extra: Iterable[str] | None = None) -> tuple[re.Pattern[str], ...]:
    """Defaults plus caller-supplied regexes, compiled and validated.

    Raises :class:`ContractError` on an invalid regex so mistakes fail at
    decoration time, not at call time.
    """
    if not extra:
        return _COMPILED_DEFAULTS
    compiled: list[re.Pattern[str]] = list(_COMPILED_DEFAULTS)
    for raw in extra:
        if not isinstance(raw, str) or not raw:
            raise ContractError(f"redact pattern {raw!r} must be a non-empty string")
        try:
            compiled.append(re.compile(raw))
        except re.error as exc:
            raise ContractError(f"invalid redact pattern {raw!r}: {exc}") from exc
    return tuple(compiled)


def value_matches_patterns(text: str, patterns: Sequence[re.Pattern[str]]) -> bool:
    """True when any pattern searches *text* successfully."""
    return any(p.search(text) is not None for p in patterns)


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


def scrub_text(
    text: str,
    redacted_values: Iterable[str],
    patterns: Sequence[re.Pattern[str]] = (),
    *,
    max_chars: int = 300,
) -> str:
    """Replace known raw sensitive values in *text* and bound its length.

    Exception messages routinely echo their inputs — an HTTP client quoting an
    ``Authorization`` header, a database driver quoting a connection string —
    so any value the traversal redacted is replaced before the message is
    persisted. Value *patterns* are additionally substituted, which catches
    secrets the traversal saw only embedded inside a larger string.

    Longer values are substituted first: replacing a short value that happens
    to be a substring of a longer one would otherwise fragment the longer one
    and leave parts of it in the text. Values shorter than
    :data:`interceptor.canonical._MIN_SCRUBBABLE_LENGTH` are skipped: they
    produce far more spurious replacements than useful scrubbing.
    """
    from .canonical import _MIN_SCRUBBABLE_LENGTH

    for raw in sorted(
        {v for v in redacted_values if v and len(v) >= _MIN_SCRUBBABLE_LENGTH},
        key=len,
        reverse=True,
    ):
        text = text.replace(raw, REDACTED)
    for pattern in patterns:
        text = pattern.sub(REDACTED, text)
    return _truncate(text, max_chars)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...(truncated)"
