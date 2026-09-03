"""Local-only privacy inspection for signed evidence v1 journals.

The analyzer reads existing signed fields without changing, re-canonicalizing,
or rewriting an event. Result objects retain names and classifications only;
ordinary argument values are never copied into reports or error messages.
"""

from __future__ import annotations

import dataclasses
import json
from enum import Enum
from pathlib import Path
from typing import Any

from .canonical import REDACTED, UNSUPPORTED_MARKER
from .errors import EvidencePrivacyInspectionError, IdentityError
from .identity import (
    default_journal_path,
    evidence_home,
    load_public_key,
    load_trusted_public_keys,
)
from .redaction import bounded_summary
from .verification import JournalSnapshot, PublicKeys, load_journal_snapshot


class PrivacyClassification(str, Enum):
    FULLY_REDACTED = "fully_redacted"
    PARTIALLY_REDACTED = "partially_redacted"
    NO_ARGUMENTS = "no_arguments"
    UNKNOWN = "unknown"


@dataclasses.dataclass(frozen=True)
class ActionPrivacyInspection:
    action_name: str
    classification: PrivacyClassification
    retained_parameter_names: tuple[str, ...]
    explanation: str


@dataclasses.dataclass(frozen=True)
class PrivacyClassificationCounts:
    fully_redacted: int = 0
    partially_redacted: int = 0
    no_arguments: int = 0
    unknown: int = 0


@dataclasses.dataclass(frozen=True)
class EvidencePrivacyReport:
    policy: str
    event_count: int
    decision_count: int
    outcome_count: int
    allowed_count: int
    denied_count: int
    succeeded_count: int
    failed_count: int
    classifications: PrivacyClassificationCounts
    actions: tuple[ActionPrivacyInspection, ...]
    safe_for_upload: bool


def inspect_journal(
    journal_path: Path | None = None,
    *,
    public_key_path: Path | None = None,
) -> EvidencePrivacyReport:
    """Verify and inspect a journal locally, without network activity or writes.

    Verification uses the trusted key set from the evidence home unless
    *public_key_path* pins a single key explicitly.
    """
    journal = journal_path or default_journal_path()
    if not journal.exists():
        raise EvidencePrivacyInspectionError("journal not found; no inspection was performed")
    try:
        if public_key_path is not None:
            public_keys: PublicKeys = (load_public_key(public_key_path),)
        else:
            public_keys = load_trusted_public_keys(evidence_home())
        if not public_keys:
            raise EvidencePrivacyInspectionError(
                "no trusted verification keys; no inspection was performed"
            )
    except (IdentityError, OSError):
        raise EvidencePrivacyInspectionError(
            "public verification key is unavailable or invalid; no inspection was performed"
        ) from None

    snapshot = load_journal_snapshot(journal, public_keys)
    if not snapshot.verification.valid:
        codes = ", ".join(issue.code for issue in snapshot.verification.issues[:5])
        raise EvidencePrivacyInspectionError(
            "journal failed local verification"
            + (f" ({codes})" if codes else "")
            + "; no privacy classification was produced"
        )
    return inspect_verified_snapshot(snapshot)


def inspect_verified_snapshot(snapshot: JournalSnapshot) -> EvidencePrivacyReport:
    """Classify argument retention in an already verified journal snapshot."""
    actions: list[ActionPrivacyInspection] = []
    decision_count = outcome_count = 0
    allowed_count = denied_count = 0
    succeeded_count = failed_count = 0

    for event in snapshot.events:
        if event.get("event_type") == "decision":
            decision_count += 1
            allowed_count += event.get("decision") == "allowed"
            denied_count += event.get("decision") == "denied"
            classification, names, explanation = _classify_event(event)
            action_name = event.get("action_name")
            actions.append(
                ActionPrivacyInspection(
                    action_name=action_name if isinstance(action_name, str) else "<unknown-action>",
                    classification=classification,
                    retained_parameter_names=names,
                    explanation=explanation,
                )
            )
        elif event.get("event_type") == "outcome":
            outcome_count += 1
            succeeded_count += event.get("status") == "succeeded"
            failed_count += event.get("status") == "failed"

    counts = PrivacyClassificationCounts(
        fully_redacted=sum(
            action.classification is PrivacyClassification.FULLY_REDACTED for action in actions
        ),
        partially_redacted=sum(
            action.classification is PrivacyClassification.PARTIALLY_REDACTED for action in actions
        ),
        no_arguments=sum(
            action.classification is PrivacyClassification.NO_ARGUMENTS for action in actions
        ),
        unknown=sum(action.classification is PrivacyClassification.UNKNOWN for action in actions),
    )
    safe = counts.partially_redacted == 0 and counts.unknown == 0
    return EvidencePrivacyReport(
        policy="ordinary_connected_upload",
        event_count=len(snapshot.events),
        decision_count=decision_count,
        outcome_count=outcome_count,
        allowed_count=allowed_count,
        denied_count=denied_count,
        succeeded_count=succeeded_count,
        failed_count=failed_count,
        classifications=counts,
        actions=tuple(actions),
        safe_for_upload=safe,
    )


_RETENTION_STATES = frozenset({"redacted", "retained", "unsupported"})


def _classify_event(event: dict[str, Any]) -> tuple[PrivacyClassification, tuple[str, ...], str]:
    """Classify a decision event, preferring the structured retention field.

    New journals record per-parameter retention at write time; re-parsing the
    bounded summary is no longer needed. Older journals lack the field, so the
    summary parser remains as a fallback and stays pinned by its own tests.
    """
    retention = event.get("parameter_retention")
    if retention is None:
        return _classify_summary(event.get("redacted_input_summary"))
    return _classify_retention(retention)


def _classify_retention(
    retention: Any,
) -> tuple[PrivacyClassification, tuple[str, ...], str]:
    if not isinstance(retention, list):
        return PrivacyClassification.UNKNOWN, (), "parameter_retention is not a list"
    if not retention:
        return PrivacyClassification.NO_ARGUMENTS, (), "the invocation recorded no arguments"

    names: list[str] = []
    states: list[str] = []
    seen: set[str] = set()
    for record in retention:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("name"), str)
            or record.get("state") not in _RETENTION_STATES
        ):
            return (
                PrivacyClassification.UNKNOWN,
                tuple(names),
                "parameter_retention contains a malformed or unknown record",
            )
        name = record["name"]
        if name in seen:
            return (
                PrivacyClassification.UNKNOWN,
                tuple(names),
                "parameter_retention repeats a parameter name",
            )
        seen.add(name)
        names.append(name)
        states.append(record["state"])

    if "unsupported" in states:
        return (
            PrivacyClassification.UNKNOWN,
            tuple(sorted(names)),
            "one or more arguments use an unsupported type placeholder",
        )
    if "retained" in states:
        retained = [name for name, state in zip(names, states, strict=True) if state == "retained"]
        return (
            PrivacyClassification.PARTIALLY_REDACTED,
            tuple(retained),
            "one or more ordinary argument values remain in signed evidence",
        )
    return (
        PrivacyClassification.FULLY_REDACTED,
        (),
        "every recorded argument value is the evidence v1 redaction marker",
    )


def _classify_summary(
    summary: Any,
) -> tuple[PrivacyClassification, tuple[str, ...], str]:
    if not isinstance(summary, str):
        return PrivacyClassification.UNKNOWN, (), "summary is not a supported string"
    if summary == "":
        return PrivacyClassification.NO_ARGUMENTS, (), "the invocation recorded no arguments"

    parsed, parsed_names = _parse_exact_summary(summary)
    if parsed is None:
        return (
            PrivacyClassification.UNKNOWN,
            parsed_names,
            "summary is malformed, truncated, unsupported, or ambiguous",
        )

    retained: list[str] = []
    unsupported: list[str] = []
    for name, value in parsed.items():
        if value == REDACTED:
            continue
        if isinstance(value, str) and value.startswith(UNSUPPORTED_MARKER):
            unsupported.append(name)
            continue
        retained.append(name)

    if unsupported:
        return (
            PrivacyClassification.UNKNOWN,
            tuple(sorted((*retained, *unsupported))),
            "one or more arguments use an unsupported type placeholder",
        )
    if retained:
        return (
            PrivacyClassification.PARTIALLY_REDACTED,
            tuple(sorted(retained)),
            "one or more ordinary argument values remain in signed evidence",
        )
    return (
        PrivacyClassification.FULLY_REDACTED,
        (),
        "every recorded argument value is the evidence v1 redaction marker",
    )


def _parse_exact_summary(summary: str) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    if summary.endswith("...(truncated)"):
        return None, ()

    decoder = json.JSONDecoder()
    parsed: dict[str, Any] = {}
    names: list[str] = []
    offset = 0
    try:
        while offset < len(summary):
            equals = summary.find("=", offset)
            if equals < 0:
                return None, tuple(names)
            name = summary[offset:equals]
            if not name.isidentifier() or name in parsed:
                return None, tuple(names)
            value, end = decoder.raw_decode(summary, equals + 1)
            parsed[name] = value
            names.append(name)
            if end == len(summary):
                break
            if summary[end : end + 2] != ", ":
                return None, tuple(names)
            offset = end + 2
    except (ValueError, RecursionError):
        return None, tuple(names)

    if names != sorted(names) or bounded_summary(parsed) != summary:
        return None, tuple(names)
    return parsed, tuple(names)
