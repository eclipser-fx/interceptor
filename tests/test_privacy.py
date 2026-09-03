"""Privacy classification of recorded summaries, including the unsupported-type marker.

Decision events now carry a structured ``parameter_retention`` list written at
record time; ``privacy._classify_retention`` reads it directly. ``_classify_summary``
— the fragile re-parse of the bounded summary string — remains as the fallback for
journals written before the field existed, and this file pins both paths,
including the unsupported-type marker, which was dead code until the
canonicalizer and the classifier agreed on one constant.
"""

from __future__ import annotations

import json

import pytest

import interceptor as ge
from helpers import allow
from interceptor.canonical import UNSUPPORTED_MARKER, canonicalize
from interceptor.privacy import (
    PrivacyClassification,
    _classify_retention,
    _classify_summary,
    inspect_journal,
    inspect_verified_snapshot,
)
from interceptor.redaction import SENSITIVE_NAMES, bounded_summary
from interceptor.verification import JournalSnapshot, VerificationResult


def classify(value, sensitive: frozenset[str] = SENSITIVE_NAMES):
    canonical, _ = canonicalize(value, sensitive)
    return _classify_summary(bounded_summary(canonical))


def test_fully_redacted_every_value_is_the_marker():
    cls, names, _ = classify({"api_key": "sk-secret", "token": "abc"})
    assert cls is PrivacyClassification.FULLY_REDACTED
    assert names == ()


def test_partially_redacted_reports_the_retained_names():
    cls, names, _ = classify({"api_key": "sk-secret", "amount": 5})
    assert cls is PrivacyClassification.PARTIALLY_REDACTED
    assert names == ("amount",)


def test_no_arguments():
    cls, _, _ = _classify_summary("")
    assert cls is PrivacyClassification.NO_ARGUMENTS


def test_malformed_summary_is_unknown():
    cls, _, _ = _classify_summary("this is not name=value syntax")
    assert cls is PrivacyClassification.UNKNOWN


def test_truncated_summary_is_unknown():
    cls, _, _ = _classify_summary("a=1...(truncated)")
    assert cls is PrivacyClassification.UNKNOWN


def test_unsupported_type_is_classified_unknown():
    cls, names, _ = classify({"payload": object()})
    assert cls is PrivacyClassification.UNKNOWN
    assert names == ("payload",)


def test_unsupported_marker_matches_the_canonicalizer_output():
    """The classifier and the canonicalizer must share one marker constant."""
    canonical, _ = canonicalize({"x": object()}, SENSITIVE_NAMES)
    assert canonical["x"].startswith(UNSUPPORTED_MARKER)
    assert canonical["x"].endswith(">")
    cls, _, _ = _classify_summary(bounded_summary(canonical))
    assert cls is PrivacyClassification.UNKNOWN


def test_inspect_flags_unsupported_types_as_not_safe(evidence_home):
    @ge.guard(action="test.unsupported", approval_provider=allow())
    def act(payload):
        return None

    act(object())

    report = inspect_journal(evidence_home / "journal.jsonl")
    assert report.safe_for_upload is False
    assert report.actions[0].classification is PrivacyClassification.UNKNOWN


def test_inspect_marks_fully_redacted_as_safe(evidence_home):
    @ge.guard(action="test.safe", approval_provider=allow())
    def act(api_key: str):
        return None

    act("sk-ONE-TWO-THREE")

    report = inspect_journal(evidence_home / "journal.jsonl")
    assert report.safe_for_upload is True
    assert report.actions[0].classification is PrivacyClassification.FULLY_REDACTED


def test_inspect_refuses_to_classify_a_tampered_journal(evidence_home):
    @ge.guard(action="test.tampered", approval_provider=allow())
    def act(api_key: str):
        return None

    act("sk-ONE-TWO-THREE")
    path = evidence_home / "journal.jsonl"
    lines = path.read_text().splitlines()
    event = json.loads(lines[0])
    event["risk"] = "low"
    lines[0] = json.dumps(event, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    with pytest.raises(ge.EvidencePrivacyInspectionError, match="failed local verification"):
        inspect_journal(path)


# --- the structured parameter_retention field -------------------------------


def test_decision_event_records_parameter_retention(evidence_home):
    @ge.guard(action="test.retention", approval_provider=allow())
    def act(api_key: str, amount: int):
        return None

    act("sk-ONE", 5)

    event = json.loads((evidence_home / "journal.jsonl").read_text().splitlines()[0])
    assert event["parameter_retention"] == [
        {"name": "amount", "state": "retained"},
        {"name": "api_key", "state": "redacted"},
    ]


def test_decision_event_records_unsupported_retention(evidence_home):
    @ge.guard(action="test.retention_unsupported", approval_provider=allow())
    def act(payload):
        return None

    act(object())

    event = json.loads((evidence_home / "journal.jsonl").read_text().splitlines()[0])
    assert event["parameter_retention"] == [{"name": "payload", "state": "unsupported"}]


def test_classify_retention_fully_redacted():
    cls, names, _ = _classify_retention([{"name": "api_key", "state": "redacted"}])
    assert cls is PrivacyClassification.FULLY_REDACTED
    assert names == ()


def test_classify_retention_partially_redacted():
    cls, names, _ = _classify_retention(
        [
            {"name": "api_key", "state": "redacted"},
            {"name": "amount", "state": "retained"},
        ]
    )
    assert cls is PrivacyClassification.PARTIALLY_REDACTED
    assert names == ("amount",)


def test_classify_retention_unsupported():
    cls, names, _ = _classify_retention([{"name": "payload", "state": "unsupported"}])
    assert cls is PrivacyClassification.UNKNOWN
    assert names == ("payload",)


def test_classify_retention_no_arguments():
    cls, _, _ = _classify_retention([])
    assert cls is PrivacyClassification.NO_ARGUMENTS


@pytest.mark.parametrize(
    "bad",
    [
        "not a list",
        [{"name": 1, "state": "redacted"}],
        [{"name": "x", "state": "nonsense"}],
        [{"name": "x"}],
        [{"state": "redacted"}],
    ],
)
def test_classify_retention_malformed(bad):
    cls, _, _ = _classify_retention(bad)
    assert cls is PrivacyClassification.UNKNOWN


def test_classify_retention_duplicate_name():
    cls, _, _ = _classify_retention(
        [
            {"name": "x", "state": "redacted"},
            {"name": "x", "state": "retained"},
        ]
    )
    assert cls is PrivacyClassification.UNKNOWN


def test_truncated_summary_still_classifies_via_structured_field(evidence_home):
    """The fix: a truncated summary can no longer hide a retained argument.

    Before the structured field, a summary ending in ``...(truncated)`` was
    unparseable and classified ``UNKNOWN``, even though the only ambiguity was
    how long a value was — not whether it survived redaction.
    """

    @ge.guard(action="test.large_argument", approval_provider=allow())
    def act(api_key: str, blob: str):
        return None

    act("sk-SECRET", "x" * 500)

    summary = json.loads((evidence_home / "journal.jsonl").read_text().splitlines()[0])[
        "redacted_input_summary"
    ]
    assert summary.endswith("...(truncated)")

    report = inspect_journal(evidence_home / "journal.jsonl")
    assert report.safe_for_upload is False
    assert report.actions[0].classification is PrivacyClassification.PARTIALLY_REDACTED
    assert report.actions[0].retained_parameter_names == ("blob",)


def test_old_journals_fall_back_to_summary_parsing():
    """Journals without ``parameter_retention`` are classified via the summary."""
    event = {
        "event_type": "decision",
        "decision": "allowed",
        "action_name": "legacy",
        "redacted_input_summary": 'amount=5, api_key="<REDACTED>"',
    }
    snapshot = JournalSnapshot(
        verification=VerificationResult(valid=True, events_verified=1, issues=()),
        events=(event,),
    )
    report = inspect_verified_snapshot(snapshot)
    action = report.actions[0]
    assert action.classification is PrivacyClassification.PARTIALLY_REDACTED
    assert action.retained_parameter_names == ("amount",)
