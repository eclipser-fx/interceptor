"""Offline journal verification.

Verification is fully deterministic and needs only the journal file and the
local public verification key. It checks, per event:

* the line parses as a JSON object;
* ``schema_version`` is a known version;
* required fields for the event type are present with sane types;
* ``event_hash`` equals SHA-256 of the canonical unsigned payload
  (everything except ``event_hash`` and ``signature``);
* the Ed25519 ``signature`` verifies over the raw digest bytes;
* ``previous_event_hash`` links to the immediately preceding event
  (JSON ``null`` for the first event).

The journal is read one line at a time, never loaded whole, so verification
memory is bounded by the largest single event rather than the total file size.

This detects modified events, reordered events, and deletion from the middle
of the chain. Deleting the final tail of the journal is NOT detectable from
the journal alone — unless the journal holds a ``checkpoint`` event, or
``verify_journal(..., checkpoint=...)`` is given a durable witness. A
checkpoint commits to the event count at a point in time; a journal shorter
than that count is truncated.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import key_id_for, verify_signature
from .journal import EVENT_SCHEMA_VERSION, event_digest, unsigned_payload

KNOWN_SCHEMA_VERSIONS = frozenset({EVENT_SCHEMA_VERSION})
KNOWN_EVENT_TYPES = frozenset(
    {
        "decision",
        "outcome",
        "checkpoint",
        "resolution",
        "countersignature",
        "archive",
        "rotation",
    }
)

_SHARED_REQUIRED_FIELDS = (
    "schema_version",
    "event_type",
    "event_id",
    "action_id",
    "action_name",
    "contract_hash",
    "timestamp_utc",
    "key_id",
    "event_hash",
    "signature",
)
_DECISION_REQUIRED_FIELDS = (
    "decision",
    "risk",
    "approval_mode",
    "redacted_input_summary",
    "input_hash",
)
_OUTCOME_REQUIRED_FIELDS = (
    "status",
    "decision_event_id",
)
_CHECKPOINT_REQUIRED_FIELDS = (
    "schema_version",
    "event_type",
    "event_id",
    "timestamp_utc",
    "key_id",
    "previous_event_hash",
    "event_hash",
    "signature",
    "checkpoint_count",
    "head_sha256",
)
_RESOLUTION_REQUIRED_FIELDS = (
    "schema_version",
    "event_type",
    "event_id",
    "action_id",
    "action_name",
    "contract_hash",
    "timestamp_utc",
    "key_id",
    "event_hash",
    "signature",
    "decision_event_id",
    "resolution",
    "note",
)
_COUNTERSIGNATURE_REQUIRED_FIELDS = (
    "schema_version",
    "event_type",
    "event_id",
    "timestamp_utc",
    "key_id",
    "previous_event_hash",
    "event_hash",
    "signature",
    "checkpoint_event_id",
    "checkpoint_count",
    "head_sha256",
)
_ARCHIVE_REQUIRED_FIELDS = (
    "schema_version",
    "event_type",
    "event_id",
    "timestamp_utc",
    "key_id",
    "previous_event_hash",
    "event_hash",
    "signature",
    "prior_count",
    "prior_head",
    "archived_path",
)
_ROTATION_REQUIRED_FIELDS = (
    "schema_version",
    "event_type",
    "event_id",
    "timestamp_utc",
    "key_id",
    "previous_event_hash",
    "event_hash",
    "signature",
    "prior_key_id",
    "successor_key_id",
    "successor_fingerprint",
)

KNOWN_RESOLUTIONS = frozenset({"confirmed_completed", "confirmed_not_completed"})


@dataclasses.dataclass(frozen=True)
class VerificationIssue:
    line_number: int  # 1-based journal line; 0 for file-level issues
    code: str
    message: str


@dataclasses.dataclass(frozen=True)
class VerificationResult:
    valid: bool
    events_verified: int
    issues: tuple[VerificationIssue, ...]


@dataclasses.dataclass(frozen=True)
class JournalSnapshot:
    """One immutable read of a journal and its local verification result."""

    verification: VerificationResult
    events: tuple[dict[str, Any], ...]


#: A single verification key, or the full set an operator still trusts.
PublicKeys = Ed25519PublicKey | Sequence[Ed25519PublicKey]


def _to_keyring(public_keys: PublicKeys) -> dict[str, Ed25519PublicKey]:
    if isinstance(public_keys, Ed25519PublicKey):
        keys: tuple[Ed25519PublicKey, ...] = (public_keys,)
    else:
        keys = tuple(public_keys)
    return {key_id_for(key): key for key in keys}


def verify_journal(
    path: Path,
    public_keys: PublicKeys,
    *,
    checkpoint: Path | None = None,
) -> VerificationResult:
    """Verify every event and the hash chain of the journal at *path*.

    Each event must be signed by one of *public_keys* (a single key or the
    full trusted set, so a rotated journal verifies as one chain).

    When *checkpoint* names a witness file written by ``checkpoint_journal``,
    the journal must also cover the checkpoint's committed event count;
    otherwise verification fails with a truncation issue.

    Streams the file one line at a time and retains no parsed events, so peak
    memory is bounded by the largest single event rather than the total journal
    size.
    """
    trusted = _to_keyring(public_keys)
    result, _ = _read_and_verify(path, trusted, retain_events=False, checkpoint_path=checkpoint)
    return result


def load_journal_snapshot(
    path: Path,
    public_keys: PublicKeys,
) -> JournalSnapshot:
    """Read, parse, and verify a journal once for local consumers.

    Streams the file one line at a time. The only retained content is the
    parsed events themselves — never a full-file buffer or a split copy — so
    peak memory is bounded by the events plus the largest single line.

    Privacy inspection and evidence sync use the returned events so signed
    content cannot change between verification and subsequent local handling.
    """
    trusted = _to_keyring(public_keys)
    result, events = _read_and_verify(path, trusted, retain_events=True)
    return JournalSnapshot(verification=result, events=events)


def _read_and_verify(
    path: Path,
    trusted: dict[str, Ed25519PublicKey],
    *,
    retain_events: bool,
    checkpoint_path: Path | None = None,
) -> tuple[VerificationResult, tuple[dict[str, Any], ...]]:
    issues: list[VerificationIssue] = []
    events: list[dict[str, Any]] = []
    previous_hash: str | None = None
    events_verified = 0
    line_number = 0

    witness: dict[str, Any] | None = None
    witness_event_id: str | None = None
    witness_found = False
    if checkpoint_path is not None:
        witness, witness_issues = _load_checkpoint_witness(checkpoint_path, trusted)
        issues.extend(witness_issues)
        if witness is not None:
            witness_event_id = str(witness["event_id"])

    newest_checkpoint: dict[str, Any] | None = None
    checkpoints_by_id: dict[str, dict[str, Any]] = {}
    total_events = 0

    try:
        handle = path.open("rb")
    except OSError as exc:
        return (
            VerificationResult(
                False,
                0,
                (
                    VerificationIssue(
                        0, "unreadable", f"cannot read journal ({type(exc).__name__})"
                    ),
                ),
            ),
            (),
        )

    try:
        with handle:
            for raw_line in handle:
                line_number += 1
                stripped = raw_line.strip()
                if not stripped:
                    continue

                try:
                    event = json.loads(stripped.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    issues.append(
                        VerificationIssue(
                            line_number, "malformed_json", f"line is not valid JSON: {exc}"
                        )
                    )
                    # The chain cannot be followed past an unparseable line.
                    break

                if not isinstance(event, dict):
                    issues.append(
                        VerificationIssue(
                            line_number, "malformed_event", "line is not a JSON object"
                        )
                    )
                    break

                if retain_events:
                    events.append(event)
                event_issues = _verify_event(
                    event, line_number, previous_hash, trusted, checkpoints_by_id
                )
                issues.extend(event_issues)
                if not event_issues:
                    events_verified += 1

                # Follow the chain using the *stored* hash so a single tampered
                # payload reports one hash/signature issue instead of cascading
                # chain errors on every subsequent line. If the attacker
                # recomputed event_hash instead, the next event's linkage check
                # breaks — either way it is detected.
                stored_hash = event.get("event_hash")
                previous_hash = stored_hash if isinstance(stored_hash, str) else None

                total_events += 1
                if event.get("event_type") == "checkpoint":
                    newest_checkpoint = event
                    event_id = event.get("event_id")
                    if isinstance(event_id, str):
                        checkpoints_by_id[event_id] = event
                if witness_event_id is not None and event.get("event_id") == witness_event_id:
                    witness_found = True
    except OSError as exc:
        issues.append(
            VerificationIssue(
                line_number, "unreadable", f"cannot read journal ({type(exc).__name__})"
            )
        )

    issues.extend(
        _checkpoint_coverage(
            newest_checkpoint=newest_checkpoint,
            witness=witness,
            witness_found=witness_found,
            total_events=total_events,
        )
    )

    return (
        VerificationResult(valid=not issues, events_verified=events_verified, issues=tuple(issues)),
        tuple(events),
    )


def _load_checkpoint_witness(
    path: Path,
    trusted: dict[str, Ed25519PublicKey],
) -> tuple[dict[str, Any] | None, list[VerificationIssue]]:
    """Parse and cryptographically validate a checkpoint witness file.

    Returns the validated checkpoint event, or None plus the issues that
    invalidate it. A witness that fails here can never make a journal verify;
    at worst it adds a file-level issue.
    """
    try:
        raw = path.read_bytes().strip()
    except OSError as exc:
        return (
            None,
            [
                VerificationIssue(
                    0,
                    "checkpoint_witness_unreadable",
                    f"cannot read checkpoint witness ({type(exc).__name__})",
                )
            ],
        )
    if not raw:
        return None, [
            VerificationIssue(0, "checkpoint_witness_invalid", "checkpoint witness file is empty")
        ]
    try:
        event = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return (
            None,
            [
                VerificationIssue(
                    0, "checkpoint_witness_invalid", f"checkpoint witness is not valid JSON: {exc}"
                )
            ],
        )
    if not isinstance(event, dict):
        return (
            None,
            [
                VerificationIssue(
                    0, "checkpoint_witness_invalid", "checkpoint witness is not a JSON object"
                )
            ],
        )
    if event.get("schema_version") not in KNOWN_SCHEMA_VERSIONS:
        return None, [
            VerificationIssue(
                0,
                "checkpoint_witness_invalid",
                "checkpoint witness has unsupported schema_version "
                f"{event.get('schema_version')!r}",
            )
        ]
    if event.get("event_type") != "checkpoint":
        return None, [
            VerificationIssue(
                0,
                "checkpoint_witness_invalid",
                "checkpoint witness has event_type "
                f"{event.get('event_type')!r}, expected 'checkpoint'",
            )
        ]
    missing = [field for field in _CHECKPOINT_REQUIRED_FIELDS if field not in event]
    if missing:
        return None, [
            VerificationIssue(
                0,
                "checkpoint_witness_invalid",
                f"checkpoint witness is missing required fields: {', '.join(sorted(missing))}",
            )
        ]
    if event.get("head_sha256") != event.get("previous_event_hash"):
        return None, [
            VerificationIssue(
                0,
                "checkpoint_witness_invalid",
                "checkpoint witness head_sha256 does not match its previous_event_hash",
            )
        ]
    count = event.get("checkpoint_count")
    if not isinstance(count, int) or count < 0:
        return None, [
            VerificationIssue(
                0,
                "checkpoint_witness_invalid",
                "checkpoint witness checkpoint_count is not a non-negative integer",
            )
        ]
    digest = event_digest(unsigned_payload(event))
    if event["event_hash"] != digest.hex():
        return None, [
            VerificationIssue(
                0,
                "checkpoint_witness_invalid",
                "checkpoint witness event_hash does not match its payload",
            )
        ]
    key_id = event.get("key_id")
    signer = trusted.get(key_id) if isinstance(key_id, str) else None
    if signer is None:
        return None, [
            VerificationIssue(
                0,
                "checkpoint_witness_invalid",
                "checkpoint witness key_id is not among the trusted verification keys",
            )
        ]
    if not verify_signature(signer, digest, str(event["signature"])):
        return None, [
            VerificationIssue(
                0, "checkpoint_witness_invalid", "checkpoint witness signature does not verify"
            )
        ]
    return event, []


def _checkpoint_coverage(
    *,
    newest_checkpoint: dict[str, Any] | None,
    witness: dict[str, Any] | None,
    witness_found: bool,
    total_events: int,
) -> list[VerificationIssue]:
    """Detect journal truncation against the newest available checkpoint.

    The effective checkpoint is the one committing to the largest event count
    among the newest checkpoint already in the journal and a validated external
    witness. Any journal shorter than that count is missing events the
    checkpoint covered — i.e., the tail was truncated.
    """
    issues: list[VerificationIssue] = []
    candidates: list[dict[str, Any]] = []
    if newest_checkpoint is not None:
        candidates.append(newest_checkpoint)
    if witness is not None and witness_found:
        candidates.append(witness)
    elif witness is not None:
        # A valid witness that is not in the journal still bounds the expected
        # length, so report the truncation it proves as well.
        issues.append(
            VerificationIssue(
                0,
                "checkpoint_not_found",
                f"the checkpoint witness event {witness['event_id']!r} is not in the journal; "
                "the journal was truncated or the witness belongs to a different journal",
            )
        )
        _truncation_issue(issues, total_events, witness)

    effective = max(candidates, key=lambda event: event["checkpoint_count"]) if candidates else None
    if effective is not None:
        _truncation_issue(issues, total_events, effective)
    return issues


def _truncation_issue(
    issues: list[VerificationIssue],
    total_events: int,
    checkpoint: dict[str, Any],
) -> None:
    count = int(checkpoint["checkpoint_count"])
    if total_events < count:
        issues.append(
            VerificationIssue(
                0,
                "checkpoint_truncation",
                f"the journal has {total_events} events but a checkpoint commits to "
                f"{count}; the journal tail was truncated",
            )
        )


def _verify_event(
    event: dict[str, Any],
    line_number: int,
    expected_previous_hash: str | None,
    trusted: dict[str, Ed25519PublicKey],
    checkpoints_by_id: dict[str, dict[str, Any]],
) -> list[VerificationIssue]:
    issues: list[VerificationIssue] = []

    schema_version = event.get("schema_version")
    if schema_version not in KNOWN_SCHEMA_VERSIONS:
        issues.append(
            VerificationIssue(
                line_number,
                "unknown_schema",
                f"unsupported schema_version {schema_version!r}; "
                f"this verifier supports {sorted(KNOWN_SCHEMA_VERSIONS)}",
            )
        )
        return issues  # Field layout of unknown schemas is undefined.

    event_type = event.get("event_type")
    if event_type not in KNOWN_EVENT_TYPES:
        issues.append(
            VerificationIssue(
                line_number, "unknown_event_type", f"unknown event_type {event_type!r}"
            )
        )
        return issues

    if event_type == "checkpoint":
        required = list(_CHECKPOINT_REQUIRED_FIELDS)
    elif event_type == "resolution":
        required = list(_RESOLUTION_REQUIRED_FIELDS)
    elif event_type == "countersignature":
        required = list(_COUNTERSIGNATURE_REQUIRED_FIELDS)
    elif event_type == "archive":
        required = list(_ARCHIVE_REQUIRED_FIELDS)
    elif event_type == "rotation":
        required = list(_ROTATION_REQUIRED_FIELDS)
    else:
        required = list(_SHARED_REQUIRED_FIELDS)
        required += (
            list(_DECISION_REQUIRED_FIELDS)
            if event_type == "decision"
            else list(_OUTCOME_REQUIRED_FIELDS)
        )
    missing = [field for field in required if field not in event]
    if "previous_event_hash" not in event:
        missing.append("previous_event_hash")
    if missing:
        issues.append(
            VerificationIssue(
                line_number,
                "missing_fields",
                f"missing required fields: {', '.join(sorted(missing))}",
            )
        )
        return issues

    # Checkpoint-specific shape.
    if event_type == "checkpoint":
        if event.get("head_sha256") != event.get("previous_event_hash"):
            issues.append(
                VerificationIssue(
                    line_number,
                    "checkpoint_head_mismatch",
                    "head_sha256 does not match previous_event_hash",
                )
            )
        count = event.get("checkpoint_count")
        if not isinstance(count, int) or count < 0:
            issues.append(
                VerificationIssue(
                    line_number,
                    "checkpoint_bad_count",
                    "checkpoint_count is not a non-negative integer",
                )
            )

    # Resolution-specific shape.
    if event_type == "resolution":
        if event.get("resolution") not in KNOWN_RESOLUTIONS:
            issues.append(
                VerificationIssue(
                    line_number,
                    "resolution_bad_value",
                    f"resolution {event.get('resolution')!r} is not one of "
                    f"{sorted(KNOWN_RESOLUTIONS)}",
                )
            )
        if not isinstance(event.get("decision_event_id"), str):
            issues.append(
                VerificationIssue(
                    line_number,
                    "resolution_bad_reference",
                    "decision_event_id is not a string",
                )
            )
        if not isinstance(event.get("note"), str):
            issues.append(
                VerificationIssue(
                    line_number,
                    "resolution_bad_note",
                    "note is not a string",
                )
            )

    # Countersignature-specific shape: the referenced checkpoint must already
    # be in this journal with matching count and head.
    if event_type == "countersignature":
        ref = event.get("checkpoint_event_id")
        checkpoint = checkpoints_by_id.get(ref) if isinstance(ref, str) else None
        if checkpoint is None:
            issues.append(
                VerificationIssue(
                    line_number,
                    "countersignature_orphan",
                    f"references unknown checkpoint event {ref!r}; the checkpoint "
                    "must appear earlier in the same journal",
                )
            )
        else:
            if event.get("checkpoint_count") != checkpoint.get("checkpoint_count"):
                issues.append(
                    VerificationIssue(
                        line_number,
                        "countersignature_count_mismatch",
                        "checkpoint_count does not match the referenced checkpoint",
                    )
                )
            if event.get("head_sha256") != checkpoint.get("head_sha256"):
                issues.append(
                    VerificationIssue(
                        line_number,
                        "countersignature_head_mismatch",
                        "head_sha256 does not match the referenced checkpoint",
                    )
                )
        count = event.get("checkpoint_count")
        if not isinstance(count, int) or count < 0:
            issues.append(
                VerificationIssue(
                    line_number,
                    "countersignature_bad_count",
                    "checkpoint_count is not a non-negative integer",
                )
            )

    # Outcome receipt shape: optional, but when present it must be an object.
    if event_type == "outcome" and "receipt" in event:
        if not isinstance(event["receipt"], dict):
            issues.append(
                VerificationIssue(
                    line_number,
                    "outcome_bad_receipt",
                    "receipt is not an object",
                )
            )

    # Archive shape: links the predecessor file and must start its own file.
    if event_type == "archive":
        if event.get("previous_event_hash") is not None:
            issues.append(
                VerificationIssue(
                    line_number,
                    "archive_not_first",
                    "archive event must be the first line of its file",
                )
            )
        count = event.get("prior_count")
        if not isinstance(count, int) or count < 1:
            issues.append(
                VerificationIssue(
                    line_number,
                    "archive_bad_count",
                    "prior_count is not a positive integer",
                )
            )
        archived_path = event.get("archived_path")
        if not isinstance(archived_path, str):
            issues.append(
                VerificationIssue(
                    line_number,
                    "archive_bad_path",
                    "archived_path is not a string",
                )
            )
        elif "/" in archived_path or "\\" in archived_path or archived_path in (".", ".."):
            issues.append(
                VerificationIssue(
                    line_number,
                    "archive_bad_path",
                    "archived_path must be a bare file name",
                )
            )

    # Rotation shape: old key authorizes its successor in-chain.
    if event_type == "rotation":
        prior = event.get("prior_key_id")
        successor = event.get("successor_key_id")
        fingerprint = event.get("successor_fingerprint")
        if prior != event.get("key_id"):
            issues.append(
                VerificationIssue(
                    line_number,
                    "rotation_signer_mismatch",
                    "prior_key_id must equal the signing key_id",
                )
            )
        if not isinstance(successor, str) or not successor.startswith("ed25519:"):
            issues.append(
                VerificationIssue(
                    line_number,
                    "rotation_bad_successor",
                    "successor_key_id is not an ed25519 key id",
                )
            )
        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(c not in "0123456789abcdef" for c in fingerprint)
        ):
            issues.append(
                VerificationIssue(
                    line_number,
                    "rotation_bad_fingerprint",
                    "successor_fingerprint is not 64-char lowercase hex",
                )
            )
        elif isinstance(successor, str) and successor != f"ed25519:{fingerprint[:16]}":
            issues.append(
                VerificationIssue(
                    line_number,
                    "rotation_fingerprint_mismatch",
                    "successor_key_id does not match successor_fingerprint",
                )
            )
        if isinstance(prior, str) and prior == successor:
            issues.append(
                VerificationIssue(
                    line_number,
                    "rotation_self_successor",
                    "successor must differ from prior key",
                )
            )

    # Chain linkage.
    if event["previous_event_hash"] != expected_previous_hash:
        issues.append(
            VerificationIssue(
                line_number,
                "chain_break",
                "previous_event_hash does not match the preceding event "
                f"(expected {expected_previous_hash!r}, found {event['previous_event_hash']!r}); "
                "events may have been modified, reordered, or deleted",
            )
        )

    # Hash integrity.
    payload = unsigned_payload(event)
    digest = event_digest(payload)
    if event["event_hash"] != digest.hex():
        issues.append(
            VerificationIssue(
                line_number,
                "hash_mismatch",
                "event_hash does not match the canonical payload; event was modified",
            )
        )

    # Signature over the recomputed digest: a tampered payload fails here even
    # if the attacker also recomputed event_hash. With a keyring, each event
    # is checked against the key that signed it, so a rotated journal (old and
    # new keys) verifies as one chain.
    key_id = event.get("key_id")
    signer = trusted.get(key_id) if isinstance(key_id, str) else None
    if signer is None:
        issues.append(
            VerificationIssue(
                line_number,
                "unknown_key",
                f"event key_id {event.get('key_id')!r} is not among the trusted verification keys",
            )
        )
    elif not verify_signature(signer, digest, str(event["signature"])):
        issues.append(
            VerificationIssue(line_number, "bad_signature", "Ed25519 signature verification failed")
        )

    return issues
