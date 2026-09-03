"""Operator resolutions: signed closure for reconciliations.

``audit`` reports an allowed decision with no outcome (or a failed outcome) as
``needs_reconciliation`` — the external side effect may have happened, so the
operator must check the real world before retrying. This module records the
result of that check as a signed ``resolution`` event appended to the same
hash chain:

* ``confirmed_completed`` — the side effect did happen; do not retry.
* ``confirmed_not_completed`` — the side effect did not happen; retry is safe.

A resolution is an operator attestation, not proof: it says a human checked
the external system, nothing more. But it turns the reconciliation queue from
a dead end into a closed loop, and ``audit`` clears resolved invocations from
``needs_reconciliation`` accordingly.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from .errors import ResolutionError
from .identity import LocalSigningIdentity, SigningIdentity
from .journal import EVENT_SCHEMA_VERSION, FileJournal, finalize_event, new_event_id, utc_timestamp

RESOLUTION_EVENT_TYPE = "resolution"

RESOLUTION_COMPLETED = "confirmed_completed"
RESOLUTION_NOT_COMPLETED = "confirmed_not_completed"
KNOWN_RESOLUTIONS = frozenset({RESOLUTION_COMPLETED, RESOLUTION_NOT_COMPLETED})

_MAX_NOTE_CHARS = 1000


@dataclasses.dataclass(frozen=True)
class ResolutionReport:
    journal_path: Path
    resolution_event: dict[str, Any]
    decision_event_id: str
    resolution: str


def resolve_journal(
    path: str | Path,
    decision_event_id: str,
    resolution: str,
    note: str = "",
    *,
    identity: SigningIdentity | None = None,
) -> ResolutionReport:
    """Append a signed resolution for a reconciled decision.

    Raises :class:`ResolutionError` for an unknown decision id, a decision
    that was denied (nothing to reconcile), or an invalid resolution value.
    """
    if resolution not in KNOWN_RESOLUTIONS:
        raise ResolutionError(
            f"invalid resolution {resolution!r}: expected one of {sorted(KNOWN_RESOLUTIONS)}"
        )
    if not isinstance(note, str):
        raise ResolutionError("resolution note must be a string")
    note = note[:_MAX_NOTE_CHARS]

    journal = Path(path)
    decision = _find_decision(journal, decision_event_id)
    if decision is None:
        raise ResolutionError(f"unknown decision_event_id {decision_event_id!r} in {journal}")
    if decision.get("decision") != "allowed":
        raise ResolutionError(
            f"decision {decision_event_id!r} was not allowed; nothing to reconcile"
        )

    signer = identity or LocalSigningIdentity.load_or_create()

    def build(previous_hash: str | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": RESOLUTION_EVENT_TYPE,
            "event_id": new_event_id(),
            "action_id": decision["action_id"],
            "action_name": decision["action_name"],
            "contract_hash": decision["contract_hash"],
            "timestamp_utc": utc_timestamp(),
            "key_id": signer.key_id,
            "previous_event_hash": previous_hash,
            "decision_event_id": decision_event_id,
            "resolution": resolution,
            "note": note,
        }
        return finalize_event(payload, signer.sign)

    event = FileJournal(journal).append_event(build)
    return ResolutionReport(
        journal_path=journal,
        resolution_event=event,
        decision_event_id=decision_event_id,
        resolution=resolution,
    )


def _find_decision(journal: Path, decision_event_id: str) -> dict[str, Any] | None:
    """The decision event with *decision_event_id*, or None."""
    try:
        with open(journal, "rb") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if (
                    isinstance(event, dict)
                    and event.get("event_type") == "decision"
                    and event.get("event_id") == decision_event_id
                ):
                    return event
    except OSError:
        return None
    return None
