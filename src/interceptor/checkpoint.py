"""Durable commit of the journal tail: the checkpoint.

Tail truncation (deleting events from the end of the journal) is undetectable
from the journal alone — every remaining event still chains correctly. The
checkpoint closes that gap with an external witness: a signed event that
commits to ``(event_count, head_hash)`` at a point in time. The operator keeps
the witness somewhere outside the journal; ``verify --checkpoint`` then treats
any journal shorter than the committed count as truncated.

The checkpoint event itself is appended to the journal, signed and hash-chained
like every other event, so a checkpoint that survives in the journal also
extends the committed prefix automatically.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path

from .identity import LocalSigningIdentity
from .journal import (
    EVENT_SCHEMA_VERSION,
    FileJournal,
    finalize_event,
    new_event_id,
    utc_timestamp,
)

CHECKPOINT_EVENT_TYPE = "checkpoint"


@dataclasses.dataclass(frozen=True)
class CheckpointReport:
    journal_path: Path
    checkpoint_event: dict[str, object]
    checkpoint_count: int
    head_sha256: str | None
    witness_path: Path


def checkpoint_journal(
    path: str | Path,
    *,
    identity: LocalSigningIdentity | None = None,
    witness_path: str | Path | None = None,
) -> CheckpointReport:
    """Append a signed checkpoint event and write its durable witness.

    The witness is the checkpoint event's canonical JSON line; save it somewhere
    the journal cannot reach (a backup, a second machine, a message). Verify a
    journal against it with ``verify_journal(..., checkpoint=witness_path)``.

    When *witness_path* is omitted the witness is written next to the journal
    as ``<journal>.checkpoint``, overwriting any older witness.
    """
    journal = Path(path)
    identity = identity or LocalSigningIdentity.load_or_create()
    store = FileJournal(journal)

    def build(count: int, previous_hash: str | None) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": CHECKPOINT_EVENT_TYPE,
            "event_id": new_event_id(),
            "timestamp_utc": utc_timestamp(),
            "key_id": identity.key_id,
            "previous_event_hash": previous_hash,
            "checkpoint_count": count,
            "head_sha256": previous_hash,
        }
        return finalize_event(payload, identity.sign)

    event = store.append_checkpoint(build)
    witness = (
        Path(witness_path)
        if witness_path is not None
        else journal.with_name(journal.name + ".checkpoint")
    )
    _write_durable(witness, json.dumps(event, sort_keys=True, separators=(",", ":")))
    return CheckpointReport(
        journal_path=journal,
        checkpoint_event=event,
        checkpoint_count=int(event["checkpoint_count"]),
        head_sha256=event.get("head_sha256"),
        witness_path=witness,
    )


def _write_durable(path: Path, text: str) -> None:
    """Write *text* and fsync so the witness survives a crash."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
