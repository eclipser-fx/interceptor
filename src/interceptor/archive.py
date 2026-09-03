"""Journal rotation: archive the live file and start a linked successor.

Journals grow without bound; operators need to rotate them without losing the
chain of custody. :func:`archive_journal` renames the live journal to a
timestamped sibling and starts a fresh file whose first event is an ``archive``
record committing to the predecessor's ``(count, head)`` — so a later reader
can follow the link backwards across rotations.

Run archives while writers are quiesced. In-process writers are held off by
the journal lock for the whole operation; a concurrent *cross-process* writer
that slips between the rename and the first append of the new file aborts the
operation with :class:`ArchiveError` instead of producing a broken chain.
"""

from __future__ import annotations

import dataclasses
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ArchiveError, JournalError
from .identity import LocalSigningIdentity, SigningIdentity
from .journal import EVENT_SCHEMA_VERSION, FileJournal, finalize_event, new_event_id, utc_timestamp

ARCHIVE_EVENT_TYPE = "archive"


@dataclasses.dataclass(frozen=True)
class ArchiveReport:
    journal_path: Path
    archived_path: Path
    archive_event: dict[str, Any]
    prior_count: int
    prior_head: str | None
    pruned: tuple[Path, ...]


def archive_journal(
    path: str | Path,
    *,
    keep: int | None = None,
    identity: SigningIdentity | None = None,
) -> ArchiveReport:
    """Rotate the journal at *path*.

    The live file becomes ``<stem>-<UTC timestamp>.jsonl`` next to it; the new
    live file starts with a signed ``archive`` event. With *keep*, only the
    newest *keep* archives are retained (oldest deleted, best-effort).
    """
    journal = Path(path)
    store = FileJournal(journal)
    try:
        count, head = store.archive_stats()
    except JournalError as exc:
        raise ArchiveError(str(exc)) from exc
    if count == 0:
        raise ArchiveError(f"nothing to archive in {journal}")

    archived = _unique_archive_path(journal)
    try:
        os.replace(journal, archived)
    except OSError as exc:
        raise ArchiveError(f"cannot archive {journal}: {exc}") from exc

    signer = identity or LocalSigningIdentity.load_or_create()
    archived_name = archived.name

    def build(previous_hash: str | None) -> dict[str, Any]:
        if previous_hash is not None:
            # A cross-process writer created the new file between our rename
            # and this append. Refuse to chain an archive link after foreign
            # events; the operator can rerun the archive (nothing was lost:
            # the old file is intact at `archived`, the new events are valid).
            raise ArchiveError(f"concurrent write to {journal} during archive; rerun the archive")
        payload: dict[str, Any] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": ARCHIVE_EVENT_TYPE,
            "event_id": new_event_id(),
            "timestamp_utc": utc_timestamp(),
            "key_id": signer.key_id,
            "previous_event_hash": None,
            "prior_count": count,
            "prior_head": head,
            "archived_path": archived_name,
        }
        return finalize_event(payload, signer.sign)

    try:
        event = store.append_event(build)
    except ArchiveError:
        raise
    except Exception as exc:
        raise ArchiveError(f"cannot start archived journal {journal}: {exc}") from exc

    pruned: tuple[Path, ...] = ()
    if keep is not None:
        if keep < 1:
            raise ArchiveError(f"keep must be positive, got {keep}")
        pruned = _prune_archives(journal, keep)
    return ArchiveReport(
        journal_path=journal,
        archived_path=archived,
        archive_event=event,
        prior_count=count,
        prior_head=head,
        pruned=pruned,
    )


def _archive_glob_root(path: Path) -> tuple[Path, str]:
    return path.parent, f"{path.stem}-*.jsonl"


def _unique_archive_path(path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = path.with_name(f"{path.stem}-{stamp}.jsonl")
    index = 1
    while candidate.exists():
        index += 1
        candidate = path.with_name(f"{path.stem}-{stamp}-{index}.jsonl")
    return candidate


def _prune_archives(path: Path, keep: int) -> tuple[Path, ...]:
    parent, pattern = _archive_glob_root(path)
    # Newest-first by mtime: same-second archive names do not sort
    # lexicographically (`-2` sorts before `.jsonl`), so names lie.
    archives = sorted(parent.glob(pattern), key=lambda p: (p.stat().st_mtime_ns, p.name))
    doomed = archives[: max(0, len(archives) - keep)]
    pruned: list[Path] = []
    for candidate in doomed:
        try:
            candidate.unlink()
        except OSError:
            continue  # best-effort: a leftover archive is clutter, not corruption
        pruned.append(candidate)
    return tuple(pruned)
