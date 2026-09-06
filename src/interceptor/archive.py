"""Journal rotation: archive the live file and start a linked successor.

Journals grow without bound; operators need to rotate them without losing the
chain of custody. :func:`archive_journal` renames the live journal to a
timestamped sibling and starts a fresh file whose first event is an ``archive``
record committing to the predecessor's ``(count, head)`` — so a later reader
can follow the link backwards across rotations.

Run archives while writers are quiesced. The destination is claimed
exclusively (no concurrent archiver can take it), and a *cross-process* writer
that slips between the stats read and the rename — or the rename and the first
append — aborts the operation with :class:`ArchiveError` (rolling the rename
back when needed) instead of producing a broken chain.
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
class ArchiveChainIssue:
    file: str
    code: str
    message: str


@dataclasses.dataclass(frozen=True)
class ArchiveChainReport:
    valid: bool
    files_checked: tuple[str, ...]
    issues: tuple[ArchiveChainIssue, ...]


def verify_archive_chain(
    live_path: str | Path,
    public_keys: Any,
    *,
    max_links: int = 1024,
) -> ArchiveChainReport:
    """Verify the live journal plus every archived predecessor it links to.

    Each successor's first event is an ``archive`` record committing to the
    predecessor's ``(count, head)``. This walks those links backwards: every
    file must verify standalone, the predecessor file must exist beside the
    successor, and its actual ``(count, head)`` must equal the committed link.
    A missing predecessor, a count/head mismatch, or a cycle fails the chain.
    """
    from .verification import verify_journal

    live = Path(live_path)
    files_checked: list[str] = []
    issues: list[ArchiveChainIssue] = []
    seen: set[str] = set()
    current = live
    links = 0
    while True:
        try:
            key = str(current.resolve())
        except OSError:
            key = str(current)
        if key in seen:
            issues.append(ArchiveChainIssue(str(current), "archive_cycle", "archive chain loops"))
            break
        seen.add(key)
        if not current.exists():
            issues.append(
                ArchiveChainIssue(
                    str(current), "archive_missing", "archived predecessor file is missing"
                )
            )
            break
        result = verify_journal(current, public_keys)
        files_checked.append(str(current))
        if not result.valid:
            first = result.issues[0] if result.issues else None
            detail = f" [{first.code}] {first.message}" if first is not None else ""
            issues.append(
                ArchiveChainIssue(
                    str(current), "archive_invalid", f"file fails verification{detail}"
                )
            )
            break
        # Read the first non-blank line to find the link (if any).
        first_event: dict[str, Any] | None = None
        try:
            import json as _json

            with open(current, "rb") as handle:
                for raw in handle:
                    if raw.strip():
                        parsed = _json.loads(raw.decode("utf-8"))
                        first_event = parsed if isinstance(parsed, dict) else None
                        break
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            issues.append(
                ArchiveChainIssue(str(current), "archive_unreadable", f"cannot read file: {exc}")
            )
            break
        if first_event is None or first_event.get("event_type") != ARCHIVE_EVENT_TYPE:
            break  # genesis file: chain complete.
        if links >= max_links:
            issues.append(
                ArchiveChainIssue(str(current), "archive_too_deep", "archive chain too long")
            )
            break
        archived_name = first_event.get("archived_path")
        prior_count = first_event.get("prior_count")
        prior_head = first_event.get("prior_head")
        if (
            not isinstance(archived_name, str)
            or "/" in archived_name
            or "\\" in archived_name
            or archived_name in (".", "..")
        ):
            issues.append(
                ArchiveChainIssue(
                    str(current), "archive_bad_link", "archived_path must be a bare file name"
                )
            )
            break
        predecessor = current.parent / archived_name
        if not predecessor.exists():
            issues.append(
                ArchiveChainIssue(
                    str(predecessor), "archive_missing", "archived predecessor file is missing"
                )
            )
            break
        # Check the predecessor's actual (count, head) against the commitment.
        try:
            import json as _json2

            count = 0
            head: str | None = None
            with open(predecessor, "rb") as handle:
                for raw in handle:
                    if not raw.strip():
                        continue
                    count += 1
                    try:
                        parsed = _json2.loads(raw.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        continue
                    h = parsed.get("event_hash") if isinstance(parsed, dict) else None
                    if isinstance(h, str):
                        head = h
        except OSError as exc:
            issues.append(
                ArchiveChainIssue(
                    str(predecessor), "archive_unreadable", f"cannot read file: {exc}"
                )
            )
            break
        if not isinstance(prior_count, int) or count != prior_count:
            issues.append(
                ArchiveChainIssue(
                    str(current),
                    "archive_count_mismatch",
                    f"archive commits to count {prior_count!r} but {predecessor.name} "
                    f"holds {count} events",
                )
            )
            break
        if head != prior_head:
            issues.append(
                ArchiveChainIssue(
                    str(current),
                    "archive_head_mismatch",
                    "archive prior_head does not match the predecessor's last event_hash",
                )
            )
            break
        current = predecessor
        links += 1
    return ArchiveChainReport(
        valid=not issues, files_checked=tuple(files_checked), issues=tuple(issues)
    )


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
    if keep is not None and keep < 1:
        raise ArchiveError(f"keep must be positive, got {keep}")
    store = FileJournal(journal)
    try:
        count, head = store.archive_stats()
    except JournalError as exc:
        raise ArchiveError(str(exc)) from exc
    if count == 0:
        raise ArchiveError(f"nothing to archive in {journal}")

    archived = _claim_archive_path(journal)
    try:
        os.replace(journal, archived)
    except OSError as exc:
        raise ArchiveError(f"cannot archive {journal}: {exc}") from exc
    # A writer that slipped between the stats read and the rename would leave
    # the archived file longer than committed. Detect it and roll back rather
    # than writing a custody link that `verify-chain` would (correctly) reject.
    try:
        settled_count, settled_head = FileJournal(archived).archive_stats()
    except JournalError as exc:
        _rollback_archive(archived, journal)
        raise ArchiveError(f"cannot archive {journal}: {exc}") from exc
    if (settled_count, settled_head) != (count, head):
        if _rollback_archive(archived, journal):
            raise ArchiveError(f"concurrent write to {journal} during archive; rerun the archive")
        raise ArchiveError(
            f"concurrent write to {journal} during archive, and a new file now "
            f"exists at the live path; old evidence is intact at {archived} — "
            "reconcile manually instead of rerunning blindly"
        )

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


def _claim_archive_path(path: Path) -> Path:
    """Reserve a destination name no concurrent archiver can take.

    The timestamped candidate is claimed with ``O_CREAT|O_EXCL`` before the
    rename, so two archivers in the same second diverge to different suffixes
    instead of the second ``os.replace`` destroying the first archive.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    index = 0
    while True:
        name = f"{path.stem}-{stamp}.jsonl" if index == 0 else f"{path.stem}-{stamp}-{index}.jsonl"
        candidate = path.with_name(name)
        try:
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            index += 1
            continue
        except OSError as exc:
            raise ArchiveError(f"cannot reserve archive path {candidate}: {exc}") from exc
        os.close(fd)
        return candidate


def _rollback_archive(archived: Path, journal: Path) -> bool:
    """Move a renamed journal back after an aborted archive.

    Refuses when a successor file already exists at the live path — rolling
    back over it would delete valid foreign events. In that case the operator
    must reconcile manually: the old evidence is intact at *archived*.
    Returns True when the rollback happened.
    """
    if journal.exists():
        return False
    try:
        os.replace(archived, journal)
    except OSError:
        return False
    return True


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
