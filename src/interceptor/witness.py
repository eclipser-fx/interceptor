"""One-command tail-truncation defense: checkpoint and ship the witness.

A checkpoint only helps if the witness actually leaves the machine before an
attacker truncates the journal. :func:`witness_journal` makes that the default
path instead of a manual two-step: it appends the signed checkpoint event and
copies the witness file into *witness_dir* (timestamped, fsynced) — a directory
that must live where the journal cannot reach (a backup mount, a second host
synced by cron, WORM storage). Optionally it also counter-signs the checkpoint
with an external key in the same run.

Run it on a schedule (cron/systemd); verify with
``interceptor verify --checkpoint <dir>/latest`` or ``verify-chain``.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checkpoint import CheckpointReport, checkpoint_journal
from .errors import JournalError
from .identity import SigningIdentity

WITNESS_EVENT_TYPE = "checkpoint"


@dataclasses.dataclass(frozen=True)
class WitnessReport:
    journal_path: Path
    checkpoint_event_id: str
    checkpoint_count: int
    head_sha256: str | None
    witness_path: Path
    shipped_path: Path
    countersignature_event_id: str | None = None


def witness_journal(
    journal_path: str | Path,
    witness_dir: str | Path,
    *,
    identity: SigningIdentity | None = None,
    counter_key: str | Path | None = None,
    counter_password: bytes | str | None = None,
) -> WitnessReport:
    """Checkpoint *journal_path* and ship the witness into *witness_dir*.

    Returns paths to the local witness and the shipped copy. When *counter_key*
    is given, the checkpoint is also counter-signed (see :mod:`cosign`); a
    counter-sign failure raises without undoing the shipped witness — the
    witness is still valid evidence, just single-signed.
    """
    journal = Path(journal_path)
    directory = Path(witness_dir)
    report: CheckpointReport = checkpoint_journal(journal, identity=identity)
    shipped = _ship_witness(report.witness_path, directory)
    countersignature_id: str | None = None
    if counter_key is not None:
        from .cosign import countersign_journal
        from .errors import CountersignError

        try:
            countersigned = countersign_journal(journal, counter_key, counter_password)
        except CountersignError:
            raise
        except Exception as exc:
            raise JournalError(f"checkpoint witnessed but countersign failed: {exc}") from exc
        countersignature_id = str(countersigned.countersignature_event["event_id"])
    return WitnessReport(
        journal_path=journal,
        checkpoint_event_id=str(report.checkpoint_event["event_id"]),
        checkpoint_count=report.checkpoint_count,
        head_sha256=report.head_sha256,
        witness_path=report.witness_path,
        shipped_path=shipped,
        countersignature_event_id=countersignature_id,
    )


def _ship_witness(witness_path: Path, directory: Path) -> Path:
    """Copy the witness into *directory* under a timestamped name + `latest`.

    Same-second witnesses get a numeric suffix so a fast schedule never drops
    one silently (only `latest` is ever overwritten, by design).
    """
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = directory / f"checkpoint-{stamp}.checkpoint"
    index = 1
    while target.exists():
        index += 1
        target = directory / f"checkpoint-{stamp}-{index}.checkpoint"
    _durable_copy(witness_path, target)
    latest = directory / "latest.checkpoint"
    _durable_copy(witness_path, latest)
    return target


def _durable_copy(source: Path, target: Path) -> Path:
    tmp = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    try:
        shutil.copyfile(source, tmp)
        with open(tmp, "rb") as handle:
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        _fsync_dir(target.parent)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise JournalError(f"cannot ship witness to {target}: {exc}") from exc
    return target


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


@dataclasses.dataclass(frozen=True)
class WitnessFileStatus:
    path: Path
    checkpoint_count: int | None
    covered: bool
    detail: str = ""


@dataclasses.dataclass(frozen=True)
class WitnessAuditReport:
    witness_dir: Path
    files: tuple[WitnessFileStatus, ...]

    @property
    def valid(self) -> bool:
        """True when every shipped witness is valid and still covered."""
        return bool(self.files) and all(item.covered for item in self.files)


def audit_witnesses(
    witness_dir: str | Path,
    journal_path: str | Path,
    public_keys: Any,
) -> WitnessAuditReport:
    """Check every shipped witness in *witness_dir* against the live journal.

    Each ``*.checkpoint`` file must parse as a signed checkpoint from a
    trusted key *and* the journal must still cover its committed count —
    otherwise the tail was truncated past what that witness protects, or the
    witness never belonged to this journal. An empty directory is invalid:
    no witnesses means no truncation defense.
    """
    from .verification import verify_journal

    directory = Path(witness_dir)
    journal = Path(journal_path)
    statuses: list[WitnessFileStatus] = []
    try:
        # `latest.checkpoint` is a convenience pointer to the newest stamped
        # copy, not an independent witness — auditing it twice would double
        # count every directory.
        candidates = sorted(
            p for p in directory.glob("*.checkpoint") if p.name != "latest.checkpoint"
        )
    except OSError as exc:
        return WitnessAuditReport(
            directory,
            (WitnessFileStatus(directory, None, False, f"cannot list witness dir: {exc}"),),
        )
    for candidate in candidates:
        result = verify_journal(journal, public_keys, checkpoint=candidate)
        count: int | None = None
        try:
            import json as _json

            parsed = _json.loads(candidate.read_bytes().decode("utf-8"))
            raw_count = parsed.get("checkpoint_count") if isinstance(parsed, dict) else None
            count = raw_count if isinstance(raw_count, int) else None
        except (OSError, ValueError, UnicodeDecodeError):
            count = None
        if result.valid:
            statuses.append(WitnessFileStatus(candidate, count, True))
            continue
        first = result.issues[0] if result.issues else None
        detail = f"[{first.code}] {first.message}" if first is not None else "invalid"
        statuses.append(WitnessFileStatus(candidate, count, False, detail))
    return WitnessAuditReport(directory, tuple(statuses))


@dataclasses.dataclass(frozen=True)
class WitnessPruneReport:
    witness_dir: Path
    kept: tuple[Path, ...]
    deleted: tuple[Path, ...]


def prune_witnesses(witness_dir: str | Path, keep: int) -> WitnessPruneReport:
    """Delete the oldest shipped witnesses, keeping the newest *keep*.

    A 5-minute witness schedule writes ~105k files a year; without pruning
    the directory grows without bound. Pruning is safe for the truncation
    bound because every witness commits to an event count and counts grow
    with the journal: the newest witness subsumes every older prefix bound,
    so keeping the newest K preserves the K strongest bounds and only
    reduces historical depth. ``latest.checkpoint`` (a pointer to the
    newest stamped copy, not an independent witness) is never deleted.

    Conservative where it matters: entries that are not regular files, or
    whose mtime cannot be read, are kept and do not count against *keep* —
    pruning deletes only what it positively identifies as an old regular
    file. Partial unlink failures raise :class:`JournalError` naming what
    could not be deleted (deletions so far are already gone).

    One directory per journal: checkpoint files carry no journal identity,
    so a directory mixing witnesses from several journals cannot prune
    per-journal — keep-newest-K would delete the only witness of a quiet
    journal while keeping K of a busy one.
    """
    if keep < 1:
        raise ValueError("keep must be positive")
    directory = Path(witness_dir)
    if not directory.exists():
        raise JournalError(f"no witness dir at {directory}")
    if not directory.is_dir():
        raise JournalError(f"witness dir {directory} is not a directory")
    try:
        candidates = sorted(
            (p for p in directory.glob("*.checkpoint") if p.name != "latest.checkpoint"),
            key=lambda p: p.name,
        )
    except OSError as exc:
        raise JournalError(f"cannot list witness dir {directory}: {exc}") from exc
    regular: list[tuple[int, str, Path]] = []
    unassessed: list[Path] = []
    for candidate in candidates:
        try:
            if not candidate.is_file():
                unassessed.append(candidate)
                continue
            mtime_ns = candidate.stat().st_mtime_ns
        except OSError:
            unassessed.append(candidate)
            continue
        regular.append((mtime_ns, candidate.name, candidate))
    regular.sort(key=lambda item: (item[0], item[1]))
    paths = [path for _, _, path in regular]
    victims = paths[: max(0, len(paths) - keep)]
    kept = paths[len(victims) :]
    deleted: list[Path] = []
    failures: list[str] = []
    for victim in victims:
        try:
            victim.unlink()
            deleted.append(victim)
        except OSError as exc:
            failures.append(f"{victim}: {exc}")
    if failures:
        raise JournalError(
            "could not delete {} witness(es) in {}: {}".format(
                len(failures), directory, "; ".join(failures)
            )
        )
    return WitnessPruneReport(
        witness_dir=directory,
        kept=tuple(kept + unassessed),
        deleted=tuple(deleted),
    )


__all__ = [
    "WITNESS_EVENT_TYPE",
    "WitnessAuditReport",
    "WitnessFileStatus",
    "WitnessPruneReport",
    "WitnessReport",
    "audit_witnesses",
    "prune_witnesses",
    "witness_journal",
]
