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

        try:
            countersigned = countersign_journal(journal, counter_key, counter_password)
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
    """Copy the witness into *directory* under a timestamped name + `latest`."""
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = directory / f"checkpoint-{stamp}.json"
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


__all__ = ["WITNESS_EVENT_TYPE", "WitnessReport", "witness_journal"]
