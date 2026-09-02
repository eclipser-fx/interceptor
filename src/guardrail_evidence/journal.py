"""Append-only, hash-chained JSONL journal for evidence events.

Event format (schema version ``1``)
-----------------------------------
Every event is one JSON object per line with the shared fields::

    schema_version, event_type, event_id, action_id, action_name,
    contract_hash, timestamp_utc, key_id, previous_event_hash,
    event_hash, signature

``decision`` events add: ``decision``, ``risk``, ``approval_mode``,
``redacted_input_summary``, ``input_hash``.

``outcome`` events add: ``status`` (``succeeded`` | ``failed``),
``observed_result_type``, ``redacted_output_hash`` (optional),
``exception_type`` / ``sanitized_error_summary`` (on failure), and
``decision_event_id`` linking back to the decision that authorized execution.

Signing (documented precisely):

1. The *unsigned payload* is the event object without ``event_hash`` and
   ``signature``. ``previous_event_hash`` IS part of the unsigned payload.
2. ``canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'),
   ensure_ascii=False).encode('utf-8')``
3. ``event_hash = SHA-256(canonical)`` hex-encoded.
4. ``signature = base64(Ed25519.sign(SHA-256(canonical) as raw 32 bytes))`` —
   the signature is over the raw digest bytes, matching the guard runtime's
   execution-receipt convention.

Chain rules: ``previous_event_hash`` is the previous line's ``event_hash``;
the first event uses JSON ``null``. Modification, reordering, and deletion
from the middle of the chain are detectable offline. Deleting the *tail* of
the journal is NOT detectable from the journal alone — that requires an
external checkpoint/witness (a Connected-mode capability).

Concurrency: appends take an in-process lock and, on platforms that support
it, an OS-level file lock (``fcntl.flock`` on Unix, ``msvcrt.locking`` on
Windows) around the read-previous-hash + append + fsync sequence. If two
uncoordinated processes write on a platform where locking is unavailable,
interleaving could break the chain; verification will detect that as a chain
error rather than silently accepting it.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from .canonical import canonical_json_bytes
from .errors import JournalError

EVENT_SCHEMA_VERSION = "1"
GENESIS_PREVIOUS_HASH = None

_process_locks: dict[str, threading.Lock] = {}
_process_locks_guard = threading.Lock()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def new_event_id() -> str:
    return str(uuid.uuid4())


def unsigned_payload(event: dict[str, Any]) -> dict[str, Any]:
    """The event without ``event_hash`` and ``signature``."""
    return {k: v for k, v in event.items() if k not in ("event_hash", "signature")}


def event_digest(payload: dict[str, Any]) -> bytes:
    """SHA-256 raw digest of the canonical unsigned payload."""
    return hashlib.sha256(canonical_json_bytes(payload)).digest()


def finalize_event(
    payload: dict[str, Any],
    sign: Callable[[bytes], str],
) -> dict[str, Any]:
    """Attach ``event_hash`` and ``signature`` to an unsigned payload."""
    digest = event_digest(payload)
    event = dict(payload)
    event["event_hash"] = digest.hex()
    event["signature"] = sign(digest)
    return event


class JournalStore(Protocol):
    """Evidence sink interface.

    ``append_event`` receives a builder because the previous event hash must
    be read and the new event appended under one lock; the builder gets the
    previous hash and returns the fully signed event. an observer integration can
    implement this same interface with a remote evidence sink.
    """

    @property
    def path(self) -> Path: ...

    def append_event(self, build: Callable[[str | None], dict[str, Any]]) -> dict[str, Any]: ...


class FileJournal:
    """Append-only JSONL journal on the local filesystem."""

    def __init__(self, path: Path) -> None:
        self._path = path
        try:
            key = str(Path(path).resolve())
        except Exception:
            # Fallback for exotic paths where resolve() fails (permission, loop).
            key = str(Path.cwd() / path) if not path.is_absolute() else str(path)
        with _process_locks_guard:
            self._lock = _process_locks.setdefault(key, threading.Lock())

    @property
    def path(self) -> Path:
        return self._path

    def append_event(self, build: Callable[[str | None], dict[str, Any]]) -> dict[str, Any]:
        """Read the chain tail, build the signed event, and durably append it.

        Raises JournalError on any I/O failure; if this happens before the
        write, nothing has been persisted.
        """
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a+b") as handle:
                    _lock_file(handle)
                    try:
                        previous_hash = _read_last_event_hash(handle)
                        event = build(previous_hash)
                        line = json.dumps(
                            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                        )
                        handle.seek(0, io.SEEK_END)
                        handle.write(line.encode("utf-8") + b"\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    finally:
                        _unlock_file(handle)
            except JournalError:
                raise
            except OSError as exc:
                raise JournalError(f"cannot append to journal {self._path}: {exc}") from exc
            return event

    def append_checkpoint(
        self, build: Callable[[int, str | None], dict[str, Any]]
    ) -> dict[str, Any]:
        """Count the journal and append a checkpoint event atomically.

        The event count and the previous event hash are read under the same
        file lock as the append, so a checkpoint commits to a state that is
        internally consistent even if another process appends concurrently.
        """
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a+b") as handle:
                    _lock_file(handle)
                    try:
                        count = _count_event_lines(handle)
                        previous_hash = _read_last_event_hash(handle)
                        event = build(count, previous_hash)
                        line = json.dumps(
                            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                        )
                        handle.seek(0, io.SEEK_END)
                        handle.write(line.encode("utf-8") + b"\n")
                        handle.flush()
                        os.fsync(handle.fileno())
                    finally:
                        _unlock_file(handle)
            except JournalError:
                raise
            except OSError as exc:
                raise JournalError(f"cannot append to journal {self._path}: {exc}") from exc
            return event


#: How much of the file tail to read when looking for the last complete line.
#: Comfortably larger than any single event, and re-read in multiples when a
#: line turns out to be longer.
_TAIL_READ_BYTES = 64 * 1024


def _read_last_event_hash(handle: io.BufferedRandom) -> str | None:
    """The ``event_hash`` of the last journal line, or None for an empty file.

    Reads backward from the end rather than scanning forward from byte zero.
    The forward scan is the obvious implementation and it is quadratic: every
    append re-reads the entire journal, so a file that grows to a hundred
    thousand events spends its time re-reading the first ninety-nine thousand.
    """
    handle.seek(0, io.SEEK_END)
    size = handle.tell()
    if size == 0:
        return GENESIS_PREVIOUS_HASH

    window = _TAIL_READ_BYTES
    while True:
        start = max(0, size - window)
        handle.seek(start)
        chunk = handle.read(size - start)

        stripped = chunk.rstrip(b"\r\n")
        if not stripped:
            # Nothing but trailing newlines in this window.
            if start == 0:
                return GENESIS_PREVIOUS_HASH
            window *= 2
            continue

        newline = stripped.rfind(b"\n")
        if newline != -1:
            return _event_hash_from_line(stripped[newline + 1 :], handle)
        if start == 0:
            # The whole file is one line.
            return _event_hash_from_line(stripped, handle)
        # The last line is longer than the window; widen and retry.
        window *= 2


def _event_hash_from_line(line: bytes, handle: io.BufferedRandom) -> str:
    try:
        event = json.loads(line.decode("utf-8"))
        event_hash = event["event_hash"]
    except (ValueError, KeyError, UnicodeDecodeError) as exc:
        raise JournalError(
            "journal tail is corrupt; refusing to extend a broken chain "
            f"(run `guardrail-evidence verify` on {handle.name})"
        ) from exc
    if not isinstance(event_hash, str):
        raise JournalError("journal tail has a non-string event_hash; refusing to extend")
    return event_hash


def _count_event_lines(handle: io.BufferedRandom) -> int:
    """Number of non-blank lines in the journal (a forward scan)."""
    handle.seek(0)
    count = 0
    for raw in handle:
        if raw.strip():
            count += 1
    return count


def _read_last_event_hash_scan(handle: io.BufferedRandom) -> str | None:
    """Forward-scanning reference implementation, kept to test the fast path."""
    handle.seek(0)
    last_line: bytes | None = None
    for raw in handle:
        stripped = raw.strip()
        if stripped:
            last_line = stripped
    if last_line is None:
        return GENESIS_PREVIOUS_HASH
    try:
        event = json.loads(last_line.decode("utf-8"))
        event_hash = event["event_hash"]
    except (ValueError, KeyError, UnicodeDecodeError) as exc:
        raise JournalError(
            "journal tail is corrupt; refusing to extend a broken chain "
            f"(run `guardrail-evidence verify` on {handle.name})"
        ) from exc
    if not isinstance(event_hash, str):
        raise JournalError("journal tail has a non-string event_hash; refusing to extend")
    return event_hash


if os.name == "posix":
    import fcntl

    def _lock_file(handle: Any) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

    def _unlock_file(handle: Any) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

elif os.name == "nt":  # pragma: no cover - exercised only on Windows
    import msvcrt

    def _lock_file(handle: Any) -> None:
        handle.seek(0)
        # typeshed omits locking/LK_*; the Windows branch cannot be exercised here.
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]

    def _unlock_file(handle: Any) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]

else:  # pragma: no cover - unknown platform: in-process lock only

    def _lock_file(handle: Any) -> None:
        pass

    def _unlock_file(handle: Any) -> None:
        pass
