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

    def archive_stats(self) -> tuple[int, str | None]:
        """(event count, last event hash) read under lock. Empty file → (0, None)."""
        with self._lock:
            try:
                with open(self._path, "a+b") as handle:
                    _lock_file(handle)
                    try:
                        handle.seek(0, io.SEEK_END)
                        if handle.tell() == 0:
                            return 0, None
                        count = _count_event_lines(handle)
                        previous_hash = _read_last_event_hash(handle)
                    finally:
                        _unlock_file(handle)
            except OSError as exc:
                raise JournalError(f"cannot read journal {self._path}: {exc}") from exc
            return count, previous_hash

    def append_event_atomic(
        self,
        build: Callable[[str | None, str | None], dict[str, Any]],
        *,
        action_name: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Check idempotency and append one event under a single file lock.

        The blocking-prior scan, the tail-hash read, and the append happen
        under the same OS file lock, so two processes racing with the same
        ``(action_name, idempotency_key)`` cannot both append an ``allowed``
        decision. ``build`` receives ``(previous_hash, blocking_prior_id)``
        and returns the fully signed event; the caller decides whether a
        non-None ``blocking_prior_id`` means a denied duplicate.
        """
        with self._lock:
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a+b") as handle:
                    _lock_file(handle)
                    try:
                        blocking: str | None = None
                        if action_name is not None and idempotency_key is not None:
                            blocking = _scan_blocking_idempotent(
                                handle, action_name, idempotency_key
                            )
                        previous_hash = _read_last_event_hash(handle)
                        event = build(previous_hash, blocking)
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
            f"(run `interceptor verify` on {handle.name})"
        ) from exc
    if not isinstance(event_hash, str):
        raise JournalError("journal tail has a non-string event_hash; refusing to extend")
    return event_hash


def _count_event_lines(handle: io.BufferedRandom) -> int:
    """Number of non-blank lines in the journal (a forward scan).

    Checkpoints are rare relative to appends, so the full scan lives here
    rather than in a sidecar file that could disagree with the journal under
    concurrent writers. The append fast path (:func:`_read_last_event_hash`)
    stays O(tail) regardless of journal size.
    """
    handle.seek(0)
    count = 0
    for raw in handle:
        if raw.strip():
            count += 1
    return count


def find_completed_idempotent_decision(
    path: Path, action_name: str, idempotency_key: str
) -> dict[str, Any] | None:
    """Prior *allowed+succeeded* decision with the same action + idempotency key.

    Returns the prior decision event, or None. Corrupt lines are skipped (the
    chain is verified separately); only decision/outcome pairs that form a
    completed success count — anything else must not block a retry.
    """
    decisions: dict[str, dict[str, Any]] = {}
    succeeded: set[str] = set()
    try:
        with open(path, "rb") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get("event_type") == "decision":
                    event_id = event.get("event_id")
                    if isinstance(event_id, str):
                        decisions[event_id] = event
                elif event.get("event_type") == "outcome":
                    if event.get("status") == "succeeded":
                        ref = event.get("decision_event_id")
                        if isinstance(ref, str):
                            succeeded.add(ref)
    except OSError:
        return None
    for event_id, event in decisions.items():
        if (
            event.get("decision") == "allowed"
            and event.get("action_name") == action_name
            and event.get("idempotency_key") == idempotency_key
            and event_id in succeeded
        ):
            return event
    return None


def _blocking_prior_from_state(
    decisions: dict[str, dict[str, Any]],
    outcomes_by_decision: dict[str, list[dict[str, Any]]],
    action_name: str,
    idempotency_key: str,
) -> dict[str, Any] | None:
    """Prior decision blocking a new execution, or None.

    Blocking means an ``allowed`` decision with the same action+key whose
    outcome is missing (in-progress, possibly crashed) or ``succeeded``.
    ``failed`` outcomes, ``denied`` decisions, and ``dry_run`` decisions never
    block — retries after failure stay allowed. Returns the earliest blocking
    decision so ``duplicate_of`` points at the original reservation.
    """
    for event_id, event in decisions.items():
        if (
            event.get("decision") != "allowed"
            or event.get("action_name") != action_name
            or event.get("idempotency_key") != idempotency_key
            or event.get("dry_run") is True
        ):
            continue
        linked = outcomes_by_decision.get(event_id, [])
        if not linked:
            return event
        if any(outcome.get("status") == "succeeded" for outcome in linked):
            return event
        # Only failed outcomes linked: retry is safe.
    return None


def _scan_blocking_idempotent(
    handle: io.BufferedRandom, action_name: str, idempotency_key: str
) -> str | None:
    """Blocking prior decision ``event_id`` visible from *handle*, or None.

    Reads from the start of the already-locked handle; corrupt lines are
    skipped (chain integrity is verified separately).
    """
    decisions: dict[str, dict[str, Any]] = {}
    outcomes: dict[str, list[dict[str, Any]]] = {}
    handle.seek(0)
    for raw in handle:
        line = raw.strip()
        if not line:
            continue
        try:
            event = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(event, dict):
            continue
        if event.get("event_type") == "decision":
            event_id = event.get("event_id")
            if isinstance(event_id, str) and event_id not in decisions:
                decisions[event_id] = event
        elif event.get("event_type") == "outcome":
            ref = event.get("decision_event_id")
            if isinstance(ref, str):
                outcomes.setdefault(ref, []).append(event)
    prior = _blocking_prior_from_state(decisions, outcomes, action_name, idempotency_key)
    if prior is None:
        return None
    prior_id = prior.get("event_id")
    return prior_id if isinstance(prior_id, str) else None


def find_blocking_idempotent_decision(
    path: Path, action_name: str, idempotency_key: str
) -> dict[str, Any] | None:
    """Best-effort pre-check: prior allowed decision blocking a retry.

    Unlocked (for avoiding an approval prompt); the authoritative check is
    :meth:`FileJournal.append_event_atomic` under lock. Returns the prior
    decision event, or None.
    """
    decisions: dict[str, dict[str, Any]] = {}
    outcomes: dict[str, list[dict[str, Any]]] = {}
    try:
        with open(path, "rb") as handle:
            for raw in handle:
                line = raw.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(event, dict):
                    continue
                if event.get("event_type") == "decision":
                    event_id = event.get("event_id")
                    if isinstance(event_id, str) and event_id not in decisions:
                        decisions[event_id] = event
                elif event.get("event_type") == "outcome":
                    ref = event.get("decision_event_id")
                    if isinstance(ref, str):
                        outcomes.setdefault(ref, []).append(event)
    except OSError:
        return None
    return _blocking_prior_from_state(decisions, outcomes, action_name, idempotency_key)


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
            f"(run `interceptor verify` on {handle.name})"
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
