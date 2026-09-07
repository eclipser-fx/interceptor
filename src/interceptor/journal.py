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

import dataclasses
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

#: Best-effort pre-check cache: resolved path -> (mtime_ns, size, per-query
#: results). Entries are trusted only while the file stat is unchanged; the
#: journal is append-only, so an unchanged size means unchanged content and
#: any append invalidates the entry. This cache is a UX fast path only — the
#: authoritative idempotency check always runs under the file lock at append
#: time, so a stale entry can cost at most one redundant approval prompt.
_PRECHECK_CACHE: dict[str, tuple[int, int, dict[tuple[str, str, str], dict[str, Any] | None]]] = {}
_PRECHECK_CACHE_LOCK = threading.Lock()
_PRECHECK_CACHE_MAX_KEYS = 1024


def _precheck_token(path: Path) -> tuple[str, int, int] | None:
    """(resolved path, mtime_ns, size) for cache validation, or None."""
    try:
        stat = path.stat()
        return (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
    except OSError:
        return None


def _precheck_cached(
    token: tuple[str, int, int], kind: str, action_name: str, idempotency_key: str
) -> tuple[bool, dict[str, Any] | None]:
    """Cached prior decision for a pre-check query: (hit, prior-or-None).

    The token must come from a stat taken *before* the scan it would replace:
    the journal is append-only, so a matching token means unchanged content. A
    file that grew mid-scan simply misses the cache and rescans — never wrong.
    """
    key = (kind, action_name, idempotency_key)
    with _PRECHECK_CACHE_LOCK:
        entry = _PRECHECK_CACHE.get(token[0])
        if entry is None or (entry[0], entry[1]) != (token[1], token[2]):
            return (False, None)
        if key not in entry[2]:
            return (False, None)
        return (True, entry[2][key])


def _precheck_store(
    token: tuple[str, int, int],
    kind: str,
    action_name: str,
    idempotency_key: str,
    prior: dict[str, Any] | None,
) -> None:
    """Record a pre-check result, but only if the file has not grown since."""
    key = (kind, action_name, idempotency_key)
    with _PRECHECK_CACHE_LOCK:
        try:
            stat = Path(token[0]).stat()
            current = (stat.st_mtime_ns, stat.st_size)
        except OSError:
            return
        if current != (token[1], token[2]):
            return  # grew mid-scan; do not cache a mix of two states
        entry = _PRECHECK_CACHE.get(token[0])
        if entry is None or (entry[0], entry[1]) != (token[1], token[2]):
            entry = (token[1], token[2], {})
            _PRECHECK_CACHE[token[0]] = entry
        results = entry[2]
        if len(results) >= _PRECHECK_CACHE_MAX_KEYS:
            results.pop(next(iter(results)))
        results[key] = prior


def reset_precheck_cache() -> None:
    """Forget cached pre-check results. For tests only."""
    with _PRECHECK_CACHE_LOCK:
        _PRECHECK_CACHE.clear()


#: Whether the in-process idempotency index may be used. It is exact only
#: where appends are serialized by an OS file lock (``fcntl`` on POSIX,
#: ``msvcrt`` on Windows — the same platforms the journal locks on). Anywhere
#: else the authoritative check keeps its full scan, exactly as before.
_USE_IDEM_INDEX = os.name in ("posix", "nt")

_IDEM_INDEX_MAX_PATHS = 128


@dataclasses.dataclass
class _IdemTables:
    """The idempotency-relevant slice of a journal prefix, in file order.

    Only ``allowed``, non-``dry_run`` decisions carrying an idempotency key
    are stored (denied, dry-run, and keyless decisions can never block, so
    omitting them changes nothing the blocking query can return), plus the
    outcomes and resolutions linked to those decisions. ``by_key`` lists each
    key's decisions in file order across incremental updates and rebuilds,
    so earliest-wins rules replay exactly as a full scan would.
    """

    decisions: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    by_key: dict[tuple[str, str], list[str]] = dataclasses.field(default_factory=dict)
    outcomes: dict[str, list[dict[str, Any]]] = dataclasses.field(default_factory=dict)
    resolutions: dict[str, list[dict[str, Any]]] = dataclasses.field(default_factory=dict)


#: Resolved journal path -> (journal size in bytes, tail event hash, tables).
#: An entry is trusted only while both the size and the hash-chained head
#: match: the head covers the entire prefix, so a match proves the cached
#: tables describe exactly this journal content (a mismatch falls back to a
#: full scan and rebuild). Foreign writers, rotation, restores, and sibling
#: implementations can only cause a fallback, never a wrong answer.
_IDEM_TABLES_CACHE: dict[str, tuple[int, str | None, _IdemTables]] = {}
_IDEM_TABLES_GUARD = threading.Lock()


def _idem_cache_key(path: Path) -> str:
    """Stable cache key for *path*, mirroring the process-lock key."""
    try:
        return str(Path(path).resolve())
    except Exception:
        return str(Path.cwd() / path) if not path.is_absolute() else str(path)


def reset_idem_index() -> None:
    """Forget cached idempotency tables. For tests only."""
    with _IDEM_TABLES_GUARD:
        _IDEM_TABLES_CACHE.clear()


def _evolve_idem_tables(tables: _IdemTables, event: Any) -> None:
    """Fold one appended *event* into *tables* (same rules as a rescan).

    Events that cannot affect a blocking query — non-decision/outcome/
    resolution types, denied or dry-run decisions, keyless decisions, and
    outcomes/resolutions for untracked decisions — leave the tables
    untouched. Malformed shapes are ignored rather than stored: the next
    read still validates against the journal itself.
    """
    if not isinstance(event, dict):
        return
    event_type = event.get("event_type")
    if event_type == "decision":
        if event.get("decision") != "allowed" or event.get("dry_run") is True:
            return
        if "idempotency_key" not in event or not isinstance(event.get("action_name"), str):
            return
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or event_id in tables.decisions:
            return
        tables.decisions[event_id] = event
        key = event.get("idempotency_key")
        action = event.get("action_name")
        if isinstance(key, str) and isinstance(action, str):
            # Secondary index so queries touch only same-key decisions, not
            # every tracked key. Non-string keys can never match a query
            # (the engine only issues non-empty strings) and stay out.
            tables.by_key.setdefault((action, key), []).append(event_id)
    elif event_type == "outcome":
        ref = event.get("decision_event_id")
        status = event.get("status")
        if isinstance(ref, str) and isinstance(status, str) and ref in tables.decisions:
            tables.outcomes.setdefault(ref, []).append({"status": status})
    elif event_type == "resolution":
        ref = event.get("decision_event_id")
        resolution = event.get("resolution")
        if isinstance(ref, str) and isinstance(resolution, str) and ref in tables.decisions:
            tables.resolutions.setdefault(ref, []).append({"resolution": resolution})


def _collect_idem_tables(handle: io.BufferedRandom) -> _IdemTables:
    """Rebuild tables from a full scan of the already-locked *handle*.

    Skips corrupt lines exactly like the idempotency scans do (chain
    integrity is verified separately), and applies the same first-wins and
    ordering rules as :func:`_evolve_idem_tables` so incremental updates and
    rebuilds always agree.
    """
    tables = _IdemTables()
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
        _evolve_idem_tables(tables, event)
    return tables


def _cache_idem_tables(key: str, size: int, head: str | None, tables: _IdemTables) -> None:
    """Publish *tables* for *key*; evicts the oldest path past the cap."""
    with _IDEM_TABLES_GUARD:
        _IDEM_TABLES_CACHE[key] = (size, head, tables)
        while len(_IDEM_TABLES_CACHE) > _IDEM_INDEX_MAX_PATHS:
            _IDEM_TABLES_CACHE.pop(next(iter(_IDEM_TABLES_CACHE)))


def _cached_idem_tables(key: str, size: int, head: str | None) -> _IdemTables | None:
    """Tables for *key* iff they describe exactly ``(size, head)``."""
    with _IDEM_TABLES_GUARD:
        entry = _IDEM_TABLES_CACHE.get(key)
    if entry is None or (entry[0], entry[1]) != (size, head):
        return None
    return entry[2]


def _drop_idem_tables(key: str) -> None:
    with _IDEM_TABLES_GUARD:
        _IDEM_TABLES_CACHE.pop(key, None)


def _locked_handle_state(handle: io.BufferedRandom) -> tuple[int, str | None]:
    """(size in bytes, tail event hash) of the locked *handle*.

    Leaves the file position unspecified; every caller seeks explicitly.
    """
    handle.seek(0, io.SEEK_END)
    size = handle.tell()
    if size == 0:
        return 0, GENESIS_PREVIOUS_HASH
    return size, _read_last_event_hash(handle)


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
                        encoded = line.encode("utf-8") + b"\n"
                        handle.seek(0, io.SEEK_END)
                        size_before = handle.tell()
                        handle.write(encoded)
                        handle.flush()
                        os.fsync(handle.fileno())
                        _note_idem_append(
                            self._path,
                            event,
                            size_before,
                            previous_hash,
                            size_before + len(encoded),
                            event.get("event_hash")
                            if isinstance(event.get("event_hash"), str)
                            else None,
                        )
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
                        encoded = line.encode("utf-8") + b"\n"
                        handle.seek(0, io.SEEK_END)
                        size_before = handle.tell()
                        handle.write(encoded)
                        handle.flush()
                        os.fsync(handle.fileno())
                        _note_idem_append(
                            self._path,
                            event,
                            size_before,
                            previous_hash,
                            size_before + len(encoded),
                            event.get("event_hash")
                            if isinstance(event.get("event_hash"), str)
                            else None,
                        )
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
                            blocking = _locked_blocking_prior_id(
                                _idem_cache_key(self._path),
                                handle,
                                action_name,
                                idempotency_key,
                            )
                        previous_hash = _read_last_event_hash(handle)
                        event = build(previous_hash, blocking)
                        line = json.dumps(
                            event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                        )
                        encoded = line.encode("utf-8") + b"\n"
                        handle.seek(0, io.SEEK_END)
                        size_before = handle.tell()
                        handle.write(encoded)
                        handle.flush()
                        os.fsync(handle.fileno())
                        _note_idem_append(
                            self._path,
                            event,
                            size_before,
                            previous_hash,
                            size_before + len(encoded),
                            event.get("event_hash")
                            if isinstance(event.get("event_hash"), str)
                            else None,
                        )
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


def _read_last_event_hash(handle: io.BufferedRandom | io.BufferedReader) -> str | None:
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


def _event_hash_from_line(line: bytes, handle: io.BufferedRandom | io.BufferedReader) -> str:
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
    completed success count — anything else must not block a retry. Results
    are cached against the file stat (see :func:`_precheck_cached`).

    An exact in-process index answers first when it describes the file;
    otherwise the scan below runs, unchanged.
    """
    indexed = _tables_for_unlocked_path(path)
    if indexed is not None:
        _, tables = indexed
        return _indexed_completed_prior(tables, action_name, idempotency_key)
    token = _precheck_token(path)
    if token is not None:
        hit, cached = _precheck_cached(token, "completed", action_name, idempotency_key)
        if hit:
            return cached
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
    prior: dict[str, Any] | None = None
    for event_id, event in decisions.items():
        if (
            event.get("decision") == "allowed"
            and event.get("action_name") == action_name
            and event.get("idempotency_key") == idempotency_key
            and event_id in succeeded
        ):
            prior = event
            break
    if token is not None:
        _precheck_store(token, "completed", action_name, idempotency_key, prior)
    return prior


def _blocking_prior_from_state(
    decisions: dict[str, dict[str, Any]],
    outcomes_by_decision: dict[str, list[dict[str, Any]]],
    action_name: str,
    idempotency_key: str,
    resolutions_by_decision: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any] | None:
    """Prior decision blocking a new execution, or None.

    Blocking means an ``allowed`` decision with the same action+key whose
    outcome is missing (in-progress, possibly crashed) or ``succeeded``.
    ``failed`` outcomes, ``denied`` decisions, and ``dry_run`` decisions never
    block — retries after failure stay allowed. An operator resolution of
    ``confirmed_not_completed`` also releases the key (the side effect was
    checked and found absent), unless a ``succeeded`` outcome contradicts it —
    that conflict stays blocking and is flagged by ``audit``. Returns the
    earliest blocking decision so ``duplicate_of`` points at the original
    reservation.
    """
    resolved_clear: dict[str, bool] = {}
    for decision_id, linked in (resolutions_by_decision or {}).items():
        if linked:
            resolved_clear[decision_id] = (
                str(linked[-1].get("resolution")) == "confirmed_not_completed"
            )
    for event_id, event in decisions.items():
        if (
            event.get("decision") != "allowed"
            or event.get("action_name") != action_name
            or event.get("idempotency_key") != idempotency_key
            or event.get("dry_run") is True
        ):
            continue
        linked = outcomes_by_decision.get(event_id, [])
        if any(outcome.get("status") == "succeeded" for outcome in linked):
            return event
        if not linked and resolved_clear.get(event_id, False):
            continue
        if not linked:
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
    resolutions: dict[str, list[dict[str, Any]]] = {}
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
        elif event.get("event_type") == "resolution":
            ref = event.get("decision_event_id")
            if isinstance(ref, str):
                resolutions.setdefault(ref, []).append(event)
    prior = _blocking_prior_from_state(
        decisions, outcomes, action_name, idempotency_key, resolutions
    )
    if prior is None:
        return None
    prior_id = prior.get("event_id")
    return prior_id if isinstance(prior_id, str) else None


def _tables_for_unlocked_path(path: Path) -> tuple[str, _IdemTables] | None:
    """Cached tables for *path* iff the file still matches them exactly.

    Opens its own handle without the journal lock (pre-check callers are
    unlocked by contract): a torn concurrent write surfaces as a parse error
    and falls back to a scan. A head match proves prefix equality because the
    head hash-chains the entire content, so a hit is exact, never heuristic.
    """
    if not _USE_IDEM_INDEX:
        return None
    key = _idem_cache_key(path)
    try:
        with open(path, "rb") as handle:
            handle.seek(0, io.SEEK_END)
            size = handle.tell()
            head = GENESIS_PREVIOUS_HASH if size == 0 else _read_last_event_hash(handle)
    except (OSError, JournalError):
        return None
    tables = _cached_idem_tables(key, size, head)
    return (key, tables) if tables is not None else None


def _indexed_completed_prior(
    tables: _IdemTables, action_name: str, idempotency_key: str
) -> dict[str, Any] | None:
    """First allowed+succeeded decision for *(action, key)* in file order."""
    for event_id in tables.by_key.get((action_name, idempotency_key), ()):
        event = tables.decisions[event_id]
        linked = tables.outcomes.get(event_id, [])
        if event.get("decision") == "allowed" and any(
            outcome.get("status") == "succeeded" for outcome in linked
        ):
            return event
    return None


def _indexed_blocking_prior(
    tables: _IdemTables, action_name: str, idempotency_key: str
) -> dict[str, Any] | None:
    """Blocking prior decision for *(action, key)* via the shared predicate.

    Only same-key decisions are replayed; the predicate skips nothing it
    would otherwise return, so the answer matches a full scan exactly.
    """
    candidates = {
        event_id: tables.decisions[event_id]
        for event_id in tables.by_key.get((action_name, idempotency_key), ())
    }
    return _blocking_prior_from_state(
        candidates, tables.outcomes, action_name, idempotency_key, tables.resolutions
    )


def _locked_blocking_prior_id(
    path_key: str, handle: io.BufferedRandom, action_name: str, idempotency_key: str
) -> str | None:
    """Authoritative blocking check with an index fast path (call under lock).

    On an index hit no scan runs; on any miss, staleness, or error the full
    scan runs and rebuilds the tables, so behavior (including failure modes
    on corrupt tails) is identical to scanning every time.
    """
    if _USE_IDEM_INDEX:
        try:
            size, head = _locked_handle_state(handle)
            tables = _cached_idem_tables(path_key, size, head)
            if tables is None:
                tables = _collect_idem_tables(handle)
                _cache_idem_tables(path_key, size, head, tables)
            prior = _indexed_blocking_prior(tables, action_name, idempotency_key)
            prior_id = prior.get("event_id") if prior is not None else None
            return prior_id if isinstance(prior_id, str) else None
        except (OSError, JournalError):
            pass
    return _scan_blocking_idempotent(handle, action_name, idempotency_key)


def _note_idem_append(
    path: Path,
    event: dict[str, Any],
    pre_size: int,
    pre_head: str | None,
    post_size: int,
    post_head: str | None,
) -> None:
    """Fold a just-appended event into the cached tables, when possible.

    Evolves the entry only if it described exactly the pre-append prefix;
    otherwise drops it (a foreign write interleaved — the next idempotent
    check rebuilds under lock). Never builds tables: that keeps a scan off
    the keyless fast path. Never raises: index trouble must not break the
    write path, so any failure drops the entry and the next check rescans.
    """
    if not _USE_IDEM_INDEX:
        return
    if not isinstance(post_head, str):
        try:
            _drop_idem_tables(_idem_cache_key(path))
        except Exception:  # noqa: S110 - index trouble must never break the write path
            pass
        return
    try:
        key = _idem_cache_key(path)
        with _IDEM_TABLES_GUARD:
            entry = _IDEM_TABLES_CACHE.get(key)
            if entry is None:
                return
            if (entry[0], entry[1]) != (pre_size, pre_head):
                _IDEM_TABLES_CACHE.pop(key, None)
                return
            tables = entry[2]
            _evolve_idem_tables(tables, event)
            _IDEM_TABLES_CACHE[key] = (post_size, post_head, tables)
            while len(_IDEM_TABLES_CACHE) > _IDEM_INDEX_MAX_PATHS:
                _IDEM_TABLES_CACHE.pop(next(iter(_IDEM_TABLES_CACHE)))
    except Exception:
        try:
            _drop_idem_tables(_idem_cache_key(path))
        except Exception:  # noqa: S110 - dropping the entry is best-effort too
            pass


def find_blocking_idempotent_decision(
    path: Path, action_name: str, idempotency_key: str
) -> dict[str, Any] | None:
    """Best-effort pre-check: prior allowed decision blocking a retry.

    Unlocked (for avoiding an approval prompt); the authoritative check is
    :meth:`FileJournal.append_event_atomic` under lock. Returns the prior
    decision event, or None. Results are cached against the file stat (see
    :func:`_precheck_cached`).

    An exact in-process index answers first when it describes the file;
    otherwise the scan below runs, unchanged.
    """
    indexed = _tables_for_unlocked_path(path)
    if indexed is not None:
        _, tables = indexed
        return _indexed_blocking_prior(tables, action_name, idempotency_key)
    token = _precheck_token(path)
    if token is not None:
        hit, cached = _precheck_cached(token, "blocking", action_name, idempotency_key)
        if hit:
            return cached
    decisions: dict[str, dict[str, Any]] = {}
    outcomes: dict[str, list[dict[str, Any]]] = {}
    resolutions: dict[str, list[dict[str, Any]]] = {}
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
                elif event.get("event_type") == "resolution":
                    ref = event.get("decision_event_id")
                    if isinstance(ref, str):
                        resolutions.setdefault(ref, []).append(event)
    except OSError:
        return None
    prior = _blocking_prior_from_state(
        decisions, outcomes, action_name, idempotency_key, resolutions
    )
    if token is not None:
        _precheck_store(token, "blocking", action_name, idempotency_key, prior)
    return prior


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
