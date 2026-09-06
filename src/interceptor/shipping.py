"""Event shipping: mirror every appended event to witness sinks.

The journal is a local file; tail truncation plus key theft rewrites it.
Shipping each event elsewhere as it is written — a second disk, a WORM store,
an append-only remote — turns that into a two-machine attack. This module is
the explicit seam for it.

:class:`FanoutJournalStore` wraps a primary :class:`FileJournal` and a list of
sinks. The primary append (including the atomic idempotency variant) happens
first; each sink then receives a copy of the appended event dict. The default
failure policy is fail-closed (``on_ship_failure="raise"``): a witness that
quietly stops receiving is worse than a call that loudly fails. Pass
``"ignore"`` only for best-effort mirrors.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from .errors import EventShipError, JournalError
from .journal import FileJournal

#: What to do when a sink fails after the primary append succeeded.
ShipFailurePolicy = str  # "raise" | "ignore"


class EventSink(Protocol):
    """Receives a copy of every appended event."""

    def send(self, event: Mapping[str, Any]) -> None: ...


class CallableSink:
    """Adapt a plain callable to :class:`EventSink`."""

    def __init__(self, send: Callable[[Mapping[str, Any]], None]) -> None:
        self._send = send

    def send(self, event: Mapping[str, Any]) -> None:
        self._send(event)


class FileMirrorSink:
    """Append-only JSONL mirror of shipped events (no chain of its own).

    The mirror is a witness copy: each line is the event as appended to the
    primary. It is written atomically (append + fsync) and never read back by
    this library — compare it against the primary with ``diff`` or ship it
    where the primary cannot reach.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def send(self, event: Mapping[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(
                dict(event), sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            with open(self._path, "ab") as handle:
                handle.write(line.encode("utf-8") + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise JournalError(f"cannot mirror event to {self._path}: {exc}") from exc


def _authorizing_decision(event: dict[str, Any]) -> str | None:
    """The decision id this event answers to, for failure attribution.

    Decisions carry their own id; outcomes and resolutions reference theirs.
    Anything else yields None rather than a guess.
    """
    if event.get("event_type") == "decision":
        event_id = event.get("event_id")
        return event_id if isinstance(event_id, str) else None
    ref = event.get("decision_event_id")
    return ref if isinstance(ref, str) else None


class FanoutJournalStore:
    """A :class:`JournalStore` that ships every event to sinks after writing.

    Exposes the primary's ``path`` and ``append_event_atomic`` so the engine's
    idempotency reservation keeps working through the wrapper.
    """

    def __init__(
        self,
        primary: FileJournal,
        sinks: list[Any] | None = None,
        *,
        on_ship_failure: ShipFailurePolicy = "raise",
    ) -> None:
        if on_ship_failure not in ("raise", "ignore"):
            raise ValueError('on_ship_failure must be "raise" or "ignore"')
        self._primary = primary
        normalized: list[EventSink] = []
        for sink in sinks or []:
            if hasattr(sink, "send"):
                normalized.append(sink)
            else:
                normalized.append(CallableSink(sink))
        self._sinks = normalized
        self._on_ship_failure = on_ship_failure

    @property
    def path(self) -> Path:
        return self._primary.path

    @property
    def primary(self) -> FileJournal:
        return self._primary

    @property
    def sinks(self) -> tuple[EventSink, ...]:
        return tuple(self._sinks)

    def _ship(self, event: dict[str, Any]) -> None:
        for sink in self._sinks:
            try:
                sink.send(dict(event))
            except EventShipError:
                raise
            except Exception as exc:
                if self._on_ship_failure == "raise":
                    raise EventShipError(
                        f"event {event.get('event_id')} persisted locally but a "
                        f"witness sink failed ({exc}); failing closed",
                        decision_event_id=_authorizing_decision(event),
                    ) from exc

    def append_event(self, build: Callable[[str | None], dict[str, Any]]) -> dict[str, Any]:
        event = self._primary.append_event(build)
        self._ship(event)
        return event

    def append_event_atomic(
        self,
        build: Callable[[str | None, str | None], dict[str, Any]],
        *,
        action_name: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        event = self._primary.append_event_atomic(
            build, action_name=action_name, idempotency_key=idempotency_key
        )
        self._ship(event)
        return event
