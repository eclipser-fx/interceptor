"""The pre-execution hook: the one seam where this library can reach outward.

The guard makes no network calls. It has no configuration that would cause it
to make one, and there is no default that changes that — which is enforced by
a test that makes socket creation raise and then runs the complete flow.

Some deployments do need a central record of which actions exist: a registry
of declared contracts, a policy service that must see a contract before it
runs, a compliance system that wants the declaration ahead of the execution.
:class:`ActionObserver` is the single, explicit place to put that, and it is
inert unless a caller passes one.

Semantics, chosen so that an observer cannot weaken the guarantees:

* Called **once per contract version per process**, before approval and
  before execution. Not once per call — the contract is what it reports, and
  the contract does not change between calls.
* Never receives arguments, results, events, journals, or key material. Only
  the :class:`~interceptor.contracts.ActionContract`, which is derived
  from the function's declaration and contains no runtime data.
* A failure **prevents execution**. If the observer raises, the guarded
  function does not run and nothing is recorded. There is no silent fallback:
  an observer that was asked for and could not be reached is an error, not a
  warning, because the alternative is a system that quietly stops recording
  the thing it was installed to record.
* Observing grants nothing. It is a notification, not an authorization; local
  approval and local signed evidence are unchanged by its presence.
"""

from __future__ import annotations

import threading
import weakref
from typing import Any, Protocol

from .contracts import ActionContract


class ActionObserver(Protocol):
    """Notified once per contract version, before the first guarded execution."""

    def contract_declared(self, contract: ActionContract) -> None:
        """Report a contract. Raising prevents execution of the guarded call."""
        ...


class _OnceTracker:
    """Remembers which contracts an observer has successfully been told about.

    Keyed by observer *identity* and contract hash, so a changed contract is
    reported again and two observers each get their own notification. Observers
    are held weakly: a garbage-collected observer never suppresses a
    notification for a later object that happens to reuse its ``id()`` — the
    failure mode of an ``id()``-keyed set. Objects that do not support weak
    references fall back to an id-keyed entry holding a strong reference.

    Only *successful* notifications are recorded. Marking before the call
    would mean a failing observer blocks the first execution and is then
    skipped for every execution after it — the guard would fail open on retry,
    which is precisely backwards for a component installed to guarantee a
    record exists.
    """

    def __init__(self) -> None:
        self._done_weak: weakref.WeakKeyDictionary[Any, set[str]] = weakref.WeakKeyDictionary()
        self._done_strong: dict[int, tuple[Any, set[str]]] = {}
        self._lock = threading.Lock()

    def _bucket(self, observer: object) -> set[str]:
        try:
            bucket = self._done_weak.get(observer)
        except TypeError:
            entry = self._done_strong.get(id(observer))
            if entry is None or entry[0] is not observer:
                entry = (observer, set())
                self._done_strong[id(observer)] = entry
            return entry[1]
        if bucket is None:
            bucket = set()
            self._done_weak[observer] = bucket
        return bucket

    def is_done(self, observer: object, contract: ActionContract) -> bool:
        with self._lock:
            return contract.contract_hash in self._bucket(observer)

    def mark_done(self, observer: object, contract: ActionContract) -> None:
        with self._lock:
            self._bucket(observer).add(contract.contract_hash)

    def reset(self) -> None:
        with self._lock:
            self._done_weak.clear()
            self._done_strong.clear()


_TRACKER = _OnceTracker()


def notify_once(observer: ActionObserver | None, contract: ActionContract) -> None:
    """Report *contract* to *observer* the first time it is successfully seen.

    Any exception propagates unchanged, which is what prevents execution.

    Delivery is at-least-once rather than exactly-once: two threads racing on
    the very first call for a contract may both notify. Duplicate declarations
    of an identical contract are harmless, whereas a missed one is not, so the
    race is resolved in the safe direction.
    """
    if observer is None:
        return
    if _TRACKER.is_done(observer, contract):
        return
    observer.contract_declared(contract)
    _TRACKER.mark_done(observer, contract)


def reset_notifications() -> None:
    """Forget every notification. For tests only."""
    _TRACKER.reset()
