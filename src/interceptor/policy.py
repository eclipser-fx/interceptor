"""Policy approval providers: budgets, rate limits, predicates, caching, timeouts.

All providers implement the :class:`ApprovalProvider` protocol (``decide``),
are thread-safe, perform no network I/O, and fail closed (deny) when their
own limits are exceeded or misconfigured. They compose: wrap any provider in
:class:`TimeoutApprovalProvider` or :class:`CachedApprovalProvider`, combine
several with :class:`AllOf` / :class:`AnyOf`.
"""

from __future__ import annotations

import fnmatch
import json
import os
import threading
import time
from collections import deque
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .approval import (
    DECISION_ALLOWED,
    DECISION_DENIED,
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRequest,
)
from .contracts import RISK_LEVELS
from .errors import PolicyError

Predicate = Callable[[ApprovalRequest], bool]


class PredicateProvider:
    """Allow exactly the requests matching *predicate*.

    Use for field rules, e.g. ``risk in {"low", "medium"}`` or
    ``"refund" not in action_name``. Anything not matching is denied with
    *deny_reason*.
    """

    def __init__(self, predicate: Predicate, *, deny_reason: str = "rejected by policy") -> None:
        self._predicate = predicate
        self._deny_reason = deny_reason

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        try:
            matched = bool(self._predicate(request))
        except Exception:
            return ApprovalDecision(DECISION_DENIED, "policy predicate errored; failing closed")
        if matched:
            return ApprovalDecision(DECISION_ALLOWED, "allowed by policy predicate")
        return ApprovalDecision(DECISION_DENIED, self._deny_reason)


class AllowListProvider(PredicateProvider):
    """Allow only actions in *actions* (optionally restricted by risk)."""

    def __init__(
        self,
        actions: Collection[str],
        *,
        risks: Collection[str] | None = None,
    ) -> None:
        action_set = frozenset(actions)
        risk_set = frozenset(risks) if risks is not None else None

        def _matches(request: ApprovalRequest) -> bool:
            if request.action_name not in action_set:
                return False
            return risk_set is None or request.risk in risk_set

        super().__init__(_matches, deny_reason="action not in allow-list")


class BudgetProvider:
    """Allow at most *max_calls* invocations (optionally per action).

    Each allowance consumes one unit; denials at an exhausted budget consume
    nothing further (there is nothing left to protect). Thread-safe.
    When *per_action* is true each action name gets its own budget.
    """

    def __init__(self, max_calls: int, *, per_action: bool = False) -> None:
        if max_calls < 0:
            raise ValueError("max_calls must be non-negative")
        self._max_calls = max_calls
        self._per_action = per_action
        self._lock = threading.Lock()
        self._total = 0
        self._per_action_counts: dict[str, int] = {}

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        with self._lock:
            if self._per_action:
                used = self._per_action_counts.get(request.action_name, 0)
                if used >= self._max_calls:
                    return ApprovalDecision(
                        DECISION_DENIED,
                        f"budget exhausted for {request.action_name!r} ({used}/{self._max_calls})",
                    )
                self._per_action_counts[request.action_name] = used + 1
                return ApprovalDecision(
                    DECISION_ALLOWED, f"within budget ({used + 1}/{self._max_calls})"
                )
            if self._total >= self._max_calls:
                return ApprovalDecision(
                    DECISION_DENIED,
                    f"budget exhausted ({self._total}/{self._max_calls})",
                )
            self._total += 1
            return ApprovalDecision(
                DECISION_ALLOWED, f"within budget ({self._total}/{self._max_calls})"
            )

    @property
    def remaining(self) -> int:
        """Remaining global budget (meaningful only when not per-action)."""
        with self._lock:
            return max(0, self._max_calls - self._total)


class RateLimitProvider:
    """Sliding-window rate limit: at most *max_calls* per *window_seconds*.

    Only allowances enter the window; denials consume no quota, so a denied
    burst does not extend the throttle. Thread-safe; the clock is injectable
    for tests.
    """

    def __init__(
        self,
        max_calls: int,
        window_seconds: float,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if max_calls <= 0:
            raise ValueError("max_calls must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max_calls = max_calls
        self._window = window_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._attempts: deque[float] = deque()

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        now = self._clock()
        with self._lock:
            cutoff = now - self._window
            while self._attempts and self._attempts[0] <= cutoff:
                self._attempts.popleft()
            if len(self._attempts) >= self._max_calls:
                return ApprovalDecision(
                    DECISION_DENIED,
                    f"rate limit exceeded ({self._max_calls} per {self._window:g}s)",
                )
            self._attempts.append(now)
            return ApprovalDecision(DECISION_ALLOWED, "within rate limit")


class CachedApprovalProvider:
    """Cache ``allowed`` decisions for *ttl_seconds*.

    The key covers contract, redacted input, risk, approval mode, and declared
    spend, so a cached allow never crosses a risk or budget boundary. Repeated
    identical calls within the TTL auto-allow without re-prompting; every
    invocation still writes its own decision/outcome evidence. Denials are
    never cached. Thread-safe.

    Composition order matters: put stateful limits *outside* the cache —
    ``Budget(Cached(inner))`` — so the budget sees every call. Reversing them
    lets the TTL re-allow calls the inner budget would now deny.
    """

    def __init__(
        self,
        inner: ApprovalProvider,
        ttl_seconds: float,
        *,
        clock: Callable[[], float] | None = None,
        max_entries: int = 1024,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._inner = inner
        self._ttl = ttl_seconds
        self._clock = clock or time.monotonic
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._cache: dict[tuple[str, str, str, str, int | None], float] = {}

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        key = (
            request.contract_hash,
            request.input_hash,
            request.risk,
            request.approval_mode,
            request.spend_cents,
        )
        now = self._clock()
        with self._lock:
            expires = self._cache.get(key)
            if expires is not None and expires > now:
                return ApprovalDecision(DECISION_ALLOWED, "allowed by cached approval")
            if expires is not None:
                del self._cache[key]
            # Opportunistic sweep so expired entries cannot accumulate.
            if len(self._cache) >= self._max_entries:
                expired = [k for k, exp in self._cache.items() if exp <= now]
                for k in expired:
                    del self._cache[k]
            while len(self._cache) >= self._max_entries:
                # Dicts preserve insertion order: evict the oldest entry.
                self._cache.pop(next(iter(self._cache)))
        decision = self._inner.decide(request)
        if decision.allowed:
            with self._lock:
                self._cache[key] = self._clock() + self._ttl
                if len(self._cache) > self._max_entries:
                    expired_now = self._clock()
                    for k in [k for k, exp in self._cache.items() if exp <= expired_now]:
                        del self._cache[k]
                    while len(self._cache) > self._max_entries:
                        self._cache.pop(next(iter(self._cache)))
        return decision


class TimeoutApprovalProvider:
    """Deny when the wrapped provider takes longer than *timeout_seconds*.

    Runs the inner ``decide`` on a daemon thread; on expiry returns a denial
    (fail closed). The inner call may still complete later with no effect.
    Denial reasons name the wrapped provider type, and at most
    *max_in_flight* decisions wait at once — past that, calls deny as
    overloaded rather than piling up threads without bound.
    """

    def __init__(
        self, inner: ApprovalProvider, timeout_seconds: float, *, max_in_flight: int = 32
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_in_flight <= 0:
            raise ValueError("max_in_flight must be positive")
        self._inner = inner
        self._timeout = timeout_seconds
        self._in_flight_guard = threading.Semaphore(max_in_flight)

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        inner_name = type(self._inner).__name__
        if not self._in_flight_guard.acquire(blocking=False):
            return ApprovalDecision(
                DECISION_DENIED,
                f"approval overloaded waiting on {inner_name}; failing closed (too many pending)",
            )
        result: dict[str, Any] = {}
        done = threading.Event()

        def _run() -> None:
            try:
                result["decision"] = self._inner.decide(request)
            except Exception as exc:  # fail closed on provider error
                result["decision"] = ApprovalDecision(
                    DECISION_DENIED, f"approval provider errored under timeout: {exc!r}"
                )
            finally:
                done.set()
                self._in_flight_guard.release()

        worker = threading.Thread(
            target=_run, daemon=True, name=f"interceptor-approval-{inner_name}"
        )
        worker.start()
        if not done.wait(self._timeout):
            return ApprovalDecision(
                DECISION_DENIED,
                f"approval timed out after {self._timeout:g}s waiting on {inner_name}; "
                "failing closed (the inner call may still complete with no effect)",
            )
        decision = result.get("decision")
        if not isinstance(decision, ApprovalDecision):
            return ApprovalDecision(DECISION_DENIED, "approval provider gave no decision")
        return decision


@dataclass
class CombinedProvider:
    """Combine providers with ``mode="all"`` (everyone must allow) or ``"any"``.

    ``all`` denies on the first denial; ``any`` allows on the first allowance.
    Reasons are joined so the evidence states which policy decided.
    """

    providers: list[ApprovalProvider] = field(default_factory=list)
    mode: str = "all"

    def __post_init__(self) -> None:
        if self.mode not in ("all", "any"):
            raise ValueError("mode must be 'all' or 'any'")
        if not self.providers:
            raise ValueError("at least one provider is required")

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        reasons: list[str] = []
        if self.mode == "all":
            for provider in self.providers:
                decision = provider.decide(request)
                reasons.append(decision.reason)
                if not decision.allowed:
                    return ApprovalDecision(
                        DECISION_DENIED, f"denied by policy [{'; '.join(reasons)}]"
                    )
            return ApprovalDecision(DECISION_ALLOWED, f"allowed by all [{'; '.join(reasons)}]")
        for provider in self.providers:
            decision = provider.decide(request)
            reasons.append(decision.reason)
            if decision.allowed:
                return ApprovalDecision(
                    DECISION_ALLOWED, f"allowed by policy [{'; '.join(reasons)}]"
                )
        return ApprovalDecision(DECISION_DENIED, f"denied by all [{'; '.join(reasons)}]")


AllOf = CombinedProvider


def AnyOf(providers: list[ApprovalProvider]) -> CombinedProvider:
    """Allow when any wrapped provider allows."""
    return CombinedProvider(providers=providers, mode="any")


class QuorumApprovalProvider:
    """Allow when at least *quorum* of the wrapped providers allow.

    Every provider is always consulted (no short-circuit), so each one records
    its own audit trail; denials name how many approvals were missing.
    Provider exceptions count as denials (named as ``errored (...)`` in the
    reason) rather than raising ``ApprovalError`` the way ``AllOf``/``AnyOf``
    do — monitor denial reasons, not just exception types, for failing
    providers behind a quorum. Thread-safe where the wrapped providers are.
    """

    def __init__(self, providers: list[ApprovalProvider], quorum: int) -> None:
        if not providers:
            raise ValueError("at least one provider is required")
        if not 1 <= quorum <= len(providers):
            raise ValueError(f"quorum must be between 1 and {len(providers)}, got {quorum}")
        self._providers = list(providers)
        self._quorum = quorum

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        allowed = 0
        reasons: list[str] = []
        for provider in self._providers:
            try:
                decision = provider.decide(request)
            except Exception as exc:
                reasons.append(f"errored ({exc!r})")
                continue
            reasons.append(decision.reason)
            if decision.allowed:
                allowed += 1
        if allowed >= self._quorum:
            return ApprovalDecision(
                DECISION_ALLOWED,
                f"quorum reached ({allowed}/{self._quorum} of {len(self._providers)})",
            )
        return ApprovalDecision(
            DECISION_DENIED,
            f"quorum missed ({allowed}/{self._quorum} of {len(self._providers)}): "
            + "; ".join(reasons),
        )


@dataclass(frozen=True)
class Rule:
    """One declarative policy rule: first match wins.

    *action* is a glob (``billing.*``) matched against the action name;
    *risks* restricts the rule to a risk subset (None means any risk).
    """

    action: str
    decision: str
    risks: frozenset[str] | None = None
    reason: str = ""

    def matches(self, request: ApprovalRequest) -> bool:
        if not fnmatch.fnmatchcase(request.action_name, self.action):
            return False
        return self.risks is None or request.risk in self.risks


@dataclass(frozen=True)
class RuleExplanation:
    """What a :class:`RuleProvider` would decide, and which rule says so."""

    decision: str
    reason: str
    matched_index: int | None
    matched_action: str | None
    total_rules: int

    @property
    def allowed(self) -> bool:
        return self.decision == DECISION_ALLOWED


class RuleProvider:
    """Decide from an ordered, serializable rule list.

    The first matching rule decides; when nothing matches, *default* (deny
    unless set to ``"allowed"``) applies. Rules are plain data, so policy can
    live in a reviewed config file via :func:`load_policy_file` instead of code.
    """

    def __init__(
        self, rules: list[Rule] | tuple[Rule, ...], *, default: str = DECISION_DENIED
    ) -> None:
        if default not in (DECISION_ALLOWED, DECISION_DENIED):
            raise PolicyError(f"invalid default {default!r}: expected allowed/denied")
        for rule in rules:
            if rule.decision not in (DECISION_ALLOWED, DECISION_DENIED):
                raise PolicyError(f"invalid decision {rule.decision!r} in rule for {rule.action!r}")
        self._rules = tuple(rules)
        self._default = default

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    def explain(self, request: ApprovalRequest) -> RuleExplanation:
        """Decide *request* and say which rule decided it.

        Returns the decision plus the zero-based index and glob of the first
        matching rule, or ``None``/``None`` when the default applied. This is
        what ``interceptor policy-test`` reports, so operators can check a
        policy file without executing anything.
        """
        for index, rule in enumerate(self._rules):
            if rule.matches(request):
                reason = rule.reason or f"matched rule {rule.action!r} -> {rule.decision}"
                return RuleExplanation(
                    decision=rule.decision,
                    reason=reason,
                    matched_index=index,
                    matched_action=rule.action,
                    total_rules=len(self._rules),
                )
        if self._default == DECISION_ALLOWED:
            return RuleExplanation(
                decision=DECISION_ALLOWED,
                reason="allowed by policy default",
                matched_index=None,
                matched_action=None,
                total_rules=len(self._rules),
            )
        return RuleExplanation(
            decision=DECISION_DENIED,
            reason="no policy rule matched; default deny",
            matched_index=None,
            matched_action=None,
            total_rules=len(self._rules),
        )

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        explanation = self.explain(request)
        return ApprovalDecision(explanation.decision, explanation.reason)


#: Per-state-file in-process locks, so threads in one process serialize
#: around the same OS file lock acquisition.
_STATE_LOCKS: dict[str, threading.Lock] = {}
_STATE_LOCKS_GUARD = threading.Lock()


def _state_lock(path: Path) -> threading.Lock:
    try:
        key = str(path.resolve())
    except OSError:
        key = str(path)
    with _STATE_LOCKS_GUARD:
        return _STATE_LOCKS.setdefault(key, threading.Lock())


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write *payload* atomically (exclusive tmp + fsync + replace).

    The temp file is created with ``O_EXCL`` semantics via :mod:`tempfile`, so
    a crashed predecessor's leftovers can never be mistaken for state: only
    ``os.replace`` publishes a complete write.
    """
    import tempfile as _tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd, tmp_name = _tempfile.mkstemp(dir=path.parent, prefix=f"{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _lock_exclusive(handle: Any) -> bool:
    """Take an exclusive OS lock on *handle*; False where unavailable.

    Mirrors the journal's platform strategy (``fcntl`` on POSIX, ``msvcrt`` on
    Windows). Callers proceed unlocked when this returns False and document
    that degradation (concurrent writers can over-allow) rather than denying
    outright, which would turn every exotic platform into a total denial of
    service. Corrupt or unwritable state still fails closed.
    """
    try:
        if os.name == "posix":
            import fcntl as _fcntl

            _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        elif os.name == "nt":
            import msvcrt as _msvcrt

            handle.seek(0)
            # typeshed omits locking/LK_*; the Windows branch cannot be exercised here.
            _msvcrt.locking(handle.fileno(), _msvcrt.LK_LOCK, 1)  # type: ignore[attr-defined]
        else:
            return False
    except Exception:
        return False
    return True


def _unlock_shared(handle: Any) -> None:
    try:
        if os.name == "posix":
            import fcntl as _fcntl

            _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
        elif os.name == "nt":
            import msvcrt as _msvcrt

            handle.seek(0)
            # typeshed omits locking/LK_*; the Windows branch cannot be exercised here.
            _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
    except Exception:  # noqa: S110 - best-effort unlock
        pass


def _read_json_state(path: Path) -> dict[str, Any] | None:
    """Parse the JSON state file, or None when missing/empty. Raises on corruption."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    if not raw.strip():
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PolicyError(f"policy state {path} is corrupt: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PolicyError(f"policy state {path} is corrupt: expected an object")
    return parsed


class FileBudgetProvider:
    """Durable budget: at most *max_calls* invocations, surviving restarts.

    State lives in *state_path* as JSON (``{"total": N, "per_action": {..}}``),
    updated under an OS file lock (``fcntl`` on POSIX, ``msvcrt`` on Windows)
    so concurrent processes share one budget. Each allowance consumes one
    unit, like :class:`BudgetProvider`. Corrupt or unwritable state fails
    closed (deny); on platforms with no OS locks, concurrent writers can
    over-allow — the same documented degradation as the journal itself.
    """

    def __init__(self, max_calls: int, state_path: str | Path, *, per_action: bool = False) -> None:
        if max_calls < 0:
            raise ValueError("max_calls must be non-negative")
        self._max_calls = max_calls
        self._state_path = Path(state_path)
        self._per_action = per_action

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        lock = _state_lock(self._state_path)
        with lock:
            try:
                self._state_path.parent.mkdir(parents=True, exist_ok=True)
                # Lock a stable sidecar so the atomic replace of the state file
                # cannot drop mutual exclusion mid-update.
                lockfile = self._state_path.with_name(f"{self._state_path.name}.lock")
                with open(lockfile, "a+b") as handle:
                    locked = _lock_exclusive(handle)
                    try:
                        state = _read_json_state(self._state_path)
                        if state is None:
                            state = {"total": 0, "per_action": {}}
                        total = state.get("total", 0)
                        per_action = state.get("per_action", {})
                        if not isinstance(total, int) or not isinstance(per_action, dict):
                            raise PolicyError(f"policy state {self._state_path} is corrupt")
                        if self._per_action:
                            used = per_action.get(request.action_name, 0)
                            if not isinstance(used, int):
                                raise PolicyError(f"policy state {self._state_path} is corrupt")
                            if used >= self._max_calls:
                                return ApprovalDecision(
                                    DECISION_DENIED,
                                    f"budget exhausted for {request.action_name!r} "
                                    f"({used}/{self._max_calls})",
                                )
                            per_action[request.action_name] = used + 1
                            _atomic_write_json(
                                self._state_path, {"total": total, "per_action": per_action}
                            )
                            return ApprovalDecision(
                                DECISION_ALLOWED,
                                f"within budget ({used + 1}/{self._max_calls})",
                            )
                        if total >= self._max_calls:
                            return ApprovalDecision(
                                DECISION_DENIED,
                                f"budget exhausted ({total}/{self._max_calls})",
                            )
                        _atomic_write_json(
                            self._state_path, {"total": total + 1, "per_action": per_action}
                        )
                        return ApprovalDecision(
                            DECISION_ALLOWED, f"within budget ({total + 1}/{self._max_calls})"
                        )
                    finally:
                        if locked:
                            _unlock_shared(handle)
            except PolicyError as exc:
                return ApprovalDecision(DECISION_DENIED, f"{exc}; failing closed")
            except OSError as exc:
                return ApprovalDecision(
                    DECISION_DENIED, f"budget state unavailable ({exc}); failing closed"
                )
        # Unreachable: kept for type-checkers.
        return ApprovalDecision(DECISION_DENIED, "budget state unavailable; failing closed")


class FileRateLimitProvider:
    """Durable sliding-window rate limit shared across processes/restarts.

    Attempt timestamps live in *state_path* as JSON (``{"attempts": [...]}``),
    updated under an OS file lock (``fcntl`` on POSIX, ``msvcrt`` on Windows).
    Only allowed attempts are recorded, matching :class:`RateLimitProvider`.
    Corrupt or unwritable state fails closed (deny); on platforms with no OS
    locks, concurrent writers can over-allow.
    """

    def __init__(
        self,
        max_calls: int,
        window_seconds: float,
        state_path: str | Path,
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if max_calls <= 0:
            raise ValueError("max_calls must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max_calls = max_calls
        self._window = window_seconds
        self._state_path = Path(state_path)
        self._clock = clock or time.monotonic

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        now = self._clock()
        lock = _state_lock(self._state_path)
        with lock:
            try:
                self._state_path.parent.mkdir(parents=True, exist_ok=True)
                lockfile = self._state_path.with_name(f"{self._state_path.name}.lock")
                with open(lockfile, "a+b") as handle:
                    locked = _lock_exclusive(handle)
                    try:
                        state = _read_json_state(self._state_path)
                        attempts: list[float] = []
                        if state is not None:
                            raw_attempts = state.get("attempts", [])
                            if not isinstance(raw_attempts, list) or not all(
                                isinstance(t, (int, float)) for t in raw_attempts
                            ):
                                raise PolicyError(f"policy state {self._state_path} is corrupt")
                            attempts = [float(t) for t in raw_attempts]
                        cutoff = now - self._window
                        attempts = [t for t in attempts if t > cutoff]
                        if len(attempts) >= self._max_calls:
                            _atomic_write_json(self._state_path, {"attempts": attempts})
                            return ApprovalDecision(
                                DECISION_DENIED,
                                f"rate limit exceeded ({self._max_calls} per {self._window:g}s)",
                            )
                        attempts.append(now)
                        _atomic_write_json(self._state_path, {"attempts": attempts})
                        return ApprovalDecision(DECISION_ALLOWED, "within rate limit")
                    finally:
                        if locked:
                            _unlock_shared(handle)
            except PolicyError as exc:
                return ApprovalDecision(DECISION_DENIED, f"{exc}; failing closed")
            except OSError as exc:
                return ApprovalDecision(
                    DECISION_DENIED, f"rate-limit state unavailable ({exc}); failing closed"
                )
        return ApprovalDecision(DECISION_DENIED, "rate-limit state unavailable; failing closed")


class SpendingBudgetProvider:
    """Allow while cumulative declared spend stays within *max_cents*.

    Reads ``request.spend_cents`` (see ``spend_from`` on ``@guard``): each
    allowed call adds its spend to the total (optionally per action). Calls
    with no declared spend are denied — an unenforceable budget must fail
    closed, not silently pass. Thread-safe.
    """

    def __init__(self, max_cents: int, *, per_action: bool = False) -> None:
        if max_cents < 0:
            raise ValueError("max_cents must be non-negative")
        self._max_cents = max_cents
        self._per_action = per_action
        self._lock = threading.Lock()
        self._total = 0
        self._per_action_totals: dict[str, int] = {}

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        spend = request.spend_cents
        if spend is None:
            return ApprovalDecision(
                DECISION_DENIED, "no spend declared; spending budget cannot account it"
            )
        with self._lock:
            if self._per_action:
                used = self._per_action_totals.get(request.action_name, 0)
                if used + spend > self._max_cents:
                    return ApprovalDecision(
                        DECISION_DENIED,
                        f"spending budget exhausted for {request.action_name!r} "
                        f"({used}+{spend}>{self._max_cents}c)",
                    )
                self._per_action_totals[request.action_name] = used + spend
                return ApprovalDecision(
                    DECISION_ALLOWED, f"within spending budget ({used + spend}/{self._max_cents}c)"
                )
            if self._total + spend > self._max_cents:
                return ApprovalDecision(
                    DECISION_DENIED,
                    f"spending budget exhausted ({self._total}+{spend}>{self._max_cents}c)",
                )
            self._total += spend
            return ApprovalDecision(
                DECISION_ALLOWED, f"within spending budget ({self._total}/{self._max_cents}c)"
            )


class FileSpendingBudgetProvider:
    """Durable spending budget shared across processes and restarts.

    Totals live in *state_path* as JSON (``{"total": C, "per_action": {..}}``),
    updated under an OS-locked sidecar file (``fcntl`` on POSIX, ``msvcrt`` on
    Windows). Like :class:`SpendingBudgetProvider`, calls with no declared
    spend are denied. Corrupt or unwritable state fails closed (deny); on
    platforms with no OS locks, concurrent writers can over-allow.
    """

    def __init__(self, max_cents: int, state_path: str | Path, *, per_action: bool = False) -> None:
        if max_cents < 0:
            raise ValueError("max_cents must be non-negative")
        self._max_cents = max_cents
        self._state_path = Path(state_path)
        self._per_action = per_action

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        spend = request.spend_cents
        if spend is None:
            return ApprovalDecision(
                DECISION_DENIED, "no spend declared; spending budget cannot account it"
            )
        lock = _state_lock(self._state_path)
        with lock:
            try:
                self._state_path.parent.mkdir(parents=True, exist_ok=True)
                lockfile = self._state_path.with_name(f"{self._state_path.name}.lock")
                with open(lockfile, "a+b") as handle:
                    locked = _lock_exclusive(handle)
                    try:
                        state = _read_json_state(self._state_path)
                        if state is None:
                            state = {"total": 0, "per_action": {}}
                        total = state.get("total", 0)
                        per_action = state.get("per_action", {})
                        if (
                            not isinstance(total, int)
                            or not isinstance(per_action, dict)
                            or any(not isinstance(v, int) for v in per_action.values())
                        ):
                            raise PolicyError(f"policy state {self._state_path} is corrupt")
                        if self._per_action:
                            used = per_action.get(request.action_name, 0)
                            if not isinstance(used, int):
                                raise PolicyError(f"policy state {self._state_path} is corrupt")
                            if used + spend > self._max_cents:
                                return ApprovalDecision(
                                    DECISION_DENIED,
                                    f"spending budget exhausted for {request.action_name!r} "
                                    f"({used}+{spend}>{self._max_cents}c)",
                                )
                            per_action[request.action_name] = used + spend
                            _atomic_write_json(
                                self._state_path, {"total": total, "per_action": per_action}
                            )
                            return ApprovalDecision(
                                DECISION_ALLOWED,
                                f"within spending budget ({used + spend}/{self._max_cents}c)",
                            )
                        if total + spend > self._max_cents:
                            return ApprovalDecision(
                                DECISION_DENIED,
                                f"spending budget exhausted ({total}+{spend}>{self._max_cents}c)",
                            )
                        _atomic_write_json(
                            self._state_path,
                            {"total": total + spend, "per_action": per_action},
                        )
                        return ApprovalDecision(
                            DECISION_ALLOWED,
                            f"within spending budget ({total + spend}/{self._max_cents}c)",
                        )
                    finally:
                        if locked:
                            _unlock_shared(handle)
            except PolicyError as exc:
                return ApprovalDecision(DECISION_DENIED, f"{exc}; failing closed")
            except OSError as exc:
                return ApprovalDecision(
                    DECISION_DENIED, f"spending state unavailable ({exc}); failing closed"
                )
        return ApprovalDecision(DECISION_DENIED, "spending state unavailable; failing closed")


class AttestedApprovalProvider:
    """Stamp inner allowances with a verified operator identity.

    The identity comes from *approved_by* or, when None, the
    *approved_by_env* environment variable (e.g. an OIDC ``sub`` your launcher
    exports after login). Allowed decisions are re-issued with that identity
    in ``approved_by`` so the journal says *who* approved; denials pass
    through unstamped. A missing or malformed identity fails closed (deny):
    unattributable approval is not approval.
    """

    def __init__(
        self,
        inner: ApprovalProvider,
        *,
        approved_by: str | None = None,
        approved_by_env: str = "INTERCEPTOR_APPROVER",
    ) -> None:
        self._inner = inner
        self._approved_by = approved_by
        self._approved_by_env = approved_by_env

    def _resolve_identity(self) -> str | None:
        if self._approved_by is not None:
            return self._approved_by
        import os as _os

        value = _os.environ.get(self._approved_by_env)
        return value if value else None

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        decision = self._inner.decide(request)
        if not decision.allowed:
            return decision
        identity = self._resolve_identity()
        if identity is None:
            return ApprovalDecision(
                DECISION_DENIED, "no approver identity configured; failing closed"
            )
        stamped = " ".join(identity.split())
        if (
            not stamped
            or len(stamped) > 120
            or any(ord(char) < 32 or ord(char) == 127 for char in stamped)
        ):
            return ApprovalDecision(
                DECISION_DENIED, "approver identity is malformed; failing closed"
            )
        return ApprovalDecision(decision.decision, decision.reason, approved_by=stamped)


class WitnessFreshnessProvider:
    """Deny unless the off-host witness is fresh.

    Tail truncation is undetectable from the journal alone; only a witness
    that left the machine bounds it (see ``docs/THREAT_MODEL.md``). This
    provider turns that operational requirement into an approval gate: it
    stats ``witness_dir/latest.checkpoint`` (written by
    :func:`interceptor.witness.witness_journal`) and denies when the witness
    is missing or older than *max_age_seconds*.

    *risks* optionally restricts enforcement to a risk subset (e.g.
    ``{"high", "critical"}``); other risks allow with a reason stating the
    gate did not apply. This composes with declarative policy::

        AllOf([RuleProvider(...), WitnessFreshnessProvider(dir, 300,
              risks={"high", "critical"})])

    The default clock is :func:`time.time` (wall clock, to compare against
    filesystem mtime — not monotonic). Inject a stub clock in tests. All
    filesystem errors fail closed (deny). Thread-safe (stateless).
    """

    def __init__(
        self,
        witness_dir: str | Path,
        max_age_seconds: float,
        *,
        risks: Collection[str] | None = None,
        clock: Callable[[], float] | None = None,
        witness_filename: str = "latest.checkpoint",
    ) -> None:
        if max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be positive")
        if not witness_filename or "/" in witness_filename or "\\" in witness_filename:
            raise ValueError("witness_filename must be a plain file name")
        risk_set: frozenset[str] | None = None
        if risks is not None:
            risk_set = frozenset(risks)
            unknown = risk_set - set(RISK_LEVELS)
            if unknown:
                raise ValueError(
                    f"unknown risks {sorted(unknown)}; expected one of {list(RISK_LEVELS)}"
                )
        self._witness_dir = Path(witness_dir)
        self._max_age = max_age_seconds
        self._risks = risk_set
        self._clock = clock or time.time
        self._witness_filename = witness_filename

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        if self._risks is not None and request.risk not in self._risks:
            return ApprovalDecision(
                DECISION_ALLOWED,
                f"witness freshness not required for risk {request.risk!r}",
            )
        witness = self._witness_dir / self._witness_filename
        try:
            if witness.is_dir():
                return ApprovalDecision(
                    DECISION_DENIED,
                    f"witness at {witness} is a directory; failing closed",
                )
            mtime = witness.stat().st_mtime
        except FileNotFoundError:
            return ApprovalDecision(
                DECISION_DENIED,
                f"no witness at {witness} (run `interceptor witness`); failing closed",
            )
        except NotADirectoryError as exc:
            return ApprovalDecision(
                DECISION_DENIED, f"witness dir unavailable ({exc}); failing closed"
            )
        except OSError as exc:
            return ApprovalDecision(DECISION_DENIED, f"witness unavailable ({exc}); failing closed")
        try:
            now = self._clock()
        except Exception as exc:
            return ApprovalDecision(
                DECISION_DENIED, f"witness clock failed ({exc!r}); failing closed"
            )
        age = now - mtime
        if age < 0:
            age = 0
        if age > self._max_age:
            return ApprovalDecision(
                DECISION_DENIED,
                f"witness stale ({age:.0f}s old, max {self._max_age:g}s); "
                "run `interceptor witness`; failing closed",
            )
        return ApprovalDecision(
            DECISION_ALLOWED, f"witness fresh ({age:.0f}s old, max {self._max_age:g}s)"
        )


def load_policy_file(path: str | Path) -> RuleProvider:
    """Load a declarative policy from a JSON file.

    Format::

        {"default": "denied",
         "rules": [{"action": "billing.*", "decision": "denied",
                    "risks": ["high", "critical"], "reason": "needs a human"},
                   {"action": "*", "decision": "allowed"}]}

    Raises :class:`PolicyError` on any malformed input, so a broken policy
    fails closed at load time instead of misbehaving at call time.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    except ValueError as exc:
        raise PolicyError(f"policy file {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"policy file {path} must hold a JSON object")
    unknown_top = set(raw) - {"default", "rules"}
    if unknown_top:
        raise PolicyError(
            f"policy file {path}: unknown top-level keys {sorted(unknown_top)}; "
            "expected 'default' and 'rules'"
        )
    entries = raw.get("rules", [])
    if not isinstance(entries, list):
        raise PolicyError(f"policy file {path}: 'rules' must be a list")
    rules: list[Rule] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise PolicyError(f"policy file {path}: rule {index} must be an object")
        unknown_keys = set(entry) - {"action", "decision", "risks", "reason"}
        if unknown_keys:
            raise PolicyError(
                f"policy file {path}: rule {index} has unknown keys {sorted(unknown_keys)}; "
                "expected 'action', 'decision', 'risks', 'reason'"
            )
        action = entry.get("action")
        decision = entry.get("decision")
        if not isinstance(action, str) or not action:
            raise PolicyError(f"policy file {path}: rule {index} needs a non-empty 'action'")
        if decision not in (DECISION_ALLOWED, DECISION_DENIED):
            raise PolicyError(f"policy file {path}: rule {index} needs decision allowed/denied")
        risks = entry.get("risks")
        risk_set: frozenset[str] | None = None
        if risks is not None:
            if not isinstance(risks, list) or not all(isinstance(r, str) for r in risks):
                raise PolicyError(f"policy file {path}: rule {index} 'risks' must be a string list")
            unknown_risks = set(risks) - set(RISK_LEVELS)
            if unknown_risks:
                raise PolicyError(
                    f"policy file {path}: rule {index} has unknown risks "
                    f"{sorted(unknown_risks)}; expected one of {list(RISK_LEVELS)}"
                )
            risk_set = frozenset(risks)
        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            raise PolicyError(f"policy file {path}: rule {index} 'reason' must be a string")
        rules.append(Rule(action=action, decision=decision, risks=risk_set, reason=reason))
    default = raw.get("default", DECISION_DENIED)
    if default not in (DECISION_ALLOWED, DECISION_DENIED):
        raise PolicyError(f"policy file {path}: 'default' must be allowed/denied")
    return RuleProvider(rules, default=default)
