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
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
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
        actions: set[str] | frozenset[str],
        *,
        risks: set[str] | frozenset[str] | None = None,
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

    Counts every ``decide`` call that reaches this provider, allowed or not,
    so a denied burst cannot be retried into an allowance. Thread-safe.
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

    Denials also consume no quota beyond the attempt itself — the window
    counts attempts, so bursts cannot evade the limit by being denied first.
    Thread-safe; the clock is injectable for tests.
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
    """Cache ``allowed`` decisions for *ttl_seconds*, keyed by contract+input.

    Repeated identical calls within the TTL auto-allow without re-prompting;
    every invocation still writes its own decision/outcome evidence. Denials
    are never cached. Thread-safe.
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
        self._cache: dict[tuple[str, str], float] = {}

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        key = (request.contract_hash, request.input_hash)
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
        if not self._in_flight_guard.acquire(blocking=False):
            return ApprovalDecision(
                DECISION_DENIED, "approval overloaded; failing closed (too many pending)"
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

        worker = threading.Thread(target=_run, daemon=True)
        worker.start()
        if not done.wait(self._timeout):
            return ApprovalDecision(
                DECISION_DENIED,
                f"approval timed out after {self._timeout:g}s; failing closed",
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
    Provider exceptions count as denials. Thread-safe where the wrapped
    providers are.
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

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        for rule in self._rules:
            if rule.matches(request):
                reason = rule.reason or f"matched rule {rule.action!r} -> {rule.decision}"
                return ApprovalDecision(rule.decision, reason)
        if self._default == DECISION_ALLOWED:
            return ApprovalDecision(DECISION_ALLOWED, "allowed by policy default")
        return ApprovalDecision(DECISION_DENIED, "no policy rule matched; default deny")


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
    entries = raw.get("rules", [])
    if not isinstance(entries, list):
        raise PolicyError(f"policy file {path}: 'rules' must be a list")
    rules: list[Rule] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise PolicyError(f"policy file {path}: rule {index} must be an object")
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
            risk_set = frozenset(risks)
        reason = entry.get("reason", "")
        if not isinstance(reason, str):
            raise PolicyError(f"policy file {path}: rule {index} 'reason' must be a string")
        rules.append(Rule(action=action, decision=decision, risks=risk_set, reason=reason))
    default = raw.get("default", DECISION_DENIED)
    if default not in (DECISION_ALLOWED, DECISION_DENIED):
        raise PolicyError(f"policy file {path}: 'default' must be allowed/denied")
    return RuleProvider(rules, default=default)
