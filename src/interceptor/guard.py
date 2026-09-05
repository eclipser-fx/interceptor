"""The ``@guard`` decorator.

Guarding a function makes the code declaration itself the registration — no
registry call, no backend, no account, no network.

The decorator builds a deterministic :class:`ActionContract` from the function
and the ``@guard`` arguments at decoration time, then hands every invocation
to the shared execution engine in :mod:`interceptor.engine` — the same
engine used by ``wrap_tool``. That engine owns the ordering, fail-closed
semantics, and evidence writes; see its module docstring for the precise flow.

The only thing this module adds on top is decoration-time handling: building
the contract, validating canonical metadata, and rejecting callables that
cannot be guarded safely in this version (generator and async-generator
functions). Synchronous and asynchronous functions are both supported.
"""

from __future__ import annotations

import functools
import inspect
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar, overload

from .approval import ApprovalProvider
from .canonical import canonicalize
from .contracts import ActionContract, _build_contract_unchecked, build_contract
from .engine import (
    IdempotencyKeySpec,
    ReceiptExtractor,
    SpendExtractor,
    _make_async_wrapper,
    _make_sync_wrapper,
)
from .errors import CanonicalizationError, ContractError, UnsupportedFunctionError
from .identity import SigningIdentity
from .journal import JournalStore
from .observer import ActionObserver
from .redaction import build_sensitive_set, compile_value_patterns

F = TypeVar("F", bound=Callable[..., Any])


def _is_async_callable(func: Any) -> bool:
    """True when calling *func* returns a coroutine."""
    if inspect.iscoroutinefunction(func):
        return True
    if isinstance(func, functools.partial):
        return inspect.iscoroutinefunction(func.func)
    call = type(func).__call__
    return inspect.iscoroutinefunction(call)


def _is_generator_callable(func: Any) -> bool:
    """True when calling *func* returns a generator (sync or async)."""
    if inspect.isgeneratorfunction(func):
        return True
    if inspect.isasyncgenfunction(func):
        return True
    if isinstance(func, functools.partial):
        return inspect.isgeneratorfunction(func.func) or inspect.isasyncgenfunction(func.func)
    call = type(func).__call__
    return inspect.isgeneratorfunction(call) or inspect.isasyncgenfunction(call)


@overload
def guard(func: F) -> F: ...


@overload
def guard(
    func: None = None,
    *,
    action: str | None = ...,
    risk: str = ...,
    approval: str = ...,
    journal: str | Path | JournalStore | None = ...,
    redact: list[str] | tuple[str, ...] | None = ...,
    redact_patterns: list[str] | tuple[str, ...] | None = ...,
    metadata: dict[str, Any] | None = ...,
    approval_provider: ApprovalProvider | None = ...,
    identity: SigningIdentity | None = ...,
    observer: ActionObserver | None = ...,
    dry_run: bool = ...,
    idempotency_key: IdempotencyKeySpec = ...,
    receipt_from: ReceiptExtractor = ...,
    spend_from: SpendExtractor = ...,
) -> Callable[[F], F]: ...


def guard(
    func: F | None = None,
    *,
    action: str | None = None,
    risk: str = "medium",
    approval: str = "required",
    journal: str | Path | JournalStore | None = None,
    redact: list[str] | tuple[str, ...] | None = None,
    redact_patterns: list[str] | tuple[str, ...] | None = None,
    metadata: dict[str, Any] | None = None,
    approval_provider: ApprovalProvider | None = None,
    identity: SigningIdentity | None = None,
    observer: ActionObserver | None = None,
    dry_run: bool = False,
    idempotency_key: IdempotencyKeySpec = None,
    receipt_from: ReceiptExtractor = None,
    spend_from: SpendExtractor = None,
) -> F | Callable[[F], F]:
    """Guard a consequential function (synchronous or asynchronous).

    Usable bare (``@guard``) or with arguments (``@guard(...)``).

    An ``async def`` target is wrapped in an async wrapper that awaits the
    original call, so the guarded callable stays a coroutine function.

    Args:
        action: Stable logical action name. Defaults to a deterministic
            identity derived from the module and qualified function name.
        risk: ``low`` | ``medium`` | ``high`` | ``critical``.
        approval: ``required`` (default; fail-safe) or ``never``.
        journal: Journal path override, or a ``JournalStore`` implementation.
        redact: Additional parameter and field names to redact
            (case-insensitive), on top of the built-in set.
        redact_patterns: Additional value regexes to redact (on top of the
            built-in secret patterns). Any string value matching one is
            replaced with ``<REDACTED>``, even under a generic name.
        metadata: Small JSON-safe dict recorded on every decision event. Passes
            the same redaction and canonicalization rules as inputs.
        approval_provider: An injectable ``ApprovalProvider``. Defaults to the
            interactive terminal prompt, which fails closed off a TTY.
        identity: An injectable ``SigningIdentity``. Defaults to the local
            Ed25519 key, created on first use.
        observer: An optional ``ActionObserver`` notified once per contract
            version before the first execution. Omitted means no outward
            calls of any kind are possible.
        dry_run: When true, record the signed decision event but do not
            execute the function and do not record an outcome. The call
            returns ``None``. Audits classify it as ``dry_run``, never as
            needing reconciliation.
        idempotency_key: A bound parameter name to read the key from, a
            literal key, or a callable taking the bound arguments dict. A
            call whose key already completed successfully records a denied
            decision and raises ``DuplicateActionError`` without executing.
        receipt_from: A callable taking the succeeded result and returning a
            JSON-native mapping of provider receipt IDs (e.g. the payment
            processor's refund id), recorded on the outcome event after the
            same redaction as inputs. Best-effort: extraction errors or
            oversized/non-canonical receipts drop the receipt, never the call.
        spend_from: A callable taking the bound arguments dict and returning a
            non-negative int spend in minor units (cents), or None. Recorded
            on the decision event and visible to approval providers as
            ``request.spend_cents`` for budget enforcement. Failures fail
            closed with ``ContractError`` before anything executes.
    """

    def decorate(target: F) -> F:
        if _is_generator_callable(target):
            raise UnsupportedFunctionError(
                f"@guard does not support generator functions; "
                f"{getattr(target, '__qualname__', target)!r} yields instead of returning. "
                "Guarding a generator would record an outcome before any work runs."
            )

        is_async = _is_async_callable(target)
        if is_async:
            contract = _build_contract_unchecked(
                target, action=action, risk=risk, approval=approval
            )
        else:
            contract = build_contract(target, action=action, risk=risk, approval=approval)

        sensitive = build_sensitive_set(redact)
        patterns = compile_value_patterns(redact_patterns)
        canonical_metadata = _prepare_metadata(metadata, sensitive, patterns, contract)
        try:
            signature = inspect.signature(target)
        except (TypeError, ValueError) as exc:
            raise ContractError(f"cannot inspect signature of {target!r}: {exc}") from exc

        if is_async:
            wrapper = _make_async_wrapper(
                target,
                contract,
                sensitive,
                patterns,
                canonical_metadata,
                signature,
                journal,
                approval_provider,
                identity,
                observer,
                dry_run,
                idempotency_key,
                receipt_from,
                spend_from,
            )
        else:
            wrapper = _make_sync_wrapper(
                target,
                contract,
                sensitive,
                patterns,
                canonical_metadata,
                signature,
                journal,
                approval_provider,
                identity,
                observer,
                dry_run,
                idempotency_key,
                receipt_from,
                spend_from,
            )

        functools.update_wrapper(wrapper, target)
        wrapper.__interceptor_contract__ = contract  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    if func is not None:
        return decorate(func)
    return decorate


def _prepare_metadata(
    metadata: dict[str, Any] | None,
    sensitive: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
    contract: ActionContract,
) -> Any:
    """Validate, redact, and canonicalize decorator metadata at decoration time."""
    if metadata is None:
        return None
    if not isinstance(metadata, dict) or not all(isinstance(k, str) for k in metadata):
        raise ContractError(
            f"metadata for action {contract.action_name!r} must be a dict with string keys"
        )
    try:
        return canonicalize(metadata, sensitive, patterns).value
    except CanonicalizationError as exc:
        raise ContractError(
            f"metadata for action {contract.action_name!r} is not canonicalizable: {exc}"
        ) from exc
