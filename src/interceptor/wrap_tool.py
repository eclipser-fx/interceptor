"""Framework-neutral wrapping for existing agent tools.

``wrap_tool`` reuses the same guard engine (contract building, redaction,
approval, evidence) as ``@guard`` without requiring source-code edits to the
original callable. ``wrap_tools`` applies the same primitive to a sequence or
mapping of callables.

The returned callables are ordinary Python functions (or async functions)
that an agent framework can register exactly as it would any other tool.
No framework dependency is introduced, no automatic discovery is performed,
and no network activity occurs without explicit observer configuration.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, ParamSpec, TypeVar, overload

from .approval import ApprovalProvider
from .contracts import _build_contract_unchecked, build_contract
from .engine import (
    IdempotencyKeySpec,
    ReceiptExtractor,
    SpendExtractor,
    _make_async_wrapper,
    _make_sync_wrapper,
)
from .errors import ToolWrapError
from .guard import _is_async_callable, _is_generator_callable, _prepare_metadata
from .identity import SigningIdentity
from .journal import JournalStore
from .observer import ActionObserver
from .redaction import build_sensitive_set, compile_value_patterns

P = ParamSpec("P")
R = TypeVar("R")

_CONTRACT_ATTR = "__interceptor_contract__"


def _tool_name(func: Any) -> str | None:
    name = getattr(func, "__name__", None)
    if isinstance(name, str) and name:
        return name
    return None


# ---------------------------------------------------------------------------
# wrap_tool
# ---------------------------------------------------------------------------


@overload
def wrap_tool(
    func: Callable[P, R],
    *,
    action: str,
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
) -> Callable[P, R]: ...


@overload
def wrap_tool(
    func: Callable[..., Any],
    *,
    action: str,
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
) -> Callable[..., Any]: ...


def wrap_tool(
    func: Callable[..., Any],
    *,
    action: str,
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
) -> Callable[..., Any]:
    """Guard an existing callable without editing its source.

    Returns a new callable that produces the same ActionContract and signed
    evidence as an equivalent ``@guard`` declaration. The original
    callable is never mutated.

    Args:
        func: The existing callable to wrap. Synchronous functions, async
            functions, bound methods, ``functools.partial`` objects, and
            callable objects with a stable ``__call__`` signature are
            supported. Generator functions and async generator functions are
            rejected.
        action: Stable logical action name (required).
        risk: ``low`` | ``medium`` | ``high`` | ``critical``.
        approval: ``required`` (default) or ``never``.
        journal: Journal path override or ``JournalStore`` implementation.
        redact: Additional parameter names to redact (case-insensitive).
        redact_patterns: Additional value regexes to redact.
        metadata: Small JSON-safe dict recorded on every decision event.
        approval_provider: Injectable ``ApprovalProvider``.
        identity: Injectable ``SigningIdentity``.
        observer: Injectable ``ActionObserver``.
        dry_run: Record the decision but do not execute; return ``None``.
        idempotency_key: Parameter name, literal, or callable over bound args.
        spend_from: Callable over bound args returning non-negative int cents,
            recorded on the decision event for budget enforcement.

    Raises:
        ToolWrapError: If *func* is already guarded, not callable, or is a
            generator/async-generator callable.
        ContractError: If the contract cannot be built (invalid action name,
            unresolvable signature, etc.).
    """
    if not callable(func):
        raise ToolWrapError(f"wrap_tool expected a callable, got {type(func).__name__}")
    if hasattr(func, _CONTRACT_ATTR):
        raise ToolWrapError(
            f"cannot wrap {getattr(func, '__qualname__', _tool_name(func) or repr(func))!r}: "
            "it is already guarded by @guard or wrap_tool"
        )
    if _is_generator_callable(func):
        raise ToolWrapError(
            f"cannot wrap {getattr(func, '__qualname__', _tool_name(func) or repr(func))!r}: "
            "generator and async-generator callables are not supported "
            "(guarding a generator would record an outcome before any work runs)"
        )

    is_async = _is_async_callable(func)

    if is_async:
        contract = _build_contract_unchecked(func, action=action, risk=risk, approval=approval)
    else:
        contract = build_contract(func, action=action, risk=risk, approval=approval)

    sensitive = build_sensitive_set(redact)
    patterns = compile_value_patterns(redact_patterns)
    canonical_metadata = _prepare_metadata(metadata, sensitive, patterns, contract)
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ToolWrapError(f"cannot inspect signature: {exc}") from exc

    if is_async:
        wrapper = _make_async_wrapper(
            func,
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
            func,
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

    functools.update_wrapper(wrapper, func, updated=())
    setattr(wrapper, _CONTRACT_ATTR, contract)
    return wrapper


# ---------------------------------------------------------------------------
# wrap_tools
# ---------------------------------------------------------------------------


def wrap_tools(
    tools: Sequence[Callable[..., Any]] | Mapping[str, Callable[..., Any]],
    *,
    configuration: Mapping[str, Mapping[str, Any]] | None = None,
    action_prefix: str = "tools",
    risk: str = "high",
    **defaults: Any,
) -> list[Callable[..., Any]] | dict[str, Callable[..., Any]]:
    """Wrap a collection of existing callables.

    Args:
        tools: A sequence or mapping of callables to wrap. For a sequence,
            each callable's ``__name__`` is used as the configuration key.
            For a mapping, the mapping keys are used directly.
        configuration: A mapping from tool name to ``wrap_tool`` keyword
            arguments. Each value must include at least an ``action`` key.
            Action names across all tools must be unique. When omitted,
            every tool is wrapped as ``action=f"{action_prefix}.{name}"``
            with the given *risk* and *defaults*.
        action_prefix: Prefix for auto-generated action names when
            *configuration* is omitted.
        risk: Default risk for auto-generated entries.
        defaults: Extra ``wrap_tool`` keyword arguments applied to every
            auto-generated entry (e.g. ``approval_provider=...``).

    Returns:
        A new list (for sequence input) or dict (for mapping input) of
        wrapped callables. The caller's collection is never mutated.

    Raises:
        ToolWrapError: If a tool name is missing from *configuration*, a
            configuration entry lacks an ``action``, duplicate action names
            are detected, a non-callable entry is found, or any individual
            ``wrap_tool`` call fails.
    """
    if configuration is None:
        configuration = _auto_configuration(tools, action_prefix, risk, defaults)
    if isinstance(tools, Mapping):
        return _wrap_tools_mapping(tools, configuration)
    return _wrap_tools_sequence(tools, configuration)


def _auto_configuration(
    tools: Sequence[Callable[..., Any]] | Mapping[str, Callable[..., Any]],
    action_prefix: str,
    risk: str,
    defaults: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Build a configuration mapping from tool names when none is given."""
    if isinstance(tools, Mapping):
        names = list(tools.keys())
    else:
        names = []
        for tool in tools:
            name = _tool_name(tool)
            if name is None:
                raise ToolWrapError(
                    f"wrap_tools cannot determine a stable name for {tool!r}; "
                    "use a mapping or ensure the callable has __name__"
                )
            names.append(name)
    return {
        name: {"action": f"{action_prefix}.{name}", "risk": risk, **dict(defaults)}
        for name in names
    }


def _wrap_tools_sequence(
    tools: Sequence[Callable[..., Any]],
    configuration: Mapping[str, Mapping[str, Any]],
) -> list[Callable[..., Any]]:
    wrapped: list[Callable[..., Any]] = []
    seen_actions: set[str] = set()
    for tool in tools:
        if not callable(tool):
            raise ToolWrapError(
                f"wrap_tools encountered a non-callable entry: {type(tool).__name__}"
            )
        name = _tool_name(tool)
        if name is None:
            raise ToolWrapError(
                f"wrap_tools cannot determine a stable name for {tool!r}; "
                "use a mapping or ensure the callable has __name__"
            )
        config = configuration.get(name)
        if config is None:
            raise ToolWrapError(f"wrap_tools: no configuration provided for tool {name!r}")
        result = _wrap_one(tool, config, name, seen_actions)
        wrapped.append(result)
    return wrapped


def _wrap_tools_mapping(
    tools: Mapping[str, Callable[..., Any]],
    configuration: Mapping[str, Mapping[str, Any]],
) -> dict[str, Callable[..., Any]]:
    wrapped: dict[str, Callable[..., Any]] = {}
    seen_actions: set[str] = set()
    for key, tool in tools.items():
        if not callable(tool):
            raise ToolWrapError(
                f"wrap_tools encountered a non-callable entry for key {key!r}: "
                f"{type(tool).__name__}"
            )
        config = configuration.get(key)
        if config is None:
            raise ToolWrapError(f"wrap_tools: no configuration provided for tool {key!r}")
        result = _wrap_one(tool, config, key, seen_actions)
        wrapped[key] = result
    return wrapped


def _wrap_one(
    tool: Callable[..., Any],
    config: Mapping[str, Any],
    display_name: str,
    seen_actions: set[str],
) -> Callable[..., Any]:
    config_dict = dict(config)
    action = config_dict.get("action")
    if not isinstance(action, str) or not action:
        raise ToolWrapError(
            f"wrap_tools: configuration for {display_name!r} must include a "
            "non-empty 'action' string"
        )
    if action in seen_actions:
        raise ToolWrapError(
            f"wrap_tools: duplicate action name {action!r} "
            f"(from tool {display_name!r}); action names must be unique"
        )
    seen_actions.add(action)
    return wrap_tool(tool, **config_dict)
