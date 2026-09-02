"""The one shared execution engine behind ``@guard`` and ``wrap_tool``.

The before/after flow — argument binding, observer notification, the fused
redact + canonicalize + hash, approval, the signed ``decision`` event,
execution, and the ``outcome`` event — is identical no matter how the guarded
callable was registered. ``@guard`` and ``wrap_tool`` differ only in how they
build the contract and how the target is invoked (synchronously vs ``await``).
Both delegate the entire run here, so the two cannot drift apart again.

Fail-closed ordering is load-bearing and must stay exactly as it is:

1. Bind call arguments to parameter names (``inspect.signature``), applying
   defaults. A ``TypeError`` from binding propagates unchanged: the call was
   malformed and nothing has executed or been recorded.
2. Notify the :class:`~guardrail_evidence.observer.ActionObserver`, if one was
   configured, once per contract version per process. Failure is a
   pre-execution error: the function does not run.
3. Redact and canonicalize the bound arguments in a single fused traversal,
   then hash the redacted canonical form.
4. Load the local signing identity (fail closed if unusable).
5. Evaluate approval (fail closed on provider failure or missing TTY).
6. Durably append a signed ``decision`` event BEFORE any execution.
   Denied → raise :class:`~guardrail_evidence.errors.ActionDenied`; nothing
   executes.
7. Execute the original function exactly once. This library does not
   deduplicate calls and does not make the action idempotent.
8. Durably append a signed ``outcome`` event (succeeded/failed).
9. Return the original result, or re-raise the original exception.

Post-execution evidence failure is reported as
:class:`~guardrail_evidence.errors.ExecutionCompletedEvidenceError` — a
distinct error meaning "the function ALREADY ran, but outcome evidence could
not be persisted". The function is never retried.

``KeyboardInterrupt`` and ``SystemExit`` raised by the guarded function
propagate immediately without an outcome event. A decision event with no
following outcome therefore reads as "execution started; the process was
interrupted or died before an outcome was recorded".
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .approval import (
    DECISION_ALLOWED,
    DECISION_DENIED,
    ApprovalDecision,
    ApprovalProvider,
    ApprovalRequest,
    AutoAllowProvider,
    TerminalApprovalProvider,
)
from .canonical import (
    REDACTED,
    UNSUPPORTED_MARKER,
    canonical_json_bytes,
    canonicalize,
    sha256_hex,
    type_name,
)
from .contracts import ActionContract
from .errors import (
    ActionDenied,
    ApprovalError,
    CanonicalizationError,
    ExecutionCompletedEvidenceError,
    GuardrailError,
)
from .identity import LocalSigningIdentity, SigningIdentity, default_journal_path
from .journal import (
    EVENT_SCHEMA_VERSION,
    FileJournal,
    JournalStore,
    finalize_event,
    new_event_id,
    utc_timestamp,
)
from .observer import ActionObserver, notify_once
from .redaction import bounded_summary, scrub_text

EVENT_TYPE_DECISION = "decision"
EVENT_TYPE_OUTCOME = "outcome"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"


def execute_sync(
    *,
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
) -> Any:
    """Guard one synchronous invocation of *target* and return its result."""
    store, active_identity, decision_event, redacted_values = _prepare_execution(
        args=args,
        kwargs=kwargs,
        contract=contract,
        sensitive=sensitive,
        canonical_metadata=canonical_metadata,
        signature=signature,
        journal=journal,
        approval_provider=approval_provider,
        identity=identity,
        observer=observer,
    )
    try:
        result = target(*args, **kwargs)
    except Exception as exc:
        _record_outcome_or_raise(
            store,
            active_identity,
            contract,
            decision_event,
            status=STATUS_FAILED,
            result=None,
            exception=exc,
            redacted_values=redacted_values,
            sensitive=sensitive,
        )
        raise
    _record_outcome_or_raise(
        store,
        active_identity,
        contract,
        decision_event,
        status=STATUS_SUCCEEDED,
        result=result,
        exception=None,
        redacted_values=redacted_values,
        sensitive=sensitive,
    )
    return result


async def execute_async(
    *,
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
) -> Any:
    """Guard one asynchronous invocation of *target* and return its result."""
    store, active_identity, decision_event, redacted_values = _prepare_execution(
        args=args,
        kwargs=kwargs,
        contract=contract,
        sensitive=sensitive,
        canonical_metadata=canonical_metadata,
        signature=signature,
        journal=journal,
        approval_provider=approval_provider,
        identity=identity,
        observer=observer,
    )
    try:
        result = await target(*args, **kwargs)
    except Exception as exc:
        _record_outcome_or_raise(
            store,
            active_identity,
            contract,
            decision_event,
            status=STATUS_FAILED,
            result=None,
            exception=exc,
            redacted_values=redacted_values,
            sensitive=sensitive,
        )
        raise
    _record_outcome_or_raise(
        store,
        active_identity,
        contract,
        decision_event,
        status=STATUS_SUCCEEDED,
        result=result,
        exception=None,
        redacted_values=redacted_values,
        sensitive=sensitive,
    )
    return result


def _parameter_retention(canonical_input: dict[str, Any]) -> list[dict[str, str]]:
    """Per-parameter retention state, in the canonical (sorted) key order.

    Records, for each top-level argument, whether its recorded value is the
    redaction marker, an unsupported-type placeholder, or an ordinary value.
    Privacy inspection reads this instead of re-parsing the bounded summary,
    so a truncated or oddly-formatted summary can no longer hide a retained
    argument.
    """
    retention: list[dict[str, str]] = []
    for name in sorted(canonical_input):
        value = canonical_input[name]
        if value == REDACTED:
            state = "redacted"
        elif isinstance(value, str) and value.startswith(UNSUPPORTED_MARKER):
            state = "unsupported"
        else:
            state = "retained"
        retention.append({"name": name, "state": state})
    return retention


def _prepare_execution(
    *,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
) -> tuple[JournalStore, SigningIdentity, dict[str, Any], tuple[str, ...]]:
    """Everything that must happen before the guarded callable runs.

    Returns ``(store, active_identity, decision_event, redacted_values)``.
    Raises ``ActionDenied`` (after the signed decision event) on denial.
    """
    # 1. Bind arguments. A TypeError here means the call itself was malformed;
    # propagate it unchanged (nothing ran, nothing recorded).
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()

    # 2. Observer notification, before anything else observable.
    notify_once(observer, contract)

    # 3. One traversal produces the redacted canonical structure and the raw
    # values it removed. There is no second pass that could disagree with this
    # one about which fields carry names.
    canonical_input, redacted_values = canonicalize(dict(bound.arguments), sensitive)
    input_hash = sha256_hex(canonical_json_bytes(canonical_input))
    input_summary = bounded_summary(canonical_input)

    # 4. Signing identity (fail closed before prompting anyone).
    active_identity = identity or LocalSigningIdentity.load_or_create()

    # 5. Approval.
    request = ApprovalRequest(
        action_name=contract.action_name,
        risk=contract.risk,
        approval_mode=contract.approval_mode,
        redacted_input_summary=input_summary,
        input_hash=input_hash,
        contract_hash=contract.contract_hash,
    )
    decision = _evaluate_approval(request, contract, approval_provider)

    # 6. Signed decision event, durably appended BEFORE execution.
    store = _resolve_journal(journal)
    decision_payload_extra: dict[str, Any] = {
        "decision": decision.decision,
        "risk": contract.risk,
        "approval_mode": contract.approval_mode,
        "redacted_input_summary": input_summary,
        "parameter_retention": _parameter_retention(canonical_input),
        "input_hash": input_hash,
    }
    if canonical_metadata is not None:
        decision_payload_extra["metadata"] = canonical_metadata
    decision_event = _append_event(
        store,
        active_identity,
        contract,
        EVENT_TYPE_DECISION,
        decision_payload_extra,
    )

    if not decision.allowed:
        raise ActionDenied(
            contract.action_name,
            f"action denied: {contract.action_name} ({decision.reason})",
        )

    return store, active_identity, decision_event, redacted_values


def _evaluate_approval(
    request: ApprovalRequest,
    contract: ActionContract,
    provider: ApprovalProvider | None,
) -> ApprovalDecision:
    if contract.approval_mode == "never":
        active: ApprovalProvider = AutoAllowProvider()
    else:
        active = provider or TerminalApprovalProvider()
    try:
        decision = active.decide(request)
    except GuardrailError:
        raise
    except Exception as exc:
        raise ApprovalError(
            f"approval provider failed for action {contract.action_name!r}: "
            f"{type_name(exc)}; failing closed"
        ) from exc
    if decision.decision not in (DECISION_ALLOWED, DECISION_DENIED):
        raise ApprovalError(
            f"approval provider returned invalid decision {decision.decision!r}; failing closed"
        )
    return decision


def _resolve_journal(journal: str | Path | JournalStore | None) -> JournalStore:
    if journal is None:
        return FileJournal(default_journal_path())
    if isinstance(journal, (str, Path)):
        return FileJournal(Path(journal))
    return journal


def _append_event(
    store: JournalStore,
    identity: SigningIdentity,
    contract: ActionContract,
    event_type: str,
    extra_fields: dict[str, Any],
) -> dict[str, Any]:
    def build(previous_hash: str | None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": EVENT_SCHEMA_VERSION,
            "event_type": event_type,
            "event_id": new_event_id(),
            "action_id": contract.action_id,
            "action_name": contract.action_name,
            "contract_hash": contract.contract_hash,
            "timestamp_utc": utc_timestamp(),
            "key_id": identity.key_id,
            "previous_event_hash": previous_hash,
        }
        payload.update(extra_fields)
        return finalize_event(payload, identity.sign)

    return store.append_event(build)


def _record_outcome_or_raise(
    store: JournalStore,
    identity: SigningIdentity,
    contract: ActionContract,
    decision_event: dict[str, Any],
    *,
    status: str,
    result: Any,
    exception: Exception | None,
    redacted_values: tuple[str, ...],
    sensitive: frozenset[str],
) -> None:
    """Append the outcome event; on failure raise ExecutionCompletedEvidenceError.

    The guarded function has ALREADY executed when this runs. Nothing here
    re-invokes it.
    """
    extra: dict[str, Any] = {
        "status": status,
        "decision_event_id": decision_event["event_id"],
    }
    if status == STATUS_SUCCEEDED:
        extra["observed_result_type"] = type_name(result)
        output_hash = _safe_output_hash(result, redacted_values, sensitive)
        if output_hash is not None:
            extra["redacted_output_hash"] = output_hash
    else:
        assert exception is not None
        extra["observed_result_type"] = None
        extra["exception_type"] = type_name(exception)
        extra["sanitized_error_summary"] = scrub_text(str(exception), redacted_values)

    try:
        _append_event(store, identity, contract, EVENT_TYPE_OUTCOME, extra)
    except Exception as journal_exc:
        message = (
            f"action {contract.action_name!r} EXECUTED (function outcome: {status}) "
            "but the outcome event could not be persisted, so outcome evidence is "
            "INCOMPLETE. The external side effect may have occurred. Automatic retry "
            f"is UNSAFE. Evidence failure: {type_name(journal_exc)}. "
            "The function was not retried."
        )
        if exception is not None:
            # Preserve the original function failure as the cause.
            raise ExecutionCompletedEvidenceError(
                message,
                action_id=contract.action_id,
                decision_event_id=decision_event["event_id"],
                function_outcome=status,
            ) from exception
        raise ExecutionCompletedEvidenceError(
            message,
            action_id=contract.action_id,
            decision_event_id=decision_event["event_id"],
            function_outcome=status,
            result=result,
        ) from journal_exc


def _safe_output_hash(
    result: Any,
    redacted_values: tuple[str, ...],
    sensitive: frozenset[str],
) -> str | None:
    """Hash of the canonical redacted result, or None when it must not be hashed.

    Two ways this returns None, both deliberate:

    * the result IS one of the call's redacted values. Hashing a low-entropy
      secret commits something that can be confirmed by guessing, which is the
      same disclosure the redaction was for;
    * the result is not canonicalizable. A NaN-bearing return value must not
      fail a call that has already succeeded, so this never raises.

    Sensitive-named fields *inside* the result are redacted by the same fused
    traversal used for inputs — including names declared via ``redact=[...]`` —
    so a returned dataclass holding a token hashes as ``<REDACTED>`` rather
    than as the token.
    """
    # Suppress hashing when the returned value echoes any redacted input,
    # even with a type change (e.g. int PIN 9074 -> str "9074" in exception).
    if redacted_values and result is not None and str(result) in redacted_values:
        return None
    if isinstance(result, str) and result in redacted_values:
        return None
    try:
        canonical = canonicalize(result, sensitive).value
        return sha256_hex(canonical_json_bytes(canonical))
    except CanonicalizationError:
        return None


def _make_sync_wrapper(
    target: Callable[..., Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
) -> Callable[..., Any]:
    """Build a synchronous wrapper delegating to the shared guard engine."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return execute_sync(
            target=target,
            args=args,
            kwargs=kwargs,
            contract=contract,
            sensitive=sensitive,
            canonical_metadata=canonical_metadata,
            signature=signature,
            journal=journal,
            approval_provider=approval_provider,
            identity=identity,
            observer=observer,
        )

    return wrapper


def _make_async_wrapper(
    target: Callable[..., Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
) -> Callable[..., Any]:
    """Build an asynchronous wrapper delegating to the shared guard engine."""

    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        return await execute_async(
            target=target,
            args=args,
            kwargs=kwargs,
            contract=contract,
            sensitive=sensitive,
            canonical_metadata=canonical_metadata,
            signature=signature,
            journal=journal,
            approval_provider=approval_provider,
            identity=identity,
            observer=observer,
        )

    return wrapper
