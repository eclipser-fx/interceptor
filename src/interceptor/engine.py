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
2. Notify the :class:`~interceptor.observer.ActionObserver`, if one was
   configured, once per contract version per process. Failure is a
   pre-execution error: the function does not run.
3. Redact and canonicalize the bound arguments in a single fused traversal
   (name-based plus value-pattern redaction), then hash the redacted form.
4. Resolve the idempotency key, if configured, and load the local signing
   identity (fail closed if unusable).
5. Reject duplicates: an idempotency key that already completed successfully
   records a denied decision and raises ``DuplicateActionError`` — nothing
   executes twice.
6. Evaluate approval (fail closed on provider failure or missing TTY).
7. Durably append a signed ``decision`` event BEFORE any execution.
   Denied → raise :class:`~interceptor.errors.ActionDenied`; nothing
   executes. ``dry_run`` returns here without executing and without an
   outcome event.
8. Execute the original function exactly once (unless dry-run).
9. Durably append a signed ``outcome`` event (succeeded/failed).

Post-execution evidence failure is reported as
:class:`~interceptor.errors.ExecutionCompletedEvidenceError` — a
distinct error meaning "the function ALREADY ran, but outcome evidence could
not be persisted". The function is never retried.

``KeyboardInterrupt`` and ``SystemExit`` raised by the guarded function
propagate immediately without an outcome event. A decision event with no
following outcome therefore reads as "execution started; the process was
interrupted or died before an outcome was recorded".
"""

from __future__ import annotations

import inspect
import json
import re
import threading
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
    ContractError,
    DuplicateActionError,
    EventShipError,
    ExecutionCompletedEvidenceError,
    InterceptorError,
)
from .identity import LocalSigningIdentity, SigningIdentity, default_journal_path
from .journal import (
    EVENT_SCHEMA_VERSION,
    FileJournal,
    JournalStore,
    finalize_event,
    find_blocking_idempotent_decision,
    find_completed_idempotent_decision,
    new_event_id,
    utc_timestamp,
)
from .observer import ActionObserver, notify_once
from .redaction import bounded_summary, scrub_text

EVENT_TYPE_DECISION = "decision"
EVENT_TYPE_OUTCOME = "outcome"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"

#: A parameter name to read the key from, a literal key, or a callable taking
#: the bound arguments dict and returning the key.
IdempotencyKeySpec = str | Callable[[dict[str, Any]], Any] | None

#: Extracts a provider receipt (external reference IDs) from a succeeded
#: result. Return a JSON-native mapping or None. Any exception, or a
#: non-canonicalizable return, drops the receipt — it must never fail a call
#: that already succeeded.
ReceiptExtractor = Callable[[Any], Any] | None

#: Extracts a spend amount in minor currency units (cents) from the bound
#: call arguments. Return a non-negative ``int`` or None when the call spends
#: nothing countable. Called before approval; failures fail closed.
SpendExtractor = Callable[[dict[str, Any]], Any] | None

_MAX_RECEIPT_CHARS = 2000


def _extract_receipt(
    receipt_from: ReceiptExtractor,
    result: Any,
    sensitive: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
) -> Any | None:
    """The redacted canonical receipt for *result*, or None when absent/unsafe."""
    if receipt_from is None:
        return None
    try:
        receipt = receipt_from(result)
    except Exception:
        return None
    if receipt is None:
        return None
    try:
        canonical = canonicalize(receipt, sensitive, patterns).value
        text = json.dumps(canonical, ensure_ascii=False, sort_keys=True)
    except CanonicalizationError:
        return None
    if not isinstance(canonical, dict):
        return None
    if len(text) > _MAX_RECEIPT_CHARS:
        return None
    return canonical


#: (journal_key, action_name, idempotency_key) triples that completed with a
#: recorded ``succeeded`` outcome in this process. File-backed journals keep
#: their triples in a FIFO-capped map: eviction is safe because the journal
#: scan (or the exact index) stays authoritative across processes, so a
#: dropped entry costs at most one rescan. Custom JournalStores have no
#: on-disk scan to fall back on, so their triples live exactly as long as
#: the store object itself (weakref finalizers purge them on collection) —
#: no cap needed, no leak possible, and dedup never silently lost.
_COMPLETED_FILE_MAX = 8192
_COMPLETED_FILE: dict[tuple[str, str, str], None] = {}
_COMPLETED_CUSTOM: set[tuple[str, str, str]] = set()
_COMPLETED_IDEMPOTENCY_LOCK = threading.Lock()
_TRACKED_CUSTOM_TOKENS: set[str] = set()

#: Stable per-store tokens that never reuse ``id()`` addresses. A token is
#: pinned to the store object itself so a garbage-collected store cannot hand
#: its identity to a later object allocated at the same address. Stores that
#: cannot pin attributes (C slots) get a fresh counter token per call — the
#: counter alone guarantees uniqueness, and nothing is retained, so there is
#: no map to leak.
_STORE_TOKEN_COUNTER = 0
_STORE_TOKEN_GUARD = threading.Lock()


def _store_path(store: JournalStore) -> Path | None:
    """Filesystem path behind *store*, or None for non-file stores."""
    try:
        path = store.path
    except Exception:
        return None
    return path if isinstance(path, Path) else None


def _has_atomic_append(store: JournalStore) -> bool:
    """Whether *store* supports reservation under one file lock."""
    return callable(getattr(store, "append_event_atomic", None))


def _journal_key(store: JournalStore) -> str:
    path = _store_path(store)
    if path is not None and isinstance(store, (FileJournal,)):
        try:
            return f"file:{path.resolve()}"
        except OSError:
            return f"file:{path}"
    if path is not None and _has_atomic_append(store):
        try:
            return f"file:{path.resolve()}"
        except OSError:
            return f"file:{path}"
    try:
        existing = getattr(store, "__interceptor_store_token__", None)
        if isinstance(existing, str) and existing:
            return existing
    except Exception:  # noqa: S110 - probing for a cached token must not fail
        pass
    try:
        import uuid as _uuid

        token = f"store:{_uuid.uuid4().hex}"
        try:
            store.__interceptor_store_token__ = token  # type: ignore[attr-defined]
        except Exception:
            global _STORE_TOKEN_COUNTER
            with _STORE_TOKEN_GUARD:
                _STORE_TOKEN_COUNTER += 1
                token = f"store:unattached-{_STORE_TOKEN_COUNTER}"
        return token
    except Exception:
        return f"store:{type(store).__name__}:{id(store)}"


def _purge_custom_token(token: str) -> None:
    """Drop every completion triple namespaced to a collected custom store."""
    try:
        with _COMPLETED_IDEMPOTENCY_LOCK:
            _COMPLETED_CUSTOM.difference_update(
                {triple for triple in _COMPLETED_CUSTOM if triple[0] == token}
            )
            _TRACKED_CUSTOM_TOKENS.discard(token)
    except Exception:  # noqa: S110 - GC callbacks must never raise, even at shutdown
        pass


def _track_custom_store(store: JournalStore, token: str) -> None:
    """Purge *token*'s triples when *store* is collected (once per token).

    Stores that cannot take a weakref (C slots without ``__weakref__``) keep
    today's behavior — their triples live with the process — rather than
    failing a call that already succeeded.
    """
    if token in _TRACKED_CUSTOM_TOKENS:
        return
    try:
        import weakref as _weakref

        _weakref.finalize(store, _purge_custom_token, token)
    except TypeError:
        return
    _TRACKED_CUSTOM_TOKENS.add(token)


def _mark_completed(store: JournalStore, action_name: str, idempotency_key: str) -> None:
    with _COMPLETED_IDEMPOTENCY_LOCK:
        triple = (_journal_key(store), action_name, idempotency_key)
        if triple[0].startswith("file:"):
            _COMPLETED_FILE[triple] = None
            while len(_COMPLETED_FILE) > _COMPLETED_FILE_MAX:
                _COMPLETED_FILE.pop(next(iter(_COMPLETED_FILE)))
        else:
            _COMPLETED_CUSTOM.add(triple)
    if not triple[0].startswith("file:"):
        _track_custom_store(store, triple[0])


def _is_completed(store: JournalStore, action_name: str, idempotency_key: str) -> bool:
    with _COMPLETED_IDEMPOTENCY_LOCK:
        triple = (_journal_key(store), action_name, idempotency_key)
        if triple[0].startswith("file:"):
            return triple in _COMPLETED_FILE
        return triple in _COMPLETED_CUSTOM


def reset_idempotency_state() -> None:
    """Forget in-process completions. For tests only."""
    with _COMPLETED_IDEMPOTENCY_LOCK:
        _COMPLETED_FILE.clear()
        _COMPLETED_CUSTOM.clear()
        _TRACKED_CUSTOM_TOKENS.clear()


def _resolve_idempotency_key(
    spec: IdempotencyKeySpec, bound_arguments: dict[str, Any], action_name: str
) -> str | None:
    """The concrete idempotency key for this call, or None when disabled."""
    if spec is None:
        return None
    if callable(spec):
        try:
            raw = spec(dict(bound_arguments))
        except Exception as exc:
            raise ContractError(
                f"idempotency key function failed for action {action_name!r}: {exc}"
            ) from exc
        if raw is None:
            raise ContractError(
                f"idempotency key function for action {action_name!r} returned None; "
                "return a non-empty key (a None spec disables idempotency, "
                "a None return does not)"
            )
    elif spec in bound_arguments:
        raw = bound_arguments[spec]
    else:
        raw = spec
    key = raw if isinstance(raw, str) else str(raw)
    if not key:
        raise ContractError(
            f"idempotency key for action {action_name!r} resolved to empty; provide a non-empty key"
        )
    return key


def _resolve_spend_cents(
    spec: SpendExtractor, bound_arguments: dict[str, Any], action_name: str
) -> int | None:
    """The declared spend for this call in minor units, or None when undeclared."""
    if spec is None:
        return None
    try:
        raw = spec(dict(bound_arguments))
    except Exception as exc:
        raise ContractError(f"spend extractor failed for action {action_name!r}: {exc}") from exc
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ContractError(
            f"spend for action {action_name!r} must be a non-negative int of minor units, "
            f"got {type_name(raw)}"
        )
    if raw < 0:
        raise ContractError(f"spend for action {action_name!r} must be non-negative, got {raw}")
    return raw


def execute_sync(
    *,
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
    dry_run: bool = False,
    idempotency_key: IdempotencyKeySpec = None,
    receipt_from: ReceiptExtractor = None,
    spend_from: SpendExtractor = None,
) -> Any:
    """Guard one synchronous invocation of *target* and return its result."""
    store, active_identity, decision_event, redacted_values, is_dry_run = _prepare_execution(
        args=args,
        kwargs=kwargs,
        contract=contract,
        sensitive=sensitive,
        patterns=patterns,
        canonical_metadata=canonical_metadata,
        signature=signature,
        journal=journal,
        approval_provider=approval_provider,
        identity=identity,
        observer=observer,
        dry_run=dry_run,
        idempotency_key=idempotency_key,
        spend_from=spend_from,
    )
    if is_dry_run:
        return None
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
            patterns=patterns,
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
        patterns=patterns,
        receipt_from=receipt_from,
    )
    if decision_event.get("idempotency_key"):
        _mark_completed(store, contract.action_name, str(decision_event["idempotency_key"]))
    return result


async def execute_async(
    *,
    target: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
    dry_run: bool = False,
    idempotency_key: IdempotencyKeySpec = None,
    receipt_from: ReceiptExtractor = None,
    spend_from: SpendExtractor = None,
) -> Any:
    """Guard one asynchronous invocation of *target* and return its result."""
    store, active_identity, decision_event, redacted_values, is_dry_run = _prepare_execution(
        args=args,
        kwargs=kwargs,
        contract=contract,
        sensitive=sensitive,
        patterns=patterns,
        canonical_metadata=canonical_metadata,
        signature=signature,
        journal=journal,
        approval_provider=approval_provider,
        identity=identity,
        observer=observer,
        dry_run=dry_run,
        idempotency_key=idempotency_key,
        spend_from=spend_from,
    )
    if is_dry_run:
        return None
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
            patterns=patterns,
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
        patterns=patterns,
        receipt_from=receipt_from,
    )
    if decision_event.get("idempotency_key"):
        _mark_completed(store, contract.action_name, str(decision_event["idempotency_key"]))
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
    patterns: tuple[re.Pattern[str], ...],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
    dry_run: bool = False,
    idempotency_key: IdempotencyKeySpec = None,
    spend_from: SpendExtractor = None,
) -> tuple[JournalStore, SigningIdentity, dict[str, Any], tuple[str, ...], bool]:
    """Everything that must happen before the guarded callable runs.

    Returns ``(store, active_identity, decision_event, redacted_values, is_dry_run)``.
    Raises ``ActionDenied`` (after the signed decision event) on denial, and
    ``DuplicateActionError`` when an idempotency key already completed.
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
    canonical_input, redacted_values = canonicalize(dict(bound.arguments), sensitive, patterns)
    input_hash = sha256_hex(canonical_json_bytes(canonical_input))
    input_summary = bounded_summary(canonical_input)

    # 4. Idempotency key + spend declaration + signing identity (fail closed
    # before prompting).
    resolved_key = _resolve_idempotency_key(
        idempotency_key, dict(bound.arguments), contract.action_name
    )
    spend_cents = _resolve_spend_cents(spend_from, dict(bound.arguments), contract.action_name)
    active_identity = identity or LocalSigningIdentity.load_or_create()
    store = _resolve_journal(journal)

    def _duplicate_extra(prior_id: str | None) -> dict[str, Any]:
        extra: dict[str, Any] = {
            "decision": DECISION_DENIED,
            "risk": contract.risk,
            "approval_mode": contract.approval_mode,
            "redacted_input_summary": input_summary,
            "parameter_retention": _parameter_retention(canonical_input),
            "input_hash": input_hash,
            "idempotency_key": resolved_key,
            "approval_reason": "duplicate idempotency key; already reserved or completed",
        }
        if spend_cents is not None:
            extra["spend_cents"] = spend_cents
        if prior_id is not None:
            extra["duplicate_of"] = prior_id
        if canonical_metadata is not None:
            extra["metadata"] = canonical_metadata
        return extra

    # 5. Duplicate pre-check, before approval so obvious duplicates never prompt.
    # Blocking covers succeeded outcomes AND in-progress allowed decisions (no
    # outcome yet), so concurrent duplicates cannot both execute. Failed and
    # dry-run decisions never block. The authoritative check is atomic under
    # file lock after approval (step 7); this pre-check is best-effort UX.
    if resolved_key is not None:
        pre_prior_id: str | None = None
        store_path = _store_path(store)
        if _is_completed(store, contract.action_name, resolved_key):
            pre_prior_id = None
        elif store_path is not None:
            try:
                completed = find_completed_idempotent_decision(
                    store_path, contract.action_name, resolved_key
                )
            except Exception:
                completed = None
            if completed is not None:
                raw_id = completed.get("event_id")
                pre_prior_id = raw_id if isinstance(raw_id, str) else None
                _mark_completed(store, contract.action_name, resolved_key)
            else:
                try:
                    blocking = find_blocking_idempotent_decision(
                        store_path, contract.action_name, resolved_key
                    )
                except Exception:
                    blocking = None
                if blocking is not None:
                    raw_id = blocking.get("event_id")
                    pre_prior_id = raw_id if isinstance(raw_id, str) else None
        if pre_prior_id is not None or _is_completed(store, contract.action_name, resolved_key):
            _append_event(
                store,
                active_identity,
                contract,
                EVENT_TYPE_DECISION,
                _duplicate_extra(pre_prior_id),
            )
            raise DuplicateActionError(contract.action_name, resolved_key, pre_prior_id)

    # 6. Approval.
    request = ApprovalRequest(
        action_name=contract.action_name,
        risk=contract.risk,
        approval_mode=contract.approval_mode,
        redacted_input_summary=input_summary,
        input_hash=input_hash,
        contract_hash=contract.contract_hash,
        spend_cents=spend_cents,
    )
    decision = _evaluate_approval(request, contract, approval_provider)

    # 7. Signed decision event, durably appended BEFORE execution.
    # For file journals with an idempotency key, the blocking re-check and the
    # append happen under one OS file lock: only the first concurrent racer
    # appends ``allowed``; the loser appends a denied duplicate and raises.
    def _allowed_extra() -> dict[str, Any]:
        extra: dict[str, Any] = {
            "decision": decision.decision,
            "risk": contract.risk,
            "approval_mode": contract.approval_mode,
            "redacted_input_summary": input_summary,
            "parameter_retention": _parameter_retention(canonical_input),
            "input_hash": input_hash,
            "approval_reason": scrub_text(decision.reason, redacted_values, patterns),
        }
        if decision.approved_by:
            extra["approved_by"] = scrub_text(
                decision.approved_by, redacted_values, patterns, max_chars=120
            )
        if resolved_key is not None:
            extra["idempotency_key"] = resolved_key
        if spend_cents is not None:
            extra["spend_cents"] = spend_cents
        if dry_run:
            extra["dry_run"] = True
        if canonical_metadata is not None:
            extra["metadata"] = canonical_metadata
        return extra

    decision_event: dict[str, Any]
    if resolved_key is not None and _has_atomic_append(store):
        atomic_duplicate_of: str | None = None
        atomic_is_duplicate = False

        def _build_atomic(
            previous_hash: str | None, blocking_prior_id: str | None
        ) -> dict[str, Any]:
            nonlocal atomic_duplicate_of, atomic_is_duplicate
            # Re-check the in-process set inside the file lock (double-checked).
            in_process_blocked = _is_completed(store, contract.action_name, resolved_key)
            effective_prior = blocking_prior_id
            if effective_prior is None and in_process_blocked:
                effective_prior = None
            if effective_prior is not None or in_process_blocked:
                atomic_is_duplicate = True
                atomic_duplicate_of = effective_prior
                payload: dict[str, Any] = {
                    "schema_version": EVENT_SCHEMA_VERSION,
                    "event_type": EVENT_TYPE_DECISION,
                    "event_id": new_event_id(),
                    "action_id": contract.action_id,
                    "action_name": contract.action_name,
                    "contract_hash": contract.contract_hash,
                    "timestamp_utc": utc_timestamp(),
                    "key_id": active_identity.key_id,
                    "previous_event_hash": previous_hash,
                }
                payload.update(_duplicate_extra(effective_prior))
                return finalize_event(payload, active_identity.sign)
            payload = {
                "schema_version": EVENT_SCHEMA_VERSION,
                "event_type": EVENT_TYPE_DECISION,
                "event_id": new_event_id(),
                "action_id": contract.action_id,
                "action_name": contract.action_name,
                "contract_hash": contract.contract_hash,
                "timestamp_utc": utc_timestamp(),
                "key_id": active_identity.key_id,
                "previous_event_hash": previous_hash,
            }
            payload.update(_allowed_extra())
            return finalize_event(payload, active_identity.sign)

        atomic_store: Any = store
        decision_event = atomic_store.append_event_atomic(
            _build_atomic,
            action_name=contract.action_name,
            idempotency_key=resolved_key,
        )
        if atomic_is_duplicate:
            raise DuplicateActionError(contract.action_name, resolved_key, atomic_duplicate_of)
    else:
        # Non-file stores: close the thread race with a post-approval check.
        if resolved_key is not None and _is_completed(store, contract.action_name, resolved_key):
            _append_event(
                store, active_identity, contract, EVENT_TYPE_DECISION, _duplicate_extra(None)
            )
            raise DuplicateActionError(contract.action_name, resolved_key, None)
        decision_event = _append_event(
            store,
            active_identity,
            contract,
            EVENT_TYPE_DECISION,
            _allowed_extra(),
        )

    if not decision.allowed:
        raise ActionDenied(
            contract.action_name,
            f"action denied: {contract.action_name} ({decision.reason})",
        )

    return store, active_identity, decision_event, redacted_values, dry_run


def _evaluate_approval(
    request: ApprovalRequest,
    contract: ActionContract,
    provider: ApprovalProvider | None,
) -> ApprovalDecision:
    if contract.approval_mode == "never":
        if provider is not None and not isinstance(provider, AutoAllowProvider):
            raise ContractError(
                "approval='never' ignores any approval_provider; remove the provider "
                "or use approval='required' so budgets, quorum, and attribution "
                "actually enforce (decoration-time checks cover @guard/wrap_tool; "
                "this covers raw-engine use)"
            )
        active: ApprovalProvider = AutoAllowProvider()
    else:
        active = provider or TerminalApprovalProvider()
    try:
        decision = active.decide(request)
    except InterceptorError:
        raise
    except Exception as exc:
        raise ApprovalError(
            f"approval provider failed for action {contract.action_name!r}: "
            f"{type_name(exc)}; failing closed"
        ) from exc
    try:
        verdict = decision.decision
    except AttributeError as exc:
        raise ApprovalError(
            f"approval provider returned {type_name(decision)} instead of an "
            f"ApprovalDecision; failing closed"
        ) from exc
    if verdict not in (DECISION_ALLOWED, DECISION_DENIED):
        raise ApprovalError(
            f"approval provider returned invalid decision {verdict!r}; failing closed"
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
    patterns: tuple[re.Pattern[str], ...] = (),
    receipt_from: ReceiptExtractor = None,
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
        output_hash = _safe_output_hash(result, redacted_values, sensitive, patterns)
        if output_hash is not None:
            extra["redacted_output_hash"] = output_hash
        receipt = _extract_receipt(receipt_from, result, sensitive, patterns)
        if receipt is not None:
            extra["receipt"] = receipt
    else:
        assert exception is not None
        extra["observed_result_type"] = None
        extra["exception_type"] = type_name(exception)
        extra["sanitized_error_summary"] = scrub_text(str(exception), redacted_values, patterns)

    try:
        _append_event(store, identity, contract, EVENT_TYPE_OUTCOME, extra)
    except EventShipError as ship_exc:
        # The local outcome IS durable; only a witness copy is missing. Report
        # that precisely (with the result attached) instead of claiming the
        # outcome could not be persisted. Retry is unsafe: the side effect ran.
        raise EventShipError(
            f"action {contract.action_name!r} EXECUTED and its outcome was recorded "
            f"locally, but a witness sink failed ({ship_exc}). Backfill the witness "
            "before relying on off-host evidence.",
            decision_event_id=decision_event["event_id"],
            result=result,
            executed=True,
            retry_safe=False,
            function_outcome=status,
            action_id=contract.action_id,
        ) from ship_exc
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
    patterns: tuple[re.Pattern[str], ...] = (),
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
    if isinstance(result, str) and any(p.search(result) is not None for p in patterns):
        return None
    try:
        canonical = canonicalize(result, sensitive, patterns).value
        return sha256_hex(canonical_json_bytes(canonical))
    except CanonicalizationError:
        return None


def _make_sync_wrapper(
    target: Callable[..., Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
    dry_run: bool = False,
    idempotency_key: IdempotencyKeySpec = None,
    receipt_from: ReceiptExtractor = None,
    spend_from: SpendExtractor = None,
) -> Callable[..., Any]:
    """Build a synchronous wrapper delegating to the shared guard engine."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return execute_sync(
            target=target,
            args=args,
            kwargs=kwargs,
            contract=contract,
            sensitive=sensitive,
            patterns=patterns,
            canonical_metadata=canonical_metadata,
            signature=signature,
            journal=journal,
            approval_provider=approval_provider,
            identity=identity,
            observer=observer,
            dry_run=dry_run,
            idempotency_key=idempotency_key,
            receipt_from=receipt_from,
            spend_from=spend_from,
        )

    return wrapper


def _make_async_wrapper(
    target: Callable[..., Any],
    contract: ActionContract,
    sensitive: frozenset[str],
    patterns: tuple[re.Pattern[str], ...],
    canonical_metadata: Any,
    signature: inspect.Signature,
    journal: str | Path | JournalStore | None,
    approval_provider: ApprovalProvider | None,
    identity: SigningIdentity | None,
    observer: ActionObserver | None,
    dry_run: bool = False,
    idempotency_key: IdempotencyKeySpec = None,
    receipt_from: ReceiptExtractor = None,
    spend_from: SpendExtractor = None,
) -> Callable[..., Any]:
    """Build an asynchronous wrapper delegating to the shared guard engine."""

    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        return await execute_async(
            target=target,
            args=args,
            kwargs=kwargs,
            contract=contract,
            sensitive=sensitive,
            patterns=patterns,
            canonical_metadata=canonical_metadata,
            signature=signature,
            journal=journal,
            approval_provider=approval_provider,
            identity=identity,
            observer=observer,
            dry_run=dry_run,
            idempotency_key=idempotency_key,
            receipt_from=receipt_from,
            spend_from=spend_from,
        )

    return wrapper
