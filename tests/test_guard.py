"""End-to-end behaviour of the guard: ordering, fail-closed, evidence."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import interceptor as ge
from helpers import RecordingObserver, StaticProvider, allow, deny
from interceptor import guard
from interceptor.identity import LocalSigningIdentity, load_public_key
from interceptor.journal import JournalStore
from interceptor.verification import verify_journal


def events(home: Path) -> list[dict]:
    path = home / "journal.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --- the happy path ---------------------------------------------------------


def test_records_decision_then_outcome(evidence_home):
    @guard(action="test.basic", approval_provider=allow())
    def act(amount: int) -> dict:
        return {"ok": amount}

    assert act(5) == {"ok": 5}

    recorded = events(evidence_home)
    assert [e["event_type"] for e in recorded] == ["decision", "outcome"]
    assert recorded[1]["status"] == "succeeded"
    assert recorded[1]["decision_event_id"] == recorded[0]["event_id"]


def test_return_value_is_untouched(evidence_home):
    sentinel = object()

    @guard(action="test.identity", approval_provider=allow())
    def act():
        return sentinel

    assert act() is sentinel


def test_decision_is_recorded_before_execution(evidence_home):
    """The decision must be durable before the side effect, not after."""
    seen_during_execution: list[int] = []

    @guard(action="test.ordering", approval_provider=allow())
    def act():
        seen_during_execution.append(len(events(evidence_home)))

    act()
    assert seen_during_execution == [1], "decision event was not durable before execution"


# --- fail closed ------------------------------------------------------------


def test_denied_action_does_not_execute(evidence_home):
    executed = []

    @guard(action="test.denied", approval_provider=deny())
    def act():
        executed.append(True)

    with pytest.raises(ge.ActionDenied):
        act()

    assert executed == []
    recorded = events(evidence_home)
    assert [e["event_type"] for e in recorded] == ["decision"]
    assert recorded[0]["decision"] == "denied"


def test_approval_provider_failure_fails_closed(evidence_home):
    class Exploding:
        def decide(self, request):
            raise RuntimeError("provider is down")

    executed = []

    @guard(action="test.provider_down", approval_provider=Exploding())
    def act():
        executed.append(True)

    with pytest.raises(ge.ApprovalError):
        act()
    assert executed == []


def test_invalid_decision_value_fails_closed(evidence_home):
    executed = []

    @guard(action="test.bad_decision", approval_provider=StaticProvider("maybe"))
    def act():
        executed.append(True)

    with pytest.raises(ge.ApprovalError):
        act()
    assert executed == []


def test_non_tty_without_provider_fails_closed(evidence_home, monkeypatch):
    executed = []

    @guard(action="test.no_tty")
    def act():
        executed.append(True)

    with pytest.raises(ge.ApprovalUnavailableError):
        act()
    assert executed == []


def test_approval_never_skips_the_prompt_but_not_the_evidence(evidence_home):
    @guard(action="test.never", approval="never")
    def act():
        return "ran"

    assert act() == "ran"
    assert [e["event_type"] for e in events(evidence_home)] == ["decision", "outcome"]


# --- failures inside the guarded function -----------------------------------


def test_function_exception_is_reraised_and_recorded(evidence_home):
    @guard(action="test.raises", approval_provider=allow())
    def act():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        act()

    outcome = events(evidence_home)[1]
    assert outcome["status"] == "failed"
    assert outcome["exception_type"] == "builtins.ValueError"
    assert "boom" in outcome["sanitized_error_summary"]


def test_malformed_call_records_nothing(evidence_home):
    @guard(action="test.binding", approval_provider=allow())
    def act(a: int, b: int):
        return a + b

    with pytest.raises(TypeError):
        act(1)  # missing b

    assert events(evidence_home) == []


def test_evidence_failure_after_execution_is_distinct(evidence_home):
    """The caller must be able to tell "did not run" from "ran, unrecorded"."""
    calls = []

    class FailsOnOutcome(JournalStore):
        def __init__(self) -> None:
            self._real = ge.FileJournal(evidence_home / "journal.jsonl")
            self.appends = 0

        @property
        def path(self) -> Path:
            return self._real.path

        def append_event(self, build):
            self.appends += 1
            if self.appends > 1:
                raise ge.JournalError("disk full")
            return self._real.append_event(build)

    @guard(action="test.evidence_fail", approval_provider=allow(), journal=FailsOnOutcome())
    def act():
        calls.append(True)
        return "side effect happened"

    with pytest.raises(ge.ExecutionCompletedEvidenceError) as caught:
        act()

    assert calls == [True], "the function must have run"
    assert caught.value.function_outcome == "succeeded"
    assert "not retried" in str(caught.value)


# --- observer ---------------------------------------------------------------


def test_no_observer_means_no_outward_call(evidence_home):
    @guard(action="test.no_observer", approval_provider=allow())
    def act():
        return "ok"

    assert act() == "ok"  # the autouse socket guard would have raised


def test_observer_notified_once_per_contract(evidence_home):
    observer = RecordingObserver()

    @guard(action="test.observed", approval_provider=allow(), observer=observer)
    def act():
        return "ok"

    for _ in range(5):
        act()

    assert observer.calls == 1
    assert observer.contracts[0].action_name == "test.observed"


def test_observer_failure_prevents_execution(evidence_home):
    executed = []
    observer = RecordingObserver(fail_with=RuntimeError("registry unreachable"))

    @guard(action="test.observer_fails", approval_provider=allow(), observer=observer)
    def act():
        executed.append(True)

    with pytest.raises(RuntimeError, match="registry unreachable"):
        act()

    assert executed == []
    assert events(evidence_home) == []


def test_failing_observer_does_not_fail_open_on_retry(evidence_home):
    """Marking a contract seen before the call succeeds would skip it next time."""
    executed = []
    observer = RecordingObserver(fail_with=RuntimeError("still down"))

    @guard(action="test.observer_retry", approval_provider=allow(), observer=observer)
    def act():
        executed.append(True)

    for _ in range(3):
        with pytest.raises(RuntimeError):
            act()

    assert observer.calls == 3, "a failing observer must be retried, not skipped"
    assert executed == []


# --- contracts and metadata -------------------------------------------------


def test_contract_is_attached_and_stable(evidence_home):
    @guard(action="test.contract", risk="high", approval_provider=allow())
    def act(a: int, b: str = "x"):
        return None

    contract = act.__interceptor_contract__
    assert contract.action_name == "test.contract"
    assert contract.risk == "high"
    assert contract.execution_mode == "embedded"
    assert [p.name for p in contract.parameter_descriptors] == ["a", "b"]
    assert len(contract.contract_hash) == 64


def test_metadata_is_redacted_and_recorded(evidence_home):
    @guard(
        action="test.metadata",
        approval_provider=allow(),
        metadata={"team": "payments", "api_key": "sk-META-SECRET"},
    )
    def act():
        return None

    act()
    decision = events(evidence_home)[0]
    assert decision["metadata"]["team"] == "payments"
    assert decision["metadata"]["api_key"] == "<REDACTED>"
    assert "sk-META-SECRET" not in (evidence_home / "journal.jsonl").read_text()


def test_generator_functions_are_rejected():
    with pytest.raises(ge.UnsupportedFunctionError):

        @guard(action="test.gen")
        def gen():
            yield 1

    with pytest.raises(ge.UnsupportedFunctionError):

        @guard(action="test.agen")
        async def agen():
            yield 1


# --- async ------------------------------------------------------------------


def test_async_success_records_evidence_and_redacts(evidence_home, allow_socket_creation):
    @guard(action="test.async.ok", approval_provider=allow(), redact=["api_key"])
    async def act(customer_id: str, api_key: str) -> dict:
        return {"ok": True}

    result = asyncio.run(act("c1", "sk-ASYNC-SECRET"))
    assert result == {"ok": True}

    recorded = events(evidence_home)
    assert [e["event_type"] for e in recorded] == ["decision", "outcome"]
    assert recorded[1]["status"] == "succeeded"
    assert recorded[0]["redacted_input_summary"] == 'api_key="<REDACTED>", customer_id="c1"'
    assert recorded[0]["parameter_retention"] == [
        {"name": "api_key", "state": "redacted"},
        {"name": "customer_id", "state": "retained"},
    ]
    assert "sk-ASYNC-SECRET" not in (evidence_home / "journal.jsonl").read_text()


def test_async_failure_records_failed_outcome(evidence_home, allow_socket_creation):
    @guard(action="test.async.fail", approval_provider=allow())
    async def fail(customer_id: str) -> None:
        raise ValueError("async boom")

    with pytest.raises(ValueError, match="async boom"):
        asyncio.run(fail("c1"))

    outcome = events(evidence_home)[1]
    assert outcome["status"] == "failed"
    assert outcome["exception_type"] == "builtins.ValueError"


def test_async_denied_does_not_execute(evidence_home, allow_socket_creation):
    executed: list[bool] = []

    @guard(action="test.async.denied", approval_provider=deny())
    async def act(x: int) -> int:
        executed.append(True)
        return x

    with pytest.raises(ge.ActionDenied):
        asyncio.run(act(1))

    assert executed == []


def test_async_wrapper_is_detected_as_async():
    @guard(action="test.async.detect")
    async def act() -> None:
        return None

    assert asyncio.iscoroutinefunction(act)


def test_bare_decorator_form_applies_the_safe_defaults(evidence_home):
    """``@guard`` with no parentheses must decorate, not return a decorator."""

    @guard
    def act():
        return "ok"

    contract = act.__interceptor_contract__
    assert contract.risk == "medium"
    assert contract.approval_mode == "required"
    # Default name is the code location: module + qualified name.
    assert contract.action_name.startswith("test_guard.")
    assert contract.action_name.endswith(".act")

    # Defaulting to required approval off a TTY means it fails closed, which is
    # the observable proof that the bare form did not skip the defaults.
    with pytest.raises(ge.ApprovalUnavailableError):
        act()


def test_bare_and_called_forms_produce_the_same_contract(evidence_home):
    @guard
    def bare(a: int, b: str = "x"):
        return None

    @guard()
    def called(a: int, b: str = "x"):
        return None

    bare_contract = bare.__interceptor_contract__
    called_contract = called.__interceptor_contract__
    assert bare_contract.risk == called_contract.risk
    assert bare_contract.approval_mode == called_contract.approval_mode
    assert [p.name for p in bare_contract.parameter_descriptors] == [
        p.name for p in called_contract.parameter_descriptors
    ]


# --- the whole thing verifies offline ---------------------------------------


def test_full_flow_verifies(evidence_home):
    @guard(action="test.verify.ok", approval_provider=allow())
    def good():
        return 1

    @guard(action="test.verify.denied", approval_provider=deny())
    def denied():
        raise AssertionError("must not run")

    @guard(action="test.verify.fails", approval_provider=allow())
    def fails():
        raise ValueError("x")

    good()
    with pytest.raises(ge.ActionDenied):
        denied()
    with pytest.raises(ValueError):
        fails()

    identity = LocalSigningIdentity.load_or_create()
    result = verify_journal(
        evidence_home / "journal.jsonl", load_public_key(identity.public_key_path)
    )
    assert result.valid, result.issues
    assert result.events_verified == 5
