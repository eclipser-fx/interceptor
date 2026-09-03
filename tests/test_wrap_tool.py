"""``wrap_tool`` / ``wrap_tools``: the same guard engine for existing callables.

This file exists because the wrapped-tools API is a public surface with its own
semantics (no source edits, async support, collection wrapping) and was shipped
untested — a regression that is easy to reintroduce by changing the shared
engine and forgetting the wrappers.
"""

from __future__ import annotations

import asyncio
import functools
import json
from pathlib import Path

import pytest

import interceptor as ge
from helpers import RecordingObserver, allow, deny
from interceptor import guard, wrap_tool, wrap_tools
from interceptor.identity import LocalSigningIdentity, load_public_key
from interceptor.verification import verify_journal


def events(home: Path) -> list[dict]:
    path = home / "journal.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def verify(home: Path):
    identity = LocalSigningIdentity.load_or_create()
    return verify_journal(home / "journal.jsonl", load_public_key(identity.public_key_path))


# --- the happy path ---------------------------------------------------------


def test_wrap_tool_records_decision_then_outcome(evidence_home):
    def refund(customer_id: str, amount_cents: int) -> dict:
        return {"ok": amount_cents}

    wrapped = wrap_tool(refund, action="billing.refund", approval_provider=allow())
    assert wrapped("c1", 100) == {"ok": 100}

    recorded = events(evidence_home)
    assert [e["event_type"] for e in recorded] == ["decision", "outcome"]
    assert recorded[1]["status"] == "succeeded"
    assert recorded[1]["decision_event_id"] == recorded[0]["event_id"]


def test_wrap_tool_returns_original_result_untouched(evidence_home):
    sentinel = object()

    def act() -> object:
        return sentinel

    wrapped = wrap_tool(act, action="test.identity", approval_provider=allow())
    assert wrapped() is sentinel


def test_wrap_tool_does_not_mutate_the_original(evidence_home):
    def refund(customer_id: str) -> str:
        return customer_id

    wrapped = wrap_tool(refund, action="test.no.mutate", approval_provider=allow())
    assert not hasattr(refund, "__interceptor_contract__")
    assert hasattr(wrapped, "__interceptor_contract__")
    assert wrapped("x") == "x"
    assert refund("x") == "x"


def test_wrap_tool_decision_recorded_before_execution(evidence_home):
    seen: list[int] = []

    def act() -> None:
        seen.append(len(events(evidence_home)))

    wrapped = wrap_tool(act, action="test.ordering", approval_provider=allow())
    wrapped()
    assert seen == [1], "decision event was not durable before execution"


# --- fail closed ------------------------------------------------------------


def test_wrap_tool_denied_does_not_execute(evidence_home):
    executed: list[bool] = []

    def act(x: int) -> int:
        executed.append(True)
        return x

    wrapped = wrap_tool(act, action="test.wrap.denied", approval_provider=deny())
    with pytest.raises(ge.ActionDenied):
        wrapped(1)

    assert executed == []
    assert [e["event_type"] for e in events(evidence_home)] == ["decision"]
    assert events(evidence_home)[0]["decision"] == "denied"


def test_wrap_tool_provider_failure_fails_closed(evidence_home):
    class Exploding:
        def decide(self, request):
            raise RuntimeError("provider is down")

    executed: list[bool] = []

    def act(x: int) -> int:
        executed.append(True)
        return x

    wrapped = wrap_tool(act, action="test.wrap.down", approval_provider=Exploding())
    with pytest.raises(ge.ApprovalError):
        wrapped(1)
    assert executed == []


def test_wrap_tool_off_tty_without_provider_fails_closed(evidence_home):
    def act(x: int) -> int:
        return x

    wrapped = wrap_tool(act, action="test.wrap.no_tty")
    with pytest.raises(ge.ApprovalUnavailableError):
        wrapped(1)


def test_wrap_tool_approval_never_skips_the_prompt_but_not_the_evidence(evidence_home):
    def act(x: int) -> int:
        return x

    wrapped = wrap_tool(act, action="test.wrap.never", approval="never")
    assert wrapped(1) == 1
    assert [e["event_type"] for e in events(evidence_home)] == ["decision", "outcome"]


# --- failures inside the wrapped callable -----------------------------------


def test_wrap_tool_exception_is_reraised_and_recorded(evidence_home):
    def act(x: int) -> int:
        raise ValueError("boom")

    wrapped = wrap_tool(act, action="test.wrap.raises", approval_provider=allow())
    with pytest.raises(ValueError, match="boom"):
        wrapped(1)

    outcome = events(evidence_home)[1]
    assert outcome["status"] == "failed"
    assert outcome["exception_type"] == "builtins.ValueError"
    assert "boom" in outcome["sanitized_error_summary"]


def test_wrap_tool_malformed_call_records_nothing(evidence_home):
    def act(a: int, b: int) -> int:
        return a + b

    wrapped = wrap_tool(act, action="test.wrap.binding", approval_provider=allow())
    with pytest.raises(TypeError):
        wrapped(1)  # missing b

    assert events(evidence_home) == []


# --- redaction and metadata -------------------------------------------------


def test_wrap_tool_redacts_named_secrets(evidence_home):
    def refund(customer_id: str, api_key: str) -> str:
        return customer_id

    wrapped = wrap_tool(refund, action="test.wrap.redact", approval_provider=allow())
    wrapped("c1", "sk-LIVE-TOP-SECRET")

    text = (evidence_home / "journal.jsonl").read_text()
    assert "sk-LIVE-TOP-SECRET" not in text
    assert "<REDACTED>" in text


def test_wrap_tool_custom_redact_names(evidence_home):
    def verify(user_id: str, pin: str) -> str:
        return user_id

    wrapped = wrap_tool(verify, action="test.wrap.pin", redact=["pin"], approval_provider=allow())
    wrapped("u1", "1234")

    text = (evidence_home / "journal.jsonl").read_text()
    assert "1234" not in text


def test_wrap_tool_records_redacted_metadata(evidence_home):
    def act(x: int) -> int:
        return x

    wrapped = wrap_tool(
        act,
        action="test.wrap.meta",
        approval_provider=allow(),
        metadata={"team": "payments", "api_key": "sk-META-SECRET"},
    )
    wrapped(1)

    decision = events(evidence_home)[0]
    assert decision["metadata"]["team"] == "payments"
    assert decision["metadata"]["api_key"] == "<REDACTED>"
    assert "sk-META-SECRET" not in (evidence_home / "journal.jsonl").read_text()


# --- observer ---------------------------------------------------------------


def test_wrap_tool_notifies_observer_once(evidence_home):
    observer = RecordingObserver()

    def act(x: int) -> int:
        return x

    wrapped = wrap_tool(act, action="test.wrap.obs", approval_provider=allow(), observer=observer)
    for _ in range(3):
        wrapped(1)

    assert observer.calls == 1
    assert observer.contracts[0].action_name == "test.wrap.obs"


def test_wrap_tool_observer_failure_prevents_execution(evidence_home):
    executed: list[bool] = []
    observer = RecordingObserver(fail_with=RuntimeError("registry unreachable"))

    def act(x: int) -> int:
        executed.append(True)
        return x

    wrapped = wrap_tool(
        act, action="test.wrap.obs.fail", approval_provider=allow(), observer=observer
    )
    with pytest.raises(RuntimeError, match="registry unreachable"):
        wrapped(1)

    assert executed == []
    assert events(evidence_home) == []


# --- callable shapes --------------------------------------------------------


def test_wrap_tool_handles_bound_method_and_partial(evidence_home):
    class Service:
        def refund(self, customer_id: str) -> str:
            return customer_id

    bound = wrap_tool(Service().refund, action="test.wrap.bound", approval_provider=allow())
    assert bound("c1") == "c1"

    def refund(customer_id: str, amount: int) -> str:
        return customer_id

    partial = wrap_tool(
        functools.partial(refund, amount=10), action="test.wrap.partial", approval_provider=allow()
    )
    assert partial("c1") == "c1"


# --- async ------------------------------------------------------------------


def test_wrap_tool_async_success(evidence_home, allow_socket_creation):
    async def refund(customer_id: str, amount_cents: int) -> dict:
        return {"ok": amount_cents}

    wrapped = wrap_tool(refund, action="billing.refund.async", approval_provider=allow())
    assert asyncio.run(wrapped("c1", 100)) == {"ok": 100}

    recorded = events(evidence_home)
    assert [e["event_type"] for e in recorded] == ["decision", "outcome"]
    assert recorded[1]["status"] == "succeeded"


def test_wrap_tool_async_failure_outcome(evidence_home, allow_socket_creation):
    async def fail(customer_id: str) -> None:
        raise ValueError("async boom")

    wrapped = wrap_tool(fail, action="test.wrap.async.fail", approval_provider=allow())
    with pytest.raises(ValueError, match="async boom"):
        asyncio.run(wrapped("c1"))

    outcome = events(evidence_home)[1]
    assert outcome["status"] == "failed"
    assert outcome["exception_type"] == "builtins.ValueError"


def test_wrap_tool_async_denied_does_not_execute(evidence_home, allow_socket_creation):
    executed: list[bool] = []

    async def act(x: int) -> int:
        executed.append(True)
        return x

    wrapped = wrap_tool(act, action="test.wrap.async.denied", approval_provider=deny())
    with pytest.raises(ge.ActionDenied):
        asyncio.run(wrapped(1))

    assert executed == []
    assert [e["event_type"] for e in events(evidence_home)] == ["decision"]


# --- rejection --------------------------------------------------------------


def test_wrap_tool_rejects_non_callable(evidence_home):
    with pytest.raises(ge.ToolWrapError):
        wrap_tool(42, action="test.notcallable")


def test_wrap_tool_rejects_generators(evidence_home):
    def gen():
        yield 1

    with pytest.raises(ge.ToolWrapError, match="generator"):
        wrap_tool(gen, action="test.gen")


def test_wrap_tool_rejects_async_generators(evidence_home):
    async def agen():
        yield 1

    with pytest.raises(ge.ToolWrapError, match="generator"):
        wrap_tool(agen, action="test.agen")


def test_wrap_tool_rejects_already_guarded(evidence_home):
    @guard(action="test.already.guarded", approval_provider=allow())
    def act(x: int) -> int:
        return x

    with pytest.raises(ge.ToolWrapError, match="already guarded"):
        wrap_tool(act, action="test.wrap.double")


# --- wrap_tools -------------------------------------------------------------


def test_wrap_tools_sequence(evidence_home):
    def refund(customer_id: str) -> str:
        return customer_id

    def deploy(ref: str) -> str:
        return ref

    wrapped = wrap_tools(
        [refund, deploy],
        configuration={
            "refund": {"action": "billing.refund", "approval_provider": allow()},
            "deploy": {"action": "deploy.staging", "approval_provider": allow()},
        },
    )
    assert [w.__name__ for w in wrapped] == ["refund", "deploy"]
    assert wrapped[0]("c1") == "c1"
    assert wrapped[1]("r1") == "r1"
    assert [e["action_name"] for e in events(evidence_home)] == [
        "billing.refund",
        "billing.refund",
        "deploy.staging",
        "deploy.staging",
    ]


def test_wrap_tools_mapping(evidence_home):
    def refund(customer_id: str) -> str:
        return customer_id

    wrapped = wrap_tools(
        {"refund": refund},
        configuration={"refund": {"action": "billing.refund", "approval_provider": allow()}},
    )
    assert wrapped["refund"]("c1") == "c1"
    assert [e["action_name"] for e in events(evidence_home)] == ["billing.refund", "billing.refund"]


def test_wrap_tools_missing_configuration(evidence_home):
    def refund(customer_id: str) -> str:
        return customer_id

    with pytest.raises(ge.ToolWrapError, match="no configuration"):
        wrap_tools([refund], configuration={})


def test_wrap_tools_requires_action(evidence_home):
    def refund(customer_id: str) -> str:
        return customer_id

    with pytest.raises(ge.ToolWrapError, match="must include a"):
        wrap_tools({"refund": refund}, configuration={"refund": {"risk": "high"}})


def test_wrap_tools_duplicate_action_names(evidence_home):
    def a(x: int) -> int:
        return x

    def b(x: int) -> int:
        return x

    with pytest.raises(ge.ToolWrapError, match="duplicate action"):
        wrap_tools(
            {"a": a, "b": b},
            configuration={"a": {"action": "same.action"}, "b": {"action": "same.action"}},
        )


def test_wrap_tools_rejects_non_callable_entry(evidence_home):
    with pytest.raises(ge.ToolWrapError):
        wrap_tools({"x": 42}, configuration={"x": {"action": "a"}})


def test_wrap_tools_does_not_mutate_the_input_collection(evidence_home):
    def refund(customer_id: str) -> str:
        return customer_id

    tools = {"refund": refund}
    wrap_tools(
        tools,
        configuration={"refund": {"action": "billing.refund", "approval_provider": allow()}},
    )
    assert tools["refund"] is refund, "the caller's mapping must not be replaced"


# --- the whole thing verifies offline ---------------------------------------


def test_wrap_tool_full_flow_verifies(evidence_home):
    def good(x: int) -> int:
        return x

    def bad(x: int) -> int:
        raise ValueError("nope")

    good_wrapped = wrap_tool(good, action="test.wrap.ok", approval_provider=allow())
    bad_wrapped = wrap_tool(bad, action="test.wrap.fail", approval_provider=allow())

    assert good_wrapped(1) == 1
    with pytest.raises(ValueError):
        bad_wrapped(2)

    result = verify(evidence_home)
    assert result.valid, result.issues
    assert result.events_verified == 4
