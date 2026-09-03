"""Shared test helpers: approval providers and a recording observer.

Import these as ``from helpers import ...``; the fixtures live in
``conftest.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from interceptor.approval import ApprovalDecision, ApprovalRequest
from interceptor.contracts import ActionContract


@dataclass
class StaticProvider:
    """An approval provider with a fixed answer."""

    decision: str
    reason: str = "test provider"
    seen: list[ApprovalRequest] | None = None

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        if self.seen is None:
            self.seen = []
        self.seen.append(request)
        return ApprovalDecision(self.decision, self.reason)


def allow() -> StaticProvider:
    return StaticProvider("allowed")


def deny() -> StaticProvider:
    return StaticProvider("denied")


class RecordingObserver:
    """Collects the contracts it is told about."""

    def __init__(self, fail_with: Exception | None = None) -> None:
        self.contracts: list[ActionContract] = []
        self.calls = 0
        self._fail_with = fail_with

    def contract_declared(self, contract: ActionContract) -> None:
        self.calls += 1
        if self._fail_with is not None:
            raise self._fail_with
        self.contracts.append(contract)
