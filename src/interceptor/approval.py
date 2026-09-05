"""Local approval for guarded actions.

The default provider prompts on the controlling terminal. It shows only the
action name, declared risk, and the bounded redacted input summary — never
raw arguments, never ``repr()`` of arbitrary objects, never secrets.

The decision defaults to **deny**: only an explicit affirmative response
(``y`` / ``yes``, case-insensitive) approves. When approval is required and
stdin is not an interactive terminal (CI, cron, piped agent output) and no
explicit provider was configured, the guard fails closed with
:class:`~interceptor.errors.ApprovalUnavailableError`.

``ApprovalProvider`` is a small protocol so tests — and, later, Connected
mode's team approvals — can supply a different provider without changing
guard semantics.
"""

from __future__ import annotations

import dataclasses
import sys
from typing import Any, Protocol

from .errors import ApprovalUnavailableError

DECISION_ALLOWED = "allowed"
DECISION_DENIED = "denied"

_AFFIRMATIVE = frozenset({"y", "yes"})


@dataclasses.dataclass(frozen=True)
class ApprovalRequest:
    """Everything a provider may show or consider. Already redacted."""

    action_name: str
    risk: str
    approval_mode: str
    redacted_input_summary: str
    input_hash: str
    contract_hash: str
    spend_cents: int | None = None


@dataclasses.dataclass(frozen=True)
class ApprovalDecision:
    """Local policy decision for one invocation."""

    decision: str  # DECISION_ALLOWED or DECISION_DENIED
    reason: str
    approved_by: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == DECISION_ALLOWED


class ApprovalProvider(Protocol):
    def decide(self, request: ApprovalRequest) -> ApprovalDecision: ...


class TerminalApprovalProvider:
    """Interactive y/N prompt on the controlling terminal. Fails closed off-TTY."""

    def __init__(self, *, stdin: Any = None, stdout: Any = None) -> None:
        self._stdin = stdin if stdin is not None else sys.stdin
        self._stdout = stdout if stdout is not None else sys.stdout

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        if not _is_tty(self._stdin):
            raise ApprovalUnavailableError(
                f"approval is required for action {request.action_name!r} but stdin "
                "is not an interactive terminal; configure an approval provider or "
                "run in a terminal (the guard fails closed)"
            )
        self._stdout.write(
            "\n"
            "interceptor: approval required\n"
            f"  action: {request.action_name}\n"
            f"  risk:   {request.risk}\n"
            f"  input:  {request.redacted_input_summary or '(no arguments)'}\n"
        )
        self._stdout.write(f"Approve execution of {request.action_name}? [y/N] ")
        self._stdout.flush()
        line = self._stdin.readline()
        if not line:
            return ApprovalDecision(DECISION_DENIED, "no response (EOF); default deny")
        answer = line.strip().lower()
        if answer in _AFFIRMATIVE:
            return ApprovalDecision(DECISION_ALLOWED, "approved interactively at terminal")
        return ApprovalDecision(DECISION_DENIED, "not explicitly approved; default deny")


class AutoAllowProvider:
    """Used internally for ``approval="never"``: the guard still records a
    signed decision event, but no human prompt is involved."""

    def decide(self, request: ApprovalRequest) -> ApprovalDecision:
        return ApprovalDecision(
            DECISION_ALLOWED, "approval_mode=never; allowed without interactive approval"
        )


def _is_tty(stream: Any) -> bool:
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):
        return False
