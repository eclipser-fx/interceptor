"""Operational audit and reconciliation view over a verified journal.

Cryptographic verification answers whether the recorded lines were changed.
This module answers the next question an operator actually has: what happened
to each approved invocation, and which invocations still need reconciliation?

An allowed decision without an outcome is deliberately classified as
``needs_reconciliation``. The process may have died after the action started,
so neither retrying it nor calling it failed is safe.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import EvidenceAuditError
from .verification import JournalSnapshot, PublicKeys, load_journal_snapshot


class InvocationStatus(str, Enum):
    DENIED = "denied"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NEEDS_RECONCILIATION = "needs_reconciliation"
    DRY_RUN = "dry_run"
    RESOLVED_COMPLETED = "resolved_completed"
    RESOLVED_NOT_COMPLETED = "resolved_not_completed"


@dataclasses.dataclass(frozen=True)
class AuditIssue:
    code: str
    message: str
    event_id: str | None = None


@dataclasses.dataclass(frozen=True)
class AuditedInvocation:
    action_name: str
    action_id: str
    contract_hash: str
    input_hash: str
    risk: str
    approval_mode: str
    decision_event_id: str
    decision: str
    decision_timestamp_utc: str
    outcome_event_id: str | None
    outcome_timestamp_utc: str | None
    status: InvocationStatus


@dataclasses.dataclass(frozen=True)
class AuditReport:
    invocations: tuple[AuditedInvocation, ...]
    issues: tuple[AuditIssue, ...]

    @property
    def structurally_valid(self) -> bool:
        return not self.issues

    @property
    def needs_reconciliation(self) -> bool:
        return any(
            invocation.status in (InvocationStatus.FAILED, InvocationStatus.NEEDS_RECONCILIATION)
            for invocation in self.invocations
        )


def audit_journal(path: Path, public_keys: PublicKeys) -> AuditReport:
    """Verify *path*, then build its operational action audit.

    *public_keys* may be a single ``Ed25519PublicKey`` or the full set of keys
    an operator still trusts, so a journal spanning a key rotation audits as
    one coherent history.
    """
    return audit_verified_snapshot(load_journal_snapshot(path, public_keys))


def audit_verified_snapshot(snapshot: JournalSnapshot) -> AuditReport:
    """Build an audit only from a cryptographically valid immutable snapshot."""
    if not snapshot.verification.valid:
        first = snapshot.verification.issues[0] if snapshot.verification.issues else None
        detail = f" [{first.code}] {first.message}" if first is not None else ""
        raise EvidenceAuditError(
            "refusing to audit a journal that failed cryptographic verification" + detail
        )

    issues: list[AuditIssue] = []
    decisions: dict[str, tuple[int, dict[str, Any]]] = {}
    outcomes: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    resolutions: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    seen_event_ids: set[str] = set()

    for index, event in enumerate(snapshot.events):
        event_id = str(event["event_id"])
        if event_id in seen_event_ids:
            issues.append(AuditIssue("duplicate_event_id", "event_id is not unique", event_id))
        seen_event_ids.add(event_id)

        if event["event_type"] == "decision":
            decisions.setdefault(event_id, (index, event))
        elif event["event_type"] == "outcome":
            decision_id = str(event["decision_event_id"])
            outcomes.setdefault(decision_id, []).append((index, event))
        elif event["event_type"] == "resolution":
            decision_id = str(event["decision_event_id"])
            resolutions.setdefault(decision_id, []).append((index, event))

    for decision_id, linked in resolutions.items():
        if decision_id not in decisions:
            for _, resolution in linked:
                issues.append(
                    AuditIssue(
                        "orphan_resolution",
                        f"resolution references unknown decision_event_id {decision_id!r}",
                        str(resolution["event_id"]),
                    )
                )
            continue
        decision_index, _ = decisions[decision_id]
        values = {str(resolution.get("resolution")) for _, resolution in linked}
        if len(values) > 1:
            issues.append(
                AuditIssue(
                    "conflicting_resolution",
                    "more than one resolution value recorded for the same decision; "
                    "the latest wins",
                    decision_id,
                )
            )
        for resolution_index, resolution in linked:
            if resolution_index <= decision_index:
                issues.append(
                    AuditIssue(
                        "resolution_before_decision",
                        "resolution appears before the decision it references",
                        str(resolution["event_id"]),
                    )
                )

    for decision_id, linked in outcomes.items():
        if decision_id not in decisions:
            for _, outcome in linked:
                issues.append(
                    AuditIssue(
                        "orphan_outcome",
                        f"outcome references unknown decision_event_id {decision_id!r}",
                        str(outcome["event_id"]),
                    )
                )
            continue

        decision_index, decision = decisions[decision_id]
        if len(linked) > 1:
            issues.append(
                AuditIssue(
                    "duplicate_outcome",
                    "more than one outcome references the same decision",
                    decision_id,
                )
            )
        for outcome_index, outcome in linked:
            outcome_id = str(outcome["event_id"])
            if outcome_index <= decision_index:
                issues.append(
                    AuditIssue(
                        "outcome_before_decision",
                        "outcome appears before the decision it references",
                        outcome_id,
                    )
                )
            if decision["decision"] != "allowed":
                issues.append(
                    AuditIssue(
                        "outcome_for_denied_decision",
                        "an outcome references a decision that was not allowed",
                        outcome_id,
                    )
                )
            for field in ("action_id", "action_name", "contract_hash"):
                if outcome[field] != decision[field]:
                    issues.append(
                        AuditIssue(
                            "outcome_identity_mismatch",
                            f"outcome {field} does not match its decision",
                            outcome_id,
                        )
                    )
            if outcome.get("status") not in ("succeeded", "failed"):
                issues.append(
                    AuditIssue(
                        "invalid_outcome_status",
                        f"unsupported outcome status {outcome.get('status')!r}",
                        outcome_id,
                    )
                )

    invocations: list[AuditedInvocation] = []
    seen_idempotency: dict[tuple[str, str], str] = {}
    for decision_id, (_, decision) in decisions.items():
        decision_value = decision.get("decision")
        if decision_value not in ("allowed", "denied"):
            issues.append(
                AuditIssue(
                    "invalid_decision",
                    f"unsupported decision {decision_value!r}",
                    decision_id,
                )
            )

        linked = outcomes.get(decision_id, [])
        outcome_event = linked[0][1] if len(linked) == 1 else None
        linked_resolutions = resolutions.get(decision_id, [])
        # Latest resolution wins; disagreement was already flagged above.
        resolution_value = (
            str(linked_resolutions[-1][1].get("resolution")) if linked_resolutions else None
        )
        is_dry_run = decision.get("dry_run") is True
        if is_dry_run and decision_value == "allowed" and outcome_event is None:
            status = InvocationStatus.DRY_RUN
        elif decision_value == "denied" and not linked:
            status = InvocationStatus.DENIED
        elif (
            decision_value == "allowed"
            and outcome_event is not None
            and outcome_event.get("status") == "succeeded"
            and resolution_value is None
        ):
            status = InvocationStatus.SUCCEEDED
        elif (
            decision_value == "allowed"
            and outcome_event is not None
            and outcome_event.get("status") == "succeeded"
        ):
            # A resolution on a succeeded invocation contradicts the recorded
            # evidence; keep it open rather than silently clearing it.
            issues.append(
                AuditIssue(
                    "conflicting_resolution",
                    "a resolution contradicts a recorded succeeded outcome",
                    decision_id,
                )
            )
            status = InvocationStatus.NEEDS_RECONCILIATION
        elif decision_value == "allowed" and resolution_value == "confirmed_completed":
            status = InvocationStatus.RESOLVED_COMPLETED
        elif decision_value == "allowed" and resolution_value == "confirmed_not_completed":
            status = InvocationStatus.RESOLVED_NOT_COMPLETED
        elif decision_value == "allowed" and outcome_event is not None:
            if outcome_event.get("status") == "failed":
                status = InvocationStatus.FAILED
            else:
                status = InvocationStatus.NEEDS_RECONCILIATION
        else:
            status = InvocationStatus.NEEDS_RECONCILIATION

        key = decision.get("idempotency_key")
        if (
            isinstance(key, str)
            and key
            and status == InvocationStatus.SUCCEEDED
            and isinstance(decision.get("action_name"), str)
        ):
            marker = (str(decision["action_name"]), key)
            if marker in seen_idempotency:
                issues.append(
                    AuditIssue(
                        "duplicate_idempotency_key",
                        f"action {decision['action_name']!r} completed twice with "
                        f"idempotency key {key!r}",
                        decision_id,
                    )
                )
            else:
                seen_idempotency[marker] = decision_id

        invocations.append(
            AuditedInvocation(
                action_name=str(decision["action_name"]),
                action_id=str(decision["action_id"]),
                contract_hash=str(decision["contract_hash"]),
                input_hash=str(decision["input_hash"]),
                risk=str(decision["risk"]),
                approval_mode=str(decision["approval_mode"]),
                decision_event_id=decision_id,
                decision=str(decision_value),
                decision_timestamp_utc=str(decision["timestamp_utc"]),
                outcome_event_id=(
                    str(outcome_event["event_id"]) if outcome_event is not None else None
                ),
                outcome_timestamp_utc=(
                    str(outcome_event["timestamp_utc"]) if outcome_event is not None else None
                ),
                status=status,
            )
        )

    return AuditReport(tuple(invocations), tuple(issues))
