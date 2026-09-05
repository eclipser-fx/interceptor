"""Provider reconciliation: check transcribed receipts against external truth.

A `receipt` on a succeeded outcome is a transcribed claim — the guarded
function *said* the provider created this refund id, request id, or delivery
id. Reconciliation closes the loop: fetch the provider's own record and
compare. This module never touches the network itself (the suite forbids
sockets); you supply a `fetch` callable that does whatever your stack uses —
Stripe's SDK, a CloudTrail lookup, a warehouse query — and this module handles
the evidence side: pairing outcomes with receipts, comparing field-by-field,
and reporting matched/mismatched/unknown without ever mutating the journal.

A mismatch is an operational finding, not a verification failure: the evidence
is still valid, it just disagrees with the provider. Investigate before
retrying anything.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Protocol

from .errors import EvidenceAuditError
from .verification import JournalSnapshot, PublicKeys, load_journal_snapshot

#: Fetch the provider's record for a transcribed receipt (e.g. Stripe refund
#: retrieve, CloudTrail lookup). Return the provider-side mapping, or None
#: when the provider has no such record. Raising signals a fetch error.
ExternalFetch = Callable[[Mapping[str, Any]], Mapping[str, Any] | None]


class ProviderFetcher(Protocol):
    """Object form of :data:`ExternalFetch` for classes carrying credentials."""

    def fetch(self, receipt: Mapping[str, Any]) -> Mapping[str, Any] | None: ...


@dataclasses.dataclass(frozen=True)
class ReceiptReconciliation:
    decision_event_id: str
    outcome_event_id: str
    action_name: str
    receipt: dict[str, Any]
    status: str  # "matched" | "mismatched" | "provider_unknown" | "fetch_error"
    detail: str = ""


@dataclasses.dataclass(frozen=True)
class ReconcileReport:
    reconciliations: tuple[ReceiptReconciliation, ...]

    @property
    def complete(self) -> bool:
        """True when every receipted outcome matched its provider record."""
        return bool(self.reconciliations) and all(
            item.status == "matched" for item in self.reconciliations
        )

    @property
    def mismatched(self) -> bool:
        return any(item.status == "mismatched" for item in self.reconciliations)


def reconcile_journal(
    path: Path,
    public_keys: PublicKeys,
    fetch: ExternalFetch | ProviderFetcher,
) -> ReconcileReport:
    """Reconcile every succeeded outcome carrying a receipt in *path*."""
    return reconcile_verified_snapshot(load_journal_snapshot(path, public_keys), fetch)


def reconcile_verified_snapshot(
    snapshot: JournalSnapshot, fetch: ExternalFetch | ProviderFetcher
) -> ReconcileReport:
    """Reconcile receipts from an already-verified immutable snapshot."""
    if not snapshot.verification.valid:
        first = snapshot.verification.issues[0] if snapshot.verification.issues else None
        detail = f" [{first.code}] {first.message}" if first is not None else ""
        raise EvidenceAuditError(
            "refusing to reconcile a journal that failed cryptographic verification" + detail
        )
    call: ExternalFetch = fetch.fetch if hasattr(fetch, "fetch") else fetch
    items: list[ReceiptReconciliation] = []
    for event in snapshot.events:
        if event.get("event_type") != "outcome" or event.get("status") != "succeeded":
            continue
        receipt = event.get("receipt")
        if not isinstance(receipt, dict):
            continue
        decision_id = str(event.get("decision_event_id", ""))
        outcome_id = str(event.get("event_id", ""))
        action = str(event.get("action_name", "<unknown>"))
        try:
            provider_state = call(dict(receipt))
        except Exception as exc:
            items.append(
                ReceiptReconciliation(
                    decision_id, outcome_id, action, dict(receipt), "fetch_error", str(exc)[:500]
                )
            )
            continue
        if provider_state is None:
            items.append(
                ReceiptReconciliation(
                    decision_id,
                    outcome_id,
                    action,
                    dict(receipt),
                    "provider_unknown",
                    "provider has no record for this receipt",
                )
            )
            continue
        mismatch = _first_mismatch(dict(receipt), provider_state)
        if mismatch is None:
            items.append(
                ReceiptReconciliation(decision_id, outcome_id, action, dict(receipt), "matched")
            )
        else:
            items.append(
                ReceiptReconciliation(
                    decision_id, outcome_id, action, dict(receipt), "mismatched", mismatch
                )
            )
    return ReconcileReport(tuple(items))


def _first_mismatch(receipt: dict[str, Any], provider_state: Mapping[str, Any]) -> str | None:
    """The first receipt field disagreeing with the provider, or None."""
    for key, claimed in receipt.items():
        if key not in provider_state:
            return f"provider record has no field {key!r}"
        actual = provider_state[key]
        if str(actual) != str(claimed):
            return f"field {key!r}: journal {claimed!r} != provider {actual!r}"
    return None
