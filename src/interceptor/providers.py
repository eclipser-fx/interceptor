"""Provider fetchers for :mod:`interceptor.reconcile`: external truth, injected.

Each fetcher answers "what does the provider say about this receipt?" against
a client *you* configure and pass in — this library takes no network
dependency and performs no I/O itself, so the suite's no-socket guarantee
holds. Fetchers translate provider records into the plain mappings
:func:`reconcile_journal` compares; anything the provider cannot answer maps
to ``None`` (unknown), and transport errors propagate as fetch errors.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class StripeRefundFetcher:
    """Fetch Stripe refunds for receipts like ``{"refund_id": "re_..."}``.

    Pass your configured ``stripe`` module (or any object with
    ``Refund.retrieve``); no import happens here, so ``stripe`` stays an
    application dependency, never a library one::

        import stripe
        from interceptor import StripeRefundFetcher, reconcile_journal

        report = reconcile_journal(journal, keys, StripeRefundFetcher(stripe))

    Receipts naming another processor return None (not applicable, not a
    mismatch). The compared state is ``processor`` + ``refund_id`` +
    ``status``; pass ``extra_fields`` (e.g. ``("amount",)``) to compare more,
    compared with the same string coercion as the reconciler core.
    """

    def __init__(self, stripe: Any, *, extra_fields: tuple[str, ...] = ()) -> None:
        self._stripe = stripe
        self._extra_fields = tuple(extra_fields)

    def fetch(self, receipt: Mapping[str, Any]) -> Mapping[str, Any] | None:
        if receipt.get("processor") != "stripe":
            return None
        refund_id = receipt.get("refund_id")
        if not isinstance(refund_id, str) or not refund_id:
            return None
        refund = self._stripe.Refund.retrieve(refund_id)
        state: dict[str, Any] = {
            "processor": receipt.get("processor"),
            "refund_id": getattr(refund, "id", refund_id),
            "status": getattr(refund, "status", None),
        }
        for field in self._extra_fields:
            state[field] = getattr(refund, field, None)
        return state
