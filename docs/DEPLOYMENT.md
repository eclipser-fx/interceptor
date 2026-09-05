# Deployment guide

How to run `interceptor` in production so the guarantees survive contact with
operations. Read `THREAT_MODEL.md` first — this guide implements its
"what would strengthen it" list.

## 1. Witness on a schedule (closes tail truncation)

```cron
*/5 * * * * interceptor witness --witness-dir /mnt/backup-witness >>/var/log/interceptor-witness.log 2>&1
0   * * * * interceptor verify --checkpoint /mnt/backup-witness/latest.checkpoint || page-oncall
```

Rules: the witness dir must live where the journal cannot reach (separate
mount, second host, WORM bucket). Alert on any non-zero `verify` exit —
including `needs_reconciliation` from `audit`, which is an operational state,
not a clean bill of health. With a second key available, pass
`--counter-key` so each witness is also countersigned.

## 2. Rotate keys and journals

- **Signing keys**: `interceptor key-rotate --journal <live>` quarterly or on
  any suspected exposure. The rotation record is witnessed in-chain; keep old
  public keys in `trusted_keys/` and pin the current fingerprint out of band.
- **Journals**: `interceptor archive --keep 12` when files approach ~100k
  events (see `PERFORMANCE.md`). Keep every predecessor the live chain links
  to — `--keep` deletion destroys evidence. Verify custody end-to-end with
  `interceptor verify-chain`.

## 3. Approve with identity

Export the on-call identity where agents run (`INTERCEPTOR_APPROVER`, ideally
an OIDC `sub` your launcher provides) and wrap approval in
`AttestedApprovalProvider` + `QuorumApprovalProvider` for high-risk actions.
The journal then records *who* approved, and `audit` shows it.

## 4. Reconcile against providers (close the receipt loop)

A `receipt` is a transcribed claim until checked. Nightly, run
`reconcile_journal` with a fetcher over your provider and alert on anything
but `matched`:

```python
import stripe
from interceptor import reconcile_journal, load_trusted_public_keys

stripe.api_key = os.environ["STRIPE_API_KEY"]

def fetch(receipt):
    if receipt.get("processor") != "acme":
        return None
    refund = stripe.Refund.retrieve(receipt["refund_id"])
    return {"processor": "acme", "refund_id": refund.id, "status": refund.status}

report = reconcile_journal(journal, keys, fetch)
assert report.complete, [r for r in report.reconciliations if r.status != "matched"]
```

AWS equivalent: fetch CloudTrail `LookupEvents` for the recorded request id
and compare status fields. Treat `mismatched` as an incident and
`provider_unknown` as a queue to work — never as permission to retry blindly.

## 5. Monitor and retain

- Alert on: `verify` failure, `audit` needing reconciliation, spending-budget
  denials spiking, witness age exceeding 2× the schedule.
- Retention: keep journals + witnesses + archived predecessors together per
  environment. If erasure is required (GDPR), purge only after `inspect`
  confirms full redaction, and record the purge itself out-of-band — a gap in
  the chain is evidence of a gap, nothing more.
- Ship `FanoutJournalStore` mirrors to a second disk as a cheap second copy;
  it is a copy, not a witness — only off-host checkpoints detect truncation.
