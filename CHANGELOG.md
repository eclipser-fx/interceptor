# Changelog

All notable changes to `interceptor` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[`docs/API_STABILITY.md`](docs/API_STABILITY.md) (SemVer once 1.0 ships,
pre-1.0 additive-only discipline until then).

## [Unreleased]

### Added
- `spend_from=` on `@guard`/`wrap_tool`: declared spend in minor units, recorded
  as `spend_cents` on decision events and visible to providers.
- `SpendingBudgetProvider` / `FileSpendingBudgetProvider`: enforce spend caps
  (memory and durable variants; undeclared spend fails closed).
- `AttestedApprovalProvider`: stamp allowances with an operator identity from an
  explicit value or `INTERCEPTOR_APPROVER`.
- `ToolGateway`: single name-routed choke point for agent tool invocation.
- `CallbackSigningIdentity`: external signers (TPM/HSM/KMS) without moving keys.
- Password-encrypted PEMs: `generate_private_key(..., password)`,
  `load_private_key(..., password)`, `keygen`/`countersign --password-env`.
- `FanoutJournalStore` + `FileMirrorSink`: per-event witness shipping.
- `verify_archive_chain` + `interceptor verify-chain`: custody across rotations.
- Signed `rotation` events: key succession witnessed in-chain.
- `uv.lock`: pinned, reviewable dependency tree; CI runs `uv sync --frozen`.
- `witness_journal` + `interceptor witness`: checkpoint and ship the witness
  off-host in one command (cron-ready), with optional countersigning.
- `reconcile_journal`: compare transcribed receipts against provider records
  (`matched`/`mismatched`/`provider_unknown`/`fetch_error`).
- Committed cross-language vectors (`verifiers/vectors/v1/`): Python and Node
  verify the same journals, including tamper and truncation cases.
- `docs/API_STABILITY.md` (SemVer + deprecation policy), `docs/DEPLOYMENT.md`
  (witness cron, rotation, reconciliation recipes), `docs/PERFORMANCE.md`
  (measured envelope), `docs/REVIEW_GUIDE.md` (external review playbook).

## [0.1.0] — current

First public package (`interceptor`, CLI `interceptor`):

- Approval-gated `@guard`/`wrap_tool` with fail-closed terminal approval.
- Signed, hash-chained JSONL evidence (`decision`/`outcome`), offline `verify`.
- Fused redact+canonicalize traversal (names, homoglyphs, value patterns).
- Composable policy providers (budget, rate limit, allow-list, predicate, TTL
  cache, timeout, `AllOf`/`AnyOf`, quorum, glob rules, JSON policy files).
- Idempotency keys with `DuplicateActionError`; dry runs; provider receipts.
- Reconciliation workflow: `audit` statuses, signed `resolution` events.
- Checkpoints + witness files, second-key countersignatures, archive rotation
  with custody links, JSON/HTML evidence packs, `stats`, `inspect`.
- Independent Node verifier (`verifiers/node/verify.mjs`).
- Evidence format v1 (`docs/EVIDENCE_FORMAT.md`), threat model
  (`docs/THREAT_MODEL.md`), security policy (`SECURITY.md`).
