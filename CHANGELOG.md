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
- `WitnessFreshnessProvider`: deny unless `witness_dir/latest.checkpoint` is
  fresh (`max_age_seconds`), with optional `risks=` subset enforcement —
  turns tail-truncation defense into an approval gate.
- Production ops: `benchmarks/bench_idempotent.py` (idempotent hot-path
  envelope: ~32–46/s at 400 events, 4–6× slower than keyless — shard/archive
  hot keys), `deploy/systemd/` witness + verify timers with `OnFailure`
  paging contract, `PERFORMANCE.md` idempotency numbers.
- `interceptor audit --status/--limit`: triage filtering for large journals
  (display only — counts and fail-closed exit codes always reflect the full
  journal, so a filter can never mask `needs_reconciliation`).
- `prune_witnesses` + `interceptor witness-prune --keep N`: bounded witness
  retention — keeps the newest N shipped witnesses (the strongest truncation
  bounds), never touches `latest.checkpoint`, keeps unassessable entries
  rather than deleting them; one witness dir per journal.
- `audit_journal_streaming` (and the `audit` CLI, which now uses it): identical
  audit reports from a single pass retaining only the 15 fields the audit
  reads — no full event bodies, proven equivalent on a rich local journal and
  every committed vector with audit expectations.
- In-process idempotency index (`journal.py`): exact `(size, tail-hash)`-
  validated tables with a per-key secondary index replace the per-call
  pre-check and locked scans (~306 guarded calls/s flat from 400 to 4,000
  events, vs ~32–46/s with scans); any mismatch falls back to a scan and
  rebuilds, keyless journals build nothing, exotic platforms keep the old
  scan path. Proven step-by-step equivalent to scans, plus thread (8×) and
  multiprocess (4× spawn) same-key races with exactly one execution and a
  2,000-call soak (verify + streaming audit clean).

### Fixed (engineering-review batch)
- `approval="never"` with an `approval_provider` is now a decoration-time
  error instead of silently ignoring the provider.
- Duplicate detection no longer compares free-text reason strings; the atomic
  append path reports duplication explicitly.
- `export --output` exits non-zero on invalid evidence, like the stdout path.
- `inspect` flags outcome disclosures (receipts, error summaries) and accepts
  repeated `--public-key`; `safe_for_upload` covers outcomes, not just inputs.
- Witness ship failures raise `EventShipError` (local evidence intact, result
  attached) instead of misreporting persistence loss; operator resolutions of
  `confirmed_not_completed` release idempotency keys for retry.
- Archive claims its destination exclusively, rolls back on a raced writer,
  and rejects dot-segment `archived_path` (Python and Node verifiers).
- File-backed policy providers lock via `msvcrt` on Windows, not just `fcntl`.
- `CachedApprovalProvider` keys on risk, mode, and spend; composition order
  with budgets is documented.
- Policy files reject unknown keys and unknown risk names at load time.
- `AttestedApprovalProvider` accepts human names (whitespace collapsed) while
  still rejecting empty, overlong, and control-character identities.
- `wrap_tools` translates bad per-tool config to `ToolWrapError` and rejects
  `configuration`+`defaults` combinations.
- Short secrets no longer mangle error text during scrubbing (hash suppression
  is unchanged); `render_html` raises `EvidenceAuditError` on bad bundles;
  `resolve` notes mark truncation with an ellipsis; policy state temp files
  are exclusive and cleaned up.

### Deprecated
- `EvidenceIncompleteError` (alias of `ExecutionCompletedEvidenceError`):
  kept working with no behavior change, but new code should use the canonical
  name; the alias is scheduled for removal in 2.0 per `docs/API_STABILITY.md`.

### Fixed (second review batch)
- Pre-check idempotency scans are cached against the file stat (~14× faster
  hot path on a 6k-event journal); the authoritative check still runs under
  the file lock, so staleness costs at most a redundant prompt.
- `countersign` reports `superseded` when a checkpoint lands mid-operation.
- `pyproject.toml` gains `Project-URLs`; source checkouts report
  `0.0.0+unknown` instead of masquerading as the release version.
- `inspect` names the pinned key path when it cannot be loaded.

### Added (TypeScript sibling)
- `ts/` package `interceptor-effect`: Effect-native Canonical, Identity,
  Journal, Event Schemas, Verify, and Guard modules with `vitest` suites —
  including cross-language conformance over all committed vectors, so both
  implementations must agree on validity, counts, and failure codes.
- STM idempotency reservation in the Effect guard (`TMap` completions +
  per-journal semaphore + file-scan blocking with resolution release),
  dry runs, receipts, and typed `GuardedCallFailed` — proven by a 10-fiber
  exactly-once race test.
- TypeScript: homoglyph folding + value-pattern redaction (parity-tested),
  `O_EXCL` cross-process lock files with stale recovery, HTTP witness service
  with signed checkpoints and coverage checks, budget/attested providers,
  checkpoint command, strict vector conformance (ordered per-line findings),
  and a Python test suite that verifies TypeScript-written journals.
- `EventShipError` now subclasses `EvidencePersistenceError` too and carries
  executed/retry-safe signals plus the decision id on both paths.
- TypeScript: value-pattern + homoglyph redaction with Python parity tests,
  `O_EXCL` cross-process lock files (proven by 4-process appends), HTTP
  witness service with signed checkpoints and coverage checks, spending/
  quorum/rate-limit/declarative policy providers, countersign/archive/chain
  verification, `DurableBudgetProvider` (lock-guarded cross-process budgets
  where denials consume nothing), and a TypeScript CI job.

### Added (edge-hardening batch)
- `describe_tool` keeps nullability (`anyOf` with `null`, including PEP 604
  unions, which were previously unwrapped), describes `*args`/`**kwargs`
  instead of dropping them, resolves dataclass field types, and lists
  dataclass required fields — with a `test_schemas.py` fidelity matrix.
- Approval server: constant-time token comparison, single-use per-request
  decision tokens (forged POSTs get 410 and decide nothing), and an
  attested-approval recipe in place of the unattributed default.
- Timeout/overload denials name the wrapped provider.
- `StripeRefundFetcher`: shipped, duck-typed Stripe reconciliation with no new
  dependency (client injected, offline-tested with fakes).
- `audit_witnesses` + `interceptor witness-audit`: every shipped witness must
  stay covered; same-second witnesses no longer collide; S3 ObjectLock
  remote-witness recipe in `docs/DEPLOYMENT.md`.

### Fixed (re-review batch)
- TypeScript: integral numbers encode verbatim (matching Python ints),
  `-0.0` preserved, exponent padding fixed; journal scans fail closed on
  unreadable files; error summaries, approval reasons, and receipts are
  scrubbed/redacted; non-object receipts dropped; verifier checks decision/
  status enums and integer counts, stops at unparseable lines, and validates
  through Effect Schema; guard emits `parameter_retention` and
  `redacted_output_hash`; provider defects normalize to `ApprovalError`;
  appends loop partial writes, fsync new-file directories, and widen the tail
  window; STM registry uses collision-free keys plus `forgetJournal`.
- Python: `EventShipError` carries executed/retry-safe signals and the
  decision id on both paths; `archive --keep` validates before mutating;
  rollbacks refuse to clobber successor files; `witness` preserves
  `CountersignError`; `resolve` rejects dry runs; raw-engine `never`+provider
  and non-key successors fail with precise errors; policy lock helper
  documents its degradation honestly.

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
