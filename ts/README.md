# interceptor-effect

Approval-gated, tamper-evident evidence for consequential function calls —
the Effect/TypeScript sibling of the Python `interceptor` package. Same
evidence format v1, same guarantees, enforced where TypeScript agents run.

```sh
pnpm install
pnpm check    # tsc --noEmit
pnpm test     # vitest (includes cross-language vector conformance)
```

## What is implemented

- `Canonical` — byte-exact canonical JSON (sorted keys, compact separators,
  Python float repr rules) plus a lexical-number-preserving parse, so `2` and
  `2.0` hash exactly as written.
- `Identity` — Ed25519 over Node builtins, same digest-sign-keyId scheme.
- `Journal` — append-only JSONL with tail-read chain tip and fsync durability.
- `Schemas` — Effect Schema codecs for every event type.
- `Verify` — offline verification (shape, hash, signature, chain, checkpoint /
  countersignature / rotation / archive semantics) as pure Effect.
- `Guard` — approval gate recording signed decision/outcome evidence with
  typed errors (`ApprovalError` / `ActionDenied` / `JournalError`); denial
  never executes, exactly like the Python engine.

## Conformance

`test/vectors.test.ts` checks the committed Python-produced journals in
`verifiers/vectors/v1/` — validity, event counts, and failure codes must match
across implementations. Divergences fail here, not in audits.

## Deliberate gaps (next)

- Redaction covers folded names, custom names, and value patterns (parity
  tested against Python's folder); exotic Unicode beyond the ported lookalike
  table stays best-effort on both sides.
- Cross-process appends serialize through an `O_EXCL` sidecar lock file with
  pid-liveness stale recovery; the guard layer additionally holds a
  per-journal semaphore around its check-then-append reservation.
- Policy surface is budget (memory + durable file-backed), spending,
  rate-limit, quorum, attested-identity, and declarative JSON rules.
- No hosted witness: `Witness` runs wherever you run it; pair with TLS, real
  auth, and off-host storage in production.
- `parameterNames` must be supplied for positional secrets to redact by name.
