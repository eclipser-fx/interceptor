# API stability and deprecation policy

Trustworthy evidence needs a trustworthy interface. This document states what
is stable, what may change, and how breaking changes ship.

## What is stable

- **Evidence format v1** (`docs/EVIDENCE_FORMAT.md`): journals written by any
  0.x/1.x release verify under any later release. New event *types* may be
  added; existing field semantics never change within a major version, and any
  added field is covered by the event signature.
- **Verification semantics**: `verify`/`audit` exit codes and the
  `needs_reconciliation` fail-closed behavior do not change without a major
  version bump.
- **Exception hierarchy**: every error derives from `InterceptorError`;
  existing exception names and their catch semantics (`ActionDenied` covers
  `DuplicateActionError`) are stable.

## What may grow

New keyword arguments (e.g. `spend_from=`), new providers, new event types,
new CLI subcommands, and new optional decision/outcome fields are
backward-compatible additions and may ship in minor releases. They never alter
the meaning of existing fields.

## Deprecation policy

1. A deprecated name keeps working for **at least two minor releases** (or six
   months, whichever is longer) and emits a `DeprecationWarning` pointing at
   the replacement.
2. Removals happen only in a **major** release and are listed in `CHANGELOG.md`
   under "Removed" with migration notes.
3. Pre-1.0 discipline is stricter in one direction: no removals at all before
   1.0 — only additions. Anything that would need a removal waits for 2.0
   scoping instead.

## Versioning

`pyproject.toml` is the single source of truth for the version. Until 1.0,
minor bumps mark feature batches; after 1.0, strict SemVer applies.
