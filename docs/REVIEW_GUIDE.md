# External review guide

For a security-minded reader evaluating `interceptor` without trusting its
authors. Budget ~1 day.

## 1. Read the contract (30 min)

- `docs/THREAT_MODEL.md` — the guarantees and, more importantly, the stated
  non-guarantees. Every item under "does not establish" should have a matching
  test or an explicit residual-risk note.
- `docs/EVIDENCE_FORMAT.md` — the wire spec. Check that required-field lists
  match `verification.py` and `verifiers/node/verify.mjs`.

## 2. Attack the redaction (1 h)

- `canonical.py::_walk` — confirm every name-producing branch consults the
  sensitive set (dict keys, dataclass fields, named-tuple fields *before* the
  tuple branch). Try to smuggle a secret: new container types, nested
  dataclasses under innocent names, homoglyph field names.
- `tests/test_redaction_property.py` — the property test, not just examples.

## 3. Attack the chain (1 h)

- `journal.py` — tail-read fast path vs `_read_last_event_hash_scan` reference.
- `verifiers/vectors/v1/` — the committed fixtures. Tamper one byte and
  confirm both verifiers agree on the failure code. Note
  `truncated-tail-no-witness.json` verifies *valid*: the documented limit.
- `engine.py::_prepare_execution` — the idempotency reservation: two racers,
  one key, one execution. Crash between decision and outcome must read
  `needs_reconciliation`, never success.

## 4. Attack the trust roots (1 h)

- Key handling (`identity.py`): permissions check, rotation records, trusted
  set semantics. Steal the test key and forge a journal — confirm it verifies
  (it should: stolen key is a stated assumption break), then confirm the
  rotation record + countersignature raise the bar as documented.
- Approval paths: TTY detection, timeout fail-closed, quorum counting,
  `AttestedApprovalProvider` identity validation.

## 5. Report format

File findings as: violated assumption (or new one), minimal reproduction with
a patched journal, and classification — forgery, integrity break, disclosure,
or denial of service (see `SECURITY.md`). Out-of-scope items are listed there;
argue the scope, not just the bug, if you disagree with it.
