# Evidence format v1

The journal is newline-delimited JSON: one event per line, append-only. This
document specifies it completely enough to write an independent verifier in
another language, which is the point — evidence you can only check with the
library that produced it is a weaker claim than it appears.

## Canonical JSON

Every hash and signature is computed over the same encoding:

- UTF-8
- object keys sorted lexicographically by code point
- separators `,` and `:` with no whitespace
- `NaN`, `Infinity`, `-Infinity` rejected
- non-ASCII emitted as UTF-8, **not** `\u` escaped

In Python:

```python
json.dumps(
    value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
).encode("utf-8")
```

## Value canonicalization

Before hashing, argument structures are converted to JSON-safe values and
redacted in the same traversal:

| Python value | Canonical form |
|---|---|
| `None`, `bool`, `int`, `str` | unchanged |
| `float` | unchanged if finite; otherwise an error |
| `list`, `tuple` | JSON array |
| named tuple | JSON object keyed by field name |
| dataclass instance | JSON object keyed by field name |
| `dict` with all-string keys | JSON object |
| `dict` with any non-string key | `"<unsupported:mapping-with-non-string-keys>"` |
| anything else | `"<unsupported:module.QualifiedTypeName>"` |

At every point that produces a **name** — a mapping key, a dataclass field, a
named-tuple field — the name is lowercased and matched against the sensitive
set. A match replaces the value with the literal string `"<REDACTED>"`.
Additionally, any **string value** matching a value pattern (built-in secret
patterns such as `sk-live-…`, `ghp_…`, `AKIA…`, PEM keys, JWTs, plus caller
regexes via `redact_patterns`) is replaced with `"<REDACTED>"`, even under a
generic name. Pattern-matched results also suppress `redacted_output_hash`,
since hashing a recognizable secret commits something confirmable by guessing.

Named tuples must be checked before the generic tuple branch. A named tuple is
a `tuple`, and treating it as a sequence discards the field names, which is
both a fidelity loss and a redaction bypass.

Cycles and nesting deeper than 64 are errors.

## Event structure

Every event carries:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | `"1"` |
| `event_type` | string | `"decision"`, `"outcome"`, `"checkpoint"`, `"resolution"`, `"countersignature"`, `"archive"`, or `"rotation"` |
| `event_id` | string | UUIDv4 |
| `action_id` | string | `module.qualified_name` (absent on `checkpoint`/`countersignature`) |
| `action_name` | string | declared logical name (absent on `checkpoint`/`countersignature`) |
| `contract_hash` | string | SHA-256 hex of the contract (absent on `checkpoint`/`countersignature`) |
| `timestamp_utc` | string | RFC 3339 UTC, microseconds, `Z` suffix |
| `key_id` | string | `ed25519:` + first 16 hex of SHA-256 of the raw public key |
| `previous_event_hash` | string \| null | previous line's `event_hash`; `null` for the first |
| `event_hash` | string | see below |
| `signature` | string | see below |

`decision` events add:

| Field | Type |
|---|---|
| `decision` | `"allowed"` \| `"denied"` |
| `risk` | `"low"` \| `"medium"` \| `"high"` \| `"critical"` |
| `approval_mode` | `"required"` \| `"never"` |
| `redacted_input_summary` | string, bounded |
| `parameter_retention` | list of `{"name", "state"}` records |
| `input_hash` | SHA-256 hex over the redacted canonical arguments |
| `metadata` | object, optional |
| `idempotency_key` | string, optional — the caller-supplied duplicate guard |
| `dry_run` | boolean, optional — true when the function was not executed |
| `duplicate_of` | string, optional — prior decision `event_id` this duplicate was blocked by |
| `approval_reason` | string — the provider's reason, scrubbed of redacted values, bounded |
| `approved_by` | string, optional — provider-supplied approver identity, scrubbed, bounded |

`parameter_retention` records, for each top-level argument in canonical key
order, whether its recorded value is the redaction marker (`"redacted"`), an
unsupported-type placeholder (`"unsupported"`), or an ordinary value
(`"retained"`). Privacy inspection reads this structure directly instead of
re-parsing `redacted_input_summary`, so a truncated or oddly-formatted summary
cannot hide a retained argument. The field was added after the v1 summary
format; journals without it are still verified and inspected via summary
parsing.

`outcome` events add:

| Field | Type |
|---|---|
| `status` | `"succeeded"` \| `"failed"` |
| `decision_event_id` | the authorizing decision's `event_id` |
| `observed_result_type` | dotted type name, or `null` on failure |
| `redacted_output_hash` | optional; absent when the result must not be hashed |
| `exception_type` | on failure |
| `sanitized_error_summary` | on failure, bounded and scrubbed |

`redacted_output_hash` is absent when the result is itself one of the redacted
input values — hashing a low-entropy secret commits something confirmable by
guessing — or when the result is not canonicalizable.

`outcome` events optionally carry `receipt`: the redacted canonical provider
receipt (external reference IDs such as a processor's refund id), as an object.
It is transcribed from the guarded function's return value via a caller
extractor, so it attests to what the function *claimed*, not to what the
provider did. Non-object, oversized, or non-canonicalizable receipts are
dropped rather than recorded, and never fail the call.

`checkpoint` events add:

| Field | Type |
|---|---|
| `checkpoint_count` | integer, number of events before this one |
| `head_sha256` | `previous_event_hash` value — the hash of the last event committed |

A checkpoint commits to the journal's length at a point in time. It is signed
and hash-chained like every other event, and its canonical JSON line is a
self-contained **witness**: copied somewhere the journal cannot reach, it lets a
verifier treat any journal shorter than `checkpoint_count` as truncated. See
`THREAT_MODEL.md` for why tail truncation otherwise escapes offline detection.

`resolution` events add (carrying the referenced decision's `action_id`,
`action_name`, and `contract_hash`):

| Field | Type |
|---|---|
| `decision_event_id` | the reconciled decision's `event_id` |
| `resolution` | `"confirmed_completed"` \| `"confirmed_not_completed"` |
| `note` | operator note, bounded to 1000 chars |

A resolution is an operator attestation that the external system was checked,
not proof of the external result.

`countersignature` events add (no action fields — they attest to a checkpoint,
not an action):

| Field | Type |
|---|---|
| `checkpoint_event_id` | the counter-signed checkpoint's `event_id` |
| `checkpoint_count` | must equal the referenced checkpoint's count |
| `head_sha256` | must equal the referenced checkpoint's head |

The referenced checkpoint must appear earlier in the same journal; the
countersignature is signed by a second key and verified against the same
trusted keyring.

`rotation` events have no action fields. They witness a key succession
in-chain, signed by the outgoing key:

| Field | Type |
|---|---|
| `prior_key_id` | must equal the signing `key_id` |
| `successor_key_id` | `ed25519:` + first 16 hex of the successor fingerprint |
| `successor_fingerprint` | full 64-char lowercase hex SHA-256 of the successor raw key |

`archive` events have no action fields and must be the first line of their
file. They link a rotated successor back to its predecessor:

| Field | Type |
|---|---|
| `prior_count` | positive integer — events the archived file held |
| `prior_head` | the archived file's last `event_hash` |
| `archived_path` | file name (not path) of the archived predecessor |

## Hashing and signing

1. **Unsigned payload**: the event object minus `event_hash` and `signature`.
   `previous_event_hash` *is* included.
2. `event_hash = SHA-256(canonical_json(unsigned_payload))`, hex.
3. `signature = base64(Ed25519_sign(raw_32_byte_digest))`.

Note step 3 signs the **raw digest bytes**, not the canonical JSON. Ed25519
hashes internally, so this is a hash of a hash; it is safe under SHA-256
collision resistance and it is what a verifier must reproduce exactly.

## Contract hash

```
contract_hash = SHA-256(canonical_json({
    schema_version, action_name, module, qualified_name, risk,
    approval_mode, execution_mode, parameter_descriptors, code_fingerprint
}))
```

`parameter_descriptors` is an array of `{name, kind, has_default, annotation}`
in declaration order. `kind` is the `inspect.Parameter.kind` name, for example
`POSITIONAL_OR_KEYWORD`. `annotation` is a stable string or `null`.
`code_fingerprint` is SHA-256 of the dedented function source, or `null` when
source is unavailable — a missing source never invents a fingerprint.

The contract contains no timestamps, absolute paths, memory addresses, or
interpreter-specific values, so the same declaration hashes identically across
machines and runs.

## Verification algorithm

```
previous = null
for each non-empty line, in order:
    event = parse_json(line)
    payload = event without {event_hash, signature}

    assert event.schema_version == "1"
    assert payload.previous_event_hash == previous

    digest = SHA-256(canonical_json(payload))
    assert digest.hex() == event.event_hash
    assert ed25519_verify(public_key, base64_decode(event.signature), digest)
    assert key_id_for(public_key) == event.key_id

    previous = event.event_hash
```

A verifier that stops at the first failure and reports the index is sufficient;
this implementation collects issues so it can report more than one.

When a `checkpoint` event is present (or a witness file is supplied to
`verify --checkpoint`), the verifier additionally requires:

```
assert journal_event_count >= checkpoint.checkpoint_count
```

A journal with fewer events than the checkpoint commits to is reported as
`checkpoint_truncation`; a valid witness whose event is absent from the journal
is reported as `checkpoint_not_found`. A `checkpoint` event is validated like
any other event (schema, required fields, hash, signature, chain link) plus the
self-consistency rule `head_sha256 == previous_event_hash` and a non-negative
integer `checkpoint_count`.

## Operational audit rules

Signature and chain verification is necessary but does not establish that the
events form a coherent invocation history. After cryptographic verification,
the `audit` command applies these additional rules:

- every `event_id` is unique;
- every outcome references an earlier decision;
- every resolution references an earlier decision (else `orphan_resolution`);
- conflicting resolutions for one decision are flagged (`conflicting_resolution`,
  latest wins); a resolution contradicting a `succeeded` outcome is flagged and
  left open (`conflicting_resolution` + `needs_reconciliation`);
- no decision has more than one outcome;
- an outcome may reference only an `allowed` decision;
- the outcome's `action_id`, `action_name`, and `contract_hash` match its decision;
- decision values and outcome statuses are from their documented enums.

An allowed decision without an outcome is valid evidence of an incomplete
invocation, not malformed evidence. It is reported as `needs_reconciliation`,
except when the decision carries `dry_run: true`, which is reported as
`dry_run` — a deliberate non-execution that never needs reconciliation — and
except when a resolution closed it: `resolved_completed` (side effect confirmed,
do not retry) or `resolved_not_completed` (side effect absent, retry is safe).
Both `needs_reconciliation` and a recorded `failed` outcome make the command
exit non-zero:
an external side effect may have occurred before an exception or process death,
so automatic retry is unsafe. `succeeded` means the guarded function returned
normally; it does not prove the external side effect occurred. Two `succeeded`
outcomes under the same `(action_name, idempotency_key)` are reported as a
`duplicate_idempotency_key` issue: at most one should exist.

Note what the algorithm cannot check: that the chain is *complete*. Any prefix
of a valid chain is itself a valid chain. See
[`THREAT_MODEL.md`](THREAT_MODEL.md).

## Compatibility

`schema_version` is `"1"`. A verifier encountering a different value should
refuse rather than guess. New optional fields within version 1 will not change
existing field semantics, but note that any added field changes `event_hash`
for events that carry it — which is correct, since the signature must cover
everything recorded.
