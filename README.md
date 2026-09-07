# interceptor

Approval-gated, tamper-evident evidence for consequential Python function
calls — the ones you would not want to happen twice, silently, or unapproved.

```python
from interceptor import guard


@guard(action="billing.refund", risk="high")
def refund(customer_id: str, amount_cents: int, api_key: str) -> dict:
    return payments.refund(customer_id, amount_cents)
```

That decorator does four things on every call:

1. asks for approval, and **denies by default** if nobody can answer;
2. writes a signed `decision` record **before** the function runs;
3. runs the function exactly once — unless `dry_run=True` (never runs) or its
   `idempotency_key` already completed (raises `DuplicateActionError` instead);
4. writes a signed `outcome` record after (skipped for dry runs).

The records form a hash chain in an append-only file, signed with a local
Ed25519 key. `api_key` never appears in the file, in the approval prompt, or in
any hash.

There is no service behind this. No account, no API key, no network — the
whole guarantee is a local key and a file you can verify offline:

```console
$ interceptor verify
OK  ~/.interceptor/journal.jsonl
    2 events, signatures and hash chain intact
    note: tail truncation is detectable only with a checkpoint witness
```

## Install

```sh
pip install interceptor
```

One runtime dependency: `cryptography`, for Ed25519. Everything else is the
standard library.

## What's new in interceptor

Renamed from `guardrail-evidence` (package `interceptor`, CLI `interceptor`,
home `~/.interceptor`, env `INTERCEPTOR_EVIDENCE_HOME`), plus new capabilities:

- **Value-pattern redaction** — built-in secret shapes (`sk-live-…`, `ghp_…`,
  `xoxb-…`, `AKIA…`, PEM keys, JWTs) redacted even under generic names, with
  custom `redact_patterns=[...]` regexes on `@guard` and `wrap_tool`.
- **Policy approvals** (`interceptor.policy`) — composable offline providers:
  `BudgetProvider`, `RateLimitProvider`, `AllowListProvider`/`PredicateProvider`,
  `CachedApprovalProvider` (TTL auto-allow of identical calls, every call still
  evidenced), `TimeoutApprovalProvider` (fail-closed), `AllOf`/`AnyOf`.
- **Idempotency** (`idempotency_key=`) — a completed key records a denied
  decision and raises `DuplicateActionError` instead of executing twice.
  Retries after failure still run. File journals deduplicate across processes.
- **Dry runs** (`dry_run=True`) — records the signed decision, returns `None`,
  never executes; audits report `dry_run`, never `needs_reconciliation`.
- **Easier bulk wrapping** — `wrap_tools(tools, risk="high")` now works without
  an explicit `configuration` mapping (action per tool name).
- **Hardening** — the once-per-process observer tracker no longer keys on
  `id()` (a collected observer can't suppress a later one); audit flags
  repeated `(action, idempotency_key)` successes as `duplicate_idempotency_key`.

Maturity batch:

- **Approval attribution** — the provider's `reason` and optional `approved_by`
  are recorded on every decision event (scrubbed of redacted values), so audits
  show *why* and *who*, not just *allowed*.
- **Resolutions** — `audit` no longer dead-ends at `needs_reconciliation`:
  `interceptor resolve --decision … --result completed|not-completed` appends a
  signed operator attestation and clears the invocation to `resolved_completed`
  or `resolved_not_completed`.
- **Declarative policy** — `RuleProvider` with glob rules, plus
  `load_policy_file()` for JSON policy-as-config (first match wins, default deny).
- **Counter-signatures** — `interceptor keygen` + `interceptor countersign`
  let a second key held elsewhere witness the newest checkpoint in-chain;
  rewriting history then needs both keys.
- **Auditor deliverables** — `interceptor export --format json|html` writes a
  self-contained evidence pack; `interceptor stats` gives operational counts.

Production-hardening batch:

- **Receipts** — `receipt_from=` extracts provider reference IDs (processor
  refund ids) from succeeded results into the signed outcome, after the same
  redaction as inputs. Transcribed claims, not proof — but reconcilable ones.
- **Quorum + web approvals** — `QuorumApprovalProvider` (N-of-M must allow)
  and `ApprovalServer`, a token-authenticated LAN page to approve from a
  browser or phone (stdlib only, fail-closed timeouts).
- **Tool schemas** — `describe_tool()` / `as_openai_tool()` / `mcp_tool()`
  derive JSON Schema from the signature the evidence commits to.
- **Archive rotation** — `interceptor archive [--keep N]` rotates the live
  journal to a timestamped file; the successor starts with a signed link to
  the predecessor's `(count, head)`.
- **Independent verifier** — `verifiers/node/verify.mjs` checks any journal
  with Node builtins only, cross-tested against Python-made journals.

## What problem this solves

An agent that can issue refunds, delete infrastructure, or send email needs two
things that are usually bolted on afterwards and separately: someone to say yes
before the irreversible part, and a record afterwards that survives the
argument about what happened.

Logging is not that record. A log line is written by the same process that
performed the action, in the same trust domain, with nothing preventing its
later edit. It answers "what did we print" rather than "what did we do."

This library aims at the narrow, checkable version: a signed statement that a
specific declared action, with a specific redacted input hash, was approved at
a specific point in a chain, and that the chain has not been reordered or
edited since. That is less than "proof the refund happened" and the difference
matters — [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) is explicit about
where the line falls.

## Redaction is fused into canonicalization

This is the design decision most worth explaining, because getting it wrong is
subtle and the failure is silent.

Evidence needs a deterministic serialization to hash. Secrets need removing
before that serialization. The obvious structure is two passes — redact, then
canonicalize — and it has a hole: any container type the canonicalizer expands
but the redactor does not becomes a route for named secrets into evidence.

Dataclasses are exactly that shape. A redactor written for mappings does not
recognise `Credentials(api_key="sk-live-...")` as having named fields, so it
passes it through untouched. The canonicalizer must expand it to produce
deterministic output, so it becomes `{"api_key": "sk-live-..."}` — with the
secret intact, in the input hash, in the journal, and in the text shown to
whoever is being asked to approve the call.

Named tuples are worse, because a named tuple *is* a `tuple`: a sequence-aware
redactor flattens it positionally and the field names cease to exist before
anything can match against them.

Here they are one traversal. A single function decides how a value expands, and
it consults the sensitive-name set at every point where it produces a name, so
expansion without redaction is unrepresentable rather than merely discouraged.
`tests/test_redaction_property.py` asserts the property over generated nested
structures rather than over a list of types someone thought of.

## Usage

### Approval

The default provider prompts on the controlling terminal and denies on anything
that is not an explicit yes. Off a TTY — CI, cron, a daemon — it raises rather
than assuming consent.

```python
from interceptor import ApprovalDecision, guard


class PolicyProvider:
    def decide(self, request):
        if request.risk in ("low", "medium"):
            return ApprovalDecision("allowed", "auto-approved by policy")
        return ApprovalDecision("denied", "high risk needs a human")


@guard(action="deploy.staging", approval_provider=PolicyProvider())
def deploy(ref: str): ...
```

The provider sees the action name, declared risk, input hash, contract hash,
and a bounded **redacted** summary. It never sees raw arguments. Its answer —
`ApprovalDecision("allowed", reason, approved_by=...)` — is recorded on the
decision event (scrubbed of redacted values), so the journal says who approved
what and why.

### Redaction

Built-in names (`api_key`, `password`, `token`, `secret`, `authorization`, and
others) are matched at any depth, case-insensitively and confusable-insensitively
(NFKC, accent stripping, and common Cyrillic/Greek lookalikes fold to ASCII, so
`api_kеy` with a Cyrillic е is redacted like `api_key`). Add your own:

```python
@guard(action="user.verify", redact=["pin", "ssn"])
def verify(user_id: str, pin: str): ...
```

On top of name-based redaction, built-in **value patterns** catch secrets
passed under generic names (`data`, `payload`) or embedded in larger strings:
`sk-live-…`/`sk-test-…`, `ghp_…`/`gho_…`, `xoxb-…`, `AKIA…`, PEM private keys,
and JWTs. Any string value matching one becomes `<REDACTED>`, its output hash
is suppressed, and exception text is scrubbed. Add your own regexes:

```python
@guard(action="orders.create", redact_patterns=[r"ORDER-\d{6}"])
def create(payload: str): ...
```

### Policy approvals

`interceptor.policy` ships composable, offline providers — budgets, sliding-window
rate limits, allow-lists/predicates, TTL caching of identical allows, timeouts,
and `AllOf`/`AnyOf` combinations:

```python
from interceptor import TerminalApprovalProvider
from interceptor.policy import (
    AllOf,
    BudgetProvider,
    RateLimitProvider,
    TimeoutApprovalProvider,
)

policy = AllOf(
    [
        BudgetProvider(100, per_action=True),
        RateLimitProvider(10, window_seconds=60),
        TimeoutApprovalProvider(TerminalApprovalProvider(), timeout_seconds=300),
    ]
)


@guard(action="billing.refund", risk="high", approval_provider=policy)
def refund(order_id: str, amount_cents: int): ...
```

All deny on exhaustion/error (fail closed) and perform no I/O. `CachedApprovalProvider`
remembers identical `allowed` decisions for a TTL so repeats don't re-prompt —
each call still writes its own decision/outcome evidence; denials are never cached.

Enforce the witness schedule inside approval so a stale off-host witness blocks
high-risk actions instead of merely paging afterwards:

```python
from interceptor import WitnessFreshnessProvider

policy = AllOf(
    [
        BudgetProvider(100, per_action=True),
        WitnessFreshnessProvider(
            "/mnt/backup-witness",
            max_age_seconds=600,
            risks={"high", "critical"},
        ),
    ]
)
```

For policy-as-config instead of policy-as-code, use glob rules from a JSON file:

```json
{"default": "denied",
 "rules": [{"action": "billing.*", "decision": "denied",
            "risks": ["high", "critical"], "reason": "needs a human"},
           {"action": "deploy.*", "decision": "allowed", "risks": ["low"]}]}
```

```python
from interceptor import load_policy_file

policy = load_policy_file("policy.json")  # first match wins, default deny
```

Quorums compose with everything above — two independent approvers beat one:

```python
from interceptor.policy import QuorumApprovalProvider

two_humans = QuorumApprovalProvider([duty_officer, team_lead], quorum=2)
```

And for approvals from a browser or a phone on the LAN (standard library only,
token-authenticated, fail-closed on timeout):

```python
from interceptor import ApprovalServer, ServerApprovalProvider

server = ApprovalServer()  # prints server.url — keep it private
print("Approve at:", server.url)


@guard(action="deploy.prod", approval_provider=ServerApprovalProvider(server))
def deploy(ref: str): ...
```

### Idempotency and dry runs

Pass `idempotency_key` as a parameter name, a literal, or a callable over the
bound arguments. A key that already completed successfully records a denied
decision and raises `DuplicateActionError` (a subclass of `ActionDenied`)
without executing — retries after failure are still allowed:

```python
from interceptor import guard


@guard(action="billing.refund", risk="high", idempotency_key="order_id")
def refund(order_id: str, amount_cents: int): ...
```

Cross-process detection scans the file journal; custom `JournalStore`s are
covered within the process. This blocks duplicates — it does not replay
results, since results are never stored.

`dry_run=True` records the signed decision event and returns `None` without
executing and without an outcome. Audits classify it as `dry_run`, never as
needing reconciliation. `DuplicateActionError` subclasses `ActionDenied`, so
existing denial handlers catch duplicate attempts too.

### Receipts

A succeeded outcome can carry the provider's own reference IDs — the payment
processor's refund id, the cloud request id — extracted from the result:

```python
@guard(
    action="billing.refund",
    receipt_from=lambda result: {"processor": "acme", "refund_id": result["id"]},
)
def refund(order_id: str) -> dict: ...
```

The receipt is canonicalized and redacted like inputs, bounded, and optional:
extraction errors, non-mapping, or oversized receipts drop it without failing
a call that already succeeded. It upgrades "the function returned" to "the
function named this external record" — reconcilable against provider
statements, but still a transcribed claim, not proof the provider acted.

### Wrapping tools you did not write

```python
from interceptor import wrap_tools

safe_tools = wrap_tools(existing_tools, risk="high")  # action per tool name
# or pin every action explicitly:
safe_tools = wrap_tools(
    existing_tools,
    configuration={
        "refund": {"action": "billing.refund", "risk": "high"},
    },
)
```

### Describing tools to frameworks

```python
from interceptor import as_openai_tool, describe_tool, mcp_tool

describe_tool(refund)  # {"name", "description", "parameters": JSON Schema}
as_openai_tool(refund)  # {"type": "function", "function": {...}}
mcp_tool(server, refund)  # register on an MCP server; the guard stays on
```

Schemas derive from the signature the evidence commits to, so the description
a framework shows can never disagree with the contract the journal records.

### Async functions

`@guard` and `wrap_tool` accept `async def` functions too — the guarded
callable stays a coroutine function, with the same decision/outcome evidence:

```python
@guard(action="billing.refund", risk="high")
async def refund(customer_id: str, amount_cents: int) -> dict:
    return await payments.refund(customer_id, amount_cents)
```

Generator and async-generator functions are rejected: guarding a generator
would record an outcome before any work runs.

### Verifying

```sh
interceptor verify --journal ./journal.jsonl --public-key ./verify_key.pem
interceptor audit --journal ./journal.jsonl --public-key ./verify_key.pem
interceptor inspect          # what would this journal disclose if shared?
interceptor key-info
interceptor key-rotate      # replace the signing key; old events stay verifiable
interceptor keygen --output ./counter.pem   # standalone key for counter-signing
interceptor resolve --decision <id> --result completed|not-completed
interceptor export --format html --output ./pack.html
interceptor stats
interceptor archive --keep 12   # rotate the live journal, keep 12 predecessors
```

Journals are checkable without this package: `verifiers/node/verify.mjs`
implements `docs/EVIDENCE_FORMAT.md` with Node builtins only, and the test
suite cross-verifies Python-made journals with it.

`verify` checks signatures and the hash chain. Each event must be signed by a
key the operator trusts: pass `--public-key` (repeatable) to pin specific keys,
or omit it to use the trusted key set registered in the evidence home
(`trusted_keys/`). `audit` then pairs every decision
with its outcome and gives an operational status: `denied`, `succeeded`,
`failed`, `dry_run`, `resolved_completed`, `resolved_not_completed`, or
`needs_reconciliation`. Failed calls and allowed decisions with no
outcome make the command exit non-zero: an external side effect may have
completed before an exception or process death, so the operator must check the
external system before any retry. It also rejects duplicate outcomes, orphan
outcomes, outcomes for denied decisions, identity mismatches between a
decision and its outcome, and repeated `(action, idempotency_key)` successes
(`duplicate_idempotency_key`).

```console
$ interceptor audit
~/.interceptor/journal.jsonl
  needs_reconciliation     billing.refund
    decision: 4f6a...
  ATTENTION: one or more allowed actions failed or have no outcome.
  Check the external system before retrying; the side effect may have occurred.
```

This is a reconciliation queue, not proof of the external-world result. A
recorded `succeeded` status still means only that the Python function returned
without raising.

`inspect` exists because the journal is designed to be shareable, and "designed
to be" is not the same as "is". It classifies each action by whether its
recorded inputs are fully redacted, so you can check before sending one to an
auditor.

### Resolving reconciliations

`audit` flags an allowed decision with no outcome (or a failed one) as
`needs_reconciliation`: the side effect may have happened, so check the
external system before retrying — then record what you found:

```console
$ interceptor resolve --decision 4f6a... --result not-completed --note "no charge made"
Resolved 4f6a... as confirmed_not_completed
  event:   9c2e...
  journal: ~/.interceptor/journal.jsonl
```

The resolution is a signed event on the same chain, and `audit` clears the
invocation to `resolved_completed` (do not retry) or `resolved_not_completed`
(retry is safe). It is an operator attestation, not proof — conflicting
resolutions are flagged, never silently merged.

### Counter-signing checkpoints

One local key can forge its own journal. A second key held elsewhere — a
manager, an auditor, a witness box — raises that bar to two keys:

```console
$ interceptor keygen --output ./counter.pem        # lives outside ~/.interceptor
$ interceptor checkpoint
$ interceptor countersign --signing-key ./counter.pem
Counter-signed checkpoint 7bd1...
  events committed: 42
  counter key_id:   ed25519:9f3c...
```

Verification checks the countersignature against the trusted keyring, so pass
the counter public key too: `interceptor verify --public-key ./counter-pub.pem`.
Only countersign checkpoints you have verified.

### Exporting evidence packs

```console
$ interceptor export --format html --output ./pack.html
$ interceptor stats
~/.interceptor/journal.jsonl  (valid)
  43 events: 20 decisions, 19 outcomes, 1 resolutions, 1 countersignatures, 2 checkpoints
      12  billing.refund
```

The JSON pack carries the verification result, the audit, and the signed events;
the HTML pack is a single self-contained report for humans.

### Key rotation

`key-rotate` replaces the local signing key. The outgoing public key stays in
`trusted_keys/` inside the evidence home, and verification defaults to that
whole set — so a journal spanning a rotation still verifies as one chain, with
each event checked against the key that actually signed it. This bounds the
blast radius of a compromised key going forward: new events cannot be forged
with an older key. The trusted set is local operator state, not a signature;
pin the public key out of band with `--public-key` for real authentication.

### Archiving old journals

```console
$ interceptor archive --keep 12
Archived ~/.interceptor/journal.jsonl to ~/.interceptor/journal-20260903T120000Z.jsonl
  events archived: 1024
  prior head:      a1b2...
```

The new live file starts with a signed `archive` event linking to the
predecessor's `(count, head)`; both files verify standalone, and custody
follows the links. Archive while writers are quiesced, keep predecessors where
the live journal cannot reach, and note that `--keep` deletion destroys
evidence — a custody chain with a missing link proves nothing about the gap.

### Checkpoints and tail truncation

Deleting events from the *end* of the journal is undetectable from the journal
alone — every remaining event still chains correctly. The `checkpoint` command
closes that gap with a signed, durable witness:

```console
$ interceptor checkpoint
Checkpointed ~/.interceptor/journal.jsonl
  events committed: 42
  head sha256:      a1b2...
  witness:          ~/.interceptor/journal.jsonl.checkpoint
  Keep the witness somewhere the journal cannot reach; verify with
    interceptor verify --checkpoint ~/.interceptor/journal.jsonl.checkpoint
```

The checkpoint event commits to the event count at that moment. Copy the
witness file somewhere the journal cannot reach (a backup, a second machine);
`verify --checkpoint` then fails any journal with fewer events than the
checkpoint committed to. Without a witness, `verify` notes that tail truncation
is undetectable. See `docs/THREAT_MODEL.md`.

### Reaching outward, if you must

The library makes no network calls and has no configuration that would cause
one. If you need a central registry of declared actions, that is a single
explicit seam:

```python
class Registry:
    def contract_declared(self, contract):
        requests.post(URL, json={"action": contract.action_name, "hash": contract.contract_hash})


@guard(action="billing.refund", observer=Registry())
def refund(order_id: str, amount_cents: int): ...
```

Called once per contract version, before approval and before execution, with
the contract only — never arguments, results, events, or keys. If it raises,
the function does not run. There is no silent fallback, because a recorder that
quietly stops recording is worse than one that stops.

## What the evidence does and does not establish

**Does**, given the verifying key and the journal file:

- an action with this declared contract was approved before execution;
- the recorded inputs hash to this value, after redaction;
- events have not been edited, reordered, or removed from the middle;
- each event was signed by a key in the trusted set, checked per event.

**Does not**:

- prove the external side effect occurred. The record says the function was
  called and what it returned, not what the payment processor did;
- detect deletion of the journal's **tail**. Truncation needs an external
  witness — a checkpoint, a counter-signature, an append-only remote;
- protect against an attacker who holds a *current* signing key. It is a local
  file; anyone who can read it can forge new events. Rotation bounds this
  going forward — old events cannot be forged with a newer key — but not the
  past, and the trusted set authenticates nothing by itself;
- replay results for idempotent calls. `idempotency_key` *blocks* a second
  execution of a completed key (raising `DuplicateActionError`) but never
  replays a stored result — results are not stored, and retries after failure
  are allowed. Cross-process detection scans the file journal; custom
  `JournalStore`s are covered within the process only.

`ExecutionCompletedEvidenceError` names the one genuinely awkward state — the
function ran, the outcome could not be recorded — as its own exception type, so
callers can distinguish it from "did not run" instead of guessing.

## Development

```sh
uv sync          # creates .venv, installs the package + dev group from uv.lock
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

`uv.lock` pins the full dependency tree — CI runs `uv sync --frozen`, so a
stale lock fails fast and dependency changes always show up as explicit diffs.
Prefer `uv add` for new dependencies so the lock stays in sync. Plain `pip`
still works (`pip install -e . pytest hypothesis pytest-cov`), since
`pyproject.toml` remains the single source of truth.

The suite runs under an autouse fixture that makes socket creation raise, so a
network call introduced anywhere fails the tests rather than the audit.
Coverage must stay at or above 85% (`pytest` enforces the gate).

## Provenance and license

Renamed to `interceptor` from an internal agent-action layer. New since the
rename: the fused value-pattern redaction, the `interceptor.policy` providers,
idempotency keys with `DuplicateActionError`, dry runs with a `dry_run` audit
status, configuration-free `wrap_tools`, and the weak-reference observer
tracker — alongside the original fused name redaction, observer seam, tail-read
journal, and private-key permission check. See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
and [`docs/EVIDENCE_FORMAT.md`](docs/EVIDENCE_FORMAT.md).

Stability and changes: [`docs/API_STABILITY.md`](docs/API_STABILITY.md) states
what is stable and how deprecations ship; [`CHANGELOG.md`](CHANGELOG.md) records
every notable change.

MIT.
