/**
 * Minimal Effect-based guard: approval gate + signed decision/outcome
 * evidence over a `FileJournal`. Typed errors make fail-closed handling
 * exhaustive at compile time — denial, provider failure, and persistence
 * failure are distinct types, not branches of one catch.
 *
 * Redaction here is intentionally narrow (case-insensitive sensitive names
 * over plain JSON values); homoglyph folding and value patterns arrive with
 * the full canonicalizer port. The journal lines it writes already verify
 * under both this package and the Python verifier.
 */
import { createHash, randomUUID } from "node:crypto";
import { Data, Effect } from "effect";
import { canonical } from "./Canonical.js";
import type { SigningIdentity } from "./Identity.js";
import {
  CompletionRegistry,
  DuplicateActionError,
  journalMutex,
  scanBlocking,
} from "./Idempotency.js";
import { compileValuePatterns, foldName, valueMatchesPatterns } from "./Redaction.js";
import {
  SCHEMA_VERSION,
  finalizeEvent,
  utcTimestamp,
  type EventRecord,
  type FileJournal,
  type JournalError,
} from "./Journal.js";

const DUPLICATE_REASON = "duplicate idempotency key; already reserved or completed";

/** Process-wide completion registry backing every guard instance. */
const completions = Effect.runSync(CompletionRegistry.make());

export class ApprovalError extends Data.TaggedError("ApprovalError")<{
  readonly message: string;
}> {}

export class ActionDenied extends Data.TaggedError("ActionDenied")<{
  readonly actionName: string;
  readonly reason: string;
}> {}

export class ContractError extends Data.TaggedError("ContractError")<{
  readonly message: string;
}> {}

export class GuardedCallFailed extends Data.TaggedError("GuardedCallFailed")<{
  readonly actionName: string;
  readonly cause: unknown;
}> {}

export interface ApprovalRequest {
  readonly actionName: string;
  readonly risk: string;
  readonly approvalMode: string;
  readonly redactedInputSummary: string;
  readonly inputHash: string;
  readonly contractHash: string;
  readonly spendCents?: number | null;
}

export interface ApprovalDecision {
  readonly decision: "allowed" | "denied";
  readonly reason: string;
  readonly approvedBy?: string;
}

export type Approve = (request: ApprovalRequest) => Effect.Effect<ApprovalDecision, ApprovalError>;

export const SENSITIVE_NAMES: ReadonlySet<string> = new Set([
  "access_token",
  "api_key",
  "apikey",
  "auth_header",
  "authorization",
  "client_secret",
  "credential",
  "credentials",
  "passwd",
  "password",
  "private_key",
  "refresh_token",
  "secret",
  "secret_key",
  "session_token",
  "token",
]);

export const REDACTED = "<REDACTED>";

const isSensitiveName = (name: string, sensitive: ReadonlySet<string>): boolean =>
  sensitive.has(foldName(name));

export interface Redacted {
  readonly value: unknown;
  /** Raw string values that were removed — for scrubbing persisted text only. */
  readonly removed: ReadonlyArray<string>;
}

/**
 * Redact plain JSON values by (case-insensitive) name; mirrors the v1
 * marker. Collects every removed raw string so error text, approval reasons,
 * and output hashes can be scrubbed or suppressed exactly like the engine.
 */
export const redact = (
  value: unknown,
  sensitive: ReadonlySet<string> = SENSITIVE_NAMES,
  patterns: ReadonlyArray<RegExp> = [],
): Redacted => {
  const removed: Array<string> = [];
  const erase = (item: unknown): void => {
    if (typeof item === "string" && item !== "") removed.push(item);
    else if (item !== null && item !== undefined && typeof item !== "string") {
      removed.push(String(item));
    }
  };
  const walk = (node: unknown): unknown => {
    if (typeof node === "string") {
      if (valueMatchesPatterns(node, patterns)) {
        erase(node);
        return REDACTED;
      }
      return node;
    }
    if (Array.isArray(node)) return node.map(walk);
    if (typeof node === "object" && node !== null) {
      const out: Record<string, unknown> = {};
      for (const [key, item] of Object.entries(node)) {
        if (isSensitiveName(key, sensitive)) {
          erase(item);
          out[key] = REDACTED;
        } else {
          out[key] = walk(item);
        }
      }
      return out;
    }
    return node;
  };
  return { value: walk(value), removed };
};

/** Legacy shape: redacted value only. Prefer {@link redact}. */
export const redactValue = (value: unknown): unknown => redact(value).value;

/** Replace removed raw values in persisted text (approval reasons, errors). */
export const scrubText = (
  text: string,
  removed: ReadonlyArray<string>,
  patterns: ReadonlyArray<RegExp> = [],
  maxChars = 300,
): string => {
  const unique = [...new Set(removed.filter((v) => v !== ""))].sort((a, b) => b.length - a.length);
  for (const raw of unique) text = text.split(raw).join(REDACTED);
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    text = text.replace(pattern, REDACTED);
  }
  return text.length <= maxChars ? text : text.slice(0, maxChars);
};

/** Per-parameter retention states for the decision event (cross-impl audit). */
export const parameterRetention = (canonicalInput: unknown): Array<{ name: string; state: string }> => {
  if (typeof canonicalInput !== "object" || canonicalInput === null || Array.isArray(canonicalInput)) {
    return [];
  }
  return Object.keys(canonicalInput)
    .sort()
    .map((name) => {
      const value = (canonicalInput as Record<string, unknown>)[name];
      if (value === REDACTED) return { name, state: "redacted" };
      if (typeof value === "string" && value.startsWith("<unsupported:")) {
        return { name, state: "unsupported" };
      }
      return { name, state: "retained" };
    });
};

const boundedSummary = (canonicalInput: unknown): string => {
  if (typeof canonicalInput !== "object" || canonicalInput === null || Array.isArray(canonicalInput)) {
    return JSON.stringify(canonicalInput ?? null).slice(0, 2000);
  }
  const parts = Object.keys(canonicalInput)
    .sort()
    .map((name) => `${name}=${JSON.stringify((canonicalInput as Record<string, unknown>)[name]).slice(0, 120)}`);
  return parts.join(", ").slice(0, 2000);
};

export interface GuardOptions {
  readonly action: string;
  readonly risk?: string;
  readonly journal: FileJournal;
  readonly approve: Approve;
  readonly identity: SigningIdentity;
  /** Stable code-location identity, e.g. `module.fn`. Defaults to the action. */
  readonly actionId?: string;
  /**
   * Parameter names for positional args, zipped into `{name: value}` before
   * redaction — the equivalent of Python's bound arguments. Without it,
   * positional secrets have no name to match and stay visible.
   */
  readonly parameterNames?: ReadonlyArray<string>;
  /**
   * Duplicate guard: a literal key, or a function over the bound-argument
   * object. A completed (or in-flight) key records a denied duplicate and
   * raises `DuplicateActionError` without executing; failures and
   * `confirmed_not_completed` resolutions release the key. The key itself is
   * journaled, so never derive it from a secret.
   */
  readonly idempotencyKey?: string | ((bound: Record<string, unknown>) => string);
  /** Record the signed decision and return without executing (no outcome). */
  readonly dryRun?: boolean;
  /** Extract a provider receipt from a succeeded result for the outcome. */
  readonly receiptFrom?: (result: unknown) => unknown;
  /** Extra names to redact (case- and confusable-insensitive), beyond built-ins. */
  readonly redact?: ReadonlyArray<string>;
  /** Extra value regexes to redact (on top of built-in secret shapes). */
  readonly redactPatterns?: ReadonlyArray<string>;
  /**
   * Declared spend in minor units, from the bound-argument object (or a
   * literal). Recorded on the decision event and visible to budgets as
   * `spendCents`. Invalid declarations fail closed with `ContractError`.
   */
  readonly spendFrom?: number | ((bound: Record<string, unknown>) => number | null) | null;
}

/**
 * Guard `fn`: record a signed decision, run on allow, record the outcome.
 * Returns an Effect — composition, retries, and error handling stay in
 * Effect-land with the caller.
 */
const resolveSpend = (
  spec: GuardOptions["spendFrom"],
  bound: Record<string, unknown>,
  actionName: string,
): Effect.Effect<number | null, ContractError> => {
  if (spec === undefined || spec === null) return Effect.succeed(null);
  if (typeof spec === "number") {
    return Number.isInteger(spec) && spec >= 0
      ? Effect.succeed(spec)
      : Effect.fail(
          new ContractError({
            message: `spend for action '${actionName}' must be a non-negative int of minor units`,
          }),
        );
  }
  let raw: number | null;
  try {
    raw = spec(bound);
  } catch (cause) {
    return Effect.fail(
      new ContractError({ message: `spend extractor failed for action '${actionName}': ${cause}` }),
    );
  }
  if (raw === null) return Effect.succeed(null);
  if (!Number.isInteger(raw) || (raw as number) < 0) {
    return Effect.fail(
      new ContractError({
        message: `spend for action '${actionName}' must be a non-negative int of minor units`,
      }),
    );
  }
  return Effect.succeed(raw);
};

export const guard = (options: GuardOptions) =>
  <A extends Array<unknown>, Result>(fn: (...args: A) => Promise<Result> | Result) =>
  (...args: A): Effect.Effect<
    Result | undefined,
    ApprovalError | ActionDenied | JournalError | ContractError | DuplicateActionError | GuardedCallFailed
  > => {
    const actionId = options.actionId ?? options.action;
    const risk = options.risk ?? "medium";
    const journalPath = options.journal.path;
    const sensitive: ReadonlySet<string> = new Set([
      ...SENSITIVE_NAMES,
      ...(options.redact ?? []).map((name) => foldName(name)),
    ]);
    // Compiled once per guarded function; invalid regexes fail here, never mid-call.
    let patterns: ReadonlyArray<RegExp>;
    try {
      patterns = compileValuePatterns(options.redactPatterns);
    } catch (cause) {
      throw new ContractError({
        message: cause instanceof Error ? cause.message : String(cause),
      });
    }
    return Effect.gen(function* () {
      const bound: Record<string, unknown> =
        options.parameterNames !== undefined
          ? Object.fromEntries(
              args.map((value, index) => [options.parameterNames?.[index] ?? `$${index}`, value]),
            )
          : Object.fromEntries(args.map((value, index) => [`$${index}`, value]));
      const { value: redacted, removed } = redact(bound, sensitive, patterns);
      const inputHash = createHash("sha256").update(canonical(redacted), "utf8").digest("hex");
      const summary = boundedSummary(redacted);
      const contract = createHash("sha256")
        .update(canonical({ action: options.action, actionId, risk }), "utf8")
        .digest("hex");

      // Resolve the idempotency key and declared spend before anything
      // observable. Fail closed on either.
      const spendCents = yield* resolveSpend(options.spendFrom, bound, options.action);
      let key: string | null = null;
      if (options.idempotencyKey !== undefined) {
        if (typeof options.idempotencyKey === "string") {
          key = options.idempotencyKey;
        } else {
          try {
            const raw = options.idempotencyKey(bound);
            if (typeof raw !== "string" || raw === "") {
              return yield* Effect.fail(
                new ContractError({
                  message: `idempotency key for action '${options.action}' must resolve to a non-empty string`,
                }),
              );
            }
            key = raw;
          } catch (cause) {
            return yield* Effect.fail(
              new ContractError({
                message: `idempotency key function failed for action '${options.action}': ${cause}`,
              }),
            );
          }
        }
      }

      const duplicateDecision = (duplicateOf: string | null) => ({
        schema_version: SCHEMA_VERSION,
        event_type: "decision",
        event_id: randomUUID(),
        action_id: actionId,
        action_name: options.action,
        contract_hash: contract,
        timestamp_utc: utcTimestamp(),
        key_id: options.identity.keyId,
        previous_event_hash: null as string | null,
        decision: "denied",
        risk,
        approval_mode: "required",
        redacted_input_summary: summary,
        input_hash: inputHash,
        ...(spendCents !== null ? { spend_cents: spendCents } : {}),
        idempotency_key: key,
        approval_reason: DUPLICATE_REASON,
        ...(duplicateOf !== null ? { duplicate_of: duplicateOf } : {}),
      } satisfies EventRecord);

      // Pre-check (best-effort UX): obvious duplicates never prompt.
      if (key !== null) {
        if (yield* completions.isCompleted(journalPath, options.action, key)) {
          yield* options.journal.appendEvent((previousHash) =>
            finalizeEvent({ ...duplicateDecision(null), previous_event_hash: previousHash }, options.identity),
          );
          return yield* Effect.fail(
            new DuplicateActionError({
              actionName: options.action,
              idempotencyKey: key as string,
              duplicateOf: null,
            }),
          );
        }
        const prior = yield* scanBlocking(journalPath, options.action, key);
        if (prior !== null) {
          const priorId = prior["event_id"];
          yield* options.journal.appendEvent((previousHash) =>
            finalizeEvent(
              {
                ...duplicateDecision(typeof priorId === "string" ? priorId : null),
                previous_event_hash: previousHash,
              },
              options.identity,
            ),
          );
          return yield* Effect.fail(
            new DuplicateActionError({
              actionName: options.action,
              idempotencyKey: key as string,
              duplicateOf: typeof priorId === "string" ? priorId : null,
            }),
          );
        }
      }

      // Provider defects normalize to ApprovalError (fail closed), mirroring
      // the engine: typed ApprovalError failures pass through untouched, while
      // defects (which would otherwise escape the documented channel) become
      // fail-closed approval failures.
      const decision = yield* options
        .approve({
          actionName: options.action,
          risk,
          approvalMode: "required",
          redactedInputSummary: summary,
          inputHash,
          contractHash: contract,
          spendCents,
        })
        .pipe(
          Effect.catchAllDefect((defect) =>
            Effect.fail(
              new ApprovalError({
                message: `approval provider defected for action '${options.action}': ${String(defect).slice(0, 200)}`,
              }),
            ),
          ),
        );

      const allowedFields = {
        parameter_retention: parameterRetention(redacted),
        schema_version: SCHEMA_VERSION,
        event_type: "decision",
        event_id: randomUUID(),
        action_id: actionId,
        action_name: options.action,
        contract_hash: contract,
        timestamp_utc: utcTimestamp(),
        key_id: options.identity.keyId,
        previous_event_hash: null as string | null,
        decision: decision.decision,
        risk,
        approval_mode: "required",
        redacted_input_summary: summary,
        input_hash: inputHash,
        ...(spendCents !== null ? { spend_cents: spendCents } : {}),
        approval_reason: scrubText(decision.reason, removed, patterns),
        ...(decision.approvedBy !== undefined
          ? { approved_by: scrubText(decision.approvedBy, removed, patterns, 120) }
          : {}),
        ...(key !== null ? { idempotency_key: key } : {}),
        ...(options.dryRun === true ? { dry_run: true } : {}),
      } satisfies EventRecord;

      // Authoritative reservation under the per-journal mutex: only the first
      // concurrent racer appends `allowed`; losers append a denied duplicate.
      // The outcome travels in a discriminated wrapper, never re-derived
      // from the recorded reason text.
      const mutex = journalMutex(journalPath);
      interface Reserved {
        readonly event: EventRecord;
        readonly duplicateOf: string | null | undefined;
      }
      const reserved: Reserved = yield* mutex.withPermits(1)(
        Effect.gen(function* () {
          if (key !== null) {
            if (yield* completions.isCompleted(journalPath, options.action, key)) {
              const event = yield* options.journal.appendEvent((previousHash) =>
                finalizeEvent(
                  { ...duplicateDecision(null), previous_event_hash: previousHash },
                  options.identity,
                ),
              );
              return { event, duplicateOf: null } as Reserved;
            }
            const blocking = yield* scanBlocking(journalPath, options.action, key);
            if (blocking !== null) {
              const blockingId = blocking["event_id"];
              const of = typeof blockingId === "string" ? blockingId : null;
              const event = yield* options.journal.appendEvent((previousHash) =>
                finalizeEvent(
                  { ...duplicateDecision(of), previous_event_hash: previousHash },
                  options.identity,
                ),
              );
              return { event, duplicateOf: of } as Reserved;
            }
          }
          const event = yield* options.journal.appendEvent((previousHash) =>
            finalizeEvent({ ...allowedFields, previous_event_hash: previousHash }, options.identity),
          );
          return { event, duplicateOf: undefined } as Reserved;
        }),
      );
      const decisionEvent = reserved.event;
      if (reserved.duplicateOf !== undefined) {
        return yield* Effect.fail(
          new DuplicateActionError({
            actionName: options.action,
            idempotencyKey: key as string,
            duplicateOf: reserved.duplicateOf,
          }),
        );
      }
      if (decision.decision !== "allowed") {
        return yield* Effect.fail(
          new ActionDenied({ actionName: options.action, reason: decision.reason }),
        );
      }
      if (options.dryRun === true) return undefined;

      // tryPromise (not promise): a rejection is an expected failure carrying
      // the reason, not a fiber defect. promise would defect and escape the
      // failed-outcome recording below.
      const settled = yield* Effect.either(
        Effect.tryPromise({
          try: () => Promise.resolve().then(() => fn(...args)),
          catch: (cause) => cause,
        }),
      );
      if (settled._tag === "Left") {
        const cause: unknown = settled.left;
        yield* options.journal.appendEvent((previousHash) =>
          finalizeEvent(
            {
              schema_version: SCHEMA_VERSION,
              event_type: "outcome",
              event_id: randomUUID(),
              action_id: actionId,
              action_name: options.action,
              contract_hash: contract,
              timestamp_utc: utcTimestamp(),
              key_id: options.identity.keyId,
              previous_event_hash: previousHash,
              status: "failed",
              decision_event_id: decisionEvent["event_id"],
              observed_result_type: null,
              exception_type: cause instanceof Error ? cause.constructor.name : "Unknown",
              sanitized_error_summary: scrubText(
                String(cause instanceof Error ? cause.message : cause),
                removed,
                patterns,
              ),
            } satisfies EventRecord,
            options.identity,
          ),
        );
        return yield* Effect.fail(new GuardedCallFailed({ actionName: options.action, cause }));
      }
      const result: Result = settled.right;
      // Best-effort receipt (never fails a succeeded call); non-object
      // receipts are dropped, matching the engine.
      let receipt: unknown;
      try {
        receipt = options.receiptFrom === undefined ? undefined : options.receiptFrom(result);
      } catch {
        receipt = undefined;
      }
      const redactedReceipt =
        typeof receipt === "object" && receipt !== null
          ? redact(receipt, sensitive, patterns).value
          : undefined;
      // Suppress the output hash when the result echoes a removed secret
      // (hashing it would commit something confirmable by guessing).
      const echoedSecret =
        result !== null &&
        result !== undefined &&
        removed.some((secret) => secret !== "" && String(result) === secret);
      const outputHash =
        echoedSecret || result === null || result === undefined
          ? undefined
          : createHash("sha256").update(canonical(redact(result, sensitive, patterns).value), "utf8").digest("hex");
      yield* options.journal.appendEvent((previousHash) =>
        finalizeEvent(
          {
            schema_version: SCHEMA_VERSION,
            event_type: "outcome",
            event_id: randomUUID(),
            action_id: actionId,
            action_name: options.action,
            contract_hash: contract,
            timestamp_utc: utcTimestamp(),
            key_id: options.identity.keyId,
            previous_event_hash: previousHash,
            status: "succeeded",
            decision_event_id: decisionEvent["event_id"],
            observed_result_type: result === null ? "null" : typeof result,
            ...(outputHash !== undefined ? { redacted_output_hash: outputHash } : {}),
            ...(redactedReceipt !== undefined ? { receipt: redactedReceipt } : {}),
          } satisfies EventRecord,
          options.identity,
        ),
      );
      if (key !== null) {
        yield* completions.markCompleted(journalPath, options.action, key);
      }
      return result;
    });
  };
