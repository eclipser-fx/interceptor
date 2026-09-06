/**
 * Exactly-once reservations over the journal, enforced with two layers that
 * mirror the Python engine:
 *
 * 1. An STM registry of keys this process already completed (covers custom
 *    stores and avoids rescanning for known keys).
 * 2. A file scan for a *blocking* prior decision: `allowed` with a missing
 *    (in-flight) or `succeeded` outcome. `failed` outcomes, denials, dry
 *    runs, and `confirmed_not_completed` resolutions (without a contradicting
 *    success) release the key.
 *
 * The authoritative check runs inside a per-journal mutex at decision-append
 * time, so concurrent fibers racing the same key produce exactly one
 * execution; losers record a denied duplicate. A mutex is per-process by
 * nature — cross-process file locking is a documented follow-up, same as the
 * pre-lock Python history.
 */
import { readFileSync } from "node:fs";
import { Data, Effect, STM, TMap } from "effect";
import { JournalError } from "./Journal.js";
import type { EventRecord } from "./Journal.js";

export class IdempotencyError extends Data.TaggedError("IdempotencyError")<{
  readonly message: string;
}> {}

export class DuplicateActionError extends Data.TaggedError("DuplicateActionError")<{
  readonly actionName: string;
  readonly idempotencyKey: string;
  readonly duplicateOf: string | null;
}> {}

interface JournalState {
  readonly decisions: Map<string, EventRecord>;
  readonly outcomes: Map<string, Array<EventRecord>>;
  readonly resolutions: Map<string, Array<EventRecord>>;
}

const emptyState = (): JournalState => ({
  decisions: new Map<string, EventRecord>(),
  outcomes: new Map<string, Array<EventRecord>>(),
  resolutions: new Map<string, Array<EventRecord>>(),
});

/**
 * Read and classify the journal. A missing file means "no blocker" (first
 * call); any other I/O failure fails closed with `JournalError` — an
 * unreadable journal must never read as a free key.
 */
const readState = (journalPath: string): Effect.Effect<JournalState, JournalError> =>
  Effect.try({
    try: () => {
      const state = emptyState();
      let content: string;
      try {
        content = readFileSync(journalPath, "utf8");
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException)?.code === "ENOENT") return state;
        throw cause;
      }
    for (const raw of content.split("\n")) {
      if (!raw.trim()) continue;
      let event: unknown;
      try {
        event = JSON.parse(raw);
      } catch {
        continue;
      }
      if (typeof event !== "object" || event === null) continue;
      const record = event as EventRecord;
      if (record["event_type"] === "decision") {
        if (typeof record["event_id"] === "string" && !state.decisions.has(record["event_id"])) {
          state.decisions.set(record["event_id"], record);
        }
      } else if (record["event_type"] === "outcome") {
        if (typeof record["decision_event_id"] === "string") {
          const list = state.outcomes.get(record["decision_event_id"]) ?? [];
          list.push(record);
          state.outcomes.set(record["decision_event_id"], list);
        }
      } else if (record["event_type"] === "resolution") {
        if (typeof record["decision_event_id"] === "string") {
          const list = state.resolutions.get(record["decision_event_id"]) ?? [];
          list.push(record);
          state.resolutions.set(record["decision_event_id"], list);
        }
      }
    }
    return state;
    },
    catch: (cause) =>
      cause instanceof JournalError
        ? cause
        : new JournalError({ message: `cannot scan journal ${journalPath}: ${cause}` }),
  });

/** Earliest blocking decision, or null. Same rules as the Python engine. */
export const findBlocking = (
  state: JournalState,
  actionName: string,
  key: string,
): EventRecord | null => {
  const cleared = new Map<string, boolean>();
  for (const [decisionId, linked] of state.resolutions) {
    if (linked.length > 0) {
      cleared.set(decisionId, String(linked[linked.length - 1]["resolution"]) === "confirmed_not_completed");
    }
  }
  for (const [eventId, event] of state.decisions) {
    if (
      event["decision"] !== "allowed" ||
      event["action_name"] !== actionName ||
      event["idempotency_key"] !== key ||
      event["dry_run"] === true
    ) {
      continue;
    }
    const linked = state.outcomes.get(eventId) ?? [];
    if (linked.some((o) => o["status"] === "succeeded")) return event;
    if (linked.length === 0 && cleared.get(eventId) === true) continue;
    if (linked.length === 0) return event;
    // Only failed outcomes: retry is safe.
  }
  return null;
};

export const scanBlocking = (
  journalPath: string,
  actionName: string,
  key: string,
): Effect.Effect<EventRecord | null, JournalError> =>
  Effect.map(readState(journalPath), (state) => findBlocking(state, actionName, key));

/** In-process completions, transactional so check-and-mark compose. */
export class CompletionRegistry {
  private constructor(private readonly map: TMap.TMap<string, true>) {}

  static make(): Effect.Effect<CompletionRegistry, never> {
    return Effect.map(STM.commit(TMap.empty<string, true>()), (map) => new CompletionRegistry(map));
  }

  private static key(journalPath: string, actionName: string, key: string): string {
    // NUL separators: journal paths and keys may legally contain spaces.
    return `${journalPath}\0${actionName}\0${key}`;
  }

  /** Drop one journal's completions (after archive/rotation replaces the file). */
  forgetJournal(journalPath: string): Effect.Effect<void, never> {
    const prefix = `${journalPath}\0`;
    return STM.commit(
      STM.asVoid(
        STM.flatMap(TMap.keys(this.map), (keys) =>
          STM.forEach([...keys].filter((key) => key.startsWith(prefix)), (key: string) =>
            TMap.remove(this.map, key),
          ),
        ),
      ),
    );
  }

  isCompleted(journalPath: string, actionName: string, key: string): Effect.Effect<boolean, never> {
    return STM.commit(
      STM.map(
        TMap.get(this.map, CompletionRegistry.key(journalPath, actionName, key)),
        (opt) => opt._tag === "Some",
      ),
    );
  }

  markCompleted(journalPath: string, actionName: string, key: string): Effect.Effect<void, never> {
    return STM.commit(
      STM.asVoid(TMap.set(this.map, CompletionRegistry.key(journalPath, actionName, key), true as const)),
    );
  }
}

const semaphores = new Map<string, Effect.Semaphore>();

/**
 * Per-journal single-permit semaphore serializing the check-then-append
 * reservation. Permits are always released (acquireRelease semantics), so a
 * crashed fiber cannot wedge the journal.
 */
export const journalMutex = (journalPath: string): Effect.Semaphore => {
  const existing = semaphores.get(journalPath);
  if (existing !== undefined) return existing;
  const created = Effect.runSync(Effect.makeSemaphore(1));
  semaphores.set(journalPath, created);
  return created;
};
