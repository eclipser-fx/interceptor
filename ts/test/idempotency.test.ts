/**
 * STM idempotency: exactly-once under concurrent fibers, duplicate denial
 * without execution, retry-after-failure, resolution release, dry runs.
 */
import { mkdtempSync, readFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Effect, Either, Fiber } from "effect";
import { describe, expect, it } from "vitest";
import { guard } from "../src/Guard.js";
import { generateIdentity } from "../src/Identity.js";
import {
  SCHEMA_VERSION,
  finalizeEvent,
  utcTimestamp,
  type EventRecord,
  type FileJournal,
} from "../src/Journal.js";
import { makeFileJournal } from "../src/Journal.js";
import { keyringFromPems, verifyLines } from "../src/Verify.js";

const allow = {
  approve: () => Effect.succeed({ decision: "allowed" as const, reason: "test" }),
};

const setup = () =>
  Effect.gen(function* () {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-idem-"));
    const journalPath = path.join(dir, "journal.jsonl");
    const identity = yield* generateIdentity();
    return { journalPath, journal: makeFileJournal(journalPath), identity };
  });

describe("idempotency", () => {
  it("blocks sequential duplicates without executing", async () => {
    const { journal, identity } = await Effect.runPromise(setup());
    let runs = 0;
    const act = guard({
      action: "billing.refund",
      journal,
      approve: allow.approve,
      identity,
      idempotencyKey: "order_id",
      parameterNames: ["orderId"],
    })((orderId: string) => {
      runs++;
      return orderId;
    });

    await Effect.runPromise(act("K-1"));
    const exit = await Effect.runPromise(Effect.flip(act("K-1")));
    expect(exit).toMatchObject({ _tag: "DuplicateActionError" });
    expect(runs).toBe(1);
    // In-process completions short-circuit before the journal scan, so no
    // prior id is linked — same as the Python engine.
    expect((exit as { duplicateOf: unknown }).duplicateOf).toBeNull();
  });

  it("executes exactly once under concurrent fibers", async () => {
    const { journal, identity } = await Effect.runPromise(setup());
    let runs = 0;
    const act = guard({
      action: "billing.refund",
      journal,
      approve: allow.approve,
      identity,
      idempotencyKey: "order_id",
      parameterNames: ["orderId"],
    // Genuinely async work so fibers overlap inside the reservation window
    // (a loop-blocked event loop would serialize them and prove nothing).
    })((orderId: string) =>
      (async () => {
        runs++;
        await new Promise((r) => setTimeout(r, 50));
        return orderId;
      })(),
    );

    // forkDaemon: fork would attach fibers to the runPromise scope, which
    // closes (interrupting children) before a later join runs.
    const fibers = await Effect.runPromise(
      Effect.all(Array.from({ length: 10 }, () => Effect.forkDaemon(Effect.either(act("RACE")))), {
        concurrency: "unbounded",
      }),
    );
    const joined: Array<unknown> = await Effect.runPromise(
      Effect.forEach(fibers, (f: Fiber.RuntimeFiber<unknown, unknown>) => Fiber.join(f)),
    );
    const results = joined.map((e) => e as Either.Either<unknown, unknown>);
    const successes = results.filter(Either.isRight);
    const duplicates = results.filter(
      (r) => Either.isLeft(r) && (r.left as { _tag: string })._tag === "DuplicateActionError",
    );
    expect(runs).toBe(1);
    expect(successes).toHaveLength(1);
    expect(duplicates).toHaveLength(9);
  });

  it("allows retry after failure", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    let attempts = 0;
    const act = guard({
      action: "job.run",
      journal,
      approve: allow.approve,
      identity,
      idempotencyKey: "k",
      parameterNames: ["k"],
    })((k: string) => {
      attempts++;
      if (attempts === 1) throw new Error("boom");
      return k;
    });

    await Effect.runPromise(Effect.flip(act("K1")));
    await Effect.runPromise(act("K1") as Effect.Effect<unknown, unknown>);
    expect(attempts).toBe(2);
    // Evidence half: one failed outcome, then one succeeded outcome.
    const statuses = readFileSync(journalPath, "utf8")
      .split("\n")
      .filter((l) => l.trim())
      .map((l) => (JSON.parse(l) as Record<string, unknown>)["status"])
      .filter((s) => s !== undefined);
    expect(statuses).toEqual(["failed", "succeeded"]);
  });

  it("resolution not-completed releases an in-flight key", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    const { JournalError } = await import("../src/Journal.js");
    let failOutcomes = 1;
    // Crash between execution and outcome persistence: decision recorded,
    // outcome lost — the key reads in-flight.
    const flaky: FileJournal = {
      ...journal,
      appendEvent: (build) =>
        journal.appendEvent((prev) =>
          Effect.flatMap(build(prev), (event) =>
            event["event_type"] === "outcome" && failOutcomes-- > 0
              ? Effect.fail(new JournalError({ message: "crash" }))
              : Effect.succeed(event),
          ),
        ),
    };
    const act = guard({
      action: "x.res",
      journal: flaky,
      approve: allow.approve,
      identity,
      idempotencyKey: "k",
      parameterNames: ["k"],
    })((k: string) => k);

    await Effect.runPromise(Effect.flip(act("K-9")));
    const dup = await Effect.runPromise(Effect.flip(act("K-9")));
    expect((dup as { _tag: string })._tag).toBe("DuplicateActionError");

    const lines = readFileSync(journalPath, "utf8").split("\n").filter((l) => l.trim());
    const decision = JSON.parse(lines[0]) as Record<string, unknown>;
    await Effect.runPromise(
      journal.appendEvent((previousHash) =>
        finalizeEvent(
          {
            schema_version: SCHEMA_VERSION,
            event_type: "resolution",
            event_id: crypto.randomUUID(),
            action_id: "x",
            action_name: "x.res",
            contract_hash: "c",
            timestamp_utc: utcTimestamp(),
            key_id: identity.keyId,
            previous_event_hash: previousHash,
            decision_event_id: decision["event_id"],
            resolution: "confirmed_not_completed",
            note: "checked: absent",
          } satisfies EventRecord,
          identity,
        ),
      ),
    );
    // Key released; the retried call executes successfully.
    await Effect.runPromise(act("K-9"));
    const result = await Effect.runPromise(
      verifyLines(
        readFileSync(journalPath, "utf8").split("\n"),
        keyringFromPems([identity.publicKeyPem]),
      ),
    );
    expect(result.valid).toBe(true);
  });

  it("failed outcomes allow retry even with a completion attestation", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    const act = guard({
      action: "x.done",
      journal,
      approve: allow.approve,
      identity,
      idempotencyKey: "k",
      parameterNames: ["k"],
    })((_k: string) => {
      throw new Error("failed");
    });

    await Effect.runPromise(Effect.flip(act("K-9")));
    const lines = readFileSync(journalPath, "utf8").split("\n").filter((l) => l.trim());
    const decision = JSON.parse(lines[0]) as Record<string, unknown>;
    await Effect.runPromise(
      journal.appendEvent((previousHash) =>
        finalizeEvent(
          {
            schema_version: SCHEMA_VERSION,
            event_type: "resolution",
            event_id: crypto.randomUUID(),
            action_id: "x",
            action_name: "x.done",
            contract_hash: "c",
            timestamp_utc: utcTimestamp(),
            key_id: identity.keyId,
            previous_event_hash: previousHash,
            decision_event_id: decision["event_id"],
            resolution: "confirmed_completed",
            note: "operator says it happened",
          } satisfies EventRecord,
          identity,
        ),
      ),
    );
    // A failed function stays retryable even with a completion attestation:
    // only succeeded (or in-flight) outcomes block, exactly like the Python
    // engine — resolutions release missing-outcome keys, never failed ones
    // into duplicates. The attestation/retry tension belongs to `audit`,
    // not to the reservation.
    let attempts = 0;
    const retrying = guard({
      action: "x.done",
      journal,
      approve: allow.approve,
      identity,
      idempotencyKey: "k",
      parameterNames: ["k"],
    })((_k: string) => {
      attempts++;
      throw new Error("failed again");
    });
    const failed = await Effect.runPromise(Effect.flip(retrying("K-9")));
    expect((failed as { _tag: string })._tag).toBe("GuardedCallFailed");
    expect(attempts).toBe(1);
  });

  it("forgetJournal releases a rotated journal", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    const { CompletionRegistry } = await import("../src/Idempotency.js");
    const registry = await Effect.runPromise(CompletionRegistry.make());
    await Effect.runPromise(registry.markCompleted(journalPath, "a", "K"));
    expect(await Effect.runPromise(registry.isCompleted(journalPath, "a", "K"))).toBe(true);
    await Effect.runPromise(registry.forgetJournal(journalPath));
    expect(await Effect.runPromise(registry.isCompleted(journalPath, "a", "K"))).toBe(false);
    expect(journal.path).toBe(journalPath);
    expect(identity.keyId.startsWith("ed25519:")).toBe(true);
  });

  it("dry runs record a decision and never execute", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    let ran = false;
    const act = guard({
      action: "ops.plan",
      journal,
      approve: allow.approve,
      identity,
      dryRun: true,
    })(() => {
      ran = true;
      return "x";
    });

    await Effect.runPromise(act());
    expect(ran).toBe(false);
    const lines = readFileSync(journalPath, "utf8").split("\n").filter((l) => l.trim());
    expect(lines).toHaveLength(1);
    expect((JSON.parse(lines[0]) as Record<string, unknown>)["dry_run"]).toBe(true);
    const result = await Effect.runPromise(
      verifyLines(lines, keyringFromPems([identity.publicKeyPem])),
    );
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(1);
  });
});
