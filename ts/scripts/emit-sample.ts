/**
 * Emit a sample journal for the Python interop test (`tests/test_ts_interop.py`):
 * one succeeded refund with a receipt and a redacted secret, plus one denied
 * idempotent duplicate. Usage: `node dist/scripts/emit-sample.js <journal> <pubkey>`.
 */
import { writeFileSync } from "node:fs";
import { Effect } from "effect";
import { generateIdentity } from "../src/Identity.js";
import { makeFileJournal } from "../src/Journal.js";
import { guard } from "../src/Guard.js";

const [journalPath, pubkeyPath] = process.argv.slice(2);
if (journalPath === undefined || pubkeyPath === undefined) {
  console.error("usage: emit-sample.js <journal> <pubkey>");
  process.exit(2);
}

const program = Effect.gen(function* () {
  const identity = yield* generateIdentity();
  writeFileSync(pubkeyPath, identity.publicKeyPem);
  const journal = makeFileJournal(journalPath);
  const refund = guard({
    action: "billing.refund",
    risk: "high",
    journal,
    approve: () => Effect.succeed({ decision: "allowed" as const, reason: "interop" }),
    identity,
    parameterNames: ["orderId", "amountCents", "apiKey"],
    idempotencyKey: "order-1",
    receiptFrom: (result) => ({ processor: "stripe", refund_id: (result as { id: string }).id }),
  })((orderId: string, amountCents: number, apiKey: string) => ({
    id: "re_9",
    orderId,
    amountCents,
    apiKey,
  }));

  const first = (yield* refund("order-1", 1999, "sk-live-INTEROP")) as { id: string };
  if (first.id !== "re_9") {
    return yield* Effect.fail(new Error("expected refund re_9"));
  }
  const second = yield* Effect.flip(refund("order-1", 1999, "sk-live-INTEROP"));
  if ((second as { _tag: string })._tag !== "DuplicateActionError") {
    return yield* Effect.fail(new Error("expected DuplicateActionError"));
  }
});

Effect.runPromise(program).catch((cause) => {
  console.error(cause);
  process.exit(1);
});
