/**
 * Multi-process lock test helper: appends N signed decision events with a
 * PEM-loaded identity. Usage:
 * `node dist/scripts/append-child.js <journal> <publicPem> <privatePem> <count> <tag>`
 */
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { Effect } from "effect";
import { identityFromPems } from "../src/Identity.js";
import { SCHEMA_VERSION, finalizeEvent, makeFileJournal, utcTimestamp } from "../src/Journal.js";
import { canonical } from "../src/Canonical.js";
import { createHash } from "node:crypto";

const [journalPath, publicPemPath, privatePemPath, countRaw, tag] = process.argv.slice(2);
if (
  journalPath === undefined ||
  publicPemPath === undefined ||
  privatePemPath === undefined ||
  countRaw === undefined ||
  tag === undefined
) {
  console.error("usage: append-child.js <journal> <publicPem> <privatePem> <count> <tag>");
  process.exit(2);
}
const count = Number.parseInt(countRaw, 10);

const program = Effect.gen(function* () {
  const identity = identityFromPems(
    readFileSync(publicPemPath, "utf8"),
    readFileSync(privatePemPath, "utf8"),
  );
  const journal = makeFileJournal(journalPath);
  const inputHash = createHash("sha256").update(canonical({ n: 1 }), "utf8").digest("hex");
  const contract = createHash("sha256").update(canonical({ action: tag }), "utf8").digest("hex");
  for (let i = 0; i < count; i++) {
    yield* journal.appendEvent((previousHash) =>
      finalizeEvent(
        {
          schema_version: SCHEMA_VERSION,
          event_type: "decision",
          event_id: randomUUID(),
          action_id: `load.${tag}`,
          action_name: `load.${tag}`,
          contract_hash: contract,
          timestamp_utc: utcTimestamp(),
          key_id: identity.keyId,
          previous_event_hash: previousHash,
          decision: "allowed",
          risk: "low",
          approval_mode: "never",
          redacted_input_summary: `n=${i}`,
          input_hash: inputHash,
          approval_reason: "load test",
        },
        identity,
      ),
    );
  }
});

Effect.runPromise(program).catch((cause) => {
  console.error(cause);
  process.exit(1);
});
