/**
 * Durable tail-truncation defense: append a signed checkpoint committing to
 * `(event_count, head_hash)` and write its canonical line as a witness file
 * for somewhere the journal cannot reach. Count, hash read, and append all
 * happen under the journal lock, so the commitment is internally consistent
 * even with concurrent writers.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { randomUUID } from "node:crypto";
import { Data, Effect } from "effect";
import { canonical } from "./Canonical.js";
import type { SigningIdentity } from "./Identity.js";
import {
  JournalError,
  SCHEMA_VERSION,
  finalizeEvent,
  readLastEventHash,
  utcTimestamp,
  type EventRecord,
} from "./Journal.js";
import { withJournalLock } from "./Lock.js";

export class CheckpointError extends Data.TaggedError("CheckpointError")<{
  readonly message: string;
}> {}

export interface CheckpointReport {
  readonly journalPath: string;
  readonly checkpointEvent: EventRecord;
  readonly checkpointCount: number;
  readonly headSha256: string | null;
  readonly witnessPath: string;
}

const countLines = (journalPath: string): number => {
  let content: string;
  try {
    content = fs.readFileSync(journalPath, "utf8");
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException)?.code === "ENOENT") return 0;
    throw cause;
  }
  let count = 0;
  for (const raw of content.split("\n")) {
    if (raw.trim() !== "") count++;
  }
  return count;
};

export const checkpointJournal = (
  journalPath: string,
  identity: SigningIdentity,
  witnessPath?: string,
): Effect.Effect<CheckpointReport, JournalError | CheckpointError> =>
  Effect.gen(function* () {
    const dir = path.dirname(journalPath);
    yield* Effect.try({
      try: () => fs.mkdirSync(dir, { recursive: true }),
      catch: (cause) => new JournalError({ message: `cannot create journal dir: ${cause}` }),
    });
    const report = yield* withJournalLock(
      journalPath,
      () =>
        Effect.gen(function* () {
          const count = yield* Effect.try({
            try: () => countLines(journalPath),
            catch: (cause) =>
              cause instanceof JournalError
                ? cause
                : new CheckpointError({ message: `cannot count journal ${journalPath}: ${cause}` }),
          });
          const previousHash = yield* readLastEventHash(journalPath);
          const event = yield* finalizeEvent(
            {
              schema_version: SCHEMA_VERSION,
              event_type: "checkpoint",
              event_id: randomUUID(),
              timestamp_utc: utcTimestamp(),
              key_id: identity.keyId,
              previous_event_hash: previousHash,
              checkpoint_count: count,
              head_sha256: previousHash,
            } satisfies EventRecord,
            identity,
          );
          // Append under the same lock: the commitment stays consistent
          // with exactly what follows it in the file.
          yield* Effect.try({
            try: () => {
              const data = Buffer.from(canonical(event) + "\n", "utf8");
              const fd = fs.openSync(journalPath, "a");
              try {
                let offset = 0;
                while (offset < data.length) {
                  offset += fs.writeSync(fd, data, offset);
                }
                fs.fsyncSync(fd);
              } finally {
                fs.closeSync(fd);
              }
            },
            catch: (cause) =>
              new JournalError({ message: `cannot append checkpoint to ${journalPath}: ${cause}` }),
          });
          return { count, previousHash, event };
        }),
    ).pipe(
      Effect.mapError((cause) =>
        cause instanceof JournalError || cause instanceof CheckpointError
          ? cause
          : new JournalError({ message: `journal lock failed for ${journalPath}: ${cause}` }),
      ),
    );
    // The witness is the checkpoint event's canonical line (self-contained:
    // `verify --checkpoint` needs only this file plus a pinned key).
    const witness =
      witnessPath ?? path.join(path.dirname(journalPath), `${path.basename(journalPath)}.checkpoint`);
    yield* Effect.try({
      try: () => {
        fs.mkdirSync(path.dirname(witness), { recursive: true });
        fs.writeFileSync(witness, canonical(report.event) + "\n");
        const fd = fs.openSync(witness, "r");
        try {
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
      },
      catch: (cause) => new CheckpointError({ message: `cannot write witness ${witness}: ${cause}` }),
    });
    return {
      journalPath,
      checkpointEvent: report.event,
      checkpointCount: report.count,
      headSha256: report.previousHash,
      witnessPath: witness,
    } satisfies CheckpointReport;
  });
