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

export interface WitnessPruneReport {
  readonly witnessDir: string;
  readonly kept: ReadonlyArray<string>;
  readonly deleted: ReadonlyArray<string>;
}

/**
 * Delete the oldest shipped witnesses, keeping the newest `keep`.
 *
 * A frequent checkpoint schedule fills a witness directory without bound;
 * pruning keeps it finite. It is safe for the truncation bound because every
 * witness commits to an event count and counts grow with the journal: the
 * newest witness subsumes every older prefix bound, so keeping the newest K
 * preserves the K strongest bounds and only reduces historical depth.
 * `latest.checkpoint` (a pointer, not an independent witness) is never
 * deleted. Entries that are not regular files, or whose mtime cannot be
 * read, are kept and do not count against `keep` — pruning deletes only
 * what it positively identifies as an old regular file.
 *
 * One directory per journal: checkpoint files carry no journal identity, so
 * a directory mixing witnesses from several journals cannot prune
 * per-journal.
 */
export const pruneWitnesses = (
  witnessDir: string,
  keep: number,
): Effect.Effect<WitnessPruneReport, CheckpointError> => {
  if (!Number.isInteger(keep) || keep < 1) {
    return Effect.die(new Error("keep must be a positive integer"));
  }
  return Effect.gen(function* () {
    let names: Array<string>;
    try {
      const stat = fs.statSync(witnessDir);
      if (!stat.isDirectory()) {
        return yield* new CheckpointError({ message: `witness dir ${witnessDir} is not a directory` });
      }
      names = fs.readdirSync(witnessDir);
    } catch (cause) {
      return yield* new CheckpointError({ message: `no witness dir at ${witnessDir}: ${cause}` });
    }
    const dated: Array<{ mtimeMs: number; name: string }> = [];
    const unassessed: Array<string> = [];
    for (const name of names) {
      if (!name.endsWith(".checkpoint") || name === "latest.checkpoint") continue;
      const full = path.join(witnessDir, name);
      try {
        const stat = fs.statSync(full);
        if (!stat.isFile()) {
          unassessed.push(full);
          continue;
        }
        dated.push({ mtimeMs: stat.mtimeMs, name });
      } catch {
        unassessed.push(full);
      }
    }
    dated.sort((a, b) => a.mtimeMs - b.mtimeMs || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const victims = dated.slice(0, Math.max(0, dated.length - keep)).map((entry) => entry.name);
    const kept = dated.slice(victims.length).map((entry) => entry.name);
    const deleted: Array<string> = [];
    const failures: Array<string> = [];
    for (const name of victims) {
      try {
        fs.unlinkSync(path.join(witnessDir, name));
        deleted.push(path.join(witnessDir, name));
      } catch (cause) {
        failures.push(`${name}: ${cause}`);
      }
    }
    if (failures.length > 0) {
      return yield* new CheckpointError({
        message: `could not delete ${failures.length} witness(es) in ${witnessDir}: ${failures.join("; ")}`,
      });
    }
    return {
      witnessDir,
      kept: [...kept.map((name) => path.join(witnessDir, name)), ...unassessed],
      deleted,
    } satisfies WitnessPruneReport;
  });
};

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
