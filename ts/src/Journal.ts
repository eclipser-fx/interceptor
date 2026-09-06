/**
 * Append-only JSONL journal: tail-read chain tip, signed events, fsync
 * durability. Every append holds the sidecar lock directory (`Lock.ts`,
 * atomic `mkdir` + pid-liveness stale recovery), so read-tail + append +
 * fsync is one critical section across processes — the same guarantee the
 * Python engine gets from `fcntl`/`msvcrt`.
 */
import { createHash } from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { Data, Effect } from "effect";
import { canonical } from "./Canonical.js";
import type { SigningIdentity } from "./Identity.js";
import { withJournalLock } from "./Lock.js";

export const SCHEMA_VERSION = "1";

export class JournalError extends Data.TaggedError("JournalError")<{
  readonly message: string;
}> {}

export type EventRecord = Record<string, unknown>;

export const utcTimestamp = (): string => {
  // RFC 3339 UTC with microseconds and Z suffix, matching Python's isoformat.
  const now = new Date();
  const ms = now.getUTCMilliseconds().toString().padStart(3, "0");
  return `${now.toISOString().slice(0, 19)}.${ms}000Z`;
};

export const eventDigest = (unsignedPayload: EventRecord): Buffer =>
  createHash("sha256").update(canonical(unsignedPayload), "utf8").digest();

export const finalizeEvent = (
  payload: EventRecord,
  identity: SigningIdentity,
): Effect.Effect<EventRecord, JournalError> =>
  Effect.gen(function* () {
    const digest = eventDigest(payload);
    const signature = yield* identity.signEffect(digest).pipe(
      Effect.mapError((cause) => new JournalError({ message: `signing failed: ${cause.message}` })),
    );
    return {
      ...payload,
      event_hash: digest.toString("hex"),
      signature,
    };
  });

const TAIL_READ_BYTES = 64 * 1024;

const hashFromLine = (line: Buffer, journalPath: string): string => {
  let event: unknown;
  try {
    event = JSON.parse(line.toString("utf-8"));
  } catch {
    throw new JournalError({
      message: `journal tail is corrupt; refusing to extend a broken chain (verify ${journalPath})`,
    });
  }
  const hash = (event as Record<string, unknown>)["event_hash"];
  if (typeof hash !== "string") {
    throw new JournalError({ message: "journal tail has a non-string event_hash" });
  }
  return hash;
};

/** The `event_hash` of the last journal line, or null for an empty file. */
export const readLastEventHash = (journalPath: string): Effect.Effect<string | null, JournalError> =>
  Effect.try({
    try: () => {
      let fd: number | undefined;
      try {
        fd = fs.openSync(journalPath, "a+");
        const size = fs.fstatSync(fd).size;
        if (size === 0) return null;
        let window = TAIL_READ_BYTES;
      for (;;) {
        const start = Math.max(0, size - window);
        const chunk = Buffer.alloc(size - start);
        fs.readSync(fd, chunk, 0, chunk.length, start);
        const stripped = chunk.toString("utf-8").replace(/[\r\n]+$/, "");
        if (!stripped) {
          if (start === 0) return null;
          window *= 2;
          continue;
        }
        const newline = stripped.lastIndexOf("\n");
        if (newline === -1 && start > 0) {
          // The last line is longer than the window; widen and retry rather
          // than hashing a fragment.
          window *= 2;
          continue;
        }
        return hashFromLine(
          Buffer.from(newline === -1 ? stripped : stripped.slice(newline + 1)),
          journalPath,
        );
      }
      } finally {
        if (fd !== undefined) fs.closeSync(fd);
      }
    },
    catch: (cause) =>
      cause instanceof JournalError
        ? cause
        : new JournalError({ message: `cannot read journal ${journalPath}: ${cause}` }),
  });

export interface FileJournal {
  readonly path: string;
  readonly appendEvent: (
    build: (previousHash: string | null) => Effect.Effect<EventRecord, JournalError>,
  ) => Effect.Effect<EventRecord, JournalError>;
}

export const makeFileJournal = (journalPath: string): FileJournal => ({
  path: journalPath,
  appendEvent: (build) =>
    withJournalLock(
      journalPath,
      () =>
        Effect.gen(function* () {
          yield* Effect.try({
            try: () => fs.mkdirSync(path.dirname(journalPath), { recursive: true }),
            catch: (cause) => new JournalError({ message: `cannot create journal dir: ${cause}` }),
          });
          const previousHash = yield* readLastEventHash(journalPath);
          const event = yield* build(previousHash);
          const line = canonical(event);
          yield* Effect.try({
            try: () => {
              const created = !fs.existsSync(journalPath);
              const fd = fs.openSync(journalPath, "a");
              try {
                const data = Buffer.from(line + "\n", "utf8");
                // Partial writes must never leave a truncated line behind.
                let offset = 0;
                while (offset < data.length) {
                  offset += fs.writeSync(fd, data, offset);
                }
                fs.fsyncSync(fd);
              } finally {
                fs.closeSync(fd);
              }
              if (created) {
                // Durably link a brand-new file into its directory.
                const dirFd = fs.openSync(path.dirname(journalPath), "r");
                try {
                  fs.fsyncSync(dirFd);
                } finally {
                  fs.closeSync(dirFd);
                }
              }
            },
            catch: (cause) =>
              cause instanceof JournalError
                ? cause
                : new JournalError({ message: `cannot append to journal ${journalPath}: ${cause}` }),
          });
          return event;
        }),
    ).pipe(
      Effect.mapError((cause) =>
        cause instanceof JournalError
          ? cause
          : new JournalError({ message: `journal lock failed for ${journalPath}: ${cause}` }),
      ),
    ),
});
