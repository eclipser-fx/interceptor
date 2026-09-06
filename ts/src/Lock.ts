/**
 * Cross-process mutual exclusion without `flock` (which Node does not
 * expose): a sidecar lock *file* claimed with `O_CREAT|O_EXCL` — a single
 * atomic syscall, so exactly one contender wins and there is no
 * create-then-write race. The winner holds its fd open for the critical
 * section; losers poll. Stale locks from crashed holders are reclaimed only
 * on proof: an unreadable/partial record is left alone while fresh (the
 * writer may be mid-claim) and reclaimed once older than `staleAfterMs`;
 * a readable record is reclaimed when its pid is provably dead, or when it
 * is older than `staleAfterMs` regardless of liveness.
 *
 * Held across read-tail + append + fsync, this gives TS journals the same
 * check-then-append atomicity the Python engine gets from `fcntl`/`msvcrt`.
 */
import * as fs from "node:fs";
import * as os from "node:os";
import { Data, Effect } from "effect";

export class LockError extends Data.TaggedError("LockError")<{
  readonly message: string;
}> {}

export interface LockOptions {
  /** How long to wait for a live holder before failing closed. */
  readonly timeoutMs?: number;
  /** How often to re-poll a held lock. */
  readonly pollMs?: number;
  /** Age past which even a possibly-live holder is declared stale. */
  readonly staleAfterMs?: number;
}

interface LockRecord {
  readonly pid: number;
  readonly hostname: string;
  readonly takenAt: number;
}

const readRecord = (lockfile: string): { record: LockRecord | null; mtimeMs: number } => {
  try {
    const stat = fs.statSync(lockfile);
    let parsed: unknown;
    try {
      parsed = JSON.parse(fs.readFileSync(lockfile, "utf8"));
    } catch {
      return { record: null, mtimeMs: stat.mtimeMs };
    }
    if (typeof parsed !== "object" || parsed === null) {
      return { record: null, mtimeMs: stat.mtimeMs };
    }
    const candidate = parsed as Record<string, unknown>;
    if (typeof candidate["pid"] !== "number" || typeof candidate["takenAt"] !== "number") {
      return { record: null, mtimeMs: stat.mtimeMs };
    }
    return {
      record: {
        pid: candidate["pid"],
        hostname: String(candidate["hostname"] ?? ""),
        takenAt: candidate["takenAt"],
      },
      mtimeMs: stat.mtimeMs,
    };
  } catch {
    return { record: null, mtimeMs: Number.NaN };
  }
};

const pidAlive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause) {
    const code = (cause as NodeJS.ErrnoException)?.code;
    if (code === "ESRCH") return false; // no such process: definitely dead
    return true; // EPERM (alive, other user) or anything unclear: assume alive
  }
};

const isStale = (
  seen: { record: LockRecord | null; mtimeMs: number },
  staleAfterMs: number,
): boolean => {
  if (seen.record === null) {
    // Partial write or garbage: reclaim only by age, never by guess — the
    // writer may be between create and write right now.
    return !Number.isNaN(seen.mtimeMs) && Date.now() - seen.mtimeMs > staleAfterMs;
  }
  if (!pidAlive(seen.record.pid)) return true;
  return Date.now() - seen.record.takenAt > staleAfterMs;
};

const tryUnlink = (lockfile: string): void => {
  try {
    fs.unlinkSync(lockfile);
  } catch {
    // Lost a reclaim race or never existed; the next poll decides.
  }
};

/**
 * In-process reentrancy depth per lockfile. The OS lock is acquired once;
 * nested `withJournalLock` calls in the same process (e.g. archive driving
 * a journal append) bump the counter instead of self-deadlocking. This is
 * safe precisely because it is in-process: cooperating fibers share fate,
 * while other processes still see one atomic holder.
 */
const reentryDepth = new Map<string, number>();

/**
 * Run `use` with the journal lock held. The fd stays open for the whole
 * critical section and is always released (acquire-release); failure to
 * acquire within `timeoutMs` fails closed with `LockError`. Synchronous I/O
 * only — never blocks the event loop longer than a stat/open round trip.
 */
export const withJournalLock = <A, E>(
  journalPath: string,
  use: () => Effect.Effect<A, E>,
  options?: LockOptions,
): Effect.Effect<A, E | LockError> =>
  Effect.gen(function* () {
    const timeoutMs = options?.timeoutMs ?? 30_000;
    const pollMs = options?.pollMs ?? 10;
    const staleAfterMs = options?.staleAfterMs ?? 30_000;
    const lockfile = `${journalPath}.lock`;
    const deadline = Date.now() + timeoutMs;
    // In-process reentrancy: nested holders in this process share fate, so
    // they bump a counter instead of self-deadlocking. Other processes still
    // see exactly one atomic holder.
    const depth = reentryDepth.get(lockfile) ?? 0;
    if (depth > 0) {
      reentryDepth.set(lockfile, depth + 1);
      return yield* Effect.acquireUseRelease(
        Effect.void,
        () => use(),
        () =>
          Effect.sync(() => {
            const current = (reentryDepth.get(lockfile) ?? 1) - 1;
            if (current <= 0) reentryDepth.delete(lockfile);
            else reentryDepth.set(lockfile, current);
          }),
      );
    }
    // Unique ownership token: release unlinks only while the file still
    // carries OUR token, so we can never delete a successor's lock
    // (the steal-and-delete that naive unlock-unconditionally has).
    const ownerToken = `${process.pid}:${Date.now().toString(36)}:${Math.floor(Math.random() * 2 ** 32).toString(36)}`;
    const acquire: Effect.Effect<{ lockfile: string; fd: number }, LockError> = Effect.gen(
      function* () {
        for (;;) {
          // One atomic claim attempt; everything else below is async sleep.
          const claimed: number | null = yield* Effect.try({
            try: () => {
              try {
                const fd = fs.openSync(lockfile, "wx", 0o600);
                const record = JSON.stringify({
                  pid: process.pid,
                  hostname: os.hostname(),
                  takenAt: Date.now(),
                  token: ownerToken,
                });
                fs.writeSync(fd, record);
                return fd;
              } catch (cause) {
                if ((cause as NodeJS.ErrnoException)?.code !== "EEXIST") {
                  throw new LockError({
                    message: `cannot create lock for ${journalPath}: ${cause}`,
                  });
                }
                return null;
              }
            },
            catch: (cause) =>
              cause instanceof LockError
                ? cause
                : new LockError({ message: `cannot acquire lock for ${journalPath}: ${cause}` }),
          });
          if (claimed !== null) return { lockfile, fd: claimed };
          if (isStale(readRecord(lockfile), staleAfterMs)) tryUnlink(lockfile);
          if (Date.now() >= deadline) {
            return yield* Effect.fail(
              new LockError({
                message: `timed out waiting for journal lock ${lockfile}; failing closed`,
              }),
            );
          }
          yield* Effect.sleep(pollMs / 1000);
        }
      },
    );
    // acquireRelease (not try/finally): release runs on success, failure,
    // defect, and interruption alike. NOTE: `return yield*` inside a
    // try/finally is NOT safe in Effect.gen — a failing yield skips the
    // finally block — so all cleanup lives in `release` here.
    reentryDepth.set(lockfile, 1);
    return yield* Effect.acquireUseRelease(
      acquire,
      () => use(),
      ({ lockfile: held, fd: heldFd }) =>
        Effect.sync(() => {
          try {
            reentryDepth.delete(lockfile);
            fs.closeSync(heldFd);
          } catch {
            // Best effort; the token check below still protects others.
          }
          // Release only our own claim: if a successor already replaced the
          // file (stale-reclaim race), deleting it would break THEIR mutual
          // exclusion. Their lock then guards the file; ours is simply gone.
          try {
            const current = fs.readFileSync(held, "utf8");
            let token: unknown = null;
            try {
              token = (JSON.parse(current) as Record<string, unknown>)["token"];
            } catch {
              token = null;
            }
            if (token === ownerToken) tryUnlink(held);
          } catch {
            // Already gone; nothing to release.
          }
        }),
    );
  });
