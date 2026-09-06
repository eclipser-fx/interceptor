/**
 * Custody operations: counter-signing checkpoints, archive rotation with
 * custody links, and chain-of-archives verification. Mirrors the Python
 * `cosign`/`archive` semantics: a countersignature commits a second key to a
 * checkpoint's `(count, head)`; an archive successor starts with a signed
 * link to its predecessor's `(count, head)`.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { Data, Effect } from "effect";
import { canonical } from "./Canonical.js";
import {
  JournalError,
  SCHEMA_VERSION,
  finalizeEvent,
  makeFileJournal,
  utcTimestamp,
  type EventRecord,
  type FileJournal,
} from "./Journal.js";
import type { SigningIdentity } from "./Identity.js";
import { verifyLines, type Keyring } from "./Verify.js";

export class CustodyError extends Data.TaggedError("CustodyError")<{
  readonly message: string;
}> {}

export interface CountersignatureReport {
  readonly journalPath: string;
  readonly checkpointEventId: string;
  readonly checkpointCount: number;
  readonly headSha256: string | null;
  readonly superseded: boolean;
}

const readEvents = (journalPath: string): Array<EventRecord> => {
  let content: string;
  try {
    content = fs.readFileSync(journalPath, "utf8");
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    throw cause;
  }
  const events: Array<EventRecord> = [];
  for (const raw of content.split("\n")) {
    if (!raw.trim()) continue;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === "object" && parsed !== null) {
        events.push(parsed as EventRecord);
      }
    } catch {
      continue;
    }
  }
  return events;
};

const newestCheckpoint = (journalPath: string): EventRecord | null => {
  let newest: EventRecord | null = null;
  for (const event of readEvents(journalPath)) {
    if (event["event_type"] === "checkpoint") newest = event;
  }
  return newest;
};

/**
 * Counter-sign the newest checkpoint with an external key. Reports
 * `superseded` when a checkpoint landed mid-operation (re-run to attest it).
 */
export const countersignJournal = (
  journal: FileJournal,
  signer: SigningIdentity,
): Effect.Effect<CountersignatureReport, CustodyError | JournalError> =>
  Effect.gen(function* () {
    const journalPath = journal.path;
    let checkpoint: EventRecord | null;
    try {
      checkpoint = newestCheckpoint(journalPath);
    } catch (cause) {
      return yield* Effect.fail(
        new CustodyError({ message: `cannot read journal ${journalPath}: ${cause}` }),
      );
    }
    if (checkpoint === null) {
      return yield* Effect.fail(
        new CustodyError({
          message: `no checkpoint in ${journalPath}; checkpoint first`,
        }),
      );
    }
    const checkpointEventId = checkpoint["event_id"];
    const checkpointCount = checkpoint["checkpoint_count"];
    const headSha256 = checkpoint["head_sha256"];
    if (typeof checkpointEventId !== "string" || typeof checkpointCount !== "number") {
      return yield* Effect.fail(
        new CustodyError({ message: `newest checkpoint in ${journalPath} is malformed` }),
      );
    }
    // Integrity before legitimacy: recompute the checkpoint's own hash from
    // its canonical payload. A corrupt tail must fail closed here, not gain
    // a second key's attestation. (Full signature trust still belongs to the
    // verifier and the human who checks the checkpoint out of band.)
    try {
      const { event_hash, signature: _signature, ...unsigned } = checkpoint;
      void _signature;
      const recomputed = createHash("sha256").update(canonical(unsigned), "utf8").digest("hex");
      if (event_hash !== recomputed) {
        return yield* Effect.fail(
          new CustodyError({
            message: `newest checkpoint in ${journalPath} fails its own hash check; verify first`,
          }),
        );
      }
    } catch (cause) {
      return yield* Effect.fail(
        new CustodyError({ message: `newest checkpoint in ${journalPath} is unhashable: ${cause}` }),
      );
    }
    yield* journal.appendEvent((previousHash) =>
      finalizeEvent(
        {
          schema_version: SCHEMA_VERSION,
          event_type: "countersignature",
          event_id: randomUUID(),
          timestamp_utc: utcTimestamp(),
          key_id: signer.keyId,
          previous_event_hash: previousHash,
          checkpoint_event_id: checkpointEventId,
          checkpoint_count: checkpointCount,
          head_sha256: headSha256,
        } satisfies EventRecord,
        signer,
      ),
    );
    const latest = newestCheckpoint(journalPath);
    const latestId = latest === null ? null : latest["event_id"];
    return {
      journalPath,
      checkpointEventId,
      checkpointCount,
      headSha256: typeof headSha256 === "string" ? headSha256 : null,
      superseded: latestId !== checkpointEventId,
    } satisfies CountersignatureReport;
  });

export interface ArchiveReport {
  readonly journalPath: string;
  readonly archivedPath: string;
  readonly priorCount: number;
  readonly priorHead: string | null;
  readonly archiveEvent: EventRecord;
}

export interface ArchiveChainIssue {
  readonly file: string;
  readonly code: string;
  readonly message: string;
}

export interface ArchiveChainReport {
  readonly valid: boolean;
  readonly filesChecked: ReadonlyArray<string>;
  readonly issues: ReadonlyArray<ArchiveChainIssue>;
}

const badLinkName = (value: unknown): boolean =>
  typeof value !== "string" ||
  value === "" ||
  value === "." ||
  value === ".." ||
  value.includes("/") ||
  value.includes("\\");

/**
 * Verify the live journal plus every archived predecessor it links to: each
 * file verifies standalone, each `archive` link's `(count, head)` matches
 * the predecessor's actual tail, cycles and missing files fail the chain.
 */
export const verifyArchiveChain = (
  livePath: string,
  keyring: Keyring,
  maxLinks = 1024,
): Effect.Effect<ArchiveChainReport, never> =>
  Effect.gen(function* () {
    const filesChecked: Array<string> = [];
    const issues: Array<ArchiveChainIssue> = [];
    const seen = new Set<string>();
    let current = livePath;
    let links = 0;
    for (;;) {
      let resolved: string;
      try {
        resolved = fs.realpathSync(current);
      } catch {
        resolved = path.resolve(current);
      }
      if (seen.has(resolved)) {
        issues.push({ file: current, code: "archive_cycle", message: "archive chain loops" });
        break;
      }
      seen.add(resolved);
      let lines: Array<string>;
      try {
        lines = fs.readFileSync(current, "utf8").split("\n");
      } catch {
        issues.push({ file: current, code: "archive_missing", message: "predecessor file is missing" });
        break;
      }
      const verification = yield* verifyLines(lines, keyring).pipe(
        Effect.catchAllDefect(() => Effect.succeed(null)),
      );
      if (verification === null || !verification.valid) {
        const detail = verification === null ? "unreadable" : verification.issues[0]?.code ?? "invalid";
        issues.push({ file: current, code: "archive_invalid", message: `file fails verification [${detail}]` });
        break;
      }
      filesChecked.push(current);
      const first = lines.map((l) => l.trim()).find((l) => l !== "");
      let firstEvent: Record<string, unknown> | null = null;
      if (first !== undefined) {
        try {
          const parsed: unknown = JSON.parse(first);
          firstEvent = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
        } catch {
          firstEvent = null;
        }
      }
      if (firstEvent === null || firstEvent["event_type"] !== "archive") break;
      if (links >= maxLinks) {
        issues.push({ file: current, code: "archive_too_deep", message: "archive chain too long" });
        break;
      }
      const archivedName = firstEvent["archived_path"];
      const priorCount = firstEvent["prior_count"];
      const priorHead = firstEvent["prior_head"];
      if (badLinkName(archivedName)) {
        issues.push({ file: current, code: "archive_bad_link", message: "archived_path must be a bare file name" });
        break;
      }
      const predecessor = path.join(path.dirname(current), archivedName as string);
      let predecessors: Array<Record<string, unknown>>;
      try {
        predecessors = fs
          .readFileSync(predecessor, "utf8")
          .split("\n")
          .filter((l) => l.trim() !== "")
          .map((l) => JSON.parse(l) as Record<string, unknown>);
      } catch {
        issues.push({ file: predecessor, code: "archive_missing", message: "predecessor file is missing" });
        break;
      }
      const last = predecessors[predecessors.length - 1];
      const actualHead = typeof last?.["event_hash"] === "string" ? last["event_hash"] : null;
      if (priorCount !== predecessors.length || priorHead !== actualHead) {
        issues.push({
          file: current,
          code: priorCount !== predecessors.length ? "archive_count_mismatch" : "archive_head_mismatch",
          message: "archive link does not match the predecessor file",
        });
        break;
      }
      current = predecessor;
      links++;
    }
    return { valid: issues.length === 0, filesChecked, issues };
  });

/**
 * Rotate the live journal: claim an exclusive destination, move the file,
 * roll back on a raced writer, and start the successor with a signed
 * `archive` link. Refuses to roll back over a concurrently-created
 * successor (manual reconciliation instead).
 */
export const archiveJournal = (
  journalPath: string,
  identity: SigningIdentity,
): Effect.Effect<ArchiveReport, CustodyError | JournalError> =>
  Effect.gen(function* () {
    const dir = path.dirname(journalPath);
    const stem = path.basename(journalPath, ".jsonl");
    const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
    yield* Effect.try({
      try: () => fs.mkdirSync(dir, { recursive: true }),
      catch: (cause) => new CustodyError({ message: `cannot prepare archive dir: ${cause}` }),
    });
    // Exclusive destination claim: concurrent archivers diverge by suffix.
    let archived = "";
    for (let index = 0; ; index++) {
      const candidate =
        index === 0
          ? path.join(dir, `${stem}-${stamp}.jsonl`)
          : path.join(dir, `${stem}-${stamp}-${index}.jsonl`);
      try {
        const fd = fs.openSync(candidate, "wx", 0o644);
        fs.closeSync(fd);
        archived = candidate;
        break;
      } catch (cause) {
        if ((cause as NodeJS.ErrnoException)?.code !== "EEXIST") {
          return yield* Effect.fail(
            new CustodyError({ message: `cannot reserve archive path: ${cause}` }),
          );
        }
      }
    }
    const countAndHead = (file: string): { count: number; head: string | null } => {
      const events = readEvents(file);
      if (events.length === 0) return { count: 0, head: null };
      const head = events[events.length - 1]["event_hash"];
      return { count: events.length, head: typeof head === "string" ? head : null };
    };
    let before: { count: number; head: string | null };
    try {
      before = countAndHead(journalPath);
    } catch (cause) {
      return yield* Effect.fail(
        new CustodyError({ message: `cannot read journal ${journalPath}: ${cause}` }),
      );
    }
    if (before.count === 0) {
      try {
        fs.unlinkSync(archived);
      } catch {
        // Best effort; an empty placeholder is clutter, not corruption.
      }
      return yield* Effect.fail(
        new CustodyError({ message: `nothing to archive in ${journalPath}` }),
      );
    }
    try {
      fs.renameSync(journalPath, archived);
    } catch (cause) {
      return yield* Effect.fail(
        new CustodyError({ message: `cannot archive ${journalPath}: ${cause}` }),
      );
    }
    const settled = countAndHead(archived);
    if (settled.count !== before.count || settled.head !== before.head) {
      if (!fs.existsSync(journalPath)) {
        fs.renameSync(archived, journalPath);
        return yield* Effect.fail(
          new CustodyError({
            message: `concurrent write to ${journalPath} during archive; rerun the archive`,
          }),
        );
      }
      return yield* Effect.fail(
        new CustodyError({
          message:
            `concurrent write to ${journalPath} during archive, and a new file now exists ` +
            `at the live path; old evidence is intact at ${archived}`,
        }),
      );
    }
    const successor = makeFileJournal(journalPath);
    const archivedName = path.basename(archived);
    const event = yield* successor.appendEvent((previousHash) => {
      if (previousHash !== null) {
        // Typed as JournalError for the append contract; the message names
        // the recovery (a CustodyError in spirit).
        return Effect.fail(
          new JournalError({
            message: `concurrent write to ${journalPath} during archive; rerun the archive`,
          }),
        );
      }
      return finalizeEvent(
        {
          schema_version: SCHEMA_VERSION,
          event_type: "archive",
          event_id: randomUUID(),
          timestamp_utc: utcTimestamp(),
          key_id: identity.keyId,
          previous_event_hash: null,
          prior_count: before.count,
          prior_head: before.head,
          archived_path: archivedName,
        } satisfies EventRecord,
        identity,
      );
    });
    return {
      journalPath,
      archivedPath: archived,
      priorCount: before.count,
      priorHead: before.head,
      archiveEvent: event,
    };
  });
