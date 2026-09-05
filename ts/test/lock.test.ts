/**
 * Lockdir protocol: stale reclamation, live-holder timeout, and real
 * multi-process appends with an intact chain afterwards.
 */
import { execSync, fork } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { generateExportableIdentity } from "../src/Identity.js";
import { makeFileJournal } from "../src/Journal.js";
import { keyringFromPems, verifyLines } from "../src/Verify.js";
import { withJournalLock } from "../src/Lock.js";

const tsRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const plantLock = (journalPath: string, record: Record<string, unknown>): void => {
  writeFileSync(`${journalPath}.lock`, JSON.stringify(record));
};

describe("file lock", () => {
  it("reclaims stale locks from dead holders", async () => {
    const dir = path.join(os.tmpdir(), `ic-lock-${process.pid}-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    const journalPath = path.join(dir, "j.jsonl");
    writeFileSync(journalPath, "");
    // PID that surely does not exist + ancient timestamp.
    // (utimes backdates the file so age-based reclaim also agrees.)
    plantLock(journalPath, { pid: 2147483647, hostname: "dead", takenAt: 1 });
    const past = new Date(1000);
    await import("node:fs").then((fs) => fs.utimesSync(`${journalPath}.lock`, past, past));
    const journal = makeFileJournal(journalPath);
    await Effect.runPromise(
      journal.appendEvent(() =>
        Effect.succeed({
          schema_version: "1",
          event_type: "checkpoint",
          event_id: "e",
          timestamp_utc: "t",
          key_id: "k",
          previous_event_hash: null,
          checkpoint_count: 0,
          head_sha256: null,
          event_hash: "h",
          signature: "s",
        }),
      ),
    );
    // The dead holder's lock was reclaimed: our line landed, lock released.
    expect(readFileSync(journalPath, "utf8").trim().split("\n")).toHaveLength(1);
    expect(existsSync(`${journalPath}.lock`)).toBe(false);
  });

  it("fails closed while a live holder owns the lock", async () => {
    const dir = path.join(os.tmpdir(), `ic-locklive-${process.pid}-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    const journalPath = path.join(dir, "j.jsonl");
    writeFileSync(journalPath, "");
    plantLock(journalPath, { pid: process.pid, hostname: "here", takenAt: Date.now() });
    const journal = makeFileJournal(journalPath);
    const exit = await Effect.runPromise(
      Effect.exit(
        withJournalLock(journalPath, () => journal.appendEvent(() => Effect.succeed({})), {
          timeoutMs: 200,
          pollMs: 10,
        }),
      ),
    );
    expect(exit._tag).toBe("Failure");
  });

  it("survives concurrent multi-process appends with an intact chain", async () => {
    execSync("./node_modules/.bin/tsc -p tsconfig.json", { cwd: tsRoot, stdio: "pipe" });
    const dir = path.join(os.tmpdir(), `ic-mp-${process.pid}-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    const journalPath = path.join(dir, "j.jsonl");
    const { identity, privatePem } = await Effect.runPromise(generateExportableIdentity());
    const pubPath = path.join(dir, "pub.pem");
    const privPath = path.join(dir, "priv.pem");
    writeFileSync(pubPath, identity.publicKeyPem);
    writeFileSync(privPath, privatePem);
    const helper = path.join(tsRoot, "dist", "scripts", "append-child.js");
    const children = [0, 1, 2, 3].map(
      (tag) =>
        new Promise<void>((resolve, reject) => {
          const child = fork(helper, [journalPath, pubPath, privPath, "25", `c${tag}`], {
            stdio: "pipe",
          });
          let stderr = "";
          child.stderr?.on("data", (chunk: Buffer) => {
            stderr += chunk.toString();
          });
          child.on("error", reject);
          child.on("exit", (code) =>
            code === 0
              ? resolve()
              : reject(new Error(`child ${tag} exited ${code}: ${stderr.slice(0, 500)}`)),
          );
        }),
    );
    await Promise.all(children);
    const lines = readFileSync(journalPath, "utf8").split("\n");
    const result = await Effect.runPromise(
      verifyLines(lines, keyringFromPems([identity.publicKeyPem])),
    );
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(100);
  }, 120000);
});
