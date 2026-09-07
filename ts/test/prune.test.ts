/**
 * Witness retention: prune oldest shipped witnesses, keep the newest N.
 * Mirrors the Python `prune_witnesses` safety rules.
 */
import { mkdtempSync, readFileSync, readdirSync, utimesSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { checkpointJournal, pruneWitnesses } from "../src/Checkpoint.js";
import { guard } from "../src/Guard.js";
import { generateIdentity } from "../src/Identity.js";
import { makeFileJournal } from "../src/Journal.js";
import { keyringFromPems, verifyLines } from "../src/Verify.js";

const stamp = (file: string, seconds: number): void => {
  writeFileSync(file, "witness");
  utimesSync(file, seconds, seconds);
};

describe("pruneWitnesses", () => {
  it("keeps the newest witnesses and never latest.checkpoint", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-prune-"));
    for (let index = 0; index < 5; index++) {
      stamp(path.join(dir, `checkpoint-2024010${index}T000000Z.checkpoint`), 1_700_000_000 + index);
    }
    stamp(path.join(dir, "latest.checkpoint"), 1_600_000_000);

    const report = await Effect.runPromise(pruneWitnesses(dir, 2));
    expect(report.deleted.map((file) => path.basename(file)).sort()).toEqual([
      "checkpoint-20240100T000000Z.checkpoint",
      "checkpoint-20240101T000000Z.checkpoint",
      "checkpoint-20240102T000000Z.checkpoint",
    ]);
    expect(report.kept.map((file) => path.basename(file)).sort()).toEqual([
      "checkpoint-20240103T000000Z.checkpoint",
      "checkpoint-20240104T000000Z.checkpoint",
    ]);
    expect(readdirSync(dir).sort()).toEqual([
      "checkpoint-20240103T000000Z.checkpoint",
      "checkpoint-20240104T000000Z.checkpoint",
      "latest.checkpoint",
    ]);
  });

  it("is a no-op when there is nothing to prune", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-prune-"));
    stamp(path.join(dir, "checkpoint-20240101T000000Z.checkpoint"), 100);
    const kept = await Effect.runPromise(pruneWitnesses(dir, 10));
    expect(kept.deleted).toEqual([]);
    expect(kept.kept).toHaveLength(1);

    const empty = mkdtempSync(path.join(os.tmpdir(), "ic-prune-"));
    const report = await Effect.runPromise(pruneWitnesses(empty, 4));
    expect(report.kept).toEqual([]);
    expect(report.deleted).toEqual([]);
  });

  it("rejects invalid configuration and missing directories", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-prune-"));
    await expect(Effect.runPromise(pruneWitnesses(dir, 0))).rejects.toThrow("positive integer");
    const exit = await Effect.runPromise(
      Effect.exit(pruneWitnesses(path.join(dir, "absent"), 2)),
    );
    expect(exit._tag).toBe("Failure");
  });

  it("keeps the newest bound covering the journal", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-prune-"));
    const journalPath = path.join(dir, "j.jsonl");
    const journal = makeFileJournal(journalPath);
    const identity = await Effect.runPromise(generateIdentity());
    const act = guard({
      action: "w.act",
      journal,
      approve: () => Effect.succeed({ decision: "allowed" as const, reason: "t" }),
      identity,
    })((x: number) => x);
    await Effect.runPromise(act(1));
    const witnessDir = path.join(dir, "witness");
    const first = await Effect.runPromise(
      checkpointJournal(journalPath, identity, path.join(witnessDir, "checkpoint-a.checkpoint")),
    );
    await Effect.runPromise(act(2));
    const second = await Effect.runPromise(
      checkpointJournal(journalPath, identity, path.join(witnessDir, "checkpoint-b.checkpoint")),
    );
    // Force distinct mtimes so ordering is deterministic across filesystems.
    utimesSync(first.witnessPath, 1_700_000_000, 1_700_000_000);
    utimesSync(second.witnessPath, 1_700_000_100, 1_700_000_100);

    const report = await Effect.runPromise(pruneWitnesses(witnessDir, 1));
    expect(report.deleted).toEqual([first.witnessPath]);
    expect(report.kept).toEqual([second.witnessPath]);

    const lines = readFileSync(journalPath, "utf8").split("\n");
    const result = await Effect.runPromise(
      verifyLines(lines, keyringFromPems([identity.publicKeyPem])),
    );
    expect(result.valid).toBe(true);
  });
});
