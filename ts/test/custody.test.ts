/**
 * Custody: countersign attests checkpoints, archive links predecessors,
 * chain verification follows custody and rejects tampering.
 */
import { mkdtempSync, readFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { archiveJournal, countersignJournal, verifyArchiveChain } from "../src/Custody.js";
import { checkpointJournal } from "../src/Checkpoint.js";
import { guard } from "../src/Guard.js";
import { generateIdentity } from "../src/Identity.js";
import { makeFileJournal } from "../src/Journal.js";
import { keyringFromPems, verifyLines } from "../src/Verify.js";

const setup = () =>
  Effect.gen(function* () {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-cust-"));
    const journalPath = path.join(dir, "journal.jsonl");
    const journal = makeFileJournal(journalPath);
    const identity = yield* generateIdentity();
    return { dir, journalPath, journal, identity };
  });

describe("countersign", () => {
  it("attests the newest checkpoint with a second key", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    const counter = await Effect.runPromise(generateIdentity());
    const act = guard({
      action: "a",
      journal,
      approve: () => Effect.succeed({ decision: "allowed" as const, reason: "t" }),
      identity,
    })(() => "x");
    await Effect.runPromise(act());
    await Effect.runPromise(checkpointJournal(journalPath, identity));
    const report = await Effect.runPromise(countersignJournal(journal, counter));
    expect(report.superseded).toBe(false);
    const result = await Effect.runPromise(
      verifyLines(
        readFileSync(journalPath, "utf8").split("\n"),
        keyringFromPems([identity.publicKeyPem, counter.publicKeyPem]),
      ),
    );
    expect(result.valid).toBe(true);
  });

  it("refuses journals without checkpoints", async () => {
    const { journal } = await Effect.runPromise(setup());
    const counter = await Effect.runPromise(generateIdentity());
    const exit = await Effect.runPromise(Effect.exit(countersignJournal(journal, counter)));
    expect(exit._tag).toBe("Failure");
  });
});

describe("archive", () => {
  it("rotates with a verifiable custody chain", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    const act = guard({
      action: "a",
      journal,
      approve: () => Effect.succeed({ decision: "allowed" as const, reason: "t" }),
      identity,
    })(() => "x");
    await Effect.runPromise(act());
    const report = await Effect.runPromise(archiveJournal(journalPath, identity));
    expect(report.priorCount).toBe(2);
    await Effect.runPromise(act());
    const chain = await Effect.runPromise(
      verifyArchiveChain(journalPath, keyringFromPems([identity.publicKeyPem])),
    );
    expect(chain.valid).toBe(true);
    expect(chain.filesChecked).toHaveLength(2);
    expect(report.archivedPath).toContain("journal-");
  });

  it("detects a tampered predecessor", async () => {
    const { journalPath, journal, identity } = await Effect.runPromise(setup());
    const act = guard({
      action: "a",
      journal,
      approve: () => Effect.succeed({ decision: "allowed" as const, reason: "t" }),
      identity,
    })(() => "x");
    await Effect.runPromise(act());
    const report = await Effect.runPromise(archiveJournal(journalPath, identity));
    const { appendFileSync } = await import("node:fs");
    appendFileSync(report.archivedPath, '{"tampered":true}\n');
    const chain = await Effect.runPromise(
      verifyArchiveChain(journalPath, keyringFromPems([identity.publicKeyPem])),
    );
    expect(chain.valid).toBe(false);
  });

  it("refuses empty journals", async () => {
    const { journalPath, identity } = await Effect.runPromise(setup());
    const exit = await Effect.runPromise(Effect.exit(archiveJournal(journalPath, identity)));
    expect(exit._tag).toBe("Failure");
  });
});
