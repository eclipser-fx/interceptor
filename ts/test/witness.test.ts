/**
 * Two-party witness: ship local events, verify signed coverage, detect
 * truncation and unauthorized use.
 */
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { guard } from "../src/Guard.js";
import { generateIdentity } from "../src/Identity.js";
import { makeFileJournal } from "../src/Journal.js";
import { makeWitnessClient, serveWitness } from "../src/Witness.js";

const setup = () =>
  Effect.gen(function* () {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-wit-"));
    const journalPath = path.join(dir, "journal.jsonl");
    const journal = makeFileJournal(journalPath);
    const identity = yield* generateIdentity();
    const server = yield* serveWitness({ logPath: path.join(dir, "witness.jsonl") });
    const token = new URL(server.url).searchParams.get("token") ?? "";
    const client = makeWitnessClient(server.url, token);
    return { dir, journalPath, journal, identity, server, client };
  });

describe("witness service", () => {
  it("ships events and reports coverage", async () => {
    const ctx = await Effect.runPromise(setup());
    try {
      const act = guard({
        action: "billing.refund",
        journal: ctx.journal,
        approve: () => Effect.succeed({ decision: "allowed" as const, reason: "t" }),
        identity: ctx.identity,
        parameterNames: ["orderId"],
      })((orderId: string) => orderId);
      await Effect.runPromise(act("o-1"));

      const lines = readFileSync(ctx.journalPath, "utf8").split("\n").filter((l) => l.trim());
      for (const line of lines) {
        await Effect.runPromise(ctx.client.ship(JSON.parse(line) as Record<string, unknown>));
      }
      const report = await Effect.runPromise(
        ctx.client.verifyCoverage(
          readFileSync(ctx.journalPath, "utf8").split("\n"),
          ctx.server.publicKeyPem,
        ),
      );
      expect(report.covered).toBe(true);
      expect(report.checkpoint.count).toBe(2);
    } finally {
      await Effect.runPromise(ctx.server.close());
    }
  });

  it("detects a truncated local journal as uncovered", async () => {
    const ctx = await Effect.runPromise(setup());
    try {
      const act = guard({
        action: "a",
        journal: ctx.journal,
        approve: () => Effect.succeed({ decision: "allowed" as const, reason: "t" }),
        identity: ctx.identity,
      })(() => "x");
      await Effect.runPromise(act());
      await Effect.runPromise(act());
      const lines = readFileSync(ctx.journalPath, "utf8").split("\n").filter((l) => l.trim());
      for (const line of lines) {
        await Effect.runPromise(ctx.client.ship(JSON.parse(line) as Record<string, unknown>));
      }
      // Attacker truncates the tail locally; the witness still commits to 4.
      writeFileSync(ctx.journalPath, lines.slice(0, 2).join("\n") + "\n");
      const report = await Effect.runPromise(
        ctx.client.verifyCoverage(
          readFileSync(ctx.journalPath, "utf8").split("\n"),
          ctx.server.publicKeyPem,
        ),
      );
      expect(report.covered).toBe(false);
    } finally {
      await Effect.runPromise(ctx.server.close());
    }
  });

  it("rejects unauthenticated ships and restarts with its log", async () => {
    const ctx = await Effect.runPromise(setup());
    try {
      const stranger = makeWitnessClient(ctx.server.url, "wrong-token");
      const exit = await Effect.runPromise(
        Effect.exit(stranger.ship({ event_id: "x", event_hash: "y" })),
      );
      expect(exit._tag).toBe("Failure");
      // Two shaped (but unsigned — the server is a store, not a verifier)
      // events, then restart: the count must survive.
      const shipped = [
        { event_id: "e1", event_hash: "a".repeat(64) },
        { event_id: "e2", event_hash: "b".repeat(64) },
      ];
      for (const event of shipped) {
        await Effect.runPromise(ctx.client.ship(event));
      }
      await Effect.runPromise(ctx.server.close());
      const second = await Effect.runPromise(
        (await import("../src/Witness.js")).serveWitness({
          logPath: path.join(ctx.dir, "witness.jsonl"),
        }),
      );
      try {
        const token = new URL(second.url).searchParams.get("token") ?? "";
        const client = makeWitnessClient(second.url, token);
        const lines = shipped.map((e) => JSON.stringify(e));
        const report = await Effect.runPromise(
          client.verifyCoverage(lines, second.publicKeyPem),
        );
        expect(report.covered).toBe(true);
        expect(report.checkpoint.count).toBe(2);
      } finally {
        await Effect.runPromise(second.close());
      }
    } finally {
      await Effect.runPromise(ctx.server.close().pipe(Effect.ignore));
    }
  });
});
