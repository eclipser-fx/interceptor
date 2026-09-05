/**
 * Guard round-trip: an Effect-guarded call writes decision+outcome evidence
 * that the Effect verifier accepts — including redaction of sensitive args.
 */
import { mkdtempSync, readFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { guard } from "../src/Guard.js";
import { generateIdentity } from "../src/Identity.js";
import { makeFileJournal } from "../src/Journal.js";
import { keyringFromPems, verifyLines } from "../src/Verify.js";

const allow = {
  approve: () =>
    Effect.succeed({ decision: "allowed" as const, reason: "test allow" }),
};

describe("guard round-trip", () => {
  it("records decision+outcome that verify", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-"));
    const journalPath = path.join(dir, "journal.jsonl");
    const identity = await Effect.runPromise(generateIdentity());
    const journal = makeFileJournal(journalPath);

    const refund = guard({
      action: "billing.refund",
      risk: "high",
      journal,
      approve: allow.approve,
      identity,
      parameterNames: ["customerId", "amountCents", "apiKey"],
    })((customerId: string, amountCents: number, apiKey: string) =>
      Effect.runSync(Effect.succeed({ customerId, amountCents, apiKey })),
    );

    await Effect.runPromise(refund("c_1", 999, "sk-live-SECRET") as Effect.Effect<unknown, unknown>);
    const lines = readFileSync(journalPath, "utf8").split("\n");
    const result = await Effect.runPromise(
      verifyLines(lines, keyringFromPems([identity.publicKeyPem])),
    );
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(2);
    const decision = JSON.parse(lines[0]) as Record<string, unknown>;
    expect(decision["action_name"]).toBe("billing.refund");
    expect(String(decision["redacted_input_summary"])).toContain("<REDACTED>");
    expect(String(decision["redacted_input_summary"])).not.toContain("sk-live-SECRET");
  });

  it("denial never executes", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-"));
    const journalPath = path.join(dir, "journal.jsonl");
    const identity = await Effect.runPromise(generateIdentity());
    const journal = makeFileJournal(journalPath);
    let ran = false;

    const act = guard({
      action: "ops.delete",
      journal,
      approve: () => Effect.succeed({ decision: "denied" as const, reason: "no" }),
      identity,
    })(() => {
      ran = true;
      return "x";
    });

    const exit = await Effect.runPromise(Effect.flip(act()));
    expect(ran).toBe(false);
    expect(exit).toMatchObject({ _tag: "ActionDenied" });
    // Evidence half: a denied decision is recorded and no outcome follows.
    const lines = readFileSync(journalPath, "utf8").split("\n").filter((l) => l.trim());
    expect(lines).toHaveLength(1);
    expect((JSON.parse(lines[0]) as Record<string, unknown>)["decision"]).toBe("denied");
    const result = await Effect.runPromise(
      verifyLines(lines, keyringFromPems([identity.publicKeyPem])),
    );
    expect(result.valid).toBe(true);
  });
});
