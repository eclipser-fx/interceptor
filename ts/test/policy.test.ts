/**
 * Policy providers: budgets enforce, attested stamps identity, checkpoint
 * commits the tail atomically.
 */
import { mkdirSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import {
  AttestedApprovalProvider,
  BudgetProvider,
  WitnessFreshnessProvider,
} from "../src/Policy.js";
import { checkpointJournal } from "../src/Checkpoint.js";
import { guard } from "../src/Guard.js";
import { generateIdentity } from "../src/Identity.js";
import { makeFileJournal } from "../src/Journal.js";
import { keyringFromPems, verifyLines } from "../src/Verify.js";

const req = {
  actionName: "billing.refund",
  risk: "high",
  approvalMode: "required",
  redactedInputSummary: "",
  inputHash: "h",
  contractHash: "c",
};

const allowInner = () => Effect.succeed({ decision: "allowed" as const, reason: "inner" });
const denyInner = () => Effect.succeed({ decision: "denied" as const, reason: "inner" });

describe("BudgetProvider", () => {
  it("allows N then denies, per-action optional", async () => {
    const budget = await Effect.runPromise(BudgetProvider.make(2));
    expect((await Effect.runPromise(budget.decide(req))).decision).toBe("allowed");
    expect((await Effect.runPromise(budget.decide(req))).decision).toBe("allowed");
    expect((await Effect.runPromise(budget.decide(req))).decision).toBe("denied");

    const perAction = await Effect.runPromise(BudgetProvider.make(1, true));
    expect((await Effect.runPromise(perAction.decide(req))).decision).toBe("allowed");
    expect((await Effect.runPromise(perAction.decide(req))).decision).toBe("denied");
    expect(
      (await Effect.runPromise(perAction.decide({ ...req, actionName: "other.act" }))).decision,
    ).toBe("allowed");
  });

  it("budgets gate real guarded calls", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-pol-"));
    const journal = makeFileJournal(path.join(dir, "j.jsonl"));
    const identity = await Effect.runPromise(generateIdentity());
    const budget = await Effect.runPromise(BudgetProvider.make(1));
    const act = guard({
      action: "paid.act",
      journal,
      approve: (r) => budget.decide(r),
      identity,
    })(() => "ok");
    await Effect.runPromise(act());
    const exit = await Effect.runPromise(Effect.exit(act()));
    expect(exit._tag).toBe("Failure");
  });
});

describe("SpendingBudgetProvider", () => {
  it("caps cumulative spend and denies undeclared spend", async () => {
    const { SpendingBudgetProvider } = await import("../src/Policy.js");
    const budget = await Effect.runPromise(SpendingBudgetProvider.make(300));
    expect((await Effect.runPromise(budget.decide({ ...req, spendCents: 100 }))).decision).toBe(
      "allowed",
    );
    expect((await Effect.runPromise(budget.decide({ ...req, spendCents: 200 }))).decision).toBe(
      "allowed",
    );
    expect((await Effect.runPromise(budget.decide({ ...req, spendCents: 1 }))).decision).toBe(
      "denied",
    );
    expect((await Effect.runPromise(budget.decide(req))).decision).toBe("denied");
  });

  it("enforces real guarded calls by declared spend", async () => {
    const { SpendingBudgetProvider } = await import("../src/Policy.js");
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-spend-"));
    const journal = makeFileJournal(path.join(dir, "j.jsonl"));
    const identity = await Effect.runPromise(generateIdentity());
    const budget = await Effect.runPromise(SpendingBudgetProvider.make(100));
    const act = guard({
      action: "spend.cap",
      journal,
      approve: (r) => budget.decide(r),
      identity,
      parameterNames: ["amountCents"],
      spendFrom: (bound) => bound["amountCents"] as number,
    })((amountCents: number) => amountCents);
    await Effect.runPromise(act(60));
    const denied = await Effect.runPromise(Effect.flip(act(60)));
    expect((denied as { _tag: string })._tag).toBe("ActionDenied");
    const lines = readFileSync(path.join(dir, "j.jsonl"), "utf8").split("\n").filter((l) => l.trim());
    expect((JSON.parse(lines[0]) as Record<string, unknown>)["spend_cents"]).toBe(60);
  });
});

describe("RateLimitProvider", () => {
  it("slides the window with an injectable clock", async () => {
    const { RateLimitProvider } = await import("../src/Policy.js");
    let now = 1000;
    const limit = new RateLimitProvider(2, 60, () => now);
    expect((await Effect.runPromise(limit.decide(req))).decision).toBe("allowed");
    expect((await Effect.runPromise(limit.decide(req))).decision).toBe("allowed");
    expect((await Effect.runPromise(limit.decide(req))).decision).toBe("denied");
    now += 61;
    expect((await Effect.runPromise(limit.decide(req))).decision).toBe("allowed");
  });
});

describe("QuorumApprovalProvider", () => {
  const allowInner = () => Effect.succeed({ decision: "allowed" as const, reason: "yes" });
  const denyInner = () => Effect.succeed({ decision: "denied" as const, reason: "no" });

  it("requires the quorum and consults everyone", async () => {
    const { QuorumApprovalProvider } = await import("../src/Policy.js");
    const seen: Array<string> = [];
    const spy = (name: string, inner: () => Effect.Effect<{ decision: "allowed" | "denied"; reason: string }, never>) =>
      () =>
        Effect.map(inner(), (d) => {
          seen.push(name);
          return d;
        });
    const quorum = new QuorumApprovalProvider([spy("a", allowInner), spy("b", denyInner)], 2);
    const decision = await Effect.runPromise(quorum.decide(req));
    expect(decision.decision).toBe("denied");
    expect(seen).toEqual(["a", "b"]);
    expect(
      (await Effect.runPromise(new QuorumApprovalProvider([spy("a", allowInner)], 1).decide(req))).decision,
    ).toBe("allowed");
  });

  it("counts defects as named denials", async () => {
    const { QuorumApprovalProvider } = await import("../src/Policy.js");
    const broken = () =>
      Effect.die(new Error("provider exploded")) as Effect.Effect<never, never, never>;
    const decision = await Effect.runPromise(
      new QuorumApprovalProvider([broken as never, allowInner], 2).decide(req),
    );
    expect(decision.decision).toBe("denied");
    expect(decision.reason).toContain("errored");
  });
});

describe("RuleProvider and loadPolicyFile", () => {
  it("matches first-win glob rules with risk scoping", async () => {
    const { RuleProvider, loadPolicyFile } = await import("../src/Policy.js");
    const provider = new RuleProvider(
      [{ action: "billing.*", decision: "denied", risks: ["high"], reason: "needs a human" }],
      "denied",
    );
    expect(provider.decide({ ...req, actionName: "billing.refund", risk: "high" }).decision).toBe(
      "denied",
    );
    expect(provider.decide({ ...req, actionName: "billing.refund", risk: "low" }).decision).toBe(
      "denied",
    );
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-pol-"));
    const file = path.join(dir, "policy.json");
    writeFileSync(
      file,
      JSON.stringify({
        default: "denied",
        rules: [{ action: "a.*", decision: "allowed", risks: ["low"], reason: "ok" }],
      }),
    );
    expect(loadPolicyFile(file).decide({ ...req, actionName: "a.x", risk: "low" }).decision).toBe(
      "allowed",
    );
  });

  it("fails closed on malformed policy files", async () => {
    const { PolicyError, loadPolicyFile } = await import("../src/Policy.js");
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-polbad-"));
    const cases: Array<[string, string]> = [
      ["unknown-key", JSON.stringify({ rules: [{ action: "a", decision: "allowed", typo: 1 }] })],
      ["unknown-risk", JSON.stringify({ rules: [{ action: "a", decision: "allowed", risks: ["bogus"] }] })],
      ["unknown-top", JSON.stringify({ default: "denied", rules: [], extra: 1 })],
      ["bad-default", JSON.stringify({ default: "maybe" })],
      ["not-json", "{oops"],
    ];
    for (const [name, body] of cases) {
      const file = path.join(dir, `${name}.json`);
      writeFileSync(file, body);
      expect(() => loadPolicyFile(file), name).toThrowError(PolicyError);
    }
  });
});

describe("DurableBudgetProvider", () => {
  it("survives restarts and denies without consuming", async () => {
    const { DurableBudgetProvider } = await import("../src/Policy.js");
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-db-"));
    const state = path.join(dir, "budget.json");
    const first = new DurableBudgetProvider(2, state);
    expect((await Effect.runPromise(first.decide(req))).decision).toBe("allowed");
    expect((await Effect.runPromise(first.decide(req))).decision).toBe("allowed");
    expect((await Effect.runPromise(first.decide(req))).decision).toBe("denied");
    // New instance = restarted process: the budget persists...
    const second = new DurableBudgetProvider(2, state);
    expect((await Effect.runPromise(second.decide(req))).decision).toBe("denied");
    // ...and the denied burst above consumed nothing extra (still exactly 2).
    const raw = JSON.parse(readFileSync(state, "utf8")) as Record<string, unknown>;
    expect(raw["total"]).toBe(2);
  });

  it("fails closed on corrupt state", async () => {
    const { DurableBudgetProvider } = await import("../src/Policy.js");
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-dbcor-"));
    const state = path.join(dir, "budget.json");
    writeFileSync(state, "{not json");
    const exit = await Effect.runPromise(
      Effect.exit(new DurableBudgetProvider(5, state).decide(req)),
    );
    expect(exit._tag).toBe("Failure");
  });
});

describe("AttestedApprovalProvider", () => {
  it("stamps allowances, passes denials, fails closed without identity", async () => {
    const stamped = await Effect.runPromise(
      new AttestedApprovalProvider(allowInner, "  Jane   Doe ").decide(req),
    );
    expect(stamped).toMatchObject({ decision: "allowed", approvedBy: "Jane Doe" });
    const denied = await Effect.runPromise(new AttestedApprovalProvider(denyInner, "x").decide(req));
    expect(denied.decision).toBe("denied");
    expect(denied.approvedBy).toBeUndefined();
    const missing = await Effect.runPromise(
      new AttestedApprovalProvider(allowInner, undefined, "INTERCEPTOR_DEFINITELY_UNSET").decide(req),
    );
    expect(missing.decision).toBe("denied");
  });
});

describe("WitnessFreshnessProvider", () => {
  const stamp = (file: string, seconds: number): void => {
    writeFileSync(file, "witness");
    utimesSync(file, seconds, seconds);
  };

  it("allows fresh witnesses and denies stale or missing ones", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-fresh-"));
    const witness = path.join(dir, "latest.checkpoint");
    stamp(witness, 1_700_000_000);
    const fresh = new WitnessFreshnessProvider(witness, 300, { clock: () => 1_700_000_010 });
    expect((await Effect.runPromise(fresh.decide(req))).decision).toBe("allowed");
    const stale = new WitnessFreshnessProvider(witness, 300, { clock: () => 1_700_001_000 });
    const denial = await Effect.runPromise(stale.decide(req));
    expect(denial.decision).toBe("denied");
    expect(denial.reason).toContain("stale");

    const missing = new WitnessFreshnessProvider(path.join(dir, "absent.checkpoint"), 300, {
      clock: () => 1_700_000_010,
    });
    expect((await Effect.runPromise(missing.decide(req))).decision).toBe("denied");
  });

  it("never deletes through a directory witness and bypasses other risks", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-fresh-"));
    mkdirSync(path.join(dir, "latest.checkpoint"));
    const asDir = new WitnessFreshnessProvider(path.join(dir, "latest.checkpoint"), 300, {
      clock: () => 1_700_000_010,
    });
    expect((await Effect.runPromise(asDir.decide(req))).decision).toBe("denied");

    const witness = path.join(dir, "w.checkpoint");
    stamp(witness, 1_000);
    const scoped = new WitnessFreshnessProvider(witness, 300, {
      risks: ["high", "critical"],
      clock: () => 1_700_000_010,
    });
    expect((await Effect.runPromise(scoped.decide({ ...req, risk: "low" }))).decision).toBe(
      "allowed",
    );
    expect((await Effect.runPromise(scoped.decide(req))).decision).toBe("denied");
  });

  it("rejects invalid configuration", () => {
    expect(() => new WitnessFreshnessProvider("w", 0)).toThrow("maxAgeSeconds must be positive");
    expect(() => new WitnessFreshnessProvider("w", 60, { risks: ["bogus"] })).toThrow(
      "unknown risks",
    );
    expect(() => new WitnessFreshnessProvider("sub/dir", 60)).not.toThrow();
    expect(() => new WitnessFreshnessProvider("sub\\dir", 60)).toThrow("plain file");
  });

  it("denies guarded calls when the witness is stale", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-fresh-"));
    const journal = makeFileJournal(path.join(dir, "j.jsonl"));
    const identity = await Effect.runPromise(generateIdentity());
    const witness = path.join(dir, "latest.checkpoint");
    stamp(witness, 1_000);
    const gate = new WitnessFreshnessProvider(witness, 300, { clock: () => 1_700_000_010 });
    const act = guard({
      action: "paid.act",
      journal,
      approve: (r) => gate.decide(r),
      identity,
    })(() => "ok");
    const exit = await Effect.runPromise(Effect.exit(act()));
    expect(exit._tag).toBe("Failure");
  });
});

describe("RuleProvider.explain", () => {
  it("names the first matching rule and the default", async () => {
    const { RuleProvider } = await import("../src/Policy.js");
    const provider = new RuleProvider([
      { action: "billing.*", decision: "denied", reason: "money needs a human" },
      { action: "*", decision: "allowed", reason: "catch-all" },
    ]);
    const first = provider.explain({ ...req, actionName: "billing.refund" });
    expect(first.decision).toBe("denied");
    expect([first.matchedIndex, first.matchedAction]).toEqual([0, "billing.*"]);
    expect(first.totalRules).toBe(2);
    expect(provider.decide({ ...req, actionName: "billing.refund" }).reason).toBe(first.reason);

    const caught = provider.explain({ ...req, actionName: "deploy.prod", risk: "low" });
    expect(caught.decision).toBe("allowed");
    expect([caught.matchedIndex, caught.matchedAction]).toEqual([1, "*"]);

    const defaulted = new RuleProvider([]).explain(req);
    expect(defaulted.decision).toBe("denied");
    expect(defaulted.matchedIndex).toBeNull();
    expect(defaulted.matchedAction).toBeNull();
  });
});

describe("checkpointJournal", () => {
  it("commits count+head and the witness verifies", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "ic-cp-"));
    const journalPath = path.join(dir, "j.jsonl");
    const journal = makeFileJournal(journalPath);
    const identity = await Effect.runPromise(generateIdentity());
    const act = guard({
      action: "a",
      journal,
      approve: () => Effect.succeed({ decision: "allowed" as const, reason: "t" }),
      identity,
    })(() => "x");
    await Effect.runPromise(act());
    const report = await Effect.runPromise(checkpointJournal(journalPath, identity));
    expect(report.checkpointCount).toBe(2);
    expect(report.headSha256).not.toBeNull();
    const lines = readFileSync(journalPath, "utf8").split("\n");
    const result = await Effect.runPromise(
      verifyLines(lines, keyringFromPems([identity.publicKeyPem])),
    );
    expect(result.valid).toBe(true);
    expect(result.eventsVerified).toBe(3);
    expect(readFileSync(report.witnessPath, "utf8").trim().split("\n")).toHaveLength(1);
  });
});
