/**
 * Composable approval policy. Providers are plain values over
 * `ApprovalRequest` returning `Effect<ApprovalDecision, never>` — they
 * cannot fail, only deny, so composition never needs to handle provider
 * errors (a throwing provider is a defect, and defects fail closed at the
 * guard boundary).
 */
import * as fs from "node:fs";
import { Cause, Data, Effect, Ref } from "effect";
import type { ApprovalDecision, ApprovalRequest } from "./Guard.js";
import { withJournalLock } from "./Lock.js";

export type Decide = (request: ApprovalRequest) => Effect.Effect<ApprovalDecision, never>;

export class PolicyError extends Data.TaggedError("PolicyError")<{
  readonly message: string;
}> {}

export class BudgetProvider {
  private constructor(
    private readonly maxCalls: number,
    private readonly perAction: boolean,
    private readonly total: Ref.Ref<number>,
    private readonly perActionCounts: Ref.Ref<Map<string, number>>,
  ) {}

  static make(maxCalls: number, perAction = false): Effect.Effect<BudgetProvider, never> {
    if (!Number.isInteger(maxCalls) || maxCalls < 0) {
      return Effect.die(new Error("maxCalls must be a non-negative integer"));
    }
    return Effect.map(
      Effect.all([Ref.make(0), Ref.make(new Map<string, number>())]),
      ([total, counts]) => new BudgetProvider(maxCalls, perAction, total, counts),
    );
  }

  decide(request: ApprovalRequest): Effect.Effect<ApprovalDecision, never> {
    // Decide first, consume only on allow: a denied burst must never poison
    // the budget for later legitimate calls.
    if (!this.perAction) {
      return Effect.flatMap(
        Ref.get(this.total),
        (used): Effect.Effect<ApprovalDecision, never> => {
          if (used >= this.maxCalls) {
            return Effect.succeed({
              decision: "denied",
              reason: `budget exhausted (${used}/${this.maxCalls})`,
            });
          }
          return Effect.as(
            Ref.set(this.total, used + 1),
            { decision: "allowed", reason: `within budget (${used + 1}/${this.maxCalls})` },
          );
        },
      );
    }
    return Effect.flatMap(
      Ref.get(this.perActionCounts),
      (counts): Effect.Effect<ApprovalDecision, never> => {
        const used = counts.get(request.actionName) ?? 0;
      if (used >= this.maxCalls) {
        return Effect.succeed({
          decision: "denied",
          reason: `budget exhausted for '${request.actionName}' (${used}/${this.maxCalls})`,
        } as const);
      }
      const next = new Map(counts);
      next.set(request.actionName, used + 1);
      return Effect.as(
        Ref.set(this.perActionCounts, next),
        {
          decision: "allowed",
          reason: `within budget (${used + 1}/${this.maxCalls})`,
        } as const,
      );
    });
  }
}

const IDENTITY_PATTERN = /^[A-Za-z0-9._@:\- ]{1,120}$/;

interface BudgetVerdict {
  readonly allowed: boolean;
  readonly reason: string;
  /** Next state to persist; absent means "leave state untouched" (denials). */
  readonly next?: Record<string, unknown>;
}

/**
 * Read-modify-write a JSON state file under the journal-grade file lock.
 * Corrupt or unwritable state fails closed with `PolicyError`.
 */
const withStateFile = (
  statePath: string,
  decide: (state: Record<string, unknown>) => BudgetVerdict,
): Effect.Effect<ApprovalDecision, PolicyError> =>
  withJournalLock(
    statePath,
    () =>
      Effect.gen(function* () {
        const dir = statePath.split("/").slice(0, -1).join("/") || ".";
        yield* Effect.try({
          try: () => fs.mkdirSync(dir, { recursive: true }),
          catch: (cause) => new PolicyError({ message: `cannot create state dir: ${cause}` }),
        });
        let state: Record<string, unknown>;
        try {
          const raw = fs.readFileSync(statePath, "utf8");
          if (raw.trim() === "") {
            state = {};
          } else {
            const parsed: unknown = JSON.parse(raw);
            if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
              return yield* new PolicyError({ message: `policy state ${statePath} is corrupt` });
            }
            state = parsed as Record<string, unknown>;
          }
        } catch (cause) {
          if ((cause as NodeJS.ErrnoException)?.code === "ENOENT") {
            state = {};
          } else if (cause instanceof PolicyError) {
            return yield* cause;
          } else {
            return yield* new PolicyError({ message: `policy state ${statePath} is corrupt: ${cause}` });
          }
        }
        const verdict = decide(state);
        if (verdict.next !== undefined) {
          yield* Effect.try({
            try: () => {
              const tmp = `${statePath}.${process.pid}.tmp`;
              fs.writeFileSync(tmp, JSON.stringify(verdict.next));
              const fd = fs.openSync(tmp, "r");
              try {
                fs.fsyncSync(fd);
              } finally {
                fs.closeSync(fd);
              }
              fs.renameSync(tmp, statePath);
            },
            catch: (cause) => new PolicyError({ message: `cannot persist policy state: ${cause}` }),
          });
        }
        return (verdict.allowed
          ? { decision: "allowed", reason: verdict.reason }
          : { decision: "denied", reason: verdict.reason }) as ApprovalDecision;
      }),
  ).pipe(
    Effect.mapError((cause) =>
      cause instanceof PolicyError
        ? cause
        : new PolicyError({ message: `policy state ${statePath} unavailable: ${cause}` }),
    ),
  );

/**
 * Durable call-count budget surviving restarts: state lives in `statePath`
 * as JSON and every read-modify-write runs under the journal-grade file
 * lock, so concurrent processes share one budget. Corrupt or unwritable
 * state fails closed; allowances consume, denials don't.
 */
export class DurableBudgetProvider {
  constructor(
    private readonly maxCalls: number,
    private readonly statePath: string,
    private readonly perAction = false,
  ) {
    if (!Number.isInteger(maxCalls) || maxCalls < 0) {
      throw new Error("maxCalls must be a non-negative integer");
    }
  }

  decide(request: ApprovalRequest): Effect.Effect<ApprovalDecision, PolicyError> {
    return withStateFile(this.statePath, (state) => {
      const total = typeof state["total"] === "number" ? state["total"] : 0;
      const perAction =
        typeof state["perAction"] === "object" && state["perAction"] !== null
          ? (state["perAction"] as Record<string, unknown>)
          : {};
      if (this.perAction) {
        const raw = perAction[request.actionName];
        const used = typeof raw === "number" ? raw : 0;
        if (used >= this.maxCalls) {
          return { allowed: false, reason: `budget exhausted for '${request.actionName}' (${used}/${this.maxCalls})` };
        }
        return {
          allowed: true,
          reason: `within budget (${used + 1}/${this.maxCalls})`,
          next: { total, perAction: { ...perAction, [request.actionName]: used + 1 } },
        };
      }
      if (total >= this.maxCalls) {
        return { allowed: false, reason: `budget exhausted (${total}/${this.maxCalls})` };
      }
      return {
        allowed: true,
        reason: `within budget (${total + 1}/${this.maxCalls})`,
        next: { total: total + 1, perAction },
      };
    });
  }
}

export class SpendingBudgetProvider {
  private constructor(
    private readonly maxCents: number,
    private readonly perAction: boolean,
    private readonly total: Ref.Ref<number>,
    private readonly perActionTotals: Ref.Ref<Map<string, number>>,
  ) {}

  /** Spend caps in minor units from `request.spendCents`; undeclared spend denies. */
  static make(maxCents: number, perAction = false): Effect.Effect<SpendingBudgetProvider, never> {
    if (!Number.isInteger(maxCents) || maxCents < 0) {
      return Effect.die(new Error("maxCents must be a non-negative integer"));
    }
    return Effect.map(
      Effect.all([Ref.make(0), Ref.make(new Map<string, number>())]),
      ([total, counts]) => new SpendingBudgetProvider(maxCents, perAction, total, counts),
    );
  }

  decide(request: ApprovalRequest & { spendCents?: number | null }): Effect.Effect<ApprovalDecision, never> {
    const spend = request.spendCents ?? null;
    if (spend === null || !Number.isInteger(spend) || spend < 0) {
      return Effect.succeed({
        decision: "denied",
        reason: "no declared spend; spending budget cannot account it",
      } as const);
    }
    if (!this.perAction) {
      return Effect.flatMap(
      Ref.get(this.total),
      (used): Effect.Effect<ApprovalDecision, never> => {
        if (used + spend > this.maxCents) {
          return Effect.succeed({
            decision: "denied",
            reason: `spending budget exhausted (${used}+${spend}>${this.maxCents}c)`,
          } as const);
        }
        return Effect.as(
          Ref.set(this.total, used + spend),
          {
            decision: "allowed",
            reason: `within spending budget (${used + spend}/${this.maxCents}c)`,
          } as const,
        );
      });
    }
    return Effect.flatMap(
      Ref.get(this.perActionTotals),
      (counts): Effect.Effect<ApprovalDecision, never> => {
        const used = counts.get(request.actionName) ?? 0;
      if (used + spend > this.maxCents) {
        return Effect.succeed({
          decision: "denied",
          reason: `spending budget exhausted for '${request.actionName}' (${used}+${spend}>${this.maxCents}c)`,
        } as const);
      }
      const next = new Map(counts);
      next.set(request.actionName, used + spend);
      return Effect.as(
        Ref.set(this.perActionTotals, next),
        {
          decision: "allowed",
          reason: `within spending budget (${used + spend}/${this.maxCents}c)`,
        } as const,
      );
    });
  }
}

export class RateLimitProvider {
  private readonly attempts: Array<number> = [];

  constructor(
    private readonly maxCalls: number,
    private readonly windowSeconds: number,
    private readonly clock: () => number = () => Date.now() / 1000,
  ) {
    if (!Number.isInteger(maxCalls) || maxCalls <= 0) {
      throw new Error("maxCalls must be a positive integer");
    }
    if (!(windowSeconds > 0)) {
      throw new Error("windowSeconds must be positive");
    }
  }

  /** Sliding window over allowances; denials consume no quota. Not cross-process. */
  decide(_request: ApprovalRequest): Effect.Effect<ApprovalDecision, never> {
    const now = this.clock();
    const cutoff = now - this.windowSeconds;
    while (this.attempts.length > 0 && (this.attempts[0] as number) <= cutoff) {
      this.attempts.shift();
    }
    if (this.attempts.length >= this.maxCalls) {
      return Effect.succeed({
        decision: "denied",
        reason: `rate limit exceeded (${this.maxCalls} per ${this.windowSeconds}s)`,
      } as const);
    }
    this.attempts.push(now);
    return Effect.succeed({ decision: "allowed", reason: "within rate limit" } as const);
  }
}

export class QuorumApprovalProvider {
  constructor(
    private readonly providers: ReadonlyArray<Decide>,
    private readonly quorum: number,
  ) {
    if (providers.length === 0) throw new Error("at least one provider is required");
    if (!Number.isInteger(quorum) || quorum < 1 || quorum > providers.length) {
      throw new Error(`quorum must be between 1 and ${providers.length}`);
    }
  }

  /**
   * Every provider is consulted (no short-circuit); defects count as denials
   * and are named in the reason, matching the Python provider. Monitor denial
   * reasons, not just error types, behind a quorum.
   */
  decide(request: ApprovalRequest): Effect.Effect<ApprovalDecision, never> {
    return Effect.map(
      Effect.forEach(this.providers, (decide) =>
        Effect.matchCauseEffect(decide(request), {
          onFailure: (cause) =>
            Effect.succeed({
              allowed: false,
              reason: `errored (${Cause.pretty(cause).split("\n")[0].slice(0, 120)})`,
            }),
          onSuccess: (decision) =>
            Effect.succeed({ allowed: decision.decision === "allowed", reason: decision.reason }),
        }),
      ),
      (outcomes) => {
        const allowed = outcomes.filter((outcome) => outcome.allowed);
        if (allowed.length >= this.quorum) {
          return {
            decision: "allowed",
            reason: `quorum reached (${allowed.length}/${this.quorum} of ${this.providers.length})`,
          } as const;
        }
        return {
          decision: "denied",
          reason:
            `quorum missed (${allowed.length}/${this.quorum} of ${this.providers.length}): ` +
            outcomes.map((outcome) => outcome.reason).join("; "),
        } as const;
      },
    );
  }
}

export interface PolicyRule {
  readonly action: string;
  readonly decision: "allowed" | "denied";
  readonly risks?: ReadonlyArray<string>;
  readonly reason?: string;
}

const globToRegExp = (glob: string): RegExp => {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
};

export class RuleProvider {
  private readonly compiled: Array<{ rule: PolicyRule; pattern: RegExp }>;

  constructor(
    rules: ReadonlyArray<PolicyRule>,
    private readonly defaultDecision: "allowed" | "denied" = "denied",
  ) {
    for (const rule of rules) {
      if (rule.decision !== "allowed" && rule.decision !== "denied") {
        throw new Error(`invalid decision ${JSON.stringify(rule.decision)} in rule for ${JSON.stringify(rule.action)}`);
      }
    }
    this.compiled = rules.map((rule) => ({ rule, pattern: globToRegExp(rule.action) }));
  }

  /** First matching rule decides; otherwise the default (deny unless allowed). */
  decide(request: ApprovalRequest): ApprovalDecision {
    for (const { rule, pattern } of this.compiled) {
      if (!pattern.test(request.actionName)) continue;
      if (rule.risks !== undefined && !rule.risks.includes(request.risk)) continue;
      return {
        decision: rule.decision,
        reason: rule.reason ?? `matched rule '${rule.action}' -> ${rule.decision}`,
      };
    }
    return this.defaultDecision === "allowed"
      ? { decision: "allowed", reason: "allowed by policy default" }
      : { decision: "denied", reason: "no policy rule matched; default deny" };
  }
}

const KNOWN_RISKS = new Set(["low", "medium", "high", "critical"]);

/** Load a declarative JSON policy file; malformed input fails closed at load. */
export const loadPolicyFile = (filePath: string): RuleProvider => {
  let raw: unknown;
  try {
    raw = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (cause) {
    throw new PolicyError({ message: `cannot read policy file ${filePath}: ${cause}` });
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new PolicyError({ message: `policy file ${filePath} must hold a JSON object` });
  }
  const document = raw as Record<string, unknown>;
  const topKeys = new Set(Object.keys(document));
  for (const key of topKeys) {
    if (key !== "default" && key !== "rules") {
      throw new PolicyError({ message: `policy file ${filePath}: unknown top-level key ${JSON.stringify(key)}` });
    }
  }
  const entries = document["rules"] ?? [];
  if (!Array.isArray(entries)) {
    throw new PolicyError({ message: `policy file ${filePath}: 'rules' must be a list` });
  }
  const rules: Array<PolicyRule> = entries.map((entry: unknown, index: number) => {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new PolicyError({ message: `policy file ${filePath}: rule ${index} must be an object` });
    }
    const candidate = entry as Record<string, unknown>;
    for (const key of Object.keys(candidate)) {
      if (!["action", "decision", "risks", "reason"].includes(key)) {
        throw new PolicyError({ message: `policy file ${filePath}: rule ${index} has unknown key ${JSON.stringify(key)}` });
      }
    }
    const action = candidate["action"];
    const decision = candidate["decision"];
    if (typeof action !== "string" || action === "") {
      throw new PolicyError({ message: `policy file ${filePath}: rule ${index} needs a non-empty 'action'` });
    }
    if (decision !== "allowed" && decision !== "denied") {
      throw new PolicyError({ message: `policy file ${filePath}: rule ${index} needs decision allowed/denied` });
    }
    let risks: Array<string> | undefined;
    if (candidate["risks"] !== undefined) {
      if (!Array.isArray(candidate["risks"]) || !candidate["risks"].every((r) => typeof r === "string")) {
        throw new PolicyError({ message: `policy file ${filePath}: rule ${index} 'risks' must be a string list` });
      }
      const unknown = (candidate["risks"] as Array<string>).filter((r) => !KNOWN_RISKS.has(r));
      if (unknown.length > 0) {
        throw new PolicyError({
          message: `policy file ${filePath}: rule ${index} has unknown risks ${unknown.join(",")}`,
        });
      }
      risks = candidate["risks"] as Array<string>;
    }
    const reason = candidate["reason"] ?? "";
    if (typeof reason !== "string") {
      throw new PolicyError({ message: `policy file ${filePath}: rule ${index} 'reason' must be a string` });
    }
    return { action, decision, risks, reason };
  });
  const defaultDecision = document["default"] ?? "denied";
  if (defaultDecision !== "allowed" && defaultDecision !== "denied") {
    throw new PolicyError({ message: `policy file ${filePath}: 'default' must be allowed/denied` });
  }
  return new RuleProvider(rules, defaultDecision);
};

/**
 * Stamp inner allowances with an operator identity (explicit or from
 * `INTERCEPTOR_APPROVER`, e.g. an OIDC `sub` the launcher exports). Denials
 * pass through; missing or malformed identity fails closed.
 */
export class AttestedApprovalProvider {
  constructor(
    private readonly inner: Decide,
    private readonly approvedBy?: string,
    private readonly approvedByEnv = "INTERCEPTOR_APPROVER",
  ) {}

  decide(request: ApprovalRequest): Effect.Effect<ApprovalDecision, never> {
    return Effect.flatMap(this.inner(request), (decision) => {
      if (decision.decision !== "allowed") return Effect.succeed(decision);
      const raw = this.approvedBy ?? process.env[this.approvedByEnv] ?? null;
      // Collapse whitespace runs (matching the Python provider); control
      // characters fail the charset below.
      const identity = raw === null ? null : raw.trim().split(/\s+/).join(" ");
      if (identity === null || identity === "" || !IDENTITY_PATTERN.test(identity)) {
        return Effect.succeed({
          decision: "denied",
          reason: "no attributable approver identity; failing closed",
        } as const);
      }
      return Effect.succeed({ ...decision, approvedBy: identity });
    });
  }
}
