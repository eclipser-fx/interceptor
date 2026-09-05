/**
 * Redaction parity with the Python engine: homoglyph folding, value shapes,
 * custom names/patterns, and scrubbing. Cases mirror
 * `tests/test_redaction_homoglyphs.py` classes (Cyrillic, fullwidth, Greek).
 */
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { guard } from "../src/Guard.js";
import {
  compileValuePatterns,
  foldName,
  isSensitiveName,
  valueMatchesPatterns,
  DEFAULT_VALUE_PATTERNS,
} from "../src/Redaction.js";
import { SENSITIVE_NAMES } from "../src/Guard.js";

// Sampled outputs of Python's canonical.fold_name (shared limitation: an
// UPPERCASE lookalike like Cyrillic Е survives in both implementations,
// because transliteration runs before case folding).
const FOLD_PARITY: Array<[string, string]> = [
  ["API_KEY", "api_key"],
  ["api_kеy", "api_key"],
  ["тoken", "token"],
  ["passwоrd", "password"],
  ["ａpi_key", "api_key"],
  ["τοken", "token"],
  ["API_KЕY", "api_kеy"],
  ["sеcret", "secret"],
];

describe("foldName", () => {
  it("matches Python fold_name on sampled cases", () => {
    for (const [input, expected] of FOLD_PARITY) expect(foldName(input)).toBe(expected);
  });

  it("is sensitive against the built-in set", () => {
    expect(isSensitiveName("api_kеy", SENSITIVE_NAMES)).toBe(true);
    expect(isSensitiveName("totally_benign", SENSITIVE_NAMES)).toBe(false);
  });
});

describe("valueMatchesPatterns", () => {
  const patterns = compileValuePatterns();

  it("matches built-in secret shapes under generic names", () => {
    expect(patterns).toHaveLength(DEFAULT_VALUE_PATTERNS.length);
    expect(valueMatchesPatterns("sk-live-abcDEF123456", patterns)).toBe(true);
    expect(valueMatchesPatterns("ghp_abcdefgh12345678", patterns)).toBe(true);
    expect(valueMatchesPatterns("AKIAIOSFODNN7EXAMPLE", patterns)).toBe(true);
    expect(valueMatchesPatterns("ordinary prose without secrets", patterns)).toBe(false);
  });

  it("rejects invalid custom patterns", () => {
    expect(() => compileValuePatterns(["(["])).toThrow();
    expect(compileValuePatterns(["ORDER-\\d{6}"])).toHaveLength(patterns.length + 1);
  });
});

describe("guard redaction", () => {
  it("redacts homoglyph names and pattern values end to end", async () => {
    const { mkdtempSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const path = await import("node:path");
    const { generateIdentity } = await import("../src/Identity.js");
    const { makeFileJournal } = await import("../src/Journal.js");

    const dir = mkdtempSync(path.join(tmpdir(), "ic-red-"));
    const journalPath = path.join(dir, "j.jsonl");
    const journal = makeFileJournal(journalPath);
    const identity = await Effect.runPromise(generateIdentity());
    const seen: Array<unknown> = [];
    const act = guard({
      action: "user.verify",
      journal,
      approve: (req) => {
        seen.push(req.redactedInputSummary);
        return Effect.succeed({ decision: "allowed" as const, reason: "t" });
      },
      identity,
      parameterNames: ["userId", "api_kеy", "payload"],
    })((_userId: string, _key: string, _payload: string) => "ok");

    await Effect.runPromise(act("u-1", "TOPSECRET", "prefix sk-live-abcDEF123456 suffix"));
    const summary = String(seen[0]);
    expect(summary).toContain("<REDACTED>");
    expect(summary).not.toContain("TOPSECRET");
    expect(summary).not.toContain("sk-live-abcDEF123456");
    expect(summary).toContain("u-1");
  });
});
