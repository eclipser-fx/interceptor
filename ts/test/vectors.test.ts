/**
 * Cross-language conformance: the Effect verifier checks the exact journals
 * Python produced (`verifiers/vectors/v1/*.json`) and must reproduce validity,
 * event counts, and failure codes. Any divergence between implementations
 * fails here, not in an audit.
 */
import { readFileSync, readdirSync } from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { Effect } from "effect";
import { describe, expect, it } from "vitest";
import { keyringFromPems, verifyLines } from "../src/Verify.js";

const vectorsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../verifiers/vectors/v1",
);

const vectors = readdirSync(vectorsDir).filter((f) => f.endsWith(".json")).sort();

describe.each(vectors)("%s", (file) => {
  it("matches the committed expectations", async () => {
    const vector = JSON.parse(readFileSync(path.join(vectorsDir, file), "utf8")) as {
      journal: Array<string>;
      public_keys: Array<string>;
      expect: {
        valid: boolean;
        events_verified: number;
        codes: Array<string>;
        issues: Array<string>;
      };
    };
    const result = await Effect.runPromise(
      verifyLines(vector.journal, keyringFromPems(vector.public_keys)),
    );
    expect(result.valid).toBe(vector.expect.valid);
    expect(result.eventsVerified).toBe(vector.expect.events_verified);
    // Ordered per-line findings: right codes on the wrong lines fail here.
    expect(result.issues.map((i) => `${i.lineNumber}:${i.code}`)).toEqual(
      vector.expect.issues as Array<string>,
    );
  });
});
