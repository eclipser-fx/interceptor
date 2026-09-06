/**
 * Offline journal verification as Effect: per-event shape, hash, signature,
 * and chain linkage, plus checkpoint / countersignature / rotation / archive
 * semantics matching the Python verifier and `docs/EVIDENCE_FORMAT.md`.
 *
 * Pure and dependency-free apart from Node's crypto: give it lines and a
 * keyring, get a result. Journal I/O stays at the edges (see test/ for the
 * vector harness pattern).
 */
import { createHash } from "node:crypto";
import { Data, Effect, Option, Schema } from "effect";
import { canonicalRaw, parseRaw } from "./Canonical.js";
import { publicKeyFromPem, verifySignature } from "./Identity.js";

/** Structural gate shared with `Schemas.ts`: untrusted lines decode to string-keyed records or not at all. */
const asRecord = Schema.decodeUnknownOption(Schema.Record({ key: Schema.String, value: Schema.Unknown }));

export interface VerifyIssue {
  readonly lineNumber: number;
  readonly code: string;
  readonly message: string;
}

export interface VerifyResult {
  readonly valid: boolean;
  readonly eventsVerified: number;
  readonly issues: ReadonlyArray<VerifyIssue>;
}

export class JournalReadError extends Data.TaggedError("JournalReadError")<{
  readonly message: string;
}> {}

const KNOWN_SCHEMAS = new Set(["1"]);
const KNOWN_TYPES = new Set([
  "decision",
  "outcome",
  "checkpoint",
  "resolution",
  "countersignature",
  "archive",
  "rotation",
]);

const SHARED = [
  "schema_version",
  "event_type",
  "event_id",
  "timestamp_utc",
  "key_id",
  "event_hash",
  "signature",
];
const ACTION = ["action_id", "action_name", "contract_hash"];
const REQUIRED: Record<string, ReadonlyArray<string>> = {
  decision: [...SHARED, ...ACTION, "decision", "risk", "approval_mode", "redacted_input_summary", "input_hash"],
  outcome: [...SHARED, ...ACTION, "status", "decision_event_id"],
  checkpoint: [...SHARED, "checkpoint_count", "head_sha256"],
  resolution: [...SHARED, ...ACTION, "decision_event_id", "resolution", "note"],
  countersignature: [...SHARED, "checkpoint_event_id", "checkpoint_count", "head_sha256"],
  archive: [...SHARED, "prior_count", "prior_head", "archived_path"],
  rotation: [...SHARED, "prior_key_id", "successor_key_id", "successor_fingerprint"],
};

const KNOWN_RESOLUTIONS = new Set(["confirmed_completed", "confirmed_not_completed"]);

export interface Keyring {
  readonly keys: Map<string, ReturnType<typeof publicKeyFromPem>>;
}

// NOTE on rotation: like the Python verifier, rotation checks are structural
// (the successor is named by a fingerprint the prior key signed). They do not
// grant trust — each event still verifies against the caller-supplied keyring,
// so a successor key must be added to the keyring out of band, exactly as
// `trusted_keys/` works on the Python side.

export const keyringFromPems = (pems: ReadonlyArray<string>): Keyring => {
  const keys = new Map<string, ReturnType<typeof publicKeyFromPem>>();
  for (const pem of pems) {
    const key = publicKeyFromPem(pem);
    const jwk = key.export({ format: "jwk" }) as { x: string };
    const raw = Buffer.from(jwk.x, "base64url");
    keys.set(`ed25519:${createHash("sha256").update(raw).digest("hex").slice(0, 16)}`, key);
  }
  return { keys };
};

const digestOfUnsigned = (rawLine: string): string => {
  // Hash the number-preserving tree so ints ("2") and floats ("2.0") encode
  // exactly as the writer emitted them.
  const tree = parseRaw(rawLine.trim()) as Record<string, unknown>;
  delete tree["event_hash"];
  delete tree["signature"];
  return createHash("sha256").update(canonicalRaw(tree), "utf8").digest("hex");
};

const badArchivePath = (value: unknown): boolean =>
  typeof value !== "string" ||
  value === "" ||
  value === "." ||
  value === ".." ||
  value.includes("/") ||
  value.includes("\\");

export const verifyLines = (
  lines: ReadonlyArray<string>,
  keyring: Keyring,
): Effect.Effect<VerifyResult, never> =>
  Effect.sync(() => {
    const issues: VerifyIssue[] = [];
    let previous: string | null = null;
    let verified = 0;
    let total = 0;
    let newestCheckpoint: Record<string, unknown> | null = null;
    const checkpoints = new Map<string, Record<string, unknown>>();
    let firstNonEmpty = -1;

    for (const [index, raw] of lines.entries()) {
      const lineNumber = index + 1;
      if (!raw.trim()) continue;
      if (firstNonEmpty === -1) firstNonEmpty = lineNumber;
      let event: unknown;
      try {
        event = JSON.parse(raw);
      } catch {
        issues.push({ lineNumber, code: "malformed_json", message: "not valid JSON" });
        break; // The chain cannot be followed past an unparseable line.
      }
      const maybeRecord = asRecord(event);
      if (Option.isNone(maybeRecord)) {
        issues.push({ lineNumber, code: "malformed_event", message: "not an object" });
        break;
      }
      const record = maybeRecord.value;
      total++;
      if (!KNOWN_SCHEMAS.has(record["schema_version"] as string)) {
        issues.push({ lineNumber, code: "unknown_schema", message: "bad schema_version" });
        continue;
      }
      if (!KNOWN_TYPES.has(record["event_type"] as string)) {
        issues.push({ lineNumber, code: "unknown_event_type", message: "bad event_type" });
        continue;
      }
      const eventType = record["event_type"] as string;
      const missing = [...REQUIRED[eventType], "previous_event_hash"].filter((f) => !(f in record));
      if (missing.length > 0) {
        issues.push({
          lineNumber,
          code: "missing_fields",
          message: `missing: ${[...missing].sort().join(",")}`,
        });
        continue;
      }

      // Type-specific shape.
      if (eventType === "decision" && record["decision"] !== "allowed" && record["decision"] !== "denied") {
        issues.push({
          lineNumber,
          code: "invalid_decision",
          message: `unsupported decision ${String(record["decision"])}`,
        });
      }
      if (
        eventType === "outcome" &&
        record["status"] !== "succeeded" &&
        record["status"] !== "failed"
      ) {
        issues.push({
          lineNumber,
          code: "invalid_outcome_status",
          message: `unsupported outcome status ${String(record["status"])}`,
        });
      }
      if (eventType === "checkpoint" && record["head_sha256"] !== record["previous_event_hash"]) {
        issues.push({
          lineNumber,
          code: "checkpoint_head_mismatch",
          message: "head_sha256 does not match previous_event_hash",
        });
      }
      if (eventType === "checkpoint" || eventType === "countersignature") {
        const count = record["checkpoint_count"];
        if (typeof count !== "number" || !Number.isInteger(count) || count < 0) {
          issues.push({
            lineNumber,
            code: eventType === "checkpoint" ? "checkpoint_bad_count" : "countersignature_bad_count",
            message: "checkpoint_count is not a non-negative integer",
          });
        }
      }
      if (eventType === "resolution" && !KNOWN_RESOLUTIONS.has(record["resolution"] as string)) {
        issues.push({
          lineNumber,
          code: "resolution_bad_value",
          message: `unknown resolution ${String(record["resolution"])}`,
        });
      }
      if (eventType === "archive") {
        if (lineNumber !== firstNonEmpty) {
          issues.push({
            lineNumber,
            code: "archive_not_first",
            message: "archive event must be the first line of its file",
          });
        }
        if (badArchivePath(record["archived_path"])) {
          issues.push({
            lineNumber,
            code: "archive_bad_path",
            message: "archived_path must be a bare file name",
          });
        }
        if (
          typeof record["prior_count"] !== "number" ||
          !Number.isInteger(record["prior_count"]) ||
          (record["prior_count"] as number) < 1
        ) {
          issues.push({
            lineNumber,
            code: "archive_bad_count",
            message: "prior_count is not a positive integer",
          });
        }
      }
      if (eventType === "rotation") {
        if (record["prior_key_id"] !== record["key_id"]) {
          issues.push({
            lineNumber,
            code: "rotation_signer_mismatch",
            message: "prior_key_id must equal key_id",
          });
        }
        const fp = record["successor_fingerprint"];
        if (typeof fp !== "string" || !/^[0-9a-f]{64}$/.test(fp)) {
          issues.push({
            lineNumber,
            code: "rotation_bad_fingerprint",
            message: "successor_fingerprint is not 64-char hex",
          });
        } else if (record["successor_key_id"] !== `ed25519:${(fp as string).slice(0, 16)}`) {
          issues.push({
            lineNumber,
            code: "rotation_fingerprint_mismatch",
            message: "successor_key_id does not match fingerprint",
          });
        }
        if (record["prior_key_id"] === record["successor_key_id"]) {
          issues.push({
            lineNumber,
            code: "rotation_self_successor",
            message: "successor must differ from prior",
          });
        }
      }

      if (record["previous_event_hash"] !== previous) {
        issues.push({ lineNumber, code: "chain_break", message: "previous_event_hash mismatch" });
      }
      let digestHex: string;
      try {
        digestHex = digestOfUnsigned(raw);
      } catch (cause) {
        issues.push({ lineNumber, code: "hash_mismatch", message: String(cause) });
        // Follow the stored hash so one unhashable line does not cascade
        // chain errors down the rest of the file.
        if (typeof record["event_hash"] === "string") previous = record["event_hash"];
        continue;
      }
      if (record["event_hash"] !== digestHex) {
        issues.push({ lineNumber, code: "hash_mismatch", message: "event_hash mismatch" });
      }
      const signer = typeof record["key_id"] === "string" ? keyring.keys.get(record["key_id"]) : undefined;
      if (!signer) {
        issues.push({ lineNumber, code: "unknown_key", message: `untrusted ${String(record["key_id"])}` });
      } else {
        const ok = verifySignature(signer, Buffer.from(digestHex, "hex"), String(record["signature"]));
        if (!ok) {
          issues.push({ lineNumber, code: "bad_signature", message: "Ed25519 failed" });
        } else {
          verified++;
        }
      }
      if (typeof record["event_hash"] === "string") previous = record["event_hash"];
      if (eventType === "checkpoint") {
        newestCheckpoint = record;
        if (typeof record["event_id"] === "string") checkpoints.set(record["event_id"], record);
      }
      if (eventType === "countersignature") {
        const ref = checkpoints.get(record["checkpoint_event_id"] as string);
        if (!ref) {
          issues.push({
            lineNumber,
            code: "countersignature_orphan",
            message: "unknown checkpoint",
          });
        } else if (
          ref["checkpoint_count"] !== record["checkpoint_count"] ||
          ref["head_sha256"] !== record["head_sha256"]
        ) {
          issues.push({
            lineNumber,
            code: "countersignature_mismatch",
            message: "count/head differ",
          });
        }
      }
    }

    const effective = newestCheckpoint;
    if (effective && total < (effective["checkpoint_count"] as number)) {
      issues.push({
        lineNumber: 0,
        code: "checkpoint_truncation",
        message: "journal shorter than checkpoint",
      });
    }
    return { valid: issues.length === 0, eventsVerified: verified, issues };
  });
