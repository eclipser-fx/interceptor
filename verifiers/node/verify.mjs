#!/usr/bin/env node
/**
 * Independent interceptor journal verifier — no dependency on the Python
 * package. Implements docs/EVIDENCE_FORMAT.md from scratch using only
 * Node.js builtins: chain linkage, canonical-JSON event hashes, Ed25519
 * signatures over the raw digest, per-type required fields, and checkpoint
 * truncation coverage.
 *
 * Usage:
 *   node verify.mjs --journal journal.jsonl --public-key verify_key.pem \
 *     [--checkpoint journal.jsonl.checkpoint] [--json]
 *
 * Exit 0 when valid, 1 otherwise.
 *
 * Known divergences from the Python verifier (deliberate, documented):
 * - integers beyond 2^53 lose precision in JSON.parse and will mismatch;
 * - integral floats are re-encoded with a ".0" suffix to match Python;
 * - object keys sort by UTF-16 code units (differs from code-point order
 *   only for astral-plane key names, which cannot be produced by matching
 *   the Python redactor's ASCII-folded sensitive set anyway).
 */
import { readFileSync } from "node:fs";
import { createHash, createPublicKey, verify } from "node:crypto";

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
  "schema_version", "event_type", "event_id", "timestamp_utc",
  "key_id", "event_hash", "signature",
];
const ACTION = ["action_id", "action_name", "contract_hash"];
const REQUIRED = {
  decision: [...SHARED, ...ACTION, "decision", "risk", "approval_mode",
    "redacted_input_summary", "input_hash"],
  outcome: [...SHARED, ...ACTION, "status", "decision_event_id"],
  checkpoint: [...SHARED, "checkpoint_count", "head_sha256"],
  resolution: [...SHARED, ...ACTION, "decision_event_id", "resolution", "note"],
  countersignature: [...SHARED, "checkpoint_event_id", "checkpoint_count", "head_sha256"],
  archive: [...SHARED, "prior_count", "prior_head", "archived_path"],
  rotation: [...SHARED, "prior_key_id", "successor_key_id", "successor_fingerprint"],
};

function pyFloat(value) {
  // Python repr() subset sufficient for evidence values. Both runtimes use
  // shortest-round-trip digits, so plain decimals already agree; the gaps are
  // integral floats ("1.0" vs "1") and exponent *formatting*.
  if (Number.isInteger(value) && Math.abs(value) < 1e16) return `${value}.0`;
  const text = `${value}`;
  if (!/[eE]/.test(text)) return text; // plain decimal: identical digits
  const [mantissa, exp] = text.toLowerCase().split("e");
  const point = mantissa.includes(".") ? mantissa : `${mantissa}.0`;
  const num = Number.parseInt(exp, 10);
  const sign = num < 0 ? "-" : "+";
  return `${point}e${sign}${`${Math.abs(num)}`.padStart(2, "0")}`;
}

/**
 * Raw JSON parser that preserves each number's lexical form.
 *
 * JSON.parse erases the int/float distinction Python's json module keeps
 * ("2" vs "2.0" hash differently), so canonical hashing walks this tree
 * instead: numbers become { $num: <source text> } markers. Duplicate object
 * keys resolve last-wins, matching JSON.parse.
 */
function parseRaw(text) {
  let pos = 0;
  const fail = (msg) => { throw new Error(`invalid JSON at ${pos}: ${msg}`); };
  const skipWs = () => {
    while (pos < text.length && " \t\n\r".includes(text[pos])) pos++;
  };
  function parseValue() {
    skipWs();
    const ch = text[pos];
    if (ch === "{") return parseObject();
    if (ch === "[") return parseArray();
    if (ch === '"') return parseString();
    if (ch === "t") return parseLiteral("true", true);
    if (ch === "f") return parseLiteral("false", false);
    if (ch === "n") return parseLiteral("null", null);
    if (ch === "-" || (ch >= "0" && ch <= "9")) return parseNumber();
    fail("unexpected character");
  }
  function parseLiteral(word, value) {
    if (!text.startsWith(word, pos)) fail("bad literal");
    pos += word.length;
    return value;
  }
  function parseString() {
    // Reuse the platform parser for one string: it validates escapes.
    const match = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(
      text.slice(pos),
    );
    if (!match) fail("bad string");
    pos += match[0].length;
    return JSON.parse(match[0]);
  }
  function parseNumber() {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(pos));
    if (!match) fail("bad number");
    pos += match[0].length;
    return { $num: match[0] };
  }
  function parseArray() {
    pos++; // [
    const out = [];
    skipWs();
    if (text[pos] === "]") { pos++; return out; }
    for (;;) {
      out.push(parseValue());
      skipWs();
      if (text[pos] === ",") { pos++; continue; }
      if (text[pos] === "]") { pos++; return out; }
      fail("expected , or ]");
    }
  }
  function parseObject() {
    pos++; // {
    const out = {};
    skipWs();
    if (text[pos] === "}") { pos++; return out; }
    for (;;) {
      skipWs();
      if (text[pos] !== '"') fail("expected string key");
      const key = parseString();
      skipWs();
      if (text[pos] !== ":") fail("expected :");
      pos++;
      out[key] = parseValue();
      skipWs();
      if (text[pos] === ",") { pos++; continue; }
      if (text[pos] === "}") { pos++; return out; }
      fail("expected , or }");
    }
  }
  const value = parseValue();
  skipWs();
  if (pos !== text.length) fail("trailing data");
  return value;
}

function isNum(node) {
  return typeof node === "object" && node !== null && !Array.isArray(node) && "$num" in node;
}

function canonicalRaw(node) {
  if (node === null || node === true || node === false) return canonical(node);
  if (typeof node === "string") return canonical(node);
  if (isNum(node)) {
    const token = node.$num;
    if (/^-?(?:0|[1-9]\d*)$/.test(token)) return token; // JSON int: verbatim
    return pyFloat(Number(token)); // JSON float: Python float repr rules
  }
  if (Array.isArray(node)) return `[${node.map(canonicalRaw).join(",")}]`;
  if (typeof node === "object") {
    const keys = Object.keys(node).sort();
    return `{${keys.map((k) => `${canonical(k)}:${canonicalRaw(node[k])}`).join(",")}}`;
  }
  throw new Error("unserializable");
}

function canonical(value) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return pyFloat(value);
  }
  if (typeof value === "string") {
    // JSON.stringify emits non-ASCII literally (like ensure_ascii=False),
    // except U+2028/2029 which Python leaves literal too.
    return JSON.stringify(value).replace(/\\u2028/g, "\u2028").replace(/\\u2029/g, "\u2029");
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(",")}}`;
  }
  throw new Error(`unserializable ${typeof value}`);
}

function keyIdFor(pemPath) {
  const key = createPublicKey(readFileSync(pemPath));
  const raw = Buffer.from(key.export({ format: "jwk" }).x, "base64url");
  return `ed25519:${createHash("sha256").update(raw).digest("hex").slice(0, 16)}`;
}

function loadPem(pemPath) {
  return createPublicKey(readFileSync(pemPath));
}

function parseArgs(argv) {
  const out = { publicKeys: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--journal") out.journal = argv[++i];
    else if (a === "--public-key") out.publicKeys.push(argv[++i]);
    else if (a === "--checkpoint") out.checkpoint = argv[++i];
    else if (a === "--json") out.json = true;
    else throw new Error(`unknown arg ${a}`);
  }
  if (!out.journal || out.publicKeys.length === 0) throw new Error("need --journal and --public-key");
  return out;
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`error: ${err.message}`);
    process.exitCode = 2;
    return;
  }
  const keyring = new Map(args.publicKeys.map((p) => [keyIdFor(p), loadPem(p)]));
  const issues = [];
  let previous = null;
  let verified = 0;
  let total = 0;
  let newestCheckpoint = null;
  const checkpoints = new Map();

  const lines = readFileSync(args.journal, "utf8").split("\n");
  lines.forEach((raw, idx) => {
    const lineNo = idx + 1;
    if (!raw.trim()) return;
    let event;
    try {
      event = JSON.parse(raw);
    } catch {
      issues.push({ line_number: lineNo, code: "malformed_json", message: "not valid JSON" });
      return;
    }    if (typeof event !== "object" || event === null) {
      issues.push({ line_number: lineNo, code: "malformed_event", message: "not an object" });
      return;
    }
    total++;
    if (!KNOWN_SCHEMAS.has(event.schema_version)) {
      issues.push({ line_number: lineNo, code: "unknown_schema", message: "bad schema_version" });
      return;
    }
    if (!KNOWN_TYPES.has(event.event_type)) {
      issues.push({ line_number: lineNo, code: "unknown_event_type", message: "bad event_type" });
      return;
    }
    const missing = [...REQUIRED[event.event_type], "previous_event_hash"]
      .filter((f) => !(f in event));
    if (missing.length > 0) {
      issues.push({ line_number: lineNo, code: "missing_fields", message: `missing: ${missing.sort().join(",")}` });
      return;
    }
    if (event.previous_event_hash !== previous) {
      issues.push({ line_number: lineNo, code: "chain_break", message: "previous_event_hash mismatch" });
    }
    const { event_hash, signature } = event;
    let digestHex;
    try {
      // Hash the number-preserving tree so ints ("2") and floats ("2.0")
      // encode exactly as the Python writer emitted them.
      const rawTree = parseRaw(raw.trim());
      delete rawTree.event_hash;
      delete rawTree.signature;
      digestHex = createHash("sha256").update(canonicalRaw(rawTree), "utf8").digest("hex");
    } catch (err) {
      issues.push({ line_number: lineNo, code: "hash_mismatch", message: String(err) });
      return;
    }
    if (event_hash !== digestHex) {
      issues.push({ line_number: lineNo, code: "hash_mismatch", message: "event_hash mismatch" });
    }
    const signer = keyring.get(event.key_id);
    if (!signer) {
      issues.push({ line_number: lineNo, code: "unknown_key", message: `untrusted ${event.key_id}` });
    } else {
      const ok = verify(
        null,
        Buffer.from(digestHex, "hex"),
        signer,
        Buffer.from(signature, "base64"),
      );
      if (!ok) issues.push({ line_number: lineNo, code: "bad_signature", message: "Ed25519 failed" });
      else verified++;
    }
    if (typeof event_hash === "string") previous = event_hash;
    if (event.event_type === "checkpoint") {
      newestCheckpoint = event;
      checkpoints.set(event.event_id, event);
    }
    if (event.event_type === "countersignature") {
      const ref = checkpoints.get(event.checkpoint_event_id);
      if (!ref) {
        issues.push({ line_number: lineNo, code: "countersignature_orphan", message: "unknown checkpoint" });
      } else if (ref.checkpoint_count !== event.checkpoint_count || ref.head_sha256 !== event.head_sha256) {
        issues.push({ line_number: lineNo, code: "countersignature_mismatch", message: "count/head differ" });
      }
    }
  });

  const effective = newestCheckpoint;
  if (args.checkpoint) {
    try {
      const witness = JSON.parse(readFileSync(args.checkpoint, "utf8").trim());
      if (witness.event_type === "checkpoint" && total < witness.checkpoint_count) {
        issues.push({ line_number: 0, code: "checkpoint_truncation", message: "journal shorter than witness" });
      }
    } catch {
      issues.push({ line_number: 0, code: "checkpoint_witness_invalid", message: "bad witness" });
    }
  } else if (effective && total < effective.checkpoint_count) {
    issues.push({ line_number: 0, code: "checkpoint_truncation", message: "journal shorter than checkpoint" });
  }

  const valid = issues.length === 0;
  if (args.json) {
    console.log(JSON.stringify({ valid, events_verified: verified, issues }, null, 2));
  } else if (valid) {
    console.log(`OK  ${args.journal}\n    ${verified} events verified (independent node verifier)`);
  } else {
    console.log(`FAIL  ${args.journal}`);
    for (const i of issues) console.log(`      line ${i.line_number}: [${i.code}] ${i.message}`);
  }
  process.exitCode = valid ? 0 : 1;
}

main();
