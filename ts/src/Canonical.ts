/**
 * Canonical JSON matching the Python evidence format v1 byte-for-byte:
 * UTF-8, keys sorted lexicographically, compact separators, no whitespace,
 * non-ASCII emitted literally, NaN/Infinity rejected.
 *
 * Two entry points: `canonical` for values we construct, and `canonicalRaw`
 * for hashing journal lines verbatim, where a raw-number preserving parse
 * keeps `2` and `2.0` distinct exactly as written.
 */

export class NonCanonicalError extends Error {
  readonly _tag = "NonCanonicalError";
}

/**
 * Number formatting matching Python's `json` encoder for the values that can
 * actually agree across implementations. JavaScript cannot distinguish `2`
 * from `2.0`, so integral values encode verbatim (matching Python ints, the
 * overwhelmingly common case in evidence: counts, cents, lengths). A genuine
 * Python `float` 2.0 encodes as `2.0` there and `2` here — a documented,
 * unavoidable divergence of cross-language floats, not a bug in either
 * encoder. Non-integral doubles already agree via shortest-round-trip digits.
 */
export const pyFloat = (value: number): string => {
  if (!Number.isFinite(value)) throw new NonCanonicalError("non-finite number");
  if (Object.is(value, -0)) return "-0.0";
  if (Number.isInteger(value) && Math.abs(value) < 1e16) return `${value}`;
  const text = `${value}`;
  if (!/[eE]/.test(text)) return text; // plain decimal: identical digits
  const [mantissa, exp] = text.toLowerCase().split("e");
  const num = Number.parseInt(exp, 10);
  const sign = num < 0 ? "-" : "+";
  return `${mantissa}e${sign}${`${Math.abs(num)}`.padStart(2, "0")}`;
};

const escapeString = (value: string): string =>
  // JSON.stringify emits non-ASCII literally (like ensure_ascii=False),
  // except U+2028/2029 which Python leaves literal too.
  JSON.stringify(value).replace(/\\u2028/g, "\u2028").replace(/\\u2029/g, "\u2029");

export const canonical = (value: unknown): string => {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return pyFloat(value);
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${escapeString(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  throw new NonCanonicalError(`unserializable ${typeof value}`);
};

/** Raw-number marker from the lexical JSON parse below. */
export interface RawNum {
  readonly $num: string;
}

export const isRawNum = (node: unknown): node is RawNum =>
  typeof node === "object" && node !== null && !Array.isArray(node) && "$num" in node;

/**
 * Minimal JSON parser that preserves each number's lexical form.
 * `JSON.parse` erases the int/float distinction Python's json module keeps
 * (`2` vs `2.0` hash differently), so canonical hashing walks this tree:
 * numbers become `{ $num: <source text> }` markers.
 */
export const parseRaw = (text: string): unknown => {
  let pos = 0;
  const fail = (msg: string): never => {
    throw new Error(`invalid JSON at ${pos}: ${msg}`);
  };
  const skipWs = (): void => {
    while (pos < text.length && " \t\n\r".includes(text[pos])) pos++;
  };
  function parseValue(): unknown {
    skipWs();
    const ch = text[pos];
    if (ch === "{") return parseObject();
    if (ch === "[") return parseArray();
    if (ch === '"') return parseString();
    if (ch === "t") return parseLiteral("true", true);
    if (ch === "f") return parseLiteral("false", false);
    if (ch === "n") return parseLiteral("null", null);
    if (ch === "-" || (ch >= "0" && ch <= "9")) return parseNumber();
    return fail("unexpected character");
  }
  function parseLiteral(word: string, value: unknown): unknown {
    if (!text.startsWith(word, pos)) fail("bad literal");
    pos += word.length;
    return value;
  }
  function parseString(): string {
    const match = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(
      text.slice(pos),
    );
    if (match === null) throw new Error(`invalid JSON at ${pos}: bad string`);
    pos += match[0].length;
    return JSON.parse(match[0]) as string;
  }
  function parseNumber(): RawNum {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(pos));
    if (match === null) throw new Error(`invalid JSON at ${pos}: bad number`);
    pos += match[0].length;
    return { $num: match[0] };
  }
  function parseArray(): unknown[] {
    pos++; // [
    const out: unknown[] = [];
    skipWs();
    if (text[pos] === "]") {
      pos++;
      return out;
    }
    for (;;) {
      out.push(parseValue());
      skipWs();
      if (text[pos] === ",") {
        pos++;
        continue;
      }
      if (text[pos] === "]") {
        pos++;
        return out;
      }
      fail("expected , or ]");
    }
  }
  function parseObject(): Record<string, unknown> {
    pos++; // {
    const out: Record<string, unknown> = {};
    skipWs();
    if (text[pos] === "}") {
      pos++;
      return out;
    }
    for (;;) {
      skipWs();
      if (text[pos] !== '"') fail("expected string key");
      const key = parseString();
      skipWs();
      if (text[pos] !== ":") fail("expected :");
      pos++;
      out[key] = parseValue();
      skipWs();
      if (text[pos] === ",") {
        pos++;
        continue;
      }
      if (text[pos] === "}") {
        pos++;
        return out;
      }
      fail("expected , or }");
    }
  }
  const value = parseValue();
  skipWs();
  if (pos !== text.length) fail("trailing data");
  return value;
};

export const canonicalRaw = (node: unknown): string => {
  if (node === null || node === true || node === false) return canonical(node);
  if (typeof node === "string") return canonical(node);
  if (isRawNum(node)) {
    const token = node.$num;
    if (/^-?(?:0|[1-9]\d*)$/.test(token)) return token; // JSON int: verbatim
    return pyFloat(Number(token)); // JSON float: Python float repr rules
  }
  if (Array.isArray(node)) return `[${node.map(canonicalRaw).join(",")}]`;
  if (typeof node === "object") {
    const record = node as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    return `{${keys.map((k) => `${canonical(k)}:${canonicalRaw(record[k])}`).join(",")}}`;
  }
  throw new NonCanonicalError("unserializable");
};
