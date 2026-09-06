/**
 * Name folding and value patterns for redaction, ported from the Python
 * canonicalizer so both implementations redact the same inputs.
 *
 * `foldName` reproduces `canonical.fold_name` step for step: NFKC normalize
 * (fullwidth/compatibility forms collapse), transliterate common
 * Cyrillic/Greek lookalikes, decompose and strip combining marks, then
 * casefold. JavaScript has no casefold; `toLowerCase` plus an explicit
 * sharp-s mapping covers the comparison-against-ASCII-sensitive-set use
 * (the only practical casefold gap at this stage).
 */
import { Data } from "effect";

export class RedactionError extends Data.TaggedError("RedactionError")<{
  readonly message: string;
}> {}

/**
 * Cross-script lookalikes for ASCII letters, collapsed before matching.
 * Code points mirror Python's `_CONFUSABLE_TO_ASCII` exactly.
 */
const CONFUSABLES: Readonly<Record<string, string>> = {
  // Cyrillic
  "а": "a", // 0430
  "в": "b", // 0432
  "е": "e", // 0435
  "ё": "e", // 0451
  "і": "i", // 0456
  "ї": "i", // 0457
  "ј": "j", // 0458
  "к": "k", // 043a
  "м": "m", // 043c
  "н": "h", // 043d
  "о": "o", // 043e
  "р": "p", // 0440
  "с": "c", // 0441
  "т": "t", // 0442
  "у": "y", // 0443
  "х": "x", // 0445
  "ц": "u", // 0446
  "ш": "w", // 0448
  "щ": "w", // 0449
  "ъ": "b", // 044a
  "ь": "b", // 044c
  "я": "r", // 044f
  "ѕ": "s", // 0455
  // Greek
  "α": "a", // 03b1
  "β": "b", // 03b2
  "γ": "y", // 03b3
  "ε": "e", // 03b5
  "ι": "i", // 03b9
  "κ": "k", // 03ba
  "μ": "u", // 03bc
  "ν": "v", // 03bd
  "ο": "o", // 03bf
  "ρ": "p", // 03c1
  "ς": "s", // 03c2
  "σ": "s", // 03c3
  "τ": "t", // 03c4
  "υ": "u", // 03c5
  "χ": "x", // 03c7
  "ω": "w", // 03c9
  "ϰ": "k", // 03f0
  "ϱ": "p", // 03f1
  "ϲ": "c", // 03f2
  "ϵ": "e", // 03f5
  // Latin and punctuation lookalikes
  "µ": "u", // 00b5
  "º": "o", // 00ba
};

export const foldName = (name: string): string => {
  const nfkc = name.normalize("NFKC");
  const transliterated = [...nfkc].map((ch) => CONFUSABLES[ch] ?? ch).join("");
  const stripped = transliterated.normalize("NFD").replace(/\p{M}/gu, "");
  return stripped.toLowerCase().replace(/ß/g, "ss");
};

export const isSensitiveName = (name: string, sensitive: ReadonlySet<string>): boolean =>
  sensitive.has(foldName(name));

/** High-precision secret shapes, identical to the Python defaults. */
export const DEFAULT_VALUE_PATTERNS: ReadonlyArray<string> = [
  "sk-live-[A-Za-z0-9_-]{8,}",
  "sk-test-[A-Za-z0-9_-]{8,}",
  "ghp_[A-Za-z0-9]{8,}",
  "gho_[A-Za-z0-9]{8,}",
  "xox[bap]-[A-Za-z0-9-]{8,}",
  "AKIA[0-9A-Z]{16}",
  "-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
  "eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
];

export const compileValuePatterns = (extra?: ReadonlyArray<string>): Array<RegExp> => {
  // Global flag: `scrubText` must replace EVERY occurrence (Python `re.sub`
  // semantics) — a first-match-only scrub leaks the second secret. The flag
  // makes `.test()` stateful, so every use resets `lastIndex` first.
  const sources = [...DEFAULT_VALUE_PATTERNS, ...(extra ?? [])];
  return sources.map((source) => {
    try {
      return new RegExp(source, "g");
    } catch (cause) {
      throw new RedactionError({ message: `invalid redact pattern ${JSON.stringify(source)}: ${cause}` });
    }
  });
};

export const valueMatchesPatterns = (text: string, patterns: ReadonlyArray<RegExp>): boolean =>
  patterns.some((pattern) => {
    pattern.lastIndex = 0;
    return pattern.test(text);
  });
