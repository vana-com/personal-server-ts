/**
 * PDPP Core §5 "Display text languages" and §6 "Display language".
 *
 * A localizable declaration display value is a plain string or a language
 * map: a JSON object keyed by BCP 47 language tag (RFC 5646), one version of
 * the same text per language (spec-core L836). This module holds the three
 * pieces the AS needs:
 *
 *   - `isWellFormedLanguageTag`: RFC 5646 §2.1 well-formedness, the
 *     "language-tag rule" the AS MUST enforce at declaration acceptance
 *     (spec-core L857, AS item 22).
 *   - `validateLanguageMap`: the structural rules of L857 — at least one
 *     entry, well-formed keys unique without regard to case, non-empty
 *     string values.
 *   - `chooseLanguageVersion`: the RFC 4647 §3.4 Lookup the AS MUST run over
 *     a map's keys (spec-core L1079-L1083, AS item 34), falling back to
 *     `display.default_language`.
 */

// RFC 5646 §2.1 ABNF, transcribed. Case-insensitive throughout.
const ALPHANUM = "[a-z0-9]";
const EXTLANG = "[a-z]{3}(?:-[a-z]{3}){0,2}";
const LANGUAGE = `(?:[a-z]{2,3}(?:-${EXTLANG})?|[a-z]{4}|[a-z]{5,8})`;
const SCRIPT = "[a-z]{4}";
const REGION = "(?:[a-z]{2}|[0-9]{3})";
const VARIANT = `(?:${ALPHANUM}{5,8}|[0-9]${ALPHANUM}{3})`;
const SINGLETON = "[0-9a-wy-z]";
const EXTENSION = `${SINGLETON}(?:-${ALPHANUM}{2,8})+`;
const PRIVATEUSE = `x(?:-${ALPHANUM}{1,8})+`;
const LANGTAG =
  `${LANGUAGE}(?:-${SCRIPT})?(?:-${REGION})?(?:-${VARIANT})*` +
  `(?:-${EXTENSION})*(?:-${PRIVATEUSE})?`;
const GRANDFATHERED = [
  "en-gb-oed",
  "i-ami",
  "i-bnn",
  "i-default",
  "i-enochian",
  "i-hak",
  "i-klingon",
  "i-lux",
  "i-mingo",
  "i-navajo",
  "i-pwn",
  "i-tao",
  "i-tay",
  "i-tsu",
  "sgn-be-fr",
  "sgn-be-nl",
  "sgn-ch-de",
  "art-lojban",
  "cel-gaulish",
  "no-bok",
  "no-nyn",
  "zh-guoyu",
  "zh-hakka",
  "zh-min",
  "zh-min-nan",
  "zh-xiang",
];
const LANGUAGE_TAG = new RegExp(`^(?:${LANGTAG}|${PRIVATEUSE})$`, "i");

/** RFC 5646 §2.1 well-formedness. Validity against the registry is not checked. */
export function isWellFormedLanguageTag(tag: unknown): tag is string {
  if (typeof tag !== "string" || tag.length === 0) return false;
  if (GRANDFATHERED.includes(tag.toLowerCase())) return true;
  if (!LANGUAGE_TAG.test(tag)) return false;
  // RFC 5646 §2.2.6 / §2.2.5: a singleton and a variant may not repeat.
  const subtags = tag.toLowerCase().split("-");
  const privateAt = subtags.indexOf("x");
  const head = privateAt === -1 ? subtags : subtags.slice(0, privateAt);
  const singletons = head.filter((s) => s.length === 1);
  if (new Set(singletons).size !== singletons.length) return false;
  return true;
}

/** A language map: one version of the same text per BCP 47 tag. */
export type LanguageMap = Record<string, string>;

/** A localizable display value as a declaration may author it. */
export type LocalizableValue = string | LanguageMap;

/**
 * The structural rules of spec-core L857 for one language map. Returns a
 * reason, or null when the map is well formed.
 */
export function validateLanguageMap(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    return "a language map must be a JSON object";
  const keys = Object.keys(value);
  if (keys.length === 0) return "a language map must have at least one entry";
  const seen = new Set<string>();
  for (const key of keys) {
    if (!isWellFormedLanguageTag(key))
      return `language map key '${key}' is not a well-formed BCP 47 language tag`;
    const folded = key.toLowerCase();
    if (seen.has(folded))
      return `language map key '${key}' repeats another key without regard to case`;
    seen.add(folded);
    const text = (value as Record<string, unknown>)[key];
    if (typeof text !== "string" || text.length === 0)
      return `language map value for '${key}' must be a non-empty string`;
  }
  return null;
}

/** Case-insensitive key lookup over a language map. */
function keyMatching(map: LanguageMap, tag: string): string | undefined {
  const folded = tag.toLowerCase();
  return Object.keys(map).find((key) => key.toLowerCase() === folded);
}

/**
 * Parse an OIDC `ui_locales` value (spec-core L1073): space-separated BCP 47
 * tags, most preferred first. Each tag the AS cannot parse is ignored, never
 * an error (spec-core L1073: "The AS ignores each tag it cannot parse").
 */
export function parseUiLocales(value: unknown): string[] {
  if (typeof value !== "string") return [];
  return value
    .split(" ")
    .filter((tag) => tag.length > 0 && isWellFormedLanguageTag(tag));
}

/**
 * RFC 4647 §3.4 Lookup of one priority list over a map's keys.
 *
 * "Lookup shortens each tag from the end until a key matches, so `es-MX`
 * matches an `es` key" (spec-core L1082). A single-character subtag left at the
 * end after a truncation is removed too (RFC 4647 §3.4 step).
 */
function lookup(map: LanguageMap, priority: string[]): string | undefined {
  for (const tag of priority) {
    let range = tag;
    for (;;) {
      const hit = keyMatching(map, range);
      if (hit !== undefined) return hit;
      const cut = range.lastIndexOf("-");
      if (cut === -1) break;
      range = range.slice(0, cut);
      // Drop a trailing singleton (e.g. "x" or "u") exposed by the cut.
      const nextCut = range.lastIndexOf("-");
      if (nextCut !== -1 && range.length - nextCut - 1 === 1)
        range = range.slice(0, nextCut);
    }
  }
  return undefined;
}

/** The version the AS renders, with the tag it chose, when the value had one. */
export interface ChosenVersion {
  value: string;
  /** Absent for a plain string whose declaration states no default language. */
  language?: string;
}

/**
 * Choose the one version of a localizable value the AS renders (spec-core
 * L1077-L1083, AS item 34).
 *
 * 1. Priority list = the owner's AS preference (none in this build), then the
 *    parseable `ui_locales` tags in request order.
 * 2. RFC 4647 Lookup over the map keys.
 * 3. No match, or an empty list: the key matching `display.default_language`
 *    without regard to case.
 *
 * A plain string is its own only version; its language is
 * `display.default_language` when present, otherwise unstated (L857: "the AS
 * MUST NOT assume one").
 */
export function chooseLanguageVersion(
  value: LocalizableValue,
  priority: string[],
  defaultLanguage: string | undefined,
): ChosenVersion | undefined {
  if (typeof value === "string") {
    return {
      value,
      ...(defaultLanguage !== undefined && { language: defaultLanguage }),
    };
  }
  const chosen =
    lookup(value, priority) ??
    (defaultLanguage !== undefined
      ? keyMatching(value, defaultLanguage)
      : undefined);
  if (chosen === undefined) return undefined;
  return { value: value[chosen]!, language: chosen };
}
