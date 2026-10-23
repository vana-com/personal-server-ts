/**
 * Stream and field names are data.
 *
 * The spec gives names no character grammar, so `constructor`, `__proto__`
 * and `hasOwnProperty` are valid names, and owner choices arrive as plain JSON
 * objects keyed by them. An index read on such an object also finds inherited
 * members, which turns "the owner made no choice for this stream" into a
 * built-in function. Only an own property is a choice.
 */

/** Read a value keyed by name. Absent, null or non-object maps hold no value. */
export function ownValue<T>(
  record: Readonly<Record<string, T>> | null | undefined,
  name: string,
): T | undefined {
  return typeof record === "object" &&
    record !== null &&
    Object.hasOwn(record, name)
    ? record[name]
    : undefined;
}

const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/**
 * Whether every key and string in a parsed JSON value is well-formed Unicode.
 *
 * A lone UTF-16 surrogate has no UTF-8 form, so a name holding one cannot
 * survive a URL, a UTF-8 store or most other JSON readers unchanged. PDPP
 * refuses it at every boundary that accepts names instead of repairing it.
 */
export function isWellFormedJson(value: unknown): boolean {
  if (typeof value === "string") return !LONE_SURROGATE.test(value);
  if (Array.isArray(value)) return value.every(isWellFormedJson);
  if (typeof value === "object" && value !== null) {
    return Object.entries(value).every(
      ([key, entry]) => !LONE_SURROGATE.test(key) && isWellFormedJson(entry),
    );
  }
  return true;
}
