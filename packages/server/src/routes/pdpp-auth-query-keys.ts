/** Bracket-key axes used by the PDPP consent query. */
export type NamedQueryAxis =
  "approve" | "decline" | "field" | "instance" | "since" | "until";

/** Read `axis[name]` using the final bracket as the delimiter. */
export function readNamedQueryKey(
  key: string,
  axis: NamedQueryAxis,
): string | null {
  const open = `${axis}[`;
  return key.length > open.length + 1 &&
    key.startsWith(open) &&
    key.endsWith("]")
    ? key.slice(open.length, -1)
    : null;
}

/** Collect repeated values without using protocol names as object keys. */
export function readNamedQueryValues(
  params: URLSearchParams,
  axis: NamedQueryAxis,
): Map<string, string[]> {
  const values = new Map<string, string[]>();
  for (const [key, value] of params.entries()) {
    const name = readNamedQueryKey(key, axis);
    if (name === null) continue;
    const existing = values.get(name);
    if (existing) existing.push(value);
    else values.set(name, [value]);
  }
  return values;
}

const AXES: readonly NamedQueryAxis[] = [
  "approve",
  "decline",
  "field",
  "instance",
  "since",
  "until",
];

/**
 * Whether a named-axis parameter of a raw query string is not well-formed
 * UTF-8 once percent-decoded.
 *
 * A lone surrogate cannot be written in UTF-8, so on the wire it can only be an
 * invalid percent-encoded sequence. `URLSearchParams` silently turns that into
 * U+FFFD, so the name the owner chose and the name the server reads would
 * differ. A U+FFFD that was sent validly encoded (`%EF%BF%BD`) is an ordinary
 * name and is not flagged. Parameters outside the named axes are not examined.
 */
export function hasMalformedNamedQuery(search: string): boolean {
  const query = search.startsWith("?") ? search.slice(1) : search;
  if (query === "") return false;
  for (const pair of query.split("&")) {
    const [rawKey, ...rest] = pair.split("=");
    const lenientKey = new URLSearchParams(pair).keys().next().value ?? "";
    if (!AXES.some((axis) => readNamedQueryKey(lenientKey, axis) !== null))
      continue;
    if (!decodesStrictly(rawKey) || !decodesStrictly(rest.join("="))) {
      return true;
    }
  }
  return false;
}

function decodesStrictly(raw: string): boolean {
  try {
    decodeURIComponent(raw.replaceAll("+", " "));
    return true;
  } catch {
    return false;
  }
}

const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Whether every key and string in a parsed JSON value is well-formed Unicode. */
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
