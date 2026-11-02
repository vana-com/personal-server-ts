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
