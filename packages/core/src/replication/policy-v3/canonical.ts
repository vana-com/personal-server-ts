/** Byte-for-byte serializer contract copied from immutable v1; parity is tested. */
/** Canonical JSON for the profile, preserving every own key at every depth. */
export function canonicalJson(value: unknown): string {
  return exactJson(value);
}

/** Canonical JSON serializer shared by wire encoding and replication digests. */
export function exactJson(value: unknown): string {
  if (Array.isArray(value)) {
    // `map` skips holes, which would encode `new Array(1)` as `[]`.
    for (let index = 0; index < value.length; index++)
      if (!Object.hasOwn(value, index))
        throw new TypeError(`not a JSON value: array hole at ${index}`);
    return `[${value.map(exactJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${exactJson(record[key])}`)
      .join(",")}}`;
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  )
    return JSON.stringify(value);
  throw new TypeError(`not a JSON value: ${typeof value}`);
}
