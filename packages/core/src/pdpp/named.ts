/**
 * Read a value keyed by a stream or field name.
 *
 * Names are data. The spec gives them no character grammar, so `constructor`,
 * `__proto__` and `hasOwnProperty` are valid names, and owner choices arrive
 * as plain JSON objects keyed by them. An index read on such an object also
 * finds inherited members, which turns "the owner made no choice for this
 * stream" into a built-in function. Only an own property is a choice.
 */
export function ownValue<T>(
  record: Readonly<Record<string, T>> | undefined,
  name: string,
): T | undefined {
  return record !== undefined && Object.hasOwn(record, name)
    ? record[name]
    : undefined;
}
