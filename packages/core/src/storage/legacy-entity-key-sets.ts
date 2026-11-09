import { LEGACY_SCOPE_ENTITY_KEYS } from "./legacy-scope-entity-keys.js";

/**
 * The entity keys of a legacy scope body, per top-level collection path
 * (`$.events`). The same reviewed table the canonical takeover check uses
 * (`LEGACY_SCOPE_ENTITY_KEYS`), so a local file and the stream view's
 * projection of the same scope reduce to comparable key sets.
 */
export type EntityKeySets = ReadonlyMap<string, ReadonlySet<string>>;

const TOP_LEVEL_PATH = /^\$\.([A-Za-z0-9_]+)$/;

/**
 * The key sets of `body` for `scope`, or `null` when membership cannot be
 * proven: the scope has no reviewed top-level key, the body is not an object,
 * a collection is not an array, or an item lacks a key field. `null` means
 * "unknown", and a caller that deletes must treat unknown as not held.
 */
export function entityKeySets(
  scope: string,
  body: unknown,
): EntityKeySets | null {
  const paths = LEGACY_SCOPE_ENTITY_KEYS[scope];
  if (!paths || body === null || typeof body !== "object") return null;
  if (Array.isArray(body)) return null;
  const sets = new Map<string, Set<string>>();
  for (const [path, fields] of Object.entries(paths)) {
    const match = TOP_LEVEL_PATH.exec(path);
    if (!match) continue; // nested collections are not compared
    const collection = (body as Record<string, unknown>)[match[1]!];
    const keys = new Set<string>();
    if (collection !== undefined && collection !== null) {
      if (!Array.isArray(collection)) return null;
      for (const item of collection) {
        if (item === null || typeof item !== "object") return null;
        const values = fields.map((f) => (item as Record<string, unknown>)[f]);
        if (
          values.some(
            (v) =>
              v === undefined ||
              v === null ||
              (typeof v !== "string" && typeof v !== "number") ||
              v === "",
          )
        ) {
          return null;
        }
        keys.add(JSON.stringify(values));
      }
    }
    sets.set(path, keys);
  }
  return sets.size > 0 ? sets : null;
}

/** Whether every key of `local` is in the same path's set of `view`. */
export function keysHeld(local: EntityKeySets, view: EntityKeySets): boolean {
  for (const [path, keys] of local) {
    const held = view.get(path);
    if (!held) return keys.size === 0;
    for (const key of keys) if (!held.has(key)) return false;
  }
  return true;
}
