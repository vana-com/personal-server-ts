import { canonicalJson } from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { LEGACY_SCOPE_ENTITY_KEYS } from "./legacy-scope-entity-keys.js";

/**
 * The entities of a legacy scope body, per top-level collection path
 * (`$.events`): entity key (JSON of the reviewed key fields) to the SHA-256 of
 * the entity's canonical JSON. The key table is the one the canonical
 * takeover check uses (`LEGACY_SCOPE_ENTITY_KEYS`); no table is added here.
 */
export type EntityHashes = ReadonlyMap<string, ReadonlyMap<string, string>>;

/** Pseudo-path of an uncovered top-level scalar: `$scalar.<key>`. */
export const SCALAR_PREFIX = "$scalar.";
const TOP_LEVEL_PATH = /^\$\.([A-Za-z0-9_]+)$/;
/** The top-level key a table path starts at (`$.a` and `$.a[].b` both: `a`). */
const PATH_ROOT = /^\$\.([A-Za-z0-9_]+)/;

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 hex of the canonical JSON of `value`. */
export function contentHash(value: unknown): string {
  return hex(sha256(new TextEncoder().encode(canonicalJson(value))));
}

/**
 * The entity hashes of `body` for `scope`, or `null` when membership cannot
 * be proven: the scope has no reviewed top-level key, the body is not an
 * object, a collection is not an array, an item lacks a key field, two
 * items share a key, or the body holds a top-level array or object that no
 * table path covers (data the comparison would never see). A top-level
 * scalar or null that no table path covers (`totalContributionsLastYear`,
 * `fetchedAt`, `userName`) is NOT ignored: it is compared as one
 * pseudo-entity under `SCALAR_PREFIX`, so a value the stream data does not
 * hold equal fails the readback. The one exception is `total` when it equals
 * the length of a keyed collection of the same body: a count derived from
 * entities that are compared holds nothing else, and it differs between two
 * snapshots whenever the collection grew. `null` means "unknown", and a
 * caller that deletes must treat unknown as not held.
 */
export function entityHashes(
  scope: string,
  body: unknown,
): EntityHashes | null {
  const paths = LEGACY_SCOPE_ENTITY_KEYS[scope];
  if (!paths || body === null || typeof body !== "object") return null;
  if (Array.isArray(body)) return null;
  const covered = new Set(
    Object.keys(paths).flatMap((path) => {
      const root = PATH_ROOT.exec(path);
      return root ? [root[1]!] : [];
    }),
  );
  const scalars = new Map<string, Map<string, string>>();
  const record = body as Record<string, unknown>;
  const derivedCount = (key: string, value: unknown): boolean =>
    key === "total" &&
    [...covered].some((c) => {
      const items = record[c];
      return Array.isArray(items) && items.length === value;
    });
  for (const [key, value] of Object.entries(body)) {
    if (covered.has(key) || value === undefined) continue;
    if (value !== null && typeof value === "object") return null;
    if (derivedCount(key, value)) continue;
    scalars.set(
      `${SCALAR_PREFIX}${key}`,
      new Map([["[]", contentHash(value)]]),
    );
  }
  const sets = new Map<string, Map<string, string>>();
  for (const [path, fields] of Object.entries(paths)) {
    const match = TOP_LEVEL_PATH.exec(path);
    if (!match) continue; // nested collections are covered by their parent's hash
    const collection = (body as Record<string, unknown>)[match[1]!];
    const entities = new Map<string, string>();
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
        const key = JSON.stringify(values);
        if (entities.has(key)) return null;
        entities.set(key, contentHash(item));
      }
    }
    sets.set(path, entities);
  }
  if (sets.size === 0) return null;
  for (const [path, entities] of scalars) sets.set(path, entities);
  return sets;
}
