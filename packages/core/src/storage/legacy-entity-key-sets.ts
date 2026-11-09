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

const TOP_LEVEL_PATH = /^\$\.([A-Za-z0-9_]+)$/;

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
 * object, a collection is not an array, an item lacks a key field, or two
 * items share a key. `null` means "unknown", and a caller that deletes must
 * treat unknown as not held.
 */
export function entityHashes(
  scope: string,
  body: unknown,
): EntityHashes | null {
  const paths = LEGACY_SCOPE_ENTITY_KEYS[scope];
  if (!paths || body === null || typeof body !== "object") return null;
  if (Array.isArray(body)) return null;
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
  return sets.size > 0 ? sets : null;
}
