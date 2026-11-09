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

/**
 * Values the READER makes, not data from the source. They differ between the
 * legacy file (stamped when the old connector ran) and the published view
 * (stamped when the view is read) whatever the source holds, so comparing
 * them would fail every readback of the scope under the real clock. Every
 * other uncovered scalar is compared and fails closed. Each entry names its
 * producer; add one only when its producer is a stamp or a count the
 * projection computes, never for a field the source supplies.
 */

/**
 * Top-level scalars the projection stamps with the time of the read
 * (`projectionTime` in `legacy-projection/bindings.ts`: the github.events,
 * github.history and github.contributions payloads). Left out of the
 * comparison entirely.
 */
export const READER_STAMPED_SCALARS: ReadonlySet<string> = new Set([
  "fetchedAt",
]);

/**
 * Per-scope fields of a top-level collection's items that the projection
 * stamps with the time of the read (`fetched_at` in the chatgpt.conversations
 * binding, `projectionTime`). Dropped from an item before it is hashed.
 */
export const READER_STAMPED_ITEM_FIELDS: Readonly<
  Record<string, readonly string[]>
> = {
  "chatgpt.conversations": ["fetched_at"],
};

/**
 * Top-level counts the projection computes from a collection of the same
 * body (`total: items.length`, `totalOrders: orders.length` in
 * `legacy-projection/bindings.ts`), mapped to the collection they count
 * (null: any covered collection). A body holds such a count as the marker
 * `DERIVED_COUNT` when it equals the length of its own collection, so two
 * snapshots of a growing collection still agree, and holds the value when it
 * does not, so a count that is not derived is compared like any scalar. The
 * marker is decided per body: a derived local count matches only a derived
 * published count.
 */
export const DERIVED_COUNT_SCALARS: Readonly<Record<string, string | null>> = {
  total: null,
  totalOrders: "orders",
};
const DERIVED_COUNT = "$derived-count";
const TOP_LEVEL_PATH = /^\$\.([A-Za-z0-9_]+)$/;
/** The top-level key a table path starts at (`$.a` and `$.a[].b` both: `a`). */
const PATH_ROOT = /^\$\.([A-Za-z0-9_]+)/;

function withoutFields(item: object, drop: ReadonlySet<string>): object {
  return Object.fromEntries(
    Object.entries(item).filter(([field]) => !drop.has(field)),
  );
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 hex of the canonical JSON of `value`. */
export function contentHash(value: unknown): string {
  return hex(sha256(new TextEncoder().encode(canonicalJson(value))));
}

/**
 * Whether the envelope data a storage holds is the data the fence was decided
 * for. A fence with no `contentHash` asks for no content check.
 */
export function fenceContentMatches(
  fence: { readonly contentHash?: string | undefined } | undefined,
  data: unknown,
): boolean {
  return (
    fence?.contentHash === undefined || contentHash(data) === fence.contentHash
  );
}

/**
 * The entity hashes of `body` for `scope`, or `null` when membership cannot
 * be proven: the scope has no reviewed top-level key, the body is not an
 * object, a collection is not an array, an item lacks a key field, two
 * items share a key, or the body holds a top-level array or object that no
 * table path covers (data the comparison would never see). A top-level
 * scalar or null that no table path covers (`totalContributionsLastYear`,
 * `userName`) is NOT ignored: it is compared as one
 * pseudo-entity under `SCALAR_PREFIX`, so a value the stream data does not
 * hold equal fails the readback. The exceptions are values the reader makes
 * (`READER_STAMPED_SCALARS`, `READER_STAMPED_ITEM_FIELDS`) and a count that
 * equals the length of its own collection (`DERIVED_COUNT_SCALARS`), which
 * is held as a marker, so a count the other body does not derive the same
 * way still fails. `null` means "unknown", and a
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
  const derivedCount = (key: string, value: unknown): boolean => {
    if (!Object.hasOwn(DERIVED_COUNT_SCALARS, key)) return false;
    const counted = DERIVED_COUNT_SCALARS[key];
    return [...covered].some((c) => {
      const items = record[c];
      return (
        (counted === null || counted === c) &&
        Array.isArray(items) &&
        items.length === value
      );
    });
  };
  for (const [key, value] of Object.entries(body)) {
    if (covered.has(key) || value === undefined) continue;
    if (value !== null && typeof value === "object") return null;
    if (READER_STAMPED_SCALARS.has(key)) continue;
    scalars.set(
      `${SCALAR_PREFIX}${key}`,
      new Map([
        ["[]", contentHash(derivedCount(key, value) ? DERIVED_COUNT : value)],
      ]),
    );
  }
  const stamped = new Set(READER_STAMPED_ITEM_FIELDS[scope] ?? []);
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
        entities.set(
          key,
          contentHash(stamped.size === 0 ? item : withoutFields(item, stamped)),
        );
      }
    }
    sets.set(path, entities);
  }
  if (sets.size === 0) return null;
  for (const [path, entities] of scalars) sets.set(path, entities);
  return sets;
}
