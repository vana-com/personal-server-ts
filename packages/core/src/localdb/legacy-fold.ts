import { classifyImportKey, classifyImportRow } from "./import-snapshot.js";
import type { ImportSource } from "./legacy-import-types.js";
import {
  DELETE_ENVELOPE,
  QuarantinedRow,
  isQuarantinedRow,
} from "./legacy-quarantine.js";

/**
 * Several stored versions of one stream as one `ImportSource`.
 *
 * Old stores keep a stream as many layers: the `{records}` files each
 * collection left. A key can sit in
 * many layers. The import takes the newest layer's version of each key, so the
 * result follows layer rank, not the order anything is read or submitted in.
 *
 * - Layers are given newest first. The first layer to name a key decides it.
 *   An older version is left out and counted as `superseded`: not a loss, a
 *   newer version of the key stands.
 * - A layer that deleted a key decides it for every older layer: their rows
 *   for it are left out (`deleted_in_newer_layer`), and the fold reports the
 *   deletion (once) so the import can tombstone it. A newer layer that holds
 *   the key live restores it: that layer decided first.
 *   A layer names its deletions by typed key (`deletions`).
 * - A layer may carry `$pdpp.sourceId` on its rows. With `sourceId` set, a
 *   row must carry exactly that source (`untagged` and `source_mismatch`
 *   rows are counted out, never guessed into a stream). The envelope is not
 *   part of the record: it is dropped.
 * - A v1-full envelope names its operation in `$pdpp.record.op` and the key
 *   in `$pdpp.record.key` (the shape `sync/pdpp-import.ts` reads). `delete`
 *   makes the row a deletion of that layer, handled like `deletions()`, and
 *   applies only when the envelope is complete (version 1, source, declaration,
 *   stream name, scope and primary key, a record key object), names this
 *   stream and its primary key, and claims a full key that agrees with the
 *   payload's key fields when the payload has them. Otherwise it is counted
 *   out (`deletion_envelope_incomplete`, `deletion_stream_mismatch`,
 *   `deletion_<key fault>`) and deletes nothing. `upsert` or no op is a row,
 *   unless its envelope names another stream (`stream_mismatch`). Any other
 *   op is counted out as `unknown_op`.
 * - A row whose body has no JSON form (a cycle, a BigInt) is counted out
 *   before it claims its key, so an older readable copy still stands.
 * - A row with no full identity passes through for the import to count. A
 *   second row for a key within one layer is counted as `duplicate_key` when
 *   its body is the same. With another body it is a conflict: the fold throws
 *   `invalid_record`, and the import refuses the stream, as it does for a
 *   direct source (`stageImportSnapshot`).
 *
 * Identity is the legacy record key (`computeRecordKeyFromData`), the key the
 * database keeps a row under, never the typed key hash: `{id: 42}` and
 * `{id: "42"}` are one key, and the newest layer's row stands.
 *
 * Every stored record of `records()` is yielded once in the row pass, as a
 * row or as a marker with its reason: a row left out by its reason, a valid
 * delete envelope as `delete_envelope` (also when a live row shadows it), a
 * malformed one as `deletion_<reason>`. So a host that reads only `records()`
 * loses no count, and stored records = rows + markers. Keys a layer lists
 * apart from its records (`deletions`) are not stored records; only a
 * malformed `deletions()` key is counted.
 *
 * Memory: the record keys of the layers read so far,
 * a body digest per key of the layer being read, and the key fields of
 * the layer's delete envelopes. No body or payload is kept; each traversal
 * reads the layers again.
 */
export interface FoldLayer {
  records(): AsyncIterable<unknown>;
  /** Keys this layer deleted, each an object holding the typed key fields. */
  deletions?(): AsyncIterable<unknown>;
}

export interface FoldOptions {
  /** The source id every row must carry in `$pdpp.sourceId`. */
  readonly sourceId?: string;
}

type Event =
  { readonly row: unknown } | { readonly deletion: Record<string, unknown> };

const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

/** One stored record, decoded: a row, or the deletion its envelope declares. */
type Decoded =
  | { readonly row: unknown }
  | { readonly deletion: unknown; readonly claim: unknown };

/** An own property of an envelope object: an envelope field never comes from a
 * prototype. */
const field = (object: Record<string, unknown>, name: string): unknown =>
  Object.hasOwn(object, name) ? object[name] : undefined;

const text = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

/** Why a delete envelope cannot be applied to `target`, or null. A delete is
 * destructive, so it must be complete: every field `sync/pdpp-import.ts`
 * requires of a v1-full envelope (the declaration digest cannot be checked
 * here: the fold holds no declaration). It must belong to this stream, and
 * declare the stream's own primary key. Its key is checked apart, by
 * `deletedKey`. */
function deleteFault(
  meta: Record<string, unknown>,
  target: { readonly stream: string; readonly primaryKey: readonly string[] },
): "envelope_incomplete" | "stream_mismatch" | null {
  const declaration = field(meta, "declaration");
  const stream = field(meta, "stream");
  const record = field(meta, "record");
  if (
    field(meta, "version") !== 1 ||
    !text(field(meta, "sourceId")) ||
    !isObject(declaration) ||
    !text(field(declaration, "digest")) ||
    typeof field(declaration, "version") !== "string" ||
    !isObject(stream) ||
    !text(field(stream, "name")) ||
    !text(field(stream, "scope")) ||
    !isObject(record) ||
    !isObject(field(record, "key"))
  )
    return "envelope_incomplete";
  const primaryKey = field(stream, "primaryKey");
  if (
    !Array.isArray(primaryKey) ||
    primaryKey.length === 0 ||
    !primaryKey.every((name) => typeof name === "string")
  )
    return "envelope_incomplete";
  if (
    field(stream, "name") !== target.stream ||
    primaryKey.length !== target.primaryKey.length ||
    !primaryKey.every((name, index) => name === target.primaryKey[index])
  )
    return "stream_mismatch";
  return null;
}

/** The row without its `$pdpp` envelope, the marker that counts it out, or the
 * deletion the envelope declares (`claim` is its `record.key`). */
function decode(
  record: unknown,
  sourceId: string | undefined,
  target: { readonly stream: string; readonly primaryKey: readonly string[] },
): Decoded {
  if (!isObject(record)) return { row: record };
  const has = Object.hasOwn(record, "$pdpp");
  const meta = has ? record["$pdpp"] : undefined;
  if (sourceId !== undefined) {
    const claimed = isObject(meta) ? field(meta, "sourceId") : undefined;
    if (typeof claimed !== "string" || claimed === "")
      return { row: new QuarantinedRow("untagged") };
    if (claimed !== sourceId)
      return { row: new QuarantinedRow("source_mismatch") };
  }
  if (!has) return { row: record };
  const data = { ...record };
  delete data["$pdpp"];
  const op = isObject(meta) ? field(meta, "record") : undefined;
  const name = isObject(op) ? field(op, "op") : undefined;
  if (name === "delete") {
    const fault = deleteFault(meta as Record<string, unknown>, target);
    if (fault) return { row: new QuarantinedRow(`deletion_${fault}`) };
    return {
      deletion: data,
      claim: field(op as Record<string, unknown>, "key"),
    };
  }
  if (isObject(op) && name !== undefined && name !== "upsert")
    return { row: new QuarantinedRow("unknown_op") };
  // A row an envelope assigns to another stream is not a row of this one.
  const stream = isObject(meta) ? field(meta, "stream") : undefined;
  if (isObject(stream) && field(stream, "name") !== target.stream)
    return { row: new QuarantinedRow("stream_mismatch") };
  return { row: data };
}

const isKeyValue = (value: unknown): boolean =>
  typeof value === "string" ||
  typeof value === "boolean" ||
  (typeof value === "number" && Number.isFinite(value));

/** Only the primary-key fields of `source`, taken from the first of `sources`
 * that holds each: all a tombstone needs, and all the fold keeps. The field
 * names come from the stored record, so the object is built with own
 * properties (`Object.fromEntries`): assigning `key["__proto__"]` would set a
 * prototype instead and drop the field, and the key would have no identity. */
function keyFields(
  primaryKey: readonly string[],
  ...sources: readonly Record<string, unknown>[]
): Record<string, unknown> {
  return Object.fromEntries(
    primaryKey.map((field) => [
      field,
      sources.find((s) => Object.hasOwn(s, field))?.[field],
    ]),
  );
}

/** The key a v1-full delete names, or why it names none. The claim must be a
 * full key. Every key field the payload holds must agree with the claim (by
 * the record key's own rule, so `1` and `"1"` agree); a field it holds that
 * disagrees makes the claim a forgery, however few fields the payload has.
 * The payload's typed values stand in for the claim's where it holds them. */
async function deletedKey(
  payload: unknown,
  claim: unknown,
  primaryKey: readonly string[],
): Promise<
  | { readonly id: string; readonly key: Record<string, unknown> }
  | QuarantinedRow
> {
  const claimed = await classifyImportKey(claim, primaryKey);
  if ("quarantine" in claimed) return new QuarantinedRow(claimed.quarantine);
  const held = isObject(payload) ? payload : {};
  const claimedFields = claim as Record<string, unknown>;
  for (const field of primaryKey) {
    if (!Object.hasOwn(held, field)) continue;
    if (
      !isKeyValue(held[field]) ||
      String(held[field]) !== String(claimedFields[field])
    )
      return new QuarantinedRow("record_key_mismatch");
  }
  return {
    id: claimed.key.record_key,
    key: keyFields(primaryKey, held, claimedFields),
  };
}

export function foldLayers(
  base: Omit<ImportSource, "records" | "deletions">,
  layers: readonly FoldLayer[],
  options: FoldOptions = {},
): ImportSource {
  const { primaryKey } = base.target;
  async function* walk(): AsyncIterable<Event> {
    // Keys a newer layer decided: live (`true`) or deleted (`false`).
    const taken = new Map<string, boolean>();
    for (const layer of layers) {
      // Every record key this layer holds, with the digest of its body: a
      // repeat is checked against the first, whatever became of the first.
      const seen = new Map<string, string>();
      // The record keys this layer holds live.
      const own = new Set<string>();
      const deleted = new Set<string>();
      // Deletions the layer's own envelopes declare, by record key. They are
      // applied after its rows, so a live row of the layer outranks them.
      const declared = new Map<string, Record<string, unknown>>();
      for await (const record of layer.records()) {
        const decoded = decode(record, options.sourceId, base.target);
        if ("deletion" in decoded) {
          const named = await deletedKey(
            decoded.deletion,
            decoded.claim,
            primaryKey,
          );
          // A malformed deletion is counted in the row pass, by its own reason,
          // so every consumer of `records()` sees it once.
          if (isQuarantinedRow(named))
            yield { row: new QuarantinedRow(`deletion_${named.reason}`) };
          else {
            // A valid delete envelope is a stored record that becomes no row:
            // it is counted here, whatever happens to its key below (a live
            // row of its layer, or a newer layer, may outrank it).
            yield { row: new QuarantinedRow(DELETE_ENVELOPE) };
            if (!declared.has(named.id)) declared.set(named.id, named.key);
          }
          continue;
        }
        const row = decoded.row;
        // The body is read before the key is claimed: a row that cannot become
        // a record must not hide an older copy that can.
        const classified = await classifyImportRow(row, primaryKey);
        if ("quarantine" in classified) {
          yield { row: new QuarantinedRow(classified.quarantine) };
          continue;
        }
        // The legacy record key is the identity the database keeps a row
        // under: `{id: 42}` and `{id: "42"}` are one key, not two.
        const id = classified.row.record_key;
        // Within one layer a repeat of a key is the same row again (counted),
        // or a conflict, and the stream is refused exactly as the direct
        // importer refuses it (`stageImportSnapshot`). Two typed forms of one
        // record key cannot share a body, so the body digest alone tells them.
        const digest = classified.row.body_sha256;
        const first = seen.get(id);
        if (first !== undefined) {
          if (first !== digest) throw new Error("invalid_record");
          yield { row: new QuarantinedRow("duplicate_key") };
          continue;
        }
        seen.set(id, digest);
        const decided = taken.get(id);
        if (decided !== undefined) {
          yield {
            row: new QuarantinedRow(
              decided ? "superseded" : "deleted_in_newer_layer",
            ),
          };
          continue;
        }
        own.add(id);
        yield { row };
      }
      // A layer that holds a key live, or a newer layer that decided it,
      // outranks this layer's deletion.
      for (const [id, key] of declared) {
        if (own.has(id) || taken.has(id) || deleted.has(id)) continue;
        deleted.add(id);
        yield { deletion: key };
      }
      if (layer.deletions)
        for await (const record of layer.deletions()) {
          const key = await classifyImportKey(record, primaryKey);
          if ("quarantine" in key) {
            yield { row: new QuarantinedRow(`deletion_${key.quarantine}`) };
            continue;
          }
          const id = key.key.record_key;
          if (own.has(id) || taken.has(id) || deleted.has(id)) continue;
          deleted.add(id);
          yield {
            deletion: keyFields(primaryKey, record as Record<string, unknown>),
          };
        }
      for (const id of own) taken.set(id, true);
      for (const id of deleted) taken.set(id, false);
    }
  }
  return {
    ...base,
    async *records() {
      for await (const event of walk()) if ("row" in event) yield event.row;
    },
    // An envelope in any layer may declare a deletion, so every fold has the pass.
    async *deletions() {
      for await (const event of walk())
        if ("deletion" in event) yield event.deletion;
    },
  };
}
