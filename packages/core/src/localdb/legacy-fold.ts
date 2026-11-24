import { classifyImportKey } from "./import-snapshot.js";
import type { ImportSource } from "./legacy-import-types.js";
import { QuarantinedRow } from "./legacy-quarantine.js";

/**
 * Several stored versions of one stream as one `ImportSource`.
 *
 * Old stores keep a stream as many layers: the `{records}` files each
 * collection left, an older instance of the same source. A key can sit in
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
 *   A layer names its deletions by typed key (`deletions`) or, for stores
 *   that keep only the canonical record key of a deleted row, by
 *   `deletedRecordKeys`; the older row's own fields give the typed key then.
 * - A layer may carry `$pdpp.sourceId` on its rows. With `sourceId` set, a
 *   row must carry exactly that source (`untagged` and `source_mismatch`
 *   rows are counted out, never guessed into a stream). The envelope is not
 *   part of the record: it is dropped.
 * - A row with no full identity passes through for the import to count. A
 *   second row for a key within one layer is counted as `duplicate_key`; the
 *   first stands.
 *
 * Memory: the key hashes (and deleted record keys) of the layers read so far.
 * No body is kept; each traversal reads the layers again.
 */
export interface FoldLayer {
  records(): AsyncIterable<unknown>;
  /** Keys this layer deleted, each an object holding the typed key fields. */
  deletions?(): AsyncIterable<unknown>;
  /** Canonical record keys this layer deleted. */
  deletedRecordKeys?(): AsyncIterable<string>;
}

export interface FoldOptions {
  /** The source id every row must carry in `$pdpp.sourceId`. */
  readonly sourceId?: string;
}

type Event = { readonly row: unknown } | { readonly deletion: unknown };

const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

/** The row without its `$pdpp` envelope, or the marker that counts it out. */
function unwrapRow(record: unknown, sourceId: string | undefined): unknown {
  if (!isObject(record)) return record;
  const has = Object.hasOwn(record, "$pdpp");
  if (sourceId !== undefined) {
    const meta = has ? record["$pdpp"] : undefined;
    const claimed = isObject(meta) ? meta["sourceId"] : undefined;
    if (typeof claimed !== "string" || claimed === "")
      return new QuarantinedRow("untagged");
    if (claimed !== sourceId) return new QuarantinedRow("source_mismatch");
  }
  if (!has) return record;
  const data = { ...record };
  delete data["$pdpp"];
  return data;
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
    // Record keys a newer layer deleted that no row has named yet.
    const deletedByKey = new Set<string>();
    for (const layer of layers) {
      const own = new Set<string>();
      const deleted = new Set<string>();
      for await (const record of layer.records()) {
        const row = unwrapRow(record, options.sourceId);
        const key = await classifyImportKey(row, primaryKey);
        if ("quarantine" in key) {
          // No identity to decide with: the import counts it.
          yield { row };
          continue;
        }
        const id = key.key.pk_hash;
        const decided = taken.get(id);
        if (decided !== undefined) {
          yield {
            row: new QuarantinedRow(
              decided ? "superseded" : "deleted_in_newer_layer",
            ),
          };
          continue;
        }
        if (deletedByKey.has(key.key.record_key)) {
          // A newer layer deleted this key and holds no version of it: leave
          // the row out, and tombstone the key so another copy cannot return it.
          taken.set(id, false);
          deleted.add(id);
          yield { row: new QuarantinedRow("deleted_in_newer_layer") };
          yield { deletion: row };
          continue;
        }
        // One version per key per layer: the first stands, a repeat is counted.
        if (own.has(id)) {
          yield { row: new QuarantinedRow("duplicate_key") };
          continue;
        }
        own.add(id);
        yield { row };
      }
      if (layer.deletions)
        for await (const record of layer.deletions()) {
          const key = await classifyImportKey(record, primaryKey);
          if ("quarantine" in key) {
            yield { deletion: new QuarantinedRow(key.quarantine) };
            continue;
          }
          const id = key.key.pk_hash;
          // A layer that holds a key live, or a newer layer that decided it,
          // outranks this layer's deletion.
          if (own.has(id) || taken.has(id) || deleted.has(id)) continue;
          deleted.add(id);
          yield { deletion: record };
        }
      if (layer.deletedRecordKeys)
        for await (const recordKey of layer.deletedRecordKeys())
          deletedByKey.add(recordKey);
      for (const id of own) taken.set(id, true);
      for (const id of deleted) taken.set(id, false);
    }
  }
  return {
    ...base,
    async *records() {
      for await (const event of walk()) if ("row" in event) yield event.row;
    },
    ...(layers.some((layer) => layer.deletions || layer.deletedRecordKeys)
      ? {
          async *deletions() {
            for await (const event of walk())
              if ("deletion" in event) yield event.deletion;
          },
        }
      : {}),
  };
}
