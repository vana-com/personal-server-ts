import type { Head } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  deleteEndedEarlierLifetime,
  deleteMetadataHash,
  endedGenerationDeleteMetadataHash,
} from "../stream-sync/delete-metadata.js";
import type { LocalSyncDeps } from "./deps.js";

/**
 * A stream head the registry holds from an earlier connection lifetime.
 *
 * Deleting a connection posts an empty head for each stream, always at
 * generation 1. A reconnect raises the connection to a later generation
 * (3, 5, ...), so that head is older than the connection but is still the
 * stream's registry row. The publisher must write over it, not wait on it.
 *
 * Three values stay apart:
 * - the registry version and data hash: the compare-and-set basis of the next
 *   post (the caller keeps them);
 * - the delete fence this function derives: the highest stream delete the
 *   old lifetime recorded, which the new head must carry;
 * - the content base: none. No rows, parts, schema, profile or floor of the
 *   old head enter the new lifetime.
 */
export function olderLifetimeFence(
  scope: string,
  row: { readonly version: number; readonly metadataHash: string },
  head: Pick<Head, "lastDeleteVersion">,
  generation: number,
): number {
  // The delete writer marks its row twice: in the head and in the metadata
  // hash. Either one is evidence of a delete at this version; take both.
  const hash = row.metadataHash.toLowerCase();
  const marked =
    hash === deleteMetadataHash(scope, row.version) ||
    hash ===
      endedGenerationDeleteMetadataHash(scope, row.version, generation) ||
    deleteEndedEarlierLifetime(scope, row, generation);
  return Math.max(head.lastDeleteVersion ?? 0, marked ? row.version : 0);
}

/**
 * Whether the stream row is the delete of a lifetime EARLIER than the
 * connection's. Only a delete that recorded the generation it ended proves it.
 * Without that proof the delete may belong to the active lifetime (its stream
 * delete landed, its control tombstone has not), and nothing may write over it.
 */
export function endsEarlierLifetime(
  scope: string,
  row: { readonly version: number; readonly metadataHash: string },
  generation: number,
): boolean {
  return deleteEndedEarlierLifetime(scope, row, generation);
}

/**
 * Record the delete fence locally. Idempotent and monotonic.
 *
 * With `provenEarlier`, a run that began in this generation, under a control
 * row of this generation, began after the deletion that ended the old
 * lifetime, so its snapshot is raised to the fence. Without proof no run
 * snapshot moves: the fence then discards every run collected before it.
 */
export async function hydrateLifetimeBoundary(
  deps: LocalSyncDeps,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly generation: number;
    readonly fence: number;
    readonly provenEarlier: boolean;
    readonly primaryKey: readonly string[];
  },
): Promise<void> {
  const { connectionId, stream, generation, fence } = input;
  if (fence <= 0) return;
  const raise = input.provenEarlier
    ? [
        {
          sql: `UPDATE run_streams SET delete_snapshot = ?
             WHERE stream = ? AND delete_snapshot < ?
               AND run_id IN (SELECT run_id FROM runs
                               WHERE connection_id = ? AND generation = ?
                                 AND begin_control_version = ?)`,
          params: [fence, stream, fence, connectionId, generation, generation],
        },
      ]
    : [];
  await deps.db.batch([
    {
      sql: `INSERT OR IGNORE INTO stream_state (connection_id,stream,primary_key,semantics,incremental) VALUES (?,?,?,'mutable_state',1)`,
      params: [connectionId, stream, JSON.stringify(input.primaryKey)],
    },
    {
      sql: `UPDATE stream_state SET last_delete_version = MAX(last_delete_version, ?)
             WHERE connection_id = ? AND stream = ?`,
      params: [fence, connectionId, stream],
    },
    ...raise,
  ]);
}
