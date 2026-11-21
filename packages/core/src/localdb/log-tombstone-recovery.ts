// What a late seed needs to know about deletions this device made before it
// wrote its own tombstones.
//
// The build before `late-seed` wrote a tombstone only for a deletion or
// omission it applied from the log. A deletion it published itself left a
// pending change, which compaction pruned once the segment was acknowledged, so
// an upgraded database can hold a removed record with no trace of the removal.
// `fillOnly` (legacy-import.ts) cannot tell such a key from one the stream
// never held, and would bring the record back.
//
// The log still has every deletion: a segment lists its own, and a snapshot
// keeps every tombstone (log-compact.ts). So before a seed fills a connection,
// this writes the tombstone of every deletion and omission in the log this
// device holds (its snapshot and the tail after it). A tombstone merges by
// (stamp, rank), so it is safe to write again and to write for a key that a
// later real write has since restored: the real row is held, and the seed
// leaves a held key alone.

import {
  deriveKeyCheck,
  logScope,
  type LogOmitted,
  type LogOperation,
  type LogStreamMeta,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { LocalSyncDeps } from "./deps.js";
import { fetchSegment, fetchSnapshotPart } from "./log-apply.js";
import { prepareOperations, tombstoneStatements } from "./log-batch.js";
import { readLogState } from "./log-state.js";

/**
 * The connections of an open database whose log deletions were written this
 * process. A deletion after this point leaves its tombstone through the code
 * that makes it (publish, or apply), so once per connection is enough.
 */
const recovered = new WeakMap<object, Set<string>>();

export async function recoverLogTombstones(
  deps: LocalSyncDeps,
  connectionId: string,
): Promise<void> {
  const done = recovered.get(deps.db) ?? new Set<string>();
  recovered.set(deps.db, done);
  if (done.has(connectionId)) return;
  const log = await readLogState(deps, connectionId);
  const [connection] = await deps.db.query<{ connector: string; ns: string }>(
    "SELECT connector, ns FROM connections WHERE connection_id = ?",
    [connectionId],
  );
  if (connection && (log.snapshot !== null || log.refs.length > 0)) {
    const scope = logScope(connection.connector, connection.ns);
    const context = {
      connector: connection.connector,
      ns: connection.ns,
      keyCheck: await deriveKeyCheck((m) => deps.keys.namespaceHmac(m)),
    };
    // Both fetches drop the upserts, so what is left is deletions.
    const write = async (
      streams: readonly LogStreamMeta[],
      deletions: readonly (LogOperation | LogOmitted)[],
    ) => {
      const statements = tombstoneStatements(
        connectionId,
        await prepareOperations(streams, deletions),
      );
      if (statements.length > 0) await deps.db.batch(statements);
    };
    for (const { dataHash } of log.snapshot?.parts ?? []) {
      const part = await fetchSnapshotPart(
        deps,
        scope,
        context,
        dataHash,
        log.snapshot!.position,
        true,
      );
      await write(part.streams, part.entries as (LogOperation | LogOmitted)[]);
    }
    for (const { dataHash, position } of log.refs) {
      const { segment } = await fetchSegment(
        deps,
        scope,
        context,
        dataHash,
        position,
        true,
      );
      await write(segment.streams, segment.operations);
    }
  }
  done.add(connectionId);
}
