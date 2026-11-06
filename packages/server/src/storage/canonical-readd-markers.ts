import type { Database } from "better-sqlite3";
import { legacyScopesBackedBy } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import {
  knownTombstoneVersion,
  type ScopeDeletionTracker,
} from "@opendatalabs/personal-server-ts-core/sync";

/**
 * Canonical re-add markers: the canonical counterpart of a file's
 * `afterTombstoneVersion`.
 *
 * A gateway tombstone of a legacy scope covers the canonical rows that serve
 * it (`resolveReadDeletion`). Rows can only show that they were re-added after
 * that deletion, rather than survived it, when a proven full replacement of
 * the stream (a completion receipt: a P7 replace with `source_collected_at`,
 * or a native completion) committed after this server knew the tombstone.
 * Every live row of the stream then comes from that collection or a later
 * write. A marker records exactly that, causally and without clocks:
 *
 *   (scope, instance, generation, stream) ->
 *     tombstone_version  the tombstone the scope stood under when the write
 *                        committed (the tracker's current tombstone, never
 *                        the durable history alone; see
 *                        `knownTombstoneVersion`);
 *     write_seq          the receipt's store write sequence;
 *     arrival_revision   the record arrival clock when the marker was set.
 *
 * A scope's canonical body is live again only when every stream backing it
 * holds a marker for the selected connection generation and every known
 * tombstone is at or below the lowest acknowledged version. A later
 * tombstone, an unversioned one, a missing stream, a partial upsert without a
 * receipt, or a receipt written before the tombstone was known all leave the
 * body refused (410). Later writes do not remove a marker: they come after
 * the replacement that proved the re-add.
 */
export interface CanonicalReaddMarkers {
  /**
   * Before a proven write, in the same synchronous turn as the write: the
   * scopes it can re-add and the tombstone version each acknowledges.
   */
  acknowledge(method: string, streams: readonly string[]): CanonicalReaddIntent;
  /** After the write committed: one marker per scope for each fresh receipt. */
  record(
    intent: CanonicalReaddIntent,
    receipts: readonly {
      instance: string;
      stream: string;
      method: string;
      generation: number;
      writeSeq: number;
    }[],
  ): void;
}

export interface CanonicalReaddIntent {
  method: string;
  acknowledged: { scope: string; stream: string; version: string }[];
}

const MARKERS_TABLE = "pdpp_canonical_readd";

function ensureTable(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS ${MARKERS_TABLE} (
      scope TEXT NOT NULL,
      instance TEXT NOT NULL,
      generation INTEGER NOT NULL,
      stream TEXT NOT NULL,
      method TEXT NOT NULL,
      tombstone_version TEXT NOT NULL,
      write_seq INTEGER NOT NULL,
      arrival_revision INTEGER NOT NULL,
      PRIMARY KEY (scope, instance, generation, stream)
    );
  `);
}

export function createCanonicalReaddMarkers(
  db: Database,
  deletions: Pick<ScopeDeletionTracker, "knownDeletion">,
): CanonicalReaddMarkers {
  ensureTable(db);
  const get = db.prepare(
    `SELECT tombstone_version FROM ${MARKERS_TABLE}
      WHERE scope = ? AND instance = ? AND generation = ? AND stream = ?`,
  );
  const put = db.prepare(`
    INSERT INTO ${MARKERS_TABLE}
      (scope, instance, generation, stream, method, tombstone_version, write_seq, arrival_revision)
    VALUES (@scope, @instance, @generation, @stream, @method, @version, @writeSeq, @arrival)
    ON CONFLICT (scope, instance, generation, stream) DO UPDATE SET
      method = excluded.method,
      tombstone_version = excluded.tombstone_version,
      write_seq = excluded.write_seq,
      arrival_revision = excluded.arrival_revision
  `);
  const arrivalRevision = () => {
    const exists = db
      .prepare(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pdpp_record_arrival_clock'",
      )
      .get();
    if (!exists) return 0;
    return (
      (
        db
          .prepare("SELECT value FROM pdpp_record_arrival_clock WHERE id = 1")
          .get() as { value: number } | undefined
      )?.value ?? 0
    );
  };

  return {
    acknowledge(method, streams) {
      const acknowledged: CanonicalReaddIntent["acknowledged"] = [];
      for (const stream of streams) {
        for (const scope of legacyScopesBackedBy(method, stream)) {
          const known = knownTombstoneVersion(deletions, scope);
          // No tombstone: nothing to re-add. An unversioned one covers
          // everything and cannot be acknowledged.
          if (known.kind !== "known") continue;
          acknowledged.push({ scope, stream, version: known.version });
        }
      }
      return { method, acknowledged };
    },

    record(intent, receipts) {
      if (intent.acknowledged.length === 0) return;
      db.transaction(() => {
        const arrival = arrivalRevision();
        for (const receipt of receipts) {
          if (receipt.method !== intent.method) continue;
          for (const ack of intent.acknowledged) {
            if (ack.stream !== receipt.stream) continue;
            const row = get.get(
              ack.scope,
              receipt.instance,
              receipt.generation,
              receipt.stream,
            ) as { tombstone_version: string } | undefined;
            // Knowledge only grows: never lower an acknowledged version.
            if (row && BigInt(row.tombstone_version) >= BigInt(ack.version)) {
              continue;
            }
            put.run({
              scope: ack.scope,
              instance: receipt.instance,
              generation: receipt.generation,
              stream: receipt.stream,
              method: receipt.method,
              version: ack.version,
              writeSeq: receipt.writeSeq,
              arrival,
            });
          }
        }
      })();
    },
  };
}

/**
 * The lowest tombstone version the markers of `streams` acknowledge for one
 * connection generation, or null when any stream has none (or no stream is
 * named). Read-only: a database without the table holds no marker.
 */
export function canonicalReaddVersion(
  db: Database,
  scope: string,
  instance: string,
  generation: number,
  streams: readonly string[],
): string | null {
  if (streams.length === 0) return null;
  const exists = db
    .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(MARKERS_TABLE);
  if (!exists) return null;
  const query = db.prepare(
    `SELECT tombstone_version FROM ${MARKERS_TABLE}
      WHERE scope = ? AND instance = ? AND generation = ? AND stream = ?`,
  );
  let lowest: bigint | null = null;
  for (const stream of new Set(streams)) {
    const row = query.get(scope, instance, generation, stream) as
      { tombstone_version: string } | undefined;
    if (!row || !/^\d+$/.test(row.tombstone_version)) return null;
    const version = BigInt(row.tombstone_version);
    if (lowest === null || version < lowest) lowest = version;
  }
  return lowest === null ? null : lowest.toString();
}
