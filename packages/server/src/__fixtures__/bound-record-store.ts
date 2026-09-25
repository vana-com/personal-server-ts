import type Database from "better-sqlite3";
import {
  summarizeIngest,
  type IngestOutcome,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";

/** The method and generation `createTestBoundRecordStore` supplies. */
export const TEST_BINDING = { method: "test_method", generation: 1 } as const;

/**
 * Test-only SQLite record store for suites that exercise record and blob-read
 * semantics, not method authority. The real store refuses every ingest
 * without a method and generation (P8a), and every `blob_ref` without a
 * current-generation claim (P8c). When a call passes no binding, this view
 * supplies `TEST_BINDING`, claims each referenced blob for the envelope's
 * instance first, and ingests each instance's envelopes as its own batch.
 * An explicit binding passes through unchanged.
 */
export function createTestBoundRecordStore(
  db: Database.Database,
): ReturnType<typeof createSqliteRecordStore> {
  const store = createSqliteRecordStore(db);
  const claim = db.prepare(
    "INSERT OR IGNORE INTO pdpp_blob_claims (blob_id, instance, generation) VALUES (?, ?, ?)",
  );
  return {
    ...store,
    ingestBatch: (envelopes, semantics, primaryKey, binding) => {
      if (binding) {
        return store.ingestBatch(envelopes, semantics, primaryKey, binding);
      }
      const results: IngestOutcome[] = [];
      const instances = new Set(envelopes.map((e) => e.instance));
      for (const instance of instances) {
        const positions = envelopes.flatMap((e, i) =>
          e.instance === instance ? [i] : [],
        );
        const batch = positions.map((i) => envelopes[i]);
        for (const envelope of batch) {
          const blobId = (envelope.data?.blob_ref as { blob_id?: unknown })
            ?.blob_id;
          if (typeof blobId === "string") {
            claim.run(blobId, instance, TEST_BINDING.generation);
          }
        }
        store
          .ingestBatch(batch, semantics, primaryKey, TEST_BINDING)
          .results.forEach((result, j) => {
            results[positions[j]] = { ...result, index: positions[j] };
          });
      }
      return summarizeIngest(results);
    },
  };
}
