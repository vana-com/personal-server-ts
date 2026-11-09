/**
 * The legacy import's sink: stage a device's own rows as a Desktop-style seed
 * upload (design §2.9), which the writer merges into the connector's first
 * publish with `collectedAt` 0. Staging replaces the stream's previous
 * upload, so a retried import is safe.
 */

import type {
  ImportStream,
  LegacyImportSink,
} from "@opendatalabs/personal-server-ts-core/sync";
import type { SeedStaging } from "./seed-staging.js";

const encoder = new TextEncoder();

export function createSeedImportSink(staging: SeedStaging): LegacyImportSink {
  return {
    async stage(connector, stream, rows) {
      // The descriptor carries the row count, so count first. The rows are
      // read twice, one at a time; memory stays at one row.
      let count = 0;
      for await (const _ of stream.records()) count += 1;
      async function* body(): AsyncGenerator<Uint8Array> {
        yield encoder.encode(
          `${JSON.stringify({
            primaryKey: stream.primaryKey,
            profile: stream.profile,
            records: count,
          })}\n`,
        );
        let sent = 0;
        for await (const row of rows) {
          sent += 1;
          yield encoder.encode(`${JSON.stringify(row)}\n`);
        }
        if (sent !== count) {
          throw new Error("legacy import source changed while it was staged");
        }
      }
      const seed = await staging.stage(connector, stream.stream, body());
      // The intake drops a row it cannot key; only what it kept is delivered.
      return seed.records;
    },
  } satisfies LegacyImportSink;
}

export type { ImportStream };
