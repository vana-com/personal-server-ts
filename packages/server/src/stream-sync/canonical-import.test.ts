/**
 * The production import path over a REAL SQLite record store and the real seed
 * staging: what a switched device holds in its canonical store reaches the
 * seed intake with no run, and what it cannot hold stays, with a count.
 */

import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryStreamSyncFiles,
  type StreamSyncFiles,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createCanonicalImportSource,
  LegacyImporter,
  RetireLedger,
  type CanonicalImportDeps,
} from "@opendatalabs/personal-server-ts-core/sync";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { createSeedImportSink } from "./legacy-import-sink.js";
import { createSeedStaging } from "./seed-staging.js";

const OWNER = `0x${"aa".repeat(20)}`;
/** The source `createTestBoundRecordStore` registers a connection under. */
const SOURCE_ID = "https://test.invalid/connector";
const CONNECTOR = "connector";
const INSTANCE = `${CONNECTOR}:${OWNER}`;

const declaration = {
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "1.0.0",
  digest: "sha256:test",
  streams: [
    {
      name: "notes",
      primary_key: ["id"],
      semantics: "mutable_state",
      fields: [],
      required_fields: [],
    },
  ],
} as unknown as CanonicalImportDeps["declarations"][number];

function seedStore(notes: number) {
  const store = createTestBoundRecordStore(new Database(":memory:"));
  const put = (stream: string, key: string) =>
    store.ingestBatch(
      [
        {
          instance: INSTANCE,
          stream,
          key,
          data: { id: key, text: `${stream} ${key}` },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
  for (let i = 1; i <= notes; i += 1) put("notes", `n${i}`);
  put("extras", "x1");
  put("extras", "x2");
  return store;
}

async function staged(files: StreamSyncFiles, connector: string) {
  const staging = createSeedStaging(files);
  const source = staging.source(await staging.installId(), async () => ({}));
  const out: Record<string, string[]> = {};
  for (const { stream } of await source.streams(connector)) {
    const ids: string[] = [];
    for await (const row of source.records(connector, stream)) {
      ids.push(String(row.id));
    }
    out[stream] = ids.sort();
  }
  return out;
}

describe("the canonical import source over a real record store (IMPORT_SOURCE_EMPTY_IN_PRODUCTION)", () => {
  it("is pending until the stores are bound, then stages every declared row once and counts the rest", async () => {
    const store = seedStore(5);
    let deps: CanonicalImportDeps | null = null;
    const files = createMemoryStreamSyncFiles(7);
    const ledger = new RetireLedger(createMemoryStreamSyncFiles(), OWNER);
    const importer = new LegacyImporter({
      source: createCanonicalImportSource({
        owner: OWNER,
        deps: () => deps,
        pageSize: 2, // five rows over three pages
      }),
      sink: createSeedImportSink(createSeedStaging(files)),
      ledger,
      owner: OWNER,
      mode: { read: () => "switched" as const },
      publish: async () => ({ state: "done", skipped: [] }), // staging only
    });

    // Boot order: the importer exists before the canonical reader opens.
    expect(await importer.run()).toMatchObject({ ran: true, pending: true });
    expect(await importer.importDone(CONNECTOR)).toBe(false);
    expect(await staged(files, CONNECTOR)).toEqual({});

    deps = { store, declarations: [declaration] };
    expect(await importer.run()).toEqual({
      ran: true,
      connectorsStaged: 1,
      failed: 0,
    });
    expect(await importer.importDone(CONNECTOR)).toBe(true);
    expect(await staged(files, CONNECTOR)).toEqual({
      notes: ["n1", "n2", "n3", "n4", "n5"],
    });
    const data = await ledger.read();
    expect(data.imported[CONNECTOR]?.staged).toEqual({ notes: 5 });
    expect(await ledger.staged(CONNECTOR, "notes")).toBe(true);
    // The stream no declaration names stays in the legacy file, with a count.
    expect(data.excluded[CONNECTOR]).toEqual([
      { stream: "extras", reason: "unmapped_stream", rows: 2 },
    ]);

    // A restart: the same ledger, a new importer. Nothing is staged twice.
    const again = new LegacyImporter({
      source: createCanonicalImportSource({
        owner: OWNER,
        deps: () => deps,
        pageSize: 2,
      }),
      sink: createSeedImportSink(createSeedStaging(files)),
      ledger,
      owner: OWNER,
      mode: { read: () => "switched" as const },
      publish: async () => ({ state: "done", skipped: [] }), // staging only
    });
    expect(await again.run()).toMatchObject({ ran: false });
    expect(await staged(files, CONNECTOR)).toEqual({
      notes: ["n1", "n2", "n3", "n4", "n5"],
    });
  });
});
