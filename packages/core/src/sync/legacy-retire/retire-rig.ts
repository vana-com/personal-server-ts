/**
 * A retire flow over the REAL writer, registry fake and read service (the
 * writer-parity rig), for one bound connector. The legacy file is a made-up
 * `chatgpt.memories` body. Shared by the retire tests.
 */

import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createMemoryStreamSyncFiles } from "../../stream-sync/memory-files.js";
import type { StreamSyncSeedSource } from "../../stream-sync/index.js";
import { Rig } from "../../stream-sync-read/writer-rig.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import { createRetireHost } from "./host.js";
import { LegacyImporter, type ImportStream } from "./import.js";
import { RetireLedger } from "./ledger.js";
import { retireLegacyFiles, type RetireHost } from "./retire.js";

export const CONNECTOR = "chatgpt";
export const SCOPE = "chatgpt.memories";
export const STREAM = "memories";
export const AT = "2026-11-01T00:00:00.000Z";

export const raw = (id: string) => ({
  id,
  content: `memory ${id}`,
  created_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-02T00:00:00Z",
});
/** The legacy projection of a raw row (what the old install wrote). */
export const legacy = (id: string) => ({
  id,
  content: `memory ${id}`,
  created_at: "2026-10-01T00:00:00Z",
  type: "memory",
  updated_at: "2026-10-02T00:00:00Z",
});

export async function flow(options: {
  seed?: string[];
  /**
   * The import source lists the connector (and stages `seed`, if any). The
   * default is production's: an empty source that stages nothing.
   */
  imported?: boolean;
  switched?: boolean;
  local: string[];
  /** When the legacy file was collected; default `AT`. */
  collectedAt?: string;
  /** When this device stored it; default the memory store's epoch. */
  createdAt?: string;
  /** Wraps the retire host, for a test that changes the world mid-pass. */
  wrapHost?: (host: RetireHost) => RetireHost;
  /** The legacy body's rows instead of `local` ids (a changed entity). */
  localRows?: Record<string, unknown>[];
  /** More top-level keys of the legacy body. */
  extraBody?: Record<string, unknown>;
}) {
  const staged = new Map<string, Record<string, unknown>[]>();
  const ledger = new RetireLedger(createMemoryStreamSyncFiles());
  const importStream: ImportStream = {
    stream: STREAM,
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
    async *records() {
      for (const id of options.seed ?? []) yield raw(id);
    },
  };
  const importer = new LegacyImporter({
    source: {
      connectors: async () =>
        options.seed || options.imported ? [CONNECTOR] : [],
      streams: async () => (options.seed ? [importStream] : []),
    },
    sink: {
      async stage(_connector, stream, rows) {
        const out: Record<string, unknown>[] = [];
        for await (const row of rows) out.push(row);
        staged.set(stream.stream, out);
      },
    },
    ledger,
    switched: () => options.switched ?? true,
  });
  const seedSource: StreamSyncSeedSource = {
    installId: "install-1",
    streams: async (connector) =>
      connector === CONNECTOR
        ? [...staged.keys()].map((stream) => ({
            stream,
            primaryKey: ["id"],
            profile: { key: null, version: "1.0.0" },
          }))
        : [],
    async *records(_connector, stream) {
      for (const row of staged.get(stream) ?? []) yield row;
    },
  };
  const rig = new Rig(undefined, CONNECTOR, {
    seedSource,
    writer: { importDone: importer.importDone },
  });
  await rig.open();
  const storage = createMemoryDataStorage();
  const written = await storage.writeEnvelope(
    createDataFileEnvelope(SCOPE, options.collectedAt ?? AT, {
      memories: options.localRows ?? options.local.map(legacy),
      total: (options.localRows ?? options.local).length,
      ...options.extraBody,
    } as Record<string, unknown>),
  );
  const entry = await storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: written.relativePath,
    scope: SCOPE,
    collectedAt: options.collectedAt ?? AT,
    sizeBytes: written.sizeBytes,
    afterTombstoneVersion: null,
  });
  if (options.createdAt) entry.createdAt = options.createdAt;
  const wrapHost = options.wrapHost ?? ((host) => host);
  const retire = async (deleteEnabled = true, dryRun = false) => {
    await rig.sync();
    return retireLegacyFiles({
      storage,
      host: wrapHost(
        createRetireHost({ reader: rig.service, writer: rig.writer, ledger }),
      ),
      ledger,
      deleteEnabled,
      dryRun,
    });
  };
  const runRows = (
    runId: string,
    rows: Record<string, unknown>[],
    other = false,
  ) =>
    rig.collect({
      runId,
      full: true,
      key: "id",
      version: "1.0.0",
      stream: STREAM,
      rows,
      otherDevice: other,
    });
  const run = (runId: string, ids: string[], other = false) =>
    rig.collect({
      runId,
      full: true,
      key: "id",
      version: "1.0.0",
      stream: STREAM,
      rows: ids.map(raw),
      otherDevice: other,
    });
  return { rig, importer, ledger, storage, retire, run, runRows, staged };
}
