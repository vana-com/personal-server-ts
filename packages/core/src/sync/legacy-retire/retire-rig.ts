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
import {
  LegacyImporter,
  type ImportStream,
  type LegacyImportSource,
} from "./import.js";
import { RetireLedger } from "./ledger.js";
import { retireLegacyFiles, type RetireHost } from "./retire.js";

export const CONNECTOR = "chatgpt";
export const SCOPE = "chatgpt.memories";
export const STREAM = "memories";
export const OWNER = `0x${"aa".repeat(20)}`;
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
  /** The sink pulls every row of the seed and keeps none (an intake that drops rows it cannot key). */
  sinkKeepsNone?: boolean;
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
  /** A real import source instead of `seed` / `imported`. */
  source?: LegacyImportSource;
  /** The Account owner of this home; default `OWNER`. */
  owner?: string;
  /** The sink throws the first time it is handed this stream. */
  crashOnce?: string;
  /** The sink throws every time it is handed this stream. */
  sinkThrows?: string;
  /** Failed attempts before a connector's import is given up (default: the importer's). */
  maxAttempts?: number;
  /** Publish the staged seed with no connector run (default on); or a replacement. */
  publishSeed?: boolean | ((connector: string) => Promise<"done" | "waiting">);
}) {
  let switched = options.switched ?? true;
  const staged = new Map<string, Record<string, unknown>[]>();
  const owner = options.owner ?? OWNER;
  const files = createMemoryStreamSyncFiles();
  const ledger = new RetireLedger(files, owner);
  let stagings = 0;
  let crashed = false;
  const importStream: ImportStream = {
    stream: STREAM,
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
    async *records() {
      for (const id of options.seed ?? []) yield raw(id);
    },
  };
  const defaultSource: LegacyImportSource = {
    owner,
    connectors: async () =>
      options.seed || options.imported ? [CONNECTOR] : [],
    streams: async () => (options.seed ? [importStream] : []),
  };
  const importerFor = (own: { source: LegacyImportSource; owner: string }) =>
    new LegacyImporter({
      source: own.source,
      sink: {
        async stage(_connector, stream, rows) {
          stagings += 1;
          if (options.sinkThrows === stream.stream) {
            throw new Error("the sink cannot take this stream");
          }
          if (options.crashOnce === stream.stream && !crashed) {
            crashed = true;
            throw new Error("crash while staging");
          }
          const out: Record<string, unknown>[] = [];
          for await (const row of rows) out.push(row);
          if (options.sinkKeepsNone) return 0;
          staged.set(stream.stream, out);
          return out.length;
        },
      },
      ledger: new RetireLedger(files, own.owner),
      switched: () => switched,
      ...(options.maxAttempts ? { maxAttempts: options.maxAttempts } : {}),
      ...(options.publishSeed === false
        ? {}
        : {
            publish:
              typeof options.publishSeed === "function"
                ? options.publishSeed
                : (connector: string) => rig.writer.publishSeed(connector),
          }),
      deleted: async (connector): Promise<boolean> =>
        rig.writer.connectionDeleted(connector),
    });
  // eslint-disable-next-line prefer-const -- bound below; the importer reads it late
  let rig: Rig;
  const importer = importerFor({
    source: options.source ?? defaultSource,
    owner,
  });
  const seedSource: StreamSyncSeedSource = {
    installId: "install-1",
    streams: async (connector) =>
      connector === CONNECTOR
        ? [...staged.keys()].map((stream) => ({
            stream,
            upload: "upload-1",
            primaryKey: ["id"],
            profile: { key: null, version: "1.0.0" },
          }))
        : [],
    async *records(_connector, stream) {
      for (const row of staged.get(stream) ?? []) yield row;
    },
  };
  rig = new Rig(undefined, CONNECTOR, ["items"], [], {
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
  // `connect`: an explicit connect, the only run a deleted connection accepts.
  const run = (runId: string, ids: string[], other = false, connect = false) =>
    rig.collect({
      runId,
      full: true,
      key: "id",
      version: "1.0.0",
      stream: STREAM,
      rows: ids.map(raw),
      otherDevice: other,
      userConnect: connect,
    });
  return {
    rig,
    setSwitched(value: boolean) {
      switched = value;
    },
    importer,
    importerFor,
    ledger,
    files,
    storage,
    retire,
    run,
    runRows,
    staged,
    get stagings() {
      return stagings;
    },
  };
}
