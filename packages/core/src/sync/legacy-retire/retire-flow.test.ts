/**
 * Import, publish, readback and retire against the REAL writer, registry fake
 * and read service (the writer-parity rig), for one bound connector. The legacy
 * file is a made-up `chatgpt.memories` body.
 */

import { describe, expect, it } from "vitest";
import { createMemoryStreamSyncFiles } from "../../stream-sync/memory-files.js";
import { ImportPendingError } from "../../stream-sync/writer.js";
import type { StreamSyncSeedSource } from "../../stream-sync/index.js";
import { Rig } from "../../stream-sync-read/writer-rig.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createRetireHost } from "./host.js";
import { LegacyImporter, type ImportStream } from "./import.js";
import { RetireLedger } from "./ledger.js";
import { retireLegacyFiles } from "./retire.js";

const CONNECTOR = "chatgpt";
const SCOPE = "chatgpt.memories";
const STREAM = "memories";
const AT = "2026-11-01T00:00:00.000Z";

const raw = (id: string) => ({
  id,
  content: `memory ${id}`,
  created_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-10-02T00:00:00Z",
});
/** The legacy projection of a raw row (what the old install wrote). */
const legacy = (id: string) => ({
  id,
  content: `memory ${id}`,
  created_at: "2026-10-01T00:00:00Z",
  type: "memory",
  updated_at: "2026-10-02T00:00:00Z",
});

async function flow(options: {
  seed?: string[];
  switched?: boolean;
  local: string[];
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
      connectors: async () => (options.seed ? [CONNECTOR] : []),
      streams: async () => [importStream],
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
    createDataFileEnvelope(SCOPE, AT, {
      memories: options.local.map(legacy),
      total: options.local.length,
    } as Record<string, unknown>),
  );
  await storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: written.relativePath,
    scope: SCOPE,
    collectedAt: AT,
    sizeBytes: written.sizeBytes,
    afterTombstoneVersion: null,
  });
  const retire = async (deleteEnabled = true, dryRun = false) => {
    await rig.sync();
    return retireLegacyFiles({
      storage,
      host: createRetireHost({
        reader: rig.service,
        writer: rig.writer,
        ledger,
      }),
      ledger,
      deleteEnabled,
      dryRun,
    });
  };
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
  return { rig, importer, ledger, storage, retire, run, staged };
}

describe("a stream run of a connector waits for its import (RUN_BEFORE_IMPORT)", () => {
  it("refuses to begin a run until the import finished, then accepts it", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await expect(f.run("early", ["e2"])).rejects.toBeInstanceOf(
      ImportPendingError,
    );
    await f.importer.run();
    await f.run("late", ["e2"]);
  });

  it("merges the imported rows into the first publish", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("first", ["e2"]);
    await f.rig.publish();
    const head = await f.rig.registeredHead(STREAM);
    expect(head?.recordCount).toBe(3);
  });
});

describe("retire reads the published heads only (RETIRE_ON_SPOOL, READBACK_ON_SPOOL)", () => {
  it("keeps the file while the stream copy exists only in this device's unpublished run", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0"]);
    await f.rig.publish();
    await f.run("b", ["e1"]); // collected, not published: overlay only
    const report = await f.retire();
    expect(report.deleted).toBe(0);
    expect(report.files[0]).toMatchObject({
      readback: "fail",
      readbackReason: "mismatch",
      wouldDelete: false,
    });
    expect(f.storage.entries).toHaveLength(1);
  });

  it("deletes the file once the run is published and the heads hold it", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0"]);
    await f.rig.publish();
    await f.run("b", ["e1"]);
    expect((await f.retire()).deleted).toBe(0);
    await f.rig.publish();
    const report = await f.retire();
    expect(report.deleted).toBe(1);
    expect(f.storage.entries).toHaveLength(0);
  });
});

describe("the delete fence (IMPORT_IGNORES_FENCE, DEVICE_ONLY_RETIRED_EARLY)", () => {
  it("does not import rows of a stream that was deleted", async () => {
    const f = await flow({ seed: ["e0", "e1"], local: ["e0", "e1"] });
    await f.rig.other.deleteStreams(CONNECTOR, [STREAM]);
    await f.importer.run();
    await f.run("learn", ["x"]);
    await f.rig.publish();
    await f.run("live", ["e9"]);
    await f.rig.publish();
    const head = await f.rig.registeredHead(STREAM);
    expect(head?.recordCount).toBe(1);
    const lines = (await f.rig.publications())
      .at(-1)!
      .lines.map((l) => (l.v as { id: string }).id);
    expect(lines).toEqual(["e9"]);
  });

  it("keeps a file the fence dropped until this device re-collected the stream", async () => {
    const f = await flow({ local: ["e0", "e1"] });
    await f.importer.run();
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    // A run collected before the delete is seen, published after it: the fence
    // discards it, so it is no re-collect.
    await f.run("stale", ["s"]);
    await f.rig.other.deleteStreams(CONNECTOR, [STREAM]);
    const published = await f.rig.publish();
    expect(published.find((s) => s.runId === "stale")?.outcome).toMatchObject({
      kind: "discarded",
    });

    const early = await f.retire();
    expect(early.files[0]).toMatchObject({
      readback: "pass",
      decision: "fence_not_recollected",
    });
    expect(early.deleted).toBe(0);
    expect(f.storage.entries).toHaveLength(1);

    // A full run that begins after the delete and commits re-collects it.
    await f.run("live", ["e5"]);
    await f.rig.publish();
    const done = await f.retire();
    expect(done.files[0]).toMatchObject({ decision: "ready" });
    expect(done.deleted).toBe(1);
  });
});

describe("unswitched accounts are unchanged (UNSWITCHED_CHANGED)", () => {
  it("stages nothing, gates no run, and leaves the ledger empty", async () => {
    const f = await flow({ seed: ["e0"], local: ["e0"], switched: false });
    expect(await f.importer.run()).toEqual({
      ran: false,
      connectorsStaged: 0,
      failed: 0,
    });
    expect(f.staged.size).toBe(0);
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
    await f.run("any", ["e1"]);
    expect(await f.ledger.read()).toEqual({
      importComplete: false,
      imported: {},
      readbacks: {},
    });
  });
});
