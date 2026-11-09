import { describe, expect, it } from "vitest";
import {
  createMemoryStreamSyncFiles,
  type StreamSyncFiles,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  LegacyImporter,
  RetireLedger,
  type ImportStream,
  type LegacyImportSink,
} from "@opendatalabs/personal-server-ts-core/sync";
import { createSeedStaging } from "./seed-staging.js";
import { createSeedImportSink } from "./legacy-import-sink.js";

const row = (id: string) => ({ id, text: `row ${id}` });
const ids = (rows: { id: unknown }[]) => rows.map((r) => String(r.id));

function streamOf(name: string, rows: string[]): ImportStream {
  return {
    stream: name,
    primaryKey: ["id"],
    profile: { key: null, version: "1.0.0" },
    async *records() {
      for (const id of rows) yield row(id);
    },
  };
}

async function staged(files: StreamSyncFiles, connector: string) {
  const staging = createSeedStaging(files);
  const source = staging.source(await staging.installId(), async () => ({}));
  const out: Record<string, string[]> = {};
  for (const { stream } of await source.streams(connector)) {
    const rows: { id: unknown }[] = [];
    for await (const r of source.records(connector, stream)) {
      rows.push(r as { id: unknown });
    }
    out[stream] = ids(rows);
  }
  return out;
}

describe("importing through the real seed staging", () => {
  it("a crash mid-import then a re-run stages every stream exactly once (IMPORT_DUPLICATES, IMPORT_LOSES_ON_RERUN)", async () => {
    const files = createMemoryStreamSyncFiles(7);
    const ledger = new RetireLedger(createMemoryStreamSyncFiles());
    const sink = createSeedImportSink(createSeedStaging(files));
    let crashOnce = true;
    const flaky: LegacyImportSink = {
      async stage(connector, stream, rows) {
        if (crashOnce && stream.stream === "b") {
          crashOnce = false;
          throw new Error("injected crash");
        }
        return sink.stage(connector, stream, rows);
      },
    };
    const streams = [
      streamOf("a", ["a1", "a2", "a3"]),
      streamOf("b", ["b1", "b2"]),
    ];
    const importer = new LegacyImporter({
      source: {
        connectors: async () => ["acme"],
        streams: async () => streams,
      },
      sink: flaky,
      ledger,
      switched: () => true,
    });

    const first = await importer.run();
    expect(first).toEqual({ ran: true, connectorsStaged: 0, failed: 1 });
    expect(await importer.importDone("acme")).toBe(false);

    const second = await importer.run();
    expect(second).toEqual({ ran: true, connectorsStaged: 1, failed: 0 });
    expect(await importer.importDone("acme")).toBe(true);
    expect(await staged(files, "acme")).toEqual({
      a: ["a1", "a2", "a3"],
      b: ["b1", "b2"],
    });

    // A third run (the next boot) changes nothing.
    expect(await importer.run()).toEqual({
      ran: false,
      connectorsStaged: 0,
      failed: 0,
    });
    expect(await staged(files, "acme")).toEqual({
      a: ["a1", "a2", "a3"],
      b: ["b1", "b2"],
    });
  });

  it("a source that changes while it is staged fails the import instead of staging a short copy", async () => {
    const files = createMemoryStreamSyncFiles(7);
    const ledger = new RetireLedger(createMemoryStreamSyncFiles());
    let calls = 0;
    const shifting: ImportStream = {
      stream: "s",
      primaryKey: ["id"],
      profile: { key: null, version: "1.0.0" },
      async *records() {
        calls += 1;
        // The second pass (the body) sees one row fewer than the count pass.
        for (const id of calls === 1 ? ["x1", "x2"] : ["x1"]) yield row(id);
      },
    };
    const importer = new LegacyImporter({
      source: {
        connectors: async () => ["acme"],
        streams: async () => [shifting],
      },
      sink: createSeedImportSink(createSeedStaging(files)),
      ledger,
      switched: () => true,
    });
    expect(await importer.run()).toMatchObject({ failed: 1 });
    expect(await importer.importDone("acme")).toBe(false);
    expect(await staged(files, "acme")).toEqual({});
  });

  it("receipts the rows the intake kept, not the rows it was handed (SINK_RETURNS_PULLED)", async () => {
    const files = createMemoryStreamSyncFiles(7);
    const ledger = new RetireLedger(createMemoryStreamSyncFiles());
    const unkeyed: ImportStream = {
      stream: "u",
      primaryKey: ["id"],
      profile: { key: null, version: "1.0.0" },
      async *records() {
        yield { text: "no key 1" };
        yield { text: "no key 2" };
      },
    };
    const mixed: ImportStream = {
      stream: "m",
      primaryKey: ["id"],
      profile: { key: null, version: "1.0.0" },
      async *records() {
        yield row("m1");
        yield { text: "no key" };
        yield row("m2");
      },
    };
    const sink = createSeedImportSink(createSeedStaging(files));
    expect(await sink.stage("acme", unkeyed, unkeyed.records())).toBe(0);
    expect(await sink.stage("acme", mixed, mixed.records())).toBe(2);
    const importer = new LegacyImporter({
      source: {
        connectors: async () => ["acme"],
        streams: async () => [unkeyed, mixed],
      },
      sink,
      ledger,
      switched: () => true,
    });
    await importer.run();
    expect(await ledger.staged("acme", "u")).toBe(false);
    expect(await ledger.staged("acme", "m")).toBe(true);
    expect((await ledger.read()).imported.acme?.staged).toEqual({ u: 0, m: 2 });
  });
});
