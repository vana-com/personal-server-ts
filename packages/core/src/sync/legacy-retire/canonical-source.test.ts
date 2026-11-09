/**
 * The production legacy import source: a device's own canonical PDPP rows,
 * mapped to streams through verified connector declarations. The titles name
 * the mutants `__mutants__/run-mutants.mjs` applies.
 */

import { describe, expect, it } from "vitest";
import type { DeclarationSnapshot } from "../../pdpp/types.js";
import { ImportPendingError } from "../../stream-sync/writer.js";
import {
  createCanonicalImportSource,
  type CanonicalImportDeps,
  type CanonicalImportStore,
} from "./canonical-source.js";
import {
  ImportSourceUnavailableError,
  type ImportStream,
  type LegacyImportSource,
} from "./import.js";
import { CONNECTOR, flow, OWNER, raw, STREAM } from "./retire-rig.js";

const OTHER = `0x${"bb".repeat(20)}`;
const SOURCE_ID = `https://registry.example.test/connectors/${CONNECTOR}`;

const declaration = (
  streams: { name: string; primary_key: string[] }[],
  sourceId = SOURCE_ID,
): DeclarationSnapshot =>
  ({
    source_id: sourceId,
    source_kind: "connector",
    version: "9.9.9",
    digest: "sha256:test",
    streams: streams.map((s) => ({
      name: s.name,
      fields: [],
      required_fields: [],
      ...s,
    })),
  }) as unknown as DeclarationSnapshot;

type Connection = {
  instance: string;
  method: string | null;
  deletedAt: string | null;
};

/** A canonical store with the read methods the source uses, paged by 2. */
function fakeStore(options: {
  connections: Record<string, Connection[]>;
  rows: Record<string, Record<string, unknown>[]>;
  /** When each instance last had a row arrive. */
  updated?: Record<string, string>;
}): CanonicalImportStore & { reads: number } {
  const store = {
    reads: 0,
    listConnections: (sourceId: string) => options.connections[sourceId] ?? [],
    listStreams: (instances: string[]) =>
      Object.entries(options.rows)
        .filter(([key]) => instances.includes(key.split("|")[0]!))
        .map(([key, rows]) => ({
          stream: key.split("|")[1]!,
          recordCount: rows.length,
          lastUpdated: options.updated?.[key.split("|")[0]!] ?? null,
        })),
    listRecords: (
      stream: string,
      o: { instanceIds: string[]; cursor?: string; limit: number },
    ) => {
      store.reads += 1;
      const rows = options.rows[`${o.instanceIds[0]}|${stream}`] ?? [];
      const from = o.cursor ? Number(o.cursor) : 0;
      const size = Math.min(o.limit, 2);
      const page = rows.slice(from, from + size);
      const more = from + size < rows.length;
      return {
        data: page.map((data) => ({ data })),
        hasMore: more,
        ...(more ? { nextCursor: String(from + size) } : {}),
      };
    },
  };
  return store as never;
}

const INSTANCE = `${CONNECTOR}:${OWNER}`;
const ACTIVE: Connection = {
  instance: INSTANCE,
  method: "browser",
  deletedAt: null,
};

function canonical(
  rows: Record<string, unknown>[],
  extra: Record<string, Record<string, unknown>[]> = {},
) {
  return fakeStore({
    connections: { [SOURCE_ID]: [ACTIVE] },
    rows: {
      [`${INSTANCE}|${STREAM}`]: rows,
      ...Object.fromEntries(
        Object.entries(extra).map(([k, v]) => [`${INSTANCE}|${k}`, v]),
      ),
    },
  });
}

const DECLARED = [declaration([{ name: STREAM, primary_key: ["id"] }])];

function sourceOf(
  deps: CanonicalImportDeps | null,
  owner = OWNER,
): LegacyImportSource {
  return createCanonicalImportSource({ owner, deps: () => deps });
}

async function rowsOf(stream: ImportStream) {
  const out: Record<string, unknown>[] = [];
  for await (const row of stream.records()) out.push(row);
  return out;
}

describe("the canonical import source maps through verified declarations", () => {
  it("names the connector by its source id and the stream and key by its declaration", async () => {
    const store = canonical([raw("e0"), raw("e1"), raw("e2")]);
    const source = sourceOf({ store, declarations: DECLARED });
    expect(await source.connectors()).toEqual([CONNECTOR]);
    const [stream, ...rest] = await source.streams(CONNECTOR);
    expect(rest).toEqual([]);
    expect(stream).toMatchObject({
      stream: STREAM,
      primaryKey: ["id"],
      profile: { key: null, version: "0.0.0" },
    });
    // Three rows over pages of two: every row once, in store order.
    expect((await rowsOf(stream!)).map((r) => r.id)).toEqual([
      "e0",
      "e1",
      "e2",
    ]);
  });

  it("is not available until the host has bound its stores, never empty (PENDING_COUNTED_AS_EMPTY)", async () => {
    const source = sourceOf(null);
    await expect(source.connectors()).rejects.toBeInstanceOf(
      ImportSourceUnavailableError,
    );
  });

  it("lists no stream for a declared stream the device holds no row of", async () => {
    const store = canonical([]);
    const source = sourceOf({ store, declarations: DECLARED });
    expect(await source.streams(CONNECTOR)).toEqual([]);
  });

  it("uses a composite key exactly as declared", async () => {
    const store = fakeStore({
      connections: { [SOURCE_ID]: [ACTIVE] },
      rows: {
        [`${INSTANCE}|pairs`]: [
          { a: "1", b: "x" },
          { a: "1", b: "y" },
        ],
      },
    });
    const source = sourceOf({
      store,
      declarations: [declaration([{ name: "pairs", primary_key: ["a", "b"] }])],
    });
    const [stream] = await source.streams(CONNECTOR);
    expect(stream).toMatchObject({ primaryKey: ["a", "b"] });
    expect(await rowsOf(stream!)).toHaveLength(2);
  });
});

describe("what the source cannot import stays, with a reason and a count (UNMAPPED_SCOPE_DROPPED_SILENTLY)", () => {
  it("counts an undeclared stream, an unkeyed row (UNKEYED_ROW_IMPORTED) and a keyless declaration", async () => {
    const store = canonical(
      [
        raw("e0"),
        { content: "no key" }, // unkeyed
        { id: "", content: "empty key" }, // unkeyed
      ],
      {
        extras: [{ id: "x1" }, { id: "x2" }], // no declaration names it
        keyless: [{ id: "k1" }], // declared with no primary key
      },
    );
    const source = sourceOf({
      store,
      declarations: [
        declaration([
          { name: STREAM, primary_key: ["id"] },
          { name: "keyless", primary_key: [] },
        ]),
      ],
    });
    const streams = await source.streams(CONNECTOR);
    expect(streams.map((s) => s.stream)).toEqual([STREAM]);
    expect((await rowsOf(streams[0]!)).map((r) => r.id)).toEqual(["e0"]);
    expect(await source.excluded!(CONNECTOR)).toEqual([
      { stream: "extras", reason: "unmapped_stream", rows: 2 },
      { stream: "keyless", reason: "no_primary_key", rows: 1 },
      { stream: STREAM, reason: "unkeyed_row", rows: 2 },
    ]);
  });

  it("imports the most recently active of two live connections and counts the other (CONNECTOR_DROPPED_WHEN_AMBIGUOUS, OLDEST_CONNECTION_CHOSEN, OTHER_CONNECTION_NOT_COUNTED)", async () => {
    const second = { ...ACTIVE, instance: `${CONNECTOR}:second` };
    const store = fakeStore({
      connections: { [SOURCE_ID]: [ACTIVE, second] },
      rows: {
        [`${INSTANCE}|${STREAM}`]: [raw("old1"), raw("old2")],
        [`${CONNECTOR}:second|${STREAM}`]: [raw("new1")],
      },
      updated: {
        [INSTANCE]: "2026-01-01T00:00:00Z",
        [`${CONNECTOR}:second`]: "2026-06-01T00:00:00Z",
      },
    });
    const source = sourceOf({ store, declarations: DECLARED });
    expect(await source.connectors()).toEqual([CONNECTOR]);
    const streams = await source.streams(CONNECTOR);
    // The newer connection's rows are the ones imported (OLDEST_CONNECTION_CHOSEN).
    expect((await rowsOf(streams[0]!)).map((r) => r.id)).toEqual(["new1"]);
    // The other connection's rows are counted, never silent (OTHER_CONNECTION_NOT_COUNTED).
    expect(await source.excluded!(CONNECTOR)).toEqual([
      { stream: null, reason: "other_connection", rows: 2 },
    ]);
  });

  it("imports a row that points at a blob, since the reference is plain data (BLOB_ROW_EXCLUDED)", async () => {
    const store = canonical([
      raw("e0"),
      { id: "e9", file: { blob_id: "sha256:abc" } },
    ]);
    const source = sourceOf({ store, declarations: DECLARED });
    const streams = await source.streams(CONNECTOR);
    expect((await rowsOf(streams[0]!)).map((r) => r.id)).toEqual(["e0", "e9"]);
    expect(await source.excluded!(CONNECTOR)).toEqual([]);
  });

  it("ignores a deleted connection and a source nobody connected (DELETED_CONNECTION_IMPORTED)", async () => {
    const store = fakeStore({
      connections: { [SOURCE_ID]: [{ ...ACTIVE, deletedAt: "2026-10-01" }] },
      rows: { [`${INSTANCE}|${STREAM}`]: [raw("e0")] },
    });
    const source = sourceOf({ store, declarations: DECLARED });
    expect(await source.connectors()).toEqual([]);
  });
});

describe("a switched device imports its canonical rows with no new run (IMPORT_SOURCE_EMPTY_IN_PRODUCTION)", () => {
  it("stages every keyed row, records the receipt, and the first run publishes them", async () => {
    const store = canonical([raw("e0"), raw("e1")]);
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf({ store, declarations: DECLARED }),
      owner: OWNER,
    });
    expect(await f.importer.run()).toEqual({
      ran: true,
      connectorsStaged: 1,
      failed: 0,
    });
    expect(f.staged.get(STREAM)?.map((r) => r.id)).toEqual(["e0", "e1"]);
    expect((await f.ledger.read()).imported[CONNECTOR]).toMatchObject({
      staged: { [STREAM]: 2 },
    });
    // The stream copy comes from the first run; the import rows join it.
    await f.run("first", ["e2"]);
    await f.rig.publish();
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(3);
  });

  it("does not let a source that was not ready inherit an empty completion", async () => {
    let deps: CanonicalImportDeps | null = null;
    const store = canonical([raw("e0"), raw("e1")]);
    const f = await flow({
      local: ["e0", "e1"],
      source: createCanonicalImportSource({ owner: OWNER, deps: () => deps }),
      owner: OWNER,
    });
    // The host has not bound its stores: pending, not empty, not complete.
    const early = await f.importer.run();
    expect(early).toMatchObject({ ran: true, pending: true });
    expect(await f.ledger.importPending()).toBe(true);
    expect(await f.importer.importDone(CONNECTOR)).toBe(false);
    await expect(f.run("early", ["e2"])).rejects.toBeInstanceOf(
      ImportPendingError,
    );
    deps = { store, declarations: DECLARED };
    expect(await f.importer.run()).toMatchObject({ connectorsStaged: 1 });
    expect(f.staged.get(STREAM)?.map((r) => r.id)).toEqual(["e0", "e1"]);
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
    await f.run("late", ["e2"]);
  });

  it("keeps the file when the only rows it held are unmapped, and shows why", async () => {
    const store = fakeStore({
      connections: { [SOURCE_ID]: [ACTIVE] },
      rows: { [`${INSTANCE}|extras`]: [{ id: "x1" }, { id: "x2" }] },
    });
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf({ store, declarations: DECLARED }),
      owner: OWNER,
    });
    await f.importer.run();
    expect(f.staged.size).toBe(0);
    const data = await f.ledger.read();
    expect(data.imported[CONNECTOR]).toMatchObject({ staged: {} });
    expect(data.excluded[CONNECTOR]).toEqual([
      { stream: "extras", reason: "unmapped_stream", rows: 2 },
    ]);
    await f.run("a", ["e0", "e1"]);
    await f.rig.publish();
    // The published view holds the file, but the connector still has rows in
    // the legacy store that the import left there: no file of it is retired
    // (EXCLUDED_ROWS_RETIRE).
    const report = await f.retire();
    expect(report.deleted).toBe(0);
    expect(report.files[0]?.decision).toBe("no_import");
  });
});

describe("a re-run adds nothing (IMPORT_DUPLICATES_ON_RERUN)", () => {
  it("retries a crash between streams twice and stages the same unique rows", async () => {
    const store = canonical([raw("e0"), raw("e1")], {
      more: [{ id: "m1" }, { id: "m2" }, { id: "m3" }],
    });
    const declared = [
      declaration([
        { name: STREAM, primary_key: ["id"] },
        { name: "more", primary_key: ["id"] },
      ]),
    ];
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf({ store, declarations: declared }),
      owner: OWNER,
      publishSeed: false,
      crashOnce: "more",
    });
    expect(await f.importer.run()).toEqual({
      ran: true,
      connectorsStaged: 0,
      failed: 1,
    });
    expect(await f.importer.importDone(CONNECTOR)).toBe(false);
    expect(await f.importer.run()).toMatchObject({ connectorsStaged: 1 });
    const once = JSON.stringify([...f.staged]);
    expect(await f.importer.run()).toMatchObject({ ran: false });
    expect(await f.importer.run()).toMatchObject({ ran: false });
    expect(JSON.stringify([...f.staged])).toBe(once);
    expect(f.staged.get("more")).toHaveLength(3);
    // The retry stages the connector's streams again (the receipt is written
    // only once all of them are in); staging replaces, so nothing doubles.
    expect(f.stagings).toBe(4);
    await f.run("a", ["e2"]);
    await f.rig.publish();
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(3);
  });
});

describe("rows are staged only for the owner the source was built for (IMPORT_WRONG_OWNER)", () => {
  it("refuses a source of another owner than the request owner and stages nothing (IMPORT_SOURCE_OWNER_UNCHECKED)", async () => {
    const store = canonical([raw("e0")]);
    const f = await flow({
      local: ["e0"],
      source: sourceOf({ store, declarations: DECLARED }, OWNER),
      owner: OTHER, // this home belongs to another owner
    });
    expect(await f.importer.run()).toMatchObject({
      ran: false,
      refused: "owner_mismatch",
    });
    expect(f.staged.size).toBe(0);
    expect(await f.importer.importDone(CONNECTOR)).toBe(false);
    expect(await f.ledger.importPending()).toBe(true);
  });

  it("refuses when the request owner differs from the owner the ledger was recorded for (IMPORT_LEDGER_OWNER_UNCHECKED)", async () => {
    const store = canonical([raw("e0")]);
    const f = await flow({
      local: ["e0"],
      source: sourceOf({ store, declarations: DECLARED }, OTHER),
      owner: OWNER, // the ledger is A's
      requestOwner: OTHER, // the source and the request are B's
    });
    expect(await f.importer.run()).toMatchObject({
      ran: false,
      refused: "owner_mismatch",
    });
    expect(f.staged.size).toBe(0);
    expect((await f.ledger.read()).imported).toEqual({});
  });

  it("drops what another owner's pass recorded when the home changes hands and back (LEDGER_OWNER_IGNORED)", async () => {
    const store = canonical([raw("e0")]);
    const f = await flow({
      local: ["e0"],
      source: sourceOf({ store, declarations: DECLARED }, OWNER),
      owner: OWNER,
    });
    await f.importer.run();
    expect(await f.importer.importDone(CONNECTOR)).toBe(true);
    // The same home is opened by the other owner's importer (a source of its
    // own, with a row to stage): A's import state is not B's.
    const asOther = f.importerFor({
      source: sourceOf(
        { store: canonical([raw("o0")]), declarations: DECLARED },
        OTHER,
      ),
      owner: OTHER,
    });
    await asOther.run();
    expect((await f.ledger.read()).imported).toEqual({});
    // Back to A: the import runs again, from A's source.
    const again = f.importerFor({
      source: sourceOf({ store, declarations: DECLARED }, OWNER),
      owner: OWNER,
    });
    expect(await again.run()).toMatchObject({ connectorsStaged: 1 });
    expect((await f.ledger.read()).imported[CONNECTOR]).toMatchObject({
      staged: { [STREAM]: 1 },
    });
  });

  it("discards an import record that no owner or source revision vouches for", async () => {
    const store = canonical([raw("e0")]);
    const f = await flow({
      local: ["e0"],
      source: sourceOf({ store, declarations: DECLARED }),
      owner: OWNER,
    });
    // What the empty production source left behind before this source
    // existed: a completed import that names no owner.
    await f.files.write(
      "legacy-retire/ledger.json",
      new TextEncoder().encode(
        JSON.stringify({ importComplete: true, imported: {}, readbacks: {} }),
      ),
    );
    expect(await f.importer.importDone(CONNECTOR)).toBe(false);
    expect(await f.importer.run()).toMatchObject({ connectorsStaged: 1 });
    expect(f.staged.get(STREAM)).toHaveLength(1);
  });
});

describe("a run of a connector waits for the import (RUN_BEFORE_IMPORT)", () => {
  it("refuses an ordinary run until the source was read, then merges the rows into its first publish", async () => {
    const store = canonical([raw("e0"), raw("e1")]);
    const f = await flow({
      local: ["e0", "e1"],
      source: sourceOf({ store, declarations: DECLARED }),
      owner: OWNER,
    });
    await expect(f.run("early", ["e2"])).rejects.toBeInstanceOf(
      ImportPendingError,
    );
    await f.importer.run();
    await f.run("first", ["e2"]);
    await f.rig.publish();
    expect((await f.rig.registeredHead(STREAM))?.recordCount).toBe(3);
  });
});
