import { afterEach, expect, it } from "vitest";
import { foldLayers, type FoldLayer } from "../../../core/src/localdb/index.js";
import { drivers, world } from "./late-seed-harness.test-utils.js";

// Layers are stored versions of one stream, newest first: the `{records}`
// files a source left, one after another. The fold lets the newest version of
// each key decide, so the result follows layer rank, not read order. Shapes 5
// and 6 of the legacy inventory (docs/formal/late-seed/README.md).

afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const SOURCE = "urn:fixture";
const tagged = (id: string, v: string, sourceId = SOURCE) => ({
  id,
  v,
  $pdpp: { sourceId },
});
const layer = (
  rows: readonly unknown[],
  deletions?: readonly unknown[],
): FoldLayer => ({
  async *records() {
    yield* rows;
  },
  ...(deletions
    ? {
        async *deletions() {
          yield* deletions;
        },
      }
    : {}),
});
const bodies = async (
  device: Awaited<ReturnType<Awaited<ReturnType<typeof world>>["device"]>>,
) =>
  Object.fromEntries(
    (await device.snapshot()).map((r) => [
      (r as { record_key: string }).record_key,
      (r as { body: string }).body,
    ]),
  );

it("fold-newest-file-wins-and-unfit-rows-are-counted-by-reason", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(
      base,
      [
        layer([
          tagged("a", "new"),
          tagged("b", "only-new"),
          { v: "no key field", $pdpp: { sourceId: SOURCE } },
        ]),
        layer([
          tagged("a", "mid"),
          tagged("c", "mid-c"),
          { id: "x", v: "untagged" },
          tagged("y", "other", "urn:other"),
        ]),
        layer([tagged("a", "old"), tagged("c", "old-c"), tagged("d", "old-d")]),
      ],
      { sourceId: SOURCE },
    ),
  );
  expect(result).toMatchObject({
    kind: "imported",
    quarantine: {
      missing_key_field: 1,
      untagged: 1,
      source_mismatch: 1,
      superseded: 3,
    },
    tombstoned: 0,
  });
  // The envelope is not part of the record, and the newest version of a key wins.
  expect(await bodies(a)).toEqual({
    a: '{"id":"a","v":"new"}',
    b: '{"id":"b","v":"only-new"}',
    c: '{"id":"c","v":"mid-c"}',
    d: '{"id":"d","v":"old-d"}',
  });
  expect(
    await a.db.query<{ state: string; reason: string; rows: number }>(
      "SELECT state, reason, rows FROM import_ledger",
    ),
  ).toEqual([
    {
      state: "imported",
      reason:
        'quarantined:{"missing_key_field":1,"source_mismatch":1,"superseded":3,"untagged":1}',
      rows: 4,
    },
  ]);
});

it("fold-delete-in-a-newer-layer-keeps-older-copies-out-and-leaves-a-seed-tombstone", async () => {
  const w = await world();
  const a = await w.device("a");
  const layers = [
    layer([{ id: "d", v: "new" }], [{ id: "b" }]),
    layer([
      { id: "a", v: 1 },
      { id: "b", v: 1 },
    ]),
    layer([
      { id: "b", v: 0 },
      { id: "c", v: 0 },
    ]),
  ];
  const result = await a.importSource("files", (base) =>
    foldLayers(base, layers),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 1,
    quarantine: { deleted_in_newer_layer: 2 },
  });
  expect(await a.keys()).toEqual(["a", "c", "d"]);
  expect(
    await a.db.query(
      "SELECT record_key, stamp_o, stamp_r, rank FROM log_tombstones",
    ),
  ).toEqual([{ record_key: "b", stamp_o: 0, stamp_r: "seed", rank: 2 }]);
  // Another copy's seed cannot bring it back; a real write still can.
  await a.seed("another-install", ["b"]);
  expect(await a.keys()).toEqual(["a", "c", "d"]);
  await a.run("later", ["a", "b", "c", "d"]);
  expect(await a.keys()).toEqual(["a", "b", "c", "d"]);
});

it("fold-a-layer-that-names-deleted-record-keys-keeps-older-rows-out-and-tombstones-them", async () => {
  const w = await world();
  const a = await w.device("a");
  const newest: FoldLayer = {
    ...layer([{ id: "x", v: "kept" }]),
    async *deletedRecordKeys() {
      yield "b";
      yield "never-held";
    },
  };
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [
      newest,
      layer([
        { id: "a", v: 1 },
        { id: "b", v: 1 },
      ]),
      layer([{ id: "b", v: 0 }]),
    ]),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 1,
    quarantine: { deleted_in_newer_layer: 2 },
  });
  expect(await a.keys()).toEqual(["a", "x"]);
  expect(
    await a.db.query("SELECT record_key, stamp_r FROM log_tombstones"),
  ).toEqual([{ record_key: "b", stamp_r: "seed" }]);
});

it("fold-a-newer-layer-that-holds-the-key-live-outranks-an-older-delete", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [
      layer([{ id: "b", v: "revived" }]),
      layer([], [{ id: "b" }]),
      layer([{ id: "b", v: "old" }]),
    ]),
  );
  expect(result).toMatchObject({ kind: "imported", tombstoned: 0 });
  expect(await bodies(a)).toEqual({ b: '{"id":"b","v":"revived"}' });
  expect(await a.db.query("SELECT * FROM log_tombstones")).toEqual([]);
});

it("fold-a-deletion-for-a-key-the-stream-holds-writes-no-tombstone", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [layer([{ id: "C" }], [{ id: "A" }, { id: "Z" }])]),
  );
  // A is held by a real write: the seed never changes it. Z is not held.
  expect(result).toMatchObject({ kind: "imported", tombstoned: 1 });
  expect(await a.keys()).toEqual(["A", "B", "C"]);
  expect(
    await a.db.query<{ record_key: string }>(
      "SELECT record_key FROM log_tombstones",
    ),
  ).toEqual([{ record_key: "Z" }]);
});

it("fold-a-key-deleted-live-stays-deleted-whatever-the-layers-hold", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  await a.importSource("files", (base) =>
    foldLayers(base, [
      layer([{ id: "A" }, { id: "B", v: "old" }, { id: "C" }]),
    ]),
  );
  expect(await a.keys()).toEqual(["B", "C"]);
  expect(await bodies(a)).toMatchObject({ B: '{"id":"B"}' });
});

it("fold-a-deletion-with-no-full-key-is-counted-not-written", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [layer([{ id: "A" }], [{ nope: 1 }, null, { id: "Z" }])]),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 1,
    quarantine: { deletion_missing_key_field: 1, deletion_not_an_object: 1 },
  });
});

it("fold-replay-adds-nothing", async () => {
  const w = await world();
  const a = await w.device("a");
  const build = (base: Parameters<Parameters<typeof a.importSource>[1]>[0]) =>
    foldLayers(base, [
      layer([{ id: "a", v: 2 }], [{ id: "b" }]),
      layer([
        { id: "a", v: 1 },
        { id: "b", v: 1 },
      ]),
    ]);
  expect((await a.importSource("files", build)).kind).toBe("imported");
  const before = {
    rows: await a.db.query("SELECT * FROM records"),
    changes: await a.db.query("SELECT * FROM record_changes"),
    tombstones: await a.db.query("SELECT * FROM log_tombstones"),
  };
  expect(await a.importSource("files", build)).toMatchObject({
    kind: "already-imported",
  });
  expect({
    rows: await a.db.query("SELECT * FROM records"),
    changes: await a.db.query("SELECT * FROM record_changes"),
    tombstones: await a.db.query("SELECT * FROM log_tombstones"),
  }).toEqual(before);
});

it("fold-an-unreadable-newer-row-leaves-the-older-copy-standing", async () => {
  const w = await world();
  const a = await w.device("a");
  const cyclic: Record<string, unknown> = { id: "b", v: "new" };
  cyclic["self"] = cyclic;
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [
      layer([{ id: "a", v: 1n }, cyclic, { id: "c", v: "new-c" }]),
      layer([
        { id: "a", v: "old-a" },
        { id: "b", v: "old-b" },
        { id: "c", v: "old-c" },
      ]),
    ]),
  );
  // The newer copies of a and b have no JSON form. They claim nothing, so the
  // older copies stand; c is readable in the newer layer and wins there.
  expect(result).toMatchObject({
    kind: "imported",
    quarantine: { unserializable_body: 2, superseded: 1 },
  });
  expect(await bodies(a)).toEqual({
    a: '{"id":"a","v":"old-a"}',
    b: '{"id":"b","v":"old-b"}',
    c: '{"id":"c","v":"new-c"}',
  });
});

// A v1-full row names its operation in `$pdpp.record`. A delete holds the
// key (`record.key`) and its payload still carries the key fields.
const deleteEnvelope = (
  id: string,
  extra: { sourceId?: string; claim?: unknown; op?: string } = {},
) => ({
  id,
  $pdpp: {
    version: 1,
    sourceId: extra.sourceId ?? SOURCE,
    record: {
      key: "claim" in extra ? extra.claim : { id },
      op: extra.op ?? "delete",
    },
  },
});

it("fold-a-v1-full-delete-envelope-hides-older-rows-and-writes-a-seed-tombstone", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(
      base,
      [
        layer([tagged("n", "new"), deleteEnvelope("b")]),
        layer([tagged("a", "mid"), tagged("b", "mid-b")]),
        layer([tagged("b", "old-b"), tagged("c", "old-c")]),
      ],
      { sourceId: SOURCE },
    ),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 1,
    quarantine: { deleted_in_newer_layer: 2 },
  });
  expect(await a.keys()).toEqual(["a", "c", "n"]);
  expect(
    await a.db.query("SELECT record_key, stamp_o, stamp_r FROM log_tombstones"),
  ).toEqual([{ record_key: "b", stamp_o: 0, stamp_r: "seed" }]);
  // Another copy's seed cannot bring it back.
  await a.seed("another-install", ["b"]);
  expect(await a.keys()).toEqual(["a", "c", "n"]);
});

it("fold-a-v1-full-upsert-envelope-is-a-row-and-an-unknown-op-is-counted", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(
      base,
      [
        layer([
          deleteEnvelope("u", { op: "upsert" }),
          deleteEnvelope("p", { op: "patch" }),
        ]),
      ],
      { sourceId: SOURCE },
    ),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 0,
    quarantine: { unknown_op: 1 },
  });
  expect(await a.keys()).toEqual(["u"]);
});

it("fold-a-delete-envelope-of-another-source-or-with-a-wrong-key-claim-deletes-nothing", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(
      base,
      [
        layer([
          deleteEnvelope("x", { sourceId: "urn:other" }),
          deleteEnvelope("y", { claim: { id: "not-y" } }),
          deleteEnvelope("z", { claim: "z" }),
        ]),
        layer([tagged("x", "kept"), tagged("y", "kept"), tagged("z", "kept")]),
      ],
      { sourceId: SOURCE },
    ),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 0,
    quarantine: {
      source_mismatch: 1,
      deletion_record_key_mismatch: 1,
      deletion_not_an_object: 1,
    },
  });
  expect(await a.keys()).toEqual(["x", "y", "z"]);
});

it("fold-a-live-row-in-the-same-or-a-newer-layer-outranks-a-v1-full-delete", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(
      base,
      [
        layer([tagged("k", "revived")]),
        layer([deleteEnvelope("k"), tagged("m", "same-layer-live")]),
        layer([deleteEnvelope("m"), tagged("k", "old")]),
      ],
      { sourceId: SOURCE },
    ),
  );
  expect(result).toMatchObject({ kind: "imported", tombstoned: 0 });
  expect(await bodies(a)).toEqual({
    k: '{"id":"k","v":"revived"}',
    m: '{"id":"m","v":"same-layer-live"}',
  });
});
