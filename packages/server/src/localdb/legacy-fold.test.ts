import { afterEach, expect, it } from "vitest";
import { foldLayers, type FoldLayer } from "../../../core/src/localdb/index.js";
import { drivers, state, world } from "./late-seed-harness.test-utils.js";

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
        'outcomes:{"quarantined":{"missing_key_field":1,"source_mismatch":1,"superseded":3,"untagged":1}}',
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
// key (`record.key`) and its payload still carries the key fields. The
// envelope is complete (`sync/pdpp-import.ts` reads the same fields) and names
// the stream it belongs to.
const meta = (
  record: { key: unknown; op: string },
  over: Record<string, unknown> = {},
  primaryKey: readonly string[] = ["id"],
) => ({
  version: 1,
  sourceId: SOURCE,
  declaration: { digest: "digest", version: "1" },
  stream: { name: "items", scope: "items", primaryKey },
  record,
  ...over,
});
const deleteEnvelope = (
  id: string,
  extra: { sourceId?: string; claim?: unknown; op?: string } = {},
) => ({
  id,
  $pdpp: meta(
    {
      key: "claim" in extra ? extra.claim : { id },
      op: extra.op ?? "delete",
    },
    extra.sourceId === undefined ? {} : { sourceId: extra.sourceId },
  ),
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
      // A claim that is no key object leaves the envelope incomplete.
      deletion_envelope_incomplete: 1,
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

it("fold-layers-collide-by-legacy-record-key-not-by-typed-key", async () => {
  const w = await world();
  const a = await w.device("a");
  // `{id: 42}` and `{id: "42"}` are one legacy record key, `42`. The newest
  // layer's row stands; the import must not see both.
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [
      layer([
        { id: 42, v: "new" },
        { id: "7", v: "only-new" },
      ]),
      layer([
        { id: "42", v: "old" },
        { id: "9", v: "only-old" },
      ]),
    ]),
  );
  expect(result).toMatchObject({
    kind: "imported",
    quarantine: { superseded: 1 },
  });
  expect(await bodies(a)).toEqual({
    "42": '{"id":42,"v":"new"}',
    "7": '{"id":"7","v":"only-new"}',
    "9": '{"id":"9","v":"only-old"}',
  });
});

it("fold-an-identical-repeat-of-a-record-key-is-a-duplicate-and-a-typed-delete-hides-an-older-row", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [
      layer(
        [
          { id: 5, v: "first" },
          { id: 5, v: "first" },
        ],
        [{ id: "6" }],
      ),
      layer([{ id: 6, v: "old-six" }]),
    ]),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 1,
    quarantine: { duplicate_key: 1, deleted_in_newer_layer: 1 },
  });
  expect(await bodies(a)).toEqual({ "5": '{"id":5,"v":"first"}' });
});

it("fold-a-typed-delete-keeps-hiding-the-record-key-from-a-later-separate-seed", async () => {
  const w = await world();
  const a = await w.device("a");
  // The newer layer deletes `"6"` (string); the older layer holds `6` (number).
  // They are one record key, so the fold hides the row and tombstones the key.
  await a.importSource("files", (base) =>
    foldLayers(base, [
      layer([{ id: "5", v: "five" }], [{ id: "6" }]),
      layer([{ id: 6, v: "old-six" }]),
    ]),
  );
  // Another install's upload holds the key in the other type. The tombstone
  // covers the record key, not one typed hash of it.
  const later = await a.importSource("other", (base) => ({
    ...base,
    async *records() {
      yield { id: 6, v: "again" };
      yield { id: 7, v: "seven" };
    },
  }));
  expect(later).toMatchObject({ kind: "imported" });
  expect(await bodies(a)).toEqual({
    "5": '{"id":"5","v":"five"}',
    "7": '{"id":7,"v":"seven"}',
  });
  const reverse = await a.importSource("third", (base) => ({
    ...base,
    async *records() {
      yield { id: "6", v: "string" };
    },
  }));
  expect(reverse).toMatchObject({ kind: "imported" });
  expect(Object.keys(await bodies(a))).toEqual(["5", "7"]);
});

it("fold-a-live-row-in-another-type-fills-nothing-and-is-not-a-conflict", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("live", ["7"]);
  // The seed holds the same record key as a number. Live wins: the row is
  // left out, not refused as a key-type conflict, and a seed deletion of it
  // tombstones nothing.
  const result = await a.importSource("files", (base) => ({
    ...base,
    async *records() {
      yield { id: 7, v: "old" };
      yield { id: 8, v: "eight" };
    },
    async *deletions() {
      yield { id: 7 };
    },
  }));
  expect(result).toMatchObject({ kind: "imported", tombstoned: 0 });
  expect(Object.keys(await bodies(a))).toEqual(["7", "8"]);
  expect(await a.db.query("SELECT 1 FROM log_tombstones")).toEqual([]);
});

it("fold-every-stored-record-is-imported-or-counted-once: legacy = imported + counted", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("live", ["g"]); // the stream already holds `g`
  const newest = [
    tagged("g", "old-g"), // blocked: a live row holds the key
    tagged("a", "live"), // imported
    deleteEnvelope("a"), // a delete a live row of its own layer shadows
    deleteEnvelope("b"), // a delete the older layer's row is hidden by
    deleteEnvelope("b"), // a repeat of that delete
    deleteEnvelope("d", { claim: { id: "not-d" } }), // a wrong key claim
    deleteEnvelope("e", { op: "patch" }), // an unknown op
    { v: "no key", $pdpp: { sourceId: SOURCE } }, // no identity
    { id: "x", v: "untagged" }, // no source
    tagged("f", "first"),
    tagged("f", "first"), // an identical repeat in one layer
  ];
  const older = [
    tagged("a", "old"), // superseded
    tagged("b", "old-b"), // hidden by the delete above
    tagged("c", "old-c"), // imported
  ];
  const stored = newest.length + older.length;
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [layer(newest), layer(older)], { sourceId: SOURCE }),
  );
  if (result.kind !== "imported") throw new Error(result.kind);
  const counted = Object.values(result.quarantine).reduce((n, v) => n + v, 0);
  expect(result.quarantine).toMatchObject({ delete_envelope: 3 });
  expect(result.blocked).toBe(1);
  // legacy = imported + blocked + quarantined (no stream is refused here).
  const imported = result.receipt.rows - result.blocked;
  expect(imported).toBe(3); // a, c and f
  expect(stored).toBe(imported + result.blocked + counted);
  expect(await a.keys()).toEqual(["a", "c", "f", "g"]);
});

const compound = (base: Parameters<typeof foldLayers>[0]) => ({
  ...base,
  target: { ...base.target, primaryKey: ["tenant", "id"] },
});
const tenantRow = (tenant: string, id: number, v: string) => ({
  tenant,
  id,
  v,
  $pdpp: { sourceId: SOURCE },
});

it("fold-a-delete-whose-payload-disagrees-with-its-claim-on-any-key-field-deletes-nothing", async () => {
  const w = await world();
  const a = await w.device("a");
  // The payload names tenant B but claims A/1: a partial payload must not
  // pass for a claim it contradicts.
  const forged = {
    tenant: "B",
    $pdpp: meta({ key: { tenant: "A", id: 1 }, op: "delete" }, {}, [
      "tenant",
      "id",
    ]),
  };
  const honest = {
    tenant: "A",
    $pdpp: meta({ key: { tenant: "A", id: 2 }, op: "delete" }, {}, [
      "tenant",
      "id",
    ]),
  };
  const result = await a.importSource("files", (base) =>
    foldLayers(
      compound(base),
      [
        layer([forged, honest]),
        layer([tenantRow("A", 1, "keep"), tenantRow("A", 2, "gone")]),
      ],
      { sourceId: SOURCE },
    ),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 1,
    quarantine: {
      deletion_record_key_mismatch: 1,
      delete_envelope: 1,
      deleted_in_newer_layer: 1,
    },
  });
  expect(Object.keys(await bodies(a))).toEqual(['["A","1"]']);
});

it("fold-a-delete-yields-only-its-key-fields", async () => {
  const fold = foldLayers(
    {
      source: "s",
      owner: "o",
      network: "test",
      revision: "r",
      target: {
        connectionId: "c",
        connector: "fixture",
        stream: "items",
        primaryKey: ["id"],
        semantics: "mutable_state",
        incremental: true,
      },
      exclusions: [],
    },
    [
      layer([
        {
          id: "a",
          big: "x".repeat(1000),
          $pdpp: meta({ key: { id: "a" }, op: "delete" }),
        },
      ]),
      layer([tagged("b", "older")], undefined),
    ],
    { sourceId: SOURCE },
  );
  const kept: unknown[] = [];
  for await (const key of fold.deletions!()) kept.push(key);
  expect(kept).toEqual([{ id: "a" }]);
});

it("fold-conflicting-repeats-of-a-key-in-one-layer-refuse-the-stream-as-the-direct-importer-does", async () => {
  const w = await world();
  const rows = [
    { id: "r", v: "one", $pdpp: { sourceId: SOURCE } },
    { id: "r", v: "two", $pdpp: { sourceId: SOURCE } },
  ];
  const direct = await (
    await w.device("direct")
  ).importSource("files", (base) => ({
    ...base,
    async *records() {
      yield* rows.map(({ $pdpp: _p, ...row }) => row);
    },
  }));
  expect(direct).toMatchObject({ kind: "refused", reason: "invalid_record" });
  // A second live layer must not turn that into a first-row-wins import.
  for (const [index, layers] of [
    [layer(rows)],
    [layer(rows), layer([tagged("older", "x")])],
    // The conflict is among copies a newer layer already outranks: still a
    // conflict in that layer's own file.
    [layer([tagged("r", "new")]), layer(rows)],
  ].entries()) {
    const a = await w.device(`fold-${index}`);
    const result = await a.importSource("files", (base) =>
      foldLayers(base, layers, { sourceId: SOURCE }),
    );
    expect(result).toMatchObject({ kind: "refused", reason: "invalid_record" });
    expect(await a.keys()).toEqual([]);
  }
});

it("an identical repeat of a row is counted by the direct importer too", async () => {
  const w = await world();
  const a = await w.device("a");
  const result = await a.importSource("files", (base) => ({
    ...base,
    async *records() {
      yield { id: "r", v: "same" };
      yield { id: "r", v: "same" };
    },
  }));
  expect(result).toMatchObject({
    kind: "imported",
    quarantine: { duplicate_key: 1 },
  });
});

// A delete envelope in the old store is a claim about the old store. A delete
// that has already landed here decides first: the import never contradicts it.
const tombstones = (
  device: Awaited<ReturnType<Awaited<ReturnType<typeof world>>["device"]>>,
) =>
  device.db.query(
    "SELECT record_key, stamp_o, stamp_r FROM log_tombstones WHERE stream = 'items' ORDER BY record_key",
  );
const envelopeLayers = () => [
  layer([deleteEnvelope("A")]),
  layer([tagged("A", "old"), tagged("B", "old-b")]),
];

it.each([
  [
    "a connection that was deleted",
    "UPDATE connections SET deleted_at = 1, control_state = 'deleted' WHERE connection_id = 'pdpp.fixture~'",
  ],
  [
    "a connection whose delete is landing",
    "INSERT INTO delete_intents (connector, delete_id, intent) VALUES ('fixture', 'd1', 'delete')",
  ],
])(
  "a delete-envelope import into %s is refused and writes no row and no tombstone",
  async (_name, sql) => {
    const w = await world();
    const a = await w.device("a");
    await a.run("real", ["R"]);
    await a.publish();
    await a.db.batch([{ sql }]);
    const result = await a.importSource("files", (base) =>
      foldLayers(base, envelopeLayers(), { sourceId: SOURCE }),
    );
    expect(result).toEqual({ kind: "refused", reason: "connection_deleted" });
    expect(await a.keys()).toEqual(["R"]);
    expect(await tombstones(a)).toEqual([]);
  },
);

it("a delete envelope never replaces the tombstone of a delete that already landed", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  await a.run("delete", ["A"], { remove: true });
  await a.publish();
  const landed = await tombstones(a);
  expect(landed).toMatchObject([{ record_key: "A", stamp_r: "delete" }]);
  const result = await a.importSource("files", (base) =>
    foldLayers(base, envelopeLayers(), { sourceId: SOURCE }),
  );
  expect(result).toMatchObject({ kind: "imported" });
  // The landed tombstone is the only one for the key, with its own stamp; the
  // old row of the key stayed out, and the other key filled.
  expect(await tombstones(a)).toEqual(landed);
  expect(await a.keys()).toEqual(["B"]);
});

it("a delete envelope never removes a row a real write holds", async () => {
  const w = await world();
  const a = await w.device("a");
  await a.run("real", ["A", "B"]);
  await a.publish();
  const before = await state(a);
  const result = await a.importSource("files", (base) =>
    foldLayers(base, envelopeLayers(), { sourceId: SOURCE }),
  );
  expect(result).toMatchObject({ kind: "imported" });
  expect(await state(a)).toEqual(before);
  expect(await tombstones(a)).toEqual([]);
});

it("a primary-key field named __proto__ still writes its tombstone", async () => {
  const w = await world();
  const a = await w.device("a");
  // JSON.parse makes `__proto__` an own property, as a stored row has it.
  const own = (json: string) => JSON.parse(json) as unknown;
  const result = await a.importSource("files", (base) =>
    foldLayers(
      { ...base, target: { ...base.target, primaryKey: ["__proto__"] } },
      [
        layer([
          own(
            `{"__proto__":"a","$pdpp":{"version":1,"sourceId":"${SOURCE}","declaration":{"digest":"d","version":"1"},"stream":{"name":"items","scope":"items","primaryKey":["__proto__"]},"record":{"key":{"__proto__":"a"},"op":"delete"}}}`,
          ),
        ]),
        layer([
          own(`{"__proto__":"a","v":"old","$pdpp":{"sourceId":"${SOURCE}"}}`),
          own(`{"__proto__":"b","v":"kept","$pdpp":{"sourceId":"${SOURCE}"}}`),
        ]),
      ],
      { sourceId: SOURCE },
    ),
  );
  expect(result).toMatchObject({
    kind: "imported",
    tombstoned: 1,
    quarantine: { deleted_in_newer_layer: 1, delete_envelope: 1 },
  });
  expect(await a.keys()).toEqual(["b"]);
  expect(
    await a.db.query(
      "SELECT record_key FROM log_tombstones WHERE stream = 'items'",
    ),
  ).toEqual([{ record_key: "a" }]);
});

it("a key object keeps a field named __proto__ as its own property", async () => {
  const fold = foldLayers(
    {
      source: "s",
      owner: "o",
      network: "test",
      revision: "r",
      target: {
        connectionId: "c",
        connector: "fixture",
        stream: "items",
        primaryKey: ["__proto__", "id"],
        semantics: "mutable_state",
        incremental: true,
      },
      exclusions: [],
    },
    [
      layer(
        [],
        [
          JSON.parse('{"__proto__":"t","id":1}'),
          JSON.parse('{"__proto__":"u","id":2}'),
        ],
      ),
    ],
  );
  const keys: unknown[] = [];
  for await (const key of fold.deletions!()) keys.push(key);
  expect(keys.map((k) => JSON.stringify(k))).toEqual([
    '{"__proto__":"t","id":1}',
    '{"__proto__":"u","id":2}',
  ]);
});

// A delete envelope is destructive, so it applies only when it is complete (the
// fields `sync/pdpp-import.ts` requires), names this stream, and names the full
// key. Anything else is counted out by reason and deletes nothing.
const olderLayers = (envelope: unknown) => [
  layer([envelope, tagged("n", "new")]),
  layer([tagged("b", "kept"), tagged("c", "kept")]),
];

it.each([
  ["no stream", { stream: undefined }, { deletion_envelope_incomplete: 1 }],
  [
    "no declaration",
    { declaration: undefined },
    { deletion_envelope_incomplete: 1 },
  ],
  ["version 2", { version: 2 }, { deletion_envelope_incomplete: 1 }],
  [
    "no stream scope",
    { stream: { name: "items", primaryKey: ["id"] } },
    { deletion_envelope_incomplete: 1 },
  ],
  [
    "another stream",
    { stream: { name: "other", scope: "other", primaryKey: ["id"] } },
    { deletion_stream_mismatch: 1 },
  ],
  [
    "another primary key",
    { stream: { name: "items", scope: "items", primaryKey: ["uuid"] } },
    { deletion_stream_mismatch: 1 },
  ],
])(
  "fold-a-delete-envelope-with-%s-deletes-nothing",
  async (_name, over, counted) => {
    const w = await world();
    const a = await w.device("a");
    const envelope = {
      id: "b",
      $pdpp: meta({ key: { id: "b" }, op: "delete" }, over),
    };
    const result = await a.importSource("files", (base) =>
      foldLayers(base, olderLayers(envelope), { sourceId: SOURCE }),
    );
    expect(result).toMatchObject({
      kind: "imported",
      tombstoned: 0,
      quarantine: counted,
    });
    // The older copy of `b` stands: the envelope did not delete it.
    expect(await a.keys()).toEqual(["b", "c", "n"]);
    expect(await a.db.query("SELECT * FROM log_tombstones")).toEqual([]);
  },
);

it("fold-an-upsert-envelope-for-another-stream-is-counted-not-imported-here", async () => {
  const w = await world();
  const a = await w.device("a");
  const stray = {
    id: "x",
    v: "other stream",
    $pdpp: meta(
      { key: { id: "x" }, op: "upsert" },
      { stream: { name: "other", scope: "other", primaryKey: ["id"] } },
    ),
  };
  const result = await a.importSource("files", (base) =>
    foldLayers(base, [layer([stray, tagged("n", "new")])], {
      sourceId: SOURCE,
    }),
  );
  expect(result).toMatchObject({
    kind: "imported",
    quarantine: { stream_mismatch: 1 },
  });
  expect(await a.keys()).toEqual(["n"]);
});
