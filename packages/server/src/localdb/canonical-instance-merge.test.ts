import { afterEach, expect, it } from "vitest";
import type {
  ImportInventoryEntry,
  ImportSource,
} from "../../../core/src/localdb/index.js";
import {
  createCanonicalImportSource,
  type CanonicalImportPageReader,
} from "./canonical-import-source.js";
import { connectionId, drivers, owner, world } from "./late-seed-harness.js";

// Two live instances of one source hold overlapping keys with different
// bodies. The newest instance's body wins on every device, whatever order the
// devices or the submissions run in: the merged source is one source whose
// layers have a rank, not two sources whose arrival order decides.

afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

const SOURCE_ID = "urn:fixture";
type Rows = Record<string, Record<string, unknown>[]>;

/** A fake canonical store: `instances` by name, newest first by `lastActive`. */
function store(
  rows: Rows,
  lastActive: Record<string, number>,
  deleted: Record<string, string[]> = {},
  gone: string[] = [],
) {
  const reader: CanonicalImportPageReader = {
    declarations: [
      {
        source_id: SOURCE_ID,
        source_kind: "connector",
        version: "1",
        digest: "digest",
        streams: [
          {
            name: "items",
            primary_key: ["id"],
            fields: ["id"],
            required_fields: ["id"],
          },
        ],
      } as CanonicalImportPageReader["declarations"][number],
    ],
    async *inventory() {
      for (const instance of Object.keys(rows).sort())
        yield {
          sourceId: SOURCE_ID,
          instance,
          stream: "items",
          rows: rows[instance]!.length,
        };
    },
    async assertRevision() {},
    async connections() {
      return Object.keys(rows).map((instance) => ({
        instance,
        deleted: gone.includes(instance),
        lastActive: lastActive[instance]!,
      }));
    },
    async rows(instance) {
      return rows[instance]!.length;
    },
    async deletedKeys(instance, _stream, after) {
      const keys = (deleted[instance] ?? [])
        .filter((k) => after === null || k > after)
        .sort();
      return { keys, next: null };
    },
    async page(instance, _stream, after) {
      const all = [...rows[instance]!].sort((a, b) =>
        String(a["id"]).localeCompare(String(b["id"])),
      );
      const page = all.filter((r) => after === null || String(r["id"]) > after);
      return { rows: page.slice(0, 100), next: null };
    },
  };
  return reader;
}

async function entries(
  reader: CanonicalImportPageReader,
  olderInstances: "merge" | "exclude" = "merge",
) {
  const out: ImportInventoryEntry[] = [];
  for await (const entry of createCanonicalImportSource({
    owner,
    network: "test",
    revision: "rev",
    bindings: new Map([
      [
        "fixture.items",
        {
          connector: "fixture",
          streams: ["items"],
          primaryKey: { items: ["id"] },
        },
      ],
    ]),
    reader,
    olderInstances,
    resolveTarget: async () => ({
      connectionId,
      connector: "fixture",
      stream: "items",
      primaryKey: ["id"],
      semantics: "mutable_state",
      incremental: true,
    }),
  }))
    out.push(entry);
  return out;
}
const sources = (all: ImportInventoryEntry[]) =>
  all.filter((e): e is ImportSource => !("kind" in e));

const NEW = [
  { id: "a", v: "new" },
  { id: "b", v: "new" },
];
const OLD = [
  { id: "b", v: "old" },
  { id: "c", v: "old" },
];
const UNION = {
  a: '{"id":"a","v":"new"}',
  b: '{"id":"b","v":"new"}',
  c: '{"id":"c","v":"old"}',
};
const bodies = async (device: { snapshot(): Promise<unknown[]> }) =>
  Object.fromEntries(
    (await device.snapshot()).map((r) => [
      (r as { record_key: string }).record_key,
      (r as { body: string }).body,
    ]),
  );

it("merged-instances-are-one-source-and-the-newest-body-wins", async () => {
  const reader = store({ old: OLD, new: NEW }, { old: 10, new: 20 });
  const all = await entries(reader);
  expect(all).toHaveLength(1);
  const w = await world();
  const a = await w.device("a");
  expect(await a.importEntry(sources(all)[0]!)).toMatchObject({
    kind: "imported",
    quarantine: { superseded: 1 },
  });
  expect(await bodies(a)).toEqual(UNION);
  expect(sources(all)[0]!.rows).toBe(4);
});

it("T2: the result follows instance rank, not arrival, on two devices in both orders", async () => {
  const w = await world();
  const reader = store({ old: OLD, new: NEW }, { old: 10, new: 20 });
  const a = await w.device("a");
  const b = await w.device("b");
  // The merged source is the same however often or whenever it is submitted.
  for (const device of [a, b, a]) {
    const [merged] = sources(await entries(reader));
    await device.importEntry(merged!);
  }
  expect(await bodies(a)).toEqual(UNION);
  expect(await bodies(b)).toEqual(UNION);
  // Another world, the instances' activity swapped: the other body wins, by rank.
  const w2 = await world();
  const c = await w2.device("c");
  const flipped = store({ old: OLD, new: NEW }, { old: 30, new: 20 });
  await c.importEntry(sources(await entries(flipped))[0]!);
  expect(await bodies(c)).toEqual({
    ...UNION,
    b: '{"id":"b","v":"old"}',
  });
});

it("T2 negative control: two separate sources let arrival decide, which is why instances merge", async () => {
  const reader = store({ old: OLD, new: NEW }, { old: 10, new: 20 });
  // One source per instance, each its own layer alone: submitted old-first the
  // older body stays (an import never replaces a held key).
  const layerOnly = (instance: "old" | "new"): ImportSource => ({
    source: JSON.stringify([instance]),
    owner,
    network: "test",
    revision: "rev",
    target: {
      connectionId,
      connector: "fixture",
      stream: "items",
      primaryKey: ["id"],
      semantics: "mutable_state",
      incremental: true,
    },
    exclusions: [],
    async *records() {
      const page = await reader.page(
        instance,
        "items",
        null,
        100,
        1 << 20,
        "rev",
      );
      yield* page.rows;
    },
  });
  const w = await world();
  const oldFirst = await w.device("old-first");
  await oldFirst.importEntry(layerOnly("old"));
  await oldFirst.importEntry(layerOnly("new"));
  const newFirst = await w.device("new-first");
  await newFirst.importEntry(layerOnly("new"));
  await newFirst.importEntry(layerOnly("old"));
  expect((await bodies(oldFirst))["b"]).toBe('{"id":"b","v":"old"}');
  expect((await bodies(newFirst))["b"]).toBe('{"id":"b","v":"new"}');
});

it("a key the newest instance deleted stays out of the merge and is tombstoned", async () => {
  const reader = store(
    { old: OLD, new: NEW },
    { old: 10, new: 20 },
    { new: ["c"] },
  );
  const w = await world();
  const a = await w.device("a");
  expect(await a.importEntry(sources(await entries(reader))[0]!)).toMatchObject(
    {
      kind: "imported",
      tombstoned: 1,
      quarantine: { deleted_in_newer_layer: 1 },
    },
  );
  expect(await a.keys()).toEqual(["a", "b"]);
});

it("a deleted connection's rows are never merged", async () => {
  const reader = store({ old: OLD, new: NEW }, { old: 10, new: 20 }, {}, [
    "old",
  ]);
  const all = await entries(reader);
  expect(all.map((e) => ("kind" in e ? e.reason : "source"))).toEqual([
    "source",
    "deleted_instance",
  ]);
  const w = await world();
  const a = await w.device("a");
  await a.importEntry(sources(all)[0]!);
  expect(await bodies(a)).toEqual({
    a: '{"id":"a","v":"new"}',
    b: '{"id":"b","v":"new"}',
  });
});

it("olderInstances exclude keeps today's behaviour: the newest instance only", async () => {
  const reader = store({ old: OLD, new: NEW }, { old: 10, new: 20 });
  const all = await entries(reader, "exclude");
  expect(all.map((e) => ("kind" in e ? e.reason : "source"))).toEqual([
    "source",
    "older_instance",
  ]);
});
