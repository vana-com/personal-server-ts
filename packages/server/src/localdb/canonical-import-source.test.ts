import { expect, it } from "vitest";
import {
  createCanonicalImportSource,
  type CanonicalImportPageReader,
} from "./canonical-import-source.js";
import type { ImportSource } from "../../../core/src/localdb/legacy-import-types.js";

function fixture() {
  let changed = false;
  let declarations = true;
  let ambiguous = false;
  let unknown = false;
  const calls: number[] = [];
  const reader: CanonicalImportPageReader = {
    get declarations() {
      return declarations
        ? [
            {
              source_id: "urn:fixture",
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
          ]
        : [];
    },
    async *inventory() {
      yield {
        sourceId: "urn:fixture",
        instance: "local",
        stream: unknown ? "unknown" : "items",
        rows: 2,
      };
    },
    async assertRevision() {
      if (changed) throw new Error("source_changed");
    },
    async connections() {
      return [
        { instance: "local", deleted: false },
        ...(ambiguous ? [{ instance: "other", deleted: false }] : []),
      ];
    },
    async page(_instance, _stream, after, limit, maxBytes) {
      calls.push(maxBytes);
      expect(limit).toBeLessThanOrEqual(128);
      return {
        rows: [{ id: after === null ? "a" : "b" }],
        next: after === null ? "next" : null,
      };
    },
  };
  const options = {
    owner: "owner",
    network: "network",
    revision: "revision",
    reader,
    resolveTarget: async () => ({
      connectionId: "known-control",
      connector: "verified-connector",
      stream: "items",
      primaryKey: ["id"],
      semantics: "mutable_state" as const,
      incremental: true,
    }),
  };
  return {
    reader,
    options,
    calls,
    change() {
      changed = true;
    },
    undeclared() {
      declarations = false;
    },
    ambiguous() {
      ambiguous = true;
    },
    unknown() {
      unknown = true;
    },
  };
}
async function collect<T>(iter: AsyncIterable<T>) {
  const values: T[] = [];
  for await (const value of iter) values.push(value);
  return values;
}
async function source(f: ReturnType<typeof fixture>) {
  return (
    await collect(createCanonicalImportSource(f.options))
  )[0] as ImportSource;
}

it("canonical-verified-declarations-only", async () => {
  const f = fixture();
  f.undeclared();
  expect(await collect(createCanonicalImportSource(f.options))).toMatchObject([
    { kind: "excluded", reason: "undeclared_source", rows: 2 },
  ]);
  expect(f.calls).toEqual([]);
});
it("canonical-limit-pages", async () => {
  const f = fixture();
  const s = await source(f);
  expect(await collect(s.records())).toEqual([{ id: "a" }, { id: "b" }]);
  expect(await collect(s.records())).toEqual([{ id: "a" }, { id: "b" }]);
  expect(f.calls).toEqual(Array(4).fill(4 * 1024 * 1024));
});
it("canonical-ambiguous-instance-holds", async () => {
  const f = fixture();
  f.ambiguous();
  expect(await collect(createCanonicalImportSource(f.options))).toMatchObject([
    { kind: "excluded", reason: "ambiguous_instance" },
  ]);
});
it("canonical-unkeyed-and-undeclared-hold", async () => {
  const f = fixture();
  f.unknown();
  expect(await collect(createCanonicalImportSource(f.options))).toMatchObject([
    { kind: "excluded", reason: "undeclared_stream" },
  ]);
  const g = fixture();
  // Retain a verified snapshot whose stream has no primary key.
  Object.defineProperty(g.reader, "declarations", {
    value: [
      {
        ...g.reader.declarations[0]!,
        streams: [
          { ...g.reader.declarations[0]!.streams[0]!, primary_key: [] },
        ],
      },
    ],
  });
  expect(await collect(createCanonicalImportSource(g.options))).toMatchObject([
    { kind: "excluded", reason: "unkeyed_stream" },
  ]);
});
it("canonical-revision-changed-refuses", async () => {
  const f = fixture();
  const s = await source(f);
  f.change();
  await expect(collect(s.records())).rejects.toThrow("source_changed");
});
it("canonical-oversize-and-invalid-key-refuse", async () => {
  const f = fixture();
  const s = await source(f);
  f.reader.page = async () => ({
    rows: [{ id: "a", body: "x".repeat(4 * 1024 * 1024) }],
    next: null,
  });
  await expect(collect(s.records())).rejects.toThrow("record_or_page_oversize");
  f.reader.page = async () => ({ rows: [{ value: 1 }], next: null });
  await expect(collect(s.records())).rejects.toThrow("invalid_record");
});

it("canonical-revision-change-during-final-page-refuses", async () => {
  const f = fixture();
  const s = await source(f);
  f.reader.page = async () => {
    f.change();
    return { rows: [], next: null };
  };
  await expect(collect(s.records())).rejects.toThrow("source_changed");
});
it("canonical-iteration-is-backpressured", async () => {
  const f = fixture();
  const s = await source(f);
  const iterator = s.records()[Symbol.asyncIterator]();
  expect(f.calls).toHaveLength(0);
  expect((await iterator.next()).value).toEqual({ id: "a" });
  expect(f.calls).toHaveLength(1);
  await iterator.return?.();
  expect(f.calls).toHaveLength(1);
});
it("canonical-unknown-target-holds-without-reading", async () => {
  const f = fixture();
  expect(
    await collect(
      createCanonicalImportSource({
        ...f.options,
        resolveTarget: async () => null,
      }),
    ),
  ).toMatchObject([{ kind: "excluded", reason: "unknown_identity" }]);
  expect(f.calls).toHaveLength(0);
});
