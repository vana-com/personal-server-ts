import { expect, it } from "vitest";
import {
  createLegacyScopeStore,
  type LegacyScopeExclusionReason,
  type LegacyScopeTarget,
} from "./legacy-scope-store.js";

const manifestOf = (connector: string, stream: string) =>
  JSON.stringify({
    connector_key: connector,
    version: "1",
    streams: [
      { name: stream, semantics: "mutable_state", primary_key: ["id"] },
    ],
  });

type Versions = Map<string, { collectedAt: string; body: unknown }[]>;

const storageOf = (scopes: Versions) =>
  ({
    listScopes: () => ({
      scopes: [...scopes.keys()].map((scope) => ({ scope })),
    }),
    listVersions: (scope: string) =>
      (scopes.get(scope) ?? []).map((v, id) => ({
        collectedAt: v.collectedAt,
        id,
      })),
    readEnvelope: async (scope: string, collectedAt: string) => ({
      data: scopes.get(scope)!.find((v) => v.collectedAt === collectedAt)!.body,
    }),
  }) as never;

const tagged = (sourceId: string, id: string) => ({
  id,
  $pdpp: { sourceId },
});
const layer = (rows: unknown[], collectedAt: string) => ({
  collectedAt,
  body: { records: rows },
});

const A = { connector: "a", stream: "items", sourceId: "urn:a" };
const B = { connector: "b", stream: "items", sourceId: "urn:b" };

async function enumerate(
  scopes: Versions,
  manifests: string[],
  targets: LegacyScopeTarget[] = [A, B],
) {
  const excluded: LegacyScopeExclusionReason[] = [];
  const store = createLegacyScopeStore({
    storage: storageOf(scopes),
    manifests: () => manifests,
    targets: new Map([["shared.items", targets]]),
    onExcluded: ({ reason }) => excluded.push(reason),
  });
  const streams = [];
  for await (const stream of store.streams()) streams.push(stream);
  return { streams, excluded };
}

it("rows of connector A are never seeded into B when only B's manifest is retained", async () => {
  const scopes: Versions = new Map([
    ["shared.items", [layer([tagged("urn:a", "1")], "2026-11-01T00:00:00Z")]],
  ]);
  const { streams, excluded } = await enumerate(scopes, [
    manifestOf("b", "items"),
  ]);
  expect(streams).toEqual([]);
  expect(excluded).toEqual(["unknown_source"]);
});

it("two retained connectors sharing a scope: the stored source id picks one", async () => {
  const scopes: Versions = new Map([
    ["shared.items", [layer([tagged("urn:b", "1")], "2026-11-01T00:00:00Z")]],
  ]);
  const { streams } = await enumerate(scopes, [
    manifestOf("a", "items"),
    manifestOf("b", "items"),
  ]);
  expect(streams.map((s) => [s.connector, s.sourceId])).toEqual([
    ["b", "urn:b"],
  ]);
});

it("an older layer with another source id excludes the scope", async () => {
  const scopes: Versions = new Map([
    [
      "shared.items",
      [
        layer([tagged("urn:b", "2")], "2026-11-02T00:00:00Z"),
        layer([tagged("urn:a", "1")], "2026-11-01T00:00:00Z"),
      ],
    ],
  ]);
  const { streams, excluded } = await enumerate(scopes, [
    manifestOf("b", "items"),
  ]);
  expect(streams).toEqual([]);
  expect(excluded).toEqual(["source_conflict"]);
});

it("untagged rows keep the declaration-only choice", async () => {
  const scopes: Versions = new Map([
    ["shared.items", [layer([{ id: "1" }], "2026-11-01T00:00:00Z")]],
  ]);
  const { streams } = await enumerate(scopes, [manifestOf("b", "items")]);
  expect(streams.map((s) => [s.connector, s.sourceId])).toEqual([
    ["b", undefined],
  ]);
});

it("one declaration snapshot serves a whole enumeration", async () => {
  let reads = 0;
  const scopes: Versions = new Map([
    ["shared.items", [layer([{ id: "1" }], "2026-11-01T00:00:00Z")]],
  ]);
  const store = createLegacyScopeStore({
    storage: storageOf(scopes),
    manifests: () => {
      reads += 1;
      return [manifestOf("b", "items")];
    },
    targets: new Map([["shared.items", [A, B]]]),
  });
  for await (const _ of store.streams());
  expect(reads).toBe(1);
});

it("a manifest with a keyless stream is rejected whole: its keyed sibling has no declaration either", async () => {
  const mixed = JSON.stringify({
    connector_key: "a",
    version: "1",
    streams: [
      { name: "items", semantics: "mutable_state", primary_key: ["id"] },
      { name: "loose", semantics: "mutable_state", primary_key: [] },
    ],
  });
  const { streams, excluded } = await enumerate(
    new Map([
      ["shared.items", [layer([{ id: "1" }], "2026-11-01T00:00:00.000Z")]],
    ]),
    [mixed],
    [A],
  );
  expect(streams).toEqual([]);
  expect(excluded).toEqual(["no_declaration"]);
});

it("a stop between storage reads ends the scan of excluded scopes at once", async () => {
  const other = tagged("urn:other", "1");
  const scopes: Versions = new Map(
    ["shared.items", "shared.two", "shared.three"].map((scope) => [
      scope,
      [
        layer([other], "2026-11-01T00:00:00.000Z"),
        layer([other], "2026-11-02T00:00:00.000Z"),
      ],
    ]),
  );
  const reads: string[] = [];
  const controller = new AbortController();
  const storage = storageOf(scopes) as unknown as {
    readEnvelope: (scope: string, at: string) => Promise<unknown>;
  };
  const read = storage.readEnvelope;
  storage.readEnvelope = async (scope, at) => {
    reads.push(`${scope}@${at}`);
    controller.abort();
    return read(scope, at);
  };
  const store = createLegacyScopeStore({
    storage: storage as never,
    manifests: () => [manifestOf("a", "items")],
    targets: new Map(
      ["shared.items", "shared.two", "shared.three"].map((scope) => [
        scope,
        [A, { ...A, connector: "a2" }],
      ]),
    ),
    signal: controller.signal,
  });
  await expect(async () => {
    for await (const _ of store.streams());
  }).rejects.toThrow();
  expect(reads).toHaveLength(1);
});
