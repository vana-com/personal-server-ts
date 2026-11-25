import { expect, it } from "vitest";
import type { SeedIntake } from "@opendatalabs/personal-server-ts-core/localdb";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { createSeedIntake } from "@opendatalabs/personal-server-ts-core/localdb";
import { createLiteLegacyStoreRunner } from "./legacy-runner.js";
import { createPsLiteSeedStaging } from "./seed-staging.js";
import { createMemoryPsLiteStateStore } from "./test-support/memory.js";

// The runner's import decisions, over in-memory scope storage and a
// recording seed intake.

const manifestOf = (connector: string, ...streams: string[]) =>
  JSON.stringify({
    connector_key: connector,
    version: "1",
    streams: streams.map((name) => ({
      name,
      semantics: "mutable_state",
      primary_key: ["id"],
    })),
  });
const manifest = manifestOf("spotify", "saved_tracks", "profile");
const githubManifest = manifestOf("github", "starred");

type Versions = Map<string, { collectedAt: string; body: unknown }[]>;

function memoryStorage(scopes: Versions, reads: string[] = []) {
  return {
    listScopes: () => ({
      scopes: [...scopes.keys()].map((scope) => ({ scope })),
    }),
    listVersions: (scope: string) =>
      (scopes.get(scope) ?? []).map((v, id) => ({
        collectedAt: v.collectedAt,
        id,
      })),
    readEnvelope: async (scope: string, collectedAt: string) => {
      reads.push(`${scope}@${collectedAt}`);
      const found = scopes
        .get(scope)
        ?.find((v) => v.collectedAt === collectedAt);
      if (!found) throw new Error(`missing envelope ${scope}@${collectedAt}`);
      return { data: found.body };
    },
  } as never;
}

const gone = () =>
  new ProtocolError(410, "CONNECTION_DELETED", "The connection was deleted");

function recordingIntake(
  deleted: readonly string[] = [],
  extra: {
    /** Streams holding a pending upload that waits for its target. */
    staged?: Record<string, string>;
    /** Connectors deleted once the run has started: status calls past the
     * first (the runner's preflight) refuse. */
    deletedAfterPreflight?: readonly string[];
    /** Connectors whose `put` refuses as deleted. */
    deletedOnPut?: readonly string[];
  } = {},
) {
  const receipts = new Set<string>();
  const imported: string[] = [];
  const puts: string[] = [];
  const statusCalls = new Map<string, number>();
  const intake: SeedIntake = {
    status: async (connector: string) => {
      if (deleted.includes(connector)) throw gone();
      const calls = (statusCalls.get(connector) ?? 0) + 1;
      statusCalls.set(connector, calls);
      if (calls > 1 && extra.deletedAfterPreflight?.includes(connector))
        throw gone();
      return {
        targetKnown: true,
        streams: {
          ...Object.fromEntries(
            Object.keys(extra.staged ?? {}).map((stream) => [
              stream,
              { state: "staged" as const, records: 1, invalid: 0 },
            ]),
          ),
          ...Object.fromEntries(
            [...receipts].map((stream) => [
              stream,
              { state: "merged" as const },
            ]),
          ),
        },
      };
    },
    put: async (connector, stream, body) => {
      puts.push(`${connector}.${stream}`);
      if (extra.deletedOnPut?.includes(connector)) throw gone();
      const decoder = new TextDecoder();
      let text = "";
      for await (const chunk of body) text += decoder.decode(chunk);
      const lines = text.trim().split("\n").slice(1);
      for (const line of lines) imported.push(JSON.parse(line).id);
      receipts.add(stream);
      return { state: "staged", records: lines.length, invalid: 0 };
    },
  } as never;
  return { intake, imported, puts };
}

const version = (rows: unknown, collectedAt = "2026-11-01T00:00:00.000Z") => ({
  collectedAt,
  body: { records: rows },
});

function runner(
  scopes: Versions,
  intake: SeedIntake,
  options: { reads?: string[] } = {},
) {
  return createLiteLegacyStoreRunner({
    storage: memoryStorage(scopes, options.reads),
    intake: async () => intake,
    manifests: () => [manifest, githubManifest],
  });
}

it("imports the newest rows and leaves an older app-shaped version out", async () => {
  const scopes: Versions = new Map([
    [
      "spotify.saved_tracks",
      [
        version([{ id: "new" }], "2026-11-02T00:00:00.000Z"),
        {
          collectedAt: "2026-11-01T00:00:00.000Z",
          body: { savedTracks: [{ id: "old" }] },
        },
      ],
    ],
  ]);
  const { intake, imported } = recordingIntake();
  const controller = new AbortController();
  await runner(scopes, intake).run(controller.signal);
  expect(imported).toEqual(["new"]);
  expect(scopes.has("spotify.saved_tracks")).toBe(true);
});

it("an app-shaped newest body is left out without reading older versions, and later streams still import", async () => {
  const scopes: Versions = new Map([
    [
      "spotify.saved_tracks",
      [
        {
          collectedAt: "2026-11-02T00:00:00.000Z",
          body: { savedTracks: [{ id: "app" }] },
        },
        // An older version whose envelope is unreadable.
        { collectedAt: "2026-11-01T00:00:00.000Z", body: null },
      ],
    ],
    ["github.starred", [version([{ id: "g1" }], "2026-11-03T00:00:00.000Z")]],
  ]);
  const storage = memoryStorage(scopes, []) as unknown as {
    readEnvelope: (scope: string, at: string) => Promise<unknown>;
  };
  const read = storage.readEnvelope;
  storage.readEnvelope = async (scope, at) => {
    if (at === "2026-11-01T00:00:00.000Z") throw new Error("unreadable");
    return read(scope, at);
  };
  const { intake, imported } = recordingIntake();
  const live = createLiteLegacyStoreRunner({
    storage: storage as never,
    intake: async () => intake,
    manifests: () => [manifest, githubManifest],
  });
  await live.run(new AbortController().signal);
  expect(imported).toEqual(["g1"]);
  expect(live.report()?.streams.excluded).toEqual([
    { reason: "not_stream_rows", scopes: 1 },
  ]);
});

it("a second wake never deletes an alias whose rows were not imported", async () => {
  const scopes: Versions = new Map([
    ["spotify.saved_tracks", [version([{ id: "canonical" }])]],
    ["spotify.savedTracks", [version([{ id: "alias" }])]],
  ]);
  const { intake, imported } = recordingIntake();
  const live = runner(scopes, intake);
  const signal = new AbortController().signal;
  await live.run(signal);
  // The alias was left out in favor of the canonical scope, and is counted.
  expect(live.report()?.streams.excluded).toEqual([
    { reason: "shadowed_alias", scopes: 1 },
  ]);
  await live.run(signal);
  expect(imported).toEqual(["canonical"]);
  // Nothing is removed: both scopes stay.
  expect([...scopes.keys()].sort()).toEqual([
    "spotify.savedTracks",
    "spotify.saved_tracks",
  ]);
});

it("imports a scope and never removes it", async () => {
  const scopes: Versions = new Map([
    ["spotify.saved_tracks", [version([{ id: "a" }])]],
  ]);
  const { intake, imported } = recordingIntake();
  await runner(scopes, intake).run(new AbortController().signal);
  expect(imported).toEqual(["a"]);
  expect(scopes.has("spotify.saved_tracks")).toBe(true);
});

it("a deleted connector is refused and the next connector still imports", async () => {
  const scopes: Versions = new Map([
    ["spotify.saved_tracks", [version([{ id: "s1" }])]],
    ["spotify.profile", [version([{ id: "p1" }])]],
    ["github.starred", [version([{ id: "g1" }])]],
  ]);
  const { intake, imported } = recordingIntake(["spotify"]);
  const live = runner(scopes, intake);
  await live.run(new AbortController().signal);
  expect(imported).toEqual(["g1"]);
  expect(scopes.has("spotify.saved_tracks")).toBe(true);
  expect(scopes.has("github.starred")).toBe(true);
  expect(live.report()?.streams.refused).toEqual([
    { reason: "deleted", streams: 2, rows: 0 },
  ]);
});

it("a second wake reads no history of a completed stream, and its missing old envelope blocks nothing", async () => {
  const scopes: Versions = new Map([
    [
      "spotify.saved_tracks",
      [
        version([{ id: "s1" }], "2026-11-02T00:00:00.000Z"),
        version([{ id: "s0" }], "2026-11-01T00:00:00.000Z"),
      ],
    ],
  ]);
  const reads: string[] = [];
  const { intake, imported } = recordingIntake();
  const live = runner(scopes, intake, { reads });
  const signal = new AbortController().signal;
  await live.run(signal);
  expect(imported.sort()).toEqual(["s0", "s1"]);
  reads.length = 0;
  await live.run(signal);
  expect(reads).toEqual([]);
  // The old envelope is lost; another stream arrives and still imports.
  scopes.get("spotify.saved_tracks")!.pop();
  scopes.set("github.starred", [version([{ id: "g1" }])]);
  await live.run(signal);
  expect(imported).toContain("g1");
  expect(reads.every((r) => r.startsWith("github.starred"))).toBe(true);
});

it("rows stamped with another connector's source id are not imported under the retained one", async () => {
  const scopes: Versions = new Map([
    [
      "spotify.saved_tracks",
      [
        version([
          {
            id: "x",
            $pdpp: { sourceId: "https://registry.pdpp.dev/sources/other" },
          },
        ]),
      ],
    ],
  ]);
  const { intake, imported } = recordingIntake();
  const live = runner(scopes, intake);
  await live.run(new AbortController().signal);
  expect(imported).toEqual([]);
  expect(live.report()?.streams.excluded).toEqual([
    { reason: "unknown_source", scopes: 1 },
  ]);
});

it("rows stamped with the connector's own source id import", async () => {
  const scopes: Versions = new Map([
    [
      "spotify.saved_tracks",
      [
        version([
          {
            id: "x",
            $pdpp: { sourceId: "https://registry.pdpp.dev/sources/spotify" },
          },
        ]),
      ],
    ],
  ]);
  const { intake, imported } = recordingIntake();
  await runner(scopes, intake).run(new AbortController().signal);
  expect(imported).toEqual(["x"]);
});

it("a stream with a pending staged upload is left alone, counted, and its upload is untouched", async () => {
  const scopes: Versions = new Map([
    ["spotify.saved_tracks", [version([{ id: "legacy" }])]],
    ["spotify.profile", [version([{ id: "p1" }])]],
  ]);
  const staged = { saved_tracks: '{"id":"host-seed"}\n' };
  const before = JSON.stringify(staged);
  const { intake, imported, puts } = recordingIntake([], { staged });
  const live = runner(scopes, intake);
  await live.run(new AbortController().signal);
  expect(puts).toEqual(["spotify.profile"]);
  expect(imported).toEqual(["p1"]);
  expect(JSON.stringify(staged)).toBe(before);
  expect(live.report()?.streams.refused).toEqual([
    { reason: "staged_upload_pending", streams: 1, rows: 0 },
  ]);
  expect(scopes.has("spotify.saved_tracks")).toBe(true);
});

it("a host upload that stages while the legacy fold reads survives, and the stream is counted", async () => {
  const scopes: Versions = new Map([
    ["spotify.saved_tracks", [version([{ id: "legacy" }])]],
    ["spotify.profile", [version([{ id: "p1" }])]],
  ]);
  const staging = createPsLiteSeedStaging(
    createMemoryPsLiteStateStore(),
    "0xabc",
    "network",
  );
  // The real intake and staging; the target is not known yet, so an upload
  // waits staged. The writer holds no receipts.
  const intake = createSeedIntake({
    staging,
    writer: {
      importStaged: async () => {},
      seedStatus: async () => ({ targetKnown: false, receipts: {} }),
    },
  });
  const encoder = new TextEncoder();
  const upload = (id: string) =>
    (async function* () {
      yield encoder.encode(
        JSON.stringify({
          primaryKey: ["id"],
          profile: { key: null, version: "1" },
          records: 1,
        }) +
          "\n" +
          JSON.stringify({ id }) +
          "\n",
      );
    })();
  const stagedRows = async () => {
    const rows: unknown[] = [];
    const source = staging.source(await staging.installId(), async () => ({
      receipts: {},
      skipped: [],
    }));
    for await (const row of source.records("spotify", "saved_tracks"))
      rows.push(row);
    return rows;
  };
  // Pause the first stored read: the runner has passed its own pending check.
  let release!: () => void;
  const paused = new Promise<void>((resolve) => (release = resolve));
  let reading!: () => void;
  const started = new Promise<void>((resolve) => (reading = resolve));
  const base = memoryStorage(scopes) as unknown as {
    readEnvelope: (scope: string, at: string) => Promise<unknown>;
  };
  let first = true;
  const storage = {
    ...base,
    listScopes: (base as never as { listScopes: () => unknown }).listScopes,
    listVersions: (base as never as { listVersions: () => unknown })
      .listVersions,
    readEnvelope: async (scope: string, at: string) => {
      if (first && scope === "spotify.saved_tracks") {
        first = false;
        reading();
        await paused;
      }
      return base.readEnvelope(scope, at);
    },
  } as never;
  const live = createLiteLegacyStoreRunner({
    storage,
    intake: async () => intake,
    manifests: () => [manifest, githubManifest],
  });
  const running = live.run(new AbortController().signal);
  await started;
  await intake.put("spotify", "saved_tracks", upload("host-seed"));
  release();
  await running;
  expect(await stagedRows()).toEqual([{ id: "host-seed" }]);
  expect(live.report()?.streams.refused).toContainEqual({
    reason: "staged_upload_pending",
    streams: 1,
    rows: 1,
  });
  // The other stream still imported.
  expect(live.report()?.streams.staged).toBe(1);
});

it("a connection deleted after preflight costs only that connector", async () => {
  for (const extra of [
    { deletedAfterPreflight: ["spotify"] },
    { deletedOnPut: ["spotify"] },
  ]) {
    const scopes: Versions = new Map([
      ["spotify.saved_tracks", [version([{ id: "s1" }])]],
      ["spotify.profile", [version([{ id: "p1" }])]],
      ["github.starred", [version([{ id: "g1" }])]],
    ]);
    const { intake, imported } = recordingIntake([], extra);
    const live = runner(scopes, intake);
    await live.run(new AbortController().signal);
    expect(imported).toEqual(["g1"]);
    // Rows a refused stream held when the producer read it are counted.
    expect(live.report()?.streams).toMatchObject({
      staged: 1,
      refused: [{ reason: "deleted", streams: 2 }],
    });
  }
});

it("stop during a scan of excluded scopes reads nothing more", async () => {
  const scopes: Versions = new Map(
    ["a", "b", "c"].map((name) => [
      `spotify.saved_tracks${name === "a" ? "" : name}`,
      [
        version(
          [{ id: "x", $pdpp: { sourceId: "other" } }],
          "2026-11-01T00:00:00.000Z",
        ),
        version(
          [{ id: "y", $pdpp: { sourceId: "other" } }],
          "2026-11-02T00:00:00.000Z",
        ),
      ],
    ]),
  );
  const reads: string[] = [];
  const controller = new AbortController();
  const storage = memoryStorage(scopes, reads) as unknown as {
    readEnvelope: (scope: string, at: string) => Promise<unknown>;
  };
  const read = storage.readEnvelope;
  storage.readEnvelope = async (scope, at) => {
    const result = await read(scope, at);
    controller.abort();
    return result;
  };
  const { intake } = recordingIntake();
  const live = createLiteLegacyStoreRunner({
    storage: storage as never,
    intake: async () => intake,
    manifests: () => [manifest, githubManifest],
  });
  await live.run(controller.signal).catch(() => {});
  expect(reads).toHaveLength(1);
});
