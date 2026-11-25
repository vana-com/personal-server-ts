import { expect, it } from "vitest";
import type { SeedIntake } from "@opendatalabs/personal-server-ts-core/localdb";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { createLiteLegacyStoreRunner } from "./legacy-runner.js";

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

function recordingIntake(deleted: readonly string[] = []) {
  const receipts = new Set<string>();
  const imported: string[] = [];
  const intake: SeedIntake = {
    status: async (connector: string) => {
      if (deleted.includes(connector))
        throw new ProtocolError(
          410,
          "CONNECTION_DELETED",
          "The connection was deleted",
        );
      return {
        targetKnown: true,
        streams: Object.fromEntries(
          [...receipts].map((stream) => [stream, { state: "merged" as const }]),
        ),
      };
    },
    put: async (_connector, stream, body) => {
      const decoder = new TextDecoder();
      let text = "";
      for await (const chunk of body) text += decoder.decode(chunk);
      const lines = text.trim().split("\n").slice(1);
      for (const line of lines) imported.push(JSON.parse(line).id);
      receipts.add(stream);
      return { state: "staged", records: lines.length, invalid: 0 };
    },
  } as never;
  return { intake, imported };
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
