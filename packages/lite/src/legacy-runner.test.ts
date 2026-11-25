import { expect, it } from "vitest";
import type { SeedIntake } from "@opendatalabs/personal-server-ts-core/localdb";
import { createLiteLegacyStoreRunner } from "./legacy-runner.js";

// The runner's retirement decisions, over in-memory scope storage and a
// recording seed intake.

const manifest = JSON.stringify({
  connector_key: "spotify",
  version: "1",
  streams: [
    { name: "saved_tracks", semantics: "mutable_state", primary_key: ["id"] },
  ],
});

type Versions = Map<string, { collectedAt: string; body: unknown }[]>;

function memoryStorage(scopes: Versions) {
  return {
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
    deleteScope: async (scope: string) => {
      scopes.delete(scope);
    },
  } as never;
}

function recordingIntake() {
  const receipts = new Set<string>();
  const imported: string[] = [];
  const intake: SeedIntake = {
    status: async () => ({
      targetKnown: true,
      streams: Object.fromEntries(
        [...receipts].map((stream) => [stream, { state: "merged" as const }]),
      ),
    }),
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

function runner(scopes: Versions, intake: SeedIntake) {
  return createLiteLegacyStoreRunner({
    storage: memoryStorage(scopes),
    intake: async () => intake,
    manifests: () => [manifest],
    retireLegacy: () => true,
  });
}

it("keeps a scope whose older version the import skipped", async () => {
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

it("a second wake never deletes an alias whose rows were not imported", async () => {
  const scopes: Versions = new Map([
    ["spotify.saved_tracks", [version([{ id: "canonical" }])]],
    ["spotify.savedTracks", [version([{ id: "alias" }])]],
  ]);
  const { intake, imported } = recordingIntake();
  const live = runner(scopes, intake);
  const signal = new AbortController().signal;
  await live.run(signal);
  await live.run(signal);
  expect(imported).toEqual(["canonical"]);
  // Either every row of both scopes is imported, or the alias is kept.
  expect(imported.includes("alias") || scopes.has("spotify.savedTracks")).toBe(
    true,
  );
  expect(scopes.has("spotify.saved_tracks")).toBe(false);
});

it("retires a scope it imported itself", async () => {
  const scopes: Versions = new Map([
    ["spotify.saved_tracks", [version([{ id: "a" }])]],
  ]);
  const { intake } = recordingIntake();
  await runner(scopes, intake).run(new AbortController().signal);
  expect(scopes.size).toBe(0);
});
