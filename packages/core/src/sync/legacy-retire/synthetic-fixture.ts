/**
 * A synthetic, real-shaped legacy store for the import / readback / retire
 * flow. Every value is made up; nothing here reads a real data directory.
 *
 * It builds, in memory:
 *   - a stream-sync read service whose registry mirror holds published heads
 *     for four connectors;
 *   - a local legacy store (index rows and envelopes) of five scopes, each
 *     with a known expected outcome (see `SyntheticScope.expect`);
 *   - an importable source with one stream per connector stream.
 *
 * Used by `synthetic-fixture.test.ts`. The legacy body of a scope is the
 * published view's own legacy projection, so a scope that is meant to pass
 * matches the stream by construction; the tampered and fenced scopes are then
 * altered on purpose.
 */

import type { JsonObject } from "@opendatalabs/personal-server-ts-stream-sync";
import { createDataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import type { MemoryDataStorage } from "../../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../../stream-sync-read/service-fixture.js";
import type { StreamSyncReadService } from "../../stream-sync-read/service.js";
import { testOwnerKey } from "../../stream-sync-read/testing.js";
import type { LegacyImportSource, ImportStream } from "./import.js";

export type ExpectedOutcome = "pass" | "fenced" | "tampered" | "empty";

export interface SyntheticScope {
  readonly scope: string;
  readonly connector: string;
  readonly expect: ExpectedOutcome;
  /** Entities in the local legacy file. */
  readonly localEntities: number;
}

export interface SyntheticFixture {
  readonly fixture: Fixture;
  readonly reader: StreamSyncReadService;
  readonly storage: MemoryDataStorage;
  readonly scopes: readonly SyntheticScope[];
  readonly source: LegacyImportSource;
  /** `connector:stream` of the stream that was deleted and re-collected. */
  readonly deletedStream: { connector: string; stream: string };
}

const CHATGPT = "chatgpt";
const GITHUB = "github";
const ICLOUD = "icloud-notes";
const META = "meta";

const COLLECTED_AT = "2026-11-01T00:00:00.000Z";
const T0 = Date.parse("2026-10-30T00:00:00Z");

/** Thousands of records in one scope. */
export const LARGE_SCOPE_RECORDS = 4000;

const pad = (n: number, width = 5) => String(n).padStart(width, "0");

function memories(count: number): JsonObject[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `mem-${pad(i)}`,
    content: `synthetic memory ${i}`,
    created_at: new Date(T0 + i * 1000).toISOString(),
    updated_at: new Date(T0 + i * 1000 + 500).toISOString(),
  }));
}

function events(count: number): JsonObject[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `evt-${pad(i, 3)}`,
    type: i % 2 === 0 ? "PushEvent" : "WatchEvent",
    created_at: new Date(T0 + i * 60_000).toISOString(),
    repository_full_name: `example/repo-${i % 3}`,
    is_public: true,
  }));
}

function folders(count: number): JsonObject[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `folder-${pad(i, 2)}`,
    name: `Synthetic folder ${i}`,
  }));
}

function following(count: number): JsonObject[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `acct-${pad(i, 3)}`,
    username: `user_${pad(i, 3)}`,
    full_name: `Synthetic Person ${i}`,
    is_private: i % 4 === 0,
    is_verified: false,
    profile_pic_url: null,
  }));
}

async function writeLegacy(
  storage: MemoryDataStorage,
  scope: string,
  data: unknown,
): Promise<void> {
  const written = await storage.writeEnvelope(
    createDataFileEnvelope(
      scope,
      COLLECTED_AT,
      data as Record<string, unknown>,
    ),
  );
  await storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: written.relativePath,
    scope,
    collectedAt: COLLECTED_AT,
    sizeBytes: written.sizeBytes,
    afterTombstoneVersion: null,
  });
}

function listItems(body: unknown, key: string): number {
  const list = (body as Record<string, unknown>)[key];
  return Array.isArray(list) ? list.length : 0;
}

export async function buildSyntheticFixture(): Promise<SyntheticFixture> {
  const fixture = new Fixture(await testOwnerKey(masterKey(901)));
  const connectors = [CHATGPT, GITHUB, ICLOUD, META];
  const ns: Record<string, string> = {};
  for (const connector of connectors) {
    ns[connector] = await fixture.key.ns(connector, "synthetic-account");
    await fixture.activate(connector, ns[connector]!);
  }
  const publish = (connector: string, stream: string, records: JsonObject[]) =>
    fixture.publish({
      connector,
      ns: ns[connector]!,
      stream,
      generation: 1,
      records,
    });

  // Published heads: one large scope, small ones, a stream copy to be
  // deleted, and a connector with streams that hold no record.
  const memoryRows = memories(LARGE_SCOPE_RECORDS);
  const eventRows = events(24);
  const folderRows = folders(6);
  const followingRows = following(12);
  await publish(CHATGPT, "memories", memoryRows);
  await publish(GITHUB, "events", eventRows);
  await publish(ICLOUD, "folders", folderRows);
  const followingHead = await publish(META, "following", followingRows);
  await publish(CHATGPT, "conversations", []);
  await publish(CHATGPT, "messages", []);

  const reader = await fixture.service();
  await fixture.sync(reader);

  // The legacy bodies an old install would hold: the projection of what was
  // published before any delete.
  const body = async (scope: string) => {
    const found = await reader.publishedBody(scope);
    if (found === null)
      throw new Error(`fixture: no published body for ${scope}`);
    return found as Record<string, unknown>;
  };
  const memoriesBody = await body("chatgpt.memories");
  const eventsBody = await body("github.events");
  const foldersBody = await body("icloud_notes.folders");
  const followingBody = await body("instagram.following");
  const conversationsBody = await body("chatgpt.conversations");

  // Tampered: the stream copy differs from the legacy file in one record body.
  const tamperedFolders = structuredClone(foldersBody) as {
    folders: { title: string }[];
  };
  tamperedFolders.folders[2]!.title = "Renamed after the legacy file was made";

  // Deleted: the stream was deleted (a tombstone row) and re-collected with
  // fewer records, so the fence drops the older ones from the published view.
  fixture.tombstoneStream(followingHead.scope);
  await fixture.sync(reader); // the reader must see the tombstone row itself
  await publish(META, "following", followingRows.slice(0, 3));
  await fixture.sync(reader);

  const storage = createMemoryDataStorage();
  await writeLegacy(storage, "chatgpt.memories", memoriesBody);
  await writeLegacy(storage, "github.events", eventsBody);
  await writeLegacy(storage, "icloud_notes.folders", tamperedFolders);
  await writeLegacy(storage, "instagram.following", followingBody);
  await writeLegacy(storage, "chatgpt.conversations", conversationsBody);

  const scopes: SyntheticScope[] = [
    {
      scope: "chatgpt.memories",
      connector: CHATGPT,
      expect: "pass",
      localEntities: listItems(memoriesBody, "memories"),
    },
    {
      scope: "github.events",
      connector: GITHUB,
      expect: "pass",
      localEntities: listItems(eventsBody, "events"),
    },
    {
      scope: "icloud_notes.folders",
      connector: ICLOUD,
      expect: "tampered",
      localEntities: listItems(tamperedFolders, "folders"),
    },
    {
      scope: "instagram.following",
      connector: META,
      expect: "fenced",
      localEntities: listItems(followingBody, "accounts"),
    },
    {
      scope: "chatgpt.conversations",
      connector: CHATGPT,
      expect: "empty",
      localEntities: listItems(conversationsBody, "conversations"),
    },
  ];

  const streamRows: Record<string, JsonObject[]> = {
    "chatgpt/memories": memoryRows,
    "github/events": eventRows,
    "icloud-notes/folders": folderRows,
    "meta/following": followingRows,
    "chatgpt/conversations": [],
    "chatgpt/messages": [],
  };
  const source: LegacyImportSource = {
    connectors: async () => connectors,
    streams: async (connector) =>
      Object.entries(streamRows)
        .filter(([key]) => key.startsWith(`${connector}/`))
        .map(([key, rows]): ImportStream => ({
          stream: key.slice(connector.length + 1),
          primaryKey: ["id"],
          profile: { key: connector, version: "1.0.0" },
          async *records() {
            for (const row of rows) yield row;
          },
        })),
  };

  return {
    fixture,
    reader,
    storage,
    scopes,
    source,
    deletedStream: { connector: META, stream: "following" },
  };
}
