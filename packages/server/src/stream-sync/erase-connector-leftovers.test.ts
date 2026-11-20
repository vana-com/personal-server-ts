import { describe, expect, it } from "vitest";
import { eraseConnectorLeftovers } from "./erase-connector-leftovers.js";

const SOURCE = (key: string) => `https://registry.pdpp.dev/connectors/${key}`;

function fakeStorage() {
  const deleted: string[] = [];
  return {
    deleted,
    storage: {
      deleteScope: async (scope: string) => {
        deleted.push(scope);
        return 0;
      },
    },
  };
}

function fakeRecords(
  connections: Record<string, string[]>,
  sourceIds: string[],
) {
  const erased: string[] = [];
  return {
    erased,
    pdpp: {
      sourceIds,
      store: {
        listConnections: (sourceId: string) =>
          (connections[sourceId] ?? []).map((instance) => ({ instance })),
        deleteConnection: (instance: string) => {
          erased.push(instance);
          return undefined;
        },
      },
    },
  };
}

describe("eraseConnectorLeftovers", () => {
  it("erases the live connections of the connector's sources, and no other connector's", async () => {
    const storage = fakeStorage();
    const records = fakeRecords(
      {
        [SOURCE("oura")]: ["oura-1", "oura-2"],
        [SOURCE("oura-browser")]: ["oura-browser-1"],
        [SOURCE("spotify")]: ["spotify-1"],
      },
      [SOURCE("oura"), SOURCE("oura-browser"), SOURCE("spotify")],
    );
    await eraseConnectorLeftovers("oura", {
      storage: storage.storage,
      pdpp: records.pdpp,
    });
    expect(records.erased).toEqual(["oura-1", "oura-2"]);
  });

  it("erases the legacy scope files the connector's bindings name, and no other connector's", async () => {
    const storage = fakeStorage();
    await eraseConnectorLeftovers("oura", { storage: storage.storage });
    expect(storage.deleted).toEqual(
      expect.arrayContaining(["oura.sleep", "oura.activity"]),
    );
    expect(storage.deleted).not.toContain("spotify.playlists");
  });

  it("with no PDPP records on this host, erases only the legacy files", async () => {
    const storage = fakeStorage();
    await expect(
      eraseConnectorLeftovers("spotify", { storage: storage.storage }),
    ).resolves.toBeUndefined();
    expect(storage.deleted).toContain("spotify.playlists");
  });
});
