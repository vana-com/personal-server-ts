import { afterEach, beforeEach, describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { PdppBindingError } from "./pdpp-records-sqlite-store.js";

const SOURCE = "https://registry.pdpp.dev/connectors/spotify";
const METHOD = "spotify";
const EMITTED_AT = "2026-09-28T00:00:00.000Z";

function connectionStore() {
  const db = new Database(":memory:");
  const store = createSqliteRecordStore(db);
  return { db, store };
}

describe("PDPP connection registry", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;

  beforeEach(() => {
    ({ db, store } = connectionStore());
  });

  afterEach(() => {
    store.close();
    db.close();
  });

  it("stores same-source accounts under separate instance ids", () => {
    const accountA = "spotify:0xowner";
    const accountB = "conn_123e4567-e89b-42d3-a456-426614174000";
    store.registerConnection({
      instance: accountA,
      sourceId: SOURCE,
      method: METHOD,
      label: "Personal",
    });
    store.registerConnection({
      instance: accountB,
      sourceId: SOURCE,
      method: METHOD,
      label: "Work",
    });

    const write = (instance: string, title: string) =>
      store.ingestBatch(
        [
          {
            instance,
            stream: "playlists",
            key: "same-key",
            data: { id: "same-key", title },
            emitted_at: EMITTED_AT,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      );
    expect(write(accountA, "A").accepted).toBe(1);
    expect(write(accountB, "B").accepted).toBe(1);
    expect(store.getRecord(accountA, "playlists", "same-key")?.data.title).toBe(
      "A",
    );
    expect(store.getRecord(accountB, "playlists", "same-key")?.data.title).toBe(
      "B",
    );
    expect(
      store.listConnections(SOURCE).map(({ instance }) => instance),
    ).toEqual([accountB, accountA].sort());
  });

  it("does not bind a new connection id from its first write", () => {
    const unregistered = "conn_123e4567-e89b-42d3-a456-426614174099";
    expect(() =>
      store.ingestBatch(
        [
          {
            instance: unregistered,
            stream: "playlists",
            key: "one",
            data: { id: "one" },
            emitted_at: EMITTED_AT,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      ),
    ).toThrowError(new PdppBindingError("connection_required"));
    expect(store.getRecord(unregistered, "playlists", "one")).toBeUndefined();
  });

  it("keeps a registered connection's method fixed across reset", () => {
    const account = "conn_123e4567-e89b-42d3-a456-426614174000";
    store.registerConnection({
      instance: account,
      sourceId: SOURCE,
      method: METHOD,
      label: "Personal",
    });
    store.ingestBatch(
      [
        {
          instance: account,
          stream: "playlists",
          key: "one",
          data: { id: "one" },
          emitted_at: EMITTED_AT,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: METHOD, generation: 1 },
    );

    expect(() =>
      store.resetInstanceBinding({
        instance: account,
        expectedMethod: METHOD,
        expectedGeneration: 1,
        nextMethod: "another-method",
      }),
    ).toThrowError(new PdppBindingError("connection_conflict"));
    expect(store.getRecord(account, "playlists", "one")).toBeDefined();
    expect(store.getInstanceBinding(account)).toMatchObject({
      method: METHOD,
      generation: 1,
    });
  });

  it("keeps A's rows when B replaces its stream snapshot", () => {
    const accountA = "conn_123e4567-e89b-42d3-a456-426614174000";
    const accountB = "conn_123e4567-e89b-42d3-a456-426614174001";
    for (const [instance, title] of [
      [accountA, "A"],
      [accountB, "B"],
    ]) {
      store.registerConnection({
        instance,
        sourceId: SOURCE,
        method: METHOD,
        label: title,
      });
      store.replaceStream({
        instance,
        stream: "playlists",
        method: METHOD,
        generation: 1,
        emittedAt: EMITTED_AT,
        primaryKey: ["id"],
        envelopes: [
          {
            instance,
            stream: "playlists",
            key: "same-key",
            data: { id: "same-key", title },
            emitted_at: EMITTED_AT,
          },
        ],
      });
    }
    store.replaceStream({
      instance: accountB,
      stream: "playlists",
      method: METHOD,
      generation: 1,
      emittedAt: "2026-09-29T00:00:00.000Z",
      primaryKey: ["id"],
      envelopes: [],
    });
    expect(store.getRecord(accountA, "playlists", "same-key")?.data.title).toBe(
      "A",
    );
    expect(store.getRecord(accountB, "playlists", "same-key")).toBeUndefined();
  });

  it("deletes only that connection's rows and keeps a re-registration tombstone", () => {
    const accountA = "conn_123e4567-e89b-42d3-a456-426614174000";
    const accountB = "conn_123e4567-e89b-42d3-a456-426614174001";
    for (const [instance, label] of [
      [accountA, "A"],
      [accountB, "B"],
    ]) {
      store.registerConnection({
        instance,
        sourceId: SOURCE,
        method: METHOD,
        label,
      });
      store.ingestBatch(
        [
          {
            instance,
            stream: "playlists",
            key: "one",
            data: { id: "one", label },
            emitted_at: EMITTED_AT,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      );
    }
    const deleted = store.deleteConnection(accountA);
    expect(deleted.deletedAt).toBeTruthy();
    expect(store.getRecord(accountA, "playlists", "one")).toBeUndefined();
    expect(store.getRecord(accountB, "playlists", "one")?.data.label).toBe("B");
    expect(() =>
      store.registerConnection({
        instance: accountA,
        sourceId: SOURCE,
        method: METHOD,
        label: "A",
      }),
    ).toThrowError(new PdppBindingError("connection_deleted"));
    expect(() =>
      store.ingestBatch(
        [
          {
            instance: accountA,
            stream: "playlists",
            key: "two",
            data: { id: "two" },
            emitted_at: EMITTED_AT,
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      ),
    ).toThrowError(new PdppBindingError("connection_deleted"));
  });

  it("keeps blob bytes claimed by B when A is deleted", () => {
    const accountA = "conn_123e4567-e89b-42d3-a456-426614174000";
    const accountB = "conn_123e4567-e89b-42d3-a456-426614174001";
    for (const [instance, label] of [
      [accountA, "A"],
      [accountB, "B"],
    ]) {
      store.registerConnection({
        instance,
        sourceId: SOURCE,
        method: METHOD,
        label,
      });
    }
    const bytes = new TextEncoder().encode("shared image");
    const uploadedA = store.storeBlobBytesForInstance({
      instance: accountA,
      method: METHOD,
      generation: 1,
      bytes,
      mimeType: "image/png",
    });
    const uploadedB = store.storeBlobBytesForInstance({
      instance: accountB,
      method: METHOD,
      generation: 1,
      bytes,
      mimeType: "image/png",
    });
    expect(uploadedB.blobId).toBe(uploadedA.blobId);
    store.deleteConnection(accountA);
    expect(store.getBlobBytes(uploadedA.blobId)).toEqual(bytes);
    expect(
      db
        .prepare("SELECT instance FROM pdpp_blob_claims WHERE blob_id = ?")
        .all(uploadedA.blobId),
    ).toEqual([{ instance: accountB }]);
  });
});
