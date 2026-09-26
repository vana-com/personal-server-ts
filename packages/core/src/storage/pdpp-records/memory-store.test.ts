import { describe, it, expect } from "vitest";
import { createMemoryRecordStore } from "./memory-store.js";
import { decodeCursor, encodeCursor, type CursorPayload } from "./cursor.js";
import { InvalidCursorError, type PdppRecordEnvelopeInput } from "./types.js";

function messagesSemantics() {
  return "append_only" as const;
}
function messagesPk() {
  return ["id"];
}

function playlistsSemantics() {
  return "mutable_state" as const;
}
function playlistsPk() {
  return ["id"];
}

describe("memory record store: ingest", () => {
  it("ingests an append_only record and makes it readable", () => {
    const store = createMemoryRecordStore();
    const envelope: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_1",
      data: { id: "msg_1", content: "hi" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const result = store.ingestBatch([envelope], messagesSemantics, messagesPk);
    expect(result.accepted).toBe(1);
    expect(result.rejected).toEqual([]);
    const record = store.getRecord("inst_1", "messages", "msg_1");
    expect(record?.data).toEqual({ id: "msg_1", content: "hi" });
    expect(record?.version).toBe(1);
  });

  it("rejects an envelope whose key does not match data's primary key", () => {
    const store = createMemoryRecordStore();
    const envelope: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "wrong_key",
      data: { id: "msg_1", content: "hi" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const result = store.ingestBatch([envelope], messagesSemantics, messagesPk);
    expect(result.accepted).toBe(0);
    expect(result.rejected).toHaveLength(1);
    expect(store.getRecord("inst_1", "messages", "msg_1")).toBeUndefined();
  });

  it("is a no-op (not an error) for a duplicate key on an append_only stream", () => {
    const store = createMemoryRecordStore();
    const envelope: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_1",
      data: { id: "msg_1", content: "hi" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    store.ingestBatch([envelope], messagesSemantics, messagesPk);
    const second = store.ingestBatch(
      [{ ...envelope, data: { id: "msg_1", content: "changed" } }],
      messagesSemantics,
      messagesPk,
    );
    expect(second.accepted).toBe(0); // duplicate key on append_only: no-op, not a write
    const record = store.getRecord("inst_1", "messages", "msg_1");
    // append_only duplicate must not overwrite existing content.
    expect(record?.data.content).toBe("hi");
    expect(record?.version).toBe(1);
  });

  it("allocates monotonic versions on mutable_state upsert", () => {
    const store = createMemoryRecordStore();
    const base: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "playlists",
      key: "pl_1",
      data: { id: "pl_1", name: "v1" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    store.ingestBatch([base], playlistsSemantics, playlistsPk);
    store.ingestBatch(
      [
        {
          ...base,
          data: { id: "pl_1", name: "v2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const record = store.getRecord("inst_1", "playlists", "pl_1");
    expect(record?.version).toBe(2);
    expect(record?.data.name).toBe("v2");
  });

  it("does not leave partial state when one envelope in a batch is invalid", () => {
    const store = createMemoryRecordStore();
    const good: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_1",
      data: { id: "msg_1", content: "hi" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const bad: PdppRecordEnvelopeInput = {
      instance: "inst_1",
      stream: "messages",
      key: "msg_2",
      data: { id: "different", content: "bad" },
      emitted_at: "2026-04-01T00:00:00.000Z",
    };
    const result = store.ingestBatch(
      [good, bad],
      messagesSemantics,
      messagesPk,
    );
    expect(result.accepted).toBe(1);
    expect(result.rejected).toEqual([{ index: 1, reason: expect.any(String) }]);
    expect(store.getRecord("inst_1", "messages", "msg_1")).toBeDefined();
    expect(store.getRecord("inst_1", "messages", "msg_2")).toBeUndefined();
  });
});

describe("memory record store: delete + tombstones", () => {
  it("produces a spec-shaped tombstone on owner delete", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const deleted = store.deleteRecord(
      "inst_1",
      "playlists",
      "pl_1",
      "2026-04-02T00:00:00.000Z",
      "mutable_state",
    );
    expect(deleted).toBe(true);
    expect(store.getRecord("inst_1", "playlists", "pl_1")).toBeUndefined();
  });

  it("rejects delete on an append_only stream", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    const deleted = store.deleteRecord(
      "inst_1",
      "messages",
      "msg_1",
      "2026-04-02T00:00:00.000Z",
      "append_only",
    );
    expect(deleted).toBe(false);
  });

  it("rejects an explicit delete directive for an append_only stream at ingest", () => {
    const store = createMemoryRecordStore();
    const result = store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: null,
          emitted_at: "2026-04-01T00:00:00.000Z",
          op: "delete",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    expect(result.accepted).toBe(0);
    expect(result.rejected).toHaveLength(1);
  });
});

describe("memory record store: list records", () => {
  it("clamps and paginates with a stable cursor", () => {
    const store = createMemoryRecordStore();
    const envelopes: PdppRecordEnvelopeInput[] = Array.from(
      { length: 3 },
      (_, i) => ({
        instance: "inst_1",
        stream: "messages",
        key: `msg_${i}`,
        data: { id: `msg_${i}`, n: i },
        emitted_at: `2026-04-0${i + 1}T00:00:00.000Z`,
      }),
    );
    store.ingestBatch(envelopes, messagesSemantics, messagesPk);

    const page1 = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 2,
      order: "asc",
    });
    expect(page1.data).toHaveLength(2);
    expect(page1.hasMore).toBe(true);
    expect(page1.nextCursor).toBeDefined();

    const page2 = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 2,
      order: "asc",
      cursor: page1.nextCursor,
    });
    expect(page2.data).toHaveLength(1);
    expect(page2.hasMore).toBe(false);
  });

  it("rejects a cursor reused against a different order", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_2",
          data: { id: "msg_2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    const page1 = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 1,
      order: "asc",
    });
    expect(() =>
      store.listRecords("messages", {
        instanceIds: ["inst_1"],
        limit: 1,
        order: "desc",
        cursor: page1.nextCursor,
      }),
    ).toThrow();
  });

  it("never exposes an unprojected field through fields projection", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "msg_1",
          data: { id: "msg_1", a: "visible", b: "visible", c: "secret" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      messagesSemantics,
      messagesPk,
    );
    const page = store.listRecords("messages", {
      instanceIds: ["inst_1"],
      limit: 10,
      order: "asc",
      fields: ["id", "a", "b"],
    });
    expect(page.data[0].data).not.toHaveProperty("c");
  });
});

describe("memory record store: changes_since", () => {
  it("rejects invalid changes_since page offsets", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      ["a", "b", "c"].map((key) => ({
        instance: "inst_1",
        stream: "playlists",
        key,
        data: { id: key },
        emitted_at: "2026-04-01T00:00:00.000Z",
      })),
      playlistsSemantics,
      playlistsPk,
    );
    const page = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 1,
    });
    const payload = decodeCursor(page.nextCursor!);
    const forgeOffset = (offset: unknown) =>
      encodeCursor({ ...payload, offset } as CursorPayload);

    for (const offset of [
      "1",
      "abc",
      -1,
      1.5,
      null,
      "9007199254740993",
      9007199254740992,
    ]) {
      expect(() =>
        store.changesSince("playlists", {
          instanceIds: ["inst_1"],
          limit: 1,
          cursor: forgeOffset(offset),
        }),
      ).toThrow(InvalidCursorError);
    }
    expect(
      store.changesSince("playlists", {
        instanceIds: ["inst_1"],
        limit: 1,
        cursor: forgeOffset(1),
      }).data,
    ).toHaveLength(1);
  });

  it("returns all current records on a first-ever sync", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const page = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
    });
    expect(page.data).toHaveLength(1);
    expect(page.hasMore).toBe(false);
    expect(page.nextChangesSince).toBeDefined();
  });

  it("does not leak writes made after page 1 into later pages of the same session", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_2",
          data: { id: "pl_2", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );

    const page1 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 1,
    });
    expect(page1.hasMore).toBe(true);
    expect(page1.nextCursor).toBeDefined();

    // A write happens after page 1 was served but before page 2 is fetched.
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_3",
          data: { id: "pl_3", name: "brand new" },
          emitted_at: "2026-04-03T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );

    const page2 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
      cursor: page1.nextCursor,
    });
    const keys = page2.data.map((r) => r.recordKey);
    expect(keys).not.toContain("pl_3");
  });

  it("surfaces the new write in the next session via next_changes_since", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const session1 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
    });
    expect(session1.nextChangesSince).toBeDefined();

    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );

    const session2 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
      changesSince: session1.nextChangesSince,
    });
    expect(session2.data).toHaveLength(1);
    expect(session2.data[0].recordKey).toBe("pl_1");
  });

  it("does not surface a record whose only change is outside the field projection", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", a: "1", c: "secret1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const session1 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
      fields: ["id", "a"],
    });

    // Only field `c` (unauthorized) changes.
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", a: "1", c: "secret2" },
          emitted_at: "2026-04-02T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );

    const session2 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
      fields: ["id", "a"],
      changesSince: session1.nextChangesSince,
    });
    expect(session2.data).toHaveLength(0);
  });

  it("surfaces a tombstone for a deletion to a cursor predating it", () => {
    const store = createMemoryRecordStore();
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "playlists",
          key: "pl_1",
          data: { id: "pl_1", name: "v1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      playlistsSemantics,
      playlistsPk,
    );
    const session1 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
    });

    store.deleteRecord(
      "inst_1",
      "playlists",
      "pl_1",
      "2026-04-02T00:00:00.000Z",
      "mutable_state",
    );

    const session2 = store.changesSince("playlists", {
      instanceIds: ["inst_1"],
      limit: 10,
      changesSince: session1.nextChangesSince,
    });
    expect(session2.data).toHaveLength(1);
    expect(session2.data[0].deleted).toBe(true);
  });

  it("throws CursorExpiredError for a malformed changes_since token", () => {
    const store = createMemoryRecordStore();
    expect(() =>
      store.changesSince("playlists", {
        instanceIds: ["inst_1"],
        limit: 10,
        changesSince: "not-a-real-cursor",
      }),
    ).toThrow();
  });
});
