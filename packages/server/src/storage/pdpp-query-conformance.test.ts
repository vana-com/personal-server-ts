import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createPdppSyncSessionService,
  type PdppRecordStore,
  type SyncRequest,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";

for (const backend of ["memory", "sqlite"])
  describe(`${backend} snapshot and temporal sync`, () => {
    const create = (): PdppRecordStore =>
      backend === "memory"
        ? createMemoryRecordStore()
        : createTestBoundRecordStore(new Database(":memory:"));
    const write = (
      store: PdppRecordStore,
      key: string,
      day: number,
      at = "2026-01-02",
      instance = "inst_1",
    ) =>
      store.ingestBatch(
        [
          {
            instance,
            stream: "events",
            key,
            data: { id: key, at, name: `day-${day}` },
            emitted_at: `2026-04-0${day}T00:00:00.000Z`,
          },
        ],
        () => "mutable_state",
        () => ["id"],
      );
    it.each(["asc", "desc"] as const)(
      "freezes a complete list under mutations (%s)",
      (order) => {
        const store = create();
        try {
          ["a", "b", "c"].forEach((key, i) => write(store, key, i + 1));
          const options = { instanceIds: ["inst_1"], limit: 1, order };
          const first = store.listRecords("events", options);
          write(store, "a", 4);
          write(store, "b", 5);
          write(store, "d", 6);

          const rows = [...first.data];
          let cursor = first.nextCursor;
          for (let n = 0; cursor && n < 10; n++) {
            const page = store.listRecords("events", { ...options, cursor });
            rows.push(...page.data);
            cursor = page.nextCursor;
          }
          expect(rows.map((r) => r.recordKey)).toEqual(
            order === "asc" ? ["a", "b", "c"] : ["c", "b", "a"],
          );
          expect(rows.find((r) => r.recordKey === "b")?.data.name).toBe(
            "day-2",
          );
        } finally {
          store.close();
        }
      },
    );
    it("uses one code-point identity ordering for list and sync", () => {
      const store = create();
      try {
        const keys = ["z", "a", "A", "ä", "é", "e\u0301", "\uE000", "😀"];
        keys.forEach((key) => write(store, key, 1));
        const expected = ["A", "a", "e\u0301", "z", "ä", "é", "\uE000", "😀"];
        const options = { instanceIds: ["inst_1"], limit: 100 };
        expect(
          store
            .listRecords("events", { ...options, order: "asc" })
            .data.map((r) => r.recordKey),
        ).toEqual(expected);
        expect(
          createPdppSyncSessionService(store)
            .read({ stream: "events", ...options })
            .data.map((r) => r.recordKey),
        ).toEqual(expected);
      } finally {
        store.close();
      }
    });
    it("continues tied rows from separate instances", () => {
      const store = create();
      try {
        write(store, "a", 1);
        write(store, "a", 1, undefined, "inst_2");
        const options = {
          instanceIds: ["inst_1", "inst_2"],
          limit: 1,
          order: "asc" as const,
        };
        const first = store.listRecords("events", options);
        const second = store.listRecords("events", {
          ...options,
          cursor: first.nextCursor,
        });
        expect([...first.data, ...second.data].map((r) => r.instance)).toEqual([
          "inst_1",
          "inst_2",
        ]);
      } finally {
        store.close();
      }
    });
    it("emits deletion only for a record visible at the previous time-filtered horizon", () => {
      const store = create();
      try {
        write(store, "visible", 1);
        write(store, "hidden", 1, "2025-01-01");
        const options: SyncRequest = {
          stream: "events",
          instanceIds: ["inst_1"],
          limit: 100,
          eligibilityFields: ["id"],
          access: {
            canSeeKey: () => true,
            canSeeRecord: (row) => row.data.at === "2026-01-02",
          },
          candidate: { binding: "test", order: "asc" },
        };
        const baseline = createPdppSyncSessionService(store).read({
          stream: "events",
          ...options,
        });
        expect(baseline.data.map((r) => r.recordKey)).toEqual(["visible"]);
        for (const key of ["visible", "hidden"])
          store.deleteRecord(
            "inst_1",
            "events",
            key,
            "2026-04-02T00:00:00Z",
            "mutable_state",
          );
        const changes = createPdppSyncSessionService(store).read({
          stream: "events",
          ...options,
          changesSince: baseline.nextChangesSince,
        });
        expect(
          changes.data.map((r) => ({ key: r.recordKey, deleted: r.deleted })),
        ).toEqual([{ key: "visible", deleted: true }]);
        expect(
          createPdppSyncSessionService(store).read({
            stream: "events",
            ...options,
          }).data,
        ).toEqual([]);
      } finally {
        store.close();
      }
    });
    it("evaluates time-window transitions even when disclosed fields are unchanged", () => {
      const store = create();
      try {
        write(store, "enter", 1, "2025-01-01");
        write(store, "leave", 1);
        const options: SyncRequest = {
          stream: "events",
          instanceIds: ["inst_1"],
          limit: 100,
          eligibilityFields: ["id"],
          access: {
            canSeeKey: () => true,
            canSeeRecord: (row) => row.data.at === "2026-01-02",
          },
          candidate: { binding: "test", order: "asc" },
        };
        const baseline = createPdppSyncSessionService(store).read({
          stream: "events",
          ...options,
        });
        write(store, "enter", 2);
        write(store, "leave", 2, "invalid");
        const changes = createPdppSyncSessionService(store).read({
          stream: "events",
          ...options,
          changesSince: baseline.nextChangesSince,
        });
        expect(
          changes.data.map((r) => ({ key: r.recordKey, deleted: r.deleted })),
        ).toEqual([
          { key: "enter", deleted: false },
          { key: "leave", deleted: true },
        ]);
      } finally {
        store.close();
      }
    });
  });

it("old list cursors lacking complete identity explicitly expire rather than duplicate a row", async () => {
  const { decodeCursor, encodeCursor, CursorExpiredError } =
    await import("@opendatalabs/personal-server-ts-core/storage/pdpp-records");
  for (const store of [
    createMemoryRecordStore(),
    createTestBoundRecordStore(new Database(":memory:")),
  ]) {
    try {
      for (const key of ["a", "b"])
        store.ingestBatch(
          [
            {
              instance: "inst_1",
              stream: "events",
              key,
              data: { id: key },
              emitted_at: "2026-04-01T00:00:00Z",
            },
          ],
          () => "mutable_state",
          () => ["id"],
        );
      const options = {
        instanceIds: ["inst_1"],
        limit: 1,
        order: "asc" as const,
      };
      const first = store.listRecords("events", options);
      const payload = decodeCursor(first.nextCursor!);
      if (payload.kind !== "list") throw Error("expected list cursor");
      delete payload.instance;
      expect(() =>
        store.listRecords("events", {
          ...options,
          cursor: encodeCursor(payload),
        }),
      ).toThrow(CursorExpiredError);
    } finally {
      store.close();
    }
  }
});

const stores = () => [
  createMemoryRecordStore(),
  createTestBoundRecordStore(new Database(":memory:")),
];
const put = (
  store: PdppRecordStore,
  key: string,
  emittedAt: string,
  data: Record<string, unknown> = { id: key },
) =>
  store.ingestBatch(
    [
      {
        instance: "inst_1",
        stream: "events",
        key,
        data,
        emitted_at: emittedAt,
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );
const traverse = (
  store: PdppRecordStore,
  options: { instanceIds: string[]; limit: number; order: "asc" | "desc" },
  between: (page: number) => void = () => {},
) => {
  const first = store.listRecords("events", options);
  const rows = [...first.data];
  let cursor = first.nextCursor;
  for (let n = 1; cursor && n < 20; n++) {
    between(n);
    const page = store.listRecords("events", { ...options, cursor });
    rows.push(...page.data);
    cursor = page.nextCursor;
  }
  return rows;
};

it.each([false, true])(
  "withholds only a record erased after the first page and completes the listing (reinserted: %s)",
  (reinsert) => {
    for (const store of stores()) {
      try {
        for (const key of ["a", "b", "c"])
          put(store, key, "2026-04-01T00:00:00Z", { id: key, v: "old" });
        const rows = traverse(
          store,
          { instanceIds: ["inst_1"], limit: 1, order: "asc" },
          (page) => {
            if (page !== 1) return;
            expect(
              store.deleteRecord(
                "inst_1",
                "events",
                "b",
                "2026-04-02T00:00:00Z",
                "mutable_state",
              ),
            ).toBe(true);
            if (reinsert)
              put(store, "b", "2026-04-01T00:00:00Z", { id: "b", v: "new" });
          },
        );
        // The erased version is never served; the rest of the snapshot is.
        expect(rows.map((r) => [r.recordKey, r.data.v])).toEqual([
          ["a", "old"],
          ["c", "old"],
        ]);
      } finally {
        store.close();
      }
    }
  },
);

it("ends a listing cleanly when the only remaining record is erased", () => {
  for (const store of stores()) {
    try {
      for (const key of ["a", "b"]) put(store, key, "2026-04-01T00:00:00Z");
      const options = {
        instanceIds: ["inst_1"],
        limit: 1,
        order: "asc" as const,
      };
      const first = store.listRecords("events", options);
      store.deleteRecord(
        "inst_1",
        "events",
        "b",
        "2026-04-02T00:00:00Z",
        "mutable_state",
      );
      const second = store.listRecords("events", {
        ...options,
        cursor: first.nextCursor,
      });
      expect(second.data).toEqual([]);
      expect(second.hasMore).toBe(false);
      expect(second.nextCursor).toBeUndefined();
    } finally {
      store.close();
    }
  }
});

it.each(["asc", "desc"] as const)(
  "orders a listing by emitted instant, not timestamp text (%s)",
  (order) => {
    // Instant order: z0 < z0.1 < z0.1000001 < plus2 (08:00Z) == utc8 < utc9.
    const emitted: Record<string, string> = {
      utc9: "2026-01-01T09:00:00Z",
      plus2: "2026-01-01T10:00:00+02:00",
      utc8: "2026-01-01T08:00:00.000Z",
      z01: "2026-01-01T00:00:00.1Z",
      z0: "2026-01-01T00:00:00Z",
      z010: "2026-01-01T00:00:00.1000001Z",
    };
    const ascending = ["z0", "z01", "z010", "plus2", "utc8", "utc9"];
    for (const store of stores()) {
      try {
        for (const [key, at] of Object.entries(emitted)) put(store, key, at);
        for (const limit of [1, 2, 100]) {
          const rows = traverse(store, {
            instanceIds: ["inst_1"],
            limit,
            order,
          });
          expect(rows.map((r) => r.recordKey)).toEqual(
            order === "asc" ? ascending : [...ascending].reverse(),
          );
          // The stored spelling is served unchanged.
          expect(rows.find((r) => r.recordKey === "plus2")?.emittedAt).toBe(
            emitted.plus2,
          );
        }
      } finally {
        store.close();
      }
    }
  },
);

it("expires a list cursor minted under timestamp-text order instead of resuming it by instant", async () => {
  const { encodeCursor, CursorExpiredError } =
    await import("@opendatalabs/personal-server-ts-core/storage/pdpp-records");
  for (const store of stores()) {
    try {
      // Text order put A (09:00Z) before B ("10:00+02:00", 08:00Z): a
      // pre-v13 build served A first and left B unread.
      put(store, "a", "2026-01-01T09:00:00Z");
      put(store, "b", "2026-01-01T10:00:00+02:00");
      const options = {
        instanceIds: ["inst_1"],
        limit: 1,
        order: "asc" as const,
      };
      const fresh = store.listRecords("events", options);
      const { decodeCursor } =
        await import("@opendatalabs/personal-server-ts-core/storage/pdpp-records");
      const minted = decodeCursor(fresh.nextCursor!);
      if (minted.kind !== "list") throw Error("expected list cursor");
      // The same position as an older build minted it: no order revision.
      const legacy = {
        kind: "list" as const,
        stream: minted.stream,
        epoch: minted.epoch,
        horizon: minted.horizon,
        order: "asc" as const,
        sortValue: "2026-01-01T09:00:00Z",
        recordKey: "a",
        instance: "inst_1",
      };
      expect(() =>
        store.listRecords("events", {
          ...options,
          cursor: encodeCursor(legacy),
        }),
      ).toThrow(CursorExpiredError);
      // A cursor this build mints still resumes.
      expect(
        store
          .listRecords("events", { ...options, cursor: fresh.nextCursor })
          .data.map((r) => r.recordKey),
      ).toEqual(["a"]);
    } finally {
      store.close();
    }
  }
});
