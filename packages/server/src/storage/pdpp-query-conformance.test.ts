import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  type PdppRecordStore,
  type ChangesSinceOptions,
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
          store.changesSince("events", options).data.map((r) => r.recordKey),
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
        const options = {
          instanceIds: ["inst_1"],
          limit: 100,
          fields: ["id"],
          isVisible: (row: { data: Record<string, unknown> }) =>
            row.data.at === "2026-01-02",
        } as ChangesSinceOptions;
        const baseline = store.changesSince("events", options);
        expect(baseline.data.map((r) => r.recordKey)).toEqual(["visible"]);
        for (const key of ["visible", "hidden"])
          store.deleteRecord(
            "inst_1",
            "events",
            key,
            "2026-04-02T00:00:00Z",
            "mutable_state",
          );
        const changes = store.changesSince("events", {
          ...options,
          changesSince: baseline.nextChangesSince,
        });
        expect(
          changes.data.map((r) => ({ key: r.recordKey, deleted: r.deleted })),
        ).toEqual([{ key: "visible", deleted: true }]);
        expect(store.changesSince("events", options).data).toEqual([]);
      } finally {
        store.close();
      }
    });
    it("evaluates time-window transitions even when disclosed fields are unchanged", () => {
      const store = create();
      try {
        write(store, "enter", 1, "2025-01-01");
        write(store, "leave", 1);
        const options = {
          instanceIds: ["inst_1"],
          limit: 100,
          fields: ["id"],
          isVisible: (row: { data: Record<string, unknown> }) =>
            row.data.at === "2026-01-02",
        } as ChangesSinceOptions;
        const baseline = store.changesSince("events", options);
        write(store, "enter", 2);
        write(store, "leave", 2, "invalid");
        const changes = store.changesSince("events", {
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

it("expires a listing before disclosing a record erased after its first page", async () => {
  const { CursorExpiredError } =
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
      expect(
        store.deleteRecord(
          "inst_1",
          "events",
          "b",
          "2026-04-02T00:00:00Z",
          "mutable_state",
        ),
      ).toBe(true);
      expect(() =>
        store.listRecords("events", { ...options, cursor: first.nextCursor }),
      ).toThrow(CursorExpiredError);
    } finally {
      store.close();
    }
  }
});
