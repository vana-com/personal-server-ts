import { describe, expect, it, vi } from "vitest";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { RecordQuery } from "../../../core/src/localdb/query.js";
import {
  createLocalRequirements,
  type SinceFieldSource,
} from "../../../core/src/localdb/requirements.js";

type Bodies = Record<string, Record<string, unknown>[]>;

function harness(
  fields: Record<string, string>,
  bodies: Bodies,
  heads: Record<string, number> = {},
) {
  const readHeads = vi.fn(async (sql: string, params?: readonly unknown[]) => {
    expect(sql).toMatch(/SELECT stream, head_version FROM stream_state/);
    expect(sql).toMatch(/WHERE connection_id = \? ORDER BY stream/);
    expect(params).toEqual(["connection-a"]);
    return Object.entries(heads)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([stream, head_version]) => ({ stream, head_version }));
  });
  const deps = { db: { query: readHeads } } as unknown as LocalSyncDeps;
  const sinceFields = vi.fn(async (connectionId: string) => {
    expect(connectionId).toBe("connection-a");
    return fields;
  });
  const source: SinceFieldSource = { sinceFields };
  const listRecords = vi.fn(async (input: Parameters<RecordQuery["listRecords"]>[0]) => {
    expect(input.connectionId).toBe("connection-a");
    expect(input.limit).toBeGreaterThan(0);
    expect(input.limit).toBeLessThanOrEqual(100);
    const all = bodies[input.stream] ?? [];
    const start = input.cursor === undefined ? 0 : Number(input.cursor) + 1;
    const end = Math.min(start + (input.limit ?? 25), all.length);
    return {
      records: all.slice(start, end).map((body, index) => ({
        stream: input.stream,
        recordKey: String(start + index).padStart(4, "0"),
        pkHash: `key-${start + index}`,
        body: JSON.stringify(body),
        emittedAt: 0,
      })),
      nextCursor: end < all.length ? String(end - 1).padStart(4, "0") : null,
    };
  });
  const query: RecordQuery = {
    listRecords,
    async getRecord() {
      throw new Error("Unexpected getRecord");
    },
    async changesSince() {
      throw new Error("Unexpected changesSince");
    },
    async *streamRecords() {
      throw new Error("Unexpected streamRecords");
    },
  };
  return {
    requirements: createLocalRequirements(deps, { query, source }),
    listRecords,
    readHeads,
  };
}

describe("local history requirements", () => {
  it("requirements-min-of-declared-since-field", async () => {
    const bodies: Bodies = {
      amber: Array.from({ length: 102 }, () => ({
        openedDay: "2026-10-01",
        closedDay: "1800-01-01",
      })),
      violet: Array.from({ length: 103 }, () => ({
        closedDay: "2000-02-29",
        openedDay: "not-a-day",
      })),
    };
    bodies.amber![101] = { openedDay: "1998-12-31" };
    bodies.violet![102] = { closedDay: "1996-02-29" };
    const h = harness(
      { amber: "openedDay", violet: "closedDay" },
      bodies,
      { amber: 1, violet: 1 },
    );

    expect(await h.requirements.requirements("connection-a")).toEqual({
      ok: true,
      since: "1996-02-29",
    });
    expect(
      h.listRecords.mock.calls.map(([input]) => [input.stream, input.cursor]),
    ).toEqual([
      ["amber", undefined],
      ["amber", "0099"],
      ["violet", undefined],
      ["violet", "0099"],
    ]);
  });

  it("requirements-malformed-day-refused", async () => {
    for (const day of [
      "2026-02-30",
      "1900-02-29",
      "2026-04-31",
      "2026-00-10",
      "2026-13-10",
      "2026-01-00",
      "0000-01-01",
      "2026-2-03",
      "2026-02-03T00:00:00Z",
      " 2026-02-03",
      "not-a-day",
      20260203,
      null,
    ]) {
      const h = harness(
        { amber: "openedDay" },
        { amber: [{ openedDay: day }] },
        { amber: 1 },
      );
      expect(await h.requirements.requirements("connection-a")).toEqual({
        ok: false,
        reason: "malformed_day",
      });
      expect(h.listRecords).toHaveBeenCalledTimes(1);
    }
  });

  it("requirements-none-declared-is-null", async () => {
    const undeclared = harness({}, { amber: [{ openedDay: "2026-01-01" }] });
    expect(await undeclared.requirements.requirements("connection-a")).toEqual({
      ok: true,
      since: null,
    });
    expect(undeclared.listRecords).not.toHaveBeenCalled();

    const absent = harness(
      { amber: "openedDay", violet: "closedDay" },
      { amber: [{ otherDay: "2026-01-01" }], violet: [] },
      { amber: 1, violet: 1 },
    );
    expect(await absent.requirements.requirements("connection-a")).toEqual({
      ok: true,
      since: null,
    });
    expect(absent.listRecords).toHaveBeenCalledTimes(2);
  });

  it("requirements cache", async () => {
    const fields = { amber: "openedDay" };
    const bodies = {
      amber: [{ openedDay: "2026-01-01", closedDay: "2024-01-01" }],
    };
    const heads = { amber: 1 };
    const h = harness(fields, bodies, heads);
    const first = await h.requirements.requirements("connection-a");
    expect(first).toEqual({ ok: true, since: "2026-01-01" });
    expect(h.listRecords).toHaveBeenCalledTimes(1);

    expect(await h.requirements.requirements("connection-a")).toEqual(first);
    expect(h.listRecords).toHaveBeenCalledTimes(1);
    expect(h.readHeads).toHaveBeenCalledTimes(2);

    bodies.amber[0]!.openedDay = "2025-01-01";
    heads.amber = 2;
    expect(await h.requirements.requirements("connection-a")).toEqual({
      ok: true,
      since: "2025-01-01",
    });
    expect(h.listRecords).toHaveBeenCalledTimes(2);
    expect(h.readHeads).toHaveBeenCalledTimes(3);

    fields.amber = "closedDay";
    expect(await h.requirements.requirements("connection-a")).toEqual({
      ok: true,
      since: "2024-01-01",
    });
    expect(h.listRecords).toHaveBeenCalledTimes(3);
  });
});
