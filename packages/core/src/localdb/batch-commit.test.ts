import { describe, expect, it } from "vitest";
import { connectionQueue } from "./queue.js";
import {
  createCommitGroup,
  settleRequirementFailure,
  settleRow,
} from "./batch-commit.js";
import type { LocalSyncDeps } from "./deps.js";

const held = {} as LocalSyncDeps;

/** A group over a real connection queue; `flushes` records each turn's entries. */
function group(
  flush: (
    entries: readonly string[],
  ) => Promise<PromiseSettledResult<string>[]>,
  extra: { canJoin?: (taken: readonly string[], next: string) => boolean } = {},
) {
  const queue = connectionQueue();
  const flushes: (readonly string[])[] = [];
  const created = createCommitGroup<string, string>({
    runInSlot: (work) => queue.run("c", "publish", () => work(held)),
    flush: (_held, entries) => {
      flushes.push(entries);
      return flush(entries);
    },
    ...extra,
  });
  return { ...created, flushes, queue };
}

const ok = (entries: readonly string[]): PromiseSettledResult<string>[] =>
  entries.map((value) => ({ status: "fulfilled", value: `ok:${value}` }));

describe("the commit group", () => {
  it("a stream that arrives while a turn is in flight joins the next turn, and the first turn does not wait for it", async () => {
    let release!: () => void;
    const blocked = new Promise<void>((r) => (release = r));
    let first = true;
    const g = group(async (entries) => {
      if (first) {
        first = false;
        await blocked;
      }
      return ok(entries);
    });
    const a = g.submit("a");
    await Promise.resolve();
    await new Promise((r) => setTimeout(r, 5));
    const b = g.submit("b");
    release();
    expect(await a).toBe("ok:a");
    expect(await b).toBe("ok:b");
    expect(g.flushes).toEqual([["a"], ["b"]]);
  });

  it("the first entry takes the slot at once and does not wait for company", async () => {
    const g = group(async (entries) => ok(entries));
    const a = g.submit("a");
    // A timer of any length would not have fired yet: the turn did not wait.
    await new Promise((r) => setImmediate(r));
    expect(g.flushes).toEqual([["a"]]);
    expect(await a).toBe("ok:a");
  });

  it("entries that become ready while a request is in flight go together in exactly one next turn", async () => {
    let release!: () => void;
    const blocked = new Promise<void>((r) => (release = r));
    let first = true;
    const g = group(async (entries) => {
      if (first) {
        first = false;
        await blocked;
      }
      return ok(entries);
    });
    const a = g.submit("a");
    await new Promise((r) => setTimeout(r, 5));
    expect(g.flushes).toEqual([["a"]]);
    const rest = ["b", "c", "d"].map((e) => g.submit(e));
    // Nothing more is sent while the first request is in flight.
    await new Promise((r) => setTimeout(r, 5));
    expect(g.flushes).toEqual([["a"]]);
    release();
    expect(await Promise.all([a, ...rest])).toEqual([
      "ok:a",
      "ok:b",
      "ok:c",
      "ok:d",
    ]);
    expect(g.flushes).toEqual([["a"], ["b", "c", "d"]]);
  });

  it("entries that wait for the slot join the turn that gets it", async () => {
    const g = group(async (entries) => ok(entries));
    let release!: () => void;
    const busy = g.queue.run(
      "c",
      "publish",
      () => new Promise<void>((r) => (release = r)),
    );
    const all = ["a", "b"].map((e) => g.submit(e));
    await new Promise((r) => setTimeout(r, 5));
    expect(g.flushes).toEqual([]);
    release();
    await busy;
    await Promise.all(all);
    expect(g.flushes).toEqual([["a", "b"]]);
  });

  it("a turn takes entries while canJoin accepts them; the rest take the next turns", async () => {
    const g = group(async (entries) => ok(entries), {
      canJoin: (taken) => taken.length < 2,
    });
    let release!: () => void;
    const busy = g.queue.run(
      "c",
      "publish",
      () => new Promise<void>((r) => (release = r)),
    );
    const all = ["a", "b", "c", "d", "e"].map((e) => g.submit(e));
    await new Promise((r) => setTimeout(r, 5));
    release();
    await busy;
    await Promise.all(all);
    expect(g.flushes.map((f) => f.length)).toEqual([2, 2, 1]);
  });

  it("a flush that throws fails every entry of that turn and no later one", async () => {
    let first = true;
    const g = group(async (entries) => {
      if (first) {
        first = false;
        throw new Error("registry down");
      }
      return ok(entries);
    });
    const a = g.submit("a");
    const b = g.submit("b");
    await expect(a).rejects.toThrow("registry down");
    await expect(b).rejects.toThrow("registry down");
    expect(await g.submit("c")).toBe("ok:c");
  });

  it("one entry's failure does not fail its siblings", async () => {
    const g = group(async (entries) =>
      entries.map((value) =>
        value === "bad"
          ? { status: "rejected", reason: new Error("local commit failed") }
          : { status: "fulfilled", value: `ok:${value}` },
      ),
    );
    const results = await Promise.allSettled(
      ["a", "bad", "c"].map((e) => g.submit(e)),
    );
    expect(results.map((r) => r.status)).toEqual([
      "fulfilled",
      "rejected",
      "fulfilled",
    ]);
  });

  it("a slot that refuses the turn (a purge) releases every waiting entry, and the group works again", async () => {
    const queue = connectionQueue();
    let purged = true;
    const created = createCommitGroup<string, string>({
      runInSlot: (work) =>
        queue.run("c", "publish", () => {
          if (purged) throw new Error("purged");
          return work(held);
        }),
      flush: async (_held, entries) => ok(entries),
    });
    const a = created.submit("a");
    const b = created.submit("b");
    await expect(a).rejects.toThrow("purged");
    await expect(b).rejects.toThrow("purged");
    purged = false;
    expect(await created.submit("c")).toBe("ok:c");
  });

  it("a result count that does not match the entries is a failure, not a hang", async () => {
    const g = group(async () => []);
    await expect(g.submit("a")).rejects.toThrow(/1 entries, 0 results/);
  });
});

describe("what the registry's answer means", () => {
  const sent = { expectedVersion: "3", dataHash: "0xAA" };
  it.each([
    [{ kind: "committed" }, "committed"],
    [
      { kind: "conflict", latestVersion: "3", latestDataHash: "0xaa" },
      "committed",
    ],
    [
      { kind: "conflict", latestVersion: "3", latestDataHash: "0xbb" },
      "conflict",
    ],
    [
      { kind: "conflict", latestVersion: "4", latestDataHash: "0xaa" },
      "conflict",
    ],
    [
      { kind: "conflict", latestVersion: "3", latestDataHash: null },
      "conflict",
    ],
    [
      { kind: "conflict", latestVersion: null, latestDataHash: null },
      "conflict",
    ],
  ] as const)("%j is %s", (row, expected) => {
    expect(settleRow(row, sent)).toBe(expected);
  });

  it.each([
    [
      { scope: "c", latestVersion: "2", deleted: true },
      { kind: "purge", controlVersion: 2 },
    ],
    [
      { scope: "c", reason: "deleted", latestVersion: "2", deleted: true },
      { kind: "purge", controlVersion: 2 },
    ],
    [
      {
        scope: "c",
        reason: "version-mismatch",
        latestVersion: "5",
        deleted: false,
      },
      { kind: "defer" },
    ],
    [
      {
        scope: "c",
        reason: "data-hash-mismatch",
        latestVersion: "2",
        deleted: false,
      },
      { kind: "defer" },
    ],
    [
      { scope: "c", reason: "absent", latestVersion: null, deleted: false },
      { kind: "defer" },
    ],
    [{ scope: "c", latestVersion: null, deleted: true }, { kind: "defer" }],
    // A condition on a stream row says nothing about the connection: even a
    // tombstone there is not a connection delete.
    [
      { scope: "s", reason: "deleted", latestVersion: "4", deleted: true },
      { kind: "stream_moved", scope: "s" },
    ],
    [
      {
        scope: "s",
        reason: "data-hash-mismatch",
        latestVersion: "1",
        deleted: false,
      },
      { kind: "stream_moved", scope: "s" },
    ],
  ] as const)("a failed condition %j is %j", (failure, expected) => {
    expect(settleRequirementFailure(failure, "c")).toEqual(expected);
  });
});
