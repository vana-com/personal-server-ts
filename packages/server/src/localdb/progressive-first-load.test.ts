// Progressive first load: a stream with no complete head is readable by its
// owner from its first applied part, in an explicit partial state, and fills in
// part by part. Real SQLite, the real apply and the real resolver; a part's
// blob fetch is held open to stop the apply between parts, so each state is
// read while it is still the state.
import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import {
  partBlobName,
  pkHash,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import {
  PartialViewMoved,
  partialBody,
} from "../../../core/src/localdb/partial-read.js";
import {
  loadStreams,
  selectForTarget,
  type Connection,
} from "../../../core/src/localdb/read-selection.js";
import {
  createViewChanges,
  type ViewChange,
} from "../../../core/src/localdb/view-changes.js";
import type { ResolveInput } from "../../../core/src/stream-sync-read/service.js";
import { remoteFixture } from "./apply-fixture.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const SHA = async (bytes: Uint8Array) => sha256(bytes);
const SCOPE = "pdpp.fixture-source.items";
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

type Head = Awaited<
  ReturnType<Awaited<ReturnType<typeof remoteFixture>>["head"]>
>;

async function harness(options: { progressive: boolean }) {
  const views = createViewChanges();
  const raw = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "progressive",
  });
  const db = views.attach(raw, { warn: () => {} });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    blobs: remote.storage,
    registry: remote.registry,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 1000,
    newOp: () => `progressive-${++op}`,
    progressiveFirstLoad: options.progressive,
  };
  const id = remote.control;
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture-source','',1,'active',1)",
      params: [id],
    },
  ]);
  const resolver = createLocalResolver(deps, {
    query: createRecordQuery(db),
    olderVersions: { read: vi.fn(), list: vi.fn(), counts: vi.fn() } as never,
  });

  // Stops the apply where it fetches one part's blob, until released.
  const held: Promise<void>[] = [];
  const get = remote.storage.get.bind(remote.storage);
  const holds = new Map<string, () => Promise<void>>();
  remote.storage.get = async (key: string) => {
    await holds.get(key)?.();
    return get(key);
  };
  function hold(head: Head, index: number, generation = 1) {
    const key = `${head.scope}/${partBlobName(generation, head.parts[index]!.hash)}`;
    let release!: () => void;
    const open = new Promise<void>((r) => (release = r));
    held.push(open);
    holds.set(key, () => open);
    return { release };
  }

  async function read(extra: Partial<ResolveInput> = {}) {
    const decision = await resolver.resolve({
      scope: SCOPE,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
      ...extra,
    });
    if (decision.kind !== "view")
      return {
        kind: decision.kind === "unavailable" ? decision.reason : decision.kind,
        ids: [] as string[],
        partial: undefined,
      };
    const body = JSON.parse(await new Response(decision.body).text()) as {
      data: { records: { id: string }[] };
    };
    return {
      kind: "view" as const,
      ids: body.data.records.map((r) => r.id).sort(),
      partial: decision.partial,
    };
  }
  /** Waits for `n` parts of `version` to be applied (the next part is held). */
  async function until(n: number, version = 1) {
    for (let i = 0; i < 500; i++) {
      const [row] = await db.query<{ parts_applied: number; version: number }>(
        "SELECT parts_applied, version FROM stream_partial",
      );
      if (row?.version === version && row.parts_applied === n) return;
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error(`the load did not reach ${n} parts of version ${version}`);
  }
  const rows = async (stream = "items") =>
    (
      await db.query<{ body: string }>(
        "SELECT body FROM records WHERE stream = ?",
        [stream],
      )
    )
      .map((r) => (JSON.parse(r.body) as { id: string }).id)
      .sort();
  const partialRows = () => db.query("SELECT * FROM stream_partial");
  return {
    db,
    deps,
    remote,
    resolver,
    views,
    id,
    hold,
    read,
    until,
    rows,
    partialRows,
    held,
  };
}

/** Ids in the order their parts apply: key-hash order. */
async function applyOrder(ids: string[]) {
  const hashed = await Promise.all(
    ids.map(async (id) => ({ id, k: await pkHash(SHA, { id }, ["id"]) })),
  );
  return hashed.sort((a, b) => a.k.localeCompare(b.k)).map((h) => h.id);
}
const values = (ids: string[]) => ids.map((id) => ({ id }));

describe("progressive first load", () => {
  it("a three-part stream is a partial view after each part, then complete", async () => {
    const f = await harness({ progressive: true });
    const ids = ["a", "b", "c"];
    const order = await applyOrder(ids);
    const h = await f.remote.head("items", values(ids));
    expect(h.parts).toHaveLength(3);
    const two = f.hold(h, 1);
    const three = f.hold(h, 2);
    const applying = applyConnection(f.deps, f.id);

    await f.until(1);
    const first = await f.read();
    expect(first.kind).toBe("view");
    expect(first.ids).toEqual([order[0]]);
    expect(first.partial).toEqual({
      partsApplied: 1,
      partsTotal: 3,
      recordsTotal: 3,
    });

    two.release();
    await f.until(2);
    const second = await f.read();
    expect(second.ids).toEqual(order.slice(0, 2).sort());
    expect(second.partial).toMatchObject({ partsApplied: 2, partsTotal: 3 });

    three.release();
    await applying;
    const done = await f.read();
    expect(done.ids).toEqual(ids);
    expect(done.partial).toBeUndefined();
    expect(await f.partialRows()).toEqual([]);
    const [state] = await f.db.query<{
      complete: number;
      head_version: number;
    }>("SELECT complete, head_version FROM stream_state");
    expect(state).toEqual({ complete: 1, head_version: 1 });
  });

  it("a head that moves mid-load drops the old head's rows with the new head's first part", async () => {
    const f = await harness({ progressive: true });
    const one = await f.remote.head("items", values(["a1", "a2", "a3"]));
    const oneThree = f.hold(one, 2);
    const first = applyConnection(f.deps, f.id);
    await f.until(2);
    expect((await f.read()).ids).toHaveLength(2);

    // The registry moves to a second head while the first is mid-load.
    const two = await f.remote.head("items", values(["b1", "b2", "b3"]), {
      version: 2,
    });
    const twoSecond = f.hold(two, 1);
    oneThree.release();
    await expect(first).rejects.toThrow("stream changed during download");
    // Still one head: the first, all its parts applied but never completed.
    const stale = await f.read();
    expect(stale.ids.every((id) => id.startsWith("a"))).toBe(true);

    const second = applyConnection(f.deps, f.id);
    await f.until(1, 2);
    const view = await f.read();
    expect(view.kind).toBe("view");
    expect(view.ids).toHaveLength(1);
    expect(view.ids[0]).toMatch(/^b/);
    expect(view.partial).toMatchObject({ partsApplied: 1, partsTotal: 3 });
    expect((await f.rows()).every((id) => id.startsWith("b"))).toBe(true);

    twoSecond.release();
    await second;
    expect((await f.read()).ids).toEqual(["b1", "b2", "b3"]);
  });

  it("rows an earlier incomplete head left, which the complete state would drop, are never shown", async () => {
    const f = await harness({ progressive: true });
    // An incomplete head applies in full but is not readable.
    await f.remote.head("items", values(["a", "b", "c"]), { complete: false });
    await applyConnection(f.deps, f.id);
    expect(await f.rows()).toEqual(["a", "b", "c"]);
    expect((await f.read()).kind).toBe("no_data");

    const next = await f.remote.head("items", values(["b", "d", "e"]), {
      version: 2,
    });
    const second = f.hold(next, 1);
    const applying = applyConnection(f.deps, f.id);
    await f.until(1, 2);
    const view = await f.read();
    expect(view.ids).toHaveLength(1);
    expect(["b", "d", "e"]).toContain(view.ids[0]);
    second.release();
    await applying;
    expect((await f.read()).ids).toEqual(["b", "d", "e"]);
    expect(await f.rows()).toEqual(["b", "d", "e"]);
  });

  it("an unchanged prefix of an earlier head stays in the partial view; its omitted rows do not", async () => {
    const f = await harness({ progressive: true });
    const bit = async (id: string) =>
      (await pkHash(SHA, { id }, ["id"])).charCodeAt(0) < "8".charCodeAt(0)
        ? 0
        : 1;
    const low: string[] = [];
    const high: string[] = [];
    for (let i = 0; low.length < 2 || high.length < 4; i++) {
      const id = `r${i}`;
      if ((await bit(id)) === 0) {
        if (low.length < 2) low.push(id);
      } else if (high.length < 4) high.push(id);
    }
    await f.remote.head("items", values([...low, ...high.slice(0, 3)]), {
      complete: false,
      prefixBits: 1,
    });
    await applyConnection(f.deps, f.id);
    // The second head keeps the low prefix and replaces one row of the high one.
    const next = await f.remote.head(
      "items",
      values([...low, ...high.slice(1, 3), high[3]!]),
      { version: 2, prefixBits: 1 },
    );
    const lowParts = next.parts.filter((p) => p.prefix === "0").length;
    expect(lowParts).toBeGreaterThan(0);
    const hold = f.hold(next, lowParts + 1);
    const applying = applyConnection(f.deps, f.id);
    await f.until(lowParts + 1, 2);
    const view = await f.read();
    // Kept rows are served from the start; the replaced row is not.
    expect(view.ids).toEqual(expect.arrayContaining(low));
    expect(view.ids).not.toContain(high[0]);
    expect(view.partial).toMatchObject({
      partsApplied: lowParts + 1,
      partsTotal: next.parts.length,
    });
    hold.release();
    await applying;
    expect((await f.read()).ids).toEqual(
      [...low, ...high.slice(1, 3), high[3]!].sort(),
    );
  });

  it("a local row the complete state keeps is in the partial view", async () => {
    const f = await harness({ progressive: true });
    await f.db.batch([
      {
        sql: "UPDATE write_ctx SET origin='local' WHERE id=1",
      },
      {
        sql: "INSERT INTO records(connection_id,stream,pk_hash,record_key,stamp_o,stamp_r,body,body_sha256) VALUES (?,?,?,?,?,?,?,?)",
        params: [
          f.id,
          "items",
          "ff".repeat(32),
          "mine",
          900,
          "run-local",
          '{"id":"mine"}',
          "00",
        ],
      },
    ]);
    const h = await f.remote.head("items", values(["a", "b"]));
    const two = f.hold(h, 1);
    const applying = applyConnection(f.deps, f.id);
    await f.until(1);
    expect((await f.read()).ids).toContain("mine");
    two.release();
    await applying;
    expect((await f.read()).ids).toEqual(["a", "b", "mine"]);
  });

  it("a head that is incomplete never serves a partial view", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b", "c"]), {
      complete: false,
    });
    const two = f.hold(h, 1);
    const applying = applyConnection(f.deps, f.id);
    await new Promise((r) => setTimeout(r, 50));
    expect(await f.partialRows()).toEqual([]);
    expect((await f.rows()).length).toBeLessThan(3);
    two.release();
    await applying;
    expect(await f.partialRows()).toEqual([]);
    expect((await f.read()).kind).toBe("no_data");
  });

  it("a load that failed and began again never shows fewer parts than it showed", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    const third = `${h.scope}/${partBlobName(1, h.parts[2]!.hash)}`;
    const blob = f.remote.blobs.get(third)!;
    f.remote.blobs.delete(third);
    await expect(applyConnection(f.deps, f.id)).rejects.toThrow(
      "missing part blob",
    );
    await f.until(2);
    expect((await f.read()).ids).toHaveLength(2);

    f.remote.blobs.set(third, blob);
    const two = f.hold(h, 1);
    const again = applyConnection(f.deps, f.id);
    // Part one applies again, over rows already there.
    await new Promise((r) => setTimeout(r, 50));
    const view = await f.read();
    expect(view.ids).toHaveLength(2);
    expect(view.partial?.partsApplied).toBe(2);
    two.release();
    await again;
    expect((await f.read()).ids).toEqual(["a", "b", "c"]);
  });

  it("a generation that moves mid-load leaves nothing visible", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    const third = `${h.scope}/${partBlobName(1, h.parts[2]!.hash)}`;
    f.remote.blobs.delete(third);
    await expect(applyConnection(f.deps, f.id)).rejects.toThrow();
    await f.until(2);
    expect((await f.read()).kind).toBe("view");

    f.remote.setControl(2);
    await applyConnection(f.deps, f.id);
    expect(await f.rows()).toEqual([]);
    expect(await f.partialRows()).toEqual([]);
    expect((await f.read()).kind).toBe("no_data");
  });

  it("a connection deleted mid-load leaves nothing visible", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    const third = `${h.scope}/${partBlobName(1, h.parts[2]!.hash)}`;
    f.remote.blobs.delete(third);
    await expect(applyConnection(f.deps, f.id)).rejects.toThrow();
    await f.until(2);

    f.remote.setControl(1, true);
    await applyConnection(f.deps, f.id);
    expect(await f.rows()).toEqual([]);
    expect(await f.partialRows()).toEqual([]);
    expect((await f.read()).kind).toBe("deleted");
  });

  it("the read side refuses a partial row of another generation, a deleted connection, or a stale floor", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    f.remote.blobs.delete(`${h.scope}/${partBlobName(1, h.parts[2]!.hash)}`);
    await expect(applyConnection(f.deps, f.id)).rejects.toThrow();
    const target = { connector: "fixture-source", streams: ["items"] };
    const pick = async (
      patch: Partial<Connection>,
      floor = 0,
      progressive = true,
    ) => {
      const [c] = await f.db.query<Connection>(
        "SELECT connection_id, connector, ns, generation, control_state, deleted_at FROM connections",
      );
      const streams = (await loadStreams(f.deps)).map((s) => ({
        ...s,
        last_delete_version: floor,
      }));
      return selectForTarget(
        target,
        [{ connection: { ...c!, ...patch }, streams }],
        { progressive },
      );
    };
    expect((await pick({})).candidate?.partialStreams).toEqual(["items"]);
    expect((await pick({}, 0, false)).candidate).toBeUndefined();
    expect((await pick({ generation: 2 })).candidate).toBeUndefined();
    expect(
      (await pick({ control_state: "deleted" })).candidate,
    ).toBeUndefined();
    expect((await pick({ deleted_at: 5 })).candidate).toBeUndefined();
    expect((await pick({}, 1)).candidate).toBeUndefined();
  });

  it("a body that is reading when its head moves ends in an error, not a mixed body", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    f.remote.blobs.delete(`${h.scope}/${partBlobName(1, h.parts[2]!.hash)}`);
    await expect(applyConnection(f.deps, f.id)).rejects.toThrow();
    const [load] = await f.db.query<{ data_hash: string }>(
      "SELECT data_hash FROM stream_partial",
    );
    const body = partialBody(f.db, {
      connectionId: f.id,
      generation: 1,
      stream: "items",
      version: 1,
      dataHash: load!.data_hash,
    });
    expect((await body.next()).value).toBe('{"records":[');
    await f.db.batch([
      { sql: "UPDATE stream_partial SET version = 2, data_hash = 'moved'" },
    ]);
    await expect(body.next()).rejects.toBeInstanceOf(PartialViewMoved);
  });

  it("a view event fires with each part", async () => {
    const f = await harness({ progressive: true });
    const events: ViewChange[] = [];
    f.views.subscribe((change) => events.push(change));
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    const two = f.hold(h, 1);
    const three = f.hold(h, 2);
    const applying = applyConnection(f.deps, f.id);
    await f.until(1);
    await f.views.settled();
    const afterOne = events.length;
    expect(afterOne).toBeGreaterThan(0);
    two.release();
    await f.until(2);
    await f.views.settled();
    const afterTwo = events.length;
    expect(afterTwo).toBeGreaterThan(afterOne);
    three.release();
    await applying;
    await f.views.settled();
    expect(events.length).toBeGreaterThan(afterTwo);
    expect(events.every((e) => e.connectionIds.includes(f.id))).toBe(true);
  });

  it("rewriting the same progress changes nothing; new progress moves the view", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b"]));
    const two = f.hold(h, 1);
    const applying = applyConnection(f.deps, f.id);
    await f.until(1);
    const counter = async () =>
      (
        await f.db.query<{ version: number }>(
          "SELECT version FROM view_versions",
        )
      )[0]!.version;
    const [row] = await f.db.query<Record<string, string | number>>(
      "SELECT * FROM stream_partial",
    );
    const write = (progress: number) =>
      f.db.batch([
        {
          sql: "INSERT OR REPLACE INTO stream_partial (connection_id,stream,version,generation,data_hash,head_blob,observed_at,parts_applied,parts_total,records_total) VALUES (?,?,?,?,?,?,?,?,?,?)",
          params: [
            row!.connection_id!,
            row!.stream!,
            row!.version!,
            row!.generation!,
            row!.data_hash!,
            row!.head_blob!,
            row!.observed_at!,
            progress,
            row!.parts_total!,
            row!.records_total!,
          ],
        },
      ]);
    const before = await counter();
    await write(Number(row!.parts_applied));
    expect(await counter()).toBe(before);
    await write(Number(row!.parts_applied) + 1);
    expect(await counter()).toBe(before + 1);
    two.release();
    await applying;
  });
});

describe("with the flag off", () => {
  it("a stream is readable only when its head is complete, and no load row is written", async () => {
    const f = await harness({ progressive: false });
    // Any write of a load row, even one deleted again, leaves a trace.
    await f.db.batch([
      { sql: "CREATE TABLE writes_seen (n INTEGER)" },
      {
        sql: "CREATE TRIGGER writes_seen_ai AFTER INSERT ON stream_partial BEGIN INSERT INTO writes_seen VALUES (1); END",
      },
    ]);
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    const two = f.hold(h, 1);
    const applying = applyConnection(f.deps, f.id);
    await new Promise((r) => setTimeout(r, 50));
    // The read waits for the whole apply, as it always did.
    const settled = vi.fn();
    const reading = f.read().then((view) => {
      settled();
      return view;
    });
    await new Promise((r) => setTimeout(r, 100));
    expect(settled).not.toHaveBeenCalled();
    two.release();
    await applying;
    const view = await reading;
    expect(view.ids).toEqual(["a", "b", "c"]);
    expect(view.partial).toBeUndefined();
    expect(await f.db.query("SELECT * FROM writes_seen")).toEqual([]);
    expect(await f.partialRows()).toEqual([]);
  });

  it("selection ignores a load row, so a stale one serves nothing", async () => {
    const f = await harness({ progressive: false });
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    f.remote.blobs.delete(`${h.scope}/${partBlobName(1, h.parts[2]!.hash)}`);
    await expect(applyConnection(f.deps, f.id)).rejects.toThrow();
    const [c] = await f.db.query<Connection>(
      "SELECT connection_id, connector, ns, generation, control_state, deleted_at FROM connections",
    );
    const streams = await loadStreams(f.deps);
    const picked = selectForTarget(
      { connector: "fixture-source", streams: ["items"] },
      [{ connection: c!, streams }],
    );
    expect(picked.candidate).toBeUndefined();
  });
});

describe("with the flag on, for a reader who is not the owner", () => {
  it("is served only the complete head", async () => {
    const f = await harness({ progressive: true });
    const h = await f.remote.head("items", values(["a", "b", "c"]));
    const two = f.hold(h, 1);
    const applying = applyConnection(f.deps, f.id);
    await f.until(1);
    const settled = vi.fn();
    const reading = f.read({ isOwnerView: false }).then((view) => {
      settled();
      return view;
    });
    await new Promise((r) => setTimeout(r, 100));
    expect(settled).not.toHaveBeenCalled();
    two.release();
    await applying;
    const view = await reading;
    expect(view.ids).toEqual(["a", "b", "c"]);
    expect(view.partial).toBeUndefined();
  });
});
