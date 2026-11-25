// A change delta applied by the local stream database (`applyRegistryDelta`).
//
// The receiving device holds the registry as of the delta's `since` (it ran a
// clean cycle). A peer commits one log segment; the delta carries the log row.
// Applying it must leave the device exactly where a full cycle would, with no
// registry read and one segment GET; anything it cannot prove so it hands to
// the cycle and leaves untouched. Each test names the mutation it pins.
import { keccak_256 } from "@noble/hashes/sha3";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  digestSegment,
  encodeSegment,
  controlScope,
  logScope,
  streamScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { RegistryChangeDelta } from "../../../core/src/stream-sync/ports.js";
import {
  connectionQueue,
  createLocalSync,
} from "../../../core/src/localdb/index.js";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { applyRegistryDelta } from "../../../core/src/localdb/delta-apply.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  CONTROL,
  LOG,
  OWNER,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";
import { requestTrace } from "./request-trace.test-utils.js";
import { StorageDeferredError } from "../../../core/src/stream-sync/storage-retry.js";

afterEach(closeWorldDrivers);

type World = Awaited<ReturnType<typeof world>>;
type Device = Awaited<ReturnType<World["device"]>>;

const records = (prefix: string) =>
  [0, 1].flatMap((s) =>
    [1, 2].map((i) => ({ stream: sName(s), id: `${prefix}-${s}-${i}` })),
  );

/** Two devices that both hold the registry; the peer then commits once more. */
async function peerCommitted() {
  const w = await world({ streams: 2 });
  const peer = await w.device("peer");
  const here = await w.device("here");
  await peer.run("run-1", records("a"));
  await peer.cycle();
  await here.cycle();
  await peer.run("run-2", [{ stream: sName(0), id: "late" }], {
    full: false,
    covered: [sName(0)],
  });
  await peer.cycle();
  return { w, peer, here };
}

const markPartial = (device: Device) =>
  device.db.batch([
    {
      sql: "UPDATE connections SET apply_partial=1 WHERE connection_id=?",
      params: [CONNECTION_ID],
    },
  ]);

/** The delta the gateway would send for these scopes, read from the registry. */
async function deltaOf(
  device: Device,
  scopes: readonly string[],
  extra: Partial<Extract<RegistryChangeDelta, { reset: false }>> = {},
): Promise<RegistryChangeDelta> {
  const rows = [];
  for (const scope of scopes)
    rows.push({ scope, read: await device.deps.registry.read(scope) });
  return {
    since: "1",
    cursor: "2",
    reset: false,
    rows,
    gone: [],
    serversChanged: false,
    ...extra,
  };
}

async function applied(w: World, device: Device, delta: RegistryChangeDelta) {
  const calls = w.gateway.calls.length;
  const gets = device.gets.length;
  const result = await device.sync.applyDelta(delta);
  return {
    result,
    registryCalls: w.gateway.calls.slice(calls),
    gets: device.gets.slice(gets),
  };
}

/** What a device holds for its connections, apart from per-device ids. */
// Publish watermarks are local change-sequence cursors; a full cycle advances
// them, while a download-only startup apply does not.
const remoteStreamState = (rows: Record<string, unknown>[]) =>
  rows.map(({ publish_watermark: _watermark, ...state }) => state);

async function localState(device: Device) {
  const q = (sql: string) => device.db.query(sql);
  return {
    connections: await q(
      "SELECT connection_id, connector, ns, generation, control_state, control_version, apply_partial, checkpoint FROM connections ORDER BY connection_id",
    ),
    streams: await q(
      "SELECT * FROM stream_state ORDER BY connection_id, stream",
    ),
    log: await q("SELECT * FROM log_state ORDER BY connection_id"),
    records: await device.rows(),
    blobRefs: await q("SELECT count(*) AS n FROM blob_refs"),
  };
}

/** The scopes whose registry rows a step changed: the rows its delta carries. */
async function changedBy(w: World, step: () => Promise<unknown>) {
  const snapshot = () =>
    new Map(
      [...w.gateway.versions].map(([scope, v]) => [scope, JSON.stringify(v)]),
    );
  const before = snapshot();
  await step();
  return [...snapshot()]
    .filter(([scope, v]) => before.get(scope) !== v)
    .map(([scope]) => scope);
}

it("an explicit control observation wins over a listed control", async () => {
  const { here } = await peerCommitted();
  const listed = await here.deps.registry.listOwnerRows();
  const live = await here.deps.registry.read(CONTROL);
  if (!live.found) throw new Error("no control row");
  const observedControl = { ...live, version: live.version + 1, deleted: true };
  const listedControl = listed.find((row) => row.scope === CONTROL)?.read;
  expect(listedControl).toEqual(live);
  expect(observedControl).not.toEqual(listedControl);
  const reads: string[] = [];
  const read = here.deps.registry.read.bind(here.deps.registry);
  here.deps.registry.read = async (scope) => {
    reads.push(scope);
    return read(scope);
  };
  await applyConnection(here.deps, CONNECTION_ID, listed, observedControl);
  expect(reads).toEqual([]);
  expect(
    await here.db.query(
      "SELECT control_state FROM connections WHERE connection_id=?",
      [CONNECTION_ID],
    ),
  ).toEqual([{ control_state: "deleted" }]);
  expect(await here.rows()).toEqual([]);
});

it("an old listing cannot roll back a reconnected generation", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  const here = await w.device("here");
  await peer.run("old", [{ stream: sName(0), id: "old" }]);
  await peer.cycle();
  await here.cycle();
  const listed = await here.deps.registry.listOwnerRows();
  const oldControl = listed.find((row) => row.scope === CONTROL)!.read;
  const oldState = await localState(here);
  await peer.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await peer.sync.deleter.resumeDeletes()).toEqual([]);
  await here.cycle();
  expect(await here.rows()).toEqual([]);
  await peer.run("new", [{ stream: sName(0), id: "new" }], { connect: true });
  await peer.cycle();
  await here.cycle();
  const current = await localState(here);
  expect(current.connections[0]!.generation).toBeGreaterThan(
    oldState.connections[0]!.generation,
  );
  expect(current.records.join(" ")).toContain('"new"');
  const reads: string[] = [];
  const read = here.deps.registry.read.bind(here.deps.registry);
  here.deps.registry.read = async (scope) => {
    reads.push(scope);
    return read(scope);
  };
  await applyConnection(here.deps, CONNECTION_ID, listed, oldControl);
  expect(await localState(here)).toEqual(current);
  expect(reads).toContain(CONTROL);
  expect((await here.rows()).join(" ")).not.toContain('"old"');
});

describe("applying a change delta", () => {
  it("startup apply and cycle converge after a peer update", async () => {
    const w = await world({ streams: 2 });
    const peer = await w.device("peer");
    const here = await w.device("startup");
    const twin = await w.device("cycle");
    await peer.run("seed", records("a"));
    await peer.cycle();
    await here.cycle();
    await twin.cycle();
    const before = await localState(here);
    expect(await localState(twin)).toEqual(before);
    await peer.run("update", [{ stream: sName(0), id: "a-0-1", pad: 64 }], {
      full: false,
      covered: [sName(0)],
    });
    await peer.cycle();
    const peerRows = await peer.rows();
    expect(peerRows).not.toEqual(before.records);
    await here.sync.apply();
    await twin.cycle();
    const startup = await localState(here);
    const cycled = await localState(twin);
    expect(cycled.records).toEqual(peerRows);
    expect(startup.records).toEqual(cycled.records);
    expect(remoteStreamState(startup.streams)).toEqual(
      remoteStreamState(cycled.streams),
    );
    expect(await here.position()).toBe(await twin.position());
  });
  it("a peer's log commit: no registry read, one segment GET, the rows a cycle gives (mutation: applyLog without the delta's read)", async () => {
    const { w, peer, here } = await peerCommitted();
    const delta = await deltaOf(here, [LOG]);
    const out = await applied(w, here, delta);
    expect(out.result).toMatchObject({ outcome: "applied", connections: 1 });
    expect(out.result).toMatchObject({ blobGets: 1 });
    expect(out.registryCalls).toEqual([]);
    expect(out.gets).toHaveLength(1);
    expect(out.gets[0]).toMatch(/\.~log\/s-[0-9a-f]{64}$/);
    expect(await here.rows()).toEqual(await peer.rows());
    expect(await here.position()).toBe(await peer.position());
    // A cycle after it finds nothing to fetch.
    const before = here.gets.length;
    await here.cycle();
    expect(here.gets.slice(before)).toEqual([]);
  });

  it("this device's own commit is a no-op: nothing fetched", async () => {
    const { w, peer } = await peerCommitted();
    const out = await applied(w, peer, await deltaOf(peer, [LOG]));
    expect(out.result).toMatchObject({ outcome: "applied", connections: 0 });
    expect(out.gets).toEqual([]);
    expect(out.registryCalls).toEqual([]);
  });

  it("a row that is not a stream-sync scope is not the cycle's: skipped", async () => {
    const { w, here } = await peerCommitted();
    const before = await here.rows();
    const delta = await deltaOf(here, []);
    const out = await applied(w, here, {
      ...delta,
      rows: [
        {
          scope: "legacy.conversations",
          read: {
            found: true,
            version: 1,
            dataHash: `0x${"aa".repeat(32)}`,
            metadataHash: `0x${"bb".repeat(32)}`,
            deleted: false,
          },
        },
      ],
    } as RegistryChangeDelta);
    expect(out.result).toMatchObject({ outcome: "applied", connections: 0 });
    expect(await here.rows()).toEqual(before);
  });

  it("an unsupported stream row hands the whole delta to the cycle, applying nothing (mutation: unsupported rows skipped)", async () => {
    const { w, here } = await peerCommitted();
    const before = await here.rows();
    const out = await applied(
      w,
      here,
      await deltaOf(here, [LOG, streamScope(CONNECTOR, "", sName(0))]),
    );
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
    expect(await here.rows()).toEqual(before);
  });

  it("an active control row this device already holds (a settlement moved it) is skipped; the log applies (mutation: any control row handed to the cycle)", async () => {
    const { w, peer, here } = await peerCommitted();
    const out = await applied(w, here, await deltaOf(here, [CONTROL, LOG]));
    expect(out.result).toMatchObject({ outcome: "applied", connections: 1 });
    expect(out.registryCalls).toEqual([]);
    expect(await here.rows()).toEqual(await peer.rows());
  });

  it("an active control row of another lifetime (a reconnect) hands to the cycle, applying nothing (mutation: a new lifetime applied from the delta)", async () => {
    const { w, here } = await peerCommitted();
    const before = await localState(here);
    const read = await here.deps.registry.read(CONTROL);
    if (!read.found) throw new Error("no control row");
    const delta = await deltaOf(here, []);
    const out = await applied(w, here, {
      ...delta,
      rows: [{ scope: CONTROL, read: { ...read, version: read.version + 5 } }],
    } as RegistryChangeDelta);
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
    expect(await localState(here)).toEqual(before);
  });

  it("a deleted log row on an active connection hands to the cycle (mutation: a deleted log read applied)", async () => {
    const { w, here } = await peerCommitted();
    const read = await here.deps.registry.read(LOG);
    if (!read.found) throw new Error("no log row");
    const before = await localState(here);
    const delta = await deltaOf(here, []);
    const out = await applied(w, here, {
      ...delta,
      rows: [
        {
          scope: LOG,
          read: { ...read, version: read.version + 1, deleted: true },
        },
      ],
    } as RegistryChangeDelta);
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
    expect(await localState(here)).toEqual(before);
  });

  it("a partial mark standing after the apply hands to the cycle (mutation: partial checked only before the apply)", async () => {
    const w = await world({ streams: 2 });
    const peer = await w.device("peer");
    let markDuringGet = false;
    const here = await w.device("here", {
      beforeGet: async () => {
        if (!markDuringGet) return;
        markDuringGet = false;
        await here.db.batch([
          {
            sql: "UPDATE connections SET apply_partial=1 WHERE connection_id=?",
            params: [CONNECTION_ID],
          },
        ]);
      },
    });
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await here.cycle();
    await peer.run("run-2", [{ stream: sName(0), id: "late" }], {
      full: false,
      covered: [sName(0)],
    });
    await peer.cycle();
    markDuringGet = true;
    const out = await applied(w, here, await deltaOf(here, [LOG]));
    expect(out.result.outcome).toBe("cycle");
  });

  it("a delta that arrives while another apply of the connection runs does not take that apply's answer as its own (mutation: the delta joins an in-flight apply)", async () => {
    const w = await world({ streams: 2 });
    const peer = await w.device("peer");
    let hold: Promise<void> | null = null;
    let reached!: () => void;
    const atGet = new Promise<void>((resolve) => (reached = resolve));
    const here = await w.device("here", {
      beforeGet: async () => {
        if (!hold) return;
        reached();
        await hold;
      },
    });
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await here.cycle();
    await peer.run("run-2", [{ stream: sName(0), id: "late" }], {
      full: false,
      covered: [sName(0)],
    });
    await peer.cycle();
    // A whole-device apply begins and stops at its first GET, before the
    // peer's next commit.
    let release!: () => void;
    hold = new Promise<void>((resolve) => (release = resolve));
    const inFlight = here.sync.apply();
    await atGet;
    hold = null;
    await peer.run("run-3", [{ stream: sName(1), id: "later" }], {
      full: false,
      covered: [sName(1)],
    });
    await peer.cycle();
    const delta = await deltaOf(here, [LOG]);
    const answer = here.sync.applyDelta(delta);
    release();
    await inFlight;
    const result = await answer;
    // Either the delta applied its own row, or it handed to the cycle.
    if (result.outcome === "applied")
      expect(await here.position()).toBe(await peer.position());
    else expect(result.outcome).toBe("cycle");
    expect(await here.position()).toBe(await peer.position());
  });

  it.each([
    ["a removed row (mutation: gone ignored)", { gone: ["0x01"] }],
    [
      "a server change (mutation: serversChanged ignored)",
      { serversChanged: true },
    ],
  ])("%s hands to the cycle", async (_n, extra) => {
    const { w, here } = await peerCommitted();
    const out = await applied(w, here, await deltaOf(here, [LOG], extra));
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
  });

  it("a log of a connection this device does not hold hands to the cycle (mutation: no active-connection check)", async () => {
    const w = await world({ streams: 2 });
    const peer = await w.device("peer");
    const fresh = await w.device("fresh");
    await peer.run("run-1", records("a"));
    await peer.cycle();
    const out = await applied(w, fresh, await deltaOf(fresh, [LOG]));
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
  });

  it("a partly applied connection hands to the cycle (mutation: no partial check)", async () => {
    const { w, here } = await peerCommitted();
    await here.db.batch([
      {
        sql: "UPDATE connections SET apply_partial=1 WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
    ]);
    const out = await applied(w, here, await deltaOf(here, [LOG]));
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
  });

  it("a log of a later lifetime than this device holds: the apply returns below the row, and hands to the cycle (mutation: no position check)", async () => {
    const { w, here } = await peerCommitted();
    // This device's view of the connection is a lifetime behind the log's
    // (its control row moved in a way the delta does not show): `applyLog`
    // returns without applying, and the position stays where it was.
    await here.db.batch([
      {
        sql: "UPDATE connections SET generation=0 WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
    ]);
    const before = await here.position();
    const out = await applied(w, here, await deltaOf(here, [LOG]));
    expect(out.result.outcome).toBe("cycle");
    expect(await here.position()).toBe(before);
  });

  it("a segment it cannot read leaves the delta unapplied", async () => {
    const { w, peer, here } = await peerCommitted();
    await peer.run("run-3", [{ stream: sName(1), id: "later" }], {
      full: false,
      covered: [sName(1)],
    });
    await peer.cycle();
    // The newest segment is readable, the one before it is not (yet): the
    // apply stops below the row, as it does when a GET fails.
    const keys = await w.segmentKeys();
    const newest = Math.max(...keys.keys());
    w.innerBlobs.delete(keys.get(newest - 1)!);
    const out = await here.sync.applyDelta(await deltaOf(here, [LOG])).then(
      (r) => r.outcome,
      () => "threw",
    );
    expect(out).not.toBe("applied");
    expect(await here.position()).toBeLessThan(newest);
  });

  it("first-log seeding publishes records with no pending change or run", async () => {
    const { w, peer, here } = await peerCommitted();
    await here.run("pre-log", [{ stream: sName(0), id: "seed-only" }], {
      full: false,
    });
    // Persisted pre-log/import state: records, without a queued run or change.
    await here.db.batch([
      {
        sql: "DELETE FROM log_state WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
      {
        sql: "DELETE FROM record_changes WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
      {
        sql: "UPDATE run_streams SET publication_state='published' WHERE run_id='pre-log'",
      },
    ]);
    const out = await applied(w, here, await deltaOf(here, [LOG]));
    expect(out.result.outcome).toBe("applied");
    expect(out.registryCalls.some((c) => c.kind === "batch")).toBe(true);
    await peer.cycle();
    expect(await peer.rows()).toEqual(await here.rows());
    expect(
      (await peer.records()).some((r) => r.startsWith("s0/seed-only=")),
    ).toBe(true);
  });

  it("a connection with a delete intent hands to the cycle (mutation: no delete-intent check)", async () => {
    const { here } = await peerCommitted();
    await here.db.batch([
      {
        sql: "INSERT INTO delete_intents (connector, delete_id, intent) VALUES (?, 'd1', '{}')",
        params: [CONNECTOR],
      },
    ]);
    // Straight to the apply: the host's entry first finishes pending deletes.
    const before = here.gets.length;
    const result = await applyRegistryDelta(
      here.deps,
      await deltaOf(here, [LOG]),
    );
    expect(result.outcome).toBe("cycle");
    expect(here.gets.slice(before)).toEqual([]);
  });

  it.each([
    ["no rows", []],
    [
      "only a row that is not a stream-sync scope",
      [
        {
          scope: "legacy.conversations",
          read: {
            found: true,
            version: 1,
            dataHash: `0x${"aa".repeat(32)}`,
            metadataHash: `0x${"bb".repeat(32)}`,
            deleted: false,
          },
        },
      ],
    ],
  ])(
    "a stale partial mark on a connection the delta does not name hands to the cycle, which repairs it (mutation: partial checked only for the delta's connections), %s",
    async (_n, rows) => {
      const { w, here } = await peerCommitted();
      await markPartial(here);
      const before = await localState(here);
      const delta = await deltaOf(here, []);
      const out = await applied(w, here, {
        ...delta,
        rows,
      } as RegistryChangeDelta);
      expect(out.result.outcome).toBe("cycle");
      expect(await localState(here)).toEqual(before);
      // The cycle it hands to clears the mark.
      await here.cycle();
      expect(
        await here.db.query(
          "SELECT apply_partial FROM connections WHERE connection_id=?",
          [CONNECTION_ID],
        ),
      ).toEqual([{ apply_partial: 0 }]);
    },
  );

  it("a row this device's own commit has passed hands to the cycle without an apply (mutation: no position check before applyLog)", async () => {
    const { w, here } = await peerCommitted();
    // The delta was read at the peer's commit; before it is applied, this
    // device catches up and commits on top.
    const stale = await deltaOf(here, [LOG]);
    await here.cycle();
    await here.run("run-3", [{ stream: sName(1), id: "mine" }], {
      full: false,
      covered: [sName(1)],
    });
    await here.cycle();
    const row = (stale as { rows: { read: { version: number } }[] }).rows[0]!;
    expect(await here.position()).toBeGreaterThan(row.read.version);
    const before = await localState(here);
    const out = await applied(w, here, stale);
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
    expect(await localState(here)).toEqual(before);
  });

  it("a reset hands to the cycle", async () => {
    const { w, here } = await peerCommitted();
    const out = await applied(w, here, {
      since: "0",
      cursor: "2",
      reset: true,
    });
    expect(out.result.outcome).toBe("cycle");
  });
});

describe("publish work created during delta apply", () => {
  it("a fork at the held position republishes recovery records, deletes and omissions without another local action", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run(
      "first",
      ["x", "v", "w"].map((id) => ({ stream: sName(0), id })),
      { observedAt: 1100 },
    );
    await a.cycle();
    const b = await w.device("b");
    await b.cycle();
    await a.run("delete", [{ stream: sName(0), id: "x", remove: true }], {
      full: false,
      observedAt: 1300,
    });
    await a.cycle();
    await a.run(
      "omit",
      ["w", "z"].map((id) => ({ stream: sName(0), id })),
      { observedAt: 1400 },
    );
    await a.cycle();
    expect(await a.position()).toBe(3);
    w.gateway.versions.get(LOG)!.splice(-2);
    await b.run(
      "fork",
      ["q", "x", "v"].map((id) => ({ stream: sName(0), id })),
      { full: false, observedAt: 1200 },
    );
    await b.cycle();
    await b.run("fork-more", [{ stream: sName(0), id: "extra" }], {
      full: false,
      observedAt: 1250,
    });
    await b.cycle();
    expect(await b.position()).toBe(3);
    expect(await a.sync.applyDelta(await deltaOf(a, [LOG]))).toMatchObject({
      outcome: "applied",
    });
    // No follow-up on A: its recovery must already be in the registry.
    await b.cycle();
    const fresh = await w.device("fresh");
    await fresh.cycle();
    expect((await a.records()).map((r) => r.split("=")[0])).toEqual([
      "s0/extra",
      "s0/q",
      "s0/w",
      "s0/z",
    ]);
    expect(await b.rows()).toEqual(await a.rows());
    expect(await fresh.rows()).toEqual(await a.rows());
  });

  it("a successful first publication round followed by storage deferral leaves the delta unsettled", async () => {
    const w = await world({ streams: 1, partTargetBytes: 3000 });
    const peer = await w.device("peer");
    let armed = false;
    let puts = 0;
    const here = await w.device("here", {
      beforePut: async (key) => {
        if (armed && key.includes(`${LOG}/s-`) && ++puts === 2)
          throw new StorageDeferredError(
            180_000,
            new Error("storage deferred"),
          );
      },
    });
    await peer.run("base", [{ stream: sName(0), id: "base" }]);
    await peer.cycle();
    await here.cycle();
    await here.run(
      "pre-log",
      Array.from({ length: 24 }, (_, i) => ({
        stream: sName(0),
        id: `seed-${i}`,
        pad: 200,
      })),
      { full: false },
    );
    await here.db.batch([
      {
        sql: "DELETE FROM log_state WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
      {
        sql: "DELETE FROM record_changes WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
      {
        sql: "UPDATE run_streams SET publication_state='published' WHERE run_id='pre-log'",
      },
    ]);
    const delta = await deltaOf(here, [LOG]);
    const before = w.gateway.rowsOf(LOG);
    armed = true;
    const result = await here.sync.applyDelta(delta);
    expect(puts).toBe(2);
    expect(w.gateway.rowsOf(LOG)).toBe(before + 1);
    const pending = async () =>
      (
        await here.db.query<{ n: number }>(
          `SELECT COUNT(*) AS n FROM record_changes c JOIN stream_state s
         ON s.connection_id=c.connection_id AND s.stream=c.stream
       WHERE c.connection_id=? AND c.seq>s.publish_watermark AND c.origin='import'`,
          [CONNECTION_ID],
        )
      )[0]!.n;
    expect(await pending()).toBeGreaterThan(0);
    expect(result.outcome).toBe("cycle");
    armed = false;
    await here.cycle();
    expect(await pending()).toBe(0);
    await peer.cycle();
    expect(await peer.rows()).toEqual(await here.rows());
    expect(await peer.records()).toHaveLength(25);
  });

  it("publishes a local write to another connection arriving during the delta's GET", async () => {
    const w = await world({ streams: 1 });
    const peer = await w.device("peer");
    let racing = false;
    const here = await w.device("here", {
      beforeGet: async () => {
        if (!racing) return;
        racing = false;
        await here.run(
          "racing-write",
          [{ stream: sName(0), id: "local-only" }],
          { connector: "other", full: false },
        );
      },
    });
    await peer.run("base", [{ stream: sName(0), id: "base" }]);
    await peer.cycle();
    await here.cycle();
    await peer.run("remote", [{ stream: sName(0), id: "remote" }], {
      full: false,
    });
    await peer.cycle();
    racing = true;
    expect(
      await here.sync.applyDelta(await deltaOf(here, [LOG])),
    ).toMatchObject({ outcome: "applied" });
    await peer.cycle();
    expect(await peer.rows()).toEqual(await here.rows());
    expect(
      (await peer.records()).some((r) => r.startsWith("s0/local-only=")),
    ).toBe(true);
  });
});

describe("multiple connections", () => {
  it("waits for every connection after a sibling fails (mutation: fail-fast Promise.all)", async () => {
    const w = await world({ streams: 1 });
    const peer = await w.device("peer");
    const here = await w.device("here");
    for (const connector of [CONNECTOR, "other"]) {
      await peer.run(
        `first-${connector}`,
        [{ stream: sName(0), id: "first" }],
        { connector },
      );
    }
    await peer.cycle();
    await here.cycle();
    for (const connector of [CONNECTOR, "other"]) {
      await peer.run(`next-${connector}`, [{ stream: sName(0), id: "next" }], {
        connector,
        full: false,
      });
    }
    await peer.cycle();
    const delta = await deltaOf(here, [LOG, "pdpp.other~.~log"]);
    let release!: () => void;
    const hold = new Promise<void>((resolve) => {
      release = resolve;
    });
    let failed!: () => void;
    const atFailure = new Promise<void>((resolve) => {
      failed = resolve;
    });
    let settled = false;
    const applying = applyRegistryDelta(
      {
        ...here.deps,
        queue: {
          run: async (id, kind, work) => {
            if (id === CONNECTION_ID) await hold;
            else {
              failed();
              throw new Error("other connection failed");
            }
            return here.deps.queue.run(id, kind, work);
          },
        },
      },
      delta,
    ).finally(() => {
      settled = true;
    });
    // Attach the rejection handler before allowing either branch to finish.
    const outcome = applying.catch((error: unknown) => error);
    await atFailure;
    await new Promise<void>((resolve) => setImmediate(resolve));
    const settledEarly = settled;
    release();
    expect(await outcome).toMatchObject({ message: "other connection failed" });
    expect(settledEarly).toBe(false);
    expect(await here.position()).toBe(await peer.position());
  });
});

describe("a peer's connection delete", () => {
  async function peerDeleted(beforeDelete?: (peer: Device) => Promise<void>) {
    const w = await world({ streams: 2 });
    const peer = await w.device("peer");
    const here = await w.device("here");
    const twin = await w.device("twin");
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await here.cycle();
    await twin.cycle();
    const scopes = await changedBy(w, async () => {
      await beforeDelete?.(peer);
      await peer.sync.deleter.requestConnectionDelete(CONNECTOR);
      expect(await peer.sync.deleter.resumeDeletes()).toEqual([]);
    });
    return { w, peer, here, twin, scopes };
  }

  it.each(["delete", "re-create"] as const)(
    "startup apply and cycle converge after a peer %s",
    async (change) => {
      const { peer, here, twin } = await peerDeleted();
      const before = await localState(here);
      expect(before.records.length).toBeGreaterThan(0);
      expect(await localState(twin)).toEqual(before);
      if (change === "re-create") {
        await peer.sync.intake.begin("startup-reconnect", {
          connector: CONNECTOR,
          artifactDigest: CONNECTOR,
          connect: true,
          observedAt: 3000,
          owner: { address: OWNER, leaseId: null },
        });
        await peer.sync.intake.abort("startup-reconnect", "cancelled");
        await peer.run("new-lifetime", [{ stream: sName(1), id: "new" }]);
        await peer.cycle();
      }
      const peerRows = await peer.rows();
      expect(peerRows).not.toEqual(before.records);
      if (change === "delete") expect(peerRows).toEqual([]);
      else expect(await peer.records()).toHaveLength(1);
      // No local writes: both receivers observe the same settled peer state.
      await here.sync.apply();
      await twin.cycle();
      const startup = await localState(here);
      const cycled = await localState(twin);
      expect(cycled.records).toEqual(peerRows);
      expect(startup.records).toEqual(cycled.records);
      expect(remoteStreamState(startup.streams)).toEqual(
        remoteStreamState(cycled.streams),
      );
      expect(startup.connections).toEqual(cycled.connections);
    },
  );
  it("applies with no registry read and no GET, leaving what a cycle leaves (mutation: control tombstones handed to the cycle)", async () => {
    const { w, here, twin, scopes } = await peerDeleted();
    expect(scopes).toContain(CONTROL);
    expect(await here.records()).not.toEqual([]);
    const out = await applied(w, here, await deltaOf(here, scopes));
    expect(out.result).toMatchObject({ outcome: "applied", deleted: 1 });
    expect(out.registryCalls).toEqual([]);
    expect(out.gets).toEqual([]);
    expect(await here.records()).toEqual([]);
    await twin.cycle();
    expect(await localState(here)).toEqual(await localState(twin));
    // A cycle after it changes nothing and fetches nothing.
    const gets = here.gets.length;
    await here.cycle();
    expect(here.gets.slice(gets)).toEqual([]);
    expect(await localState(here)).toEqual(await localState(twin));
  });

  it("a connection left partly applied hands to the cycle, which finishes it (mutation: no partial check)", async () => {
    const { w, here, twin, scopes } = await peerDeleted();
    for (const device of [here, twin]) await markPartial(device);
    const before = await localState(here);
    const out = await applied(w, here, await deltaOf(here, scopes));
    expect(out.result.outcome).toBe("cycle");
    expect(await localState(here)).toEqual(before);
    await here.cycle();
    await twin.cycle();
    expect(await localState(here)).toEqual(await localState(twin));
  });

  it("a partial mark an apply leaves after the delta is decided hands to the cycle (mutation: no partial check in the queue)", async () => {
    const { here, scopes } = await peerDeleted();
    const before = await localState(here);
    const delta = await deltaOf(here, scopes);
    // Another apply holds the queue when the delete reaches it, and leaves a
    // partial mark.
    const result = await applyRegistryDelta(
      {
        ...here.deps,
        queue: {
          run: async (id, kind, work) => {
            await markPartial(here);
            return here.deps.queue.run(id, kind, work);
          },
        },
      },
      delta,
    );
    expect(result.outcome).toBe("cycle");
    expect(await localState(here)).toEqual({
      ...before,
      connections: before.connections.map((c) => ({ ...c, apply_partial: 1 })),
    });
  });

  it("a commit the peer made before the delete, in the same delta, is not fetched (mutation: a deleted connection's rows applied)", async () => {
    const { w, here, twin, scopes } = await peerDeleted(async (peer) => {
      await peer.run("run-2", [{ stream: sName(0), id: "late" }], {
        full: false,
        covered: [sName(0)],
      });
      await peer.cycle();
    });
    expect(scopes).toEqual(expect.arrayContaining([CONTROL, LOG]));
    const out = await applied(w, here, await deltaOf(here, scopes));
    expect(out.result).toMatchObject({ outcome: "applied", deleted: 1 });
    expect(out.gets).toEqual([]);
    await twin.cycle();
    expect(await localState(here)).toEqual(await localState(twin));
  });

  it("a delete of a connection this device never held is recorded as a cycle records it (mutation: a tombstone for an unknown connection handed to the cycle)", async () => {
    const { w, scopes } = await peerDeleted();
    const fresh = await w.device("fresh");
    const twin = await w.device("fresh-twin");
    const out = await applied(w, fresh, await deltaOf(fresh, scopes));
    expect(out.result).toMatchObject({ outcome: "applied" });
    expect(out.registryCalls).toEqual([]);
    await twin.cycle();
    expect(await localState(fresh)).toEqual(await localState(twin));
  });

  it("a delete and a reconnect after it hand to the cycle (mutation: an active control of a new lifetime skipped)", async () => {
    const { w, peer, here } = await peerDeleted();
    const scopes = await changedBy(w, async () => {
      await peer.sync.intake.begin("reconnect", {
        connector: CONNECTOR,
        artifactDigest: CONNECTOR,
        connect: true,
        observedAt: 3000,
        owner: { address: OWNER, leaseId: null },
      });
      await peer.sync.intake.abort("reconnect", "cancelled");
      await peer.run("run-2", [{ stream: sName(1), id: "new" }]);
      await peer.cycle();
    });
    expect(scopes).toContain(CONTROL);
    const before = await localState(here);
    const out = await applied(w, here, await deltaOf(here, scopes));
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
    expect(await localState(here)).toEqual(before);
  });

  it("a delete pending on this device hands to the cycle (mutation: no delete-intent check)", async () => {
    const { here, scopes } = await peerDeleted();
    await here.db.batch([
      {
        sql: "INSERT INTO delete_intents (connector, delete_id, intent) VALUES (?, 'd1', '{}')",
        params: [CONNECTOR],
      },
    ]);
    const result = await applyRegistryDelta(
      here.deps,
      await deltaOf(here, scopes),
    );
    expect(result.outcome).toBe("cycle");
  });
});

describe("the receive path's depth", () => {
  it("a delete wake is zero requests deep; the cycle it replaces is not", async () => {
    const trace = requestTrace();
    const w = await world({ streams: 2, trace });
    const peer = await w.device("peer");
    const here = await w.device("here");
    const twin = await w.device("twin");
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await here.cycle();
    await twin.cycle();
    const scopes = await changedBy(w, async () => {
      await peer.sync.deleter.requestConnectionDelete(CONNECTOR);
      expect(await peer.sync.deleter.resumeDeletes()).toEqual([]);
    });
    const delta = await deltaOf(here, scopes);

    trace.clear();
    expect(await here.sync.applyDelta(delta)).toMatchObject({
      outcome: "applied",
      deleted: 1,
    });
    expect(trace.describe()).toBe("");

    trace.clear();
    await twin.cycle();
    expect(await localState(twin)).toEqual(await localState(here));
    // Apply reuses listed control; publish still checks the deleted control.
    expect(trace.count(), trace.describe()).toBe(2);
    expect(trace.count("list")).toBe(1);
    expect(trace.count("read")).toBe(1);
    expect(trace.depth()).toBeGreaterThan(1);
  });

  it("a delta wake is one request deep (the segment GET); the cycle it replaces is deeper", async () => {
    const trace = requestTrace();
    const w = await world({ streams: 2, trace });
    const peer = await w.device("peer");
    const here = await w.device("here");
    const twin = await w.device("twin");
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await here.cycle();
    await twin.cycle();
    await peer.run("run-2", [{ stream: sName(0), id: "late" }], {
      full: false,
      covered: [sName(0)],
    });
    await peer.cycle();
    const delta = await deltaOf(here, [LOG]);

    trace.clear();
    expect(await here.sync.applyDelta(delta)).toMatchObject({
      outcome: "applied",
    });
    expect(trace.describe()).toBe("get");
    expect(trace.depth()).toBe(1);

    // The same change received by a full cycle, on a device in the same state.
    trace.clear();
    await twin.cycle();
    expect(await twin.rows()).toEqual(await here.rows());
    // The listing supplies both control and log; only the segment is fetched.
    expect(trace.count(), trace.describe()).toBe(2);
    expect(trace.count("list")).toBe(1);
    expect(trace.count("read")).toBe(0);
    expect(trace.count("get")).toBe(1);
    expect(trace.depthToLast("get")).toBeGreaterThan(1);
  });
});

describe("empty delta and idle full cycle request counts", () => {
  it("an empty delta does no reads; an invoked idle cycle only lists", async () => {
    const trace = requestTrace();
    const w = await world({ streams: 2, trace });
    const peer = await w.device("peer");
    const here = await w.device("here");
    await peer.run("run-1", records("a"));
    await peer.cycle();
    await here.cycle();
    const delta = await deltaOf(here, []);
    trace.clear();
    expect(await here.sync.applyDelta(delta)).toMatchObject({
      outcome: "applied",
    });
    expect(trace.count()).toBe(0);
    trace.clear();
    await here.cycle();
    expect(trace.count(), trace.describe()).toBe(1);
    expect(trace.count("list")).toBe(1);
    expect(trace.count("read")).toBe(0);
  });
});

it("a first-create pair avoids the owner listing and downloads only its segment", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  const here = await w.device("receiver");
  await here.cycle(); // establish an empty owner baseline
  await peer.run("first", [{ stream: sName(0), id: "first-record" }]);
  await peer.cycle();
  const delta = await deltaOf(here, [CONTROL, LOG], {
    since: "0",
    cursor: "2",
  });
  const list = vi.spyOn(here.deps.registry, "listOwnerRows");
  const out = await applied(w, here, delta);
  if (out.result.outcome === "cycle") await here.cycle();
  expect(await here.rows()).toEqual(await peer.rows());
  expect(list).not.toHaveBeenCalled();
  expect(out.result.outcome).toBe("applied");
  expect(out.gets).toEqual(peer.puts);
  expect(out.gets).toHaveLength(1);
  expect(out.registryCalls).toEqual([]);
});

async function firstCreated() {
  const w = await world({ streams: 1 });
  const peer = await w.device("creator");
  const here = await w.device("receiver");
  await here.cycle();
  await peer.run("first", [{ stream: sName(0), id: "first" }]);
  await peer.cycle();
  const delta = await deltaOf(here, [CONTROL, LOG], {
    since: "0",
    cursor: "2",
  });
  if (delta.reset) throw new Error("expected rows");
  return { w, peer, here, delta };
}

it("a first-create delta that reaches the cursor it started from is no delta: the cycle takes it", async () => {
  // Cursors have no order, so "reaches above `since`" is "reaches another
  // cursor than `since`". An answer with the same cursor on both ends says
  // nothing was read between them.
  const { here, delta } = await firstCreated();
  const before = await localState(here);
  const out = await here.sync.applyDelta({ ...delta, cursor: delta.since });
  expect(out.outcome).toBe("cycle");
  expect(await localState(here)).toEqual(before);
});

it.each([
  "control only",
  "log only",
  "reset",
  "foreign control",
  "later generation",
  "split namespace",
])("first-create rejects %s before local writes", async (scenario) => {
  const { here, delta } = await firstCreated();
  let candidate: RegistryChangeDelta = delta;
  if (scenario === "control only")
    candidate = { ...delta, rows: delta.rows.slice(0, 1) };
  if (scenario === "log only")
    candidate = { ...delta, rows: delta.rows.slice(1) };
  if (scenario === "reset")
    candidate = { since: delta.since, cursor: delta.cursor, reset: true };
  if (scenario === "foreign control" || scenario === "later generation") {
    candidate = {
      ...delta,
      rows: delta.rows.map((row) =>
        row.scope !== CONTROL || !row.read.found
          ? row
          : {
              ...row,
              read: {
                ...row.read,
                ...(scenario === "foreign control"
                  ? { dataHash: `0x${"ab".repeat(32)}` }
                  : { version: 3 }),
              },
            },
      ),
    };
  }
  if (scenario === "split namespace")
    candidate = {
      ...delta,
      rows: delta.rows.map((row) =>
        row.scope === LOG
          ? { ...row, scope: logScope(CONNECTOR, "0123456789abcdef") }
          : row,
      ),
    };
  const before = await localState(here);
  expect((await here.sync.applyDelta(candidate)).outcome).toBe("cycle");
  expect(await localState(here)).toEqual(before);
  expect(here.gets).toEqual([]);
});

it("a pair split across answers keeps reconciliation until the connection is established", async () => {
  const { here, peer, delta } = await firstCreated();
  for (const [index, row] of delta.rows.entries()) {
    expect(
      (
        await here.sync.applyDelta({
          ...delta,
          since: String(index),
          cursor: String(index + 1),
          rows: [row],
        })
      ).outcome,
    ).toBe("cycle");
    expect(await here.rows()).toEqual([]);
  }
  await here.cycle();
  expect(await here.rows()).toEqual(await peer.rows());
});

it.each(["delete intent", "local tombstone"])(
  "first-create rechecks %s after queue admission",
  async (scenario) => {
    const { here, delta } = await firstCreated();
    const deps = {
      ...here.deps,
      queue: {
        run: async <T>(
          id: string,
          kind: "end" | "publish" | "apply" | "purge",
          work: () => Promise<T>,
        ) => {
          await here.deps.queue.run(id, "end", () =>
            here.db
              .batch([
                scenario === "delete intent"
                  ? {
                      sql: "INSERT INTO delete_intents (connector, delete_id, intent) VALUES (?, 'delete', '{}')",
                      params: [CONNECTOR],
                    }
                  : {
                      sql: "INSERT INTO connections (connection_id, connector, ns, generation, control_state, control_version) VALUES (?, ?, '', 1, 'deleted', 2)",
                      params: [CONNECTION_ID, CONNECTOR],
                    },
              ])
              .then(() => {}),
          );
          return here.deps.queue.run(id, kind, work);
        },
      },
    };
    expect((await applyRegistryDelta(deps, delta)).outcome).toBe("cycle");
    expect(await here.rows()).toEqual([]);
    expect(here.gets).toEqual([]);
  },
);

it("a tombstone followed by recreation requires a full cycle", async () => {
  const { here, peer } = await firstCreated();
  await peer.sync.deleter.requestConnectionDelete(CONNECTOR);
  await peer.sync.deleter.resumeDeletes();
  await peer.run("recreated", [{ stream: sName(0), id: "recreated" }], {
    connect: true,
  });
  await peer.cycle();
  expect(
    (await here.sync.applyDelta(await deltaOf(here, [CONTROL, LOG]))).outcome,
  ).toBe("cycle");
  expect(await here.rows()).toEqual([]);
  await here.cycle();
  expect(await here.rows()).toEqual(await peer.rows());
});

it("a first control paired with a later-generation log cannot settle", async () => {
  const { here, peer, delta } = await firstCreated();
  await peer.sync.deleter.requestConnectionDelete(CONNECTOR);
  await peer.sync.deleter.resumeDeletes();
  await peer.run("recreated", [{ stream: sName(0), id: "recreated" }], {
    connect: true,
  });
  await peer.cycle();
  const later = await deltaOf(here, [LOG]);
  if (later.reset) throw new Error("expected rows");
  expect(
    (
      await here.sync.applyDelta({
        ...delta,
        rows: [delta.rows[0]!, ...later.rows],
      })
    ).outcome,
  ).toBe("cycle");
  expect(await here.rows()).toEqual([]);
});

it("a log from another namespace fails verification even with a matching control", async () => {
  const { here, delta, w } = await firstCreated();
  const ns = "0123456789abcdef";
  const original = (await w.innerBlobs.get((await w.segmentKeys()).get(1)!))!;
  here.deps.blobs.get = async () => original;
  const candidate = {
    ...delta,
    rows: delta.rows.map((row) => ({
      ...row,
      scope:
        row.scope === CONTROL
          ? controlScope(CONNECTOR, ns)
          : logScope(CONNECTOR, ns),
    })),
  };
  await expect(here.sync.applyDelta(candidate)).rejects.toThrow(
    /invalid log segment/,
  );
  expect(await here.rows()).toEqual([]);
});

it("failure after control insertion is recoverable by a new sync instance and replay", async () => {
  const { here, peer, delta } = await firstCreated();
  const get = here.deps.blobs.get;
  here.deps.blobs.get = async () => {
    throw new Error("interrupted download");
  };
  await expect(here.sync.applyDelta(delta)).rejects.toThrow(
    "interrupted download",
  );
  expect((await localState(here)).connections).toMatchObject([
    { control_state: "active", generation: 1 },
  ]);
  expect(await here.position()).toBe(0);
  expect(await here.rows()).toEqual([]);
  here.deps.blobs.get = get;
  const restarted = createLocalSync(
    { ...here.deps, queue: connectionQueue() },
    {
      resolveArtifact: () => {
        throw new Error("replay must not resolve an artifact");
      },
    },
  );
  expect((await restarted.applyDelta(delta)).outcome).toBe("applied");
  expect(await here.rows()).toEqual(await peer.rows());
  expect((await restarted.applyDelta(delta)).outcome).toBe("applied");
  expect(await here.rows()).toEqual(await peer.rows());
});

it("a first-create log with another key check fails before committing records", async () => {
  const { here, delta, w } = await firstCreated();
  const segment = (await w.segments()).get(1)!;
  const bytes = encodeSegment({ ...segment, keyCheck: "0123456789abcdef" });
  const { dataHash } = await digestSegment(async (b) => keccak_256(b), bytes);
  await w.innerBlobs.put(`${LOG}/s-${dataHash.slice(2)}`, bytes);
  const candidate = {
    ...delta,
    rows: delta.rows.map((row) =>
      row.scope === LOG && row.read.found
        ? { ...row, read: { ...row.read, dataHash } }
        : row,
    ),
  };
  await expect(here.sync.applyDelta(candidate)).rejects.toThrow(
    /invalid log segment/,
  );
  expect(await here.rows()).toEqual([]);
  expect(await here.position()).toBe(0);
});

it("a first-create pair uses the production first-load bootstrap path", async () => {
  const { here, peer, delta } = await firstCreated();
  const list = vi.spyOn(here.deps.registry, "listOwnerRows");
  const result = await applyRegistryDelta(
    { ...here.deps, bootstrapFirstLoad: true },
    delta,
  );
  expect(result).toMatchObject({ outcome: "applied", blobGets: 1 });
  expect(list).not.toHaveBeenCalled();
  expect(here.gets).toEqual(peer.puts);
  expect(await here.rows()).toEqual(await peer.rows());
});
