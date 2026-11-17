// A change delta applied by the local stream database (`applyRegistryDelta`).
//
// The receiving device holds the registry as of the delta's `since` (it ran a
// clean cycle). A peer commits one log segment; the delta carries the log row.
// Applying it must leave the device exactly where a full cycle would, with no
// registry read and one segment GET; anything it cannot prove so it hands to
// the cycle and leaves untouched. Each test names the mutation it pins.
import { afterEach, describe, expect, it } from "vitest";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import type { RegistryChangeDelta } from "../../../core/src/stream-sync/ports.js";
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
    seq: "2",
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

describe("applying a change delta", () => {
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

  it("an active connection without local log state loads through the supplied log row", async () => {
    const { w, peer, here } = await peerCommitted();
    await here.db.batch([
      {
        sql: "DELETE FROM log_state WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
    ]);
    const out = await applied(w, here, await deltaOf(here, [LOG]));
    expect(out.result.outcome).toBe("applied");
    expect(out.registryCalls).toEqual([]);
    expect(await here.rows()).toEqual(await peer.rows());
    expect(await here.position()).toBe(await peer.position());
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
    const out = await applied(w, here, { since: "0", seq: "2", reset: true });
    expect(out.result.outcome).toBe("cycle");
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
    expect(trace.count(), trace.describe()).toBe(3);
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
    expect(trace.count(), trace.describe()).toBe(3);
    expect(trace.count("list")).toBe(1);
    expect(trace.count("read")).toBe(1);
    expect(trace.count("get")).toBe(1);
    expect(trace.depthToLast("get")).toBeGreaterThan(1);
  });
});

describe("empty delta and idle full cycle request counts", () => {
  it("an empty delta does no reads; an invoked idle cycle still lists and reads control", async () => {
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
    expect(trace.count(), trace.describe()).toBe(2);
    expect(trace.count("list")).toBe(1);
    expect(trace.count("read")).toBe(1);
  });
});
