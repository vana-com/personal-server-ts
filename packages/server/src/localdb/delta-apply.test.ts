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
  const w = await world({ streams: 2, logProtocol: true });
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

  it.each([
    ["a control row (mutation: control rows skipped)", [CONTROL, LOG]],
    [
      "a stream head (mutation: stream heads skipped)",
      [LOG, streamScope(CONNECTOR, "", sName(0))],
    ],
  ])(
    "%s hands the whole delta to the cycle, applying nothing",
    async (_n, scopes) => {
      const { w, here } = await peerCommitted();
      const before = await here.rows();
      const out = await applied(w, here, await deltaOf(here, scopes));
      expect(out.result.outcome).toBe("cycle");
      expect(out.gets).toEqual([]);
      expect(await here.rows()).toEqual(before);
    },
  );

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
    const w = await world({ streams: 2, logProtocol: true });
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

  it("a connection this device does not yet follow by its log hands to the cycle (mutation: no log-follow check)", async () => {
    const { w, here } = await peerCommitted();
    await here.db.batch([
      {
        sql: "DELETE FROM log_state WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
    ]);
    const out = await applied(w, here, await deltaOf(here, [LOG]));
    expect(out.result.outcome).toBe("cycle");
    expect(out.gets).toEqual([]);
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

  it("a reset hands to the cycle", async () => {
    const { w, here } = await peerCommitted();
    const out = await applied(w, here, { since: "0", seq: "2", reset: true });
    expect(out.result.outcome).toBe("cycle");
  });
});

describe("the receive path's depth", () => {
  it("a delta wake is one request deep (the segment GET); the cycle it replaces is deeper", async () => {
    const trace = requestTrace();
    const w = await world({ streams: 2, logProtocol: true, trace });
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
    expect(trace.depthToLast("get")).toBeGreaterThan(1);
  });
});
