import { describe, expect, it } from "vitest";
import { HostContractError } from "./errors.js";
import type { JsonObject } from "./json.js";
import { filesOfConnection } from "./connection-files.js";
import {
  backoffDelayMs,
  DEFAULT_MAX_ATTEMPTS,
  onConflict,
  planPublish,
  publishStream,
  reconnectStream,
  type PublishContext,
  type PublishPorts,
  type PublishStreamArgs,
} from "./publish.js";
import { plainRecords, type Run } from "./records.js";
import { newDeviceDisk, ReferenceDevice } from "./reference-host.js";
import { gate, newStore, nodeSha256, stamped } from "./test-support/index.js";

const ref = { connectionId: "conn", stream: "items" };
const ctx: PublishContext = { ...ref, primaryKey: ["id"], sha256: nodeSha256 };
const run = (records: JsonObject[], observedAt = 1000): Run => ({
  records,
  observedAt,
});
const args = (
  r: Run,
  extra: Partial<PublishStreamArgs> = {},
): PublishStreamArgs => ({ ...ctx, run: r, ...extra });
const ids = (records: readonly { record: JsonObject }[]) =>
  records.map((r) => r.record["id"]);
const values = (records: readonly { record: JsonObject }[]) =>
  records.map((r) => r.record);

async function seed(
  store = newStore(),
  records: JsonObject[] = [{ id: 1, v: "a" }],
  at = 1000,
) {
  const outcome = await publishStream(
    store.portsFor("seed"),
    args(run(records, at)),
  );
  if (outcome.status !== "registered") throw new Error("seed failed");
  return {
    store,
    version: outcome.version,
    base: { version: outcome.version, records: stamped(records, at) },
  };
}

describe("planPublish and onConflict", () => {
  it("plans parts and a head that expects the base version it was built from", async () => {
    const plan = await planPublish({
      ...ctx,
      latestCopy: stamped([{ id: 1 }], 1),
      baseVersion: "7",
      run: run([{ id: 2 }]),
    });
    expect(plan.expectedBase).toBe("7");
    expect(plan.head.baseVersion).toBe("7");
    expect(plan.head.recordCount).toBe(2);
    expect(plan.head.parts).toHaveLength(plan.parts.length);
  });

  it("re-plans from the NEW latest copy with the SAME run, never the stale copy", async () => {
    const same = run([{ id: 2, v: "mine" }], 2000);
    const stale = await planPublish({
      ...ctx,
      latestCopy: stamped([{ id: 1 }], 1),
      baseVersion: "1",
      run: same,
    });
    const replanned = await onConflict(
      {
        version: "2",
        records: stamped([{ id: 1 }, { id: 9, v: "theirs" }], 1500),
      },
      same,
      ctx,
    );
    expect(replanned.expectedBase).toBe("2");
    expect(replanned.head.recordCount).toBe(3);
    expect(replanned.head.parts).not.toEqual(stale.head.parts);
    const text = new TextDecoder().decode(replanned.parts[0]!.bytes);
    expect(text).toContain('"id":9');
    expect(text).toContain('"v":"mine"');
  });

  it("is pure: the same input gives the same bytes and head hash", async () => {
    const input = {
      ...ctx,
      latestCopy: stamped([{ id: 1 }], 1),
      baseVersion: "1",
      run: run([{ id: 2 }]),
    };
    const a = await planPublish(input);
    const b = await planPublish(input);
    expect(a.headBytes).toEqual(b.headBytes);
    expect(a.headHash).toBe(b.headHash);
  });

  it("surfaces the oversized-record warning", async () => {
    const plan = await planPublish({
      ...ctx,
      partSizeBytes: 10,
      latestCopy: [],
      baseVersion: null,
      run: run([{ id: 1 }]),
    });
    expect(plan.warnings).toMatchObject([
      { code: "oversized-record", partIndex: 0, limit: 10 },
    ]);
  });
});

describe("an older value never overwrites a newer one", () => {
  it("a lagging device rebases correctly and still cannot put its old value over a newer row", async () => {
    const { store, base } = await seed(
      newStore(),
      [{ id: 1, title: "A" }],
      1000,
    );
    // Another device observes a rename later, and registers it.
    await publishStream(
      store.portsFor("desktop"),
      args(run([{ id: 1, title: "B" }], 2000)),
    );
    // The phone observed "A" earlier (t=1500), from a stale base, and publishes late.
    const outcome = await publishStream(
      store.portsFor("phone"),
      args(run([{ id: 1, title: "A" }], 1500), { localBase: base }),
    );
    expect(outcome).toMatchObject({ status: "registered", attempts: 2 });
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, title: "B" },
    ]);
  });

  it("with a declared order field the source version decides, whatever the clocks say", async () => {
    const { store, base } = await seed(
      newStore(),
      [{ id: 1, rev: 1, v: "r1" }],
      1000,
    );
    await publishStream(
      store.portsFor("desktop"),
      args(run([{ id: 1, rev: 3, v: "r3" }], 1100), { orderField: "rev" }),
    );
    // The phone's clock runs far ahead, but its record has the lower source version.
    await publishStream(
      store.portsFor("phone"),
      args(run([{ id: 1, rev: 2, v: "r2" }], 9_000_000), {
        orderField: "rev",
        localBase: base,
      }),
    );
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, rev: 3, v: "r3" },
    ]);
  });

  it("the observation time is stored beside the record, not inside it", async () => {
    const { store } = await seed(newStore(), [{ id: 1, v: "a" }], 4242);
    const copy = (await store.readStream(ref))!;
    expect(copy.records).toEqual([
      { record: { id: 1, v: "a" }, observedAt: 4242 },
    ]);
    const head = store.snapshot(ref);
    if (head.kind !== "head") throw new Error("expected a head");
    const headBytes = store.readHead(ref, head.headHash)!;
    const part = JSON.parse(
      new TextDecoder().decode(
        store.readPart(
          ref,
          JSON.parse(new TextDecoder().decode(headBytes)).parts[0].hash,
        )!,
      ),
    );
    expect(part).toEqual({ observedAt: [4242], records: [{ id: 1, v: "a" }] });
  });
});

describe("the head is content-addressed", () => {
  it("stores the head under the hash of its own bytes and registers that hash", async () => {
    const { store } = await seed();
    const latest = store.snapshot(ref);
    if (latest.kind !== "head") throw new Error("expected a head");
    expect(store.readHead(ref, latest.headHash)).toBeDefined();
    const names = store.names();
    expect(names.filter((n) => n.includes(".head-"))).toHaveLength(1);
    // No object is stored under the fixed stream name; it is only the registry key.
    expect(names.filter((n) => n === "pdpp.conn.items")).toHaveLength(1);
  });

  it("a writer that loses the compare-and-set cannot damage the registered head", async () => {
    const { store, version, base } = await seed();
    const winner = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 2, v: "a2" }], 2000)),
    );
    expect(winner.status).toBe("registered");
    const registered = store.snapshot(ref);
    if (registered.kind !== "head") throw new Error("expected a head");
    const bytesBefore = store.readHead(ref, registered.headHash)!.slice();
    // The loser stores its own head object, which loses the CAS, and retries.
    const loser = await publishStream(
      store.portsFor("b"),
      args(run([{ id: 3, v: "b3" }], 3000), { localBase: base }),
    );
    expect(loser.status).toBe("registered");
    expect(store.readHead(ref, registered.headHash)).toEqual(bytesBefore);
    expect(version).toBe("1");
    expect(ids((await store.readStream(ref))!.records)).toEqual([1, 2, 3]);
  });

  it("a crashed write leaves the registered head readable", async () => {
    const { store } = await seed();
    const crashing = store.portsFor("a", {
      beforeCommit: () => {
        throw new Error("crash after the head object was stored");
      },
    });
    await expect(
      publishStream(crashing, args(run([{ id: 2 }], 2000))),
    ).rejects.toThrow("crash after");
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, v: "a" },
    ]);
  });

  it("refuses a head whose bytes do not hash to its name, and a reader checks the registry hash", async () => {
    const { store } = await seed();
    const ports = store.portsFor("a");
    const plan = await planPublish({
      ...ctx,
      latestCopy: [],
      baseVersion: null,
      run: run([{ id: 5 }]),
    });
    await expect(
      ports.putHead(ref, "0".repeat(64), plan.headBytes),
    ).rejects.toThrow(HostContractError);
    const swapped: PublishPorts = {
      ...ports,
      fetchHead: async () => plan.headBytes,
    };
    await expect(
      publishStream(swapped, args(run([{ id: 2 }]))),
    ).rejects.toMatchObject({ code: "part-integrity", reason: "hash" });
  });
});

describe("state table", () => {
  it("idle -> planning: the base is the latest local synced copy at version V", async () => {
    const { store, base } = await seed();
    const outcome = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 2 }], 2000), { localBase: base }),
    );
    expect(outcome.status).toBe("registered");
    if (outcome.status === "registered")
      expect(outcome.plan.head.baseVersion).toBe(base.version);
  });

  it("idle with no local copy: the driver reads the latest copy first", async () => {
    const { store } = await seed();
    const outcome = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 2 }], 2000)),
    );
    expect(outcome.status).toBe("registered");
    expect(ids((await store.readStream(ref))!.records)).toEqual([1, 2]);
  });

  it("planning -> uploading-parts: parts are content-addressed and immutable", async () => {
    const store = newStore();
    const ports = store.portsFor("a");
    const bytes = new TextEncoder().encode(
      '{"observedAt":[1],"records":[{"id":1}]}',
    );
    await expect(ports.putPart(ref, "0".repeat(64), bytes)).rejects.toThrow(
      HostContractError,
    );
    const outcome = await publishStream(ports, args(run([{ id: 1 }])));
    if (outcome.status !== "registered") throw new Error("expected registered");
    const part = outcome.plan.parts[0]!;
    await ports.putPart(ref, part.hash, part.bytes); // idempotent re-put
    expect(store.readPart(ref, part.hash)).toEqual(part.bytes);
    expect(store.names().filter((n) => n.includes(".part-"))).toHaveLength(1);
  });

  it("uploading-parts -> writing-head -> registering: parts, then the head object, then the registration", async () => {
    const store = newStore();
    const outcome = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }]), {
        partSizeBytes: 60,
      }),
    );
    expect(outcome.status).toBe("registered");
    expect(store.events.map((e) => e.op)).toEqual([
      "put-part",
      "put-part",
      "put-head",
      "commit-head",
    ]);
  });

  it("a host that registers before storing the head or its parts is refused", async () => {
    const store = newStore();
    const plan = await planPublish({
      ...ctx,
      latestCopy: [],
      baseVersion: null,
      run: run([{ id: 1 }]),
    });
    const ports = store.portsFor("a");
    const request = {
      headHash: plan.headHash,
      expectedBase: null,
      intent: "publish" as const,
    };
    await expect(ports.commitHead(ref, request)).rejects.toThrow(
      HostContractError,
    ); // no head object
    await ports.putHead(ref, plan.headHash, plan.headBytes);
    await expect(ports.commitHead(ref, request)).rejects.toThrow(
      HostContractError,
    ); // no parts
    expect(store.currentVersion(ref)).toBeNull();
  });

  it("uploading-parts -> idle on crash: orphan parts are harmless, nothing is registered", async () => {
    const { store, version } = await seed();
    let puts = 0;
    const crashing = store.portsFor("a", {
      afterPutPart: () => {
        puts += 1;
        if (puts === 2) throw new Error("crash");
      },
    });
    const records = [{ id: 2 }, { id: 3 }, { id: 4 }, { id: 5 }];
    await expect(
      publishStream(crashing, args(run(records, 2000), { partSizeBytes: 60 })),
    ).rejects.toThrow("crash");
    expect(store.currentVersion(ref)).toBe(version);
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, v: "a" },
    ]);
    const retry = await publishStream(
      store.portsFor("a"),
      args(run(records, 2000), { partSizeBytes: 60 }),
    );
    expect(retry.status).toBe("registered");
    expect(ids((await store.readStream(ref))!.records)).toEqual([
      1, 2, 3, 4, 5,
    ]);
  });

  it("registering -> done: the registry accepts V -> V+1", async () => {
    const { store, version } = await seed();
    expect(version).toBe("1");
    const outcome = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 2 }], 2000)),
    );
    expect(outcome).toMatchObject({
      status: "registered",
      version: "2",
      attempts: 1,
      runDisposition: "complete",
    });
  });

  it("registering -> refetch -> planning: a moved version re-plans the same run on the new copy", async () => {
    const { store, base } = await seed();
    await publishStream(
      store.portsFor("other"),
      args(run([{ id: 7, v: "other" }], 1500)),
    );
    const outcome = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 2, v: "mine" }], 2000), { localBase: base }),
    );
    expect(outcome).toMatchObject({
      status: "registered",
      version: "3",
      attempts: 2,
    });
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, v: "a" },
      { id: 2, v: "mine" },
      { id: 7, v: "other" },
    ]);
  });

  describe("any -> stopped when the connection is tombstoned", () => {
    it("before planning: nothing is uploaded, and the run is to be discarded", async () => {
      const { store } = await seed();
      store.deleteConnection(ref.connectionId);
      const before = store.events.length;
      const outcome = await publishStream(
        store.portsFor("a"),
        args(run([{ id: 2 }])),
      );
      expect(outcome).toMatchObject({
        status: "stopped",
        runDisposition: "discard",
      });
      expect(store.events.length).toBe(before);
    });

    it("between planning and the head write: the registry rejects and nothing new is visible", async () => {
      const { store } = await seed();
      const ports = store.portsFor("a", {
        beforeCommit: () => void store.deleteConnection(ref.connectionId),
      });
      const outcome = await publishStream(ports, args(run([{ id: 2 }], 2000)));
      expect(outcome).toEqual({
        status: "stopped",
        runDisposition: "discard",
        reason: "tombstoned",
        attempts: 1,
      });
      expect(store.snapshot(ref).kind).toBe("tombstone");
      expect(await store.readStream(ref)).toBeNull();
    });

    it("during a refetch after a moved version", async () => {
      const { store, base } = await seed();
      await publishStream(
        store.portsFor("other"),
        args(run([{ id: 7 }], 1500)),
      );
      const outcome = await publishStream(
        store.portsFor("a", {
          afterCommit: (result) => {
            if (result.kind === "version-moved")
              store.deleteConnection(ref.connectionId);
          },
        }),
        args(run([{ id: 2 }], 2000), { localBase: base }),
      );
      expect(outcome).toMatchObject({
        status: "stopped",
        runDisposition: "discard",
      });
    });

    it("a publish over a tombstone is refused by the registry; only a reconnect may register over it", async () => {
      const { store } = await seed();
      store.deleteConnection(ref.connectionId);
      store.runCleanup(ref.connectionId);
      const ports = store.portsFor("d2");
      const plan = await planPublish({
        ...ctx,
        latestCopy: [],
        baseVersion: "2",
        run: run([{ id: 9 }]),
      });
      for (const part of plan.parts)
        await ports.putPart(ref, part.hash, part.bytes);
      await ports.putHead(ref, plan.headHash, plan.headBytes);
      const result = await ports.commitHead(ref, {
        headHash: plan.headHash,
        expectedBase: "2",
        intent: "publish",
      });
      expect(result.kind).toBe("tombstoned");
    });
  });

  it("fails closed instead of overwriting when the latest copy does not verify", async () => {
    const { store } = await seed();
    const corrupt: PublishPorts = {
      ...store.portsFor("a"),
      fetchPart: async () => new TextEncoder().encode("garbage"),
    };
    await expect(
      publishStream(corrupt, args(run([{ id: 2 }]))),
    ).rejects.toMatchObject({ code: "part-integrity" });
    expect(store.currentVersion(ref)).toBe("1");
  });
});

describe("a completed run stays pending until its head is registered", () => {
  const device = (
    store: ReturnType<typeof newStore>,
    name: string,
    disk = newDeviceDisk(),
    hooks = {},
  ) => new ReferenceDevice(name, store, ctx, disk, hooks);

  it("reports registered only after the compare-and-set succeeds, and only then advances the cursor", async () => {
    const store = newStore();
    const d = device(store, "d");
    d.completeRun(run([{ id: 1 }]), "cursor-1");
    expect(d.disk.cursor).toBeNull(); // completing a run does not advance the cursor
    expect(d.disk.pending).not.toBeNull();
    const outcome = await d.publishPending();
    expect(outcome).toMatchObject({
      status: "registered",
      runDisposition: "complete",
    });
    expect(d.disk.cursor).toBe("cursor-1");
    expect(d.disk.pending).toBeNull();
  });

  it("a crash after the parts and before the registration loses nothing: the run and cursor survive", async () => {
    const store = newStore();
    const disk = newDeviceDisk();
    const crashing = device(store, "d", disk, {
      beforeCommit: () => {
        throw new Error("crash before registration");
      },
    });
    crashing.completeRun(run([{ id: 1, v: "only-copy" }], 5000), "cursor-1");
    await expect(crashing.publishPending()).rejects.toThrow(
      "crash before registration",
    );
    expect(disk.cursor).toBeNull();
    expect(disk.pending?.run.records).toEqual([{ id: 1, v: "only-copy" }]);
    expect(await store.readStream(ref)).toBeNull();
    // The device restarts from the same disk and the run is registered.
    const restarted = device(store, "d", disk);
    expect(await restarted.publishPending()).toMatchObject({
      status: "registered",
    });
    expect(disk.cursor).toBe("cursor-1");
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, v: "only-copy" },
    ]);
  });

  it("a stopped publish does not advance the cursor either", async () => {
    const { store } = await seed();
    const d = device(store, "d");
    d.completeRun(run([{ id: 2 }]), "cursor-2");
    store.deleteConnection(ref.connectionId);
    expect(await d.publishPending()).toMatchObject({
      status: "stopped",
      runDisposition: "discard",
    });
    expect(d.disk.cursor).toBeNull();
    expect(d.disk.pending).toBeNull();
  });

  it("the outcome carries the disposition so a host cannot mistake pending for done", async () => {
    const { store } = await seed();
    const outcome = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 2 }], 2000)),
    );
    expect(outcome.runDisposition).toBe("complete");
  });
});

describe("no retry limit drops a run", () => {
  it("when attempts run out the run stays pending, and a later attempt registers it", async () => {
    const store = newStore();
    const { base } = await seed(store);
    let bump = 100;
    const busy: PublishPorts = {
      ...store.portsFor("a"),
      commitHead: async (r, request) => {
        await publishStream(
          store.portsFor("other"),
          args(run([{ id: bump++ }], 1100)),
        );
        return store.portsFor("a").commitHead(r, request);
      },
    };
    const disk = newDeviceDisk();
    disk.localBase = base;
    const outcome = await publishStream(
      busy,
      args(run([{ id: 2, v: "mine" }], 2000), {
        maxAttempts: 2,
        localBase: base,
      }),
    );
    expect(outcome).toEqual({
      status: "pending",
      runDisposition: "keep-pending",
      reason: "conflict-retries-exhausted",
      attempts: 2,
    });
    // Later, with the registry quiet, the SAME run registers and keeps the others' rows.
    const later = await publishStream(
      store.portsFor("a"),
      args(run([{ id: 2, v: "mine" }], 2000)),
    );
    expect(later.status).toBe("registered");
    const copy = values((await store.readStream(ref))!.records);
    expect(copy).toContainEqual({ id: 2, v: "mine" });
    expect(copy).toContainEqual({ id: 100 });
    expect(DEFAULT_MAX_ATTEMPTS).toBe(5);
  });

  it("a device keeps its pending run and cursor when attempts run out", async () => {
    const store = newStore();
    await seed(store);
    let bump = 100;
    const disk = newDeviceDisk();
    const d = new ReferenceDevice("a", store, ctx, disk, {
      beforeCommit: async () => {
        await publishStream(
          store.portsFor("other"),
          args(run([{ id: bump++ }], 1100)),
        );
      },
    });
    d.completeRun(run([{ id: 2 }], 2000), "cursor-2");
    expect(await d.publishPending(1)).toMatchObject({
      status: "pending",
      runDisposition: "keep-pending",
    });
    expect(disk.pending).not.toBeNull();
    expect(disk.cursor).toBeNull();
  });

  it("spaces later attempts with a capped doubling delay", () => {
    expect(backoffDelayMs(0)).toBe(0);
    expect(backoffDelayMs(1)).toBe(1_000);
    expect(backoffDelayMs(2)).toBe(2_000);
    expect(backoffDelayMs(4)).toBe(8_000);
    expect(backoffDelayMs(50)).toBe(300_000);
    expect(backoffDelayMs(3, { baseMs: 10, maxMs: 25 })).toBe(25);
  });
});

describe("reconnect", () => {
  const rows = [
    { id: 1, v: "a" },
    { id: 2, v: "b" },
  ];

  it("reconnect registers an empty live head over the tombstone, using the tombstone's version", async () => {
    const { store } = await seed(newStore(), rows);
    store.deleteConnection(ref.connectionId);
    store.runCleanup(ref.connectionId);
    expect(store.snapshot(ref)).toEqual({ kind: "tombstone", version: "2" });
    const outcome = await reconnectStream(store.portsFor("owner"), ctx);
    expect(outcome).toEqual({ status: "reconnected", version: "3" });
    expect(store.snapshot(ref).kind).toBe("head");
    expect(await store.readStream(ref)).toMatchObject({
      version: "3",
      records: [],
    });
    const [last] = store.events.slice(-1);
    expect(last).toMatchObject({
      op: "commit-head",
      intent: "reconnect",
      result: "committed",
    });
  });

  it("a device that stopped at the tombstone resumes when it sees the live head, with its cursor cleared", async () => {
    const { store, base } = await seed(newStore(), rows);
    const disk = newDeviceDisk();
    disk.localBase = base;
    disk.cursor = "old-cursor";
    const phone = new ReferenceDevice("phone", store, ctx, disk);
    store.deleteConnection(ref.connectionId);
    expect(await phone.syncDownload()).toBe("tombstoned");
    expect(disk).toMatchObject({ stopped: true, cursor: null, pending: null });
    expect(() => phone.completeRun(run([{ id: 3 }]), "c")).toThrow(
      HostContractError,
    );
    // The owner reconnects on another device; the phone is not told directly.
    store.runCleanup(ref.connectionId);
    await reconnectStream(store.portsFor("desktop"), ctx);
    expect(await phone.syncDownload()).toBe("live");
    expect(disk).toMatchObject({ stopped: false, cursor: null });
    phone.completeRun(run([{ id: 3, v: "c" }], 3000), "c-1");
    expect(await phone.publishPending()).toMatchObject({
      status: "registered",
    });
    expect(ids((await store.readStream(ref))!.records)).toEqual([3]);
  });

  it("a device that never saw the tombstone rebases onto the live empty head and is not stopped", async () => {
    const { store, base } = await seed(newStore(), rows);
    store.deleteConnection(ref.connectionId);
    store.runCleanup(ref.connectionId);
    await reconnectStream(store.portsFor("desktop"), ctx);
    const outcome = await publishStream(
      store.portsFor("phone"),
      args(run([{ id: 3, v: "owed" }], 4000), { localBase: base, ...{} }),
    );
    // The connection is live again, so the owed run is registered, not dropped.
    expect(outcome).toMatchObject({ status: "registered" });
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 3, v: "owed" },
    ]);
  });

  it("reconnect on a stream that is not tombstoned does nothing", async () => {
    const { store } = await seed();
    expect(await reconnectStream(store.portsFor("o"), ctx)).toEqual({
      status: "not-tombstoned",
      latest: "live",
    });
    expect(
      await reconnectStream(store.portsFor("o"), { ...ctx, stream: "nothing" }),
    ).toEqual({
      status: "not-tombstoned",
      latest: "none",
    });
  });

  it("two devices reconnect at once; exactly one registers", async () => {
    const { store } = await seed(newStore(), rows);
    store.deleteConnection(ref.connectionId);
    store.runCleanup(ref.connectionId);
    const first = await reconnectStream(store.portsFor("a"), ctx);
    expect(first.status).toBe("reconnected");
    expect((await reconnectStream(store.portsFor("b"), ctx)).status).toBe(
      "not-tombstoned",
    );
  });

  it("reconnect is blocked until the delete's blob cleanup is final", async () => {
    const { store } = await seed(newStore(), rows);
    const queued = store.deleteConnection(ref.connectionId);
    expect(queued.length).toBeGreaterThan(0);
    expect(store.cleanupFinal(ref.connectionId)).toBe(false);
    expect(await reconnectStream(store.portsFor("owner"), ctx)).toEqual({
      status: "blocked",
      reason: "cleanup-pending",
    });
    expect(store.snapshot(ref).kind).toBe("tombstone");
    store.runCleanup(ref.connectionId);
    expect((await reconnectStream(store.portsFor("owner"), ctx)).status).toBe(
      "reconnected",
    );
  });

  it("re-collecting the same rows after the reconnect gives the same part names, and cleanup cannot delete them", async () => {
    const { store } = await seed(newStore(), rows);
    const firstHead = store.snapshot(ref);
    if (firstHead.kind !== "head") throw new Error("expected a head");
    const queued = store.deleteConnection(ref.connectionId);
    // The user reconnects at once; the registry refuses until cleanup is final.
    expect((await reconnectStream(store.portsFor("owner"), ctx)).status).toBe(
      "blocked",
    );
    expect(store.runCleanup(ref.connectionId)).toEqual(queued);
    await reconnectStream(store.portsFor("owner"), ctx);
    const outcome = await publishStream(
      store.portsFor("a"),
      args(run(rows, 1000)),
    );
    expect(outcome.status).toBe("registered");
    // Same rows, same bytes, same part names as before the delete: the reason cleanup must finish first.
    if (outcome.status === "registered") {
      expect(store.names().filter((n) => n.includes(".part-"))).toEqual(
        queued.filter((n) => n.includes(".part-")),
      );
    }
    expect(values((await store.readStream(ref))!.records)).toEqual(rows);
    // There is nothing queued that could remove these names later.
    expect(store.runCleanup(ref.connectionId)).toEqual([]);
    expect(values((await store.readStream(ref))!.records)).toEqual(rows);
  });
});

describe("race points", () => {
  it("two devices plan from the same V and both try V -> V+1: exactly one wins, the loser lands in V+2", async () => {
    const { store, base } = await seed();
    const arrived = { a: gate(), b: gate() };
    const release = { a: gate(), b: gate() };
    const blockFirstCommit = (id: "a" | "b") => {
      let first = true;
      return async () => {
        if (!first) return;
        first = false;
        arrived[id].open();
        await release[id].promise;
      };
    };
    const runA = publishStream(
      store.portsFor("a", { beforeCommit: blockFirstCommit("a") }),
      args(run([{ id: 3, v: "from-a" }], 2000), { localBase: base }),
    );
    const runB = publishStream(
      store.portsFor("b", { beforeCommit: blockFirstCommit("b") }),
      args(run([{ id: 4, v: "from-b" }], 2100), { localBase: base }),
    );
    await Promise.all([arrived.a.promise, arrived.b.promise]);
    release.a.open();
    const outcomeA = await runA;
    release.b.open();
    const outcomeB = await runB;

    expect(outcomeA).toMatchObject({
      status: "registered",
      version: "2",
      attempts: 1,
    });
    expect(outcomeB).toMatchObject({
      status: "registered",
      version: "3",
      attempts: 2,
    });
    const commits = store.events.filter(
      (e) => e.op === "commit-head" && e.device !== "seed",
    );
    expect(commits.map((e) => e.op === "commit-head" && e.result)).toEqual([
      "committed",
      "version-moved",
      "committed",
    ]);
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, v: "a" },
      { id: 3, v: "from-a" },
      { id: 4, v: "from-b" },
    ]);
  });

  it("download lag: a device plans from a stale V while V+1 exists; the retry keeps both devices' rows", async () => {
    const { store, base } = await seed();
    await publishStream(
      store.portsFor("fast"),
      args(run([{ id: 5, v: "fast" }], 1500)),
    );
    expect(store.currentVersion(ref)).toBe("2");
    const outcome = await publishStream(
      store.portsFor("lagging"),
      args(run([{ id: 6, v: "lagging" }], 2000), { localBase: base }),
    );
    expect(outcome).toMatchObject({
      status: "registered",
      version: "3",
      attempts: 2,
    });
    expect(ids((await store.readStream(ref))!.records)).toEqual([1, 5, 6]);
    expect(
      store.events.filter(
        (e) => e.op === "commit-head" && e.result === "version-moved",
      ),
    ).toHaveLength(1);
  });

  it("an incremental device that never re-sends unchanged rows still keeps every other device's rows", async () => {
    const { store, base } = await seed(newStore(), [
      { id: 1, v: "a" },
      { id: 2, v: "b" },
    ]);
    await publishStream(
      store.portsFor("other"),
      args(run([{ id: 3, v: "c" }], 1500)),
    );
    await publishStream(
      store.portsFor("incremental"),
      args(run([{ id: 2, v: "b2" }], 2000), { localBase: base }),
    );
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, v: "a" },
      { id: 2, v: "b2" },
      { id: 3, v: "c" },
    ]);
  });

  it("a reader that reads head H1 while a writer uploads parts for H2 gets exactly H1's data", async () => {
    const { store } = await seed(newStore(), [{ id: 1, v: "h1" }]);
    const paused = gate();
    const resume = gate();
    const writer = publishStream(
      store.portsFor("w", {
        afterPutPart: async () => {
          paused.open();
          await resume.promise;
        },
      }),
      args(run([{ id: 2, v: "h2" }], 2000)),
    );
    await paused.promise; // H2's part is stored; H2's head is not
    const during = await store.readStream(ref);
    expect(during).toEqual({
      version: "1",
      records: stamped([{ id: 1, v: "h1" }], 1000),
    });
    resume.open();
    expect((await writer).status).toBe("registered");
    expect(ids((await store.readStream(ref))!.records)).toEqual([1, 2]);
  });

  it("a reader that already holds H1 still reads H1 after H2 is registered", async () => {
    const { store } = await seed(newStore(), [{ id: 1, v: "h1" }]);
    const snapshot = store.snapshot(ref);
    if (snapshot.kind !== "head") throw new Error("expected a head");
    await publishStream(
      store.portsFor("w"),
      args(run([{ id: 2, v: "h2" }], 2000)),
    );
    const { decodeHead } = await import("./head.js");
    const { assemble } = await import("./assemble.js");
    const records = await assemble(
      decodeHead(store.readHead(ref, snapshot.headHash)!),
      async (hash) => store.readPart(ref, hash),
      nodeSha256,
      ref,
    );
    expect(plainRecords(records)).toEqual([{ id: 1, v: "h1" }]);
  });

  it("a crash after parts and before the head is registered leaves no change visible", async () => {
    const { store, version } = await seed();
    const objectsBefore = store.names().length;
    const crashing = store.portsFor("a", {
      beforeCommit: () => {
        throw new Error("crash before head");
      },
    });
    await expect(
      publishStream(crashing, args(run([{ id: 2 }], 2000))),
    ).rejects.toThrow("crash before head");
    expect(store.currentVersion(ref)).toBe(version);
    expect(values((await store.readStream(ref))!.records)).toEqual([
      { id: 1, v: "a" },
    ]);
    expect(store.names().length).toBeGreaterThan(objectsBefore); // orphan objects stored
  });

  it("a tombstone between planning and the head write: the write never succeeds afterwards", async () => {
    const { store } = await seed();
    const outcome = await publishStream(
      store.portsFor("a", {
        beforeCommit: () => void store.deleteConnection(ref.connectionId),
      }),
      args(run([{ id: 2 }], 2000)),
    );
    expect(outcome.status).toBe("stopped");
    expect(await store.readStream(ref)).toBeNull();
    expect(store.events.at(-1)).toMatchObject({
      op: "commit-head",
      result: "tombstoned",
    });
  });
});

describe("connection deletion on the reference host", () => {
  it("queues every stream, head object and part of the connection and nothing of another", async () => {
    const store = newStore();
    await publishStream(
      store.portsFor("a"),
      args(run([{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }]), {
        partSizeBytes: 60,
      }),
    );
    await publishStream(store.portsFor("a"), {
      ...ctx,
      stream: "other-stream",
      run: run([{ id: 1 }]),
    });
    await publishStream(store.portsFor("a"), {
      ...ctx,
      connectionId: "pdpp",
      run: run([{ id: 1 }]),
    });
    const queued = store.deleteConnection("conn");
    expect(queued.some((n) => n.includes(".head-"))).toBe(true);
    expect(
      queued.filter((n) => n.includes(".part-")).length,
    ).toBeGreaterThanOrEqual(3);
    store.runCleanup("conn");
    const left = filesOfConnection(store.names(), "conn");
    expect(left).toEqual(["pdpp.conn.items", "pdpp.conn.other-stream"]); // only the tombstoned registry keys remain
    expect(
      store.names().filter((n) => n.startsWith("pdpp.pdpp.")).length,
    ).toBeGreaterThanOrEqual(3);
    expect(store.snapshot(ref).kind).toBe("tombstone");
  });
});
