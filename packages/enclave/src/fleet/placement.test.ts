import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { openFleetController } from "./placement.js";
import type { FleetWorkerPort } from "./contracts.js";
const paths: string[] = [];
it("records approved-owner membership while paused without allocating a sandbox", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-membership-"));
  paths.push(path);
  const enroll = vi.fn(),
    publish = vi.fn();
  const options = {
    path: join(path, "state.json"),
    enroll,
    publish,
    release: vi.fn(),
    startPaused: true,
  };
  const controller = await openFleetController(options);
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.enroll(owner);
  await controller.enroll(owner);
  expect(controller.paused()).toBe(true);
  expect(controller.assignment(owner)).toBeNull();
  expect(publish).not.toHaveBeenCalled();
  expect((await openFleetController(options)).snapshot()).toEqual([
    expect.objectContaining({ owner, generation: 0, assignment: null }),
  ]);
});
afterEach(async () => {
  await Promise.all(
    paths.splice(0).map((p) => rm(p, { recursive: true, force: true })),
  );
});
it("joins MCP/prewarm/job allocation, preserves affinity and generations across restart", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-"));
  paths.push(path);
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const opts = {
    path: join(path, "placements.json"),
    publish: vi.fn(),
    enroll: vi.fn(),
    release: vi.fn(),
    now: () => 1000,
  };
  const controller = await openFleetController(opts);
  controller.admit({ nodeId: "a", nodeIncarnation: "a1", capacity: 2, worker });
  controller.admit({ nodeId: "b", nodeIncarnation: "b1", capacity: 2, worker });
  const owner = { chainId: 14800, userPsId: "0xabc", identityEpoch: 1 };
  const assignments = await Promise.all(
    Array.from({ length: 3 }, () => controller.ensure(owner, [])),
  );
  expect(assignments.map((x) => [x.nodeId, x.generation])).toEqual([
    ["a", 1],
    ["a", 1],
    ["a", 1],
  ]);
  expect(worker.prepare).toHaveBeenCalledTimes(1);
  const restarted = await openFleetController(opts);
  restarted.admit({ nodeId: "a", nodeIncarnation: "a1", capacity: 2, worker });
  expect((await restarted.ensure(owner, [])).generation).toBe(1);
  await restarted.drain("a");
  restarted.admit({ nodeId: "b", nodeIncarnation: "b1", capacity: 2, worker });
  expect(await restarted.ensure(owner, [])).toMatchObject({
    nodeId: "b",
    generation: 2,
  });
});

it("expires an ambiguous failed renewal instead of extending the dead worker forever", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-renew-"));
  paths.push(path);
  let now = 1000;
  const a: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(async () => {
      throw new Error("partition");
    }),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const b = { ...a, renew: vi.fn() };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker: a,
  });
  await controller.admit({
    nodeId: "b",
    nodeIncarnation: "b1",
    capacity: 1,
    worker: b,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);
  now = 11000;
  await controller.renew();

  // A blocked renewal whose lease is still live may still be executing: the
  // row keeps its slot and the sandbox is not released underneath it. The
  // second consecutive failure is what blocks it; the first only spends grace.
  now = 21000;
  await controller.renew();
  expect(controller.snapshot()[0]?.assignment).toMatchObject({ nodeId: "a" });
  expect(controller.nodeStatus()[0]).toMatchObject({ nodeId: "a", live: 1 });
  expect(a.release).not.toHaveBeenCalled();

  // Once it expires the row is a corpse: reaped, not skipped forever.
  now = 51001;
  await controller.renew();
  expect(controller.snapshot()[0]?.assignment).toBeNull();
  expect(a.release).toHaveBeenCalledTimes(1);
  expect(a.release).toHaveBeenCalledWith(
    expect.objectContaining({
      nodeId: "a",
      nodeIncarnation: "a1",
      generation: 1,
    }),
  );
  expect(controller.nodeStatus()[0]).toMatchObject({ nodeId: "a", live: 0 });
  expect(await controller.prune(["b"])).toEqual({
    removed: ["a"],
    retained: [],
  });

  expect(await controller.ensure(owner, [])).toMatchObject({
    nodeId: "b",
    generation: 2,
  });
  expect(a.renew).toHaveBeenCalledTimes(2);
});

it("reaps an expired placement even when the worker refuses the release", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-reap-"));
  paths.push(path);
  let now = 1000;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(async () => {
      throw new Error("partition");
    }),
    execute: vi.fn(),
    release: vi.fn(async () => {
      throw new Error("unreachable");
    }),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);
  now = 11000;
  await controller.renew();

  now = 41001;
  await expect(controller.renew()).resolves.toBeUndefined();

  expect(controller.snapshot()[0]?.assignment).toBeNull();
  expect(controller.nodeStatus()[0]).toMatchObject({ live: 0 });
});

it("keeps an owner in place through a single stalled renewal", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-grace-"));
  paths.push(path);
  let now = 1000;
  let stalls = 1;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(async () => {
      if (stalls-- > 0) throw new Error("Peer RPC deadline expired");
    }),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const events: string[] = [];
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
    event: (event) => {
      events.push(event);
    },
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);

  // A controller-side stall trips one tick. The member keeps its slot, the row
  // keeps its generation, and nothing is latched.
  now = 11000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({
    nodeId: "a",
    unavailable: false,
    live: 1,
  });
  expect(controller.snapshot()[0]).toMatchObject({
    generation: 1,
    renewalBlocked: false,
  });
  expect(events).toContain("placement_renewal_deferred");
  expect(events).not.toContain("placement_renewal_failed");

  now = 21000;
  await controller.renew();
  expect(controller.snapshot()[0]?.assignment).toMatchObject({
    generation: 1,
    leaseExpiresAt: new Date(51000).toISOString(),
  });

  // The success ended the streak, so a later isolated stall spends grace again
  // instead of landing on an exhausted counter.
  stalls = 1;
  now = 31000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({
    unavailable: false,
    live: 1,
  });
  expect(controller.snapshot()[0]).toMatchObject({
    generation: 1,
    renewalBlocked: false,
  });
});

it("demotes on the first renewal an attestation refusal rejects", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-terminal-"));
  paths.push(path);
  let now = 1000;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(async () => {
      throw new Error("Peer measurements rejected");
    }),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);

  // The grace covers stalls, never a verdict on the peer itself.
  now = 11000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({ unavailable: true });
  expect(controller.snapshot()[0]).toMatchObject({ renewalBlocked: true });
  expect(worker.renew).toHaveBeenCalledTimes(1);

  now = 41001;
  await controller.renew();
  expect(controller.snapshot()[0]?.assignment).toBeNull();
  expect(controller.nodeStatus()[0]).toMatchObject({ live: 0 });
});

it("releases a renewal block once the member answers again", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-unlatch-"));
  paths.push(path);
  let now = 1000;
  let stalls = 2;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(async () => {
      if (stalls-- > 0) throw new Error("Peer RPC deadline expired");
    }),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
  });
  const member = {
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  };
  await controller.admit(member);
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);

  now = 11000;
  await controller.renew();
  now = 21000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({ unavailable: true });
  expect(controller.snapshot()[0]).toMatchObject({ renewalBlocked: true });

  // The warm-pool loop re-admits the member while the lease is still live. The
  // block must lift with it, or the lease lapses and every owner is evicted.
  now = 25000;
  await controller.admit(member);
  now = 30000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({
    unavailable: false,
    live: 1,
  });
  expect(controller.snapshot()[0]).toMatchObject({
    generation: 1,
    renewalBlocked: false,
  });
  expect(await controller.ensure(owner, [])).toMatchObject({ generation: 1 });
});

it("renewal during slow hydration preserves the ready state and latest lease", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-slow-"));
  paths.push(path);
  let now = 1000;
  let prepared!: () => void;
  const blocked = new Promise<void>((r) => {
    prepared = r;
  });
  let started!: () => void;
  const entered = new Promise<void>((r) => {
    started = r;
  });
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => {
      started();
      await blocked;
      return [];
    }),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  const starting = controller.ensure(owner, []);
  await entered;
  now = 11000;
  await controller.renew();
  prepared();
  const assignment = await starting;
  expect(assignment.state).toBe("ready");
  expect(Date.parse(assignment.leaseExpiresAt)).toBe(41000);
  expect(controller.assignment(owner)).toEqual(assignment);
});

it("releases an evicted idle sandbox reservation only after worker acknowledgment", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-idle-"));
  paths.push(path);
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: false,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => 1000,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);
  await controller.renew();
  expect(controller.assignment(owner)).toBeNull();
  expect(worker.release).toHaveBeenCalledTimes(1);
  expect((await controller.ensure(owner, [])).generation).toBe(2);
});

it("an obsolete owner projection never disables an unrelated owner on the worker", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-epoch-"));
  paths.push(path);
  let rejectOld = false;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: async (a) => {
      if (rejectOld && a.userPsId === "old") throw new Error("retired epoch");
    },
    release: vi.fn(),
    now: () => 1000,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 3,
    worker,
  });
  await controller.ensure(
    { chainId: 14800, userPsId: "old", identityEpoch: 1 },
    [],
  );
  await controller.ensure(
    { chainId: 14800, userPsId: "unrelated", identityEpoch: 1 },
    [],
  );
  rejectOld = true;
  await controller.renew();
  expect(
    await controller.ensure(
      { chainId: 14800, userPsId: "third", identityEpoch: 1 },
      [],
    ),
  ).toMatchObject({ nodeId: "a" });
});

it("a delayed idle-release acknowledgment cannot clear a newer reserved generation", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-release-race-"));
  paths.push(path);
  let now = 1000;
  let releaseEntered!: () => void;
  const entered = new Promise<void>((r) => (releaseEntered = r));
  let acknowledge!: () => void;
  const held = new Promise<void>((r) => (acknowledge = r));
  let reserved!: () => void;
  const newerReserved = new Promise<void>((r) => (reserved = r));
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: false,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: async () => {
      releaseEntered();
      await held;
    },
    now: () => now,
    event: (event, fields) => {
      if (event === "placement_starting" && fields.generation === 2) reserved();
    },
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);
  now = 11000;
  const renewing = controller.renew();
  await entered;
  now = 42000;
  const replacing = controller.ensure(owner, []);
  await newerReserved;
  acknowledge();
  await renewing;
  expect(await replacing).toMatchObject({ generation: 2, state: "ready" });
  expect(controller.assignment(owner)?.generation).toBe(2);
});

it("persists a recovery pause and never reenrolls on restart until explicit activation", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-pause-"));
  paths.push(path);
  const enroll = vi.fn();
  const options = {
    path: join(path, "state.json"),
    enroll,
    publish: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController(options);
  await controller.pause();
  const restarted = await openFleetController(options);
  await expect(
    restarted.ensure(
      { chainId: 14800, userPsId: "owner", identityEpoch: 1 },
      [],
    ),
  ).rejects.toThrow("paused");
  expect(enroll).not.toHaveBeenCalled();
  expect(restarted.paused()).toBe(true);
  await restarted.resume();
  expect(restarted.paused()).toBe(false);
});

it("declares a stopped pool member as visible, unselectable and drainable", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-declare-"));
  paths.push(path);
  const worker: FleetWorkerPort = {
    activity: vi.fn(),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const options = {
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController(options);
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.declare({ nodeId: "stopped", capacity: 2 });
  await controller.declare({ nodeId: "stopped", capacity: 9 });

  expect(controller.nodeStatus()).toEqual([
    {
      nodeId: "stopped",
      nodeIncarnation: "",
      capacity: 2,
      draining: false,
      unavailable: true,
      live: 0,
    },
  ]);
  await expect(controller.ensure(owner, [])).rejects.toThrow(
    "Fleet capacity unavailable",
  );
  await expect(controller.drain("stopped")).resolves.toBeUndefined();
  expect(controller.nodeStatus()[0]?.draining).toBe(true);

  // A later attestation must clear neither the operator drain nor the capacity.
  await controller.admit({
    nodeId: "stopped",
    nodeIncarnation: "i1",
    capacity: 2,
    worker,
  });
  expect(controller.nodeStatus()[0]).toMatchObject({
    draining: true,
    unavailable: false,
  });

  // Only an explicit resume clears the operator's durable drain decision.
  await controller.admit({
    nodeId: "stopped",
    nodeIncarnation: "i2",
    capacity: 2,
    worker,
    draining: false,
  });
  expect(controller.nodeStatus()[0]).toMatchObject({
    draining: false,
    unavailable: false,
  });
  expect((await openFleetController(options)).nodeStatus()).toHaveLength(1);
});

it("prunes retired directory members but keeps one a placement still references", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-prune-"));
  paths.push(path);
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const options = {
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController(options);
  await controller.admit({
    nodeId: "held",
    nodeIncarnation: "h1",
    capacity: 1,
    worker,
  });
  await controller.declare({ nodeId: "orphan", capacity: 1 });
  await controller.ensure(
    { chainId: 14800, userPsId: "owner", identityEpoch: 1 },
    [],
  );

  expect(await controller.prune(["kept"])).toEqual({
    removed: ["orphan"],
    retained: ["held"],
  });
  expect(controller.nodeStatus().map((node) => node.nodeId)).toEqual(["held"]);
});

it("demotes an admitted member the controller can no longer reach", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-unavailable-"));
  paths.push(path);
  const worker: FleetWorkerPort = {
    activity: vi.fn(),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const options = {
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
  };
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  const controller = await openFleetController(options);
  await controller.declare({ nodeId: "member", capacity: 2 });
  await controller.admit({
    nodeId: "member",
    nodeIncarnation: "i1",
    capacity: 2,
    worker,
  });
  expect(controller.nodeStatus()[0]).toMatchObject({ unavailable: false });

  await controller.markUnavailable("member");

  expect(controller.nodeStatus()[0]).toMatchObject({
    unavailable: true,
    draining: false,
  });
  await expect(controller.ensure(owner, [])).rejects.toThrow(
    "Fleet capacity unavailable",
  );

  // A restart keeps the persisted entry but loses every admitted worker port,
  // so the boot-time redeclaration must not report the member as available.
  await controller.admit({
    nodeId: "member",
    nodeIncarnation: "i2",
    capacity: 2,
    worker,
  });
  await controller.drain("member");
  const restarted = await openFleetController(options);
  expect(restarted.nodeStatus()[0]).toMatchObject({ unavailable: false });

  await restarted.declare({ nodeId: "member", capacity: 2 });

  expect(restarted.nodeStatus()[0]).toMatchObject({
    unavailable: true,
    draining: true,
  });
});

it("extends the lease only for a renewal that lands", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-rollback-"));
  paths.push(path);
  let now = 1000;
  let stalled = false;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(async () => {
      if (stalled) throw new Error("Peer RPC deadline expired");
    }),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);

  // A renewal the member answered buys the next lease period.
  now = 11000;
  await controller.renew();
  expect(controller.snapshot()[0]?.assignment).toMatchObject({
    leaseExpiresAt: new Date(41000).toISOString(),
  });

  // One that never lands must not: the expiry stays where the last answer left
  // it, so the row lapses inside one lease instead of being immortal.
  stalled = true;
  now = 21000;
  await controller.renew();
  now = 31000;
  await controller.renew();
  expect(controller.snapshot()[0]?.assignment).toMatchObject({
    leaseExpiresAt: new Date(41000).toISOString(),
  });

  now = 41001;
  await controller.renew();
  expect(controller.snapshot()[0]?.assignment).toBeNull();
  expect(worker.release).toHaveBeenCalledTimes(1);
});

it("renews the member before the Gateway sees the extension, and never projects a refused one", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-order-"));
  paths.push(path);
  let now = 1000;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const publish = vi.fn();
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish,
    release: vi.fn(),
    now: () => now,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 1,
    worker,
  });
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  await controller.ensure(owner, []);
  const allocation = publish.mock.calls.length;

  // The Gateway round trip must not stand between the tick and the worker's
  // own retirement timer, so the member is renewed first.
  now = 11000;
  await controller.renew();
  expect(vi.mocked(worker.renew).mock.invocationCallOrder[0]).toBeLessThan(
    publish.mock.invocationCallOrder[allocation]!,
  );
  expect(publish).toHaveBeenLastCalledWith(
    expect.objectContaining({ leaseExpiresAt: new Date(41000).toISOString() }),
  );

  vi.mocked(worker.renew).mockRejectedValue(new Error("stale placement"));
  now = 21000;
  await controller.renew();
  now = 31000;
  await controller.renew();
  expect(publish).toHaveBeenCalledTimes(allocation + 1);
});

it("re-places an owner whose worker has retired the lease as stale", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-stale-"));
  paths.push(path);
  let now = 1000;
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    // The worker retires its own lease a second before the controller's expiry
    // and refuses every later call on it. Nothing it is sent can revive the
    // row, so the outage ends only if the controller lets the lease lapse.
    renew: vi.fn(async () => {
      throw new Error("stale placement");
    }),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
  });
  const member = { nodeId: "a", nodeIncarnation: "a1", capacity: 1, worker };
  await controller.admit(member);
  const owner = { chainId: 14800, userPsId: "owner", identityEpoch: 1 };
  expect(await controller.ensure(owner, [])).toMatchObject({ generation: 1 });

  for (now of [11000, 21000, 31001]) await controller.renew();

  // Inside one lease of the last answer, not forever.
  expect(controller.snapshot()[0]?.assignment).toBeNull();
  expect(controller.nodeStatus()[0]).toMatchObject({ live: 0 });

  // The pool loop re-admits the member it can still attest, as it did tonight.
  await controller.admit(member);
  expect(await controller.ensure(owner, [])).toMatchObject({
    nodeId: "a",
    generation: 2,
  });
});

it("spends the renew grace once per tick, not once per owner on the member", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-grace-capacity-"));
  paths.push(path);
  let now = 1000;
  let stalled = true;
  const events: string[] = [];
  const worker: FleetWorkerPort = {
    activity: vi.fn(async (assignment) => ({
      assignment,
      present: true,
      busy: false,
    })),
    prepare: vi.fn(async () => []),
    readiness: vi.fn(async () => []),
    renew: vi.fn(async () => {
      if (stalled) throw new Error("Peer RPC deadline expired");
    }),
    execute: vi.fn(),
    release: vi.fn(),
  };
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll: vi.fn(),
    publish: vi.fn(),
    release: vi.fn(),
    now: () => now,
    event: (event) => {
      events.push(event);
    },
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 3,
    worker,
  });
  for (const userPsId of ["owner-1", "owner-2", "owner-3"])
    await controller.ensure({ chainId: 14800, userPsId, identityEpoch: 1 }, []);
  expect(controller.nodeStatus()[0]).toMatchObject({ live: 3 });

  // `renew` fans the rows out together, so one stalled tick reaches the grace
  // three times. Counting rows would demote this member on its second owner,
  // inside the very first tick - the controller stall the grace exists for.
  now = 11000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({
    unavailable: false,
    live: 3,
  });
  expect(events).toContain("placement_renewal_deferred");
  expect(events).not.toContain("placement_renewal_failed");

  // A tick the member answers ends the streak, so the next stall starts over.
  stalled = false;
  now = 16000;
  await controller.renew();
  stalled = true;

  now = 21000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({
    unavailable: false,
    live: 3,
  });
  expect(events).not.toContain("placement_renewal_failed");

  // Two consecutive stalled ticks demote, exactly as they do at capacity 1.
  now = 26000;
  await controller.renew();
  expect(controller.nodeStatus()[0]).toMatchObject({ unavailable: true });
  expect(controller.snapshot()[0]).toMatchObject({ renewalBlocked: true });
  expect(events).toContain("placement_renewal_failed");
});
