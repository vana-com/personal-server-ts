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
  now = 21000;
  await controller.renew();
  now = 41001;
  expect(await controller.ensure(owner, [])).toMatchObject({
    nodeId: "b",
    generation: 2,
  });
  expect(a.renew).toHaveBeenCalledTimes(1);
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
