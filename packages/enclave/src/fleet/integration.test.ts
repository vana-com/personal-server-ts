import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it, vi } from "vitest";
import { createFakeDstackClient } from "../dstack/fake.js";
import { openFleetController } from "./placement.js";
import { createFleetWorker } from "./worker.js";
import {
  createFleetPeerClient,
  createFleetPeerServer,
  fleetWorkerPort,
} from "./peer.js";
import type {
  FleetPeerIdentity,
  FleetPrepareRequest,
  FleetAssignment,
  FleetExecuteRequest,
} from "./contracts.js";

it("routes one owner through encrypted worker peers, drains, then fences crash failover", async () => {
  const path = await mkdtemp(join(tmpdir(), "fleet-integration-"));
  let now = 1_000;
  const identity = (nodeId: string): FleetPeerIdentity => ({
    role: nodeId === "controller" ? "controller" : "worker",
    nodeId,
    nodeIncarnation: `${nodeId}-boot`,
    appId: nodeId === "controller" ? "central-app" : "worker-app",
    instanceId: nodeId,
    composeHash: "approved",
  });
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const captures: string[] = [];
  const createNode = (nodeId: string) => {
    let online = true;
    const observations = (r: FleetPrepareRequest) =>
      r.scopes.map((s) => ({
        assignment: r.assignment,
        scope: s.scope,
        dataVersion: s.minimumVersion ?? 1,
        state: "ready" as const,
        observedAt: new Date(now).toISOString(),
      }));
    const backend = {
      activity: () => ({ present: true, busy: false }),
      prepare: vi.fn(async (r: FleetPrepareRequest) => observations(r)),
      readiness: async (r: FleetPrepareRequest) => observations(r),
      execute: vi.fn(async (_r: FleetExecuteRequest) => ({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ nodeId, privateData: "owner-secret" }),
      })),
      release: vi.fn(async () => {}),
    };
    const worker = createFleetWorker({
      nodeId,
      nodeIncarnation: `${nodeId}-boot`,
      capacity: 1,
      backend,
      wallNow: () => now,
      monotonicNow: () => now,
    });
    const handler = createFleetPeerServer({
      identity: identity(nodeId),
      client: dstack,
      verifyPeer: async (_e, _d, claims) => {
        expect(claims).toEqual(identity("controller"));
      },
      dispatch: async (method, body) => {
        switch (method) {
          case "prepare":
            return worker.prepare(body as FleetPrepareRequest);
          case "readiness":
            return worker.readiness(body as FleetPrepareRequest);
          case "renew":
            return worker.renew(body as FleetAssignment);
          case "activity":
            return worker.activity(body as FleetAssignment);
          case "release":
            return worker.release(body as FleetAssignment);
          case "execute":
            return worker.execute(body as FleetExecuteRequest);
          default:
            throw new Error("unsupported");
        }
      },
    });
    const peer = createFleetPeerClient({
      identity: identity("controller"),
      client: dstack,
      expectedPeer: identity(nodeId),
      baseUrl: `https://${nodeId}.invalid`,
      verifyPeer: async (_e, _d, claims) => {
        expect(claims).toEqual(identity(nodeId));
      },
      fetch: async (input, init) => {
        if (!online) throw new Error("worker stopped");
        captures.push(String(init?.body));
        const response = await handler(new Request(input, init));
        captures.push(await response.clone().text());
        return response;
      },
    });
    return {
      worker,
      backend,
      port: fleetWorkerPort(peer),
      stop: () => {
        online = false;
      },
    };
  };
  const a = createNode("a"),
    b = createNode("b");
  const options = {
    path: join(path, "placements.json"),
    drainGraceMs: 0,
    now: () => now,
    enroll: vi.fn(async () => {}),
    publish: vi.fn(async () => {}),
    release: vi.fn(async () => {}),
  };
  let controller = await openFleetController(options);
  const admit = async () => {
    await controller.admit({
      ...identity("a"),
      capacity: 1,
      worker: a.port,
      draining: false,
    });
    await controller.admit({
      ...identity("b"),
      capacity: 1,
      worker: b.port,
      draining: false,
    });
  };
  const owner = {
    chainId: 14800,
    userPsId: `0x${"1".repeat(64)}`,
    identityEpoch: 1,
  };
  const scopes = [{ scope: "chat", minimumVersion: 2 }];
  const execute = (assignment: FleetAssignment) =>
    controller.worker(assignment).execute({
      assignment,
      scopes,
      deadline: new Date(now + 20_000).toISOString(),
      requestId: "read",
      binding: {} as never,
      connection: {} as never,
      message: { privateData: "owner-secret" },
    });
  try {
    await admit();
    const allocation = await Promise.all([
      controller.ensure(owner, scopes),
      controller.ensure(owner, scopes),
      controller.ensure(owner, scopes),
    ]);
    expect(allocation.map((a) => [a.nodeId, a.generation])).toEqual([
      ["a", 1],
      ["a", 1],
      ["a", 1],
    ]);
    expect(a.worker.assignments()).toHaveLength(1);
    expect(b.worker.assignments()).toHaveLength(0);
    expect(JSON.parse((await execute(allocation[0])).body)).toMatchObject({
      nodeId: "a",
    });
    controller = await openFleetController(options);
    await admit();
    expect((await controller.ensure(owner, scopes)).generation).toBe(1);
    await controller.drain("a");
    expect(() => a.worker.assertCurrent(allocation[0])).toThrow(
      "stale placement",
    );
    const moved = await controller.ensure(owner, scopes);
    expect(moved).toMatchObject({ nodeId: "b", generation: 2 });
    expect(JSON.parse((await execute(moved)).body)).toMatchObject({
      nodeId: "b",
    });
    await controller.admit({
      ...identity("a"),
      capacity: 1,
      worker: a.port,
      draining: false,
    });
    b.stop();
    now += 10_000;
    await controller.renew();
    await expect(controller.ensure(owner, scopes)).rejects.toThrow();
    now += 30_001;
    const recovered = await controller.ensure(owner, scopes);
    expect(recovered).toMatchObject({ nodeId: "a", generation: 3 });
    expect(() => b.worker.assertCurrent(moved)).toThrow("stale placement");
    await expect(
      b.worker.execute({
        assignment: moved,
        scopes,
        deadline: new Date(now + 20_000).toISOString(),
        requestId: "old",
        binding: {} as never,
        connection: {} as never,
        message: {},
      }),
    ).rejects.toThrow("stale placement");
    expect(JSON.parse((await execute(recovered)).body)).toMatchObject({
      nodeId: "a",
    });
    expect(captures.some((c) => c.includes("owner-secret"))).toBe(false);
    await controller.drain("a");
  } finally {
    await rm(path, { recursive: true, force: true });
  }
});
