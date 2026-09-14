import { describe, expect, it, vi } from "vitest";
import { createFleetWorker } from "./worker.js";
import type { FleetAssignment } from "./contracts.js";

const assignment: FleetAssignment = {
  chainId: 14800,
  userPsId: `0x${"1".repeat(64)}`,
  identityEpoch: 1,
  nodeId: "worker-a",
  nodeIncarnation: "boot-a",
  generation: 1,
  controllerTerm: 1,
  state: "starting",
  leaseExpiresAt: new Date(30_000).toISOString(),
};
function fixture() {
  let wall = 0;
  let mono = 0;
  const backend = {
    activity: vi.fn().mockReturnValue({ present: false, busy: false }),
    prepare: vi.fn().mockResolvedValue([]),
    readiness: vi.fn().mockResolvedValue([]),
    execute: vi.fn().mockResolvedValue({
      status: 200,
      contentType: "application/json",
      body: "{}",
    }),
    release: vi.fn().mockResolvedValue(undefined),
  };
  const worker = createFleetWorker({
    nodeId: "worker-a",
    nodeIncarnation: "boot-a",
    capacity: 2,
    backend,
    wallNow: () => wall,
    monotonicNow: () => mono,
  });
  return {
    worker,
    backend,
    advance(ms: number) {
      mono += ms;
      wall += ms;
    },
    setWall(ms: number) {
      wall = ms;
    },
  };
}

describe("fleet worker assignment fencing", () => {
  it("rejects another node or incarnation before sandbox preparation", async () => {
    const { worker, backend } = fixture();
    await expect(
      worker.prepare({
        assignment: { ...assignment, nodeId: "worker-b" },
        scopes: [],
      }),
    ).rejects.toThrow("stale placement");
    await expect(
      worker.prepare({
        assignment: { ...assignment, nodeIncarnation: "old-boot" },
        scopes: [],
      }),
    ).rejects.toThrow("stale placement");
    expect(backend.prepare).not.toHaveBeenCalled();
  });
});

it("uses a conservative monotonic expiry and refuses late renewal even after wall clock rollback", async () => {
  const f = fixture();
  await f.worker.prepare({ assignment, scopes: [] });
  f.advance(29_001);
  f.setWall(0);
  expect(() => f.worker.assertCurrent(assignment)).toThrow("stale placement");
  await expect(
    f.worker.renew({
      ...assignment,
      leaseExpiresAt: new Date(30_000).toISOString(),
    }),
  ).rejects.toThrow("stale placement");
});

it("rejects obsolete responses when a backend ignores the abort signal", async () => {
  const f = fixture();
  await f.worker.prepare({ assignment, scopes: [] });
  f.backend.execute.mockImplementation(async () => {
    f.advance(29_001);
    return {
      status: 200,
      contentType: "application/json",
      body: "stale result",
    };
  });
  await expect(
    f.worker.execute({
      assignment,
      scopes: [],
      deadline: new Date(60_000).toISOString(),
      requestId: "read",
      binding: {} as never,
      connection: {} as never,
      message: {},
    }),
  ).rejects.toThrow("stale placement");
});

it("does not resurrect a released generation", async () => {
  const f = fixture();
  await f.worker.prepare({ assignment, scopes: [] });
  await f.worker.release(assignment);
  await expect(f.worker.prepare({ assignment, scopes: [] })).rejects.toThrow(
    "stale placement",
  );
  await expect(
    f.worker.prepare({
      assignment: { ...assignment, generation: 2 },
      scopes: [],
    }),
  ).resolves.toEqual([]);
});

it("tears down an expired executor before installing a replacement generation", async () => {
  const f = fixture();
  await f.worker.prepare({ assignment, scopes: [] });
  f.advance(29_001);
  await f.worker.prepare({
    assignment: {
      ...assignment,
      generation: 2,
      leaseExpiresAt: new Date(59_001).toISOString(),
    },
    scopes: [],
  });
  expect(f.backend.release).toHaveBeenCalledWith(assignment);
  expect(f.backend.release.mock.invocationCallOrder[0]).toBeLessThan(
    f.backend.prepare.mock.invocationCallOrder[1],
  );
});

it("does not extend a lease by replaying its expiry after wall-clock rollback", async () => {
  const f = fixture();
  await f.worker.prepare({ assignment, scopes: [] });
  f.advance(10_000);
  f.setWall(0);
  await f.worker.renew(assignment);
  f.advance(19_001);
  expect(() => f.worker.assertCurrent(assignment)).toThrow("stale placement");
});

it("rejects idle release while an accepted job is still decrypting before sandbox acquisition", async () => {
  const f = fixture();
  await f.worker.prepare({ assignment, scopes: [] });
  let done!: () => void;
  const job = f.worker.trackAssignment(
    assignment,
    () =>
      new Promise<void>((resolve) => {
        done = resolve;
      }),
  );
  expect(await f.worker.activity(assignment)).toMatchObject({
    present: false,
    busy: true,
  });
  await expect(f.worker.release(assignment)).rejects.toThrow("placement busy");
  await f.worker.renew({ ...assignment, state: "draining" });
  await expect(
    f.worker.trackAssignment(assignment, async () => {}),
  ).rejects.toThrow("stale placement");
  done();
  await job;
  await f.worker.release(assignment);
});
