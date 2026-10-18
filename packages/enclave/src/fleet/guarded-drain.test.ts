import { mkdtemp, rm, rename, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { openFleetController } from "./placement.js";
import { createFleetControlHttp } from "./controller-http.js";
import type { FleetWorkerPort } from "./contracts.js";
const paths: string[] = [];
afterEach(async () => {
  await Promise.all(
    paths.splice(0).map((p) => rm(p, { recursive: true, force: true })),
  );
});
async function fixture() {
  const path = await mkdtemp(join(tmpdir(), "guarded-drain-"));
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
  const release = vi.fn(),
    enroll = vi.fn();
  let now = 1000;
  const controller = await openFleetController({
    path: join(path, "state.json"),
    enroll,
    publish: vi.fn(),
    release,
    now: () => now,
    drainGraceMs: 0,
  });
  await controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 4,
    worker,
  });
  const owner = {
    chainId: 14800,
    userPsId: `0x${"1".repeat(64)}`,
    identityEpoch: 1,
  };
  const assignment = await controller.ensure(owner, []);
  const handler = createFleetControlHttp({
    controller,
    credential: "a".repeat(32),
    role: "admin",
    identity: vi.fn(),
    seal: vi.fn(),
    admit: vi.fn(),
    migrate: vi.fn(),
    prepareRollback: vi.fn(),
    activate: vi.fn(),
    quiesce: vi.fn(),
  });
  const drain = (body: unknown) =>
    handler(
      new Request("https://local.invalid/fleet/v1/drain", {
        method: "POST",
        headers: { authorization: `Bearer ${"a".repeat(32)}` },
        body: JSON.stringify(body),
      }),
    );
  return {
    path,
    worker,
    release,
    enroll,
    controller,
    owner,
    assignment,
    drain,
    setTime: (value: number) => {
      now = value;
    },
  };
}
it("rejects an unexpected placement through the admin route without draining or releasing it", async () => {
  const f = await fixture();
  const before = f.controller.snapshot();
  const response = await f.drain({ nodeId: "a", expectedAssignments: [] });
  expect(response.status).toBe(409);
  expect(f.controller.snapshot()).toEqual(before);
  expect(f.controller.nodeStatus()[0]?.draining).toBe(false);
  expect(f.worker.release).not.toHaveBeenCalled();
  expect(f.release).not.toHaveBeenCalled();
});

it("drains only the exact expected assignment and preserves enrollment", async () => {
  const f = await fixture();
  const enrolled = f.enroll.mock.calls.length;
  expect(
    (await f.drain({ nodeId: "a", expectedAssignments: [f.assignment] }))
      .status,
  ).toBe(200);
  expect(f.worker.release).toHaveBeenCalledWith(
    expect.objectContaining({ generation: 1, userPsId: f.owner.userPsId }),
  );
  expect(f.controller.assignment(f.owner)).toBeNull();
  expect(f.enroll).toHaveBeenCalledTimes(enrolled);
  expect(f.controller.nodeStatus()[0]?.draining).toBe(true);
});
it("rejects stale generations, incarnations and leases without changing state", async () => {
  const f = await fixture();
  for (const delta of [
    { generation: 2 },
    { nodeIncarnation: "old" },
    { leaseExpiresAt: new Date(999).toISOString() },
  ]) {
    expect(
      (
        await f.drain({
          nodeId: "a",
          expectedAssignments: [{ ...f.assignment, ...delta }],
        })
      ).status,
    ).toBe(409);
    expect(f.controller.nodeStatus()[0]?.draining).toBe(false);
  }
  expect(f.worker.release).not.toHaveBeenCalled();
});
it("rejects malformed, duplicate and unknown guard arguments without falling back", async () => {
  const f = await fixture();
  for (const body of [
    { nodeId: "a", expectedAssignments: null },
    { nodeId: "a", expectedAssignments: [f.assignment, f.assignment] },
    { nodeId: "a", expectedAssignments: [{ ...f.assignment, extra: true }] },
    { nodeId: "a", expectedOwner: [] },
  ])
    expect((await f.drain(body)).status).toBe(400);
  expect(f.worker.release).not.toHaveBeenCalled();
  expect(f.controller.nodeStatus()[0]?.draining).toBe(false);
});
it("fences concurrent placement and resume until captured releases finish", async () => {
  const f = await fixture();
  let started!: () => void, finish!: () => void;
  const entered = new Promise<void>((r) => {
    started = r;
  });
  const hold = new Promise<void>((r) => {
    finish = r;
  });
  f.worker.release = vi.fn(async () => {
    started();
    await hold;
  });
  const operation = f.drain({
    nodeId: "a",
    expectedAssignments: [f.assignment],
  });
  await entered;
  await expect(
    f.controller.ensure({ ...f.owner, userPsId: `0x${"2".repeat(64)}` }, []),
  ).rejects.toThrow("capacity unavailable");
  await expect(
    f.controller.admit({
      nodeId: "a",
      nodeIncarnation: "a1",
      capacity: 4,
      worker: f.worker,
      draining: false,
    }),
  ).rejects.toThrow("Drain in progress");
  expect(
    (await f.drain({ nodeId: "a", expectedAssignments: [f.assignment] }))
      .status,
  ).toBe(409);
  finish();
  expect((await operation).status).toBe(200);
  expect(f.worker.release).toHaveBeenCalledTimes(1);
});
it("retains a fail-closed fence and releases nothing after a state write failure", async () => {
  const f = await fixture();
  await rename(f.path, `${f.path}-saved`);
  await writeFile(f.path, "not a directory");
  try {
    expect(
      (await f.drain({ nodeId: "a", expectedAssignments: [f.assignment] }))
        .status,
    ).toBe(503);
    expect(f.controller.nodeStatus()[0]?.draining).toBe(true);
    expect(f.worker.release).not.toHaveBeenCalled();
    expect(f.controller.assignment(f.owner)?.generation).toBe(1);
  } finally {
    await rm(f.path);
    await rename(`${f.path}-saved`, f.path);
  }
  expect(
    (await f.drain({ nodeId: "a", expectedAssignments: [f.assignment] }))
      .status,
  ).toBe(200);
});
it("supports a guarded empty-node drain and preserves the legacy explicit drain", async () => {
  const f = await fixture();
  expect((await f.drain({ nodeId: "a" })).status).toBe(200);
  await f.controller.admit({
    nodeId: "a",
    nodeIncarnation: "a1",
    capacity: 4,
    worker: f.worker,
    draining: false,
  });
  expect((await f.drain({ nodeId: "a", expectedAssignments: [] })).status).toBe(
    200,
  );
  expect(f.controller.nodeStatus()[0]?.draining).toBe(true);
});

it("fences a placement whose enrollment was already in flight before the guard", async () => {
  const f = await fixture();
  let entered!: () => void, finish!: () => void;
  const started = new Promise<void>((r) => {
    entered = r;
  });
  const hold = new Promise<void>((r) => {
    finish = r;
  });
  f.enroll.mockImplementationOnce(async () => {
    entered();
    await hold;
  });
  const allocation = f.controller.ensure(
    { ...f.owner, userPsId: `0x${"2".repeat(64)}` },
    [],
  );
  const failed = expect(allocation).rejects.toThrow("capacity unavailable");
  await started;
  expect(
    (await f.drain({ nodeId: "a", expectedAssignments: [f.assignment] }))
      .status,
  ).toBe(200);
  finish();
  await failed;
  expect(f.worker.release).toHaveBeenCalledTimes(1);
});

it("holds the resume fence until all captured releases settle, including after a peer error", async () => {
  const f = await fixture();
  const second = await f.controller.ensure(
    { ...f.owner, userPsId: `0x${"2".repeat(64)}` },
    [],
  );
  let entered!: () => void, finish!: () => void;
  const started = new Promise<void>((r) => {
    entered = r;
  });
  const hold = new Promise<void>((r) => {
    finish = r;
  });
  f.worker.release = vi.fn(async (a) => {
    if (a.userPsId === f.owner.userPsId) throw new Error("busy");
    entered();
    await hold;
  });
  let settled = false;
  const operation = f
    .drain({ nodeId: "a", expectedAssignments: [f.assignment, second] })
    .then((r) => {
      settled = true;
      return r;
    });
  await started;
  expect(settled).toBe(false);
  await expect(
    f.controller.admit({
      nodeId: "a",
      nodeIncarnation: "a1",
      capacity: 4,
      worker: f.worker,
      draining: false,
    }),
  ).rejects.toThrow("Drain in progress");
  finish();
  expect((await operation).status).toBe(503);
  expect(f.controller.nodeStatus()[0]?.draining).toBe(true);
  expect(f.controller.assignment(f.owner)?.generation).toBe(1);
  expect(f.controller.assignment(second)).toBeNull();
});

it("allows lease renewal of the captured identity while waiting for an owner operation", async () => {
  const f = await fixture();
  let entered!: () => void, finish!: () => void;
  const started = new Promise<void>((r) => {
    entered = r;
  });
  const hold = new Promise<void>((r) => {
    finish = r;
  });
  vi.mocked(f.worker.prepare).mockImplementationOnce(async () => {
    entered();
    await hold;
    return [];
  });
  const preparation = f.controller.ensure(f.owner, [{ scope: "test" }]);
  await started;
  const operation = f.drain({
    nodeId: "a",
    expectedAssignments: [f.assignment],
  });
  await vi.waitFor(() =>
    expect(f.controller.nodeStatus()[0]?.draining).toBe(true),
  );
  f.setTime(2000);
  await f.controller.renew();
  expect(f.controller.assignment(f.owner)?.leaseExpiresAt).not.toBe(
    f.assignment.leaseExpiresAt,
  );
  finish();
  await preparation;
  expect((await operation).status).toBe(200);
  expect(f.worker.release).toHaveBeenCalledTimes(1);
});
it("rejects a captured identity removed while its owner operation was queued", async () => {
  const f = await fixture();
  let entered!: () => void, finish!: () => void;
  const started = new Promise<void>((r) => {
    entered = r;
  });
  const hold = new Promise<void>((r) => {
    finish = r;
  });
  vi.mocked(f.worker.prepare).mockImplementationOnce(async () => {
    entered();
    await hold;
    return [];
  });
  const preparation = f.controller.ensure(f.owner, [{ scope: "test" }]);
  const failed = expect(preparation).rejects.toThrow();
  await started;
  const operation = f.drain({
    nodeId: "a",
    expectedAssignments: [f.assignment],
  });
  await vi.waitFor(() =>
    expect(f.controller.nodeStatus()[0]?.draining).toBe(true),
  );
  f.setTime(40000);
  await f.controller.renew();
  const releases = vi.mocked(f.worker.release).mock.calls.length;
  finish();
  await failed;
  expect((await operation).status).toBe(409);
  expect(f.worker.release).toHaveBeenCalledTimes(releases);
  expect(f.controller.assignment(f.owner)).toBeNull();
  expect(f.controller.nodeStatus()[0]?.draining).toBe(true);
});
