import { describe, expect, it } from "vitest";
import type { ProgressReport } from "@opendatalabs/personal-server-ts-core/replication/coordinator";
import type { ReplicationTimers } from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import { sha256 } from "viem";
import {
  LITE_REPLICATION_LIMITS,
  LiteReplicaTransferError,
  type ReplicationBootConfig,
} from "./replication-ports.js";
import { createLiteReplicationRuntime } from "./replication-runtime.js";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  createMemoryReplicaObjectTransfers,
  createMemoryReplicaPersistence,
  createScriptedReplicationEngine,
} from "./test-support/replication.js";

const report = (overrides: Partial<ProgressReport> = {}): ProgressReport => ({
  receipts: [],
  waits: [],
  problems: [],
  quarantines: [],
  unsupported: [],
  nextWake: undefined,
  ...overrides,
});
const config: ReplicationBootConfig = {
  enabled: true,
  owner: `0x${"ab".repeat(20)}`,
  environment: "dev",
  chainId: 14800,
  limits: LITE_REPLICATION_LIMITS,
};
/** The driver's idle timer never fires: tests step by trigger. */
const manualTimers: ReplicationTimers = {
  now: () => 1_000,
  setTimeout: () => undefined,
  clearTimeout: () => {},
};
const on = { state: "on" } as const;

describe("createLiteReplicationRuntime", () => {
  it("stays inert unless the door is on and the host opted in with a valid config", async () => {
    const { engine, budgets } = createScriptedReplicationEngine([report()]);
    const cases = [
      [{ door: { state: "never" as const }, config }, { state: "off" }],
      [{ door: { state: "off" as const }, config }, { state: "off" }],
      [{ door: on }, { state: "off" }],
      [{ door: on, config: { ...config, enabled: false } }, { state: "off" }],
      [
        {
          door: {
            state: "refused" as const,
            refusal: "reenable_refused" as const,
          },
          config,
        },
        { state: "refused", refusal: "reenable_refused" },
      ],
      [
        { door: on, config: { ...config, owner: "0x1" as `0x${string}` } },
        { state: "blocked", reason: "invalid_owner" },
      ],
      [
        {
          door: on,
          config: {
            ...config,
            limits: { ...config.limits, fragmentBytes: 2 * 1024 * 1024 },
          },
        },
        { state: "blocked", reason: "invalid_limits" },
      ],
    ] as const;
    for (const [input, status] of cases) {
      const runtime = createLiteReplicationRuntime({ ...input, engine });
      runtime.resume();
      expect(runtime.status()).toEqual(status);
      expect(await runtime.trigger("sync_now")).toBeUndefined();
      expect(await runtime.stop(10)).toBe(true);
    }
    expect(budgets).toEqual([]);
  });

  it("is blocked with no engine: PS-Lite has none yet", () => {
    expect(createLiteReplicationRuntime({ door: on, config }).status()).toEqual(
      { state: "blocked", reason: "no_engine" },
    );
  });

  it("steps the engine with the phone's step bound from foreground to pause", async () => {
    const scripted = createScriptedReplicationEngine([
      report(),
      report({ nextWake: 61_000 }),
    ]);
    const reports: ProgressReport[] = [];
    const runtime = createLiteReplicationRuntime({
      door: on,
      config,
      engine: scripted.engine,
      timers: manualTimers,
      onReport: (r) => reports.push(r),
    });
    expect(runtime.status()).toMatchObject({
      state: "paused",
      stepping: false,
    });
    // Paused: a trigger runs nothing.
    expect(await runtime.trigger("local_write")).toBeUndefined();
    runtime.resume();
    expect(runtime.status().state).toBe("on");
    // Single-flight: the trigger joins the foreground step, then one more runs.
    expect(await runtime.trigger("sync_now")).toEqual(report());
    expect(await runtime.trigger("sync_now")).toEqual(
      report({ nextWake: 61_000 }),
    );
    expect(scripted.budgets[0]).toEqual({ units: 20, bytes: 8 * 1024 * 1024 });
    runtime.wake("mapping:conn");
    expect(scripted.dependencies).toEqual(["mapping:conn"]);
    await runtime.pause();
    expect(runtime.status()).toMatchObject({
      state: "paused",
      stepping: false,
    });
    expect(reports.length).toBeGreaterThanOrEqual(2);
  });

  it("a pause aborts the running step and a resume steps again", async () => {
    const scripted = createScriptedReplicationEngine([report()], {
      stepMs: 60_000,
    });
    const runtime = createLiteReplicationRuntime({
      door: on,
      config,
      engine: scripted.engine,
      timers: manualTimers,
    });
    runtime.resume();
    expect(runtime.status()).toMatchObject({ state: "on", stepping: true });
    await runtime.pause();
    expect(scripted.aborted).toBe(1);
    expect(runtime.status()).toMatchObject({
      state: "paused",
      stepping: false,
    });
    runtime.resume();
    expect(runtime.status()).toMatchObject({ state: "on", stepping: true });
    expect(await runtime.stop(1_000)).toBe(true);
    expect(scripted.budgets).toHaveLength(2);
  });

  it("a resume queued behind a pause does not override a later pause", async () => {
    const scripted = createScriptedReplicationEngine([report()], {
      stepMs: 60_000,
    });
    const runtime = createLiteReplicationRuntime({
      door: on,
      config,
      engine: scripted.engine,
      timers: manualTimers,
    });
    runtime.resume();
    expect(scripted.budgets).toHaveLength(1);
    // Neither pause has settled the aborted first step when resume and the
    // second pause are issued.
    const firstPause = runtime.pause();
    runtime.resume();
    const secondPause = runtime.pause();
    await Promise.all([firstPause, secondPause]);
    await new Promise((resolve) => setImmediate(resolve));
    expect(scripted.budgets).toHaveLength(1);
    expect(runtime.status()).toMatchObject({
      state: "paused",
      stepping: false,
    });
  });

  it("a resume queued behind a pause still starts when nothing supersedes it", async () => {
    const scripted = createScriptedReplicationEngine([report()], {
      stepMs: 60_000,
    });
    const runtime = createLiteReplicationRuntime({
      door: on,
      config,
      engine: scripted.engine,
      timers: manualTimers,
    });
    runtime.resume();
    const pause = runtime.pause();
    runtime.resume();
    await pause;
    await new Promise((resolve) => setImmediate(resolve));
    expect(scripted.budgets).toHaveLength(2);
    expect(runtime.status()).toMatchObject({ state: "on", stepping: true });
    expect(await runtime.stop(1_000)).toBe(true);
  });

  it("aborts a step at the configured deadline", async () => {
    const scripted = createScriptedReplicationEngine([report()], {
      stepMs: 60_000,
    });
    const runtime = createLiteReplicationRuntime({
      door: on,
      config: {
        ...config,
        limits: {
          ...config.limits,
          step: { ...config.limits.step, deadlineMs: 20 },
        },
      },
      engine: scripted.engine,
    });
    runtime.resume();
    expect(await runtime.trigger("foreground")).toEqual(report());
    expect(scripted.aborted).toBe(1);
    expect(await runtime.stop(1_000)).toBe(true);
  });
});

describe("PS-Lite replication routes", () => {
  function liteRuntime(
    replication?: ReturnType<typeof createLiteReplicationRuntime>,
  ) {
    const logs = createMemoryPsLiteAccessLogStore();
    return createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      gateway: createMockPsLiteGateway(),
      accessLogReader: logs,
      accessLogWriter: logs,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      auth: createBearerTokenPsLiteAuth({ ownerToken: "owner-token" }),
      replication,
    });
  }
  const owner = { Authorization: "Bearer owner-token" };
  const call = (
    runtime: ReturnType<typeof liteRuntime>,
    path: string,
    init: RequestInit = {},
  ) => runtime.fetch(new Request(`https://ps.local${path}`, init));

  it("status is owner-only and reads off without a replication runtime", async () => {
    const runtime = liteRuntime();
    expect((await call(runtime, "/v1/replication/status")).status).toBe(401);
    const res = await call(runtime, "/v1/replication/status", {
      headers: owner,
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ state: "off" });
    expect(
      (
        await call(runtime, "/v1/replication/status", {
          method: "POST",
          headers: owner,
        })
      ).status,
    ).toBe(405);
  });

  it("activate resumes replication, sync starts a step, deactivate pauses it", async () => {
    const scripted = createScriptedReplicationEngine([report()]);
    const replication = createLiteReplicationRuntime({
      door: on,
      config,
      engine: scripted.engine,
      timers: manualTimers,
    });
    const runtime = liteRuntime(replication);
    // Inactive: status answers, sync does not.
    expect(
      await (
        await call(runtime, "/v1/replication/status", { headers: owner })
      ).json(),
    ).toMatchObject({ state: "paused" });
    expect(
      (
        await call(runtime, "/v1/replication/sync", {
          method: "POST",
          headers: owner,
        })
      ).status,
    ).toBe(503);
    runtime.activate();
    await replication.trigger("foreground");
    const before = scripted.budgets.length;
    expect(
      (await call(runtime, "/v1/replication/sync", { method: "POST" })).status,
    ).toBe(401);
    const sync = await call(runtime, "/v1/replication/sync", {
      method: "POST",
      headers: owner,
    });
    expect(sync.status).toBe(202);
    expect(await sync.json()).toMatchObject({
      accepted: true,
      status: { state: "on" },
    });
    await replication.trigger("sync_now");
    expect(scripted.budgets.length).toBeGreaterThan(before);
    runtime.deactivate();
    await replication.pause();
    expect(replication.status().state).toBe("paused");
  });

  it("sync answers 409 when replication is not running", async () => {
    const runtime = liteRuntime(
      createLiteReplicationRuntime({ door: on, config }),
    );
    runtime.activate();
    const res = await call(runtime, "/v1/replication/sync", {
      method: "POST",
      headers: owner,
    });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "REPLICATION_NOT_RUNNING" },
      status: { state: "blocked", reason: "no_engine" },
    });
  });
});

describe("in-memory LiteReplicaPersistence", () => {
  const frames = async function* (...parts: Uint8Array[]) {
    yield* parts;
  };
  const hash = (bytes: Uint8Array) => sha256(bytes).slice(2);
  const read = async (iterable: AsyncIterable<Uint8Array>) => {
    const parts: Uint8Array[] = [];
    for await (const part of iterable) parts.push(part);
    return parts;
  };

  it("publishes staged bytes only when a transaction attaches them, in 128 KiB frames", async () => {
    const { port } = createMemoryReplicaPersistence();
    const bytes = new Uint8Array(300 * 1024).map((_, i) => i % 251);
    const id = await port.stageBytes(
      frames(
        bytes.slice(0, 100 * 1024),
        bytes.slice(100 * 1024, 228 * 1024),
        bytes.slice(228 * 1024),
      ),
    );
    await expect(read(port.readBytes(id))).rejects.toThrow("missing");
    await port.transaction(async (tx) => {
      await tx.attachBytes(id, { length: bytes.length, sha256: hash(bytes) });
      await tx.put("journal/1", "row");
      // Attaching the same bytes again is a no-op.
      await tx.attachBytes(id, { length: bytes.length, sha256: hash(bytes) });
    });
    const parts = await read(port.readBytes(id));
    expect(parts.map((p) => p.length)).toEqual([
      128 * 1024,
      128 * 1024,
      44 * 1024,
    ]);
    expect(Buffer.concat(parts).equals(Buffer.from(bytes))).toBe(true);
    await port.transaction((tx) => tx.releaseBytes(id));
    await expect(read(port.readBytes(id))).rejects.toThrow("missing");
  });

  it("refuses a wrong length or hash, an oversized frame, and rolls back with the rows", async () => {
    const persistence = createMemoryReplicaPersistence();
    const { port } = persistence;
    const bytes = new Uint8Array([1, 2, 3]);
    const id = await port.stageBytes(frames(bytes));
    for (const expected of [
      { length: 4, sha256: hash(bytes) },
      { length: 3, sha256: hash(new Uint8Array([3, 2, 1])) },
    ])
      await expect(
        port.transaction((tx) => tx.attachBytes(id, expected)),
      ).rejects.toThrow("do not match");
    await expect(
      port.stageBytes(frames(new Uint8Array(128 * 1024 + 1))),
    ).rejects.toThrow("128 KiB");
    await expect(
      port.transaction(async (tx) => {
        await tx.attachBytes(id, { length: 3, sha256: hash(bytes) });
        await tx.put("journal/1", "row");
        throw new Error("callback failed");
      }),
    ).rejects.toThrow("callback failed");
    persistence.failNextCommit();
    await expect(
      port.transaction(async (tx) => {
        await tx.attachBytes(id, { length: 3, sha256: hash(bytes) });
        await tx.put("journal/1", "row");
      }),
    ).rejects.toThrow("before-commit");
    expect(persistence.disk.rows.size).toBe(0);
    expect(persistence.disk.bytes.size).toBe(0);
    // Still staged: a later transaction may attach it.
    await port.transaction((tx) =>
      tx.attachBytes(id, { length: 3, sha256: hash(bytes) }),
    );
    expect(await read(port.readBytes(id))).toEqual([bytes]);
  });
});

describe("in-memory LiteReplicaObjectTransfers", () => {
  const call = () => ({
    signal: new AbortController().signal,
    deadlineMs: 30_000,
  });
  const hex = (bytes: Uint8Array) => sha256(bytes).slice(2);

  it("uploads attached bytes and downloads them into a stage a transaction attaches", async () => {
    const { port: persistence } = createMemoryReplicaPersistence();
    const { port: transfers } = createMemoryReplicaObjectTransfers(persistence);
    const bytes = new Uint8Array([7, 8, 9]);
    const expected = { length: 3, sha256: hex(bytes) };
    const local = await persistence.stageBytes(
      (async function* () {
        yield bytes;
      })(),
    );
    await persistence.transaction((tx) => tx.attachBytes(local, expected));
    const url = "https://storage.invalid/scope/fragments/a";
    expect(await transfers.probe({ url }, call())).toBe(false);
    expect(
      await transfers.upload(
        { url, method: "PUT", headers: {}, bytesId: local },
        call(),
      ),
    ).toEqual({ status: 201 });
    expect(await transfers.probe({ url }, call())).toBe(true);
    const got = await transfers.download(
      { url, maxBytes: 3, expected },
      call(),
    );
    expect(got).toMatchObject(expected);
    await persistence.transaction((tx) =>
      tx.attachBytes(got.stagingId, expected),
    );
  });

  it("fails with the native codes: not-found, too-large, digest-mismatch, cancelled, busy", async () => {
    const { port: persistence } = createMemoryReplicaPersistence();
    const memory = createMemoryReplicaObjectTransfers(persistence, {
      maxTransfers: 1,
    });
    const url = "https://storage.invalid/o";
    memory.objects.set(url, new Uint8Array([1, 2]));
    const code = (promise: Promise<unknown>) =>
      promise.then(
        () => "ok",
        (error: unknown) =>
          error instanceof LiteReplicaTransferError ? error.code : error,
      );
    expect(
      await code(memory.port.download({ url: `${url}x`, maxBytes: 9 }, call())),
    ).toBe("not-found");
    expect(await code(memory.port.download({ url, maxBytes: 1 }, call()))).toBe(
      "too-large",
    );
    expect(
      await code(
        memory.port.download(
          { url, maxBytes: 9, expected: { length: 2, sha256: "0".repeat(64) } },
          call(),
        ),
      ),
    ).toBe("digest-mismatch");
    expect(
      await code(
        memory.port.probe(
          { url },
          { signal: AbortSignal.abort(), deadlineMs: 1 },
        ),
      ),
    ).toBe("cancelled");
    const first = memory.port.download({ url, maxBytes: 9 }, call());
    expect(await code(memory.port.probe({ url }, call()))).toBe("busy");
    expect(await code(first)).toBe("ok");
  });

  it("discards the stage of a download cancelled after it staged", async () => {
    const { port: persistence, stagedBytes } = createMemoryReplicaPersistence();
    const memory = createMemoryReplicaObjectTransfers(persistence);
    const url = "https://storage.invalid/o";
    memory.objects.set(url, new Uint8Array([1, 2, 3]));
    const controller = new AbortController();
    const download = memory.port.download(
      { url, maxBytes: 9 },
      { signal: controller.signal, deadlineMs: 30_000 },
    );
    controller.abort();
    await expect(download).rejects.toMatchObject({ code: "cancelled" });
    expect(stagedBytes()).toBe(0);
  });

  it("caps unattached stages in aggregate until they are discarded or attached", async () => {
    const { port: persistence, stagedBytes } = createMemoryReplicaPersistence(
      undefined,
      { maxStagedBytes: 10 },
    );
    const stage = (size: number) =>
      persistence.stageBytes(
        (async function* () {
          yield new Uint8Array(size).fill(1);
        })(),
      );
    const first = await stage(6);
    await expect(stage(5)).rejects.toMatchObject({ code: "storage-full" });
    expect(stagedBytes()).toBe(6);
    const second = await stage(4);
    expect(stagedBytes()).toBe(10);
    persistence.discardBytes(first);
    expect(stagedBytes()).toBe(4);
    const third = await stage(6);
    // Attaching publishes a stage, so it stops counting against the cap.
    await persistence.transaction((tx) =>
      tx.attachBytes(second, {
        length: 4,
        sha256: sha256(new Uint8Array(4).fill(1)).slice(2),
      }),
    );
    expect(stagedBytes()).toBe(6);
    persistence.discardBytes(third);
    expect(stagedBytes()).toBe(0);
  });
});
