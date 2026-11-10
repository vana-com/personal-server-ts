import type * as RuntimeModule from "./runtime.js";
import type * as SyncModule from "./sync.js";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeAll, beforeEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";

const faults = vi.hoisted(() => ({
  point: "",
  failure: new Error("injected"),
  runtimes: [] as { isAvailable(): boolean }[],
}));
vi.mock("./runtime.js", async (original) => {
  const real = await original<typeof RuntimeModule>();
  return {
    ...real,
    createWeb3SignedPsLiteAuth: (
      ...args: Parameters<typeof real.createWeb3SignedPsLiteAuth>
    ) => {
      if (faults.point === "auth") throw faults.failure;
      return real.createWeb3SignedPsLiteAuth(...args);
    },
    createPsLiteRuntime: (
      ...args: Parameters<typeof real.createPsLiteRuntime>
    ) => {
      if (faults.point === "construction") throw faults.failure;
      const runtime = real.createPsLiteRuntime(...args);
      faults.runtimes.push(runtime);
      const setAvailable = runtime.setAvailable;
      runtime.setAvailable = (available) => {
        setAvailable(available);
        if (faults.point === (available ? "activation" : "stop"))
          throw faults.failure;
      };
      return runtime;
    },
  };
});

const managers: Awaited<
  ReturnType<(typeof SyncModule)["createPsLiteSyncManager"]>
>["syncManager"][] = [];
vi.mock("./sync.js", async (original) => {
  const real = await original<typeof SyncModule>();
  return {
    ...real,
    createPsLiteSyncManager: async (
      ...args: Parameters<typeof real.createPsLiteSyncManager>
    ) => {
      const result = await real.createPsLiteSyncManager(...args);
      const start = result.syncManager.start;
      result.syncManager.start = () => {
        start();
        if (faults.point === "sync-start") throw faults.failure;
      };
      managers.push(result.syncManager);
      return result;
    },
  };
});

import { prepareIndexedDbPsLiteRuntime } from "./browser-runtime.js";
import { startPersonalServer } from "./client.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import type { PsLiteRelayWebSocket } from "./relay.js";

import { buildPersonalServerLiteOwnerBindingMessage } from "@opendatalabs/vana-sdk/protocol/personal-server-lite-owner-binding";
const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
let ownerSignature: `0x${string}`;
beforeAll(async () => {
  ownerSignature = await owner.signMessage({
    message: buildPersonalServerLiteOwnerBindingMessage(owner.address),
  });
});
const sockets: TestSocket[] = [];
class TestSocket implements PsLiteRelayWebSocket {
  binaryType = "arraybuffer";
  readyState = 1;
  readonly OPEN = 1;
  readonly CONNECTING = 0;
  onopen: (() => void) | null = null;
  onmessage: PsLiteRelayWebSocket["onmessage"] = null;
  onclose: PsLiteRelayWebSocket["onclose"] = null;
  onerror: PsLiteRelayWebSocket["onerror"] = null;
  send() {}
  close() {
    this.readyState = 3;
    this.onclose?.({});
  }
}
let activity = 0;
let writers = 0;
let maximumWriters = 0;
function options() {
  const gateway = createMockPsLiteGateway();
  gateway.getServer = vi.fn().mockResolvedValue({ id: "registered" });
  return {
    dbName: "lifecycle-same-database",
    ownerSignature,
    ownerAddress: owner.address,
    gateway,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => {
        activity++;
        writers++;
        maximumWriters = Math.max(maximumWriters, writers);
        await Promise.resolve();
        writers--;
        return { dataPoints: [], cursor: null };
      },
    },
    configDefaults: { sync: { enabled: true } },
    relay: {
      sessionId: "lifecycle-session",
      tls: false as const,
      webSocketFactory: () => {
        if (faults.point === "relay") throw faults.failure;
        const socket = new TestSocket();
        sockets.push(socket);
        return socket;
      },
      onStatus: () => {
        if (faults.point === "callback") throw faults.failure;
      },
    },
  };
}

beforeEach(() => {
  vi.useFakeTimers({
    toFake: [
      "setTimeout",
      "clearTimeout",
      "setInterval",
      "clearInterval",
      "Date",
    ],
  });
  vi.stubGlobal("indexedDB", new IDBFactory());
  faults.point = "";
  faults.runtimes.length = 0;
  sockets.length = 0;
  activity = writers = maximumWriters = 0;
  managers.length = 0;
});
afterEach(async () => {
  faults.point = "";
  await Promise.all(managers.map((manager) => manager.stop()));
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function assertQuiet() {
  const before = activity;
  await vi.advanceTimersByTimeAsync(180_000);
  expect(activity).toBe(before);
  expect(writers).toBe(0);
  expect(faults.runtimes.every((runtime) => !runtime.isAvailable())).toBe(true);
  expect(managers.every((manager) => !manager.running)).toBe(true);
  expect(sockets.every((socket) => socket.readyState === 3)).toBe(true);
  expect(vi.getTimerCount()).toBe(0);
}
async function retry() {
  faults.point = "";
  const handle = await startPersonalServer(options());
  const before = activity;
  await managers.at(-1)!.trigger();
  expect(activity).toBeGreaterThan(before);
  expect(managers.filter((manager) => manager.running)).toHaveLength(1);
  expect(sockets.filter((socket) => socket.readyState === 1)).toHaveLength(1);
  expect(maximumWriters).toBe(1);
  expect(
    faults.runtimes.filter((runtime) => runtime.isAvailable()),
  ).toHaveLength(1);
  await handle.stop();
  await assertQuiet();
}

it.each([
  "auth",
  "construction",
  "activation",
  "relay",
  "callback",
  "sync-start",
])("rolls back %s failure before retrying the same database", async (point) => {
  faults.point = point;
  await expect(startPersonalServer(options())).rejects.toBe(faults.failure);
  await assertQuiet();
  await retry();
});

it("continues cleanup when a stop step throws and reports all errors", async () => {
  const handle = await startPersonalServer(options());
  faults.point = "stop";
  const stop = handle.stop();
  expect(handle.stop()).toBe(stop);
  await expect(stop).rejects.toMatchObject({ errors: [faults.failure] });
  await assertQuiet();
  await retry();
});

it("cold assembly never starts sync before explicit start", async () => {
  const bundle = await prepareIndexedDbPsLiteRuntime(options());
  expect(bundle.runtime.isAvailable()).toBe(false);
  await vi.advanceTimersByTimeAsync(180_000);
  expect(bundle.syncManager?.running).toBe(false);
  expect(activity).toBe(0);
  expect(vi.getTimerCount()).toBe(0);
  await bundle.start();
  await bundle.syncManager!.trigger();
  expect(activity).toBeGreaterThan(0);
  await bundle.dispose();
  await assertQuiet();
  await expect(bundle.start()).rejects.toThrow("disposed");
});

it("closes relay heartbeat when a connected status callback throws", async () => {
  const handle = await startPersonalServer(options());
  faults.point = "callback";
  expect(() => sockets[0].onopen?.()).toThrow(faults.failure);
  await handle.stop();
  await assertQuiet();
  await retry();
});

it("stops sync even when both socket close and admission cleanup throw", async () => {
  const handle = await startPersonalServer(options());
  const socketFailure = new Error("socket close failed");
  const socket = sockets[0];
  socket.close = () => {
    socket.readyState = 3;
    throw socketFailure;
  };
  faults.point = "stop";
  await expect(handle.stop()).rejects.toMatchObject({
    errors: [socketFailure, faults.failure],
  });
  await assertQuiet();
  await retry();
});

it("waits for an in-flight sync writer before rejecting a failed start", async () => {
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  let entered!: () => void;
  const writing = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const input = options();
  const read = input.dataPointFeed.listDataPointsByOwner;
  input.dataPointFeed.listDataPointsByOwner = async () => {
    entered();
    await held;
    return read();
  };
  faults.point = "activation";
  let settled = false;
  const starting = startPersonalServer(input);
  const rejected = expect(starting).rejects.toBe(faults.failure);
  void starting.catch(() => {
    settled = true;
  });
  await writing;
  await vi.advanceTimersByTimeAsync(180_000);
  expect(settled).toBe(false);
  release();
  await rejected;
  await assertQuiet();
  await retry();
});

it("serializes start and makes disposal terminal", async () => {
  const bundle = await prepareIndexedDbPsLiteRuntime(options());
  const starting = bundle.start();
  expect(bundle.start()).toBe(starting);
  await starting;
  const stopping = bundle.dispose();
  expect(bundle.dispose()).toBe(stopping);
  await stopping;
  await assertQuiet();
  await expect(bundle.start()).rejects.toThrow("disposed");
});

it("preserves the start error together with cleanup errors", async () => {
  const input = options();
  const createSocket = input.relay.webSocketFactory;
  const cleanupFailure = new Error("socket cleanup failed");
  input.relay.webSocketFactory = () => {
    const socket = createSocket();
    socket.close = () => {
      socket.readyState = 3;
      throw cleanupFailure;
    };
    return socket;
  };
  faults.point = "sync-start";
  await expect(startPersonalServer(input)).rejects.toMatchObject({
    cause: faults.failure,
    errors: [faults.failure, cleanupFailure],
  });
  await assertQuiet();
  await retry();
});
