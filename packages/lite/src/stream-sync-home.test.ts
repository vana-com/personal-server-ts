import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createMemoryPsLiteStateStore,
  createMemoryPsLiteStorage,
} from "./test-support/memory.js";
import { loadOrCreatePsLiteServerIdentity } from "./state.js";
import { createPsLiteSyncManager } from "./sync.js";

/** Minimal exclusive Web Locks: `request` queues, `ifAvailable` answers null. */
function fakeLocks() {
  const held = new Set<string>();
  const waiting = new Map<string, Array<() => void>>();
  const request = vi.fn(
    async (
      name: string,
      options: { mode?: string; ifAvailable?: boolean },
      callback: (lock: { name: string } | null) => Promise<unknown>,
    ) => {
      while (held.has(name)) {
        if (options.ifAvailable) return callback(null);
        await new Promise<void>((resolve) => {
          waiting.set(name, [...(waiting.get(name) ?? []), resolve]);
        });
      }
      held.add(name);
      try {
        return await callback({ name });
      } finally {
        held.delete(name);
        waiting.get(name)?.shift()?.();
      }
    },
  );
  return { request, held };
}

let factory: IDBFactory;
let locks: ReturnType<typeof fakeLocks>;

beforeEach(() => {
  factory = new IDBFactory();
  locks = fakeLocks();
  vi.stubGlobal("indexedDB", factory);
  vi.stubGlobal("IDBKeyRange", IDBKeyRange);
  vi.stubGlobal("navigator", { locks });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function manager(
  keyByte: string,
  streamSync: { write: boolean } | null = { write: true },
) {
  const owner = privateKeyToAccount(`0x${keyByte.repeat(32)}`);
  const OWNER_SIGNATURE = await owner.signMessage({
    message: "vana-master-key-v1",
  });
  const stateStore = createMemoryPsLiteStateStore();
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: OWNER_SIGNATURE,
  });
  const result = await createPsLiteSyncManager({
    config: ServerConfigSchema.parse({
      sync: { enabled: true },
      ...(streamSync ? { streamSync } : {}),
    }),
    storage: createMemoryPsLiteStorage(),
    stateStore,
    ownerSignature: OWNER_SIGNATURE,
    serverAccount: identity.account,
    ownerSyncSigner: {
      address: owner.address,
      signMessage: (message: string) => owner.signMessage({ message }),
      signAddData: vi.fn(),
      signLineageAttestation: vi.fn(),
    },
    gateway: { getServer: vi.fn().mockResolvedValue(null) } as never,
    dataPointFeed: {
      getDataPoint: async () => null,
      listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
    },
    autoStartSync: false,
  });
  return result;
}

/** Every file of every database on the fake origin, `path` → decoded body. */
async function allFiles(): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  for (const info of await factory.databases()) {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open(info.name!);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    if (db.objectStoreNames.contains("chunks")) {
      const rows = await new Promise<Array<{ key: string; bytes: Uint8Array }>>(
        (resolve, reject) => {
          const request = db
            .transaction("chunks", "readonly")
            .objectStore("chunks")
            .getAll();
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        },
      );
      for (const row of rows) {
        files.set(
          `${info.name}:${row.key.slice(0, row.key.indexOf("\u0001"))}`,
          new TextDecoder().decode(row.bytes),
        );
      }
    }
    db.close();
  }
  return files;
}

/** The unbound name the first stream-sync build used for every owner. */
const LEGACY_DB = "ps-lite-stream-sync";

describe("stream-sync storage home", () => {
  it("a second instance on the same home does not recover or delete the first instance's run", async () => {
    const tabA = await manager("12");
    await tabA.streamSyncWriter!.beginRun({
      runId: "run-a",
      connector: "c",
      userConnect: false,
    });
    const collecting = (files: Map<string, string>) =>
      [...files].filter(([path]) => path.endsWith("runs/run-a/entry.json"));
    expect(collecting(await allFiles())).toHaveLength(1);
    // Tab B's first publish pass must not treat tab A's collecting run as abandoned.
    const tabB = await manager("12");
    await tabB.streamSyncWriter?.publishPending();
    const entries = collecting(await allFiles());
    expect(entries).toHaveLength(1);
    expect(JSON.parse(entries[0]![1]).phase).toBe("collecting");
    // The second instance runs no stream sync at all; legacy sync is intact.
    expect(tabB.streamSyncWriter).toBeNull();
    expect(tabB.streamSyncIntake).toBeNull();
    expect(tabB.syncManager).toBeDefined();
  });

  it("does not adopt a checkpoint saved in the old unbound database", async () => {
    // A previous owner (or build) saved a cursor in the shared constant-name DB.
    const seed = await new Promise<IDBDatabase>((resolve, reject) => {
      const request = factory.open(LEGACY_DB, 1);
      request.onupgradeneeded = () =>
        request.result.createObjectStore("chunks", { keyPath: "key" });
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const state = {
      version: 1,
      needsFull: [],
      checkpoints: {
        c: { ns: "ns1", generation: 1, value: { cursor: 100 } },
      },
      seedTargets: {},
      receipts: {},
    };
    await new Promise<void>((resolve, reject) => {
      const tx = seed.transaction("chunks", "readwrite");
      tx.objectStore("chunks").put({
        key: "state.json\u00010000000000",
        bytes: new TextEncoder().encode(JSON.stringify(state)),
      });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    seed.close();
    const ownerB = await manager("34");
    const start = await ownerB.streamSyncWriter!.beginRun({
      runId: "run-b",
      connector: "c",
      userConnect: false,
      issue: { wantFull: false },
    });
    expect(start.collectionMode).toBe("full_refresh");
    expect(start.state).toBeNull();
  });

  it("two owners on one origin get separate databases", async () => {
    const ownerA = await manager("12");
    await ownerA.streamSyncWriter!.beginRun({
      runId: "run-a",
      connector: "c",
      userConnect: false,
    });
    const ownerB = await manager("34");
    await ownerB.streamSyncWriter!.beginRun({
      runId: "run-b",
      connector: "c",
      userConnect: false,
    });
    const names = new Set(
      [...(await allFiles())]
        .filter(([path]) => path.includes("entry.json"))
        .map(([path]) => path.slice(0, path.indexOf(":"))),
    );
    expect(names.size).toBe(2);
    expect(names.has(LEGACY_DB)).toBe(false);
    for (const name of names) expect(name).not.toMatch(/0x|[A-Fa-f0-9]{40}/);
  });

  it("with stream sync off, never opens the database or takes the lock", async () => {
    const open = vi.spyOn(factory, "open");
    const off = await manager("12", null);
    const explicitOff = await manager("12", { write: false });
    expect(off.streamSyncWriter).toBeNull();
    expect(explicitOff.streamSyncWriter).toBeNull();
    expect(open).not.toHaveBeenCalled();
    expect(locks.request).not.toHaveBeenCalled();
  });

  it("without navigator.locks, stream sync is off and legacy sync still builds", async () => {
    vi.stubGlobal("navigator", {});
    const result = await manager("12");
    expect(result.streamSyncWriter).toBeNull();
    expect(result.streamSyncIntake).toBeNull();
    expect(result.syncManager).toBeDefined();
  });
});

describe("stream-sync home lock", () => {
  it("is released when the first instance closes, so another can take it", async () => {
    const first = await manager("12");
    const blocked = await manager("12");
    expect(blocked.streamSyncWriter).toBeNull();
    await first.closeStreamSync();
    const second = await manager("12");
    expect(second.streamSyncWriter).not.toBeNull();
  });

  it("lets two owners on one origin hold their own locks", async () => {
    const a = await manager("12");
    const b = await manager("34");
    expect(a.streamSyncWriter).not.toBeNull();
    expect(b.streamSyncWriter).not.toBeNull();
  });
});
