import { afterEach, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
  type MemoryStreamSyncRegistry,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { RegistryRefusedError } from "../../../core/src/stream-sync/ports.js";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { remoteFixture } from "./apply-fixture.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const syncs: { close(): Promise<void> }[] = [];
afterEach(async () => {
  for (const sync of syncs.splice(0)) await sync.close();
  vi.useRealTimers();
});

/** One device with a delete that the gateway refuses to finish. */
async function stuckDelete(
  controlReply?: "conflict" | "refused" | "unconfirmed",
) {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const fixture = await remoteFixture(keys);
  const registry = createMemoryStreamSyncRegistry() as MemoryStreamSyncRegistry;
  const blobs = createMemoryStreamSyncBlobs();
  await fixture.head("items", [{ id: "base" }]);
  for (const [key, value] of fixture.blobs) await blobs.put(key, value);
  for (const [scope, row] of fixture.reads)
    if (row.found)
      await registry.post({
        ownerAddress: owner,
        scope,
        dataHash: row.dataHash as `0x${string}`,
        metadataHash: row.metadataHash as `0x${string}`,
        expectedVersion: "1",
        signature: "0x00",
      });
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "pending",
  });
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    registry,
    blobs,
    queue: connectionQueue(),
    ownerAddress: owner,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 1000,
    newOp: () => `pending-${++op}`,
  };
  await bootstrapConnections(deps);
  await applyConnection(deps, fixture.control);
  const sync = createLocalSync(deps, {
    resolveArtifact: (digest) => ({
      connector: digest,
      version: "1",
      streams: [
        { name: "items", semantics: "mutable_state", primaryKey: ["id"] },
      ],
    }),
    declaredStreams: () => ["items"],
    olderVersionReads: () => true,
    deleteRetryMs: { first: 5, max: 20 },
  });
  syncs.push(sync);
  if (controlReply) {
    const real = registry.post.bind(registry);
    vi.spyOn(registry, "post").mockImplementation(async (req) => {
      if (req.scope !== fixture.control) return real(req);
      if (controlReply === "refused")
        throw new RegistryRefusedError("refused", 409);
      return controlReply === "conflict"
        ? { kind: "conflict", latestVersion: "1" }
        : { kind: "committed" };
    });
  } else
    registry.beforePost = async () => {
      throw new Error("gateway refused");
    };
  await sync.deleter.requestConnectionDelete("fixture-source");
  const begin = (id: string, connect: boolean) =>
    sync.intake.begin(id, {
      connector: "fixture-source",
      artifactDigest: "fixture-source",
      owner: { address: owner, leaseId: null },
      observedAt: 40,
      ...(connect ? { connect: true } : {}),
    });
  const intents = () => db.query("SELECT connector FROM delete_intents");
  return { db, registry, sync, begin, intents };
}

it.each([true, false])(
  "a begin (connect %s) that meets a delete it cannot finish says delete_pending, with the last error name",
  async (connect) => {
    const f = await stuckDelete();
    await expect(f.begin("run", connect)).rejects.toMatchObject({
      code: "delete_pending",
      status: 409,
      lastError: "Error",
    });
    expect(await f.intents()).toHaveLength(1);
    expect(await f.db.query("SELECT * FROM runs")).toEqual([]);
  },
);

it("a delete the gateway stops refusing finishes without any begin, then connect:true works", async () => {
  const f = await stuckDelete();
  await expect(f.begin("blocked", true)).rejects.toMatchObject({
    code: "delete_pending",
  });
  f.registry.beforePost = undefined;
  await vi.waitFor(async () => expect(await f.intents()).toEqual([]), {
    timeout: 5000,
  });
  const response = await f.begin("connected", true);
  expect(response.status).toBe("collecting");
});

it("keeps retrying while the gateway keeps refusing, and a begin still refuses", async () => {
  const f = await stuckDelete();
  const seen = vi.fn();
  f.registry.beforePost = async () => {
    seen();
    throw new Error("gateway refused");
  };
  await vi.waitFor(() => expect(seen.mock.calls.length).toBeGreaterThan(2), {
    timeout: 5000,
  });
  expect(await f.intents()).toHaveLength(1);
  await expect(f.begin("blocked", false)).rejects.toMatchObject({
    code: "delete_pending",
  });
  expect(await f.db.query("SELECT * FROM runs")).toEqual([]);
});

it("stops retrying once the sync is closed", async () => {
  const f = await stuckDelete();
  const seen = vi.fn();
  f.registry.beforePost = async () => {
    seen();
    throw new Error("gateway refused");
  };
  await vi.waitFor(() => expect(seen).toHaveBeenCalled(), { timeout: 5000 });
  await f.sync.close();
  const settled = seen.mock.calls.length;
  await new Promise((resolve) => setTimeout(resolve, 100));
  expect(seen.mock.calls.length).toBeLessThanOrEqual(settled + 1);
});

it("explicit resume clears the armed retry after finishing the delete", async () => {
  vi.useFakeTimers();
  const f = await stuckDelete();
  await expect(f.begin("blocked", true)).rejects.toMatchObject({
    code: "delete_pending",
  });
  expect(vi.getTimerCount()).toBe(1);
  f.registry.beforePost = undefined;
  expect(await f.sync.deleter.resumeDeletes()).toEqual([]);
  const queries = vi.spyOn(f.db, "query");
  expect(vi.getTimerCount()).toBe(0);
  await vi.advanceTimersByTimeAsync(100);
  expect(queries).not.toHaveBeenCalled();
});

it.each(["conflict", "refused", "unconfirmed"] as const)(
  "unchanged control %s keeps reconnect retriable through the sync API",
  async (reply) => {
    const f = await stuckDelete(reply);
    await expect(f.begin("blocked", true)).rejects.toMatchObject({
      code: "delete_pending",
      status: 409,
    });
    expect(await f.intents()).toHaveLength(1);
    vi.mocked(f.registry.post).mockRestore();
    expect(await f.sync.deleter.resumeDeletes()).toEqual([]);
    expect((await f.begin("reconnected", true)).status).toBe("collecting");
  },
);
