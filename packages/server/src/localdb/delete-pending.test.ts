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
import { remoteFixture } from "./apply-fixture.test-utils.js";
import { legacyHeadRow } from "./legacy-head-fixture.test-utils.js";
import { deriveKeyCheck } from "@opendatalabs/personal-server-ts-stream-sync";
import { endRequest } from "../../../core/src/test-utils/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const syncs: { close(): Promise<void> }[] = [];
afterEach(async () => {
  for (const sync of syncs.splice(0)) await sync.close();
  vi.useRealTimers();
});

/** One device with a delete that the gateway refuses to finish. */
async function stuckDelete(
  controlReply?:
    | "conflict"
    | "refused"
    | "unconfirmed"
    | "hang"
    | "committed-hang"
    | "uncommitted-hang",
  options: { holdConfirmation?: boolean; successfulReplies?: boolean } = {},
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
  await legacyHeadRow({
    ...fixture,
    keys,
    keyCheck: await deriveKeyCheck((m) => keys.namespaceHmac(m)),
    connector: "fixture-source",
    ns: "",
    stream: "items",
  });
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
    deleteRetryMs: controlReply?.endsWith("-hang")
      ? { first: 200, max: 400 }
      : { first: 5, max: 20 },
  });
  syncs.push(sync);
  if (controlReply?.endsWith("-hang")) {
    await sync.intake.begin("other", {
      connector: "other-source",
      artifactDigest: "other-source",
      owner: { address: owner, leaseId: null },
      observedAt: 40,
    });
    await sync.intake.batch("other", {
      batch: 0,
      records: [{ stream: "items", data: { id: "other" } }],
    });
    await sync.intake.end(
      "other",
      endRequest({ lastBatch: 0, live: ["items"] }),
    );
  }
  const postSignals: AbortSignal[] = [];
  const successfulReplies: (() => void)[] = [];
  let confirmationStarted!: () => void;
  const confirming = new Promise<void>(
    (resolve) => (confirmationStarted = resolve),
  );
  let failConfirmation!: () => void;
  const confirmationGate = new Promise<void>(
    (resolve) => (failConfirmation = resolve),
  );
  let confirmNormally = false;
  let postStarted!: () => void;
  const postStartedPromise = new Promise<void>(
    (resolve) => (postStarted = resolve),
  );
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  if (controlReply) {
    // The fence's batch request gets no answer, so the per-row pass posts it
    // alone, and the reply below is that post's. A hang holds the request.
    const realBatch = registry.postBatch.bind(registry);
    vi.spyOn(registry, "postBatch").mockImplementation(async (req) => {
      if (!req.rows.some((row) => row.scope === fixture.control))
        return realBatch(req);
      if (controlReply === "hang") {
        await gate;
        return realBatch(req);
      }
      throw new Error("connection reset fixture");
    });
    const real = registry.post.bind(registry);
    vi.spyOn(registry, "post").mockImplementation(async (req, signal) => {
      if (req.scope !== fixture.control) return real(req);
      if (controlReply === "hang") {
        await gate;
        return real(req);
      }
      if (
        controlReply === "committed-hang" ||
        controlReply === "uncommitted-hang"
      ) {
        if (signal) postSignals.push(signal);
        if (controlReply === "committed-hang") await real(req);
        postStarted();
        if (options.successfulReplies) {
          await new Promise<void>((resolve) => successfulReplies.push(resolve));
          // A successful remote response, even if its AbortSignal was ignored.
          return real(req);
        }
        await gate;
        throw new Error("held response released");
      }
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
  const realRead = registry.read.bind(registry);
  const reads = vi.spyOn(registry, "read");
  if (options.holdConfirmation) {
    reads.mockImplementation(async (scope, signal) => {
      if (scope === fixture.control && signal && !confirmNormally) {
        confirmationStarted();
        await confirmationGate;
        throw new Error("confirming read failed");
      }
      return realRead(scope, signal);
    });
  }
  // Start before the request: an early purge must not evade the assertion.
  const writes = vi.spyOn(db, "batch");
  const queries = vi.spyOn(db, "query");
  const startedAt = Date.now();
  const request = sync.deleter.requestConnectionDelete("fixture-source");
  if (controlReply?.endsWith("-hang")) await postStartedPromise;
  const started = controlReply?.endsWith("-hang")
    ? { deleteId: "", fenced: false }
    : await request;
  const answeredMs = Date.now() - startedAt;
  const begin = (id: string, connect: boolean) =>
    sync.intake.begin(id, {
      connector: "fixture-source",
      artifactDigest: "fixture-source",
      owner: { address: owner, leaseId: null },
      observedAt: 40,
      ...(connect ? { connect: true } : {}),
    });
  const intents = () => db.query("SELECT connector FROM delete_intents");
  return {
    db,
    registry,
    sync,
    begin,
    intents,
    started,
    answeredMs,
    release,
    control: fixture.control,
    postSignals,
    reads,
    writes,
    queries,
    request,
    confirming,
    failConfirmation,
    successfulReplies,
    confirmNormally: () => {
      confirmNormally = true;
    },
  };
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
  const queries = f.queries.mockClear();
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

it("a registry that never answers the fence gets fenced:false within the resume wait, and the fence lands when it recovers", async () => {
  const f = await stuckDelete("hang");
  // deleteRetryMs.first is 5 ms here: the request waits that long for the fence.
  expect(f.started.fenced).toBe(false);
  expect(f.answeredMs).toBeLessThan(1000);
  expect(await f.intents()).toHaveLength(1);
  f.release();
  await vi.waitFor(async () => expect(await f.intents()).toEqual([]), {
    timeout: 5000,
  });
  expect(await f.registry.read(f.control)).toMatchObject({
    found: true,
    version: 2,
  });
});

it("does not certify hydration when a pending delete skips a connection download", async () => {
  const f = await stuckDelete();
  expect(await f.intents()).toHaveLength(1);
  expect(
    (await f.registry.listOwnerRows()).some((row) => row.scope === f.control),
  ).toBe(true);
  expect((await f.sync.listing.status()).accountHydrated).toBe(false);
  await f.sync.apply();
  expect(await f.intents()).toHaveLength(1);
  expect((await f.sync.listing.status()).accountHydrated).toBe(false);
  await f.sync.cycle();
  expect((await f.sync.listing.status()).accountHydrated).toBe(false);
  f.registry.beforePost = undefined;
  expect(await f.sync.deleter.resumeDeletes()).toEqual([]);
  expect((await f.begin("reconnected", true)).status).toBe("collecting");
  await f.sync.apply();
  expect((await f.sync.listing.status()).accountHydrated).toBe(true);
});

it("does not hold a sync cycle on a stalled delete landing", async () => {
  const f = await stuckDelete("hang");
  try {
    const outcome = await Promise.race([
      f.sync.cycle().then(() => "completed"),
      new Promise<string>((resolve) =>
        setTimeout(() => resolve("blocked"), 100),
      ),
    ]);
    expect(outcome).toBe("completed");
  } finally {
    f.release();
  }
});

/** No completed fence may erase the durable intent before confirmation. */
function expectIntentNotErased(f: Awaited<ReturnType<typeof stuckDelete>>) {
  expect(
    f.writes.mock.calls
      .flatMap(([statements]) => statements)
      .some((statement) =>
        /DELETE\s+FROM\s+delete_intents/i.test(statement.sql),
      ),
  ).toBe(false);
}

it("keeps the intent through a stalled then failed confirming read until the tombstone is confirmed", async () => {
  // Protects the delete landing continuation that confirms the tombstone fence
  // before removing delete_intents; the batch spy predates requestConnectionDelete.
  const f = await stuckDelete("committed-hang", { holdConfirmation: true });
  try {
    await vi.waitFor(() => expect(f.postSignals[0]?.aborted).toBe(true), {
      timeout: 2000,
    });
    await f.confirming;
    expect((await f.request).fenced).toBe(false);
    expect(await f.intents()).toHaveLength(1);
    expectIntentNotErased(f);
    f.failConfirmation();
    await vi.waitFor(() => expect(f.postSignals.length).toBeGreaterThan(1), {
      timeout: 2000,
    });
    expect(await f.intents()).toHaveLength(1);
    expectIntentNotErased(f);
    f.confirmNormally();
    await vi.waitFor(async () => expect(await f.intents()).toEqual([]), {
      timeout: 5000,
    });
    expect(await f.registry.read(f.control)).toMatchObject({
      found: true,
      version: 2,
    });
  } finally {
    f.failConfirmation();
    f.release();
  }
});

it("ignores a successful POST response arriving after close", async () => {
  // Protects the post-await closed/attempt guard before any local landing write.
  const f = await stuckDelete("uncommitted-hang", { successfulReplies: true });
  try {
    expect(f.successfulReplies).toHaveLength(1);
    await f.sync.close();
    const writes = f.writes.mock.calls.length;
    const queries = f.queries.mock.calls.length;
    f.successfulReplies[0]!();
    // Drain the late asynchronous continuation, without starting a new attempt.
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(f.writes.mock.calls.length).toBe(writes);
    expect(f.queries.mock.calls.length).toBe(queries);
    expect(f.postSignals[0]?.aborted).toBe(true);
  } finally {
    f.successfulReplies.forEach((release) => release());
    f.release();
  }
});

it("ignores an old successful POST after a newer attempt has started", async () => {
  // Protects the landing continuation's attempt identity check: old success
  // cannot purge or finish the intent now owned by the newer retry.
  const f = await stuckDelete("uncommitted-hang", {
    successfulReplies: true,
    holdConfirmation: true,
  });
  try {
    await f.confirming;
    f.failConfirmation();
    await vi.waitFor(
      () => expect(f.successfulReplies.length).toBeGreaterThan(1),
      { timeout: 2000 },
    );
    const intent = await f.db.query("SELECT * FROM delete_intents");
    const connection = await f.db.query("SELECT * FROM connections");
    const records = await f.db.query("SELECT * FROM records");
    expect(intent).toHaveLength(1);
    const writes = f.writes.mock.calls.length;
    f.successfulReplies[0]!();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(f.writes.mock.calls.length).toBe(writes);
    expect(await f.db.query("SELECT * FROM delete_intents")).toEqual(intent);
    expect(await f.db.query("SELECT * FROM connections")).toEqual(connection);
    expect(await f.db.query("SELECT * FROM records")).toEqual(records);
    expect(f.postSignals[0]?.aborted).toBe(true);
  } finally {
    await f.sync.close();
    f.failConfirmation();
    f.successfulReplies.forEach((release) => release());
    f.release();
  }
});

it("publishes connector B while connector A's confirming READ is stalled", async () => {
  // Protects the confirming-read deadline/released landing slot, not just the
  // POST deadline: A has already timed out its POST before B starts publishing.
  const f = await stuckDelete("committed-hang", { holdConfirmation: true });
  try {
    await f.confirming;
    expect(f.postSignals[0]?.aborted).toBe(true);
    const outcome = await Promise.race([
      f.sync.publish().then(() => "completed"),
      new Promise<string>((resolve) =>
        setTimeout(() => resolve("blocked"), 100),
      ),
    ]);
    expect(outcome).toBe("completed");
    expect((await f.sync.intake.publicationStatus("other")).state).toBe(
      "published",
    );
    expect(await f.intents()).toHaveLength(1);
    expectIntentNotErased(f);
  } finally {
    await f.sync.close();
    f.failConfirmation();
    f.release();
  }
});

it.each(["committed-hang", "uncommitted-hang"] as const)(
  "reconciles a %s POST without blocking another connection",
  async (reply) => {
    const f = await stuckDelete(reply);
    try {
      const outcome = await Promise.race([
        f.sync.publish().then(() => "completed"),
        new Promise<string>((resolve) =>
          setTimeout(() => resolve("blocked"), 100),
        ),
      ]);
      expect(outcome).toBe("completed");
      expect((await f.sync.intake.publicationStatus("other")).state).toBe(
        "published",
      );
      if (reply === "committed-hang") {
        await vi.waitFor(async () => expect(await f.intents()).toEqual([]), {
          timeout: 2000,
        });
      } else {
        await vi.waitFor(
          () => expect(f.postSignals.length).toBeGreaterThan(1),
          { timeout: 2000 },
        );
        expect(await f.intents()).toHaveLength(1);
      }
      expect(f.postSignals[0]?.aborted).toBe(true);
      expect(f.reads).toHaveBeenCalledWith(f.control, expect.any(AbortSignal));
    } finally {
      f.release();
    }
  },
);

it("aborts the held registry request before closing the database", async () => {
  const f = await stuckDelete("uncommitted-hang");
  try {
    expect(f.postSignals[0]?.aborted).toBe(false);
    await f.sync.close();
    expect(f.postSignals[0]?.aborted).toBe(true);
  } finally {
    f.release();
  }
});
