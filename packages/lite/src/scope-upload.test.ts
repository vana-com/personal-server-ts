/**
 * Streamed scope writes (`/v1/data/:scope/uploads`) through the PS-Lite
 * runtime, on a file store shaped like the Android native one: a file being
 * written is invisible at its path until it is committed.
 */

import { setFlagsFromString } from "node:v8";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { createScopeUploadRegistry } from "@opendatalabs/personal-server-ts-core/api";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import {
  createBearerTokenPsLiteAuth,
  createPsLiteRuntime,
  type PsLiteRuntime,
} from "./runtime.js";
import {
  createPersistentPsLiteStorage,
  type PsLiteDataFileStore,
  type PsLitePersistenceAdapter,
} from "./storage.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLitePersistence,
  createMemoryPsLiteStagedFileStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

const SCOPE = "notes.entries";
const OWNER = { Authorization: "Bearer owner-token" };
const JSON_OWNER = { ...OWNER, "Content-Type": "application/json" };

async function createRuntime(
  fileStore: PsLiteDataFileStore,
  persistence: PsLitePersistenceAdapter = createMemoryPsLitePersistence(),
): Promise<PsLiteRuntime> {
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  return createPsLiteRuntime({
    storage: await createPersistentPsLiteStorage(
      { kind: "custom" },
      persistence,
      fileStore,
    ),
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
  });
}

function call(
  runtime: PsLiteRuntime,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = JSON_OWNER,
): Promise<Response> {
  return runtime.fetch(
    new Request(`https://ps.local/v1/data/${SCOPE}${path}`, {
      method,
      headers,
      body:
        body === undefined
          ? undefined
          : typeof body === "string"
            ? body
            : JSON.stringify(body),
    }),
  );
}

async function begin(
  runtime: PsLiteRuntime,
  body: unknown = { data: { exportedBy: "test" } },
): Promise<string> {
  const res = await call(runtime, "POST", "/uploads", body);
  expect(res.status).toBe(201);
  return ((await res.json()) as { uploadId: string }).uploadId;
}

async function readLatest(runtime: PsLiteRuntime) {
  const res = await call(runtime, "GET", "", undefined, OWNER);
  expect(res.status).toBe(200);
  return (await res.json()) as { collectedAt: string; data: unknown };
}

async function seedOldVersion(runtime: PsLiteRuntime) {
  const res = await call(runtime, "POST", "", { records: [{ id: "old" }] });
  expect(res.status).toBe(201);
  return readLatest(runtime);
}

describe("streamed scope uploads", () => {
  it("makes the batches visible as one new version only at commit", async () => {
    const runtime = await createRuntime(createMemoryPsLiteStagedFileStore());
    const old = await seedOldVersion(runtime);

    const id = await begin(runtime);
    const batches = [
      [{ id: "a", text: "π ünïcode" }, { id: "b" }],
      [{ id: "c", nested: { ok: [1, 2] } }],
    ];
    for (const [seq, items] of batches.entries()) {
      const res = await call(runtime, "PUT", `/uploads/${id}/batches/${seq}`, {
        items,
      });
      expect(res.status).toBe(201);
      // Mid-stream, every reader still sees the previous version.
      expect(await readLatest(runtime)).toEqual(old);
    }

    const committed = await call(runtime, "POST", `/uploads/${id}/commit`, {
      data: { total: 3 },
    });
    expect(committed.status).toBe(201);
    expect(await committed.json()).toMatchObject({ scope: SCOPE, records: 3 });

    const latest = await readLatest(runtime);
    expect(latest.collectedAt > old.collectedAt).toBe(true);
    // The same data a single JSON write of the whole document stores.
    expect(latest.data).toEqual({
      exportedBy: "test",
      records: batches.flat(),
      total: 3,
    });
    const versions = await call(runtime, "GET", "/versions", undefined, OWNER);
    expect(((await versions.json()) as { total: number }).total).toBe(2);
  });

  it("leaves the previous version after an abort", async () => {
    const fileStore = createMemoryPsLiteStagedFileStore();
    const runtime = await createRuntime(fileStore);
    const old = await seedOldVersion(runtime);
    const id = await begin(runtime);
    await call(runtime, "PUT", `/uploads/${id}/batches/0`, {
      items: [{ id: "new" }],
    });

    const aborted = await call(runtime, "DELETE", `/uploads/${id}`);
    expect(aborted.status).toBe(204);

    expect(await readLatest(runtime)).toEqual(old);
    expect(fileStore.files.size).toBe(1);
    const late = await call(runtime, "PUT", `/uploads/${id}/batches/1`, {
      items: [{ id: "late" }],
    });
    expect(late.status).toBe(410);
  });

  it("leaves the previous version after a crash mid-stream", async () => {
    const files = new Map<string, string>();
    const persistence = createMemoryPsLitePersistence();
    const before = await createRuntime(
      createMemoryPsLiteStagedFileStore(files),
      persistence,
    );
    const old = await seedOldVersion(before);
    const id = await begin(before);
    await call(before, "PUT", `/uploads/${id}/batches/0`, {
      items: [{ id: "new" }],
    });

    // The process dies: the open writer and the registry are gone, the
    // committed files and the persisted index survive.
    const after = await createRuntime(
      createMemoryPsLiteStagedFileStore(files),
      persistence,
    );

    expect(await readLatest(after)).toEqual(old);
    const versions = await call(after, "GET", "/versions", undefined, OWNER);
    expect(((await versions.json()) as { total: number }).total).toBe(1);
    const commit = await call(after, "POST", `/uploads/${id}/commit`, {});
    expect(commit.status).toBe(404);
  });

  it("keeps the previous version when the commit cannot be persisted", async () => {
    const files = new Map<string, string>();
    const memory = createMemoryPsLitePersistence();
    let diskFull = false;
    const persistence: PsLitePersistenceAdapter = {
      ...memory,
      async write(state) {
        if (diskFull) throw new Error("ENOSPC: no space left on device");
        return memory.write(state);
      },
    };
    const runtime = await createRuntime(
      createMemoryPsLiteStagedFileStore(files),
      persistence,
    );
    const old = await seedOldVersion(runtime);
    const id = await begin(runtime);
    await call(runtime, "PUT", `/uploads/${id}/batches/0`, {
      items: [{ id: "new" }],
    });

    diskFull = true;
    const commit = await call(runtime, "POST", `/uploads/${id}/commit`, {});
    expect(commit.status).toBeGreaterThanOrEqual(500);
    // The failed commit ends the upload and publishes nothing.
    expect(await readLatest(runtime)).toEqual(old);
    const retry = await call(runtime, "POST", `/uploads/${id}/commit`, {});
    expect(retry.status).toBe(410);
    // The blob the failed commit wrote is unpublished, so it is removed.
    expect(files.size).toBe(1);

    // A later write that succeeds persists its own state, not the failed one.
    diskFull = false;
    const other = await runtime.fetch(
      new Request("https://ps.local/v1/data/notes.other", {
        method: "POST",
        headers: JSON_OWNER,
        body: JSON.stringify({ records: [{ id: "unrelated" }] }),
      }),
    );
    expect(other.status).toBe(201);
    expect(await readLatest(runtime)).toEqual(old);

    const restarted = await createRuntime(
      createMemoryPsLiteStagedFileStore(files),
      persistence,
    );
    expect(await readLatest(restarted)).toEqual(old);
  });

  it("answers a repeated batch as a replay and stores it once", async () => {
    const runtime = await createRuntime(createMemoryPsLiteStagedFileStore());
    const id = await begin(runtime, {});
    const batch = { items: [{ id: "a" }, { id: "b" }] };

    const first = await call(runtime, "PUT", `/uploads/${id}/batches/0`, batch);
    const retry = await call(runtime, "PUT", `/uploads/${id}/batches/0`, batch);
    expect(first.status).toBe(201);
    expect(retry.status).toBe(200);
    expect(await retry.json()).toEqual({ seq: 0, items: 0, replay: true });

    const conflict = await call(runtime, "PUT", `/uploads/${id}/batches/0`, {
      items: [{ id: "other" }],
    });
    expect(conflict.status).toBe(409);
    expect(await conflict.json()).toMatchObject({
      error: { errorCode: "BATCH_CONFLICT" },
    });
    const skipped = await call(runtime, "PUT", `/uploads/${id}/batches/2`, {
      items: [{ id: "c" }],
    });
    expect(skipped.status).toBe(409);
    expect(await skipped.json()).toMatchObject({
      error: { errorCode: "BATCH_OUT_OF_ORDER" },
    });

    // The refused requests did not end the upload.
    await call(runtime, "PUT", `/uploads/${id}/batches/1`, {
      items: [{ id: "c" }],
    });
    const committed = await call(runtime, "POST", `/uploads/${id}/commit`);
    expect(committed.status).toBe(201);
    expect((await readLatest(runtime)).data).toEqual({
      records: [{ id: "a" }, { id: "b" }, { id: "c" }],
    });
  });

  it("replays only the latest batch, and refuses an older one", async () => {
    const runtime = await createRuntime(createMemoryPsLiteStagedFileStore());
    const id = await begin(runtime, {});
    const put = (seq: number, items: unknown[]) =>
      call(runtime, "PUT", `/uploads/${id}/batches/${seq}`, { items });
    await put(0, [{ id: "a" }]);
    await put(1, [{ id: "b" }]);
    await put(2, [{ id: "c" }]);

    const latest = await put(2, [{ id: "c" }]);
    expect(latest.status).toBe(200);
    expect(await latest.json()).toEqual({ seq: 2, items: 0, replay: true });

    // Only the latest batch's body is remembered, so an older number is refused
    // even when its body matches what was stored.
    const older = await put(0, [{ id: "a" }]);
    expect(older.status).toBe(409);
    expect(await older.json()).toMatchObject({
      error: { errorCode: "BATCH_OUT_OF_ORDER" },
    });

    await call(runtime, "POST", `/uploads/${id}/commit`);
    expect((await readLatest(runtime)).data).toEqual({
      records: [{ id: "a" }, { id: "b" }, { id: "c" }],
    });
  });

  it("refuses to commit under a version written during the upload", async () => {
    const runtime = await createRuntime(createMemoryPsLiteStagedFileStore());
    const id = await begin(runtime, {});
    await call(runtime, "PUT", `/uploads/${id}/batches/0`, {
      items: [{ id: "streamed" }],
    });
    // Same-process writes take a later stamp than the open upload.
    const plain = await call(runtime, "POST", "", {
      records: [{ id: "plain" }],
    });
    expect(plain.status).toBe(201);

    const commit = await call(runtime, "POST", `/uploads/${id}/commit`);
    expect(commit.status).toBe(409);
    expect(await commit.json()).toMatchObject({
      error: { errorCode: "UPLOAD_SUPERSEDED" },
    });
    expect((await readLatest(runtime)).data).toEqual({
      records: [{ id: "plain" }],
    });
  });

  it("refuses a commit when a newer version lands between its closing writes and its publication", async () => {
    const store = createMemoryPsLiteStagedFileStore();
    const open = store.openEnvelopeWriter!;
    let closing: () => void = () => {};
    let reachedClosing: () => void = () => {};
    const gate = new Promise<void>((resolve) => (closing = resolve));
    const reached = new Promise<void>((resolve) => (reachedClosing = resolve));
    store.openEnvelopeWriter = async (path) => {
      const file = await open(path);
      return {
        ...file,
        async write(text) {
          // The closing write is the one that ends the records array.
          if (text.startsWith("]")) {
            reachedClosing();
            await gate;
          }
          return file.write(text);
        },
      };
    };
    const runtime = await createRuntime(store);
    const id = await begin(runtime, {});
    await call(runtime, "PUT", `/uploads/${id}/batches/0`, {
      items: [{ id: "streamed" }],
    });

    const commit = call(runtime, "POST", `/uploads/${id}/commit`);
    await reached;
    const plain = await call(runtime, "POST", "", {
      records: [{ id: "plain" }],
    });
    expect(plain.status).toBe(201);
    closing();

    const res = await commit;
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({
      error: { errorCode: "UPLOAD_SUPERSEDED" },
    });
    expect((await readLatest(runtime)).data).toEqual({
      records: [{ id: "plain" }],
    });
    const versions = await call(runtime, "GET", "/versions", undefined, OWNER);
    expect(((await versions.json()) as { total: number }).total).toBe(1);
    // The superseded upload's file is not left behind.
    expect(store.files.size).toBe(1);
  });

  it("refuses server-owned keys, builders and stores that cannot stream", async () => {
    const runtime = await createRuntime(createMemoryPsLiteStagedFileStore());
    for (const body of [
      { data: { $writtenBy: "x" } },
      { data: { lineage: {} } },
      { data: { records: [] } },
      { arrayKey: "$lineage" },
    ]) {
      const res = await call(runtime, "POST", "/uploads", body);
      expect(res.status).toBe(400);
    }
    const id = await begin(runtime, { data: { kept: true } });
    const clash = await call(runtime, "POST", `/uploads/${id}/commit`, {
      data: { kept: false },
    });
    expect(clash.status).toBe(400);

    const builder = await call(
      runtime,
      "POST",
      "/uploads",
      {},
      {
        Authorization: "Bearer builder-token",
        "Content-Type": "application/json",
      },
    );
    expect(builder.status).toBeGreaterThanOrEqual(401);
    expect(builder.status).toBeLessThanOrEqual(403);

    const accessLogStore = createMemoryPsLiteAccessLogStore();
    const plainStore = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      gateway: createMockPsLiteGateway(),
      accessLogReader: accessLogStore,
      accessLogWriter: accessLogStore,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
    });
    const unsupported = await call(plainStore, "POST", "/uploads", {});
    expect(unsupported.status).toBe(501);
  });

  it("aborts an upload left idle and frees the scope", async () => {
    const files = new Map<string, string>();
    const storage = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      createMemoryPsLiteStagedFileStore(files),
    );
    const registry = createScopeUploadRegistry({ idleTimeoutMs: 20 });
    let released = 0;
    const { uploadId } = await registry.begin({
      storage,
      scope: SCOPE,
      collectedAt: "2026-10-26T00:00:00.000Z",
      release: () => {
        released += 1;
      },
      body: {},
    });

    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(released).toBe(1);
    await expect(
      registry.append({
        scope: SCOPE,
        uploadId,
        seq: 0,
        text: '{"items":[1]}',
      }),
    ).rejects.toMatchObject({ status: 410, code: "UPLOAD_EXPIRED" });
    expect(storage.findEntry({ scope: SCOPE })).toBeUndefined();
    expect(files.size).toBe(0);
  });

  it("lets only one of two overlapping begins keep a writer", async () => {
    const files = new Map<string, string>();
    const base = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      createMemoryPsLiteStagedFileStore(files),
    );
    let writers = 0;
    let aborted = 0;
    const storage: DataStoragePort = {
      ...base,
      async openVersionWriter(scope, collectedAt) {
        await new Promise((resolve) => setTimeout(resolve, 20));
        const writer = await base.openVersionWriter!(scope, collectedAt);
        writers += 1;
        return {
          ...writer,
          async abort() {
            aborted += 1;
            await writer.abort();
          },
        };
      },
    };
    const registry = createScopeUploadRegistry();
    let released = 0;
    const input = (collectedAt: string) => ({
      storage,
      scope: SCOPE,
      collectedAt,
      release: () => {
        released += 1;
      },
      body: {},
    });

    const [first, second] = await Promise.all([
      registry.begin(input("2026-10-26T00:00:00.000Z")),
      registry.begin(input("2026-10-26T00:00:01.000Z")),
    ]);

    expect(writers).toBe(2);
    expect(aborted).toBe(1);
    expect(released).toBe(1);
    await expect(
      registry.append({
        scope: SCOPE,
        uploadId: first.uploadId,
        seq: 0,
        text: '{"items":[1]}',
      }),
    ).rejects.toMatchObject({ status: 410, code: "UPLOAD_ABORTED" });
    await registry.append({
      scope: SCOPE,
      uploadId: second.uploadId,
      seq: 0,
      text: '{"items":[1]}',
    });
    await registry.commit({
      scope: SCOPE,
      uploadId: second.uploadId,
      body: {},
      afterTombstoneVersion: null,
    });
    expect(released).toBe(2);
    expect(storage.findEntry({ scope: SCOPE })?.collectedAt).toBe(
      "2026-10-26T00:00:01.000Z",
    );
  });

  it("does not expire an upload while its commit is still writing", async () => {
    const files = new Map<string, string>();
    const base = await createPersistentPsLiteStorage(
      { kind: "custom" },
      createMemoryPsLitePersistence(),
      createMemoryPsLiteStagedFileStore(files),
    );
    let aborted = 0;
    const storage: DataStoragePort = {
      ...base,
      async openVersionWriter(scope, collectedAt) {
        const writer = await base.openVersionWriter!(scope, collectedAt);
        return {
          ...writer,
          async commit(entry) {
            // Longer than the idle timeout.
            await new Promise((resolve) => setTimeout(resolve, 80));
            return writer.commit(entry);
          },
          async abort() {
            aborted += 1;
            await writer.abort();
          },
        };
      },
    };
    const registry = createScopeUploadRegistry({ idleTimeoutMs: 20 });
    let released = 0;
    const { uploadId } = await registry.begin({
      storage,
      scope: SCOPE,
      collectedAt: "2026-10-26T00:00:00.000Z",
      release: () => {
        released += 1;
      },
      body: {},
    });
    await registry.append({
      scope: SCOPE,
      uploadId,
      seq: 0,
      text: '{"items":[1]}',
    });

    const committed = await registry.commit({
      scope: SCOPE,
      uploadId,
      body: {},
      afterTombstoneVersion: null,
    });
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(committed.records).toBe(1);
    expect(aborted).toBe(0);
    expect(released).toBe(1);
    expect(storage.findEntry({ scope: SCOPE })?.collectedAt).toBe(
      "2026-10-26T00:00:00.000Z",
    );
  });
});

describe("streamed scope upload memory", () => {
  // Retained heap must follow the batch, not the scope. The file store
  // keeps only a byte count, so anything that grows with the upload is the
  // server holding records it should have let go.
  setFlagsFromString("--expose-gc");
  const gc = runInNewContext("gc") as () => void;

  function retainedHeap(): number {
    gc();
    gc();
    return process.memoryUsage().heapUsed;
  }

  function discardingFileStore(): PsLiteDataFileStore & { bytes: number } {
    const store = {
      ...createMemoryPsLiteStagedFileStore(),
      bytes: 0,
      async openEnvelopeWriter() {
        let open = 0;
        return {
          async write(text: string) {
            open += text.length;
          },
          async commit() {
            store.bytes = open;
            return open;
          },
          async abort() {},
        };
      },
    };
    return store;
  }

  /** Upload `batches` batches of ~1 MiB; return the peak retained growth. */
  async function peakGrowth(
    batches: number,
    fileStore: PsLiteDataFileStore & { bytes?: number } = discardingFileStore(),
  ): Promise<number> {
    const runtime = await createRuntime(fileStore);
    const filler = "x".repeat(1000);
    const id = await begin(runtime, {});
    const baseline = retainedHeap();
    let peak = 0;
    for (let seq = 0; seq < batches; seq += 1) {
      const items = Array.from({ length: 1000 }, (_, i) => ({
        id: `${seq}-${i}`,
        text: filler,
      }));
      const res = await call(runtime, "PUT", `/uploads/${id}/batches/${seq}`, {
        items,
      });
      expect(res.status).toBe(201);
      if (seq % 8 === 7) peak = Math.max(peak, retainedHeap() - baseline);
    }
    const committed = await call(runtime, "POST", `/uploads/${id}/commit`);
    expect(committed.status).toBe(201);
    if (fileStore.bytes !== undefined) {
      expect(fileStore.bytes).toBeGreaterThan(batches * 1_000_000);
    }
    return peak;
  }

  it("keeps retained heap flat from 32 MiB to 128 MiB of records", async () => {
    const small = await peakGrowth(32);
    const large = await peakGrowth(128);
    const MiB = 1024 * 1024;
    console.info(
      `scope upload retained heap growth: 32 MiB upload ${(small / MiB).toFixed(1)} MiB, ` +
        `128 MiB upload ${(large / MiB).toFixed(1)} MiB`,
    );
    // A server that kept the records would grow by ~96 MiB more on the
    // larger upload; allow GC noise only.
    expect(large).toBeLessThan(16 * MiB);
    expect(large - small).toBeLessThan(8 * MiB);
  }, 120_000);

  it("detects a writer that retains what it was sent", async () => {
    // The probe itself: the staged store keeps every piece until commit.
    const growth = await peakGrowth(32, createMemoryPsLiteStagedFileStore());
    expect(growth).toBeGreaterThan(24 * 1024 * 1024);
  }, 120_000);

  it("keeps retained heap flat across 100k one-record batches", async () => {
    // The large-batch runs above cannot show a cost per batch: this one sends
    // many tiny batches, where any per-batch record would dominate.
    const registry = createScopeUploadRegistry({ idleTimeoutMs: 60_000 });
    const storage = {
      openVersionWriter: async () => ({
        write: async () => {},
        abort: async () => {},
        commit: async () => {
          throw new Error("not committed in this test");
        },
      }),
    } as unknown as DataStoragePort;
    const { uploadId } = await registry.begin({
      storage,
      scope: SCOPE,
      collectedAt: "2026-10-26T00:00:00.000Z",
      release() {},
      body: {},
    });
    const text = '{"items":[{"id":1}]}';
    let seq = 0;
    const appendBatches = async (count: number) => {
      for (let i = 0; i < count; i += 1) {
        await registry.append({ scope: SCOPE, uploadId, seq, text });
        seq += 1;
      }
    };

    await appendBatches(10_000);
    const early = retainedHeap();
    await appendBatches(100_000);
    const late = retainedHeap();
    await registry.abort({ scope: SCOPE, uploadId });

    const MiB = 1024 * 1024;
    console.info(
      `scope upload retained heap growth over 90k more batches: ${((late - early) / MiB).toFixed(2)} MiB`,
    );
    // Keeping a digest per batch measured about 1.5 KiB each here (the hex
    // string is built by concatenation and stays a rope): about 145 MiB for
    // these 90k batches. Allow GC noise only.
    expect(late - early).toBeLessThan(4 * MiB);
  }, 120_000);
});
