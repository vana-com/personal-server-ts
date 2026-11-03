import { afterEach, expect, it, vi } from "vitest";
import { createMessage, encrypt, enums } from "openpgp";
import { DiagnosticsRecorder } from "./diagnostics.js";
import { Worker } from "node:worker_threads";
import { setTimeout as delay } from "node:timers/promises";
import { build } from "esbuild";
import { IDBFactory } from "fake-indexeddb";
import { encodeAbiParameters, keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createDataFileEnvelope,
  decryptWithPassword,
  deriveMasterKey,
  deriveScopeKey,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createPsLiteSyncManager } from "./sync.js";
import { createIndexedDbPsLiteStateStore } from "./state.js";
import { createMemoryPsLiteStorage } from "./test-support/memory.js";
import type { AdditionsWorkerPort } from "./additions-session.js";

const workers = new Set<Worker>();
afterEach(async () => {
  await Promise.all([...workers].map((worker) => worker.terminate()));
  workers.clear();
  vi.unstubAllGlobals();
});

async function fixture() {
  vi.stubGlobal("indexedDB", new IDBFactory());
  vi.stubGlobal("navigator", {
    locks: {
      request: async (_name: string, _options: unknown, run: () => unknown) =>
        run(),
    },
  });
  const bundled = await build({
    entryPoints: [new URL("./additions-worker.ts", import.meta.url).pathname],
    bundle: true,
    platform: "browser",
    format: "cjs",
    write: false,
    logLevel: "silent",
  });
  function workerFactory(): AdditionsWorkerPort {
    // Run the actual browser worker in a fresh thread; only its platform message bridge is adapted.
    const thread = new Worker(
      `
      const { parentPort } = require('node:worker_threads');
      globalThis.postMessage = (message, transfer) => parentPort.postMessage(message, transfer);
      parentPort.on('message', data => globalThis.onmessage({ data }));
      ${bundled.outputFiles[0].text}
    `,
      { eval: true },
    );
    workers.add(thread);
    const port: AdditionsWorkerPort = {
      onmessage: null,
      onerror: null,
      postMessage: (message, transfer) =>
        thread.postMessage(
          message,
          transfer?.filter((item) => item instanceof ArrayBuffer),
        ),
      terminate: () => {
        void thread.terminate();
      },
    };
    thread.on("message", (data) =>
      port.onmessage?.(new MessageEvent("message", { data })),
    );
    thread.on("error", (error) =>
      port.onerror?.({ message: error.message } as ErrorEvent),
    );
    return port;
  }
  const owner = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const signature = await owner.signMessage({ message: "vana-master-key-v1" });
  const masterKey = deriveMasterKey(signature);
  const password = (scope: string) =>
    Array.from(deriveScopeKey(masterKey, scope), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  const idFor = (scope: string) =>
    keccak256(
      encodeAbiParameters(
        [{ type: "address" }, { type: "string" }],
        [owner.address, scope],
      ),
    );
  type Slot = {
    expectedVersion: string;
    dataHash: string;
    metadataHash: string;
    status: string;
    addedAt: string;
    isTombstone: boolean;
  };
  let inventoryDelayMs = 0;
  const slots = new Map<string, Slot[]>();
  const blobs = new Map<string, Uint8Array>();
  const stall = new Set<string>();
  const failedRegistrations = new Set<string>();
  const interruptRegistration = new Set<string>();
  const failRegistrationOnDownload = new Set<string>();
  const collectedAt = "2026-10-20T00:00:00.000Z";
  function register(scope: string, slot: Slot) {
    slots.set(scope, [...(slots.get(scope) ?? []), slot]);
  }
  async function source(
    scope: string,
    version: string,
    data: Record<string, unknown>,
    compressed = false,
  ) {
    const plaintext = new TextEncoder().encode(
      JSON.stringify(createDataFileEnvelope(scope, collectedAt, data)),
    );
    const encrypted = compressed
      ? await encrypt({
          message: await createMessage({ binary: plaintext }),
          passwords: [password(scope)],
          format: "binary",
          config: { preferredCompressionAlgorithm: enums.compression.zlib },
        })
      : await encryptWithPassword(plaintext, password(scope));
    blobs.set(`${scope}/${version}`, encrypted);
    register(scope, {
      expectedVersion: version,
      dataHash: keccak256(plaintext),
      metadataHash: keccak256(
        stringToHex(
          JSON.stringify({
            scope,
            collectedAt,
            sizeBytes: encrypted.byteLength,
          }),
        ),
      ),
      status: "finalized",
      addedAt: collectedAt,
      isTombstone: false,
    });
    return encrypted.byteLength;
  }
  vi.stubGlobal(
    "fetch",
    async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname.includes("/blobs/")) {
        const key = url.pathname.split("/").slice(-2).join("/");
        if (init?.method === "PUT") {
          blobs.set(
            key,
            new Uint8Array(await new Response(init.body).arrayBuffer()),
          );
          return Response.json({}, { status: 201 });
        }
        if (stall.has(key)) {
          const signal = init?.signal;
          if (!signal) throw new Error("Missing bounded download signal");
          signal.throwIfAborted();
          await new Promise<never>((_resolve, reject) =>
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            }),
          );
        }
        const bytes = blobs.get(key);
        if (failRegistrationOnDownload.delete(key)) {
          const [scope, version] = key.split("/");
          const registration = slots
            .get(scope)
            ?.find((slot) => slot.expectedVersion === version);
          if (!registration)
            throw new Error("Missing registration to transition");
          registration.status = "failed";
        }
        return bytes
          ? new Response(new Uint8Array(bytes))
          : new Response(null, { status: 404 });
      }
      if (init?.method === "POST") {
        const data = JSON.parse(await new Response(init.body).text());
        register(data.scope, {
          ...data,
          status: failedRegistrations.has(data.scope) ? "failed" : "finalized",
          addedAt: collectedAt,
          isTombstone: false,
        });
        if (interruptRegistration.delete(data.scope))
          throw new Error("Connection interrupted after registration");
        return Response.json({
          dataPointId: idFor(data.scope),
          expectedVersion: data.expectedVersion,
        });
      }
      const scope = url.searchParams.get("scope");
      if (scope !== null) {
        if (inventoryDelayMs)
          await delay(inventoryDelayMs, undefined, {
            signal: init?.signal ?? undefined,
          });
        const versions = slots.get(scope) ?? [];
        const limit = Number(url.searchParams.get("limit"));
        const remaining = versions.filter(
          (row) =>
            BigInt(row.expectedVersion) >
            BigInt(url.searchParams.get("after") ?? "0"),
        );
        const page = remaining.slice(0, limit);
        const hasMore = remaining.length > page.length;
        return Response.json({
          data: {
            dataPointId: idFor(scope),
            ownerAddress: owner.address,
            scope,
            head: versions.length
              ? {
                  ...versions.at(-1),
                  deletedAt: versions.at(-1)!.isTombstone ? collectedAt : null,
                }
              : null,
            versions: page,
          },
          pagination: {
            limit,
            hasMore,
            nextAfter: hasMore ? page.at(-1)!.expectedVersion : null,
          },
        });
      }
      return Response.json({
        data: {
          dataPoints: [...slots.keys()]
            .filter((scope) => !scope.startsWith("vana.system."))
            .map((scope) => ({
              id: idFor(scope),
              ownerAddress: owner.address,
              scope,
              deletedAt: null,
            })),
        },
        pagination: { limit: 100, hasMore: false, nextCursor: null },
      });
    },
  );
  const dbName = crypto.randomUUID();
  async function session(
    bytes?: number,
    diagnostics?: DiagnosticsRecorder,
    milliseconds = 120_000,
  ) {
    const result = await createPsLiteSyncManager({
      config: ServerConfigSchema.parse({
        gateway: { url: "https://gateway.example" },
        storage: { config: { vana: { apiUrl: "https://storage.example" } } },
      }),
      storage: createMemoryPsLiteStorage(),
      stateStore: createIndexedDbPsLiteStateStore({ dbName }),
      ownerSignature: signature,
      serverAccount: owner,
      ownerSyncSigner: {
        address: owner.address,
        signMessage: async () => signature,
        signMessageBounded: async () => signature,
        signAddData: async () => signature,
        signAddDataBounded: async () => signature,
        signLineageAttestation: async () => signature,
      },
      additionsWorkerFactory: workerFactory,
      autoStartSync: false,
      diagnostics,
      additionsTimeBudgetMs: milliseconds,
      ...{ additionsByteBudget: bytes },
    });
    return result.additions!;
  }
  const query = {
    timezone: "UTC",
    days: 2,
    now: new Date("2026-10-21T00:00:00Z"),
  };
  async function document(scope: string) {
    const version = slots.get(scope)?.at(-1)?.expectedVersion;
    const encrypted = blobs.get(`${scope}/${version}`);
    if (!encrypted) throw new Error("Missing committed checkpoint");
    return JSON.parse(
      new TextDecoder().decode(
        await decryptWithPassword(encrypted, password(scope)),
      ),
    ).data;
  }
  return {
    source,
    session,
    document,
    slots,
    blobs,
    stall,
    query,
    failedRegistrations,
    interruptRegistration,
    failRegistrationOnDownload,
    tombstone: (scope: string) =>
      register(scope, {
        expectedVersion: String(
          BigInt(slots.get(scope)?.at(-1)?.expectedVersion ?? "0") + 1n,
        ),
        dataHash:
          "0x30c45ee72fe56d1927701316925ab7ceacd3b6f9267061735d59396f075c6222",
        metadataHash:
          "0xc5255a141acd6a2ae55971b62c0a85977c2511989dc114ad2abc2b7644f57d90",
        status: "finalized",
        addedAt: collectedAt,
        isTombstone: true,
      }),
    delayInventory: (milliseconds: number) => {
      inventoryDelayMs = milliseconds;
    },
  };
}

it("recovers a large source after warm checkpoints while upload hints retain their smaller allowance", async () => {
  const { source, session, document, blobs, query } = await fixture();
  await source("github.events", "1", {
    events: Array.from({ length: 100 }, (_, id) => ({ id: String(id) })),
  });
  await source("instagram.following", "1", {
    accounts: Array.from({ length: 100 }, (_, pk) => ({ pk: String(pk) })),
  });
  expect((await (await session()).summarize(query)).total).toBe(200);
  const posts = Array.from({ length: 400 }, (_, taken_at) => ({
    taken_at,
    caption: "x".repeat(1500),
  }));
  const size = await source("instagram.posts", "1", { posts });
  expect(size).toBeGreaterThan(600_000);
  expect(size).toBeLessThan(650_000);
  expect((await (await session()).summarize(query)).coverage).toBe("behind");
  expect(await document("vana.system.additions.instagram.posts")).toMatchObject(
    { through: "0" },
  );
  const recovered = await (await session(32 * 1024 * 1024)).summarize(query);
  expect(recovered).toMatchObject({ coverage: "complete", total: 600 });
  expect(await document("vana.system.additions.instagram.posts")).toMatchObject(
    { through: "1", currentTotal: 400 },
  );
  expect(await document("vana.system.additions")).toMatchObject({
    coverage: "complete",
    total: 600,
    through: { "instagram.posts": "1" },
  });
  posts.push({ taken_at: 400, caption: "x".repeat(1500) });
  await source("instagram.posts", "2", { posts });
  await (
    await session(32 * 1024 * 1024)
  ).recordUpload({ scope: "instagram.posts" });
  expect(await document("vana.system.additions.instagram.posts")).toMatchObject(
    { through: "1" },
  );
  expect(
    await (await session(32 * 1024 * 1024)).summarize(query),
  ).toMatchObject({ coverage: "complete", total: 601 });
  blobs.delete("instagram.posts/1");
  blobs.delete("instagram.posts/2");
  expect(
    await (await session(32 * 1024 * 1024)).summarize(query),
  ).toMatchObject({
    coverage: "complete",
    total: 601,
    through: { "instagram.posts": "2" },
  });
}, 60_000);

it("checkpoints a multi-megabyte source that cannot advance under the 32 MiB allowance", async () => {
  const { source, session, document, blobs, query } = await fixture();
  const posts = Array.from({ length: 600 }, (_, taken_at) => ({
    taken_at,
    caption: "x".repeat(8000),
  }));
  const size = await source("instagram.posts", "1", { posts });
  expect(size).toBeGreaterThan(4_700_000);
  expect(size).toBeLessThan(5_000_000);
  const limited = await (await session(32 * 1024 * 1024)).summarize(query);
  expect(limited.coverage).toBe("behind");
  expect(await document("vana.system.additions.instagram.posts")).toMatchObject(
    { through: "0" },
  );
  const recovered = await (await session(256 * 1024 * 1024)).summarize(query);
  expect(recovered).toMatchObject({ coverage: "complete", total: 600 });
  expect(await document("vana.system.additions")).toMatchObject({
    coverage: "complete",
    total: 600,
    through: { "instagram.posts": "1" },
  });
  blobs.delete("instagram.posts/1");
  expect(
    await (await session(256 * 1024 * 1024)).summarize(query),
  ).toMatchObject({
    coverage: "complete",
    total: 600,
  });
}, 60_000);

it.each(["metadata_hash_mismatch", "compressed_packet"] as const)(
  "reports %s through the existing diagnostics recorder while rejecting the source",
  async (code) => {
    const { source, session, slots, query } = await fixture();
    await source(
      "github.profile",
      "1",
      { name: "private-diagnostic-sentinel" },
      code === "compressed_packet",
    );
    if (code === "metadata_hash_mismatch")
      slots.get("github.profile")![0]!.metadataHash = `0x${"ab".repeat(32)}`;
    const diagnostics = new DiagnosticsRecorder();
    diagnostics.beginOperation("indexing", "github.profile");
    diagnostics.setScopeReadyAfterIndex("github.profile");
    const summary = await (
      await session(32 * 1024 * 1024, diagnostics)
    ).summarize(query);
    expect(summary).toMatchObject({
      coverage: "partial",
      total: 0,
      through: { "github.profile": "0" },
    });
    expect(diagnostics.snapshot().recentEvents).toContainEqual(
      expect.objectContaining({
        scope: "github.profile",
        fileId: "1",
        detail: `additions:${code}`,
        error: true,
      }),
    );
    expect(JSON.stringify(diagnostics.snapshot())).not.toContain(
      "private-diagnostic-sentinel",
    );
    expect(diagnostics.snapshot().scopes).toContainEqual(
      expect.objectContaining({ scope: "github.profile", status: "ready" }),
    );
    expect(diagnostics.snapshot()).toMatchObject({
      currentPhase: "indexing",
      activeOperation: { phase: "indexing", scope: "github.profile" },
    });
  },
  30_000,
);

it("reports a source-unit timeout as a budget limit rather than corrupt data", async () => {
  const { source, session, stall, query } = await fixture();
  await source("github.profile", "1", { name: "valid" });
  stall.add("github.profile/1");
  const diagnostics = new DiagnosticsRecorder();
  await (await session(32 * 1024 * 1024, diagnostics, 3000)).summarize(query);
  expect(diagnostics.snapshot().recentEvents).toContainEqual(
    expect.objectContaining({
      scope: "github.profile",
      fileId: "1",
      detail: "additions:budget_exceeded",
    }),
  );
}, 10000);

it.each(["before restart", "after checkpoint download"])(
  "retains an interrupted checkpoint intent when registration fails %s",
  async (phase) => {
    const f = await fixture();
    const scope = "vana.system.additions.github.profile";
    await f.source("github.profile", "1", { name: "a" });
    if (phase === "before restart") f.failedRegistrations.add(scope);
    f.interruptRegistration.add(scope);
    await (await f.session(256 * 1024 * 1024)).summarize(f.query);
    expect(f.slots.get(scope)).toHaveLength(1);
    expect(f.slots.get(scope)![0].status).toBe(
      phase === "before restart" ? "failed" : "finalized",
    );
    if (phase === "after checkpoint download")
      f.failRegistrationOnDownload.add(`${scope}/1`);
    const checkpoint = f.blobs.get(`${scope}/1`);
    f.blobs.delete("github.profile/1");
    const result = await (
      await f.session(256 * 1024 * 1024)
    ).summarize(f.query);
    expect(result.coverage).not.toBe("complete");
    expect(f.slots.get(scope)).toHaveLength(1);
    expect(f.blobs.get(`${scope}/1`)).toEqual(checkpoint);
    expect(f.blobs.has(`${scope}/2`)).toBe(false);
  },
  60_000,
);

it("reconstructs cold multi-scope history through the actual worker under inventory latency", async () => {
  const f = await fixture();
  const scopes = Array.from({ length: 30 }, (_, i) => `notes.${i}`);
  for (const scope of scopes)
    await f.source(scope, "1", { records: [{ id: scope }] });
  for (let i = 0; i < 44; i++) f.tombstone(`removed.${i}`);
  expect(
    await (await f.session(256 * 1024 * 1024)).summarize(f.query),
  ).toMatchObject({ coverage: "complete", total: 30 });
  for (const scope of scopes) f.blobs.delete(`${scope}/1`);
  f.delayInventory(200);
  const recovered = await (
    await f.session(256 * 1024 * 1024, undefined, 13_000)
  ).summarize(f.query);
  expect(recovered).toMatchObject({ coverage: "complete", total: 30 });
  expect(recovered.days.map((day) => day.added)).toEqual([30, 0]);
}, 30_000);

it("returns verified cold history when portable publication is fenced without replacing its tombstone", async () => {
  const f = await fixture();
  await f.source("github.events", "1", { events: [{ id: "a" }] });
  expect(await (await f.session()).summarize(f.query)).toMatchObject({
    coverage: "complete",
    total: 1,
  });
  f.tombstone("vana.system.additions");
  f.blobs.delete("github.events/1");
  const diagnostics = new DiagnosticsRecorder();
  expect(
    await (await f.session(undefined, diagnostics)).summarize(f.query),
  ).toMatchObject({ coverage: "complete", total: 1 });
  expect(f.slots.get("vana.system.additions")).toHaveLength(2);
  expect(f.slots.get("vana.system.additions")?.at(-1)).toMatchObject({
    expectedVersion: "2",
    isTombstone: true,
  });
  expect(diagnostics.snapshot().recentEvents).toContainEqual(
    expect.objectContaining({ detail: "additions:publication_blocked" }),
  );
});
