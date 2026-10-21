import { afterEach, expect, it, vi } from "vitest";
import { createMessage, encrypt, enums } from "openpgp";
import { DiagnosticsRecorder } from "./diagnostics.js";
import { Worker } from "node:worker_threads";
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
  const slots = new Map<string, Slot[]>();
  const blobs = new Map<string, Uint8Array>();
  const stall = new Set<string>();
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
        return bytes
          ? new Response(new Uint8Array(bytes))
          : new Response(null, { status: 404 });
      }
      if (init?.method === "POST") {
        const data = JSON.parse(await new Response(init.body).text());
        register(data.scope, {
          ...data,
          status: "finalized",
          addedAt: collectedAt,
          isTombstone: false,
        });
        return Response.json({ expectedVersion: data.expectedVersion });
      }
      const scope = url.searchParams.get("scope");
      if (scope !== null) {
        const versions = slots.get(scope) ?? [];
        return Response.json({
          data: {
            dataPointId: idFor(scope),
            ownerAddress: owner.address,
            scope,
            head: versions.length
              ? { ...versions.at(-1), deletedAt: null }
              : null,
            versions: versions.filter(
              (row) =>
                BigInt(row.expectedVersion) >
                BigInt(url.searchParams.get("after") ?? "0"),
            ),
          },
          pagination: {
            limit: Number(url.searchParams.get("limit")),
            hasMore: false,
            nextAfter: null,
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
  return { source, session, document, slots, blobs, stall, query };
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
