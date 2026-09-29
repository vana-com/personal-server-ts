import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import { mkdir, open, readFile, rm, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildDataFilePath } from "../../packages/core/src/storage/hierarchy/index.js";
import type { IndexManager } from "../../packages/core/src/storage/index/index.js";
import {
  SCOPE_IMPORT_TTL_MS,
  beginScopeImport,
  cleanupExpiredScopeImports,
  finalizeScopeImport,
  putScopeImportChunk,
  type ScopeImportDeps,
} from "../../packages/server/src/routes/chunked-scope-import.js";
import { startChildTestServer } from "./helpers/child-server.js";
import { startTestServer, type TestServer } from "./helpers/server.js";

const CHUNK_BYTES = 8 * 1024 * 1024;
const DATA_BYTES = 170 * 1024 * 1024;
const SERVER_DIR = resolve(process.cwd(), ".scratch", "chunked-scope-import");
const OWNER_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

async function digestFile(path: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function digestRange(
  path: string,
  start: number,
  end: number,
): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path, { start, end }))
    hash.update(chunk);
  return hash.digest("hex");
}

async function writeChatGptScope(path: string): Promise<string> {
  await mkdir(resolve(path, ".."), { recursive: true });
  const handle = await open(path, "w");
  const hash = createHash("sha256");
  let bytes = 0;
  const write = async (chunk: Buffer) => {
    bytes += chunk.byteLength;
    hash.update(chunk);
    await handle.writeFile(chunk);
  };
  const prefix = Buffer.from('{"conversations":[{"id":"conv-000001","title":"');
  const suffix = Buffer.from('"},{"id":"conv-000002","title":"follow-up"}]}');
  await write(prefix);
  const fillBytes = DATA_BYTES - prefix.byteLength - suffix.byteLength;
  const fill = Buffer.alloc(CHUNK_BYTES, 0x78);
  let left = fillBytes;
  while (left > 0) {
    const next = fill.subarray(0, Math.min(left, fill.byteLength));
    await write(next);
    left -= next.byteLength;
  }
  await write(suffix);
  await handle.sync();
  await handle.close();
  expect(bytes).toBe(DATA_BYTES);
  return hash.digest("hex");
}

async function beginImport(
  server: Pick<TestServer, "url" | "devToken">,
  scope: string,
  body: { totalBytes: number; totalChunks: number; sha256: string },
) {
  const response = await fetch(`${server.url}/v1/data/${scope}/imports`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${server.devToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() };
}

async function putChunk(
  server: Pick<TestServer, "url" | "devToken">,
  scope: string,
  id: string,
  index: number,
  body: Buffer | ReadableStream<Uint8Array>,
  digest?: string,
) {
  const bodyDigest =
    digest ??
    (body instanceof Buffer
      ? createHash("sha256").update(body).digest("hex")
      : "");
  return fetch(`${server.url}/v1/data/${scope}/imports/${id}/chunks/${index}`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${server.devToken}`,
      "Content-Type": "application/octet-stream",
      "X-Chunk-SHA256": bodyDigest,
    },
    body: body as BodyInit,
    ...(body instanceof Buffer ? {} : { duplex: "half" }),
  } as RequestInit & { duplex?: "half" });
}

async function openServer(): Promise<TestServer> {
  return startTestServer({
    masterKeySignature: OWNER_SIGNATURE,
    serverDir: SERVER_DIR,
  });
}

describe("legacy chunked scope import (real server)", () => {
  it("keeps the committed scope readable across restart during an incomplete import", async () => {
    await rm(SERVER_DIR, { recursive: true, force: true });
    const server = await startChildTestServer({
      rootPath: SERVER_DIR,
      ownerSignature: OWNER_SIGNATURE,
    });
    let restarted: Awaited<ReturnType<typeof startChildTestServer>> | undefined;
    try {
      const oldBody = JSON.stringify({
        conversations: [{ id: "old", title: "committed" }],
      });
      const oldWrite = await fetch(`${server.url}/v1/data/chatgpt.scope`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${server.devToken}`,
          "Content-Type": "application/json",
        },
        body: oldBody,
      });
      expect(oldWrite.status).toBe(201);

      const pendingBytes = Buffer.from('{"conversations":[{"id":"new"}]}');
      const pending = await beginImport(server, "chatgpt.scope", {
        totalBytes: pendingBytes.length + 1,
        totalChunks: 1,
        sha256: createHash("sha256")
          .update(Buffer.concat([pendingBytes, Buffer.from(" ")]))
          .digest("hex"),
      });
      const id = pending.body.importId as string;
      const chunk = await putChunk(
        server,
        "chatgpt.scope",
        id,
        0,
        Buffer.concat([pendingBytes, Buffer.from(" ")]),
      );
      expect(chunk.status).toBe(200);
      await server.kill();

      restarted = await startChildTestServer({
        rootPath: SERVER_DIR,
        ownerSignature: OWNER_SIGNATURE,
      });
      const read = await fetch(`${restarted.url}/v1/data/chatgpt.scope`, {
        headers: { Authorization: `Bearer ${restarted.devToken}` },
      });
      expect(read.status).toBe(200);
      const envelope = await read.json();
      expect(envelope.data).toEqual({
        conversations: [{ id: "old", title: "committed" }],
      });
    } finally {
      await server.stop();
      await restarted?.stop();
      await rm(SERVER_DIR, { recursive: true, force: true });
    }
  }, 60_000);

  it("aborts an import idempotently only for its authenticated owner and scope", async () => {
    await rm(SERVER_DIR, { recursive: true, force: true });
    const server = await openServer();
    try {
      const data = Buffer.from('{"unfinished":true}');
      const started = await beginImport(server, "chatgpt.abort", {
        totalBytes: data.length,
        totalChunks: 1,
        sha256: createHash("sha256").update(data).digest("hex"),
      });
      const id = started.body.importId as string;
      expect(
        (await putChunk(server, "chatgpt.abort", id, 0, data)).status,
      ).toBe(200);

      const abortUrl = `${server.url}/v1/data/chatgpt.abort/imports/${id}`;
      const unauthorized = await fetch(abortUrl, {
        method: "DELETE",
        headers: { Authorization: "Bearer invalid" },
      });
      expect(unauthorized.status).not.toBe(200);

      const wrongScope = await fetch(
        `${server.url}/v1/data/chatgpt.other/imports/${id}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${server.devToken}` },
        },
      );
      expect(wrongScope.status).toBe(404);
      const importDirectory = join(SERVER_DIR, "data", ".scope-imports", id);
      expect((await stat(join(importDirectory, "chunk-0.bin"))).isFile()).toBe(
        true,
      );

      const aborted = await fetch(abortUrl, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${server.devToken}` },
      });
      expect(aborted.status).toBe(200);
      expect(await aborted.json()).toMatchObject({
        importId: id,
        status: "aborted",
      });
      const repeated = await fetch(abortUrl, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${server.devToken}` },
      });
      expect(repeated.status).toBe(200);
      expect(await repeated.json()).toMatchObject({
        importId: id,
        status: "aborted",
      });
      expect(await stat(importDirectory).catch(() => null)).toBeNull();

      const finalize = await fetch(`${abortUrl}/finalize`, {
        method: "POST",
        headers: { Authorization: `Bearer ${server.devToken}` },
      });
      expect(finalize.status).toBe(410);
      expect(
        (
          await beginImport(server, "chatgpt.abort", {
            totalBytes: data.length,
            totalChunks: 1,
            sha256: createHash("sha256").update(data).digest("hex"),
          })
        ).response.status,
      ).toBe(201);
    } finally {
      await server.cleanup();
      await rm(SERVER_DIR, { recursive: true, force: true });
    }
  }, 60_000);

  it("cleans pending envelopes when a failed import expires", async () => {
    const dataDir = join(SERVER_DIR, "direct-cleanup-data");
    await rm(SERVER_DIR, { recursive: true, force: true });
    await mkdir(dataDir, { recursive: true });
    const deps: ScopeImportDeps = {
      hierarchyOptions: { dataDir },
      indexManager: {
        findByPath: () => undefined,
        findLatestByScope: () => undefined,
      } as unknown as IndexManager,
      serverOwner: "0x1111111111111111111111111111111111111111",
      authorizeOwner: async () => undefined,
      afterTombstoneVersion: async () => {
        throw new Error("injected finalize failure");
      },
    };
    try {
      const data = Buffer.from('{"unfinished":true}');
      const request = new Request("http://localhost", { method: "POST" });
      const started = await beginScopeImport(deps, request, "chatgpt.failure", {
        totalBytes: data.length,
        totalChunks: 1,
        sha256: createHash("sha256").update(data).digest("hex"),
      });
      const chunkRequest = new Request("http://localhost/chunk", {
        method: "PUT",
        headers: {
          "content-type": "application/octet-stream",
          "x-chunk-sha256": createHash("sha256").update(data).digest("hex"),
        },
        body: data,
      });
      await putScopeImportChunk(
        deps,
        chunkRequest,
        "chatgpt.failure",
        started.importId,
        0,
      );
      await expect(
        finalizeScopeImport(deps, request, "chatgpt.failure", started.importId),
      ).rejects.toThrow("injected finalize failure");

      const metadata = JSON.parse(
        await readFile(
          join(dataDir, ".scope-imports", started.importId, "metadata.json"),
          "utf8",
        ),
      ) as { scope: string; collectedAt: string };
      const finalPath = buildDataFilePath(
        dataDir,
        metadata.scope,
        metadata.collectedAt,
      );
      const pendingPath = `${finalPath}.pending.${started.importId}`;
      expect(await stat(pendingPath).catch(() => null)).toBeNull();

      // Recreate the exact orphan a process crash before cleanup could leave.
      await (await open(pendingPath, "w")).close();
      await cleanupExpiredScopeImports(
        deps,
        Date.now() + SCOPE_IMPORT_TTL_MS + 1,
      );
      expect(await stat(pendingPath).catch(() => null)).toBeNull();
      expect(
        await stat(join(dataDir, ".scope-imports", started.importId)).catch(
          () => null,
        ),
      ).toBeNull();
    } finally {
      await rm(SERVER_DIR, { recursive: true, force: true });
    }
  }, 60_000);

  it("rejects wrong hashes, gaps, and conflicting retries", async () => {
    await rm(SERVER_DIR, { recursive: true, force: true });
    const server = await openServer();
    try {
      const data = Buffer.from("{}");
      const wrong = await beginImport(server, "chatgpt.errors", {
        totalBytes: data.length,
        totalChunks: 1,
        sha256: createHash("sha256").update(data).digest("hex"),
      });
      const wrongHash = await putChunk(
        server,
        "chatgpt.errors",
        wrong.body.importId,
        0,
        data,
        "0".repeat(64),
      );
      expect(wrongHash.status).toBe(422);

      const gap = await beginImport(server, "chatgpt.gaps", {
        totalBytes: CHUNK_BYTES + 1,
        totalChunks: 2,
        sha256: "a".repeat(64),
      });
      const skipped = await putChunk(
        server,
        "chatgpt.gaps",
        gap.body.importId,
        1,
        Buffer.from("b"),
      );
      expect(skipped.status).toBe(409);

      const first = Buffer.from('{"x":1}');
      const conflicting = await beginImport(server, "chatgpt.duplicate", {
        totalBytes: first.length,
        totalChunks: 1,
        sha256: createHash("sha256").update(first).digest("hex"),
      });
      expect(
        (
          await putChunk(
            server,
            "chatgpt.duplicate",
            conflicting.body.importId,
            0,
            first,
          )
        ).status,
      ).toBe(200);
      expect(
        (
          await putChunk(
            server,
            "chatgpt.duplicate",
            conflicting.body.importId,
            0,
            first,
          )
        ).status,
      ).toBe(200);
      expect(
        (
          await putChunk(
            server,
            "chatgpt.duplicate",
            conflicting.body.importId,
            0,
            Buffer.from('{"x":2}'),
          )
        ).status,
      ).toBe(409);

      const invalid = Buffer.from('{"value": }');
      const invalidImport = await beginImport(server, "chatgpt.invalid", {
        totalBytes: invalid.length,
        totalChunks: 1,
        sha256: createHash("sha256").update(invalid).digest("hex"),
      });
      expect(
        (
          await putChunk(
            server,
            "chatgpt.invalid",
            invalidImport.body.importId,
            0,
            invalid,
          )
        ).status,
      ).toBe(200);
      const invalidFinalize = await fetch(
        `${server.url}/v1/data/chatgpt.invalid/imports/${invalidImport.body.importId}/finalize`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${server.devToken}` },
        },
      );
      expect(invalidFinalize.status).toBe(400);

      await rm(
        join(SERVER_DIR, "data", ".scope-imports", invalidImport.body.importId),
        {
          recursive: true,
          force: true,
        },
      );
      const bomJson = Buffer.from('\uFEFF{"value":1}');
      const bomImport = await beginImport(server, "chatgpt.bom", {
        totalBytes: bomJson.length,
        totalChunks: 1,
        sha256: createHash("sha256").update(bomJson).digest("hex"),
      });
      expect(
        (
          await putChunk(
            server,
            "chatgpt.bom",
            bomImport.body.importId,
            0,
            bomJson,
          )
        ).status,
      ).toBe(200);
      const bomFinalize = await fetch(
        `${server.url}/v1/data/chatgpt.bom/imports/${bomImport.body.importId}/finalize`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${server.devToken}` },
        },
      );
      expect(bomFinalize.status).toBe(400);
    } finally {
      await server.cleanup();
      await rm(SERVER_DIR, { recursive: true, force: true });
    }
  }, 60_000);

  it("imports and serves a 170 MiB ChatGPT-shaped scope byte-identically with bounded RSS", async () => {
    await rm(SERVER_DIR, { recursive: true, force: true });
    const server = await openServer();
    const bodyPath = join(SERVER_DIR, "chatgpt-scope.json");
    try {
      const expectedDigest = await writeChatGptScope(bodyPath);
      const peakRssBeforeImport = process.resourceUsage().maxRSS * 1024;
      const rssBefore = process.memoryUsage().rss;
      let peakObservedRss = rssBefore;
      const started = await beginImport(server, "chatgpt.large", {
        totalBytes: DATA_BYTES,
        totalChunks: Math.ceil(DATA_BYTES / CHUNK_BYTES),
        sha256: expectedDigest,
      });
      expect(started.response.status).toBe(201);
      const id = started.body.importId as string;
      for (
        let index = 0;
        index < Math.ceil(DATA_BYTES / CHUNK_BYTES);
        index++
      ) {
        const size = Math.min(CHUNK_BYTES, DATA_BYTES - index * CHUNK_BYTES);
        const start = index * CHUNK_BYTES;
        const end = start + size - 1;
        const chunkDigest = await digestRange(bodyPath, start, end);
        const body = Readable.toWeb(
          createReadStream(bodyPath, { start, end }),
        ) as ReadableStream<Uint8Array>;
        const response = await putChunk(
          server,
          "chatgpt.large",
          id,
          index,
          body,
          chunkDigest,
        );
        expect(response.status).toBe(200);
        peakObservedRss = Math.max(peakObservedRss, process.memoryUsage().rss);
      }
      const finalize = await fetch(
        `${server.url}/v1/data/chatgpt.large/imports/${id}/finalize`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${server.devToken}` },
        },
      );
      expect(finalize.status).toBe(201);
      const receipt = await finalize.json();
      expect(receipt.sha256).toBe(expectedDigest);
      expect(receipt.totalBytes).toBe(DATA_BYTES);
      const retryReceipt = await fetch(
        `${server.url}/v1/data/chatgpt.large/imports/${id}/finalize`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${server.devToken}` },
        },
      );
      expect(retryReceipt.status).toBe(201);
      expect(await retryReceipt.json()).toEqual(receipt);

      const peakRssDuringImport = process.resourceUsage().maxRSS * 1024;
      process.stderr.write(
        `chunked-scope-import-rss bytes=${DATA_BYTES} chunk=${CHUNK_BYTES} peak_delta=${peakRssDuringImport - peakRssBeforeImport} observed_rss=${peakObservedRss} baseline_rss=${rssBefore}\n`,
      );
      expect(
        peakRssDuringImport - peakRssBeforeImport,
        JSON.stringify({
          peakRssBeforeImport,
          peakRssDuringImport,
          peakObservedRss,
          rssBefore,
        }),
      ).toBeLessThan(128 * 1024 * 1024);

      const served = await fetch(`${server.url}/v1/data/chatgpt.large`, {
        headers: { Authorization: `Bearer ${server.devToken}` },
      });
      expect(served.status, await served.clone().text()).toBe(200);
      const envelope = await served.json();
      expect(envelope.collectedAt).toBe(receipt.collectedAt);
      const storedPath = buildDataFilePath(
        join(SERVER_DIR, "data"),
        "chatgpt.large",
        receipt.collectedAt,
      );
      const dataPrefixBytes = Buffer.byteLength(
        `{"version":"1.0","scope":"chatgpt.large","collectedAt":${JSON.stringify(receipt.collectedAt)},"data":`,
      );
      expect(
        await digestRange(
          storedPath,
          dataPrefixBytes,
          dataPrefixBytes + DATA_BYTES - 1,
        ),
      ).toBe(expectedDigest);
      const storedDigest = await digestFile(storedPath);
      expect(storedDigest).toBe(
        createHash("sha256").update(JSON.stringify(envelope)).digest("hex"),
      );
      const stats = await stat(storedPath);
      expect(stats.size).toBeGreaterThan(DATA_BYTES);
      console.info(JSON.stringify({ storedBytes: stats.size }));
    } finally {
      await server.cleanup();
      await rm(SERVER_DIR, { recursive: true, force: true });
    }
  }, 300_000);
});
