import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { pino } from "pino";
import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import {
  fixedLegacyWriteSeal,
  buildWeb3SignedHeader,
  createTestWallet,
  fixedOwnedAccountStorageMode,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  authenticateRequest,
  cacheRequestBodyBytes,
} from "@opendatalabs/personal-server-ts-core/auth";
import { ContentTooLargeError } from "@opendatalabs/personal-server-ts-core/errors";
import {
  buildDataFilePath,
  type HierarchyManagerOptions,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { LegacyWriteSeal } from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { listenHttpServer } from "../listen.js";
import { dataRoutes } from "./data.js";
import { SCOPE_IMPORT_CHUNK_BYTES } from "./chunked-scope-import.js";

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    stat: vi.fn(actual.stat),
    readFile: vi.fn(actual.readFile),
  };
});

const owner = createTestWallet(9);
const logger = pino({ level: "silent" });
const scope = "chatgpt.conversations";

function sendHttp(
  port: number,
  input: {
    method: string;
    path: string;
    body?: Uint8Array;
    headers: Record<string, string>;
  },
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: "127.0.0.1",
        port,
        method: input.method,
        path: input.path,
        headers: input.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("error", reject);
    if (input.body) req.write(input.body);
    req.end();
  });
}

async function signedHeaders(input: {
  method: string;
  path: string;
  body?: Uint8Array;
}) {
  return {
    authorization: await buildWeb3SignedHeader({
      wallet: owner,
      aud: "http://127.0.0.1",
      method: input.method,
      uri: input.path,
      body: input.body,
    }),
  };
}

describe("chunked scope imports over the @hono/node-server HTTP adapter", () => {
  it("stops caching at the chunk limit and cancels an oversized stream", async () => {
    let cancelled = false;
    let pulls = 0;
    let bytesOffered = 0;
    const request = new Request("http://127.0.0.1/upload", {
      method: "PUT",
      body: new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            pulls++;
            const size = [4, 4, 1, 100][pulls - 1];
            if (size === undefined) return controller.close();
            bytesOffered += size;
            controller.enqueue(new Uint8Array(size));
          },
          cancel() {
            cancelled = true;
          },
        },
        { highWaterMark: 0 },
      ),
      // @ts-expect-error Node's Request requires duplex for streaming bodies.
      duplex: "half",
    });

    await expect(
      cacheRequestBodyBytes(request, 8, true),
    ).rejects.toBeInstanceOf(ContentTooLargeError);
    expect(cancelled).toBe(true);
    expect(bytesOffered).toBe(9);
    expect(pulls).toBe(3);
  });

  it("rejects an oversized Content-Length before reading the body", async () => {
    let pulls = 0;
    const request = new Request("http://127.0.0.1/upload", {
      method: "PUT",
      headers: { "content-length": "9" },
      body: new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            pulls++;
            controller.enqueue(new Uint8Array(1));
          },
        },
        { highWaterMark: 0 },
      ),
      // @ts-expect-error Node's Request requires duplex for streaming bodies.
      duplex: "half",
    });

    await expect(
      cacheRequestBodyBytes(request, 8, true),
    ).rejects.toBeInstanceOf(ContentTooLargeError);
    expect(pulls).toBe(0);
  });

  it("begins with Content-Length, accepts a signed chunk, and finalizes", async () => {
    const dataDir = await mkdtemp(join(tmpdir(), "scope-import-node-http-"));
    const db = initializeDatabase(":memory:");
    const indexManager = createIndexManager(db);
    const hierarchyOptions: HierarchyManagerOptions = { dataDir };
    const app = new Hono();
    app.route(
      "/v1/data",
      dataRoutes({
        accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
        legacyWriteSeal: fixedLegacyWriteSeal("unswitched"),
        indexManager,
        hierarchyOptions,
        logger,
        serverOrigin: "http://127.0.0.1",
        serverOwner: owner.address,
        gateway: { isRegisteredBuilder: async () => true } as never,
        accessLogWriter: { write: async () => undefined },
        mountPath: "/v1/data",
      }),
    );
    const server = await listenHttpServer({
      fetch: app.fetch,
      port: 0,
      hostname: "127.0.0.1",
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Expected a TCP address");
    const port = address.port;
    const path = `/v1/data/${scope}/imports`;
    const chunk = new Uint8Array(SCOPE_IMPORT_CHUNK_BYTES).fill(0x20);
    chunk.set(new TextEncoder().encode('{"data":[]}'));
    const beginBytes = new TextEncoder().encode(
      JSON.stringify({
        totalBytes: chunk.byteLength,
        totalChunks: 1,
        sha256: createHash("sha256").update(chunk).digest("hex"),
      }),
    );
    try {
      const begin = await sendHttp(port, {
        method: "POST",
        path,
        body: beginBytes,
        headers: {
          "content-type": "application/json",
          "content-length": String(beginBytes.byteLength),
          ...(await signedHeaders({ method: "POST", path, body: beginBytes })),
        },
      });
      expect(begin.status, begin.body).toBe(201);
      const { importId } = JSON.parse(begin.body) as { importId: string };
      expect(importId).toEqual(expect.any(String));

      const chunkPath = `${path}/${importId}/chunks/0`;
      const chunkHash = createHash("sha256").update(chunk).digest("hex");
      const upload = await sendHttp(port, {
        method: "PUT",
        path: chunkPath,
        body: chunk,
        headers: {
          "content-type": "application/octet-stream",
          "content-length": String(chunk.byteLength),
          "x-chunk-sha256": chunkHash,
          ...(await signedHeaders({
            method: "PUT",
            path: chunkPath,
            body: chunk,
          })),
        },
      });
      expect(upload.status, upload.body).toBe(200);

      const finalizePath = `${path}/${importId}/finalize`;
      const finalize = await sendHttp(port, {
        method: "POST",
        path: finalizePath,
        headers: {
          "content-length": "0",
          ...(await signedHeaders({ method: "POST", path: finalizePath })),
        },
      });
      expect(finalize.status, finalize.body).toBe(201);
      expect(JSON.parse(finalize.body)).toMatchObject({
        importId,
        sha256: createHash("sha256").update(chunk).digest("hex"),
      });
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      indexManager.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it.each(["normal", "recovery"] as const)(
    "refuses %s finalization when the seal switches during pre-publication I/O",
    async (kind) => {
      // Keep scratch in the checkout even if the runner has no TMPDIR.
      const dataDir = await mkdtemp(
        join(process.cwd(), ".scope-import-fence-"),
      );
      const indexManager = createIndexManager(initializeDatabase(":memory:"));
      let currentSeal = fixedLegacyWriteSeal("unswitched");
      const legacyWriteSeal: LegacyWriteSeal = {
        commit: (write) => currentSeal.commit(write),
        remove: (work) => currentSeal.remove(work),
        admit: () => currentSeal.admit(),
        verdict: () => currentSeal.verdict(),
      };
      const app = new Hono();
      app.route(
        "/v1/data",
        dataRoutes({
          // Keep the early answer stale: the durable seal must refuse even
          // when admission already answered Off.
          accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
          legacyWriteSeal,
          indexManager,
          hierarchyOptions: { dataDir },
          logger,
          serverOrigin: "http://127.0.0.1",
          serverOwner: owner.address,
          gateway: { isRegisteredBuilder: async () => true } as never,
          accessLogWriter: { write: async () => undefined },
          mountPath: "/v1/data",
        }),
      );
      const server = await listenHttpServer({
        fetch: app.fetch,
        port: 0,
        hostname: "127.0.0.1",
      });
      const address = server.address();
      if (!address || typeof address === "string")
        throw new Error("Expected a TCP address");
      const path = `/v1/data/${scope}/imports`;
      const chunk = new TextEncoder().encode('{"data":[]}');
      const hash = createHash("sha256").update(chunk).digest("hex");
      const beginBytes = new TextEncoder().encode(
        JSON.stringify({
          totalBytes: chunk.byteLength,
          totalChunks: 1,
          sha256: hash,
        }),
      );
      let enterIo!: () => void;
      let releaseIo!: () => void;
      const entered = new Promise<void>((resolve) => {
        enterIo = resolve;
      });
      const released = new Promise<void>((resolve) => {
        releaseIo = resolve;
      });
      const actualFs =
        await vi.importActual<typeof import("node:fs/promises")>(
          "node:fs/promises",
        );
      let pending: Promise<{ status: number; body: string }> | undefined;
      try {
        const begin = await sendHttp(address.port, {
          method: "POST",
          path,
          body: beginBytes,
          headers: {
            "content-type": "application/json",
            ...(await signedHeaders({
              method: "POST",
              path,
              body: beginBytes,
            })),
          },
        });
        expect(begin.status, begin.body).toBe(201);
        const { importId } = JSON.parse(begin.body) as { importId: string };
        const chunkPath = `${path}/${importId}/chunks/0`;
        const upload = await sendHttp(address.port, {
          method: "PUT",
          path: chunkPath,
          body: chunk,
          headers: {
            "content-type": "application/octet-stream",
            "x-chunk-sha256": hash,
            ...(await signedHeaders({
              method: "PUT",
              path: chunkPath,
              body: chunk,
            })),
          },
        });
        expect(upload.status, upload.body).toBe(200);
        const sessionPath = join(dataDir, ".scope-imports", importId);
        const metadataPath = join(sessionPath, "metadata.json");
        const metadata = JSON.parse(
          await actualFs.readFile(metadataPath, "utf8"),
        ) as { collectedAt: string };
        let finalPath = buildDataFilePath(dataDir, scope, metadata.collectedAt);
        const stageSuffix = `.pending.${importId}`;
        let stagePath = finalPath + stageSuffix;
        if (kind === "recovery") {
          // Model the crash state: a row exists but only the staged file does.
          await actualFs.mkdir(dirname(finalPath), { recursive: true });
          await actualFs.writeFile(stagePath, chunk);
          await currentSeal.commit((hold) => {
            const inserted = indexManager.insertIfCurrent(
              hold,
              {
                fileId: null,
                schemaId: null,
                path: relative(dataDir, finalPath),
                scope,
                collectedAt: metadata.collectedAt,
                sizeBytes: chunk.byteLength,
                dataPointId: null,
                afterTombstoneVersion: null,
                producer: null,
                producerProvenance: null,
              },
              { kind: "none" },
            );
            expect(inserted.ok).toBe(true);
          });
          vi.mocked(fs.readFile).mockImplementation(async (file, options) => {
            if (String(file) === metadataPath) {
              enterIo();
              await released;
            }
            return Reflect.apply(actualFs.readFile, actualFs, [file, options]);
          });
        } else {
          // Publication and insertion share the seal, so On cannot land
          // between them. Pause the last staged-file I/O before that seal.
          vi.mocked(fs.stat).mockImplementation(async (file, options) => {
            const candidate = String(file);
            if (candidate.endsWith(stageSuffix)) {
              stagePath = candidate;
              finalPath = candidate.slice(0, -stageSuffix.length);
              enterIo();
              await released;
            }
            return Reflect.apply(actualFs.stat, actualFs, [file, options]);
          });
        }
        const finalizePath = `${path}/${importId}/finalize`;
        pending = sendHttp(address.port, {
          method: "POST",
          path: finalizePath,
          headers: {
            "content-length": "0",
            ...(await signedHeaders({ method: "POST", path: finalizePath })),
          },
        });
        // Fail if finalize returns without reaching the intended wait.
        await Promise.race([
          entered,
          pending.then(() => {
            throw new Error("Finalize returned before the deferred I/O");
          }),
        ]);
        expect(await actualFs.stat(stagePath)).toBeDefined();
        currentSeal = fixedLegacyWriteSeal("switched");
        releaseIo();
        const response = await pending;
        const refusal = currentSeal.admit();
        expect(refusal).not.toBeNull();
        expect(response.status, response.body).toBe(refusal!.status);
        expect(JSON.parse(response.body)).toMatchObject(await refusal!.json());
        expect(
          indexManager.findByPath(relative(dataDir, finalPath)),
        ).toBeFalsy();
        expect(indexManager.findLatestByScope(scope)).toBeFalsy();
        await expect(actualFs.stat(stagePath)).rejects.toMatchObject({
          code: "ENOENT",
        });
        await expect(actualFs.stat(finalPath)).rejects.toMatchObject({
          code: "ENOENT",
        });
        await expect(actualFs.stat(sessionPath)).rejects.toMatchObject({
          code: "ENOENT",
        });
      } finally {
        releaseIo();
        await pending?.catch(() => undefined);
        vi.mocked(fs.stat).mockImplementation(actualFs.stat);
        vi.mocked(fs.readFile).mockImplementation(actualFs.readFile);
        await new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        );
        indexManager.close();
        await rm(dataDir, { recursive: true, force: true });
      }
    },
  );

  it("begins a signed import without an explicit Content-Length", async () => {
    const dataDir = await mkdtemp(join(tmpdir(), "scope-import-node-http-"));
    const indexManager = createIndexManager(initializeDatabase(":memory:"));
    const app = new Hono();
    app.route(
      "/v1/data",
      dataRoutes({
        accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
        legacyWriteSeal: fixedLegacyWriteSeal("unswitched"),
        indexManager,
        hierarchyOptions: { dataDir },
        logger,
        serverOrigin: "http://127.0.0.1",
        serverOwner: owner.address,
        gateway: { isRegisteredBuilder: async () => true } as never,
        accessLogWriter: { write: async () => undefined },
        mountPath: "/v1/data",
      }),
    );
    const server = await listenHttpServer({
      fetch: app.fetch,
      port: 0,
      hostname: "127.0.0.1",
    });
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Expected a TCP address");
    const path = `/v1/data/${scope}/imports`;
    const data = new TextEncoder().encode('{"data":[]}');
    const body = new TextEncoder().encode(
      JSON.stringify({
        totalBytes: data.byteLength,
        totalChunks: 1,
        sha256: createHash("sha256").update(data).digest("hex"),
      }),
    );
    try {
      const changedBody = new TextEncoder().encode(
        `${new TextDecoder().decode(body)} `,
      );
      const tampered = await sendHttp(address.port, {
        method: "POST",
        path,
        body: changedBody,
        headers: {
          "content-type": "application/json",
          "content-length": String(changedBody.byteLength),
          ...(await signedHeaders({ method: "POST", path, body })),
        },
      });
      expect(tampered.status, tampered.body).toBe(401);
      expect(JSON.parse(tampered.body)).toMatchObject({
        error: "INVALID_SIGNATURE",
      });

      const begin = await sendHttp(address.port, {
        method: "POST",
        path,
        body,
        headers: {
          "content-type": "application/json",
          ...(await signedHeaders({ method: "POST", path, body })),
        },
      });
      expect(begin.status, begin.body).toBe(201);
      expect(JSON.parse(begin.body).importId).toEqual(expect.any(String));
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      indexManager.close();
      await rm(dataDir, { recursive: true, force: true });
    }
  });

  it.each([true, false])(
    "returns 413 for an oversized chunk with Content-Length: %s",
    async (withContentLength) => {
      const dataDir = await mkdtemp(join(tmpdir(), "scope-import-node-http-"));
      const indexManager = createIndexManager(initializeDatabase(":memory:"));
      const app = new Hono();
      app.route(
        "/v1/data",
        dataRoutes({
          accountStorageMode: fixedOwnedAccountStorageMode("unswitched"),
          legacyWriteSeal: fixedLegacyWriteSeal("unswitched"),
          indexManager,
          hierarchyOptions: { dataDir },
          logger,
          serverOrigin: "http://127.0.0.1",
          serverOwner: owner.address,
          gateway: { isRegisteredBuilder: async () => true } as never,
          accessLogWriter: { write: async () => undefined },
          mountPath: "/v1/data",
        }),
      );
      const server = await listenHttpServer({
        fetch: app.fetch,
        port: 0,
        hostname: "127.0.0.1",
      });
      const address = server.address();
      if (!address || typeof address === "string")
        throw new Error("Expected a TCP address");
      const path = `/v1/data/${scope}/imports/not-created/chunks/0`;
      const body = new Uint8Array(SCOPE_IMPORT_CHUNK_BYTES + 1);
      try {
        const unsigned = await sendHttp(address.port, {
          method: "PUT",
          path,
          body: new Uint8Array([1]),
          headers: { "content-type": "application/octet-stream" },
        });
        expect(unsigned.status, unsigned.body).toBe(401);

        const response = await sendHttp(address.port, {
          method: "PUT",
          path,
          body,
          headers: {
            "content-type": "application/octet-stream",
            ...(withContentLength
              ? { "content-length": String(body.byteLength) }
              : {}),
          },
        });
        expect(response.status, response.body).toBe(413);
        expect(JSON.parse(response.body)).toMatchObject({
          error: "CONTENT_TOO_LARGE",
        });
      } finally {
        await new Promise<void>((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        );
        indexManager.close();
        await rm(dataDir, { recursive: true, force: true });
      }
    },
  );

  it("rejects cached bytes that differ from the signed body after JSON parsing", async () => {
    const path = `/v1/data/${scope}/imports`;
    const signedBody = new TextEncoder().encode('{"data":[]}');
    const changedBody = new TextEncoder().encode('{"data":[]} ');
    const request = new Request(`http://127.0.0.1${path}`, {
      method: "POST",
      headers: {
        authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: "http://127.0.0.1",
          method: "POST",
          uri: path,
          body: signedBody,
        }),
      },
      body: changedBody,
    });
    await cacheRequestBodyBytes(request);
    await request.json();

    await expect(
      authenticateRequest({
        request,
        serverOrigin: "http://127.0.0.1",
        serverOwner: owner.address,
      }),
    ).rejects.toMatchObject({ errorCode: "INVALID_SIGNATURE" });
  });
});
