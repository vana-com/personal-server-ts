import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pino } from "pino";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  authenticateRequest,
  cacheRequestBodyBytes,
} from "@opendatalabs/personal-server-ts-core/auth";
import type { HierarchyManagerOptions } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { listenHttpServer } from "../listen.js";
import { dataRoutes } from "./data.js";

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
  it("begins with Content-Length, accepts a signed chunk, and finalizes", async () => {
    const dataDir = await mkdtemp(join(tmpdir(), "scope-import-node-http-"));
    const db = initializeDatabase(":memory:");
    const indexManager = createIndexManager(db);
    const hierarchyOptions: HierarchyManagerOptions = { dataDir };
    const app = new Hono();
    app.route(
      "/v1/data",
      dataRoutes({
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
    const beginBytes = new TextEncoder().encode(
      JSON.stringify({
        totalBytes: new TextEncoder().encode('{"data":[]}').byteLength,
        totalChunks: 1,
        sha256: createHash("sha256").update('{"data":[]}').digest("hex"),
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
      const chunk = new TextEncoder().encode('{"data":[]}');
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

  it("begins a signed import without an explicit Content-Length", async () => {
    const dataDir = await mkdtemp(join(tmpdir(), "scope-import-node-http-"));
    const indexManager = createIndexManager(initializeDatabase(":memory:"));
    const app = new Hono();
    app.route(
      "/v1/data",
      dataRoutes({
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
      expect(tampered.status, tampered.body).not.toBe(201);

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
