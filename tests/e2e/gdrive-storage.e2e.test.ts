import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Hono } from "hono";
import { serve, type ServerType } from "@hono/node-server";
import { IDBFactory } from "fake-indexeddb";
import { privateKeyToAccount } from "viem/accounts";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { signOwnerMasterKey } from "../../packages/core/src/keys/index.js";
import { ServerConfigSchema } from "../../packages/core/src/schemas/server-config.js";
import type { StorageCredentialProvider } from "../../packages/core/src/storage/adapters/index.js";
import { computeDataPointId } from "../../packages/core/src/sync/data-point-id.js";
import {
  TOMBSTONE_DATA_HASH,
  TOMBSTONE_METADATA_HASH,
} from "../../packages/core/src/sync/tombstone.js";
import { createIndexedDbPsLiteRuntime } from "../../packages/lite/src/browser-runtime.js";
import { createServer } from "../../packages/server/src/bootstrap.js";
import { declareAccountMode } from "../../packages/server/src/account-mode/unswitched-server.test-utils.js";

interface StoredDriveFile {
  id: string;
  name: string;
  parents: string[];
  bytes: Uint8Array;
  sha256Checksum: string;
  createdTime: string;
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseMultipartRelated(
  body: Buffer,
  contentType: string,
): { metadata: { name: string; parents?: string[] }; media: Uint8Array } {
  const match = /boundary=([^\s;]+)/i.exec(contentType);
  if (!match) throw new Error(`Missing boundary in ${contentType}`);
  const parts = body
    .toString("latin1")
    .split(`--${match[1]}`)
    .slice(1)
    .filter((p) => !p.startsWith("--"));
  const extract = (part: string): Buffer => {
    const idx = part.indexOf("\r\n\r\n");
    const content = part.slice(idx + 4);
    return Buffer.from(
      content.endsWith("\r\n") ? content.slice(0, -2) : content,
      "latin1",
    );
  };
  return {
    metadata: JSON.parse(extract(parts[0]!).toString("utf8")) as {
      name: string;
      parents?: string[];
    },
    media: new Uint8Array(extract(parts[1]!)),
  };
}

function unescapeDriveQueryString(input: string): string {
  return input.replace(/\\(['\\])/g, "$1");
}

async function startLoopbackDrive() {
  const files = new Map<string, StoredDriveFile>();
  const validTokens = new Set<string>([
    "desktop-access-token",
    "web-access-token",
  ]);
  let permissionsCalled = false;
  let idCounter = 1;

  const server: Server = createHttpServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks);
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    if (url.pathname.includes("/permissions")) {
      permissionsCalled = true;
      res.writeHead(500);
      res.end("permissions forbidden");
      return;
    }

    const auth = req.headers.authorization;
    const token = auth?.startsWith("Bearer ")
      ? auth.slice("Bearer ".length)
      : null;
    if (!token || !validTokens.has(token)) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: {
            code: 401,
            message: "Invalid Credentials",
            errors: [{ reason: "authError" }],
          },
        }),
      );
      return;
    }

    if (method === "GET" && url.pathname === "/drive/v3/files") {
      const q = url.searchParams.get("q") ?? "";
      const parentMatch = /'((?:\\.|[^'\\])*)' in parents/.exec(q);
      const nameMatch = /name = '((?:\\.|[^'\\])*)'/.exec(q);
      const parentId = parentMatch
        ? unescapeDriveQueryString(parentMatch[1]!)
        : "";
      const name = nameMatch ? unescapeDriveQueryString(nameMatch[1]!) : "";
      const matched = [...files.values()].filter(
        (f) => f.parents.includes(parentId) && f.name === name,
      );
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          files: matched.map((f) => ({
            id: f.id,
            name: f.name,
            size: String(f.bytes.byteLength),
            sha256Checksum: f.sha256Checksum,
            createdTime: f.createdTime,
          })),
        }),
      );
      return;
    }

    if (method === "POST" && url.pathname === "/upload/drive/v3/files") {
      const parsed = parseMultipartRelated(
        body,
        req.headers["content-type"] ?? "",
      );
      const id = `drive-file-${idCounter++}`;
      const record: StoredDriveFile = {
        id,
        name: parsed.metadata.name,
        parents: parsed.metadata.parents ?? [],
        bytes: parsed.media,
        sha256Checksum: sha256Hex(parsed.media),
        createdTime: new Date().toISOString(),
      };
      files.set(id, record);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          id: record.id,
          name: record.name,
          size: String(record.bytes.byteLength),
          sha256Checksum: record.sha256Checksum,
          createdTime: record.createdTime,
        }),
      );
      return;
    }

    if (method === "GET" && url.pathname.startsWith("/drive/v3/files/")) {
      const id = decodeURIComponent(
        url.pathname.slice("/drive/v3/files/".length),
      );
      const record = files.get(id);
      if (!record) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: 404, message: "Not Found" } }));
        return;
      }
      if (url.searchParams.get("alt") === "media") {
        res.writeHead(200, {
          "content-type": "application/octet-stream",
          "content-length": String(record.bytes.byteLength),
        });
        res.end(Buffer.from(record.bytes));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ id: record.id, name: record.name }));
      return;
    }

    if (method === "DELETE" && url.pathname.startsWith("/drive/v3/files/")) {
      const id = decodeURIComponent(
        url.pathname.slice("/drive/v3/files/".length),
      );
      if (!files.delete(id)) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { code: 404, message: "Not Found" } }));
        return;
      }
      res.writeHead(204);
      res.end();
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    files,
    validTokens,
    wasPermissionsCalled: () => permissionsCalled,
    close: async () => {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

interface StoredPoint {
  id: string;
  ownerAddress: string;
  scope: string;
  dataHash: string;
  metadataHash: string;
  expectedVersion: string;
  addedAt: string;
  deletedAt: string | null;
  versions: Array<{
    expectedVersion: string;
    dataHash: string;
    metadataHash: string;
    status: string;
    addedAt: string;
    isTombstone: boolean;
  }>;
}

async function startLoopbackSyncGateway() {
  const registeredServers = new Set<string>();
  const points = new Map<string, StoredPoint>();
  const app = new Hono();

  const wrap = <T>(data: T) => ({
    data,
    proof: {
      signature: "0xmockproof",
      timestamp: new Date().toISOString(),
      gatewayAddress: "0xMockGateway",
      requestHash: "0xreqhash",
      responseHash: "0xreshash",
      userSignature: "0xusersig",
      status: "confirmed",
      chainBlockHeight: 1000,
    },
  });

  app.get("/v1/servers/:address", (c) => {
    const addr = c.req.param("address").toLowerCase();
    if (!registeredServers.has(addr)) {
      return c.json({ error: "not found" }, 404);
    }
    return c.json(
      wrap({
        id: "0xserver1",
        ownerAddress: "0xOwner",
        serverAddress: c.req.param("address"),
        publicKey: "0x04pubkey",
        serverUrl: "https://server.example.com",
        addedAt: new Date().toISOString(),
      }),
    );
  });

  app.post("/v1/data", async (c) => {
    const body = (await c.req.json()) as {
      ownerAddress: string;
      scope: string;
      dataHash: string;
      metadataHash: string;
      expectedVersion: string | number;
    };
    const id = computeDataPointId(
      body.ownerAddress as `0x${string}`,
      body.scope,
    );
    const now = new Date().toISOString();
    const version = String(body.expectedVersion);
    const existing = points.get(id);
    const versionRow = {
      expectedVersion: version,
      dataHash: body.dataHash,
      metadataHash: body.metadataHash,
      status: "finalized",
      addedAt: now,
      isTombstone: false,
    };
    const updated: StoredPoint = {
      id,
      ownerAddress: body.ownerAddress,
      scope: body.scope,
      dataHash: body.dataHash,
      metadataHash: body.metadataHash,
      expectedVersion: version,
      addedAt: now,
      deletedAt: null,
      versions: [...(existing?.versions ?? []), versionRow],
    };
    points.set(id, updated);
    return c.json(wrap({ dataPointId: id, ...updated }), 201);
  });

  app.get("/v1/data", (c) => {
    const user = (c.req.query("user") ?? "").toLowerCase();
    const includeDeleted = c.req.query("includeDeleted") === "true";
    const rows = [...points.values()].filter(
      (p) =>
        p.ownerAddress.toLowerCase() === user &&
        (includeDeleted || p.deletedAt === null),
    );
    return c.json({
      data: {
        dataPoints: rows.map((p) => ({
          id: p.id,
          ownerAddress: p.ownerAddress,
          scope: p.scope,
          dataHash: p.dataHash,
          metadataHash: p.metadataHash,
          expectedVersion: p.expectedVersion,
          addedAt: p.addedAt,
          deletedAt: p.deletedAt,
        })),
      },
      pagination: { hasMore: false, nextCursor: null },
    });
  });

  app.get("/v1/data/:id/versions", (c) => {
    const id = c.req.param("id");
    const limit = Number(c.req.query("limit") ?? "100");
    const after = BigInt(c.req.query("after") ?? "0");
    const user = c.req.query("user") ?? "";
    const scope = c.req.query("scope") ?? "";
    const point = points.get(id);
    if (!point) {
      return c.json({
        data: {
          dataPointId: id,
          ownerAddress: user,
          scope,
          head: null,
          versions: [],
        },
        pagination: { limit, hasMore: false, nextAfter: null },
      });
    }
    return c.json({
      data: {
        dataPointId: point.id,
        ownerAddress: point.ownerAddress,
        scope: point.scope,
        head: {
          expectedVersion: point.expectedVersion,
          dataHash: point.dataHash,
          metadataHash: point.metadataHash,
          status: "finalized",
          deletedAt: point.deletedAt,
        },
        versions: point.versions.filter(
          (v) => BigInt(v.expectedVersion) > after,
        ),
      },
      pagination: { limit, hasMore: false, nextAfter: null },
    });
  });

  app.get("/v1/data/:id", (c) => {
    const point = points.get(c.req.param("id"));
    if (!point) return c.json({ error: "not found" }, 404);
    return c.json(wrap(point));
  });

  app.delete("/v1/data/:id", async (c) => {
    const id = c.req.param("id");
    const body = (await c.req.json()) as { expectedVersion: string };
    const existing = points.get(id);
    if (!existing) return c.json({ error: "not found" }, 404);
    const now = new Date().toISOString();
    existing.expectedVersion = String(body.expectedVersion);
    existing.dataHash = TOMBSTONE_DATA_HASH;
    existing.metadataHash = TOMBSTONE_METADATA_HASH;
    existing.deletedAt = now;
    existing.versions.push({
      expectedVersion: existing.expectedVersion,
      dataHash: TOMBSTONE_DATA_HASH,
      metadataHash: TOMBSTONE_METADATA_HASH,
      status: "finalized",
      addedAt: now,
      isTombstone: true,
    });
    return c.json(wrap(existing));
  });

  const server: ServerType = serve({ fetch: app.fetch, port: 0 });
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    registerServer: (address: string) =>
      registeredServers.add(address.toLowerCase()),
    points,
    close: async () => {
      await new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      );
    },
  };
}

describe("Google Drive storage E2E (PS Node -> Drive -> PS Lite)", () => {
  const folderId = "vana-e2e-folder";
  let drive: Awaited<ReturnType<typeof startLoopbackDrive>>;
  let gateway: Awaited<ReturnType<typeof startLoopbackSyncGateway>>;
  let serverDir: string;
  let ownerAddress: `0x${string}`;
  let ownerSignature: `0x${string}`;

  beforeAll(async () => {
    const ownerAccount = privateKeyToAccount(`0x${"42".repeat(32)}`);
    ownerAddress = ownerAccount.address;
    ownerSignature = await signOwnerMasterKey(ownerAccount);
    drive = await startLoopbackDrive();
    gateway = await startLoopbackSyncGateway();
    serverDir = await mkdtemp(join(tmpdir(), "e2e-gdrive-ps-"));
  }, 30_000);

  afterAll(async () => {
    await drive?.close();
    await gateway?.close();
    if (serverDir) await rm(serverDir, { recursive: true, force: true });
  });

  it("uploads encrypted blob from PS Node to Google Drive, reads & decrypts it in PS Lite, handles revocation, and deletes blob on scope delete", async () => {
    const desktopCredentials: StorageCredentialProvider = {
      async getAccessToken() {
        return "desktop-access-token";
      },
    };
    const webRevocations: Array<{ provider: string; reason: string }> = [];
    const webCredentials: StorageCredentialProvider = {
      async getAccessToken() {
        return "web-access-token";
      },
      onAuthRevoked(provider, reason) {
        webRevocations.push({ provider, reason });
      },
    };

    const nodeConfig = ServerConfigSchema.parse({
      server: { port: 19876, origin: "http://127.0.0.1:19876" },
      gateway: { url: gateway.url, chainId: 14800 },
      storage: {
        backend: "gdrive",
        config: {
          gdrive: {
            folderId,
            folderName: "Vana",
            apiBaseUrl: drive.baseUrl,
          },
        },
      },
      sync: { enabled: true },
      tunnel: { enabled: false },
      logging: { level: "fatal" },
    });

    const nodeCtx = await createServer(nodeConfig, {
      rootPath: serverDir,
      dataDir: join(serverDir, "data"),
      ownerSignature,
      storageCredentials: desktopCredentials,
    });

    // Register PS Node server account on loopback gateway & set legacy mode
    gateway.registerServer(nodeCtx.serverAccount!.address);
    await declareAccountMode(nodeCtx, "off");

    try {
      // 1. Ingest plaintext user data into PS Node
      const ingestRes = await nodeCtx.app.request("/v1/data/spotify.profile", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${nodeCtx.devToken}`,
        },
        body: JSON.stringify({
          displayName: "Alice",
          favoriteTrack: "secret-playlist-42",
        }),
      });
      expect(ingestRes.status).toBe(201);

      // 2. Run PS Node sync -> encrypts & uploads blob to Google Drive "Vana" folder
      expect(nodeCtx.syncManager).not.toBeNull();
      await nodeCtx.syncManager!.trigger();

      expect(drive.files.size).toBe(1);
      const [uploadedBlob] = [...drive.files.values()];
      expect(uploadedBlob!.parents).toEqual([folderId]);
      expect(uploadedBlob!.name).toBe(encodeURIComponent("spotify.profile/1"));
      // Security: plaintext must NEVER appear in Drive bytes, and /permissions must NEVER be called
      expect(Buffer.from(uploadedBlob!.bytes).toString("utf8")).not.toContain(
        "secret-playlist-42",
      );
      expect(drive.wasPermissionsCalled()).toBe(false);

      // 3. Boot independent PS Lite runtime (simulating app.vana.org) with its own Drive token
      const originalIndexedDb = globalThis.indexedDB;
      globalThis.indexedDB = new IDBFactory();
      try {
        const lite = await createIndexedDbPsLiteRuntime({
          ownerAddress,
          ownerSignature,
          storageCredentials: webCredentials,
          dbName: "e2e-gdrive-ps-lite",
          configDefaults: {
            gateway: {
              url: gateway.url,
              chainId: 14800,
              contracts: nodeConfig.gateway.contracts,
            },
            storage: {
              backend: "gdrive",
              config: {
                gdrive: {
                  folderId,
                  folderName: "Vana",
                  apiBaseUrl: drive.baseUrl,
                },
              },
            },
            sync: { enabled: true },
          },
        });
        gateway.registerServer(lite.identity.account.address);
        await lite.accountModeAuthority.submitEvidence({
          owner: ownerAddress,
          state: "off",
        });

        try {
          // PS Lite pulls from gateway + downloads & decrypts from Google Drive!
          await lite.syncManager!.trigger();
          const statusAfterPull = lite.syncManager!.getStatus();
          const profileEntry = lite.storage.findEntry({
            scope: "spotify.profile",
          });
          expect(profileEntry, JSON.stringify(statusAfterPull)).toBeDefined();
          const readBack = await lite.storage.readEnvelope(
            "spotify.profile",
            profileEntry!.collectedAt,
          );
          expect(readBack.data).toMatchObject({
            displayName: "Alice",
            favoriteTrack: "secret-playlist-42",
          });

          // 4. Revoke Drive token -> upload a second scope from PS Node -> PS Lite must fail download cleanly
          const ingest2 = await nodeCtx.app.request(
            "/v1/data/spotify.top_tracks",
            {
              method: "POST",
              headers: {
                "content-type": "application/json",
                authorization: `Bearer ${nodeCtx.devToken}`,
              },
              body: JSON.stringify({ tracks: ["track-99"] }),
            },
          );
          expect(ingest2.status).toBe(201);
          await nodeCtx.syncManager!.trigger();
          expect(drive.files.size).toBe(2);

          drive.validTokens.delete("web-access-token");
          await lite.syncManager!.trigger();
          expect(
            lite.storage.findEntry({ scope: "spotify.top_tracks" }),
          ).toBeUndefined();
          expect(webRevocations.length).toBeGreaterThanOrEqual(1);
          expect(webRevocations[0]?.provider).toBe("gdrive");
          expect(webRevocations[0]?.reason).toMatch(
            /401|revoked|unauthorized/i,
          );

          // Reconnect token -> PS Lite recovers and downloads the second scope!
          drive.validTokens.add("web-access-token");
          await lite.syncManager!.trigger();
          const topTracksEntry = lite.storage.findEntry({
            scope: "spotify.top_tracks",
          });
          expect(topTracksEntry).toBeDefined();
          const recovered = await lite.storage.readEnvelope(
            "spotify.top_tracks",
            topTracksEntry!.collectedAt,
          );
          expect(recovered.data).toMatchObject({ tracks: ["track-99"] });
        } finally {
          await lite.syncManager?.stop();
          await lite.closeStreamSync?.();
          await lite.accountModeAuthority.close();
        }
      } finally {
        globalThis.indexedDB = originalIndexedDb;
      }

      // 5. Delete both scopes on PS Node -> tombstones on Gateway & removes encrypted blobs from Google Drive
      const deleteOutcome1 =
        await nodeCtx.syncManager!.deleteScope("spotify.profile");
      expect(deleteOutcome1.durable).toBe(true);
      const deleteOutcome2 =
        await nodeCtx.syncManager!.deleteScope("spotify.top_tracks");
      expect(deleteOutcome2.durable).toBe(true);
      // Pending blob deletions drain on the sync pass once tombstones are finalized.
      await nodeCtx.syncManager!.trigger();
      expect(drive.files.size).toBe(0);
    } finally {
      await nodeCtx.cleanup();
    }
  }, 30_000);
});
