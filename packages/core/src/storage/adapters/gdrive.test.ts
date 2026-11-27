import { createHash } from "node:crypto";
import { createServer as createHttpServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AdditionsBudget } from "../../additions/budget.js";
import { ServerConfigSchema } from "../../schemas/server-config.js";
import { createGatewayDeleteDataPort } from "../../sync/delete-data-port.js";
import { createSyncStorageAdapter } from "./factory.js";
import { createGoogleDriveStorageAdapter } from "./gdrive.js";
import {
  StorageAuthRevokedError,
  StorageQuotaExceededError,
  StoredBlobConflictError,
  type StorageCredentialProvider,
} from "./interface.js";

interface StoredDriveFile {
  id: string;
  name: string;
  parents: string[];
  bytes: Uint8Array;
  sha256Checksum: string;
  createdTime: string;
}

interface ResumableSession {
  name: string;
  parents: string[];
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function parseMultipartRelated(
  body: Buffer,
  contentType: string,
): { metadata: { name: string; parents?: string[] }; media: Uint8Array } {
  const match = /boundary=([^\s;]+)/i.exec(contentType);
  if (!match) {
    throw new Error(`Missing multipart boundary in ${contentType}`);
  }
  const delimiter = `--${match[1]}`;
  const raw = body.toString("latin1");
  const parts = raw
    .split(delimiter)
    .slice(1)
    .filter((part) => !part.startsWith("--"));
  if (parts.length < 2) {
    throw new Error(`Expected 2 multipart parts, got ${parts.length}`);
  }
  const extractBody = (part: string): Buffer => {
    const idx = part.indexOf("\r\n\r\n");
    if (idx === -1) throw new Error("Malformed multipart part");
    const content = part.slice(idx + 4);
    const trimmed = content.endsWith("\r\n") ? content.slice(0, -2) : content;
    return Buffer.from(trimmed, "latin1");
  };
  const metadata = JSON.parse(extractBody(parts[0]!).toString("utf8")) as {
    name: string;
    parents?: string[];
  };
  const media = new Uint8Array(extractBody(parts[1]!));
  return { metadata, media };
}

function unescapeDriveQueryString(input: string): string {
  return input.replace(/\\(['\\])/g, "$1");
}

interface FakeDriveServer {
  baseUrl: string;
  files: Map<string, StoredDriveFile>;
  requests: Array<{ method: string; path: string; auth?: string }>;
  validTokens: Set<string>;
  nextError: {
    status: number;
    body: unknown;
    headers?: Record<string, string>;
  } | null;
  duplicateOnUploadForName: string | null;
  /** "empty-first": first list page is empty with a continuation; "loop": every page repeats one token. */
  listPaging: "empty-first" | "loop" | null;
  reset: () => void;
  close: () => Promise<void>;
}

async function startFakeDriveServer(): Promise<FakeDriveServer> {
  const files = new Map<string, StoredDriveFile>();
  const sessions = new Map<string, ResumableSession>();
  const requests: Array<{ method: string; path: string; auth?: string }> = [];
  const validTokens = new Set<string>(["token-v1"]);
  let nextError: FakeDriveServer["nextError"] = null;
  let duplicateOnUploadForName: string | null = null;
  let listPaging: FakeDriveServer["listPaging"] = null;
  let idCounter = 1;
  let clockCounter = 0;

  const nextTimestamp = (): string => {
    clockCounter += 1;
    return new Date(1_700_000_000_000 + clockCounter * 1000).toISOString();
  };

  const server: Server = createHttpServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    }
    const body = Buffer.concat(chunks);
    const method = req.method ?? "GET";
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const auth = req.headers.authorization;
    requests.push({ method, path: `${url.pathname}${url.search}`, auth });

    // Security invariant: never allow /permissions endpoints to be touched.
    if (url.pathname.includes("/permissions")) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          error: { message: "permissions must never be called" },
        }),
      );
      return;
    }

    // Auth check
    if (!auth?.startsWith("Bearer ")) {
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
    const token = auth.slice("Bearer ".length);
    if (!validTokens.has(token)) {
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

    if (nextError) {
      const injected = nextError;
      nextError = null;
      res.writeHead(injected.status, {
        "content-type": "application/json",
        ...injected.headers,
      });
      res.end(JSON.stringify(injected.body));
      return;
    }

    // GET /drive/v3/files (list by folder + exact name)
    if (method === "GET" && url.pathname === "/drive/v3/files") {
      const q = url.searchParams.get("q") ?? "";
      const parentMatch = /'((?:\\.|[^'\\])*)' in parents/.exec(q);
      const nameMatch = /name = '((?:\\.|[^'\\])*)'/.exec(q);
      const parentId = parentMatch
        ? unescapeDriveQueryString(parentMatch[1]!)
        : "";
      const name = nameMatch ? unescapeDriveQueryString(nameMatch[1]!) : "";
      const matched = [...files.values()]
        .filter((f) => f.parents.includes(parentId) && f.name === name)
        .sort(
          (a, b) =>
            a.createdTime.localeCompare(b.createdTime) ||
            a.id.localeCompare(b.id),
        );
      const pageToken = url.searchParams.get("pageToken");
      if (listPaging === "loop") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ files: [], nextPageToken: "same" }));
        return;
      }
      if (listPaging === "empty-first" && !pageToken) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ files: [], nextPageToken: "page-2" }));
        return;
      }
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

    // POST /upload/drive/v3/files (multipart or resumable init)
    if (method === "POST" && url.pathname === "/upload/drive/v3/files") {
      const uploadType = url.searchParams.get("uploadType");
      if (uploadType === "multipart") {
        const parsed = parseMultipartRelated(
          body,
          req.headers["content-type"] ?? "",
        );
        const parents = parsed.metadata.parents ?? [];
        // Optional concurrent-race injector: plant an earlier conflicting or identical winner first.
        if (duplicateOnUploadForName === parsed.metadata.name) {
          duplicateOnUploadForName = null;
          const winnerId = `file-winner-${idCounter++}`;
          const winnerBytes = new TextEncoder().encode("earlier-device-bytes");
          files.set(winnerId, {
            id: winnerId,
            name: parsed.metadata.name,
            parents,
            bytes: winnerBytes,
            sha256Checksum: sha256Hex(winnerBytes),
            createdTime: nextTimestamp(),
          });
        }
        const id = `file-${idCounter++}`;
        const record: StoredDriveFile = {
          id,
          name: parsed.metadata.name,
          parents,
          bytes: parsed.media,
          sha256Checksum: sha256Hex(parsed.media),
          createdTime: nextTimestamp(),
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

      if (uploadType === "resumable") {
        const metadata = JSON.parse(body.toString("utf8")) as {
          name: string;
          parents?: string[];
        };
        const sessionId = `session-${idCounter++}`;
        sessions.set(sessionId, {
          name: metadata.name,
          parents: metadata.parents ?? [],
        });
        const addr = server.address() as AddressInfo;
        res.writeHead(200, {
          location: `http://127.0.0.1:${addr.port}/upload/resumable/${sessionId}`,
        });
        res.end();
        return;
      }
    }

    // PUT /upload/resumable/:sessionId
    if (method === "PUT" && url.pathname.startsWith("/upload/resumable/")) {
      const sessionId = url.pathname.slice("/upload/resumable/".length);
      const session = sessions.get(sessionId);
      if (!session) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Session not found" } }));
        return;
      }
      sessions.delete(sessionId);
      const id = `file-${idCounter++}`;
      const bytes = new Uint8Array(body);
      const record: StoredDriveFile = {
        id,
        name: session.name,
        parents: session.parents,
        bytes,
        sha256Checksum: sha256Hex(bytes),
        createdTime: nextTimestamp(),
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

    // GET /drive/v3/files/:id?alt=media
    if (method === "GET" && url.pathname.startsWith("/drive/v3/files/")) {
      const id = decodeURIComponent(
        url.pathname.slice("/drive/v3/files/".length),
      );
      const record = files.get(id);
      if (!record) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ error: { code: 404, message: "File not found" } }),
        );
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

    // DELETE /drive/v3/files/:id
    if (method === "DELETE" && url.pathname.startsWith("/drive/v3/files/")) {
      const id = decodeURIComponent(
        url.pathname.slice("/drive/v3/files/".length),
      );
      if (!files.has(id)) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(
          JSON.stringify({ error: { code: 404, message: "File not found" } }),
        );
        return;
      }
      files.delete(id);
      res.writeHead(204);
      res.end();
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(
      JSON.stringify({
        error: { message: `Unhandled ${method} ${url.pathname}` },
      }),
    );
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    files,
    requests,
    validTokens,
    get nextError() {
      return nextError;
    },
    set nextError(value) {
      nextError = value;
    },
    get duplicateOnUploadForName() {
      return duplicateOnUploadForName;
    },
    set duplicateOnUploadForName(value) {
      duplicateOnUploadForName = value;
    },
    get listPaging() {
      return listPaging;
    },
    set listPaging(value) {
      listPaging = value;
    },
    reset() {
      listPaging = null;
      files.clear();
      sessions.clear();
      requests.length = 0;
      validTokens.clear();
      validTokens.add("token-v1");
      nextError = null;
      duplicateOnUploadForName = null;
    },
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

describe("createGoogleDriveStorageAdapter (loopback Drive v3 HTTP)", () => {
  let drive: FakeDriveServer;
  const folderId = "vana-folder-123";

  beforeAll(async () => {
    drive = await startFakeDriveServer();
  });

  afterAll(async () => {
    await drive.close();
  });

  beforeEach(() => {
    drive.reset();
  });

  function makeCredentials(tokens: string[] = ["token-v1"]): {
    provider: StorageCredentialProvider;
    calls: Array<{ provider: string; forceRefresh?: boolean }>;
  } {
    const calls: Array<{ provider: string; forceRefresh?: boolean }> = [];
    let index = 0;
    return {
      calls,
      provider: {
        async getAccessToken(req) {
          calls.push({
            provider: req.provider,
            forceRefresh: req.forceRefresh,
          });
          if (req.forceRefresh && index + 1 < tokens.length) {
            index += 1;
          }
          return tokens[index]!;
        },
      },
    };
  }

  it("delete and upload see an object behind an empty first list page", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });
    const key = "paged.stream/key/1";
    const url = adapter.urlForKey(key);
    await adapter.upload(key, new TextEncoder().encode("one"));
    expect(drive.files.size).toBe(1);

    drive.listPaging = "empty-first";
    drive.requests.length = 0;
    expect(await adapter.delete(url)).toBe(true);
    expect(drive.files.size).toBe(0);
    const listPaths = drive.requests
      .filter(
        (r) => r.method === "GET" && r.path.startsWith("/drive/v3/files?"),
      )
      .map((r) => r.path);
    expect(listPaths).toHaveLength(2);
    expect(listPaths[1]).toContain("pageToken=page-2");
  });

  it("list paging throws when a page token repeats", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });
    drive.listPaging = "loop";
    await expect(
      adapter.delete(adapter.urlForKey("loop/key/1")),
    ).rejects.toThrow(/page token/i);
  });

  it("urlForKey is synchronous and exact inverse of upload; private blobs round-trip", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    const key = "instagram.profile/special+name with spaces/1";
    const expectedUrl = adapter.urlForKey(key);
    expect(expectedUrl).toBe(
      `gdrive://${folderId}/instagram.profile/special%2Bname%20with%20spaces/1`,
    );

    const payload = new TextEncoder().encode("encrypted-ciphertext-payload-v1");
    const uploadedUrl = await adapter.upload(key, payload);
    expect(uploadedUrl).toBe(expectedUrl);

    // exists uses metadata-only list (never downloads media body)
    drive.requests.length = 0;
    expect(await adapter.exists(uploadedUrl)).toBe(true);
    expect(drive.requests.some((r) => r.path.includes("alt=media"))).toBe(
      false,
    );

    // download returns exact bytes
    const downloaded = await adapter.download(uploadedUrl);
    expect(downloaded).toEqual(payload);

    // Never makes files public
    expect(drive.requests.some((r) => r.path.includes("/permissions"))).toBe(
      false,
    );

    // delete removes file idempotently
    expect(await adapter.delete(uploadedUrl)).toBe(true);
    expect(await adapter.exists(uploadedUrl)).toBe(false);
    expect(await adapter.delete(uploadedUrl)).toBe(false);
  });

  it("enforces write-once idempotency and throws StoredBlobConflictError on different bytes", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    const key = "spotify.saved_tracks/1";
    const bytesA = new TextEncoder().encode("ciphertext-A");
    const bytesB = new TextEncoder().encode("ciphertext-B-different");

    const url1 = await adapter.upload(key, bytesA);
    // Identical re-upload succeeds idempotently without creating a second file
    const url2 = await adapter.upload(key, bytesA);
    expect(url2).toBe(url1);
    expect(drive.files.size).toBe(1);

    // Different bytes throw StoredBlobConflictError and leave original bytes intact
    await expect(adapter.upload(key, bytesB)).rejects.toBeInstanceOf(
      StoredBlobConflictError,
    );
    expect(drive.files.size).toBe(1);
    expect(await adapter.download(url1)).toEqual(bytesA);
  });

  it("resolves multi-device duplicate upload race deterministically and cleans up loser", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    const key = "oura.sleep/42";
    const encodedName = encodeURIComponent(key);
    drive.duplicateOnUploadForName = encodedName;

    // Adapter uploads "later-device-bytes", while fake server plants an earlier winner "earlier-device-bytes".
    await expect(
      adapter.upload(key, new TextEncoder().encode("later-device-bytes")),
    ).rejects.toBeInstanceOf(StoredBlobConflictError);

    // Losing duplicate was deleted; only the earliest winner survives.
    expect(drive.files.size).toBe(1);
    const survivor = await adapter.download(adapter.urlForKey(key));
    expect(new TextDecoder().decode(survivor)).toBe("earlier-device-bytes");
  });

  it("uses resumable upload for blobs larger than 5 MiB and enforces downloadBounded ByteBudget", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    const large = new Uint8Array(5 * 1024 * 1024 + 64 * 1024);
    for (let i = 0; i < large.length; i += 4096) {
      large[i] = i & 0xff;
    }

    const url = await adapter.upload("large.blob/1", large);
    expect(
      drive.requests.some((r) => r.path.includes("uploadType=resumable")),
    ).toBe(true);

    const downloaded = await adapter.download(url);
    expect(downloaded.byteLength).toBe(large.byteLength);
    expect(sha256Hex(downloaded)).toBe(sha256Hex(large));

    // downloadBounded rejects when ByteBudget is smaller than Content-Length
    const tightBudget = new AdditionsBudget(1024, 5000);
    await expect(adapter.downloadBounded(url, tightBudget)).rejects.toThrow();
  });

  it("refreshes access token once on 401 and throws StorageAuthRevokedError when revoked", async () => {
    drive.validTokens.clear();
    drive.validTokens.add("token-v2");
    const { provider, calls } = makeCredentials(["token-v1", "token-v2"]);
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    const url = await adapter.upload(
      "auth.refresh/1",
      new TextEncoder().encode("ok-after-refresh"),
    );
    expect(await adapter.download(url)).toEqual(
      new TextEncoder().encode("ok-after-refresh"),
    );
    expect(calls.some((c) => c.forceRefresh === true)).toBe(true);

    // Now revoke all tokens -> StorageAuthRevokedError
    drive.validTokens.clear();
    await expect(adapter.download(url)).rejects.toBeInstanceOf(
      StorageAuthRevokedError,
    );
  });

  it("maps 403 storageQuotaExceeded to StorageQuotaExceededError and preserves 429 retry-after", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    drive.nextError = {
      status: 403,
      body: {
        error: {
          code: 403,
          message: "The user's Drive storage quota has been exceeded.",
          errors: [{ reason: "storageQuotaExceeded" }],
        },
      },
    };
    await expect(
      adapter.upload("quota.full/1", new TextEncoder().encode("bytes")),
    ).rejects.toBeInstanceOf(StorageQuotaExceededError);

    drive.nextError = {
      status: 429,
      headers: { "retry-after": "7" },
      body: {
        error: {
          code: 429,
          message: "Rate Limit Exceeded",
          errors: [{ reason: "userRateLimitExceeded" }],
        },
      },
    };
    await expect(
      adapter.exists(adapter.urlForKey("rate.limited/1")),
    ).rejects.toMatchObject({
      status: 429,
      retryAfterMs: 7000,
    });
  });

  it("factory fallbackReadToVana reads pre-switch blobs from Vana Hosted Storage on 404 from Drive", async () => {
    const vanaBlobs = new Map<string, Uint8Array>();
    const vanaServer: Server = createHttpServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      const bytes = vanaBlobs.get(path);
      if (!bytes) {
        res.writeHead(404);
        res.end("not found");
        return;
      }
      res.writeHead(200, { "content-type": "application/octet-stream" });
      res.end(Buffer.from(bytes));
    });
    await new Promise<void>((resolve) =>
      vanaServer.listen(0, "127.0.0.1", resolve),
    );
    const vanaPort = (vanaServer.address() as AddressInfo).port;
    const vanaBaseUrl = `http://127.0.0.1:${vanaPort}`;

    try {
      const owner = "0x1111111111111111111111111111111111111111" as const;
      const preSwitchKey = "legacy.scope/1";
      const preSwitchBytes = new TextEncoder().encode(
        "uploaded-before-gdrive-switch",
      );
      vanaBlobs.set(
        `/v1/chains/14800/blobs/${owner.toLowerCase()}/legacy.scope/1`,
        preSwitchBytes,
      );

      const config = ServerConfigSchema.parse({
        storage: {
          backend: "gdrive",
          config: {
            vana: { apiUrl: vanaBaseUrl },
            gdrive: { folderId, folderName: "Vana", apiBaseUrl: drive.baseUrl },
          },
        },
        gateway: { chainId: 14800 },
      });

      const { provider } = makeCredentials();
      const adapter = createSyncStorageAdapter({
        config,
        serverOwner: owner,
        serverAccount: {
          address: owner,
          signMessage: async () => ("0x" + "11".repeat(65)) as `0x${string}`,
        },
        reads: "public",
        storageCredentials: provider,
        fallbackReadToVana: true,
      });

      // Missing in Drive -> transparently read from Vana Hosted Storage!
      const fallbackRead = await adapter.download(
        adapter.urlForKey(preSwitchKey),
      );
      expect(fallbackRead).toEqual(preSwitchBytes);

      // New uploads go to Google Drive, not Vana Storage (scoped by chainId).
      const newBytes = new TextEncoder().encode("new-gdrive-blob");
      const newUrl = await adapter.upload("new.scope/1", newBytes);
      expect(newUrl).toBe(`gdrive://${folderId}/chains/14800/new.scope/1`);
      expect(drive.files.size).toBe(1);
    } finally {
      await new Promise<void>((resolve, reject) =>
        vanaServer.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("downloadBounded classifies 403 insufficientPermissions and userRateLimitExceeded like download()", async () => {
    const revokedEvents: string[] = [];
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: {
        ...provider,
        onAuthRevoked: (_p, reason) => revokedEvents.push(reason ?? "revoked"),
      },
      apiBaseUrl: drive.baseUrl,
    });

    const url = await adapter.upload(
      "spotify.profile/1",
      new TextEncoder().encode("cached-id-blob"),
    );

    // Cached fileId bypasses listMatchingFiles and hits media GET directly.
    drive.nextError = {
      status: 403,
      body: {
        error: {
          code: 403,
          message: "Insufficient Permission",
          errors: [{ reason: "insufficientPermissions" }],
        },
      },
    };
    await expect(
      adapter.downloadBounded(url, new AdditionsBudget(1024, 5000)),
    ).rejects.toThrow(StorageAuthRevokedError);
    expect(revokedEvents).toHaveLength(1);

    drive.nextError = {
      status: 403,
      body: {
        error: {
          code: 403,
          message: "User rate limit exceeded",
          errors: [{ reason: "userRateLimitExceeded" }],
        },
      },
    };
    let rateErr: unknown;
    try {
      await adapter.downloadBounded(url, new AdditionsBudget(1024, 5000));
    } catch (err) {
      rateErr = err;
    }
    expect((rateErr as { status?: number })?.status).toBe(429);
  });

  it("namespaces Drive blobs by chainId so independent networks never collide", async () => {
    const { provider } = makeCredentials();
    const moksha = createGoogleDriveStorageAdapter({
      folderId,
      chainId: 14800,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });
    const mainnet = createGoogleDriveStorageAdapter({
      folderId,
      chainId: 1480,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    const key = "spotify.profile/1";
    const mokshaBytes = new TextEncoder().encode("moksha-ciphertext");
    const mainnetBytes = new TextEncoder().encode("mainnet-ciphertext");

    const mokshaUrl = await moksha.upload(key, mokshaBytes);
    const mainnetUrl = await mainnet.upload(key, mainnetBytes);
    expect(mokshaUrl).toBe(`gdrive://${folderId}/chains/14800/${key}`);
    expect(mainnetUrl).toBe(`gdrive://${folderId}/chains/1480/${key}`);
    expect(drive.files.size).toBe(2);

    // Deleting on Moksha leaves Mainnet untouched.
    expect(await moksha.delete(mokshaUrl)).toBe(true);
    expect(await moksha.exists(mokshaUrl)).toBe(false);
    expect(await mainnet.exists(mainnetUrl)).toBe(true);
    expect(await mainnet.download(mainnetUrl)).toEqual(mainnetBytes);
  });

  it("fallbackReadToVana deletes pre-switch Vana blobs and propagates Vana delete failures", async () => {
    const owner = "0x1111111111111111111111111111111111111111" as const;
    const preSwitchKey = "pre.switch/1";
    const vanaBlobs = new Map<string, Uint8Array>([
      [
        `/v1/chains/14800/blobs/${owner}/${encodeURIComponent("pre.switch")}/1`,
        new TextEncoder().encode("legacy-vana-ciphertext"),
      ],
    ]);
    let failNextDelete = false;
    const vanaServer = createHttpServer((req, res) => {
      const path = new URL(req.url ?? "/", "http://127.0.0.1").pathname;
      if (req.method === "DELETE") {
        if (failNextDelete) {
          failNextDelete = false;
          res.writeHead(500);
          res.end("vana storage error");
          return;
        }
        if (vanaBlobs.delete(path)) {
          res.writeHead(204);
          res.end();
          return;
        }
        res.writeHead(404);
        res.end("not found");
        return;
      }
      res.writeHead(404);
      res.end("not found");
    });
    await new Promise<void>((resolve) =>
      vanaServer.listen(0, "127.0.0.1", resolve),
    );
    const vanaPort = (vanaServer.address() as AddressInfo).port;

    try {
      const config = ServerConfigSchema.parse({
        storage: {
          backend: "gdrive",
          config: {
            vana: { apiUrl: `http://127.0.0.1:${vanaPort}` },
            gdrive: {
              folderId,
              folderName: "Vana",
              apiBaseUrl: drive.baseUrl,
            },
          },
        },
        gateway: { chainId: 14800 },
      });
      const { provider } = makeCredentials();
      const adapter = createSyncStorageAdapter({
        config,
        serverOwner: owner,
        serverAccount: {
          address: owner,
          signMessage: async () => ("0x" + "11".repeat(65)) as `0x${string}`,
        },
        reads: "signed",
        storageCredentials: provider,
        fallbackReadToVana: true,
      });

      // Transient Vana delete failure must reject rather than acknowledging missing.
      failNextDelete = true;
      await expect(
        adapter.delete(adapter.urlForKey(preSwitchKey)),
      ).rejects.toThrow();
      expect(vanaBlobs.size).toBe(1);

      // Retrying succeeds and removes the pre-switch Vana blob.
      expect(await adapter.delete(adapter.urlForKey(preSwitchKey))).toBe(true);
      expect(vanaBlobs.size).toBe(0);

      // Deleting again when absent in both Drive and Vana returns false.
      expect(await adapter.delete(adapter.urlForKey(preSwitchKey))).toBe(false);
    } finally {
      await new Promise<void>((resolve, reject) =>
        vanaServer.close((err) => (err ? reject(err) : resolve())),
      );
    }
  });

  it("createGatewayDeleteDataPort delegates deleteBlobVersions to gdrive storageAdapter", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });

    await adapter.upload("spotify.profile/1", new TextEncoder().encode("v1"));
    expect(drive.files.size).toBe(1);

    const owner = "0x1111111111111111111111111111111111111111" as const;
    const deletePort = createGatewayDeleteDataPort({
      gatewayUrl: "http://127.0.0.1:1",
      dataPointFeed: {
        getDataPoint: async () => null,
        listDataPointsByOwner: async () => [],
      },
      serverOwner: owner,
      signer: {
        signAddData: async () => ("0x" + "22".repeat(65)) as `0x${string}`,
      },
      storage: {
        endpoint: "http://127.0.0.1:1",
        chainId: 14800,
        signMessage: async () => ("0x" + "33".repeat(65)) as `0x${string}`,
      },
      storageAdapter: adapter,
    });

    const outcome = await deletePort.deleteBlobVersions("spotify.profile", [
      "1",
      "2",
    ]);
    expect(outcome).toEqual({
      deleted: ["1"],
      missing: ["2"],
      failed: [],
    });
    expect(drive.files.size).toBe(0);
  });

  it("a repeated upload finds an existing object behind an empty first list page", async () => {
    const { provider } = makeCredentials();
    const adapter = createGoogleDriveStorageAdapter({
      folderId,
      credentials: provider,
      apiBaseUrl: drive.baseUrl,
    });
    const key = "paged.repeat/key/1";
    const bytes = new TextEncoder().encode("same synthetic content");
    await adapter.upload(key, bytes);
    const initialIds = [...drive.files.keys()];
    expect(initialIds).toHaveLength(1);

    drive.listPaging = "empty-first";
    drive.requests.length = 0;
    await adapter.upload(key, bytes);

    expect([...drive.files.keys()]).toEqual(initialIds);
    expect(
      drive.requests.some(
        (r) => r.method === "GET" && r.path.includes("pageToken=page-2"),
      ),
    ).toBe(true);
    expect(
      drive.requests.some(
        (r) =>
          r.method === "POST" && r.path.startsWith("/upload/drive/v3/files"),
      ),
    ).toBe(false);
  });
});
