/**
 * Real HTTP + real on-disk SQLite proof for the blob-bytes storage slice.
 *
 * `pdpp-blobs.test.ts` dispatches through `app.request(...)`, an in-process
 * Hono call over `:memory:` SQLite -- it never touches a socket or the
 * filesystem. This file closes that gap for the acceptance bar this slice
 * was built against: a real file-backed SQLite database, a real listening
 * HTTP server (the same `listenHttpServer` production uses), a real ingest
 * write, and a real `fetch()` GET that returns the exact bytes and headers.
 * It also proves durability across closing and reopening BOTH the database
 * and the route/server, not just the in-process store.
 *
 * Deliberately narrow: this is the transport + persistence proof for the
 * store/route wiring added in this slice, not a copy of every authorization
 * branch already covered by `pdpp-blobs.test.ts`.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { createHash } from "node:crypto";
import { Hono } from "hono";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";
import { listenHttpServer, type NodeServer } from "../listen.js";

const declarations = createStreamDeclarationRegistry([
  {
    name: "media",
    semantics: "append_only",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

let tempDir: string;
let dbPath: string;
let server: NodeServer | undefined;
let baseUrl: string;

/**
 * Boots the blob route against a REAL on-disk SQLite file and binds a real
 * loopback socket, mirroring how `records-bootstrap.ts` wires
 * `readBlobBytes` to `store.getBlobBytes` at real boot.
 */
async function bootAndListen(): Promise<void> {
  const db = new Database(dbPath);
  const store = createTestBoundRecordStore(db);
  const app = new Hono();
  app.route(
    "/v1/blobs",
    pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": {
          active: true,
          tokenKind: "owner",
          subjectId: "sub_1",
          instanceIds: ["inst_1"],
        },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      readBlobBytes: async (blobId) => store.getBlobBytes(blobId),
    }),
  );

  let bound: AddressInfo | undefined;
  server = await listenHttpServer({
    fetch: app.fetch,
    port: 0,
    hostname: "127.0.0.1",
    onListening: (info) => {
      bound = info;
    },
  });
  baseUrl = `http://127.0.0.1:${bound!.port}`;
}

async function stopServer(): Promise<void> {
  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-blob-live-"));
  dbPath = join(tempDir, "pdpp.db");
});

afterEach(async () => {
  await stopServer();
  await rm(tempDir, { recursive: true, force: true });
});

describe("PDPP blob GET over a real listening HTTP server and real on-disk SQLite", () => {
  it("serves exact bytes and headers for a real ingested blob over a real socket", async () => {
    // Direct write to the on-disk database, independent of the route's own
    // connection, then the actual read happens over a real HTTP GET.
    const seedDb = new Database(dbPath);
    const seedStore = createTestBoundRecordStore(seedDb);
    const payload = new Uint8Array([1, 2, 3, 4, 5, 250, 251]);
    const meta = seedStore.storeBlobBytes(payload, "application/octet-stream");
    seedStore.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: meta.blobId } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    seedStore.close();

    await bootAndListen();

    const res = await fetch(`${baseUrl}/v1/blobs/${meta.blobId}`, {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expect(res.headers.get("content-length")).toBe(String(payload.byteLength));
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    const returned = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(returned)).toEqual(Array.from(payload));
  });

  it("denies an unauthenticated real HTTP GET for a genuinely stored blob", async () => {
    const seedDb = new Database(dbPath);
    const seedStore = createTestBoundRecordStore(seedDb);
    const meta = seedStore.storeBlobBytes(
      new Uint8Array([1, 2, 3]),
      "image/jpeg",
    );
    seedStore.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: meta.blobId } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    seedStore.close();

    await bootAndListen();

    const res = await fetch(`${baseUrl}/v1/blobs/${meta.blobId}`);
    expect(res.status).toBe(401);
  });

  it("persists and re-serves bytes correctly after closing and reopening BOTH the database and the HTTP route/server", async () => {
    const payload = new Uint8Array([9, 9, 9, 8, 7, 6, 5]);
    let blobId = "";

    // Round 1: ingest, serve over the wire, then fully tear down (close the
    // route's server AND its underlying SQLite connection).
    {
      const db = new Database(dbPath);
      const store = createTestBoundRecordStore(db);
      const meta = store.storeBlobBytes(payload, "application/pdf");
      blobId = meta.blobId;
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: blobId } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );

      const app = new Hono();
      app.route(
        "/v1/blobs",
        pdppBlobsRoutes({
          store,
          auth: createFixtureAuthorizationService({
            "owner-tok": {
              active: true,
              tokenKind: "owner",
              subjectId: "sub_1",
              instanceIds: ["inst_1"],
            },
          }),
          declarations,
          instancesForSubject: () => ["inst_1"],
          readBlobBytes: async (id) => store.getBlobBytes(id),
        }),
      );
      let bound: AddressInfo | undefined;
      const s = await listenHttpServer({
        fetch: app.fetch,
        port: 0,
        hostname: "127.0.0.1",
        onListening: (info) => {
          bound = info;
        },
      });
      const url = `http://127.0.0.1:${bound!.port}`;

      const res = await fetch(`${url}/v1/blobs/${blobId}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(200);
      const returned = new Uint8Array(await res.arrayBuffer());
      expect(Array.from(returned)).toEqual(Array.from(payload));

      await new Promise<void>((resolve) => s.close(() => resolve()));
      store.close(); // closes the underlying `db` handle too
    }

    // Round 2: brand-new SQLite connection to the same file, brand-new Hono
    // app, brand-new socket -- proves the bytes actually round-tripped to
    // disk rather than living only in the first process's in-memory cache.
    {
      const db = new Database(dbPath);
      const store = createTestBoundRecordStore(db);
      const app = new Hono();
      app.route(
        "/v1/blobs",
        pdppBlobsRoutes({
          store,
          auth: createFixtureAuthorizationService({
            "owner-tok": {
              active: true,
              tokenKind: "owner",
              subjectId: "sub_1",
              instanceIds: ["inst_1"],
            },
          }),
          declarations,
          instancesForSubject: () => ["inst_1"],
          readBlobBytes: async (id) => store.getBlobBytes(id),
        }),
      );
      let bound: AddressInfo | undefined;
      server = await listenHttpServer({
        fetch: app.fetch,
        port: 0,
        hostname: "127.0.0.1",
        onListening: (info) => {
          bound = info;
        },
      });
      baseUrl = `http://127.0.0.1:${bound!.port}`;

      const res = await fetch(`${baseUrl}/v1/blobs/${blobId}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("content-length")).toBe(
        String(payload.byteLength),
      );
      const returned = new Uint8Array(await res.arrayBuffer());
      expect(Array.from(returned)).toEqual(Array.from(payload));
      expect(createHash("sha256").update(returned).digest("hex")).toBe(
        blobId.slice("sha256:".length),
      );
    }
  });
});
