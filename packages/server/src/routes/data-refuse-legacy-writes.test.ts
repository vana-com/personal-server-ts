/**
 * Once an account has moved to stream sync, every legacy write that does not
 * declare a stream-sync client is refused with `update_required` (426), on
 * every legacy write route of the data surface. A switched-off server and a
 * declaring client are never refused.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pino } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { STREAM_SYNC_CLIENT_HEADER } from "@opendatalabs/personal-server-ts-core/api";
import type { ScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { dataRoutes } from "./data.js";
import { SCOPE_IMPORT_CHUNK_BYTES } from "./chunked-scope-import.js";
import { createLegacyWriteSeal } from "@opendatalabs/personal-server-ts-core/storage/legacy-write-seal";
import { openLegacyWriteSealForTests } from "@opendatalabs/personal-server-ts-core/test-utils/legacy-write-seal";

const owner = "0x1111111111111111111111111111111111111111";
const scope = "github.events";
const operation = "a".repeat(64);
const bearer = { Authorization: "Bearer refuse-legacy-test" };

interface LegacyWriteRoute {
  name: string;
  method: "POST" | "PUT";
  path: string;
  body: unknown;
}

/** Every route an old client writes a legacy version through. */
const LEGACY_WRITE_ROUTES: LegacyWriteRoute[] = [
  { name: "POST scope", method: "POST", path: `/${scope}`, body: { v: 1 } },
  {
    name: "PUT owner import",
    method: "PUT",
    path: `/${scope}/imports/${operation}`,
    body: { v: 1 },
  },
  {
    name: "POST chunked import begin",
    method: "POST",
    path: `/${scope}/imports`,
    body: {},
  },
  {
    name: "PUT chunked import chunk",
    method: "PUT",
    path: `/${scope}/imports/some-id/chunks/0`,
    body: {},
  },
  {
    name: "POST chunked import finalize",
    method: "POST",
    path: `/${scope}/imports/some-id/finalize`,
    body: {},
  },
  {
    name: "POST upload begin",
    method: "POST",
    path: `/${scope}/uploads`,
    body: {},
  },
  {
    name: "PUT upload batch",
    method: "PUT",
    path: `/${scope}/uploads/some-id/batches/0`,
    body: {},
  },
  {
    name: "POST upload commit",
    method: "POST",
    path: `/${scope}/uploads/some-id/commit`,
    body: {},
  },
];

describe("refuse legacy writes after the stream-sync switch", () => {
  let root: string;
  let index: ReturnType<typeof createIndexManager>;
  let switchedOn = false;
  let app: ReturnType<typeof dataRoutes>;
  let gatewayTouched: string[] = [];
  let writeHooks: string[] = [];

  beforeEach(async () => {
    switchedOn = false;
    gatewayTouched = [];
    writeHooks = [];
    root = await mkdtemp(join(tmpdir(), "refuse-legacy-"));
    index = createIndexManager(initializeDatabase(join(root, "index.db")), {
      legacyWriteSeal: openLegacyWriteSealForTests(),
    });
    app = dataRoutes({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
      logger: pino({ level: "silent" }),
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      devToken: "refuse-legacy-test",
      gateway: new Proxy(
        {},
        {
          get: (_target, key) => {
            gatewayTouched.push(String(key));
            return undefined;
          },
        },
      ) as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      onDataWritten: (event) => {
        writeHooks.push(`${event.scope}@${event.collectedAt}`);
      },
      syncManager: {
        notifyNewData: () => {
          writeHooks.push("notifyNewData");
        },
      },
      // A test stand-in that follows the flag in both directions (the real
      // mode latches once switched).
      accountStorageMode: {
        read: () => (switchedOn ? "switched" : "unswitched"),
      },
    });
  });

  afterEach(async () => {
    index.close();
    await rm(root, { recursive: true, force: true });
  });

  function send(route: LegacyWriteRoute, headers: Record<string, string> = {}) {
    return app.request(route.path, {
      method: route.method,
      headers: {
        ...bearer,
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify(route.body),
    });
  }

  describe.each(LEGACY_WRITE_ROUTES)("$name", (route) => {
    it("is refused with update_required when the switch is on", async () => {
      switchedOn = true;
      const response = await send(route);
      expect(response.status).toBe(426);
      const body = await response.json();
      expect(body.errorCode).toBe("update_required");
      expect(body.error.errorCode).toBe("update_required");
      expect(body.message).toMatch(/Update the Vana app/);
      expect(response.headers.get("upgrade")).toBe("vana-stream-sync");
    });

    it("is not refused when the switch is off", async () => {
      const response = await send(route);
      expect(response.status).not.toBe(426);
    });

    it("is refused for a client that declares stream sync: a header is no exemption", async () => {
      switchedOn = true;
      const response = await send(route, { [STREAM_SYNC_CLIENT_HEADER]: "1" });
      expect(response.status).toBe(426);
    });
  });

  it("stores nothing from a refused write", async () => {
    switchedOn = true;
    await send(LEGACY_WRITE_ROUTES[0]);
    await send(LEGACY_WRITE_ROUTES[1]);
    expect(index.countByScope(scope)).toBe(0);
  });

  it("refuses a declaring client's writes and stores nothing when the switch is on", async () => {
    switchedOn = true;
    const post = await send(LEGACY_WRITE_ROUTES[0], {
      [STREAM_SYNC_CLIENT_HEADER]: "1",
    });
    expect(post.status).toBe(426);
    const put = await send(LEGACY_WRITE_ROUTES[1], {
      [STREAM_SYNC_CLIENT_HEADER]: "1",
    });
    expect(put.status).toBe(426);
    expect(index.countByScope(scope)).toBe(0);
  });

  it("answers a refused write before reading an oversized body", async () => {
    switchedOn = true;
    const response = await app.request(`/${scope}`, {
      method: "POST",
      headers: {
        ...bearer,
        "Content-Type": "application/json",
        "Content-Length": String(200 * 1024 * 1024),
      },
      body: "{}",
    });
    expect(response.status).toBe(426);
  });

  it("leaves reads and deletes alone", async () => {
    switchedOn = true;
    const read = await app.request(`/${scope}`, { headers: bearer });
    expect(read.status).not.toBe(426);
    const del = await app.request(`/${scope}`, {
      method: "DELETE",
      headers: bearer,
    });
    expect(del.status).not.toBe(426);
  });

  it("refuses an owner write that only carries a forged write signature", async () => {
    switchedOn = true;
    const response = await app.request(`/${scope}`, {
      method: "POST",
      headers: {
        ...bearer,
        "X-Vana-Write-Signature": "forged",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ v: 1 }),
    });
    expect(response.status).toBe(426);
    expect(index.countByScope(scope)).toBe(0);
  });

  /** Every file under the data directory, with its size: staging and storage. */
  async function dataTree(): Promise<string[]> {
    const out: string[] = [];
    const walk = async (dir: string): Promise<void> => {
      let names: string[];
      try {
        names = await readdir(dir);
      } catch {
        return;
      }
      for (const name of names.sort()) {
        const full = join(dir, name);
        const info = await stat(full);
        if (info.isDirectory()) await walk(full);
        else out.push(`${full.slice(root.length)}:${info.size}`);
      }
    };
    await walk(join(root, "data"));
    return out;
  }

  async function expectNothingTouched(before: string[]): Promise<void> {
    expect(await dataTree()).toEqual(before);
    expect(index.countByScope(scope)).toBe(0);
    expect(gatewayTouched).toEqual([]);
    expect(writeHooks).toEqual([]);
  }

  const forged = { "X-Vana-Write-Signature": "forged" };

  describe("a forged write signature and path aliases, on every write route", () => {
    const aliases = [
      { name: "forged signature", headers: forged, suffix: "" },
      { name: "trailing slash", headers: {}, suffix: "/" },
      { name: "doubled slash", headers: {}, suffix: "//" },
      {
        name: "trailing slash and forged signature",
        headers: forged,
        suffix: "/",
      },
    ];
    describe.each(LEGACY_WRITE_ROUTES)("$name", (route) => {
      it.each(aliases)(
        "is refused with $name and writes nothing",
        async ({ headers, suffix }) => {
          switchedOn = true;
          const before = await dataTree();
          const response = await app.request(route.path + suffix, {
            method: route.method,
            headers: {
              ...bearer,
              "Content-Type": "application/json",
              ...headers,
            },
            body: JSON.stringify(route.body),
          });
          // The chunked-import handlers are mounted only on the canonical
          // path; an alias of them is an unknown route (404), never a write.
          const chunkedAlias =
            route.path.includes("/imports") &&
            !route.path.endsWith(operation) &&
            suffix !== "";
          expect(chunkedAlias ? [404, 426] : [426]).toContain(response.status);
          await expectNothingTouched(before);
        },
      );
    });

    it("commits the aliased durable import when the switch is off", async () => {
      const response = await app.request(`/${scope}/imports/${operation}/`, {
        method: "PUT",
        headers: { ...bearer, "Content-Type": "application/json", ...forged },
        body: JSON.stringify({ v: 1 }),
      });
      expect(response.status).toBe(201);
      expect(index.countByScope(scope)).toBe(1);
    });
  });

  describe("a real chunked import", () => {
    const chunk = new Uint8Array(SCOPE_IMPORT_CHUNK_BYTES).fill(0x20);
    chunk.set(new TextEncoder().encode('{"data":[]}'));
    const chunkSha = createHash("sha256").update(chunk).digest("hex");
    const importsPath = `/${scope}/imports`;

    const begin = (headers: Record<string, string> = {}) =>
      app.request(importsPath, {
        method: "POST",
        headers: { ...bearer, "Content-Type": "application/json", ...headers },
        body: JSON.stringify({
          totalBytes: chunk.byteLength,
          totalChunks: 1,
          sha256: chunkSha,
        }),
      });
    const putChunk = (id: string, headers: Record<string, string> = {}) =>
      app.request(`${importsPath}/${id}/chunks/0`, {
        method: "PUT",
        headers: {
          ...bearer,
          "Content-Type": "application/octet-stream",
          "x-chunk-sha256": chunkSha,
          ...headers,
        },
        body: chunk,
      });
    const finalize = (id: string, headers: Record<string, string> = {}) =>
      app.request(`${importsPath}/${id}/finalize`, {
        method: "POST",
        headers: { ...bearer, ...headers },
      });

    it("completes with enforcement off", async () => {
      const opened = await begin();
      expect(opened.status).toBe(201);
      const { importId } = await opened.json();
      expect((await putChunk(importId)).status).toBe(200);
      expect((await finalize(importId)).status).toBe(201);
      expect(index.countByScope(scope)).toBe(1);
    });

    it("refuses a declaring client's import with enforcement on", async () => {
      switchedOn = true;
      const declared = { [STREAM_SYNC_CLIENT_HEADER]: "1" };
      const opened = await begin(declared);
      expect(opened.status).toBe(426);
      expect(index.countByScope(scope)).toBe(0);
    });

    it.each([
      ["no signature", {}],
      ["a forged signature", forged],
    ])(
      "refuses begin, chunk and finalize with %s and leaves nothing, even for a session opened before the switch",
      async (_name, extra) => {
        // The session opens while the switch is off, as an old client's would.
        const opened = await begin();
        expect(opened.status).toBe(201);
        const { importId } = await opened.json();
        gatewayTouched = [];
        writeHooks = [];
        const stagedBeforeSwitch = await dataTree();

        switchedOn = true;
        const chunkRefused = await putChunk(importId, extra);
        expect(chunkRefused.status).toBe(426);
        const finalizeRefused = await finalize(importId, extra);
        expect(finalizeRefused.status).toBe(426);
        const beginRefused = await begin(extra);
        expect(beginRefused.status).toBe(426);

        // The refused session can never finish (the switch is one-way), so
        // its chunks and metadata are removed with the refusal.
        expect(stagedBeforeSwitch).not.toEqual([]);
        await expectNothingTouched([]);
        switchedOn = false;
        expect((await finalize(importId)).status).not.toBe(201);
        expect(index.countByScope(scope)).toBe(0);
      },
    );
  });
  // ADMISSION_ONLY_GATE: Node chunked finalize
  describe("a chunked import whose finalize is parked while the account switches", () => {
    it("refuses at publication with 426 and leaves nothing staged, published or indexed", async () => {
      const state = { switched: false, onResolve: () => {} };
      const parkedMode = {
        read: () => (state.switched ? "switched" : "unswitched"),
      } as const;
      // The storage seal answers for the same account the routes do.
      const parkedIndex = createIndexManager(initializeDatabase(":memory:"), {
        legacyWriteSeal: createLegacyWriteSeal({ mode: parkedMode, owner }),
      });
      const chunk = new Uint8Array(SCOPE_IMPORT_CHUNK_BYTES).fill(0x20);
      chunk.set(new TextEncoder().encode('{"data":[]}'));
      const chunkSha = createHash("sha256").update(chunk).digest("hex");
      const parkedApp = dataRoutes({
        indexManager: parkedIndex,
        hierarchyOptions: { dataDir: join(root, "data") },
        logger: pino({ level: "silent" }),
        serverOrigin: "http://localhost:8080",
        serverOwner: owner,
        devToken: "refuse-legacy-test",
        gateway: {} as GatewayClient,
        accessLogWriter: { write: async () => undefined },
        // Finalize asks for the scope's deletion marker after it has admitted
        // the request and assembled the chunks, just before it publishes.
        scopeDeletions: {
          resolve: async () => {
            state.onResolve();
            return { deleted: false, version: null };
          },
        } as unknown as ScopeDeletionTracker,
        accountStorageMode: parkedMode,
      });
      const base = `/${scope}/imports`;
      const opened = await parkedApp.request(base, {
        method: "POST",
        headers: { ...bearer, "Content-Type": "application/json" },
        body: JSON.stringify({
          totalBytes: chunk.byteLength,
          totalChunks: 1,
          sha256: chunkSha,
        }),
      });
      const { importId } = await opened.json();
      expect(
        (
          await parkedApp.request(`${base}/${importId}/chunks/0`, {
            method: "PUT",
            headers: {
              ...bearer,
              "Content-Type": "application/octet-stream",
              "x-chunk-sha256": chunkSha,
            },
            body: chunk,
          })
        ).status,
      ).toBe(200);

      // The account switches while finalize is between admission and publish.
      state.onResolve = () => {
        state.switched = true;
      };
      const response = await parkedApp.request(`${base}/${importId}/finalize`, {
        method: "POST",
        headers: bearer,
      });
      expect(response.status).toBe(426);
      expect((await response.json()).errorCode).toBe("update_required");
      expect(parkedIndex.countByScope(scope)).toBe(0);
      parkedIndex.close();
      const tree = await dataTree();
      expect(tree.filter((file) => file.includes(".pending."))).toEqual([]);
      expect(tree.filter((file) => file.includes(`/${scope}/`))).toEqual([]);
      // CHUNK_REFUSAL_KEEPS_CHUNKS: the session's chunks and metadata go too.
      expect(tree.filter((file) => file.includes(".scope-imports"))).toEqual(
        [],
      );
    });
  });

  // RECOVER_AFTER_SWITCH: DELETE reaches storage.deleteScope, which first
  // recovers prepared imports; on a switched account that must drop them.
  it("does not publish a prepared import when a DELETE runs after the switch", async () => {
    const state = { switched: false };
    const mode = {
      read: () => (state.switched ? "switched" : "unswitched"),
    } as const;
    const db = initializeDatabase(join(root, "recover.db"));
    const recoverIndex = createIndexManager(db, {
      legacyWriteSeal: createLegacyWriteSeal({ mode, owner }),
    });
    const dataDir = join(root, "recover-data");
    const prepared = {
      version: "1.0",
      scope: "notes.documents",
      collectedAt: "2026-11-09T00:00:00Z",
      data: { value: "prepared" },
    };
    const preparedPath = "notes/documents/2026-11-09T00-00-00Z.json";
    const recoverApp = dataRoutes({
      indexManager: recoverIndex,
      hierarchyOptions: { dataDir },
      logger: pino({ level: "silent" }),
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      devToken: "refuse-legacy-test",
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      accountStorageMode: mode,
    });
    // An import prepared (acknowledged, not yet published) while the account
    // was still unswitched; the switch lands before it publishes.
    db.prepare(
      `INSERT INTO owner_import_operations (authority, owner, scope, operation, body_sha256, state, collected_at, path, envelope_bytes, metadata_json)
       VALUES ('local', 'owner', @scope, @operation, @sha, 'prepared', @collectedAt, @path, @bytes, '{}')`,
    ).run({
      scope: prepared.scope,
      operation: "p".repeat(64),
      sha: "p".repeat(64),
      collectedAt: prepared.collectedAt,
      path: preparedPath,
      bytes: Buffer.from(JSON.stringify(prepared)),
    });
    state.switched = true;
    const deleted = await recoverApp.request(`/${scope}`, {
      method: "DELETE",
      headers: bearer,
    });
    expect(deleted.status).not.toBe(426);
    expect(recoverIndex.countByScope(prepared.scope)).toBe(0);
    await expect(readdir(join(dataDir, "notes"))).rejects.toThrow();
    expect(
      db.prepare("SELECT COUNT(*) AS n FROM owner_import_operations").get(),
    ).toEqual({ n: 0 });
    recoverIndex.close();
  });

  // CHUNK_REFUSAL_KEEPS_CHUNKS: a session that can never finish is removed at
  // each refusal point, not left to expire.
  describe("a refused chunked import leaves no chunks or metadata", () => {
    const chunk = new Uint8Array(SCOPE_IMPORT_CHUNK_BYTES).fill(0x20);
    chunk.set(new TextEncoder().encode('{"data":[]}'));
    const chunkSha = createHash("sha256").update(chunk).digest("hex");
    const base = `/${scope}/imports`;

    async function beginAndUploadOneChunk(): Promise<string> {
      const opened = await app.request(base, {
        method: "POST",
        headers: { ...bearer, "Content-Type": "application/json" },
        body: JSON.stringify({
          totalBytes: chunk.byteLength * 2,
          totalChunks: 2,
          sha256: chunkSha,
        }),
      });
      expect(opened.status).toBeLessThan(300);
      const { importId } = await opened.json();
      const put = await app.request(`${base}/${importId}/chunks/0`, {
        method: "PUT",
        headers: {
          ...bearer,
          "Content-Type": "application/octet-stream",
          "x-chunk-sha256": chunkSha,
        },
        body: chunk,
      });
      expect(put.status).toBe(200);
      expect(
        (await dataTree()).filter((file) => file.includes(importId)),
      ).not.toEqual([]);
      return importId as string;
    }
    const sessionFiles = async (importId: string) =>
      (await dataTree()).filter((file) => file.includes(importId));

    it("removes the session when the next chunk arrives after the switch", async () => {
      const importId = await beginAndUploadOneChunk();
      switchedOn = true;
      const response = await app.request(`${base}/${importId}/chunks/1`, {
        method: "PUT",
        headers: {
          ...bearer,
          "Content-Type": "application/octet-stream",
          "x-chunk-sha256": chunkSha,
        },
        body: chunk,
      });
      expect(response.status).toBe(426);
      expect(await sessionFiles(importId)).toEqual([]);
    });

    it("removes the session when finalize arrives after the switch", async () => {
      const importId = await beginAndUploadOneChunk();
      switchedOn = true;
      const response = await app.request(`${base}/${importId}/finalize`, {
        method: "POST",
        headers: bearer,
      });
      expect(response.status).toBe(426);
      expect(await sessionFiles(importId)).toEqual([]);
    });
  });
});
