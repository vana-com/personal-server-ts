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
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { dataRoutes } from "./data.js";
import { SCOPE_IMPORT_CHUNK_BYTES } from "./chunked-scope-import.js";

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
    index = createIndexManager(initializeDatabase(join(root, "index.db")));
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
        owner,
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
      "refuses begin, chunk and finalize with %s and stages nothing, even for a session opened before the switch",
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

        await expectNothingTouched(stagedBeforeSwitch);

        // Nothing was staged: with the switch off the refused chunk is still
        // missing, and the session completes only once the chunk is re-sent.
        switchedOn = false;
        expect((await finalize(importId)).status).not.toBe(201);
        expect(index.countByScope(scope)).toBe(0);
        expect((await putChunk(importId)).status).toBe(200);
        expect((await finalize(importId)).status).toBe(201);
        expect(index.countByScope(scope)).toBe(1);
      },
    );
  });
});
