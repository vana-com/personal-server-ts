/**
 * Once an account has moved to stream sync, every legacy write that does not
 * declare a stream-sync client is refused with `update_required` (426), on
 * every legacy write route of the data surface. A switched-off server and a
 * declaring client are never refused.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pino } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { STREAM_SYNC_CLIENT_HEADER } from "@opendatalabs/personal-server-ts-core/api";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { dataRoutes } from "./data.js";

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

  beforeEach(async () => {
    switchedOn = false;
    root = await mkdtemp(join(tmpdir(), "refuse-legacy-"));
    index = createIndexManager(initializeDatabase(join(root, "index.db")));
    app = dataRoutes({
      indexManager: index,
      hierarchyOptions: { dataDir: join(root, "data") },
      logger: pino({ level: "silent" }),
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      devToken: "refuse-legacy-test",
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      legacyWritesRefused: () => switchedOn,
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

    it("is not refused for a client that declares stream sync", async () => {
      switchedOn = true;
      const response = await send(route, { [STREAM_SYNC_CLIENT_HEADER]: "1" });
      expect(response.status).not.toBe(426);
    });
  });

  it("stores nothing from a refused write", async () => {
    switchedOn = true;
    await send(LEGACY_WRITE_ROUTES[0]);
    await send(LEGACY_WRITE_ROUTES[1]);
    expect(index.countByScope(scope)).toBe(0);
  });

  it("still stores a declaring client's write when the switch is on", async () => {
    switchedOn = true;
    const post = await send(LEGACY_WRITE_ROUTES[0], {
      [STREAM_SYNC_CLIENT_HEADER]: "1",
    });
    expect(post.status).toBe(201);
    const put = await send(LEGACY_WRITE_ROUTES[1], {
      [STREAM_SYNC_CLIENT_HEADER]: "1",
    });
    expect(put.status).toBe(201);
    expect(index.countByScope(scope)).toBe(2);
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
});
