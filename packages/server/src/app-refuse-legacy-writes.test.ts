/**
 * The mounted app reads the stream-sync switch from the server's own config
 * (`streamSync.write`, set by the host from the Account setting) and refuses
 * an undeclared legacy write on `/v1/data` only when it is on.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pino } from "pino";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { STREAM_SYNC_CLIENT_HEADER } from "@opendatalabs/personal-server-ts-core/api";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { createApp } from "./app.js";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "./storage/index-manager.js";

const owner = "0x1111111111111111111111111111111111111111";
const token = "refuse-legacy-app-token";

describe("createApp legacy-write refusal", () => {
  let dir: string;
  let index: IndexManager;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "app-refuse-legacy-"));
    index = createIndexManager(initializeDatabase(":memory:"));
  });
  afterEach(async () => {
    index.close();
    await rm(dir, { recursive: true, force: true });
  });

  function makeApp(streamSync: {
    write?: boolean;
    refuseLegacyWrites?: boolean;
  }) {
    return createApp({
      logger: pino({ level: "silent" }),
      version: "0.0.1",
      startedAt: new Date(),
      indexManager: index,
      hierarchyOptions: { dataDir: join(dir, "data") },
      serverOrigin: "http://localhost:8080",
      serverOwner: owner,
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      devToken: token,
      config: ServerConfigSchema.parse({
        streamSync,
      }),
    });
  }

  function post(app: ReturnType<typeof makeApp>, headers = {}) {
    return app.request("/v1/data/github.events", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        ...headers,
      },
      body: JSON.stringify({ v: 1 }),
    });
  }

  it("accepts an old client's write by default, even with streamSync.write on", async () => {
    expect((await post(makeApp({ write: true }))).status).toBe(201);
  });

  it("refuses an old client's write only when both flags are on", async () => {
    const response = await post(
      makeApp({ write: true, refuseLegacyWrites: true }),
    );
    expect(response.status).toBe(426);
    expect((await response.json()).errorCode).toBe("update_required");
  });

  it("refuses a declaring client's write when both flags are on: a header is no exemption", async () => {
    const response = await post(
      makeApp({ write: true, refuseLegacyWrites: true }),
      { [STREAM_SYNC_CLIENT_HEADER]: "1" },
    );
    expect(response.status).toBe(426);
    expect(index.countByScope("github.events")).toBe(0);
  });

  it("refuses an Oura browser import when both flags are on, and stores nothing", async () => {
    const app = makeApp({ write: true, refuseLegacyWrites: true });
    const response = await app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ streams: [] }),
    });
    expect(response.status).toBe(426);
    expect((await response.json()).errorCode).toBe("update_required");
    expect(index.countByScope("oura.sleep")).toBe(0);
  });

  it("lets an Oura browser import through when the switch is off", async () => {
    const app = makeApp({ write: true, refuseLegacyWrites: false });
    const response = await app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ streams: [] }),
    });
    expect(response.status).not.toBe(426);
  });

  it("accepts an old client's write when streamSync.write is off", async () => {
    expect(
      (await post(makeApp({ write: false, refuseLegacyWrites: true }))).status,
    ).toBe(201);
  });
});
