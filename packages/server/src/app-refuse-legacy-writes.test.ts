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

  // SWITCH_REQUIRES_SECOND_FLAG
  it("refuses an old client's write when streamSync.write is on and refuseLegacyWrites is left at its default", async () => {
    const response = await post(makeApp({ write: true }));
    expect(response.status).toBe(426);
    expect(index.countByScope("github.events")).toBe(0);
  });

  // SWITCH_REQUIRES_SECOND_FLAG
  it("refuses an old client's write when streamSync.write is on and refuseLegacyWrites is false", async () => {
    const response = await post(
      makeApp({ write: true, refuseLegacyWrites: false }),
    );
    expect(response.status).toBe(426);
    expect(index.countByScope("github.events")).toBe(0);
  });

  it("refuses an old client's write when streamSync.write is on", async () => {
    const response = await post(
      makeApp({ write: true, refuseLegacyWrites: true }),
    );
    expect(response.status).toBe(426);
    expect((await response.json()).errorCode).toBe("update_required");
  });

  it("refuses a declaring client's write when the account is switched: a header is no exemption", async () => {
    const response = await post(
      makeApp({ write: true, refuseLegacyWrites: true }),
      { [STREAM_SYNC_CLIENT_HEADER]: "1" },
    );
    expect(response.status).toBe(426);
    expect(index.countByScope("github.events")).toBe(0);
  });

  it("refuses an Oura browser import when the account is switched, and stores nothing", async () => {
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
    const app = makeApp({ write: false });
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

  it("accepts an old client's write when streamSync.write is off, whatever refuseLegacyWrites says", async () => {
    expect(
      (await post(makeApp({ write: false, refuseLegacyWrites: true }))).status,
    ).toBe(201);
  });
  it("uses the host's one mode instance for the write gate, not a second one built from config", async () => {
    const reads: Array<string | undefined> = [];
    const app = createApp({
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
      // Config says the account is unswitched; the host's mode says switched.
      config: ServerConfigSchema.parse({ streamSync: {} }),
      accountStorageMode: {
        read: (requestOwner) => {
          reads.push(requestOwner);
          return "switched";
        },
      },
    });
    expect((await post(app)).status).toBe(426);
    expect(reads.length).toBeGreaterThan(0);
    expect(index.countByScope("github.events")).toBe(0);
  });
  function appWithMode(read: () => "switched" | "unswitched" | "unknown") {
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
      config: ServerConfigSchema.parse({ streamSync: {} }),
      accountStorageMode: { read },
    });
  }

  const ouraStreams = ["sleep", "readiness", "activity"] as const;
  /** A complete, valid batch: it reaches the importer's first durable write. */
  const validOuraBatch = {
    selection: { streams: ouraStreams.map((name) => ({ name })) },
    collectedAt: "2026-10-15T00:00:00.000Z",
    records: ouraStreams.map((stream) => ({
      stream,
      data: {
        id: `${stream}-1`,
        day: "2026-10-13",
        score: 80,
        ...(stream === "sleep"
          ? { record_type: "daily_score", sleep_score: 80 }
          : {}),
      },
    })),
    completion: {
      streams: ouraStreams.map((stream) => ({
        stream,
        status: "complete",
        recordCount: 1,
      })),
    },
  };
  const ouraImport = (app: ReturnType<typeof makeApp>) =>
    app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(validOuraBatch),
    });

  // UNKNOWN_WRITES_PASS
  it("refuses a legacy write with a retryable 503 while the account mode is unknown", async () => {
    const app = appWithMode(() => "unknown");
    const response = await post(app);
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(index.countByScope("github.events")).toBe(0);
  });

  // UNKNOWN_WRITES_PASS
  it("refuses an Oura browser import with a retryable 503 while the account mode is unknown", async () => {
    const response = await ouraImport(appWithMode(() => "unknown"));
    expect(response.status).toBe(503);
    expect(index.countByScope("oura.sleep")).toBe(0);
  });

  // ADMISSION_ONLY_GATE
  it("answers an Oura import 426 when the account switches after the route admitted it", async () => {
    let reads = 0;
    const app = appWithMode(() => (++reads > 1 ? "switched" : "unswitched"));
    const response = await ouraImport(app);
    expect(response.status).toBe(426);
    expect(index.countByScope("oura.sleep")).toBe(0);
  });
});
