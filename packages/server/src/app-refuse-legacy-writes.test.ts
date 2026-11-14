/**
 * The mounted app takes the account's storage mode from the host's one mode
 * module and nothing else. The spawn-time `streamSync` config flags no longer
 * decide it: a write is refused with 426 after the Account said On, refused
 * with a retryable 503 while the mode is unknown, and accepted as before only
 * after a fresh explicit Off.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { pino } from "pino";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  STREAM_SYNC_CLIENT_HEADER,
  type AccountStorageModeValue,
} from "@opendatalabs/personal-server-ts-core/api";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  authorityHearing,
  fixedModeAuthority,
  spyOnModeAuthority,
  type ModeAsked,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { createApp } from "./app.js";
import { initializeDatabase } from "./storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "./storage/index-manager.js";

const owner = "0x1111111111111111111111111111111111111111";
const other = "0x2222222222222222222222222222222222222222";
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

  function makeApp(
    accountModeAuthority?: ModeAuthority,
    streamSync: { write?: boolean } = {},
  ) {
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
      config: ServerConfigSchema.parse({ streamSync }),
      accountModeAuthority,
    });
  }

  const modeApp = (value: AccountStorageModeValue) =>
    makeApp(fixedModeAuthority(value));

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

  const ouraImport = (app: ReturnType<typeof makeApp>) =>
    app.request("/v1/import/oura-browser", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ streams: [] }),
    });

  // UNSWITCHED_CHANGED
  it("accepts an old client's write on an unswitched account", async () => {
    expect((await post(modeApp("unswitched"))).status).toBe(201);
  });

  it("refuses an old client's write on a switched account", async () => {
    const response = await post(modeApp("switched"));
    expect(response.status).toBe(426);
    expect((await response.json()).errorCode).toBe("update_required");
  });

  it("refuses a declaring client's write on a switched account: a header is no exemption", async () => {
    const response = await post(modeApp("switched"), {
      [STREAM_SYNC_CLIENT_HEADER]: "1",
    });
    expect(response.status).toBe(426);
    expect(index.countByScope("github.events")).toBe(0);
  });

  it("refuses an Oura browser import on a switched account, and stores nothing", async () => {
    const response = await ouraImport(modeApp("switched"));
    expect(response.status).toBe(426);
    expect((await response.json()).errorCode).toBe("update_required");
    expect(index.countByScope("oura.sleep")).toBe(0);
  });

  it("lets an Oura browser import through on an unswitched account", async () => {
    const response = await ouraImport(modeApp("unswitched"));
    expect([426, 503]).not.toContain(response.status);
  });

  // UNKNOWN_AS_OFF
  it("refuses with a retryable 503 while the mode is unknown, and stores nothing", async () => {
    for (const app of [modeApp("unknown"), makeApp(undefined)]) {
      const write = await post(app);
      expect(write.status).toBe(503);
      expect((await write.json()).error.errorCode).toBe("ACCOUNT_MODE_UNKNOWN");
      expect((await ouraImport(app)).status).toBe(503);
    }
    expect(index.countByScope("github.events")).toBe(0);
  });

  it("does not read the old spawn-time flags as an Off", async () => {
    const flagOnly = createModeAuthority({
      store: createMemoryModeRecordStore(),
    });
    await flagOnly.ready;
    const app = makeApp(flagOnly, { write: true });
    expect((await post(app)).status).toBe(503);
  });

  // UNSWITCHED_CHANGED
  it("takes the answer from the host's module: a fresh Off writes, a later On refuses", async () => {
    const authority = await authorityHearing(owner, "off");
    const app = makeApp(authority);
    expect((await post(app)).status).toBe(201);
    await authority.submitEvidence({
      owner,
      state: "on",
    });
    expect((await post(app)).status).toBe(426);
    expect(index.countByScope("github.events")).toBe(1);
  });

  describe.each([
    { name: "own mode", bound: owner, expected: "switched", refused: 426 },
    {
      name: "mode of another account",
      bound: other,
      expected: "unknown",
      refused: 503,
    },
  ] as const)("a latched switched $name in this server", (c) => {
    let calls: ModeAsked[] = [];

    async function makeSpiedApp() {
      const inner = await authorityHearing(c.bound, "on");
      expect(inner.read(c.bound).kind).toBe("streams");
      const spied = spyOnModeAuthority(inner);
      calls = spied.calls;
      return makeApp(spied.authority);
    }

    function expectOnlyThisServersOwnerWasAsked() {
      expect(calls.length).toBeGreaterThan(0);
      expect(new Set(calls.map((x) => x.owner))).toEqual(new Set([owner]));
      expect(new Set(calls.map((x) => x.answer))).toEqual(
        new Set([c.expected]),
      );
    }

    // OWNERLESS_READ_ANSWERS
    it("answers the legacy data write for this server's owner only", async () => {
      const response = await post(await makeSpiedApp());
      expect(response.status).toBe(c.refused);
      expectOnlyThisServersOwnerWasAsked();
    });

    // OWNERLESS_READ_ANSWERS
    it("answers the Oura browser import for this server's owner only", async () => {
      const response = await ouraImport(await makeSpiedApp());
      expect(response.status).toBe(c.refused);
      expectOnlyThisServersOwnerWasAsked();
    });

    // OWNERLESS_READ_ANSWERS
    it("answers a read's selector for this server's owner only", async () => {
      const response = await (
        await makeSpiedApp()
      ).request("/v1/data/github.events", {
        headers: { Authorization: `Bearer ${token}` },
      });
      expect(response.status).not.toBe(426);
      expectOnlyThisServersOwnerWasAsked();
    });
  });
});
