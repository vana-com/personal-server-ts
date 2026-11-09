/**
 * `POST /v1/account-mode/evidence`: the one door a host uses to tell the
 * server what the Account said. Every case goes through the mounted app, the
 * real owner auth and the real module; the data route shows what the answer
 * does to a legacy write.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pino } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  authorityHearing,
  buildWeb3SignedHeader,
  createTestWallet,
  fixedAccountStorageMode,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createApp } from "../app.js";
import { initializeDatabase } from "../storage/index-schema.js";
import {
  createIndexManager,
  type IndexManager,
} from "../storage/index-manager.js";

const ORIGIN = "http://localhost:8080";
const owner = createTestWallet(0);
const stranger = createTestWallet(1);
const PATH = "/v1/account-mode/evidence";

describe("POST /v1/account-mode/evidence", () => {
  let dir: string;
  let index: IndexManager;
  let authority: ModeAuthority;
  let app: ReturnType<typeof createApp>;
  const store = () => createMemoryModeRecordStore();

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "account-mode-route-"));
    index = createIndexManager(initializeDatabase(":memory:"));
    authority = createModeAuthority({ store: store() });
    await authority.ready;
    app = createApp({
      logger: pino({ level: "silent" }),
      version: "0.0.1",
      startedAt: new Date(),
      indexManager: index,
      hierarchyOptions: { dataDir: join(dir, "data") },
      serverOrigin: ORIGIN,
      serverOwner: owner.address,
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      accountModeAuthority: authority,
    });
  });
  afterEach(async () => {
    index.close();
    await rm(dir, { recursive: true, force: true });
  });

  async function post(
    body: unknown,
    wallet: ReturnType<typeof createTestWallet> | null = owner,
  ) {
    const text = JSON.stringify(body);
    return app.request(PATH, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(wallet
          ? {
              authorization: await buildWeb3SignedHeader({
                wallet,
                aud: ORIGIN,
                method: "POST",
                uri: PATH,
                body: new TextEncoder().encode(text),
              }),
            }
          : {}),
      },
      body: text,
    });
  }

  const evidence = (state: string, extra: Record<string, unknown> = {}) => ({
    owner: owner.address,
    state,
    ...extra,
  });

  const legacyWrite = async () =>
    app.request("/v1/data/github.events", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: ORIGIN,
          method: "POST",
          uri: "/v1/data/github.events",
          body: new TextEncoder().encode('{"v":1}'),
        }),
      },
      body: '{"v":1}',
    });

  // UNKNOWN_AS_OFF
  it("answers 503 to a legacy write before the Account has answered", async () => {
    expect((await legacyWrite()).status).toBe(503);
  });

  // NEVER_SEEN_OWNER_ADMITS, OFF_WAITS_FOR_SAVE
  it("takes the first launch's explicit Off as the very first call, and legacy work proceeds", async () => {
    const res = await post(evidence("off"));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ decision: "legacy" });
    expect((await legacyWrite()).status).toBe(201);
  });

  it("takes the first launch's On and answers streams, then refuses a legacy write with 426", async () => {
    const res = await post(evidence("on"));
    expect(await res.json()).toEqual({ decision: "streams" });
    expect((await legacyWrite()).status).toBe(426);
  });

  it("answers an unknown state with the decision and changes nothing", async () => {
    const before = await post(evidence("unknown"));
    expect(before.status).toBe(503);
    expect(before.headers.get("retry-after")).toBe("5");
    expect(await before.json()).toEqual({
      decision: "refuse",
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    });
    expect((await legacyWrite()).status).toBe(503);
    await post(evidence("off"));
    expect((await (await post(evidence("unknown"))).json()).decision).toBe(
      "legacy",
    );
  });

  it("accepts and ignores the fetchStartedAt and rawStatus fields older hosts send", async () => {
    const res = await post(
      evidence("off", { fetchStartedAt: Date.now(), rawStatus: 200 }),
    );
    expect(await res.json()).toEqual({ decision: "legacy" });
  });

  it("keeps an Off with no expiry", async () => {
    await post(evidence("off"));
    const later = createModeAuthority({
      store: createMemoryModeRecordStore([
        ["x", { answer: "off", generation: 0, receivedAt: 1 }],
      ]),
      now: () => 1e15,
    });
    await later.ready;
    expect(later.read("x").kind).toBe("legacy");
  });

  // OFF_AFTER_ON_LOWERS
  it("never lowers an On with a later Off", async () => {
    await post(evidence("on"));
    const res = await post(evidence("off"));
    expect((await res.json()).decision).toBe("streams");
    expect((await legacyWrite()).status).toBe(426);
  });

  // RESET_ACCEPTS_EQUAL_GENERATION, OFF_AFTER_ON_WITHOUT_GENERATION
  it("lowers an On only for an Off at a higher generation, then lets legacy work proceed", async () => {
    await post(evidence("on", { generation: 3 }));
    for (const body of [
      evidence("off"),
      evidence("off", { generation: 2 }),
      evidence("off", { generation: 3 }),
    ]) {
      const res = await post(body);
      expect((await res.json()).decision, JSON.stringify(body)).toBe("streams");
      expect((await legacyWrite()).status).toBe(426);
    }
    const reset = await post(evidence("off", { generation: 4 }));
    expect(reset.status).toBe(200);
    expect(await reset.json()).toEqual({ decision: "legacy" });
    expect((await legacyWrite()).status).toBe(201);
  });

  it("rejects a generation that is not a non-negative integer with a 400", async () => {
    for (const generation of [-1, 1.5, "2", null, true, 2 ** 60]) {
      const res = await post(evidence("on", { generation }));
      expect(res.status, JSON.stringify(generation)).toBe(400);
    }
    expect(authority.read(owner.address).kind).toBe("refuse");
  });

  // OWNERLESS_READ_ANSWERS, CROSS_OWNER_READ_ANSWERS
  it("answers evidence about another owner with 403 and changes nothing", async () => {
    const res = await post(evidence("on", { owner: stranger.address }));
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: {
        code: 403,
        errorCode: "ACCOUNT_MODE_OWNER_MISMATCH",
        message: "This server only takes account mode for its own owner",
      },
    });
    expect(authority.read(stranger.address).kind).toBe("refuse");
  });

  it("rejects a caller that is not the owner", async () => {
    const res = await post(evidence("on"), stranger);
    expect(res.status).toBe(401);
    expect(authority.read(owner.address).kind).toBe("refuse");
  });

  it("rejects a call with no credentials", async () => {
    const res = await post(evidence("on"), null);
    expect(res.status).toBe(401);
    expect(authority.read(owner.address).kind).toBe("refuse");
  });

  it("rejects a body that is not evidence with a 400", async () => {
    for (const body of [
      {},
      { owner: owner.address, state: "maybe" },
      { owner: 7, state: "on" },
    ]) {
      const res = await post(body);
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
    expect(authority.read(owner.address).kind).toBe("refuse");
  });
});

describe("the app's mode comes from the module and nothing else", () => {
  let dir: string;
  let index: IndexManager;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "account-mode-one-source-"));
    index = createIndexManager(initializeDatabase(":memory:"));
  });
  afterEach(async () => {
    index.close();
    await rm(dir, { recursive: true, force: true });
  });

  async function legacyWrite(extra: Record<string, unknown>) {
    const app = createApp({
      logger: pino({ level: "silent" }),
      version: "0.0.1",
      startedAt: new Date(),
      indexManager: index,
      hierarchyOptions: { dataDir: join(dir, "data") },
      serverOrigin: ORIGIN,
      serverOwner: owner.address,
      gateway: {} as GatewayClient,
      accessLogWriter: { write: async () => undefined },
      ...extra,
    } as never);
    return app.request("/v1/data/github.events", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: await buildWeb3SignedHeader({
          wallet: owner,
          aud: ORIGIN,
          method: "POST",
          uri: "/v1/data/github.events",
          body: new TextEncoder().encode('{"v":1}'),
        }),
      },
      body: '{"v":1}',
    });
  }

  // INDEPENDENT_APP_MODE_PORT
  it("ignores a mode passed beside the module: an On in the module refuses a legacy write", async () => {
    const authority = await authorityHearing(owner.address, "on");
    const res = await legacyWrite({
      accountModeAuthority: authority,
      accountStorageMode: fixedAccountStorageMode("unswitched"),
    });
    expect(res.status).toBe(426);
    expect(index.countByScope("github.events")).toBe(0);
  });

  // INDEPENDENT_APP_MODE_PORT
  it("ignores a mode passed with no module: legacy writes stay refused with 503", async () => {
    const res = await legacyWrite({
      accountStorageMode: fixedAccountStorageMode("unswitched"),
    });
    expect(res.status).toBe(503);
    expect(index.countByScope("github.events")).toBe(0);
  });

  it("follows the module: an Off writes, and a later On refuses", async () => {
    const authority = await authorityHearing(owner.address, "off");
    expect(
      (await legacyWrite({ accountModeAuthority: authority })).status,
    ).toBe(201);
    await authority.submitEvidence({ owner: owner.address, state: "on" });
    expect(
      (await legacyWrite({ accountModeAuthority: authority })).status,
    ).toBe(426);
  });
});
