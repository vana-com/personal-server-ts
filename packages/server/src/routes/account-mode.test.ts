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
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  accountStorageModeOf,
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
    authority = createModeAuthority({ store: store(), bootId: "b" });
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
      accountStorageMode: accountStorageModeOf(authority),
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
    fetchStartedAt: Date.now(),
    rawStatus: 200,
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
    expect(await res.json()).toEqual({
      decision: "legacy",
      importRequired: false,
    });
    expect((await legacyWrite()).status).toBe(201);
  });

  it("takes the first launch's On and answers streams, then refuses a legacy write with 426", async () => {
    const res = await post(evidence("on"));
    expect(await res.json()).toEqual({
      decision: "streams",
      importRequired: false,
    });
    expect((await legacyWrite()).status).toBe(426);
  });

  it("answers a refusal, with a 200, for an Account answer that was unknown", async () => {
    for (const body of [
      evidence("unknown", { rawStatus: 503 }),
      evidence("unknown", { rawStatus: null }),
      evidence("off", { rawStatus: 500 }),
    ]) {
      const res = await post(body);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        decision: "refuse",
        importRequired: false,
        code: "ACCOUNT_MODE_UNKNOWN",
        status: 503,
      });
    }
    expect((await legacyWrite()).status).toBe(503);
  });

  // OFF_AFTER_ON_LOWERS
  it("never lowers an On with a later Off", async () => {
    await post(evidence("on"));
    const res = await post(evidence("off"));
    expect((await res.json()).decision).toBe("streams");
    expect((await legacyWrite()).status).toBe(426);
  });

  // OWNERLESS_READ_ANSWERS
  it("changes nothing for evidence about another owner", async () => {
    const res = await post(evidence("on", { owner: stranger.address }));
    expect((await res.json()).decision).toBe("refuse");
    expect(authority.read(stranger.address).kind).toBe("refuse");
    expect(authority.snapshot().size).toBe(0);
  });

  it("rejects a caller that is not the owner", async () => {
    const res = await post(evidence("on"), stranger);
    expect(res.status).toBe(401);
    expect(authority.snapshot().size).toBe(0);
  });

  it("rejects a call with no credentials", async () => {
    const res = await post(evidence("on"), null);
    expect(res.status).toBe(401);
    expect(authority.snapshot().size).toBe(0);
  });

  it("rejects a body that is not evidence with a 400", async () => {
    for (const body of [
      {},
      { owner: owner.address, state: "maybe" },
      { owner: 7, state: "on" },
      { ...evidence("on"), rawStatus: "200" },
    ]) {
      const res = await post(body);
      expect(res.status, JSON.stringify(body)).toBe(400);
    }
    expect(authority.snapshot().size).toBe(0);
  });
});
