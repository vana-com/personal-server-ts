/**
 * The Lite runtime's account-mode door: `POST /v1/account-mode/evidence` and
 * the in-process authority behind it, with legacy writes shown on the same
 * runtime so the answer's effect is visible.
 */
import { describe, expect, it } from "vitest";
import {
  createMemoryModeRecordStore,
  createModeAuthority,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  buildWeb3SignedHeader,
  createTestWallet,
  fixedAccountStorageMode,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createPsLiteRuntime, createWeb3SignedPsLiteAuth } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMemoryPsLiteAccessLogStore } from "./test-support/memory.js";

const ORIGIN = "https://ps-lite.local";
const owner = createTestWallet(7);
const stranger = createTestWallet(8);

async function build(
  extra: Partial<Parameters<typeof createModeAuthority>[0]> = {},
  runtimeExtra: Record<string, unknown> = {},
  given?: ReturnType<typeof createModeAuthority>,
) {
  const authority =
    given ??
    createModeAuthority({
      store: createMemoryModeRecordStore(),
      bootId: "b",
      ...extra,
    });
  await authority.ready;
  const accessLog = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage: createMemoryPsLiteStorage(),
    gateway: {} as never,
    accountModeAuthority: authority,
    ...runtimeExtra,
    serverOwner: owner.address,
    serverOrigin: ORIGIN,
    accessLogReader: accessLog,
    accessLogWriter: accessLog,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createWeb3SignedPsLiteAuth({
      origin: ORIGIN,
      ownerAddress: owner.address,
      dataReadPolicyPorts: {} as never,
    }),
    active: true,
  });
  return { runtime, authority };
}

async function signed(
  runtime: { fetch(request: Request): Promise<Response> },
  path: string,
  body: unknown,
  wallet = owner,
) {
  const text = JSON.stringify(body);
  return runtime.fetch(
    new Request(`${ORIGIN}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: await buildWeb3SignedHeader({
          wallet,
          aud: ORIGIN,
          method: "POST",
          uri: path,
          body: new TextEncoder().encode(text),
        }),
      },
      body: text,
    }),
  );
}

const evidence = (state: string, extra: Record<string, unknown> = {}) => ({
  owner: owner.address,
  state,
  fetchStartedAt: Date.now(),
  rawStatus: 200,
  ...extra,
});

describe("the Lite runtime's account-mode evidence route", () => {
  // UNKNOWN_AS_OFF
  it("refuses a legacy write with a retryable 503 before the Account has answered", async () => {
    const { runtime } = await build();
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(503);
    expect(write.headers.get("retry-after")).toBe("5");
  });

  // NEVER_SEEN_OWNER_ADMITS
  it("takes a first explicit Off and lets legacy work proceed with no 503", async () => {
    const { runtime } = await build();
    const res = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("off"),
    );
    expect(await res.json()).toEqual({
      decision: "legacy",
      importRequired: false,
    });
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(201);
  });

  it("takes an On, then refuses a legacy write with 426 and never lowers it", async () => {
    const { runtime } = await build();
    await signed(runtime, "/v1/account-mode/evidence", evidence("on"));
    await signed(runtime, "/v1/account-mode/evidence", evidence("off"));
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(426);
  });

  // OWNERLESS_READ_ANSWERS
  it("changes nothing for evidence about another owner", async () => {
    const { runtime, authority } = await build();
    const res = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("on", { owner: stranger.address }),
    );
    expect((await res.json()).decision).toBe("refuse");
    expect(authority.snapshot().size).toBe(0);
  });

  it("rejects a caller that is not the owner, and a body that is not evidence", async () => {
    const { runtime, authority } = await build();
    const wrongCaller = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("on"),
      stranger,
    );
    expect(wrongCaller.status).toBe(401);
    const badBody = await signed(runtime, "/v1/account-mode/evidence", {
      owner: owner.address,
      state: "maybe",
    });
    expect(badBody.status).toBe(400);
    expect(authority.snapshot().size).toBe(0);
  });

  it("answers 405 to a method other than POST", async () => {
    const { runtime } = await build();
    const res = await runtime.fetch(
      new Request(`${ORIGIN}/v1/account-mode/evidence`),
    );
    expect(res.status).toBe(405);
  });
});

describe("the Lite runtime's import-done route", () => {
  const latch = (runtime: Awaited<ReturnType<typeof build>>["runtime"]) =>
    signed(runtime, "/v1/account-mode/evidence", evidence("on"));

  it("keeps importRequired on every answer until the host reports the import done", async () => {
    const { runtime, authority } = await build({ hasLegacyFiles: () => true });
    expect((await (await latch(runtime)).json()).importRequired).toBe(true);
    expect(authority.commitStream(owner.address, "op")).toMatchObject({
      code: "IMPORT_PENDING",
    });
    const done = await signed(runtime, "/v1/account-mode/import-done", {
      owner: owner.address,
    });
    expect(await done.json()).toEqual({
      decision: "streams",
      importRequired: false,
    });
    expect(authority.commitStream(owner.address, "op").kind).toBe("streams");
  });

  it("answers a caller that is not the owner with 401, another owner's report with a refusal, a bad body with 400", async () => {
    const { runtime, authority } = await build({ hasLegacyFiles: () => true });
    await latch(runtime);
    expect(
      (
        await signed(
          runtime,
          "/v1/account-mode/import-done",
          { owner: owner.address },
          stranger,
        )
      ).status,
    ).toBe(401);
    const other = await signed(runtime, "/v1/account-mode/import-done", {
      owner: stranger.address,
    });
    expect((await other.json()).decision).toBe("refuse");
    expect(
      (await signed(runtime, "/v1/account-mode/import-done", {})).status,
    ).toBe(400);
    expect(authority.commitStream(owner.address, "op")).toMatchObject({
      code: "IMPORT_PENDING",
    });
  });
});

describe("the Lite runtime's mode comes from the module and nothing else", () => {
  // INDEPENDENT_APP_MODE_PORT
  it("ignores a mode passed beside the module: an On in the module refuses a legacy write", async () => {
    const { runtime } = await build(
      {},
      { accountStorageMode: fixedAccountStorageMode("unswitched") },
    );
    await signed(runtime, "/v1/account-mode/evidence", evidence("on"));
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(426);
  });

  // INDEPENDENT_APP_MODE_PORT
  it("ignores a mode passed with no module: legacy writes stay refused with 503", async () => {
    const accessLog = createMemoryPsLiteAccessLogStore();
    const runtime = createPsLiteRuntime({
      storage: createMemoryPsLiteStorage(),
      gateway: {} as never,
      accountStorageMode: fixedAccountStorageMode("unswitched"),
      serverOwner: owner.address,
      serverOrigin: ORIGIN,
      accessLogReader: accessLog,
      accessLogWriter: accessLog,
      tokenStore: createMemoryPsLiteTokenStore(),
      saveConfig: async () => {},
      stateCapabilities: { config: "memory" },
      auth: createWeb3SignedPsLiteAuth({
        origin: ORIGIN,
        ownerAddress: owner.address,
        dataReadPolicyPorts: {} as never,
      }),
      active: true,
    } as never);
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(503);
  });
});
