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
      ...extra,
    });
  await authority.ready;
  const accessLog = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage: createMemoryPsLiteStorage(),
    gateway: {} as never,
    accountModeAuthority: authority,
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
    ...runtimeExtra,
  });
  return { runtime, authority };
}

async function signed(
  runtime: { fetch(request: Request): Promise<Response> },
  path: string,
  body: unknown,
  wallet = owner,
  options: { chunked?: boolean } = {},
) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  const bytes = new TextEncoder().encode(text);
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
          body: bytes,
        }),
      },
      // A stream has no declared length: the cap has to count what arrives.
      ...(options.chunked
        ? {
            body: new ReadableStream({
              start(controller) {
                controller.enqueue(bytes);
                controller.close();
              },
            }),
            duplex: "half",
          }
        : { body: text }),
    } as RequestInit),
  );
}

const evidence = (state: string, extra: Record<string, unknown> = {}) => ({
  owner: owner.address,
  state,
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
    expect(await res.json()).toEqual({ decision: "legacy" });
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

  // RESET_ACCEPTS_EQUAL_GENERATION, OFF_AFTER_ON_WITHOUT_GENERATION
  it("lowers an On only for an Off at a higher generation, then lets legacy work proceed", async () => {
    const { runtime } = await build();
    const send = (body: unknown) =>
      signed(runtime, "/v1/account-mode/evidence", body);
    await send(evidence("on", { generation: 3 }));
    for (const body of [
      evidence("off"),
      evidence("off", { generation: 2 }),
      evidence("off", { generation: 3 }),
    ]) {
      const res = await send(body);
      expect((await res.json()).decision, JSON.stringify(body)).toBe("streams");
      const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
      expect(write.status).toBe(426);
    }
    const reset = await send(evidence("off", { generation: 4 }));
    expect(reset.status).toBe(200);
    expect(await reset.json()).toEqual({ decision: "legacy" });
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(201);
  });

  it("rejects a generation that is not a non-negative integer with a 400", async () => {
    const { runtime, authority } = await build();
    for (const generation of [-1, 1.5, "2", null, true, 2 ** 60]) {
      const res = await signed(
        runtime,
        "/v1/account-mode/evidence",
        evidence("on", { generation }),
      );
      expect(res.status, JSON.stringify(generation)).toBe(400);
    }
    expect(authority.read(owner.address).kind).toBe("refuse");
  });

  // OWNERLESS_READ_ANSWERS
  it("changes nothing for evidence about another owner", async () => {
    const { runtime, authority } = await build();
    const res = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("on", { owner: stranger.address }),
    );
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_OWNER_MISMATCH",
    );
    expect(authority.read(owner.address).kind).toBe("refuse");
  });

  it("answers another owner with 403 before the rest of the body is read, and never asks the module", async () => {
    const { runtime, authority } = await build();
    const asked: string[] = [];
    const submit = authority.submitEvidence.bind(authority);
    authority.submitEvidence = (input) => {
      asked.push(input.owner);
      return submit(input);
    };
    for (const body of [
      evidence("on", { owner: stranger.address }),
      { owner: stranger.address, state: "maybe" },
      { owner: stranger.address },
    ]) {
      const res = await signed(runtime, "/v1/account-mode/evidence", body);
      expect(res.status).toBe(403);
      expect(await res.json()).toEqual({
        error: {
          code: 403,
          errorCode: "ACCOUNT_MODE_OWNER_MISMATCH",
          message: "This server only takes account mode for its own owner",
        },
      });
    }
    expect(asked).toEqual([]);
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
    expect(authority.read(owner.address).kind).toBe("refuse");
  });

  it("answers 405 to a method other than POST", async () => {
    const { runtime } = await build();
    const res = await runtime.fetch(
      new Request(`${ORIGIN}/v1/account-mode/evidence`),
    );
    expect(res.status).toBe(405);
  });
});

describe("the Lite runtime's mode routes bound what they read", () => {
  const paths = ["/v1/account-mode/evidence"];

  // LITE_BODY_CAP_COUNTS_ONLY_DECLARED_SIZE
  it("answers 413 above 16 KiB, whether the length is declared or the body is chunked", async () => {
    const { runtime } = await build();
    const big = { ...evidence("on"), note: "x".repeat(20_000) };
    for (const path of paths) {
      for (const chunked of [false, true]) {
        const res = await signed(runtime, path, big, owner, { chunked });
        expect(res.status, `${path} chunked=${chunked}`).toBe(413);
        expect((await res.json()).error).toBe("CONTENT_TOO_LARGE");
      }
    }
  });

  it("answers 400 to a body that is not a flat object of at most 8 plain values, or whose owner is too long", async () => {
    const { runtime, authority } = await build();
    for (const path of paths) {
      for (const body of [
        [],
        "not json",
        { ...evidence("on"), nested: { a: 1 } },
        { ...evidence("on"), list: [1] },
        Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`k${i}`, i])),
        { ...evidence("on"), owner: "0x".padEnd(101, "1") },
        { ...evidence("on"), owner: 7 },
      ]) {
        const res = await signed(runtime, path, body);
        expect(res.status, `${path} ${JSON.stringify(body).slice(0, 40)}`).toBe(
          400,
        );
      }
    }
    expect(authority.read(owner.address).kind).toBe("refuse");
  });

  it("answers 405 with Allow: POST to any other method", async () => {
    const { runtime } = await build();
    for (const path of paths) {
      const res = await runtime.fetch(new Request(`${ORIGIN}${path}`));
      expect(res.status).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
    }
  });
});

describe("the Lite runtime takes mode evidence before activation", () => {
  it("hears an Off while inactive, then lets the worker start", async () => {
    const { runtime } = await build({}, { active: false });
    const res = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("off"),
    );
    expect(res.status).toBe(200);
    expect((await res.json()).decision).toBe("legacy");
    const get = await runtime.fetch(
      new Request(`${ORIGIN}/v1/account-mode/evidence`),
    );
    expect(get.status).toBe(405);
  });
});

describe("the Lite runtime binds the mode to the person's owner only", () => {
  it("refuses evidence when only a server identity is given, and latches nothing", async () => {
    const { runtime, authority } = await build(
      {},
      {
        serverOwner: undefined,
        identity: { address: owner.address },
      },
    );
    const res = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("off"),
    );
    expect(res.status).toBe(403);
    expect(authority.read(owner.address).kind).toBe("refuse");
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(503);
  });
});
