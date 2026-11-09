/**
 * The Lite runtime's account-mode door: `POST /v1/account-mode/evidence` and
 * the in-process authority behind it, with legacy writes shown on the same
 * runtime so the answer's effect is visible.
 */
import { createRequire } from "node:module";
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

// The shared vectors say what status a route answers with for a decision.
const sharedVectors = createRequire(import.meta.url)(
  "@opendatalabs/personal-server-ts-core/account-mode/vectors.json",
) as {
  expect: { decision?: string; code?: string; httpStatus?: number }[];
}[];

/** The one HTTP status the shared vectors give a decision (and refusal code). */
function vectorHttpStatus(decision: string, code?: string): number {
  const seen = new Set<number>();
  for (const vector of sharedVectors) {
    for (const exp of vector.expect) {
      if (exp.decision === decision && exp.code === code) {
        seen.add(exp.httpStatus as number);
      }
    }
  }
  expect([...seen], `${decision} ${code}`).toHaveLength(1);
  return [...seen][0];
}
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
  // A given authority may be one the store refused.
  await (given ? authority.ready.catch(() => undefined) : authority.ready);
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
    expect(await reset.json()).toEqual({
      decision: "legacy",
      importRequired: false,
    });
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
    expect(authority.snapshot().size).toBe(0);
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
    expect(authority.snapshot().size).toBe(0);
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
    expect(
      await authority.commitStream(owner.address, "op", () => 1),
    ).toMatchObject({ ok: false, decision: { code: "IMPORT_PENDING" } });
    const done = await signed(runtime, "/v1/account-mode/import-done", {
      owner: owner.address,
    });
    expect(await done.json()).toEqual({
      decision: "streams",
      importRequired: false,
    });
    expect(
      (await authority.commitStream(owner.address, "op", () => 1)).ok,
    ).toBe(true);
  });

  it("answers a caller that is not the owner with 401, another owner's report with 403, a bad body with 400", async () => {
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
    expect(other.status).toBe(403);
    expect((await other.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_OWNER_MISMATCH",
    );
    expect(
      (await signed(runtime, "/v1/account-mode/import-done", {})).status,
    ).toBe(400);
    expect(
      await authority.commitStream(owner.address, "op", () => 1),
    ).toMatchObject({ ok: false, decision: { code: "IMPORT_PENDING" } });
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

describe("the Lite runtime's mode answers carry their HTTP status", () => {
  // EvidenceAndImportDoneRefusalsAre503
  it("answers every refusal with its own status and body, and a success with 200", async () => {
    const { runtime } = await build({ hasLegacyFiles: () => true });
    const unknown = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("unknown", { rawStatus: null }),
    );
    expect(unknown.status).toBe(
      vectorHttpStatus("refuse", "ACCOUNT_MODE_UNKNOWN"),
    );
    expect(await unknown.json()).toEqual({
      decision: "refuse",
      importRequired: false,
      code: "ACCOUNT_MODE_UNKNOWN",
      status: 503,
    });
    const on = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("on"),
    );
    expect(on.status).toBe(vectorHttpStatus("streams"));
    expect(await on.json()).toEqual({
      decision: "streams",
      importRequired: true,
    });
    const foreign = await signed(runtime, "/v1/account-mode/import-done", {
      owner: stranger.address,
    });
    expect(foreign.status).toBe(403);
    expect((await foreign.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_OWNER_MISMATCH",
    );
  });

  // LITE_503_WITHOUT_RETRY_AFTER
  it("tells a client to retry a 503 after 5 seconds, and not a 426 or a success", async () => {
    const { runtime } = await build({ hasLegacyFiles: () => true });
    const unknown = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("unknown", { rawStatus: null }),
    );
    expect(unknown.status).toBe(503);
    expect(unknown.headers.get("retry-after")).toBe("5");
    const on = await signed(
      runtime,
      "/v1/account-mode/evidence",
      evidence("on"),
    );
    expect(on.status).toBe(200);
    expect(on.headers.get("retry-after")).toBeNull();
    const pending = await signed(runtime, "/v1/account-mode/import-done", {
      owner: owner.address,
    });
    expect(pending.status).toBe(200);
    const refused = await build(
      {},
      {},
      (() => {
        const store = createMemoryModeRecordStore();
        void createModeAuthority({ store, bootId: "owner" });
        return createModeAuthority({ store, bootId: "second" });
      })(),
    );
    const owned = await signed(
      refused.runtime,
      "/v1/account-mode/import-done",
      { owner: owner.address },
    );
    expect(owned.status).toBe(503);
    expect(owned.headers.get("retry-after")).toBe("5");
  });

  it("answers 503 ACCOUNT_MODE_STORE_OWNED when another runtime owns the store", async () => {
    const store = createMemoryModeRecordStore();
    await createModeAuthority({ store, bootId: "owner" }).ready;
    const refused = createModeAuthority({ store, bootId: "second" });
    await refused.ready.catch(() => undefined);
    const { runtime } = await build({}, {}, refused);
    for (const path of [
      "/v1/account-mode/evidence",
      "/v1/account-mode/import-done",
    ]) {
      const res = await signed(
        runtime,
        path,
        path.endsWith("evidence") ? evidence("off") : { owner: owner.address },
      );
      expect(res.status).toBe(
        vectorHttpStatus("refuse", "ACCOUNT_MODE_STORE_OWNED"),
      );
      expect((await res.json()).code).toBe("ACCOUNT_MODE_STORE_OWNED");
    }
  });

  it("does not read another owner's mode to answer their import-done report", async () => {
    const { runtime, authority } = await build();
    const asked: string[] = [];
    const read = authority.read.bind(authority);
    authority.read = (who: string) => {
      asked.push(`read ${who}`);
      return read(who);
    };
    const importDone = authority.importDone.bind(authority);
    authority.importDone = (who: string) => {
      asked.push(`importDone ${who}`);
      return importDone(who);
    };
    const res = await signed(runtime, "/v1/account-mode/import-done", {
      owner: stranger.address,
    });
    expect(res.status).toBe(403);
    expect(asked).toEqual([]);
  });
});

describe("the Lite runtime's mode routes bound what they read", () => {
  const paths = ["/v1/account-mode/evidence", "/v1/account-mode/import-done"];

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
    expect(authority.snapshot().size).toBe(0);
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
    const done = await signed(runtime, "/v1/account-mode/import-done", {
      owner: owner.address,
    });
    expect(done.status).toBe(200);
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
    expect(authority.snapshot().size).toBe(0);
    const write = await signed(runtime, "/v1/data/notes.entries", { v: 1 });
    expect(write.status).toBe(503);
  });
});
