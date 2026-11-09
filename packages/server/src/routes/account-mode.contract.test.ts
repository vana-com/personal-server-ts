/**
 * The HTTP contract of the account-mode routes, apart from what the module
 * decides: status per decision, who may ask about whom, what a body may look
 * like, which methods answer, and that a failed save never answers legacy.
 * Every case goes through the mounted app and the real owner auth.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pino } from "pino";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  buildWeb3SignedHeader,
  createTestWallet,
  fixedModeAuthority,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  OFF_TTL_MS,
  createMemoryModeRecordStore,
  createModeAuthority,
  type ModeAuthority,
  type ModeDecision,
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
const EVIDENCE = "/v1/account-mode/evidence";
const IMPORT_DONE = "/v1/account-mode/import-done";
const PATHS = [EVIDENCE, IMPORT_DONE];
const ACCESS_TOKEN = "control-plane-token-for-tests";
const MAX_BODY = 16 * 1024;

type Wallet = ReturnType<typeof createTestWallet>;

describe("the account-mode routes' HTTP contract", () => {
  let dir: string;
  let index: IndexManager;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "account-mode-contract-"));
    index = createIndexManager(initializeDatabase(":memory:"));
  });
  afterEach(async () => {
    index.close();
    await rm(dir, { recursive: true, force: true });
  });

  function appWith(
    authority: ModeAuthority,
    extra: Record<string, unknown> = {},
  ) {
    return createApp({
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
      ...extra,
    } as never);
  }

  async function sign(path: string, bytes: Uint8Array, wallet: Wallet) {
    return buildWeb3SignedHeader({
      wallet,
      aud: ORIGIN,
      method: "POST",
      uri: path,
      body: bytes,
    });
  }

  /** A signed POST of exactly `text`. `wallet: null` sends no credentials. */
  async function postText(
    app: ReturnType<typeof createApp>,
    path: string,
    text: string,
    wallet: Wallet | null = owner,
  ) {
    return app.request(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(wallet
          ? {
              authorization: await sign(
                path,
                new TextEncoder().encode(text),
                wallet,
              ),
            }
          : {}),
      },
      body: text,
    });
  }

  const postJson = (
    app: ReturnType<typeof createApp>,
    path: string,
    body: unknown,
    wallet: Wallet | null = owner,
  ) => postText(app, path, JSON.stringify(body), wallet);

  const evidence = (state: string, extra: Record<string, unknown> = {}) => ({
    owner: owner.address,
    state,
    fetchStartedAt: Date.now(),
    rawStatus: 200,
    ...extra,
  });

  const bodyFor = (path: string, extra: Record<string, unknown> = {}) =>
    path === EVIDENCE
      ? evidence("on", extra)
      : { owner: owner.address, ...extra };

  const fresh = async (options: Parameters<typeof createModeAuthority>[0]) => {
    const authority = createModeAuthority(options);
    await authority.ready;
    return authority;
  };

  /** The module with its two route-facing answers replaced. */
  function answering(decision: ModeDecision): ModeAuthority {
    return {
      ...fixedModeAuthority("unswitched"),
      submitEvidence: async () => decision,
      importDone: async () => decision,
    };
  }

  // refusal_http_status_code_matrix
  describe("status per decision", () => {
    const MATRIX: Array<{
      name: string;
      decision: ModeDecision;
      status: number;
      retryAfter: string | null;
      body: Record<string, unknown>;
    }> = [
      {
        name: "streams",
        decision: { kind: "streams", importRequired: false },
        status: 200,
        retryAfter: null,
        body: { decision: "streams", importRequired: false },
      },
      {
        name: "streams with the import owed",
        decision: { kind: "streams", importRequired: true },
        status: 200,
        retryAfter: null,
        body: { decision: "streams", importRequired: true },
      },
      {
        name: "legacy",
        decision: { kind: "legacy" },
        status: 200,
        retryAfter: null,
        body: { decision: "legacy", importRequired: false },
      },
      {
        name: "unknown",
        decision: { kind: "refuse", code: "ACCOUNT_MODE_UNKNOWN", status: 503 },
        status: 503,
        retryAfter: "5",
        body: {
          decision: "refuse",
          importRequired: false,
          code: "ACCOUNT_MODE_UNKNOWN",
          status: 503,
        },
      },
      {
        name: "store owned by another runtime",
        decision: {
          kind: "refuse",
          code: "ACCOUNT_MODE_STORE_OWNED",
          status: 503,
        },
        status: 503,
        retryAfter: "5",
        body: {
          decision: "refuse",
          importRequired: false,
          code: "ACCOUNT_MODE_STORE_OWNED",
          status: 503,
        },
      },
      {
        name: "import pending",
        decision: { kind: "refuse", code: "IMPORT_PENDING", status: 503 },
        status: 503,
        retryAfter: "5",
        body: {
          decision: "refuse",
          importRequired: false,
          code: "IMPORT_PENDING",
          status: 503,
        },
      },
      {
        name: "legacy refused after the switch",
        decision: {
          kind: "refuse",
          code: "LEGACY_REFUSED_SWITCHED",
          status: 426,
        },
        status: 426,
        retryAfter: null,
        body: {
          decision: "refuse",
          importRequired: false,
          code: "LEGACY_REFUSED_SWITCHED",
          status: 426,
        },
      },
    ];

    for (const path of PATHS) {
      for (const row of MATRIX) {
        it(`${path}: ${row.name} answers ${row.status} with its body`, async () => {
          const app = appWith(answering(row.decision));
          const res = await postJson(app, path, bodyFor(path));
          expect(res.status).toBe(row.status);
          expect(res.headers.get("retry-after")).toBe(row.retryAfter);
          expect(await res.json()).toEqual(row.body);
        });
      }
    }

    it("answers 503 ACCOUNT_MODE_STORE_OWNED when another runtime owns the records", async () => {
      const store = createMemoryModeRecordStore();
      await fresh({ store, bootId: "first" });
      const blocked = createModeAuthority({ store, bootId: "second" });
      await blocked.ready.catch(() => undefined);
      const app = appWith(blocked);
      for (const path of PATHS) {
        const res = await postJson(app, path, bodyFor(path));
        expect(res.status).toBe(503);
        expect(res.headers.get("retry-after")).toBe("5");
        expect(await res.json()).toMatchObject({
          decision: "refuse",
          code: "ACCOUNT_MODE_STORE_OWNED",
          status: 503,
        });
      }
    });
  });

  // CROSS_OWNER_READ_ANSWERS
  describe("cross-owner submissions", () => {
    it("answer 403 before the module is asked anything, and say nothing about the other owner", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      // The other owner has a saved On and another has a saved Off.
      for (const [who, state] of [
        [stranger.address, "on"],
        ["0x3333333333333333333333333333333333333333", "off"],
      ] as const) {
        await authority.submitEvidence({
          owner: who,
          authOwner: who,
          state,
          fetchStartedAt: Date.now(),
          rawStatus: 200,
        });
      }
      const before = JSON.stringify([...authority.snapshot()]);
      const spies = [
        vi.spyOn(authority, "read"),
        vi.spyOn(authority, "admit"),
        vi.spyOn(authority, "submitEvidence"),
        vi.spyOn(authority, "importDone"),
        vi.spyOn(authority, "importPending"),
      ];
      const app = appWith(authority);
      for (const who of [
        stranger.address,
        stranger.address.toUpperCase().replace("0X", "0x"),
        "0x3333333333333333333333333333333333333333",
        "0xnever-seen",
      ]) {
        for (const path of PATHS) {
          const res = await postJson(app, path, bodyFor(path, { owner: who }));
          expect(res.status, `${path} ${who}`).toBe(403);
          const text = await res.text();
          expect(JSON.parse(text)).toEqual({
            error: {
              code: 403,
              errorCode: "ACCOUNT_MODE_OWNER_MISMATCH",
              message: "This server only takes account mode for its own owner",
            },
          });
          for (const word of [
            "decision",
            "streams",
            "legacy",
            "refuse",
            "importRequired",
          ]) {
            expect(text).not.toContain(word);
          }
        }
      }
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
      expect(JSON.stringify([...authority.snapshot()])).toBe(before);
    });

    it("answer 403 even when the rest of the body is malformed", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const app = appWith(authority);
      const res = await postJson(app, EVIDENCE, {
        owner: stranger.address,
        state: "maybe",
      });
      expect(res.status).toBe(403);
    });

    it("answer the owner themselves, in any letter case, as before", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const app = appWith(authority);
      const res = await postJson(
        app,
        EVIDENCE,
        evidence("on", { owner: owner.address.toLowerCase() }),
      );
      expect(res.status).toBe(200);
    });
  });

  // bearer_owner_binding_and_missing_owner_fail_closed
  describe("owner binding", () => {
    const bearer = (path: string, body: unknown, token = ACCESS_TOKEN) => ({
      path,
      init: {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      },
    });

    it("binds a bearer caller to the server's owner too", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const app = appWith(authority, { accessToken: ACCESS_TOKEN });
      for (const path of PATHS) {
        const other = bearer(path, bodyFor(path, { owner: stranger.address }));
        expect((await app.request(other.path, other.init)).status).toBe(403);
      }
      expect(authority.snapshot().size).toBe(0);
      const own = bearer(EVIDENCE, evidence("on"));
      expect((await app.request(own.path, own.init)).status).toBe(200);
      const wrong = bearer(EVIDENCE, evidence("on"), "not-the-token");
      expect((await app.request(wrong.path, wrong.init)).status).toBe(401);
    });

    it("fails closed with no configured owner: no credential reaches the module", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const submit = vi.spyOn(authority, "submitEvidence");
      const importDone = vi.spyOn(authority, "importDone");
      const app = appWith(authority, {
        serverOwner: undefined,
        accessToken: ACCESS_TOKEN,
      });
      for (const path of PATHS) {
        for (const who of [owner.address, stranger.address, ""]) {
          const body = bodyFor(path, { owner: who });
          const viaToken = bearer(path, body);
          const a = await app.request(viaToken.path, viaToken.init);
          expect(a.status, `${path} bearer ${who}`).toBeGreaterThanOrEqual(400);
          const b = await postJson(app, path, body);
          expect(b.status, `${path} signed ${who}`).toBeGreaterThanOrEqual(400);
        }
      }
      expect(submit).not.toHaveBeenCalled();
      expect(importDone).not.toHaveBeenCalled();
      expect(authority.snapshot().size).toBe(0);
    });
  });

  // forged_authOwner_is_ignored
  describe("a forged authOwner field", () => {
    it("is not read from the body: the module is told the server's owner", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const submit = vi.spyOn(authority, "submitEvidence");
      const app = appWith(authority);
      const res = await postJson(
        app,
        EVIDENCE,
        evidence("on", { authOwner: stranger.address }),
      );
      expect(res.status).toBe(200);
      expect(submit).toHaveBeenCalledTimes(1);
      expect(submit.mock.calls[0][0]).toMatchObject({
        owner: owner.address,
        authOwner: owner.address,
      });
      expect(submit.mock.calls[0][0]).not.toMatchObject({
        authOwner: stranger.address,
      });
    });

    it("cannot make another owner's evidence pass", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const app = appWith(authority);
      const res = await postJson(
        app,
        EVIDENCE,
        evidence("on", {
          owner: stranger.address,
          authOwner: stranger.address,
        }),
      );
      expect(res.status).toBe(403);
      expect(authority.snapshot().size).toBe(0);
    });
  });

  // no_credentials_and_method_parity
  describe("credentials and methods", () => {
    it("answers 401 to a call with no credentials on both paths, touching nothing", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const app = appWith(authority);
      for (const path of PATHS) {
        expect((await postJson(app, path, bodyFor(path), null)).status).toBe(
          401,
        );
        expect(
          (await postJson(app, path, bodyFor(path), stranger)).status,
        ).toBe(401);
      }
      expect(authority.snapshot().size).toBe(0);
    });

    it("answers any method but POST with 405, Allow and the error body, with or without credentials", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const app = appWith(authority);
      for (const path of PATHS) {
        for (const method of ["GET", "HEAD", "PUT", "PATCH", "DELETE"]) {
          for (const credentials of [false, true]) {
            const res = await app.request(path, {
              method,
              headers: credentials
                ? { authorization: `Bearer ${ACCESS_TOKEN}` }
                : {},
            });
            expect(res.status, `${method} ${path}`).toBe(405);
            expect(res.headers.get("allow")).toBe("POST");
            if (method !== "HEAD") {
              expect(await res.json()).toEqual({
                error: {
                  code: 405,
                  errorCode: "METHOD_NOT_ALLOWED",
                  message: "Method not allowed",
                },
              });
            }
          }
        }
      }
      expect(authority.snapshot().size).toBe(0);
    });

    it("does not make up a route: another path under the prefix is 404", async () => {
      const authority = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
      });
      const app = appWith(authority);
      const res = await app.request("/v1/account-mode/other");
      expect(res.status).toBe(404);
    });
  });

  describe("request bodies", () => {
    async function authority() {
      return fresh({ store: createMemoryModeRecordStore(), bootId: "b" });
    }

    it("takes a body at the limit and refuses one a byte over it with 413", async () => {
      const mode = await authority();
      const app = appWith(mode);
      const frame = (pad: number) =>
        JSON.stringify({ ...evidence("on"), pad: "x".repeat(pad) });
      const base = new TextEncoder().encode(frame(0)).byteLength;
      const atLimit = frame(MAX_BODY - base);
      expect(new TextEncoder().encode(atLimit).byteLength).toBe(MAX_BODY);
      expect((await postText(app, EVIDENCE, atLimit)).status).toBe(200);
      const over = frame(MAX_BODY - base + 1);
      const res = await postText(app, EVIDENCE, over);
      expect(res.status).toBe(413);
    });

    it("refuses an oversized body on both paths before the module is asked", async () => {
      const mode = await authority();
      const submit = vi.spyOn(mode, "submitEvidence");
      const importDone = vi.spyOn(mode, "importDone");
      const app = appWith(mode);
      for (const path of PATHS) {
        const big = JSON.stringify(
          bodyFor(path, { pad: "x".repeat(MAX_BODY * 4) }),
        );
        expect((await postText(app, path, big)).status, path).toBe(413);
        // No credentials: the size is judged first.
        expect((await postText(app, path, big, null)).status, path).toBe(413);
      }
      expect(submit).not.toHaveBeenCalled();
      expect(importDone).not.toHaveBeenCalled();
    });

    it("refuses an oversized chunked body that declares no length", async () => {
      const mode = await authority();
      const submit = vi.spyOn(mode, "submitEvidence");
      const app = appWith(mode);
      const chunk = new TextEncoder().encode("x".repeat(4096));
      const stream = () =>
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"owner":"'));
            for (let i = 0; i < 64; i += 1) controller.enqueue(chunk);
            controller.enqueue(new TextEncoder().encode('"}'));
            controller.close();
          },
        });
      const res = await app.request(EVIDENCE, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: await sign(EVIDENCE, new Uint8Array(), owner),
        },
        body: stream(),
        duplex: "half",
      } as RequestInit);
      expect(res.status).toBe(413);
      expect(submit).not.toHaveBeenCalled();
    });

    it("takes a small chunked body that declares no length", async () => {
      const mode = await authority();
      const app = appWith(mode);
      const bytes = new TextEncoder().encode(JSON.stringify(evidence("on")));
      const half = Math.floor(bytes.byteLength / 2);
      const res = await app.request(EVIDENCE, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: await sign(EVIDENCE, bytes, owner),
        },
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(bytes.slice(0, half));
            controller.enqueue(bytes.slice(half));
            controller.close();
          },
        }),
        duplex: "half",
      } as RequestInit);
      expect(res.status).toBe(200);
    });

    it("refuses a malformed, empty or non-object body with 400, touching nothing", async () => {
      const mode = await authority();
      const app = appWith(mode);
      const submit = vi.spyOn(mode, "submitEvidence");
      const importDone = vi.spyOn(mode, "importDone");
      for (const path of PATHS) {
        for (const text of [
          "",
          "{",
          "not json",
          "null",
          "7",
          '"owner"',
          "[]",
          JSON.stringify([bodyFor(path)]),
        ]) {
          const res = await postText(app, path, text);
          expect(res.status, `${path} ${JSON.stringify(text)}`).toBe(400);
        }
      }
      expect(submit).not.toHaveBeenCalled();
      expect(importDone).not.toHaveBeenCalled();
    });

    it("refuses a nested value, too many keys and an over-long owner with 400", async () => {
      const mode = await authority();
      const app = appWith(mode);
      const submit = vi.spyOn(mode, "submitEvidence");
      const importDone = vi.spyOn(mode, "importDone");
      const deep = "[".repeat(5000) + "]".repeat(5000);
      const many = Object.fromEntries(
        Array.from({ length: 9 }, (_, i) => [`k${i}`, i]),
      );
      for (const path of PATHS) {
        for (const extra of [
          { nested: { a: 1 } },
          { nested: [1] },
          many,
          { owner: owner.address + "0".repeat(100) },
        ]) {
          const res = await postJson(app, path, bodyFor(path, extra));
          expect(
            res.status,
            `${path} ${JSON.stringify(extra).slice(0, 40)}`,
          ).toBe(400);
        }
        // A deeply nested body that is under the size limit is bounded too.
        const res = await postText(
          app,
          path,
          `{"owner":"${owner.address}","state":"on","x":${deep}}`,
        );
        expect(res.status).toBe(400);
      }
      expect(submit).not.toHaveBeenCalled();
      expect(importDone).not.toHaveBeenCalled();
    });

    it("takes a few extra plain fields", async () => {
      const mode = await authority();
      const app = appWith(mode);
      const res = await postJson(
        app,
        EVIDENCE,
        evidence("on", { note: "x", n: 1, b: true, z: null }),
      );
      expect(res.status).toBe(200);
    });
  });

  describe("a failed or late save never answers legacy", () => {
    const legacyWrite = async (app: ReturnType<typeof createApp>) =>
      app.request("/v1/data/github.events", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: await sign(
            "/v1/data/github.events",
            new TextEncoder().encode('{"v":1}'),
            owner,
          ),
        },
        body: '{"v":1}',
      });

    // unknown_after_saved_off_never_falls_back_on_error
    it("keeps an expired saved Off unknown on every error answer, never legacy", async () => {
      let mono = 0;
      const mode = await fresh({
        store: createMemoryModeRecordStore(),
        bootId: "b",
        clock: { mono: () => mono, wall: () => 1_000_000 + mono },
      });
      const app = appWith(mode);
      const off = await postJson(app, EVIDENCE, {
        ...evidence("off"),
        fetchStartedAt: 1_000_000,
      });
      expect(await off.json()).toEqual({
        decision: "legacy",
        importRequired: false,
      });
      mono = OFF_TTL_MS + 1;
      for (const body of [
        {
          ...evidence("unknown"),
          rawStatus: 503,
          fetchStartedAt: 1_000_000 + mono,
        },
        {
          ...evidence("unknown"),
          rawStatus: null,
          fetchStartedAt: 1_000_000 + mono,
        },
        {
          ...evidence("off"),
          rawStatus: 500,
          fetchStartedAt: 1_000_000 + mono,
        },
        {
          ...evidence("off"),
          rawStatus: 404,
          fetchStartedAt: 1_000_000 + mono,
        },
      ]) {
        const res = await postJson(app, EVIDENCE, body);
        expect(res.status, JSON.stringify(body)).toBe(503);
        expect(await res.json()).toMatchObject({
          decision: "refuse",
          code: "ACCOUNT_MODE_UNKNOWN",
        });
      }
      expect((await legacyWrite(app)).status).toBe(503);
    });

    // rejected_timed_out_and_cas_save_never_returns_legacy
    it("answers a rejected Off save 503, never legacy, and writes nothing", async () => {
      const store = createMemoryModeRecordStore();
      const mode = await fresh({ store, bootId: "b" });
      const app = appWith(mode);
      store.failSaves(true);
      const res = await postJson(app, EVIDENCE, evidence("off"));
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ code: "ACCOUNT_MODE_UNKNOWN" });
      expect((await legacyWrite(app)).status).toBe(503);
      expect(store.durable.size).toBe(0);
    });

    it("answers a rejected On save 503, never streams", async () => {
      const store = createMemoryModeRecordStore();
      const mode = await fresh({ store, bootId: "b" });
      const app = appWith(mode);
      store.failSaves(true);
      const res = await postJson(app, EVIDENCE, evidence("on"));
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ code: "ACCOUNT_MODE_UNKNOWN" });
      expect(store.durable.size).toBe(0);
    });

    it("answers an Off save that does not settle in time 503, never legacy", async () => {
      const store = createMemoryModeRecordStore();
      const mode = await fresh({ store, bootId: "b", saveTimeoutMs: 20 });
      const app = appWith(mode);
      store.pauseSaves();
      const res = await postJson(app, EVIDENCE, evidence("off"));
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ code: "ACCOUNT_MODE_UNKNOWN" });
      expect((await legacyWrite(app)).status).toBe(503);
      store.abandonHeldSaves();
    });

    it("answers a save the store refuses as a stale write 503, never legacy", async () => {
      const store = createMemoryModeRecordStore();
      const mode = await fresh({ store, bootId: "b" });
      const app = appWith(mode);
      // Another writer got an On into the store behind this runtime's back.
      store.durable.set(owner.address.toLowerCase(), {
        switched: true,
        switchedAt: 1,
        cleanOffAt: null,
        offFetchStartMono: null,
        bootId: "other",
        importPending: false,
      });
      const res = await postJson(app, EVIDENCE, evidence("off"));
      expect(res.status).toBe(503);
      expect(await res.json()).toMatchObject({ code: "ACCOUNT_MODE_UNKNOWN" });
      expect((await legacyWrite(app)).status).not.toBe(201);
      expect(store.durable.get(owner.address.toLowerCase())?.switched).toBe(
        true,
      );
    });
  });
});
