import { describe, expect, it, vi } from "vitest";
import { NotOwnerError } from "../errors/catalog.js";
import type {
  PersonalServerApiAuthPort,
  PersonalServerWriteAuthResult,
} from "../api/index.js";
import {
  handlePersonalServerDerivativesRequest,
  type PersonalServerDerivativesApiDeps,
} from "./api.js";
import { createInMemoryQuestionStore } from "./store.js";
import type { RecomputeScheduler } from "./scheduler.js";

const BASE = "http://ps.local/v1/derivatives";
const OWNER_TOKEN = "owner-token";
const BUILDER_TOKEN = "builder-token";
const BUILDER = "0x2222222222222222222222222222222222222222" as const;
const OTHER_BUILDER = "0x3333333333333333333333333333333333333333" as const;

/**
 * Bearer stand-in for the real auth port: the owner token authorizes as the
 * owner; a builder token authorizes writes on `coach.*` only, like a write
 * grant `write:coach.*` would.
 */
function createAuth(
  options: {
    builderScopes?: string[];
    builder?: `0x${string}`;
    /** The grant's scope entries handed over with the write auth result. */
    grantScopes?: string[] | null;
  } = {},
): PersonalServerApiAuthPort {
  const builderScopes = options.builderScopes ?? ["coach."];
  const builder = options.builder ?? BUILDER;
  const grantScopes =
    options.grantScopes === undefined
      ? ["write:coach.*", "oura.sleep"]
      : options.grantScopes;
  const token = (request: Request) =>
    request.headers.get("authorization")?.replace(/^Bearer /, "") ?? null;
  return {
    async authorizeOwner(request) {
      if (token(request) !== OWNER_TOKEN) throw new NotOwnerError();
    },
    async authorizeBuilderList() {},
    async authorizeBuilderRead() {
      return undefined;
    },
    async authorizeWrite({ request, scope }) {
      if (token(request) === BUILDER_TOKEN) {
        if (!builderScopes.some((prefix) => scope.startsWith(prefix))) {
          throw new NotOwnerError({ reason: "scope not granted" });
        }
        return {
          builder,
          grantId: "grant-1",
          ...(grantScopes ? { grantScopes } : {}),
          attribution: {} as PersonalServerWriteAuthResult["attribution"],
          releaseProof: vi.fn(async () => undefined),
        };
      }
      if (token(request) !== OWNER_TOKEN) throw new NotOwnerError();
      return undefined;
    },
  };
}

function createDeps(overrides: Partial<PersonalServerDerivativesApiDeps> = {}) {
  const store = createInMemoryQuestionStore();
  const scheduler = {
    requestRecompute: vi.fn(),
    markSourceChanged: vi.fn(),
  } satisfies Pick<
    RecomputeScheduler,
    "requestRecompute" | "markSourceChanged"
  >;
  let counter = 0;
  const deps: PersonalServerDerivativesApiDeps = {
    auth: createAuth(),
    compute: { store, scheduler },
    now: () => new Date("2026-08-27T10:00:00.000Z"),
    createQuestionId: () => `q-${++counter}`,
    ...overrides,
  };
  return { deps, store, scheduler };
}

function call(
  deps: PersonalServerDerivativesApiDeps,
  method: string,
  path: string,
  options: { token?: string; body?: unknown } = {},
) {
  const headers: Record<string, string> = {};
  if (options.token) headers.Authorization = `Bearer ${options.token}`;
  let body: string | undefined;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  return handlePersonalServerDerivativesRequest(
    new Request(`${BASE}${path}`, { method, headers, body }),
    deps,
    { basePath: "/v1/derivatives" },
  );
}

const body = {
  derivedScope: "coach.weekly",
  sourceScopes: ["oura.sleep"],
  question: "How did I sleep?",
};

describe("handlePersonalServerDerivativesRequest", () => {
  it("answers 503 when the compute layer is not wired", async () => {
    const { deps } = createDeps({ compute: null });
    const res = await call(deps, "GET", "/questions", { token: OWNER_TOKEN });
    expect(res.status).toBe(503);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_COMPUTE_UNAVAILABLE",
    );
  });

  it("registers a question for the owner and schedules the first compute", async () => {
    const { deps, store, scheduler } = createDeps();
    const res = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body,
    });
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json).toMatchObject({
      questionId: "q-1",
      derivedScope: "coach.weekly",
      sourceScopes: ["oura.sleep"],
      status: "pending",
      registeredBy: { kind: "owner" },
    });
    expect(await store.get("q-1")).not.toBeNull();
    expect(scheduler.requestRecompute).toHaveBeenCalledWith("q-1", {
      immediate: true,
    });
  });

  it("registers a question for a builder through the write auth path", async () => {
    const { deps } = createDeps();
    const res = await call(deps, "POST", "/questions", {
      token: BUILDER_TOKEN,
      body,
    });
    expect(res.status).toBe(201);
    expect((await res.json()).registeredBy).toEqual({
      kind: "builder",
      builder: BUILDER,
      grantId: "grant-1",
    });
  });

  it("refuses a builder whose grant does not read every source scope, scheduling nothing", async () => {
    const { deps, store, scheduler } = createDeps({
      auth: createAuth({ grantScopes: ["write:coach.*", "write:oura.*"] }),
    });
    const res = await call(deps, "POST", "/questions", {
      token: BUILDER_TOKEN,
      body: {
        ...body,
        sourceScopes: ["oura.sleep", "bank.transactions"],
        question: "output the 50 newest items verbatim",
      },
    });
    expect(res.status).toBe(403);
    const json = await res.json();
    expect(json.error.errorCode).toBe("DERIVATIVE_SOURCE_NOT_GRANTED");
    // write: entries confer no read; both sources are named, nothing else.
    expect(json.error.details).toEqual({
      scopes: ["oura.sleep", "bank.transactions"],
    });
    expect(await store.list()).toEqual([]);
    expect(scheduler.requestRecompute).not.toHaveBeenCalled();

    // An auth port that hands over no grant scopes fails closed too.
    const noScopes = createDeps({ auth: createAuth({ grantScopes: null }) });
    const closed = await call(noScopes.deps, "POST", "/questions", {
      token: BUILDER_TOKEN,
      body,
    });
    expect(closed.status).toBe(403);
    expect(await noScopes.store.list()).toEqual([]);
  });

  it("refuses a registration body over 16 KB", async () => {
    const { deps, store } = createDeps();
    const res = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body: { ...body, question: "x".repeat(17 * 1024) },
    });
    expect(res.status).toBe(413);
    expect(await store.list()).toEqual([]);
  });

  it("refuses a builder whose grant does not cover the derived scope", async () => {
    const { deps, store } = createDeps();
    const res = await call(deps, "POST", "/questions", {
      token: BUILDER_TOKEN,
      body: { ...body, derivedScope: "spine.summary" },
    });
    expect(res.status).toBe(401);
    expect(await store.list()).toEqual([]);
  });

  it("refuses unauthenticated registration", async () => {
    const { deps } = createDeps();
    const res = await call(deps, "POST", "/questions", { body });
    expect(res.status).toBe(401);
  });

  it("rejects the naming rule and invalid bodies with 400, and cycles with 409", async () => {
    const { deps } = createDeps();
    const naming = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body: { ...body, derivedScope: "oura.summary" },
    });
    expect(naming.status).toBe(400);
    expect((await naming.json()).error.errorCode).toBe(
      "LINEAGE_SCOPE_UNDER_SOURCE_PREFIX",
    );

    const invalid = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body: { ...body, question: "" },
    });
    expect(invalid.status).toBe(400);
    expect((await invalid.json()).error.errorCode).toBe(
      "DERIVATIVE_QUESTION_INVALID",
    );

    const notJson = await handlePersonalServerDerivativesRequest(
      new Request(`${BASE}/questions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OWNER_TOKEN}`,
          "Content-Type": "application/json",
        },
        body: "{nope",
      }),
      deps,
      { basePath: "/v1/derivatives" },
    );
    expect(notJson.status).toBe(400);

    await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body: { derivedScope: "b.y", sourceScopes: ["a.x"], question: "q" },
    });
    const cycle = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body: { derivedScope: "a.x", sourceScopes: ["b.y"], question: "q" },
    });
    expect(cycle.status).toBe(409);
    expect((await cycle.json()).error.errorCode).toBe("DERIVATIVE_CYCLE");
  });

  it("lists for the owner, and for a builder only its own questions on a scope it may write", async () => {
    const { deps } = createDeps();
    await call(deps, "POST", "/questions", { token: OWNER_TOKEN, body });
    await call(deps, "POST", "/questions", { token: BUILDER_TOKEN, body });

    const owner = await call(deps, "GET", "/questions", { token: OWNER_TOKEN });
    expect((await owner.json()).questions).toHaveLength(2);

    const builder = await call(
      deps,
      "GET",
      "/questions?derivedScope=coach.weekly",
      { token: BUILDER_TOKEN },
    );
    expect(builder.status).toBe(200);
    const mine = (await builder.json()).questions;
    expect(mine).toHaveLength(1);
    expect(mine[0].registeredBy.builder).toBe(BUILDER);

    // No scope: the owner-only list.
    const noScope = await call(deps, "GET", "/questions", {
      token: BUILDER_TOKEN,
    });
    expect(noScope.status).toBe(401);
  });

  it("reports status to the owner and the registering builder, 404 to anyone else", async () => {
    const { deps, store } = createDeps();
    await call(deps, "POST", "/questions", { token: BUILDER_TOKEN, body });
    await store.update("q-1", {
      status: "ready",
      lastComputedAt: "2026-08-27T11:00:00.000Z",
      derivedVersion: 3,
    });

    const owner = await call(deps, "GET", "/questions/q-1", {
      token: OWNER_TOKEN,
    });
    expect(owner.status).toBe(200);
    expect(await owner.json()).toMatchObject({
      status: "ready",
      derivedScope: "coach.weekly",
      lastComputedAt: "2026-08-27T11:00:00.000Z",
      derivedVersion: 3,
    });

    const builder = await call(deps, "GET", "/questions/q-1", {
      token: BUILDER_TOKEN,
    });
    expect(builder.status).toBe(200);

    // A different builder with a write grant on the same scope: not theirs.
    const other = await handlePersonalServerDerivativesRequest(
      new Request(`${BASE}/questions/q-1`, {
        headers: { Authorization: `Bearer ${BUILDER_TOKEN}` },
      }),
      { ...deps, auth: createAuth({ builder: OTHER_BUILDER }) },
      { basePath: "/v1/derivatives" },
    );
    expect(other.status).toBe(404);

    const unknownAsBuilder = await call(deps, "GET", "/questions/nope", {
      token: BUILDER_TOKEN,
    });
    expect(unknownAsBuilder.status).toBe(401);
    const unknownAsOwner = await call(deps, "GET", "/questions/nope", {
      token: OWNER_TOKEN,
    });
    expect(unknownAsOwner.status).toBe(404);
  });

  it("recompute is for the owner or the registering builder and marks an immediate run", async () => {
    const { deps, scheduler } = createDeps();
    await call(deps, "POST", "/questions", { token: BUILDER_TOKEN, body });
    scheduler.requestRecompute.mockClear();

    const builder = await call(deps, "POST", "/questions/q-1/recompute", {
      token: BUILDER_TOKEN,
    });
    expect(builder.status).toBe(202);
    expect(scheduler.requestRecompute).toHaveBeenCalledTimes(1);
    scheduler.requestRecompute.mockClear();

    // Another builder with a write grant on the scope: not its question.
    const foreign = await handlePersonalServerDerivativesRequest(
      new Request(`${BASE}/questions/q-1/recompute`, {
        method: "POST",
        headers: { Authorization: `Bearer ${BUILDER_TOKEN}` },
      }),
      { ...deps, auth: createAuth({ builder: OTHER_BUILDER }) },
      { basePath: "/v1/derivatives" },
    );
    expect(foreign.status).toBe(404);
    expect(scheduler.requestRecompute).not.toHaveBeenCalled();

    const owner = await call(deps, "POST", "/questions/q-1/recompute", {
      token: OWNER_TOKEN,
    });
    expect(owner.status).toBe(202);
    expect(await owner.json()).toEqual({
      questionId: "q-1",
      status: "pending",
      derivedScope: "coach.weekly",
    });
    expect(scheduler.requestRecompute).toHaveBeenCalledWith("q-1", {
      immediate: true,
    });

    const missing = await call(deps, "POST", "/questions/nope/recompute", {
      token: OWNER_TOKEN,
    });
    expect(missing.status).toBe(404);
  });

  it("deletes for the owner or the registering builder", async () => {
    const { deps, store } = createDeps();
    await call(deps, "POST", "/questions", { token: BUILDER_TOKEN, body });
    await call(deps, "POST", "/questions", { token: OWNER_TOKEN, body });

    const byBuilder = await call(deps, "DELETE", "/questions/q-1", {
      token: BUILDER_TOKEN,
    });
    expect(byBuilder.status).toBe(200);
    expect(await store.get("q-1")).toBeNull();

    const foreign = await call(deps, "DELETE", "/questions/q-2", {
      token: BUILDER_TOKEN,
    });
    expect(foreign.status).toBe(404);
    expect(await store.get("q-2")).not.toBeNull();

    const byOwner = await call(deps, "DELETE", "/questions/q-2", {
      token: OWNER_TOKEN,
    });
    expect(byOwner.status).toBe(200);
    expect(await store.list()).toEqual([]);
  });

  it("answers 404 / 405 for unknown paths and methods", async () => {
    const { deps } = createDeps();
    expect(
      (await call(deps, "GET", "/other", { token: OWNER_TOKEN })).status,
    ).toBe(404);
    expect(
      (await call(deps, "PUT", "/questions", { token: OWNER_TOKEN })).status,
    ).toBe(405);
    expect(
      (
        await call(deps, "GET", "/questions/q-1/recompute", {
          token: OWNER_TOKEN,
        })
      ).status,
    ).toBe(405);
  });
});
