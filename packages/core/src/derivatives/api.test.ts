import { describe, expect, it, vi } from "vitest";
import { NotOwnerError, ScopeMismatchError } from "../errors/catalog.js";
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
const READER_TOKEN = "reader-token";
const BUILDER = "0x2222222222222222222222222222222222222222" as const;
const OTHER_READER = "0x3333333333333333333333333333333333333333" as const;
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
    /** Scopes a READER_TOKEN read grant covers (status route tests). */
    readScopes?: string[];
    /**
     * Who the READER_TOKEN is. Defaults to the registering builder, which is
     * the common case (a builder reading back its own answer); a test that
     * needs a THIRD-PARTY reader sets a different address.
     */
    readerBuilder?: `0x${string}`;
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
  const readScopes = options.readScopes ?? ["coach.weekly"];
  return {
    async authorizeOwner(request) {
      if (token(request) !== OWNER_TOKEN) throw new NotOwnerError();
    },
    async authorizeBuilderList() {},
    async authorizeBuilderRead({ request, scope }) {
      // Mirrors the real adapters: the owner passes, a reader passes only
      // for a scope its grant covers, anything else fails closed.
      if (token(request) === OWNER_TOKEN) {
        return { builder: "owner", grantId: "owner" };
      }
      if (token(request) === READER_TOKEN) {
        if (!readScopes.includes(scope)) {
          throw new ScopeMismatchError({ requestedScope: scope });
        }
        return {
          builder: options.readerBuilder ?? builder,
          grantId: "read-grant-1",
        };
      }
      throw new NotOwnerError();
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
    async authorizeWriteSession(request) {
      // Identity only, as the real port does: the bearer resolves to a live
      // write session, no scope is authorized.
      if (token(request) !== BUILDER_TOKEN) return undefined;
      return {
        builder,
        grantId: "grant-1",
        releaseProof: vi.fn(async () => undefined),
      };
    },
  };
}

function createDeps(overrides: Partial<PersonalServerDerivativesApiDeps> = {}) {
  const store = createInMemoryQuestionStore();
  const scheduler = {
    requestRecompute: vi.fn(),
    markSourceChanged: vi.fn(),
    markDemand: vi.fn(),
  } satisfies Pick<
    RecomputeScheduler,
    "requestRecompute" | "markSourceChanged" | "markDemand"
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
      recompute: "on-change",
      registeredBy: { kind: "owner" },
    });
    expect(await store.get("q-1")).not.toBeNull();
    expect(scheduler.requestRecompute).toHaveBeenCalledWith("q-1", {
      immediate: true,
    });
  });

  it("stores an explicit recompute policy and rejects an unknown one", async () => {
    const { deps, store } = createDeps();
    const res = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body: { ...body, recompute: "snapshot" },
    });
    expect(res.status).toBe(201);
    expect((await res.json()).recompute).toBe("snapshot");
    expect((await store.get("q-1"))!.recompute).toBe("snapshot");

    const invalid = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body: { ...body, derivedScope: "spine.summary", recompute: "weekly" },
    });
    expect(invalid.status).toBe(400);
    expect((await invalid.json()).error.errorCode).toBe(
      "DERIVATIVE_QUESTION_INVALID",
    );
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

    // No scope: the owner-only list. A builder gets the missing-parameter
    // answer, not a 401 that would send it re-handshaking for nothing.
    const noScope = await call(deps, "GET", "/questions", {
      token: BUILDER_TOKEN,
    });
    expect(noScope.status).toBe(400);
    expect((await noScope.json()).error.errorCode).toBe(
      "DERIVATIVE_DERIVED_SCOPE_REQUIRED",
    );

    // An anonymous caller still gets the owner gate's 401.
    const anonymous = await call(deps, "GET", "/questions");
    expect(anonymous.status).toBe(401);

    // An auth port with no write sessions (PS-Lite) is unchanged.
    const ownerOnly = createDeps();
    ownerOnly.deps.auth = {
      ...ownerOnly.deps.auth,
      authorizeWriteSession: undefined,
    };
    expect(
      (
        await call(ownerOnly.deps, "GET", "/questions", {
          token: BUILDER_TOKEN,
        })
      ).status,
    ).toBe(401);
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

    // An unknown id is 404 for a builder holding a live write session: it
    // already gets 404 for another builder's question, so nothing new leaks,
    // and a 401 here would burn a handshake and report the wrong problem.
    const unknownAsBuilder = await call(deps, "GET", "/questions/nope", {
      token: BUILDER_TOKEN,
    });
    expect(unknownAsBuilder.status).toBe(404);
    expect((await unknownAsBuilder.json()).error.errorCode).toBe(
      "DERIVATIVE_QUESTION_NOT_FOUND",
    );
    // Unauthenticated callers still get the owner gate.
    expect((await call(deps, "GET", "/questions/nope")).status).toBe(401);
    expect(
      (await call(deps, "DELETE", "/questions/nope", { token: BUILDER_TOKEN }))
        .status,
    ).toBe(404);
    expect(
      (
        await call(deps, "POST", "/questions/nope/recompute", {
          token: BUILDER_TOKEN,
        })
      ).status,
    ).toBe(404);
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
    // The full registration view, like every other route: one schema.
    expect(await owner.json()).toEqual({
      questionId: "q-1",
      derivedScope: "coach.weekly",
      sourceScopes: ["oura.sleep"],
      question: "How did I sleep?",
      model: null,
      recompute: "on-change",
      registeredBy: { kind: "builder", builder: BUILDER, grantId: "grant-1" },
      status: "pending",
      error: null,
      errorCode: null,
      createdAt: "2026-08-27T10:00:00.000Z",
      updatedAt: "2026-08-27T10:00:00.000Z",
      lastComputedAt: null,
      derivedVersion: null,
      derivedCollectedAt: null,
    });
    expect(scheduler.requestRecompute).toHaveBeenCalledWith("q-1", {
      immediate: true,
    });

    // A question that already computed reports the status the scheduled run
    // starts from, with the rest of the view intact.
    await deps.compute!.store.update("q-1", {
      status: "ready",
      derivedVersion: 2,
      lastComputedAt: "2026-08-27T11:00:00.000Z",
    });
    const again = await call(deps, "POST", "/questions/q-1/recompute", {
      token: OWNER_TOKEN,
    });
    expect(await again.json()).toMatchObject({
      questionId: "q-1",
      status: "stale",
      derivedVersion: 2,
      lastComputedAt: "2026-08-27T11:00:00.000Z",
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

describe("GET /v1/derivatives/status", () => {
  async function seedOwnerQuestion(
    deps: PersonalServerDerivativesApiDeps,
  ): Promise<string> {
    const res = await call(deps, "POST", "/questions", {
      token: OWNER_TOKEN,
      body,
    });
    expect(res.status).toBe(201);
    return ((await res.json()) as { questionId: string }).questionId;
  }

  it("requires a derivedScope query", async () => {
    const { deps } = createDeps();
    const res = await call(deps, "GET", "/status", { token: READER_TOKEN });
    expect(res.status).toBe(400);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_DERIVED_SCOPE_REQUIRED",
    );
  });

  it("authorizes before looking anything up: an uncovered scope is refused even when a question exists", async () => {
    const { deps } = createDeps({ auth: createAuth({ readScopes: [] }) });
    await seedOwnerQuestion(deps);
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    expect(res.status).toBe(403);
    expect((await res.json()).error.errorCode).toBe("SCOPE_MISMATCH");
  });

  it("answers 404 for a covered scope with no registered question", async () => {
    const { deps } = createDeps();
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    expect(res.status).toBe(404);
    expect((await res.json()).error.errorCode).toBe(
      "DERIVATIVE_QUESTION_NOT_FOUND",
    );
  });

  it("shows a reader the lifecycle of an owner-registered question and nothing else", async () => {
    const { deps } = createDeps();
    await seedOwnerQuestion(deps);
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(Object.keys(json).sort()).toEqual([
      "derivedCollectedAt",
      "derivedScope",
      "derivedVersion",
      "errorCode",
      "lastComputedAt",
      "retryAfterSeconds",
      "status",
    ]);
    expect(json).toEqual({
      derivedScope: "coach.weekly",
      status: "pending",
      lastComputedAt: null,
      derivedVersion: null,
      derivedCollectedAt: null,
      errorCode: null,
      retryAfterSeconds: null,
    });
  });

  it("never discloses the question text, sources, id, registrar, model or raw error", async () => {
    const { deps, store } = createDeps();
    const questionId = await seedOwnerQuestion(deps);
    await store.update(questionId, {
      status: "failed",
      error: "source scope oura.sleep is deleted",
      updatedAt: "2026-08-27T11:00:00.000Z",
    });
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain("oura.sleep");
    expect(text).not.toContain("How did I sleep?");
    expect(text).not.toContain(questionId);
    expect(text).not.toContain("owner");
  });

  it("serves the owner through the same route", async () => {
    const { deps } = createDeps();
    await seedOwnerQuestion(deps);
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: OWNER_TOKEN,
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { status: string }).status).toBe("pending");
  });

  it("a served answer wins over a newer failed duplicate on the same scope", async () => {
    // Data serving is registration-agnostic: if any registration is ready,
    // the scope HAS an answer, and the reader must not be told "failed" by
    // a duplicate that never wrote anything.
    const { deps, store } = createDeps();
    const first = await seedOwnerQuestion(deps);
    const second = await seedOwnerQuestion(deps);
    await store.update(first, {
      status: "ready",
      updatedAt: "2026-08-27T10:00:01.000Z",
      lastComputedAt: "2026-08-27T10:00:01.000Z",
      derivedVersion: 3,
    });
    await store.update(second, {
      status: "failed",
      error: "upstream down",
      updatedAt: "2026-08-27T12:00:00.000Z",
    });
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    const json = (await res.json()) as {
      status: string;
      derivedVersion: number | null;
    };
    expect(json.status).toBe("ready");
    expect(json.derivedVersion).toBe(3);
  });

  it("an in-flight recompute wins over failed; among equals the newest speaks", async () => {
    const { deps, store } = createDeps();
    const first = await seedOwnerQuestion(deps);
    const second = await seedOwnerQuestion(deps);
    const third = await seedOwnerQuestion(deps);
    await store.update(first, {
      status: "failed",
      updatedAt: "2026-08-27T12:00:00.000Z",
    });
    await store.update(second, {
      status: "stale",
      updatedAt: "2026-08-27T10:00:01.000Z",
    });
    await store.update(third, {
      status: "failed",
      updatedAt: "2026-08-27T11:00:00.000Z",
    });
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    expect(((await res.json()) as { status: string }).status).toBe("stale");

    // All failed: the newest failure is the one that speaks.
    await store.update(second, {
      status: "failed",
      error: "later",
      errorCode: "internal",
      updatedAt: "2026-08-27T13:00:00.000Z",
    });
    const allFailed = await call(
      deps,
      "GET",
      "/status?derivedScope=coach.weekly",
      { token: READER_TOKEN },
    );
    const json = (await allFailed.json()) as { errorCode: string | null };
    expect(json.errorCode).toBe("internal");
  });

  it("computes retryAfterSeconds from the scheduler's next retry", async () => {
    const store = createInMemoryQuestionStore();
    const scheduler = {
      requestRecompute: vi.fn(),
      markSourceChanged: vi.fn(),
      markDemand: vi.fn(),
      nextRetryAt: vi.fn(() => "2026-08-27T10:05:00.000Z"),
    };
    const { deps } = createDeps({ compute: { store, scheduler } });
    await seedOwnerQuestion(deps);
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    const json = (await res.json()) as { retryAfterSeconds: number | null };
    expect(json.retryAfterSeconds).toBe(300);
  });

  it("hides grant_invalid from a reader that did not register the question", async () => {
    // Only a builder-registered question runs the live grant re-check, so
    // grant_invalid names the registrar class the rest of this view hides.
    const { deps, store } = createDeps({
      auth: createAuth({ readerBuilder: OTHER_READER }),
    });
    const registered = await call(deps, "POST", "/questions", {
      token: BUILDER_TOKEN,
      body,
    });
    expect(registered.status).toBe(201);
    const { questionId } = (await registered.json()) as { questionId: string };
    await store.update(questionId, {
      status: "failed",
      error: "grant no longer covers oura.sleep",
      errorCode: "grant_invalid",
      updatedAt: "2026-08-27T11:00:00.000Z",
    });

    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    const json = (await res.json()) as { status: string; errorCode: string };
    expect(json.status).toBe("failed");
    expect(json.errorCode).toBe("internal");
  });

  it("serves grant_invalid to the registrar and to the owner", async () => {
    const { deps, store } = createDeps();
    const registered = await call(deps, "POST", "/questions", {
      token: BUILDER_TOKEN,
      body,
    });
    const { questionId } = (await registered.json()) as { questionId: string };
    await store.update(questionId, {
      status: "failed",
      error: "grant no longer covers oura.sleep",
      errorCode: "grant_invalid",
      updatedAt: "2026-08-27T11:00:00.000Z",
    });

    // The default reader IS the registering builder: it learns nothing about
    // itself that it did not already know, and this is the class it can act on.
    const registrar = await call(
      deps,
      "GET",
      "/status?derivedScope=coach.weekly",
      { token: READER_TOKEN },
    );
    expect(((await registrar.json()) as { errorCode: string }).errorCode).toBe(
      "grant_invalid",
    );

    const asOwner = await call(
      deps,
      "GET",
      "/status?derivedScope=coach.weekly",
      {
        token: OWNER_TOKEN,
      },
    );
    expect(((await asOwner.json()) as { errorCode: string }).errorCode).toBe(
      "grant_invalid",
    );
  });

  it("never serves an errorCode for a non-failed status", async () => {
    // A stale row can still carry an old errorCode (stores written before
    // markStale cleared it). The reader contract is: null unless failed.
    const { deps, store } = createDeps();
    const questionId = await seedOwnerQuestion(deps);
    await store.update(questionId, {
      status: "stale",
      error: "upstream down",
      errorCode: "inference_unavailable",
      updatedAt: "2026-08-27T11:00:00.000Z",
    });
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    const json = (await res.json()) as {
      status: string;
      errorCode: string | null;
    };
    expect(json.status).toBe("stale");
    expect(json.errorCode).toBeNull();
  });

  it("refuses a scope that fails the grammar before authorizing anything", async () => {
    const auth = createAuth();
    const readSpy = vi.spyOn(auth, "authorizeBuilderRead");
    const { deps } = createDeps({ auth });
    const res = await call(
      deps,
      "GET",
      "/status?derivedScope=Not%20A%20Scope",
      { token: READER_TOKEN },
    );
    expect(res.status).toBe(400);
    expect((await res.json()).error.errorCode).toBe("INVALID_SCOPE");
    expect(readSpy).not.toHaveBeenCalled();
  });

  it("serves a short poll hint while the retry compute is in flight", async () => {
    const store = createInMemoryQuestionStore();
    const scheduler = {
      requestRecompute: vi.fn(),
      markSourceChanged: vi.fn(),
      markDemand: vi.fn(),
      nextRetryAt: vi.fn(() => null),
      retryInFlight: vi.fn(() => true),
    };
    const { deps } = createDeps({ compute: { store, scheduler } });
    const questionId = await seedOwnerQuestion(deps);
    await store.update(questionId, {
      status: "failed",
      error: "upstream down",
      errorCode: "inference_unavailable",
      updatedAt: "2026-08-27T11:00:00.000Z",
    });
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    const json = (await res.json()) as { retryAfterSeconds: number | null };
    // Not null: null is the terminal "will never retry" signature, and a
    // retry is running right now. Not 0: that invites a tight poll loop.
    expect(json.retryAfterSeconds).toBe(5);
  });

  it("an authorized poll is demand: it asks the scheduler to run the question", async () => {
    const { deps, scheduler } = createDeps();
    await seedOwnerQuestion(deps);
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    expect(res.status).toBe(200);
    expect(scheduler.markDemand).toHaveBeenCalledWith("coach.weekly");
    // Once per poll, and always through the scheduler, which is where
    // concurrent demand collapses into a single compute.
    expect(scheduler.markDemand).toHaveBeenCalledTimes(1);
  });

  it("the owner's poll is demand too", async () => {
    const { deps, scheduler } = createDeps();
    await seedOwnerQuestion(deps);
    await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: OWNER_TOKEN,
    });
    expect(scheduler.markDemand).toHaveBeenCalledWith("coach.weekly");
  });

  it("a refused or unauthenticated poll never becomes demand", async () => {
    // Cost is the reason compute waits for a reader, so the trigger sits
    // strictly behind the same gate as the data read: an uncovered grant,
    // an unknown credential and a scope that fails the grammar all spend
    // nothing.
    const { deps, scheduler } = createDeps({
      auth: createAuth({ readScopes: [] }),
    });
    await seedOwnerQuestion(deps);
    const refused = await call(
      deps,
      "GET",
      "/status?derivedScope=coach.weekly",
      { token: READER_TOKEN },
    );
    expect(refused.status).toBe(403);
    const anonymous = await call(
      deps,
      "GET",
      "/status?derivedScope=coach.weekly",
    );
    expect(anonymous.status).toBe(401);
    const malformed = await call(
      deps,
      "GET",
      "/status?derivedScope=Not%20A%20Scope",
      { token: READER_TOKEN },
    );
    expect(malformed.status).toBe(400);
    expect(scheduler.markDemand).not.toHaveBeenCalled();
  });

  it("a covered scope with no question behind it wakes nothing", async () => {
    const { deps, scheduler } = createDeps();
    const res = await call(deps, "GET", "/status?derivedScope=coach.weekly", {
      token: READER_TOKEN,
    });
    expect(res.status).toBe(404);
    expect(scheduler.markDemand).not.toHaveBeenCalled();
  });

  it("only accepts GET", async () => {
    const { deps } = createDeps();
    const res = await call(deps, "POST", "/status?derivedScope=coach.weekly", {
      token: OWNER_TOKEN,
    });
    expect(res.status).toBe(405);
  });
});
