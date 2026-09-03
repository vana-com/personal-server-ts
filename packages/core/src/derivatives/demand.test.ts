/**
 * The read side of demand-driven recompute: GET /v1/data/:scope is what
 * pays for a stale derivative, and only when the caller was allowed to read
 * it. The whole path is wired here (data route -> onDataRead -> the real
 * scheduler) because the guarantees under test are about the seam: one
 * compute for N readers, none at all for a refused reader, and a read that
 * never waits on inference.
 */

import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "../api/index.js";
import { ingestDataContract } from "../contracts/data.js";
import { NotOwnerError, ScopeMismatchError } from "../errors/catalog.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { createRecomputeScheduler } from "./scheduler.js";
import { createInMemoryQuestionStore } from "./store.js";
import type { QuestionRegistration } from "./types.js";

const READER_TOKEN = "reader-token";
const OWNER_TOKEN = "owner-token";
const BUILDER = "0x2222222222222222222222222222222222222222" as const;
const DERIVED_SCOPE = "coach.weekly";

function registration(
  overrides: Partial<QuestionRegistration> = {},
): QuestionRegistration {
  return {
    questionId: "q-1",
    derivedScope: DERIVED_SCOPE,
    sourceScopes: ["oura.sleep"],
    question: "How did I sleep?",
    model: null,
    recompute: "on-change",
    registeredBy: { kind: "owner" },
    status: "stale",
    error: null,
    errorCode: null,
    createdAt: "2026-08-27T00:00:00.000Z",
    updatedAt: "2026-08-27T00:00:00.000Z",
    lastComputedAt: "2026-08-27T00:00:00.000Z",
    derivedVersion: 1,
    derivedCollectedAt: "2026-08-20T00:00:00Z",
    ...overrides,
  };
}

function bearer(request: Request): string | null {
  return request.headers.get("authorization")?.replace(/^Bearer /, "") ?? null;
}

/**
 * A Personal Server whose data route wakes the compute layer, with the
 * compute itself under the test's control: it resolves only when the test
 * releases it, so "while the recompute runs" is a real window and not a
 * race with the fake.
 */
function harness(
  options: {
    initial?: QuestionRegistration[];
    /** Runs when the gate opens, before the compute resolves. */
    onCompute?: (questionId: string) => Promise<void>;
  } = {},
) {
  const storage = createMemoryDataStorage();
  const store = createInMemoryQuestionStore({
    initial: options.initial ?? [registration()],
  });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const compute = vi.fn(async (questionId: string) => {
    await gate;
    await options.onCompute?.(questionId);
    return undefined;
  });
  const scheduler = createRecomputeScheduler({
    store,
    compute,
    debounceMs: 0,
  });
  const deps: PersonalServerDataApiDeps = {
    storage,
    auth: {
      async authorizeOwner(request) {
        if (bearer(request) !== OWNER_TOKEN) throw new NotOwnerError();
      },
      async authorizeBuilderList() {},
      async authorizeBuilderRead({ request, scope }) {
        // Mirrors the real adapters: the owner passes, a reader passes only
        // for a scope its grant covers, anything else fails closed.
        if (bearer(request) === OWNER_TOKEN) {
          return { builder: "owner", grantId: "owner" };
        }
        if (bearer(request) === READER_TOKEN) {
          if (scope !== DERIVED_SCOPE) {
            throw new ScopeMismatchError({ requestedScope: scope });
          }
          return { builder: BUILDER, grantId: "read-grant-1" };
        }
        throw new NotOwnerError();
      },
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
    onDataRead: (event) => scheduler.markDemand(event.scope),
  };
  return { compute, deps, release, scheduler, storage, store };
}

async function seed(
  storage: ReturnType<typeof createMemoryDataStorage>,
  scope: string,
  body: Record<string, unknown>,
  collectedAt: string,
) {
  const result = await ingestDataContract({
    storage,
    scopeParam: scope,
    body,
    collectedAt,
    status: "stored",
  });
  if (!result.ok) throw new Error("seed failed");
}

/**
 * Demand never runs inline with the read (that is the point: a read is
 * never held up by inference), so the test hands the event loop over until
 * the scheduler's zero-delay timer has fired.
 */
async function settle(predicate: () => boolean = () => false): Promise<void> {
  for (let attempt = 0; attempt < 50 && !predicate(); attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

function read(
  deps: PersonalServerDataApiDeps,
  scope: string,
  token?: string,
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  return handlePersonalServerDataRequest(
    new Request(`http://ps.local/v1/data/${scope}`, { headers }),
    deps,
    { basePath: "/v1/data" },
  );
}

describe("an authorized read is the demand that recomputes a derivative", () => {
  it("triggers exactly one compute and serves the version already stored", async () => {
    const h = harness({
      onCompute: async (questionId) => {
        await seed(
          h.storage,
          DERIVED_SCOPE,
          { answer: "the fresh one" },
          "2026-08-21T00:00:00Z",
        );
        await h.store.update(questionId, {
          status: "ready",
          derivedVersion: 2,
          updatedAt: "2026-08-21T00:00:00.000Z",
        });
      },
    });
    await seed(
      h.storage,
      DERIVED_SCOPE,
      { answer: "the stale one" },
      "2026-08-20T00:00:00Z",
    );

    const res = await read(h.deps, DERIVED_SCOPE, READER_TOKEN);
    expect(res.status).toBe(200);
    // Stale is not wrong: the reader gets the answer that is stored, and
    // the recompute it just paid for has not even started.
    expect((await res.json()).data.answer).toBe("the stale one");
    await settle(() => h.compute.mock.calls.length > 0);
    expect(h.compute).toHaveBeenCalledTimes(1);
    expect(h.compute).toHaveBeenCalledWith("q-1");

    h.release();
    await h.scheduler.whenIdle();
    const fresh = await read(h.deps, DERIVED_SCOPE, READER_TOKEN);
    expect((await fresh.json()).data.answer).toBe("the fresh one");
    // The question is ready now, so reading it again buys no inference.
    await h.scheduler.whenIdle();
    expect(h.compute).toHaveBeenCalledTimes(1);
    h.scheduler.stop();
  });

  it("collapses concurrent readers into one compute", async () => {
    const h = harness();
    await seed(
      h.storage,
      DERIVED_SCOPE,
      { answer: "v1" },
      "2026-08-20T00:00:00Z",
    );

    const responses = await Promise.all(
      Array.from({ length: 8 }, () =>
        read(h.deps, DERIVED_SCOPE, READER_TOKEN),
      ),
    );
    expect(responses.every((res) => res.status === 200)).toBe(true);
    await settle(() => h.compute.mock.calls.length > 0);
    // Eight readers, one inference bill: the trigger goes through the
    // scheduler, which already runs one compute per question.
    expect(h.compute).toHaveBeenCalledTimes(1);
    h.release();
    await h.scheduler.whenIdle();
    expect(h.compute).toHaveBeenCalledTimes(1);
    h.scheduler.stop();
  });

  it("never computes for a refused or unauthenticated read", async () => {
    const h = harness();
    await seed(
      h.storage,
      DERIVED_SCOPE,
      { answer: "v1" },
      "2026-08-20T00:00:00Z",
    );

    // No credential at all.
    expect((await read(h.deps, DERIVED_SCOPE)).status).toBe(401);
    // A grant that does not cover the derived scope. The reader's token is
    // good for `coach.weekly` only, so it is refused on another scope and
    // must not be able to spend an inference call on this one either.
    expect((await read(h.deps, "other.scope", READER_TOKEN)).status).toBe(403);
    await settle();
    expect(h.compute).not.toHaveBeenCalled();
    h.scheduler.stop();
  });

  it("wakes the question on a read that finds nothing stored", async () => {
    // Nothing was ever computed: the read answers 404 exactly as before and
    // the reader polls the status route, but the compute it asked for is
    // now on its way.
    const h = harness({ initial: [registration({ status: "pending" })] });
    const res = await read(h.deps, DERIVED_SCOPE, OWNER_TOKEN);
    expect(res.status).toBe(404);
    await settle(() => h.compute.mock.calls.length > 0);
    expect(h.compute).toHaveBeenCalledTimes(1);
    h.release();
    await h.scheduler.whenIdle();
    h.scheduler.stop();
  });

  it("leaves a snapshot question alone", async () => {
    const h = harness({
      initial: [registration({ recompute: "snapshot", status: "stale" })],
    });
    await seed(
      h.storage,
      DERIVED_SCOPE,
      { answer: "v1" },
      "2026-08-20T00:00:00Z",
    );
    expect((await read(h.deps, DERIVED_SCOPE, READER_TOKEN)).status).toBe(200);
    await settle();
    expect(h.compute).not.toHaveBeenCalled();
    h.scheduler.stop();
  });
});
