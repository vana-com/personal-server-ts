import { describe, expect, it } from "vitest";

import { createVanaApi } from "./api.js";
import { mergePartiallyScanned } from "./coverage.js";
import type { QueryToolContext, QueryToolDeps, ScopeInfo } from "./types.js";

/**
 * `scopesPartiallyScanned`: the anti-sampling half of the removed `complete`
 * flag, as a list of parts.
 *
 * `complete`'s load-bearing conjunct was `#partiallyScanned.size === 0` — a
 * bounded read falsified it, so **the model could not buy a completeness claim
 * by sampling**, measured at 0 false completeness across 80 runs (design
 * §19.16). The flag went for an unrelated reason (it measured the shape of the
 * grant), and its removal folded the partial and fully-scanned sets into one
 * `scopesScanned` list, leaving nothing in the shipped surface to distinguish a
 * scope streamed end to end from one read through a window. These are the pins
 * for the property, now carried by the list rather than by the flag.
 */
const DOCS = "documents.files";
const MAIL = "email.messages";

const rows = (n: number): unknown[] =>
  Array.from({ length: n }, (_, i) => ({
    id: `d${i}`,
    text_extracted: "body",
  }));

function harness(scopeInfo: Partial<ScopeInfo> = {}) {
  const all = rows(340);
  const ctx: QueryToolContext = {
    grantedScopes: [DOCS, MAIL],
    resolveScopePath: (scope) => `/corpus/${scope}.json`,
    budget: { toolCalls: 50, outputBytes: 1_000_000 },
  };
  const deps: QueryToolDeps = {
    listScopes: async () => [
      { scope: DOCS, contentKind: "documents", ...scopeInfo },
      { scope: MAIL, contentKind: "messages" },
    ],
    streamScope: async (_scope, onItem) => {
      for (const r of all) await onItem(r);
      return 677_698;
    },
    readBlocks: async (scope, opts) => {
      const from = opts.cursor ? Number(opts.cursor) : 0;
      return all.slice(from, from + 100).map((json, i) => ({
        id: `b${from + i}`,
        scope,
        json,
        itemCount: 1,
        sizeBytes: 100,
      }));
    },
    search: async () => [],
  };
  return { ctx, deps };
}

describe("a bounded read is reported as a bounded read", () => {
  it("names the scope in scopesPartiallyScanned", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.read(DOCS, {});
    const snap = coverage.snapshot();
    expect(snap.scopesPartiallyScanned).toEqual([DOCS]);
    // Still scanned — it WAS read. The two lists say different things.
    expect(snap.scopesScanned).toEqual([DOCS]);
  });

  it("leaves the list empty after a full pass", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.readAll(DOCS);
    const snap = coverage.snapshot();
    expect(snap.scopesPartiallyScanned).toEqual([]);
    expect(snap.scopesScanned).toEqual([DOCS]);
  });

  it("leaves the list empty after a full stream", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.stream(DOCS, () => {});
    expect(coverage.snapshot().scopesPartiallyScanned).toEqual([]);
  });

  it("is a subset of scopesScanned, sorted, per scope", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.read(DOCS, {});
    await api.readAll(MAIL);
    const snap = coverage.snapshot();
    expect(snap.scopesScanned).toEqual([DOCS, MAIL]);
    expect(snap.scopesPartiallyScanned).toEqual([DOCS]);
    for (const scope of snap.scopesPartiallyScanned) {
      expect(snap.scopesScanned).toContain(scope);
    }
  });
});

/**
 * The property itself: sampling cannot be presented as a full scan.
 *
 * Stated as what a consumer computes — the fully-scanned set is
 * `scopesScanned` minus `scopesPartiallyScanned` — because that is the claim a
 * builder or the answer text would rest on. If a sampled scope can appear in
 * that difference, the model has bought a completeness claim by sampling.
 */
describe("the model cannot buy a completeness claim by sampling", () => {
  const fullyScanned = (snap: {
    scopesScanned: string[];
    scopesPartiallyScanned: string[];
  }): string[] => {
    const partial = new Set(snap.scopesPartiallyScanned);
    return snap.scopesScanned.filter((s) => !partial.has(s));
  };

  it("a windowed read never reaches the fully-scanned set", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.read(DOCS, {});
    expect(fullyScanned(coverage.snapshot())).toEqual([]);
  });

  it("many windows are still a sample, however many records they cover", async () => {
    // The tempting mistake: enough windows look like a full pass by the
    // numbers. `recordsScanned` can reach the scope's true size while the
    // scope was never exhausted, and only this list says so.
    const { ctx, deps } = harness({ itemCount: 340 });
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.scopes();
    for (let cursor = 0; cursor < 340; cursor += 100) {
      await api.read(DOCS, { cursor: String(cursor) });
    }
    const snap = coverage.snapshot();
    expect(snap.recordsScanned).toBe(340);
    expect(snap.scopesPartiallyScanned).toEqual([DOCS]);
    expect(fullyScanned(snap)).toEqual([]);
  });

  it("a sample after a full pass cannot un-cover the scope", async () => {
    // The other direction. A full pass happened; windowing afterwards is
    // ordinary code and must not read as doubt about what was covered.
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.readAll(DOCS);
    await api.read(DOCS, {});
    const snap = coverage.snapshot();
    expect(snap.scopesPartiallyScanned).toEqual([]);
    expect(fullyScanned(snap)).toEqual([DOCS]);
  });

  it("an aborted stream claims nothing at all", async () => {
    // `completeScope` is only reached after the host's loader has run to
    // exhaustion, so a script that throws out of the callback cannot mark the
    // scope covered. It reports nothing rather than a partial — which fails in
    // the safe direction.
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await expect(
      api.stream(DOCS, (_item, i) => {
        if (i > 5) throw new Error("script bailed out early");
      }),
    ).rejects.toThrow("script bailed out early");
    const snap = coverage.snapshot();
    expect(fullyScanned(snap)).toEqual([]);
    expect(snap.scopesScanned).toEqual([]);
  });
});

/**
 * The request-level rule, unit-tested directly.
 *
 * `coverage-merge.test.ts` and `lite-tool-host.merge.test.ts` drive it through
 * both hosts; these cover the shape decisions the hosts never exercise.
 */
describe("mergePartiallyScanned", () => {
  it("drops a scope some run exhausted, keeps one no run did", () => {
    expect(
      mergePartiallyScanned(
        { scopesScanned: [DOCS, MAIL], scopesPartiallyScanned: [DOCS, MAIL] },
        { scopesScanned: [MAIL], scopesPartiallyScanned: [] },
      ),
    ).toEqual([DOCS]);
  });

  it("sorts, so the result is a function of the set and not of turn order", () => {
    const a = mergePartiallyScanned(
      { scopesScanned: ["z", "a"], scopesPartiallyScanned: ["z", "a"] },
      { scopesScanned: [], scopesPartiallyScanned: [] },
    );
    const b = mergePartiallyScanned(
      { scopesScanned: ["a", "z"], scopesPartiallyScanned: ["a", "z"] },
      { scopesScanned: [], scopesPartiallyScanned: [] },
    );
    expect(a).toEqual(["a", "z"]);
    expect(a).toEqual(b);
  });

  it("fails closed on a frame that declares no list", () => {
    // The field is required by the type and `decodeResultFrame` does not check
    // it, so absence means a violated contract. Reading it as "nothing was
    // partial" would let such a frame promote its scopes to fully scanned;
    // reading it as "everything it read might be partial" can only
    // over-report doubt.
    const merged = mergePartiallyScanned(
      { scopesScanned: [DOCS], scopesPartiallyScanned: [DOCS] },
      {
        scopesScanned: [DOCS],
        scopesPartiallyScanned: undefined as unknown as string[],
      },
    );
    expect(merged).toEqual([DOCS]);
  });
});
