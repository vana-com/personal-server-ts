import { describe, expect, it } from "vitest";

import { createVanaApi } from "./api.js";
import type { QueryToolContext, QueryToolDeps, ScopeInfo } from "./types.js";

/**
 * Regression suite for a P1 found live: re-reading a scope double-counted
 * every coverage counter.
 *
 * Q8 over a 340-document scope reported `recordsScanned: 680` and
 * `unreadable: 44` against 22 planted, because the script read the scope
 * twice — once to count, once to filter, which is ordinary code — and the
 * ledger accumulated unconditionally. An inflated denominator makes an
 * absence claim look better founded than it is, which is the precise shape of
 * the worst failure in the system (design §3 Q8, §4.3 point 1).
 */
const DOCS = "documents.files";

const rows = (n: number, unreadable: number): unknown[] =>
  Array.from({ length: n }, (_, i) =>
    i < unreadable
      ? { id: `d${i}`, text_extracted: null, extraction_error: "scanned image" }
      : { id: `d${i}`, text_extracted: "readable body" },
  );

function harness(scopeInfo: Partial<ScopeInfo> = {}) {
  const all = rows(340, 22);
  const ctx: QueryToolContext = {
    grantedScopes: [DOCS],
    resolveScopePath: () => "/corpus/documents.json",
    budget: { toolCalls: 50, outputBytes: 1_000_000 },
  };
  const deps: QueryToolDeps = {
    listScopes: async () => [
      { scope: DOCS, contentKind: "documents", ...scopeInfo },
    ],
    streamScope: async (_scope, onItem) => {
      for (const r of all) await onItem(r);
      return 677_698;
    },
    readBlocks: async (_scope, opts) => {
      const from = opts.cursor ? Number(opts.cursor) : 0;
      return all.slice(from, from + 100).map((json, i) => ({
        id: `b${from + i}`,
        scope: DOCS,
        json,
        itemCount: 1,
        sizeBytes: 100,
      }));
    },
    search: async () => [],
  };
  return { ctx, deps };
}

describe("a re-read covers the same records, not twice as many", () => {
  it("counts one full pass once", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.readAll(DOCS);
    const snap = coverage.snapshot();
    expect(snap.recordsScanned).toBe(340);
    expect(snap.unreadable).toBe(22);
  });

  it("counts two full passes ONCE — the live Q8 bug", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.readAll(DOCS); // count
    await api.readAll(DOCS); // filter
    const snap = coverage.snapshot();
    expect(snap.recordsScanned, "was 680 before the fix").toBe(340);
    expect(snap.unreadable, "was 44 before the fix").toBe(22);
    expect(snap.bytesScanned).toBe(677_698);
  });

  it("counts a stream and a readAll of one scope once", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.stream(DOCS, () => {});
    await api.readAll(DOCS);
    expect(coverage.snapshot().recordsScanned).toBe(340);
  });

  it("lets disjoint partial reads add up", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.read(DOCS, {});
    await api.read(DOCS, { cursor: "100" });
    // Two distinct windows really do cover more than one.
    expect(coverage.snapshot().recordsScanned).toBe(200);
  });

  it("NEVER exceeds the scope's true size, even on overlapping reads", async () => {
    // The invariant that makes a denominator trustworthy.
    const { ctx, deps } = harness({ itemCount: 340 });
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.scopes(); // declares the size
    for (let i = 0; i < 10; i++) await api.read(DOCS, {}); // same window, 10x
    const snap = coverage.snapshot();
    expect(snap.recordsScanned).toBeLessThanOrEqual(340);
  });

  it("a full pass subsumes a partial read of the same scope", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.read(DOCS, {}); // 100 records
    await api.readAll(DOCS); // all 340
    // You cannot cover more than all of it.
    expect(coverage.snapshot().recordsScanned).toBe(340);
  });

  it("attributes per scope so the cross-run merge can dedupe", async () => {
    const { ctx, deps } = harness();
    const { api, state } = createVanaApi(ctx, deps);
    const coverage = state().coverage;
    await api.readAll(DOCS);
    expect(coverage.snapshot().perScope[DOCS]).toEqual({
      records: 340,
      bytes: 677_698,
      unreadable: 22,
    });
  });
});
