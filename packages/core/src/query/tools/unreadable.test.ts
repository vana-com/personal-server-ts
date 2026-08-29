import { describe, expect, it } from "vitest";

import { CoverageLedger } from "./coverage.js";
import { createVanaApi, isUnreadableRecord } from "./api.js";
import type { QueryToolContext, QueryToolDeps } from "./types.js";

/**
 * `coverage.unreadable` is what makes an absence answer honest.
 *
 * Q8 in the dogfood benchmark answered "no conflicting agreement across 318
 * readable documents" — the right answer and the right denominator — and was
 * graded a failure only because this counter was never populated. The model
 * behaved correctly; the host did not.
 */
describe("unreadable records are counted by the host", () => {
  const rows = [
    { id: "d1", text_extracted: "readable", extraction_error: null },
    { id: "d2", text_extracted: null, extraction_error: "scanned image" },
    { id: "d3", text_extracted: null, extraction_error: "scanned image" },
    { id: "d4", text_extracted: "also readable", extraction_error: null },
  ];

  const ctx: QueryToolContext = {
    grantedScopes: ["documents.files"],
    resolveScopePath: (s: string) => `/data/${s}.json`,
    budget: { toolCalls: 20, outputBytes: 1_000_000 },
  } as unknown as QueryToolContext;

  const deps = (): QueryToolDeps =>
    ({
      listScopes: async () => [{ scope: "documents.files" }],
      streamScope: async (
        _scope: string,
        onItem: (item: unknown) => void | Promise<void>,
      ) => {
        for (const r of rows) await onItem(r);
        return 1234;
      },
      readBlocks: async () =>
        rows.map((r) => ({ id: r.id, scope: "documents.files", json: r })),
      search: async () => [],
      classify: async () => ({ values: [], usd: 0 }),
      introspect: async () => ({ grants: [], accessLog: [], lineage: [] }),
    }) as unknown as QueryToolDeps;

  it("recognises the marker, and only with an explicit reason", () => {
    expect(isUnreadableRecord(rows[1])).toBe(true);
    expect(isUnreadableRecord(rows[0])).toBe(false);
    // A record that merely lacks text is NOT unreadable. Counting those would
    // inflate the number and corrupt the absence answers it exists to serve.
    expect(isUnreadableRecord({ id: "x" })).toBe(false);
    expect(isUnreadableRecord({ extraction_error: "" })).toBe(false);
    expect(isUnreadableRecord({ extraction_error: null })).toBe(false);
    expect(isUnreadableRecord(null)).toBe(false);
    expect(isUnreadableRecord("a string")).toBe(false);
  });

  it("counts them on readAll", async () => {
    const { api, state } = createVanaApi(ctx, deps());
    await api.readAll("documents.files");
    const snap = state().coverage.snapshot();
    expect(snap.recordsScanned).toBe(4);
    expect(snap.unreadable).toBe(2);
  });

  it("counts them on stream", async () => {
    const { api, state } = createVanaApi(ctx, deps());
    await api.stream("documents.files", () => {});
    expect(state().coverage.snapshot().unreadable).toBe(2);
  });

  it("counts them on read (blocks)", async () => {
    const { api, state } = createVanaApi(ctx, deps());
    await api.read("documents.files");
    expect(state().coverage.snapshot().unreadable).toBe(2);
  });

  it("is host-authored: the ledger is never reachable from a script", () => {
    // The ledger is closed over by the API factory and never bound into the
    // script's realm, so incrementing it is the only way the number moves.
    const ledger = new CoverageLedger(["documents.files"]);
    ledger.unreadableRead(2);
    expect(ledger.snapshot().unreadable).toBe(2);
    const { api } = createVanaApi(ctx, deps());
    expect(Object.keys(api)).not.toContain("coverage");
  });
});
