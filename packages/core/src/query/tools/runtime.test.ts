import { describe, expect, it } from "vitest";
import { runQueryScript } from "./runtime.js";
import type { QueryToolContext, QueryToolDeps, ScopeInfo } from "./types.js";

const SCOPES: Record<string, unknown[]> = {
  "oura.sleep": [
    { day: "2026-01-01", type: "long_sleep", total_sleep_duration: 25200 },
    { day: "2026-01-01", type: "late_nap", total_sleep_duration: 1800 },
    { day: "2026-01-02", type: "long_sleep", total_sleep_duration: 23400 },
  ],
  "spotify.streams": [
    { ts: "2026-01-01T00:00:00Z" },
    { ts: "2026-01-02T00:00:00Z" },
  ],
  "secret.notes": [{ text: "NOT GRANTED" }],
};

function makeCtx(granted: string[], budget = 50): QueryToolContext {
  return {
    grantedScopes: granted,
    resolveScopePath: (scope) => {
      if (!granted.includes(scope)) {
        throw new Error(`scope "${scope}" is not in this grant`);
      }
      return `/data/${scope}.json`;
    },
    budget: { toolCalls: budget, outputBytes: 1_000_000 },
  };
}

function makeDeps(over: Partial<QueryToolDeps> = {}): QueryToolDeps {
  return {
    listScopes: async (): Promise<ScopeInfo[]> =>
      Object.keys(SCOPES).map((scope) => ({
        scope,
        itemCount: SCOPES[scope]!.length,
      })),
    streamScope: async (scope, onItem) => {
      for (const item of SCOPES[scope] ?? []) await onItem(item);
    },
    readBlocks: async (scope) => [
      { id: `${scope}#0`, scope, itemCount: 1, sizeBytes: 100 },
    ],
    search: async () => [{ id: "h1", scope: "oura.sleep", score: 1 }],
    ...over,
  };
}

describe("grant binding", () => {
  it("hides ungranted scopes from vana.scopes()", async () => {
    const out = await runQueryScript(
      `const s = await vana.scopes(); vana.result({ answer: s.map((x) => x.scope).join(",") });`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(out.result?.answer).toBe("oura.sleep");
    expect(out.result?.answer).not.toContain("secret.notes");
  });

  it("throws rather than returning empty for an ungranted scope", async () => {
    // Returning [] would let the script conclude "there is nothing there" —
    // the false negative the absence class must never produce.
    const out = await runQueryScript(
      `await vana.readAll("secret.notes");`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(out.error?.code).toBe("SCOPE_NOT_GRANTED");
    expect(out.coverage.scopesScanned).toEqual([]);
  });

  it("refuses an ungranted scope passed to search", async () => {
    const out = await runQueryScript(
      `await vana.search("x", { scopes: ["secret.notes"] });`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(out.error?.code).toBe("SCOPE_NOT_GRANTED");
  });
});

describe("coverage is host-authored (prompt contract §1)", () => {
  it("counts records the host streamed, not what the script claims", async () => {
    const out = await runQueryScript(
      `
      const rows = await vana.readAll("oura.sleep");
      vana.result({ answer: "I scanned 999999 records and found everything" });
      `,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    // The prose says 999999; the ledger says 3. The ledger is the fact.
    expect(out.coverage.recordsScanned).toBe(3);
    expect(out.result?.answer).toContain("999999");
  });

  it("a script cannot claim a granted scope it never read", async () => {
    const out = await runQueryScript(
      `
      await vana.readAll("oura.sleep");
      vana.result({ answer: "done" });
      `,
      // Two scopes granted, only one read.
      makeCtx(["oura.sleep", "spotify.streams"]),
      makeDeps(),
    );
    expect(out.coverage.scopesScanned).toEqual(["oura.sleep"]);
  });

  it("counts every granted scope the script actually streamed", async () => {
    const out = await runQueryScript(
      `
      await vana.readAll("oura.sleep");
      await vana.readAll("spotify.streams");
      vana.result({ answer: "done" });
      `,
      makeCtx(["oura.sleep", "spotify.streams"]),
      makeDeps(),
    );
    expect(out.coverage.scopesScanned).toEqual([
      "oura.sleep",
      "spotify.streams",
    ]);
    expect(out.coverage.recordsScanned).toBe(5);
  });

  it("marks a search-driven run as prefiltered", async () => {
    const out = await runQueryScript(
      `
      await vana.search("thai restaurant");
      vana.result({ answer: "earliest mention is X" });
      `,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(out.coverage.method).toBe("prefiltered");
  });

  it("counts a bounded read as only what it read, never the whole scope", async () => {
    // The partial/full distinction survives as a counter, not as a flag: a
    // windowed read must not report the record count a full pass would.
    const full = await runQueryScript(
      `await vana.readAll("oura.sleep"); vana.result({ answer: "x" });`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    const bounded = await runQueryScript(
      `await vana.read("oura.sleep", { maxBytes: 100 }); vana.result({ answer: "x" });`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(bounded.coverage.recordsScanned).toBeLessThan(
      full.coverage.recordsScanned,
    );
  });

  it("surfaces sandbox enforcement notes rather than swallowing them", async () => {
    const out = await runQueryScript(
      `vana.result({ answer: "x" });`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
      {
        enforcementNotes: [
          "memory bounded by RSS watchdog, not a kernel limit",
        ],
      },
    );
    expect(out.coverage.enforcementNotes).toContain(
      "memory bounded by RSS watchdog, not a kernel limit",
    );
  });
});

describe("budgets are first-class outcomes, not errors", () => {
  it("ends with a partial answer and stoppedBecause=budget", async () => {
    const out = await runQueryScript(
      `
      for (let i = 0; i < 100; i++) { await vana.readAll("oura.sleep"); }
      vana.result({ answer: "never reached" });
      `,
      makeCtx(["oura.sleep"], 3),
      makeDeps(),
    );
    expect(out.error?.code).toBe("BUDGET_EXHAUSTED");
    expect(out.coverage.stoppedBecause).toBe("budget");
  });

  const classifyDeps = () =>
    makeDeps({
      classify: async (items) => ({
        values: items.map(() => "yes"),
        usd: 5,
        inputTokens: 10,
        outputTokens: 10,
      }),
    });

  it("lets the in-flight classify overshoot but records it as stopped", async () => {
    // Cost is only known once the call returns, so the ceiling cannot prevent
    // the overshoot — it can only make the run stop and say so. That is the
    // "partial answer with honest coverage" outcome the prompt contract wants,
    // not an error.
    const ctx = makeCtx(["oura.sleep"]);
    ctx.budget.classifyUsd = 6;
    const out = await runQueryScript(
      `
      await vana.classify([1,2], "is this X?");
      await vana.classify([3,4], "is this X?");
      vana.result({ answer: "partial" });
      `,
      ctx,
      classifyDeps(),
    );
    expect(out.classifyUsd).toBe(10);
    expect(out.coverage.stoppedBecause).toBe("budget");
    expect(out.result?.answer).toBe("partial");
  });

  it("refuses the next classify once the ceiling is passed", async () => {
    const ctx = makeCtx(["oura.sleep"]);
    ctx.budget.classifyUsd = 6;
    const out = await runQueryScript(
      `
      await vana.classify([1,2], "is this X?");
      await vana.classify([3,4], "is this X?");
      await vana.classify([5,6], "is this X?");
      vana.result({ answer: "never reached" });
      `,
      ctx,
      classifyDeps(),
    );
    expect(out.error?.code).toBe("BUDGET_EXHAUSTED");
    expect(out.classifyUsd).toBe(10);
    expect(out.result).toBeUndefined();
  });
});

describe("capabilities the host did not register", () => {
  it("refuses classify when unregistered", async () => {
    const out = await runQueryScript(
      `await vana.classify([1], "x");`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(out.error?.code).toBe("CAPABILITY_UNAVAILABLE");
  });

  it("refuses introspect when unregistered", async () => {
    const out = await runQueryScript(
      `await vana.introspect();`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(out.error?.code).toBe("CAPABILITY_UNAVAILABLE");
  });
});

describe("the script can still do real work", () => {
  it("computes the Oura nap trap correctly under confinement", async () => {
    const out = await runQueryScript(
      `
      const rows = await vana.readAll("oura.sleep");
      const main = rows.filter((r) => r.type === "long_sleep");
      const total = main.reduce((a, r) => a + r.total_sleep_duration, 0);
      const hours = total / 3600 / main.length;
      vana.result({ answer: "avg " + hours.toFixed(2) + "h over " + main.length + " nights", value: hours });
      `,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    // (25200 + 23400) / 2 / 3600 = 6.75 — naps correctly excluded.
    expect(out.result?.value).toBeCloseTo(6.75, 2);
    expect(out.error).toBeUndefined();
  });

  it("collects vana.note output for the host", async () => {
    const out = await runQueryScript(
      `vana.note("checked the profile"); vana.result({ answer: "x" });`,
      makeCtx(["oura.sleep"]),
      makeDeps(),
    );
    expect(out.notes).toContain("checked the profile");
  });
});
