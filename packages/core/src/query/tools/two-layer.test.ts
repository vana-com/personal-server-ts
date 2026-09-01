import { describe, expect, it } from "vitest";
import { createVanaApi } from "./api.js";
import { QueryToolError } from "./errors.js";
import type { QueryToolContext, QueryToolDeps } from "./types.js";

/**
 * The two layers must agree about the grant (design §19.7).
 *
 * The OS layer confines the *process* to `readPaths`; this layer confines the
 * *script* to named scopes. They are independent mechanisms, and a
 * disagreement between them is a bug in either direction:
 *
 * - a scope the API will name but `readPaths` omits ⇒ the script gets an
 *   unexplained EPERM instead of an honest "not granted";
 * - a path in `readPaths` for a scope the API will not name ⇒ ungranted data
 *   sitting inside the sandbox's reach, which is design §3 risk 1 exactly.
 *
 * `resolveScopePath` is the single source of paths, so the invariant to hold
 * is that the path set fed to the sandbox is derived from it and from nothing
 * else. Phase 5 owns the wiring; this pins the contract it must wire to.
 */

const ALL = ["oura.sleep", "spotify.streams", "secret.notes"];

function ctxFor(granted: string[]): QueryToolContext {
  return {
    grantedScopes: granted,
    resolveScopePath: (scope) => {
      if (!granted.includes(scope)) {
        throw new QueryToolError(
          "SCOPE_NOT_GRANTED",
          `scope "${scope}" is not in this grant`,
        );
      }
      return `/data/${scope}.json`;
    },
    budget: { toolCalls: 100, outputBytes: 1_000_000 },
  };
}

const deps: QueryToolDeps = {
  listScopes: async () => ALL.map((scope) => ({ scope })),
  streamScope: async () => {},
  readBlocks: async () => [],
  search: async () => [],
};

/** What phase 5 must hand to `SandboxSpec.readPaths`. */
function readPathsFor(ctx: QueryToolContext): string[] {
  return ctx.grantedScopes.map((s) => ctx.resolveScopePath(s));
}

describe("the capability layer and the OS layer agree on the grant", () => {
  const granted = ["oura.sleep", "spotify.streams"];
  const ctx = ctxFor(granted);

  it("derives readPaths for exactly the granted scopes", () => {
    expect(readPathsFor(ctx)).toEqual([
      "/data/oura.sleep.json",
      "/data/spotify.streams.json",
    ]);
  });

  it("never produces a path for an ungranted scope", () => {
    expect(() => ctx.resolveScopePath("secret.notes")).toThrow(QueryToolError);
    expect(readPathsFor(ctx).join()).not.toContain("secret.notes");
  });

  it("names exactly the scopes it has paths for", async () => {
    const { api } = createVanaApi(ctx, deps);
    const named = (await api.scopes()).map((s) => s.scope);
    const pathed = readPathsFor(ctx).map((p) =>
      p.replace("/data/", "").replace(".json", ""),
    );
    // Set equality in both directions: neither layer may be wider.
    expect([...named].sort()).toEqual([...pathed].sort());
  });

  it("an ungranted scope is unnameable at the API layer", async () => {
    const { api } = createVanaApi(ctx, deps);
    const named = (await api.scopes()).map((s) => s.scope);
    expect(named).not.toContain("secret.notes");
    await expect(api.readAll("secret.notes")).rejects.toThrow(QueryToolError);
  });
});
