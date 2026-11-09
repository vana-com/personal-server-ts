/**
 * The entry installs the network guard before it loads any module that could
 * hold a reference to `fetch`. This file has one test, on its own, because the
 * module it probes is loaded once per test file.
 */

import { rm } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";
import type * as PublishedHeads from "./published-heads.js";
import { NetworkGuardError } from "./network-guard.js";
import { runLegacyRetireDryRun } from "./run.js";
import { persistFixture } from "./persisted-fixture.test-utils.js";

const hooks = vi.hoisted(() => ({
  // Settles with what the early reference gave back.
  early: null as null | Promise<unknown>,
}));

// A module that takes a reference to `fetch` as it loads, then uses it. It is
// loaded through the entry (run.ts loads it), the way a library would be.
// Only run.ts imports this module, so the fixture helper does not load it first.
vi.mock("./published-heads.js", async (importOriginal) => {
  const actual = await importOriginal<typeof PublishedHeads>();
  const early = globalThis.fetch;
  hooks.early = early("https://other.test/x").then(
    () => "answered",
    (error: unknown) => error,
  );
  return actual;
});

describe("the guard is in place before any module that could capture fetch", () => {
  it("refuses a fetch captured at module load, imported through the entry", async () => {
    const p = await persistFixture({ importDone: true, fullRun: true });
    try {
      vi.stubGlobal("fetch", p.fetch);
      await expect(
        runLegacyRetireDryRun({
          dataDir: p.dataDir,
          outPath: p.outPath,
          home: p.home,
          masterKeySignature: p.signature,
          now: () => new Date("2026-11-02T00:00:00Z"),
        }),
      ).rejects.toBeInstanceOf(NetworkGuardError);
      expect(await hooks.early).toBeInstanceOf(NetworkGuardError);
    } finally {
      vi.unstubAllGlobals();
      await rm(p.home, { recursive: true, force: true });
    }
  });
});
