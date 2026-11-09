/**
 * The shipped entry (legacy-retire-dry-run.ts) installs the network guard
 * before it loads any module that could hold a reference to `fetch`. This file
 * imports the entry itself, so the entry's static imports run at file load,
 * exactly as they do when the tool starts. It has one test, on its own, because
 * the module it probes is loaded once per test file.
 */

import { readFile, rm } from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { main } from "../legacy-retire-dry-run.js";
import type * as LegacyStoreModule from "./legacy-store.js";
import { persistFixture } from "./persisted-fixture.test-utils.js";
import { NetworkGuardError } from "./network-guard.js";

const hooks = vi.hoisted(() => ({
  // Settles with what the early reference gave back.
  early: null as null | Promise<unknown>,
}));

// A module that takes a reference to `fetch` as it loads, then uses it. The
// entry must not load it before the guard is in place; the run loads it after.
vi.mock("./legacy-store.js", async (importOriginal) => {
  const actual = await importOriginal<typeof LegacyStoreModule>();
  const early = globalThis.fetch;
  hooks.early = early("https://other.test/x").then(
    () => "answered",
    (error: unknown) => error,
  );
  return actual;
});

const homes: string[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  for (const home of homes.splice(0)) {
    await rm(home, { recursive: true, force: true });
  }
});

describe("the shipped entry loads nothing that could capture fetch before the guard", () => {
  it("refuses a fetch captured at module load, imported through the entry", async () => {
    const p = await persistFixture({ importDone: true, fullRun: true });
    homes.push(p.home);
    vi.stubGlobal("fetch", p.fetch);
    const signature = process.env.VANA_MASTER_KEY_SIGNATURE;
    process.env.VANA_MASTER_KEY_SIGNATURE = p.signature;
    try {
      const code = await main(["--data-dir", p.dataDir, "--out", p.outPath]);
      expect(code).toBe(2);
      expect(await hooks.early).toBeInstanceOf(NetworkGuardError);
      const report = JSON.parse(await readFile(p.outPath, "utf8"));
      expect(report).toMatchObject({
        status: "aborted",
        abortReason: "network_guard",
      });
    } finally {
      if (signature === undefined) delete process.env.VANA_MASTER_KEY_SIGNATURE;
      else process.env.VANA_MASTER_KEY_SIGNATURE = signature;
    }
  });
});
