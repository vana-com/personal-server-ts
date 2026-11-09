/**
 * A file that changes between its readback and the last check is reported as
 * file_changed. The store is wrapped so the second read of one legacy file
 * returns other data; every other read is the real one.
 */

import { readFile, rm } from "node:fs/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import type * as NodeStorage from "../../storage/node-data-storage.js";
import { scopeHash } from "./report.js";
import { runLegacyRetireDryRun } from "./run.js";
import { persistFixture } from "./persisted-fixture.test-utils.js";

const reads = vi.hoisted(() => ({
  changed: null as null | string,
  seen: new Map<string, number>(),
}));
vi.mock("../../storage/node-data-storage.js", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeStorage>();
  return {
    ...actual,
    createNodeDataStorage: (
      ...args: Parameters<typeof actual.createNodeDataStorage>
    ) => {
      const node = actual.createNodeDataStorage(...args);
      return {
        ...node,
        readEnvelope: async (scope: string, collectedAt: string) => {
          const envelope = await node.readEnvelope(scope, collectedAt);
          const key = `${scope}|${collectedAt}`;
          const n = (reads.seen.get(key) ?? 0) + 1;
          reads.seen.set(key, n);
          return scope === reads.changed && n > 1
            ? { ...envelope, data: { ...envelope.data, rewritten: true } }
            : envelope;
        },
      };
    },
  };
});

vi.setConfig({ testTimeout: 60_000 });

const homes: string[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  reads.changed = null;
  reads.seen.clear();
  for (const home of homes.splice(0)) {
    await rm(home, { recursive: true, force: true });
  }
});

async function run(changed: string | null) {
  const p = await persistFixture({ importDone: true, fullRun: true });
  homes.push(p.home);
  vi.stubGlobal("fetch", p.fetch);
  reads.changed = changed;
  const report = await runLegacyRetireDryRun({
    dataDir: p.dataDir,
    outPath: p.outPath,
    home: p.home,
    masterKeySignature: p.signature,
    now: () => new Date("2026-11-02T00:00:00Z"),
  });
  return { p, report };
}

describe("file_changed in the dry run", () => {
  it("is zero when no file changes", async () => {
    const { report } = await run(null);
    expect(report.totals.byDecision.file_changed).toBe(0);
    expect(report.totals.wouldDelete).toBe(3);
  });

  it("holds a ready file that no longer hashes to its readback", async () => {
    const { p, report } = await run("github.events");
    const changed = report.files.find(
      (f) => f.scopeHash === scopeHash("github.events"),
    );
    expect(changed).toMatchObject({
      decision: "file_changed",
      wouldDelete: false,
      readback: "pass",
    });
    expect(report.totals.byDecision.file_changed).toBe(1);
    expect(report.totals.byDecision.ready).toBe(2);
    expect(report.totals.wouldDelete).toBe(2);
    expect(report.mode).toBe("dry-run");
    // The report on disk says the same.
    expect(
      JSON.parse(await readFile(p.outPath, "utf8")).totals.byDecision
        .file_changed,
    ).toBe(1);
  });
});
