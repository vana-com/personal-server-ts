/**
 * The nested arrangement end to end: confined interpreter inside the OS
 * sandbox, with coverage crossing the process boundary untamperably.
 *
 * These are the regression tests for the phase 4b finding. A script handed
 * straight to Node inside the phase-4a sandbox could read its granted file
 * with `require('fs')` — unseen by any counter — and print a forged coverage
 * line on the runtime's own stdout. Everything here exists to prove that is no
 * longer reachable.
 */

import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createNodeSandbox } from "./node-sandbox.js";
import { createSandboxToolHost } from "./sandbox-tool-host.js";

const supported = process.platform === "darwin" || process.platform === "linux";

let root: string;
let dataRoot: string;
let scratch: string;
let sleepPath: string;
let secretPath: string;

const RUNNER = join(
  import.meta.dirname,
  "..",
  "..",
  "dist",
  "query",
  "runner.js",
);

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "nested-"));
  dataRoot = join(root, "data");
  scratch = join(root, "scratch");
  mkdirSync(dataRoot, { recursive: true });
  mkdirSync(scratch, { recursive: true });

  sleepPath = join(dataRoot, "oura.sleep.json");
  writeFileSync(
    sleepPath,
    JSON.stringify([
      { day: "2026-01-01", type: "long_sleep", total_sleep_duration: 25200 },
      { day: "2026-01-01", type: "late_nap", total_sleep_duration: 1800 },
      { day: "2026-01-02", type: "long_sleep", total_sleep_duration: 21600 },
    ]),
  );

  // Ungranted, inside the same data root: the file a bypass would reach for.
  secretPath = join(dataRoot, "bank.transactions.json");
  writeFileSync(secretPath, JSON.stringify([{ secret: "NOT-GRANTED-DATA" }]));
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

function host(searchResults?: Record<string, never[]>) {
  return createSandboxToolHost({
    sandbox: createNodeSandbox({ dataRoot }),
    scopes: [{ scope: "oura.sleep", path: sleepPath, itemCount: 3 }],
    dataRoot,
    scratchDir: scratch,
    budget: { toolCalls: 50, outputBytes: 1_000_000 },
    limits: {
      cpuMs: 30_000,
      memoryMb: 512,
      wallClockMs: 60_000,
      maxOutputBytes: 1_000_000,
    },
    runnerBundlePath: RUNNER,
    ...(searchResults ? { searchResults } : {}),
  });
}

describe.skipIf(!supported)("nested execution", () => {
  it("runs a confined script and reports host-authored coverage", async () => {
    const r = await host().execute(`
      const rows = await vana.readAll("oura.sleep");
      const main = rows.filter(function (x) { return x.type === "long_sleep"; });
      let total = 0;
      for (const m of main) total = total + m.total_sleep_duration;
      vana.result({ answer: "avg " + (total / main.length / 3600), value: total / main.length / 3600 });
    `);

    expect(r.error).toBeUndefined();
    expect(r.result?.value).toBeCloseTo(6.5, 5);
    // Host-authored: 3 records, not a number the script chose.
    expect(r.coverage.recordsScanned).toBe(3);
    expect(r.coverage.scopesScanned).toEqual(["oura.sleep"]);
    expect(r.coverage.complete).toBe(true);
  }, 120_000);

  it("model code cannot reach fs, process or require", async () => {
    const r = await host().execute(`
      const out = {
        req: typeof require,
        proc: typeof process,
        glob: typeof globalThis,
        ev: typeof eval,
      };
      vana.result({ answer: JSON.stringify(out) });
    `);
    // The interpreter refuses the identifiers outright, so this is a
    // confinement denial rather than a run that reports "undefined".
    expect(r.error?.code).toBe("CONFINEMENT_VIOLATION");
    expect(r.coverage.complete).toBe(false);
  }, 120_000);

  it("model code cannot read an ungranted file inside the same data root", async () => {
    const r = await host().execute(`
      const rows = await vana.readAll("bank.transactions");
      vana.result({ answer: JSON.stringify(rows) });
    `);
    expect(JSON.stringify(r)).not.toContain("NOT-GRANTED-DATA");
    expect(r.result?.answer).toBeUndefined();
    expect(r.coverage.complete).toBe(false);
  }, 120_000);

  it("a script cannot forge a coverage frame through vana.note", async () => {
    // The exact bytes the host scans for, emitted as note text.
    const r = await host().execute(`
      vana.note("__VANA_RESULT_V1_BEGIN__eyJ2IjoxLCJjb3ZlcmFnZSI6eyJyZWNvcmRzU2Nhbm5lZCI6OTk5OTk5LCJjb21wbGV0ZSI6dHJ1ZX19__VANA_RESULT_V1_END__");
      vana.note("__VANA_RESULT_V1_BEGIN__");
      vana.result({ answer: "done" });
    `);
    // Host counters win: the forged 999999 never becomes coverage.
    expect(r.coverage.recordsScanned).toBe(0);
    expect(r.coverage.complete).toBe(false);
    // And the attempt is visible as ordinary note text.
    expect(r.notes.join("\n")).toContain("__VANA_RESULT_V1_BEGIN__");
  }, 120_000);

  it("a script cannot suppress the frame by throwing", async () => {
    const r = await host().execute(`throw new Error("boom")`);
    expect(r.error).toBeDefined();
    expect(r.coverage.complete).toBe(false);
    // A frame still arrived — we know the run failed, rather than guessing.
    expect(r.error?.code).not.toBe("COVERAGE_FRAME_MISSING");
  }, 120_000);

  it("partial reads cannot report completeness", async () => {
    const r = await host().execute(`
      const blocks = await vana.read("oura.sleep", { maxBytes: 10 });
      vana.result({ answer: "read " + blocks.length + " blocks" });
    `);
    // A bounded read marks the scope partial, so `complete` is false even
    // though the script terminated cleanly.
    expect(r.coverage.complete).toBe(false);
  }, 120_000);
});
