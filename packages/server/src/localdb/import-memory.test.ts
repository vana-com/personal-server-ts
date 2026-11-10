import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, expect, it } from "vitest";
import { run } from "../../../core/src/test-support/memory-oracle.js";
import {
  createImportMemoryFixture,
  MEMORY_BUDGET,
  MEMORY_ROWS,
  MEMORY_ROW_BYTES,
  type ImportMemoryFixture,
} from "./import-memory-fixture.test-utils.js";
import type { ImportMemoryResult } from "./import-memory.child.js";

let fixture: ImportMemoryFixture;
let root: string;
beforeAll(() => {
  const temporary = join(homedir(), ".tmp");
  mkdirSync(temporary, { recursive: true });
  root = mkdtempSync(join(temporary, "ps3-import-memory-"));
  fixture = createImportMemoryFixture(root);
}, 600_000);
afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

async function measure(path: "node" | "upload", loadWhole = false) {
  expect(fixture.bytes).toBe(MEMORY_ROWS * MEMORY_ROW_BYTES);
  const measured = await run<ImportMemoryResult>({
    module: fileURLToPath(new URL("./import-memory.child.ts", import.meta.url)),
    exportName: "importMemoryWorkload",
    args: { fixture, path, loadWhole },
  });
  console.info(
    "IMPORT_MEMORY " +
      JSON.stringify({
        path,
        loadWhole,
        fixtureBytes: fixture.bytes,
        node: process.version,
        abi: process.versions.modules,
        ...measured,
      }),
  );
  expect(measured.result.kind).toBe("imported");
  expect(measured.result.rows).toBe(MEMORY_ROWS);
  expect(measured.result.receiptRows).toBe(MEMORY_ROWS);
  expect(measured.result.payloadBytes).toBe(fixture.payloadBytes);
  expect(measured.result.retainedRows).toBe(loadWhole ? MEMORY_ROWS : 0);
  expect(measured.result.retainedPayloadBytes).toBe(
    loadWhole ? fixture.payloadBytes : 0,
  );
  return measured;
}

function expectWithinBudget(peakBytes: number) {
  expect(peakBytes).toBeLessThanOrEqual(MEMORY_BUDGET);
}

it("import-memory-48mib-node", async () => {
  expectWithinBudget((await measure("node")).peakBytes);
}, 600_000);

it("import-memory-48mib-upload", async () => {
  expectWithinBudget((await measure("upload")).peakBytes);
}, 600_000);

it("import-load-whole-mutant-fails", async () => {
  // The same 48 MiB assertion must reject a real whole-source retention.
  const mutant = await measure("upload", true);
  expect(() => expectWithinBudget(mutant.peakBytes)).toThrow();
}, 600_000);
