// Writes that carry bodies are cut by the bytes the phone bridge will see.
// The cost of a statement is the length of its JSON, exactly: a batch under
// the budget by this count is under the frame.
import { describe, expect, it } from "vitest";
import type { SqlStatement } from "../../../core/src/localdb/driver.js";
import {
  jsonStringBytes,
  statementBytes,
  utf8Length,
  writeInBatches,
  WRITE_BATCH_BYTES,
} from "../../../core/src/localdb/write-batches.js";

const utf8 = (text: string) => Buffer.byteLength(text, "utf8");

describe("the cost of a string is its JSON", () => {
  const samples = [
    "",
    "plain ascii",
    'quotes " and \\ backslashes',
    "controls \u0000\u0001\b\t\n\f\r\u001f",
    "latin é ñ",
    "bmp 世界   ￿",
    "pair 😀 𝄞",
    "lone \ud800 high, lone \udc00 low, \udc00\ud800 swapped",
    '"'.repeat(1000),
  ];
  it("equals the UTF-8 length of JSON.stringify on each kind of character", () => {
    for (const text of samples)
      expect(jsonStringBytes(text), JSON.stringify(text)).toBe(
        utf8(JSON.stringify(text)),
      );
  });
  it("equals it on random strings over every unit", () => {
    let a = 12345;
    const next = () => (a = (Math.imul(a, 1103515245) + 12345) >>> 0);
    for (let n = 0; n < 300; n++) {
      let text = "";
      for (let i = 0; i < 40; i++) text += String.fromCharCode(next() >>> 16);
      expect(jsonStringBytes(text)).toBe(utf8(JSON.stringify(text)));
    }
  });
  it("counts UTF-8 length as SQLite does, a lone surrogate as three bytes", () => {
    expect(utf8Length("a😀\ud800")).toBe(1 + 4 + 3);
  });
});

describe("a write is cut into batches by its bytes", () => {
  const body = (n: number): SqlStatement => ({
    sql: "UPDATE t SET body = ? WHERE k = ?",
    params: ["x".repeat(n), 1],
  });
  const recorder = () => {
    const batches: SqlStatement[][] = [];
    return {
      batches,
      db: {
        batch: async (statements: readonly SqlStatement[]) => {
          batches.push([...statements]);
          return { changes: statements.map(() => 0) };
        },
      },
    };
  };

  it("keeps every batch under the budget and loses no statement or order", async () => {
    const { db, batches } = recorder();
    const groups = Array.from({ length: 100 }, (_, i) => [body(100_000 + i)]);
    await writeInBatches(db, groups);
    expect(batches.length).toBeGreaterThan(1);
    for (const batch of batches) {
      const bytes = batch.reduce((n, s) => n + statementBytes(s), 0);
      expect(bytes).toBeLessThanOrEqual(WRITE_BATCH_BYTES);
    }
    expect(batches.flat()).toEqual(groups.flat());
  });

  it("puts a group over the budget in a batch of its own, and keeps a group whole", async () => {
    const { db, batches } = recorder();
    const small = (): SqlStatement[] => [body(10), body(10)];
    const big = [body(WRITE_BATCH_BYTES * 3), body(5)];
    await writeInBatches(db, [small(), small(), big, small()]);
    expect(batches.map((batch) => batch.length)).toEqual([4, 2, 2]);
    expect(batches[1]).toEqual(big);
  });

  it("writes nothing for no groups", async () => {
    const { db, batches } = recorder();
    await writeInBatches(db, []);
    expect(batches).toEqual([]);
  });
});
