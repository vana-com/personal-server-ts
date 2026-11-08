import { describe, expect, it } from "vitest";
import {
  READ_BUDGET,
  READ_CATEGORIES,
  ReadBudget,
  retainedBytes,
  textCharge,
} from "./budget.js";

const KiB = 1024;

describe("read budget accounting (calibration)", () => {
  it("peaks at the sum of overlapping live buffers, and returns to zero", () => {
    const b = new ReadBudget();
    b.acquire("importedPart", 64 * KiB);
    b.acquire("importedPart", 96 * KiB);
    b.release("importedPart", 64 * KiB);
    b.release("importedPart", 96 * KiB);
    const s = b.snapshot();
    expect(s.categories.importedPart.peak).toBe(160 * KiB);
    expect(s.categories.importedPart.current).toBe(0);
    expect(s.totalBytesPeak).toBe(160 * KiB);
    expect(s.totalBytesCurrent).toBe(0);
  });

  it("the total peak is the peak of the sum at one instant, not the sum of category peaks", () => {
    const b = new ReadBudget();
    b.acquire("importedPart", 100);
    b.release("importedPart", 100);
    b.acquire("decodedPart", 100);
    b.release("decodedPart", 100);
    const s = b.snapshot();
    expect(s.categories.importedPart.peak).toBe(100);
    expect(s.categories.decodedPart.peak).toBe(100);
    expect(s.totalBytesPeak).toBe(100);
  });

  it("counts allocations and exceedances, and does not refuse", () => {
    const b = new ReadBudget();
    // One acquisition above the 16 MiB part limit: counted, never thrown.
    b.acquire("importedPart", READ_BUDGET.partLimitBytes + 1);
    const s = b.snapshot();
    expect(s.categories.importedPart.allocations).toBe(1);
    expect(s.categories.importedPart.allocated).toBe(
      READ_BUDGET.partLimitBytes + 1,
    );
    expect(s.categories.importedPart.exceedances).toBe(1);
    expect(s.categories.importedPart.budget).toBe(READ_BUDGET.partLimitBytes);
  });

  it("an unbudgeted category never exceeds", () => {
    const b = new ReadBudget();
    b.acquire("otherRows", 10_000_000);
    expect(b.snapshot().categories.otherRows.exceedances).toBe(0);
    expect(b.snapshot().categories.otherRows.budget).toBe(
      Number.POSITIVE_INFINITY,
    );
  });

  it("releasing more than was acquired throws, and so does a negative or NaN amount", () => {
    const b = new ReadBudget();
    b.acquire("spoolBuffer", 10);
    expect(() => b.release("spoolBuffer", 11)).toThrow(/released more/);
    expect(() => b.acquire("spoolBuffer", -1)).toThrow(/finite and >= 0/);
    expect(() => b.acquire("spoolBuffer", Number.NaN)).toThrow(
      /finite and >= 0/,
    );
    expect(b.snapshot().categories.spoolBuffer.current).toBe(10);
  });

  it("counts count-unit categories without adding them to the byte total", () => {
    const b = new ReadBudget();
    b.acquire("overlayWinners", 500);
    const s = b.snapshot();
    expect(s.categories.overlayWinners.unit).toBe("count");
    expect(s.categories.overlayWinners.peak).toBe(500);
    expect(s.totalBytesPeak).toBe(0);
  });

  it("charges a retained view by its whole buffer, and decoded text at 2 bytes a unit", () => {
    const backing = new Uint8Array(1024 * KiB);
    const view = backing.subarray(0, KiB);
    expect(retainedBytes(view)).toBe(1024 * KiB);
    expect(retainedBytes(new Uint8Array(7))).toBe(7);
    expect(textCharge("abc")).toBe(6);
    // Astral text: two UTF-16 units per code point, so the charge is 4 per code point.
    expect(textCharge("😀")).toBe(4);
  });

  it("reports oversize ordinary records as a count, never as a refusal", () => {
    const b = new ReadBudget();
    b.noteOversizeRecord();
    b.noteOversizeRecord();
    expect(b.snapshot().oversizeRecords).toBe(2);
  });

  it("names every category exactly once in the snapshot", () => {
    const s = new ReadBudget().snapshot();
    expect(Object.keys(s.categories).sort()).toEqual(
      [...READ_CATEGORIES].sort(),
    );
    expect(new Set(READ_CATEGORIES).size).toBe(READ_CATEGORIES.length);
  });

  it("the byte budgets follow the protocol constants they cite", () => {
    // Writer default and decode cap of the protocol, as read from the package.
    expect(READ_BUDGET.partTargetBytes).toBe(4 * 1024 * 1024);
    expect(READ_BUDGET.partLimitBytes).toBe(16 * 1024 * 1024);
    expect(READ_BUDGET.mergeCursors).toBe(256);
    // The ordinary-record limit sits well below the protocol publish cap.
    expect(READ_BUDGET.ordinaryRecordBytes).toBeLessThan(8 * 1024 * 1024);
  });
});
